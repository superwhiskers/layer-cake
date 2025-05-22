// SPDX-LICENSE-IDENTIFIER: GPL-3.0-or-later

//! Utilities for cross-platform sandboxing

#![warn(
    clippy::cargo_common_metadata,
    clippy::dbg_macro,
    clippy::expect_used,
    clippy::needless_pass_by_ref_mut,
    clippy::needless_pass_by_value,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::todo,
    clippy::unimplemented
)]
#![deny(
    clippy::await_holding_lock,
    rustdoc::broken_intra_doc_links,
    clippy::cast_lossless,
    clippy::clone_on_ref_ptr,
    clippy::default_trait_access,
    clippy::doc_markdown,
    clippy::empty_enum,
    clippy::enum_glob_use,
    clippy::exit,
    clippy::explicit_deref_methods,
    clippy::explicit_into_iter_loop,
    clippy::explicit_iter_loop,
    clippy::fallible_impl_from,
    clippy::filetype_is_file,
    clippy::float_cmp,
    clippy::float_cmp_const,
    clippy::imprecise_flops,
    clippy::inefficient_to_string,
    clippy::large_digit_groups,
    clippy::large_stack_arrays,
    clippy::manual_filter_map,
    clippy::match_like_matches_macro,
    missing_docs,
    clippy::missing_errors_doc,
    clippy::missing_safety_doc,
    clippy::mut_mut,
    clippy::option_option,
    clippy::panic_in_result_fn,
    clippy::redundant_clone,
    clippy::redundant_else,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::single_match_else,
    clippy::string_to_string,
    trivial_casts,
    trivial_numeric_casts,
    clippy::undocumented_unsafe_blocks,
    clippy::unused_self,
    clippy::unwrap_used,
    clippy::wildcard_dependencies,
    clippy::wildcard_imports
)]

//TODO: attempt to provide sane fallbacks for some environment variables such
//      as `PATH` so that it isn't necessarily a problem if it doesn't exist
//
//      such as:
//      - /bin
//      - /usr/bin
//      - /usr/local/bin
//      - /sbin
//      - /usr/sbin
//      - /usr/local/sbin

use flume::SendError;
use futures::{
    future,
    stream::{self, TryStreamExt},
};
use nix::{
    errno::{self, Errno},
    sys::memfd::{self, MemFdCreateFlag},
    unistd::{Gid, SysconfVar, Uid, User, sysconf},
};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    env::{self, VarError},
    ffi::{OsStr, OsString},
    fs::{File as StdFile, Metadata},
    io::Error as IoError,
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::{
    fs::{self, DirEntry, File},
    io::AsyncWriteExt,
    process::Command as TokioCommand,
};
use tokio_stream::wrappers::ReadDirStream;

/// The machine id to present to the sandbox. This is set to the whonix
/// machine id
const MACHINE_ID: &[u8] = b"b08dfa6083e7567a1921a715000001fb";

/// Locate directory entries satisfying the provided predicate within the
/// specified directories
///
/// # Errors
///
/// Will error if the code is unable to retrieve directory entries or their
/// metadata.
pub async fn find_within(
    pred: impl Fn(OsString, Metadata) -> bool,
    dirs: impl IntoIterator<Item = PathBuf>,
) -> Result<Vec<PathBuf>, Error> {
    let rdf = future::join_all(
        dirs.into_iter().map(|d| async { fs::read_dir(d).await }),
    )
    .await;

    let (s, r) = flume::bounded(rdf.len());
    let mut rds = Vec::with_capacity(rdf.len());
    for rd in rdf {
        rds.push(ReadDirStream::new(rd?));
    }

    // i'm not actually sure if this is faster but why not
    stream::select_all(rds)
        .err_into::<Error>()
        .try_for_each_concurrent(None, |de| async {
            if pred(de.file_name(), de.metadata().await?) {
                //PANIC: Err(_) is only returned from the function if the
                //       receiving end of the channel is dropped, and we
                //       do not drop it in this case until the end of the
                //       function
                #[allow(clippy::expect_used)]
                s.send_async(de)
                    .await
                    .expect(
                        "the channel used to receive directory entries should not be dropped at this point"
                    );
            }
            Ok(())
        })
        .await?;

    Ok(r.into_iter().map(|rd| rd.path()).collect())
}

/// Build an /etc/passwd with the selected users from the old one and write
/// the result to the provided stream
fn build_passwd(stream: *mut libc::FILE, users: &[Uid]) -> Result<(), Error> {
    let mut passwd = MaybeUninit::<libc::passwd>::uninit();
    let mut result = MaybeUninit::<*mut libc::passwd>::uninit();

    let mut buffer_size = sysconf(SysconfVar::GETPW_R_SIZE_MAX)?
        .map(|m| m as libc::size_t)
        .unwrap_or(16384);

    //SAFETY: this just allocates a block of memory
    let mut buffer =
        unsafe { libc::malloc(buffer_size) } as *mut libc::c_char;
    if buffer.is_null() {
        Err(errno::from_i32(errno::errno()))?;
    }

    for uid in users {
        loop {
            //SAFETY: we just call a library function here with no special
            //        requirements on the input
            let res = unsafe {
                libc::getpwuid_r(
                    uid.as_raw(),
                    passwd.as_mut_ptr(),
                    buffer,
                    buffer_size,
                    result.as_mut_ptr(),
                )
            };

            if res == 0 {
                //SAFETY: `result` will be initialized if `res` is 0
                let result = unsafe { result.assume_init() };
                if result.is_null() {
                    return Err(Error::NoPasswdEntry(*uid));
                }
            } else {
                match errno::from_i32(res) {
                    // according to getpwuid_r(3) these denote it not being
                    // found
                    Errno::ENOENT
                    | Errno::ESRCH
                    | Errno::EBADF
                    | Errno::EPERM => {
                        return Err(Error::NoPasswdEntry(*uid));
                    }
                    Errno::ERANGE => {
                        buffer_size *= 2;

                        //SAFETY: this just reallocates a block of memory
                        //        already known to be allocated by this point
                        buffer = unsafe {
                            libc::realloc(
                                buffer as *mut libc::c_void,
                                buffer_size,
                            )
                        }
                            as *mut libc::c_char;
                        if buffer.is_null() {
                            Err(errno::from_i32(errno::errno()))?;
                        }

                        continue;
                    }
                    e => Err(e)?,
                }
            }

            break;
        }

        //SAFETY: by this point `passwd` will be a valid `passwd` structure
        if unsafe { libc::putpwent(passwd.as_mut_ptr(), stream) }
            .is_negative()
        {
            Err(errno::from_i32(errno::errno()))?;
        }
    }

    //SAFETY: this just frees memory
    unsafe { libc::free(buffer as *mut libc::c_void) };

    Ok(())
}

/// Build an /etc/group with the selected groups from the old one and write
/// the result to the provided stream
fn build_group(stream: *mut libc::FILE, groups: &[Gid]) -> Result<(), Error> {
    let mut group = MaybeUninit::<libc::group>::uninit();
    let mut result = MaybeUninit::<*mut libc::group>::uninit();

    let mut buffer_size = sysconf(SysconfVar::GETGR_R_SIZE_MAX)?
        .map(|m| m as libc::size_t)
        .unwrap_or(16384);

    //SAFETY: this just allocates a block of memory
    let mut buffer =
        unsafe { libc::malloc(buffer_size) } as *mut libc::c_char;
    if buffer.is_null() {
        Err(errno::from_i32(errno::errno()))?;
    }

    for gid in groups {
        loop {
            //SAFETY: we just call a library function here with no special
            //        requirements on the input
            let res = unsafe {
                libc::getgrgid_r(
                    gid.as_raw(),
                    group.as_mut_ptr(),
                    buffer,
                    buffer_size,
                    result.as_mut_ptr(),
                )
            };

            if res == 0 {
                //SAFETY: `result` will be initialized if `res` is 0
                let result = unsafe { result.assume_init() };
                if result.is_null() {
                    return Err(Error::NoGroupEntry(*gid));
                }
            } else {
                match errno::from_i32(res) {
                    _ if res == 0 => {
                        return Err(Error::NoGroupEntry(*gid));
                    }
                    // according to getgrgid_r(3) these denote it not being
                    // found
                    Errno::ENOENT
                    | Errno::ESRCH
                    | Errno::EBADF
                    | Errno::EPERM => {
                        return Err(Error::NoGroupEntry(*gid));
                    }
                    Errno::ERANGE => {
                        buffer_size *= 2;

                        //SAFETY: this just reallocates a block of memory
                        //        already known to be allocated by this point
                        buffer = unsafe {
                            libc::realloc(
                                buffer as *mut libc::c_void,
                                buffer_size,
                            )
                        }
                            as *mut libc::c_char;
                        if buffer.is_null() {
                            Err(errno::from_i32(errno::errno()))?;
                        }

                        continue;
                    }
                    e => Err(e)?,
                }
            }

            break;
        }

        //SAFETY: by this point `group` will be a valid `group` structure
        if unsafe { libc::putgrent(group.as_mut_ptr(), stream) }.is_negative()
        {
            Err(errno::from_i32(errno::errno()))?;
        }
    }

    //SAFETY: this just frees memory
    unsafe { libc::free(buffer as *mut libc::c_void) };

    Ok(())
}

/// Permissions that can be granted within a [`Sandbox`]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Permission<'a> {
    /// Permission to access a path on the host system
    Path {
        /// The path to bind-mount outside the sandbox
        src: Cow<'a, Path>,

        /// The path to bind mount the path at within the sandbox
        dest: Cow<'a, Path>,

        /// Whether or not it should be mounted read-only
        readonly: bool,

        /// Whether or not it must be mounted in order for the sandbox to be
        /// built
        required: bool,
    },

    /// Set an environment variable within the sandbox
    SetEnv {
        /// The environment variable to set
        variable: Cow<'a, str>,

        /// The value to set it to
        value: Cow<'a, str>,
    },

    /// Forward an environment variable to the sandbox
    ForwardEnv(Cow<'a, str>),

    /// Permission to access the network stack
    Network,

    /// Permission to access the Wayland display
    Wayland,

    /// Permission to access the Direct Rendering Interface
    DRI,

    /// Permission to access the audio subsystem (currently PulseAudio and
    /// PipeWire)
    Audio,

    /// Permission to access the DBus session bus
    DbusSession,

    /// Permission to access the DBus system bus
    DbusSystem,

    /// Set up a system call filter using seccomp
    ///
    /// The byte array must be in eBPF bytecode. Filters of this format can
    /// be made using the [`libseccomp`](https://crates.io/crates/libseccomp)
    /// crate, among others
    Seccomp(Vec<u8>),
}

/// Alias for a set of permissions granted to a [`Sandbox`]
pub type Permissions<'a> = HashSet<Permission<'a>>;

impl<'a> From<Permission<'a>> for Permissions<'a> {
    fn from(permission: Permission<'a>) -> Self {
        let mut permissions = Self::new();
        permissions.insert(permission);
        permissions
    }
}

/// A sandbox builder
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Sandbox<'a> {
    permissions: Permissions<'a>,
}

impl<'a> Sandbox<'a> {
    /// Set permissions for the sandbox
    pub fn permissions(
        &mut self,
        permissions: impl Into<Permissions<'a>>,
    ) -> &mut Self {
        self.permissions = &self.permissions | &permissions.into();
        self
    }
}

/// A process builder, akin to [Tokio's command builder](TokioCommand) and
/// [the standard library's command builder](StdCommand) but within the
/// [`Sandbox`] that created it
#[derive(Debug)]
pub struct Command<'a> {
    permissions: Permissions<'a>,

    program: OsString,

    arguments: Vec<OsString>,

    kill_on_drop: bool,

    environment: HashMap<OsString, OsString>,
    keys_to_remove: Vec<OsString>,
    clear_environment: bool,

    stdin: Option<Stdio>,
    stdout: Option<Stdio>,
    stderr: Option<Stdio>,
}

impl<'a> Command<'a> {
    /// Add a single argument for the sandboxed program
    pub fn arg(&mut self, argument: impl AsRef<OsStr>) -> &mut Self {
        self.arguments.push(argument.as_ref().to_owned());
        self
    }

    /// Add several arguments for the sandboxed program
    pub fn args(
        &mut self,
        arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
    ) -> &mut Self {
        //TODO: add them
        self
    }

    /// Controls whether or not to kill the sandboxed process when the handle
    /// is dropped
    ///
    /// This is by default assumed to be false
    pub fn kill_on_drop(&mut self, kill_on_drop: bool) -> &mut Self {
        self.kill_on_drop = kill_on_drop;
        self
    }

    /// Build the [`TokioCommand`]
    async fn build_command(
        self,
        directory: Option<&Path>,
    ) -> Result<TokioCommand, Error> {
        let mut command = TokioCommand::new(
            option_env!("BUBBLEWRAP_EXECUTABLE").unwrap_or("bwrap"),
        );

        let user =
            User::from_uid(Uid::current())?.ok_or(Error::NoAssociatedUser)?;

        let mut runtime_dir = PathBuf::new();
        runtime_dir.push("/run/user");
        runtime_dir.push(format!("{}", user.uid.as_raw()));

        let local_runtime_dir = PathBuf::from(env::var("XDG_RUNTIME_DIR")?);

        let root_uid = Uid::from_raw(0);
        let root = User::from_uid(root_uid)?
            .ok_or(Error::NoPasswdEntry(root_uid))?;

        let current_uid = Uid::current();
        let current = User::from_uid(current_uid)?
            .ok_or(Error::NoPasswdEntry(current_uid))?;

        let passwd_fd =
            memfd::memfd_create(c"passwd", MemFdCreateFlag::empty())?;

        //SAFETY: this just creates a file stream for a file descriptor, the
        //        latter of which is known to exist by this point
        let passwd_stream = unsafe { libc::fdopen(passwd_fd, c"w".as_ptr()) };
        if passwd_stream.is_null() {
            Err(errno::from_i32(errno::errno()))?;
        }

        build_passwd(passwd_stream, &[root_uid, current_uid])?;

        let group_fd =
            memfd::memfd_create(c"group", MemFdCreateFlag::empty())?;

        //SAFETY: this just creates a file stream for a file descriptor, the
        //        latter of which is known to exist by this point
        let group_stream = unsafe { libc::fdopen(group_fd, c"w".as_ptr()) };
        if group_stream.is_null() {
            Err(errno::from_i32(errno::errno()))?;
        }

        // honestly this is a red flag but w/e
        if root.gid == current.gid {
            build_group(group_stream, &[root.gid])?;
        } else {
            build_group(group_stream, &[root.gid, current.gid])?;
        }

        //SAFETY: we create an entirely new file descriptor for this file. no
        //        other code will touch it directly beyond this point
        let mut machine_id = File::from(StdFile::from(unsafe {
            OwnedFd::from_raw_fd(memfd::memfd_create(
                c"machine-id",
                MemFdCreateFlag::empty(),
            )?)
        }));

        machine_id.write_all(MACHINE_ID).await?;

        // remember to fclose both of the manually handled streams

        command.args(["--tmpfs", "/etc", "--ro-bind-data"]);
        command.arg(passwd_fd.to_string());
        command.args(["/etc/passwd", "--ro-bind-data"]);
        command.arg(group_fd.to_string());
        command.args(["/etc/group", "--ro-bind-data"]);
        command.arg(machine_id.as_raw_fd().to_string());
        command.args([
            "/etc/machine-id",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/run",
            "--symlink",
            "/run",
            "/var/run",
            "--perms",
            "0700",
            "--dir",
        ]);
        command.arg(&runtime_dir);
        command.args(["--clearenv", "--setenv", "XDG_RUNTIME_DIR"]);
        command.arg(&runtime_dir);
        command.args(["--dev", "/dev", "--setenv", "SHELL"]);

        //TODO(superwhiskers): forward the directory as part of `PATH`
        let nologin = find_within(
            |n, m| n == "nologin" && (m.mode() & libc::S_IXOTH) != 0,
            env::split_paths(
                &env::var_os("PATH")
                    .ok_or(Error::MissingEnvVar(EnvVar::Path))?,
            ),
        )
        .await?
        .into_iter()
        .next()
        .ok_or(Error::MissingBinary(Binary::Nologin))?;

        command.arg(nologin);
        command.args(["--setenv", "HOME"]);
        command.arg(current.dir.as_os_str());
        command.args([
            "--unshare-all",
            "--hostname",
            "host",
            "--new-session",
            "--cap-drop-all",
            "--die-with-parent",
        ]);

        if let Some(directory) = directory {
            command.arg("--chdir");
            command.arg(directory.as_os_str());
        }

        for permission in self.permissions {
            match permission {
                Permission::Path {
                    src,

                    dest,

                    readonly,

                    required,
                } => {
                    command.arg(match (readonly, required) {
                        (true, true) => "--ro-bind",
                        (true, false) => "--ro-bind-try",
                        (false, true) => "--bind",
                        (false, false) => "--bind-try",
                    });
                    command.arg(src.as_ref());
                    command.arg(dest.as_ref());
                }
                Permission::SetEnv { variable, value } => {
                    command.arg("--setenv");
                    command.arg(variable.as_ref());
                    command.arg(value.as_ref());
                }
                //TODO(superwhiskers): finish this
                Permission::ForwardEnv(_) => {}
                Permission::Network => {
                    command.args(["--share-net"]);
                }
                Permission::Wayland => {
                    let wl_display = env::var("WAYLAND_DISPLAY")?;
                    let wl_socket_path = local_runtime_dir.join(&wl_display);
                    let sandboxed_socket_path = runtime_dir.join(&wl_display);

                    let wl_socket = File::open(&wl_socket_path).await?;
                    if (wl_socket.metadata().await?.mode() & libc::S_IFMT)
                        == libc::S_IFSOCK
                    {
                        command.arg("--ro-bind");
                        command
                            .args([&wl_socket_path, &sandboxed_socket_path]);
                        command.args(["--setenv", "WAYLAND_DISPLAY"]);
                        command.arg(&wl_display);
                    }
                }
                Permission::DRI => {
                    command.args(["--dev-bind", "/dev/dri", "/dev/dri"]);
                }
                Permission::Audio => {
                    //TODO(superwhiskers): consider cutting out pulse entirely and spawning it
                    //                     in the sandbox
                    //TODO(superwhiskers): double check that these paths are reliable

                    command.arg("--ro-bind");
                    command.arg(local_runtime_dir.join("pulse"));
                    command.arg(runtime_dir.join("pulse"));

                    command.arg("--ro-bind");
                    command.arg(local_runtime_dir.join("pipewire-0"));
                    command.arg(runtime_dir.join("pipewire-0"));
                }
                Permission::DbusSession => {
                    command.arg("--ro-bind");
                    command.arg(local_runtime_dir.join("bus"));
                    command.arg(runtime_dir.join("bus"));
                }
                Permission::DbusSystem => {
                    command.args(["--ro-bind", "/run/dbus", "/run/dbus"]);
                }
                Permission::Seccomp(_) => {
                    //TODO(superwhiskers): add fd stuff here
                    command.args(["--seccomp"]);
                }
            }
        }

        Ok(command)
    }
}

/// An enumeration over possible errors when working with bubblebox
#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// An error encountered when querying environment variables
    #[error("An error was encountered while querying environment variables")]
    VarError(#[from] VarError),

    /// An error encountered when working with the native API directly
    #[error("An error was encountered while working with the native API")]
    Errno(#[from] Errno),

    /// An error encountered while performing I/O
    #[error("An error was encountered while performing I/O")]
    IoError(#[from] IoError),

    /// An error encountered while attempting to send a directory entry over a channel
    #[error(
        "An error was encountered while attempting to send a directory entry over a channel"
    )]
    SendError(#[from] SendError<DirEntry>),

    /// The current process lacks a valid associated user
    #[error("There is no valid associated user with the process")]
    NoAssociatedUser,

    /// There is a necessary binary that is missing
    #[error("A necessary binary is missing")]
    MissingBinary(Binary),

    /// The current process' environment lacks a necessary environment variable
    #[error(
        "The process' environment lacks a necessary environment variable"
    )]
    MissingEnvVar(EnvVar),

    /// One of the [`Uid`]s required to build the mock passwd file lacks a /etc/passwd entry
    #[error("There is no /etc/passwd entry for the uid `{0}`")]
    NoPasswdEntry(Uid),

    /// One of the [`Gid`]s required to build the mock group file lacks a /etc/group entry
    #[error("There is no /etc/group entry for the gid `{0}`")]
    NoGroupEntry(Gid),
}

/// A binary necessary for the library to function
#[non_exhaustive]
#[derive(Debug)]
pub enum Binary {
    /// The `nologin` binary, usually at `/usr/sbin/nologin`
    Nologin,
}

/// An environment variable required for the library to function
#[non_exhaustive]
#[derive(Debug)]
pub enum EnvVar {
    /// The `PATH` environment variable
    Path,
}
