// SPDX-License-Identifier: AGPL-3.0-only

//! Sandbox spawning implementation.

//TODO: in guest code, use `Vec::push_within_capacity` to ensure we don't
//      exceed the capacity and allocate
//TODO: install seccomp policy prior to exec or supervisor
//FIXME: ensure needless parent-death and child-death wait logic is removed.
//       don't introduce sigchld disp. check
//FIXME: consider making `CLONE_PIDFD_AUTOKILL` optional, even if it simplifies
//       logic because the host may not want the process to die automatically on
//       thread death. will need the reintroduction of manual killing on error,
//       though

use core::{
    ffi::{self, CStr},
    mem::ManuallyDrop,
};
use linux_raw_sys::general as linux;
use meowix::{
    capabilities::{self, CapabilitySet, CapabilitySets},
    errno::Errno,
    errors::SyscallError,
    fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd},
    ids::{Gid, Pid, Uid},
    mode::Mode,
    netlink, open_beneath_and_write, retry_on_interrupt, sigaction,
    syscalls::{self, CloneResult},
    util::{AtFd, Cwd, FdReadWriteExt, PATH_COMPONENT_MAX, WithCStr},
};

use super::{
    cgroups,
    errors::{Error, ResultSyscallExt},
    mounts::{File, MountAttributes},
    policy::{
        Policy,
        namespace::{Namespace, UserMappingMode},
    },
};
use crate::paths::Guest;
use errors::{
    PostSpawnGuest as PostSpawnGuestError,
    PostSpawnGuestOther as PostSpawnGuestOtherError,
    PostSpawnHost as PostSpawnHostError, PreSpawn as PreSpawnError,
};
use mounts::ResolvedMount;
use wire::PostSpawnGuestWire;

pub mod errors;
mod fd;
mod fmt;
mod guest;
mod host;
mod mounts;
mod namespace;
mod wire;

/// Action to take following sandbox setup.
pub(super) enum SpawnAction<'str, Dirfd, Argv, Envp> {
    /// Terminate the guest process with the given exit code.
    Exit(ffi::c_int),

    /// Execute the given process within the sandbox.
    ///
    /// This calls `execveat(2)` under the hood.
    Exec {
        /// Directory file descriptor of `execveat(2)`.
        ///
        /// If `AT_EMPTY_PATH` is specified, this refers to an executable file.
        dirfd: Dirfd,

        /// Path to an executable file.
        ///
        /// If empty, use `AT_EMPTY_PATH` to specify that `dirfd` refers to the
        /// executable.
        path: &'str CStr,

        /// Null-terminated array of arguments to pass to the program.
        argv: Argv,

        /// Null-terminated array of environment variables to pass to the
        /// program.
        envp: Envp,

        /// Flags to set for the `execveat(2)` call.
        flags: ffi::c_int,
    },

    /// Take the role of an init process in the sandbox.
    ///
    /// This will use the given [`OwnedFd`] representing an end of a pair of
    /// sockets created using `socketpair(2)` to communicate with the host.
    Supervisor(OwnedFd),
}

/// Build a set of namespaces according to the policy, yielding to
/// execution within them.
///
/// The [`Pid`] of the created process and an [`OwnedFd`] of a
/// `pidfd_open(2)` for the guest is returned on parent-side setup
/// success.
///
/// # Notes
///
/// The process within the sandbox retains supplementary groups had by the
/// caller. This is to ensure that it has the same view of bind mounts from
/// the host filesystem as the caller.
///
/// In order for this method to return in the parent, the `guest_callback`
/// must do exactly one of the following:
///
/// - Return a [`PostSpawnGuestError`].
/// - Return a [`SpawnAction`] indicating what to do next with the created
///   sandbox.
///
/// # Safety
///
/// This method invokes `clone3(2)` directly, without sharing the parent
/// process' address space.
///
/// The caller must ensure that `guest_callback` only performs operations
/// that are valid in a child process created from a potentially
/// multithreaded parent. Until returning the [`SpawnAction`], avoid
/// allocations, logging, unwinding, or anything else that may touch
/// inherited runtime-managed global state. Prefer direct syscalls.
///
/// If the [`SpawnAction`] returned from the callback is [`SpawnAction::Exec`],
/// `argv` and `envp` must be null-terminated.
///
/// Additionally, for accurate error reporting, avoid panicking and return
/// an error instead. As it is not guaranteed that stdin/stdout/stderr are
/// fed to the process, the error may not be visible to the caller.
///
/// # Errors
///
/// This method errors if the namespace setup fails.
pub unsafe fn clone_into<
    'str,
    'policy,
    'fd,
    CgroupsBackend,
    Dirfd,
    Argv,
    Envp,
>(
    policy: &Policy<'policy, CgroupsBackend>,
    guest_callback: impl FnOnce() -> Result<
        SpawnAction<'str, Dirfd, Argv, Envp>,
        PostSpawnGuestError,
    >,
    mut cgroups_state: CgroupsBackend::State,
) -> Result<(Pid, OwnedFd, CgroupsBackend::State), Error>
where
    CgroupsBackend: cgroups::Backend,
    Dirfd: Into<AtFd<'fd>>,
    Argv: AsRef<[*const ffi::c_char]>,
    Envp: AsRef<[*const ffi::c_char]>,
{
    //NOTE: necessary invariant for unprivileged userns
    let host_uid = syscalls::geteuid().wrap_error::<PreSpawnError>()?;
    let host_gid = syscalls::getegid().wrap_error::<PreSpawnError>()?;

    // this needs to be allocated all the way up here because we can't
    // allocate once we `clone3(2)`.
    let resolved_mappings = Vec::with_capacity(policy.mount_tree.0.len());
    let namespace_fd_scratch_space =
        Vec::with_capacity(policy.mount_tree.0.len());

    //FIXME: send success over this too. work out how to do this
    let (host_pipe, guest_pipe) = syscalls::pipe2(linux::O_CLOEXEC as i32)
        .wrap_error::<PreSpawnError>()?;

    // this is always unshared. see the documentation for `Namespaces` for
    // more details. the third is to ensure we are handed a pidfd to
    // the guest process.
    let mut clone_flags = linux::CLONE_NEWUSER | linux::CLONE_PIDFD;

    if !policy.namespaces.ipc.is_shared() {
        clone_flags |= linux::CLONE_NEWIPC;
    }

    if !policy.namespaces.pid.is_shared() {
        clone_flags |= linux::CLONE_NEWPID;
    }

    if !policy.namespaces.network.is_shared() {
        clone_flags |= linux::CLONE_NEWNET;
    }

    if !policy.namespaces.uts.is_shared() {
        clone_flags |= linux::CLONE_NEWUTS;
    }

    let mut guest_pidfd: ffi::c_int = -1;
    let mut clone_args = linux::clone_args {
        flags: clone_flags as u64
            | syscalls::CLONE_AUTOREAP
            //NOTE: nnp required for autokill
            | syscalls::CLONE_NNP
            | syscalls::CLONE_PIDFD_AUTOKILL,
        pidfd: <*mut _>::addr(&mut guest_pidfd) as linux::__u64,
        child_tid: 0,
        parent_tid: 0,
        //NOTE: needs to be zero for autoreap
        exit_signal: 0,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: 0,
    };

    if let Some(cgroup_fd) = policy.cgroups.clone_args_cgroup(&cgroups_state) {
        //NOTE: we can't unshare the cgroup namespace here because the
        //      backend may have a post-clone hook that needs to do
        //      something related to it, so we wait until all of the
        //      hooks have (presumably) finished
        clone_args.cgroup = cgroup_fd?.as_raw_fd() as linux::__u64;
        clone_args.flags |= linux::CLONE_INTO_CGROUP;
    }

    //SAFETY: the safety documentation for this method applies here:
    // - the caller must only provide closures which it is safe to call in a
    //   child process after clone
    // - we don't do things unsafe to perform after clone in the guest (it's not
    //   super well specified, but it's "like async-signal-safety")
    let clone_result =
        unsafe { syscalls::clone3(clone_args).wrap_error::<PreSpawnError>()? };
    let guest_pipe = guest_pipe.into_raw_fd();

    if let CloneResult::Parent(guest_pid) = clone_result {
        //SAFETY: there are no error conditions which would cause the
        //        syscall to succeed but the pidfd to not be created
        let guest_pidfd = unsafe { OwnedFd::from_raw_fd(guest_pidfd) };

        //SAFETY: we want it to leak into the guest but we also need to
        //        read from it and rely upon its closure in the guest
        unsafe { syscalls::close(guest_pipe) };

        return match host_post_clone(
            &policy,
            &mut cgroups_state,
            guest_pid,
            host_pipe,
        ) {
            Ok(()) => Ok((guest_pid, guest_pidfd, cgroups_state)),
            Err(err) => {
                //TODO: consider preserving this error
                let _teardown_result = policy.cgroups.teardown(cgroups_state);

                Err(err.into())
            }
        };
    }

    //TODO: consider using a `match` here to branch on parent vs child.

    //NOTE: this is where the guest process begins

    //NOTE: this is the only `std` call we use here. there really isn't an
    //      alternative, and this is necessary for safety. i think this being
    //      invalid to call post-clone should be a standard library bug
    //      regardless of the state of [rust-lang/rust #133604]
    //
    // [rust-lang/rust #133604]: https://github.com/rust-lang/rust/issues/133604
    std::panic::always_abort();

    let resolved_mappings = ManuallyDrop::new(resolved_mappings);
    let namespace_fd_scratch_space =
        ManuallyDrop::new(namespace_fd_scratch_space);

    //SAFETY: we're in the guest, we own this fd now
    let guest_pipe = unsafe { OwnedFd::from_raw_fd(guest_pipe) };

    match guest_post_clone(
        &policy,
        guest_callback,
        cgroups_state,
        resolved_mappings,
        namespace_fd_scratch_space,
        host_uid,
        host_gid,
    ) {
        Ok(action) => {
            //FIXME: update wire protocol, signal success to host, indicate
            //       we're about to perform the spawn action

            match action {
                SpawnAction::Exit(code) => {
                    drop(guest_pipe);
                    syscalls::exit(code);
                }
                SpawnAction::Exec {
                    dirfd,
                    path,
                    argv,
                    envp,
                    flags,
                } => {
                    //FIXME: don't ignore the error
                    //SAFETY: this executes in the guest post-clone
                    let _result = unsafe {
                        fd::apply_file_descriptor_policy(
                            &policy.file_descriptors.0,
                        )
                    };

                    //FIXME: don't ignore the error
                    let _ = capabilities::set_ambient_capabilities(
                        policy.target_capabilities,
                    );

                    //SAFETY: caller asserts the closure assembled
                    //        null-terminated arrays for argv, envp
                    let Err(error) = unsafe {
                        syscalls::execveat(dirfd, path, argv, envp, flags)
                    };

                    //FIXME: temporary. change once we have success signals /
                    //       etc
                    let wire_error: PostSpawnGuestWire =
                        <SyscallError as Into<PostSpawnGuestError>>::into(
                            error,
                        )
                        .into();

                    if guest_pipe
                        .write_all(bytemuck::bytes_of(&wire_error))
                        .is_err()
                    {
                        syscalls::exit(-2);
                    }

                    drop(guest_pipe);

                    syscalls::exit(-1);
                }
                SpawnAction::Supervisor(_) => {
                    //FIXME: apply fd policy but keep the provided fd alive,
                    //       leave capability handling as a "just in time
                    //       action" done immediately before
                    //       spawning guest processes to avoid
                    //       having greater capabilities than necessary in the
                    //       supervisor, even if those given to the supervised
                    //       processes

                    drop(guest_pipe);

                    syscalls::exit(-3);
                }
            }
        }
        Err(error) => {
            let wire_error: PostSpawnGuestWire = error.into();

            if guest_pipe
                .write_all(bytemuck::bytes_of(&wire_error))
                .is_err()
            {
                //TODO: document this as a means of determining the error
                syscalls::exit(-2);
            }

            drop(guest_pipe);

            syscalls::exit(-1);
        }
    }
}

/// Helper method for `clone_into`.
///
/// # Errors
///
/// This method errors if the namespace setup fails.
#[inline(always)]
fn host_post_clone<'policy, CgroupsBackend>(
    policy: &Policy<'policy, CgroupsBackend>,
    cgroups_state: &mut CgroupsBackend::State,
    guest_pid: Pid,
    host_pipe: OwnedFd,
) -> Result<(), Error>
where
    CgroupsBackend: cgroups::Backend,
{
    policy
        .cgroups
        .host_post_clone_hook(cgroups_state, guest_pid)?;

    //TODO: use read_array here once we have serialization of an "ok"
    //      status working
    let mut potential_error = Vec::new();
    let _ = host_pipe
        .read_to_end(&mut potential_error)
        .map_err(PostSpawnHostError::Syscall)?;

    if potential_error.is_empty() {
        return Ok(());
    }

    Err(<PostSpawnGuestWire as Into<PostSpawnGuestError>>::into(
        *bytemuck::try_from_bytes::<PostSpawnGuestWire>(
            potential_error.as_slice(),
        )
        .map_err(PostSpawnHostError::PodCastError)?,
    )
    .into())
}

/// Helper method for `clone_into`.
///
/// # Errors
///
/// This method errors if the namespace setup fails.
#[inline(always)]
fn guest_post_clone<
    'str,
    'policy,
    'policy_ref,
    'bind,
    'fd,
    CgroupsBackend,
    Dirfd,
    Argv,
    Envp,
>(
    policy: &'policy_ref Policy<'policy, CgroupsBackend>,
    guest_callback: impl FnOnce() -> Result<
        SpawnAction<'str, Dirfd, Argv, Envp>,
        PostSpawnGuestError,
    >,
    cgroups_state: CgroupsBackend::State,
    mut resolved_mappings: ManuallyDrop<Vec<ResolvedMount<'policy_ref>>>,
    mut namespace_fd_scratch_space: ManuallyDrop<
        Vec<(
            usize,
            OwnedFd,
            &'policy_ref Guest,
            Option<(&'bind CStr, BorrowedFd<'bind>)>,
            MountAttributes,
            bool,
        )>,
    >,
    host_uid: Uid,
    host_gid: Gid,
) -> Result<SpawnAction<'str, Dirfd, Argv, Envp>, PostSpawnGuestError>
where
    CgroupsBackend: cgroups::Backend,
    Dirfd: Into<AtFd<'fd>>,
    Argv: AsRef<[*const ffi::c_char]>,
    Envp: AsRef<[*const ffi::c_char]>,
    'policy: 'bind,
    'policy_ref: 'bind,
{
    let UserMappingMode::Simple {
        uid: guest_uid,
        gid: guest_gid,
    } = policy.namespaces.user.mapping_mode;
    let guest_uid = guest_uid.unwrap_or(host_uid);
    let guest_gid = guest_gid.unwrap_or(host_gid);

    //NOTE: should be set by clone_nnp?
    //syscalls::set_no_new_privs()?;
    capabilities::drop_bounding_set(policy.target_capabilities)?;

    //NOTE: we need to do this because `SIG_IGN` isn't reset on exec. see:
    //      https://www.man7.org/linux/man-pages/man7/signal.7.html#:~:text=A%20child,unchanged%2E
    //SAFETY: we're in a singlethreaded child process post-fork
    unsafe { sigaction::reset_signal_dispositions()? };

    policy.cgroups.guest_post_clone_hook(cgroups_state)?;

    //NOTE: we always unshare the cgroup namespace, but we do it right
    //      here because if the cgroup was moved post-clone and we
    //      perform unshare pre-clone, then the sandbox would be
    //      aware of its place in the hierarchy to a degree
    //SAFETY: this isn't unsharing the file descriptors
    unsafe {
        syscalls::unshare(linux::CLONE_NEWCGROUP as ffi::c_int)?;
    }

    //NOTE: we track the number of resolved mappings as rust can
    //      over-allocate a vector made with `Vec::with_capacity`, so we
    //      cannot just blindly set it to its capacity
    let mut n_resolved = mounts::resolve_bind_mappings(
        &policy.mount_tree.0,
        &mut resolved_mappings,
        &mut namespace_fd_scratch_space,
    )?;

    let guest_proc_fs_fd = syscalls::fsopen(c"proc", linux::FSOPEN_CLOEXEC)?;

    //NOTE: we set these to increase the chance we pass the
    //      `mount_too_revealing` check. the latter isn't important for it,
    //      but we set it anyway as we don't need more than that
    //TODO: set nosuid,nodev,noexec too just in case
    //FIXME: we can't set this and disable userns?? hmm
    //syscalls::fsconfig_set_string(&guest_proc_fs_fd, c"subset", c"pid")?;
    syscalls::fsconfig_set_string(
        &guest_proc_fs_fd,
        c"hidepid",
        c"ptraceable",
    )?;

    syscalls::fsconfig_cmd_create_excl(&guest_proc_fs_fd)?;

    let guest_proc_fd = syscalls::fsmount(
        guest_proc_fs_fd,
        linux::FSMOUNT_CLOEXEC,
        linux::MOUNT_ATTR_NOSUID
            | linux::MOUNT_ATTR_NOEXEC
            | linux::MOUNT_ATTR_NODEV,
    )?;

    namespace::write_simple_uid_gid_map(
        &guest_proc_fd,
        host_uid,
        host_gid,
        guest_uid,
        guest_gid,
        true,
    )?;

    if let Namespace::Unshared(ref time) = policy.namespaces.time {
        //SAFETY: this doesn't affect any state in the guest that we
        //        care about
        unsafe { syscalls::unshare(linux::CLONE_NEWTIME as ffi::c_int)? };

        namespace::write_timens_offsets(
            &guest_proc_fd,
            time.monotonic_offset,
            time.boottime_offset,
        )?;

        let timens_fd = retry_on_interrupt!({
            syscalls::openat2(
                &guest_proc_fd,
                c"self/ns/time_for_children",
                linux::open_how {
                    flags: (linux::O_RDONLY | linux::O_CLOEXEC) as u64,
                    mode: 0,
                    //NOTE: we can't use beneath/in_root because those
                    //      disable magic link resolution
                    resolve: 0,
                },
            )
        })?;

        syscalls::setns(timens_fd, linux::CLONE_NEWTIME as ffi::c_int)?;
    }

    //NOTE: we want to ensure our bind mounts are not tampered with
    let old_umask = syscalls::umask(0)?;

    //FIXME: why is it just this one that triggers on 32-bit
    #[allow(trivial_numeric_casts)]
    syscalls::update_mount_propagation_flags(
        c"/",
        (linux::MS_REC | linux::MS_PRIVATE) as ffi::c_ulong,
    )?;

    n_resolved += mounts::resolve_nonbind_mappings(
        &policy.mount_tree.0,
        &mut resolved_mappings,
    )?;

    //NOTE: we need a better error here
    (n_resolved == policy.mount_tree.0.len())
        .ok_or(PostSpawnGuestOtherError::MappingsLengthMismatch)?;

    //SAFETY: we just checked the length matches the number of mappings
    //        exactly
    unsafe { resolved_mappings.set_len(n_resolved) };

    let guest_root_fs_fd = syscalls::fsopen(c"tmpfs", linux::FSOPEN_CLOEXEC)?;

    //TODO: consider setting restrictions on the size of the root
    //      tmpfs

    syscalls::fsconfig_set_string(&guest_root_fs_fd, c"mode", c"755")?;

    syscalls::fsconfig_cmd_create_excl(&guest_root_fs_fd)?;

    let guest_root_fd = syscalls::fsmount(
        guest_root_fs_fd,
        linux::FSMOUNT_CLOEXEC,
        linux::MOUNT_ATTR_NOSUID | linux::MOUNT_ATTR_NODEV,
    )?;

    //TODO: we could probably take the following and the code above
    //      and factor it out into another function
    //TODO: we should consider using `O_EXCL` for synthetic destination
    //      creation instead of the statx -> openat2 dance. this wasn't used
    //      initially, but as long as we can guarantee that no nfs version older
    //      than 3 is the target of a mountpoint, we don't need to worry about
    //      its lack of support for it
    //
    //      see https://www.man7.org/linux/man-pages/man2/open.2.html#:~:text=O%5FEXCL,-Ensure
    //FIXME: above is wrong actually. we should just ignore all of that
    //       nonsense on synthetic mounts and just create the destination and we
    //       should safely assume a race isn't possible in any meaningful way
    //       (unless someone stole the fd i guess and tampered with it). under a
    //       non-synthetic mount, we should open a fd to the destination and do
    //       nothing else. this would reduce the amount of redundant checks we
    //       perform

    for resolved in resolved_mappings.iter() {
        match resolved {
            ResolvedMount::Fd {
                fd,
                destination,
                is_directory,
            } if *is_directory => {
                let (parent_fd, file_name) =
                    mounts::open_parent_in_root(&guest_root_fd, destination)?;

                file_name.with_c_str::<{
                        PATH_COMPONENT_MAX
                    }, _, PostSpawnGuestError>(
                        |file_name| {
                            match syscalls::statx(
                                &parent_fd,
                                file_name,
                                linux::AT_SYMLINK_NOFOLLOW as i32,
                                linux::STATX_TYPE,
                            ) {
                                Ok(statx) => {
                                    if u32::from(statx.stx_mode) & linux::S_IFMT
                                        != linux::S_IFDIR
                                    {
                                        Err(PostSpawnGuestOtherError::InvalidDirectoryMountPoint)?;
                                    }
                                }
                                Err(e) if e.error() == Errno::NOENT => {
                                    syscalls::mkdirat(
                                        &parent_fd,
                                        file_name,
                                        (Mode::RWXU
                                            | Mode::RGRP
                                            | Mode::XGRP
                                            | Mode::ROTH
                                            | Mode::XOTH).bits(),
                                    )
                                    ?;
                                }
                                Err(e) => Err(e)?,
                            }

                            syscalls::move_mount(
                                fd,
                                c"",
                                &parent_fd,
                                file_name,
                                linux::MOVE_MOUNT_F_EMPTY_PATH,
                            )
                            ?;

                            Ok(())
                        }
                    )?;
            }
            ResolvedMount::Fd {
                fd, destination, ..
            } => {
                let (parent_fd, file_name) =
                    mounts::open_parent_in_root(&guest_root_fd, destination)?;

                file_name.with_c_str::<{
                        PATH_COMPONENT_MAX
                    }, _, PostSpawnGuestError>(
                        |file_name| {
                            match syscalls::statx(
                                &parent_fd,
                                file_name,
                                linux::AT_SYMLINK_NOFOLLOW as i32,
                                linux::STATX_TYPE,
                            ) {
                                Ok(statx) => {
                                    if u32::from(statx.stx_mode) & linux::S_IFMT
                                        != linux::S_IFREG
                                    {
                                        Err(PostSpawnGuestOtherError::InvalidRegularFileMountPoint)?;
                                    }
                                }
                                Err(e) if e.error() == Errno::NOENT => {
                                    //NOTE: we only care about creating it
                                    drop(
                                        retry_on_interrupt!({
                                            syscalls::openat2(
                                                &parent_fd,
                                                file_name,
                                                linux::open_how {
                                                    flags: (linux::O_CREAT
                                                        | linux::O_WRONLY)
                                                        as u64,
                                                    mode: (linux::S_IRUSR
                                                        | linux::S_IWUSR
                                                        | linux::S_IRGRP
                                                        | linux::S_IROTH)
                                                        as u64,
                                                    resolve: linux::RESOLVE_BENEATH
                                                        as u64,
                                                },
                                            )
                                        })
                                        ?
                                    );
                                }
                                Err(e) => Err(e)?,
                            }

                            syscalls::move_mount(
                                fd,
                                c"",
                                &parent_fd,
                                file_name,
                                linux::MOVE_MOUNT_F_EMPTY_PATH,
                            )
                            ?;

                            Ok(())
                        }
                    )?;
            }
            ResolvedMount::File {
                file:
                    File {
                        contents,
                        permissions,
                        ..
                    },
                destination,
            } => {
                let (parent_fd, file_name) =
                    mounts::open_parent_in_root(&guest_root_fd, destination)?;

                file_name.with_c_str::<{
                        PATH_COMPONENT_MAX
                    }, _, PostSpawnGuestError>(
                        |file_name| {
                            if !matches!(
                                syscalls::statx(
                                    &parent_fd,
                                    file_name,
                                    linux::AT_SYMLINK_NOFOLLOW as i32,
                                    0,
                                ),
                                Err(e) if e.error() == Errno::NOENT
                            ) {
                                //TODO: relax this restriction by truncating the
                                //      existing file and chmod-ing it
                                Err(PostSpawnGuestOtherError::DestinationExists)?;
                            }

                            retry_on_interrupt!({
                                syscalls::openat2(
                                    &parent_fd,
                                    file_name,
                                    linux::open_how {
                                        flags: (linux::O_CREAT | linux::O_RDWR)
                                            as u64,
                                        mode: permissions.bits() as u64,
                                        resolve: linux::RESOLVE_BENEATH as u64,
                                    },
                                )
                            })?
                            .write_all(contents)
                            .map_err(|e| {
                                if let Some(e) = e.error {
                                    e.into()
                                } else {
                                    PostSpawnGuestError::IncompleteWrite
                                }
                            })?;

                            Ok(())
                        }
                    )?;
            }
            ResolvedMount::Directory {
                permissions,
                destination,
                ..
            } => {
                let (parent_fd, file_name) =
                    mounts::open_parent_in_root(&guest_root_fd, destination)?;

                file_name.with_c_str::<{
                        PATH_COMPONENT_MAX
                    }, _, PostSpawnGuestError>(
                        |file_name| {
                            if !matches!(
                                syscalls::statx(
                                    &parent_fd,
                                    file_name,
                                    linux::AT_SYMLINK_NOFOLLOW as i32,
                                    0,
                                ),
                                Err(e) if e.error() == Errno::NOENT
                            ) {
                                //TODO: and relax this one
                                Err(PostSpawnGuestOtherError::DestinationExists)?;
                            }

                            syscalls::mkdirat(
                                &parent_fd,
                                file_name,
                                permissions.bits()
                            )
                            ?;

                            Ok(())
                        }
                    )?;
            }
        }
    }

    let guest_root_mount_attr = linux::mount_attr {
        attr_set: (linux::MOUNT_ATTR_RDONLY
            | linux::MOUNT_ATTR_NOSUID
            | linux::MOUNT_ATTR_NODEV
            | linux::MOUNT_ATTR_NOEXEC
            | linux::MOUNT_ATTR_NOSYMFOLLOW)
            .into(),
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };

    syscalls::mount_setattr(
        &guest_root_fd,
        c"",
        linux::AT_EMPTY_PATH,
        guest_root_mount_attr,
    )?;

    syscalls::fchdir(&guest_root_fd)?;

    syscalls::move_mount(
        guest_root_fd,
        c"",
        Cwd,
        c"/",
        linux::MOVE_MOUNT_F_EMPTY_PATH | linux::MOVE_MOUNT_BENEATH,
    )?;

    syscalls::chroot(c".")?;
    syscalls::umount2(c".", linux::MNT_DETACH as i32)?;
    syscalls::chdir(c"/")?;

    if let Namespace::Unshared(ref uts) = policy.namespaces.uts {
        if let Some(hostname) = uts.hostname {
            syscalls::sethostname(hostname)?;
        }

        if let Some(domain) = uts.domain {
            syscalls::setdomainname(domain)?;
        }
    }

    if let Namespace::Unshared(ref _network) = policy.namespaces.network {
        netlink::setup_loopback()?;
    }

    let _ = syscalls::umask(old_umask);

    if policy.new_session {
        let _ = syscalls::setsid()?;
    }

    if policy.namespaces.user.disable_userns {
        open_beneath_and_write!(
            &guest_proc_fd,
            c"sys/user/max_user_namespaces",
            b"1\n"
        );

        //SAFETY: we're not unsharing the file descriptor namespace so
        //        no fds are invalidated
        unsafe {
            syscalls::unshare(linux::CLONE_NEWUSER as ffi::c_int)?;
        }

        capabilities::drop_bounding_set(policy.target_capabilities)?;

        namespace::write_simple_uid_gid_map(
            &guest_proc_fd,
            guest_uid,
            guest_gid,
            guest_uid,
            guest_gid,
            true,
        )?;
    }

    syscalls::set_capabilities(CapabilitySets {
        effective: CapabilitySet::empty(),
        permitted: policy.target_capabilities,
        inheritable: policy.target_capabilities,
    })?;

    //TODO: somewhere here or before performing the callback's suggested
    //      action, we should unset syscalls::set_parent_thread_death_signal
    //      because at this low level of an interface, there's no
    //      "guarantee" we can enforce it
    guest_callback()
}
