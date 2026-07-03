// SPDX-License-Identifier: AGPL-3.0-only

//! Sandbox policy implementation.

//TODO: implement constructors for each of these types and a builder for the
//      sandbox type, which will effectively act as a handle to all of the
//      namespaces
//TODO: add back arbitrary id mappings by having the parent call
//      newuidmap/newgidmap
//TODO: use systemd-nsresourced to perform larger id mappings on request.
//      this ensures systemd-homed systems continue to work as they lack the
//      subuid/subgid delegations
//TODO: add selinux support through file label options for mounts, executable
//      labels for the program
//TODO: add support for io_uring syscall denylists using the new api introduced
//      in kernel 7.0
//TODO: in child code, use `Vec::push_within_capacity` to ensure we don't
//      exceed the capacity and allocate

use linux_raw_sys::general as linux;
use std::{
    collections::BTreeMap,
    ffi::{self, OsStr},
    io::{Read, Write},
    mem::ManuallyDrop,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
    panic,
};

#[cfg(feature = "seccomp")]
use seccompiler::SeccompFilter;

use super::{
    cgroups::{self, Cgroups},
    errors::{
        Error, PostCloneGuest as PostCloneGuestError,
        PostCloneGuestOther as PostCloneGuestOtherError, PostCloneGuestWire,
        PostCloneHost as PostCloneHostError, PreClone as PreCloneError,
        ResultSyscallExt, SyscallError,
    },
    mapping::{File, Mode, MountAttributes, Source},
    netlink,
    syscalls::{
        self, CapabilitySet, CapabilitySets, CloneResult, Cwd, Errno, Gid, Pid,
        PollFd, Uid, WaitFor, WithCStr,
    },
    util::{self, FdPolicy, FdReadWrite, ResolvedMount, TimeOffset},
};
use crate::{
    command::{Child, Command, Sandbox},
    path::Guest,
};

/// Sandbox policy.
#[derive(Clone, Debug)]
pub struct Policy<'a, CgroupsBackend> {
    /// Map of destinations to their source.
    ///
    /// This is used to prevent duplicate destinations by construction.
    mappings: BTreeMap<Guest, Source<'a>>,

    /// Seccomp policy.
    //TODO: make this not have a hard dependency upon seccompiler to work
    #[cfg(feature = "seccomp")]
    seccomp: Option<SeccompFilter>,

    /// Namespaces.
    namespaces: Namespaces<'a>,

    /// Cgroups.
    cgroups: Cgroups<CgroupsBackend>,

    /// Capability set of the final environment.
    ///
    /// By default, none are passed through.
    target_capabilities: CapabilitySet,

    /// File descriptor policy.
    ///
    /// Any file descriptors not specified in this map are marked as
    /// close-on-exec.
    file_descriptors: BTreeMap<RawFd, FdPolicy<'a>>,

    /// User ID to execute as in the sandbox by default.
    ///
    /// This [`Uid`] also provides the default user owner of synthetic
    /// mappings within the sandbox.
    ///
    /// By default, this is the caller's uid. If it differs, the caller's uid
    /// is mapped to this by the user namespace.
    uid: Option<Uid>,

    /// Group ID to execute as in the sandbox by default.
    ///
    /// This [`Gid`] also provides the default group owner of synthetic
    /// mappings within the sandbox.
    ///
    /// By default, this is the caller's gid. If it differs, the caller's gid
    /// is mapped to this by the user namespace.
    gid: Option<Gid>,

    /// Whether to kill the child process(es) when the parent thread dies.
    die_with_parent_thread: bool,

    /// Whether to create a new session using `setsid(2)`.
    new_session: bool,
}

impl<'a, CgroupsBackend> Policy<'a, CgroupsBackend>
where
    CgroupsBackend: cgroups::Backend,
{
    /// Builds a reusable [`Sandbox`] instance with a supervisor process.
    ///
    /// # Errors
    ///
    /// something about the sandbox setup failing
    pub fn supervise(&self) -> Result<Sandbox, Error> {
        //NOTE: this one can leave out the docs about sigchld because we'll
        //      pass along the exit code via another channel. the supervisor
        //      process should set the disposition for itself, though, and use
        //      pidfds to monitor the status or something.

        //TODO: apply file descriptor policy, raise ambient capabilities,
        //      install seccomp policy

        todo!("needs `Sandbox`")
    }

    /// Executes the given [`Command`], sandboxed according to the policy.
    ///
    /// # Errors
    ///
    /// something about the sandbox setup failing
    pub fn spawn(&self, command: Command) -> Result<Child, Error> {
        //NOTE: check process sigchld disposition somewhere in this path
        //      because we need to be able to capture the exit code. add docs
        //      about this too akin to those on the private initialization
        //      method.

        //TODO: apply file descriptor policy, raise ambient capabilities,
        //      install seccomp policy

        todo!("needs `Command`, `Child`")
    }

    /// Build a set of namespaces according to the policy, yielding to
    /// execution within them.
    ///
    /// The [`Pid`] of the created process and an [`OwnedFd`] of a
    /// `pidfd_open(2)` for the child is returned on parent-side setup
    /// success.
    ///
    /// The process within the sandbox retains supplementary groups had by the
    /// caller. This is to ensure that it has the same view of bind mounts from
    /// the host filesystem as the caller.
    ///
    /// # Notes
    ///
    /// In order to accurately capture the exit code of the child process, the
    /// `SIGCHLD` disposition of the current process must satisfy some
    /// conditions:
    ///
    /// - `SIGCHLD` must not have the disposition set to `SIG_IGN`.
    /// - The `SIGCHLD` action must not have `SA_NOCLDWAIT` set.
    /// - An explicit `SIGCHLD` handler must not reap the child.
    ///
    /// If the targeted capabilities are desired in the ambient capability
    /// set, then the `child_callback` must raise them on its own. This is done
    /// to avoid accidentally giving undesired privileges to a helper process.
    /// This may be performed with [`util::set_ambient_capabilities`]. Note
    /// additionally that the `child_callback` executes without any effective
    /// capabilities.
    ///
    /// If it is desired for the file descriptor policy to be applied, then the
    /// `child_callback` must implement it on its own. This may be performed
    /// with [`util::apply_file_descriptor_policy`]. This choice was made as
    /// were it applied in `clone_into`, file descriptors opened within the
    /// callback would conflict with the desired state of the policy.
    ///
    /// In order for this method to return in the parent, the `child_callback`
    /// must do one of the following:
    /// - Return a [`PostCloneGuestError`].
    /// - Call `execve(2)`, `_exit(2)`, or another syscall which will trigger fd
    ///   close-on-exit behavior.
    /// - Close the writing end of the file descriptor used to pass errors back
    ///   to the parent.
    ///
    /// # Safety
    ///
    /// This method invokes `clone3(2)` directly, without sharing the parent
    /// process' address space. No clone trampoline is used, hence
    /// `child_callback` is responsible for either replacing the process
    /// image---such as through `execve(2)`---or terminating it using
    /// `_exit(2)`.
    ///
    /// The caller must ensure that `child_callback` only performs operations
    /// that are valid in a child process created from a potentially
    /// multithreaded parent. Until `execve(2)` or `_exit(2)`, avoid
    /// allocations, logging, unwinding, or anything else that may touch
    /// inherited runtime-managed global state. Prefer direct syscalls.
    ///
    /// Additionally, for accurate error reporting, avoid panicking and return
    /// an error instead. As it is not guaranteed that stdin/stdout/stderr are
    /// fed to the process, the error may not be visible to the caller.
    ///
    /// # Errors
    ///
    /// This method errors if the namespace setup fails.
    unsafe fn clone_into(
        &self,
        child_callback: impl FnOnce() -> Result<!, PostCloneGuestError>,
        mut cgroups_state: CgroupsBackend::State,
    ) -> Result<(Pid, OwnedFd, CgroupsBackend::State), Error> {
        util::is_valid_fd_policy(&self.file_descriptors)
            .ok_or(PreCloneError::InvalidFdPolicy)?;
        util::is_valid_mapping_tree(&self.mappings)
            .ok_or(PreCloneError::InvalidMappings)?;

        let parent_pidfd = if self.die_with_parent_thread {
            Some(
                syscalls::pidfd_open(
                    syscalls::getpid().wrap_error::<PreCloneError>()?,
                    0,
                )
                .wrap_error::<PreCloneError>()?,
            )
        } else {
            None
        };

        //NOTE: necessary invariant for unprivileged userns
        let host_uid = syscalls::geteuid().wrap_error::<PreCloneError>()?;
        let host_gid = syscalls::getegid().wrap_error::<PreCloneError>()?;

        // this needs to be allocated all the way up here because we can't
        // allocate once we `clone3(2)`.
        let resolved_mappings = Vec::with_capacity(self.mappings.len());
        let namespace_fd_scratch_space =
            Vec::with_capacity(self.mappings.len());

        //FIXME: send success over this too. work out how to do this
        let (host_pipe, guest_pipe) = syscalls::pipe2(linux::O_CLOEXEC as i32)
            .wrap_error::<PreCloneError>()?;

        // this is always unshared. see the documentation for `Namespaces` for
        // more details. the third is to ensure we are handed a pidfd to
        // the child process.
        let mut clone_flags = linux::CLONE_NEWUSER | linux::CLONE_PIDFD;

        if !self.namespaces.ipc.is_shared() {
            clone_flags |= linux::CLONE_NEWIPC;
        }

        if !self.namespaces.pid.is_shared() {
            clone_flags |= linux::CLONE_NEWPID;
        }

        if !self.namespaces.network.is_shared() {
            clone_flags |= linux::CLONE_NEWNET;
        }

        if !self.namespaces.uts.is_shared() {
            clone_flags |= linux::CLONE_NEWUTS;
        }

        let mut child_pidfd: ffi::c_int = -1;
        let mut clone_args = linux::clone_args {
            flags: clone_flags.into(),
            pidfd: <*mut _>::addr(&mut child_pidfd) as linux::__u64,
            child_tid: 0,
            parent_tid: 0,
            exit_signal: linux::SIGCHLD.into(),
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: 0,
        };

        if let Some(cgroup_fd) = self.cgroups.clone_args_cgroup(&cgroups_state)
        {
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
        // - we don't do things unsafe to perform after clone in the child (it's
        //   not super well specified, but it's "like async-signal-safety")
        let clone_result = unsafe {
            syscalls::clone3(clone_args).wrap_error::<PreCloneError>()?
        };
        let guest_pipe = guest_pipe.into_raw_fd();

        if let CloneResult::Parent(child_pid) = clone_result {
            //SAFETY: there are no error conditions which would cause the
            //        syscall to succeed but the pidfd to not be created
            let child_pidfd = unsafe { OwnedFd::from_raw_fd(child_pidfd) };

            //SAFETY: we want it to leak into the child but we also need to
            //        read from it and rely upon its closure in the child
            unsafe { syscalls::close(guest_pipe) };
            let host_pipe = FdReadWrite::new(host_pipe);

            return match self.host_post_clone(
                &mut cgroups_state,
                child_pid,
                child_pidfd.as_fd(),
                host_pipe,
            ) {
                Ok(()) => Ok((child_pid, child_pidfd, cgroups_state)),
                Err(err) => {
                    //TODO: we want to preserve the original error so we ignore
                    //      everything. maybe provide a custom error type that
                    //      preserves everything

                    let _pidfd_result = syscalls::pidfd_send_signal(
                        &child_pidfd,
                        linux::SIGKILL as i32,
                        0,
                    );
                    let _waitid_result = syscalls::waitid(
                        WaitFor::PidFd(child_pidfd.as_fd()),
                        linux::WEXITED as i32,
                    );
                    let _teardown_result = self.cgroups.teardown(cgroups_state);

                    Err(err.into())
                }
            };
        }

        //TODO: consider using a `match` here to branch on parent vs child.

        //NOTE: this is where the child process begins

        let resolved_mappings = ManuallyDrop::new(resolved_mappings);
        let namespace_fd_scratch_space =
            ManuallyDrop::new(namespace_fd_scratch_space);

        //SAFETY: we're in the child, we own this fd now
        let mut guest_pipe =
            FdReadWrite::new(unsafe { OwnedFd::from_raw_fd(guest_pipe) });

        panic::always_abort();

        let Err(e) = self.guest_post_clone(
            child_callback,
            cgroups_state,
            parent_pidfd,
            resolved_mappings,
            namespace_fd_scratch_space,
            host_uid,
            host_gid,
        );

        let wire_error: PostCloneGuestWire = e.into();
        guest_pipe
            .write_all(bytemuck::bytes_of(&wire_error))
            .expect("unable to write the serialized error to the pipe");
        drop(guest_pipe);

        syscalls::exit(-1);
    }

    /// Helper method for `clone_into`.
    ///
    /// # Errors
    ///
    /// This method errors if the namespace setup fails.
    #[inline(always)]
    fn host_post_clone(
        &self,
        cgroups_state: &mut CgroupsBackend::State,
        child_pid: Pid,
        child_pidfd: BorrowedFd<'_>,
        mut host_pipe: FdReadWrite,
    ) -> Result<(), Error> {
        self.cgroups
            .host_post_clone_hook(cgroups_state, child_pid)?;

        //TODO: use read_array here once we have serialization of an "ok"
        //      status working
        let mut potential_error = Vec::new();
        let _ = host_pipe
            .read_to_end(&mut potential_error)
            .map_err(PostCloneHostError::StdIo)?;

        if potential_error.is_empty() {
            return Ok(());
        }

        //NOTE: ensure the child doesn't become a zombie. we ignore the
        //      error here to avoid masking the child error
        let _ = syscalls::waitid(
            WaitFor::PidFd(child_pidfd.as_fd()),
            linux::WEXITED as i32,
        );

        Err(<PostCloneGuestWire as Into<PostCloneGuestError>>::into(
            *bytemuck::from_bytes::<PostCloneGuestWire>(
                potential_error.as_slice(),
            ),
        )
        .into())
    }

    /// Helper method for `clone_into`.
    ///
    /// # Errors
    ///
    /// This method errors if the namespace setup fails.
    #[inline(always)]
    fn guest_post_clone<'b, 'c>(
        &'b self,
        child_callback: impl FnOnce() -> Result<!, PostCloneGuestError>,
        cgroups_state: CgroupsBackend::State,
        parent_pidfd: Option<OwnedFd>,
        mut resolved_mappings: ManuallyDrop<Vec<ResolvedMount<'b>>>,
        mut namespace_fd_scratch_space: ManuallyDrop<
            Vec<(
                usize,
                OwnedFd,
                &'b Guest,
                Option<(&'c OsStr, BorrowedFd<'c>)>,
                MountAttributes,
                bool,
            )>,
        >,
        host_uid: Uid,
        host_gid: Gid,
    ) -> Result<!, PostCloneGuestError>
    where
        'a: 'c,
        'b: 'c,
    {
        let guest_uid = self.uid.unwrap_or(host_uid);
        let guest_gid = self.gid.unwrap_or(host_gid);

        if let Some(parent_pidfd) = parent_pidfd {
            syscalls::set_parent_process_death_signal(
                linux::SIGKILL as ffi::c_int,
            )?;

            let mut fds =
                [PollFd::new(parent_pidfd.as_fd(), linux::POLLIN as i16)];

            //NOTE: this avoids a race where the parent process dies prior
            //      to us checking liveness
            if util::retry_on_interrupt!({
                syscalls::ppoll(
                    &mut fds,
                    Some(linux::__kernel_timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    }),
                )
            })? != 0
            {
                syscalls::exit(-1);
            }
        }

        syscalls::set_no_new_privs()?;
        util::drop_bounding_set(self.target_capabilities)?;
        util::reset_signal_dispositions()?;

        self.cgroups.guest_post_clone_hook(cgroups_state)?;

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
        let mut n_resolved = util::resolve_bind_mappings(
            &self.mappings,
            &mut resolved_mappings,
            &mut namespace_fd_scratch_space,
        )?;

        let guest_proc_fs_fd =
            syscalls::fsopen(c"proc", linux::FSOPEN_CLOEXEC)?;

        //NOTE: we set these to increase the chance we pass the
        //      `mount_too_revealing` check. the latter isn't important for it,
        //      but we set it anyway as we don't need more than that
        //TODO: set nosuid,nodev,noexec too just in case
        syscalls::fsconfig_set_string(&guest_proc_fs_fd, c"subset", c"pid")?;
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

        util::write_simple_uid_gid_map(
            &guest_proc_fd,
            host_uid,
            host_gid,
            guest_uid,
            guest_gid,
            true,
        )?;

        if let Namespace::Unshared(ref time) = self.namespaces.time {
            //SAFETY: this doesn't affect any state in the child that we
            //        care about
            unsafe { syscalls::unshare(linux::CLONE_NEWTIME as ffi::c_int)? };

            util::write_timens_offsets(
                &guest_proc_fd,
                time.monotonic_offset,
                time.boottime_offset,
            )?;

            let timens_fd = util::retry_on_interrupt!({
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

        n_resolved += util::resolve_nonbind_mappings(
            &self.mappings,
            &mut resolved_mappings,
        )?;

        //NOTE: we need a better error here
        (n_resolved == self.mappings.len())
            .ok_or(PostCloneGuestOtherError::MappingsLengthMismatch)?;

        //SAFETY: we just checked the length matches the number of mappings
        //        exactly
        unsafe { resolved_mappings.set_len(n_resolved) };

        let guest_root_fs_fd =
            syscalls::fsopen(c"tmpfs", linux::FSOPEN_CLOEXEC)?;

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
        //      and factor it out into a separate function in `util`

        for resolved in resolved_mappings.iter() {
            match resolved {
                ResolvedMount::Fd {
                    fd,
                    destination,
                    is_directory,
                } if *is_directory => {
                    let (parent_fd, file_name) =
                        util::open_parent_in_root(&guest_root_fd, destination)?;

                    file_name.with_c_str::<{
                        syscalls::PATH_COMPONENT_MAX
                    }, _, PostCloneGuestError>(
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
                                        Err(PostCloneGuestOtherError::InvalidDirectoryMountPoint)?;
                                    }
                                }
                                Err(SyscallError { error: Errno::NOENT, .. }) => {
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
                        util::open_parent_in_root(&guest_root_fd, destination)?;

                    file_name.with_c_str::<{
                        syscalls::PATH_COMPONENT_MAX
                    }, _, PostCloneGuestError>(
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
                                        Err(PostCloneGuestOtherError::InvalidRegularFileMountPoint)?;
                                    }
                                }
                                Err(SyscallError { error: Errno::NOENT, .. }) => {
                                    //NOTE: we only care about creating it
                                    drop(
                                        util::retry_on_interrupt!({
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
                            owner,
                            permissions,
                        },
                    destination,
                } => {
                    let (parent_fd, file_name) =
                        util::open_parent_in_root(&guest_root_fd, destination)?;

                    file_name.with_c_str::<{
                        syscalls::PATH_COMPONENT_MAX
                    }, _, PostCloneGuestError>(
                        |file_name| {
                            if !matches!(
                                syscalls::statx(
                                    &parent_fd,
                                    file_name,
                                    linux::AT_SYMLINK_NOFOLLOW as i32,
                                    0,
                                ),
                                Err(SyscallError { error: Errno::NOENT, .. })
                            ) {
                                //TODO: relax this restriction by truncating the
                                //      existing file and chmod-ing it
                                Err(PostCloneGuestOtherError::DestinationExists)?;
                            }

                            FdReadWrite::new(
                                util::retry_on_interrupt!({
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
                                })
                                ?
                             )
                            .write_all(contents)?;

                            Ok(())
                        }
                    )?;
                }
                ResolvedMount::Directory {
                    owner,
                    permissions,
                    destination,
                } => {
                    let (parent_fd, file_name) =
                        util::open_parent_in_root(&guest_root_fd, destination)?;

                    file_name.with_c_str::<{
                        syscalls::PATH_COMPONENT_MAX
                    }, _, PostCloneGuestError>(
                        |file_name| {
                            if !matches!(
                                syscalls::statx(
                                    &parent_fd,
                                    file_name,
                                    linux::AT_SYMLINK_NOFOLLOW as i32,
                                    0,
                                ),
                                Err(SyscallError { error: Errno::NOENT, .. })
                            ) {
                                //TODO: and relax this one
                                Err(PostCloneGuestOtherError::DestinationExists)?;
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

        if let Namespace::Unshared(ref uts) = self.namespaces.uts {
            if let Some(ref hostname) = uts.hostname {
                syscalls::sethostname(hostname)?;
            }

            if let Some(ref domain) = uts.domain {
                syscalls::setdomainname(domain)?;
            }
        }

        if let Namespace::Unshared(ref network) = self.namespaces.network {
            netlink::setup_loopback()?;
        }

        let _ = syscalls::umask(old_umask);

        if self.new_session {
            let _ = syscalls::setsid()?;
        }

        if self.namespaces.user.disable_userns {
            util::open_beneath_and_write!(
                &guest_proc_fd,
                c"sys/user/max_user_namespaces",
                b"1\n"
            );

            //SAFETY: we're not unsharing the file descriptor namespace so
            //        no fds are invalidated
            unsafe {
                syscalls::unshare(linux::CLONE_NEWUSER as ffi::c_int)?;
            }

            util::drop_bounding_set(self.target_capabilities)?;

            util::write_simple_uid_gid_map(
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
            permitted: self.target_capabilities,
            inheritable: self.target_capabilities,
        })?;

        child_callback()
    }
}

/// Enumeration over states a namespace may be left in.
///
/// Used to indicate a namespace's usage is user-controllable. For namespaces
/// which are always unshared, such as the mount namespace and user namespace,
/// this type is not used.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Namespace<Options> {
    /// Leave the namespace alone.
    Shared,

    /// `unshare(2)` the namespace and apply `Options`.
    Unshared(Options),
    //TODO: add a file descriptor option so that an existing namespace can
    //      be used
}

impl<Options> Namespace<Options>
where
    Options: PartialEq,
{
    /// Indicates if the namespace represented by this [`Namespace`] is shared
    /// or not.
    pub fn is_shared(&self) -> bool {
        *self == Self::Shared
    }
}

/// Namespace policy.
///
/// Configures optional namespaces and mandatory namespace setup. Neither
/// mount nor user namespaces may be shared with the caller.
///
/// # Notes
///
/// - Mount namespaces are always used to create a synthetic filesystem view.
/// - User namespaces are always used to gain local namespace creation
///   privileges, regardless of the process' uid.
/// - cgroup namespaces are always used because they don't do much other than
///   change the view of cgroups that the sandbox gets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Namespaces<'a> {
    ipc: Namespace<IpcOptions>,
    pid: Namespace<PidOptions>,
    network: Namespace<NetworkOptions>,
    uts: Namespace<UtsOptions<'a>>,
    time: Namespace<TimeOptions>,
    user: UserOptions,
}

/// IPC namespace policy.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IpcOptions;

/// Pid namespace policy.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PidOptions;

/// Network namespace policy.
#[expect(
    missing_copy_implementations,
    reason = "later variants might not work with copy"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkOptions {
    /// Leave the created network namespace isolated.
    Isolate,
    //TODO: add option to establish veth from parent namespace to the
    //      created network namespace, probably with name options. this needs
    //      `CAP_NET_ADMIN` to work
}

/// UTS namespace policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UtsOptions<'a> {
    /// Hostname to set with `sethostname(2)`.
    ///
    /// # Notes
    ///
    /// The kernel appears to see this as a set of arbitrary bytes. Userland
    /// applications may have expectations of this field. At a minimum, treat
    /// this field as if it were only containing alphanumerical characters as
    /// well as not starting with a period or a hyphen.
    hostname: Option<&'a [u8]>,

    /// Domain name to set with `setdomainname(2)`.
    ///
    /// On most modern Linux systems, this field is unset.
    ///
    /// # Notes
    ///
    /// The kernel appears to see this as a set of arbitrary bytes. Userland
    /// applications may have expectations of this field. At a minimum, treat
    /// this field as if it were only containing alphanumerical characters as
    /// well as not starting with a hyphen.
    domain: Option<&'a [u8]>,
}

/// Time namespace policy.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TimeOptions {
    /// Offset for the initial time namespace's `CLOCK_MONOTONIC`.
    monotonic_offset: Option<TimeOffset>,

    /// Offset for the initial time namespace's `CLOCK_BOOTTIME`.
    boottime_offset: Option<TimeOffset>,
}

/// User namespace policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserOptions {
    /// Mapping mode to apply to the user namespace.
    mapping_mode: UserMappingMode,

    /// Whether to allow the creation of new user namespaces within the
    /// sandbox.
    disable_userns: bool,
}

/// User namespace policy.
#[derive(Clone, Debug, Eq, PartialEq)]
enum UserMappingMode {
    /// Maps parent uid/gid to the default.
    ///
    /// Does not attempt to map any other uid/gids. Works without
    /// newuidmap/newgidmap or systemd-nsresourced.
    Simple,
}

#[cfg(test)]
mod test {
    use super::*;

    use std::ptr;

    use super::super::{
        cgroups::{
            CgroupController, PidsController, Policy as CgroupsPolicy,
            Resource, /* SystemdState, */
        },
        mapping::{Mode, ProcHidepid, ProcSubset},
        path::{HostDirectory, HostFile},
    };

    #[test]
    fn simple_policy() {
        let bin_directory = HostDirectory::open(
            "/home/superwhiskers/documents/rust/layer-cake/result/bin",
        )
        .unwrap();
        let hosts_file =
            HostFile::open("/nix/store/9n0d1v9nli13hh4yrjxf6qkcrxws0ahv-hosts")
                .unwrap();
        let mappings = BTreeMap::from([
            (
                "/bin".try_into().unwrap(),
                Source::read_only_directory(bin_directory.as_borrowed()),
            ),
            (
                "/etc/hosts".try_into().unwrap(),
                Source::read_only_file(hosts_file.as_borrowed()),
            ),
            (
                "/proc".try_into().unwrap(),
                Source::proc(ProcHidepid::Ptraceable, ProcSubset::Pid),
            ),
            (
                "/etc".try_into().unwrap(),
                Source::tmpfs(None, Mode::RUSR | Mode::WUSR | Mode::XUSR),
            ),
        ]);

        let policy = Policy {
            mappings,
            /* seccomp: None, */
            namespaces: Namespaces {
                ipc: Namespace::Unshared(IpcOptions),
                pid: Namespace::Unshared(PidOptions),
                network: Namespace::Unshared(NetworkOptions::Isolate),
                uts: Namespace::Unshared(UtsOptions {
                    hostname: Some(b"host"),
                    domain: Some(b"domain"),
                }),
                time: Namespace::Unshared(TimeOptions {
                    monotonic_offset: Some(TimeOffset {
                        seconds: 67,
                        nanoseconds: 0,
                    }),
                    boottime_offset: None,
                }),
                user: UserOptions {
                    mapping_mode: UserMappingMode::Simple,
                    //disable_userns: true,
                    disable_userns: false,
                },
            },
            cgroups: Cgroups::new_null(CgroupsPolicy {
                cgroup: CgroupController {
                    is_threaded: false,
                    enable_psi_accounting: false,
                },
                cpu: None,
                memory: None,
                io: None,
                pids: Some(PidsController {
                    subtree_control: false,
                    max: Some(Resource::Value(10)),
                }),
            }),
            target_capabilities: CapabilitySet::SYS_ADMIN,
            file_descriptors: BTreeMap::new(),
            uid: None,
            gid: None,
            die_with_parent_thread: true,
            new_session: true,
        };

        //SAFETY: idc
        let (_, fd, cgroups_state) = unsafe {
            policy
                .clone_into(
                    || {
                        let _ = libc::execve(
                            c"/bin/sh".as_ptr(),
                            /*[
                                c"sh".as_ptr(),
                                c"-c".as_ptr(),
                                c"exit".as_ptr(),
                                ptr::null(),
                            ]
                            .as_ptr(),*/
                            [c"sh".as_ptr(), ptr::null()].as_ptr(),
                            [c"PATH=/bin".as_ptr(), ptr::null()]
                                .as_slice()
                                .as_ptr(),
                        );
                        panic!("{} failed", syscalls::last_errno());
                    },
                    (),
                    /* SystemdState::new().expect("idc"), */
                )
                .expect("unable to start a sandboxed process")
        };

        //FIXME: when [`WaitIdStatus`] has a debug impl
        let _ =
            syscalls::waitid(WaitFor::PidFd(fd.as_fd()), linux::WEXITED as i32)
                .expect("unable to wait on the sandboxed process");

        policy.cgroups.teardown(cgroups_state).expect(
            "unable to teardown the cgroups policy of the sandboxed process",
        );
    }
}
