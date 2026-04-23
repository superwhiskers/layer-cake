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
//TODO: use `FSMOUNT_NAMESPACE` instead of `MOVE_MOUNT_BENEATH` to swap root
//      in the sandbox
//TODO: add support for io_uring syscall denylists using the new api introduced
//      in kernel 7.0
//TODO: write an extension trait for rustix's `Errno` that allows you to wrap
//      the errno with a syscall name (stored in an enum) for provenance

use linux_raw_sys::general as linux_general;
use rkyv::{
    Archive,
    rancor::Failure,
    ser::{
        Serializer, allocator::SubAllocator, sharing::Unshare, writer::IoWriter,
    },
    util::Align,
};
use rustix::{
    event::{PollFd, PollFlags, Timespec},
    fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
    fs::{AtFlags, CWD, Gid, Mode, OFlags, ResolveFlags, StatxFlags, Uid},
    io::Errno,
    //NOTE: why is it exposed here only???
    io_uring::Signal,
    mount::{
        FsMountFlags, FsOpenFlags, MountAttrFlags, MountPropagationFlags,
        MoveMountFlags, UnmountFlags,
    },
    pipe::PipeFlags,
    process::{Pid, PidfdFlags, WaitId, WaitIdOptions},
    thread::{CapabilitySet, CapabilitySets, LinkNameSpaceType, UnshareFlags},
};
use seccompiler::SeccompFilter;
use std::{
    collections::BTreeMap,
    ffi,
    io::{self, Read, Write},
    mem::ManuallyDrop,
    panic,
};

use super::{
    cgroups::{self, Cgroups},
    mapping::{File, Source},
    netlink,
    util::{self, FdPolicy, FdReadWrite, ResolvedMount, TimeOffset},
};
use crate::{
    command::{Child, Command, Sandbox},
    errors::{ChildError, Error},
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
    seccomp: Option<SeccompFilter>,

    /// Namespaces.
    namespaces: Namespaces,

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
    /// - Return a `ChildError`.
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
        child_callback: impl FnOnce() -> Result<!, ChildError>,
        mut cgroups_state: CgroupsBackend::State,
    ) -> Result<(Pid, OwnedFd, CgroupsBackend::State), Error> {
        util::is_valid_fd_policy(&self.file_descriptors)
            .ok_or(Error::InvalidFdPolicy)?;
        util::is_valid_mapping_tree(&self.mappings)
            .ok_or(Error::InvalidMappings)?;

        let parent_pidfd = if self.die_with_parent_thread {
            Some(rustix::process::pidfd_open(
                rustix::process::getpid(),
                PidfdFlags::empty(),
            )?)
        } else {
            None
        };

        //NOTE: necessary invariant for unprivileged userns
        let host_uid = rustix::process::geteuid();
        let host_gid = rustix::process::getegid();

        // this needs to be allocated all the way up here because we can't
        // allocate once we `clone3(2)`.
        let resolved_mappings = Vec::with_capacity(self.mappings.len());

        let (host_pipe, guest_pipe) =
            rustix::pipe::pipe_with(PipeFlags::CLOEXEC)?;

        // these three are always unshared. see the documentation for
        // `Namespaces` for more details. the third is to ensure we are handed
        // a pidfd to the child process.
        let mut clone_flags = linux_general::CLONE_NEWNS
            | linux_general::CLONE_NEWUSER
            | linux_general::CLONE_PIDFD;

        if !self.namespaces.ipc.is_shared() {
            clone_flags |= linux_general::CLONE_NEWIPC;
        }

        if !self.namespaces.pid.is_shared() {
            clone_flags |= linux_general::CLONE_NEWPID;
        }

        if !self.namespaces.network.is_shared() {
            clone_flags |= linux_general::CLONE_NEWNET;
        }

        if !self.namespaces.uts.is_shared() {
            clone_flags |= linux_general::CLONE_NEWUTS;
        }

        let mut child_pidfd: ffi::c_int = -1;
        let mut clone_args = linux_general::clone_args {
            flags: clone_flags.into(),
            pidfd: <*mut _>::addr(&mut child_pidfd) as linux_general::__u64,
            child_tid: 0,
            parent_tid: 0,
            exit_signal: linux_general::SIGCHLD.into(),
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
            clone_args.cgroup = cgroup_fd?.as_raw_fd() as linux_general::__u64;
            clone_args.flags |= linux_general::CLONE_INTO_CGROUP;
        }

        //SAFETY: the safety documentation for this method applies here:
        // - the caller must only provide closures which it is safe to call in a
        //   child process after clone
        // - we don't do things unsafe to perform after clone in the child (it's
        //   not super well specified, but it's "like async-signal-safety")
        let child_pid = unsafe {
            libc::syscall(
                linux_general::__NR_clone3.into(),
                &clone_args,
                //NOTE: might be better to hardcode it to the size of the
                //      structure up to the fields we use
                size_of::<linux_general::clone_args>(),
            )
        };
        if child_pid == -1 {
            //NOTE: could probably provide better diagnostics here
            Err(io::Error::last_os_error())?;
        }

        let guest_pipe = guest_pipe.into_raw_fd();

        if child_pid != 0 {
            debug_assert!(
                child_pid > 0,
                "`child_pid` should be greater than zero",
            );

            //SAFETY: there are no error conditions which would cause the
            //        syscall to succeed but the pidfd to not be created
            let child_pidfd = unsafe { OwnedFd::from_raw_fd(child_pidfd) };

            //SAFETY: we want it to leak into the child but we also need to
            //        read from it and rely upon its closure in the child
            unsafe { rustix::io::close(guest_pipe) };
            let host_pipe = FdReadWrite::new(host_pipe);

            //NOTE: this must fit within an i32 by the documentation of
            //      `clone3(2)`
            //SAFETY: we just checked that it wasn't zero, which is the
            //        only contract this method requires. negative return
            //        values of `clone3(2)` other than `-1` are imposible by
            //        contract
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the return value of clone3(2) will fit within a pid"
            )]
            let child_pid =
                unsafe { Pid::from_raw_unchecked(child_pid as i32) };

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

                    let _pidfd_result = rustix::process::pidfd_send_signal(
                        child_pidfd.as_fd(),
                        Signal::KILL,
                    );
                    let _waitid_result = rustix::process::waitid(
                        WaitId::PidFd(child_pidfd.as_fd()),
                        WaitIdOptions::EXITED,
                    );
                    let _teardown_result = self.cgroups.teardown(cgroups_state);

                    Err(err)
                }
            };
        }

        //NOTE: this is where the child process begins

        let resolved_mappings = ManuallyDrop::new(resolved_mappings);

        //SAFETY: we're in the child, we own this fd now
        let guest_pipe =
            FdReadWrite::new(unsafe { OwnedFd::from_raw_fd(guest_pipe) });

        panic::always_abort();

        //SAFETY: by the preconditions of this method, this call is safe
        let Err(e) = self.guest_post_clone(
            child_callback,
            cgroups_state,
            parent_pidfd,
            resolved_mappings,
            host_uid,
            host_gid,
        );

        let mut serializer = Serializer::new(
            IoWriter::new(guest_pipe),
            SubAllocator::empty(),
            Unshare,
        );

        if rkyv::api::serialize_using::<_, Failure>(&e, &mut serializer)
            .is_err()
        {
            //NOTE: writing a single byte will still signal to the parent that
            //      an error occurred
            let mut guest_pipe = serializer.into_writer().into_inner();

            #[expect(
                clippy::expect_used,
                reason = "we have no other way of propagating errors in this path"
            )]
            util::check_if_incomplete(
                guest_pipe
                    .write(&[0xe])
                    .expect("unable to write a single byte to the error pipe"),
                1,
            )
            .expect("unable to write an error sentinel to the pipe");
        } else {
            //NOTE: ensure we close the writing end of the pipe
            drop(serializer);
        }

        //SAFETY: this is exactly how you call _exit
        unsafe { libc::_exit(-1) };
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

        //NOTE: we could read a fixed size here but we control the writer, so
        //      unless untrusted code ran in the callback (which should not
        //      happen), this is safe
        let mut potential_error = Align(Vec::new());
        let _ = host_pipe.read_to_end(&mut potential_error)?;

        if potential_error.is_empty() {
            return Ok(());
        }

        //NOTE: ensure the child doesn't become a zombie. we ignore the
        //      error here to avoid masking the child error
        let _ = rustix::process::waitid(
            WaitId::PidFd(child_pidfd.as_fd()),
            WaitIdOptions::EXITED,
        );

        let archived =
            rkyv::access::<<ChildError as Archive>::Archived, Failure>(
                &potential_error,
            )
            .map_err(|_| {
                ChildError::UnspecifiedError(potential_error.first().copied())
            })?;

        Err(
            rkyv::deserialize::<ChildError, rkyv::rancor::Error>(archived)?
                .into(),
        )
    }

    /// Helper method for `clone_into`.
    ///
    /// # Errors
    ///
    /// This method errors if the namespace setup fails.
    #[inline(always)]
    fn guest_post_clone<'b>(
        &'b self,
        child_callback: impl FnOnce() -> Result<!, ChildError>,
        cgroups_state: CgroupsBackend::State,
        parent_pidfd: Option<OwnedFd>,
        mut resolved_mappings: ManuallyDrop<Vec<ResolvedMount<'b>>>,
        host_uid: Uid,
        host_gid: Gid,
    ) -> Result<!, ChildError> {
        let guest_uid = self.uid.unwrap_or(host_uid);
        let guest_gid = self.gid.unwrap_or(host_gid);

        if let Some(parent_pidfd) = parent_pidfd {
            rustix::process::set_parent_process_death_signal(Some(
                Signal::KILL,
            ))?;

            let mut fds = [PollFd::new(&parent_pidfd, PollFlags::IN)];
            let timespec = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };

            //NOTE: this avoids a race where the parent process dies prior
            //      to us checking liveness
            if util::retry_on_interrupt!({
                rustix::event::poll(&mut fds, Some(&timespec))
            })? != 0
            {
                //SAFETY: this is exactly how you call _exit
                unsafe { libc::_exit(-1) };
            }
        }

        rustix::thread::set_no_new_privs(true)?;
        util::drop_bounding_set(self.target_capabilities)?;
        util::reset_signal_dispositions()?;

        self.cgroups.guest_post_clone_hook(cgroups_state)?;

        //NOTE: we always unshare the cgroup namespace, but we do it right
        //      here because if the cgroup was moved post-clone and we
        //      perform unshare pre-clone, then the sandbox would be
        //      aware of its place in the hierarchy to a degree
        //SAFETY: this isn't unsharing the file descriptors
        unsafe {
            rustix::thread::unshare_unsafe(UnshareFlags::NEWCGROUP)?;
        }

        let guest_proc_fs_fd =
            rustix::mount::fsopen("proc", FsOpenFlags::FSOPEN_CLOEXEC)?;

        rustix::mount::fsconfig_create_exclusive(&guest_proc_fs_fd)?;

        let guest_proc_fd = rustix::mount::fsmount(
            guest_proc_fs_fd,
            FsMountFlags::FSMOUNT_CLOEXEC,
            MountAttrFlags::MOUNT_ATTR_NOSUID
                | MountAttrFlags::MOUNT_ATTR_NOEXEC
                | MountAttrFlags::MOUNT_ATTR_NODEV,
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
            unsafe { rustix::thread::unshare_unsafe(UnshareFlags::NEWTIME) }?;

            util::write_timens_offsets(
                &guest_proc_fd,
                time.monotonic_offset,
                time.boottime_offset,
            )?;

            let timens_fd = util::retry_on_interrupt!({
                rustix::fs::openat2(
                    &guest_proc_fd,
                    "self/ns/time_for_children",
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                    //NOTE: we can't use beneath/in_root because those
                    //      disable magic link resolution
                    ResolveFlags::empty(),
                )
            })?;

            rustix::thread::move_into_link_name_space(
                timens_fd.as_fd(),
                Some(LinkNameSpaceType::Time),
            )?;
        }

        //NOTE: we want to ensure our bind mounts are not tampered with
        let old_umask = rustix::process::umask(Mode::empty());

        rustix::mount::mount_change(
            "/",
            MountPropagationFlags::REC | MountPropagationFlags::PRIVATE,
        )?;

        let host_root_fd = util::retry_on_interrupt!({
            rustix::fs::openat2(
                CWD,
                "/",
                OFlags::PATH | OFlags::CLOEXEC | OFlags::DIRECTORY,
                Mode::empty(),
                ResolveFlags::empty(),
            )
        })?;

        util::resolve_mappings(
            &host_root_fd,
            &self.mappings,
            &mut resolved_mappings,
        )?;

        let guest_root_fs_fd =
            rustix::mount::fsopen("tmpfs", FsOpenFlags::FSOPEN_CLOEXEC)?;

        //TODO: consider setting restrictions on the size of the root
        //      tmpfs

        rustix::mount::fsconfig_set_string(&guest_root_fs_fd, "mode", "755")?;

        rustix::mount::fsconfig_create_exclusive(&guest_root_fs_fd)?;

        let guest_root_fd = rustix::mount::fsmount(
            guest_root_fs_fd,
            FsMountFlags::FSMOUNT_CLOEXEC,
            MountAttrFlags::MOUNT_ATTR_NOSUID
                | MountAttrFlags::MOUNT_ATTR_NODEV,
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

                    match rustix::fs::statx(
                        &parent_fd,
                        file_name,
                        AtFlags::SYMLINK_NOFOLLOW,
                        StatxFlags::TYPE,
                    ) {
                        Ok(statx) => {
                            if u32::from(statx.stx_mode) & linux_general::S_IFMT
                                != linux_general::S_IFDIR
                            {
                                Err(ChildError::InvalidDirectoryMountPoint)?;
                            }
                        }
                        Err(Errno::NOENT) => {
                            rustix::fs::mkdirat(
                                &parent_fd,
                                file_name,
                                //NOTE: 0o755
                                Mode::RWXU
                                    | Mode::RGRP
                                    | Mode::XGRP
                                    | Mode::ROTH
                                    | Mode::XOTH,
                            )?;
                        }
                        Err(e) => Err(e)?,
                    }

                    rustix::mount::move_mount(
                        fd,
                        "",
                        &parent_fd,
                        file_name,
                        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
                    )?;
                }
                ResolvedMount::Fd {
                    fd, destination, ..
                } => {
                    let (parent_fd, file_name) =
                        util::open_parent_in_root(&guest_root_fd, destination)?;

                    match rustix::fs::statx(
                        &parent_fd,
                        file_name,
                        AtFlags::SYMLINK_NOFOLLOW,
                        StatxFlags::TYPE,
                    ) {
                        Ok(statx) => {
                            if u32::from(statx.stx_mode) & linux_general::S_IFMT
                                != linux_general::S_IFREG
                            {
                                Err(ChildError::InvalidRegularFileMountPoint)?;
                            }
                        }
                        Err(Errno::NOENT) => {
                            //NOTE: we only care about creating it
                            drop(util::retry_on_interrupt!({
                                rustix::fs::openat2(
                                    &parent_fd,
                                    file_name,
                                    OFlags::CREATE | OFlags::WRONLY,
                                    Mode::RUSR
                                        | Mode::WUSR
                                        | Mode::RGRP
                                        | Mode::ROTH,
                                    ResolveFlags::BENEATH,
                                )
                            })?);
                        }
                        Err(e) => Err(e)?,
                    }

                    rustix::mount::move_mount(
                        fd,
                        "",
                        &parent_fd,
                        file_name,
                        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
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

                    if !matches!(
                        rustix::fs::statx(
                            &parent_fd,
                            file_name,
                            AtFlags::SYMLINK_NOFOLLOW,
                            StatxFlags::empty(),
                        ),
                        Err(Errno::NOENT)
                    ) {
                        //TODO: relax this restriction by truncating the
                        //      existing file and chmod-ing it
                        Err(ChildError::DestinationExisted)?;
                    }

                    FdReadWrite::new(util::retry_on_interrupt!({
                        rustix::fs::openat2(
                            &parent_fd,
                            file_name,
                            OFlags::CREATE | OFlags::RDWR,
                            *permissions,
                            ResolveFlags::BENEATH,
                        )
                    })?)
                    .write_all(contents)?;
                }
                ResolvedMount::Directory {
                    owner,
                    permissions,
                    destination,
                } => {
                    let (parent_fd, file_name) =
                        util::open_parent_in_root(&guest_root_fd, destination)?;

                    if !matches!(
                        rustix::fs::statx(
                            &parent_fd,
                            file_name,
                            AtFlags::SYMLINK_NOFOLLOW,
                            StatxFlags::empty(),
                        ),
                        Err(Errno::NOENT)
                    ) {
                        //TODO: and relax this one
                        Err(ChildError::DestinationExisted)?;
                    }

                    rustix::fs::mkdirat(&parent_fd, file_name, *permissions)?;
                }
            }
        }

        let guest_root_mount_attr = linux_general::mount_attr {
            attr_set: (linux_general::MOUNT_ATTR_RDONLY
                | linux_general::MOUNT_ATTR_NOSUID
                | linux_general::MOUNT_ATTR_NODEV
                | linux_general::MOUNT_ATTR_NOEXEC
                | linux_general::MOUNT_ATTR_NOSYMFOLLOW)
                .into(),
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };

        //SAFETY: the arguments are as expected (TODO: make better)
        if unsafe {
            libc::syscall(
                linux_general::__NR_mount_setattr.into(),
                guest_root_fd.as_raw_fd(),
                c"".as_ptr(),
                linux_general::AT_EMPTY_PATH,
                &guest_root_mount_attr,
                size_of::<linux_general::mount_attr>(),
            )
        } != 0
        {
            Err::<(), _>(io::Error::last_os_error())?;
        }

        rustix::process::fchdir(&guest_root_fd)?;

        rustix::mount::move_mount(
            guest_root_fd,
            "",
            CWD,
            "/",
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH
                | MoveMountFlags::MOVE_MOUNT_BENEATH,
        )?;

        rustix::process::chroot(".")?;
        rustix::mount::unmount(".", UnmountFlags::DETACH)?;
        rustix::process::chdir("/")?;

        if let Namespace::Unshared(ref uts) = self.namespaces.uts {
            if let Some(ref hostname) = uts.hostname {
                rustix::system::sethostname(hostname.as_slice())?;
            }

            if let Some(ref domain) = uts.domain {
                rustix::system::setdomainname(domain.as_slice())?;
            }
        }

        if let Namespace::Unshared(ref network) = self.namespaces.network {
            netlink::setup_loopback()?;
        }

        let _ = rustix::process::umask(old_umask);

        if self.new_session {
            let _ = rustix::process::setsid()?;
        }

        if self.namespaces.user.disable_userns {
            let max_user_ns_fd = util::retry_on_interrupt!({
                rustix::fs::openat2(
                    &guest_proc_fd,
                    "sys/user/max_user_namespaces",
                    OFlags::WRONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::BENEATH,
                )
            })?;

            util::check_if_incomplete(
                util::retry_on_interrupt!({
                    rustix::io::write(&max_user_ns_fd, b"1\n")
                })?,
                2,
            )?;

            //SAFETY: we're not unsharing the file descriptor namespace so
            //        no fds are invalidated
            unsafe {
                rustix::thread::unshare_unsafe(UnshareFlags::NEWUSER)?;
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

        rustix::thread::set_capabilities(
            None,
            CapabilitySets {
                effective: CapabilitySet::empty(),
                permitted: self.target_capabilities,
                inheritable: self.target_capabilities,
            },
        )?;

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
pub struct Namespaces {
    ipc: Namespace<IpcOptions>,
    pid: Namespace<PidOptions>,
    network: Namespace<NetworkOptions>,
    uts: Namespace<UtsOptions>,
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
pub struct UtsOptions {
    /// Hostname to set with `sethostname(2)`.
    ///
    /// # Notes
    ///
    /// The kernel appears to see this as a set of arbitrary bytes. Userland
    /// applications may have expectations of this field. At a minimum, treat
    /// this field as if it were only containing alphanumerical characters as
    /// well as not starting with a period or a hyphen.
    hostname: Option<Vec<u8>>,

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
    domain: Option<Vec<u8>>,
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
            Resource, SystemdState,
        },
        mapping::{ProcHidepid, ProcSubset},
    };
    use crate::path::Host;

    #[test]
    fn simple_policy() {
        let mappings = BTreeMap::from([
            (
                "/bin".try_into().unwrap(),
                Source::read_only(
                    Host::new_using_fs("/home/superwhiskers/documents/rust/layer-cake/result/bin")
                        .unwrap(),
                    false,
                ),
            ),
            (
                "/proc".try_into().unwrap(),
                Source::proc(ProcHidepid::Ptraceable, ProcSubset::Pid),
            ),
            (
                "/amogus".try_into().unwrap(),
                Source::tmpfs(None, Mode::RUSR | Mode::WUSR | Mode::XUSR),
            ),
        ]);

        let policy = Policy {
            mappings,
            seccomp: None,
            namespaces: Namespaces {
                ipc: Namespace::Unshared(IpcOptions),
                pid: Namespace::Unshared(PidOptions),
                network: Namespace::Unshared(NetworkOptions::Isolate),
                uts: Namespace::Unshared(UtsOptions {
                    hostname: None,
                    domain: None,
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
            cgroups: Cgroups::new_systemd(CgroupsPolicy {
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
                        panic!("{} failed", io::Error::last_os_error());
                    },
                    SystemdState::new().expect("idc"),
                )
                .expect("unable to start a sandboxed process")
        };

        println!(
            "{:?}",
            rustix::process::waitid(
                WaitId::PidFd(fd.as_fd()),
                WaitIdOptions::EXITED,
            )
            .expect("unable to wait on the sandboxed process")
        );

        policy.cgroups.teardown(cgroups_state).expect(
            "unable to teardown the cgroups policy of the sandboxed process",
        );
    }
}
