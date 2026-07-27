// SPDX-License-Identifier: AGPL-3.0-only

//! Sandbox policy implementation.

//TODO: add support for io_uring syscall denylists using the new api introduced
//      in kernel 7.0
//TODO: add rlimit support. modify cgroups documentation to reflect that there
//      would then be another way to enforce resource usage (but cgroups are
//      more powerful)
//TODO: try to get `Clone` back on here somehow
//TODO: try to make the builder use `&mut self` instead of `self`. it isn't
//      super important right now, though

use meowix::{
    capabilities::CapabilitySet,
    syscalls,
    util::{Cwd, PATH_MAX},
};
use std::{ptr, slice};

use super::{
    cgroups::{self, Cgroups, NullCgroups, OwnedFdCgroups},
    command::GuestInner,
    errors::Error,
    spawn::{self, SpawnAction, errors::PostSpawnGuest as PostSpawnGuestError},
};
use crate::command::{Command, Guest};
use errors::Policy as PolicyError;
use fd::FdPolicy;
use mounts::MountTree;
use namespace::Namespaces;

#[cfg(feature = "seccomp")]
use seccompiler::SeccompFilter;

#[cfg(feature = "systemd-cgroups")]
use super::cgroups::{SystemdCgroups, SystemdState};

pub mod errors;
pub mod fd;
pub mod mounts;
pub mod namespace;

/// Sandbox policy builder.
#[derive(Debug)]
pub struct Policy<'a, CgroupsBackend> {
    /// Map of destinations to their mount source.
    pub(super) mount_tree: MountTree,

    /// Namespace configuration.
    pub(super) namespaces: Namespaces<'a>,

    /// Cgroups policy.
    pub(super) cgroups: Cgroups<CgroupsBackend>,

    /// Capability set of the final environment.
    ///
    /// By default, none are passed through.
    pub(super) target_capabilities: CapabilitySet,

    /// File descriptor policy.
    pub(super) file_descriptors: FdPolicy<'a>,

    /// Whether to create a new session using `setsid(2)`.
    pub(super) new_session: bool,

    /// Seccomp policy.
    //TODO: make this not have a hard dependency upon seccompiler to work
    #[cfg(feature = "seccomp")]
    pub(super) seccomp: Option<SeccompFilter>,
}

impl<'a, CgroupsBackend> Default for Policy<'a, CgroupsBackend>
where
    CgroupsBackend: Default,
{
    fn default() -> Self {
        Self {
            mount_tree: Default::default(),
            namespaces: Default::default(),
            cgroups: Default::default(),
            target_capabilities: Default::default(),
            file_descriptors: Default::default(),
            new_session: true,
            //FIXME: provide a strict default policy
            #[cfg(feature = "seccomp")]
            seccomp: None,
        }
    }
}

impl<'a> Policy<'a, NullCgroups> {
    /// Don't create a cgroups hierarchy for the sandbox.
    ///
    /// # Warning
    ///
    /// This has the effect of not enforcing any restrictions on resource usage.
    /// This should not be used for potentially hostile programs. Do not use
    /// this if the cgroups policy represents a security boundary for the
    /// application. It will not be enforced.
    pub fn null_cgroups_unenforced(mut self) -> Self {
        self.cgroups = Cgroups::null_unenforced();
        self
    }

    /// Executes the given [`Command`], sandboxed according to this policy.
    ///
    /// # Errors
    ///
    /// This method errors if setting up the sandbox fails.
    pub fn spawn(&self, command: &Command) -> Result<Guest<'_>, Error> {
        self.spawn_with(command, ())
    }
}

impl<'a> Policy<'a, OwnedFdCgroups> {
    //TODO: relax the "ownership" of the hierarchy by bubblebox.

    /// Create a cgroups hierarchy using the owned file descriptor backend.
    ///
    /// This requires the caller to have access to a cgroups subtree that they
    /// may pass a path file descriptor to.
    ///
    /// # Warning
    ///
    /// ## Ownership
    ///
    /// The subtree represented by the path file descriptor given to bubblebox
    /// is owned by bubblebox upon transfer. Do not reuse this subtree upon
    /// giving it to bubblebox. Do not modify the subtree externally upon giving
    /// it to bubblebox.
    ///
    /// ## Controllers
    ///
    /// Controllers requested by the caller's specified cgroups policy must be
    /// provided to the hierarchy given to bubblebox by the caller. Bubblebox
    /// will not make any changes to the hierarchy outside the scope of the
    /// hierarchy delegated to it by the caller.
    ///
    /// Provisioning of controllers may be done through the
    /// `cgroup.subtree_control` file in the cgroup above the one given to
    /// bubblebox. See the [Linux kernel documentation] for more details.
    ///
    /// [Linux kernel documentation]: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#controlling-controllers
    pub fn fd_cgroups(
        mut self,
        configure: impl FnOnce(Cgroups<OwnedFdCgroups>) -> Cgroups<OwnedFdCgroups>,
    ) -> Self {
        self.cgroups = configure(Cgroups::new_fd());
        self
    }
}

#[cfg(feature = "systemd-cgroups")]
impl<'a> Policy<'a, SystemdCgroups> {
    /// Create a cgroups hierarchy using the systemd backend.
    ///
    /// This requires the running system to have [systemd] as pid 1.
    pub fn systemd_cgroups(
        mut self,
        configure: impl FnOnce(Cgroups<SystemdCgroups>) -> Cgroups<SystemdCgroups>,
    ) -> Self {
        self.cgroups = configure(Cgroups::new_systemd());
        self
    }

    /// Executes the given [`Command`], sandboxed according to this policy.
    ///
    /// # Errors
    ///
    /// This method errors if setting up the sandbox fails.
    pub fn spawn(&self, command: &Command) -> Result<Guest<'_>, Error> {
        self.spawn_with(command, SystemdState::new()?)
    }
}

impl<'a, CgroupsBackend> Policy<'a, CgroupsBackend>
where
    CgroupsBackend: cgroups::Backend,
{
    /// Executes the given [`Command`], sandboxed according to this policy.
    ///
    /// # Errors
    ///
    /// This method errors if setting up the sandbox fails.
    fn spawn_with(
        &self,
        command: &Command,
        cgroups_state: CgroupsBackend::State,
    ) -> Result<Guest<'_>, Error> {
        let mut prepared_envs =
            Vec::with_capacity(command.inner.environment.len() + 1);

        for mapping in command.inner.environment.values() {
            prepared_envs.push(mapping.as_ptr());
        }
        prepared_envs.push(ptr::null());

        //TODO: add wrapper that removes the need to do this slice raw parts
        //      conversion. lying about the 'static lifetime of the slice is a
        //      little unclean
        let (envs, len) = (prepared_envs.as_ptr(), prepared_envs.len());

        //SAFETY: the only thing the callback does is change the working
        //        directory and return the spawn action. argv and envp
        //        are null-terminated due to our implementation of
        //        [`Command`]
        let (pid, pidfd, final_cgroups_state) = unsafe {
            spawn::clone_into(
                self,
                move || {
                    if let Some(ref working_directory) =
                        command.inner.working_directory
                    {
                        working_directory
                            .inner
                            .with_c_str::<{ PATH_MAX }, _, PostSpawnGuestError>(
                                |working_directory| {
                                    syscalls::chdir(working_directory)?;
                                    Ok(())
                                },
                            )?;
                    }

                    Ok(SpawnAction::Exec {
                        //NOTE: there's no way to get an fd in the sandbox
                        //      prior to making it
                        dirfd: Cwd,
                        path: command.inner.program.as_c_str(),
                        argv: &command.inner.arguments,
                        //SAFETY: the fork ensures the environment hashmap
                        //        lives for the duration of the guest pre-exec
                        envp: slice::from_raw_parts::<'static, _>(envs, len),
                        flags: 0,
                    })
                },
                cgroups_state,
            )?
        };

        Ok(Guest {
            inner: GuestInner {
                pidfd,
                pid,
                //FIXME: move this to be part of the cgroups api
                cgroups_destructor: Some(Box::new(|| {
                    Ok(self.cgroups.teardown(final_cgroups_state)?)
                })),
            },
        })
    }

    /// Modify the mount tree of the sandbox.
    ///
    /// # Errors
    ///
    /// This method errors if the edited mount tree is invalid.
    pub fn mount_tree(
        mut self,
        configure: impl FnOnce(MountTree) -> MountTree,
    ) -> Result<Self, Error> {
        let new_mounts = configure(self.mount_tree);
        new_mounts
            .is_valid()
            .ok_or(PolicyError::InvalidMountPolicy)?;
        self.mount_tree = new_mounts;
        Ok(self)
    }

    /// Modify the namespace configuration of the sandbox.
    pub fn namespace(
        mut self,
        configure: impl FnOnce(Namespaces<'a>) -> Namespaces<'a>,
    ) -> Self {
        self.namespaces = configure(self.namespaces);
        self
    }

    /// Set the target capability set of the sandbox.
    pub fn set_target_capabilities(
        mut self,
        target_capabilities: CapabilitySet,
    ) -> Self {
        self.target_capabilities = target_capabilities;
        self
    }

    /// Clear the target capability set of the sandbox.
    pub fn clear_target_capabilities(mut self) -> Self {
        self.target_capabilities = CapabilitySet::empty();
        self
    }

    /// Modify the file descriptor policy of the sandbox.
    ///
    /// # Errors
    ///
    /// This method errors if the edited file descriptor policy is invalid.
    pub fn fd_policy(
        mut self,
        configure: impl FnOnce(FdPolicy<'a>) -> FdPolicy<'a>,
    ) -> Result<Self, Error> {
        let new_fd_policy = configure(self.file_descriptors);
        new_fd_policy
            .is_valid()
            .ok_or(PolicyError::InvalidFdPolicy)?;
        self.file_descriptors = new_fd_policy;
        Ok(self)
    }

    /// Whether to create a new session using `setsid(2)` during sandbox
    /// initialization.
    pub fn new_session(mut self, new_session: bool) -> Self {
        self.new_session = new_session;
        self
    }

    //TODO: seccomp configuration needs to be added
}
