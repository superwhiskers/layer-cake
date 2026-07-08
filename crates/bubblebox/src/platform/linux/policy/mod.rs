// SPDX-License-Identifier: AGPL-3.0-only

//! Sandbox policy implementation.

//TODO: add support for io_uring syscall denylists using the new api introduced
//      in kernel 7.0
//TODO: add rlimit support. modify cgroups documentation to reflect that there
//      would then be another way to enforce resource usage (but cgroups are
//      more powerful)
//TODO: add back die with parent thread to the policy once we've implemented
//      the new linux 7.1 clone flags

use meowix::{capabilities::CapabilitySet, syscalls, util::Cwd};
use std::ptr;

use super::{
    cgroups::{self, Cgroups, NullCgroups, OwnedFdCgroups},
    command::GuestInner,
    errors::Error,
    spawn::{self, SpawnAction},
};
use crate::command::{Command, Guest};
use errors::Policy as PolicyError;
use fd::FdPolicy;
use mounts::MountTree;
use namespace::Namespaces;

#[cfg(feature = "seccomp")]
use seccompiler::SeccompFilter;

#[cfg(feature = "systemd-cgroups")]
use super::cgroups::SystemdCgroups;

pub mod errors;
pub mod fd;
pub mod mounts;
pub mod namespace;

/// Sandbox policy builder.
#[derive(Clone, Debug)]
pub struct Policy<'a, CgroupsBackend> {
    /// Map of destinations to their mount source.
    pub(super) mount_tree: MountTree<'a>,

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
    pub fn spawn(&self, command: &Command) -> Result<Guest, Error> {
        //SAFETY: the only thing the callback does is change the working
        //        directory and return the spawn action. argv and envp
        //        are null-terminated due to our implementation of
        //        [`Command`]
        let (pid, pidfd, _cgroups) = unsafe {
            spawn::clone_into(
                self,
                move || {
                    syscalls::chdir(
                        command.inner.working_directory.as_c_str(),
                    )?;

                    Ok(SpawnAction::Exec {
                        //NOTE: there's no way to get an fd in the sandbox
                        //      prior to making it
                        dirfd: Cwd,
                        path: command.inner.path.as_c_str(),
                        //FIXME: actually pass all of these in
                        argv: &command.inner.arguments,
                        envp: [ptr::null()],
                        flags: 0,
                    })
                },
                (),
            )?
        };
        Ok(Guest {
            inner: GuestInner {
                pidfd,
                pid,
                //FIXME: move this to be part of the cgroups api
                cgroups_destructor: None,
            },
        })
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
}

impl<'a, CgroupsBackend> Policy<'a, CgroupsBackend>
where
    CgroupsBackend: cgroups::Backend,
{
    /// Modify the mount tree of the sandbox.
    ///
    /// # Errors
    ///
    /// This method errors if the edited mount tree is invalid.
    pub fn mount_tree(
        mut self,
        //TODO: should we provide a less costly interface which doesn't clone
        //      the internal state of the [`BTreeMap`]?
        configure: impl FnOnce(MountTree<'a>) -> MountTree<'a>,
    ) -> Result<Self, Error> {
        let new_mounts = configure(self.mount_tree.clone());
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
        //TODO: we should consider a less costly interface here too
        configure: impl FnOnce(FdPolicy<'a>) -> FdPolicy<'a>,
    ) -> Result<Self, Error> {
        let new_fd_policy = configure(self.file_descriptors.clone());
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
