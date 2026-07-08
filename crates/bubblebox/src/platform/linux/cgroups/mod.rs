// SPDX-License-Identifier: AGPL-3.0-only

//! Primitives for working with `cgroups(7)`.
//!
//! This module implements two primary things. First, the acquisition of
//! cgroups. This may be either through the creation of a transient [systemd]
//! unit using D-Bus, or through the caller passing in a file descriptor
//! pointing to an owned cgroups hierarchy. Second, this module implements the
//! writing of an initial configuration to the owned cgroups hierarchy once the
//! child process is spawned within it.
//!
//! In the future, continuous monitoring of read-only attributes on an owned
//! cgroups hierarchy and reconfiguration may be added.
//!
//! [systemd]: https://systemd.io

//TODO: look into talking to elogind to acquire a cgroups instance, if this
//      would work at all
//TODO: system scoped cgroups on systemd? this could be useful but also
//      requires privileges. may allow us access to more controllers
//TODO: consider making the backend a trait object. the primary difficulty here
//      is dealing with the state
//TODO: consider using a name other than `bubblebox-child` for the cgroup. i.e.
//      use uuid like we do in the systemd backend for the wrapper cgroup

//TODO: temporary
#![allow(missing_copy_implementations)]

use meowix::{fd::BorrowedFd, ids::Pid};

use super::spawn::errors::{
    PostSpawnGuest as PostSpawnGuestError, PostSpawnHost as PostSpawnHostError,
    PreSpawn as PreSpawnError,
};
use policy::Policy;

mod null;
mod owned;
pub mod policy;

#[cfg(feature = "systemd-cgroups")]
mod systemd;

pub use null::*;
pub use owned::*;

#[cfg(feature = "systemd-cgroups")]
pub use systemd::*;

/// Representation of an owned cgroups hierarchy.
#[derive(Clone, Debug, Default)]
pub struct Cgroups<T> {
    /// Source of the cgroups hierarchy.
    inner: T,

    /// Cgroup policy applied at creation.
    policy: Policy,
}

impl<T> Cgroups<T>
where
    T: Backend,
{
    /// Modify the policy to be used on the cgroup the sandbox operates within.
    pub fn policy(mut self, configure: impl FnOnce(Policy) -> Policy) -> Self {
        self.policy = configure(self.policy);
        self
    }

    //TODO: add methods for working w/ cgroups

    /// Returns a file descriptor representing the cgroup to spawn the sandboxed
    /// process in.
    ///
    /// If provided, `CLONE_INTO_CGROUP` is added to the flags.
    ///
    /// # Warning
    ///
    /// This must be distinct from the cgroup to which settings are written, as
    /// if the sandboxed process is granted `CAP_SYS_ADMIN`, then it would
    /// be able to mount and write to the cgroups filesystem.
    pub fn clone_args_cgroup<'a>(
        &self,
        state: &'a T::State,
    ) -> Option<Result<BorrowedFd<'a>, PreSpawnError>> {
        self.inner.clone_args_cgroup(&self.policy, state)
    }

    /// Hook executed shortly after the `clone3(2)` call in the host process.
    ///
    /// # Errors
    ///
    /// This method errors if the [`Backend`] implementation errors.
    pub fn host_post_clone_hook(
        &self,
        state: &mut T::State,
        guest_pid: Pid,
    ) -> Result<(), PostSpawnHostError> {
        self.inner
            .host_post_clone_hook(&self.policy, state, guest_pid)
    }

    /// Hook executed shortly after the `clone3(2)` call in the guest process.
    ///
    /// # Errors
    ///
    /// This method errors if the [`Backend`] implementation errors.
    pub fn guest_post_clone_hook(
        &self,
        state: T::State,
    ) -> Result<(), PostSpawnGuestError> {
        self.inner.guest_post_clone_hook(&self.policy, state)
    }

    /// Returns a file descriptor representing the cgroup to write resource
    /// limits and other configuration options to.
    ///
    /// # Warning
    ///
    /// This must be distinct from the cgroup to which the sandboxed process is
    /// spawned in. If the sandboxed process is granted `CAP_SYS_ADMIN` and the
    /// two are the same cgroup, then it would be able to mount and write to the
    /// cgroups filesystem.
    pub fn as_cgroup_fd<'a>(
        &self,
        state: &'a T::State,
    ) -> Option<BorrowedFd<'a>> {
        self.inner.as_cgroup_fd(state)
    }

    /// Performs cleanup operations necessary for the backend.
    pub fn teardown(&self, state: T::State) -> Result<(), PostSpawnHostError> {
        self.inner.teardown(state)
    }
}

/// A representation of a `cgroups(7)` hierarchy and hooks to install a child
/// process into the cgroup.
///
/// This is implemented by hooking into parts of the setup process during
/// the spawn process. This trait intends to make working with cgroups (v2)
/// uniform, while abstracting over life cycle management which may be different
/// across backends.
///
/// # Safety
///
/// The implementation of [`Backend::guest_post_clone_hook`] must not perform
/// operations that are invalid in a child process created from a potentially
/// multithreaded parent. Prefer direct syscalls.
///
/// [`Backend::State`] must also have a [`Drop`] implementation safe to run
/// post-`clone3(2)`.
pub unsafe trait Backend {
    /// State required for this cgroups backend to acquire a hierarchy.
    type State;

    /// Returns a file descriptor representing the cgroup to spawn the sandboxed
    /// process in.
    ///
    /// If provided, `CLONE_INTO_CGROUP` is added to the flags.
    ///
    /// # Warning
    ///
    /// This must be distinct from the cgroup to which settings are written, as
    /// if the sandboxed process is granted `CAP_SYS_ADMIN`, then it would
    /// be able to mount and write to the cgroups filesystem.
    fn clone_args_cgroup<'a>(
        &self,
        _policy: &Policy,
        _state: &'a Self::State,
    ) -> Option<Result<BorrowedFd<'a>, PreSpawnError>> {
        None
    }

    /// Hook executed shortly after the `clone3(2)` call in the host process.
    fn host_post_clone_hook(
        &self,
        _policy: &Policy,
        _state: &mut Self::State,
        _guest_pid: Pid,
    ) -> Result<(), PostSpawnHostError> {
        Ok(())
    }

    /// Hook executed shortly after the `clone3(2)` call in the guest process.
    fn guest_post_clone_hook(
        &self,
        _policy: &Policy,
        _state: Self::State,
    ) -> Result<(), PostSpawnGuestError> {
        Ok(())
    }

    /// Returns a file descriptor representing the cgroup to write resource
    /// limits and other configuration options to.
    ///
    /// # Warning
    ///
    /// This must be distinct from the cgroup to which the sandboxed process is
    /// spawned in. If the sandboxed process is granted `CAP_SYS_ADMIN` and the
    /// two are the same cgroup, then it would be able to mount and write to the
    /// cgroups filesystem.
    fn as_cgroup_fd<'a>(
        &self,
        _state: &'a Self::State,
    ) -> Option<BorrowedFd<'a>> {
        None
    }

    /// Performs cleanup operations necessary for the backend.
    fn teardown(&self, _state: Self::State) -> Result<(), PostSpawnHostError> {
        Ok(())
    }
}
