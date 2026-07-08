// SPDX-License-Identifier: AGPL-3.0-only

//! Owned file descriptor backend for cgroups acquisition.

use linux_raw_sys::general as linux;
use meowix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    mode::Mode,
    retry_on_interrupt, syscalls,
};

use super::{
    super::spawn::errors::PreSpawn as PreSpawnError, Backend, Cgroups,
    policy::Policy,
};

/// [`Cgroups`] instantiated from an [`OwnedFd`] representing a directory in the
/// host's `cgroups(7)` hierarchy.
#[derive(Clone, Debug, Default)]
pub struct OwnedFdCgroups;

impl Cgroups<OwnedFdCgroups> {
    /// Create a new cgroups hierarchy using the owned fd backend.
    pub fn new_fd() -> Self {
        Self::default()
    }
}

/// State for the owned file descriptor backend.
#[derive(Debug)]
pub struct OwnedFdState {
    /// The file descriptor representing the cgroup to which settings are
    /// written.
    settings_fd: OwnedFd,

    /// The file descriptor representing the cgroup in which the child process
    /// is spawned.
    child_fd: OwnedFd,
}

impl OwnedFdState {
    /// Takes ownership and consumes a cgroups hierarchy.
    ///
    /// The file descriptor provided for state must refer to a directory in the
    /// cgroups hierarchy which is writeable by the process.
    ///
    /// This part of the cgroups hierarchy will be used to write the cgroups
    /// configuration to. bubblebox will create a nested cgroup in which the
    /// child process will be spawned.
    ///
    /// # Errors
    ///
    /// This method errors if creating and opening the nested cgroup for the
    /// child process fails.
    pub fn new(settings_fd: OwnedFd) -> Result<Self, PreSpawnError> {
        syscalls::mkdirat(&settings_fd, c"bubblebox-child", Mode::RWXU.bits())?;

        //NOTE: technically someone could race us here but idk what we'd really
        //      be able to do about it

        let child_fd = retry_on_interrupt!({
            syscalls::openat2(
                &settings_fd,
                c"bubblebox-child",
                linux::open_how {
                    flags: (linux::O_PATH
                        | linux::O_CLOEXEC
                        | linux::O_DIRECTORY) as u64,
                    mode: 0,
                    resolve: (linux::RESOLVE_BENEATH
                        | linux::RESOLVE_NO_MAGICLINKS
                        | linux::RESOLVE_NO_SYMLINKS)
                        as u64,
                },
            )
        })?;

        Ok(Self {
            settings_fd,
            child_fd,
        })
    }
}

//SAFETY: we don't use [`Backend::guest_post_clone_hook`]
unsafe impl Backend for OwnedFdCgroups {
    type State = OwnedFdState;

    fn clone_args_cgroup<'a>(
        &self,
        policy: &Policy,
        state: &'a Self::State,
    ) -> Option<Result<BorrowedFd<'a>, PreSpawnError>> {
        if let Err(e) = policy.apply_to_cgroup(state.settings_fd.as_fd()) {
            return Some(Err(e.into()));
        }
        Some(Ok(state.child_fd.as_fd()))
    }

    fn as_cgroup_fd<'a>(
        &self,
        state: &'a Self::State,
    ) -> Option<BorrowedFd<'a>> {
        Some(state.settings_fd.as_fd())
    }
}
