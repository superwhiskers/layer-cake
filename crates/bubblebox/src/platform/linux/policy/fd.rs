// SPDX-License-Identifier: AGPL-3.0-only

//! File descriptor policy implementation.

use meowix::fd::{AsRawFd, BorrowedFd, RawFd};
use std::collections::{BTreeMap, HashSet};

/// Action to take on a file descriptor.
///
/// This enumeration specifies actions other than closing the file descriptor.
/// File descriptors are marked close-on-exec if no policy is specified.
#[derive(Clone, Debug)]
pub(in super::super) enum Action<'a> {
    /// Leave the specified file descriptor alone.
    ///
    /// This does not clear the close-on-exec flag of the specified file
    /// descriptor if it is set. It is the responsibility of the caller to
    /// ensure this is performed.
    Ignore,

    /// Map this file descriptor to the specified file descriptor with
    /// `dup3(2)`.
    Map(BorrowedFd<'a>),
}

/// Validate the file descriptor policy.
///
/// Currently, a file descriptor policy is valid if and only if the following
/// conditions hold:
/// - No file descriptor which is the source of a mapped file descriptor is also
///   mapped itself.
/// - No file descriptor is mapped to itself.
/// - No file descriptor value is negative.
pub(in super::super) fn is_valid_fd_policy(
    policy_map: &BTreeMap<RawFd, Action<'_>>,
) -> bool {
    let sources = policy_map
        .values()
        .filter_map(|policy| {
            if let Action::Map(source_fd) = policy {
                Some(source_fd.as_raw_fd())
            } else {
                None
            }
        })
        .collect::<HashSet<_>>();

    for fd in policy_map.keys() {
        if sources.contains(fd) || *fd < 0 {
            return false;
        }
    }

    true
}

/// File descriptor policy.
///
/// File descriptors are closed by default. This structure is used to specify
/// actions to take on file descriptors if the caller wishes to do something
/// else.
#[derive(Clone, Debug, Default)]
pub struct FdPolicy<'a>(pub(in super::super) BTreeMap<RawFd, Action<'a>>);

impl<'a> FdPolicy<'a> {
    /// Create an empty file descriptor policy.
    pub fn empty() -> Self {
        Self(BTreeMap::new())
    }

    /// Ignore the specified file descriptor.
    ///
    /// This does not clear the close-on-exec flag of the specified file
    /// descriptor if it is set. It is the responsibility of the caller to
    /// ensure this is performed.
    pub fn ignore(mut self, fd: RawFd) -> Self {
        drop(self.0.insert(fd, Action::Ignore));
        self
    }

    /// Map the given file descriptor to the specified file descriptor.
    pub fn map(mut self, from: BorrowedFd<'a>, to: RawFd) -> Self {
        drop(self.0.insert(to, Action::Map(from)));
        self
    }

    /// Remove any mapping for the specified file descriptor.
    ///
    /// This has the effect of closing the file descriptor upon executing the
    /// guest process, if no later action is specified.
    pub fn close(mut self, fd: RawFd) -> Self {
        let _ = self.0.remove(&fd);
        self
    }

    /// Clear the file descriptor policy.
    ///
    /// This means all file descriptors will be closed upon executing the guest
    /// process.
    pub fn clear(mut self) -> Self {
        self.0.clear();
        self
    }

    /// Check if the file descriptor policy is valid.
    pub fn is_valid(&self) -> bool {
        is_valid_fd_policy(&self.0)
    }
}
