// SPDX-License-Identifier: AGPL-3.0-only

//! Mount tree policy implementation.

use std::collections::BTreeMap;

use super::super::mounts::{Mount, MountInner};
use crate::paths::Guest;

//TODO: relax the restrictions to the following: a mount tree is valid if and
//      only if its application does not result in the mutation of any host bind
//      mounts. a consequence of this is that on a regular bind mount, all
//      further mountpoints must already exist. implementing overlayfs will make
//      this less strict, as bubblebox may create mountpoints on an upper layer
//TODO: after the above is implemented, we may implement special case handling
//      for `/` mounts

/// Validate the mount tree and return an updated count of the constituent host
/// mounts.
///
/// Currently, a mount tree is valid if and only if the following conditions
/// hold:
/// - No mount is underneath a non-synthetic mount.
///
/// This restriction may be relaxed in the future on an opt-in basis.
fn is_valid_mount_tree(mounts: &BTreeMap<Guest, Mount>) -> Option<usize> {
    let mut stack: Vec<(&Guest, bool)> = Vec::new();
    let mut host_mount_count = 0;

    for (destination, source) in mounts {
        if let MountInner::Overlay {
            lowerdirs,
            datadirs,
            upperdirs,
            ..
        } = &source.inner
        {
            host_mount_count += lowerdirs.len() + datadirs.len();
            if upperdirs.is_some() {
                //NOTE: account for needing to store a detached mount to the
                //      ancestor
                host_mount_count += 1;
            }
        }

        if let Some((current, is_synthetic)) = stack.last() {
            if destination.starts_with(current) {
                if !is_synthetic {
                    return None;
                }
            } else {
                while let Some((current, _)) = stack.pop()
                    && !destination.starts_with(current)
                {}
            }
        }

        stack.push((destination, source.is_synthetic()));
    }

    Some(host_mount_count)
}

/// View of a mount tree.
#[derive(Debug, Default)]
pub struct MountTree {
    /// Mount tree.
    ///
    /// Maps guest paths to mounts at their location.
    pub(crate) tree: BTreeMap<Guest, Mount>,

    /// Total number of host bind mounts required to construct the overlayfs.
    ///
    /// This is used to size a buffer containing them during mapping
    /// resolution.
    //NOTE: this feels like a bit of a hack but it's the best solution i've
    //      got that doesn't involve lots of extra work
    pub(crate) host_mount_count: usize,
}

impl MountTree {
    /// Creates an empty mount tree.
    pub fn empty() -> Self {
        Default::default()
    }

    /// Returns the number of mounts in this mount tree.
    pub fn size(&self) -> usize {
        self.tree.len()
    }

    /// Insert `mount` into the mount tree at `path`.
    pub fn mount(mut self, mount: Mount, path: Guest) -> Self {
        drop(self.tree.insert(path, mount));
        self
    }

    /// Remove `path` from the mount tree.
    pub fn unmount(mut self, path: Guest) -> Self {
        //TODO: would it be useful to return the old value
        drop(self.tree.remove(&path));
        self
    }

    /// Empty the mount tree.
    pub fn clear(mut self) -> Self {
        self.tree.clear();
        self
    }

    /// Check if the mount tree is valid and ensure invariants are met.
    pub fn is_valid(&mut self) -> bool {
        if let Some(host_mount_count) = is_valid_mount_tree(&self.tree) {
            self.host_mount_count = host_mount_count;
            return true;
        }
        false
    }
}
