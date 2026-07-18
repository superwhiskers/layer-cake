// SPDX-License-Identifier: AGPL-3.0-only

//! Mount tree policy implementation.

use std::collections::BTreeMap;

use super::super::mounts::Mount;
use crate::paths::Guest;

//TODO: relax the restrictions to the following: a mount tree is valid if and
//      only if its application does not result in the mutation of any host bind
//      mounts. a consequence of this is that on a regular bind mount, all
//      further mountpoints must already exist. implementing overlayfs will make
//      this less strict, as bubblebox may create mountpoints on an upper layer
//TODO: after the above is implemented, we may implement special case handling
//      for `/` mounts

/// Validate the mount tree.
///
/// Currently, a mount tree is valid if and only if the following conditions
/// hold:
/// - No mount is underneath a non-synthetic mount.
///
/// This restriction may be relaxed in the future on an opt-in basis.
fn is_valid_mount_tree(mounts: &BTreeMap<Guest, Mount>) -> bool {
    let mut stack: Vec<(&Guest, bool)> = Vec::new();

    for (destination, source) in mounts {
        if let Some((current, is_synthetic)) = stack.last() {
            if destination.starts_with(current) {
                if !is_synthetic {
                    return false;
                }
            } else {
                while let Some((current, _)) = stack.pop()
                    && !destination.starts_with(current)
                {}
            }
        }

        stack.push((destination, source.is_synthetic()));
    }

    true
}

/// View of a mount tree.
#[derive(Debug, Default)]
pub struct MountTree(pub(in super::super) BTreeMap<Guest, Mount>);

impl MountTree {
    /// Creates an empty mount tree.
    pub fn empty() -> Self {
        Self(BTreeMap::new())
    }

    /// Insert `mount` into the mount tree at `path`.
    pub fn mount(mut self, mount: Mount, path: Guest) -> Self {
        drop(self.0.insert(path, mount));
        self
    }

    /// Remove `path` from the mount tree.
    pub fn unmount(mut self, path: Guest) -> Self {
        //TODO: would it be useful to return the old value
        drop(self.0.remove(&path));
        self
    }

    /// Empty the mount tree.
    pub fn clear(mut self) -> Self {
        self.0.clear();
        self
    }

    /// Check if the mount tree is valid.
    pub fn is_valid(&self) -> bool {
        is_valid_mount_tree(&self.0)
    }
}
