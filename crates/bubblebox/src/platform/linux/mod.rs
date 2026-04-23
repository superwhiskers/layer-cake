// SPDX-License-Identifier: AGPL-3.0-only

//! Linux sandboxing primitives.
//!
//! This sandboxing backend requires Linux 7.1 or newer to work, due to the use
//! of [`MOVE_MOUNT_BENEATH` to swap out the root filesystem] in the mount
//! namespace created.
//!
//! TODO: details about namespaces, landlock, seccomp, mseal, cgroups, etc
//!
//! [`MOVE_MOUNT_BENEATH` to swap out the root filesystem]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ccfac16e0be52b674ac04fb5ba88c643f76ae0e1

//TODO: really clean up the module structure here. some of these files are
//      quite large and messy

pub(crate) mod cgroups;
pub mod mapping;
pub(crate) mod netlink;
pub mod normalization;
pub mod policy;
pub(crate) mod util;
