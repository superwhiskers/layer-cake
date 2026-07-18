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

//TODO: implement overlayfs in the mount handling
//TODO: determine how many of the values written to kernel setting filesystems
//      actually need newlines at the end, if any, and clean up those that don't

pub mod cgroups;
pub(crate) mod command;
pub mod errors;
pub mod mounts;
pub mod paths;
pub mod policy;
mod spawn;

//NOTE: re-export meowix so users don't need to depend upon it
pub use meowix;
