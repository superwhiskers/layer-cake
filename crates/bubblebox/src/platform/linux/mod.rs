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
//TODO: permit privileged callers to bind mount whatever fds they have to
//      sidestep our unprivileged workarounds (w/ the consequence of greater ns
//      pressure)
//TODO: add lsm context setup. this is currently left out because implementing
//      it requires `lsm_set_self_attr` which uses `lsm_ctx` which is a
//      variable-sized struct due to the trailing inline array. this is
//      definitely feasible but annoying to implement
//
//      sources:
//      - https://docs.kernel.org/next/userspace-api/lsm.html
//      - https://lwn.net/Articles/919059/
//TODO: implement the following:
//      - timer slack normalization
//        - https://www.man7.org/linux/man-pages/man2/PR_SET_TIMERSLACK.2const.html
//      - transparent hugepage setting
//        - https://www.kernel.org/doc/html/latest/admin-guide/mm/transhuge.html
//      - speculation flags
//        - https://www.kernel.org/doc/html/latest/userspace-api/spec_ctrl.html
//        - of interest is force disable
//      - personality
//        - https://www.man7.org/linux/man-pages/man2/personality.2.html
//        - not very useful, only provides anything in the presence of a seccomp
//          filter
//TODO: when supervisor is implemented, `mseal(2)` on the supervisor would be a
//      good idea
//
//      see: https://docs.kernel.org/userspace-api/mseal.html
//TODO: reading pressure stall information via cgroups when enabled would be a
//      good idea
//
//      see: https://kernel.org/doc/html/latest/accounting/psi.html
//TODO: maybe providing the ability to change `PR_SET_DUMPABLE` would be useful
//      too. this has nothing to do with security, though
//
//      see: https://man7.org/linux/man-pages/man2/pr_set_dumpable.2const.html
//TODO: provide the ability to set the umask for the final sandbox. should be
//      simple

pub mod cgroups;
pub mod command;
pub mod errors;
pub mod mounts;
pub mod paths;
pub mod policy;
mod spawn;

//NOTE: re-export meowix so users don't need to depend upon it
pub use meowix;
