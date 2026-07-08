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
//TODO: add the option to constrain the lifetime of the process tree. this
//      would use the newly-introduced `CLONE_PIDFD_AUTOKILL` flag for `clone3`
//      to tie the guest process' lifetime to the lifetime of the pidfd we
//      return to the caller of `clone_into`. require the use of a pid namespace
//      for this to ensure the entire guest process tree is killed at once. this
//      would remove the race check using `ppoll(2)` and the pdeathsig setting
//      from the child setup. see https://lwn.net/Articles/1059673/ for more
//      details.
//TODO: determine how many of the values written to kernel setting filesystems
//      actually need newlines at the end, if any, and clean up those that don't

pub mod cgroups;
pub(crate) mod command;
pub mod errors;
pub mod mounts;
pub mod paths;
pub mod policy;
mod spawn;

#[cfg(test)]
mod test {
    use super::*;

    use linux_raw_sys::general as linux;
    use meowix::fd::AsFd;
    use std::{collections::HashMap, ptr};

    use crate::command::Command;
    use command::CommandInner;
    use meowix::{
        capabilities::CapabilitySet,
        mode::Mode,
        syscalls::{self, WaitFor},
    };
    use mounts::{Mount, ProcHidepid, ProcSubset};
    use paths::HostDirectory;

    #[test]
    fn dummy_test() {
        let bin = HostDirectory::open(
            "/home/superwhiskers/documents/rust/layer-cake/result/bin",
        )
        .unwrap();
        let bin_borrowed = bin.as_borrowed();
        let policy = policy::Policy::default()
            .mount_tree(|tree| {
                tree.mount(
                    Mount::read_only_directory(bin_borrowed),
                    "/bin".try_into().unwrap(),
                )
                .mount(
                    Mount::proc(ProcHidepid::Ptraceable, ProcSubset::Pid),
                    "/proc".try_into().unwrap(),
                )
                .mount(
                    Mount::tmpfs(None, Mode::RWXU),
                    "/etc".try_into().unwrap(),
                )
            })
            .unwrap()
            .set_target_capabilities(CapabilitySet::SYS_ADMIN)
            .fd_policy(|fd| fd.ignore(0).ignore(1).ignore(2))
            .unwrap();

        //FIXME: replace w/ builder
        let guest = policy
            .spawn(&Command {
                inner: CommandInner {
                    environment: HashMap::new(),
                    arguments: vec![c"sh".as_ptr(), ptr::null()],
                    path: c"/bin/sh".to_owned(),
                    working_directory: c"/etc".to_owned(),
                },
            })
            .unwrap();

        let result = guest.wait().unwrap();
        println!("exit: {result}");
        drop(guest);
    }
}
