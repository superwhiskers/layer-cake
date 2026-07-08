// SPDX-License-Identifier: AGPL-3.0-only

//! Implementations of the generic command and guest process structures.

//TODO: add better options for linux-specific code to pull cgroups fds, write
//      cstrings directly, etc GuestLinuxExt
//FIXME: add builder

use linux_raw_sys::general as linux;
use meowix::{
    fd::{AsFd, OwnedFd},
    ids::Pid,
    retry_on_interrupt,
    syscalls::{self, PollFd},
};
use std::{
    collections::HashMap, ffi, ffi::CString, fmt,
    os::unix::process::ExitStatusExt, process::ExitStatus,
};

use super::errors::{Command as CommandError, Error, ResultSyscallExt};

/// Platform implementation of the command structure.
#[derive(Debug)]
pub(crate) struct CommandInner {
    /// Environment to pass to the program.
    pub(super) environment: HashMap<CString, CString>,

    /// Arguments to pass to the program.
    pub(super) arguments: Vec<*const ffi::c_char>,

    /// Path of the executable within the sandbox environment.
    pub(super) path: CString,

    /// Working directory of the process within the sandbox.
    pub(super) working_directory: CString,
    //FIXME: add optional stdin, stdout, stderr
}

impl CommandInner {}

/// Platform implementation of the guest process structure.
pub(crate) struct GuestInner {
    /// Pidfd of the init process in the sandbox.
    pub(super) pidfd: OwnedFd,

    /// Pid of the sandboxed process.
    pub(super) pid: Pid,

    /// Cgroups backend destructor.
    pub(super) cgroups_destructor:
        Option<Box<dyn FnOnce() -> Result<(), Error>>>,
    //TODO: hold an [`OwnedFd`] to the cgroups hierarchy and add a method to
    //      the backend trait that returns a `Option<(OwnedFd, Box<dyn FnOnce()
    //      -> Result<(), errors::Error>>)>` where the former is the fd to the
    //      cgroups hierarchy and the latter is the destructor
}

impl GuestInner {
    /// Return the process identifier.
    pub(crate) fn id(&self) -> u32 {
        self.pid.into_raw() as _
    }

    /// Wait on the guest process to exit completely.
    pub(crate) fn wait(&self) -> Result<ExitStatus, Error> {
        let mut fds = [PollFd::new(self.pidfd.as_fd(), linux::POLLIN as i16)];
        let n_ready = retry_on_interrupt!({ syscalls::ppoll(&mut fds, None) })
            .wrap_error::<CommandError>()?;
        debug_assert_eq!(n_ready, 1);

        Ok(ExitStatus::from_raw(
            syscalls::pidfd_get_info(&self.pidfd)
                .wrap_error::<CommandError>()?
                .exit_code,
        ))
    }

    /// Attempt to capture the exit status of the guest process if it has
    /// already exited.
    pub(crate) fn try_wait(&self) -> Result<Option<ExitStatus>, Error> {
        let mut fds = [PollFd::new(self.pidfd.as_fd(), linux::POLLIN as i16)];
        if retry_on_interrupt!({
            syscalls::ppoll(
                &mut fds,
                Some(linux::__kernel_timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }),
            )
        })
        .wrap_error::<CommandError>()?
            == 0
        {
            return Ok(None);
        }

        Ok(Some(ExitStatus::from_raw(
            syscalls::pidfd_get_info(&self.pidfd)
                .wrap_error::<CommandError>()?
                .exit_code,
        )))
    }
}

impl fmt::Debug for GuestInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Guest").field(&self.pid).finish()
    }
}

impl Drop for GuestInner {
    fn drop(&mut self) {
        if let Some(cgroups_destructor) = self.cgroups_destructor.take() {
            //NOTE: we can't exactly error here, so we just run it and hope it
            //      worked. logging might be useful
            let _ignored = cgroups_destructor();
        }
    }
}
