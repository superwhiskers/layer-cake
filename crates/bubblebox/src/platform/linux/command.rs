// SPDX-License-Identifier: AGPL-3.0-only

//! Implementations of the generic command and guest process structures.

//TODO: add better options for linux-specific code to pull cgroups fds, write
//      cstrings directly, etc GuestLinuxExt
//FIXME: attempt to remove the lifetime parameter from the child so that the
//       policy can be destroyed while the child is executing
//FIXME: builder and spawn support for environment, working directory + support
//       in bbx

use linux_raw_sys::general as linux;
use meowix::{
    fd::{AsFd, OwnedFd},
    ids::Pid,
    retry_on_interrupt,
    syscalls::{self, PollFd},
};
use std::{
    collections::HashMap,
    ffi,
    ffi::{CString, OsStr},
    fmt,
    os::unix::{ffi::OsStrExt, process::ExitStatusExt},
    process::ExitStatus,
    ptr,
};

use super::errors::{Command as CommandError, Error, ResultSyscallExt, Tag};

/// Platform implementation of the command structure.
#[derive(Debug)]
pub(crate) struct CommandInner {
    /// Environment to pass to the program.
    pub(super) environment: HashMap<CString, CString>,

    /// Arguments to pass to the program.
    pub(super) arguments: Vec<*const ffi::c_char>,

    /// Path of the executable within the sandbox environment.
    pub(super) program: CString,

    /// Working directory of the process within the sandbox.
    pub(super) working_directory: CString,
    //FIXME: add optional stdin, stdout, stderr
}

impl CommandInner {
    /// Construct a new command for launching the program at the path `program`
    /// within the sandbox.
    ///
    /// This has the following defaults:
    ///
    /// - No arguments to the program beyond its path.
    /// - Empty environment.
    /// - Working directory of `/`.
    ///
    /// # Errors
    ///
    /// This method errors if the provided [`OsStr`] was not a valid C string.
    pub fn new(program: impl AsRef<OsStr>) -> Result<Self, Error> {
        let program = CString::new(program.as_ref().as_bytes().to_owned())
            .map_err(Tag::tag_with::<CommandError>)?;
        Ok(Self {
            environment: HashMap::new(),
            arguments: vec![program.clone().into_raw(), ptr::null()],
            program,
            working_directory: c"/".to_owned(),
        })
    }

    /// Add an argument to the program.
    ///
    /// Only one may be passed per call.
    ///
    /// # Errors
    ///
    /// This method errors if the provided [`OsStr`] was not a valid C string.
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Result<Self, Error> {
        let arg = CString::new(arg.as_ref().as_bytes().to_owned())
            .map_err(Tag::tag_with::<CommandError>)?;
        self.arguments
            .insert(self.arguments.len() - 1, arg.into_raw());
        Ok(self)
    }

    /// Add multiple arguments to the program.
    ///
    /// # Errors
    ///
    /// This method errors if the provided [`OsStr`] was not a valid C string.
    pub fn args(
        mut self,
        args: impl IntoIterator<Item = impl AsRef<OsStr>>,
    ) -> Result<Self, Error> {
        for arg in args {
            self = self.arg(arg)?;
        }

        Ok(self)
    }

    //FIXME: add methods for the rest. unsure how to do arg stuff as the
    //       lifetime needs to be tied. probably a phantomdata or something to
    //       hold and unify the lifetime
}

impl Drop for CommandInner {
    fn drop(&mut self) {
        while let Some(arg) = self.arguments.pop() {
            if arg == ptr::null() {
                continue;
            }

            //SAFETY: we manually allocate these inside of `CommandInner::arg`
            //        and thus know we possess ownership of them
            drop(unsafe { CString::from_raw(arg as *mut _) });
        }
    }
}

/// Platform implementation of the guest process structure.
pub(crate) struct GuestInner<'a> {
    /// Pidfd of the init process in the sandbox.
    pub(super) pidfd: OwnedFd,

    /// Pid of the sandboxed process.
    pub(super) pid: Pid,

    /// Cgroups backend destructor.
    pub(super) cgroups_destructor:
        Option<Box<dyn FnOnce() -> Result<(), Error> + 'a>>,
    //TODO: hold an [`OwnedFd`] to the cgroups hierarchy and add a method to
    //      the backend trait that returns a `Option<(OwnedFd, Box<dyn FnOnce()
    //      -> Result<(), errors::Error>>)>` where the former is the fd to the
    //      cgroups hierarchy and the latter is the destructor
}

impl<'a> GuestInner<'a> {
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

impl fmt::Debug for GuestInner<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Guest").field(&self.pid).finish()
    }
}

impl Drop for GuestInner<'_> {
    fn drop(&mut self) {
        if let Some(cgroups_destructor) = self.cgroups_destructor.take() {
            //NOTE: we can't exactly error here, so we just run it and hope it
            //      worked. logging might be useful
            let _ignored = cgroups_destructor();
        }
    }
}
