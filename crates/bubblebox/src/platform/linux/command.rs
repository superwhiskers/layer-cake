// SPDX-License-Identifier: AGPL-3.0-only

//! Implementations of the generic command and guest process structures.

//TODO: add better options for linux-specific code to pull cgroups fds, write
//      cstrings directly, etc GuestLinuxExt
//FIXME: attempt to remove the lifetime parameter from the child so that the
//       policy can be destroyed while the child is executing

use linux_raw_sys::general as linux;
use meowix::{
    errno::Errno,
    fd::{AsFd, OwnedFd},
    ids::Pid,
    retry_on_interrupt,
    syscalls::{self, PollFd},
};
use std::{
    collections::HashMap,
    ffi,
    ffi::{CString, OsStr, OsString},
    fmt, hint, mem,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        process::ExitStatusExt,
    },
    process::ExitStatus,
    ptr,
};

use super::{
    errors::{
        Command as CommandError, Error,
        GuestTermination as GuestTerminationError, ResultSyscallExt, Tag,
    },
    spawn::errors::PostSpawnHost,
};
use crate::{
    command::Command, errors::Error as CrateError, paths::Guest, sealed::Sealed,
};

/// Platform implementation of the command structure.
#[derive(Debug)]
pub(crate) struct CommandInner {
    /// Environment to pass to the program.
    ///
    /// This is not a mapping of environment variables to values. This is a
    /// mapping of environment variables to prepared `ENV=value` strings.
    pub(super) environment: HashMap<OsString, CString>,

    /// Arguments to pass to the program.
    ///
    /// This is stored as raw pointers to C strings as [`CString`] is not
    /// guaranteed to be equivalent to `*const ffi::c_char`, and `execveat(2)`
    /// expects the latter.
    pub(super) arguments: Vec<*const ffi::c_char>,

    /// Path of the executable within the sandbox environment.
    pub(super) program: CString,

    /// Working directory of the process within the sandbox.
    pub(super) working_directory: Option<Guest>,
}

impl CommandInner {
    /// Construct a new command for launching the guest process at the path
    /// `program` within the sandbox.
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
    pub(crate) fn new(program: impl AsRef<OsStr>) -> Result<Self, Error> {
        let program = CString::new(program.as_ref().as_bytes().to_owned())
            .map_err(Tag::tag_with::<CommandError>)?;
        Ok(Self {
            environment: HashMap::new(),
            arguments: vec![program.clone().into_raw(), ptr::null()],
            program,
            working_directory: None,
        })
    }

    /// Set the first argument given to the program to something other than the
    /// executable's path.
    ///
    /// # Errors
    ///
    /// This method erors if the provided [`OsStr`] was not a valid C string.
    pub(crate) fn arg0(
        mut self,
        arg: impl AsRef<OsStr>,
    ) -> Result<Self, Error> {
        let mut arg = CString::new(arg.as_ref().as_bytes().to_owned())
            .map_err(Tag::tag_with::<CommandError>)?
            .into_raw() as *const _;

        //NOTE: this can't panic so we don't need to worry about unintentional
        //      unwinding here and leaking the raw c string we create above
        mem::swap(&mut self.arguments[0], &mut arg);

        //SAFETY: these are guaranteed to be valid by invariants on the
        //        structure
        drop(unsafe { CString::from_raw(arg as *mut _) });

        Ok(self)
    }

    /// Add an argument to the guest process.
    ///
    /// Only one may be passed per call.
    ///
    /// # Errors
    ///
    /// This method errors if the provided [`OsStr`] was not a valid C string.
    pub(crate) fn arg(mut self, arg: impl AsRef<OsStr>) -> Result<Self, Error> {
        let arg = CString::new(arg.as_ref().as_bytes().to_owned())
            .map_err(Tag::tag_with::<CommandError>)?;
        let position = self.arguments.len() - 1;
        self.arguments.push(ptr::null());
        self.arguments[position] = arg.into_raw();
        Ok(self)
    }

    /// Add multiple arguments to the guest process.
    ///
    /// # Errors
    ///
    /// This method errors if the provided [`OsStr`] was not a valid C string.
    pub(crate) fn args(
        mut self,
        args: impl IntoIterator<Item = impl AsRef<OsStr>>,
    ) -> Result<Self, Error> {
        for arg in args {
            self = self.arg(arg)?;
        }

        Ok(self)
    }

    /// Add or update an environment variable passed to the guest process.
    ///
    /// # Errors
    ///
    /// This method errors if the provided [`OsStr`]s do not make a valid C
    /// string.
    pub(crate) fn env(
        mut self,
        key: impl AsRef<OsStr>,
        value: impl AsRef<OsStr>,
    ) -> Result<Self, Error> {
        let key = key.as_ref();

        //NOTE: reject embedded equals in the key to avoid confusion
        if key.as_bytes().contains(&b'=') {
            return Err(CommandError::InvalidEnvironmentVariable.into());
        }

        let mut env = key.to_owned();
        env.reserve(value.as_ref().len() + 2);
        env.push("=");
        env.push(&value);

        let env = CString::new(env.into_vec())
            .map_err(Tag::tag_with::<CommandError>)?;

        drop(self.environment.insert(key.to_owned(), env));
        Ok(self)
    }

    /// Add or update several environment variables passed to the guest process.
    ///
    /// # Errors
    ///
    /// This method errors if the provided [`OsStr`]s are not valid C strings.
    pub(crate) fn envs(
        mut self,
        vars: impl IntoIterator<Item = (impl AsRef<OsStr>, impl AsRef<OsStr>)>,
    ) -> Result<Self, Error> {
        for (key, value) in vars {
            self = self.env(key, value)?;
        }

        Ok(self)
    }

    /// Remove an explicitly set environment variable.
    pub(crate) fn env_remove(mut self, key: impl AsRef<OsStr>) -> Self {
        drop(self.environment.remove(key.as_ref()));
        self
    }

    /// Set the working directory of the guest process.
    pub(crate) fn current_dir(mut self, dir: Guest) -> Self {
        self.working_directory = Some(dir);
        self
    }
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

/// Extension trait for [`Command`] providing Linux-specific features.
pub trait CommandExt: Sealed + Sized {
    /// Set the first argument given to the program to something other than the
    /// executable's path.
    ///
    /// # Errors
    ///
    /// This method erors if the provided [`OsStr`] was not a valid C string.
    fn arg0(self, arg: impl AsRef<OsStr>) -> Result<Self, CrateError>;
}

impl CommandExt for Command {
    fn arg0(self, arg: impl AsRef<OsStr>) -> Result<Self, CrateError> {
        Ok(Self {
            inner: self.inner.arg0(arg)?,
        })
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
        Option<Box<dyn FnOnce() -> Result<(), PostSpawnHost> + 'a>>,
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
    #[inline(always)]
    pub(crate) fn wait(&self) -> Result<ExitStatus, Error> {
        Ok(self.wait_internal()?)
    }

    /// Implementation of wait which doesn't return the public-facing [`Error`]
    fn wait_internal(&self) -> Result<ExitStatus, CommandError> {
        let mut fds = [PollFd::new(self.pidfd.as_fd(), 0)];
        let n_ready = retry_on_interrupt!({
            syscalls::ppoll(&mut fds, None::<linux::__kernel_timespec>)
        })?;
        debug_assert_eq!(n_ready, 1);
        debug_assert_ne!(fds[0].revents() & linux::POLLHUP as ffi::c_short, 0);

        let pidfd_info = syscalls::pidfd_get_info_v0(
            &self.pidfd,
            syscalls::PIDFD_INFO_EXIT,
        )?;

        if hint::likely(pidfd_info.mask & syscalls::PIDFD_INFO_EXIT != 0) {
            Ok(ExitStatus::from_raw(pidfd_info.exit_code))
        } else {
            Err(CommandError::MissingInformation.into())
        }
    }

    /// Attempt to capture the exit status of the guest process if it has
    /// already exited.
    pub(crate) fn try_wait(&self) -> Result<Option<ExitStatus>, Error> {
        let mut fds = [PollFd::new(self.pidfd.as_fd(), 0)];
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

        debug_assert_ne!(fds[0].revents() & linux::POLLHUP as ffi::c_short, 0);

        let pidfd_info =
            syscalls::pidfd_get_info_v0(&self.pidfd, syscalls::PIDFD_INFO_EXIT)
                .wrap_error::<CommandError>()?;

        if hint::likely(pidfd_info.mask & syscalls::PIDFD_INFO_EXIT != 0) {
            Ok(Some(ExitStatus::from_raw(pidfd_info.exit_code)))
        } else {
            Err(CommandError::MissingInformation.into())
        }
    }

    /// Tear down the environment of the guest process and capture its exit
    /// status.
    ///
    /// Sends `SIGKILL` to the guest process, then performs cgroup cleanup, if
    /// necessary.
    ///
    /// This method exists to provide a non-consuming teardown primitive which
    /// can be used by the destructor as well as the explicit teardown method.
    fn terminate_internal(&mut self) -> Result<ExitStatus, Error> {
        //NOTE: we first kill the process to ensure the cgroup destructor is
        //      able to remove the cgroup if it wants to
        let mut signal = syscalls::pidfd_send_signal(
            self.pidfd.as_fd(),
            linux::SIGKILL as i32,
            0,
        )
        .err();

        //NOTE: `ESRCH` is not an error we care about because we are only
        //      ensuring it has exited
        let _ignored = signal.take_if(|e| e.error() == Errno::SRCH);

        //NOTE: we order this here to use the poll to ensure the process has
        //      actually exited. i'm not sure if this is necessary but it seems
        //      more robust
        let wait = self.wait_internal();

        let cgroup =
            if let Some(cgroups_destructor) = self.cgroups_destructor.take() {
                cgroups_destructor().err()
            } else {
                None
            };

        match wait {
            Ok(status) if signal.is_none() && cgroup.is_none() => Ok(status),
            wait => Err(GuestTerminationError {
                signal,
                wait: wait.err(),
                cgroup,
            }
            .into()),
        }
    }

    /// Tear down the environment of the guest process and capture its exit
    /// status.
    ///
    /// Sends `SIGKILL` to the guest process, then performs cgroup cleanup, if
    /// necessary.
    ///
    /// This method allows the caller to observe any errors that may occur when
    /// tearing the guest process down.
    #[inline(always)]
    pub(crate) fn terminate(mut self) -> Result<ExitStatus, Error> {
        self.terminate_internal()
    }
}

impl fmt::Debug for GuestInner<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Guest").field(&self.pid).finish()
    }
}

impl Drop for GuestInner<'_> {
    fn drop(&mut self) {
        //NOTE: we can't error here, so we just run it and hope it worked
        let _ignored = self.terminate_internal();
    }
}
