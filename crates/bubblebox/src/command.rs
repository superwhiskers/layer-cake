// SPDX-License-Identifier: AGPL-3.0-only

//! Generic command interface to bubblebox.

use std::{ffi::OsStr, process::ExitStatus};

use crate::{
    errors::Error,
    paths::Guest as GuestPath,
    platform::command::{CommandInner, GuestInner},
    sealed::Sealed,
};

/// Sandbox managed by a supervisor process.
#[expect(missing_copy_implementations, reason = "will be filled later")]
#[derive(Debug)]
pub struct Sandbox {}

/// Sandboxed process builder.
#[derive(Debug)]
pub struct Command {
    pub(crate) inner: CommandInner,
}

impl Command {
    /// Construct a new command for launching the guest process at the path
    /// `program` within the sandbox.
    ///
    /// This has the following defauts:
    ///
    /// - No arguments to the program (except for its path on Linux).
    /// - Empty environment.
    /// - Working directory of `/`.
    ///
    /// # Errors
    ///
    /// This method errors if the underlying platform implementation errors.
    pub fn new(program: impl AsRef<OsStr>) -> Result<Self, Error> {
        Ok(Self {
            inner: CommandInner::new(program)?,
        })
    }

    /// Add an argument to the guest process.
    ///
    /// Only one may be passed per call.
    ///
    /// # Errors
    ///
    /// This method errors if the underlying platform implementation errors.
    pub fn arg(self, arg: impl AsRef<OsStr>) -> Result<Self, Error> {
        Ok(Self {
            inner: self.inner.arg(arg)?,
        })
    }

    /// Add multiple arguments to the guest process.
    ///
    /// # Errors
    ///
    /// This method errors if the underlying platform implementation errors.
    pub fn args(
        self,
        args: impl IntoIterator<Item = impl AsRef<OsStr>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: self.inner.args(args)?,
        })
    }

    /// Add or update an environment variable passed to the guest process.
    ///
    /// # Errors
    ///
    /// This method errors if the underlying platform implementation errors.
    pub fn env(
        self,
        key: impl AsRef<OsStr>,
        value: impl AsRef<OsStr>,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: self.inner.env(key, value)?,
        })
    }

    /// Add or update several environment variables passed to the guest process.
    ///
    /// # Errors
    ///
    /// This method errors if the underlying platform implementation errors.
    pub fn envs(
        self,
        vars: impl IntoIterator<Item = (impl AsRef<OsStr>, impl AsRef<OsStr>)>,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: self.inner.envs(vars)?,
        })
    }

    /// Remove an explicitly set environment variable.
    pub fn env_remove(self, key: impl AsRef<OsStr>) -> Self {
        Self {
            inner: self.inner.env_remove(key),
        }
    }

    /// Set the working directory of the guest process.
    pub fn current_dir(self, dir: GuestPath) -> Self {
        Self {
            inner: self.inner.current_dir(dir),
        }
    }
}

impl Sealed for Command {}

/// Sandboxed process.
#[derive(Debug)]
pub struct Guest<'a> {
    pub(crate) inner: GuestInner<'a>,
}

impl<'a> Guest<'a> {
    /// Return the process identifier.
    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    /// Wait on the guest process to exit completely.
    ///
    /// # Errors
    ///
    /// This method errors if waiting on the guest process or getting its exit
    /// status fails.
    pub fn wait(&self) -> Result<ExitStatus, Error> {
        Ok(self.inner.wait()?)
    }

    /// Attempt to capture the exit status of the guest process if it has
    /// already exited.
    ///
    /// # Errors
    ///
    /// This method errors if waiting on the guest process or getting its exit
    /// status fails.
    pub fn try_wait(&self) -> Result<Option<ExitStatus>, Error> {
        Ok(self.inner.try_wait()?)
    }

    /// Tear down the environment of the guest process and capture its exit
    /// status.
    ///
    /// This method allows the caller to observe any errors that may occur when
    /// tearing the guest process down.
    ///
    /// # Errors
    ///
    /// This method errors if tearing down the guest process or anything
    /// associated with its environment fails.
    pub fn teardown(self) -> Result<ExitStatus, Error> {
        Ok(self.inner.teardown()?)
    }
}
