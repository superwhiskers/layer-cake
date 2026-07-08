// SPDX-License-Identifier: AGPL-3.0-only

//! Generic command interface to bubblebox.

use std::process::ExitStatus;

use crate::{
    errors::Error,
    platform::command::{CommandInner, GuestInner},
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

/// Sandboxed process.
#[derive(Debug)]
pub struct Guest {
    pub(crate) inner: GuestInner,
}

impl Guest {
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
}
