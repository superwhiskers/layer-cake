// SPDX-License-Identifier: AGPL-3.0-only

//! Tools for working with direct syscall wrappers.

use core::{
    ffi::{self, CStr},
    mem::MaybeUninit,
};
use linux_raw_sys::general as linux;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::{
    errno::Errno,
    errors::{
        CStrBufferTooSmall, IncompleteWrite,
        PartialTransfer as PartialTransferError,
    },
    fd::{AsFd, BorrowedFd, OwnedFd},
    syscalls,
};

#[cfg(feature = "alloc")]
use crate::errors::{StringRead as StringReadError, SyscallError};

/// Typical [`WithCStr`] buffer length for single path components.
///
/// Currently uses [`linux::NAME_MAX`] plus one for the null byte. See
/// `limits.h(0p)` for more details.
pub const PATH_COMPONENT_MAX: usize = linux::NAME_MAX as usize + 1;

/// Typical [`WithCStr`] buffer length for whole paths.
///
/// Currently uses [`linux::PATH_MAX`]. See `limits.h(0p)` for more details.
pub const PATH_MAX: usize = linux::PATH_MAX as usize;

/// [`linux::AT_FDCWD`].
#[derive(Copy, Clone, Debug)]
pub struct Cwd;

/// File descriptor wrapper for *at syscalls.
#[derive(Debug)]
pub struct AtFd<'fd> {
    pub(super) inner: AtFdInner<'fd>,
}

/// Internal state of the file descriptor wrapper used for *at syscalls.
#[derive(Debug)]
pub(super) enum AtFdInner<'fd> {
    /// Borrowed file descriptor.
    Borrowed(BorrowedFd<'fd>),

    /// Owned file descriptor.
    Owned(OwnedFd),

    /// [`linux::AT_FDCWD`].
    Cwd,
}

impl<'fd> From<&'fd Self> for AtFd<'fd> {
    fn from(fd: &'fd Self) -> Self {
        Self {
            inner: match &fd.inner {
                AtFdInner::Borrowed(fd) => AtFdInner::Borrowed(*fd),
                AtFdInner::Owned(fd) => AtFdInner::Borrowed(fd.as_fd()),
                AtFdInner::Cwd => AtFdInner::Cwd,
            },
        }
    }
}

impl<'fd, T> From<&'fd T> for AtFd<'fd>
where
    T: AsFd + ?Sized,
{
    fn from(fd: &'fd T) -> Self {
        Self {
            inner: AtFdInner::Borrowed(fd.as_fd()),
        }
    }
}

impl<'fd> From<BorrowedFd<'fd>> for AtFd<'fd> {
    fn from(fd: BorrowedFd<'fd>) -> Self {
        Self {
            inner: AtFdInner::Borrowed(fd),
        }
    }
}

impl<'fd> From<OwnedFd> for AtFd<'fd> {
    fn from(fd: OwnedFd) -> Self {
        Self {
            inner: AtFdInner::Owned(fd),
        }
    }
}

impl<'fd> From<Cwd> for AtFd<'fd> {
    fn from(_: Cwd) -> Self {
        Self {
            inner: AtFdInner::Cwd,
        }
    }
}

/// Extension trait for [`AsFd`] implementations which adds repeated read/write
/// operations.
pub trait FdReadWriteExt: AsFd {
    /// Read from this file descriptor and convert the result into a [`String`].
    ///
    /// # Errors
    ///
    /// This method errors if `read(2)` fails or if the read data was not valid
    /// UTF-8.
    #[cfg(feature = "alloc")]
    fn read_string(&self) -> Result<String, StringReadError> {
        let mut data = Vec::new();
        self.read_to_end(&mut data)?;
        Ok(String::from_utf8(data)?)
    }

    /// Read from this file descriptor into a vector.
    ///
    /// This will read until EOF.
    ///
    /// # Errors
    ///
    /// This method errors if `read(2)` fails.
    #[cfg(feature = "alloc")]
    fn read_to_end(&self, buf: &mut Vec<u8>) -> Result<(), SyscallError> {
        loop {
            if buf.spare_capacity_mut().is_empty() {
                buf.reserve(buf.len().max(32));
            }

            let n_read =
                match syscalls::read_uninit(self, buf.spare_capacity_mut()) {
                    Ok(0) => return Ok(()),
                    Ok(n) => n,
                    Err(e) if e.error() == Errno::INTR => continue,
                    Err(e) => return Err(e),
                };

            //SAFETY: we initialized the first `n_read` elements of the spare
            //        capacity and `buf.len() + n_read` is bounded by
            //        `buf.capacity()`.
            unsafe {
                buf.set_len(buf.len() + n_read);
            }
        }
    }

    /// Read a fixed array of bytes from the file descriptor.
    ///
    /// This will read until the buffer is filled.
    ///
    /// # Errors
    ///
    /// This method errors if `read(2)` fails or if not enough bytes were read
    /// to fill the buffer.
    fn read_array<const N: usize>(
        &self,
    ) -> Result<[u8; N], PartialTransferError> {
        let mut buf = [const { MaybeUninit::uninit() }; N];
        let mut i = 0usize;
        while let Some(segment) = buf.get_mut(i..)
            && !segment.is_empty()
        {
            match syscalls::read_uninit(self, segment) {
                Ok(0) => {
                    return Err(PartialTransferError {
                        transferred: i,
                        error: None,
                    });
                }
                Ok(n) => i += n,
                Err(e) if e.error() == Errno::INTR => continue,
                Err(err) => {
                    return Err(PartialTransferError {
                        transferred: i,
                        error: Some(err),
                    });
                }
            }
        }

        //SAFETY: we have ensured it is initialized
        Ok(unsafe { MaybeUninit::array_assume_init(buf) })
    }

    /// Read from this file descriptor into a potentially uninitialized buffer.
    ///
    /// This will read until either EOF or the buffer has been filled. The
    /// number of bytes read will be returned.
    ///
    /// # Errors
    ///
    /// This method returns an error if `read(2)` fails. On error,
    /// `buf[..error.transferred]` has been initialized by successful reads
    /// performed before the failure.
    fn read_until_full_uninit(
        &self,
        buf: &mut [MaybeUninit<u8>],
    ) -> Result<usize, PartialTransferError> {
        let mut i = 0usize;
        while let Some(segment) = buf.get_mut(i..)
            && !segment.is_empty()
        {
            match syscalls::read_uninit(self, segment) {
                Ok(0) => break,
                Ok(n) => i += n,
                Err(e) if e.error() == Errno::INTR => continue,
                Err(error) => {
                    return Err(PartialTransferError {
                        transferred: i,
                        error: Some(error),
                    });
                }
            }
        }
        Ok(i)
    }

    /// Read from this file descriptor into a buffer.
    ///
    /// This will read until either EOF or the buffer has been filled. The
    /// number of bytes read will be returned.
    ///
    /// # Errors
    ///
    /// On error, `error.transferred` is the number of bytes successfully read
    /// into the beginning of `buf` before the failure.
    fn read_until_full(
        &self,
        buf: &mut [u8],
    ) -> Result<usize, PartialTransferError> {
        let mut i = 0usize;
        while let Some(segment) = buf.get_mut(i..)
            && !segment.is_empty()
        {
            match syscalls::read(self, segment) {
                Ok(0) => break,
                Ok(n) => i += n,
                Err(e) if e.error() == Errno::INTR => continue,
                Err(error) => {
                    return Err(PartialTransferError {
                        transferred: i,
                        error: Some(error),
                    });
                }
            }
        }
        Ok(i)
    }

    /// Write to this file descriptor from a buffer.
    ///
    /// This returns the number of bytes written. If `write(2)` returns zero,
    /// this value will be less than `buf.len()`.
    ///
    /// # Errors
    ///
    /// On error, `error.transferred` is the number of bytes successfully
    /// written from the beginning of `buf` before the failure.
    fn write_until_stalled(
        &self,
        buf: &[u8],
    ) -> Result<usize, PartialTransferError> {
        let mut i = 0usize;
        while let Some(segment) = buf.get(i..)
            && !segment.is_empty()
        {
            match syscalls::write(self, segment) {
                Ok(0) => break,
                Ok(n) => i += n,
                Err(e) if e.error() == Errno::INTR => continue,
                Err(error) => {
                    return Err(PartialTransferError {
                        transferred: i,
                        error: Some(error),
                    });
                }
            }
        }
        Ok(i)
    }

    /// Write to this file descriptor from a buffer.
    ///
    /// This will write the entire buffer to the file descriptor.
    ///
    /// # Errors
    ///
    /// On error, `error.transferred` is the number of bytes successfully
    /// written from the beginning of `buf` before failure.
    fn write_all(&self, buf: &[u8]) -> Result<(), PartialTransferError> {
        match self.write_until_stalled(buf)? {
            transferred if transferred < buf.len() => {
                Err(PartialTransferError {
                    transferred,
                    error: None,
                })
            }
            _ => Ok(()),
        }
    }
}

impl<T> FdReadWriteExt for T where T: AsFd {}

/// Representation of string types that may become a [`CStr`].
pub trait WithCStr {
    /// Converts this value into a [`CStr`] and calls the provided closure with
    /// the string.
    ///
    /// # Errors
    ///
    /// This method errors if the null byte check is not passed, if the buffer's
    /// length was not enough to contain the new [`CStr`], or if the provided
    /// closure errors.
    fn with_c_str<const N: usize, T, E>(
        &self,
        //TODO: allow the error of the [`Result`] to be any type which can be
        //      converted into `E` instead of requiring it to be `E` itself
        f: impl FnOnce(&CStr) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<ffi::FromBytesWithNulError> + From<CStrBufferTooSmall>;
}

impl WithCStr for &CStr {
    fn with_c_str<const N: usize, T, E>(
        &self,
        f: impl FnOnce(&CStr) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<ffi::FromBytesWithNulError> + From<CStrBufferTooSmall>,
    {
        f(self)
    }
}

impl WithCStr for &[u8] {
    fn with_c_str<const N: usize, T, E>(
        &self,
        f: impl FnOnce(&CStr) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<ffi::FromBytesWithNulError> + From<CStrBufferTooSmall>,
    {
        //TODO: we could use [`MaybeUninit`] here...
        let mut buffer = [0; N];

        (self.len() < buffer.len()).ok_or(CStrBufferTooSmall)?;

        //SAFETY: we established the length is within our bounds
        unsafe { buffer.get_unchecked_mut(..self.len()) }.copy_from_slice(self);

        //SAFETY: we established the length is within our bounds
        let c_str = CStr::from_bytes_with_nul(unsafe {
            buffer.get_unchecked(..self.len() + 1)
        })?;

        f(c_str)
    }
}

impl WithCStr for &str {
    fn with_c_str<const N: usize, T, E>(
        &self,
        f: impl FnOnce(&CStr) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<ffi::FromBytesWithNulError> + From<CStrBufferTooSmall>,
    {
        self.as_bytes().with_c_str::<N, T, E>(f)
    }
}

/// Retry the given syscall on `EINTR`.
#[macro_export]
macro_rules! retry_on_interrupt {
    ($f:expr) => {
        loop {
            match $f {
                Err(e) if e.error() == $crate::errno::Errno::INTR => (),
                r => break r,
            }
        }
    };
}

/// Checks if a write was complete.
///
/// # Errors
///
/// This function errors if `count` is not equal to `expected`
pub const fn check_if_incomplete(
    count: usize,
    expected: usize,
) -> Result<(), IncompleteWrite> {
    if count != expected {
        return Err(IncompleteWrite);
    }
    Ok(())
}

/// Macro composition of `retry_on_interrupt` and `check_if_incomplete` that
/// treats the input as having a `len` method.
#[macro_export]
macro_rules! write_checked {
    ($fd:expr, $value:expr $(,)?) => {{
        let value = $value;

        let n = $crate::retry_on_interrupt!({
            $crate::syscalls::write($fd, value)
        })?;
        $crate::util::check_if_incomplete(n, value.len())?;
    }};
}

/// Macro that writes the given value to the path under the given file
/// descriptor.
#[macro_export]
macro_rules! open_beneath_and_write {
    ($fd:expr, $path:expr, $value:expr) => {{
        let fd = $crate::retry_on_interrupt!({
            $crate::syscalls::openat2(
                $fd,
                $path,
                ::linux_raw_sys::general::open_how {
                    flags: (::linux_raw_sys::general::O_WRONLY
                        | ::linux_raw_sys::general::O_CLOEXEC)
                        as u64,
                    mode: 0,
                    resolve: (::linux_raw_sys::general::RESOLVE_BENEATH
                        | ::linux_raw_sys::general::RESOLVE_NO_MAGICLINKS
                        | ::linux_raw_sys::general::RESOLVE_NO_SYMLINKS)
                        as u64,
                },
            )
        })?;
        $crate::write_checked!(&fd, $value);
    }};
}
