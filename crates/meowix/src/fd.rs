// SPDX-FileCopyrightText: The Rust Project Developers
// SPDX-License-Identifier: MIT
//
// Vendored and adapted from [rust-lang/rust]. This file is excluded from the
// repository's AGPL-3.0-only licensing. Local modifications are also licensed
// under MIT.
//
// [rust-lang/rust]: https://github.com/rust-lang/rust/tree/594e7379b91506fda3f288037d554ecd1e8f2f80/library/std/src/os/fd

//! Raw, owned, and borrowed Linux file descriptors.
//!
//! This module is vendored from the Rust standard library with tweaks to fit
//! within this crate. Its source code is excluded from the repository's
//! AGPL-3.0-only licensing and licensed under MIT instead.

use core::{
    ffi, fmt, marker::PhantomData, mem, mem::ManuallyDrop, pattern_type,
};

#[repr(transparent)]
#[derive(Clone, Copy)]
struct IntNotAllOnes(pattern_type!(ffi::c_int is ..-1 | 0..));

impl IntNotAllOnes {
    #[inline]
    pub const fn new(value: ffi::c_int) -> Option<Self> {
        #[allow(non_contiguous_range_endpoints)]
        if let ..-1 | 0.. = value {
            // SAFETY: The pattern check established that `value != -1`.
            Some(unsafe { Self::new_unchecked(value) })
        } else {
            None
        }
    }

    /// # Safety
    ///
    /// `value` must not be `-1`.
    #[inline]
    pub const unsafe fn new_unchecked(value: ffi::c_int) -> Self {
        // SAFETY: Required by the caller.
        unsafe { mem::transmute(value) }
    }

    #[inline]
    pub const fn as_inner(self) -> ffi::c_int {
        // SAFETY: Every valid pattern-type value is valid as its base type.
        //
        // Avoid `self.0`; rustc's implementation does the same because field
        // projection from pattern types currently has restrictions/regressions.
        unsafe { mem::transmute(self) }
    }
}

impl fmt::Debug for IntNotAllOnes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_inner())
    }
}

type ValidRawFd = IntNotAllOnes;

/// A borrowed file descriptor.
///
/// This has a lifetime parameter to tie it to the lifetime of something that
/// owns the file descriptor. For the duration of that lifetime, it is
/// guaranteed that nobody will close the file descriptor.
///
/// This uses `repr(transparent)` and has the representation of a host file
/// descriptor, so it can be used in FFI in places where a file descriptor is
/// passed as an argument, it is not captured or consumed, and it never has the
/// value `-1`.
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct BorrowedFd<'fd> {
    fd: ValidRawFd,
    _phantom: PhantomData<&'fd OwnedFd>,
}

/// An owned file descriptor.
///
/// This closes the file descriptor on drop. It is guaranteed that nobody else
/// will close the file descriptor.
///
/// This uses `repr(transparent)` and has the representation of a host file
/// descriptor, so it can be used in FFI in places where a file descriptor is
/// passed as a consumed argument or returned as an owned value, and it never
/// has the value `-1`.
///
/// You can use [`AsFd::as_fd`] to obtain a [`BorrowedFd`].
#[repr(transparent)]
pub struct OwnedFd {
    fd: ValidRawFd,
}

impl BorrowedFd<'_> {
    /// Returns a `BorrowedFd` holding the given raw file descriptor.
    ///
    /// # Safety
    ///
    /// The resource pointed to by `fd` must remain open for the duration of
    /// the returned `BorrowedFd`.
    ///
    /// # Panics
    ///
    /// Panics if the raw file descriptor has the value `-1`.
    #[inline]
    #[track_caller]
    pub const unsafe fn borrow_raw(fd: RawFd) -> Self {
        Self {
            fd: ValidRawFd::new(fd).expect("fd != -1"),
            _phantom: PhantomData,
        }
    }
}

impl AsRawFd for BorrowedFd<'_> {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_inner()
    }
}

impl AsRawFd for OwnedFd {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_inner()
    }
}

impl IntoRawFd for OwnedFd {
    #[inline]
    fn into_raw_fd(self) -> RawFd {
        ManuallyDrop::new(self).fd.as_inner()
    }
}

impl FromRawFd for OwnedFd {
    /// Constructs a new instance of `Self` from the given raw file descriptor.
    ///
    /// # Safety
    ///
    /// The resource pointed to by `fd` must be open and suitable for assuming
    /// ownership. The resource must not require any cleanup other than `close`.
    ///
    /// # Panics
    ///
    /// Panics if the raw file descriptor has the value `-1`.
    #[inline]
    #[track_caller]
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self {
            fd: ValidRawFd::new(fd).expect("fd != -1"),
        }
    }
}

impl Drop for OwnedFd {
    #[inline]
    fn drop(&mut self) {
        //SAFETY: it must be open, hence this is fine
        unsafe {
            crate::syscalls::close(self.fd.as_inner());
        }
    }
}

impl fmt::Debug for BorrowedFd<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BorrowedFd").field("fd", &self.fd).finish()
    }
}

impl fmt::Debug for OwnedFd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedFd").field("fd", &self.fd).finish()
    }
}

/// A trait to borrow the file descriptor from an underlying object.
///
/// This is only available on unix platforms and must be imported in order to
/// call the method. Windows platforms have a corresponding `AsHandle` and
/// `AsSocket` set of traits.
pub trait AsFd {
    /// Borrows the file descriptor.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::fs::File;
    /// # use std::io;
    /// # #[cfg(any(unix, target_os = "wasi"))]
    /// # use std::os::fd::{AsFd, BorrowedFd};
    ///
    /// let mut f = File::open("foo.txt")?;
    /// # #[cfg(any(unix, target_os = "wasi"))]
    /// let borrowed_fd: BorrowedFd<'_> = f.as_fd();
    /// # Ok::<(), io::Error>(())
    /// ```
    fn as_fd(&self) -> BorrowedFd<'_>;
}

impl<T: AsFd + ?Sized> AsFd for &T {
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        T::as_fd(self)
    }
}

impl<T: AsFd + ?Sized> AsFd for &mut T {
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        T::as_fd(self)
    }
}

impl AsFd for BorrowedFd<'_> {
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        *self
    }
}

impl AsFd for OwnedFd {
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        //SAFETY: `OwnedFd` and `BorrowedFd` have the same validity
        //        invariants, and the `BorrowedFd` is bounded by the lifetime
        //        of `&self`.
        unsafe { BorrowedFd::borrow_raw(self.as_raw_fd()) }
    }
}

/// Raw file descriptors.
pub type RawFd = ffi::c_int;

/// A trait to extract the raw file descriptor from an underlying object.
///
/// This is only available on unix and WASI platforms and must be imported in
/// order to call the method. Windows platforms have a corresponding
/// `AsRawHandle` and `AsRawSocket` set of traits.
pub trait AsRawFd {
    /// Extracts the raw file descriptor.
    ///
    /// This function is typically used to **borrow** an owned file descriptor.
    /// When used in this way, this method does **not** pass ownership of the
    /// raw file descriptor to the caller, and the file descriptor is only
    /// guaranteed to be valid while the original object has not yet been
    /// destroyed.
    ///
    /// However, borrowing is not strictly required. See [`AsFd::as_fd`]
    /// for an API which strictly borrows a file descriptor.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::fs::File;
    /// # use std::io;
    /// #[cfg(any(unix, target_os = "wasi"))]
    /// use std::os::fd::{AsRawFd, RawFd};
    ///
    /// let mut f = File::open("foo.txt")?;
    /// // Note that `raw_fd` is only valid as long as `f` exists.
    /// #[cfg(any(unix, target_os = "wasi"))]
    /// let raw_fd: RawFd = f.as_raw_fd();
    /// # Ok::<(), io::Error>(())
    /// ```
    fn as_raw_fd(&self) -> RawFd;
}

/// A trait to express the ability to construct an object from a raw file
/// descriptor.
pub trait FromRawFd {
    /// Constructs a new instance of `Self` from the given raw file
    /// descriptor.
    ///
    /// This function is typically used to **consume ownership** of the
    /// specified file descriptor. When used in this way, the returned object
    /// will take responsibility for closing it when the object goes out of
    /// scope.
    ///
    /// However, consuming ownership is not strictly required. Use a
    /// [`From<OwnedFd>::from`] implementation for an API which strictly
    /// consumes ownership.
    ///
    /// # Safety
    ///
    /// The `fd` passed in must be an owned file descriptor; in particular,
    /// it must be open.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::fs::File;
    /// # use std::io;
    /// #[cfg(any(unix, target_os = "wasi"))]
    /// use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
    ///
    /// let f = File::open("foo.txt")?;
    /// # #[cfg(any(unix, target_os = "wasi"))]
    /// let raw_fd: RawFd = f.into_raw_fd();
    /// // SAFETY: no other functions should call `from_raw_fd`, so there
    /// // is only one owner for the file descriptor.
    /// # #[cfg(any(unix, target_os = "wasi"))]
    /// let f = unsafe { File::from_raw_fd(raw_fd) };
    /// # Ok::<(), io::Error>(())
    /// ```
    unsafe fn from_raw_fd(fd: RawFd) -> Self;
}

/// A trait to express the ability to consume an object and acquire ownership of
/// its raw file descriptor.
pub trait IntoRawFd {
    /// Consumes this object, returning the raw underlying file descriptor.
    ///
    /// This function is typically used to **transfer ownership** of the
    /// underlying file descriptor to the caller. When used in this way,
    /// callers are then the unique owners of the file descriptor and must
    /// close it once it's no longer needed.
    ///
    /// However, transferring ownership is not strictly required. Use a
    /// [`Into<OwnedFd>::into`] implementation for an API which strictly
    /// transfers ownership.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::fs::File;
    /// # use std::io;
    /// #[cfg(any(unix, target_os = "wasi"))]
    /// use std::os::fd::{IntoRawFd, RawFd};
    ///
    /// let f = File::open("foo.txt")?;
    /// #[cfg(any(unix, target_os = "wasi"))]
    /// let raw_fd: RawFd = f.into_raw_fd();
    /// # Ok::<(), io::Error>(())
    /// ```
    #[must_use = "losing the raw file descriptor may leak resources"]
    fn into_raw_fd(self) -> RawFd;
}

impl AsRawFd for RawFd {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        *self
    }
}

impl IntoRawFd for RawFd {
    #[inline]
    fn into_raw_fd(self) -> RawFd {
        self
    }
}

impl FromRawFd for RawFd {
    #[inline]
    unsafe fn from_raw_fd(fd: RawFd) -> RawFd {
        fd
    }
}
