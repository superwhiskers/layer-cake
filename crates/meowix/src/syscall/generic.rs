// SPDX-License-Identifier: AGPL-3.0-only

//! Generic syscall wrapper using `libc`.

use core::ffi;

use super::Arg;
use crate::errno::Errno;

/// Wrapper for retrieving the last `errno(3)` value and converting it to
/// [`Errno`].
///
/// # Notes
///
/// Remove once libc has been torn from the library. Direct syscalls do not need
/// this.
#[inline(always)]
fn last_errno() -> Errno {
    //SAFETY: part of the linux binary standard. see
    //        http://refspecs.linux-foundation.org/LSB_4.0.0/LSB-Core-generic/LSB-Core-generic/baselib---errno-location.html
    let errno_location = unsafe { libc::__errno_location() };

    //SAFETY: we're dereferencing a location that by the lsb, must exist
    Errno::from_raw_os_error(unsafe { *errno_location })
}

/// Helper macro for generating syscall wrappers with fixed argument counts.
macro_rules! fixed_syscall {
    ($name:ident(number $(, $arg:ident)*)) => {
        /// System call wrapper specialized to a set number of arguments.
        ///
        /// # Safety
        ///
        /// This is fundamentally unsafe. Make sure you've read the
        /// documentation for the syscall you're using.
        #[inline(always)]
        pub unsafe fn $name(
            number: ffi::c_long,
            $($arg: Arg),*
        ) -> Result<ffi::c_ulong, Errno> {
            //SAFETY: caller knows what they're doing
            let return_value = unsafe {
                ::libc::syscall(
                    number,
                    $($arg.into_raw()),*
                )
            };
            if return_value == -1 {
                return Err(last_errno());
            }

            Ok(return_value as ffi::c_ulong)
        }
    };
}

fixed_syscall!(syscall0(number));
fixed_syscall!(syscall1(number, arg1));
fixed_syscall!(syscall2(number, arg1, arg2));
fixed_syscall!(syscall3(number, arg1, arg2, arg3));
fixed_syscall!(syscall4(number, arg1, arg2, arg3, arg4));
fixed_syscall!(syscall5(number, arg1, arg2, arg3, arg4, arg5));
fixed_syscall!(syscall6(number, arg1, arg2, arg3, arg4, arg5, arg6));
