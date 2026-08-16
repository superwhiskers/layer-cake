// SPDX-License-Identifier: AGPL-3.0-only

//! Syscall wrapper for the `aarch64` architecture.

use core::ffi;

use super::Arg;
use crate::errno::Errno;

/// Helper macro for generating syscall wrappers with fixed argument counts.
macro_rules! fixed_syscall {
    ($name:ident(number)) => {
        /// System call wrapper specialized to a set number of arguments.
        ///
        /// # Safety
        ///
        /// This is fundamentally unsafe. Make sure you've read the
        /// documentation for the syscall you're using.
        #[inline(always)]
        pub unsafe fn $name(
            number: ffi::c_long,
        ) -> Result<ffi::c_ulong, Errno> {
            let out: ffi::c_long;

            unsafe {
                core::arch::asm!(
                    "svc 0",
                    in("x8") number,
                    lateout("x0") out,
                    options(nostack),
                );
            }

            if out < 0 {
                Err(Errno(out as u16))
            } else {
                Ok(out as ffi::c_ulong)
            }
        }
    };
    ($name:ident(number, $arg1:ident $(, $arg:ident: $reg:tt)*)) => {
        /// System call wrapper specialized to a set number of arguments.
        ///
        /// # Safety
        ///
        /// This is fundamentally unsafe. Make sure you've read the
        /// documentation for the syscall you're using.
        #[inline(always)]
        pub unsafe fn $name(
            number: ffi::c_long,
            $arg1: Arg,
            $($arg: Arg),*
        ) -> Result<ffi::c_ulong, Errno> {
            let out: ffi::c_long;

            unsafe {
                core::arch::asm!(
                    "svc 0",
                    in("x8") number,
                    inlateout("x0") $arg1.into_raw() => out,
                    $(in($reg) $arg.into_raw(),)*
                    options(nostack),
                );
            }

            if out < 0 {
                Err(Errno(out as u16))
            } else {
                Ok(out as ffi::c_ulong)
            }
        }
    };
}

fixed_syscall!(syscall0(number));
fixed_syscall!(syscall1(number, arg1));
fixed_syscall!(syscall2(number, arg1, arg2: "x1"));
fixed_syscall!(syscall3(number, arg1, arg2: "x1", arg3: "x2"));
fixed_syscall!(syscall4(number, arg1, arg2: "x1", arg3: "x2", arg4: "x3"));
fixed_syscall!(syscall5(
    number,
    arg1,
    arg2: "x1",
    arg3: "x2",
    arg4: "x3",
    arg5: "x4"
));
fixed_syscall!(syscall6(
    number,
    arg1,
    arg2: "x1",
    arg3: "x2",
    arg4: "x3",
    arg5: "x4",
    arg6: "x5"
));
