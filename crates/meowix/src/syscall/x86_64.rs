// SPDX-License-Identifier: AGPL-3.0-only

//! Syscall wrapper for the `x86_64` architecture.

use core::ffi;

use super::Arg;
use crate::errno::Errno;

/// Helper macro for generating syscall wrappers with fixed argument counts.
macro_rules! fixed_syscall {
    ($name: ident(number $(, $arg:ident: $reg:tt)*)) => {
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
            let out: ffi::c_long;

            //SAFETY: caller knows what they're doing
            unsafe {
                core::arch::asm!(
                    "syscall",
                    inlateout("rax") number => out,
                    $(in($reg) $arg.into_raw(),)*
                    lateout("rcx") _,
                    lateout("r11") _,
                    options(nostack),
                );
            }

            if out < 0 {
                //SAFETY: the cast is guaranteed to result in a value in the range
                //        0xf001..=0xffff due to the check above
                Err(unsafe { Errno::from_u16_unchecked(out as u16) })
            } else {
                Ok(out as ffi::c_ulong)
            }
        }
    }
}

fixed_syscall!(syscall0(number));
fixed_syscall!(syscall1(number, arg1: "rdi"));
fixed_syscall!(syscall2(number, arg1: "rdi", arg2: "rsi"));
fixed_syscall!(syscall3(number, arg1: "rdi", arg2: "rsi", arg3: "rdx"));
fixed_syscall!(syscall4(
    number,
    arg1: "rdi",
    arg2: "rsi",
    arg3: "rdx",
    arg4: "r10"
));
fixed_syscall!(syscall5(
    number,
    arg1: "rdi",
    arg2: "rsi",
    arg3: "rdx",
    arg4: "r10",
    arg5: "r8"
));
fixed_syscall!(syscall6(
    number,
    arg1: "rdi",
    arg2: "rsi",
    arg3: "rdx",
    arg4: "r10",
    arg5: "r8",
    arg6: "r9"
));
