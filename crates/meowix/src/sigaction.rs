// SPDX-License-Identifier: AGPL-3.0-only

//! Functions that work with the `rt_sigaction(2)` and `rt_sigprocmask(2)`
//! syscalls.

use core::{ffi, mem};
use linux_raw_sys::{general as linux, signal_macros as linux_sig};

use crate::{errors::SyscallError, syscalls};

/// Resets all `rt_sigaction(2)` handlers to `SIG_DFL` and the process signal
/// mask.
///
/// # Errors
///
/// This function errors if the call to `rt_sigaction(2)` or `rt_sigprocmask(2)`
/// fails.
///
/// # Safety
///
/// Don't call this unless you're in a singlethreaded process and considerations
/// about competing signal handling infrastructure is irrelevant
pub unsafe fn reset_signal_dispositions() -> Result<(), SyscallError> {
    //SAFETY: this is a c data structure which is valid when zeroed
    let mut disposition = unsafe { mem::zeroed::<linux::kernel_sigaction>() };
    disposition.sa_handler_kernel = linux_sig::SIG_DFL;

    for signal in 1..linux::NSIG {
        if signal == linux::SIGKILL || signal == linux::SIGSTOP {
            //NOTE: we can't handle these
            continue;
        }

        //SAFETY: caller has asserted concerns about other signal handling
        //        infrastructure is irrelevant
        unsafe {
            syscalls::rt_sigaction(
                signal as ffi::c_int,
                Some(&disposition),
                None,
                size_of::<linux::kernel_sigset_t>(),
            )?
        };
    }

    //SAFETY: this is also a c data structure which is valid when zeroed
    let empty_set = unsafe { mem::zeroed::<linux::kernel_sigset_t>() };

    //SAFETY: caller has asserted concerns about other signal handling
    //        infrastructure is irrelevant
    unsafe {
        syscalls::rt_sigprocmask(
            linux::SIG_SETMASK as ffi::c_int,
            Some(&empty_set),
            None,
            size_of::<linux::kernel_sigset_t>(),
        )?
    };

    Ok(())
}
