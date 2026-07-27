// SPDX-License-Identifier: AGPL-3.0-only

//! File descriptor policy implementation.

use core::{ffi, mem::ManuallyDrop};
use meowix::{
    fd::{AsRawFd, OwnedFd, RawFd},
    retry_on_interrupt, syscalls,
};

use super::{
    super::policy::fd::Action, errors::PostSpawnGuest as PostSpawnGuestError,
};

/// Apply file descriptor policy entries and mark every other file descriptor as
/// close-on-exec.
///
/// The guest pipe must be passed through to ensure it actually refers to the
/// write end of the pipe after applying the policy. The guest pipe is
/// guaranteed to be valid even upon error, so that error reporting continues to
/// work.
///
/// # Safety
///
/// The policy must be valid according to
/// [`super::super::policy::fd::is_valid_fd_policy`].
///
/// # Errors
///
/// This function errors if duplicating a file descriptor via `dup3(2)` fails,
/// or if `close_range(2)` fails when attempting to mark fds which were not
/// retained as close-on-exec fails.
pub unsafe fn apply_file_descriptor_policy<'a>(
    policy_map: impl IntoIterator<Item = (&'a RawFd, &'a Action<'a>)>,
    guest_pipe: &mut OwnedFd,
) -> Result<(), PostSpawnGuestError> {
    //NOTE: this should be kept up to date if we ever add more file descriptors
    //      required to be open by the exec path. unlikely, though
    let mut source_for_guest_pipe = None;

    let mut range_start: ffi::c_uint = 0;
    for (fd, policy) in policy_map {
        if let Action::Map(source_fd) = policy {
            if guest_pipe.as_raw_fd() == *fd {
                //NOTE: delay the mapping so that we can ensure no other fd
                //      needs the source being mapped to it
                source_for_guest_pipe = Some(source_fd);
            } else {
                //NOTE: this is intentionally leaked so that the fd isn't
                //      closed
                let _fd = retry_on_interrupt!({
                    //SAFETY: caller has checked the validity of the policy
                    unsafe { syscalls::dup3(*source_fd, *fd, 0) }
                        .map(ManuallyDrop::new)
                })?;
            }
        }

        let fd = fd.cast_unsigned();
        if range_start < fd {
            //SAFETY: we are only applying the close-on-exec flag to these file
            //        descriptors
            unsafe {
                syscalls::close_range(
                    range_start,
                    fd.saturating_sub(1),
                    syscalls::CLOSE_RANGE_CLOEXEC,
                )?
            };
        }

        range_start = fd.saturating_add(1);
    }

    //SAFETY: we're only applying the close-on-exec flag
    unsafe {
        syscalls::close_range(
            range_start,
            !0u32,
            syscalls::CLOSE_RANGE_CLOEXEC,
        )?
    };

    //NOTE: remap the guest pipe if the policy wants to map to it. this only
    //      works this way right now because we have strict requirements on the
    //      mappings
    if let Some(source_fd) = source_for_guest_pipe {
        let raw_guest_pipe = guest_pipe.as_raw_fd();
        *guest_pipe = syscalls::fcntl_dupfd_cloexec(&*guest_pipe)?;
        let _fd = retry_on_interrupt!({
            //SAFETY: caller has checked the validity of the policy
            unsafe { syscalls::dup3(*source_fd, raw_guest_pipe, 0) }
                .map(ManuallyDrop::new)
        })?;
    }

    Ok(())
}
