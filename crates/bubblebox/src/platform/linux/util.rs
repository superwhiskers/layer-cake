// SPDX-License-Identifier: AGPL-3.0-only

//! Utilities for sandboxing on Linux.

//TODO: add overlayfs

use linux_raw_sys::general as linux;
use std::{
    cmp,
    collections::{BTreeMap, HashSet},
    ffi::{self, CStr, OsStr},
    io,
    iter::TrustedLen,
    mem::{self, ManuallyDrop, MaybeUninit},
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd},
    ptr,
};

use super::{
    errors::{
        IncompleteWrite, PostCloneGuest as PostCloneGuestError,
        PostCloneGuestOther as PostCloneGuestOtherError, Syscall, SyscallError,
    },
    mapping::{
        BindMount, File, Mode, MountAttributes, Owner, ProcHidepid,
        ProcPidNamespace, ProcSubset, Source, SourceInner,
    },
    path as linux_path,
    syscalls::{
        self, CapabilitySet, Cwd, Errno, Gid, RawGid, RawUid, Uid, WithCStr,
    },
};
use crate::path::Guest;

/// Exclusive upper bound on the bit offset of a represented capability in a
/// [`CapabilitySet`].
const MAX_LAST_CAP: u64 = u64::BITS as u64;

/// What would be `linux::OPEN_TREE_NAMESPACE` if it had it.
pub const OPEN_TREE_NAMESPACE: u32 = 1 << 1;

/// Wrapper for an [`OwnedFd`] that implements [`io::Read`] and [`io::Write`].
pub struct FdReadWrite(OwnedFd);

impl FdReadWrite {
    /// Creates a new [`FdReadWrite`] from an [`OwnedFd`]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "you aren't going to know a file descriptor at compile time"
    )]
    pub fn new(fd: OwnedFd) -> Self {
        Self(fd)
    }

    /// Converts this [`FdReadWrite`] back into an [`OwnedFd`]
    pub fn into_fd(self) -> OwnedFd {
        self.0
    }
}

impl AsFd for FdReadWrite {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl io::Read for FdReadWrite {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        syscalls::read(&mut self.0, buf).map_err(
            |SyscallError { error, .. }| {
                io::Error::from_raw_os_error(error.raw_os_error())
            },
        )
    }
}

impl io::Write for FdReadWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        syscalls::write(&mut self.0, buf).map_err(
            |SyscallError { error, .. }| {
                io::Error::from_raw_os_error(error.raw_os_error())
            },
        )
    }

    fn flush(&mut self) -> io::Result<()> {
        //NOTE: flushing may not necessarily be meaningful on a writeable fd
        Ok(())
    }
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

/// Open the parent directory of the given path, returning the file descriptor
/// and file name.
///
/// # Errors
///
/// This function errors if `openat2(2)` failed, if the path lacked a file name,
/// or if the path lacked a parent directory.
pub fn open_parent_in_root(
    root_fd: impl AsFd,
    path: &Guest,
) -> Result<(OwnedFd, &OsStr), PostCloneGuestError> {
    let file_name = path
        .as_ref()
        .file_name()
        .ok_or(PostCloneGuestOtherError::PathLackedFileName)?;
    let path_fd = path
        .as_ref()
        .parent()
        .ok_or(PostCloneGuestOtherError::PathLackedParentDirectory)?
        .as_os_str()
        .with_c_str::<{ syscalls::PATH_MAX }, _, PostCloneGuestError>(
            |path| {
                retry_on_interrupt!({
                    syscalls::openat2(
                        root_fd.as_fd(),
                        path,
                        linux::open_how {
                            flags: (linux::O_PATH
                                | linux::O_CLOEXEC
                                | linux::O_DIRECTORY)
                                as u64,
                            mode: 0,
                            resolve: (linux::RESOLVE_IN_ROOT
                                | linux::RESOLVE_NO_MAGICLINKS
                                | linux::RESOLVE_NO_SYMLINKS)
                                as u64,
                        },
                    )
                })
                .map_err(Into::into)
            },
        )?;
    Ok((path_fd, file_name))
}

/// Compute the number of decimal digits in a [`u128`] value.
pub const fn compute_decimal_digits_u128(mut n: u128) -> usize {
    let mut digits = 1usize;

    while n >= 10 {
        n /= 10;
        digits = digits.saturating_add(1);
    }

    digits
}

/// Compute the upper bound on the number of decimal digits for the given
/// unsigned integer type.
pub const fn unsigned_decimal_digits_upper_bound<T>() -> usize {
    compute_decimal_digits_u128(
        u128::MAX
            >> (128usize.saturating_sub(size_of::<T>().saturating_mul(8))),
    )
}

/// Compute the upper bound on the number of decimal digits and possible sign
/// for the given signed integer type.
pub const fn signed_decimal_digits_upper_bound<T>() -> usize {
    compute_decimal_digits_u128(
        1 << (size_of::<T>().saturating_mul(8).saturating_sub(1)),
    )
    .saturating_add(1)
}

/// `SIGCHLD` disposition of the process as relevant to bubblebox.
///
/// See `sigaction(3p)` for more details.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SigchldDisposition {
    /// Default behavior.
    Default,

    /// Ignored.
    Ignored,

    /// Custom handler.
    Handler,

    /// Reap children but generate `SIGCHLD`.
    ///
    /// See "Consequences of Process Termination" in `_exit(3p)` for more
    /// details.
    NoChildWait,
}

/// Writes bytes to the given buffer and updates the offset.
///
/// # Errors
///
/// This function errors if the [`usize`] tracking the offset within the
/// buffer would overflow or if the buffer is too small.
pub fn write_bytes(
    buffer: &mut [u8],
    offset: &mut usize,
    bytes: &[u8],
) -> Result<(), PostCloneGuestError> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or(PostCloneGuestOtherError::BufferTooSmall)?;
    let destination = buffer
        .get_mut(*offset..end)
        .ok_or(PostCloneGuestOtherError::BufferTooSmall)?;
    destination.copy_from_slice(bytes);
    *offset = end;
    Ok(())
}

/// Writes an [`itoa::Integer`] to the given buffer and updates the offset.
///
/// # Errors
///
/// This function errors if the [`usize`] tracking the offset within the
/// buffer would overflow or if the buffer is too small.
pub fn write_integer(
    buffer: &mut [u8],
    offset: &mut usize,
    integer: impl itoa::Integer,
) -> Result<(), PostCloneGuestError> {
    let mut intermediary = itoa::Buffer::new();
    write_bytes(buffer, offset, intermediary.format(integer).as_bytes())
}

/// Check the process' current `SIGCHLD` disposition.
///
/// # Errors
///
/// This function errors if the call to `sigaction(3p)` fails, and returns the
/// [`Errno`] corresponding to the `errno(3)` value.
pub fn sigchld_disposition() -> Result<SigchldDisposition, Errno> {
    let mut disposition = MaybeUninit::<libc::sigaction>::uninit();

    //SAFETY: we're retrieving the current disposition, signaled via null in
    //        the second parameter. `disposition` is valid
    if unsafe {
        libc::sigaction(libc::SIGCHLD, ptr::null(), disposition.as_mut_ptr())
    } == -1
    {
        return Err(syscalls::last_errno());
    }

    //SAFETY: `sigaction` succeeded, so it has initialized `disposition`
    let disposition = unsafe { disposition.assume_init() };

    if disposition.sa_sigaction == libc::SIG_IGN {
        return Ok(SigchldDisposition::Ignored);
    }

    if disposition.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Ok(SigchldDisposition::NoChildWait);
    }

    if disposition.sa_sigaction == libc::SIG_DFL {
        return Ok(SigchldDisposition::Default);
    }

    Ok(SigchldDisposition::Handler)
}

/// Resets all `sigaction(3p)` handlers to `SIG_DFL`.
///
/// # Errors
///
/// This function errors if the call to `sigaction(3p)` fails, and returns the
/// [`Errno`] corresponding to the `errno(3)` value.
pub fn reset_signal_dispositions() -> Result<(), SyscallError> {
    //SAFETY: this is a c data structure which is valid when zeroed
    let mut disposition = unsafe { mem::zeroed::<libc::sigaction>() };
    disposition.sa_sigaction = libc::SIG_DFL;

    //SAFETY: this is a valid pointer
    let _ = unsafe { libc::sigemptyset(&mut disposition.sa_mask) };

    for signal in 1..linux::NSIG {
        if signal == libc::SIGKILL as u32 || signal == libc::SIGSTOP as u32 {
            //NOTE: we can't handle these
            continue;
        }

        //SAFETY: the pointer is valid, rest of the arguments are as expected
        if unsafe {
            libc::sigaction(signal as ffi::c_int, &disposition, ptr::null_mut())
        } == -1
        {
            let error = syscalls::last_errno();

            //NOTE: ignore einval because this is being compiled in
            if error != Errno::INVAL {
                return Err(SyscallError {
                    syscall: Syscall::RtSigaction,
                    error,
                });
            }
        }
    }

    //SAFETY: this is also a c data structure which is valid when zeroed
    let mut empty_set = unsafe { mem::zeroed::<libc::sigset_t>() };

    //SAFETY: this is a valid pointer
    let _ = unsafe { libc::sigemptyset(&mut empty_set) };

    //SAFETY: the pointer is valid, rest of the arguments are as expected
    if unsafe {
        libc::sigprocmask(libc::SIG_SETMASK, &empty_set, ptr::null_mut())
    } == -1
    {
        return Err(SyscallError {
            syscall: Syscall::RtSigprocmask,
            error: syscalls::last_errno(),
        });
    }

    Ok(())
}

/// Retry the given call on `EINTR`.
macro_rules! retry_on_interrupt {
    ($f:expr) => {
        loop {
            match $f {
                Err($crate::platform::linux::errors::SyscallError {
                    error: $crate::platform::linux::syscalls::Errno::INTR,
                    ..
                }) => (),
                r => break r,
            }
        }
    };
}
pub(crate) use retry_on_interrupt;

/// Macro composition of `retry_on_interrupt` and `check_if_incomplete` that
/// treats the input as having a `len` method.
macro_rules! write_checked {
    ($fd:expr, $value:expr $(,)?) => {{
        let value = $value;

        match $crate::platform::linux::util::retry_on_interrupt!({
            $crate::platform::linux::syscalls::write($fd, value)
        }) {
            Ok(n) => {
                $crate::platform::linux::util::check_if_incomplete(
                    n,
                    value.len(),
                )?;
            }

            Err($crate::platform::linux::errors::SyscallError { error: e, .. }) => {
                Err::<(), _>(
                    <$crate::platform::linux::syscalls::Errno as $crate::platform::linux::errors::ErrnoExt>::attach_syscall(
                        e,
                        $crate::platform::linux::errors::Syscall::Write,
                    ),
                )?;
            }
        }
    }};
}
pub(crate) use write_checked;

/// Macro that writes the given value to the path under the given file
/// descriptor.
macro_rules! open_beneath_and_write {
    ($fd:expr, $path:expr, $value:expr) => {{
        let fd = match $crate::platform::linux::util::retry_on_interrupt!({
            $crate::platform::linux::syscalls::openat2(
                $fd,
                $path,
                ::linux_raw_sys::general::open_how {
                    flags: (::linux_raw_sys::general::O_WRONLY
                        | ::linux_raw_sys::general::O_CLOEXEC) as u64,
                    mode: 0,
                    resolve: (::linux_raw_sys::general::RESOLVE_BENEATH
                        | ::linux_raw_sys::general::RESOLVE_NO_MAGICLINKS
                        | ::linux_raw_sys::general::RESOLVE_NO_SYMLINKS) as u64,
                }
            )
        }) {
            Ok(fd) => fd,

            Err($crate::platform::linux::errors::SyscallError { error: e, .. }) => {
                Err::<_, _>(
                    <$crate::platform::linux::syscalls::Errno as $crate::platform::linux::errors::ErrnoExt>::attach_syscall(
                        e,
                        $crate::platform::linux::errors::Syscall::Openat2,
                    ),
                )?
            }
        };

        $crate::platform::linux::util::write_checked!(&fd, $value);
    }};
}
pub(crate) use open_beneath_and_write;

/// Validate the mapping tree.
///
/// Currently, a mapping tree is valid if and only if the following conditions
/// hold:
/// - No mapping is underneath a non-synthetic mapping.
///
/// This restriction may be relaxed in the future on an opt-in basis.
pub fn is_valid_mapping_tree(mappings: &BTreeMap<Guest, Source<'_>>) -> bool {
    let mut stack = Vec::new();

    for (destination, source) in mappings {
        if let Some((current, is_synthetic)) = stack.last() {
            if destination.as_ref().starts_with(&current) {
                if !is_synthetic {
                    return false;
                }
            } else {
                while let Some((current, _)) = stack.pop()
                    && !destination.as_ref().starts_with(&current)
                {
                }
            }
        }

        stack.push((destination, source.is_synthetic()));
    }

    true
}

/// File descriptor policy.
///
/// This enumeration specifies actions other than closing the file descriptor.
/// File descriptors are marked close-on-exec if no policy is specified.
#[derive(Clone, Debug)]
pub enum FdPolicy<'a> {
    /// Preserve the specified file descriptor as-is.
    ///
    /// This does not clear the close-on-exec flag of the specified file
    /// descriptor if it is set.
    Preserve,

    /// Remap to the specified file descriptor with `dup3(2)`.
    Fd(BorrowedFd<'a>),
}

/// Validate the file descriptor policy.
///
/// Currently, a file descriptor policy is valid if and only if the following
/// conditions hold:
/// - No file descriptor which is the source of a mapped file descriptor is also
///   mapped itself.
/// - No file descriptor is mapped to itself.
/// - No file descriptor value is negative.
pub fn is_valid_fd_policy(policy_map: &BTreeMap<RawFd, FdPolicy<'_>>) -> bool {
    let sources = policy_map
        .values()
        .filter_map(|policy| {
            if let FdPolicy::Fd(source_fd) = policy {
                Some(source_fd.as_raw_fd())
            } else {
                None
            }
        })
        .collect::<HashSet<_>>();

    for fd in policy_map.keys() {
        if sources.contains(fd) || *fd < 0 {
            return false;
        }
    }

    true
}

/// Apply file descriptor policy entries and mark every other file descriptor as
/// close-on-exec.
///
/// # Safety
///
/// The policy must be valid according to [`is_valid_fd_policy`].
///
/// # Errors
///
/// This function errors if duplicating a file descriptor via `dup3(2)` fails,
/// or if `close_range(2)` fails when attempting to mark fds which were not
/// retained as close-on-exec fails.
pub unsafe fn apply_file_descriptor_policy(
    policy_map: &BTreeMap<RawFd, FdPolicy<'_>>,
) -> Result<(), PostCloneGuestError> {
    for (fd, policy) in policy_map {
        if let FdPolicy::Fd(source_fd) = policy {
            //NOTE: this is intentionally leaked so that the fd isn't closed
            let _fd = retry_on_interrupt!({
                // SAFETY: caller has checked the validity of the policy
                unsafe { syscalls::dup3(*source_fd, *fd, 0) }
                    .map(ManuallyDrop::new)
            })?;
        }
    }

    let mut range_start: ffi::c_uint = 0;
    for fd in policy_map.keys() {
        let fd = fd.cast_unsigned();
        if range_start < fd {
            //SAFETY: we're passing the arguments as expected. the first
            //        argument is guaranteed to be less than or equal to the
            //        second because we're iterating over a btree's keys
            //        and `range_start` is not equal to `fd`
            if unsafe {
                //TODO: replace with custom syscall wrapper
                libc::close_range(
                    range_start,
                    fd.saturating_sub(1),
                    libc::CLOSE_RANGE_CLOEXEC.cast_signed(),
                )
            } != 0
            {
                Err(SyscallError {
                    syscall: Syscall::CloseRange,
                    error: syscalls::last_errno(),
                })?;
            }
        }

        range_start = fd.saturating_add(1);
    }

    //SAFETY: we're passing the same kinds of arguments here as we do above
    if unsafe {
        libc::close_range(
            range_start,
            !0u32,
            libc::CLOSE_RANGE_CLOEXEC.cast_signed(),
        )
    } != 0
    {
        Err(SyscallError {
            syscall: Syscall::CloseRange,
            error: syscalls::last_errno(),
        })?;
    }

    Ok(())
}

/// Drop capabilities from the bounding set of the process other than those
/// specified.
///
/// # Errors
///
/// This function errors if `PR_CAPBSET_DROP(2const)` fails with an error
/// other than `EINVAL`.
pub fn drop_bounding_set(
    other_than: CapabilitySet,
) -> Result<(), SyscallError> {
    for cap in 0..MAX_LAST_CAP {
        if other_than.contains(CapabilitySet::from_bits_retain(1_u64 << cap)) {
            continue;
        }

        if let Err(e) = syscalls::drop_capability_from_bounding_set(cap as _)
            //NOTE: einval implies the capability was not known to the kernel
            && !matches!(e.error, Errno::INVAL)
        {
            return Err(e);
        }
    }
    Ok(())
}

/// Raise the specified capabilities into the ambient set of the process.
///
/// # Errors
///
/// This function errors if `PR_CAP_AMBIENT(2const)` fails with an error other
/// than `EINVAL`.
pub fn set_ambient_capabilities(
    raise: CapabilitySet,
) -> Result<(), SyscallError> {
    for cap in 0..MAX_LAST_CAP {
        if raise.contains(CapabilitySet::from_bits_retain(1_u64 << cap))
            && let Err(e) =
                //NOTE: more c type messiness
                syscalls::raise_capability_into_ambient_set(cap as _)
            && !matches!(e.error, Errno::INVAL)
        {
            return Err(e);
        }
    }
    Ok(())
}

/// Time offset.
///
/// Used for time namespace configuration.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TimeOffset {
    /// Offset from the initial time namespace in seconds.
    ///
    /// Cannot make the clock acquire a negative value. Cannot make the clock
    /// exceed half the value of `KTIME_SEC_MAX`.
    pub seconds: i64,

    /// Offset from the initial time namespace in nanoseconds.
    ///
    /// Must not exceed 999,999,999.
    pub nanoseconds: u32,
}

/// Writes `timens_offsets` of the time namespace children of the current
/// process will enter.
///
/// # Errors
///
/// This function errors if opening `timens_offsets` in the provided proc file
/// descriptor, or if formatting and writing the offsets fails.
pub fn write_timens_offsets(
    proc_fd: impl AsFd,
    monotonic_offset: Option<TimeOffset>,
    boottime_offset: Option<TimeOffset>,
) -> Result<(), PostCloneGuestError> {
    /// Sizes the buffer we need to use to avoid heap allocations.
    const fn size_offset_buffer() -> usize {
        signed_decimal_digits_upper_bound::<i64>()
            .saturating_add(unsigned_decimal_digits_upper_bound::<u32>())
            .saturating_add(12)
    }

    let timens_offsets_fd = retry_on_interrupt!({
        syscalls::openat2(
            proc_fd.as_fd(),
            c"self/timens_offsets",
            linux::open_how {
                flags: (linux::O_WRONLY | linux::O_CLOEXEC) as u64,
                mode: 0,
                resolve: linux::RESOLVE_BENEATH as u64,
            },
        )
    })?;

    let mut offset_buffer = [0u8; size_offset_buffer()];
    let mut offset = 0;

    if let Some(monotonic_offset) = monotonic_offset {
        write_bytes(&mut offset_buffer, &mut offset, b"monotonic ")?;
        write_integer(
            &mut offset_buffer,
            &mut offset,
            monotonic_offset.seconds,
        )?;
        write_bytes(&mut offset_buffer, &mut offset, b" ")?;
        write_integer(
            &mut offset_buffer,
            &mut offset,
            monotonic_offset.nanoseconds,
        )?;
        write_bytes(&mut offset_buffer, &mut offset, b"\n")?;

        check_if_incomplete(
            retry_on_interrupt!({
                syscalls::write(
                    &timens_offsets_fd,
                    offset_buffer
                        .get(..offset)
                        .ok_or(PostCloneGuestOtherError::BufferTooSmall)?,
                )
            })?,
            offset,
        )?;
    }

    if let Some(boottime_offset) = boottime_offset {
        offset = 0;
        write_bytes(&mut offset_buffer, &mut offset, b"boottime ")?;
        write_integer(
            &mut offset_buffer,
            &mut offset,
            boottime_offset.seconds,
        )?;
        write_bytes(&mut offset_buffer, &mut offset, b" ")?;
        write_integer(
            &mut offset_buffer,
            &mut offset,
            boottime_offset.nanoseconds,
        )?;
        write_bytes(&mut offset_buffer, &mut offset, b"\n")?;

        check_if_incomplete(
            retry_on_interrupt!({
                syscalls::write(
                    &timens_offsets_fd,
                    offset_buffer
                        .get(..offset)
                        .ok_or(PostCloneGuestOtherError::BufferTooSmall)?,
                )
            })?,
            offset,
        )?;
    }

    Ok(())
}

/// Writes `uid_map` and `gid_map` of the current process using the simple
/// mapping.
///
/// # Errors
///
/// This function errors if opening `uid_map` or `gid_map` fails in the provided
/// proc file descriptor, or if formatting and writing the mapping to the map
/// fails.
pub fn write_simple_uid_gid_map(
    proc_fd: impl AsFd,
    source_uid: Uid,
    source_gid: Gid,
    dest_uid: Uid,
    dest_gid: Gid,
    deny_setgroups: bool,
) -> Result<(), PostCloneGuestError> {
    /// Sizes the buffer we need to use to avoid heap allocations.
    ///
    /// This is computed from the two ids we need, the two spaces separating
    /// the ids and the size of the mapping, the single `1`, and the newline.
    const fn size_uid_gid_map_buffer<T>() -> usize {
        2_usize
            .saturating_mul(unsigned_decimal_digits_upper_bound::<T>())
            .saturating_add(4)
    }

    //NOTE: blame `clone3(2)` and the c standard
    let mut uid_gid_map_buffer = [0u8; cmp::max(
        size_uid_gid_map_buffer::<RawUid>(),
        size_uid_gid_map_buffer::<RawGid>(),
    )];
    let mut offset = 0;

    let proc_self_fd = retry_on_interrupt!({
        syscalls::openat2(
            proc_fd.as_fd(),
            c"self",
            linux::open_how {
                flags: (linux::O_PATH | linux::O_CLOEXEC | linux::O_DIRECTORY)
                    as u64,
                mode: 0,
                resolve: linux::RESOLVE_BENEATH as u64,
            },
        )
    })?;

    let uid_map_fd = retry_on_interrupt!({
        syscalls::openat2(
            &proc_self_fd,
            c"uid_map",
            linux::open_how {
                flags: (linux::O_WRONLY | linux::O_CLOEXEC) as u64,
                mode: 0,
                resolve: linux::RESOLVE_BENEATH as u64,
            },
        )
    })?;

    write_integer(&mut uid_gid_map_buffer, &mut offset, dest_uid.as_raw())?;
    write_bytes(&mut uid_gid_map_buffer, &mut offset, b" ")?;
    write_integer(&mut uid_gid_map_buffer, &mut offset, source_uid.as_raw())?;
    write_bytes(&mut uid_gid_map_buffer, &mut offset, b" 1\n")?;

    check_if_incomplete(
        retry_on_interrupt!({
            syscalls::write(
                &uid_map_fd,
                uid_gid_map_buffer
                    .get(..offset)
                    .ok_or(PostCloneGuestOtherError::BufferTooSmall)?,
            )
        })?,
        offset,
    )?;

    if deny_setgroups {
        let setgroups_map_fd = retry_on_interrupt!({
            syscalls::openat2(
                &proc_self_fd,
                c"setgroups",
                linux::open_how {
                    flags: (linux::O_WRONLY | linux::O_CLOEXEC) as u64,
                    mode: 0,
                    resolve: linux::RESOLVE_BENEATH as u64,
                },
            )
        })?;

        check_if_incomplete(
            retry_on_interrupt!({
                syscalls::write(&setgroups_map_fd, b"deny\n")
            })?,
            5,
        )?;
    }

    let gid_map_fd = retry_on_interrupt!({
        syscalls::openat2(
            &proc_self_fd,
            c"gid_map",
            linux::open_how {
                flags: (linux::O_WRONLY | linux::O_CLOEXEC) as u64,
                mode: 0,
                resolve: linux::RESOLVE_BENEATH as u64,
            },
        )
    })?;

    offset = 0;

    write_integer(&mut uid_gid_map_buffer, &mut offset, dest_gid.as_raw())?;
    write_bytes(&mut uid_gid_map_buffer, &mut offset, b" ")?;
    write_integer(&mut uid_gid_map_buffer, &mut offset, source_gid.as_raw())?;
    write_bytes(&mut uid_gid_map_buffer, &mut offset, b" 1\n")?;

    check_if_incomplete(
        retry_on_interrupt!({
            syscalls::write(
                &gid_map_fd,
                uid_gid_map_buffer
                    .get(..offset)
                    .ok_or(PostCloneGuestOtherError::BufferTooSmall)?,
            )
        })?,
        offset,
    )?;

    Ok(())
}

/// Resolved mapping.
pub enum ResolvedMount<'a> {
    //TODO: i think some of these could be cleaned up. the inconsistency
    //      between [`File`] being its own thing and
    //      [`ResolvedMount::Directory`] storing the owner & perms directly
    //      is pretty weird
    /// Mapping resolved to a detached mount object.
    Fd {
        /// Detached mount object.
        fd: OwnedFd,

        /// Destination on the guest.
        destination: &'a Guest,

        /// Whether or not the mount object is a directory.
        ///
        /// In order to mount, we need to have a destination object of the
        /// same "kind". The relevant distinction is whether or not
        /// the mount object is a directory.
        is_directory: bool,
    },

    /// Synthetic file mapping.
    File {
        /// Description of the file.
        file: &'a File,

        /// Destination on the guest.
        destination: &'a Guest,
    },

    /// Empty directory mapping.
    Directory {
        /// Owner of the directory.
        owner: Owner,

        /// Permissions applied to the directory.
        permissions: Mode,

        /// Destination on the guest.
        destination: &'a Guest,
    },
}

/// Resolve an enumerable set of [`Guest`], [`Source`] pairs to synthetic files,
/// empty directories, and detached mount objects for mappings other than bind
/// mappings from the host.
///
/// # Notes
///
/// This function initializes all slots in the spare capacity of `resolved`
/// where non-bind mounts would go. After calling this function, those slots are
/// guaranteed to be initialized. This function returns the number of slots
/// initialized for accounting purposes.
///
/// # Errors
///
/// This function errors if opening and interacting with filesystem
/// configuration objects for a mapped filesystem fails.
pub fn resolve_nonbind_mappings<'a, I>(
    mappings: I,
    resolved: &mut Vec<ResolvedMount<'a>>,
) -> Result<usize, PostCloneGuestError>
where
    I: IntoIterator<Item = (&'a Guest, &'a Source<'a>)>,
    I::IntoIter: TrustedLen,
{
    let mappings = mappings.into_iter().enumerate();

    (resolved.len() == 0)
        .ok_or(PostCloneGuestOtherError::NonzeroResolvedLen)?;
    (resolved.capacity()
        >= mappings
            .size_hint()
            .1
            .ok_or(PostCloneGuestOtherError::BufferTooSmall)?)
    .ok_or(PostCloneGuestOtherError::BufferTooSmall)?;

    let resolved = resolved.spare_capacity_mut();

    let mut n_non_binds = 0;
    for (i, (destination, source)) in mappings {
        let resolved_mount = match &source.inner {
            SourceInner::Procfs {
                hidepid,
                gid,
                subset,
                namespace,
                attributes,
            } => {
                let fs_fd = syscalls::fsopen(c"proc", linux::FSOPEN_CLOEXEC)?;
                let mut buffer = itoa::Buffer::new();

                syscalls::fsconfig_set_string(
                    &fs_fd,
                    c"hidepid",
                    match hidepid {
                        ProcHidepid::Off => c"off",
                        ProcHidepid::NoAccess => c"noaccess",
                        ProcHidepid::Invisible => c"invisible",
                        ProcHidepid::Ptraceable => c"ptraceable",
                    },
                )?;

                if let Some(gid) = gid {
                    //TODO: we should probably pin this to a proper type
                    buffer.format(gid.as_raw()).with_c_str::<{
                        unsigned_decimal_digits_upper_bound::<u32>() + 1
                    }, _, PostCloneGuestError>(
                        |gid| {
                            syscalls::fsconfig_set_string(&fs_fd, c"gid", gid)?;

                            Ok(())
                        },
                    )?;
                }

                if *subset == ProcSubset::Pid {
                    syscalls::fsconfig_set_string(&fs_fd, c"subset", c"pid")?;
                }

                if let ProcPidNamespace::Fd(fd) = namespace {
                    syscalls::fsconfig_set_fd(&fs_fd, c"pidns", fd)?;
                }

                syscalls::fsconfig_cmd_create_excl(&fs_fd)?;
                ResolvedMount::Fd {
                    fd: syscalls::fsmount(
                        fs_fd,
                        linux::FSMOUNT_CLOEXEC,
                        attributes.into_mount_attr(),
                    )?,
                    destination,
                    is_directory: true,
                }
            }
            SourceInner::Mqueue { attributes } => {
                let fs_fd = syscalls::fsopen(c"mqueue", linux::FSOPEN_CLOEXEC)?;

                syscalls::fsconfig_cmd_create_excl(&fs_fd)?;
                ResolvedMount::Fd {
                    fd: syscalls::fsmount(
                        fs_fd,
                        linux::FSMOUNT_CLOEXEC,
                        attributes.into_mount_attr(),
                    )?,
                    destination,
                    is_directory: true,
                }
            }
            SourceInner::File(file) => {
                ResolvedMount::File { file, destination }
            }
            SourceInner::EmptyDirectory { owner, permissions } => {
                ResolvedMount::Directory {
                    owner: *owner,
                    permissions: *permissions,
                    destination,
                }
            }
            SourceInner::Tmpfs {
                size,
                owner,
                permissions,
                attributes,
            } => {
                let fs_fd = syscalls::fsopen(c"tmpfs", linux::FSOPEN_CLOEXEC)?;
                //let mut buffer = itoa::Buffer::new();

                if let Some(size) = size {
                    size.as_str().with_c_str::<{
                        //TODO: we won't need this anymore once we use a proper
                        //      enum for the size or something like that, but
                        //      for now, let's cap it at u32 literal size + 1
                        //      character for the suffix, and another for the
                        //      null byte.
                        unsigned_decimal_digits_upper_bound::<u32>() + 2
                    }, _, PostCloneGuestError>(
                        |size| {
                            syscalls::fsconfig_set_string(
                                &fs_fd, c"size", size,
                            )?;

                            Ok(())
                        },
                    )?;
                }

                //TODO: uncomment when newuidmap/newgidmap or
                //      systemd-nsresourced is supported w/ a check prior
                /*if let Owner::Ids { user, group } = owner {
                    syscalls::fsconfig_set_string(
                        &fs_fd,
                        c"gid",
                        //TODO: needs fixing
                        buffer.format(group.as_raw()),
                    )?;
                    syscalls::fsconfig_set_string(
                        &fs_fd,
                        c"uid",
                        //TODO: needs fixing
                        buffer.format(user.as_raw()),
                    )?;
                }*/

                let mut mode = *b"0000\0";
                let mut permissions = permissions.bits() & 0o7777;
                for c in mode.iter_mut().rev().skip(1) {
                    *c = b'0'.saturating_add((permissions & 0o7) as u8);
                    permissions >>= 3;
                }

                //SAFETY: we constructed it with a null terminator above
                syscalls::fsconfig_set_string(&fs_fd, c"mode", unsafe {
                    CStr::from_bytes_with_nul_unchecked(mode.as_slice())
                })?;

                syscalls::fsconfig_cmd_create_excl(&fs_fd)?;

                ResolvedMount::Fd {
                    fd: syscalls::fsmount(
                        fs_fd,
                        linux::FSMOUNT_CLOEXEC,
                        attributes.into_mount_attr(),
                    )?,
                    destination,
                    is_directory: true,
                }
            }
            //NOTE: these are handled separately
            SourceInner::Bind(_) => continue,
        };

        //SAFETY: we've ensured at the top of this function that there is
        //        enough space
        let _ = unsafe { resolved.get_unchecked_mut(i) }.write(resolved_mount);
        n_non_binds += 1;
    }

    Ok(n_non_binds)
}

/// Creates mount namespaces for each of the bind mounts and enters them to
/// create detached mounts.
///
/// It is necessary for this to be done separate from synthetic mounts due to
/// namespace rules. This function writes to the capacity of `resolved` the
/// resolved bind mounts and no others.
///
/// # Notes
///
/// This function initializes all slots in the spare capacity of `resolved`
/// where bind mounts would go. After calling this function, those slots are
/// guaranteed to be initialized. This function returns the number of slots
/// initialized for accounting purposes.
///
/// # Errors
///
/// This function errors if creating new mount namespaces or entering them
/// sequentially to create detached mount objects fails.
pub fn resolve_bind_mappings<'a, 'b, I>(
    mappings: I,
    resolved: &mut Vec<ResolvedMount<'a>>,
    namespace_fd_scratch_space: &mut Vec<(
        // the index into the resolved mapping
        //
        // this is necessary because we want to be able to keep the in-order
        // traversal that a btreemap provides for our mounts
        usize,
        // owned fd representing the generated namespace
        OwnedFd,
        // destination of the mount
        &'a Guest,
        // file to construct the detached mount from and the fd to verify it,
        // if this is a file bind mount
        Option<(&'b OsStr, BorrowedFd<'b>)>,
        // mount attributes applied to the detached mount
        MountAttributes,
        // whether or not this is a recursive mount
        bool,
    )>,
) -> Result<usize, PostCloneGuestError>
where
    I: IntoIterator<Item = (&'a Guest, &'a Source<'a>)>,
    I::IntoIter: TrustedLen,
    'a: 'b,
{
    let mappings = mappings.into_iter().enumerate();

    (resolved.len() == 0)
        .ok_or(PostCloneGuestOtherError::NonzeroResolvedLen)?;
    (resolved.capacity()
        >= mappings
            .size_hint()
            .1
            .ok_or(PostCloneGuestOtherError::BufferTooSmall)?)
    .ok_or(PostCloneGuestOtherError::BufferTooSmall)?;

    let resolved = resolved.spare_capacity_mut();

    //NOTE: so, if you're doing an absurd amount of bind mounts or already have
    //      contention for that resource on your system, this could be an issue.
    //      my local reference point is user.max_mnt_namespaces is 512051. i
    //      don't think this is likely, but if it is, there *are* ways around
    //      this, just let me know if you run into issues

    for (i, (destination, source)) in mappings {
        let mut flags = OPEN_TREE_NAMESPACE
            | linux::OPEN_TREE_CLOEXEC
            | linux::AT_EMPTY_PATH;
        let mut file_info = None;
        let (dirfd, attributes, is_recursive) = match &source.inner {
            SourceInner::Bind(BindMount::File {
                dirfd,
                name,
                fd,
                attributes,
            }) => {
                file_info = Some((*name, *fd));

                //NOTE: file mounts cannot be recursive
                (dirfd, *attributes, false)
            }
            SourceInner::Bind(BindMount::Directory {
                fd,
                attributes,
                is_recursive,
            }) => {
                if *is_recursive {
                    flags |= linux::AT_RECURSIVE;
                }

                (fd, *attributes, *is_recursive)
            }
            _ => continue,
        };

        let namespace_fd = syscalls::open_tree(dirfd, c"", flags)?;
        namespace_fd_scratch_space.push((
            i,
            namespace_fd,
            destination,
            file_info,
            attributes,
            is_recursive,
        ));
    }

    //NOTE: so, there's some real subtle ordering here. we need to capture
    //      those namespace fds prior to unsharing our own mount namespace so
    //      they stay valid for our purposes.

    // SAFETY: only unsharing the mount namespace
    unsafe {
        syscalls::unshare(linux::CLONE_NEWNS as ffi::c_int)?;
    }

    let original_ns_flags = OPEN_TREE_NAMESPACE
        | linux::OPEN_TREE_CLOEXEC
        | linux::AT_EMPTY_PATH
        | linux::AT_RECURSIVE;

    //NOTE: capture the original mount tree
    let original_ns = syscalls::open_tree(Cwd, c"/", original_ns_flags)?;

    let n_binds = namespace_fd_scratch_space.len();
    for (i, namespace_fd, destination, file_info, attributes, is_recursive) in
        namespace_fd_scratch_space
    {
        syscalls::setns(namespace_fd, linux::CLONE_NEWNS as ffi::c_int)?;
        syscalls::chdir(c"/")?;

        let mut open_tree_flags =
            linux::OPEN_TREE_CLONE | linux::OPEN_TREE_CLOEXEC;

        if *is_recursive {
            open_tree_flags |= linux::AT_RECURSIVE;
        }

        let mount_attr = linux::mount_attr {
            attr_set: attributes.into_mount_attr().into(),
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };

        let fd = if let Some((name, _)) = &file_info {
            name.with_c_str::<{
                syscalls::PATH_COMPONENT_MAX
            }, _, PostCloneGuestError>(|name| {
                syscalls::open_tree_attr(
                    Cwd,
                    name,
                    open_tree_flags,
                    &mount_attr,
                )

                .map_err(Into::into)
            })?
        } else {
            syscalls::open_tree_attr(Cwd, c"/", open_tree_flags, &mount_attr)?
        };

        if let Some((_, original_fd)) = file_info {
            linux_path::same_file_identity(original_fd.as_fd(), fd.as_fd())?
                .ok_or(PostCloneGuestOtherError::BindMappedFileMismatch)?;
        }

        //SAFETY: we've ensured at the top of this function that there is
        //        enough space
        let _ = unsafe { resolved.get_unchecked_mut(*i) }.write(
            ResolvedMount::Fd {
                fd,
                destination,
                is_directory: file_info.is_none(),
            },
        );
    }

    syscalls::setns(original_ns, linux::CLONE_NEWNS as ffi::c_int)?;
    syscalls::chdir(c"/")?;

    Ok(n_binds)
}
