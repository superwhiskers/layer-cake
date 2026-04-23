// SPDX-License-Identifier: AGPL-3.0-only

//! Utilities for sandboxing on Linux.

//TODO: add overlayfs

use linux_raw_sys::general as linux_general;
use rustix::{
    fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    fs::{AtFlags, FileType, Gid, Mode, OFlags, ResolveFlags, StatxFlags, Uid},
    io::Errno,
    mount::{FsMountFlags, FsOpenFlags, MountAttrFlags},
    process::{RawGid, RawUid},
    thread::CapabilitySet,
};
use std::{
    cmp,
    collections::{BTreeMap, HashSet},
    ffi,
    ffi::OsStr,
    io,
    mem::{self, MaybeUninit},
    ptr,
};

use super::mapping::{
    BindMount, File, Owner, ProcHidepid, ProcPidNamespace, ProcSubset, Source,
    SourceInner,
};
use crate::{
    errors::{ChildError, Error},
    path::{Guest, Host},
};

/// Exclusive upper bound on the bit offset of a represented capability in a
/// [`CapabilitySet`].
const MAX_LAST_CAP: u64 = u64::BITS as u64;

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
        rustix::io::read(&mut self.0, buf)
            .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
    }
}

impl io::Write for FdReadWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        rustix::io::write(&mut self.0, buf)
            .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
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
) -> Result<(), ChildError> {
    if count != expected {
        return Err(ChildError::IncompleteWrite);
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
) -> Result<(OwnedFd, &OsStr), ChildError> {
    let file_name = path
        .as_ref()
        .file_name()
        .ok_or(ChildError::PathLackedFileName)?;
    let path_fd = retry_on_interrupt!({
        rustix::fs::openat2(
            root_fd.as_fd(),
            path.as_ref()
                .parent()
                .ok_or(ChildError::PathLackedParentDir)?,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::DIRECTORY,
            Mode::empty(),
            ResolveFlags::IN_ROOT
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_SYMLINKS,
        )
    })?;
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
) -> Result<(), ChildError> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or(ChildError::BufferTooSmall)?;
    let destination = buffer
        .get_mut(*offset..end)
        .ok_or(ChildError::BufferTooSmall)?;
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
) -> Result<(), ChildError> {
    let mut intermediary = itoa::Buffer::new();
    write_bytes(buffer, offset, intermediary.format(integer).as_bytes())
}

/// Check the process' current `SIGCHLD` disposition.
///
/// # Errors
///
/// This function errors if the call to `sigaction(3p)` fails, and returns the
/// [`io::Error`] corresponding to the `errno(3)` value.
pub fn sigchld_disposition() -> io::Result<SigchldDisposition> {
    let mut disposition = MaybeUninit::<libc::sigaction>::uninit();

    //SAFETY: we're retrieving the current disposition, signaled via null in
    //        the second parameter. `disposition` is valid
    if unsafe {
        libc::sigaction(libc::SIGCHLD, ptr::null(), disposition.as_mut_ptr())
    } == -1
    {
        return Err(io::Error::last_os_error());
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
/// [`io::Error`] corresponding to the `errno(3)` value.
pub fn reset_signal_dispositions() -> io::Result<()> {
    //SAFETY: this is a c data structure which is valid when zeroed
    let mut disposition = unsafe { mem::zeroed::<libc::sigaction>() };
    disposition.sa_sigaction = libc::SIG_DFL;

    //SAFETY: this is a valid pointer
    let _ = unsafe { libc::sigemptyset(&mut disposition.sa_mask) };

    for signal in 1..linux_general::NSIG {
        if signal == libc::SIGKILL as u32 || signal == libc::SIGSTOP as u32 {
            //NOTE: we can't handle these
            continue;
        }

        //SAFETY: the pointer is valid, rest of the arguments are as expected
        if unsafe {
            libc::sigaction(signal as ffi::c_int, &disposition, ptr::null_mut())
        } == -1
        {
            let errno = io::Error::last_os_error();

            //NOTE: ignore einval because this is being compiled in
            if errno.kind() != io::ErrorKind::InvalidInput {
                return Err(errno);
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
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Macro variant of `rustix::io::retry_on_intr` for less wonky borrow checker
/// semantics.
macro_rules! retry_on_interrupt {
    ($f:expr) => {
        loop {
            match $f {
                Err(::rustix::io::Errno::INTR) => (),
                r => break r,
            }
        }
    };
}
pub(crate) use retry_on_interrupt;

/// Macro composition of `retry_on_interrupt` and `check_if_incomplete` that
/// treats the input as having a `len` method.
macro_rules! write_checked {
    ($fd:expr, $value:expr) => {
        match $crate::platform::linux::util::retry_on_interrupt!({
            ::rustix::io::write($fd, $value)
        }) {
            Ok(n) => $crate::platform::linux::util::check_if_incomplete(
                n,
                $value.len(),
            ),
            Err(e) => Err(e.into()),
        }
    };
}
pub(crate) use write_checked;

/// Macro that writes the given value to the path under the given file
/// descriptor.
macro_rules! open_beneath_and_write {
    ($fd:expr, $path:expr, $value:expr) => {
        match $crate::platform::linux::util::retry_on_interrupt!({
            ::rustix::fs::openat2(
                $fd,
                $path,
                ::rustix::fs::OFlags::WRONLY | ::rustix::fs::OFlags::CLOEXEC,
                ::rustix::fs::Mode::empty(),
                ::rustix::fs::ResolveFlags::BENEATH
                    | ::rustix::fs::ResolveFlags::NO_MAGICLINKS
                    | ::rustix::fs::ResolveFlags::NO_SYMLINKS,
            )
        }) {
            Ok(fd) => {
                $crate::platform::linux::util::write_checked!(&fd, $value)
            }
            Err(e) => Err(e.into()),
        }
    };
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
                while let Some((current, is_synthetic)) = stack.pop()
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
    /// Preserve the file descriptor from the parent's environment.
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
) -> Result<(), Error> {
    for (fd, policy) in policy_map {
        if let FdPolicy::Fd(source_fd) = policy {
            retry_on_interrupt!({
                // SAFETY: caller has checked the validity of the policy
                if unsafe {
                    libc::syscall(
                        linux_general::__NR_dup3.into(),
                        source_fd.as_raw_fd(),
                        *fd,
                        0,
                    )
                } < 0
                {
                    //SAFETY: we're just getting a value out of this
                    let errno_location = unsafe { libc::__errno_location() };

                    //SAFETY: this is just dereferencing a location that must
                    //        exist by the linux standard base
                    Err(Errno::from_raw_os_error(unsafe { *errno_location }))
                } else {
                    Ok(())
                }
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
                libc::close_range(
                    range_start,
                    fd.saturating_sub(1),
                    libc::CLOSE_RANGE_CLOEXEC.cast_signed(),
                )
            } != 0
            {
                Err(io::Error::last_os_error())?;
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
        Err(io::Error::last_os_error())?;
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
pub fn drop_bounding_set(other_than: CapabilitySet) -> Result<(), Errno> {
    for cap in 0..MAX_LAST_CAP {
        let flag = CapabilitySet::from_bits_retain(1_u64 << cap);
        if other_than.contains(flag) {
            continue;
        }

        if let Err(e) = rustix::thread::remove_capability_from_bounding_set(flag)
            //NOTE: einval implies the capability was not known to the kernel
            && !matches!(e, Errno::INVAL)
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
pub fn set_ambient_capabilities(raise: CapabilitySet) -> Result<(), Errno> {
    for cap in 0..MAX_LAST_CAP {
        let flag = CapabilitySet::from_bits_retain(1_u64 << cap);
        if raise.contains(flag)
            && let Err(e) =
                rustix::thread::configure_capability_in_ambient_set(flag, true)
            && !matches!(e, Errno::INVAL)
        {
            return Err(e);
        }
    }
    Ok(())
}

/// Read the value of `/proc/sys/kernel/cap_last_cap`.
///
/// # Errors
///
/// This function errors if reading the value of `cap_last_cap` fails.
fn read_cap_last_cap(proc_fd: impl AsFd) -> Result<u8, Errno> {
    let cap_last_cap_fd = retry_on_interrupt!({
        rustix::fs::openat2(
            proc_fd.as_fd(),
            "sys/kernel/cap_last_cap",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH,
        )
    })?;

    //NOTE: we interpret the limit as a u8 because it's unlikely the kernel
    //      starts representing the capability bitflags as a type wider than
    //      a u256. since we fail closed, this assumption is not a problem
    let mut raw_n = [0; 4];
    let mut i = 0;

    loop {
        match rustix::io::read(
            &cap_last_cap_fd,
            raw_n.get_mut(i..).ok_or(Errno::INVAL)?,
        ) {
            Ok(0) => break,
            //NOTE: it is very unlikely we will overflow here.
            //      incomprehensibly unlikely
            Ok(n_read) => i = i.wrapping_add(n_read),
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e),
        }

        if i == raw_n.len() {
            return Err(Errno::INVAL);
        }
    }

    let n =
        u8::from_ascii(raw_n.get(..i).ok_or(Errno::INVAL)?.trim_suffix(b"\n"))
            .map_err(|_| Errno::INVAL)?;
    if <u8 as Into<u32>>::into(n) >= u64::BITS {
        return Err(Errno::INVAL);
    }
    Ok(n)
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
) -> Result<(), ChildError> {
    /// Sizes the buffer we need to use to avoid heap allocations.
    const fn size_offset_buffer() -> usize {
        signed_decimal_digits_upper_bound::<i64>()
            .saturating_add(unsigned_decimal_digits_upper_bound::<u32>())
            .saturating_add(12)
    }

    let timens_offsets_fd = retry_on_interrupt!({
        rustix::fs::openat2(
            proc_fd.as_fd(),
            "self/timens_offsets",
            OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH,
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
                rustix::io::write(
                    &timens_offsets_fd,
                    offset_buffer
                        .get(..offset)
                        .ok_or(ChildError::BufferTooSmall)?,
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
                rustix::io::write(
                    &timens_offsets_fd,
                    offset_buffer
                        .get(..offset)
                        .ok_or(ChildError::BufferTooSmall)?,
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
) -> Result<(), ChildError> {
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
        rustix::fs::openat2(
            proc_fd.as_fd(),
            "self",
            OFlags::PATH | OFlags::CLOEXEC | OFlags::DIRECTORY,
            Mode::empty(),
            ResolveFlags::BENEATH,
        )
    })?;

    let uid_map_fd = retry_on_interrupt!({
        rustix::fs::openat2(
            &proc_self_fd,
            "uid_map",
            OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH,
        )
    })?;

    write_integer(&mut uid_gid_map_buffer, &mut offset, dest_uid.as_raw())?;
    write_bytes(&mut uid_gid_map_buffer, &mut offset, b" ")?;
    write_integer(&mut uid_gid_map_buffer, &mut offset, source_uid.as_raw())?;
    write_bytes(&mut uid_gid_map_buffer, &mut offset, b" 1\n")?;

    check_if_incomplete(
        retry_on_interrupt!({
            rustix::io::write(
                &uid_map_fd,
                uid_gid_map_buffer
                    .get(..offset)
                    .ok_or(ChildError::BufferTooSmall)?,
            )
        })?,
        offset,
    )?;

    if deny_setgroups {
        let setgroups_map_fd = retry_on_interrupt!({
            rustix::fs::openat2(
                &proc_self_fd,
                "setgroups",
                OFlags::WRONLY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH,
            )
        })?;

        check_if_incomplete(
            retry_on_interrupt!({
                rustix::io::write(&setgroups_map_fd, b"deny\n")
            })?,
            5,
        )?;
    }

    let gid_map_fd = retry_on_interrupt!({
        rustix::fs::openat2(
            &proc_self_fd,
            "gid_map",
            OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH,
        )
    })?;

    offset = 0;

    write_integer(&mut uid_gid_map_buffer, &mut offset, dest_gid.as_raw())?;
    write_bytes(&mut uid_gid_map_buffer, &mut offset, b" ")?;
    write_integer(&mut uid_gid_map_buffer, &mut offset, source_gid.as_raw())?;
    write_bytes(&mut uid_gid_map_buffer, &mut offset, b" 1\n")?;

    check_if_incomplete(
        retry_on_interrupt!({
            rustix::io::write(
                &gid_map_fd,
                uid_gid_map_buffer
                    .get(..offset)
                    .ok_or(ChildError::BufferTooSmall)?,
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

/// Resolve an enumerable set of [`Mapping`]s to synthetic files, empty
/// directories, and detached mount objects.
///
/// The mappings are resolved to a given mutable vector, which must have a
/// capacity that is at least the number of mappings given to be resolved.
///
/// # Errors
///
/// This function errors if:
/// - Resolving a mount object using `resolve_path_to_mount` fails.
/// - Opening and interacting with filesystem configuration objects for a mapped
///   filesystem fails.
pub fn resolve_mappings<'a, I>(
    host_root_fd: impl AsFd,
    mappings: I,
    resolved: &mut Vec<ResolvedMount<'a>>,
) -> Result<(), ChildError>
where
    I: IntoIterator<Item = (&'a Guest, &'a Source<'a>)>,
    I::IntoIter: ExactSizeIterator,
{
    #![expect(
        clippy::panic_in_result_fn,
        reason = "we use assertions to defensively check for user error"
    )]

    let mappings = mappings.into_iter();

    assert!(
        resolved.capacity() >= mappings.len(),
        "the buffer for resolved mappings must have at least as much capacity as there are mappings"
    );

    //NOTE: could predicate this on debug. this is a bit defensive
    resolved.clear();

    for (destination, source) in mappings {
        match &source.inner {
            SourceInner::Bind(BindMount::Path {
                path,
                attributes,
                is_optional,
                is_recursive,
            }) => {
                let path_fd = match retry_on_interrupt!({
                    rustix::fs::openat2(
                        host_root_fd.as_fd(),
                        path.as_ref(),
                        OFlags::PATH | OFlags::CLOEXEC,
                        Mode::empty(),
                        ResolveFlags::IN_ROOT
                            | ResolveFlags::NO_MAGICLINKS
                            | ResolveFlags::NO_SYMLINKS,
                    )
                }) {
                    Ok(fd) => fd,
                    Err(Errno::NOENT) if *is_optional => continue,
                    e @ Err(_) => e?,
                };

                resolved.push(resolve_path_fd_to_mount(
                    path_fd.as_fd(),
                    attributes.into_mount_attr(),
                    destination,
                    *is_recursive,
                )?);
            }
            SourceInner::Bind(BindMount::Fd {
                fd,
                attributes,
                is_recursive,
            }) => {
                resolved.push(resolve_path_fd_to_mount(
                    fd.as_fd(),
                    attributes.into_mount_attr(),
                    destination,
                    *is_recursive,
                )?);
            }
            SourceInner::Procfs {
                hidepid,
                gid,
                subset,
                namespace,
                attributes,
            } => {
                let fs_fd =
                    rustix::mount::fsopen("proc", FsOpenFlags::FSOPEN_CLOEXEC)?;
                let mut buffer = itoa::Buffer::new();

                rustix::mount::fsconfig_set_string(
                    &fs_fd,
                    "hidepid",
                    match hidepid {
                        ProcHidepid::Off => "off",
                        ProcHidepid::NoAccess => "noaccess",
                        ProcHidepid::Invisible => "invisible",
                        ProcHidepid::Ptraceable => "ptraceable",
                    },
                )?;

                if let Some(gid) = gid {
                    rustix::mount::fsconfig_set_string(
                        &fs_fd,
                        "gid",
                        buffer.format(gid.as_raw()),
                    )?;
                }

                if *subset == ProcSubset::Pid {
                    rustix::mount::fsconfig_set_string(
                        &fs_fd, "subset", "pid",
                    )?;
                }

                if let ProcPidNamespace::Fd(fd) = namespace {
                    rustix::mount::fsconfig_set_fd(&fs_fd, "pidns", fd)?;
                }

                rustix::mount::fsconfig_create_exclusive(&fs_fd)?;
                resolved.push(ResolvedMount::Fd {
                    fd: rustix::mount::fsmount(
                        fs_fd,
                        FsMountFlags::FSMOUNT_CLOEXEC,
                        attributes.into_mount_attr_flags(),
                    )?,
                    destination,
                    is_directory: true,
                });
            }
            SourceInner::Mqueue { attributes } => {
                let fs_fd = rustix::mount::fsopen(
                    "mqueue",
                    FsOpenFlags::FSOPEN_CLOEXEC,
                )?;

                rustix::mount::fsconfig_create_exclusive(&fs_fd)?;
                resolved.push(ResolvedMount::Fd {
                    fd: rustix::mount::fsmount(
                        fs_fd,
                        FsMountFlags::FSMOUNT_CLOEXEC,
                        attributes.into_mount_attr_flags(),
                    )?,
                    destination,
                    is_directory: true,
                });
            }
            SourceInner::File(file) => {
                resolved.push(ResolvedMount::File { file, destination });
            }
            SourceInner::EmptyDirectory { owner, permissions } => {
                resolved.push(ResolvedMount::Directory {
                    owner: *owner,
                    permissions: *permissions,
                    destination,
                });
            }
            SourceInner::Tmpfs {
                size,
                owner,
                permissions,
                attributes,
            } => {
                let fs_fd = rustix::mount::fsopen(
                    "tmpfs",
                    FsOpenFlags::FSOPEN_CLOEXEC,
                )?;
                //let mut buffer = itoa::Buffer::new();

                if let Some(size) = size {
                    rustix::mount::fsconfig_set_string(&fs_fd, "size", size)?;
                }

                //TODO: uncomment when newuidmap/newgidmap or
                //      systemd-nsresourced is supported w/ a check prior
                /*if let Owner::Ids { user, group } = owner {
                    rustix::mount::fsconfig_set_string(
                        &fs_fd,
                        "gid",
                        buffer.format(group.as_raw()),
                    )?;
                    rustix::mount::fsconfig_set_string(
                        &fs_fd,
                        "uid",
                        buffer.format(user.as_raw()),
                    )?;
                }*/

                let mut mode = *b"0000";
                let mut permissions = permissions.bits() & 0o7777;
                for c in mode.iter_mut().rev() {
                    *c = b'0'.saturating_add((permissions & 0o7) as u8);
                    permissions >>= 3;
                }

                rustix::mount::fsconfig_set_string(
                    &fs_fd,
                    "mode",
                    mode.as_slice(),
                )?;

                rustix::mount::fsconfig_create_exclusive(&fs_fd)?;

                resolved.push(ResolvedMount::Fd {
                    fd: rustix::mount::fsmount(
                        fs_fd,
                        FsMountFlags::FSMOUNT_CLOEXEC,
                        attributes.into_mount_attr_flags(),
                    )?,
                    destination,
                    is_directory: true,
                });
            }
        }
    }

    Ok(())
}

/// Resolve a path file descriptor to a mount object.
///
/// # Errors
///
/// This function errors if opening a detached mount object for the path fails,
/// or if checking if the path was a directory fails.
pub fn resolve_path_fd_to_mount<'a, 'b>(
    path_fd: BorrowedFd<'a>,
    mount_attr_set: u32,
    destination: &'b Guest,
    is_recursive: bool,
) -> Result<ResolvedMount<'b>, ChildError> {
    let mount_attr = linux_general::mount_attr {
        attr_set: mount_attr_set.into(),
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };

    #[expect(
        clippy::cast_sign_loss,
        reason = "rustix ensures this is a valid file descriptor"
    )]
    let raw_path_fd = path_fd.as_raw_fd() as linux_general::__u64;

    let mut open_tree_flags = linux_general::OPEN_TREE_CLONE
        | linux_general::OPEN_TREE_CLOEXEC
        | linux_general::AT_EMPTY_PATH;

    if is_recursive {
        open_tree_flags |= linux_general::AT_RECURSIVE;
    }

    //SAFETY: `raw_path_fd` is valid, everything else is passed as the manpage
    //        describes
    let fd = unsafe {
        libc::syscall(
            linux_general::__NR_open_tree_attr.into(),
            raw_path_fd,
            c"".as_ptr(),
            open_tree_flags,
            &mount_attr,
            size_of::<linux_general::mount_attr>(),
        )
    };
    if fd == -1 {
        //NOTE: could probably provide better diagnostics here
        Err(io::Error::last_os_error())?;
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "see the safety comment below"
    )]
    //SAFETY: we just checked that it wasn't `-1`. since
    //        `open_tree_attr(2)` must return a valid file
    //        descriptor, this is safe
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };

    let is_directory = FileType::from_raw_mode(
        rustix::fs::statx(
            &fd,
            "",
            AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW,
            StatxFlags::TYPE,
        )?
        .stx_mode
        .into(),
    )
    .is_dir();

    Ok(ResolvedMount::Fd {
        fd,
        destination,
        is_directory,
    })
}
