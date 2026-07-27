// SPDX-License-Identifier: AGPL-3.0-only

//! Allocation-free namespace configuration.

use core::cmp;
use linux_raw_sys::general as linux;
use meowix::{
    fd::AsFd,
    ids::{Gid, RawGid, RawUid, Uid},
    open_beneath_and_write, retry_on_interrupt, syscalls, write_checked,
};

use super::{
    super::policy::namespace::TimeOffset,
    errors::{
        PostSpawnGuest as PostSpawnGuestError,
        PostSpawnGuestOther as PostSpawnGuestOtherError,
    },
    fmt,
};

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
) -> Result<(), PostSpawnGuestError> {
    /// Sizes the buffer we need to use to avoid heap allocations.
    const fn size_offset_buffer() -> usize {
        fmt::signed_decimal_digits_upper_bound::<i64>()
            .saturating_add(fmt::unsigned_decimal_digits_upper_bound::<u32>())
            .saturating_add(11)
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
        fmt::write_bytes(&mut offset_buffer, &mut offset, b"monotonic ")?;
        fmt::write_integer(
            &mut offset_buffer,
            &mut offset,
            monotonic_offset.seconds.into_raw(),
        )?;
        fmt::write_bytes(&mut offset_buffer, &mut offset, b" ")?;
        fmt::write_integer(
            &mut offset_buffer,
            &mut offset,
            monotonic_offset.nanoseconds.into_raw(),
        )?;

        write_checked!(
            &timens_offsets_fd,
            offset_buffer
                .get(..offset)
                .ok_or(PostSpawnGuestOtherError::BufferTooSmall)?
        );
    }

    if let Some(boottime_offset) = boottime_offset {
        offset = 0;
        fmt::write_bytes(&mut offset_buffer, &mut offset, b"boottime ")?;
        fmt::write_integer(
            &mut offset_buffer,
            &mut offset,
            boottime_offset.seconds.into_raw(),
        )?;
        fmt::write_bytes(&mut offset_buffer, &mut offset, b" ")?;
        fmt::write_integer(
            &mut offset_buffer,
            &mut offset,
            boottime_offset.nanoseconds.into_raw(),
        )?;

        write_checked!(
            &timens_offsets_fd,
            offset_buffer
                .get(..offset)
                .ok_or(PostSpawnGuestOtherError::BufferTooSmall)?
        );
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
) -> Result<(), PostSpawnGuestError> {
    /// Sizes the buffer we need to use to avoid heap allocations.
    ///
    /// This is computed from the two ids we need, the two spaces separating
    /// the ids and the size of the mapping and the single `1`.
    const fn size_uid_gid_map_buffer<T>() -> usize {
        2_usize
            .saturating_mul(fmt::unsigned_decimal_digits_upper_bound::<T>())
            .saturating_add(3)
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

    fmt::write_integer(
        &mut uid_gid_map_buffer,
        &mut offset,
        dest_uid.into_raw(),
    )?;
    fmt::write_bytes(&mut uid_gid_map_buffer, &mut offset, b" ")?;
    fmt::write_integer(
        &mut uid_gid_map_buffer,
        &mut offset,
        source_uid.into_raw(),
    )?;
    fmt::write_bytes(&mut uid_gid_map_buffer, &mut offset, b" 1")?;

    open_beneath_and_write!(
        &proc_self_fd,
        c"uid_map",
        uid_gid_map_buffer
            .get(..offset)
            .ok_or(PostSpawnGuestOtherError::BufferTooSmall)?
    );

    if deny_setgroups {
        open_beneath_and_write!(&proc_self_fd, c"setgroups", b"deny");
    }

    offset = 0;

    fmt::write_integer(
        &mut uid_gid_map_buffer,
        &mut offset,
        dest_gid.into_raw(),
    )?;
    fmt::write_bytes(&mut uid_gid_map_buffer, &mut offset, b" ")?;
    fmt::write_integer(
        &mut uid_gid_map_buffer,
        &mut offset,
        source_gid.into_raw(),
    )?;
    fmt::write_bytes(&mut uid_gid_map_buffer, &mut offset, b" 1")?;

    open_beneath_and_write!(
        &proc_self_fd,
        c"gid_map",
        uid_gid_map_buffer
            .get(..offset)
            .ok_or(PostSpawnGuestOtherError::BufferTooSmall)?
    );

    Ok(())
}
