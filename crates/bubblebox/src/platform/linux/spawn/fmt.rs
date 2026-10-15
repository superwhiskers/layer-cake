// SPDX-License-Identifier: AGPL-3.0-only

//! Allocation-free string formatting primitives.

use super::errors::{
    PostSpawnGuest as PostSpawnGuestError,
    PostSpawnGuestOther as PostSpawnGuestOtherError,
};

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
) -> Result<(), PostSpawnGuestError> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or(PostSpawnGuestOtherError::BufferTooSmall)?;
    let destination = buffer
        .get_mut(*offset..end)
        .ok_or(PostSpawnGuestOtherError::BufferTooSmall)?;
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
) -> Result<(), PostSpawnGuestError> {
    let mut intermediary = itoa::Buffer::new();
    write_bytes(buffer, offset, intermediary.format(integer).as_bytes())
}
