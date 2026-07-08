// SPDX-License-Identifier: AGPL-3.0-only

//! Allocation-free string formatting primitives.

use super::errors::{
    PostSpawnGuest as PostSpawnGuestError,
    PostSpawnGuestOther as PostSpawnGuestOtherError,
};

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
