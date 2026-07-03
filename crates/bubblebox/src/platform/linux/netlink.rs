// SPDX-License-Identifier: AGPL-3.0-only

//! Netlink interaction routines.
//!
//! These are custom-written to not require memory allocation, such that they
//! may be used in the child after `clone3(2)`.

//TODO: consider adding a timeout for receiving on the netlink socket. use poll
//      or something like that
//TODO: consider zeroing padding bytes around attributes
//TODO: consider treating `EEXIST` as success (remove `NLM_F_EXCL` flag from
//      the address setup)

use linux_raw_sys::{general as linux, net as linux_net, netlink};
use std::{ffi, os::fd::AsFd, ptr};

use super::{
    errors::{
        Netlink as NetlinkError, PostCloneGuest as PostCloneGuestError,
        PostCloneGuestOther as PostCloneGuestOtherError,
    },
    syscalls, util,
};

/// Writes an arbitrary value `T` to the buffer, incrementing `offset` by the
/// number of bytes written.
///
/// # Errors
///
/// This function errors if the write would overflow the buffer.
fn write<T>(
    buffer: &mut [u8],
    offset: &mut usize,
    value: T,
) -> Result<(), PostCloneGuestError>
where
    T: Copy,
{
    let size = size_of::<T>();

    if offset
        .checked_add(size)
        .is_none_or(|sum| sum > buffer.len())
    {
        return Err(PostCloneGuestOtherError::BufferTooSmall.into());
    }

    //SAFETY: this is in the bounds of the allocation, as checked above
    let write_offset = unsafe { buffer.as_mut_ptr().add(*offset) };

    //SAFETY: the write is contained within the buffer, as checked above
    unsafe {
        ptr::write_unaligned(write_offset.cast::<T>(), value);
    }

    // SAFETY: we just checked that it wouldn't overflow
    *offset = unsafe { offset.unchecked_add(size) };

    Ok(())
}

/// Writes bytes to the buffer, incrementing `offset` by the number of bytes
/// written.
///
/// # Errors
///
/// This function errors if the write would overflow the buffer.
fn write_bytes(
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

/// Writes an rtnetlink attribute to the buffer, incrementing `offset` by the
/// number of bytes written.
///
/// # Errors
///
/// This function errors if the write would overflow the buffer.
fn write_attribute(
    buffer: &mut [u8],
    offset: &mut usize,
    ty: u16,
    payload: &[u8],
) -> Result<(), PostCloneGuestError> {
    let length = size_of::<netlink::rtattr>() + payload.len();

    write(
        &mut *buffer,
        &mut *offset,
        netlink::rtattr {
            rta_len: length as ffi::c_ushort,
            rta_type: ty,
        },
    )?;
    write_bytes(&mut *buffer, &mut *offset, payload)?;

    //NOTE: align the offset to a 4-byte boundary
    *offset = offset
        .checked_next_multiple_of(4)
        .ok_or(PostCloneGuestOtherError::IntegerOverflow)?;

    if *offset > buffer.len() {
        return Err(PostCloneGuestOtherError::BufferTooSmall.into());
    }

    Ok(())
}

/// Finishes a netlink message by writing its header, returning the sequence
/// number of the message and the slice representing the message.
///
/// # Errors
///
/// This function errors if writing to the buffer fails, if the sequence
/// number would overflow, or if indexing the message fails.
fn finish_netlink_message<'a>(
    buffer: &'a mut [u8],
    length: usize,
    ty: u16,
    flags: u16,
    sequence: &mut u32,
) -> Result<(u32, &'a [u8]), PostCloneGuestError> {
    let mut offset = 0;

    write(
        &mut *buffer,
        &mut offset,
        netlink::nlmsghdr {
            nlmsg_len: length as ffi::c_uint,
            nlmsg_type: ty,
            nlmsg_flags: flags,
            nlmsg_seq: *sequence,
            nlmsg_pid: 0,
        },
    )?;

    let old_sequence = *sequence;
    *sequence = sequence
        .checked_add(1)
        .ok_or(PostCloneGuestOtherError::IntegerOverflow)?;

    Ok((
        old_sequence,
        buffer
            .get(..length)
            .ok_or(PostCloneGuestOtherError::BufferTooSmall)?,
    ))
}

/// Send a netlink message to the kernel.
///
/// # Errors
///
/// This function errors if `sendto(2)` fails or the number of bytes written
/// does not match the size of the message.
fn send_message(
    socket: impl AsFd,
    message: &[u8],
) -> Result<(), PostCloneGuestError> {
    util::check_if_incomplete(
        util::retry_on_interrupt!({
            syscalls::sendto_nl_kernel(&socket, message, 0)
        })?,
        message.len(),
    )?;

    Ok(())
}

/// Check for an acknowledgement a netlink message from the kernel.
///
/// # Errors
///
/// This function fails if reading from the provided socket fails, if a message
/// received is malformed or unexpected, or if an error was returned.
fn check_for_ack(
    socket: impl AsFd,
    sequence: u32,
) -> Result<(), PostCloneGuestError> {
    let mut buffer = [0; 1024];

    loop {
        let n_read = util::retry_on_interrupt!({
            syscalls::recvfrom(&socket, &mut buffer, 0)
        })?;

        let mut offset = 0;
        while offset + size_of::<netlink::nlmsghdr>() <= n_read {
            //SAFETY: we just checked that a header fits at the offset
            let header = unsafe {
                ptr::read_unaligned(
                    buffer.as_ptr().add(offset).cast::<netlink::nlmsghdr>(),
                )
            };

            let message_length = header.nlmsg_len as usize;

            if message_length < size_of::<netlink::nlmsghdr>() {
                return Err(NetlinkError::MalformedHeader.into());
            }

            if offset + message_length > n_read {
                return Err(NetlinkError::TruncatedMessage.into());
            }

            if header.nlmsg_seq != sequence {
                //NOTE: we don't anticipate sharing this link
                return Err(NetlinkError::SequenceMismatch.into());
            }

            match header.nlmsg_type as u32 {
                netlink::NLMSG_ERROR => {
                    if size_of::<netlink::nlmsghdr>()
                        + size_of::<netlink::nlmsgerr>()
                        > message_length
                    {
                        return Err(NetlinkError::IncorrectSize.into());
                    }

                    //SAFETY: we just checked that the message data fits within
                    //        the buffer
                    let error = unsafe {
                        ptr::read_unaligned(
                            buffer
                                .as_ptr()
                                .add(offset + size_of::<netlink::nlmsghdr>())
                                .cast::<netlink::nlmsgerr>(),
                        )
                    };

                    if error.error == 0 {
                        return Ok(());
                    }

                    return Err(NetlinkError::Errno(
                        syscalls::Errno::from_raw_os_error(-error.error),
                    )
                    .into());
                }
                netlink::NLMSG_DONE => {
                    return Ok(());
                }
                _ => (),
            }

            let aligned_length = message_length
                .checked_next_multiple_of(4)
                .ok_or(PostCloneGuestOtherError::IntegerOverflow)?;
            offset = offset
                .checked_add(aligned_length)
                .ok_or(PostCloneGuestOtherError::IntegerOverflow)?;
        }
    }
}

/// Write a message to the given buffer to set up the loopback address.
///
/// # Errors
///
/// This function fails if writing the message to the buffer fails.
fn write_add_loopback_address<'a>(
    buffer: &'a mut [u8],
    loopback_interface_index: ffi::c_uint,
    sequence: &mut u32,
) -> Result<(u32, &'a [u8]), PostCloneGuestError> {
    let mut offset = size_of::<netlink::nlmsghdr>();

    write(
        &mut *buffer,
        &mut offset,
        netlink::ifaddrmsg {
            ifa_family: linux_net::AF_INET as ffi::c_uchar,
            ifa_prefixlen: 8,
            ifa_flags: netlink::IFA_F_PERMANENT as ffi::c_uchar,
            ifa_scope: netlink::rt_scope_t::RT_SCOPE_HOST as ffi::c_uchar,
            ifa_index: loopback_interface_index,
        },
    )?;

    write_attribute(
        &mut *buffer,
        &mut offset,
        netlink::IFA_LOCAL as u16,
        &linux_net::INADDR_LOOPBACK.to_be_bytes(),
    )?;
    write_attribute(
        &mut *buffer,
        &mut offset,
        netlink::IFA_ADDRESS as u16,
        &linux_net::INADDR_LOOPBACK.to_be_bytes(),
    )?;

    finish_netlink_message(
        &mut *buffer,
        offset,
        netlink::RTM_NEWADDR as u16,
        (netlink::NLM_F_REQUEST
            | netlink::NLM_F_CREATE
            | netlink::NLM_F_EXCL
            | netlink::NLM_F_ACK) as u16,
        &mut *sequence,
    )
}

/// Write a message to the given buffer to bring up the loopback device.
///
/// # Errors
///
/// This function fails if writing the message to the buffer fails.
fn write_bring_up_loopback_device<'a>(
    buffer: &'a mut [u8],
    loopback_interface_index: ffi::c_uint,
    sequence: &mut u32,
) -> Result<(u32, &'a [u8]), PostCloneGuestError> {
    let mut offset = size_of::<netlink::nlmsghdr>();

    write(
        &mut *buffer,
        &mut offset,
        netlink::ifinfomsg {
            ifi_family: linux_net::AF_UNSPEC as ffi::c_uchar,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: loopback_interface_index as ffi::c_int,
            ifi_flags: linux_net::net_device_flags::IFF_UP as ffi::c_uint,
            ifi_change: linux_net::net_device_flags::IFF_UP as ffi::c_uint,
        },
    )?;

    finish_netlink_message(
        &mut *buffer,
        offset,
        netlink::RTM_NEWLINK as u16,
        (netlink::NLM_F_REQUEST | netlink::NLM_F_ACK) as u16,
        &mut *sequence,
    )
}

/// Set up the loopback interface in a network namespace.
///
/// # Errors
///
/// This returns an error if opening a netlink socket, or setting up the
/// loopback interface fails.
pub fn setup_loopback() -> Result<(), PostCloneGuestError> {
    let mut buffer = [0; 1024];
    let mut sequence = 0;

    let loopback_interface_index = {
        let temporary_socket = syscalls::socket(
            linux_net::AF_INET as i32,
            (linux_net::SOCK_DGRAM | linux::O_CLOEXEC) as i32,
            0,
        )?;
        syscalls::interface_name_to_index(&temporary_socket, c"lo")?
    };

    let rtnetlink_socket = syscalls::socket(
        linux_net::AF_NETLINK as i32,
        (linux_net::SOCK_DGRAM | linux::O_CLOEXEC) as i32,
        0,
    )?;

    let (message_sequence, message) = write_add_loopback_address(
        &mut buffer,
        loopback_interface_index,
        &mut sequence,
    )?;

    send_message(&rtnetlink_socket, message)?;
    check_for_ack(&rtnetlink_socket, message_sequence)?;

    let (message_sequence, message) = write_bring_up_loopback_device(
        &mut buffer,
        loopback_interface_index,
        &mut sequence,
    )?;

    send_message(&rtnetlink_socket, message)?;
    check_for_ack(&rtnetlink_socket, message_sequence)?;

    Ok(())
}
