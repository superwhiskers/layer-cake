// SPDX-License-Identifier: AGPL-3.0-only

//! Wire error type used to communicate with the host process from the guest.

use meowix::errors::Netlink;

use super::errors::PostSpawnGuest;

/// Simplified post-spawn guest error type for the wire format.
#[derive(Copy, Clone, Debug, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C, packed)]
pub struct PostSpawnGuestWire {
    /// Which of the enum variants this corresponds to.
    pub(super) tag: u8,

    /// If `tag` referred to a variant which contains another enum, which
    /// variant of that enum this corresponds to.
    pub(super) subtag: u8,

    /// If `tag` or `subtag` referred to a variant which contains a value, the
    /// value contained within that variant.
    pub(super) value: i32,
}

impl From<Result<(), PostSpawnGuest>> for PostSpawnGuestWire {
    fn from(value: Result<(), PostSpawnGuest>) -> Self {
        match value {
            Ok(()) => PostSpawnGuestWire {
                tag: u8::MAX,
                subtag: 0,
                value: 0,
            },
            Err(PostSpawnGuest::Syscall(error)) => PostSpawnGuestWire {
                tag: u8::MAX - 1,
                subtag: error.syscall() as u8,
                value: error.error().raw_os_error(),
            },
            Err(PostSpawnGuest::Netlink(netlink_error)) => {
                let (subtag, value) = match netlink_error {
                    Netlink::MalformedHeader => (0, 1),
                    Netlink::TruncatedMessage => (0, 2),
                    Netlink::SequenceMismatch => (0, 3),
                    Netlink::IncorrectSize => (0, 4),
                    Netlink::BufferTooSmall => (0, 5),
                    Netlink::IntegerOverflow => (0, 6),
                    Netlink::IncompleteWrite => (0, 7),
                    Netlink::Errno(error) => (u8::MAX, error.raw_os_error()),
                    Netlink::Syscall(error) => {
                        (error.syscall() as u8, error.error().raw_os_error())
                    }
                    //NOTE: this should be sufficient to always result in an
                    //      invalid error
                    _ => (0, i32::MAX),
                };

                PostSpawnGuestWire {
                    tag: u8::MAX - 2,
                    subtag,
                    value,
                }
            }
            Err(PostSpawnGuest::IncompleteWrite) => PostSpawnGuestWire {
                tag: u8::MAX - 3,
                subtag: 0,
                value: 0,
            },
            Err(PostSpawnGuest::CStrBufferTooSmall) => PostSpawnGuestWire {
                tag: u8::MAX - 4,
                subtag: 0,
                value: 0,
            },
            Err(PostSpawnGuest::FromBytesWithNulError) => PostSpawnGuestWire {
                tag: u8::MAX - 5,
                subtag: 0,
                value: 0,
            },
            //NOTE: we don't need to handle this in the parse step because any
            //      unrecognized tag gets parsed as this
            Err(PostSpawnGuest::InvalidWireFormat) => PostSpawnGuestWire {
                tag: u8::MAX - 6,
                subtag: 0,
                value: 0,
            },
            Err(PostSpawnGuest::Other(e)) => {
                //NOTE: this is okay as long as we don't come into contact with
                //      the other end
                PostSpawnGuestWire {
                    tag: e as u8,
                    subtag: 0,
                    value: 0,
                }
            }
        }
    }
}
