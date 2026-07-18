// SPDX-License-Identifier: AGPL-3.0-only

//! `errno(3)`.
//!
//! This module implements a wrapper over the errno value returned from system
//! calls on Linux.

use core::{error, fmt};

/// Error value.
///
/// Akin to rustix, we store it negated to avoid the conversion cost from
/// syscalls.
#[derive(Eq, PartialEq, Hash, Copy, Clone)]
pub struct Errno(pub(crate) u16);

impl fmt::Debug for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let args = if let Some(name) = self.into_str() {
            format_args!("os error {} ({})", self.raw_os_error(), &*name)
        } else {
            format_args!("os error {}", self.raw_os_error())
        };
        f.debug_tuple("Errno").field(&args).finish()
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.into_str() {
            write!(f, "{name} (os error {})", self.raw_os_error())
        } else {
            write!(f, "unknown os error {}", self.raw_os_error())
        }
    }
}

impl error::Error for Errno {}

impl Errno {
    /// Extract the raw OS error number.
    #[inline]
    pub const fn raw_os_error(self) -> i32 {
        (self.0 as i16 as i32).wrapping_neg()
    }

    /// Construct an [`Errno`] from the given os error number.
    #[inline]
    pub const fn from_raw_os_error(raw: i32) -> Self {
        Self::from_errno(raw as u32)
    }

    /// Construct an [`Errno`] from a C errno.
    #[inline]
    const fn from_errno(raw: u32) -> Self {
        Self(raw.wrapping_neg() as u16)
    }
}

macro_rules! errno_variants {
    ($(($name:ident, $error:ident)),*) => {
        impl Errno {
            /// Convert this errno value into a string.
            pub fn into_str(self) -> Option<&'static str> {
                match self {
                    $(
                        e if e == Self::$name => Some(stringify!($error)),
                    )*
                    _ => None,
                }
            }

            $(errno_variants!(@constant $name, $error);)*
        }
    };
    (@constant $name:ident, $error:ident) => {
        /// `
        #[doc = stringify!($error)]
        /// `
        pub const $name: Self = Self::from_errno(linux_raw_sys::errno::$error);
    };
}

errno_variants![
    (TOOBIG, E2BIG),
    (ACCESS, EACCES),
    (ADDRINUSE, EADDRINUSE),
    (ADDRNOTAVAIL, EADDRNOTAVAIL),
    (ADV, EADV),
    (AFNOSUPPORT, EAFNOSUPPORT),
    (AGAIN, EAGAIN),
    (ALREADY, EALREADY),
    (BADE, EBADE),
    (BADF, EBADF),
    (BADFD, EBADFD),
    (BADMSG, EBADMSG),
    (BADR, EBADR),
    (BADRQC, EBADRQC),
    (BADSLT, EBADSLT),
    (BFONT, EBFONT),
    (BUSY, EBUSY),
    (CANCELED, ECANCELED),
    (CHILD, ECHILD),
    (CHRNG, ECHRNG),
    (COMM, ECOMM),
    (CONNABORTED, ECONNABORTED),
    (CONNREFUSED, ECONNREFUSED),
    (CONNRESET, ECONNRESET),
    (DEADLK, EDEADLK),
    (DEADLOCK, EDEADLOCK),
    (DESTADDRREQ, EDESTADDRREQ),
    (DOM, EDOM),
    (DOTDOT, EDOTDOT),
    (DQUOT, EDQUOT),
    (EXIST, EEXIST),
    (FAULT, EFAULT),
    (FBIG, EFBIG),
    (HOSTDOWN, EHOSTDOWN),
    (HOSTUNREACH, EHOSTUNREACH),
    (HWPOISON, EHWPOISON),
    (IDRM, EIDRM),
    (ILSEQ, EILSEQ),
    (INPROGRESS, EINPROGRESS),
    (INTR, EINTR),
    (INVAL, EINVAL),
    (IO, EIO),
    (ISCONN, EISCONN),
    (ISDIR, EISDIR),
    (ISNAM, EISNAM),
    (KEYEXPIRED, EKEYEXPIRED),
    (KEYREJECTED, EKEYREJECTED),
    (KEYREVOKED, EKEYREVOKED),
    (L2HLT, EL2HLT),
    (L2NSYNC, EL2NSYNC),
    (L3HLT, EL3HLT),
    (L3RST, EL3RST),
    (LIBACC, ELIBACC),
    (LIBBAD, ELIBBAD),
    (LIBEXEC, ELIBEXEC),
    (LIBMAX, ELIBMAX),
    (LIBSCN, ELIBSCN),
    (LNRNG, ELNRNG),
    (LOOP, ELOOP),
    (MEDIUMTYPE, EMEDIUMTYPE),
    (MFILE, EMFILE),
    (MLINK, EMLINK),
    (MSGSIZE, EMSGSIZE),
    (MULTIHOP, EMULTIHOP),
    (NAMETOOLONG, ENAMETOOLONG),
    (NAVAIL, ENAVAIL),
    (NETDOWN, ENETDOWN),
    (NETRESET, ENETRESET),
    (NETUNREACH, ENETUNREACH),
    (NFILE, ENFILE),
    (NOANO, ENOANO),
    (NOBUFS, ENOBUFS),
    (NOCSI, ENOCSI),
    (NODATA, ENODATA),
    (NODEV, ENODEV),
    (NOENT, ENOENT),
    (NOEXEC, ENOEXEC),
    (NOKEY, ENOKEY),
    (NOLCK, ENOLCK),
    (NOLINK, ENOLINK),
    (NOMEDIUM, ENOMEDIUM),
    (NOMEM, ENOMEM),
    (NOMSG, ENOMSG),
    (NONET, ENONET),
    (NOPKG, ENOPKG),
    (NOPROTOOPT, ENOPROTOOPT),
    (NOSPC, ENOSPC),
    (NOSR, ENOSR),
    (NOSTR, ENOSTR),
    (NOSYS, ENOSYS),
    (NOTBLK, ENOTBLK),
    (NOTCONN, ENOTCONN),
    (NOTDIR, ENOTDIR),
    (NOTEMPTY, ENOTEMPTY),
    (NOTNAM, ENOTNAM),
    (NOTRECOVERABLE, ENOTRECOVERABLE),
    (NOTSOCK, ENOTSOCK),
    (NOTTY, ENOTTY),
    (NOTUNIQ, ENOTUNIQ),
    (NXIO, ENXIO),
    (OPNOTSUPP, EOPNOTSUPP),
    (OVERFLOW, EOVERFLOW),
    (OWNERDEAD, EOWNERDEAD),
    (PERM, EPERM),
    (PFNOSUPPORT, EPFNOSUPPORT),
    (PIPE, EPIPE),
    (PROTO, EPROTO),
    (PROTONOSUPPORT, EPROTONOSUPPORT),
    (PROTOTYPE, EPROTOTYPE),
    (RANGE, ERANGE),
    (REMCHG, EREMCHG),
    (REMOTE, EREMOTE),
    (REMOTEIO, EREMOTEIO),
    (RESTART, ERESTART),
    (RFKILL, ERFKILL),
    (ROFS, EROFS),
    (SHUTDOWN, ESHUTDOWN),
    (SOCKTNOSUPPORT, ESOCKTNOSUPPORT),
    (SPIPE, ESPIPE),
    (SRCH, ESRCH),
    (SRMNT, ESRMNT),
    (STALE, ESTALE),
    (STRPIPE, ESTRPIPE),
    (TIME, ETIME),
    (TIMEDOUT, ETIMEDOUT),
    (TOOMANYREFS, ETOOMANYREFS),
    (TXTBSY, ETXTBSY),
    (UCLEAN, EUCLEAN),
    (UNATCH, EUNATCH),
    (USERS, EUSERS),
    (WOULDBLOCK, EWOULDBLOCK),
    (XDEV, EXDEV),
    (XFULL, EXFULL)
];
