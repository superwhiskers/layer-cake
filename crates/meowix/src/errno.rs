// SPDX-License-Identifier: AGPL-3.0-only

//! `errno(3)`.
//!
//! This module implements a wrapper over the errno value returned from system
//! calls on Linux.

use core::fmt;

/// Error value.
///
/// Akin to rustix, we store it negated to avoid the conversion cost from
/// syscalls.
#[derive(Eq, PartialEq, Hash, Copy, Clone)]
pub struct Errno(u16);

impl fmt::Debug for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Errno")
            .field(&format_args!("os error {}", self.raw_os_error()))
            .finish()
    }
}

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

macro_rules! errno_associated_const {
    ($name:ident, $error:ident) => {
        /// `
        #[doc = stringify!($error)]
        /// `
        pub const $name: Self = Self::from_errno(linux_raw_sys::errno::$error);
    };
}

impl Errno {
    errno_associated_const!(TOOBIG, E2BIG);
    errno_associated_const!(ACCESS, EACCES);
    errno_associated_const!(ADDRINUSE, EADDRINUSE);
    errno_associated_const!(ADDRNOTAVAIL, EADDRNOTAVAIL);
    errno_associated_const!(ADV, EADV);
    errno_associated_const!(AFNOSUPPORT, EAFNOSUPPORT);
    errno_associated_const!(AGAIN, EAGAIN);
    errno_associated_const!(ALREADY, EALREADY);
    errno_associated_const!(BADE, EBADE);
    errno_associated_const!(BADF, EBADF);
    errno_associated_const!(BADFD, EBADFD);
    errno_associated_const!(BADMSG, EBADMSG);
    errno_associated_const!(BADR, EBADR);
    errno_associated_const!(BADRQC, EBADRQC);
    errno_associated_const!(BADSLT, EBADSLT);
    errno_associated_const!(BFONT, EBFONT);
    errno_associated_const!(BUSY, EBUSY);
    errno_associated_const!(CANCELED, ECANCELED);
    errno_associated_const!(CHILD, ECHILD);
    errno_associated_const!(CHRNG, ECHRNG);
    errno_associated_const!(COMM, ECOMM);
    errno_associated_const!(CONNABORTED, ECONNABORTED);
    errno_associated_const!(CONNREFUSED, ECONNREFUSED);
    errno_associated_const!(CONNRESET, ECONNRESET);
    errno_associated_const!(DEADLK, EDEADLK);
    errno_associated_const!(DEADLOCK, EDEADLOCK);
    errno_associated_const!(DESTADDRREQ, EDESTADDRREQ);
    errno_associated_const!(DOM, EDOM);
    errno_associated_const!(DOTDOT, EDOTDOT);
    errno_associated_const!(DQUOT, EDQUOT);
    errno_associated_const!(EXIST, EEXIST);
    errno_associated_const!(FAULT, EFAULT);
    errno_associated_const!(FBIG, EFBIG);
    errno_associated_const!(HOSTDOWN, EHOSTDOWN);
    errno_associated_const!(HOSTUNREACH, EHOSTUNREACH);
    errno_associated_const!(HWPOISON, EHWPOISON);
    errno_associated_const!(IDRM, EIDRM);
    errno_associated_const!(ILSEQ, EILSEQ);
    errno_associated_const!(INPROGRESS, EINPROGRESS);
    errno_associated_const!(INTR, EINTR);
    errno_associated_const!(INVAL, EINVAL);
    errno_associated_const!(IO, EIO);
    errno_associated_const!(ISCONN, EISCONN);
    errno_associated_const!(ISDIR, EISDIR);
    errno_associated_const!(ISNAM, EISNAM);
    errno_associated_const!(KEYEXPIRED, EKEYEXPIRED);
    errno_associated_const!(KEYREJECTED, EKEYREJECTED);
    errno_associated_const!(KEYREVOKED, EKEYREVOKED);
    errno_associated_const!(L2HLT, EL2HLT);
    errno_associated_const!(L2NSYNC, EL2NSYNC);
    errno_associated_const!(L3HLT, EL3HLT);
    errno_associated_const!(L3RST, EL3RST);
    errno_associated_const!(LIBACC, ELIBACC);
    errno_associated_const!(LIBBAD, ELIBBAD);
    errno_associated_const!(LIBEXEC, ELIBEXEC);
    errno_associated_const!(LIBMAX, ELIBMAX);
    errno_associated_const!(LIBSCN, ELIBSCN);
    errno_associated_const!(LNRNG, ELNRNG);
    errno_associated_const!(LOOP, ELOOP);
    errno_associated_const!(MEDIUMTYPE, EMEDIUMTYPE);
    errno_associated_const!(MFILE, EMFILE);
    errno_associated_const!(MLINK, EMLINK);
    errno_associated_const!(MSGSIZE, EMSGSIZE);
    errno_associated_const!(MULTIHOP, EMULTIHOP);
    errno_associated_const!(NAMETOOLONG, ENAMETOOLONG);
    errno_associated_const!(NAVAIL, ENAVAIL);
    errno_associated_const!(NETDOWN, ENETDOWN);
    errno_associated_const!(NETRESET, ENETRESET);
    errno_associated_const!(NETUNREACH, ENETUNREACH);
    errno_associated_const!(NFILE, ENFILE);
    errno_associated_const!(NOANO, ENOANO);
    errno_associated_const!(NOBUFS, ENOBUFS);
    errno_associated_const!(NOCSI, ENOCSI);
    errno_associated_const!(NODATA, ENODATA);
    errno_associated_const!(NODEV, ENODEV);
    errno_associated_const!(NOENT, ENOENT);
    errno_associated_const!(NOEXEC, ENOEXEC);
    errno_associated_const!(NOKEY, ENOKEY);
    errno_associated_const!(NOLCK, ENOLCK);
    errno_associated_const!(NOLINK, ENOLINK);
    errno_associated_const!(NOMEDIUM, ENOMEDIUM);
    errno_associated_const!(NOMEM, ENOMEM);
    errno_associated_const!(NOMSG, ENOMSG);
    errno_associated_const!(NONET, ENONET);
    errno_associated_const!(NOPKG, ENOPKG);
    errno_associated_const!(NOPROTOOPT, ENOPROTOOPT);
    errno_associated_const!(NOSPC, ENOSPC);
    errno_associated_const!(NOSR, ENOSR);
    errno_associated_const!(NOSTR, ENOSTR);
    errno_associated_const!(NOSYS, ENOSYS);
    errno_associated_const!(NOTBLK, ENOTBLK);
    errno_associated_const!(NOTCONN, ENOTCONN);
    errno_associated_const!(NOTDIR, ENOTDIR);
    errno_associated_const!(NOTEMPTY, ENOTEMPTY);
    errno_associated_const!(NOTNAM, ENOTNAM);
    errno_associated_const!(NOTRECOVERABLE, ENOTRECOVERABLE);
    errno_associated_const!(NOTSOCK, ENOTSOCK);
    errno_associated_const!(NOTTY, ENOTTY);
    errno_associated_const!(NOTUNIQ, ENOTUNIQ);
    errno_associated_const!(NXIO, ENXIO);
    errno_associated_const!(OPNOTSUPP, EOPNOTSUPP);
    errno_associated_const!(OVERFLOW, EOVERFLOW);
    errno_associated_const!(OWNERDEAD, EOWNERDEAD);
    errno_associated_const!(PERM, EPERM);
    errno_associated_const!(PFNOSUPPORT, EPFNOSUPPORT);
    errno_associated_const!(PIPE, EPIPE);
    errno_associated_const!(PROTO, EPROTO);
    errno_associated_const!(PROTONOSUPPORT, EPROTONOSUPPORT);
    errno_associated_const!(PROTOTYPE, EPROTOTYPE);
    errno_associated_const!(RANGE, ERANGE);
    errno_associated_const!(REMCHG, EREMCHG);
    errno_associated_const!(REMOTE, EREMOTE);
    errno_associated_const!(REMOTEIO, EREMOTEIO);
    errno_associated_const!(RESTART, ERESTART);
    errno_associated_const!(RFKILL, ERFKILL);
    errno_associated_const!(ROFS, EROFS);
    errno_associated_const!(SHUTDOWN, ESHUTDOWN);
    errno_associated_const!(SOCKTNOSUPPORT, ESOCKTNOSUPPORT);
    errno_associated_const!(SPIPE, ESPIPE);
    errno_associated_const!(SRCH, ESRCH);
    errno_associated_const!(SRMNT, ESRMNT);
    errno_associated_const!(STALE, ESTALE);
    errno_associated_const!(STRPIPE, ESTRPIPE);
    errno_associated_const!(TIME, ETIME);
    errno_associated_const!(TIMEDOUT, ETIMEDOUT);
    errno_associated_const!(TOOMANYREFS, ETOOMANYREFS);
    errno_associated_const!(TXTBSY, ETXTBSY);
    errno_associated_const!(UCLEAN, EUCLEAN);
    errno_associated_const!(UNATCH, EUNATCH);
    errno_associated_const!(USERS, EUSERS);
    errno_associated_const!(WOULDBLOCK, EWOULDBLOCK);
    errno_associated_const!(XDEV, EXDEV);
    errno_associated_const!(XFULL, EXFULL);
}
