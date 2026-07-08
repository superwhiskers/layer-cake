// SPDX-License-Identifier: AGPL-3.0-only

//! Linux file mode constants.

use core::ffi;
use linux_raw_sys::general as linux;

bitflags::bitflags! {
    /// Linux `mode_t` constants.
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    pub struct Mode: ffi::c_uint {
        /// Read, write and execute permissions for the owning user.
        const RWXU = linux::S_IRWXU;

        /// Read permissions for the owning user.
        const RUSR = linux::S_IRUSR;

        /// Write permissions for the owning user.
        const WUSR = linux::S_IWUSR;

        /// Execute permissions for the owning user.
        const XUSR = linux::S_IXUSR;

        /// Read, write, and execute permissions for the owning group.
        const RWXG = linux::S_IRWXG;

        /// Read permissions for the owning group.
        const RGRP = linux::S_IRGRP;

        /// Write permissions for the owning group.
        const WGRP = linux::S_IWGRP;

        /// Execute permissions for the owning group.
        const XGRP = linux::S_IXGRP;

        /// Read, write, and execute permissions for other users.
        const RWXO = linux::S_IRWXO;

        /// Read permissions for other users.
        const ROTH = linux::S_IROTH;

        /// Write permissions for other users.
        const WOTH = linux::S_IWOTH;

        /// Execute permissions for other users.
        const XOTH = linux::S_IXOTH;

        /// Change the effective user id of the calling process to the owner of
        /// the file on execute.
        const SUID = linux::S_ISUID;

        /// Change the effective group id of the calling process to the owner
        /// of the file on execute.
        const SGID = linux::S_ISGID;

        /// Files inside a directory with this bit set can be renamed or
        /// deleted only by the owner of the file, the owner of the directory,
        /// or by a privileged process.
        const SVTX = linux::S_ISVTX;
    }
}
