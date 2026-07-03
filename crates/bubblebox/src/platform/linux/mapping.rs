// SPDX-License-Identifier: AGPL-3.0-only

//! Sandbox mapping realization.

//NOTE: should take a look at bwrap once more to see what it exposes by
//      default from /dev. relevant for elsewhere in the linux platform module
//TODO: write a function that inspects an elf binary and derives mappings for
//      shared libraries it relies upon in addition to itself
//TODO: `*_with_owner` methods are disabled until systemd-nsresourced or
//      newuidmap/newgidmap are supported

use linux_raw_sys::general as linux;
use std::{
    ffi::{self, OsStr},
    os::fd::BorrowedFd,
};

use super::{
    path::{HostDirectoryRef, HostFileRef},
    syscalls::Gid,
};

//FIXME: i don't think this belongs here but i'll leave it here for now
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

        //NOTE: unlikely that anyone needs this but here it is
        const _ = !0;
    }
}

/// Source of a mapping.
#[derive(Clone, Debug)]
pub struct Source<'fd> {
    /// The mapping's source.
    pub(crate) inner: SourceInner<'fd>,
}

impl<'fd> Source<'fd> {
    #![expect(
        clippy::missing_const_for_fn,
        reason = "constructors taking BorrowedFd, Uid, or Gid are intentionally non-const"
    )]

    /// Create a new source from the given inner value.
    const fn new(inner: SourceInner<'fd>) -> Self {
        Self { inner }
    }

    /// Indicates if the source is synthetic or not.
    pub const fn is_synthetic(&self) -> bool {
        let Self { inner } = self;
        !matches!(inner, SourceInner::Bind(_))
    }

    /// Read-only mapping of a file from the host to the guest, preserving
    /// ownership and permissions.
    #[must_use]
    pub fn read_only_file(fd: HostFileRef<'fd>) -> Self {
        let (dirfd, name, fd) = fd.into_parts();
        Self::new(SourceInner::Bind(BindMount::File {
            dirfd,
            name,
            fd,
            attributes: MountAttributes {
                read_only: true,
                no_setuid: true,
                no_devices: true,
                no_execution: false,
                no_symlink_following: false,
            },
        }))
    }

    /// Read-write mapping of a file from the host to the guest, preserving
    /// ownership and permissions.
    #[must_use]
    pub fn read_write_file(fd: HostFileRef<'fd>) -> Self {
        let (dirfd, name, fd) = fd.into_parts();
        Self::new(SourceInner::Bind(BindMount::File {
            dirfd,
            name,
            fd,
            attributes: MountAttributes {
                read_only: false,
                no_setuid: true,
                no_devices: true,
                no_execution: false,
                no_symlink_following: false,
            },
        }))
    }

    /// Read-write mapping of a device file from the host to the guest,
    /// preserving ownership and permissions.
    #[must_use]
    pub fn device_file(fd: HostFileRef<'fd>) -> Self {
        let (dirfd, name, fd) = fd.into_parts();
        Self::new(SourceInner::Bind(BindMount::File {
            dirfd,
            name,
            fd,
            attributes: MountAttributes {
                read_only: false,
                no_setuid: true,
                no_devices: false,
                no_execution: false,
                no_symlink_following: false,
            },
        }))
    }

    /// Mapping of a file from the host to the guest, preserving ownership and
    /// permissions.
    #[must_use]
    pub fn bind_file(
        fd: HostFileRef<'fd>,
        attributes: MountAttributes,
    ) -> Self {
        let (dirfd, name, fd) = fd.into_parts();
        Self::new(SourceInner::Bind(BindMount::File {
            dirfd,
            name,
            fd,
            attributes,
        }))
    }

    /// Read-only mapping of a directory from the host to the guest, preserving
    /// ownership and permissions.
    #[must_use]
    pub fn read_only_directory(fd: HostDirectoryRef<'fd>) -> Self {
        Self::new(SourceInner::Bind(BindMount::Directory {
            fd: fd.into_fd(),
            attributes: MountAttributes {
                read_only: true,
                no_setuid: true,
                no_devices: true,
                no_execution: false,
                no_symlink_following: false,
            },
            is_recursive: false,
        }))
    }

    /// Read-write mapping of a directory from the host to the guest, preserving
    /// ownership and permissions.
    #[must_use]
    pub fn read_write_directory(fd: HostDirectoryRef<'fd>) -> Self {
        Self::new(SourceInner::Bind(BindMount::Directory {
            fd: fd.into_fd(),
            attributes: MountAttributes {
                read_only: false,
                no_setuid: true,
                no_devices: true,
                no_execution: false,
                no_symlink_following: false,
            },
            is_recursive: false,
        }))
    }

    /// Mapping of a directory from the host to the guest, preserving ownership
    /// and permissions.
    #[must_use]
    pub fn bind_directory(
        fd: HostDirectoryRef<'fd>,
        attributes: MountAttributes,
        is_recursive: bool,
    ) -> Self {
        Self::new(SourceInner::Bind(BindMount::Directory {
            fd: fd.into_fd(),
            attributes,
            is_recursive,
        }))
    }

    /// Mapping of `proc(5)` to the given path on the guest with the pid
    /// namespace of the guest.
    #[must_use]
    pub const fn proc(hidepid: ProcHidepid, subset: ProcSubset) -> Self {
        Self::new(SourceInner::Procfs {
            hidepid,
            gid: None,
            subset,
            namespace: ProcPidNamespace::Guest,
            attributes: MountAttributes {
                read_only: false,
                no_setuid: true,
                no_devices: true,
                no_execution: true,
                no_symlink_following: false,
            },
        })
    }

    /// Mapping of `proc(5)` to the given path on the guest with the pid
    /// namespace referred to by the specified [`BorrowedFd`].
    #[must_use]
    pub fn proc_with_pid_namespace(
        hidepid: ProcHidepid,
        subset: ProcSubset,
        namespace: BorrowedFd<'fd>,
    ) -> Self {
        Self::new(SourceInner::Procfs {
            hidepid,
            gid: None,
            subset,
            namespace: ProcPidNamespace::Fd(namespace),
            attributes: MountAttributes {
                read_only: false,
                no_setuid: true,
                no_devices: true,
                no_execution: true,
                no_symlink_following: false,
            },
        })
    }

    /// Mapping of `proc(5)` with the guest's pid namespace to the given path
    /// on the guest with the specified [`Gid`] allowed full process
    /// information regardless of the [`ProcHidepid`] setting.
    #[must_use]
    pub fn proc_with_privileged_gid(
        hidepid: ProcHidepid,
        gid: Gid,
        subset: ProcSubset,
    ) -> Self {
        Self::new(SourceInner::Procfs {
            hidepid,
            gid: Some(gid),
            subset,
            namespace: ProcPidNamespace::Guest,
            attributes: MountAttributes {
                read_only: false,
                no_setuid: true,
                no_devices: true,
                no_execution: true,
                no_symlink_following: false,
            },
        })
    }

    /// Mapping of `proc(5)` with the pid namespace of the specified
    /// [`BorrowedFd`] to the given path on the guest with the specified
    /// [`Gid`] allowed full process information regardless of the
    /// [`ProcHidepid`] setting.
    #[must_use]
    pub fn proc_with_privileged_gid_and_pid_namespace(
        hidepid: ProcHidepid,
        gid: Gid,
        subset: ProcSubset,
        namespace: BorrowedFd<'fd>,
    ) -> Self {
        Self::new(SourceInner::Procfs {
            hidepid,
            gid: Some(gid),
            subset,
            namespace: ProcPidNamespace::Fd(namespace),
            attributes: MountAttributes {
                read_only: false,
                no_setuid: true,
                no_devices: true,
                no_execution: true,
                no_symlink_following: false,
            },
        })
    }

    /// Mapping of an mqueue filesystem to the given path on the guest.
    #[must_use]
    pub const fn mqueue() -> Self {
        Self::new(SourceInner::Mqueue {
            attributes: MountAttributes {
                read_only: false,
                no_setuid: true,
                no_devices: true,
                no_execution: true,
                no_symlink_following: false,
            },
        })
    }

    /// Mapping of the contents of a file to a given path on the guest.
    ///
    /// The materialized file will be owned by the user and group specified in
    /// the policy for the sandboxed process.
    ///
    /// This method is intended primarily for small synthetic files.
    #[must_use]
    pub fn file(contents: impl Into<Vec<u8>>, permissions: Mode) -> Self {
        Self::new(SourceInner::File(File {
            contents: contents.into(),
            owner: Owner::User,
            permissions,
        }))
    }

    /*
    /// Mapping of the contents of a file to a given path on the guest with
    /// the specified owner.
    ///
    /// This method is intended primarily for small synthetic files.
    #[must_use]
    pub fn file_with_owner(
        contents: impl Into<Vec<u8>>,
        user: Uid,
        group: Gid,
        permissions: Mode,
    ) -> Self {
        Self::new(SourceInner::File(File {
            contents: contents.into(),
            owner: Owner::Ids { user, group },
            permissions,
        }))
    }
    */

    /// Mapping of an empty directory to a given path on the guest.
    ///
    /// The materialized directory will be owned by the user and group
    /// specified in the policy for the sandboxed process.
    #[must_use]
    pub const fn directory(permissions: Mode) -> Self {
        Self::new(SourceInner::EmptyDirectory {
            owner: Owner::User,
            permissions,
        })
    }

    /*
    /// Mapping of an empty directory to a given path on the guest with the
    /// specified owner.
    #[must_use]
    pub fn directory_with_owner(
        user: Uid,
        group: Gid,
        permissions: Mode,
        destination: Guest,
    ) -> Self {
        Self::new(SourceInner::EmptyDirectory {
            owner: Owner::Ids { user, group },
            permissions,
        })
    }
    */

    /// Mapping of a tmpfs mount to a given path on the guest.
    ///
    /// The mount will be owned by the user and group specified in the policy
    /// for the sandboxed process.
    #[must_use]
    pub const fn tmpfs(
        //FIXME: just pass in a proper enum for the size
        size: Option<String>,
        permissions: Mode,
    ) -> Self {
        Self::new(SourceInner::Tmpfs {
            size,
            owner: Owner::User,
            permissions,
            attributes: MountAttributes {
                read_only: false,
                no_setuid: true,
                no_devices: true,
                no_execution: false,
                no_symlink_following: false,
            },
        })
    }

    /*
    /// Mapping of a tmpfs mount to a given path on the guest with the
    /// specified owner.
    #[must_use]
    pub fn tmpfs_with_owner(
        size: Option<u64>,
        user: Uid,
        group: Gid,
        permissions: Mode,
    ) -> Self {
        Self::new(SourceInner::Tmpfs {
            size,
            owner: Owner::Ids { user, group },
            permissions,
        })
    }
    */
}

/// Source of a mapping.
//TODO: maybe add a "don't create the destination" flag to bind mounts to
//      give the user the option to make it themselves
#[non_exhaustive]
#[derive(Clone, Debug)]
pub(crate) enum SourceInner<'fd> {
    /// A bind-mount sourced from the host.
    ///
    /// Preserves the permissions and ownership of the source.
    Bind(BindMount<'fd>),

    /// `proc(5)` filesystem mount.
    Procfs {
        /// Which information about other processes to hide from a calling
        /// process.
        hidepid: ProcHidepid,

        /// [`Gid`] to allow full process information to regardless of
        /// [`ProcHidepid`] setting.
        gid: Option<Gid>,

        /// Subset of procfs to expose.
        subset: ProcSubset,

        /// Pid namespace for the procfs to use to translate pids.
        namespace: ProcPidNamespace<'fd>,

        /// Attributes to apply to the mount.
        attributes: MountAttributes,
    },

    /// Mqueue mount.
    Mqueue {
        /// Attributes to apply to the mount.
        attributes: MountAttributes,
    },

    /// Mapping sourced from the contents of a file.
    File(File),

    /// Empty directory mapping.
    EmptyDirectory {
        /// Owner of the directory.
        owner: Owner,

        /// Permissions applied to the directory.
        permissions: Mode,
    },

    /// Tmpfs mount.
    Tmpfs {
        /// The size to bound the ephemeral directory by.
        size: Option<String>,

        /// Owner of the directory.
        owner: Owner,

        /// Permissions applied to the directory.
        permissions: Mode,

        /// Attributes to apply to the mount.
        attributes: MountAttributes,
    },
}

/// Mapping sourced from the contents of a file.
///
/// This struct is used to single out synthetic file mappings as they must be
/// handled separately from every other kind of mapping.
#[derive(Clone, Debug)]
pub(crate) struct File {
    /// Byte contents of the file.
    pub(crate) contents: Vec<u8>,

    /// Owner of the file.
    pub(crate) owner: Owner,

    /// Permissions applied to the file.
    pub(crate) permissions: Mode,
}

/// Mapping using a bind mount from the host.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub(crate) enum BindMount<'fd> {
    /// Bind mount of a file.
    File {
        /// File descriptor representing the parent directory of the file to
        /// mount within the guest.
        dirfd: BorrowedFd<'fd>,

        /// Name of the file underneath the dirfd to mount within the guest.
        name: &'fd OsStr,

        /// File descriptor representing the file to mount within the guest.
        ///
        /// This is used to verify that we actually mounted the intended file
        /// after the mount has been moved to the guest, not to mount it.
        fd: BorrowedFd<'fd>,

        /// Attributes to bind-mount the path with.
        attributes: MountAttributes,
    },

    /// Bind mount of a directory.
    Directory {
        /// File descriptor representing the directory to mount within the
        /// guest.
        fd: BorrowedFd<'fd>,

        /// Attributes to bind-mount the path with.
        attributes: MountAttributes,

        /// Whether the mount is recursive or not.
        is_recursive: bool,
    },
}

/// Attributes applied to a mount.
//TODO: should we just use [`MountAttrFlags`] instead of this custom structure?
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub struct MountAttributes {
    /// Make the mount read-only.
    read_only: bool,

    /// Don't honor setuid or setgid bits and file capabilities.
    no_setuid: bool,

    /// Don't allow access to device files on this mount.
    no_devices: bool,

    /// Don't allow programs to be executed from this filesystem.
    no_execution: bool,

    /// Don't follow symbolic links on this filesystem.
    no_symlink_following: bool,
}

const impl Default for MountAttributes {
    fn default() -> Self {
        Self {
            read_only: true,
            no_setuid: true,
            no_devices: true,
            no_execution: true,
            no_symlink_following: true,
        }
    }
}

impl MountAttributes {
    /// Converts this [`MountAttributes`] into `MOUNT_ATTR_*` flags.
    pub fn into_mount_attr(self) -> u32 {
        let mut mount_attr = 0;

        if self.read_only {
            mount_attr |= linux::MOUNT_ATTR_RDONLY;
        }

        if self.no_setuid {
            mount_attr |= linux::MOUNT_ATTR_NOSUID;
        }

        if self.no_devices {
            mount_attr |= linux::MOUNT_ATTR_NODEV;
        }

        if self.no_execution {
            mount_attr |= linux::MOUNT_ATTR_NOEXEC;
        }

        if self.no_symlink_following {
            mount_attr |= linux::MOUNT_ATTR_NOSYMFOLLOW;
        }

        mount_attr
    }
}

/// `proc(5)` `hidepid` options.
///
/// The names as well as the `ptraceable` option are derived from [the Linux
/// kernel] documentation of procfs. These are not documented in `proc(5)`.
///
/// [the Linux kernel]: https://www.kernel.org/doc/html/latest/filesystems/proc.html#mount-options
#[non_exhaustive]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub enum ProcHidepid {
    /// All `<pid>/` directories are visible to all users.
    Off,

    /// Only `<pid>/` directories owned by the user are accessible to a user.
    NoAccess,

    /// `<pid>/` directories not owned by the user are also invisible to a
    /// user.
    Invisible,

    /// `<pid>/` directories of processes not ptraceable by the calling
    /// process are invisible to the process.
    Ptraceable,
}

/// `proc(5)` subset options.
#[non_exhaustive]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub enum ProcSubset {
    /// All of procfs is visible.
    Full,

    /// Top level files and directories not related to tasks are invisible.
    Pid,
}

/// `proc(5)` pid namespace to use.
#[non_exhaustive]
#[derive(Copy, Clone, Debug)]
pub(crate) enum ProcPidNamespace<'a> {
    /// The pid namespace of the guest.
    Guest,

    /// The pid namespace referred to by the given file descriptor.
    Fd(BorrowedFd<'a>),
}

/// Owner of a materialized mapping.
#[non_exhaustive]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub(crate) enum Owner {
    /// User and associated primary group specified in the policy for the
    /// sandboxed process.
    User,
    //TODO: currently removed in anticipation of future newuidmap/newgidmap
    //      or systemd-nsresourced support
    /*/// Specified [`Uid`] and [`Gid`].
    Ids { user: Uid, group: Gid },*/
}
