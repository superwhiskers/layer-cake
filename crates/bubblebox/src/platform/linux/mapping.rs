// SPDX-License-Identifier: AGPL-3.0-only

//! Sandbox mapping realization.

//NOTE: should take a look at bwrap once more to see what it exposes by
//      default from /dev. relevant for elsewhere in the linux platform module
//TODO: write a function that inspects an elf binary and derives mappings for
//      shared libraries it relies upon in addition to itself
//TODO: `*_with_owner` methods are disabled until systemd-nsresourced or
//      newuidmap/newgidmap are supported

use linux_raw_sys::general as linux_general;
use rustix::{
    fd::BorrowedFd,
    fs::{Gid, Mode},
    mount::MountAttrFlags,
};

use crate::path::Host;

/// Source of a mapping.
#[derive(Clone, Debug)]
pub struct Source<'a> {
    /// The mapping's source.
    pub(crate) inner: SourceInner<'a>,
}

impl<'a> Source<'a> {
    #![expect(
        clippy::missing_const_for_fn,
        reason = "constructors taking BorrowedFd, Uid, or Gid are intentionally non-const"
    )]

    /// Create a new source from the given inner value.
    const fn new(inner: SourceInner<'a>) -> Self {
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
    pub const fn read_only(path: Host, is_optional: bool) -> Self {
        Self::new(SourceInner::Bind(BindMount::Path {
            path,
            attributes: MountAttributes {
                read_only: true,
                no_setuid: true,
                no_devices: true,
                ..Default::default()
            },
            is_optional,
            is_recursive: false,
        }))
    }

    /// Read-write mapping of a file from the host to the guest, preserving
    /// ownership and permissions.
    #[must_use]
    pub const fn read_write(path: Host, is_optional: bool) -> Self {
        Self::new(SourceInner::Bind(BindMount::Path {
            path,
            attributes: MountAttributes {
                no_setuid: true,
                no_devices: true,
                ..Default::default()
            },
            is_optional,
            is_recursive: false,
        }))
    }

    /// Read-write mapping of a device node or directory of device nodes from
    /// the host to the guest, preserving ownership and permissions.
    #[must_use]
    pub const fn device(path: Host, is_optional: bool) -> Self {
        Self::new(SourceInner::Bind(BindMount::Path {
            path,
            attributes: MountAttributes {
                no_setuid: true,
                ..Default::default()
            },
            is_optional,
            is_recursive: false,
        }))
    }

    /// Mapping of a file from the host to the guest, preserving ownership and
    /// permissions.
    #[must_use]
    pub const fn bind(
        path: Host,
        attributes: MountAttributes,
        is_optional: bool,
        is_recursive: bool,
    ) -> Self {
        Self::new(SourceInner::Bind(BindMount::Path {
            path,
            attributes,
            is_optional,
            is_recursive,
        }))
    }

    /// Mapping of a file from the host to the guest using a file descriptor,
    /// preserving ownership and permissions.
    #[must_use]
    pub fn bind_fd(
        fd: BorrowedFd<'a>,
        attributes: MountAttributes,
        is_recursive: bool,
    ) -> Self {
        Self::new(SourceInner::Bind(BindMount::Fd {
            fd,
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
                no_setuid: true,
                no_devices: true,
                no_execution: true,
                ..Default::default()
            },
        })
    }

    /// Mapping of `proc(5)` to the given path on the guest with the pid
    /// namespace referred to by the specified [`BorrowedFd`].
    #[must_use]
    pub fn proc_with_pid_namespace(
        hidepid: ProcHidepid,
        subset: ProcSubset,
        namespace: BorrowedFd<'a>,
    ) -> Self {
        Self::new(SourceInner::Procfs {
            hidepid,
            gid: None,
            subset,
            namespace: ProcPidNamespace::Fd(namespace),
            attributes: MountAttributes {
                no_setuid: true,
                no_devices: true,
                no_execution: true,
                ..Default::default()
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
                no_setuid: true,
                no_devices: true,
                no_execution: true,
                ..Default::default()
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
        namespace: BorrowedFd<'a>,
    ) -> Self {
        Self::new(SourceInner::Procfs {
            hidepid,
            gid: Some(gid),
            subset,
            namespace: ProcPidNamespace::Fd(namespace),
            attributes: MountAttributes {
                no_setuid: true,
                no_devices: true,
                no_execution: true,
                ..Default::default()
            },
        })
    }

    /// Mapping of an mqueue filesystem to the given path on the guest.
    #[must_use]
    pub const fn mqueue() -> Self {
        Self::new(SourceInner::Mqueue {
            attributes: MountAttributes {
                no_setuid: true,
                no_devices: true,
                no_execution: true,
                ..Default::default()
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
                no_setuid: true,
                no_devices: true,
                ..Default::default()
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
pub(crate) enum SourceInner<'a> {
    /// A bind-mount sourced from the host.
    ///
    /// Preserves the permissions and ownership of the source.
    Bind(BindMount<'a>),

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
        namespace: ProcPidNamespace<'a>,

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
pub(crate) enum BindMount<'a> {
    /// Bind mount sourced from a path.
    Path {
        /// Host path to mount within the guest.
        path: Host,

        /// Attributes to bind-mount the path with.
        attributes: MountAttributes,

        /// Whether the source path missing should be ignored.
        is_optional: bool,

        /// Whether the mount is recursive or not.
        is_recursive: bool,
    },

    /// Bind mount sourced from a path file descriptor.
    Fd {
        /// File descriptor representing the path to mount within the guest.
        fd: BorrowedFd<'a>,

        /// Attributes to bind-mount the path with.
        attributes: MountAttributes,

        /// Whether the mount is recursive or not.
        is_recursive: bool,
    },
}

/// Attributes applied to a mount.
//NOTE: should we just use [`MountAttrFlags`] instead of this custom structure?
#[derive_const(Default)]
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

impl MountAttributes {
    /// Converts this [`MountAttributes`] into `MOUNT_ATTR_*` flags.
    pub fn into_mount_attr(self) -> u32 {
        let mut mount_attr = 0;

        if self.read_only {
            mount_attr |= linux_general::MOUNT_ATTR_RDONLY;
        }

        if self.no_setuid {
            mount_attr |= linux_general::MOUNT_ATTR_NOSUID;
        }

        if self.no_devices {
            mount_attr |= linux_general::MOUNT_ATTR_NODEV;
        }

        if self.no_execution {
            mount_attr |= linux_general::MOUNT_ATTR_NOEXEC;
        }

        if self.no_symlink_following {
            mount_attr |= linux_general::MOUNT_ATTR_NOSYMFOLLOW;
        }

        mount_attr
    }

    /// Converts this [`MountAttributes`] into [`MountAttrFlags`].
    pub fn into_mount_attr_flags(self) -> MountAttrFlags {
        let mut mount_attr = MountAttrFlags::empty();

        if self.read_only {
            mount_attr |= MountAttrFlags::MOUNT_ATTR_RDONLY;
        }

        if self.no_setuid {
            mount_attr |= MountAttrFlags::MOUNT_ATTR_NOSUID;
        }

        if self.no_devices {
            mount_attr |= MountAttrFlags::MOUNT_ATTR_NODEV;
        }

        if self.no_execution {
            mount_attr |= MountAttrFlags::MOUNT_ATTR_NOEXEC;
        }

        if self.no_symlink_following {
            mount_attr |= MountAttrFlags::MOUNT_ATTR_NOSYMFOLLOW;
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
