// SPDX-License-Identifier: AGPL-3.0-only

//! Sandbox mount realization.

//TODO: should take a look at bwrap once more to see what it exposes by
//      default from /dev. relevant for elsewhere in the linux platform module
//TODO: write a function that inspects an elf binary and derives mappings for
//      shared libraries it relies upon in addition to itself
//TODO: `*_with_owner` methods are disabled until systemd-nsresourced or
//      newuidmap/newgidmap are supported
//TODO: provide a way to take in arbitrary detached mounts as mappings
//TODO: add selinux support through file label options for mounts, executable
//      labels for the program
//TODO: determine if there's a sane way to take borrowed fds here with a `Cow`
//      equivalent (we can't implement `Borrow` or `ToOwned`).

use linux_raw_sys::general as linux;
use meowix::{
    fd::OwnedFd,
    ids::Gid,
    mode::Mode,
    retry_on_interrupt, syscalls,
    util::{Cwd, PATH_MAX, WithCStr},
};
use std::{ffi::CString, os::unix::ffi::OsStrExt, path::Path};

use super::{
    errors::{Error, ResultSyscallExt},
    paths::{HostDirectory, HostFile},
    policy::errors::Policy as PolicyError,
};
use crate::paths::{Guest, nearest_ancestor};

/// Source of a mount.
#[derive(Debug)]
pub struct Mount {
    /// The mount's source.
    pub(crate) inner: MountInner,
}

impl Mount {
    #![expect(
        clippy::missing_const_for_fn,
        reason = "constructors taking OwnedFd, Uid, or Gid are intentionally non-const"
    )]

    /// Create a new source from the given inner value.
    const fn new(inner: MountInner) -> Self {
        Self { inner }
    }

    /// Indicates if the source is synthetic or not.
    pub const fn is_synthetic(&self) -> bool {
        let Self { inner } = self;
        !matches!(inner, MountInner::Bind(_))
    }

    /// Read-only mapping of a file from the host to the guest, preserving
    /// ownership and permissions.
    #[must_use]
    pub fn read_only_file(fd: HostFile) -> Self {
        let (dirfd, name, fd, is_symlink) = fd.into_parts();
        Self::new(MountInner::Bind(BindMount::File {
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
            is_symlink,
        }))
    }

    /// Read-write mapping of a file from the host to the guest, preserving
    /// ownership and permissions.
    #[must_use]
    pub fn read_write_file(fd: HostFile) -> Self {
        let (dirfd, name, fd, is_symlink) = fd.into_parts();
        Self::new(MountInner::Bind(BindMount::File {
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
            is_symlink,
        }))
    }

    /// Read-write mapping of a device file from the host to the guest,
    /// preserving ownership and permissions.
    #[must_use]
    pub fn device_file(fd: HostFile) -> Self {
        let (dirfd, name, fd, is_symlink) = fd.into_parts();
        Self::new(MountInner::Bind(BindMount::File {
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
            is_symlink,
        }))
    }

    /// Mapping of a file from the host to the guest, preserving ownership and
    /// permissions.
    #[must_use]
    pub fn bind_file(fd: HostFile, attributes: MountAttributes) -> Self {
        let (dirfd, name, fd, is_symlink) = fd.into_parts();
        Self::new(MountInner::Bind(BindMount::File {
            dirfd,
            name,
            fd,
            attributes,
            is_symlink,
        }))
    }

    /// Read-only mapping of a directory from the host to the guest, preserving
    /// ownership and permissions.
    ///
    /// # Notes
    ///
    /// This mount will be recursive. If that is not desired, use
    /// [`Mount::bind_directory`].
    #[must_use]
    pub fn read_only_directory(fd: HostDirectory) -> Self {
        Self::new(MountInner::Bind(BindMount::Directory {
            fd: fd.into_fd(),
            attributes: MountAttributes {
                read_only: true,
                no_setuid: true,
                no_devices: true,
                no_execution: false,
                no_symlink_following: false,
            },
            is_recursive: true,
        }))
    }

    /// Read-write mapping of a directory from the host to the guest, preserving
    /// ownership and permissions.
    ///
    /// # Notes
    ///
    /// This mount will be recursive. If that is not desired, use
    /// [`Mount::bind_directory`].
    #[must_use]
    pub fn read_write_directory(fd: HostDirectory) -> Self {
        Self::new(MountInner::Bind(BindMount::Directory {
            fd: fd.into_fd(),
            attributes: MountAttributes {
                read_only: false,
                no_setuid: true,
                no_devices: true,
                no_execution: false,
                no_symlink_following: false,
            },
            is_recursive: true,
        }))
    }

    /// Mapping of a directory from the host to the guest, preserving ownership
    /// and permissions.
    #[must_use]
    pub fn bind_directory(
        fd: HostDirectory,
        attributes: MountAttributes,
        is_recursive: bool,
    ) -> Self {
        Self::new(MountInner::Bind(BindMount::Directory {
            fd: fd.into_fd(),
            attributes,
            is_recursive,
        }))
    }

    /// Mapping of `proc(5)` to the given path on the guest with the pid
    /// namespace of the guest.
    #[must_use]
    pub const fn proc(hidepid: ProcHidepid, subset: ProcSubset) -> Self {
        Self::new(MountInner::Procfs {
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
    /// namespace referred to by the specified [`OwnedFd`].
    #[must_use]
    pub fn proc_with_pid_namespace(
        hidepid: ProcHidepid,
        subset: ProcSubset,
        namespace: OwnedFd,
    ) -> Self {
        Self::new(MountInner::Procfs {
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
        Self::new(MountInner::Procfs {
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
    /// [`OwnedFd`] to the given path on the guest with the specified [`Gid`]
    /// allowed full process information regardless of the [`ProcHidepid`]
    /// setting.
    #[must_use]
    pub fn proc_with_privileged_gid_and_pid_namespace(
        hidepid: ProcHidepid,
        gid: Gid,
        subset: ProcSubset,
        namespace: OwnedFd,
    ) -> Self {
        Self::new(MountInner::Procfs {
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
        Self::new(MountInner::Mqueue {
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
        Self::new(MountInner::File(File {
            contents: contents.into(),
            owner: Owner::User,
            permissions,
        }))
    }

    /// Mapping of an arbitrary path on the guest to another path on the guest,
    /// using a symlink.
    #[must_use]
    pub const fn symlink(source: Guest) -> Self {
        Self::new(MountInner::Symlink(source))
    }

    /// Mapping of an empty directory to a given path on the guest.
    ///
    /// The materialized directory will be owned by the user and group
    /// specified in the policy for the sandboxed process.
    #[must_use]
    pub const fn directory(permissions: Mode) -> Self {
        Self::new(MountInner::EmptyDirectory {
            owner: Owner::User,
            permissions,
        })
    }

    /// Mapping of a tmpfs mount to a given path on the guest.
    ///
    /// The mount will be owned by the user and group specified in the policy
    /// for the sandboxed process.
    #[must_use]
    pub const fn tmpfs(
        size: TmpfsSize,
        max_inodes: Option<u64>,
        permissions: Mode,
    ) -> Self {
        Self::new(MountInner::Tmpfs {
            size,
            max_inodes,
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

    /// Mapping of an overlay mount to a given path on the guest.
    ///
    /// The mount will be owned by the user and group specified in the policy
    /// for the sandboxed process.
    #[must_use]
    pub fn overlay(
        lowerdirs: impl IntoIterator<Item = HostDirectory>,
        datadirs: impl IntoIterator<Item = HostDirectory>,
        upperdirs: Option<UpperDirs>,
    ) -> Self {
        Self::new(MountInner::Overlay {
            lowerdirs: lowerdirs
                .into_iter()
                .map(HostDirectory::into_fd)
                .collect(),
            datadirs: datadirs
                .into_iter()
                .map(HostDirectory::into_fd)
                .collect(),
            upperdirs,
            attributes: MountAttributes {
                read_only: false,
                no_setuid: true,
                no_devices: true,
                no_execution: false,
                no_symlink_following: false,
            },
        })
    }
}

/// Source of a mount.
//TODO: maybe add a "don't create the destination" flag to bind mounts to
//      give the user the option to make it themselves
#[non_exhaustive]
#[derive(Debug)]
pub(crate) enum MountInner {
    /// A bind-mount sourced from the host.
    ///
    /// Preserves the permissions and ownership of the source.
    Bind(BindMount),

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
        namespace: ProcPidNamespace,

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

    /// Symbolic link on the guest.
    Symlink(Guest),

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
        size: TmpfsSize,

        /// Maximum number of inodes for the tmpfs.
        max_inodes: Option<u64>,

        /// Owner of the directory.
        owner: Owner,

        /// Permissions applied to the directory.
        permissions: Mode,

        /// Attributes to apply to the mount.
        attributes: MountAttributes,
    },

    /// Overlay filesystem.
    Overlay {
        /// `lowerdir`s used by this overlay mount.
        lowerdirs: Vec<OwnedFd>,

        /// `datadir`s used by this overlay mount.
        datadirs: Vec<OwnedFd>,

        /// Upper directories used by this overlay mount.
        upperdirs: Option<UpperDirs>,

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
    //TODO: accept `Cow<'a, [u8]>` here.
    pub(crate) contents: Vec<u8>,

    /// Owner of the file.
    pub(crate) owner: Owner,

    /// Permissions applied to the file.
    pub(crate) permissions: Mode,
}

/// Mapping using a bind mount from the host.
#[non_exhaustive]
#[derive(Debug)]
pub(crate) enum BindMount {
    /// Bind mount of a file.
    File {
        /// File descriptor representing the parent directory of the file to
        /// mount within the guest.
        dirfd: OwnedFd,

        /// Name of the file underneath the dirfd to mount within the guest.
        name: CString,

        /// File descriptor representing the file to mount within the guest.
        ///
        /// This is used to verify that we actually mounted the intended file
        /// after the mount has been moved to the guest, not to mount it.
        fd: OwnedFd,

        /// Attributes to bind-mount the path with.
        attributes: MountAttributes,

        /// Whether or not we will bind mount a symlink should `dirfd/name`
        /// refer to one, or instead mount the file it points to.
        is_symlink: bool,
    },

    /// Bind mount of a directory.
    Directory {
        /// File descriptor representing the directory to mount within the
        /// guest.
        fd: OwnedFd,

        /// Attributes to bind-mount the path with.
        attributes: MountAttributes,

        /// Whether the mount is recursive or not.
        is_recursive: bool,
    },
}

/// Attributes applied to a mount.
///
/// By default, the strictest possible attributes are set:
///
/// - Read-only mount
/// - No suid/sgid bits honored
/// - No device file access
/// - No binary execution
/// - No symlink following
//TODO: should we move this structure into meowix to make it something like
//      rustix's `MountAttrFlags`?
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub struct MountAttributes {
    /// Make the mount read-only.
    pub(crate) read_only: bool,

    /// Don't honor setuid or setgid bits and file capabilities.
    pub(crate) no_setuid: bool,

    /// Don't allow access to device files on this mount.
    pub(crate) no_devices: bool,

    /// Don't allow binaries to be executed from this filesystem.
    pub(crate) no_execution: bool,

    /// Don't follow symbolic links on this filesystem.
    pub(crate) no_symlink_following: bool,
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
    /// Whether the mount should be read-only.
    pub const fn read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// Whether the mount should ignore setuid bits, setgid bits, and file
    /// capabilities.
    pub const fn no_setuid(mut self, no_setuid: bool) -> Self {
        self.no_setuid = no_setuid;
        self
    }

    /// Whether the mount should deny access to device files.
    pub const fn no_devices(mut self, no_devices: bool) -> Self {
        self.no_devices = no_devices;
        self
    }

    /// Whether the mount should not allow binaries to be executed.
    pub const fn no_execution(mut self, no_execution: bool) -> Self {
        self.no_execution = no_execution;
        self
    }

    /// Whether the mount should not allow following symbolic links.
    pub const fn no_symlink_following(
        mut self,
        no_symlink_following: bool,
    ) -> Self {
        self.no_symlink_following = no_symlink_following;
        self
    }

    /// Converts this [`MountAttributes`] into `MOUNT_ATTR_*` flags.
    pub const fn into_mount_attr(self) -> u32 {
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

/// Upper directories (`workdir` and `upperdir`) of an overlay mount.
#[derive(Debug)]
pub struct UpperDirs {
    /// Internal representation.
    pub(crate) inner: UpperDirsInner,
}

impl UpperDirs {
    /// Upper directories sourced from the host.
    ///
    /// These will have their lexical nearest common ancestor computed to get an
    /// anchor directory to resolve from later.
    ///
    /// # Errors
    ///
    /// This method errors if capturing the parent directory file descriptor
    /// fails, or if capturing identity file descriptors for `upperdir` and
    /// `workdir` fails.
    pub fn fd(
        upperdir: impl AsRef<Path>,
        workdir: impl AsRef<Path>,
    ) -> Result<Self, Error> {
        let parent = nearest_ancestor(&upperdir, &workdir);
        let (upperdir, workdir) = (
            upperdir.as_ref().trim_prefix(&parent),
            workdir.as_ref().trim_prefix(&parent),
        );

        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent.as_path()
        }
        .as_os_str()
        .as_bytes()
        .with_c_str::<{ PATH_MAX }, _, _, PolicyError>(|parent| {
            retry_on_interrupt!({
                syscalls::openat2(
                    Cwd,
                    parent,
                    linux::open_how {
                        flags: (linux::O_PATH
                            | linux::O_CLOEXEC
                            | linux::O_DIRECTORY)
                            as u64,
                        mode: 0,
                        resolve: linux::RESOLVE_NO_MAGICLINKS as u64,
                    },
                )
            })
        })?;

        Self::fd_at(parent, upperdir, workdir)
    }

    /// Upper directories sourced from the host, opened relative to the given
    /// path file descriptor.
    ///
    /// Both `upperdir` and `workdir` must lie beneath `parent`. Additionally,
    /// `parent`, `upperdir`, and `workdir` must all reside on the same mount.
    ///
    /// # Errors
    ///
    /// This method errors if capturing identity file descriptors for `upperdir`
    /// and `workdir` fails.
    pub fn fd_at<'fd>(
        parent: OwnedFd,
        upperdir: impl AsRef<Path>,
        workdir: impl AsRef<Path>,
    ) -> Result<Self, Error> {
        let upperdir = upperdir
            .as_ref()
            .as_os_str()
            .as_bytes()
            .with_c_str::<{ PATH_MAX }, _, PolicyError, PolicyError>(
                |upperdir| Ok(upperdir.to_owned()),
            )?;

        let workdir = workdir
            .as_ref()
            .as_os_str()
            .as_bytes()
            .with_c_str::<{ PATH_MAX }, _, PolicyError, PolicyError>(
                |workdir| Ok(workdir.to_owned()),
            )?;

        let upperdir_fd = retry_on_interrupt!({
            syscalls::openat2(
                &parent,
                &upperdir,
                linux::open_how {
                    flags: (linux::O_PATH
                        | linux::O_CLOEXEC
                        | linux::O_DIRECTORY) as u64,
                    mode: 0,
                    resolve: (linux::RESOLVE_NO_MAGICLINKS
                        | linux::RESOLVE_BENEATH
                        | linux::RESOLVE_NO_XDEV)
                        as u64,
                },
            )
        })
        .wrap_error::<PolicyError>()?;

        let workdir_fd = retry_on_interrupt!({
            syscalls::openat2(
                &parent,
                &workdir,
                linux::open_how {
                    flags: (linux::O_PATH
                        | linux::O_CLOEXEC
                        | linux::O_DIRECTORY) as u64,
                    mode: 0,
                    resolve: (linux::RESOLVE_NO_MAGICLINKS
                        | linux::RESOLVE_BENEATH
                        | linux::RESOLVE_NO_XDEV)
                        as u64,
                },
            )
        })
        .wrap_error::<PolicyError>()?;

        Ok(Self {
            inner: UpperDirsInner::Fd {
                parent,
                upperdir,
                upperdir_fd,
                workdir,
                workdir_fd,
            },
        })
    }

    /// Tmpfs backed upper directories.
    pub fn tmpfs(size: TmpfsSize, max_inodes: Option<u64>) -> Self {
        Self {
            inner: UpperDirsInner::Tmpfs { size, max_inodes },
        }
    }
}

/// Internal representation of the upper directories of an overlay mount.
#[derive(Debug)]
pub enum UpperDirsInner {
    /// File descriptor backed upper directories.
    Fd {
        /// Parent directory of `upperdir` and `workdir`.
        parent: OwnedFd,

        /// Upper directory relative to `parent`.
        upperdir: CString,

        /// File descriptor representing the identity of `upperdir`.
        upperdir_fd: OwnedFd,

        /// Work directory relative to `parent`.
        workdir: CString,

        /// File descriptor representing the identity of `workdir`.
        workdir_fd: OwnedFd,
    },

    /// Tmpfs backed upper directories.
    Tmpfs {
        /// Size to use for the tmpfs holding the upper directories.
        size: TmpfsSize,

        /// Maximum number of inodes for the tmpfs.
        max_inodes: Option<u64>,
    },
}

/// `tmpfs(5)` `size` values.
#[non_exhaustive]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub enum TmpfsSize {
    /// No limit.
    Unlimited,

    /// Bytes.
    Bytes(u64),

    /// Percentage.
    Percent(u64),
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
#[derive(Debug)]
pub(crate) enum ProcPidNamespace {
    /// The pid namespace of the guest.
    Guest,

    /// The pid namespace referred to by the given file descriptor.
    Fd(OwnedFd),
}

/// Owner of a materialized mapping.
#[non_exhaustive]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub(crate) enum Owner {
    /// User and associated primary group specified in the policy for the
    /// sandboxed process.
    User,
}
