// SPDX-License-Identifier: AGPL-3.0-only

//! Host path abstractions.

use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    fs::{AtFlags, CWD, FileType, Mode, OFlags, ResolveFlags, StatxFlags},
    io::Errno,
};
use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

use super::util;
use crate::errors::Error;

/// Checks if a path represents a directory.
///
/// # Errors
///
/// This function errors if calling `statx(2)` on the given file descriptor
/// fails.
fn is_directory(fd: impl AsFd) -> Result<bool, Errno> {
    Ok(FileType::from_raw_mode(
        rustix::fs::statx(
            fd.as_fd(),
            "",
            AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW,
            StatxFlags::TYPE,
        )?
        .stx_mode
        .into(),
    )
    .is_dir())
}

/// Checks if one file descriptor shares the same file identity as another.
///
/// # Errors
///
/// This function errors if calling `statx(2)` on the two given file descriptors
/// fails.
pub fn same_file_identity(
    lhs: impl AsFd,
    rhs: impl AsFd,
) -> Result<bool, Errno> {
    let lhs = rustix::fs::statx(
        lhs.as_fd(),
        "",
        AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::INO,
    )?;
    let rhs = rustix::fs::statx(
        rhs.as_fd(),
        "",
        AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::INO,
    )?;
    Ok(lhs.stx_dev_major == rhs.stx_dev_major
        && lhs.stx_dev_minor == rhs.stx_dev_minor
        && lhs.stx_ino == rhs.stx_ino)
}

/// Owned representation of a file residing outside the sandbox.
///
/// # Notes
///
/// Unfortunately, without `CAP_SYS_ADMIN`, it appears to be impossible to
/// eliminate [TOCTOU] here. As this library is designed to permit every feature
/// to work in an unprivileged context, we cannot assume we can do
/// `open_tree_attr(OPEN_TREE_CLONE)` outright. So, we do the next best thing
/// and store three things about a host file:
///
/// - A file descriptor to its parent directory.
/// - Its name.
/// - A file descriptor to it.
///
/// With these three, we can perform an `open_tree_attr(OPEN_TREE_NAMESPACE)`
/// dance where we 1) create a mount namespace containing the contents of the
/// parent directory 2) enter the mount namespace and 3) perform
/// `open_tree_attr(OPEN_TREE_CLONE)` on the file. Using the file descriptor we
/// created to the file earlier, we are then able to double check that the mount
/// we just captured of the file is actually the original file. This is the best
/// we are able to achieve here.
///
/// [TOCTOU]: https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use
#[derive(Debug)]
pub struct HostFile {
    /// File descriptor of the file's parent directory.
    dirfd: OwnedFd,

    /// Name of the file.
    name: OsString,

    /// File descriptor of the file itself.
    fd: OwnedFd,
}

impl HostFile {
    /// Convert this [`HostFile`] into its components.
    pub fn into_parts(self) -> (OwnedFd, OsString, OwnedFd) {
        (self.dirfd, self.name, self.fd)
    }

    /// Creates a new [`HostFile`] from the given [`Path`].
    ///
    /// This method breaks apart the [`Path`] into the path of the parent
    /// directory and the file name, then opens a file descriptor to the parent
    /// directory.
    ///
    /// # Warning
    ///
    /// This intentionally does not resolve symlinks. If symlink resolution is
    /// desired, resolve it externally and pass the real path to this method.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::open_at(CWD, path)
    }

    /// Creates a new [`HostFile`] from the given [`Path`], opening the
    /// file descriptor beneath the given path file descriptor.
    ///
    /// This method breaks apart the [`Path`] into the path of the parent
    /// directory and the file name, then opens a file descriptor to the parent
    /// directory.
    ///
    /// # Warning
    ///
    /// This intentionally does not resolve symlinks. If symlink resolution is
    /// desired, resolve it externally and pass the real path to this method.
    pub fn open_at(
        relative_to: impl AsFd,
        path: impl AsRef<Path>,
    ) -> Result<Self, Error> {
        let mut components = path.as_ref().components();
        let mut directory = PathBuf::new();
        let mut name = if let Some(first) = components.next() {
            first
        } else {
            return Err(Error::NotAFile);
        };

        for component in components {
            directory.push(name);
            name = component;
        }

        let dirfd = util::retry_on_interrupt!({
            rustix::fs::openat2(
                relative_to.as_fd(),
                directory.as_os_str().as_bytes(),
                OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
            )
        })?;

        //TODO: there could be a race here but i really don't know what else to
        //      do here. the only alternative i see is opening a file descriptor
        //      -> copying the file to a safe location but then this destroys
        //      the "writes are reflected on the host" effect we want.
        //      alternatively, if the caller has `CAP_SYS_ADMIN`, they can
        //      open a tree themselves and we can provide a facility for
        //      moving it.

        let fd = util::retry_on_interrupt!({
            rustix::fs::openat2(
                dirfd.as_fd(),
                name.as_os_str().as_bytes(),
                OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_SYMLINKS
                    | ResolveFlags::BENEATH,
            )
        })?;

        if is_directory(dirfd.as_fd())? && !is_directory(fd.as_fd())? {
            Ok(Self {
                dirfd,
                name: <Component<'_> as AsRef<OsStr>>::as_ref(&name)
                    .to_os_string(),
                fd,
            })
        } else {
            Err(Error::NotAFile)
        }
    }

    /// Checks if the given file descriptor represents the same file as this
    /// [`HostFile`]'s file descriptor.
    ///
    /// # Errors
    ///
    /// This function errors if calling `statx(2)` on the file descriptors
    /// fails.
    pub fn has_same_file_identity(
        &self,
        rhs: impl AsFd,
    ) -> Result<bool, Errno> {
        same_file_identity(self.fd.as_fd(), rhs.as_fd())
    }

    /// Borrows the file descriptor.
    pub fn as_borrowed(&self) -> HostFileRef<'_> {
        HostFileRef {
            dirfd: self.dirfd.as_fd(),
            name: self.name.as_os_str(),
            fd: self.fd.as_fd(),
        }
    }
}

/// Reference to a file residing outside the sandbox.
///
/// See [`HostFile`] for more details about its representation.
#[derive(Clone, Debug)]
pub struct HostFileRef<'fd> {
    /// File descriptor of the file's parent directory.
    dirfd: BorrowedFd<'fd>,

    /// Name of the file.
    name: &'fd OsStr,

    /// File descriptor of the file itself.
    fd: BorrowedFd<'fd>,
}

impl<'fd> HostFileRef<'fd> {
    /// Convert this [`HostFileRef`] into its components.
    pub fn into_parts(self) -> (BorrowedFd<'fd>, &'fd OsStr, BorrowedFd<'fd>) {
        (self.dirfd, self.name, self.fd)
    }

    /// Checks if the given file descriptor represents the same file as this
    /// [`HostFileRef`]'s file descriptor.
    ///
    /// # Errors
    ///
    /// This function errors if calling `statx(2)` on the file descriptors
    /// fails.
    pub fn has_same_file_identity(
        &self,
        rhs: impl AsFd,
    ) -> Result<bool, Errno> {
        same_file_identity(self.fd, rhs.as_fd())
    }
}

/// Owned representation of a directory residing outside the sandbox.
///
/// A host directory contains a file descriptor representing a path to a
/// directory outside the sandbox. Host directories are never valid within a
/// sandbox.
#[derive(Debug)]
pub struct HostDirectory(OwnedFd);

impl HostDirectory {
    /// Convert this [`HostDirectory`] into its underlying [`OwnedFd`].
    pub fn into_fd(self) -> OwnedFd {
        self.0
    }

    /// Creates a new [`HostDirectory`] from the given [`Path`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::open_at(CWD, path)
    }

    /// Creates a new [`HostDirectory`] from the given [`Path`], opening
    /// the file descriptor beneath the given path file descriptor.
    pub fn open_at(
        relative_to: impl AsFd,
        path: impl AsRef<Path>,
    ) -> Result<Self, Error> {
        let fd = util::retry_on_interrupt!({
            rustix::fs::openat2(
                relative_to.as_fd(),
                path.as_ref().as_os_str().as_bytes(),
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_MAGICLINKS,
            )
        })?;

        if is_directory(fd.as_fd())? {
            Ok(Self(fd))
        } else {
            Err(Error::NotADirectory)
        }
    }

    /// Borrows the file descriptor.
    pub fn as_borrowed(&self) -> HostDirectoryRef<'_> {
        HostDirectoryRef(self.as_fd())
    }
}

impl AsFd for HostDirectory {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// Reference to a directory residing outside the sandbox.
///
/// A host directory contains a file descriptor representing a path to a
/// directory outside a sandbox. Host directories are never valid within a
/// sandbox.
#[derive(Clone, Debug)]
pub struct HostDirectoryRef<'fd>(BorrowedFd<'fd>);

impl<'fd> HostDirectoryRef<'fd> {
    /// Convert this [`HostDirectoryRef`] into its underlying [`BorrowedFd`].
    pub fn into_fd(self) -> BorrowedFd<'fd> {
        self.0
    }

    /*
    /// Constructs a new host path from the given [`Path`], only performing
    /// operations that operate on the path lexically.
    ///
    /// # Errors
    ///
    /// This method errors if the path fails the validation step.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();

        if !path.is_absolute() {
            return Err(Error::PathNotAbsolute);
        }

        let mut normalized = PathBuf::from("/");

        for component in path.components() {
            match component {
                //NOTE: the former is expected and the latter is normalized
                //      away or excluded by checking that the path is not
                //      relative earlier
                Component::RootDir | Component::CurDir => {}

                c @ Component::Prefix(_) => normalized.push(c),
                Component::Normal(c) => normalized.push(c),
                Component::ParentDir => {
                    return Err(Error::PathContainsParent);
                }
            }
        }

        Ok(Self(normalized))
    }

    /// Constructs a new host path from the given [`Path`], resolving symbolic
    /// links.
    ///
    /// This is not the default, as operations using on the filesystem may be
    /// undesired.
    ///
    /// # Errors
    ///
    /// This method errors if canonicalizing the link fails.
    pub fn new_using_fs(path: impl AsRef<Path>) -> Result<Self, Error> {
        Ok(Self(path.as_ref().canonicalize()?))
    }
    */
}

impl<'fd> AsFd for HostDirectoryRef<'fd> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/*
impl TryFrom<&Path> for Host {
    type Error = Error;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        Self::new(path)
    }
}

impl TryFrom<PathBuf> for Host {
    type Error = Error;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        Self::new(path)
    }
}

impl TryFrom<&str> for Host {
    type Error = Error;

    fn try_from(path: &str) -> Result<Self, Self::Error> {
        Self::new(PathBuf::from(path))
    }
}

impl AsRef<Path> for Host {
    fn as_ref(&self) -> &Path {
        self.0.as_path()
    }
}
*/
