// SPDX-License-Identifier: AGPL-3.0-only

//! Host path abstractions.

//TODO: add constructors for host files that take in file descriptors
//TODO: impl borrow for this
//TODO: consider giving it its own error
//TODO: accept non-meowix fds as dirfds

use linux_raw_sys::general as linux;
use meowix::{
    errors::{CStrBufferTooSmall, SyscallError, WithCStrError},
    fd::{AsFd, BorrowedFd, OwnedFd},
    retry_on_interrupt, syscalls,
    util::{AtFd, Cwd, PATH_COMPONENT_MAX, PATH_MAX, WithCStr},
};
use std::{
    cmp::Ordering,
    ffi,
    ffi::{CStr, CString, OsStr},
    iter,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

use super::{
    errors::{Error, ResultSyscallExt},
    policy::errors::Policy as PolicyError,
};
use crate::errors::GuestPath as GuestPathError;

/// Checks if a path represents a directory.
///
/// # Errors
///
/// This function errors if calling `statx(2)` on the given file descriptor
/// fails.
fn is_directory<'fd>(fd: impl Into<AtFd<'fd>>) -> Result<bool, SyscallError> {
    let filetype = syscalls::statx(
        fd,
        c"",
        (linux::AT_EMPTY_PATH | linux::AT_SYMLINK_NOFOLLOW) as i32,
        linux::STATX_TYPE,
    )?
    .stx_mode as u32
        & linux::S_IFMT;

    Ok(filetype == linux::S_IFDIR)
}

/// Checks if one file descriptor shares the same file identity as another.
///
/// # Errors
///
/// This function errors if calling `statx(2)` on the two given file descriptors
/// fails.
pub fn same_file_identity<'fd>(
    lhs: impl Into<AtFd<'fd>>,
    rhs: impl Into<AtFd<'fd>>,
) -> Result<bool, SyscallError> {
    let lhs = syscalls::statx(
        lhs,
        c"",
        (linux::AT_EMPTY_PATH | linux::AT_SYMLINK_NOFOLLOW) as i32,
        linux::STATX_INO,
    )?;
    let rhs = syscalls::statx(
        rhs,
        c"",
        (linux::AT_EMPTY_PATH | linux::AT_SYMLINK_NOFOLLOW) as i32,
        linux::STATX_INO,
    )?;

    //NOTE: be a little paranoid and double check the kernel says it provided
    //      `stx_ino`
    if lhs.stx_mask & linux::STATX_INO == 0
        || rhs.stx_mask & linux::STATX_INO == 0
    {
        //TODO: this should really be an error but failing closed is good
        //      enough for now
        return Ok(false);
    }

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
    name: CString,

    /// File descriptor of the file itself.
    fd: OwnedFd,
}

impl HostFile {
    /// Convert this [`HostFile`] into its components.
    pub fn into_parts(self) -> (OwnedFd, CString, OwnedFd) {
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
    ///
    /// # Errors
    ///
    /// TODO
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::open_at(Cwd, path)
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
    ///
    /// # Errors
    ///
    /// TODO
    pub fn open_at<'fd>(
        relative_to: impl Into<AtFd<'fd>>,
        path: impl AsRef<Path>,
    ) -> Result<Self, Error> {
        let mut components = path.as_ref().components();
        let mut directory = PathBuf::new();
        let mut name = if let Some(first) = components.next() {
            first
        } else {
            return Err(PolicyError::NotAFile.into());
        };

        for component in components {
            directory.push(name);
            name = component;
        }

        let relative_to = relative_to.into();

        //NOTE: ensure that if a single filename is provided that we can still
        //      resolve relative to the dirfd
        let dirfd = if directory.as_os_str().is_empty() {
            Path::new(".")
        } else {
            directory.as_path()
        }
        .as_os_str()
        .as_bytes()
        .with_c_str::<{ PATH_MAX }, _, PolicyError>(|directory| {
            retry_on_interrupt!({
                syscalls::openat2(
                    &relative_to,
                    directory,
                    linux::open_how {
                        flags: (linux::O_PATH
                            | linux::O_CLOEXEC
                            | linux::O_NOFOLLOW)
                            as u64,
                        mode: 0,
                        resolve: (linux::RESOLVE_NO_MAGICLINKS
                            | linux::RESOLVE_NO_SYMLINKS)
                            as u64,
                    },
                )
            })
            .map_err(Into::into)
        })?;

        //TODO: there could be a race here but i really don't know what else to
        //      do here. the only alternative i see is opening a file descriptor
        //      -> copying the file to a safe location but then this destroys
        //      the "writes are reflected on the host" effect we want.
        //      alternatively, if the caller has `CAP_SYS_ADMIN`, they can
        //      open a tree themselves and we can provide a facility for
        //      moving it.

        let name = name
            .as_os_str()
            .as_bytes()
            .with_c_str::<{ PATH_COMPONENT_MAX }, _, PolicyError>(|name| {
                Ok(name.to_owned())
            })?;

        let fd = retry_on_interrupt!({
            syscalls::openat2(
                dirfd.as_fd(),
                &name,
                linux::open_how {
                    flags: (linux::O_PATH
                        | linux::O_CLOEXEC
                        | linux::O_NOFOLLOW) as u64,
                    mode: 0,
                    resolve: (linux::RESOLVE_NO_MAGICLINKS
                        | linux::RESOLVE_NO_SYMLINKS
                        | linux::RESOLVE_BENEATH)
                        as u64,
                },
            )
        })
        .wrap_error::<PolicyError>()?;

        if is_directory(dirfd.as_fd()).wrap_error::<PolicyError>()?
            && !is_directory(fd.as_fd()).wrap_error::<PolicyError>()?
        {
            Ok(Self { dirfd, name, fd })
        } else {
            Err(PolicyError::NotAFile.into())
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
    ) -> Result<bool, SyscallError> {
        same_file_identity(self.fd.as_fd(), rhs.as_fd())
    }

    /// Borrows the file descriptor.
    pub fn as_borrowed(&self) -> HostFileRef<'_> {
        HostFileRef {
            dirfd: self.dirfd.as_fd(),
            name: self.name.as_c_str(),
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
    name: &'fd CStr,

    /// File descriptor of the file itself.
    fd: BorrowedFd<'fd>,
}

impl<'fd> HostFileRef<'fd> {
    /// Convert this [`HostFileRef`] into its components.
    pub fn into_parts(self) -> (BorrowedFd<'fd>, &'fd CStr, BorrowedFd<'fd>) {
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
    ) -> Result<bool, SyscallError> {
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
        Self::open_at(Cwd, path)
    }

    /// Creates a new [`HostDirectory`] from the given [`Path`], opening
    /// the file descriptor beneath the given path file descriptor.
    pub fn open_at<'fd>(
        relative_to: impl Into<AtFd<'fd>>,
        path: impl AsRef<Path>,
    ) -> Result<Self, Error> {
        let relative_to = relative_to.into();
        let fd = path
            .as_ref()
            .as_os_str()
            .as_bytes()
            .with_c_str::<{ PATH_MAX }, _, PolicyError>(|path| {
                retry_on_interrupt!({
                    syscalls::openat2(
                        &relative_to,
                        path,
                        linux::open_how {
                            flags: (linux::O_PATH
                                | linux::O_DIRECTORY
                                | linux::O_CLOEXEC)
                                as u64,
                            mode: 0,
                            resolve: linux::RESOLVE_NO_MAGICLINKS as u64,
                        },
                    )
                })
                .map_err(Into::into)
            })?;

        if is_directory(fd.as_fd()).wrap_error::<PolicyError>()? {
            Ok(Self(fd))
        } else {
            Err(PolicyError::NotADirectory.into())
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
}

impl<'fd> AsFd for HostDirectoryRef<'fd> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// Internal representation of a guest path.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) struct GuestInner {
    /// Parent of the file referenced by the path.
    parent_dir: CString,

    /// File name of the file referenced by the path.
    file_name: CString,
}

impl GuestInner {
    /// Constructs a new guest path from the given [`Path`].
    ///
    /// # Notes
    ///
    /// Currently this does not attempt to resolve potential symlinks within the
    /// sandbox. This will be handled in the future.
    ///
    /// # Errors
    ///
    /// This method errors if the provided path fails the validation step.
    pub(crate) fn new(
        path: impl AsRef<Path>,
    ) -> Result<Self, crate::errors::Error> {
        let path = path.as_ref();

        if !path.is_absolute() {
            return Err(GuestPathError::PathNotAbsolute.into());
        }

        let mut normalized = PathBuf::from("/");

        for component in path.components() {
            match component {
                //NOTE: the former is expected and the latter is normalized
                //      away or excluded by checking that the path is not
                //      relative earlier
                Component::RootDir | Component::CurDir => {}

                Component::Normal(c) => normalized.push(c),
                Component::ParentDir => {
                    return Err(GuestPathError::PathContainsParent.into());
                }
                Component::Prefix(_) => {
                    return Err(GuestPathError::PathContainsPrefix.into());
                }
            }
        }

        //TODO: consider storing an offset to the file name instead of a
        //      separate string buffer

        Ok(Self {
            parent_dir: normalized
                .parent()
                .ok_or(GuestPathError::NoParentDirectory)?
                .as_os_str()
                .as_bytes()
                .with_c_str::<{ PATH_MAX }, _, WithCStrError>(|path| {
                    Ok(path.to_owned())
                })
                .map_err(|_| GuestPathError::Invalid)?,
            file_name: normalized
                .file_name()
                .ok_or(GuestPathError::NoFileName)?
                .as_bytes()
                .with_c_str::<{ PATH_COMPONENT_MAX }, _, WithCStrError>(
                    |path| Ok(path.to_owned()),
                )
                .map_err(|_| GuestPathError::Invalid)?,
        })
    }

    /// Work with this path as a single [`CStr`].
    ///
    /// Useful for unavoidable path-oriented syscalls like `symlinkat(2)`.
    pub(crate) fn with_c_str<const N: usize, T, E>(
        &self,
        f: impl FnOnce(&CStr) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<ffi::FromBytesWithNulError> + From<CStrBufferTooSmall>,
    {
        //TODO: as stated in the meowix code, this could probably use
        // maybeuninit
        let mut buffer = [0; N];

        let parent_dir_len = self.parent_dir.count_bytes();
        let file_name_len = self.file_name.count_bytes();

        //NOTE: we need one more to contain the `/` separating them
        (parent_dir_len + file_name_len + 1 < buffer.len())
            .ok_or(CStrBufferTooSmall)?;

        //SAFETY: we established the lengths fit within the buffer
        unsafe { buffer.get_unchecked_mut(..parent_dir_len) }
            .copy_from_slice(self.parent_dir.to_bytes());

        //SAFETY: we established the lengths fit within the buffer
        *unsafe { buffer.get_unchecked_mut(parent_dir_len) } = b'/';

        //SAFETY: we established the lenghts fit within the buffer
        unsafe {
            buffer.get_unchecked_mut(
                parent_dir_len + 1..parent_dir_len + file_name_len + 1,
            )
        }
        .copy_from_slice(self.file_name.to_bytes());

        //SAFETY: we established the length is within our bounds
        let c_str = CStr::from_bytes_with_nul(unsafe {
            buffer.get_unchecked(..parent_dir_len + file_name_len + 2)
        })?;

        f(c_str)
    }

    /// Get the parent directory string of this guest path.
    pub(crate) fn parent_dir(&self) -> &CStr {
        self.parent_dir.as_c_str()
    }

    /// Get the file name of this guest path.
    pub(crate) fn file_name(&self) -> &CStr {
        self.file_name.as_c_str()
    }

    /// Check if one guest path starts with another.
    pub(crate) fn starts_with(&self, other: &Self) -> bool {
        let mut left_iter = self.components();
        let mut right_iter = other.components();

        while let Some(left) = left_iter.next()
            && let Some(right) = right_iter.next()
        {
            if left != right {
                return false;
            }
        }

        // the `other` must always be none in order for the left to have started
        // with it
        right_iter.next().is_none()
    }

    /// Extract the components of the path.
    fn components(&self) -> impl Iterator<Item = Component<'_>> {
        //NOTE: this is probably the only place we use `OsStr` in the library
        //      now. we have to use it here and it's fine because the path
        //      ordering is only relevant host-side---the iterator
        //      implementation for `BTreeMap` does not require an `Ord` impl
        //      on the key and that's the only part of `BTreeMap` that we use
        //      guest-side. we could remove this later, too, but ensuring
        //      accuracy w/r/t the official std ordering could be difficult
        let parent =
            Path::new(OsStr::from_bytes(self.parent_dir.as_c_str().to_bytes()));

        let file_name = OsStr::from_bytes(self.file_name.as_c_str().to_bytes());

        parent
            .components()
            .chain(iter::once(Component::Normal(file_name)))
    }
}

impl Ord for GuestInner {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.components().cmp(other.components())
    }
}

impl PartialOrd for GuestInner {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
