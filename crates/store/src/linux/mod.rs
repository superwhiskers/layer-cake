// SPDX-License-Identifier: AGPL-3.0-only

//! Linux store backend implementation.

use blake3::{Hash, Hasher};
use linux_raw_sys::general as linux;
use meowix::{
    errno::Errno,
    errors::{PartialTransfer, SyscallError},
    fd::{AsFd, OwnedFd},
    mode::Mode,
    retry_on_interrupt, syscalls,
    util::{
        AtFd, Cwd, FdReadWrite, FdReadWriteExt, PATH_MAX, WithCStr,
        is_directory, unsigned_decimal_digits_upper_bound,
    },
};
use std::{
    ffi::{self, CStr},
    io::{self, IoSlice},
    iter,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use crate::{Backend, Entry, EntryKind, WriteHandle, errors::Error, sealed};
pub use errors::Error as BackendError;

mod errors;

/// Location of a lock file underneath the store directory.
pub const LOCK_FILE_PATH: &'static CStr = c".lock";

/// Location of the generation counter underneath the store directory.
pub const GENERATION_FILE_PATH: &'static CStr = c".generation";

/// Open the lock file for a provided store path file descriptor.
fn store_lock_file(fd: impl AsFd) -> Result<OwnedFd, BackendError> {
    Ok(retry_on_interrupt!({
        syscalls::openat2(
            &fd,
            LOCK_FILE_PATH,
            linux::open_how {
                flags: (linux::O_RDONLY | linux::O_CLOEXEC | linux::O_CREAT)
                    as u64
                    | linux::OPENAT2_REGULAR,
                mode: Mode::RUSR.bits() as u64,
                resolve: (linux::RESOLVE_NO_MAGICLINKS | linux::RESOLVE_BENEATH)
                    as u64,
            },
        )
    })?)
}

/// Acquire a shared lock on the provided store path file descriptor.
///
/// This is removed when the returned [`OwnedFd`] is dropped.
fn acquire_shared_store_lock(fd: impl AsFd) -> Result<OwnedFd, BackendError> {
    let lock_file = store_lock_file(fd)?;
    retry_on_interrupt!({
        syscalls::flock(&lock_file, linux::LOCK_SH as ffi::c_int)
    })?;
    Ok(lock_file)
}

/// Acquire an exclusive lock on the provided store path file descriptor.
///
/// This is removed when the returned [`OwnedFd`] is dropped.
fn acquire_exclusive_store_lock(
    fd: impl AsFd,
) -> Result<OwnedFd, BackendError> {
    let lock_file = store_lock_file(fd)?;
    retry_on_interrupt!({
        syscalls::flock(&lock_file, linux::LOCK_EX as ffi::c_int)
    })?;
    Ok(lock_file)
}

/// Read the current generation beneath the provided store path file descriptor.
fn current_generation(fd: impl AsFd) -> Result<u64, BackendError> {
    let generation_fd = retry_on_interrupt!({
        syscalls::openat2(
            &fd,
            GENERATION_FILE_PATH,
            linux::open_how {
                flags: (linux::O_RDONLY | linux::O_CLOEXEC) as u64
                    | linux::OPENAT2_REGULAR,
                mode: 0,
                resolve: (linux::RESOLVE_NO_MAGICLINKS | linux::RESOLVE_BENEATH)
                    as u64,
            },
        )
    })?;

    let mut buffer = [0; unsigned_decimal_digits_upper_bound::<u64>()];
    match generation_fd.read_until_full(buffer.as_mut_slice()) {
        Ok(n) => Ok(u64::from_ascii_bytes(&buffer[..n])?),
        Err(PartialTransfer {
            transferred,
            error: None,
        }) => Ok(u64::from_ascii_bytes(&buffer[..transferred])?),
        Err(PartialTransfer {
            transferred,
            error: Some(error),
        }) => Err(error.into()),
    }
}

/// Store backend backed by a single directory on a Linux system.
#[derive(Debug)]
pub struct DirectoryBackend {
    /// Path file descriptor to the store directory.
    inner: OwnedFd,
}

impl DirectoryBackend {
    /// Convert this [`DirectoryBackend`] into the [`OwnedFd`] of the store
    /// path.
    #[inline(always)]
    pub fn into_inner(self) -> OwnedFd {
        self.inner
    }

    /// Use an existing file descriptor pointing to a store directory.
    ///
    /// # Errors
    ///
    /// This method errors if the file descriptor does not point to a directory.
    #[inline]
    pub fn new(fd: OwnedFd) -> Result<Self, Error> {
        if is_directory(&fd).map_err(Into::<BackendError>::into)? {
            //SAFETY: we just verified that it's a directory
            Ok(unsafe { Self::new_unchecked(fd) })
        } else {
            return Err(BackendError::NotADirectory.into());
        }
    }

    //TODO: for data structures that build a thin layer on top of a file
    //      descriptor, like bubblebox's HostFile/HostDirectory and now this, it
    //      seems that we write a lot of the same code. how could we extract out
    //      the common parts to avoid repeating it? is this worth it?

    /// Use an existing file descriptor pointing to a store directory, without
    /// checking that it is a directory.
    ///
    /// # Safety
    ///
    /// The provided [`OwnedFd`] must be a path file descriptor representing a
    /// directory.
    #[inline(always)]
    pub unsafe fn new_unchecked(inner: OwnedFd) -> Self {
        Self { inner }
    }

    /// Open the store directory relative to the current working directory,
    /// creating it if it does not already exist.
    ///
    /// # Errors
    ///
    /// This method errors if opening the underlying file descriptor fails.
    #[inline]
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::open_at_internal::<0, 0>(Cwd, path)
    }

    /// Open the store directory relative to another file descriptor, creating
    /// it if it does not already exist.
    ///
    /// # Errors
    ///
    /// This method errors if opening the underlying file descriptor fails.
    #[inline]
    pub fn open_at<'fd>(
        relative_to: impl Into<AtFd<'fd>>,
        path: impl AsRef<Path>,
    ) -> Result<Self, Error> {
        Self::open_at_internal::<0, 0>(relative_to, path)
    }

    /// Open the store directory relative to another file descriptor without
    /// resolving symlinks, creating it if it does not already exist.
    ///
    /// # Errors
    ///
    /// This method errors if opening the underlying file descriptor fails.
    #[inline]
    pub fn open_at_no_symlinks<'fd>(
        relative_to: impl Into<AtFd<'fd>>,
        path: impl AsRef<Path>,
    ) -> Result<Self, Error> {
        Self::open_at_internal::<0, { linux::RESOLVE_NO_SYMLINKS }>(
            relative_to,
            path,
        )
    }

    /// Open the store directory beneath another path file descriptor, creating
    /// it if it does not already exist.
    ///
    /// # Errors
    ///
    /// This method errors if opening the underlying file descriptor fails.
    #[inline]
    pub fn open_at_beneath<'fd>(
        relative_to: impl Into<AtFd<'fd>>,
        path: impl AsRef<Path>,
    ) -> Result<Self, Error> {
        Self::open_at_internal::<0, { linux::RESOLVE_BENEATH }>(
            relative_to,
            path,
        )
    }

    /// Open the store directory beneath another path file descriptor without
    /// resolving symlinks, creating it if it does not already exist.
    ///
    /// # Errors
    ///
    /// This method errors if opening the underlying file descriptor fails.
    #[inline]
    pub fn open_at_beneath_no_symlinks<'fd>(
        relative_to: impl Into<AtFd<'fd>>,
        path: impl AsRef<Path>,
    ) -> Result<Self, Error> {
        Self::open_at_internal::<
            0,
            { linux::RESOLVE_NO_SYMLINKS | linux::RESOLVE_BENEATH },
        >(relative_to, path)
    }

    /// Implementation code used for directory opening.
    ///
    /// # Errors
    ///
    /// This method errors if opening the underlying file descriptor fails.
    #[inline(always)]
    fn open_at_internal<
        'fd,
        const OPEN_FLAGS: u32,
        const RESOLVE_FLAGS: u32,
    >(
        relative_to: impl Into<AtFd<'fd>>,
        path: impl AsRef<Path>,
    ) -> Result<Self, Error> {
        let relative_to = relative_to.into();
        Ok(path
            .as_ref()
            .as_os_str()
            .as_bytes()
            .with_c_str::<{ PATH_MAX }, _, BackendError, BackendError>(
                |path| {
                    let open_flags = linux::open_how {
                        flags: (linux::O_PATH
                            | linux::O_DIRECTORY
                            | linux::O_CLOEXEC
                            | OPEN_FLAGS) as u64,
                        mode: 0,
                        resolve: (linux::RESOLVE_NO_MAGICLINKS | RESOLVE_FLAGS)
                            as u64,
                    };

                    match retry_on_interrupt!({
                        syscalls::openat2(&relative_to, &path, &open_flags)
                    }) {
                        Ok(fd) => {
                            //SAFETY: `O_DIRECTORY` on `OPEN_FLAGS` ensures the
                            //        returned file descriptor refers to a
                            //        directory
                            return Ok(unsafe { Self::new_unchecked(fd) });
                        }
                        Err(e) if e.error() == Errno::NOENT => (),
                        Err(e) => return Err(e.into()),
                    }

                    //NOTE: the rest of this function creates the store. to my
                    //      knowledge there's no way to remove the potential
                    //      race of creating the store directory -> it being
                    //      removed between syscalls. it should be sufficient
                    //      for the caller to retry on this

                    syscalls::mkdirat(&relative_to, &path, Mode::RWXU.bits())?;

                    let fd = retry_on_interrupt!({
                        syscalls::openat2(&relative_to, &path, &open_flags)
                    })?;

                    //NOTE: we have to ensure that this is initialized properly
                    //      because unlike the lockfile, it has to be in sync
                    //      with the generation of files stored in their xattrs
                    //TODO: create a method that "repairs" the store if a
                    //      missing generation file exists by acquiring an
                    //      exclusive store lock then resetting the generation
                    //      count to 0 by writing generation 0 to all of the
                    //      files
                    let generation_fd = retry_on_interrupt!({
                        syscalls::openat2(
                            &fd,
                            c".",
                            linux::open_how {
                                flags: (linux::O_WRONLY
                                    | linux::O_CLOEXEC
                                    | linux::O_TMPFILE)
                                    as u64,
                                mode: Mode::RUSR.bits() as u64,
                                resolve: (linux::RESOLVE_NO_MAGICLINKS
                                    | linux::RESOLVE_BENEATH)
                                    as u64,
                            },
                        )
                    })?;

                    generation_fd.write_all(b"0")?;
                    syscalls::linkat(
                        &generation_fd,
                        c"",
                        &fd,
                        GENERATION_FILE_PATH,
                        linux::AT_EMPTY_PATH as ffi::c_int,
                    )?;

                    //SAFETY: as above, `O_DIRECTORY` ensures it refers to a
                    //        directory
                    Ok(unsafe { Self::new_unchecked(fd) })
                },
            )?)
    }

    /// Open the lock file for the store.
    fn lock_file(&self) -> Result<OwnedFd, Error> {
        Ok(store_lock_file(&self.inner)?)
    }

    /// Acquire a shared lock on the store.
    ///
    /// This is removed when the returned [`OwnedFd`] is dropped.
    fn shared_lock(&self) -> Result<OwnedFd, Error> {
        Ok(acquire_shared_store_lock(&self.inner)?)
    }

    /// Acquire an exclusive lock on the store.
    ///
    /// This is removed when the returned [`OwnedFd`] is dropped.
    fn exclusive_lock(&self) -> Result<OwnedFd, Error> {
        Ok(acquire_exclusive_store_lock(&self.inner)?)
    }
}

impl Backend for DirectoryBackend {
    type Hold = OwnedFd;

    fn entries(&self) -> impl Iterator<Item = Result<Entry, Error>> {
        //NOTE: turn our path file descriptor into one of the directory
        let fd = retry_on_interrupt!({
            syscalls::openat2(
                &self.inner,
                c"",
                linux::open_how {
                    flags: (linux::O_RDONLY
                        | linux::O_DIRECTORY
                        | linux::O_CLOEXEC
                        | linux::O_EMPTYPATH) as u64,
                    mode: 0,
                    resolve: (linux::RESOLVE_NO_MAGICLINKS
                        | linux::RESOLVE_BENEATH)
                        as u64,
                },
            )
        });

        iter::iter!(|| {
            if let Err(e) = try {
                let fd = fd?;

                //NOTE: 16kb buffer. i don't think this iterator is likely to
                //      be moved around all that much so the stack consumption
                //      shouldn't be an issue
                let mut buffer = [0; 8 * 1024];

                loop {
                    let (mut offset, n_bytes) =
                        syscalls::getdents64_raw(&fd, &mut buffer)?;
                    if offset >= n_bytes {
                        break;
                    }

                    //SAFETY: returned data from `getdents64_raw` satisfies
                    //        these requirements
                    while let Some((_, name)) = unsafe {
                        syscalls::next_dirent(&buffer, n_bytes, &mut offset)
                    } {
                        //NOTE: the only file names we care about here are
                        //      those we control, which are going to be valid
                        //      utf-8
                        if let Ok(hash) = Hash::from_hex(name.to_bytes()) {
                            yield Ok(Entry::new(hash));
                        }
                    }
                }
            } {
                yield Err(<SyscallError as Into<BackendError>>::into(e).into());
            }
        })()
    }

    fn insert_blob(&self) -> Result<impl WriteHandle, Error> {
        //NOTE: clone the fd to avoid holding a reference to this structure
        let store_fd = syscalls::fcntl_dupfd_cloexec(&self.inner)
            .map_err(Into::<BackendError>::into)?;
        let file_fd = retry_on_interrupt!({
            syscalls::openat2(
                &store_fd,
                c".",
                linux::open_how {
                    flags: (linux::O_RDWR
                        | linux::O_CLOEXEC
                        | linux::O_EMPTYPATH
                        | linux::O_TMPFILE) as u64,
                    //NOTE: is this a sane default for the permissions? should
                    //      we allow other users to read?
                    mode: (Mode::RUSR | Mode::WUSR).bits() as u64,
                    resolve: (linux::RESOLVE_NO_MAGICLINKS
                        | linux::RESOLVE_BENEATH)
                        as u64,
                },
            )
        })
        .map_err(Into::<BackendError>::into)?;

        Ok(FdWriteHandle::new(store_fd, file_fd))
    }

    fn insert_tree_manifest<'a>(
        &self,
        contents: impl IntoIterator<Item = (&'a Path, Entry)>,
    ) -> Result<Entry, Error> {
        todo!()
    }

    fn insert_composition_manifest(
        &self,
        contents: impl IntoIterator<Item = Entry>,
    ) -> Result<Entry, Error> {
        todo!()
    }

    fn read_blob(&self, entry: Entry) -> Result<impl io::Read, Error> {
        Ok(io::empty())
    }

    fn read_tree_manifest(
        &self,
        entry: Entry,
    ) -> impl IntoIterator<Item = Result<(PathBuf, Entry), Error>> {
        iter::empty()
    }

    fn read_composition_manifest(
        &self,
        entry: Entry,
    ) -> impl IntoIterator<Item = Result<Entry, Error>> {
        iter::empty()
    }

    fn classify_entry(&self, entry: Entry) -> Result<EntryKind, Error> {
        todo!()
    }

    fn hold_entry(&self, entry: Entry) -> Result<Self::Hold, Error> {
        todo!()
    }

    fn collect(
        &self,
        roots: impl IntoIterator<Item = Entry>,
    ) -> Result<impl IntoIterator<Item = Entry>, Error> {
        Ok(iter::empty())
    }
}

impl sealed::Sealed for DirectoryBackend {}

/// Handle to a blob being inserted into the store.
#[derive(Debug)]
pub struct FdWriteHandle {
    /// Path file descriptor to the store.
    store: OwnedFd,

    /// File descriptor to the `O_TMPFILE` created to write the contents to.
    file: OwnedFd,
}

impl FdWriteHandle {
    fn new(store: OwnedFd, file: OwnedFd) -> Self {
        Self { store, file }
    }
}

impl io::Write for FdWriteHandle {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        FdReadWrite::new(&self.file).write(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        FdReadWrite::new(&self.file).flush()
    }

    fn write_vectored(
        &mut self,
        bufs: &[IoSlice<'_>],
    ) -> Result<usize, io::Error> {
        FdReadWrite::new(&self.file).write_vectored(bufs)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }
}

impl WriteHandle for FdWriteHandle {
    fn finish(self) -> Result<Entry, Error> {
        //NOTE: ensure we're at the beginning of the file before letting blake3
        //      read it back in
        let _offset =
            syscalls::lseek(&self.file, 0, linux::SEEK_SET as ffi::c_int)
                .map_err(Into::<BackendError>::into)?;
        debug_assert!(
            _offset == 0,
            "seeking to the beginning of the blob being written should leave us at offset 0"
        );

        let mut hasher = Hasher::new();
        //TODO: for larger files it would be useful to use mmap + rayon but the
        //      blake3 crate api doesn't accept path file descriptors so we'd
        //      need to make a pull request for this
        //TODO: alternatively, consider looking into streaming hashes
        let _ = hasher
            .update_reader(FdReadWrite::new(&self.file))
            .map_err(Into::<BackendError>::into)?;
        let hash = hasher.finalize();
        let _lock = acquire_shared_store_lock(&self.store)?;
        let generation = current_generation(&self.store)?;

        let mut itoa_buffer = itoa::Buffer::new();
        syscalls::fsetxattr(
            &self.file,
            c"user.generation",
            itoa_buffer.format(generation).as_bytes(),
            linux::XATTR_CREATE as ffi::c_int,
        )
        .map_err(Into::<BackendError>::into)?;
        syscalls::fsetxattr(
            &self.file,
            c"user.store_type",
            b"blob",
            linux::XATTR_CREATE as ffi::c_int,
        )
        .map_err(Into::<BackendError>::into)?;

        syscalls::fchmod(&self.file, Mode::RUSR.bits())
            .map_err(Into::<BackendError>::into)?;

        hash.to_hex()
            .as_str()
            .with_c_str::<{ PATH_MAX }, _, BackendError, BackendError>(
                |file_name| match syscalls::linkat(
                    &self.file,
                    c"",
                    &self.store,
                    &file_name,
                    linux::AT_EMPTY_PATH as ffi::c_int,
                ) {
                    Ok(()) => Ok(()),
                    //NOTE: hashes match so it is fine
                    //TODO: should it update the generation value? a manifest
                    //      referencing it would anyway
                    Err(e) if e.error() == Errno::EXIST => Ok(()),
                    Err(e) => return Err(e.into()),
                },
            )?;

        Ok(Entry::new(hash))
    }
}

impl sealed::Sealed for FdWriteHandle {}
