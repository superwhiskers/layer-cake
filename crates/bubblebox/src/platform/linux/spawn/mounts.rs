// SPDX-License-Identifier: AGPL-3.0-only

//! Helpers for setting up mounts.

use core::{
    ffi::{self, CStr},
    iter::TrustedLen,
};
use linux_raw_sys::general as linux;
use meowix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    mode::Mode,
    retry_on_interrupt, syscalls,
    util::{Cwd, PATH_COMPONENT_MAX, WithCStr},
};

use super::{
    super::{
        mounts::{
            BindMount, File, Mount, MountAttributes, MountInner, Owner,
            ProcHidepid, ProcPidNamespace, ProcSubset,
        },
        paths,
    },
    errors::{
        PostSpawnGuest as PostSpawnGuestError,
        PostSpawnGuestOther as PostSpawnGuestOtherError,
    },
    fmt,
};
use crate::paths::Guest;

/// Open the parent directory of the given path, returning the file descriptor
/// and file name.
///
/// # Errors
///
/// This function errors if `openat2(2)` failed, if the path lacked a file name,
/// or if the path lacked a parent directory.
pub fn open_parent_in_root(
    root_fd: impl AsFd,
    path: &Guest,
) -> Result<(OwnedFd, &CStr), PostSpawnGuestError> {
    let path_fd = retry_on_interrupt!({
        syscalls::openat2(
            root_fd.as_fd(),
            path.inner.parent_dir(),
            linux::open_how {
                flags: (linux::O_PATH | linux::O_CLOEXEC | linux::O_DIRECTORY)
                    as u64,
                mode: 0,
                resolve: (linux::RESOLVE_IN_ROOT
                    | linux::RESOLVE_NO_MAGICLINKS
                    | linux::RESOLVE_NO_SYMLINKS)
                    as u64,
            },
        )
    })?;

    Ok((path_fd, path.inner.file_name()))
}

/// Resolved mapping.
pub enum ResolvedMount<'a> {
    //TODO: i think some of these could be cleaned up. the inconsistency
    //      between [`File`] being its own thing and
    //      [`ResolvedMount::Directory`] storing the owner & perms directly
    //      is pretty weird
    /// Mapping resolved to a detached mount object.
    Fd {
        /// Detached mount object.
        fd: OwnedFd,

        /// Destination on the guest.
        destination: &'a Guest,

        /// Whether or not the mount object is a directory.
        ///
        /// In order to mount, we need to have a destination object of the
        /// same "kind". The relevant distinction is whether or not
        /// the mount object is a directory.
        is_directory: bool,
    },

    /// Synthetic file mapping.
    File {
        /// Description of the file.
        file: &'a File,

        /// Destination on the guest.
        destination: &'a Guest,
    },

    /// Empty directory mapping.
    Directory {
        /// Owner of the directory.
        owner: Owner,

        /// Permissions applied to the directory.
        permissions: Mode,

        /// Destination on the guest.
        destination: &'a Guest,
    },
}

/// Resolve an enumerable set of [`Guest`], [`Mount`] pairs to synthetic files,
/// empty directories, and detached mount objects for mappings other than bind
/// mappings from the host.
///
/// # Notes
///
/// This function initializes all slots in the spare capacity of `resolved`
/// where non-bind mounts would go. After calling this function, those slots are
/// guaranteed to be initialized. This function returns the number of slots
/// initialized for accounting purposes.
///
/// # Errors
///
/// This function errors if opening and interacting with filesystem
/// configuration objects for a mapped filesystem fails.
pub fn resolve_nonbind_mappings<'a, I>(
    mappings: I,
    resolved: &mut Vec<ResolvedMount<'a>>,
) -> Result<usize, PostSpawnGuestError>
where
    I: IntoIterator<Item = (&'a Guest, &'a Mount<'a>)>,
    I::IntoIter: TrustedLen,
{
    let mappings = mappings.into_iter().enumerate();

    resolved
        .is_empty()
        .ok_or(PostSpawnGuestOtherError::NonzeroResolvedLen)?;
    (resolved.capacity()
        >= mappings
            .size_hint()
            .1
            .ok_or(PostSpawnGuestOtherError::BufferTooSmall)?)
    .ok_or(PostSpawnGuestOtherError::BufferTooSmall)?;

    let resolved = resolved.spare_capacity_mut();

    let mut n_non_binds = 0;
    for (i, (destination, source)) in mappings {
        let resolved_mount = match &source.inner {
            MountInner::Procfs {
                hidepid,
                gid,
                subset,
                namespace,
                attributes,
            } => {
                let fs_fd = syscalls::fsopen(c"proc", linux::FSOPEN_CLOEXEC)?;
                let mut buffer = itoa::Buffer::new();

                syscalls::fsconfig_set_string(
                    &fs_fd,
                    c"hidepid",
                    match hidepid {
                        ProcHidepid::Off => c"off",
                        ProcHidepid::NoAccess => c"noaccess",
                        ProcHidepid::Invisible => c"invisible",
                        ProcHidepid::Ptraceable => c"ptraceable",
                    },
                )?;

                if let Some(gid) = gid {
                    //TODO: we should probably pin this to a proper type
                    buffer.format(gid.into_raw()).with_c_str::<{
                        fmt::unsigned_decimal_digits_upper_bound::<u32>() + 1
                    }, _, PostSpawnGuestError>(
                        |gid| {
                            syscalls::fsconfig_set_string(&fs_fd, c"gid", gid)?;

                            Ok(())
                        },
                    )?;
                }

                if *subset == ProcSubset::Pid {
                    syscalls::fsconfig_set_string(&fs_fd, c"subset", c"pid")?;
                }

                if let ProcPidNamespace::Fd(fd) = namespace {
                    syscalls::fsconfig_set_fd(&fs_fd, c"pidns", fd)?;
                }

                syscalls::fsconfig_cmd_create_excl(&fs_fd)?;
                ResolvedMount::Fd {
                    fd: syscalls::fsmount(
                        fs_fd,
                        linux::FSMOUNT_CLOEXEC,
                        attributes.into_mount_attr(),
                    )?,
                    destination,
                    is_directory: true,
                }
            }
            MountInner::Mqueue { attributes } => {
                let fs_fd = syscalls::fsopen(c"mqueue", linux::FSOPEN_CLOEXEC)?;

                syscalls::fsconfig_cmd_create_excl(&fs_fd)?;
                ResolvedMount::Fd {
                    fd: syscalls::fsmount(
                        fs_fd,
                        linux::FSMOUNT_CLOEXEC,
                        attributes.into_mount_attr(),
                    )?,
                    destination,
                    is_directory: true,
                }
            }
            MountInner::File(file) => ResolvedMount::File { file, destination },
            MountInner::EmptyDirectory { owner, permissions } => {
                ResolvedMount::Directory {
                    owner: *owner,
                    permissions: *permissions,
                    destination,
                }
            }
            MountInner::Tmpfs {
                size,
                permissions,
                attributes,
                ..
            } => {
                let fs_fd = syscalls::fsopen(c"tmpfs", linux::FSOPEN_CLOEXEC)?;
                //let mut buffer = itoa::Buffer::new();

                if let Some(size) = size {
                    size.as_str().with_c_str::<{
                        //TODO: we won't need this anymore once we use a proper
                        //      enum for the size or something like that, but
                        //      for now, let's cap it at u32 literal size + 1
                        //      character for the suffix, and another for the
                        //      null byte.
                        fmt::unsigned_decimal_digits_upper_bound::<u32>() + 2
                    }, _, PostSpawnGuestError>(
                        |size| {
                            syscalls::fsconfig_set_string(
                                &fs_fd, c"size", size,
                            )?;

                            Ok(())
                        },
                    )?;
                }

                //TODO: uncomment when newuidmap/newgidmap or
                //      systemd-nsresourced is supported w/ a check prior
                /*if let Owner::Ids { user, group } = owner {
                    syscalls::fsconfig_set_string(
                        &fs_fd,
                        c"gid",
                        //TODO: needs fixing
                        buffer.format(group.as_raw()),
                    )?;
                    syscalls::fsconfig_set_string(
                        &fs_fd,
                        c"uid",
                        //TODO: needs fixing
                        buffer.format(user.as_raw()),
                    )?;
                }*/

                let mut mode = *b"0000\0";
                let mut permissions = permissions.bits() & 0o7777;
                for c in mode.iter_mut().rev().skip(1) {
                    *c = b'0'.saturating_add((permissions & 0o7) as u8);
                    permissions >>= 3;
                }

                //SAFETY: we constructed it with a null terminator above
                syscalls::fsconfig_set_string(&fs_fd, c"mode", unsafe {
                    CStr::from_bytes_with_nul_unchecked(mode.as_slice())
                })?;

                syscalls::fsconfig_cmd_create_excl(&fs_fd)?;

                ResolvedMount::Fd {
                    fd: syscalls::fsmount(
                        fs_fd,
                        linux::FSMOUNT_CLOEXEC,
                        attributes.into_mount_attr(),
                    )?,
                    destination,
                    is_directory: true,
                }
            }
            //NOTE: these are handled separately
            MountInner::Bind(_) => continue,
        };

        //SAFETY: we've ensured at the top of this function that there is
        //        enough space
        let _ = unsafe { resolved.get_unchecked_mut(i) }.write(resolved_mount);
        n_non_binds += 1;
    }

    Ok(n_non_binds)
}

/// Creates mount namespaces for each of the bind mounts and enters them to
/// create detached mounts.
///
/// It is necessary for this to be done separate from synthetic mounts due to
/// namespace rules. This function writes to the capacity of `resolved` the
/// resolved bind mounts and no others.
///
/// # Notes
///
/// This function initializes all slots in the spare capacity of `resolved`
/// where bind mounts would go. After calling this function, those slots are
/// guaranteed to be initialized. This function returns the number of slots
/// initialized for accounting purposes.
///
/// # Errors
///
/// This function errors if creating new mount namespaces or entering them
/// sequentially to create detached mount objects fails.
pub fn resolve_bind_mappings<'a, 'b, I>(
    mappings: I,
    resolved: &mut Vec<ResolvedMount<'a>>,
    namespace_fd_scratch_space: &mut Vec<(
        // the index into the resolved mapping
        //
        // this is necessary because we want to be able to keep the in-order
        // traversal that a btreemap provides for our mounts
        usize,
        // owned fd representing the generated namespace
        OwnedFd,
        // destination of the mount
        &'a Guest,
        // file to construct the detached mount from and the fd to verify it,
        // if this is a file bind mount
        Option<(&'b CStr, BorrowedFd<'b>)>,
        // mount attributes applied to the detached mount
        MountAttributes,
        // whether or not this is a recursive mount
        bool,
    )>,
) -> Result<usize, PostSpawnGuestError>
where
    I: IntoIterator<Item = (&'a Guest, &'a Mount<'a>)>,
    I::IntoIter: TrustedLen,
    'a: 'b,
{
    let mappings = mappings.into_iter().enumerate();

    resolved
        .is_empty()
        .ok_or(PostSpawnGuestOtherError::NonzeroResolvedLen)?;
    (resolved.capacity()
        >= mappings
            .size_hint()
            .1
            .ok_or(PostSpawnGuestOtherError::BufferTooSmall)?)
    .ok_or(PostSpawnGuestOtherError::BufferTooSmall)?;

    let resolved = resolved.spare_capacity_mut();

    //NOTE: so, if you're doing an absurd amount of bind mounts or already have
    //      contention for that resource on your system, this could be an issue.
    //      my local reference point is user.max_mnt_namespaces is 512051. i
    //      don't think this is likely, but if it is, there *are* ways around
    //      this, just let me know if you run into issues

    //TODO: consider optimizing this process by grouping together file bind
    //      mounts sharing a parent directory. could share file descriptors.
    //      should work with btreemap

    for (i, (destination, source)) in mappings {
        let mut flags = syscalls::OPEN_TREE_NAMESPACE
            | linux::OPEN_TREE_CLOEXEC
            | linux::AT_EMPTY_PATH;
        let mut file_info = None;
        let (dirfd, attributes, is_recursive) = match &source.inner {
            MountInner::Bind(BindMount::File {
                dirfd,
                name,
                fd,
                attributes,
            }) => {
                file_info = Some((*name, *fd));

                //NOTE: file mounts cannot be recursive
                (dirfd, *attributes, false)
            }
            MountInner::Bind(BindMount::Directory {
                fd,
                attributes,
                is_recursive,
            }) => {
                if *is_recursive {
                    flags |= linux::AT_RECURSIVE;
                }

                (fd, *attributes, *is_recursive)
            }
            _ => continue,
        };

        let namespace_fd = syscalls::open_tree(dirfd, c"", flags)?;
        namespace_fd_scratch_space.push((
            i,
            namespace_fd,
            destination,
            file_info,
            attributes,
            is_recursive,
        ));
    }

    //NOTE: so, there's some real subtle ordering here. we need to capture
    //      those namespace fds prior to unsharing our own mount namespace so
    //      they stay valid for our purposes.

    // SAFETY: only unsharing the mount namespace
    unsafe {
        syscalls::unshare(linux::CLONE_NEWNS as ffi::c_int)?;
    }

    let original_ns_flags = syscalls::OPEN_TREE_NAMESPACE
        | linux::OPEN_TREE_CLOEXEC
        | linux::AT_EMPTY_PATH
        | linux::AT_RECURSIVE;

    //NOTE: capture the original mount tree
    let original_ns = syscalls::open_tree(Cwd, c"/", original_ns_flags)?;

    let n_binds = namespace_fd_scratch_space.len();
    for (i, namespace_fd, destination, file_info, attributes, is_recursive) in
        namespace_fd_scratch_space
    {
        syscalls::setns(namespace_fd, linux::CLONE_NEWNS as ffi::c_int)?;
        syscalls::chdir(c"/")?;

        let mut open_tree_flags =
            linux::OPEN_TREE_CLONE | linux::OPEN_TREE_CLOEXEC;

        if *is_recursive {
            open_tree_flags |= linux::AT_RECURSIVE;
        }

        let mount_attr = linux::mount_attr {
            attr_set: attributes.into_mount_attr().into(),
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };

        let fd = if let Some((name, _)) = &file_info {
            name.with_c_str::<{ PATH_COMPONENT_MAX }, _, PostSpawnGuestError>(
                |name| {
                    syscalls::open_tree_attr(
                        Cwd,
                        name,
                        open_tree_flags,
                        mount_attr,
                    )
                    .map_err(Into::into)
                },
            )?
        } else {
            syscalls::open_tree_attr(Cwd, c"/", open_tree_flags, mount_attr)?
        };

        if let Some((_, original_fd)) = file_info {
            paths::same_file_identity(original_fd.as_fd(), fd.as_fd())?
                .ok_or(PostSpawnGuestOtherError::BindMappedFileMismatch)?;
        }

        //SAFETY: we've ensured at the top of this function that there is
        //        enough space
        let _ = unsafe { resolved.get_unchecked_mut(*i) }.write(
            ResolvedMount::Fd {
                fd,
                destination,
                is_directory: file_info.is_none(),
            },
        );
    }

    syscalls::setns(original_ns, linux::CLONE_NEWNS as ffi::c_int)?;
    syscalls::chdir(c"/")?;

    Ok(n_binds)
}
