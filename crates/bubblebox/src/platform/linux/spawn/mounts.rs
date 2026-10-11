// SPDX-License-Identifier: AGPL-3.0-only

//! Helpers for setting up mounts.

//TODO: avoid capturing the host tree if we don't bind anything

use core::{
    ffi::{self, CStr},
    iter::TrustedLen,
};
use linux_raw_sys::general as linux;
use meowix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    ids::RawGid,
    mode::Mode,
    retry_on_interrupt, syscalls,
    util::{Cwd, PATH_COMPONENT_MAX, WithCStr},
};

use super::{
    super::{
        mounts::{
            BindMount, File, Mount, MountAttributes, MountInner, Owner,
            ProcHidepid, ProcPidNamespace, ProcSubset, TmpfsSize, UpperDirs,
            UpperDirsInner,
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

/// Apply a [`TmpfsSize`] to a tmpfs configuration context.
pub fn apply_tmpfs_size(
    fs_fd: impl AsFd,
    size: TmpfsSize,
    max_inodes: Option<u64>,
) -> Result<(), PostSpawnGuestError> {
    /// Sizes the buffer we use to format percentages.
    ///
    /// Sized as the upper bound on the number of digits in a u64 + a byte for
    /// "%" and a null byte.
    const fn size_percent_buffer() -> usize {
        fmt::unsigned_decimal_digits_upper_bound::<u64>().saturating_add(2)
    }
    let mut buffer = itoa::Buffer::new();

    match size {
        TmpfsSize::Unlimited => {
            syscalls::fsconfig_set_string(&fs_fd, c"size", c"0")?;
        }
        TmpfsSize::Bytes(bytes) => {
            buffer.format(bytes).with_c_str::<{
                fmt::unsigned_decimal_digits_upper_bound::<u64>()
                    .saturating_add(1)
            }, _, _, PostSpawnGuestError>(
                |bytes| syscalls::fsconfig_set_string(&fs_fd, c"size", bytes),
            )?;
        }
        TmpfsSize::Percent(percent) => {
            let mut buffer = [0u8; size_percent_buffer()];
            let mut offset = 0;

            fmt::write_integer(&mut buffer, &mut offset, percent)?;
            fmt::write_bytes(&mut buffer, &mut offset, b"%\0")?;

            syscalls::fsconfig_set_string(
                &fs_fd,
                c"size",
                //SAFETY: we write the null terminator above and size the
                //        buffer appropriately
                unsafe {
                    CStr::from_bytes_with_nul_unchecked(buffer.as_slice())
                },
            )?;
        }
    }

    if let Some(max_inodes) = max_inodes {
        buffer.format(max_inodes).with_c_str::<{
            fmt::unsigned_decimal_digits_upper_bound::<u64>().saturating_add(1)
        }, _, _, PostSpawnGuestError>(
            |max_inodes| {
                syscalls::fsconfig_set_string(&fs_fd, c"nr_inodes", max_inodes)
            },
        )?;
    }

    Ok(())
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

    /// Symlink mapping.
    Symlink {
        /// Source of the symlink.
        source: &'a Guest,

        /// Destination of the symlink.
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
    I: IntoIterator<Item = (&'a Guest, &'a Mount)>,
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
                    buffer.format(gid.into_raw()).with_c_str::<{
                        fmt::unsigned_decimal_digits_upper_bound::<RawGid>() + 1
                    }, _, _, PostSpawnGuestError>(
                        |gid| {
                            syscalls::fsconfig_set_string(&fs_fd, c"gid", gid)
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

                //NOTE: we use `FSCONFIG_CMD_CREATE` here instead of
                //      `FSCONFIG_CMD_CREATE_EXCL` as the latter will not work
                //      due to there only ever being one `mqueue` instance in
                //      an IPC namespace, and this instance is created upon IPC
                //      namespace initialization
                syscalls::fsconfig_cmd_create(&fs_fd)?;
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
            MountInner::Symlink(source) => ResolvedMount::Symlink {
                source,
                destination,
            },
            MountInner::EmptyDirectory { owner, permissions } => {
                ResolvedMount::Directory {
                    owner: *owner,
                    permissions: *permissions,
                    destination,
                }
            }
            MountInner::Tmpfs {
                size,
                max_inodes,
                permissions,
                attributes,
                ..
            } => {
                let fs_fd = syscalls::fsopen(c"tmpfs", linux::FSOPEN_CLOEXEC)?;

                apply_tmpfs_size(&fs_fd, *size, *max_inodes)?;

                //TODO: uncomment when newuidmap/newgidmap or
                //      systemd-nsresourced is supported w/ a check prior
                /*let mut buffer = itoa::Buffer::new();
                if let Owner::Ids { user, group } = owner {
                    syscalls::fsconfig_set_string(
                        &fs_fd,
                        c"gid",
                        buffer.format(group.as_raw()),
                    )?;
                    syscalls::fsconfig_set_string(
                        &fs_fd,
                        c"uid",
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
            MountInner::Overlay { .. } | MountInner::Bind(_) => continue,
        };

        //SAFETY: we've ensured at the top of this function that there is
        //        enough space
        let _ = unsafe { resolved.get_unchecked_mut(i) }.write(resolved_mount);
        n_non_binds += 1;
    }

    Ok(n_non_binds)
}

/// Creates mount namespaces for each of the bind mounts and overlay mount
/// components sourced from the host, then enters them to create detached
/// mounts.
///
/// It is necessary for this to be done separate from synthetic mounts due to
/// namespace rules. This function writes to the capacity of `resolved` the
/// resolved bind mounts and no others.
///
/// Overlay mounts must be finished by calling
/// [`finish_overlay_mount_resolution`]. See its documentation for more details.
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
        // index into the resolved mapping
        //
        // this is necessary because we want to be able to keep the in-order
        // traversal that a btreemap provides for our mounts
        usize,
        // owned fd representing the generated namespace
        OwnedFd,
        // destination of the mount
        &'a Guest,
        // file to construct the detached mount from and the fd to verify it,
        // if this is a file bind mount. last value is a boolean indicating if
        // we want to open a symlink or resolve one. equivalent to
        // `AT_SYMLINK_NOFOLLOW` when true
        Option<(&'b CStr, BorrowedFd<'b>, bool)>,
        // mount attributes applied to the detached mount
        MountAttributes,
        // whether or not this is a recursive mount
        bool,
    )>,
    // for each overlay mount, holds all constituent mounts sourced from the
    // host
    overlay_mount_scratch_space: &mut Vec<OwnedFd>,
    // stores information about overlay mounts inside the mappings
    overlay_mounts: &mut Vec<(
        // index into the resolved mapping
        usize,
        // destination of the mount
        &'a Guest,
        // lowerdirs
        &'a [OwnedFd],
        // datadirs
        &'a [OwnedFd],
        // upperdir information
        &'a Option<UpperDirs>,
        // mount attributes applied to the detached mount
        MountAttributes,
    )>,
) -> Result<usize, PostSpawnGuestError>
where
    I: IntoIterator<Item = (&'a Guest, &'a Mount)>,
    I::IntoIter: TrustedLen,
    'a: 'b,
{
    let mappings = mappings.into_iter().enumerate();

    resolved
        .is_empty()
        .ok_or(PostSpawnGuestOtherError::NonzeroResolvedLen)?;

    let mapping_size = mappings
        .size_hint()
        .1
        .ok_or(PostSpawnGuestOtherError::BufferTooSmall)?;

    (resolved.capacity() >= mapping_size)
        .ok_or(PostSpawnGuestOtherError::BufferTooSmall)?;
    (namespace_fd_scratch_space.capacity() >= mapping_size)
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
        let mut flags = linux::OPEN_TREE_NAMESPACE
            | linux::OPEN_TREE_CLOEXEC
            | linux::AT_EMPTY_PATH;
        let mut file_info = None;
        let (dirfd, attributes, is_recursive) = match &source.inner {
            MountInner::Bind(BindMount::File {
                dirfd,
                name,
                fd,
                attributes,
                is_symlink,
            }) => {
                file_info = Some((name.as_c_str(), fd.as_fd(), *is_symlink));

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
            MountInner::Overlay {
                lowerdirs,
                datadirs,
                upperdirs,
                attributes,
            } => {
                //SAFETY: we've sized this buffer appropriately
                let _ = unsafe {
                    overlay_mounts
                        .push_within_capacity((
                            i,
                            destination,
                            lowerdirs,
                            datadirs,
                            upperdirs,
                            *attributes,
                        ))
                        .unwrap_unchecked()
                };

                for dir in lowerdirs.into_iter().chain(datadirs) {
                    let namespace_fd = syscalls::open_tree(dir, c"", flags)?;

                    //SAFETY: we've sized this buffer appropriately during
                    //        mount tree validation
                    let _ = unsafe {
                        overlay_mount_scratch_space
                            .push_within_capacity(namespace_fd)
                            .unwrap_unchecked()
                    };
                }

                if let Some(UpperDirs {
                    inner: UpperDirsInner::Fd { parent, .. },
                }) = &upperdirs
                {
                    let namespace_fd = syscalls::open_tree(parent, c"", flags)?;

                    //SAFETY: we've sized this buffer appropriately during
                    //        mount tree validation
                    let _ = unsafe {
                        overlay_mount_scratch_space
                            .push_within_capacity(namespace_fd)
                            .unwrap_unchecked()
                    };
                }

                continue;
            }
            _ => continue,
        };

        let namespace_fd = syscalls::open_tree(dirfd, c"", flags)?;

        //SAFETY: we check at the beginning of the function that the capacity
        //        is greater than or equal to the number of mappings
        let _ = unsafe {
            namespace_fd_scratch_space
                .push_within_capacity((
                    i,
                    namespace_fd,
                    destination,
                    file_info,
                    attributes,
                    is_recursive,
                ))
                .unwrap_unchecked()
        };
    }

    //NOTE: so, there's some real subtle ordering here. we need to capture
    //      those namespace fds prior to unsharing our own mount namespace so
    //      they stay valid for our purposes.

    // SAFETY: only unsharing the mount namespace
    unsafe {
        syscalls::unshare(linux::CLONE_NEWNS as ffi::c_int)?;
    }

    let original_ns_flags = linux::OPEN_TREE_NAMESPACE
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
            //NOTE: ensure that mount events do not propagate in or out of this
            //      bind mount
            propagation: linux::MS_PRIVATE as _,
            userns_fd: 0,
        };

        let fd = if let Some((name, _, is_symlink)) = &file_info {
            name.with_c_str::<{ PATH_COMPONENT_MAX }, _, _, PostSpawnGuestError>(
                |name| {
                    syscalls::open_tree_attr(
                        Cwd,
                        name,
                        open_tree_flags | if *is_symlink { linux::AT_SYMLINK_NOFOLLOW } else { 0 },
                        mount_attr,
                    )
                },
            )?
        } else {
            syscalls::open_tree_attr(Cwd, c"/", open_tree_flags, mount_attr)?
        };

        if let Some((_, original_fd, _)) = file_info {
            paths::same_file_identity(original_fd.as_fd(), fd.as_fd())?
                .ok_or(PostSpawnGuestOtherError::HostSourcedFileMismatch)?;
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

    //NOTE: pre-mapping overlay mount handling

    //NOTE: recursive does not matter here, these are immutable
    const OVERLAY_OPEN_TREE_FLAGS: ffi::c_uint =
        linux::OPEN_TREE_CLONE | linux::OPEN_TREE_CLOEXEC | linux::AT_RECURSIVE;

    const OVERLAY_MOUNT_ATTR: linux::mount_attr = linux::mount_attr {
        attr_set: MountAttributes {
            //TODO: consider setting read_only on lowerdir/workdir for
            //      defense-in-depth
            read_only: false,
            no_setuid: true,
            no_devices: true,
            no_execution: false,
            no_symlink_following: false,
        }
        .into_mount_attr()
        .into(),
        attr_clr: 0,
        propagation: linux::MS_PRIVATE as _,
        userns_fd: 0,
    };

    //NOTE: so we have to convert these into detached mounts prior to setting
    //      up id mappings inside the user namespace, but we have to finish
    //      overlayfs configuration after because we need to have workdir and
    //      upperdir share the same filesystem when using a tmpfs, which
    //      requires us to mkdirat on it, which needs id mappings to be set up
    for ns_fd in overlay_mount_scratch_space.iter_mut() {
        syscalls::setns(&mut *ns_fd, linux::CLONE_NEWNS as ffi::c_int)?;
        syscalls::chdir(c"/")?;

        *ns_fd = syscalls::open_tree_attr(
            Cwd,
            c"/",
            OVERLAY_OPEN_TREE_FLAGS,
            OVERLAY_MOUNT_ATTR,
        )?;
    }

    syscalls::setns(original_ns, linux::CLONE_NEWNS as ffi::c_int)?;
    syscalls::chdir(c"/")?;

    Ok(n_binds)
}

/// Finishes resolving OverlayFS mounts.
///
/// It is necessary for this to happen in two phases because host mount capture
/// needs to happen prior to creating a new mount filesystem and writing UID/GID
/// mappings as they need access to the real host filesystem. However, creating
/// the detached mount needs to happen after because it needs to have the
/// UID/GID mapping set up if the user wants a tmpfs-backend `upperdir` and
/// `workdir`. This is because they need to be on the same mount, and doing this
/// requires creating directories on the tmpfs mount, which requires a mapping
/// to be set up.
///
/// # Notes
///
/// This function initializes all slots in the spare capacity of `resolved`
/// where OverlayFS mounts would go. After calling this function, those slots
/// are guaranteed to be initialized. This function returns the number of slots
/// initialized for accounting purposes.
///
/// # Errors
///
/// This function errors if building OverlayFS mounts or tmpfs mount
/// constituents fails.
pub fn finish_overlay_mount_resolution<'a>(
    resolved: &mut Vec<ResolvedMount<'a>>,
    overlay_mount_scratch_space: &mut Vec<OwnedFd>,
    overlay_mounts: &mut Vec<(
        usize,
        &'a Guest,
        &'a [OwnedFd],
        &'a [OwnedFd],
        &'a Option<UpperDirs>,
        MountAttributes,
    )>,
) -> Result<usize, PostSpawnGuestError> {
    let resolved = resolved.spare_capacity_mut();
    let n_overlay = overlay_mounts.len();
    let mut mount_i = 0;
    for (i, destination, lowerdirs, datadirs, upperdirs, attributes) in
        overlay_mounts
    {
        let fs_fd = syscalls::fsopen(c"overlay", linux::FSOPEN_CLOEXEC)?;

        for _ in 0..lowerdirs.len() {
            //SAFETY: size bounded by sum of all lowerdir, datadir counts and
            //        the number of fd upperdir/workdir backed overlay mounts
            let mount_fd =
                unsafe { overlay_mount_scratch_space.get_unchecked(mount_i) };
            mount_i += 1;

            syscalls::fsconfig_set_fd(&fs_fd, c"lowerdir+", mount_fd)?;
        }

        for _ in 0..datadirs.len() {
            //SAFETY: size bounded by sum of all lowerdir, datadir counts and
            //        the number of fd upperdir/workdir backed overlay mounts
            let mount_fd =
                unsafe { overlay_mount_scratch_space.get_unchecked(mount_i) };
            mount_i += 1;

            syscalls::fsconfig_set_fd(&fs_fd, c"datadir+", mount_fd)?;
        }

        let mut _tmpfs_guard = None;
        if let Some(upperdirs) = upperdirs {
            match upperdirs.inner {
                UpperDirsInner::Fd {
                    ref upperdir,
                    ref upperdir_fd,
                    ref workdir,
                    ref workdir_fd,
                    ..
                } => {
                    //SAFETY: size bounded by sum of all lowerdir, datadir
                    //        counts and the number of fd upperdir/workdir
                    //        backed overlay mounts
                    let mount_fd = unsafe {
                        overlay_mount_scratch_space.get_unchecked(mount_i)
                    };
                    mount_i += 1;

                    let workdir = retry_on_interrupt!({
                        syscalls::openat2(
                            &mount_fd,
                            &workdir,
                            linux::open_how {
                                flags: (linux::O_PATH
                                    | linux::O_CLOEXEC
                                    | linux::O_DIRECTORY)
                                    as u64,
                                mode: 0,
                                resolve: (linux::RESOLVE_NO_MAGICLINKS
                                    | linux::RESOLVE_BENEATH
                                    | linux::RESOLVE_NO_XDEV)
                                    as u64,
                            },
                        )
                    })?;
                    paths::same_file_identity(&workdir, &workdir_fd)?.ok_or(
                        PostSpawnGuestOtherError::HostSourcedFileMismatch,
                    )?;

                    let upperdir = retry_on_interrupt!({
                        syscalls::openat2(
                            &mount_fd,
                            &upperdir,
                            linux::open_how {
                                flags: (linux::O_PATH
                                    | linux::O_CLOEXEC
                                    | linux::O_DIRECTORY)
                                    as u64,
                                mode: 0,
                                resolve: (linux::RESOLVE_NO_MAGICLINKS
                                    | linux::RESOLVE_BENEATH
                                    | linux::RESOLVE_NO_XDEV)
                                    as u64,
                            },
                        )
                    })?;
                    paths::same_file_identity(&upperdir, &upperdir_fd)?.ok_or(
                        PostSpawnGuestOtherError::HostSourcedFileMismatch,
                    )?;

                    syscalls::fsconfig_set_fd(&fs_fd, c"workdir", workdir)?;
                    syscalls::fsconfig_set_fd(&fs_fd, c"upperdir", upperdir)?;
                }
                UpperDirsInner::Tmpfs { size, max_inodes } => {
                    let tmpfs_fd =
                        syscalls::fsopen(c"tmpfs", linux::FSOPEN_CLOEXEC)?;

                    apply_tmpfs_size(&tmpfs_fd, size, max_inodes)?;

                    syscalls::fsconfig_cmd_create_excl(&tmpfs_fd)?;

                    let tmpfs = syscalls::fsmount(
                        tmpfs_fd,
                        linux::FSMOUNT_CLOEXEC,
                        MountAttributes {
                            read_only: false,
                            no_setuid: true,
                            no_devices: true,
                            no_execution: false,
                            no_symlink_following: false,
                        }
                        .into_mount_attr(),
                    )?;

                    syscalls::mkdirat(&tmpfs, c"upperdir", Mode::RWXU.bits())?;
                    syscalls::mkdirat(&tmpfs, c"workdir", Mode::RWXU.bits())?;

                    let upperdir_fd = syscalls::openat2(
                        &tmpfs,
                        c"upperdir",
                        linux::open_how {
                            flags: (linux::O_PATH
                                | linux::O_DIRECTORY
                                | linux::O_CLOEXEC)
                                as u64,
                            mode: 0,
                            resolve: (linux::RESOLVE_BENEATH
                                | linux::RESOLVE_NO_MAGICLINKS)
                                as u64,
                        },
                    )?;
                    let workdir_fd = syscalls::openat2(
                        &tmpfs,
                        c"workdir",
                        linux::open_how {
                            flags: (linux::O_PATH
                                | linux::O_DIRECTORY
                                | linux::O_CLOEXEC)
                                as u64,
                            mode: 0,
                            resolve: (linux::RESOLVE_NO_MAGICLINKS
                                | linux::RESOLVE_BENEATH)
                                as u64,
                        },
                    )?;

                    //NOTE: the filesystem fd needs to live until the overlay
                    //      filesystem is created
                    _tmpfs_guard = Some(tmpfs);

                    syscalls::fsconfig_set_fd(
                        &fs_fd,
                        c"upperdir",
                        upperdir_fd,
                    )?;
                    syscalls::fsconfig_set_fd(&fs_fd, c"workdir", workdir_fd)?;
                }
            }
        };

        syscalls::fsconfig_set_flag(&fs_fd, c"userxattr")?;
        syscalls::fsconfig_cmd_create_excl(&fs_fd)?;

        //SAFETY: we've ensured at the top of this function that there is
        //        enough space
        let _ = unsafe { resolved.get_unchecked_mut(*i) }.write(
            ResolvedMount::Fd {
                fd: syscalls::fsmount(
                    fs_fd,
                    linux::FSMOUNT_CLOEXEC,
                    attributes.into_mount_attr(),
                )?,
                destination,
                is_directory: true,
            },
        );
    }

    Ok(n_overlay)
}
