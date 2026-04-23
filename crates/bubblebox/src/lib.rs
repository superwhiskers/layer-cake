// SPDX-LICENSE-IDENTIFIER: GPL-3.0-or-later

//! Utilities for cross-platform sandboxing.

//NOTE: THIS IS ALL LINUX-SPECIFIC CODE RIGHT NOW!
//TODO: manual /etc/group /etc/passwd parsing instead of libc

use rustix::{io::Errno, fs::{Uid, Gid}};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    env::{self, VarError},
    ffi::{OsStr, OsString},
    fs::{File as StdFile, Metadata},
    io::Error as IoError,
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    process::Stdio,
};

/// The machine id to present to the sandbox. This is set to the whonix
/// machine id.
const MACHINE_ID: &[u8] = b"b08dfa6083e7567a1921a715000001fb";

/// Return the errno as rustix's [`Errno`] type.
pub fn errno() -> Errno {
    Errno::from_raw_os_error(errno::errno().0)
}

/// Clears the errno.
pub fn clear_errno() {
    errno::set_errno(errno::Errno(0));
}

/// Build an /etc/passwd with the selected users from the old one and write
/// the result to the provided stream.
fn build_passwd(stream: *mut libc::FILE, users: &[Uid]) -> Result<(), Error> {
    let mut passwd = MaybeUninit::<libc::passwd>::uninit();
    let mut result = MaybeUninit::<*mut libc::passwd>::uninit();

    //SAFETY: this is a benign library function
    let mut buffer_size = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    if buffer_size == -1 {
        //NOTE: getpwuid_r(3p) recommendation as a default initial length
        buffer_size = 1024;
    }
    let buffer_size = buffer_size as libc::size_t;

    clear_errno();

    //SAFETY: this just allocates a block of memory
    let mut buffer =
        unsafe { libc::malloc(buffer_size) } as *mut libc::c_char;
    if buffer.is_null() {
        Err(errno())?;
    }

    //TODO: use a scope guard on the above allocation to avoid leaks

    for uid in users {
        loop {
            //SAFETY: we just call a library function here with no special
            //        requirements on the input
            let res = unsafe {
                libc::getpwuid_r(
                    uid.as_raw(),
                    passwd.as_mut_ptr(),
                    buffer,
                    buffer_size,
                    result.as_mut_ptr(),
                )
            };

            if res == 0 {
                //SAFETY: `result` will be initialized if `res` is 0
                let result = unsafe { result.assume_init() };
                if result.is_null() {
                    return Err(Error::NoPasswdEntry(*uid));
                }
            } else {
                match Errno::from_raw_os_error(res) {
                    // according to getpwuid_r(3) these denote it not being
                    // found
                    Errno::NOENT
                    | Errno::SRCH
                    | Errno::BADF
                    | Errno::PERM => {
                        return Err(Error::NoPasswdEntry(*uid));
                    }
                    Errno::RANGE => {
                        buffer_size *= 2;

                        clear_errno();

                        //SAFETY: this just reallocates a block of memory
                        //        already known to be allocated by this point
                        buffer = unsafe {
                            libc::realloc(
                                buffer as *mut libc::c_void,
                                buffer_size,
                            )
                        }
                            as *mut libc::c_char;
                        if buffer.is_null() {
                            Err(errno())?;
                        }

                        continue;
                    }
                    e => Err(e)?,
                }
            }

            break;
        }

        clear_errno();

        //SAFETY: by this point `passwd` will be a valid `passwd` structure
        if unsafe { libc::putpwent(passwd.as_mut_ptr(), stream) }
            .is_negative()
        {
            Err(errno())?;
        }
    }

    //SAFETY: this just frees memory
    unsafe { libc::free(buffer as *mut libc::c_void) };

    Ok(())
}

/// Build an /etc/group with the selected groups from the old one and write
/// the result to the provided stream.
fn build_group(stream: *mut libc::FILE, groups: &[Gid]) -> Result<(), Error> {
    let mut group = MaybeUninit::<libc::group>::uninit();
    let mut result = MaybeUninit::<*mut libc::group>::uninit();

    //SAFETY: this is a benign library function
    let mut buffer_size = unsafe { libc::sysconf(libc::_SC_GETGR_R_SIZE_MAX) };
    if buffer_size == -1 {
        //NOTE: getgrgid_r(3p) recommendation as a default initial length
        buffer_size = 1024;
    }
    let buffer_size = buffer_size as libc::size_t;

    clear_errno();

    //SAFETY: this just allocates a block of memory
    let mut buffer =
        unsafe { libc::malloc(buffer_size) } as *mut libc::c_char;
    if buffer.is_null() {
        Err(errno())?;
    }

    //TODO: use a scope guard for the above allocation

    for gid in groups {
        loop {
            //SAFETY: we just call a library function here with no special
            //        requirements on the input
            let res = unsafe {
                libc::getgrgid_r(
                    gid.as_raw(),
                    group.as_mut_ptr(),
                    buffer,
                    buffer_size,
                    result.as_mut_ptr(),
                )
            };

            if res == 0 {
                //SAFETY: `result` will be initialized if `res` is 0
                let result = unsafe { result.assume_init() };
                if result.is_null() {
                    return Err(Error::NoGroupEntry(*gid));
                }
            } else {
                match Errno::from_raw_os_error(res) {
                    // according to getgrgid_r(3) these denote it not being
                    // found
                    Errno::NOENT
                    | Errno::SRCH
                    | Errno::BADF
                    | Errno::PERM => {
                        return Err(Error::NoGroupEntry(*gid));
                    }
                    Errno::RANGE => {
                        buffer_size *= 2;

                        clear_errno();

                        //SAFETY: this just reallocates a block of memory
                        //        already known to be allocated by this point
                        buffer = unsafe {
                            libc::realloc(
                                buffer as *mut libc::c_void,
                                buffer_size,
                            )
                        }
                            as *mut libc::c_char;
                        if buffer.is_null() {
                            Err(errno())?;
                        }

                        continue;
                    }
                    e => Err(e)?,
                }
            }

            break;
        }

        clear_errno();

        //SAFETY: by this point `group` will be a valid `group` structure
        if unsafe { libc::putgrent(group.as_mut_ptr(), stream) }.is_negative()
        {
            Err(errno())?;
        }
    }

    //SAFETY: this just frees memory
    unsafe { libc::free(buffer as *mut libc::c_void) };

    Ok(())
}

/// An enumeration over possible errors when working with bubblebox
#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// An error encountered when querying environment variables
    #[error("An error was encountered while querying environment variables")]
    VarError(#[from] VarError),

    /// An error encountered when working with the native API directly
    #[error("An error was encountered while working with the native API")]
    Errno(#[from] Errno),

    /// An error encountered while performing I/O
    #[error("An error was encountered while performing I/O")]
    IoError(#[from] IoError),

    /// The current process lacks a valid associated user
    #[error("There is no valid associated user with the process")]
    NoAssociatedUser,

    /// The current process' environment lacks a necessary environment variable
    #[error(
        "The process' environment lacks a necessary environment variable"
    )]
    MissingEnvVar(EnvVar),

    /// One of the [`Uid`]s required to build the mock passwd file lacks a /etc/passwd entry
    #[error("There is no /etc/passwd entry for the uid `{0}`")]
    NoPasswdEntry(Uid),

    /// One of the [`Gid`]s required to build the mock group file lacks a /etc/group entry
    #[error("There is no /etc/group entry for the gid `{0}`")]
    NoGroupEntry(Gid),
}

