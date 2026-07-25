// SPDX-License-Identifier: AGPL-3.0-only

//! Command line wrapper for bubblebox.

//TODO: remaining things for bwrap-parity:
// - seccomp input
// - overlay mounts (need implementation)
// - maybe a minimal dev subset
// - files materialized via fds
// - selinux labels
// - --bind-fd equivalents to what exists on the bwrap git
// - fallible binds(?)
// - args via fd
// - namespace fds (requires implementation, would be less varied compared to
//   bwrap)
//TODO: substitutions for $uid, $gid in args when used in the zip bundle to
//      allow binding directories like /run/$uid/...

use anyhow::Context;
use bubblebox::{
    command::Command,
    paths::Guest,
    platform::{
        cgroups::NullCgroups,
        command::CommandExt,
        meowix::{
            capabilities::CapabilitySet,
            ids::{Gid, Uid},
            mode::Mode,
        },
        mounts::{Mount, ProcHidepid, ProcSubset},
        paths::{HostDirectory, HostFile},
        policy::{
            Policy,
            namespace::{TimeOffsetNanoseconds, TimeOffsetSeconds},
        },
    },
};
use std::{
    collections::HashMap,
    convert::identity,
    env, ffi,
    fs::File,
    io::Read,
    process::{self, ExitCode},
};
use zip::ZipArchive;

/// Print the help string.
fn help(name: &str) -> ! {
    eprintln!(
        "Run a command in a bubblebox sandbox.

Usage:
  {name} [OPTIONS] [--] COMMAND [ARGUMENT]...

Namespace options:
--share-ipc\t\tUse the caller's IPC namespace
--unshare-ipc\t\tCreate a private IPC namespace
--share-network\t\tUse the caller's network namespace
--unshare-network\tCreate an isolated network namespace
--share-uts\t\tUse the caller's UTS namespace
--unshare-uts\t\tCreate a private UTS namespace
--clear-hostname\tCreate a private UTS namespace and clear its hostname
--hostname NAME\t\tCreate a private UTS namespace and set its hostname
--clear-domain\t\tCreate a private UTS namespace and clear its NIS domain name
--domain NAME\t\tCreate a private UTS namespace and set its NIS domain name
--share-time\t\tUse the caller's time namespace
--unshare-time\t\tCreate a private time namespace without changing its clock
\t\t\toffsets

Time namespace offsets:
--offset-sec SECONDS\t\tStage the seconds component of a clock offset
--clear-sec-offset\t\tClear the staged seconds component
--offset-nsec NANOSECONDS\tStage the nanoseconds component of a clock offset
--clear-nsec-offset\t\tClear the staged nanoseconds component
--set-monotonic-offset\t\tApply the staged components to the CLOCK_MONOTONIC
\t\t\t\toffset
--set-boottime-offset\t\tApply the staged components to the CLOCK_BOOTTIME
\t\t\t\toffset

User namespace options:
--disable-userns\tPrevent processes in the sandbox from creating further user
\t\t\tnamespaces
--uid UID\t\tSet the UID used by the sandbox's user-namespace mapping
--gid GID\t\tSet the GID used by the sandbox's user-namespace mapping

File descriptor options:
--passthrough FD\tExclude FD from sandbox file-descriptor handling
--close FD\t\tClose the specified file descriptor
--close all\t\tClose all file descriptors

Session options:
--new-session\tStart the sandboxed command in a new session
--reuse-session\tKeep the sandboxed command in the current session

Environment options:
--set-env VAR VALUE\tSet an environment variable
--inherit-env VAR\tInherit an environment variable. If the variable is not
\t\t\tset, this option is ignored
--unset-env VAR\t\tUnset an environment variable
--cwd PATH\t\tSpawn the guest at PATH within the guest filesystem
--arg0 ARGUMENT\t\tSet the first argument to the program to something
\t\t\tother than the executable's path
--cap-add CAP\t\tGrant capability CAP to the program
--cap-drop CAP\t\tRemove capability CAP from the program
--cap-drop all\t\tRemove all capabilities from the program. This is the
\t\t\tdefault

Filesystem options:
--mode MODE\t\t\tSet the octal mode used by subsequent --directory
\t\t\t\tand --tmpfs options. The initial mode is 0000.
--ro-bind-file HOST GUEST\tExpose HOST as a read-only file at GUEST
--ro-bind-directory HOST GUEST\tExpose HOST as a read-only directory at GUEST
--rw-bind-file HOST GUEST\tExpose HOST as a read-write file at GUEST
--rw-bind-directory HOST GUEST\tExpose HOST as a read-write directory at GUEST
--dev-bind-file HOST GUEST\tExpose the host device file HOST at GUEST
--proc GUEST\t\t\tMount procfs at GUEST with hidepid=ptraceable and
\t\t\t\tsubset=pid
--proc-unrestricted GUEST\tMount procfs at GUEST with hidepid=off
--mqueue GUEST\t\t\tMount a POSIX message queue filesystem at GUEST
--directory GUEST\t\tCreate an empty directory at GUEST using the current
\t\t\t\tmode
--tmpfs[=SIZE] GUEST\t\tMount a tmpfs at GUEST using the current mode. When
\t\t\t\tspecified, SIZE must be attached using --tmpfs=SIZE.
--symlink SOURCE DEST\t\tCreate a symlink at DEST pointing to SOURCE on the
\t\t\t\tguest.

General options:
\t-h, --help\tPrint this help and exit

The staged time-offset components are copied when --set-monotonic-offset or
--set-boottime-offset is encountered. Likewise, --mode affects only subsequent
--directory and --tmpfs options.

Option parsing stops at COMMAND. All following arguments are passed to the
command unchanged."
    );
    process::exit(0);
}

/// Interprets the [`Policy`] from the given [`lexopt::Parser`].
///
/// Returns both the interpreted [`Policy`] and the interpreted [`Command`].
///
/// # Errors
///
/// This function errors if parsing the command line and constructing the policy
/// falis.
fn interpret_policy<'a>(
    mut parser: lexopt::Parser,
    mut archive: Option<ZipArchive<File>>,
) -> anyhow::Result<(Policy<'a, NullCgroups>, Command)> {
    use lexopt::prelude::*;

    let name = parser.bin_name().unwrap_or("bbx").to_owned();

    let mut policy = Policy::default();
    let mut command = None;

    let mut environment = HashMap::new();
    let mut last_seconds_offset = None;
    let mut last_nanoseconds_offset = None;
    let mut uid = None;
    let mut gid = None;
    let mut cwd = None;
    let mut arg0 = None;
    let mut capability_set = CapabilitySet::empty();
    let mut mode = Mode::empty();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('h') | Long("help") => help(&name),
            Long("share-ipc") => {
                policy = policy.namespace(|namespace| namespace.share_ipc());
            }
            Long("unshare-ipc") => {
                policy = policy.namespace(|namespace| namespace.unshare_ipc());
            }
            Long("share-network") => {
                policy =
                    policy.namespace(|namespace| namespace.share_network());
            }
            Long("unshare-network") => {
                policy = policy.namespace(|namespace| {
                    namespace.unshare_network_and_isolate()
                });
            }
            Long("share-uts") => {
                policy = policy.namespace(|namespace| namespace.share_uts());
            }
            Long("unshare-uts") => {
                policy = policy
                    .namespace(|namespace| namespace.unshare_uts(identity));
            }
            Long("clear-hostname") => {
                policy = policy.namespace(|namespace| {
                    namespace.unshare_uts(|uts| uts.clear_hostname())
                });
            }
            Long("hostname") => {
                let hostname = parser.value()?.into_encoded_bytes();
                policy = policy.namespace(|namespace| {
                    namespace.unshare_uts(|uts| uts.set_hostname(hostname))
                });
            }
            Long("clear-domain") => {
                policy = policy.namespace(|namespace| {
                    namespace.unshare_uts(|uts| uts.clear_domain())
                });
            }
            Long("domain") => {
                let domain = parser.value()?.into_encoded_bytes();
                policy = policy.namespace(|namespace| {
                    namespace.unshare_uts(|uts| uts.set_domain(domain))
                });
            }
            Long("share-time") => {
                policy = policy.namespace(|namespace| namespace.share_time());
            }
            Long("unshare-time") => {
                policy = policy
                    .namespace(|namespace| namespace.unshare_time(identity));
            }
            Long("clear-sec-offset") => {
                last_seconds_offset = None;
            }
            Long("offset-sec") => {
                last_seconds_offset = Some(
                    TimeOffsetSeconds::new(parser.value()?.parse().context(
                        "Invalid sec value of a time namespace offset",
                    )?)
                    .ok_or(anyhow::format_err!(
                        "Invalid sec value of a time namespace offset"
                    ))?,
                );
            }
            Long("clear-nsec-offset") => {
                last_nanoseconds_offset = None;
            }
            Long("offset-nsec") => {
                last_nanoseconds_offset = Some(
                    TimeOffsetNanoseconds::new(
                        parser.value()?.parse().context(
                            "Invalid nsec value of a time namespace offset",
                        )?,
                    )
                    .ok_or(anyhow::format_err!(
                        "Invalid nsec value of a time namespace offset"
                    ))?,
                );
            }
            Long("set-monotonic-offset") => {
                policy = policy.namespace(|namespace| {
                    namespace.unshare_time(|time| {
                        time.monotonic_offset(|mut monotonic| {
                            if let Some(seconds_offset) = &last_seconds_offset {
                                monotonic =
                                    monotonic.set_seconds(*seconds_offset);
                            }
                            if let Some(nanoseconds_offset) =
                                &last_nanoseconds_offset
                            {
                                monotonic = monotonic
                                    .set_nanoseconds(*nanoseconds_offset);
                            }

                            monotonic
                        })
                    })
                });
            }
            Long("set-boottime-offset") => {
                policy = policy.namespace(|namespace| {
                    namespace.unshare_time(|time| {
                        time.boottime_offset(|mut boottime| {
                            if let Some(seconds_offset) = &last_seconds_offset {
                                boottime =
                                    boottime.set_seconds(*seconds_offset);
                            }
                            if let Some(nanoseconds_offset) =
                                &last_nanoseconds_offset
                            {
                                boottime = boottime
                                    .set_nanoseconds(*nanoseconds_offset);
                            }

                            boottime
                        })
                    })
                });
            }
            Long("disable-userns") => {
                policy = policy.namespace(|namespace| {
                    namespace.user_namespace(|user| user.disable_userns(true))
                });
            }
            Long("uid") => {
                uid = Some(
                    Uid::from_raw(parser.value()?.parse()?)
                        .ok_or(anyhow::format_err!("invalid uid"))?,
                );
            }
            Long("gid") => {
                gid = Some(
                    Gid::from_raw(parser.value()?.parse()?)
                        .ok_or(anyhow::format_err!("invalid gid"))?,
                );
            }
            Long("passthrough") => {
                let fd = parser.value()?.parse()?;
                policy = policy.fd_policy(|fd_policy| fd_policy.ignore(fd))?;
            }
            Long("close") => match parser.value()? {
                s if s.to_str() == Some("all") => {
                    policy = policy.fd_policy(|fd_policy| fd_policy.clear())?;
                }
                fd => {
                    let fd = fd.parse()?;
                    policy =
                        policy.fd_policy(|fd_policy| fd_policy.close(fd))?;
                }
            },
            Long("reuse-session") => {
                policy = policy.new_session(false);
            }
            Long("new-session") => {
                policy = policy.new_session(true);
            }
            Long("mode") => {
                mode = Mode::from_bits(ffi::c_uint::from_str_radix(
                    parser.value()?.to_string_lossy().as_ref(),
                    8,
                )?)
                .ok_or(anyhow::format_err!("invalid file mode"))?;
            }
            Long("ro-bind-file") => {
                let host_file = HostFile::open(parser.value()?)?;
                let guest_path = Guest::new(parser.value()?)?;
                policy = policy.mount_tree(|tree| {
                    tree.mount(Mount::read_only_file(host_file), guest_path)
                })?;
            }
            Long("ro-bind-directory") => {
                let host_directory = HostDirectory::open(parser.value()?)?;
                let guest_path = Guest::new(parser.value()?)?;
                policy = policy.mount_tree(|tree| {
                    tree.mount(
                        Mount::read_only_directory(host_directory),
                        guest_path,
                    )
                })?;
            }
            Long("rw-bind-file") => {
                let host_file = HostFile::open(parser.value()?)?;
                let guest_path = Guest::new(parser.value()?)?;
                policy = policy.mount_tree(|tree| {
                    tree.mount(Mount::read_write_file(host_file), guest_path)
                })?;
            }
            Long("rw-bind-directory") => {
                let host_directory = HostDirectory::open(parser.value()?)?;
                let guest_path = Guest::new(parser.value()?)?;
                policy = policy.mount_tree(|tree| {
                    tree.mount(
                        Mount::read_write_directory(host_directory),
                        guest_path,
                    )
                })?;
            }
            Long("dev-bind-file") => {
                let host_file = HostFile::open(parser.value()?)?;
                let guest_path = Guest::new(parser.value()?)?;
                policy = policy.mount_tree(|tree| {
                    tree.mount(Mount::device_file(host_file), guest_path)
                })?;
            }
            Long("proc") => {
                let guest_path = Guest::new(parser.value()?)?;
                policy = policy.mount_tree(|tree| {
                    tree.mount(
                        Mount::proc(ProcHidepid::Ptraceable, ProcSubset::Pid),
                        guest_path,
                    )
                })?;
            }
            Long("proc-unrestricted") => {
                let guest_path = Guest::new(parser.value()?)?;
                policy = policy.mount_tree(|tree| {
                    tree.mount(
                        Mount::proc(ProcHidepid::Off, ProcSubset::Full),
                        guest_path,
                    )
                })?;
            }
            Long("mqueue") => {
                let guest_path = Guest::new(parser.value()?)?;
                policy = policy.mount_tree(|tree| {
                    tree.mount(Mount::mqueue(), guest_path)
                })?;
            }
            Long("directory") => {
                let guest_path = Guest::new(parser.value()?)?;
                policy = policy.mount_tree(|tree| {
                    tree.mount(Mount::directory(mode), guest_path)
                })?;
            }
            Long("bundled-file") => {
                if let Some(archive) = &mut archive {
                    let mut contents = Vec::new();
                    let _ = archive
                        .by_path(parser.value()?)?
                        .read_to_end(&mut contents)?;

                    let guest_path = Guest::new(parser.value()?)?;
                    policy = policy.mount_tree(|tree| {
                        tree.mount(Mount::file(contents, mode), guest_path)
                    })?;
                } else {
                    return Err(anyhow::format_err!(
                        "`--bundled-file` used outside a bundle",
                    ));
                }
            }
            Long("symlink") => {
                let source_path = Guest::new(parser.value()?)?;
                let destination_path = Guest::new(parser.value()?)?;
                policy = policy.mount_tree(|tree| {
                    tree.mount(Mount::symlink(source_path), destination_path)
                })?;
            }
            Long("tmpfs") => {
                let size = parser
                    .optional_value()
                    .map(|v| v.to_string_lossy().into_owned());
                let guest_path = Guest::new(parser.value()?)?;
                policy = policy.mount_tree(|tree| {
                    tree.mount(Mount::tmpfs(size, mode), guest_path)
                })?;
            }
            Long("set-env") => {
                drop(environment.insert(parser.value()?, parser.value()?));
            }
            Long("inherit-env") => {
                let var = parser.value()?;
                if let Some(value) = env::var_os(&var) {
                    drop(environment.insert(var, value));
                }
            }
            Long("unset-env") => {
                drop(environment.remove(&parser.value()?));
            }
            Long("cwd") => {
                cwd = Some(Guest::new(parser.value()?)?);
            }
            Long("arg0") => {
                arg0 = Some(parser.value()?);
            }
            Long("cap-add") => {
                capability_set |= CapabilitySet::from_str(
                    parser.value()?.string()?,
                )
                .ok_or(anyhow::format_err!("capability was not valid"))?;
            }
            Long("cap-drop") => {
                let raw_cap = parser.value()?.string()?;

                if raw_cap == "all" {
                    capability_set = CapabilitySet::empty();
                } else {
                    capability_set ^= CapabilitySet::from_str(raw_cap).ok_or(
                        anyhow::format_err!("capability was not valid"),
                    )?;
                }
            }
            Value(v) => {
                let mut final_command = Command::new(v)?
                    .args(parser.raw_args()?)?
                    .envs(environment)?;

                if let Some(cwd) = cwd {
                    final_command = final_command.current_dir(cwd);
                }

                if let Some(arg0) = arg0 {
                    final_command = final_command.arg0(arg0)?;
                }

                command = Some(final_command);
                break;
            }
            _ => return Err(arg.unexpected().into()),
        }
    }

    policy = policy
        .namespace(|namespace| {
            namespace.user_namespace(|user| user.simple_mapping(uid, gid))
        })
        .set_target_capabilities(capability_set);

    let command =
        command.ok_or(anyhow::format_err!("missing command to execute"))?;
    Ok((policy, command))
}

fn main() -> anyhow::Result<ExitCode> {
    let (policy, command) = match File::open("/proc/self/exe")
        .map_err::<anyhow::Error, _>(Into::into)
        .and_then(|file| Ok(ZipArchive::new(file)?))
        .and_then(|mut archive| {
            let mut configuration = String::new();
            let _ = archive
                .by_path("/bbx.conf")?
                .read_to_string(&mut configuration)?;

            Ok((archive, configuration))
        }) {
        Ok((archive, configuration)) => interpret_policy(
            lexopt::Parser::from_args(configuration.split_whitespace()),
            Some(archive),
        )?,
        Err(_) => interpret_policy(lexopt::Parser::from_env(), None)?,
    };

    let guest = policy.spawn(&command)?;
    let result = guest.wait()?;

    Ok(ExitCode::from(if let Some(code) = result.code() {
        code as u8
    } else {
        0
    }))
}
