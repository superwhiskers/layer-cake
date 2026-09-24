// SPDX-License-Identifier: AGPL-3.0-only

use dbus::{
    arg::{RefArg, Variant},
    blocking::{Connection, Proxy, stdintf::org_freedesktop_dbus::Properties},
    strings::Path,
};
use linux_raw_sys::general as linux;
use meowix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    ids::Pid,
    mode::Mode,
    open_beneath_and_write, retry_on_interrupt, syscalls,
    util::{Cwd, PATH_MAX, WithCStr, check_if_incomplete},
    write_checked,
};
use scopeguard::ScopeGuard;
use std::time::Duration;
use uuid::Uuid;

use super::{
    super::spawn::errors::{
        PostSpawnGuest as PostSpawnGuestError,
        PostSpawnGuestOther as PostSpawnGuestOtherError,
        PostSpawnHost as PostSpawnHostError, PreSpawn as PreSpawnError,
    },
    Backend, Cgroups,
    policy::{self, Policy},
};

impl Cgroups<SystemdCgroups> {
    /// Create a new cgroups hierarchy using the systemd backend.
    pub fn new_systemd() -> Self {
        Self::default()
    }
}

/// Owned cgroups hierarchy created using a systemd transient unit.
#[derive(Clone, Debug, Default)]
pub struct SystemdCgroups;

/// State for the systemd backend.
#[derive(Debug)]
pub struct SystemdState {
    /// State machine used to perform systemd cgroups initialization.
    inner: SystemdStateImpl,
}

impl SystemdState {
    /// Creates a new systemd backend state instance.
    ///
    /// # Errors
    ///
    /// This method errors if creating an `eventfd2(2)` fails.
    pub fn new() -> Result<Self, PreSpawnError> {
        let eventfd = syscalls::eventfd2(0, linux::EFD_CLOEXEC as i32)?;
        let inner = SystemdStateImpl::PreClone { eventfd };
        Ok(Self { inner })
    }
}

/// Internal state machine used during systemd cgroups initialization.
#[derive(Debug)]
enum SystemdStateImpl {
    /// A `cgroups(7)` hierarchy has not yet been acquired.
    PreClone {
        /// `eventfd2(2)` used to signal the guest process that it is ready to
        /// continue.
        eventfd: OwnedFd,
    },

    /// A `cgroups(7)` hierarchy has been acquired.
    PostClone {
        /// The file descriptor representing the cgroup delegated to us by
        /// systemd.
        root_fd: OwnedFd,

        /// The file descriptor representing the cgroup to which settings are
        /// written.
        settings_fd: OwnedFd,

        /// The file descriptor representing the cgroup in which the child
        /// process is executing.
        child_fd: OwnedFd,

        /// The name of the unit we started.
        unit_name: String,
    },
}

//SAFETY: we don't allocate memory in [`Backend::guest_post_clone_hook`]
unsafe impl Backend for SystemdCgroups {
    type State = SystemdState;

    fn host_post_clone_hook(
        &self,
        policy: &Policy,
        state: &mut Self::State,
        guest_pid: Pid,
    ) -> Result<(), PostSpawnHostError> {
        let connection = Connection::new_session()?;
        let systemd = Proxy::new(
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            Duration::from_secs(5),
            &connection,
        );
        let unit_name = format!("bubblebox-{}.scope", Uuid::new_v4());

        #[allow(trivial_casts)]
        let unit_properties: Vec<(&str, Variant<Box<dyn RefArg>>)> = vec![
            (
                "PIDs",
                Variant(Box::new(vec![guest_pid.into_raw() as u32]) as _),
            ),
            ("Delegate", Variant(Box::new(true) as _)),
            (
                "DelegateSubgroup",
                Variant(Box::new("anchor".to_string()) as _),
            ),
            (
                "CollectMode",
                Variant(Box::new("inactive-or-failed".to_string()) as _),
            ),
        ];
        let auxiliary: Vec<(&str, Vec<(&str, Variant<Box<dyn RefArg>>)>)> =
            vec![];

        let (_job_path,): (Path<'static>,) = systemd.method_call(
            "org.freedesktop.systemd1.Manager",
            "StartTransientUnit",
            (&unit_name, "fail", unit_properties, auxiliary),
        )?;

        //NOTE: by this point, we want to ensure that the unit is stopped on
        //      error so we set up this guard that we later remove if it
        //      succeeds
        let unit_name = scopeguard::guard(unit_name, |unit_name| match systemd
            .method_call::<(Path<'static>,), _, _, _>(
                "org.freedesktop.systemd1.Manager",
                "StopUnit",
                (unit_name, "fail"),
            ) {
            Ok(_) => (),
            Err(e)
                if matches!(
                    e.name(),
                    Some("org.freedesktop.systemd1.NoSuchUnit")
                ) =>
            {
                ()
            }
            //NOTE: we can't really do anything here. maybe logging in the
            //      future
            Err(_e) => (),
        });

        let (unit_path,): (Path<'static>,) = systemd.method_call(
            "org.freedesktop.systemd1.Manager",
            "GetUnit",
            (&*unit_name,),
        )?;

        let unit = Proxy::new(
            "org.freedesktop.systemd1",
            unit_path,
            Duration::from_secs(5),
            &connection,
        );

        //NOTE: we kind of have to hardcode this path, there's no way to pull
        //      this from systemd from what i can tell. fortunately, this is
        //      pretty isolated as an assumption. as long as you don't care
        //      about using our inbuilt systemd cgroups v2 tree acquisition
        //      this won't affect you. i'm not aware of systemd deviating from
        //      this mountpoint for cgroups anyway.
        let cgroups_root_fd = retry_on_interrupt!({
            syscalls::openat2(
                Cwd,
                c"/sys/fs/cgroup",
                linux::open_how {
                    flags: (linux::O_PATH
                        | linux::O_CLOEXEC
                        | linux::O_DIRECTORY) as u64,
                    mode: 0,
                    resolve: (linux::RESOLVE_NO_MAGICLINKS
                        | linux::RESOLVE_NO_SYMLINKS)
                        as u64,
                },
            )
        })?;

        //NOTE: we may need to poll the unit start job in order for the
        //      successive control group call to return a functioning cgroup
        //      hierarchy that we control

        //NOTE: no idea why but the `&CStr` implementation for dbus' `Get`
        //      doesn't work here for some lifetime reason
        let cgroup_path_string: String =
            unit.get("org.freedesktop.systemd1.Scope", "ControlGroup")?;
        let root_fd = cgroup_path_string
            .trim_prefix("/")
            .with_c_str::<{ PATH_MAX }, _, _, PostSpawnHostError>(
                |cgroup_path| {
                    retry_on_interrupt!({
                        syscalls::openat2(
                            &cgroups_root_fd,
                            cgroup_path,
                            linux::open_how {
                                flags: (linux::O_PATH
                                    | linux::O_CLOEXEC
                                    | linux::O_DIRECTORY)
                                    as u64,
                                mode: 0,
                                resolve: (linux::RESOLVE_IN_ROOT
                                    | linux::RESOLVE_NO_MAGICLINKS
                                    | linux::RESOLVE_NO_SYMLINKS)
                                    as u64,
                            },
                        )
                    })
                },
            )?;

        syscalls::mkdirat(&root_fd, c"bubblebox-settings", Mode::RWXU.bits())?;

        let settings_fd = retry_on_interrupt!({
            syscalls::openat2(
                &root_fd,
                c"bubblebox-settings",
                linux::open_how {
                    flags: (linux::O_PATH
                        | linux::O_CLOEXEC
                        | linux::O_DIRECTORY) as u64,
                    mode: 0,
                    resolve: (linux::RESOLVE_BENEATH
                        | linux::RESOLVE_NO_MAGICLINKS
                        | linux::RESOLVE_NO_SYMLINKS)
                        as u64,
                },
            )
        })?;

        syscalls::mkdirat(&settings_fd, c"bubblebox-child", Mode::RWXU.bits())?;

        let child_fd = retry_on_interrupt!({
            syscalls::openat2(
                &settings_fd,
                c"bubblebox-child",
                linux::open_how {
                    flags: (linux::O_PATH
                        | linux::O_CLOEXEC
                        | linux::O_DIRECTORY) as u64,
                    mode: 0,
                    resolve: (linux::RESOLVE_BENEATH
                        | linux::RESOLVE_NO_MAGICLINKS
                        | linux::RESOLVE_NO_SYMLINKS)
                        as u64,
                },
            )
        })?;

        //NOTE: shift the child process into the deepest cgroup

        let mut itoa_buffer = itoa::Buffer::new();
        let formatted = itoa_buffer.format(guest_pid.into_raw()).as_bytes();

        open_beneath_and_write!(&child_fd, c"cgroup.procs", formatted);

        //NOTE: delegate every controller down to our settings cgroup
        let subtree_control = retry_on_interrupt!({
            syscalls::openat2(
                &root_fd,
                c"cgroup.subtree_control",
                linux::open_how {
                    flags: (linux::O_WRONLY | linux::O_CLOEXEC) as u64,
                    mode: 0,
                    resolve: (linux::RESOLVE_BENEATH
                        | linux::RESOLVE_NO_MAGICLINKS
                        | linux::RESOLVE_NO_SYMLINKS)
                        as u64,
                },
            )
        })?;

        let parent_controllers = policy::parse_controllers(&root_fd)?;

        //NOTE: we don't bother erroring on a missing controller here to
        //      centralize the logic for handling that inside the policy

        if policy.cpu.is_some() && parent_controllers.cpu {
            write_checked!(&subtree_control, b"+cpu");
        }

        if policy.memory.is_some() && parent_controllers.memory {
            write_checked!(&subtree_control, b"+memory");
        }

        if policy.io.is_some() && parent_controllers.io {
            write_checked!(&subtree_control, b"+io");
        }

        if policy.pids.is_some() && parent_controllers.pids {
            write_checked!(&subtree_control, b"+pids");
        }

        policy.apply_to_cgroup(settings_fd.as_fd())?;

        if let SystemdStateImpl::PreClone { ref eventfd } = state.inner {
            check_if_incomplete(
                retry_on_interrupt!({
                    syscalls::write(eventfd, 1u64.to_ne_bytes().as_slice())
                })?,
                8,
            )?;
            *state = SystemdState {
                inner: SystemdStateImpl::PostClone {
                    root_fd,
                    settings_fd,
                    child_fd,
                    unit_name: ScopeGuard::into_inner(unit_name),
                },
            };
        } else {
            return Err(PostSpawnHostError::InvalidCgroupsState);
        }

        Ok(())
    }

    fn guest_post_clone_hook(
        &self,
        _policy: &Policy,
        state: Self::State,
    ) -> Result<(), PostSpawnGuestError> {
        if let SystemdStateImpl::PreClone { eventfd } = state.inner {
            let mut value = [0u8; 8];
            check_if_incomplete(
                retry_on_interrupt!({ syscalls::read(&eventfd, &mut value) })?,
                8,
            )?;
            if u64::from_ne_bytes(value) == 0 {
                return Err(
                    PostSpawnGuestOtherError::InvalidCgroupsState.into()
                );
            }
        } else {
            return Err(PostSpawnGuestOtherError::InvalidCgroupsState.into());
        }

        Ok(())
    }

    fn as_cgroup_fd<'a>(
        &self,
        state: &'a Self::State,
    ) -> Option<BorrowedFd<'a>> {
        if let SystemdStateImpl::PostClone {
            ref settings_fd, ..
        } = state.inner
        {
            return Some(settings_fd.as_fd());
        }
        None
    }

    fn teardown(&self, state: Self::State) -> Result<(), PostSpawnHostError> {
        if let SystemdStateImpl::PostClone { unit_name, .. } = state.inner {
            let connection = Connection::new_session()?;
            let systemd = Proxy::new(
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                Duration::from_secs(5),
                &connection,
            );
            match systemd.method_call::<(Path<'static>,), _, _, _>(
                "org.freedesktop.systemd1.Manager",
                "StopUnit",
                (unit_name, "fail"),
            ) {
                Ok(_) => (),
                Err(e)
                    if matches!(
                        e.name(),
                        Some("org.freedesktop.systemd1.NoSuchUnit")
                    ) =>
                {
                    ()
                }
                Err(e) => Err(e)?,
            }
        }

        Ok(())
    }
}
