// SPDX-License-Identifier: AGPL-3.0-only

//! Primitives for working with `cgroups(7)`.
//!
//! This module implements two primary things. First, the acquisition of
//! cgroups. This may be either through the creation of a transient [systemd]
//! unit using D-Bus, or through the caller passing in a file descriptor
//! pointing to an owned cgroups hierarchy. Second, this module implements the
//! writing of an initial configuration to the owned cgroups hierarchy once the
//! child process is spawned within it.
//!
//! In the future, continuous monitoring of read-only attributes on an owned
//! cgroups hierarchy and reconfiguration may be added.
//!
//! [systemd]: https://systemd.io

//TODO: look into talking to elogind to acquire a cgroups instance, if this
//      would work at all
//TODO: system scoped cgroups on systemd? this could be useful but also
//      requires privileges. may allow us access to more controllers
//TODO: consider making the backend a trait object. the primary difficulty here
//      is dealing with the state

//TODO: temporary
#![allow(missing_copy_implementations)]

use linux_raw_sys::general as linux;
use std::{
    io::Read,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

#[cfg(feature = "systemd-cgroups")]
use std::time::Duration;

#[cfg(feature = "systemd-cgroups")]
use dbus::{
    arg::{RefArg, Variant},
    blocking::{Connection, Proxy, stdintf::org_freedesktop_dbus::Properties},
    strings::Path,
};

#[cfg(feature = "systemd-cgroups")]
use uuid::Uuid;

use super::{
    errors::{
        Host as HostError, PostCloneGuest as PostCloneGuestError,
        PostCloneHost as PostCloneHostError, PreClone as PreCloneError,
    },
    mapping::Mode,
    syscalls::{self, Pid},
    util::{self, FdReadWrite},
};

#[cfg(feature = "systemd-cgroups")]
use super::{
    errors::PostCloneGuestOther as PostCloneGuestOtherError,
    syscalls::{Cwd, WithCStr},
};

/// Controllers available to a cgroup.
#[derive(Clone, Debug, Default)]
struct CgroupControllers {
    /// `cpu` controller.
    cpu: bool,

    /// `memory` controller.
    memory: bool,

    /// `io` controller.
    io: bool,

    /// `pids` controller.
    pids: bool,
}

/// Read the controllers available to a cgroup.
///
/// # Errors
///
/// This function errors if opening the `cgroup.controllers` file on the cgroup
/// fails, or if reading its contents fails.
fn parse_controllers(
    cgroup_fd: impl AsFd,
) -> Result<CgroupControllers, HostError> {
    let mut controllers_fd = FdReadWrite::new(util::retry_on_interrupt!({
        syscalls::openat2(
            cgroup_fd.as_fd(),
            c"cgroup.controllers",
            linux::open_how {
                flags: (linux::O_RDONLY | linux::O_CLOEXEC) as u64,
                mode: 0,
                resolve: (linux::RESOLVE_BENEATH
                    | linux::RESOLVE_NO_MAGICLINKS
                    | linux::RESOLVE_NO_SYMLINKS)
                    as u64,
            },
        )
    })?);

    //NOTE: this may be able to be simplified by using a fixed size buffer but
    //      for now let's allocate. we also can't really know the size here so
    //      we don't bother checking
    let mut controllers = String::new();
    let _ = controllers_fd.read_to_string(&mut controllers)?;

    let mut has_controllers = CgroupControllers::default();
    for controller in controllers.split_whitespace() {
        match controller {
            "cpu" => has_controllers.cpu = true,
            "memory" => has_controllers.memory = true,
            "io" => has_controllers.io = true,
            "pids" => has_controllers.pids = true,
            _ => (),
        }
    }

    Ok(has_controllers)
}

/// Policy applied to a cgroup.
///
/// There are interface files other than those covered in this structure. This
/// structure only contains those which make sense to set prior to spawning
/// processes.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Core configuration options.
    pub cgroup: CgroupController,

    /// Configuration under the `cpu` controller.
    pub cpu: Option<CpuController>,

    /// Configuration under the `memory` controller.
    pub memory: Option<MemoryController>,

    /// Configuration under the `io` controller.
    pub io: Option<IoController>,

    /// Configuration under the `pids` controller.
    pub pids: Option<PidsController>,
    //TODO: we could put more here, but the remaining controllers are less
    //      commonly useful. cpuset should be added in the future once testing
    //      is possible
}

impl Policy {
    /// Apply initial cgroup configuration.
    ///
    /// # Errors
    ///
    /// This method errors if writing to the attributes of the settings cgroup
    /// fails.
    pub fn apply_to_cgroup(
        &self,
        cgroup_fd: impl AsFd,
    ) -> Result<(), HostError> {
        self.cgroup.apply_to_cgroup(&cgroup_fd)?;

        let controllers = parse_controllers(&cgroup_fd)?;

        if let Some(cpu_policy) = &self.cpu {
            if !controllers.cpu {
                return Err(HostError::MissingCgroupController("cpu"));
            }

            cpu_policy.apply_to_cgroup(&cgroup_fd)?;
        }

        if let Some(memory_policy) = &self.memory {
            if !controllers.memory {
                return Err(HostError::MissingCgroupController("memory"));
            }

            memory_policy.apply_to_cgroup(&cgroup_fd)?;
        }

        if let Some(io_policy) = &self.io {
            if !controllers.io {
                return Err(HostError::MissingCgroupController("io"));
            }

            io_policy.apply_to_cgroup(&cgroup_fd)?;
        }

        if let Some(pids_policy) = &self.pids {
            if !controllers.pids {
                return Err(HostError::MissingCgroupController("pids"));
            }

            pids_policy.apply_to_cgroup(&cgroup_fd)?;
        }

        Ok(())
    }
}

/// Resource value.
#[derive(Copy, Clone, Debug)]
pub enum Resource<T> {
    /// The special token "max" for the given unit.
    Max,

    /// A specific value.
    Value(T),
}

impl<T> Resource<T>
where
    T: itoa::Integer,
    Self: Copy,
{
    /// Converts this [`Resource<T>`] value to a [`&str`].
    fn into_str<'a>(self, buffer: &'a mut itoa::Buffer) -> &'a str {
        match self {
            Self::Max => "max",
            Self::Value(v) => buffer.format(v),
        }
    }
}

/// Core [configuration options].
///
/// [configuration options]: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#core-interface-files
#[derive(Clone, Debug)]
pub struct CgroupController {
    /// Whether the cgroup is threaded or not.
    pub is_threaded: bool,

    /// Whether pressure stall information accounting is enabled in the
    /// sandbox's cgroup.
    pub enable_psi_accounting: bool,
}

impl CgroupController {
    /// Apply initial cgroup configuration.
    ///
    /// # Errors
    ///
    /// This method errors if writing to the attributes of the settings cgroup
    /// fails.
    pub fn apply_to_cgroup(
        &self,
        cgroup_fd: impl AsFd,
    ) -> Result<(), HostError> {
        let cgroup_fd = cgroup_fd.as_fd();

        if self.is_threaded {
            util::open_beneath_and_write!(
                &cgroup_fd,
                c"cgroup.type",
                b"threaded\n"
            );
        }

        if self.enable_psi_accounting {
            util::open_beneath_and_write!(
                &cgroup_fd,
                c"cgroup.pressure",
                b"1\n"
            );
        }

        Ok(())
    }
}

/// Configuration options ot the [`cpu` controller].
///
/// [`cpu` controller]: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#cpu
#[derive(Clone, Debug)]
pub struct CpuController {
    /// Whether to give this controller to the subtree.
    subtree_control: bool,

    /// Weight given to the cgroup.
    weight: Option<CpuWeight>,

    /// CPU time to allow the cgroup within a time interval.
    ///
    /// Units are in microseconds.
    max: Option<(Resource<u64>, u64)>,

    /// Burst CPU time allowance for the cgroup in microseconds.
    ///
    /// This permits an overrun of the value in [`CpuController`] if set.
    max_burst: Option<u64>,

    /// Requested minimum utilization for the cgroup.
    uclamp_min: Option<Resource<UclampValue>>,

    /// Requested maximum utilization for the cgroup.
    uclamp_max: Option<Resource<UclampValue>>,

    /// Whether this cgroup should be considered idle.
    ///
    /// If true, the scheduling policy of the cgroup becomes `SCHED_IDLE`. See
    /// [`sched(7)`] for more details.
    ///
    /// [`sched(7)`]: https://www.man7.org/linux/man-pages/man7/sched.7.html
    is_idle: bool,
}

impl CpuController {
    /// Apply initial cgroup configuration.
    ///
    /// # Errors
    ///
    /// This method errors if writing to the attributes of the settings cgroup
    /// fails.
    pub fn apply_to_cgroup(
        &self,
        cgroup_fd: impl AsFd,
    ) -> Result<(), HostError> {
        let mut itoa_buffer = itoa::Buffer::new();
        let cgroup_fd = cgroup_fd.as_fd();

        if self.subtree_control {
            util::open_beneath_and_write!(
                &cgroup_fd,
                c"cgroup.subtree_control",
                b"+cpu\n"
            );
        }

        if let Some(weight) = &self.weight {
            match weight {
                CpuWeight::Weight(v) => {
                    util::open_beneath_and_write!(
                        &cgroup_fd,
                        c"cpu.weight",
                        itoa_buffer.format(*v).as_bytes()
                    );
                }
                CpuWeight::Nice(v) => {
                    util::open_beneath_and_write!(
                        &cgroup_fd,
                        c"cpu.weight.nice",
                        itoa_buffer.format(*v).as_bytes()
                    );
                }
            }
        }

        if let Some((value, duration)) = &self.max {
            let max_fd = util::retry_on_interrupt!({
                syscalls::openat2(
                    &cgroup_fd,
                    c"cpu.max",
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

            //TODO: remove the allocation here
            let stringified_value = value.into_str(&mut itoa_buffer);
            let formatted = format!("{stringified_value} {}", *duration);
            util::write_checked!(&max_fd, formatted.as_bytes());
        }

        if let Some(max_burst) = &self.max_burst {
            let value = itoa_buffer.format(*max_burst);
            util::open_beneath_and_write!(
                &cgroup_fd,
                c"cpu.max.burst",
                value.as_bytes()
            );
        }

        if let Some(uclamp_min) = &self.uclamp_min {
            match uclamp_min {
                Resource::Value(value) => {
                    //TODO: temporary until i work out a non-allocating way
                    //      of doing this
                    let (whole, fractional) = value.into_parts();
                    let string = format!("{whole}.{fractional:02}");
                    util::open_beneath_and_write!(
                        &cgroup_fd,
                        c"cpu.uclamp.min",
                        string.as_bytes()
                    );
                }
                Resource::Max => {
                    util::open_beneath_and_write!(
                        &cgroup_fd,
                        c"cpu.uclamp.min",
                        b"max"
                    );
                }
            }
        }

        if let Some(uclamp_max) = &self.uclamp_max {
            match uclamp_max {
                Resource::Value(value) => {
                    //TODO: likewise
                    let (whole, fractional) = value.into_parts();
                    let string = format!("{whole}.{fractional:02}");
                    util::open_beneath_and_write!(
                        &cgroup_fd,
                        c"cpu.uclamp.max",
                        string.as_bytes()
                    );
                }
                Resource::Max => {
                    util::open_beneath_and_write!(
                        &cgroup_fd,
                        c"cpu.uclamp.max",
                        b"max"
                    );
                }
            }
        }

        if self.is_idle {
            util::open_beneath_and_write!(&cgroup_fd, c"cpu.idle", b"1");
        }

        Ok(())
    }
}

/// Utilization clamp value.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UclampValue {
    /// Has range of `[0, 10_000]`.
    value: u16,
}

impl UclampValue {
    /// Returns a [`UclampValue`] if the value is representable.
    ///
    /// Values must be in the range `[0, 10_000]`, and are an integer
    /// representation of decimals with two decimal places i.e. `23.74%` becomes
    /// `2374`.
    pub fn new(value: u16) -> Option<Self> {
        if value <= 10_000 {
            return Some(Self { value });
        }
        None
    }

    /// Returns the whole and fractional parts of the value.
    pub fn into_parts(self) -> (u8, u8) {
        ((self.value / 100) as u8, (self.value % 100) as u8)
    }

    /// Returns the corresponding [`u16`] for the [`UclampValue`].
    pub fn into_u16(self) -> u16 {
        self.value
    }
}

/// Weight given to a cgroup.
#[derive(Clone, Debug)]
pub enum CpuWeight {
    /// Hard weight value.
    ///
    /// Must be in the range `[1, 10000]`.
    Weight(u16),

    /// Nice value.
    ///
    /// Must be in the range `[-20, 19]`.
    Nice(i8),
}

/// Configuration options for the [`memory` controller]
///
/// [`memory` controller]: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#memory-interface-files
#[derive(Clone, Debug)]
pub struct MemoryController {
    /// Whether to give this controller to the subtree.
    subtree_control: bool,

    /// Hard memory protection for this cgroup, in bytes.
    ///
    /// This sets the `memory.min` threshold for the cgroup.
    min: Option<Resource<u64>>,

    /// Best-effort memory protection for this cgroup, in bytes.
    ///
    /// This sets the `memory.low` threshold for the cgroup.
    low: Option<Resource<u64>>,

    /// Memory throttle limit for this cgroup, in bytes.
    ///
    /// This sets the `memory.high` threshold for the cgroup.
    high: Option<Resource<u64>>,

    /// Memory hard limit for this cgroup, in bytes.
    ///
    /// This sets the `memory.max` threshold for the cgroup.
    max: Option<Resource<u64>>,

    /// Whether this cgroup is an indivisible workload.
    ///
    /// That is, if the OOM killer were invoked within this cgroup, whether all
    /// tasks within this cgroup should be killed at once to avoid partial
    /// kills.
    is_indivisible: bool,

    /// Swap throttle limit for this cgroup, in bytes.
    ///
    /// This sets the `memory.swap.high` threshold for the cgroup.
    swap_high: Option<Resource<u64>>,

    /// Swap hard limit for this cgroup, in bytes.
    ///
    /// This sets the `memory.swap.max` threshold for the cgroup.
    swap_max: Option<Resource<u64>>,

    /// Zswap hard limit for this cgroup, in bytes.
    ///
    /// This sets the `memory.zwap.max` threshold for the cgroup.
    zswap_max: Option<Resource<u64>>,

    /// Whether to disable writeback for zswap pages.
    disable_zswap_writeback: bool,
}

impl MemoryController {
    /// Apply initial cgroup configuration.
    ///
    /// # Errors
    ///
    /// This method errors if writing to the attributes of the settings cgroup
    /// fails.
    pub fn apply_to_cgroup(
        &self,
        cgroup_fd: impl AsFd,
    ) -> Result<(), HostError> {
        let cgroup_fd = cgroup_fd.as_fd();

        if self.subtree_control {
            util::open_beneath_and_write!(
                &cgroup_fd,
                c"cgroup.subtree_control",
                b"+memory\n"
            );
        }

        //TODO: implement these, skipped for now

        Ok(())
    }
}

/// Configuration options for the [`io` controller]
///
/// [`io` controller]: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#io-interface-files
#[derive(Clone, Debug)]
pub struct IoController {
    /// Whether to give this controller to the subtree.
    subtree_control: bool,
    //TODO: implement the io controller options. this one looks more difficult
    //      because it requires device numbers etc
}

impl IoController {
    /// Apply initial cgroup configuration.
    ///
    /// # Errors
    ///
    /// This method errors if writing to the attributes of the settings cgroup
    /// fails.
    pub fn apply_to_cgroup(
        &self,
        cgroup_fd: impl AsFd,
    ) -> Result<(), HostError> {
        let cgroup_fd = cgroup_fd.as_fd();

        if self.subtree_control {
            util::open_beneath_and_write!(
                &cgroup_fd,
                c"cgroup.subtree_control",
                b"+io\n"
            );
        }

        //TODO: implement these, skipped for now

        Ok(())
    }
}

/// Configuration options for the [`pids` controller]
///
/// [`pids` controller]: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#pid-interface-files
#[derive(Clone, Debug)]
pub struct PidsController {
    /// Whether to give this controller to the subtree.
    pub subtree_control: bool,

    /// Hard limit on the number of processes.
    pub max: Option<Resource<u64>>,
}

impl PidsController {
    /// Apply initial cgroup configuration.
    ///
    /// # Errors
    ///
    /// This method errors if writing to the attributes of the settings cgroup
    /// fails.
    pub fn apply_to_cgroup(
        &self,
        cgroup_fd: impl AsFd,
    ) -> Result<(), HostError> {
        let mut itoa_buffer = itoa::Buffer::new();
        let cgroup_fd = cgroup_fd.as_fd();

        if self.subtree_control {
            util::open_beneath_and_write!(
                &cgroup_fd,
                c"cgroup.subtree_control",
                b"+pids\n"
            );
        }

        if let Some(max) = self.max {
            let stringified_value = max.into_str(&mut itoa_buffer);
            util::open_beneath_and_write!(
                &cgroup_fd,
                c"pids.max",
                stringified_value.as_bytes()
            );
        }

        Ok(())
    }
}

/// Representation of an owned cgroups hierarchy.
#[derive(Clone, Debug)]
pub struct Cgroups<T> {
    /// Source of the cgroups hierarchy.
    inner: T,

    /// Cgroup policy applied at creation.
    policy: Policy,
}

impl<T> Cgroups<T>
where
    T: Backend,
{
    //TODO: add methods for working w/ cgroups or a way to create a reference
    //      to one so we don't have to keep checking the state of the systemd
    //      cgroup impl

    /// Returns a file descriptor representing the cgroup to spawn the sandboxed
    /// process in.
    ///
    /// If provided, `CLONE_INTO_CGROUP` is added to the flags.
    ///
    /// # Warning
    ///
    /// This must be distinct from the cgroup to which settings are written, as
    /// if the sandboxed process is granted `CAP_SYS_ADMIN`, then it would
    /// be able to mount and write to the cgroups filesystem.
    pub fn clone_args_cgroup<'a>(
        &self,
        state: &'a T::State,
    ) -> Option<Result<BorrowedFd<'a>, PreCloneError>> {
        self.inner.clone_args_cgroup(&self.policy, state)
    }

    /// Hook executed shortly after the `clone3(2)` call in the host process.
    ///
    /// # Errors
    ///
    /// This method errors if the [`Backend`] implementation errors.
    pub fn host_post_clone_hook(
        &self,
        state: &mut T::State,
        guest_pid: Pid,
    ) -> Result<(), PostCloneHostError> {
        self.inner
            .host_post_clone_hook(&self.policy, state, guest_pid)
    }

    /// Hook executed shortly after the `clone3(2)` call in the guest process.
    ///
    /// # Errors
    ///
    /// This method errors if the [`Backend`] implementation errors.
    pub fn guest_post_clone_hook(
        &self,
        state: T::State,
    ) -> Result<(), PostCloneGuestError> {
        self.inner.guest_post_clone_hook(&self.policy, state)
    }

    /// Returns a file descriptor representing the cgroup to write resource
    /// limits and other configuration options to.
    ///
    /// # Warning
    ///
    /// This must be distinct from the cgroup to which the sandboxed process is
    /// spawned in. If the sandboxed process is granted `CAP_SYS_ADMIN` and the
    /// two are the same cgroup, then it would be able to mount and write to the
    /// cgroups filesystem.
    pub fn as_cgroup_fd<'a>(
        &self,
        state: &'a T::State,
    ) -> Option<BorrowedFd<'a>> {
        self.inner.as_cgroup_fd(state)
    }

    /// Performs cleanup operations necessary for the backend.
    pub fn teardown(&self, state: T::State) -> Result<(), PostCloneHostError> {
        self.inner.teardown(state)
    }
}

/// A representation of a `cgroups(7)` hierarchy and hooks to install a child
/// process into the cgroup.
///
/// This is implemented by hooking into parts of the setup process during
/// [`super::policy::Policy::clone_into`]. This trait intends to make working
/// with cgroups (v2) uniform, while abstracting over life cycle management
/// which may be different across backends.
///
/// # Safety
///
/// The implementation of [`Backend::guest_post_clone_hook`] must not perform
/// operations that are invalid in a child process created from a potentially
/// multithreaded parent. Prefer direct syscalls.
///
/// [`Backend::State`] must also have a [`Drop`] implementation safe to run
/// post-`clone3(2)`.
pub unsafe trait Backend {
    /// State required for this cgroups backend to acquire a hierarchy.
    type State;

    /// Returns a file descriptor representing the cgroup to spawn the sandboxed
    /// process in.
    ///
    /// If provided, `CLONE_INTO_CGROUP` is added to the flags.
    ///
    /// # Warning
    ///
    /// This must be distinct from the cgroup to which settings are written, as
    /// if the sandboxed process is granted `CAP_SYS_ADMIN`, then it would
    /// be able to mount and write to the cgroups filesystem.
    fn clone_args_cgroup<'a>(
        &self,
        policy: &Policy,
        state: &'a Self::State,
    ) -> Option<Result<BorrowedFd<'a>, PreCloneError>> {
        None
    }

    /// Hook executed shortly after the `clone3(2)` call in the host process.
    fn host_post_clone_hook(
        &self,
        policy: &Policy,
        state: &mut Self::State,
        guest_pid: Pid,
    ) -> Result<(), PostCloneHostError> {
        Ok(())
    }

    /// Hook executed shortly after the `clone3(2)` call in the guest process.
    fn guest_post_clone_hook(
        &self,
        policy: &Policy,
        state: Self::State,
    ) -> Result<(), PostCloneGuestError> {
        Ok(())
    }

    /// Returns a file descriptor representing the cgroup to write resource
    /// limits and other configuration options to.
    ///
    /// # Warning
    ///
    /// This must be distinct from the cgroup to which the sandboxed process is
    /// spawned in. If the sandboxed process is granted `CAP_SYS_ADMIN` and the
    /// two are the same cgroup, then it would be able to mount and write to the
    /// cgroups filesystem.
    fn as_cgroup_fd<'a>(
        &self,
        state: &'a Self::State,
    ) -> Option<BorrowedFd<'a>> {
        None
    }

    /// Performs cleanup operations necessary for the backend.
    fn teardown(&self, state: Self::State) -> Result<(), PostCloneHostError> {
        Ok(())
    }
}

/// Null backend that doesn't initialize cgroups at all.
#[derive(Clone, Debug)]
pub struct NullCgroups;

impl Cgroups<NullCgroups> {
    /// Don't create a cgroups hierarchy.
    pub fn new_null(policy: Policy) -> Self {
        Self {
            inner: NullCgroups,
            policy,
        }
    }
}

//SAFETY: we don't implementy any of the hooks at all
unsafe impl Backend for NullCgroups {
    type State = ();
}

/// [`Cgroups`] instantiated from an [`OwnedFd`] representing a directory in the
/// host's `cgroups(7)` hierarchy.
#[derive(Clone, Debug)]
pub struct OwnedFdCgroups;

impl Cgroups<OwnedFdCgroups> {
    /// Create a new cgroups hierarchy using the owned fd backend.
    pub fn new_fd(policy: Policy) -> Self {
        Self {
            inner: OwnedFdCgroups,
            policy,
        }
    }
}

/// State for the owned file descriptor backend.
#[derive(Debug)]
pub struct OwnedFdState {
    /// The file descriptor representing the cgroup to which settings are
    /// written.
    settings_fd: OwnedFd,

    /// The file descriptor representing the cgroup in which the child process
    /// is spawned.
    child_fd: OwnedFd,
}

impl OwnedFdState {
    /// Takes ownership and consumes a cgroups hierarchy.
    ///
    /// The file descriptor provided for state must refer to a directory in the
    /// cgroups hierarchy which is writeable by the process.
    ///
    /// This part of the cgroups hierarchy will be used to write the cgroups
    /// configuration to. bubblebox will create a nested cgroup in which the
    /// child process will be spawned.
    ///
    /// # Errors
    ///
    /// This method errors if creating and opening the nested cgroup for the
    /// child process fails.
    pub fn new(settings_fd: OwnedFd) -> Result<Self, PreCloneError> {
        syscalls::mkdirat(&settings_fd, c"bubblebox-child", Mode::RWXU.bits())?;

        //NOTE: technically someone could race us here but idk what we'd really
        //      be able to do about it

        let child_fd = util::retry_on_interrupt!({
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

        Ok(Self {
            settings_fd,
            child_fd,
        })
    }
}

//SAFETY: we don't use [`Backend::guest_post_clone_hook`]
unsafe impl Backend for OwnedFdCgroups {
    type State = OwnedFdState;

    fn clone_args_cgroup<'a>(
        &self,
        policy: &Policy,
        state: &'a Self::State,
    ) -> Option<Result<BorrowedFd<'a>, PreCloneError>> {
        if let Err(e) = policy.apply_to_cgroup(state.settings_fd.as_fd()) {
            return Some(Err(e.into()));
        }
        Some(Ok(state.child_fd.as_fd()))
    }

    fn as_cgroup_fd<'a>(
        &self,
        state: &'a Self::State,
    ) -> Option<BorrowedFd<'a>> {
        Some(state.settings_fd.as_fd())
    }
}

#[cfg(feature = "systemd-cgroups")]
impl Cgroups<SystemdCgroups> {
    /// Create a new cgroups hierarchy using the systemd backend.
    pub fn new_systemd(policy: Policy) -> Self {
        Self {
            inner: SystemdCgroups,
            policy,
        }
    }
}

/// Owned cgroups hierarchy created using a systemd transient unit.
#[cfg(feature = "systemd-cgroups")]
#[derive(Clone, Debug)]
pub struct SystemdCgroups;

/// State for the systemd backend.
#[cfg(feature = "systemd-cgroups")]
#[derive(Debug)]
pub struct SystemdState {
    /// State machine used to perform systemd cgroups initialization.
    inner: SystemdStateImpl,
}

#[cfg(feature = "systemd-cgroups")]
impl SystemdState {
    /// Creates a new systemd backend state instance.
    ///
    /// # Errors
    ///
    /// This method errors if creating an `eventfd2(2)` fails.
    pub fn new() -> Result<Self, PreCloneError> {
        let eventfd = syscalls::eventfd2(0, linux::EFD_CLOEXEC as i32)?;
        let inner = SystemdStateImpl::PreClone { eventfd };
        Ok(Self { inner })
    }
}

/// Internal state machine used during systemd cgroups initialization.
#[cfg(feature = "systemd-cgroups")]
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
#[cfg(feature = "systemd-cgroups")]
unsafe impl Backend for SystemdCgroups {
    type State = SystemdState;

    fn host_post_clone_hook(
        &self,
        policy: &Policy,
        state: &mut Self::State,
        guest_pid: Pid,
    ) -> Result<(), PostCloneHostError> {
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
                Variant(
                    Box::new(vec![Pid::as_raw(Some(guest_pid)) as u32]) as _
                ),
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

        //NOTE: we may need to poll for unit creation or do something here to
        //      ensure we aren't racing systemd's start job

        let (unit_path,): (Path<'static>,) = systemd.method_call(
            "org.freedesktop.systemd1.Manager",
            "GetUnit",
            (&unit_name,),
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
        let cgroups_root_fd = util::retry_on_interrupt!({
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

        //NOTE: same note about races here does apply

        //NOTE: no idea why but the `&CStr` implementation for dbus' `Get`
        //      doesn't work here for some lifetime reason
        let cgroup_path_string: String =
            unit.get("org.freedesktop.systemd1.Scope", "ControlGroup")?;
        let root_fd =
            cgroup_path_string
                .trim_prefix("/")
                .with_c_str::<{ syscalls::PATH_MAX }, _, PostCloneHostError>(
                    |cgroup_path| {
                        util::retry_on_interrupt!({
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
                        .map_err(Into::into)
                    },
                )?;

        syscalls::mkdirat(&root_fd, c"bubblebox-settings", Mode::RWXU.bits())?;

        let settings_fd = util::retry_on_interrupt!({
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

        let child_fd = util::retry_on_interrupt!({
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
        let formatted =
            itoa_buffer.format(Pid::as_raw(Some(guest_pid))).as_bytes();

        util::open_beneath_and_write!(&child_fd, c"cgroup.procs", formatted);

        //NOTE: delegate every controller down to our settings cgroup
        let subtree_control = util::retry_on_interrupt!({
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

        let parent_controllers = parse_controllers(&root_fd)?;

        //NOTE: we don't bother erroring on a missing controller here to
        //      centralize the logic for handling that inside the policy

        if policy.cpu.is_some() && parent_controllers.cpu {
            util::write_checked!(&subtree_control, b"+cpu");
        }

        if policy.memory.is_some() && parent_controllers.memory {
            util::write_checked!(&subtree_control, b"+memory");
        }

        if policy.io.is_some() && parent_controllers.io {
            util::write_checked!(&subtree_control, b"+io");
        }

        if policy.pids.is_some() && parent_controllers.pids {
            util::write_checked!(&subtree_control, b"+pids");
        }

        policy.apply_to_cgroup(settings_fd.as_fd())?;

        if let SystemdStateImpl::PreClone { ref eventfd } = state.inner {
            util::check_if_incomplete(
                util::retry_on_interrupt!({
                    syscalls::write(eventfd, 1u64.to_ne_bytes().as_slice())
                })?,
                8,
            )?;
            *state = SystemdState {
                inner: SystemdStateImpl::PostClone {
                    root_fd,
                    settings_fd,
                    child_fd,
                    unit_name,
                },
            };
        } else {
            return Err(PostCloneHostError::InvalidCgroupsState);
        }

        Ok(())
    }

    fn guest_post_clone_hook(
        &self,
        policy: &Policy,
        state: Self::State,
    ) -> Result<(), PostCloneGuestError> {
        if let SystemdStateImpl::PreClone { eventfd } = state.inner {
            let mut value = [0u8; 8];
            util::check_if_incomplete(
                util::retry_on_interrupt!({
                    syscalls::read(&eventfd, &mut value)
                })?,
                8,
            )?;
            if u64::from_ne_bytes(value) == 0 {
                return Err(
                    PostCloneGuestOtherError::InvalidCgroupsState.into()
                );
            }
        } else {
            return Err(PostCloneGuestOtherError::InvalidCgroupsState.into());
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

    fn teardown(&self, state: Self::State) -> Result<(), PostCloneHostError> {
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
