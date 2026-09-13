// SPDX-License-Identifier: AGPL-3.0-only

//! Cgroups policy implementation.

use linux_raw_sys::general as linux;
use meowix::{
    fd::AsFd, open_beneath_and_write, retry_on_interrupt, syscalls,
    util::FdReadWriteExt, write_checked,
};

use super::super::spawn::errors::Host as HostError;

//TODO: review all documentation comments here for consistency
//TODO: make methods that take a `Resource` take an `impl Into<Resource<T>>`

/// Controllers available to a cgroup.
#[derive(Clone, Debug, Default)]
pub(super) struct CgroupControllers {
    /// `cpu` controller.
    pub cpu: bool,

    /// `memory` controller.
    pub memory: bool,

    /// `io` controller.
    pub io: bool,

    /// `pids` controller.
    pub pids: bool,
}

/// Read the controllers available to a cgroup.
///
/// # Errors
///
/// This function errors if opening the `cgroup.controllers` file on the cgroup
/// fails, or if reading its contents fails.
pub(super) fn parse_controllers(
    cgroup_fd: impl AsFd,
) -> Result<CgroupControllers, HostError> {
    let controllers_fd = retry_on_interrupt!({
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
    })?;

    let mut has_controllers = CgroupControllers::default();

    let controllers = controllers_fd.read_string()?;
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
///
/// # Notes
///
/// The policy is not validated prior to it being instantiated. Callers are
/// responsible for ensuring that the final policy is valid and handling any
/// instantiation errors. In particular, the set of requested controllers are
/// not checked to be threaded if thread mode is requested.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// Core configuration options.
    pub(super) cgroup: CgroupProperties,

    /// Configuration under the `cpu` controller.
    pub(super) cpu: Option<CpuController>,

    /// Configuration under the `memory` controller.
    pub(super) memory: Option<MemoryController>,

    /// Configuration under the `io` controller.
    pub(super) io: Option<IoController>,

    /// Configuration under the `pids` controller.
    pub(super) pids: Option<PidsController>,
    //TODO: we could put more here, but the remaining controllers are less
    //      commonly useful. cpuset should be added in the future once testing
    //      is possible
}

impl Policy {
    /// Modify the configuration of the entire cgroup.
    pub fn cgroup(
        mut self,
        configure: impl FnOnce(CgroupProperties) -> CgroupProperties,
    ) -> Self {
        self.cgroup = configure(self.cgroup);
        self
    }

    /// Enable and modify the configuration of the cpu controller on the cgroup.
    ///
    /// If the cpu controller was already enabled, modify its configuration.
    pub fn cpu(
        mut self,
        configure: impl FnOnce(CpuController) -> CpuController,
    ) -> Self {
        self.cpu = Some(configure(self.cpu.unwrap_or_default()));
        self
    }

    /// Disable the cpu controller and erase any configuration it may have.
    pub fn disable_cpu(mut self) -> Self {
        self.cpu = None;
        self
    }

    /// Enable and modify the configuration of the memory controller on the
    /// cgroup.
    ///
    /// If the memory controller was already enabled, modify its configuration.
    pub fn memory(
        mut self,
        configure: impl FnOnce(MemoryController) -> MemoryController,
    ) -> Self {
        self.memory = Some(configure(self.memory.unwrap_or_default()));
        self
    }

    /// Disable the memory controller and erase any configuration it may have.
    pub fn disable_memory(mut self) -> Self {
        self.memory = None;
        self
    }

    /// Enable and modify the configuration of the io controller on the cgroup.
    ///
    /// If the io controller was already enabled, modify its configuration.
    pub fn io(
        mut self,
        configure: impl FnOnce(IoController) -> IoController,
    ) -> Self {
        self.io = Some(configure(self.io.unwrap_or_default()));
        self
    }

    /// Disable the io controller and erase any configuraton it may have.
    pub fn disable_io(mut self) -> Self {
        self.io = None;
        self
    }

    /// Enable and modify the configuration of the pids controller on the
    /// cgroup.
    ///
    /// If the pids controller was already enabled, modify its configuration.
    pub fn pids(
        mut self,
        configure: impl FnOnce(PidsController) -> PidsController,
    ) -> Self {
        self.pids = Some(configure(self.pids.unwrap_or_default()));
        self
    }

    /// Disable the pids controller and erase any configuration it may have.
    pub fn disable_pids(mut self) -> Self {
        self.pids = None;
        self
    }

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
#[derive(Clone, Debug, Default)]
pub struct CgroupProperties {
    /// Whether the cgroup is threaded or not.
    is_threaded: bool,

    /// Whether pressure stall information accounting is enabled in the
    /// sandbox's cgroup.
    enable_psi_accounting: Option<bool>,
}

impl CgroupProperties {
    /// Whether this cgroup is threaded.
    pub fn threaded(mut self, is_threaded: bool) -> Self {
        self.is_threaded = is_threaded;
        self
    }

    /// Whether pressure stall information accounting is enabled.
    pub fn psi_accounting(mut self, enable_psi_accounting: bool) -> Self {
        self.enable_psi_accounting = Some(enable_psi_accounting);
        self
    }

    /// Unset the pressure stall information accounting configuration.
    pub fn clear_psi_accounting(mut self) -> Self {
        self.enable_psi_accounting = None;
        self
    }

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
            open_beneath_and_write!(&cgroup_fd, c"cgroup.type", b"threaded");
        }

        if let Some(enable_psi_accounting) = self.enable_psi_accounting {
            open_beneath_and_write!(
                &cgroup_fd,
                c"cgroup.pressure",
                if enable_psi_accounting { b"1" } else { b"0" }
            );
        }

        Ok(())
    }
}

/// Configuration options ot the [`cpu` controller].
///
/// [`cpu` controller]: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#cpu
#[derive(Clone, Debug, Default)]
pub struct CpuController {
    /// Whether to give this controller to the subtree.
    subtree_control: bool,

    /// Weight given to the cgroup.
    weight: Option<CpuWeight>,

    /// CPU time to allow the cgroup within a time interval.
    ///
    /// Units are in microseconds.
    max: Option<(Resource<u64>, u64)>,

    /// Burst CPU time pool bound for the cgroup, in microseconds.
    ///
    /// This property specifies the maximum amount of CPU time credit that the
    /// cgroup may accumulate during periods of under-utilization. Accumulated
    /// credit permits the cgroup to exceed the quota specified by `cpu.max`
    /// during a later period, while preserving its long-term bandwidth limit.
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
    is_idle: Option<bool>,
}

impl CpuController {
    /// Whether to give the cpu controller to the subtree.
    pub fn subtree_control(mut self, subtree_control: bool) -> Self {
        self.subtree_control = subtree_control;
        self
    }

    /// Weight given to this cgroup.
    ///
    /// This sets the `cpu.weight` property on the cgroup.
    pub fn weight(mut self, weight: CpuWeight) -> Self {
        self.weight = Some(weight);
        self
    }

    /// Unset the cpu weight property for this cgroup.
    pub fn clear_weight(mut self) -> Self {
        self.weight = None;
        self
    }

    /// CPU time permitted for the cgroup within a time interval.
    ///
    /// This sets the `cpu.max` property on the cgroup.
    pub fn max(mut self, cpu_time: Resource<u64>, interval: u64) -> Self {
        self.max = Some((cpu_time, interval));
        self
    }

    /// Unset the CPU time allocation value for this cgroup.
    pub fn clear_max(mut self) -> Self {
        self.max = None;
        self
    }

    /// Burst CPU time pool bound for the cgroup, in microseconds.
    ///
    /// This property specifies the maximum amount of CPU time credit that the
    /// cgroup may accumulate during periods of under-utilization. Accumulated
    /// credit permits the cgroup to exceed the quota specified by `cpu.max`
    /// during a later period, while preserving its long-term bandwidth limit.
    ///
    /// This sets the `cpu.max.burst` property.
    pub fn max_burst(mut self, burst: u64) -> Self {
        self.max_burst = Some(burst);
        self
    }

    /// Unset the burst CPU time pool bound for the cgroup.
    pub fn clear_max_burst(mut self) -> Self {
        self.max_burst = None;
        self
    }

    /// Requested minimum utilization for the cgroup.
    ///
    /// This sets the `cpu.uclamp.min` property.
    pub fn uclamp_min(mut self, uclamp_min: Resource<UclampValue>) -> Self {
        self.uclamp_min = Some(uclamp_min);
        self
    }

    /// Clear the requested minimum utilization of the cgroup.
    pub fn clear_uclamp_min(mut self) -> Self {
        self.uclamp_min = None;
        self
    }

    /// Requested maximum utilization for the cgroup.
    ///
    /// This sets the `cpu.uclamp.max` property.
    pub fn uclamp_max(mut self, uclamp_max: Resource<UclampValue>) -> Self {
        self.uclamp_max = Some(uclamp_max);
        self
    }

    /// Clear the requested maximum utilization of the cgroup.
    pub fn clear_uclamp_max(mut self) -> Self {
        self.uclamp_max = None;
        self
    }

    /// Whether the cgroup should be considered idle.
    pub fn idle(mut self, is_idle: bool) -> Self {
        self.is_idle = Some(is_idle);
        self
    }

    /// Clear the idle state of the cgroup.
    pub fn clear_idle(mut self) -> Self {
        self.is_idle = None;
        self
    }

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
            open_beneath_and_write!(
                &cgroup_fd,
                c"cgroup.subtree_control",
                b"+cpu"
            );
        }

        if let Some(weight) = &self.weight {
            match weight.inner {
                CpuWeightInner::Weight(v) => {
                    open_beneath_and_write!(
                        &cgroup_fd,
                        c"cpu.weight",
                        itoa_buffer.format(v).as_bytes()
                    );
                }
                CpuWeightInner::Nice(v) => {
                    open_beneath_and_write!(
                        &cgroup_fd,
                        c"cpu.weight.nice",
                        itoa_buffer.format(v).as_bytes()
                    );
                }
            }
        }

        if let Some((value, duration)) = &self.max {
            let max_fd = retry_on_interrupt!({
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
            write_checked!(&max_fd, formatted.as_bytes());
        }

        if let Some(max_burst) = &self.max_burst {
            let value = itoa_buffer.format(*max_burst);
            open_beneath_and_write!(
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
                    open_beneath_and_write!(
                        &cgroup_fd,
                        c"cpu.uclamp.min",
                        string.as_bytes()
                    );
                }
                Resource::Max => {
                    open_beneath_and_write!(
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
                    open_beneath_and_write!(
                        &cgroup_fd,
                        c"cpu.uclamp.max",
                        string.as_bytes()
                    );
                }
                Resource::Max => {
                    open_beneath_and_write!(
                        &cgroup_fd,
                        c"cpu.uclamp.max",
                        b"max"
                    );
                }
            }
        }

        if let Some(is_idle) = self.is_idle {
            open_beneath_and_write!(
                &cgroup_fd,
                c"cpu.idle",
                if is_idle { b"1" } else { b"0" }
            );
        }

        Ok(())
    }
}

/// Utilization clamp value.
///
/// This value is guaranteed to be within the range `0..=10_000`. Values are
/// stored as an integer representation of decimals with two decimal places,
/// i.e. `23.74%` becomes `2374`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UclampValue(u16);

impl UclampValue {
    /// Construct a valid `cpu.uclamp.*` value.
    ///
    /// This must be in the range `0..=10_000`.
    pub const fn new(value: u16) -> Option<Self> {
        if value <= 10_000 {
            //SAFETY: we just checked it fit within the range
            Some(unsafe { Self::new_unchecked(value) })
        } else {
            None
        }
    }

    /// Construct a new `cpu.uclamp.*` value without performing a bounds check.
    ///
    /// # Safety
    ///
    /// This value must be in the range `0..=10_000`.
    pub const unsafe fn new_unchecked(value: u16) -> Self {
        Self(value)
    }

    /// Get the whole and fractional parts of the value.
    pub const fn into_parts(self) -> (u8, u8) {
        ((self.0 / 100) as u8, (self.0 % 100) as u8)
    }

    /// Get the contained [`u16`].
    pub const fn into_u16(self) -> u16 {
        self.0
    }
}

/// Weight given to a cgroup.
///
/// This value is guaranteed to be in the range `1..=10_000` if it is a hard
/// weight value or in the range `-20..=19` if it is a nice value.
#[derive(Clone, Debug)]
pub struct CpuWeight {
    /// Contained CPU weight value.
    inner: CpuWeightInner,
}

impl CpuWeight {
    /// Construct a new CPU weight from a hard weight value.
    ///
    /// This value must be in the range `1..=10_000`.
    pub const fn new(value: u16) -> Option<Self> {
        if (1..=10_000).contains(&value) {
            //SAFETY: we just checked that it was contained in the range
            Some(unsafe { Self::new_unchecked(value) })
        } else {
            None
        }
    }

    /// Construct a new CPU weight from a hard weight value without performing a
    /// bounds check.
    ///
    /// # Safety
    ///
    /// This value must be in the range `1..=10_000`.
    pub const unsafe fn new_unchecked(value: u16) -> Self {
        Self {
            inner: CpuWeightInner::Weight(value),
        }
    }

    /// Construct a new CPU weight from a nice value.
    ///
    /// This value must be in the range `-20..=19`.
    pub const fn new_nice(value: i8) -> Option<Self> {
        if (-20..=19).contains(&value) {
            //SAFETY: we just checked that it was contained in the range
            Some(unsafe { Self::new_nice_unchecked(value) })
        } else {
            None
        }
    }

    /// Construct a new CPU weight from a nice value without performing a bounds
    /// checked.
    ///
    /// # Safety
    ///
    /// This value must be in the range `-20..=19`.
    pub const unsafe fn new_nice_unchecked(value: i8) -> Self {
        Self {
            inner: CpuWeightInner::Nice(value),
        }
    }

    /// Get the contained hard CPU weight, if it contains one.
    pub const fn into_weight(self) -> Option<u16> {
        if let CpuWeightInner::Weight(value) = self.inner {
            Some(value)
        } else {
            None
        }
    }

    /// Get the contained nice value, if it contains one.
    pub const fn into_nice(self) -> Option<i8> {
        if let CpuWeightInner::Nice(value) = self.inner {
            Some(value)
        } else {
            None
        }
    }

    //TODO: into_* methods that convert?
}

/// Internal representation of a CPU weight value.
#[derive(Clone, Debug)]
enum CpuWeightInner {
    /// Hard weight value.
    ///
    /// Must be in the range `1..=10_000`.
    Weight(u16),

    /// Nice value.
    ///
    /// Must be in the range `-20..=19`.
    Nice(i8),
}

/// Configuration options for the [`memory` controller]
///
/// [`memory` controller]: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#memory-interface-files
#[derive(Clone, Debug, Default)]
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

    /// Whether this cgroup represents an indivisible workload.
    ///
    /// That is, if the OOM killer were invoked within this cgroup, whether all
    /// tasks within this cgroup should be killed at once to avoid partial
    /// kills.
    is_indivisible: Option<bool>,

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
    /// This sets the `memory.zswap.max` threshold for the cgroup.
    zswap_max: Option<Resource<u64>>,

    /// Whether to disable writeback for zswap pages.
    disable_zswap_writeback: Option<bool>,
}

impl MemoryController {
    /// Whether to give the memory controller to the subtree.
    pub fn subtree_control(mut self, subtree_control: bool) -> Self {
        self.subtree_control = subtree_control;
        self
    }

    /// Set the `memory.min` threshold for the cgroup, in bytes.
    ///
    /// This represents hard memory protection.
    pub fn min(mut self, min: Resource<u64>) -> Self {
        self.min = Some(min);
        self
    }

    /// Unset the `memory.min` threshold for the cgroup.
    pub fn clear_min(mut self) -> Self {
        self.min = None;
        self
    }

    /// Set the `memory.low` threshold for the cgroup, in bytes.
    ///
    /// This represents best-effort memory protection.
    pub fn low(mut self, low: Resource<u64>) -> Self {
        self.low = Some(low);
        self
    }

    /// Unset the `memory.low` threshold for the cgroup.
    pub fn clear_low(mut self) -> Self {
        self.low = None;
        self
    }

    /// Set the `memory.high` threshold for the cgroup, in bytes.
    ///
    /// This represents a memory throttle limit.
    pub fn high(mut self, high: Resource<u64>) -> Self {
        self.high = Some(high);
        self
    }

    /// Unset the `memory.high` threshold for the cgroup.
    pub fn clear_high(mut self) -> Self {
        self.high = None;
        self
    }

    /// Set the `memory.max` threshold for the cgroup, in bytes.
    ///
    /// This represents a memory hard limit.
    pub fn max(mut self, max: Resource<u64>) -> Self {
        self.max = Some(max);
        self
    }

    /// Unset the `memory.max` threshold for the cgroup.
    pub fn clear_max(mut self) -> Self {
        self.max = None;
        self
    }

    /// Whether this cgroup represents an indivisible workload.
    ///
    /// That is, if the OOM killer were invoked within this cgroup, whether all
    /// tasks within this cgroup should be killed at once to avoid partial
    /// kills.
    pub fn indivisible(mut self, is_indivisible: bool) -> Self {
        self.is_indivisible = Some(is_indivisible);
        self
    }

    /// Unset the `memory.oom.group` setting.
    pub fn clear_indivisible(mut self) -> Self {
        self.is_indivisible = None;
        self
    }

    /// Set the `memory.swap.high` threshold for the cgroup.
    ///
    /// This represents a throttle limit for the swap usage of the cgroup.
    pub fn swap_high(mut self, swap_high: Resource<u64>) -> Self {
        self.swap_high = Some(swap_high);
        self
    }

    /// Unset the `memory.swap.high` threshold for the cgroup.
    pub fn clear_swap_high(mut self) -> Self {
        self.swap_high = None;
        self
    }

    /// Set the `memory.swap.max` threshold for the cgroup.
    ///
    /// This represents a hard limit for the swap usage of the cgroup.
    pub fn swap_max(mut self, swap_max: Resource<u64>) -> Self {
        self.swap_max = Some(swap_max);
        self
    }

    /// Unset the `memory.swap.max` threshold for the cgroup.
    pub fn unset_swap_max(mut self) -> Self {
        self.swap_max = None;
        self
    }

    /// Set the `memory.zswap.max` threshold for the cgroup.
    ///
    /// This represents a hard limit for the zswap usage of the cgroup.
    pub fn zswap_max(mut self, zswap_max: Resource<u64>) -> Self {
        self.zswap_max = Some(zswap_max);
        self
    }

    /// Unset the `memory.zswap.max` threshold for the cgroup.
    pub fn unset_zswap_max(mut self) -> Self {
        self.zswap_max = None;
        self
    }

    /// Whether to disable writeback for zswap pages.
    pub fn disable_zswap_writeback(
        mut self,
        disable_zswap_writeback: bool,
    ) -> Self {
        self.disable_zswap_writeback = Some(disable_zswap_writeback);
        self
    }

    /// Unset the `memory.zswap.writeback` setting.
    pub fn clear_disable_zswap_writeback(mut self) -> Self {
        self.disable_zswap_writeback = None;
        self
    }

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
            open_beneath_and_write!(
                &cgroup_fd,
                c"cgroup.subtree_control",
                b"+memory"
            );
        }

        if let Some(min) = &self.min {
            open_beneath_and_write!(
                &cgroup_fd,
                c"memory.min",
                min.into_str(&mut itoa_buffer).as_bytes()
            );
        }

        if let Some(low) = &self.low {
            open_beneath_and_write!(
                &cgroup_fd,
                c"memory.low",
                low.into_str(&mut itoa_buffer).as_bytes()
            );
        }

        if let Some(high) = &self.high {
            open_beneath_and_write!(
                &cgroup_fd,
                c"memory.high",
                high.into_str(&mut itoa_buffer).as_bytes()
            );
        }

        if let Some(max) = &self.max {
            open_beneath_and_write!(
                &cgroup_fd,
                c"memory.max",
                max.into_str(&mut itoa_buffer).as_bytes()
            );
        }

        if let Some(is_indivisible) = self.is_indivisible {
            open_beneath_and_write!(
                &cgroup_fd,
                c"memory.oom.group",
                if is_indivisible { b"1" } else { b"0" }
            );
        }

        if let Some(swap_high) = &self.swap_high {
            open_beneath_and_write!(
                &cgroup_fd,
                c"memory.swap.high",
                swap_high.into_str(&mut itoa_buffer).as_bytes()
            );
        }

        if let Some(swap_max) = &self.swap_max {
            open_beneath_and_write!(
                &cgroup_fd,
                c"memory.swap.max",
                swap_max.into_str(&mut itoa_buffer).as_bytes()
            );
        }

        if let Some(zswap_max) = &self.zswap_max {
            open_beneath_and_write!(
                &cgroup_fd,
                c"memory.zswap.max",
                zswap_max.into_str(&mut itoa_buffer).as_bytes()
            );
        }

        if let Some(disable_zswap_writeback) = self.disable_zswap_writeback {
            open_beneath_and_write!(
                &cgroup_fd,
                c"memory.zswap.writeback",
                if disable_zswap_writeback { b"0" } else { b"1" }
            );
        }

        Ok(())
    }
}

/// Configuration options for the [`io` controller]
///
/// [`io` controller]: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#io-interface-files
#[derive(Clone, Debug, Default)]
pub struct IoController {
    /// Whether to give this controller to the subtree.
    subtree_control: bool,
    //TODO: implement the io controller options. this one looks more difficult
    //      because it requires device numbers etc
}

impl IoController {
    /// Whether to give the io controller to the subtree.
    pub fn subtree_control(mut self, subtree_control: bool) -> Self {
        self.subtree_control = subtree_control;
        self
    }

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
            open_beneath_and_write!(
                &cgroup_fd,
                c"cgroup.subtree_control",
                b"+io"
            );
        }

        //TODO: implement these, skipped for now

        Ok(())
    }
}

/// Configuration options for the [`pids` controller]
///
/// [`pids` controller]: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#pid-interface-files
#[derive(Clone, Debug, Default)]
pub struct PidsController {
    /// Whether to give this controller to the subtree.
    pub subtree_control: bool,

    /// Hard limit on the number of processes.
    pub max: Option<Resource<u64>>,
}

impl PidsController {
    /// Whether to give the pids controller to the subtree.
    pub fn subtree_control(mut self, subtree_control: bool) -> Self {
        self.subtree_control = subtree_control;
        self
    }

    /// Set the `pids.max` threshold for the cgroup.
    ///
    /// This represents a hard limit on the number of processes.
    pub fn max(mut self, max: Resource<u64>) -> Self {
        self.max = Some(max);
        self
    }

    /// Unset the `pids.max` threshold for the cgroup.
    pub fn unset_max(mut self) -> Self {
        self.max = None;
        self
    }

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
            open_beneath_and_write!(
                &cgroup_fd,
                c"cgroup.subtree_control",
                b"+pids"
            );
        }

        if let Some(max) = self.max {
            open_beneath_and_write!(
                &cgroup_fd,
                c"pids.max",
                max.into_str(&mut itoa_buffer).as_bytes()
            );
        }

        Ok(())
    }
}
