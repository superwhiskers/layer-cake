// SPDX-License-Identifier: AGPL-3.0-only

//! Scheduler policy implementation.

/// Scheduler policy.
///
/// This structure holds configuration values associated with the kernel's
/// scheduler. These include but are not limited to:
///
/// - Scheduler policy
/// - Utilization hints
/// - Core scheduling behavior
/// - Whether to reset privileged scheduling policies on fork
///
/// Clearing limits does not erase them, as with [the cgroup
/// policy](super::super::cgroups::policy). It only causes the limits from the
/// host process' environment to pass through unaltered, barring a reset-on-fork
/// flag being set.
///
/// # Notes
///
/// By default, all of these attributes are inherited by the guest as-is, as
/// many of these are sensitive to the environment of the host process, and
/// would require probing parts of the environment to set automatically.
///
/// # Warning
///
/// Some scheduler policies may need `CAP_SYS_NICE` to use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scheduler {
    /// Scheduler attribute policy.
    ///
    /// This structure contains options to set with the [`sched_setattr(2)`]
    /// syscall. These are handled separately due to it requiring the scheduler
    /// policy to be set when called, as there is no way to set a "default"
    /// scheduler policy without inspecting the host's environment.
    ///
    /// [`sched_setattr(2)`]: https://www.man7.org/linux/man-pages/man2/sched_setattr.2.html
    pub(crate) attributes: Option<Attributes>,

    /// OOM-killer score adjustment.
    ///
    /// See [`proc_pid_oom_score_adj(5)`] for more details.
    ///
    /// [`proc_pid_oom_score_adj(5)`]: https://www.man7.org/linux/man-pages/man5/proc_pid_oom_score_adj.5.html
    pub(crate) oom_score_adjustment: Option<u16>,

    /// Whether to use [`PR_SCHED_CORE`] to prevent guest processes from being
    /// scheduled on a core with host processes.
    ///
    /// [`PR_SCHED_CORE`]: https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/core-scheduling.html
    pub(crate) create_core_scheduling_cookie: bool,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self {
            //NOTE: we can't set this without checking first as the host may
            //      have a nice value above any arbitrary threshold we set aside
            //      from the maximum. the maximum is not a sane default
            attributes: None,
            //NOTE: we can't safely set this without checking first. the floor
            //      is arbitrary
            oom_score_adjustment: None,
            //NOTE: in most cases your threat model will not include things
            //      prevented by this
            create_core_scheduling_cookie: false,
        }
    }
}

impl Scheduler {
    /// Update the scheduler attributes of the guest process.
    ///
    /// These include any properties set through the [`sched_setattr(2)`]
    /// syscall. By default, these are not set. Calling this method without
    ///
    /// [`sched_setattr(2)`]: https://www.man7.org/linux/man-pages/man2/sched_setattr.2.html
    pub fn attributes(
        mut self,
        configure: impl FnOnce(Attributes) -> Attributes,
    ) -> Self {
        self.attributes = Some(configure(self.attributes.unwrap_or_default()));
        self
    }

    /// Clear the scheduler attributes of the guest process, if they have been
    /// set.
    pub fn clear_attributes(mut self) -> Self {
        self.attributes = None;
        self
    }

    /// Update the OOM-killer score adjustment.
    ///
    /// See [`proc_pid_oom_score_adj(5)`] for more details.
    ///
    /// # Warning
    ///
    /// Setting this may fail due to the hidden process-specific
    /// `oom_score_adj_min` value dictating what the minimum acceptable value
    /// is. Consider probing this value prior to setting it in the guest.
    ///
    /// [`proc_pid_oom_score_adj(5)`]: https://www.man7.org/linux/man-pages/man5/proc_pid_oom_score_adj.5.html
    pub fn oom_score_adjustment(mut self, adj: u16) -> Self {
        self.oom_score_adjustment = Some(adj);
        self
    }

    /// Clear the OOM-killer score adjustment, if one has been set.
    pub fn clear_oom_score_adjustment(mut self) -> Self {
        self.oom_score_adjustment = None;
        self
    }

    /// Whether to use [`PR_SCHED_CORE`] to prevent guest processes from being
    /// scheduled on a core with host processes.
    ///
    /// [`PR_SCHED_CORE`]: https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/core-scheduling.html
    pub fn create_core_scheduling_cookie(mut self, create: bool) -> Self {
        self.create_core_scheduling_cookie = create;
        self
    }
}

/// Process scheduler attributes.
///
/// Configures the action to take regarding [scheduler policy and attributes]
/// applied to the guest's initial process.
///
/// # Notes
///
/// The default policy is to reset the scheduler policy to the normal policy
/// with the [`nice(2)`] value set to zero. This will not always work, as the
/// floor may be higher than zero. It is the caller's responsibility to ensure
/// if scheduler attributes are set that they are valid given the host's
/// environment.
///
/// [scheduler policy and attributes]: https://www.man7.org/linux/man-pages/man7/sched.7.html
/// [`nice(2)`]: https://www.man7.org/linux/man-pages/man2/nice.2.html
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attributes {
    /// Whether to reset privileged scheduling policies for child processes.
    ///
    /// See [`sched(7)`] for more details.
    ///
    /// [`sched(7)`]: https://www.man7.org/linux/man-pages/man7/sched.7.html
    pub(crate) reset_on_fork: bool,

    /// Scheduler policy.
    pub(crate) policy: Policy,

    /// Minimum utilization hint.
    ///
    /// See [`sched_setattr(2)`] for more details.
    ///
    /// [`sched_setattr(2)`]: https://www.man7.org/linux/man-pages/man2/sched_setattr.2.html
    pub(crate) min_utilization: Option<u32>,

    /// Maximum utilization hint.
    ///
    /// See [`sched_setattr(2)`] for more details.
    ///
    /// [`sched_setattr(2)`]: https://www.man7.org/linux/man-pages/man2/sched_setattr.2.html
    pub(crate) max_utilization: Option<u32>,
}

impl Default for Attributes {
    fn default() -> Self {
        Self {
            reset_on_fork: false,
            //NOTE: this will not always work, but by default this is off
            //      anyway
            policy: Policy::Normal { nice: 0 },
            min_utilization: None,
            max_utilization: None,
        }
    }
}

impl Attributes {
    /// Whether to reset privileged scheduling policies for child processes.
    ///
    /// See [`sched(7)`] for more details.
    ///
    /// [`sched(7)`]: https://www.man7.org/linux/man-pages/man7/sched.7.html
    pub fn reset_on_fork(mut self, reset: bool) -> Self {
        self.reset_on_fork = reset;
        self
    }

    /// Set the scheduler policy to [`SCHED_NORMAL`] with the specified
    /// [`nice(2)`] value.
    ///
    /// This is the normal scheduler policy, and usually what you want.
    ///
    /// # Warning
    ///
    /// Adjusting the [`nice(2)`] value beyond a certain threshold may require
    /// `CAP_SYS_NICE`.
    ///
    /// [`SCHED_NORMAL`]: https://www.man7.org/linux/man-pages/man7/sched.7.html
    /// [`nice(2)`]: https://www.man7.org/linux/man-pages/man2/nice.2.html
    pub fn normal(mut self, nice: i32) -> Self {
        self.policy = Policy::Normal { nice };
        self
    }

    /// Set the scheduler policy to [`SCHED_BATCH`] with the specified
    /// [`nice(2)`] value.
    ///
    /// # Warning
    ///
    /// Adjusting the [`nice(2)`] value beyond a certain threshold may require
    /// `CAP_SYS_NICE`.
    ///
    /// [`SCHED_BATCH`]: https://www.man7.org/linux/man-pages/man7/sched.7.html
    /// [`nice(2)`]: https://www.man7.org/linux/man-pages/man2/nice.2.html
    pub fn batch(mut self, nice: i32) -> Self {
        self.policy = Policy::Batch { nice };
        self
    }

    /// Set the scheduler policy to [`SCHED_IDLE`].
    ///
    /// [`SCHED_IDLE`]: https://www.man7.org/linux/man-pages/man7/sched.7.html
    pub fn idle(mut self) -> Self {
        self.policy = Policy::Idle;
        self
    }

    /// Set the scheduler policy to [`SCHED_FIFO`] with the specified static
    /// priority.
    ///
    /// # Notes
    ///
    /// The static priority value has limits that must be determined at runtime.
    /// See [`sched_get_priority_max(2)`] for more details.
    ///
    /// # Warning
    ///
    /// This is a real-time scheduling policy. This may need additional
    /// privileges to be used.
    ///
    /// [`SCHED_FIFO`]: https://www.man7.org/linux/man-pages/man7/sched.7.html
    /// [`sched_get_priority_max(2)`]: https://www.man7.org/linux/man-pages/man2/sched_get_priority_max.2.html
    pub fn fifo(mut self, priority: u32) -> Self {
        self.policy = Policy::Fifo { priority };
        self
    }

    /// Set the scheduler policy to [`SCHED_RR`] with the specified static
    /// priority.
    ///
    /// # Notes
    ///
    /// The static priority value has limits that must be determined at runtime.
    /// See [`sched_get_priority_max(2)`] for more details.
    ///
    /// # Warning
    ///
    /// This is a real-time scheduling policy. This may need additional
    /// privileges to be used.
    ///
    /// [`SCHED_RR`]: https://www.man7.org/linux/man-pages/man7/sched.7.html
    /// [`sched_get_priority_max(2)`]: https://www.man7.org/linux/man-pages/man2/sched_get_priority_max.2.html
    pub fn round_robin(mut self, priority: u32) -> Self {
        self.policy = Policy::RoundRobin { priority };
        self
    }

    /// Set the scheduler policy to [`SCHED_DEADLINE`] with the specified
    /// runtime, deadline, and period parameters.
    ///
    /// # Notes
    ///
    /// There are several invariants upon these parameters. Refer to
    /// [`sched(7)`] for more details.
    ///
    /// The `allow_reclaim` and `signal_on_overrun` parameters correspond to
    /// `SCHED_FLAG_RECLAIM` and `SCHED_FLAG_DL_OVERRUN`, respectively.
    ///
    /// # Warning
    ///
    /// This is a deadline scheduling policy. You probably don't need this. This
    /// will need `CAP_SYS_NICE` to be used.
    ///
    /// [`SCHED_DEADLINE`]: https://www.man7.org/linux/man-pages/man7/sched.7.html
    /// [`sched(7)`]: https://www.man7.org/linux/man-pages/man7/sched.7.html
    pub fn deadline(
        mut self,
        runtime: u64,
        deadline: u64,
        period: u64,
        allow_reclaim: bool,
        signal_on_overrun: bool,
    ) -> Self {
        self.policy = Policy::Deadline {
            runtime,
            deadline,
            period,
            allow_reclaim,
            signal_on_overrun,
        };
        self
    }

    /// Set a minimum utilization hint.
    ///
    /// See [`sched_setattr(2)`] for more details.
    ///
    /// [`sched_setattr(2)`]: https://www.man7.org/linux/man-pages/man2/sched_setattr.2.html
    pub fn min_utilization(mut self, min: u32) -> Self {
        self.min_utilization = Some(min);
        self
    }

    /// Clear a minimum utilization hint, if one has been set.
    pub fn clear_min_utilization(mut self) -> Self {
        self.min_utilization = None;
        self
    }

    /// Set a maximum utilization hint.
    ///
    /// See [`sched_setattr(2)`] for more details.
    ///
    /// [`sched_setattr(2)`]: https://www.man7.org/linux/man-pages/man2/sched_setattr.2.html
    pub fn max_utilization(mut self, max: u32) -> Self {
        self.max_utilization = Some(max);
        self
    }

    /// Clear a maximum utilization hint, if one has been set.
    pub fn clear_max_utilization(mut self) -> Self {
        self.max_utilization = None;
        self
    }
}

/// Scheduler policy kinds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Policy {
    /// `SCHED_NORMAL`.
    Normal { nice: i32 },

    /// `SCHED_BATCH`.
    Batch { nice: i32 },

    /// `SCHED_IDLE`.
    Idle,

    /// `SCHED_FIFO`.
    Fifo { priority: u32 },

    /// `SCHED_RR`.
    RoundRobin { priority: u32 },

    /// `SCHED_DEADLINE`.
    Deadline {
        runtime: u64,
        deadline: u64,
        period: u64,
        allow_reclaim: bool,
        signal_on_overrun: bool,
    },
}
