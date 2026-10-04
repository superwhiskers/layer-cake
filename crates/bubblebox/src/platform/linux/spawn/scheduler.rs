// SPDX-License-Identifier: AGPL-3.0-only

//! Scheduler policy implementation.

use linux_raw_sys::general as linux;
use meowix::{
    errno::Errno,
    fd::AsFd,
    ids::Current,
    open_beneath_and_write,
    syscalls::{self, CoreSchedulingTarget},
};
use std::mem;

use super::{
    super::policy::scheduler::{Policy, Scheduler},
    errors::PostSpawnGuest as PostSpawnGuestError,
};

/// Apply the scheduler policy.
///
/// # Errors
///
/// This function errors if setting scheduler attributes, writing to
/// `/proc/self/oom_score_adj` fails, or if using `prctl(2)` with
/// `PR_SCHED_CORE` fails.
pub fn apply_scheduler_policy(
    proc_fd: impl AsFd,
    policy: &Scheduler,
) -> Result<(), PostSpawnGuestError> {
    //SAFETY: c structs are valid when zeroed
    let mut sched_attr = unsafe { mem::zeroed::<linux::sched_attr>() };

    sched_attr.size = size_of::<linux::sched_attr>() as u32;

    if policy.reset_on_fork {
        sched_attr.sched_flags |= linux::SCHED_FLAG_RESET_ON_FORK as u64;
    }

    match policy.policy {
        Policy::Normal { nice } => {
            sched_attr.sched_policy = linux::SCHED_NORMAL;
            sched_attr.sched_nice = nice;
        }
        Policy::Batch { nice } => {
            sched_attr.sched_policy = linux::SCHED_BATCH;
            sched_attr.sched_nice = nice;
        }
        Policy::Idle => {
            sched_attr.sched_policy = linux::SCHED_IDLE;
        }
        Policy::Fifo { priority } => {
            sched_attr.sched_policy = linux::SCHED_FIFO;
            sched_attr.sched_priority = priority;
        }
        Policy::RoundRobin { priority } => {
            sched_attr.sched_policy = linux::SCHED_RR;
            sched_attr.sched_priority = priority;
        }
        Policy::Deadline {
            runtime,
            deadline,
            period,
            allow_reclaim,
            signal_on_overrun,
        } => {
            sched_attr.sched_policy = linux::SCHED_DEADLINE;
            sched_attr.sched_runtime = runtime;
            sched_attr.sched_deadline = deadline;
            sched_attr.sched_period = period;

            if allow_reclaim {
                sched_attr.sched_flags |= linux::SCHED_FLAG_RECLAIM as u64;
            }

            if signal_on_overrun {
                sched_attr.sched_flags |= linux::SCHED_FLAG_DL_OVERRUN as u64;
            }
        }
    }

    if let Some(min_utilization) = policy.min_utilization {
        sched_attr.sched_flags |= linux::SCHED_FLAG_UTIL_CLAMP_MIN as u64;
        sched_attr.sched_util_min = min_utilization;
    }

    if let Some(max_utilization) = policy.max_utilization {
        sched_attr.sched_flags |= linux::SCHED_FLAG_UTIL_CLAMP_MAX as u64;
        sched_attr.sched_util_max = max_utilization;
    }

    syscalls::sched_setattr(Current, sched_attr, 0)?;

    if let Some(oom_score_adjustment) = policy.oom_score_adjustment {
        let mut intermediary = itoa::Buffer::new();
        open_beneath_and_write!(
            proc_fd.as_fd(),
            c"self/oom_score_adj",
            intermediary.format(oom_score_adjustment).as_bytes()
        );
    }

    if policy.create_core_scheduling_cookie {
        //NOTE: as we are a single thread, targeting the current thread is fine
        match syscalls::create_core_scheduling_cookie(
            CoreSchedulingTarget::Thread(Current.into()),
        ) {
            Ok(()) => (),
            //NOTE: returned if symmetric multithreading is not active. we can
            //      ignore this error as this just means there is nothing to
            //      isolate. see
            //      https://elixir.bootlin.com/linux/v7.2.8/source/kernel/sched/core_sched.c#L139-L140
            Err(e) if e.error() == Errno::NODEV => (),
            Err(e) => Err(e)?,
        }
    }

    Ok(())
}
