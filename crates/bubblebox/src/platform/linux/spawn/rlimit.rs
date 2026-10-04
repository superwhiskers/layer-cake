// SPDX-License-Identifier: AGPL-3.0-only

//! Resource limit policy application.

use linux_raw_sys::general as linux;
use meowix::{ids::Current, syscalls};

use super::{
    super::policy::rlimit::Rlimits,
    errors::PostSpawnGuest as PostSpawnGuestError,
};

/// Apply the resource limit policy.
///
/// # Errors
///
/// This function errors if any `prlimit64(2)` call fails.
pub fn apply_resource_limit_policy(
    policy: &Rlimits,
) -> Result<(), PostSpawnGuestError> {
    macro_rules! implement_limit {
        ($resource:expr, $limit:ident) => {
            if let Some($limit) = policy.$limit {
                let (soft, hard) = $limit.into_raw();
                syscalls::prlimit64(
                    Current,
                    $resource,
                    Some(linux::rlimit64 {
                        rlim_cur: soft,
                        rlim_max: hard,
                    }),
                    None,
                )?;
            }
        };
    }

    implement_limit!(linux::RLIMIT_AS, address_space);
    implement_limit!(linux::RLIMIT_CORE, core);
    implement_limit!(linux::RLIMIT_CPU, cpu);
    implement_limit!(linux::RLIMIT_DATA, data);
    implement_limit!(linux::RLIMIT_FSIZE, fsize);
    implement_limit!(linux::RLIMIT_LOCKS, locks);
    implement_limit!(linux::RLIMIT_MEMLOCK, memlock);
    implement_limit!(linux::RLIMIT_MSGQUEUE, msgqueue);
    implement_limit!(linux::RLIMIT_NICE, nice);
    implement_limit!(linux::RLIMIT_NOFILE, nofile);
    implement_limit!(linux::RLIMIT_NPROC, nproc);
    implement_limit!(linux::RLIMIT_RTPRIO, rtprio);
    implement_limit!(linux::RLIMIT_RTTIME, rttime);
    implement_limit!(linux::RLIMIT_SIGPENDING, sigpending);
    implement_limit!(linux::RLIMIT_STACK, stack);

    Ok(())
}
