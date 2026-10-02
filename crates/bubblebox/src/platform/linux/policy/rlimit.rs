// SPDX-License-Identifier: AGPL-3.0-only

//! Resource limit policy implementation.

/// Resource limit policy.
///
/// Configures the action to take regarding [prlimits] applied to the guest's
/// initial process. These limits are applied per-process.
///
/// Clearing limits does not erase them, as with [the cgroup
/// policy](super::super::cgroups::policy). It only causes the limits from the
/// host process' environment to pass through unaltered.
///
/// # Notes
///
/// By default, no changes to the resource limits of the environment are made.
/// This is because any limit we set may end up being greater than those imposed
/// by the environment, causing it to fail.
///
/// # Warning
///
/// Most of these are not recommended to use. Prefer using cgroups wherever
/// possible due to there being fewer differences in behavior between a 32-bit
/// kernel and 64-bit kernel. Under a 32-bit kernel, cgroups permit setting
/// higher limits than what an rlimit would. Under a 64-bit kernel with a 32-bit
/// userland, rlimits behave the same as they would with a 64-bit userland.
///
/// [prlimits]: https://www.man7.org/linux/man-pages/man2/prlimit64.2.html
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct Rlimits {
    /// Amount of bytes a process' address space may occupy.
    pub(crate) address_space: Option<Rlimit>,

    /// Maximum size of a core file dumped by a process.
    pub(crate) core: Option<Rlimit>,

    /// CPU time, in seconds, that a process may consume.
    pub(crate) cpu: Option<Rlimit>,

    /// Maximum size of a process' data segment, in bytes.
    pub(crate) data: Option<Rlimit>,

    /// Maximum size in bytes of files that a process may create.
    pub(crate) fsize: Option<Rlimit>,

    /// Amount of `flock(2)` locks and `fcntl(2)` leases a process may
    /// establish.
    pub(crate) locks: Option<Rlimit>,

    /// Maximum number of bytes in memory that a process may lock into RAM.
    pub(crate) memlock: Option<Rlimit>,

    /// Maximum number of bytes that can be allocated for POSIX message queues
    /// for the real user ID of the calling process.
    pub(crate) msgqueue: Option<Rlimit>,

    /// Ceiling to the process' nice value.
    pub(crate) nice: Option<Rlimit>,

    /// Exclusive upper bound on file descriptor numbers.
    pub(crate) nofile: Option<Rlimit>,

    /// Limit on the number of extant processes under the process' real user
    /// ID.
    pub(crate) nproc: Option<Rlimit>,

    /// Ceiling on the real-time priority that may be set for this process.
    pub(crate) rtprio: Option<Rlimit>,

    /// Limit on the amount of CPU time a process under real-time scheduling
    /// may consume without making a blocking syscall.
    pub(crate) rttime: Option<Rlimit>,

    /// Limit on the number of signals that may be queued for the real user ID
    /// of the calling process.
    pub(crate) sigpending: Option<Rlimit>,

    /// Maximum size of the process' stack, in bytes.
    pub(crate) stack: Option<Rlimit>,
}

impl Rlimits {
    /// Limit the amount of bytes a process' address space may occupy.
    pub fn address_space(
        mut self,
        configure: impl FnOnce(Rlimit) -> Rlimit,
    ) -> Self {
        self.address_space =
            Some(configure(self.address_space.unwrap_or_default()));
        self
    }

    /// Unset a limit on the amount of bytes a process' address space may
    /// occupy, if one exists.
    pub fn clear_address_space(mut self) -> Self {
        self.address_space = None;
        self
    }

    /// Limit the maximum size of a core file dumped by a process.
    pub fn core(mut self, configure: impl FnOnce(Rlimit) -> Rlimit) -> Self {
        self.core = Some(configure(self.core.unwrap_or_default()));
        self
    }

    /// Unset a limit on the maximum size of a core file dumped by a process, if
    /// one exists.
    pub fn clear_core(mut self) -> Self {
        self.core = None;
        self
    }

    /// Limit the amount of CPU time a process may consume.
    pub fn cpu(mut self, configure: impl FnOnce(Rlimit) -> Rlimit) -> Self {
        self.cpu = Some(configure(self.cpu.unwrap_or_default()));
        self
    }

    /// Unset a limit on the amount of CPU time a process may consume, if one
    /// exists.
    pub fn clear_cpu(mut self) -> Self {
        self.cpu = None;
        self
    }

    /// Limit the maximum size of a process' data segment, in bytes.
    pub fn data(mut self, configure: impl FnOnce(Rlimit) -> Rlimit) -> Self {
        self.data = Some(configure(self.data.unwrap_or_default()));
        self
    }

    /// Unset a limit on the maximum size of a process' data segment, if one
    /// exists.
    pub fn clear_data(mut self) -> Self {
        self.data = None;
        self
    }

    /// Limit the maximum size in bytes of files that a process may create.
    pub fn fsize(mut self, configure: impl FnOnce(Rlimit) -> Rlimit) -> Self {
        self.fsize = Some(configure(self.fsize.unwrap_or_default()));
        self
    }

    /// Unset a limit on the maximum size in bytes of files that a process may
    /// create, if one exists.
    pub fn clear_fsize(mut self) -> Self {
        self.fsize = None;
        self
    }

    /// Limit the amount of `flock(2)` locks and `fcntl(2)` leases a process may
    /// establish.
    pub fn locks(mut self, configure: impl FnOnce(Rlimit) -> Rlimit) -> Self {
        self.locks = Some(configure(self.locks.unwrap_or_default()));
        self
    }

    /// Unset a limit on the amount of `flock(2)` locks and `fcntl(2)` leases a
    /// process may establish, if one exists.
    pub fn clear_locks(mut self) -> Self {
        self.locks = None;
        self
    }

    /// Limit the number of bytes in memory that a process may lock into RAM.
    ///
    /// This is rounded down to the nearest multiple of the system page size.
    pub fn memlock(mut self, configure: impl FnOnce(Rlimit) -> Rlimit) -> Self {
        self.memlock = Some(configure(self.memlock.unwrap_or_default()));
        self
    }

    /// Unset a limit on the number of bytes in memory that a process may lock
    /// into RAM, if one exists.
    pub fn clear_memlock(mut self) -> Self {
        self.memlock = None;
        self
    }

    /// Limit the number of bytes that may be allocated for POSIX message queues
    /// by the real user ID of the calling process.
    pub fn msgqueue(
        mut self,
        configure: impl FnOnce(Rlimit) -> Rlimit,
    ) -> Self {
        self.msgqueue = Some(configure(self.msgqueue.unwrap_or_default()));
        self
    }

    /// Unset a limit on the number of bytes that may be allocated for POSIX
    /// messague queues by the real user ID of the calling process, if one
    /// exists.
    pub fn clear_msgqueue(mut self) -> Self {
        self.msgqueue = None;
        self
    }

    /// Set the ceiling of the process' nice value.
    ///
    /// See the manpage `prlimit64(2)` for more information.
    pub fn nice(mut self, configure: impl FnOnce(Rlimit) -> Rlimit) -> Self {
        self.nice = Some(configure(self.nice.unwrap_or_default()));
        self
    }

    /// Unset the ceiling of the process' nice value, if one exists.
    pub fn clear_nice(mut self) -> Self {
        self.nice = None;
        self
    }

    /// Set an exclusive upper bound on file descriptor numbers for the process.
    pub fn nofile(mut self, configure: impl FnOnce(Rlimit) -> Rlimit) -> Self {
        self.nofile = Some(configure(self.nofile.unwrap_or_default()));
        self
    }

    /// Unset the exclusive upper bound on file descriptor numbers, if one
    /// exists.
    pub fn clear_nofile(mut self) -> Self {
        self.nofile = None;
        self
    }

    /// Limit the number of extant processes under the process' real user ID.
    pub fn nproc(mut self, configure: impl FnOnce(Rlimit) -> Rlimit) -> Self {
        self.nproc = Some(configure(self.nproc.unwrap_or_default()));
        self
    }

    /// Unset the limit on the number of extant processes under the process'
    /// real user ID, if one exists.
    pub fn clear_nproc(mut self) -> Self {
        self.nproc = None;
        self
    }

    /// Limit the real-time priority that may be set for this process.
    pub fn rtprio(mut self, configure: impl FnOnce(Rlimit) -> Rlimit) -> Self {
        self.rtprio = Some(configure(self.rtprio.unwrap_or_default()));
        self
    }

    /// Unset the limit on the real-time priority that may be set for this
    /// process, if one exists.
    pub fn clear_rtprio(mut self) -> Self {
        self.rtprio = None;
        self
    }

    /// Limit the amount of CPU time a process under real-time scheduling may
    /// consume without making a blocking syscall.
    pub fn rttime(mut self, configure: impl FnOnce(Rlimit) -> Rlimit) -> Self {
        self.rttime = Some(configure(self.rttime.unwrap_or_default()));
        self
    }

    /// Unset the limit on the amount of CPU time a process under real-time
    /// scheduling may consume without making a blocking syscall, if one exists.
    pub fn clear_rttime(mut self) -> Self {
        self.rttime = None;
        self
    }

    /// Limit the number of signals that may be queued for the real user ID of
    /// the calling process.
    pub fn sigpending(
        mut self,
        configure: impl FnOnce(Rlimit) -> Rlimit,
    ) -> Self {
        self.sigpending = Some(configure(self.sigpending.unwrap_or_default()));
        self
    }

    /// Unset the limit on the number of signals that may be queued for the real
    /// user ID of the calling process, if one exists.
    pub fn clear_sigpending(mut self) -> Self {
        self.sigpending = None;
        self
    }

    /// Limit the size of the process' stack, in bytes.
    pub fn stack(mut self, configure: impl FnOnce(Rlimit) -> Rlimit) -> Self {
        self.stack = Some(configure(self.stack.unwrap_or_default()));
        self
    }

    /// Unset the limit on the size of the process' stack, if one exists.
    pub fn clear_stack(mut self) -> Self {
        self.stack = None;
        self
    }
}

/// Resource limit.
///
/// These use the `u64` ABI implemented by `prlimit64(2)`. `None` implies
/// `RLIM_INFINITY`.
//FIXME: use niche optimization. move code to meowix
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Rlimit {
    /// Soft resource limit.
    soft: Option<u64>,

    /// Hard resource limit.
    hard: Option<u64>,
}

impl Default for Rlimit {
    fn default() -> Self {
        //NOTE: it is probably safer to set these as low as possible than to
        //      have the default be `RLIM_INFINITY`. not only would the latter
        //      likely cause `EPERM` (without `CAP_SYS_RESOURCE`), if it went
        //      through, it could allow the process to escape containment
        Self::new(0, 0)
    }
}

impl Rlimit {
    /// Construct a new resource limit.
    fn new(soft: u64, hard: u64) -> Self {
        Self {
            soft: Some(soft),
            hard: Some(hard),
        }
    }

    /// Construct a new resource limit with both hard and soft limits set at
    /// `RLIM_INFINITY`.
    fn infinity() -> Self {
        Self {
            soft: None,
            hard: None,
        }
    }

    /// Get the soft and hard resource limits as `u64` values.
    pub fn into_raw(self) -> (u64, u64) {
        //NOTE:`RLIM64_INFINITY` is equivalent to `u64::MAX`
        (self.soft.unwrap_or(u64::MAX), self.hard.unwrap_or(u64::MAX))
    }

    /// Set the soft resource limit to `RLIM_INFINITY`.
    pub fn soft_infinity(mut self) -> Self {
        self.soft = None;
        self
    }

    /// Update the soft resource limit.
    pub fn soft(mut self, limit: u64) -> Self {
        self.soft = Some(limit);
        self
    }

    /// Set the hard resource limit to `RLIM_INFINITY`.
    pub fn hard_infinity(mut self) -> Self {
        self.hard = None;
        self
    }

    /// Update the hard resource limit.
    pub fn hard(mut self, limit: u64) -> Self {
        self.hard = Some(limit);
        self
    }
}
