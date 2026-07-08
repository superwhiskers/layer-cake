// SPDX-License-Identifier: AGPL-3.0-only

//! Per-namespace policy structures.

use meowix::ids::{Gid, Uid};

//TODO: add back arbitrary id mappings by having the parent call
//      newuidmap/newgidmap
//TODO: use systemd-nsresourced to perform larger id mappings on request.
//      this ensures systemd-homed systems continue to work as they lack the
//      subuid/subgid delegations

/// Maximum attainable seconds component of a kernel time value.
///
/// Defined at [`include/linux/time64.h`], not exposed in a public header, so we
/// must define it ourselves as it is exposed via `/proc/self/timens_offsets`.
///
/// [`include/linux/time64.h`]: https://github.com/torvalds/linux/blob/master/include/linux/time64.h#L32
pub const KTIME_SEC_MAX: i64 = i64::MAX / 1_000_000_000;

/// Namespace policy.
///
/// Configures optional namespaces and mandatory namespace setup. Neither
/// mount nor user namespaces may be shared with the caller.
///
/// # Notes
///
/// - Mount namespaces are always used to create a synthetic filesystem view.
/// - User namespaces are always used to gain local namespace creation
///   privileges, regardless of the process' uid.
/// - cgroup namespaces are always used because they don't do much other than
///   change the view of cgroups that the sandbox gets.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Namespaces<'a> {
    pub(in super::super) ipc: Namespace<IpcOptions>,
    pub(in super::super) pid: Namespace<PidOptions>,
    pub(in super::super) network: Namespace<NetworkOptions>,
    pub(in super::super) uts: Namespace<UtsOptions<'a>>,
    pub(in super::super) time: Namespace<TimeOptions>,
    pub(in super::super) user: UserOptions,
}

impl<'a> Namespaces<'a> {
    /// Share the IPC namespace.
    pub fn share_ipc(mut self) -> Self {
        self.ipc = Namespace::Shared;
        self
    }

    /// Unshare the IPC namespace.
    ///
    /// There is nothing to configure for these, so no options are provided.
    pub fn unshare_ipc(mut self) -> Self {
        self.ipc = Namespace::Unshared(IpcOptions);
        self
    }

    /// Share the pid namespace.
    pub fn share_pid(mut self) -> Self {
        self.pid = Namespace::Shared;
        self
    }

    /// Unshare the pid namespace.
    ///
    /// There is nothing to configure for these, so no options are provided.
    pub fn unshare_pid(mut self) -> Self {
        self.pid = Namespace::Unshared(PidOptions);
        self
    }

    /// Share the network namespace.
    pub fn share_network(mut self) -> Self {
        self.network = Namespace::Shared;
        self
    }

    /// Unshare the network namespace and only set up the loopback devices.
    pub fn unshare_network_and_isolate(mut self) -> Self {
        self.network = Namespace::Unshared(NetworkOptions::Isolate);
        self
    }

    /// Share the UTS namespace.
    pub fn share_uts(mut self) -> Self {
        self.uts = Namespace::Shared;
        self
    }

    /// Unshare the UTS namespace.
    ///
    /// If the namespace was already unshared, modify its configuration.
    pub fn unshare_uts(
        mut self,
        configure: impl FnOnce(UtsOptions<'a>) -> UtsOptions<'a>,
    ) -> Self {
        self.uts = Namespace::Unshared(configure(self.uts.unwrap_or_default()));
        self
    }

    /// Share the time namespace.
    pub fn share_time(mut self) -> Self {
        self.time = Namespace::Shared;
        self
    }

    /// Unshare the time namespace.
    ///
    /// If the namespace was already unshared, modify its configuration.
    pub fn unshare_time(
        mut self,
        configure: impl FnOnce(TimeOptions) -> TimeOptions,
    ) -> Self {
        self.time =
            Namespace::Unshared(configure(self.time.unwrap_or_default()));
        self
    }

    /// Configure the user namespace.
    ///
    /// This namespace is always unshared.
    pub fn user_namespace(
        mut self,
        configure: impl FnOnce(UserOptions) -> UserOptions,
    ) -> Self {
        self.user = configure(self.user);
        self
    }
}

/// Enumeration over states a namespace may be left in.
///
/// Used to indicate a namespace's usage is user-controllable. For namespaces
/// which are always unshared, such as the mount namespace and user namespace,
/// this type is not used.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Namespace<Options> {
    /// Inherit the parent process' namespace.
    Shared,

    /// Create a new namespace with the specified options.
    Unshared(Options),
    //TODO: add a file descriptor option so that an existing namespace can
    //      be used
}

impl<Options> Namespace<Options>
where
    Options: PartialEq,
{
    /// Indicates if the namespace represented by this [`Namespace`] is shared
    /// or not.
    pub fn is_shared(&self) -> bool {
        *self == Self::Shared
    }
}

impl<Options> Namespace<Options>
where
    Options: Default,
{
    /// Returns the contained [`Unshared`](Self::Unshared) value or a default.
    pub fn unwrap_or_default(self) -> Options {
        if let Self::Unshared(options) = self {
            options
        } else {
            Options::default()
        }
    }
}

impl<Options> Default for Namespace<Options>
where
    Options: Default,
{
    fn default() -> Self {
        Self::Unshared(Options::default())
    }
}

/// IPC namespace policy.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct IpcOptions;

/// Pid namespace policy.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct PidOptions;

/// Network namespace policy.
#[expect(
    missing_copy_implementations,
    reason = "later variants might not work with copy"
)]
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub enum NetworkOptions {
    /// Leave the created network namespace isolated.
    #[default]
    Isolate,
    //TODO: add option to establish veth from parent namespace to the
    //      created network namespace, probably with name options. this needs
    //      `CAP_NET_ADMIN` to work
}

/// UTS namespace policy.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct UtsOptions<'a> {
    /// Hostname to set with `sethostname(2)`.
    ///
    /// # Notes
    ///
    /// The kernel appears to see this as a set of arbitrary bytes. Userland
    /// applications may have expectations of this field. At a minimum, treat
    /// this field as if it were only containing alphanumerical characters as
    /// well as not starting with a period or a hyphen.
    pub(in super::super) hostname: Option<&'a [u8]>,

    /// Domain name to set with `setdomainname(2)`.
    ///
    /// On most modern Linux systems, this field is unset.
    ///
    /// # Notes
    ///
    /// The kernel appears to see this as a set of arbitrary bytes. Userland
    /// applications may have expectations of this field. At a minimum, treat
    /// this field as if it were only containing alphanumerical characters as
    /// well as not starting with a hyphen.
    pub(in super::super) domain: Option<&'a [u8]>,
}

impl<'a> UtsOptions<'a> {
    /// Set the hostname in the namespace.
    ///
    /// # Notes
    ///
    /// The kernel appears to see this as a set of arbitrary bytes. Userland
    /// applications may have expectations of this field. At a minimum, treat
    /// this field as if it were only containing alphanumerical characters as
    /// well as not starting with a period or a hyphen.
    pub fn set_hostname(mut self, hostname: &'a [u8]) -> Self {
        self.hostname = Some(hostname);
        self
    }

    /// Clear the hostname, if one was set.
    ///
    /// This means the UTS namespace will take on the hostname of the host
    /// process.
    pub fn clear_hostname(mut self) -> Self {
        self.hostname = None;
        self
    }

    /// Set the domain name in the namespace.
    ///
    /// On most modern Linux systems, this field is unset.
    ///
    /// # Notes
    ///
    /// The kernel appears to see this as a set of arbitrary bytes. Userland
    /// applications may have expectations of this field. At a minimum, treat
    /// this field as if it were only containing alphanumerical characters as
    /// well as not starting with a hyphen.
    pub fn set_domain(mut self, domain: &'a [u8]) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Clear the domain name, if one was set.
    ///
    /// This means the UTS namespace will take on the domain name of the host
    /// process.
    pub fn clear_domain(mut self) -> Self {
        self.domain = None;
        self
    }
}

/// Time namespace policy.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct TimeOptions {
    /// Offset for the initial time namespace's `CLOCK_MONOTONIC`.
    pub(in super::super) monotonic_offset: Option<TimeOffset>,

    /// Offset for the initial time namespace's `CLOCK_BOOTTIME`.
    pub(in super::super) boottime_offset: Option<TimeOffset>,
}

impl TimeOptions {
    /// Set the offset from the initial time namespace's `CLOCK_MONOTONIC`.
    pub fn monotonic_offset(
        mut self,
        configure: impl FnOnce(TimeOffset) -> TimeOffset,
    ) -> Self {
        self.monotonic_offset =
            Some(configure(self.monotonic_offset.unwrap_or_default()));
        self
    }

    /// Clear the `CLOCK_MONOTONIC` offset if one was set.
    pub fn clear_monotonic_offset(mut self) -> Self {
        self.monotonic_offset = None;
        self
    }

    /// Set the offset from the initial time namespace's `CLOCK_BOOTTIME`.
    pub fn boottime_offset(
        mut self,
        configure: impl FnOnce(TimeOffset) -> TimeOffset,
    ) -> Self {
        self.boottime_offset =
            Some(configure(self.boottime_offset.unwrap_or_default()));
        self
    }

    /// Clear the `CLOCK_BOOTTIME` offset if one was set.
    pub fn clear_boottime_offset(mut self) -> Self {
        self.boottime_offset = None;
        self
    }
}

/// Time offset.
///
/// Used for time namespace configuration.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct TimeOffset {
    /// Offset from the initial time namespace in seconds.
    ///
    /// Must not make the clock acquire a negative value.
    pub(in super::super) seconds: TimeOffsetSeconds,

    /// Offset from the initial time namespace in nanoseconds.
    pub(in super::super) nanoseconds: TimeOffsetNanoseconds,
}

impl TimeOffset {
    /// Set the seconds component of the offset.
    pub const fn set_seconds(mut self, seconds: TimeOffsetSeconds) -> Self {
        self.seconds = seconds;
        self
    }

    /// Set the nanoseconds component of the offset.
    pub const fn set_nanoseconds(
        mut self,
        nanoseconds: TimeOffsetNanoseconds,
    ) -> Self {
        self.nanoseconds = nanoseconds;
        self
    }
}

/// Seconds component of a kernel time offset.
///
/// This value is guaranteed to not have a magnitude exceeding `KTIME_SEC_MAX`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct TimeOffsetSeconds(i64);

impl TimeOffsetSeconds {
    /// Construct a new second component of a time offset.
    ///
    /// This must not have a magnitude exceeding `KTIME_SEC_MAX`.
    pub const fn new(value: i64) -> Option<Self> {
        //NOTE: this is fine because the minimum value is still out of range
        if value.wrapping_abs() <= KTIME_SEC_MAX {
            //SAFETY: we just checked that it was within the bounds
            Some(unsafe { Self::new_unchecked(value) })
        } else {
            None
        }
    }

    /// Construct a new second component of a time offset without performing a
    /// bounds check.
    ///
    /// # Safety
    ///
    /// This value must not exceed `KTIME_SEC_MAX`.
    pub const unsafe fn new_unchecked(value: i64) -> Self {
        Self(value)
    }

    /// Get the contained time offset value.
    pub const fn into_raw(self) -> i64 {
        self.0
    }
}

/// Nanoseconds component of a kernel time offset.
///
/// This value is guaranteed to not exceed 999,999,999.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct TimeOffsetNanoseconds(u32);

impl TimeOffsetNanoseconds {
    /// Construct a new nanosecond component of a time offset.
    ///
    /// This value must not exceed 999,999,999.
    pub const fn new(value: u32) -> Option<Self> {
        //NOTE: right hand value is the number of nanoseconds in a second
        if value < 1_000_000_000 {
            //SAFETY: we just performed the check
            Some(unsafe { Self::new_unchecked(value) })
        } else {
            None
        }
    }

    /// Construct a new nanosecond component of a time offset without performing
    /// a bounds check.
    ///
    /// # Safety
    ///
    /// This value must not exceed 999,999,999.
    pub const unsafe fn new_unchecked(value: u32) -> Self {
        Self(value)
    }

    /// Get the contained time offset value.
    pub const fn into_raw(self) -> u32 {
        self.0
    }
}

/// User namespace policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserOptions {
    /// Mapping mode to apply to the user namespace.
    pub(in super::super) mapping_mode: UserMappingMode,

    /// Whether to allow the creation of new user namespaces within the
    /// sandbox.
    pub(in super::super) disable_userns: bool,
}

impl Default for UserOptions {
    fn default() -> Self {
        Self {
            mapping_mode: UserMappingMode::default(),
            disable_userns: true,
        }
    }
}

impl UserOptions {
    /// Use a normal unprivileged user namespace mapping.
    ///
    /// This will map the effective uid and effective gid of the host process to
    /// the given values. No other ids are mapped into the namespace. If an id
    /// is not set, the identity mapping is performed for that id. See
    /// [`user_namespaces(7)`] for more details.
    ///
    /// [`user_namespaces(7)`]: https://www.man7.org/linux/man-pages/man7/user_namespaces.7.html#:~:text=The%20data,namespace%2E
    pub fn simple_mapping(
        mut self,
        uid: Option<Uid>,
        gid: Option<Gid>,
    ) -> Self {
        self.mapping_mode = UserMappingMode::Simple { uid, gid };
        self
    }

    /// Use a normal unprivileged user namespace mapping.
    ///
    /// This will perform the identity mapping for both the host process'
    /// effective uid and effective gid. No other ids are mapped into the
    /// namespace. See [`user_namespaces(7)`] for more details.
    ///
    /// [`user_namespaces(7)`]: https://www.man7.org/linux/man-pages/man7/user_namespaces.7.html#:~:text=The%20data,namespace%2E
    pub fn simple_mapping_identity(self) -> Self {
        self.simple_mapping(None, None)
    }

    /// Whether to disable the creation of new user namespaces within the
    /// sandbox.
    pub fn disable_userns(mut self, disable_userns: bool) -> Self {
        self.disable_userns = disable_userns;
        self
    }
}

/// User namespace policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in super::super) enum UserMappingMode {
    /// Only map the uid and gid of the parent thread.
    ///
    /// Does not attempt to map any other uid/gids. Works without
    /// newuidmap/newgidmap or systemd-nsresourced.
    Simple {
        /// User ID to map the uid of the parent thread to.
        ///
        /// If unspecified, the identity mapping is performed.
        uid: Option<Uid>,

        /// Group ID to map the gid of the parent thread to.
        ///
        /// If unspecified, the identity mapping is performed.
        gid: Option<Gid>,
    },
}

impl Default for UserMappingMode {
    fn default() -> Self {
        Self::Simple {
            uid: None,
            gid: None,
        }
    }
}
