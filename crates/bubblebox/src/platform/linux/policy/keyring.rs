// SPDX-License-Identifier: AGPL-3.0-only

//! Keyring policy implementation.

/// Keyring policy.
///
/// Configures the action to take regarding the [kernel key retention service]
/// state inherited by the guest.
///
/// [kernel key retention service]: https://docs.kernel.org/security/keys/core.html
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Keyring {
    /// Action to take regarding the keyring.
    pub(in super::super) inner: KeyringInner,
}

impl Keyring {
    /// Inherit the session keyring of the caller, retaining `request_key(2)`
    /// authority.
    ///
    /// # Warning
    ///
    /// This causes the sandbox to retain `request_key(2)` authority if it is
    /// present. If you don't know what this is, you probably don't need it.
    /// Prefer [`Keyring::inherit`] or [`Keyring::reset`] wherever possible.
    pub fn inherit_authority(mut self) -> Self {
        self.inner = KeyringInner::InheritAuthority;
        self
    }

    /// Inherit the session keyring of the caller, discarding `request_key(2)`
    /// authority.
    ///
    /// # Warning
    ///
    /// This is usually not necessary. Prefer [`Keyring::reset`] wherever
    /// possible.
    pub fn inherit(mut self) -> Self {
        self.inner = KeyringInner::Inherit;
        self
    }

    /// Establish a new session keyring and discard any inherited
    /// `request_key(2)` authority.
    ///
    /// This is the default.
    ///
    /// # Warning
    ///
    /// This does not isolate it from the kernel key database. The guest may
    /// still access keys or keyrings for which its credentials independently
    /// grant access.
    ///
    /// Keys are a fixed resource. Allowing unrestricted key creation will
    /// consume a quota shared with other processes sharing the same filesystem
    /// UID. This may result in a denial of service. Depending upon the use
    /// case, denying the keyring syscalls (`add_key(2)`, `request_key(2)`, and
    /// `keyctl(2)`) may be desirable as a defense-in-depth measure.
    pub fn reset(mut self) -> Self {
        self.inner = KeyringInner::Reset;
        self
    }
}

/// Inner structure used to indicate the action.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub(in super::super) enum KeyringInner {
    /// Inherit the session keyring of the caller, retaining their authority.
    InheritAuthority,

    /// Inherit the session keyring of the caller.
    Inherit,

    /// Establish a new session keyring.
    #[default]
    Reset,
}
