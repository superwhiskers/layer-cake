// SPDX-License-Identifier: AGPL-3.0-only

//! Keyring policy application.

use linux_raw_sys::keyctl;
use meowix::syscalls;

use super::{
    super::policy::keyring::{Keyring, KeyringInner},
    errors::PostSpawnGuest as PostSpawnGuestError,
};

/// Apply the keyring policy.
///
/// # Errors
///
/// This function errors if any `keyctl(2)` call fails.
pub fn apply_keyring_policy(
    policy: &Keyring,
) -> Result<(), PostSpawnGuestError> {
    match policy.inner {
        //NOTE: do nothing here
        KeyringInner::InheritAuthority => (),
        KeyringInner::Inherit => {
            let _ = syscalls::keyctl_assume_authority(0)?;
        }
        KeyringInner::Reset => {
            let _ = syscalls::keyctl_assume_authority(0)?;
            let _ = syscalls::keyctl_join_session_keyring(None)?;

            //NOTE: ensure requested keys go to the new session keyring
            let _ = syscalls::keyctl_set_reqkey_keyring(
                keyctl::KEY_REQKEY_DEFL_SESSION_KEYRING as _,
            )?;
        }
    }

    Ok(())
}
