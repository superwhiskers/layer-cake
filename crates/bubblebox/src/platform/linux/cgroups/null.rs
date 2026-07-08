// SPDX-License-Identifier: AGPL-3.0-only

use super::{Backend, Cgroups};

/// Null backend that doesn't initialize cgroups at all.
#[derive(Clone, Debug, Default)]
pub struct NullCgroups;

impl Cgroups<NullCgroups> {
    /// Don't create a cgroups hierarchy.
    pub fn null_unenforced() -> Self {
        Self::default()
    }
}

//SAFETY: we don't implement any of the hooks at all
unsafe impl Backend for NullCgroups {
    type State = ();
}
