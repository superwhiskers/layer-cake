// SPDX-License-Identifier: AGPL-3.0-only

#![feature(panic_always_abort)]
#![feature(const_cmp)]
#![feature(const_trait_impl)]
#![feature(const_default)]
#![feature(trusted_len)]
#![feature(const_range)]
#![feature(try_blocks)]
#![feature(likely_unlikely)]
#![feature(vec_push_within_capacity)]

//! Painless cross-platform sandboxing.

pub mod command;
pub mod errors;
pub mod paths;
pub mod platform;

pub(crate) mod sealed {
    //! Module containing the trait used to prevent external implementations of
    //! some public traits.

    /// Trait used to prevent external implementations of some public traits.
    pub trait Sealed {}
}
