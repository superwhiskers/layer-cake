// SPDX-License-Identifier: AGPL-3.0-only

#![feature(never_type)]
#![feature(panic_always_abort)]
#![feature(trim_prefix_suffix)]
#![feature(const_cmp)]
#![feature(const_trait_impl)]
#![feature(const_default)]
#![feature(trusted_len)]

//! Painless cross-platform sandboxing.

pub mod command;
pub mod errors;
pub mod path;
pub mod platform;
