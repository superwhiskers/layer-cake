// SPDX-License-Identifier: AGPL-3.0-only

#![feature(panic_always_abort)]
#![feature(const_cmp)]
#![feature(const_trait_impl)]
#![feature(const_default)]
#![feature(trusted_len)]
#![feature(const_range)]
#![cfg_attr(feature = "systemd-cgroups", feature(trim_prefix_suffix))]

//! Painless cross-platform sandboxing.

pub mod command;
pub mod errors;
pub mod paths;
pub mod platform;
