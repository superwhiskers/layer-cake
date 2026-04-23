// SPDX-License-Identifier: AGPL-3.0-only

#![feature(never_type)]
#![feature(int_from_ascii)]
#![feature(panic_always_abort)]
#![feature(trim_prefix_suffix)]
#![feature(const_cmp)]
#![feature(const_trait_impl)]
#![feature(raw_os_error_ty)]
#![feature(const_default)]
#![feature(derive_const)]

//! Painless cross-platform sandboxing.

pub mod command;
pub mod errors;
pub mod path;
pub mod platform;
