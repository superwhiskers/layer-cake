// SPDX-License-Identifier: AGPL-3.0-only

#![no_std]
#![feature(never_type)]
#![feature(c_size_t)]
#![feature(pattern_type_macro)]
#![feature(pattern_type_range_trait)]
#![feature(const_trait_impl)]
#![feature(maybe_uninit_array_assume_init)]
//NOTE: required for the niche optimization in `fd`
#![allow(internal_features)]
#![feature(pattern_types)]

//! Linux platform system calls and abstractions.
//!
//! Except where documented otherwise, APIs that are available without the
//! `alloc` feature perform no allocation and are designed to be usable after
//! `clone3(2)` and from asynchronous signal handlers.
//!
//! These guarantees continue to apply to those APIs even when `alloc` is
//! enabled. Enabling `alloc` only exposes additional APIs. Callers remain
//! responsible for ensuring their use of non-`alloc` APIs are valid for the
//! current process state.

#[cfg(not(target_os = "linux"))]
compile_error!("this crate only supports Linux");

#[cfg(feature = "alloc")]
extern crate alloc;

mod abi;
pub mod capabilities;
pub mod errno;
pub mod errors;
pub mod fd;
pub mod ids;
pub mod mode;
pub mod netlink;
pub mod sigaction;
mod syscall;
pub mod syscalls;
pub mod util;
