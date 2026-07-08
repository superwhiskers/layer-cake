// SPDX-License-Identifier: AGPL-3.0-only

#![no_std]
#![feature(never_type)]
#![feature(c_size_t)]
#![feature(pattern_type_macro)]
#![feature(pattern_type_range_trait)]
#![feature(const_trait_impl)]
//NOTE: required for the niche optimization in `fd`
#![allow(internal_features)]
#![feature(pattern_types)]

//! Linux platform system calls and abstractions.
//!
//! These are guaranteed to be safe to use post-`clone3(2)` and to be
//! async-signal-safe.

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
