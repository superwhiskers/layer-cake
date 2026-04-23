// SPDX-License-Identifier: AGPL-3.0-only

//! Platform-specific sandboxing primitives.
//!
//! This module selects a platform-specific implementation of bubblebox's
//! sandboxing primitives and re-exports it at this crate.

cfg_select! {
    target_os = "linux" => {
        mod linux;
        pub use linux::*;
    }
    _ => {
        compile_error!("bubblebox is not supported on this platform!");
    }
}
