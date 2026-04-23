// SPDX-License-Identifier: AGPL-3.0-only

//! Tools for normalizing the Linux sandbox environment.
//!
//! These are not intended to provide privacy directly, they are more for
//! reproducibility's sake. However, they may provide some amount of privacy
//! through reducing the amount of information inherited from the host.

/// The `hostname(5)` to present to the sandbox by default.
pub const HOSTNAME: &str = "host";

/// The default username to present to the sandbox by default.
pub const USERNAME: &str = "user";
