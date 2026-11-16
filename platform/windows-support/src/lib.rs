// SPDX-License-Identifier: CC0-1.0

//! Small Windows native operations behind safe Rust interfaces.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "allocation")]
pub mod allocation;

#[cfg(all(windows, feature = "credentials"))]
pub mod credentials;
