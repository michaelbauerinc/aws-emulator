// SPDX-License-Identifier: CC0-1.0

//! Host memory observations for one prepared interpreter and its bounded runs.
//!
//! The interpreter lifecycle and stop latch stay in `python`; each backend owns only
//! its measurements and scope guards. Unix scopes are no-ops, including shared-state
//! prewarming, so selecting a backend does not change when that host creates a VM.

#[cfg_attr(windows, path = "memory/windows.rs")]
#[cfg_attr(not(windows), path = "memory/unix.rs")]
mod backend;

pub(super) use backend::{
    prewarm_shared, suppress_host, RunState, Scope, Tracker, MEASURE_FINALIZATION, UNAVAILABLE,
};

#[derive(Debug)]
pub(crate) struct Unavailable;

/// How many bytes this PROCESS holds resident, as the host reports it.
pub(super) fn resident_bytes() -> u64 {
    match ::memory_stats::memory_stats() {
        Some(stats) => u64::try_from(stats.physical_mem).unwrap_or(0),
        None => 0,
    }
}
