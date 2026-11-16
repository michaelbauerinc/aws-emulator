// SPDX-License-Identifier: CC0-1.0

//! Per-thread fault accounting, with process residency sampled by the host watch.

use std::sync::atomic::{AtomicU64, Ordering};

use super::{resident_bytes, Unavailable};

pub(crate) const UNAVAILABLE: &str = "Python Lambda execution is unavailable on this host: \
    memory accounting could not be read (supported on Linux, FreeBSD, OpenBSD, and Windows)";

pub(crate) const MEASURE_FINALIZATION: bool = false;

/// The environment's initial reading becomes its standing baseline after INIT.
pub(crate) struct Tracker {
    at_build: u64,
}

impl Tracker {
    pub(crate) fn new() -> Result<Self, Unavailable> {
        Ok(Self {
            at_build: faulted_bytes().ok_or(Unavailable)?,
        })
    }

    pub(crate) fn mark_built(&mut self) -> Result<(), Unavailable> {
        self.at_build = faulted_bytes().ok_or(Unavailable)?;
        Ok(())
    }

    pub(crate) fn grown_bytes(&self) -> Result<u64, Unavailable> {
        Ok(faulted_bytes()
            .ok_or(Unavailable)?
            .saturating_sub(self.at_build))
    }

    pub(crate) fn initial_run(&self) -> RunState {
        RunState::from_sample(self.at_build, Some(self.at_build))
    }

    pub(crate) fn existing_run(&self) -> RunState {
        RunState::from_sample(self.at_build, faulted_bytes())
    }

    pub(crate) fn enter(&self) -> Result<Scope, Unavailable> {
        Ok(Scope)
    }
}

#[derive(Debug)]
pub(crate) struct RunState {
    faulted_at_start: AtomicU64,
    resident_at_start: AtomicU64,
    unavailable_at_start: bool,
}

impl RunState {
    /// A missing reuse/teardown reading keeps the old baseline only so the common
    /// Bounds constructor can latch a stop and still permit bounded cleanup.
    pub(crate) fn from_sample(last_known: u64, sampled: Option<u64>) -> Self {
        Self {
            faulted_at_start: AtomicU64::new(sampled.unwrap_or(last_known)),
            resident_at_start: AtomicU64::new(0),
            unavailable_at_start: sampled.is_none(),
        }
    }

    /// Called at the original resident-baseline position in the Bounds constructor,
    /// after its deadline is read and before the bounds can be shared with the watch.
    pub(crate) fn capture_process_baseline(self) -> Self {
        self.resident_at_start
            .store(resident_bytes(), Ordering::Relaxed);
        self
    }

    pub(crate) fn unavailable_at_start(&self) -> bool {
        self.unavailable_at_start
    }

    pub(crate) fn rebase(&self) -> Result<(), Unavailable> {
        let faulted = faulted_bytes().ok_or(Unavailable)?;
        self.faulted_at_start.store(faulted, Ordering::Relaxed);
        self.resident_at_start
            .store(resident_bytes(), Ordering::Relaxed);
        Ok(())
    }

    pub(crate) fn past_run_limit(&self, limit: u64) -> bool {
        match faulted_bytes() {
            Some(faulted) => {
                faulted.saturating_sub(self.faulted_at_start.load(Ordering::Relaxed)) > limit
            }
            // Missing accounting stops the run rather than becoming a zero reading.
            None => true,
        }
    }

    pub(crate) fn past_run_limit_from_watch(&self, _limit: u64) -> bool {
        // RUSAGE_THREAD here would sample the watcher, not the interpreter thread.
        false
    }

    pub(crate) fn past_process_growth(&self, resident: u64, limit: u64) -> bool {
        resident.saturating_sub(self.resident_at_start.load(Ordering::Relaxed)) > limit
    }

    #[cfg(test)]
    pub(crate) fn faulted_at_start(&self) -> u64 {
        self.faulted_at_start.load(Ordering::Relaxed)
    }
}

pub(crate) struct Scope;

pub(crate) fn suppress_host() -> Result<Scope, Unavailable> {
    Ok(Scope)
}

pub(crate) fn prewarm_shared(_initialize: impl FnOnce()) -> Result<(), Unavailable> {
    // Unix does not prewarm the context or module definitions here.
    Ok(())
}

/// The size used to scale this thread's cumulative fault count.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
const PAGE_BYTES: u64 = 4_096;

/// A missing reading cannot enforce the run's memory bound.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
fn faulted_bytes() -> Option<u64> {
    let usage =
        ::nix::sys::resource::getrusage(::nix::sys::resource::UsageWho::RUSAGE_THREAD).ok()?;
    let pages = usage
        .minor_page_faults()
        .saturating_add(usage.major_page_faults());
    Some(u64::try_from(pages).ok()?.saturating_mul(PAGE_BYTES))
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd")))]
fn faulted_bytes() -> Option<u64> {
    None
}
