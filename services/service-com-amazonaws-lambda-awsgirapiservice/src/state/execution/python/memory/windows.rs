// SPDX-License-Identifier: CC0-1.0

//! Owned live backing allocations and stable per-run peak measurements.

use std::sync::{Mutex, PoisonError};

use ::aws_emulator_windows_support::allocation::{
    allocation_observer_installed, AllocationOwner, AllocationPhase, AllocationScope,
};

use super::Unavailable;

pub(crate) const UNAVAILABLE: &str = "Python Lambda execution is unavailable: the Windows \
    allocation observer is not installed or could not verify its accounting";

pub(crate) const MEASURE_FINALIZATION: bool = true;

/// Allocation identity survives every invocation and its retained allocations.
pub(crate) struct Tracker {
    owner: AllocationOwner,
    at_build: u64,
}

impl Tracker {
    pub(crate) fn new() -> Result<Self, Unavailable> {
        if !allocation_observer_installed() {
            return Err(Unavailable);
        }
        Ok(Self {
            owner: AllocationOwner::new(),
            at_build: 0,
        })
    }

    pub(crate) fn mark_built(&mut self) -> Result<(), Unavailable> {
        self.at_build = owned_live_bytes(&self.owner)?;
        Ok(())
    }

    pub(crate) fn grown_bytes(&self) -> Result<u64, Unavailable> {
        Ok(owned_live_bytes(&self.owner)?.saturating_sub(self.at_build))
    }

    pub(crate) fn initial_run(&self) -> RunState {
        RunState::new(self.owner.clone())
    }

    pub(crate) fn existing_run(&self) -> RunState {
        RunState::new(self.owner.clone())
    }

    pub(crate) fn enter(&self) -> Result<Scope, Unavailable> {
        established(self.owner.enter())
    }
}

#[derive(Debug)]
pub(crate) struct RunState {
    owner: AllocationOwner,
    // An old invocation's watch must never start observing a newer phase's peak.
    phase: Mutex<AllocationPhase>,
}

impl RunState {
    pub(crate) fn new(owner: AllocationOwner) -> Self {
        let phase = Mutex::new(owner.begin_phase());
        Self { owner, phase }
    }

    pub(crate) fn capture_process_baseline(self) -> Self {
        // Process residency cannot attribute allocations to a Windows environment.
        self
    }

    pub(crate) fn unavailable_at_start(&self) -> bool {
        // Scope entry and rebase validate accounting at their existing lifecycle points.
        false
    }

    pub(crate) fn rebase(&self) -> Result<(), Unavailable> {
        let phase = self.owner.begin_phase();
        if phase.snapshot().overflowed {
            return Err(Unavailable);
        }
        *self.phase.lock().unwrap_or_else(PoisonError::into_inner) = phase;
        Ok(())
    }

    pub(crate) fn past_run_limit(&self, limit: u64) -> bool {
        let phase = self.phase.lock().unwrap_or_else(PoisonError::into_inner);
        let snapshot = phase.snapshot();
        snapshot.overflowed
            || u64::try_from(snapshot.peak_growth_bytes()).map_or(true, |growth| growth > limit)
    }

    pub(crate) fn past_run_limit_from_watch(&self, limit: u64) -> bool {
        self.past_run_limit(limit)
    }

    pub(crate) fn past_process_growth(&self, _resident: u64, limit: u64) -> bool {
        // A process-wide change cannot identify its responsible invocation. The
        // owned phase must itself be over budget, including within a native call.
        self.past_run_limit(limit)
    }

    #[cfg(test)]
    pub(crate) fn peak_growth_bytes(&self) -> usize {
        self.phase.lock().unwrap().snapshot().peak_growth_bytes()
    }
}

pub(crate) type Scope = AllocationScope;

fn established(scope: Scope) -> Result<Scope, Unavailable> {
    if scope.is_established() {
        Ok(scope)
    } else {
        Err(Unavailable)
    }
}

pub(crate) fn suppress_host() -> Result<Scope, Unavailable> {
    established(AllocationScope::suppress())
}

pub(crate) fn prewarm_shared(initialize: impl FnOnce()) -> Result<(), Unavailable> {
    // This threading-disabled RustPython build leaks thread-local static contexts
    // and definitions. They belong to the host, outside an environment's ownership.
    let _untracked = suppress_host()?;
    initialize();
    Ok(())
}

/// Includes allocation metadata and padding. Overflow invalidates the reading.
fn owned_live_bytes(owner: &AllocationOwner) -> Result<u64, Unavailable> {
    let snapshot = owner.snapshot();
    if snapshot.overflowed {
        Err(Unavailable)
    } else {
        u64::try_from(snapshot.live_bytes).map_err(|_| Unavailable)
    }
}
