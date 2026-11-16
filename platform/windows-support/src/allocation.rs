// SPDX-License-Identifier: CC0-1.0

//! Scoped ownership of Rust allocations, measured in requested backing bytes.
//!
//! Install `ObservedAllocator` in the executable, then verify it with
//! `allocation_observer_installed` before relying on these counters. This module
//! never installs a global allocator or rejects an allocation to enforce a budget.
//! It observes Rust allocations, not foreign heaps or operating-system mappings.
//!
//! Charges include the requested payload and our prefix/alignment padding, but not
//! an underlying allocator's undisclosed rounding. Owned reallocations and
//! cross-thread frees retain the original owner. Successful reallocations of
//! unowned storage adopt the active owner, including the entire resized backing.
//! A phase records peak live growth, not allocation traffic; beginning another
//! phase freezes the previous phase's byte counters.
//! Accounting failures remain visible through every phase handle for that owner.
//! Deallocation ends ownership before calling the underlying allocator, so a
//! delayed deallocator cannot overlap an already-released block with its replacement.

use std::alloc::{GlobalAlloc, Layout};
use std::cell::{Cell, RefCell, UnsafeCell};
use std::ptr::null_mut;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Requested backing bytes, including observer metadata and alignment padding.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationSnapshot {
    pub live_bytes: usize,
    pub peak_bytes: usize,
    pub baseline_bytes: usize,
    /// Sticky: consumers must fail closed rather than trust saturated counters.
    pub overflowed: bool,
}

impl AllocationSnapshot {
    pub fn peak_growth_bytes(self) -> usize {
        self.peak_bytes.saturating_sub(self.baseline_bytes)
    }
}

// The critical sections below contain only counter arithmetic, Arc reference
// operations, and nested phase-counter updates. They never call an allocator or
// user callback. A spin lock avoids heap/TLS initialization inside an OS mutex.
struct CounterLock<T> {
    held: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: access to value is exclusively mediated by the acquire/release lock.
unsafe impl<T: Send> Sync for CounterLock<T> {}

struct CounterGuard<'a>(&'a AtomicBool);

impl Drop for CounterGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl<T> CounterLock<T> {
    fn new(value: T) -> Self {
        Self {
            held: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    fn with<R>(&self, operation: impl FnOnce(&mut T) -> R) -> R {
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::hint::spin_loop();
        }
        let _guard = CounterGuard(&self.held);
        // SAFETY: this thread owns the lock until _guard drops.
        operation(unsafe { &mut *self.value.get() })
    }
}

struct OwnerCounters {
    snapshot: AllocationSnapshot,
    phase: Option<Arc<CounterLock<AllocationSnapshot>>>,
}

struct OwnerState {
    counters: CounterLock<OwnerCounters>,
    // Phases retain this flag, never the owner itself: no Owner -> Phase -> Owner
    // cycle, while a frozen phase still fails closed on later accounting failure.
    failure: Arc<AtomicBool>,
}

impl OwnerState {
    fn resize(&self, previous: usize, next: usize) {
        self.counters.with(|counters| {
            let snapshot = &mut counters.snapshot;
            let live = if next >= previous {
                snapshot.live_bytes.checked_add(next - previous)
            } else {
                snapshot.live_bytes.checked_sub(previous - next)
            };
            snapshot.live_bytes = match live {
                Some(value) => value,
                None => {
                    snapshot.overflowed = true;
                    self.failure.store(true, Ordering::Release);
                    if next >= previous {
                        usize::MAX
                    } else {
                        0
                    }
                }
            };
            snapshot.peak_bytes = snapshot.peak_bytes.max(snapshot.live_bytes);
            if let Some(phase) = &counters.phase {
                phase.with(|phase| {
                    phase.live_bytes = snapshot.live_bytes;
                    phase.peak_bytes = phase.peak_bytes.max(snapshot.live_bytes);
                    phase.overflowed |= snapshot.overflowed;
                });
            }
        });
    }
}

/// An owner survives its interpreter while any of its allocations remain live.
#[derive(Clone)]
pub struct AllocationOwner(Arc<OwnerState>);

impl std::fmt::Debug for AllocationOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("AllocationOwner")
            .field(&self.snapshot())
            .finish()
    }
}

impl Default for AllocationOwner {
    fn default() -> Self {
        Self::new()
    }
}

impl AllocationOwner {
    pub fn new() -> Self {
        let _untracked = AllocationScope::suppress();
        Self(Arc::new(OwnerState {
            counters: CounterLock::new(OwnerCounters {
                snapshot: AllocationSnapshot::default(),
                phase: None,
            }),
            failure: Arc::new(AtomicBool::new(false)),
        }))
    }

    pub fn enter(&self) -> AllocationScope {
        AllocationScope::push(Some(self.0.clone()))
    }

    /// All-time owner counters; the baseline is zero.
    pub fn snapshot(&self) -> AllocationSnapshot {
        let mut snapshot = self.0.counters.with(|counters| counters.snapshot);
        snapshot.overflowed |= self.0.failure.load(Ordering::Acquire);
        snapshot
    }

    /// Start a new measurement from current live bytes, freezing any older phase.
    ///
    /// Phase bookkeeping is unowned. Old handles retain their final byte counters;
    /// they never silently observe the new phase. Their accounting-failure flag
    /// still becomes true if any later allocation corrupts this owner's counters.
    pub fn begin_phase(&self) -> AllocationPhase {
        let _untracked = AllocationScope::suppress();
        let phase = Arc::new(CounterLock::new(AllocationSnapshot::default()));
        let previous = self.0.counters.with(|counters| {
            let live = counters.snapshot.live_bytes;
            phase.with(|snapshot| {
                *snapshot = AllocationSnapshot {
                    live_bytes: live,
                    peak_bytes: live,
                    baseline_bytes: live,
                    overflowed: counters.snapshot.overflowed,
                };
            });
            counters.phase.replace(phase.clone())
        });
        // Drop bookkeeping outside the owner counter lock.
        drop(previous);
        AllocationPhase {
            counters: phase,
            failure: self.0.failure.clone(),
        }
    }
}

/// Stable phase byte counters, even after its owner starts a different phase.
#[derive(Clone)]
pub struct AllocationPhase {
    counters: Arc<CounterLock<AllocationSnapshot>>,
    failure: Arc<AtomicBool>,
}

impl std::fmt::Debug for AllocationPhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("AllocationPhase")
            .field(&self.snapshot())
            .finish()
    }
}

impl AllocationPhase {
    pub fn snapshot(&self) -> AllocationSnapshot {
        let mut snapshot = self.counters.with(|snapshot| *snapshot);
        snapshot.overflowed |= self.failure.load(Ordering::Acquire);
        snapshot
    }
}

struct ScopeEntry {
    owner: Option<Arc<OwnerState>>,
    active: Cell<bool>,
}

thread_local! {
    static SCOPES: RefCell<Vec<Rc<ScopeEntry>>> = const { RefCell::new(Vec::new()) };
}

/// A thread-bound allocation scope. Nested suppression temporarily masks an owner.
///
/// Guards can be dropped out of order without restoring stale owner pointers.
pub struct AllocationScope {
    entry: Option<Rc<ScopeEntry>>,
}

impl AllocationScope {
    pub fn suppress() -> Self {
        Self::push(None)
    }

    /// Whether this thread's scope was installed. Unavailable or reentrantly
    /// borrowed TLS can prevent installation. A failed owner scope also latches
    /// the owner's accounting-failure flag; suppression callers must check this
    /// status before performing work that must remain unowned.
    pub fn is_established(&self) -> bool {
        self.entry.is_some()
    }

    fn push(owner: Option<Arc<OwnerState>>) -> Self {
        let failure = owner.as_ref().map(|owner| owner.failure.clone());
        let entry = SCOPES
            .try_with(|scopes| {
                let Ok(mut scopes) = scopes.try_borrow_mut() else {
                    return None;
                };
                scopes.retain(|entry| entry.active.get());
                // The mutable TLS borrow makes observer callbacks untracked while
                // the node and vector storage are allocated.
                let entry = Rc::new(ScopeEntry {
                    owner,
                    active: Cell::new(true),
                });
                scopes.push(entry.clone());
                Some(entry)
            })
            .ok()
            .flatten();
        if entry.is_none() {
            if let Some(failure) = failure {
                failure.store(true, Ordering::Release);
            }
        }
        Self { entry }
    }
}

impl Drop for AllocationScope {
    fn drop(&mut self) {
        let Some(entry) = self.entry.take() else {
            return;
        };
        // Mark inactive even if a reentrant callback holds the TLS borrow. Such an
        // entry is ignored immediately and reclaimed on the next scope operation.
        entry.active.set(false);
        let _ = SCOPES.try_with(|scopes| {
            if let Ok(mut scopes) = scopes.try_borrow_mut() {
                if let Some(index) = scopes.iter().position(|item| Rc::ptr_eq(item, &entry)) {
                    scopes.remove(index);
                }
            }
        });
    }
}

fn active_owner() -> *const OwnerState {
    SCOPES
        .try_with(|scopes| {
            let Ok(scopes) = scopes.try_borrow() else {
                return std::ptr::null();
            };
            scopes
                .iter()
                .rev()
                .find(|entry| entry.active.get())
                .and_then(|entry| entry.owner.as_ref())
                .map_or(std::ptr::null(), |owner| Arc::into_raw(owner.clone()))
        })
        .unwrap_or(std::ptr::null())
}

#[repr(C)]
struct Header {
    owner: *const OwnerState,
}

fn backing_layout(layout: Layout) -> Option<(Layout, usize)> {
    Layout::new::<Header>()
        .extend(layout)
        .ok()
        .map(|(layout, offset)| (layout.pad_to_align(), offset))
}

/// A transparent payload allocator with an ownership prefix.
///
/// The executable must explicitly install this with `#[global_allocator]`.
pub struct ObservedAllocator<A> {
    inner: A,
}

impl<A> ObservedAllocator<A> {
    pub const fn new(inner: A) -> Self {
        Self { inner }
    }
}

// SAFETY: every successful allocation is aligned using Layout::extend; deallocation
// and reallocation recover the exact backing layout and base pointer. Metadata is
// initialized before publication. Owner references outlive every recorded block.
unsafe impl<A: GlobalAlloc> GlobalAlloc for ObservedAllocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some((backing, offset)) = backing_layout(layout) else {
            return null_mut();
        };
        let owner = active_owner();
        // SAFETY: backing is a valid nonzero layout including Header.
        let base = unsafe { self.inner.alloc(backing) };
        if base.is_null() {
            // SAFETY: active_owner returned one owned Arc reference, or null.
            unsafe { release_owner(owner) };
            return null_mut();
        }
        // SAFETY: base is aligned for Header and has sufficient space.
        unsafe { base.cast::<Header>().write(Header { owner }) };
        if !owner.is_null() {
            // SAFETY: the header owns the Arc reference returned by active_owner.
            unsafe { &*owner }.resize(0, backing.size());
        }
        // SAFETY: offset lies within the backing allocation and satisfies layout.
        unsafe { base.add(offset) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let Some((backing, offset)) = backing_layout(layout) else {
            return null_mut();
        };
        let owner = active_owner();
        // SAFETY: backing is valid; writing Header does not touch the zeroed payload.
        let base = unsafe { self.inner.alloc_zeroed(backing) };
        if base.is_null() {
            // SAFETY: active_owner returned one owned Arc reference, or null.
            unsafe { release_owner(owner) };
            return null_mut();
        }
        // SAFETY: base is aligned for Header and has sufficient space.
        unsafe { base.cast::<Header>().write(Header { owner }) };
        if !owner.is_null() {
            // SAFETY: the header owns this Arc reference.
            unsafe { &*owner }.resize(0, backing.size());
        }
        // SAFETY: offset lies within the backing allocation and satisfies layout.
        unsafe { base.add(offset) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let Some((backing, offset)) = backing_layout(layout) else {
            // A layout that succeeded in alloc cannot reach this branch. Avoid
            // unwinding even when a caller violates GlobalAlloc's unsafe contract.
            return;
        };
        // SAFETY: caller supplies this allocator's live pointer and original layout.
        let base = unsafe { pointer.sub(offset) };
        let owner = unsafe { (*base.cast::<Header>()).owner };
        if !owner.is_null() {
            // End logical ownership before the inner call. An allocator can
            // release the storage and then take time to return; decrementing
            // afterward would inflate the peak if another thread replaced it.
            // SAFETY: the captured header reference is retained until release_owner.
            unsafe { &*owner }.resize(backing.size(), 0);
        }
        // SAFETY: base/backing exactly match the underlying allocation. The raw
        // owner reference remains owned by this call until inner.dealloc returns.
        unsafe { self.inner.dealloc(base, backing) };
        // SAFETY: consume exactly the header's owned Arc reference.
        unsafe { release_owner(owner) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return null_mut();
        };
        let Some((old_backing, offset)) = backing_layout(layout) else {
            return null_mut();
        };
        let Some((new_backing, _)) = backing_layout(new_layout) else {
            return null_mut();
        };
        // The prefix offset depends only on alignment, which realloc cannot change.
        // SAFETY: caller supplies a live allocation with its original layout.
        let base = unsafe { pointer.sub(offset) };
        let owner = unsafe { (*base.cast::<Header>()).owner };
        // Bootstrap caches may have unowned capacity before guest execution. Once
        // the guest grows them, conservatively charge their complete new backing
        // to that guest. Existing ownership never moves to a different scope.
        let (next_owner, previous_charge) = if owner.is_null() {
            (active_owner(), 0)
        } else {
            (owner, old_backing.size())
        };
        // SAFETY: new backing has the same alignment; the prefix always fits.
        let resized = unsafe { self.inner.realloc(base, old_backing, new_backing.size()) };
        if resized.is_null() {
            if owner.is_null() {
                // SAFETY: unsuccessful adoption releases its candidate reference;
                // the original unowned header and backing remain untouched.
                unsafe { release_owner(next_owner) };
            }
            return null_mut();
        }
        if owner.is_null() {
            // SAFETY: resized retains its aligned prefix; successful adoption
            // transfers the candidate Arc reference into that header.
            unsafe { resized.cast::<Header>().write(Header { owner: next_owner }) };
        }
        if !next_owner.is_null() {
            // SAFETY: Header owns this reference, retained or newly adopted.
            unsafe { &*next_owner }.resize(previous_charge, new_backing.size());
        }
        // SAFETY: the unchanged offset is valid within the resized backing allocation.
        unsafe { resized.add(offset) }
    }
}

unsafe fn release_owner(owner: *const OwnerState) {
    if !owner.is_null() {
        // SAFETY: caller transfers exactly one reference produced by Arc::into_raw.
        drop(unsafe { Arc::from_raw(owner) });
    }
}

/// Probe the actual global allocator, failing closed when this observer is absent.
///
/// Manual use of an `ObservedAllocator` elsewhere cannot set a capability flag.
/// An optimized-away probe or allocation failure also returns false.
pub fn allocation_observer_installed() -> bool {
    let owner = AllocationOwner::new();
    let _scope = owner.enter();
    let Ok(layout) = Layout::from_size_align(64, 64) else {
        return false;
    };
    let Some((backing, _)) = backing_layout(layout) else {
        return false;
    };
    // SAFETY: use a nonzero valid layout through the executable's global allocator.
    let pointer = unsafe { std::alloc::alloc(layout) };
    if pointer.is_null() {
        return false;
    }
    // Keep a real use of the allocation; eliminated allocation must fail detection.
    unsafe {
        std::ptr::write_volatile(pointer, 0xA5);
        std::hint::black_box(std::ptr::read_volatile(pointer));
    }
    let allocated = owner.snapshot();
    // SAFETY: pointer is the live global allocation made with this exact layout.
    unsafe { std::alloc::dealloc(pointer, layout) };
    let released = owner.snapshot();
    allocated.live_bytes == backing.size()
        && !allocated.overflowed
        && released.live_bytes == 0
        && !released.overflowed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::System;

    static ALLOCATOR: ObservedAllocator<System> = ObservedAllocator::new(System);

    fn layout(size: usize, align: usize) -> Layout {
        Layout::from_size_align(size, align).unwrap()
    }

    fn charge(layout: Layout) -> usize {
        backing_layout(layout).unwrap().0.size()
    }

    #[test]
    fn alignment_zeroing_and_growth_shrink_preserve_the_original_owner() {
        for alignment in [1, 8, 64, 4096] {
            let owner = AllocationOwner::new();
            let other = AllocationOwner::new();
            let old = layout(257, alignment);
            let scope = owner.enter();
            let mut pointer = unsafe { ALLOCATOR.alloc_zeroed(old) };
            assert!(!pointer.is_null());
            assert_eq!(pointer as usize % alignment, 0);
            assert!(unsafe { std::slice::from_raw_parts(pointer, old.size()) }
                .iter()
                .all(|byte| *byte == 0));
            unsafe { pointer.write_bytes(0x5A, old.size()) };
            drop(scope);
            let scope = other.enter();
            pointer = unsafe { ALLOCATOR.realloc(pointer, old, 8192) };
            assert!(!pointer.is_null());
            assert_eq!(pointer as usize % alignment, 0);
            assert!(unsafe { std::slice::from_raw_parts(pointer, old.size()) }
                .iter()
                .all(|byte| *byte == 0x5A));
            let large = layout(8192, alignment);
            assert_eq!(owner.snapshot().live_bytes, charge(large));
            assert_eq!(other.snapshot().live_bytes, 0);
            pointer = unsafe { ALLOCATOR.realloc(pointer, large, 17) };
            assert!(!pointer.is_null());
            assert!(unsafe { std::slice::from_raw_parts(pointer, 17) }
                .iter()
                .all(|byte| *byte == 0x5A));
            unsafe { ALLOCATOR.dealloc(pointer, layout(17, alignment)) };
            drop(scope);
            assert_eq!(owner.snapshot().live_bytes, 0);
            assert_eq!(owner.snapshot().peak_bytes, charge(large));
        }
    }

    struct Failing {
        fail: AtomicBool,
    }

    unsafe impl GlobalAlloc for Failing {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if self.fail.load(Ordering::Relaxed) {
                null_mut()
            } else {
                unsafe { System.alloc(layout) }
            }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            if self.fail.load(Ordering::Relaxed) {
                null_mut()
            } else {
                unsafe { System.alloc_zeroed(layout) }
            }
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            unsafe { System.dealloc(pointer, layout) }
        }
        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            if self.fail.load(Ordering::Relaxed) {
                null_mut()
            } else {
                unsafe { System.realloc(pointer, layout, size) }
            }
        }
    }

    #[test]
    fn failures_and_layout_overflow_preserve_bytes_ownership_and_counters() {
        let allocator = ObservedAllocator::new(Failing {
            fail: AtomicBool::new(true),
        });
        let owner = AllocationOwner::new();
        let scope = owner.enter();
        let old = layout(32, 64);
        assert!(unsafe { allocator.alloc(old) }.is_null());
        assert!(unsafe { allocator.alloc_zeroed(old) }.is_null());
        assert_eq!(owner.snapshot().live_bytes, 0);
        allocator.inner.fail.store(false, Ordering::Relaxed);
        let pointer = unsafe { allocator.alloc(old) };
        assert!(!pointer.is_null());
        unsafe { pointer.write_bytes(0xCC, old.size()) };
        let before = owner.snapshot();
        allocator.inner.fail.store(true, Ordering::Relaxed);
        assert!(unsafe { allocator.realloc(pointer, old, 4096) }.is_null());
        assert_eq!(owner.snapshot(), before);
        allocator.inner.fail.store(false, Ordering::Relaxed);
        let enormous = layout(isize::MAX as usize, 1);
        assert!(unsafe { allocator.alloc(enormous) }.is_null());
        assert!(unsafe { allocator.realloc(pointer, old, isize::MAX as usize) }.is_null());
        assert_eq!(owner.snapshot(), before);
        assert!(unsafe { std::slice::from_raw_parts(pointer, old.size()) }
            .iter()
            .all(|byte| *byte == 0xCC));
        unsafe { allocator.dealloc(pointer, old) };
        drop(scope);
        assert_eq!(owner.snapshot().live_bytes, 0);
    }

    #[test]
    fn unowned_realloc_adopts_only_on_success_with_an_active_owner() {
        let allocator = ObservedAllocator::new(Failing {
            fail: AtomicBool::new(false),
        });
        let owner = AllocationOwner::new();
        let other = AllocationOwner::new();
        let phase = owner.begin_phase();
        let original = layout(32, 64);
        let mut pointer = unsafe { allocator.alloc(original) };
        assert!(!pointer.is_null());
        unsafe { pointer.write_bytes(0x42, original.size()) };
        let scope = owner.enter();
        let references_before = Arc::strong_count(&owner.0);
        allocator.inner.fail.store(true, Ordering::Relaxed);
        assert!(unsafe { allocator.realloc(pointer, original, 128) }.is_null());
        assert_eq!(Arc::strong_count(&owner.0), references_before);
        assert_eq!(owner.snapshot().live_bytes, 0);
        allocator.inner.fail.store(false, Ordering::Relaxed);
        let suppression = AllocationScope::suppress();
        pointer = unsafe { allocator.realloc(pointer, original, 128) };
        assert!(!pointer.is_null());
        assert_eq!(owner.snapshot().live_bytes, 0);
        drop(suppression);
        pointer = unsafe { allocator.realloc(pointer, layout(128, 64), 256) };
        assert!(!pointer.is_null());
        assert_eq!(owner.snapshot().live_bytes, charge(layout(256, 64)));
        assert_eq!(
            phase.snapshot().peak_growth_bytes(),
            charge(layout(256, 64))
        );
        assert!(
            unsafe { std::slice::from_raw_parts(pointer, original.size()) }
                .iter()
                .all(|byte| *byte == 0x42)
        );
        drop(scope);
        let other_scope = other.enter();
        pointer = unsafe { allocator.realloc(pointer, layout(256, 64), 512) };
        assert!(!pointer.is_null());
        assert_eq!(owner.snapshot().live_bytes, charge(layout(512, 64)));
        assert_eq!(other.snapshot().live_bytes, 0);
        unsafe { allocator.dealloc(pointer, layout(512, 64)) };
        drop(other_scope);
        assert_eq!(owner.snapshot().live_bytes, 0);
    }

    #[test]
    fn phases_measure_peak_live_growth_and_keep_old_snapshots_stable() {
        let owner = AllocationOwner::new();
        let scope = owner.enter();
        let block = layout(128, 16);
        let retained = unsafe { ALLOCATOR.alloc(block) };
        assert!(!retained.is_null());
        let first = owner.begin_phase();
        for _ in 0..1000 {
            let pointer = unsafe { ALLOCATOR.alloc(block) };
            assert!(!pointer.is_null());
            unsafe { ALLOCATOR.dealloc(pointer, block) };
        }
        assert_eq!(first.snapshot().baseline_bytes, charge(block));
        assert_eq!(first.snapshot().peak_growth_bytes(), charge(block));
        let frozen = first.snapshot();
        let second = owner.begin_phase();
        let larger = layout(4096, 64);
        let pointer = unsafe { ALLOCATOR.alloc(larger) };
        assert!(!pointer.is_null());
        assert_eq!(first.snapshot(), frozen);
        assert_eq!(second.snapshot().peak_growth_bytes(), charge(larger));
        unsafe {
            ALLOCATOR.dealloc(pointer, larger);
            ALLOCATOR.dealloc(retained, block);
        }
        drop(scope);
        assert_eq!(owner.snapshot().live_bytes, 0);
        assert_eq!(second.snapshot().live_bytes, 0);
    }

    #[test]
    fn nested_suppression_out_of_order_drop_and_unwinding_restore_tracking() {
        let owner = AllocationOwner::new();
        let other = AllocationOwner::new();
        let outer = owner.enter();
        let inner = other.enter();
        drop(outer);
        let block = layout(64, 8);
        let suppressed = AllocationScope::suppress();
        let unowned = unsafe { ALLOCATOR.alloc(block) };
        assert!(!unowned.is_null());
        drop(suppressed);
        let owned = unsafe { ALLOCATOR.alloc(block) };
        assert!(!owned.is_null());
        drop(inner);
        assert_eq!(owner.snapshot().live_bytes, 0);
        assert_eq!(other.snapshot().live_bytes, charge(block));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _scope = owner.enter();
            panic!("scope unwind");
        }));
        assert!(result.is_err());
        drop(result);
        assert!(active_owner().is_null());
        unsafe {
            ALLOCATOR.dealloc(unowned, block);
            ALLOCATOR.dealloc(owned, block);
        }
        assert_eq!(other.snapshot().live_bytes, 0);
    }

    #[test]
    fn allocations_keep_owners_alive_until_a_different_thread_frees_them() {
        let owner = AllocationOwner::new();
        let weak = Arc::downgrade(&owner.0);
        let phase = owner.begin_phase();
        let scope = owner.enter();
        let block = layout(256, 128);
        let pointer = unsafe { ALLOCATOR.alloc(block) };
        assert!(!pointer.is_null());
        drop(scope);
        drop(owner);
        assert!(weak.upgrade().is_some());
        let address = pointer as usize;
        std::thread::spawn(move || unsafe {
            ALLOCATOR.dealloc(address as *mut u8, block);
        })
        .join()
        .unwrap();
        assert!(weak.upgrade().is_none());
        assert_eq!(phase.snapshot().live_bytes, 0);
        assert_eq!(phase.snapshot().peak_growth_bytes(), charge(block));
    }

    #[test]
    fn concurrent_allocations_and_frees_keep_phase_snapshots_coherent() {
        const WORKERS: usize = 2;
        const BLOCKS: usize = 32;
        let owner = AllocationOwner::new();
        let first = owner.begin_phase();
        let allocated = Arc::new(std::sync::Barrier::new(WORKERS + 1));
        let release = Arc::new(std::sync::Barrier::new(WORKERS + 1));
        let block = layout(73, 64);
        let workers: Vec<_> = (0..WORKERS)
            .map(|_| {
                let owner = owner.clone();
                let allocated = allocated.clone();
                let release = release.clone();
                std::thread::spawn(move || {
                    let mut pointers = [0usize; BLOCKS];
                    let scope = owner.enter();
                    for address in &mut pointers {
                        let pointer = unsafe { ALLOCATOR.alloc_zeroed(block) };
                        assert!(!pointer.is_null());
                        *address = pointer as usize;
                    }
                    drop(scope);
                    allocated.wait();
                    release.wait();
                    for address in pointers {
                        unsafe { ALLOCATOR.dealloc(address as *mut u8, block) };
                    }
                })
            })
            .collect();
        allocated.wait();
        let expected = WORKERS * BLOCKS * charge(block);
        assert_eq!(owner.snapshot().live_bytes, expected);
        assert_eq!(first.snapshot().peak_growth_bytes(), expected);
        let frozen = first.snapshot();
        let second = owner.begin_phase();
        release.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(owner.snapshot().live_bytes, 0);
        assert_eq!(first.snapshot(), frozen);
        assert_eq!(second.snapshot().live_bytes, 0);
        assert_eq!(second.snapshot().peak_growth_bytes(), 0);
    }

    #[test]
    fn released_backing_does_not_overlap_replacement_while_dealloc_returns() {
        struct DelayedFree<'a> {
            freed: &'a std::sync::Barrier,
            finish: &'a std::sync::Barrier,
            delay_next: AtomicBool,
        }
        unsafe impl GlobalAlloc for DelayedFree<'_> {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                unsafe { System.alloc(layout) }
            }
            unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
                unsafe { System.dealloc(pointer, layout) };
                if self.delay_next.swap(false, Ordering::AcqRel) {
                    self.freed.wait();
                    self.finish.wait();
                }
            }
        }

        let freed = std::sync::Barrier::new(2);
        let finish = std::sync::Barrier::new(2);
        let allocator = ObservedAllocator::new(DelayedFree {
            freed: &freed,
            finish: &finish,
            delay_next: AtomicBool::new(true),
        });
        let owner = AllocationOwner::new();
        let phase = owner.begin_phase();
        let block = layout(73, 64);
        let scope = owner.enter();
        let original = unsafe { allocator.alloc(block) };
        assert!(!original.is_null());
        drop(scope);
        let address = original as usize;
        std::thread::scope(|threads| {
            let worker = threads.spawn(|| unsafe {
                allocator.dealloc(address as *mut u8, block);
            });
            // System has already freed the first block, but its deallocator is
            // deliberately paused before returning to the observer.
            freed.wait();
            let after_free = owner.snapshot();
            let scope = owner.enter();
            let replacement = unsafe { allocator.alloc(block) };
            drop(scope);
            let after_replacement = phase.snapshot();
            finish.wait();
            worker.join().unwrap();
            // Release the barrier and join before assertions, so a regression
            // fails normally instead of leaving a worker blocked during unwind.
            assert!(!replacement.is_null());
            unsafe { allocator.dealloc(replacement, block) };
            assert_eq!(after_replacement.peak_growth_bytes(), charge(block));
            assert_eq!(after_free.live_bytes, 0);
            assert_eq!(after_replacement.live_bytes, charge(block));
            assert_eq!(owner.snapshot().live_bytes, 0);
        });
    }

    #[test]
    fn bookkeeping_is_unowned_and_manual_use_does_not_fake_global_installation() {
        let before = allocation_observer_installed();
        let owner = AllocationOwner::new();
        let scope = owner.enter();
        let another = AllocationOwner::new();
        let phase = owner.begin_phase();
        let nested = owner.enter();
        drop(nested);
        assert_eq!(owner.snapshot().live_bytes, 0);
        drop((phase, another, scope));
        assert_eq!(allocation_observer_installed(), before);
    }

    #[test]
    fn counter_overflow_and_underflow_are_sticky_and_never_panic() {
        let owner = AllocationOwner::new();
        let frozen = owner.begin_phase();
        let phase = owner.begin_phase();
        owner.0.resize(0, usize::MAX);
        owner.0.resize(0, 1);
        assert!(owner.snapshot().overflowed);
        assert!(phase.snapshot().overflowed);
        assert_eq!(frozen.snapshot().live_bytes, 0);
        assert_eq!(frozen.snapshot().peak_bytes, 0);
        assert!(frozen.snapshot().overflowed);
        owner.0.resize(usize::MAX, 0);
        owner.0.resize(1, 0);
        assert_eq!(owner.snapshot().live_bytes, 0);
        assert!(owner.snapshot().overflowed);
    }

    #[test]
    fn tls_teardown_and_reentrant_tls_borrows_do_not_panic_or_track_bookkeeping() {
        static FINISHED: AtomicBool = AtomicBool::new(false);
        struct Teardown;
        impl Drop for Teardown {
            fn drop(&mut self) {
                let scope = AllocationScope::suppress();
                assert!(!scope.is_established());
                let owner = AllocationOwner::new();
                let failed_scope = owner.enter();
                assert!(!failed_scope.is_established());
                assert!(owner.snapshot().overflowed);
                let block = layout(64, 64);
                let pointer = unsafe { ALLOCATOR.alloc_zeroed(block) };
                assert!(!pointer.is_null());
                unsafe { ALLOCATOR.dealloc(pointer, block) };
                drop(scope);
                FINISHED.store(true, Ordering::Release);
            }
        }
        thread_local! {
            static LAST: Teardown = const { Teardown };
        }
        std::thread::spawn(|| {
            LAST.with(|_| {});
            let owner = AllocationOwner::new();
            let scope = owner.enter();
            assert!(scope.is_established());
            SCOPES.with(|scopes| {
                let _borrow = scopes.borrow_mut();
                let block = layout(32, 8);
                let pointer = unsafe { ALLOCATOR.alloc(block) };
                assert!(!pointer.is_null());
                unsafe { ALLOCATOR.dealloc(pointer, block) };
                // Inactivation must survive the failed reentrant TLS mutation.
                drop(scope);
            });
            assert!(active_owner().is_null());
            assert_eq!(owner.snapshot().live_bytes, 0);
        })
        .join()
        .unwrap();
        assert!(FINISHED.load(Ordering::Acquire));
    }

    #[test]
    fn reentrant_scope_installation_failure_invalidates_all_owner_phases() {
        let owner = AllocationOwner::new();
        let frozen = owner.begin_phase();
        let current = owner.begin_phase();
        SCOPES.with(|scopes| {
            let _borrow = scopes.borrow_mut();
            let failed = owner.enter();
            assert!(!failed.is_established());
            assert!(!AllocationScope::suppress().is_established());
        });
        assert!(owner.snapshot().overflowed);
        assert!(frozen.snapshot().overflowed);
        assert!(current.snapshot().overflowed);
        let later = owner.enter();
        assert!(later.is_established());
        assert!(owner.snapshot().overflowed);
    }
}
