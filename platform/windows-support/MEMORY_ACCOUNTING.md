# Windows Python memory accounting

Windows uses an application-installed allocation observer because a process-wide
page-fault count cannot attribute growth to one in-process Python environment.
Unix retains its thread-fault and residency measurements.

## Measurement

`ObservedAllocator` wraps the executable's allocator. It counts requested Rust
backing storage, including observer metadata and alignment padding, but not the
underlying heap's rounding, foreign allocations, OS mappings, or stacks. Each
Python environment owns its allocations and tracks peak live growth during an
execution phase. Freed scratch space does not accumulate as budget consumption.

The observer is cooperative: the runtime's instruction-monitoring callback and
host watch read its growth measurements. It does not reject allocations, unwind
from allocator callbacks, or provide a hard resident-memory cap. An allocation
can exceed the budget before the next interruption point.

## Ownership and execution phases

- Reallocations and cross-thread frees retain the original owner. A successful
  reallocation of unowned storage adopts the current owner; failure leaves the
  original allocation unchanged.
- Ownership records remain alive while their allocations remain live, including
  after an interpreter retires. Finalization does not erase outstanding charges.
- Interpreter construction, execution, and finalization run under the environment's
  owner. Shared runtime initialization and host-side SDK dispatch are unowned;
  guest result conversion restores ownership.
- Cold initialization and its first invocation share a phase. Warm invocations
  reset at the host's existing bind boundary. Starting a handler clock does not
  reset its memory baseline, and later phases cannot rewrite an earlier watch's
  measurements.
- Warm-pool retirement compares current owned bytes with the post-initialization
  baseline. This preserves retained guest growth without charging unrelated work.

Shared mutable runtime state needs explicit ownership. The Windows CSV registry
and field limit are per interpreter. Native modules that allocate outside Rust,
or create worker threads without propagating ownership, need separate accounting
before they can rely on this observer.

## Failure and embedding

Scope-entry failures and counter overflow invalidate accounting and stop guest
execution. Python verifies the actual global allocator before creating an
interpreter and refuses to run when the observer is unavailable.

Allocator selection belongs to the executable. An embedding host wraps its chosen
allocator with `WindowsLambdaAllocator`; the library does not install one through
a dependency feature. See the [embedding example](../../core/embedded/README.md).
The support crate declares its minimum Rust version in [Cargo.toml](Cargo.toml).
