//! The `alloc-count` build of the binary (not of the library): a global allocator that counts calls into the
//! allocator the binary would otherwise use, for the benchmark's allocations-per-request figure (bench/README.md).
//! Built only with `--features alloc-count`; a default build compiles none of this, so it costs nothing there.
//!
//! `SIGUSR1` prints the counters since start on stderr as one line, `alloc-count allocs=<n> reallocs=<n> deallocs=<n>
//! bytes=<n>`; the benchmark reads it before and after its measured window and divides the difference by the requests.

use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

#[cfg(target_env = "musl")]
type Inner = mimalloc::MiMalloc;
#[cfg(target_env = "musl")]
const INNER: Inner = mimalloc::MiMalloc;
#[cfg(not(target_env = "musl"))]
type Inner = std::alloc::System;
#[cfg(not(target_env = "musl"))]
const INNER: Inner = std::alloc::System;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static REALLOCS: AtomicU64 = AtomicU64::new(0);
static DEALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

/// The counting wrapper around the binary's usual allocator.
pub struct Counting;

// SAFETY: every method forwards to the inner allocator with the caller's arguments unchanged; the counters are atomics
// that never allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(layout.size() as u64, Relaxed);
        // SAFETY: the caller's contract for `alloc`, passed on unchanged
        unsafe { INNER.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(layout.size() as u64, Relaxed);
        // SAFETY: the caller's contract for `alloc_zeroed`, passed on unchanged
        unsafe { INNER.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        REALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(new_size as u64, Relaxed);
        // SAFETY: the caller's contract for `realloc`, passed on unchanged
        unsafe { INNER.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOCS.fetch_add(1, Relaxed);
        // SAFETY: the caller's contract for `dealloc`, passed on unchanged
        unsafe { INNER.dealloc(ptr, layout) }
    }
}

/// Prints the counters on stderr at every `SIGUSR1`. Called inside the runtime.
pub fn report_on_sigusr1() {
    use tokio::signal::unix::{SignalKind, signal};
    let Ok(mut usr1) = signal(SignalKind::user_defined1()) else { return };
    tokio::spawn(async move {
        while usr1.recv().await.is_some() {
            eprintln!(
                "alloc-count allocs={} reallocs={} deallocs={} bytes={}",
                ALLOCS.load(Relaxed),
                REALLOCS.load(Relaxed),
                DEALLOCS.load(Relaxed),
                BYTES.load(Relaxed)
            );
        }
    });
}
