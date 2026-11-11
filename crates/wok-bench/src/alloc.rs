//! A counting global allocator: a thin wrapper over the system allocator that
//! keeps the bytes currently allocated and the highest that figure has been.
//!
//! The engine scenario reads it to say what a session, an open subscription
//! and an attached receiver each hold. It counts every allocation of the
//! process from its start, so a free is never seen without its allocation.
//! The cost is two relaxed atomic operations per allocation, which every
//! scenario pays; the run header records that allocations are counted.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

pub struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Relaxed).wrapping_add(bytes);
    // Most allocations do not set a new peak, so look before writing.
    if live > PEAK.load(Relaxed) {
        PEAK.fetch_max(live, Relaxed);
    }
}

fn shrank(bytes: usize) {
    LIVE.fetch_sub(bytes, Relaxed);
}

// SAFETY: every call is forwarded unchanged to `System`, which upholds the
// `GlobalAlloc` contract; the counters are only bookkeeping beside it.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            grew(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            grew(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        shrank(layout.size());
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            if new_size >= layout.size() {
                grew(new_size - layout.size());
            } else {
                shrank(layout.size() - new_size);
            }
        }
        moved
    }
}

/// Bytes allocated now, by the whole process.
pub fn live_bytes() -> usize {
    LIVE.load(Relaxed)
}

/// The most bytes that were allocated at once since the last reset.
pub fn peak_bytes() -> usize {
    PEAK.load(Relaxed)
}

/// Start a new peak from the bytes allocated now.
pub fn reset_peak() {
    PEAK.store(LIVE.load(Relaxed), Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_allocation_is_counted_and_released() {
        // Other test threads allocate and free too, so the figures are only
        // checked to within half the held size.
        const HELD: usize = 64 << 20;
        let before = live_bytes();
        let held = vec![1u8; HELD];
        assert!(live_bytes() + HELD / 2 >= before + HELD);
        drop(held);
        assert!(live_bytes() < before + HELD / 2);
    }
}
