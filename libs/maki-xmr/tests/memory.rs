//! What a range proof takes of the heap at its peak, which maki-keys' heap is sized for (it runs
//! out, a panic, where a computer would just take more). A point is 160 bytes here as on maki.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

use curve25519_dalek::scalar::Scalar;
use maki_xmr::bulletproof::{self, Generators, MAX_OUTPUTS};

/// The system's allocator, counting what's allocated now, and the most since `reset`.
struct Counting;

static NOW: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        PEAK.fetch_max(NOW.fetch_add(layout.size(), SeqCst) + layout.size(), SeqCst);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        NOW.fetch_sub(layout.size(), SeqCst);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn scalar(n: u64) -> Scalar { Scalar::from_bytes_mod_order(maki_xmr::keccak(&n.to_le_bytes())) }

/// The heap a proof for `m` outputs takes at its peak, its generators (kept between proofs) too.
fn peak(m: usize) -> usize {
    let outputs: Vec<(u64, Scalar)> = (0..m as u64).map(|i| (1_000_000 * (i + 1), scalar(i))).collect();
    let before = NOW.load(SeqCst);
    PEAK.store(before, SeqCst);
    let mut generators = Generators::new();
    assert!(bulletproof::prove(&mut generators, &outputs, &mut || scalar(99)).is_some());
    PEAK.load(SeqCst) - before
}

// in one test: the counts are the whole process's
#[test]
fn a_range_proof_fits_maki_keys_heap() {
    // two outputs, most transactions: under the 512 KiB every process starts with
    assert!(peak(2) < 384 * 1024, "{} KiB", peak(2) / 1024);
    // sixteen, the most: in the 2.5 MiB maki-keys asks for, with room for the rest
    assert!(peak(MAX_OUTPUTS) < 2 * 1024 * 1024, "{} KiB", peak(MAX_OUTPUTS) / 1024);
}
