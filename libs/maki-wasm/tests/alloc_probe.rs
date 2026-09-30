use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

struct Counting;
static NOW: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static BIGGEST: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let n = NOW.fetch_add(l.size(), SeqCst) + l.size();
        PEAK.fetch_max(n, SeqCst);
        BIGGEST.fetch_max(l.size(), SeqCst);
        unsafe { System.alloc(l) }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        NOW.fetch_sub(l.size(), SeqCst);
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Counting = Counting;

#[test]
fn alloc_probe() {
    let bytes = std::fs::read(format!("{}/tests/fixtures/dice.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let b = maki_bundle::read(&bytes).unwrap();
    let base = NOW.load(SeqCst);
    PEAK.store(base, SeqCst);
    BIGGEST.store(0, SeqCst);
    let loaded = maki_wasm::load(&b.manifest, b.code).unwrap();
    eprintln!(
        "load: peak {} KiB above base, biggest single allocation {} KiB, kept {} KiB",
        (PEAK.load(SeqCst) - base) / 1024,
        BIGGEST.load(SeqCst) / 1024,
        (NOW.load(SeqCst) - base) / 1024
    );
    drop(loaded);
}
