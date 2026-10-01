// Changed for maki (a fork of Xous: github.com/KaraZajac/maki-firmware) in 2026; its git history says what.
// TODO: redo docs to match streamlined architecture

//! ==Architecture==
//!
//! The Xous philosophy is to leave the kernel lightweight and free of dependencies. The swap implementation
//! adheres to this by trying to move as much of the difficult algorithmic processing and performance tuning
//! outside of the kernel.
//!
//! The one thing swap does introduce to the kernel that is algorithm-y is a renormalization routine for
//! counting page accesses. We track page access frequency with a 32-bit "epoch" counter, which is simply
//! incremented whenever a page table interaction happens. We don't use a 64-bit counter because greatly
//! increases the memory used to track things due to the single 64-bit record forcing the next item to also
//! have 64-bit alignment, thus effectively wasting several bytes per page. Anyways, when the epoch is about
//! to roll-over, a mostly in-place sweep with no allocations beyond a few dozen bytes in stack is done to the
//! memory usage tracker to "compact" the epoch numbers down. There is a #[test] in the kernel crate for this
//! routine.
//!
//! In order to perform all the other processing outside of the kernel, the swapper introduces a special new
//! "blocking userspace handler". It's "IRQ-like", in that it borrows the same mechanism used for blocking
//! IRQ handlers, but with different entry and exit magic numbers so we can differentiate the two. The
//! blocking userspace handler happens with interrupts disabled, giving it an atomic view of all of memory for
//! the duration of the handler.
//!
//! == Measuring Memory Usage ==
//!
//! The swapper needs to come up with an answer for which page to swap out, and it
//! also needs to know when to do it (OOM pressure).
//!
//! OOM pressure is handled with a syscall to the kernel to query the current `MEMORY_ALLOCATIONS`
//! table and return the available RAM. This is queried periodically with a timer, and if we
//! fall below a certain threshold, the swapper will force a pre-emptive OOM.
//!
//! When the `swap` feature is selected, `MEMORY_ALLOCATIONS` is upgraded from a `u8` to a table of
//! `timestamp | VPN | PID | FLAGS`, where the timestamp is a u32 that is monotonically
//! incremented with every modification to the page, and the VPN | PID | FLAGS portion
//! is condensed to fit into a u32. The FLAGS can specify if the address is `wired`, which
//! would be the case of e.g. a page table page, and the VPN would be considered invalid
//! in this case (and the page should never be swapped).
//!
//! A u32 is used instead of a u64 because due to alignment issues, if we used a u64 we'd
//! waste 4 bytes per tracking slot, and the penalty is not worth it in a memory-constrained
//! system. Instead, we have a callback to handle when the "epoch" rolls over.
//!
//! The `MEMORY_ALLOCATIONS` table is page-aligned, so that it can be mapped into PID 2 inside
//! an interrupt context. To initiate OOM handling, PID 2 is invoked by the kernel with a call the swapper
//! interrupt context with `MEMORY_ALLOCATIONS` mapped into its memory space. At this point, PID 2 will copy
//! the current `MEMORY_ALLOCATIONS` table into a pre-allocated BinaryHeap in the shared state structure,
//! indexed by the timestamp. At this point, the blocking userspace handler can work through a sorted vector
//! of allocations to pick the pages it wants to remove.
mod debug;
mod platform;
mod swapmap;
use core::fmt::Write;
use std::collections::BinaryHeap;
use std::fmt::Debug;

use debug::*;
use loader::swap::{SwapAlloc, SwapSpec};
use num_traits::*;
use platform::{PAGE_SIZE, SwapHal};
use xous::arch::{SWAP_CFG_VADDR, SWAP_COUNT_VADDR, SWAP_PT_VADDR, SWAP_RPT_VADDR};
use xous::{MemoryFlags, MemoryRange, PID, Result};
use xous_swapper::Opcode;
use xous_swapper::SwapAbi;

/// Patch over SPI calls with prints, for testing in renode
const RENODE_TESTING: bool = false;

/// Target of pages to free in case of a Hard OOM. Note that the PAGE_TARGET numbers
/// are imprecise, in that there is a chance that one target is active during another
/// invocation of a routine. This is because the hard OOM handler is entirely asynchronous
/// and could be invoked at any time, including while we are trying to handle a soft OOM.
// maki: 12 rather than 24. Pages go oldest first, and the kernel dates a page by when it came in,
// not when it was last used: every page an OOM frees beyond what's needed is likely someone's
// working set, soon to come back in.
const HARD_OOM_PAGE_TARGET: usize = 12;
/// Target of pages to free in case of OOM Doom
#[cfg(feature = "oom-doom")]
const OOM_DOOM_PAGE_TARGET: usize = 48;
/// Polling interval for OOM Doom. Slightly off from an even second so we don't have constant
/// competition with other processes that probably use even-second multiples for polling.
#[cfg(feature = "oom-doom")]
const OOM_DOOM_POLL_INTERVAL_MS: u64 = 1057;

/// kernel -> swapper handler ABI
/// This structure mirrors the BlockingSwapOp's that the kernel can issue to userspace.
/// The actual numbers for the opcode are transcribed manually into the kernel, as the
/// kernel's encoding of its enum is composite to track call state.
#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
#[repr(usize)]
pub enum KernelOp {
    /// Find the requested page, decrypt it, and return it
    ReadFromSwap = 1,
    /// Hard OOM invocation - stop everything and free memory!
    HardOom = 3,
    /// Take the requested page and write it to SPI
    WriteToFlash = 4,
    /// Bulk erase
    BulkErase = 5,
}

pub struct RuntimePageTracker {
    pub allocs: &'static mut [Option<PID>],
}

pub struct SwapCountTracker {
    pub counts: &'static mut [u32],
}

/// Number of pages to reserve for hard OOM handling. In case of a hard OOM, there are 0 pages
/// available, which makes it impossible for the hard OOM handler to do things like allocate an L1
/// page table entry to track memory being swapped out. This places a hold on some memory that's
/// de-allocated on entry to the hard OOM handler, and re-allocated on exit.
///
/// Known things the swapper has to allocate memory for in hard-OOM:
///   - L1 page table entries for tracking swap
///   - An extra page for stack (needed for bao1x targets, but not on precursor due to HAL differences)
///   - An additional page seems to be necessary for handling OOM-during-move-or-lend edge cases.
const HARD_OOM_RESERVED_PAGES: usize = 3;

/// This structure contains shared state accessible between the userspace code and the blocking swap call
/// handler.
pub struct SwapperSharedState {
    /// maki: (PID, virtual address) -> (offset in swap), for every page out in swap: see
    /// `swapmap`. It took over from the swap page tables the loader made, as the swapper started.
    pub map: swapmap::SwapMap,
    /// maki: those tables (start and length), for the main thread to give back to the kernel:
    /// they're mapped in the handler's context, where unmapping isn't possible. 0 once given.
    pub loader_tables: (usize, usize),
    /// Contains all the structures specific to the HAL for accessing swap memory
    pub hal: SwapHal,
    /// This is a table of `u32` per page of swap memory, which tracks the count of how many times
    /// the swap page has been used with a 31-bit count, and the remaining 1 MSB dedicated to tracking
    /// if the page is currently used at all. The purpose of this count is to drive nonces up in a
    /// deterministic factor to deter page-reuse attacks.
    pub sct: SwapCountTracker,
    /// Address of main RAM start
    pub sram_start: usize,
    /// Size of main RAM in bytes
    pub sram_size: usize,
    /// Starting point for a search for free swap pages. A simple linear ascending search is done,
    /// starting from the free swap search origin. The unit of this variable is in pages, so it
    /// can be used to directly index the `sct` `SwapCountTracker`.
    pub free_swap_search_origin: usize,
    pub hard_oom_alloc_heap: Option<BinaryHeap<SwapAlloc>>,
    /// Reserve some memory to be freed by the hard OOM manager. These pages are needed to do things
    /// like create L1 page table entries for the swapper to track evicted pages.
    pub hard_oom_reserved_page: Option<MemoryRange>,
    pub report_full_rpt: bool,
    /// number of pages to free in the OOM routine. Note that this value is imprecise: it can
    /// be mutated by the userspace soft-OOM handler at any time.
    pub pages_to_free: usize,
}
impl SwapperSharedState {
    /// Where `pid`'s page at `va` is in swap, if it's there (with `va`'s offset in the page), and
    /// with `mark_free`, forgets it: it's coming back into RAM.
    pub fn pt_walk(&mut self, pid: u8, va: usize, mark_free: bool) -> Option<usize> {
        let offset = if mark_free { self.map.remove(pid, va) } else { self.map.get(pid, va) }?;
        Some(offset as usize | va & 0xFFF)
    }
}
struct SharedStateStorage {
    pub inner: Option<SwapperSharedState>,
}
impl SharedStateStorage {
    pub fn init(&mut self) {
        // Register the swapper with the kernel. Written as a raw syscall, since this is
        // the only instance of its use (no point in use-once code to wrap it).
        // This is an "early registration" which allows us to see debug output quickly,
        // even before we can constitute all of our shared state
        xous::rsyscall(xous::SysCall::RegisterSwapper(
            0,
            0,
            0,
            0,
            swap_handler as *mut usize as usize,
            self as *mut SharedStateStorage as usize,
        ))
        .unwrap();
    }
}

fn map_swap(ss: &mut SwapperSharedState, swap_phys: usize, virt: usize, owner: u8) {
    assert!(swap_phys & 0xFFF == 0, "PA is not page aligned");
    assert!(virt & 0xFFF == 0, "VA is not page aligned");
    #[cfg(feature = "debug-verbose")]
    writeln!(DebugUart {}, "    swap pa {:x} -> va {:x}", swap_phys, virt).ok();
    assert!(owner != 0);
    // maki: one entry in the swap map, which was made at the start for as many pages as swap
    // has: nothing is allocated here, while memory is short
    if let Some(stale) = ss.map.insert(owner, virt, swap_phys as u32) {
        if stale as usize == swap_phys {
            return;
        }
        // maki: whatever was swapped out at this address before is gone (the page being swapped
        // out now is there): its swap page is free, for the case the kernel's list of unmapped
        // pages (`forget_freed`) overflowed.
        if let Some(count) = ss.sct.counts.get_mut(stale as usize / PAGE_SIZE) {
            *count &= !loader::FLG_SWAP_USED;
        }
        // Print a warning, because this can be indicative of either an error in the algorithm, OR
        // it can be indicative of a scenario where a page was swapped, then released without updating the
        // swapper. Swap then release can happen in the case that a page was lent to a target process;
        // then it was swapped out; then, it was released without having to be swapped back in. The release
        // does not check the PTE swap bit, it simply releases the memory. This can lead to a "memory leak"
        // in swap, so we print a warning here. However, I think the leak only happens insofar as the
        // mappings are never re-used, but for lent pages the addresses tend to be re-used rapidly.
        writeln!(
            DebugUart {},
            "{}.{:08x} already mapped to PA {:08x}. Remapping to PA {:08x}! (possibly leak of swap due silent unmap of lent pages)",
            owner, virt, stale, swap_phys,
        )
        .ok();
    }
}

/// maki: the swap map, made as the swapper starts (in the handler's context, on the kernel's first
/// call), holding the pages the loader put in swap, from the swap page tables it made for them:
/// a root per process at SWAP_PT_VADDR, then the tables under them, all in a row. Says where those
/// are (start, length), for the main thread to give back.
fn swap_map_from_loader(slots: usize, roots: usize) -> (swapmap::SwapMap, (usize, usize)) {
    let places = swapmap::SwapMap::places_for(slots);
    let bytes = (places * 2 * core::mem::size_of::<u32>()).next_multiple_of(PAGE_SIZE);
    let mem = xous::map_memory(None, None, bytes, MemoryFlags::R | MemoryFlags::W)
        .expect("couldn't allocate the swap map");
    // safety: fresh pages, and `u32` is fully representable
    let words: &'static mut [u32] =
        unsafe { core::slice::from_raw_parts_mut(mem.as_mut_ptr() as *mut u32, places * 2) };
    words.fill(0);
    let (keys, offsets) = words.split_at_mut(places);
    let mut map = swapmap::SwapMap::new(keys, offsets);
    let mut end = SWAP_PT_VADDR + roots * PAGE_SIZE;
    for p in 0..roots {
        // safety: the loader mapped each root here, and the tables they point to, at the addresses
        // they point to (it patched them so), all made by it and fully initialized
        let l1 = unsafe { core::slice::from_raw_parts((SWAP_PT_VADDR + p * PAGE_SIZE) as *const u32, 1024) };
        for (vpn1, &l1_entry) in l1.iter().enumerate() {
            // valid, with RWX 0: points to an L0 table
            if (l1_entry & 0xF) != loader::FLG_VALID as u32 {
                continue;
            }
            let l0_address = (l1_entry as usize & 0xFFFF_FC00) << 2;
            assert!(l0_address >= SWAP_PT_VADDR + roots * PAGE_SIZE, "a loader swap table out of place");
            end = end.max(l0_address + PAGE_SIZE);
            let l0 = unsafe { core::slice::from_raw_parts(l0_address as *const u32, 1024) };
            for (vpn0, &entry) in l0.iter().enumerate() {
                if entry as usize & loader::FLG_VALID != 0 {
                    let offset = ((entry as usize & 0xFFFF_FC00) << 2) as u32;
                    map.insert(p as u8 + 1, vpn1 << 22 | vpn0 << 12, offset);
                }
            }
        }
    }
    (map, (SWAP_PT_VADDR, end - SWAP_PT_VADDR))
}

/// Convenience wrapper for GetFreePages syscall
fn get_free_pages() -> usize {
    match xous::rsyscall(xous::SysCall::SwapOp(SwapAbi::GetFreePages as usize, 0, 0, 0, 0, 0, 0)) {
        Ok(Result::Scalar5(free_pages, _total_memory, _, _, _)) => free_pages,
        _ => panic!("GetFreeMem syscall failed"),
    }
}

/// maki: the pages free now, without the kernel printing its table of who uses what: for the
/// hard-OOM handler, which asks often. A kernel that doesn't know the quiet form prints anyway.
fn free_pages_quietly() -> usize {
    match xous::rsyscall(xous::SysCall::SwapOp(SwapAbi::GetFreePages as usize, 1, 0, 0, 0, 0, 0)) {
        Ok(Result::Scalar5(free_pages, _total_memory, _, _, _)) => free_pages,
        _ => 0,
    }
}

/// maki: frees what processes that ended had in swap (the kernel says which), and forgets it in
/// the swap map, so the next process given the PID starts with nothing there. Done before anything is
/// evicted, so before any such process has anything in swap. Without it, every process that
/// ended with pages in swap would leak them, and a native app is a process that ends.
fn forget_ended(ss: &mut SwapperSharedState) {
    let ended = match xous::rsyscall(xous::SysCall::SwapOp(SwapAbi::TakeEnded as usize, 0, 0, 0, 0, 0, 0)) {
        Ok(Result::Scalar5(lo, hi, _, _, _)) => lo as u64 | (hi as u64) << 32,
        _ => return,
    };
    if ended == 0 {
        return;
    }
    let counts = &mut ss.sct.counts;
    ss.map.forget(
        |key| {
            let pid = swapmap::pid_of(key) as u32;
            pid >= 1 && pid <= 64 && ended & (1u64 << (pid - 1)) != 0
        },
        // free, keeping the count (nonces never repeat)
        |offset| {
            if let Some(count) = counts.get_mut(offset as usize / PAGE_SIZE) {
                *count &= !loader::FLG_SWAP_USED;
            }
        },
    );
}
/// maki: frees the swap pages of pages unmapped while they were out in swap (the kernel says
/// which: unmapping one, a process gives up a page it doesn't have in RAM, and only the swapper
/// knows which swap page holds it). Done before anything is evicted, as `forget_ended` is, so no
/// page since swapped out to the same address is mistaken for one of them. Without it, those swap
/// pages were taken for good: a few dozen with every app installed, until swap filled.
fn forget_freed(ss: &mut SwapperSharedState) {
    loop {
        let freed = match xous::rsyscall(xous::SysCall::SwapOp(SwapAbi::TakeFreed as usize, 0, 0, 0, 0, 0, 0))
        {
            Ok(Result::Scalar5(a, b, c, d, e)) => [a, b, c, d, e],
            _ => return,
        };
        if freed[0] == 0 {
            return;
        }
        for entry in freed.iter().copied().filter(|&e| e != 0) {
            let (pid, vaddr) = ((entry & 0xFF) as u8, entry & !0xFFF);
            if let Some(paddr_in_swap) = ss.pt_walk(pid, vaddr, true) {
                if let Some(count) = ss.sct.counts.get_mut(paddr_in_swap / PAGE_SIZE) {
                    *count &= !loader::FLG_SWAP_USED;
                }
            }
        }
    }
}

/// Core of write_to_swap.
fn write_to_swap_inner(
    ss: &mut SwapperSharedState,
    candidate: SwapAlloc,
    errs: &mut usize,
    pages_to_free: &mut usize,
) -> core::result::Result<(), xous::Error> {
    // step 1: steal the page from the other process. Its data gets mapped into the
    // swapper as `local_ptr`. This will also unmap the page from memory.
    let vaddr_in_swap = match xous::rsyscall(xous::SysCall::SwapOp(
        SwapAbi::StealPage as usize,
        candidate.raw_pid() as usize,
        candidate.vaddr(),
        0,
        0,
        0,
        0,
    )) {
        Ok(Result::Scalar5(page_ptr, _, _, _, _)) => page_ptr,
        Ok(_) => panic!("Malformed return value"),
        Err(_e) => {
            *errs += 1;
            return Err(xous::Error::ShareViolation); // try another page
        }
    };

    // step 2: write the page to swap
    #[cfg(feature = "debug-print-swapper")]
    writeln!(DebugUart {}, "WTS PID{} VA {:x}", candidate.raw_pid(), candidate.vaddr()).ok();
    // this is safe because the page is aligned and initialized as it comes from the kernel
    // remember that this page is overwritten with encrypted data
    let buf: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(vaddr_in_swap as *mut u8, PAGE_SIZE) };

    // search the swap page tables for the next free page
    let mut next_free_page: Option<usize> = None;
    for slot in 0..ss.sct.counts.len() {
        let candidate = (ss.free_swap_search_origin + slot) % ss.sct.counts.len();
        if (ss.sct.counts[candidate] & loader::FLG_SWAP_USED) == 0 {
            #[cfg(feature = "debug-verbose")]
            writeln!(
                DebugUart {},
                "WTS found free page {:x} with contents {:x}",
                candidate,
                ss.sct.counts[candidate]
            )
            .ok();
            next_free_page = Some(candidate);
            break;
        }
    }
    // the swap page it goes to, recorded once the page is released (below)
    let swap_slot = if let Some(free_page_number) = next_free_page {
        ss.free_swap_search_origin = free_page_number + 1; // start search at next page beyond the one about to be used
        // increment the swap counter by one, rolling over if full. Note that we only have 31
        // bits; the MSB is the "swap used" status bit
        let mut count = ss.sct.counts[free_page_number] & !loader::FLG_SWAP_USED;
        count = (count + 1) & !loader::FLG_SWAP_USED;
        ss.sct.counts[free_page_number] = count | loader::FLG_SWAP_USED;
        #[cfg(feature = "debug-verbose")]
        writeln!(
            DebugUart {},
            "WTS ss.sct.counts[{:x}] {:x}",
            free_page_number,
            ss.sct.counts[free_page_number]
        )
        .ok();

        ss.hal.encrypt_swap_to(
            buf,
            count,
            free_page_number * PAGE_SIZE,
            candidate.vaddr(),
            candidate.raw_pid(),
        );
        free_page_number
    } else {
        writeln!(DebugUart {}, "OOM detected, dumping all swap allocs:").ok();
        for (i, &entry) in ss.sct.counts.iter().enumerate() {
            writeln!(DebugUart {}, "  {:04}:{:x}", i, entry).ok();
        }
        // OOS path
        panic!("Ran out of swap space, hard OOM!");
    };

    // step 3: release the page (currently mapped into the swapper's memory space). Need
    // to demonstrate to the memory system that we know what we are
    // doing by also presenting the original PID that owned the page.
    xous::rsyscall(xous::SysCall::SwapOp(
        SwapAbi::ReleaseMemory as usize,
        vaddr_in_swap,
        candidate.raw_pid() as usize,
        0,
        0,
        0,
        0,
    ))
    .expect("Unexpected error: couldn't release a page that was mapped into the swapper's space");
    // maki: the swap page tables' entry for it, made after the release: a table page this needs
    // (the first page swapped out of a 4 MiB region) then comes from the page just freed. Made
    // before, in a hard OOM with nothing free, it had only the handler's few reserved pages, and
    // a round needing more asked the kernel for memory from inside the handler: the kernel's
    // nested hard OOM, and its panic.
    map_swap(ss, swap_slot * PAGE_SIZE, candidate.vaddr(), candidate.raw_pid());
    *pages_to_free -= 1;

    Ok(())
}

/// blocking swap call handler
/// 8 argument values are always pushed on the stack; the meaning is bound differently based upon the specific
/// opcode. Not all arguments are used in all cases, unused argument values have no valid meaning (but in
/// practice typically contain the previous call's value, or 0).
fn swap_handler(
    shared_state: usize,
    opcode: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    _a5: usize,
    _a6: usize,
    _a7: usize,
) {
    // safety: lots of footguns actually, but this is the only way to get this pointer into
    // our context. SharedStateStorage is a Rust structure that is aligned and initialized,
    // so the cast is safe enough, but we have to be careful because this is executed in an
    // interrupt context: we can't wait on locks (they'll hang forever if they are locked).
    let sss = unsafe { &mut *(shared_state as *mut SharedStateStorage) };
    if sss.inner.is_none() {
        // Unearth all of our data trackers in the spots on the map where the loader should have buried them.

        // safety: this is only safe because the loader initializes and aligns the SwapSpec structure:
        //   - The SwapSpec structure is Repr(C), page-aligned, and fully initialized.
        //   - Furthermore, SWAP_CFG_VADDR is already mapped into our address space by the loader; we don't
        //     have to do mapping requests because it's already done for us!
        let swap_spec = unsafe { &*(SWAP_CFG_VADDR as *mut SwapSpec) };

        // reserve memory for hard OOM
        let mut reserved = xous::map_memory(
            None,
            None,
            PAGE_SIZE * HARD_OOM_RESERVED_PAGES,
            MemoryFlags::R | MemoryFlags::W | MemoryFlags::RESERVE,
        )
        .expect("could't reserve space for hard OOM handler");
        // *touch* the memory -- otherwise it might not actually be demand-paged
        let reserved_slice: &mut [u32] = unsafe { reserved.as_slice_mut() }; // this is safe because `u32` is fully representable
        reserved_slice.fill(0);

        // maki: the swap map, for as many pages as swap has, with the pages the loader put there
        let slots = loader::swap::derive_usable_swap(swap_spec.swap_len as usize) / PAGE_SIZE;
        let (map, loader_tables) = swap_map_from_loader(slots, swap_spec.pid_count as usize);

        // swapper is not allowed to use `log` for debugging under most circumstances, because
        // the swapper can't send messages when handling a swap call. Instead, we use a local
        // debug UART to handle this. This needs to be enabled with the "debug-print-swapper" feature
        // and is mutually exclusive with the "gdb-stub" feature in the kernel since it uses
        // the same physical hardware.
        sss.inner = Some(SwapperSharedState {
            // safety: this is only safe because:
            //   - the loader puts the swap root page table pages starting at SWAP_PT_VADDR
            //   - all the page table entries are fully initialized and contains only representable data
            //   - the length of the region is guaranteed by the loader
            map,
            loader_tables,
            hal: SwapHal::new(swap_spec),
            // safety: this is safe because the loader has allocated this region and zeroed the contents,
            // and the length is correctly set up by the loader. Note that the length is slightly
            // longer than it needs to be -- the region that has to be tracked does not include the
            // area of swap dedicated to the MAC table, which swap_len includes.
            sct: SwapCountTracker {
                counts: unsafe {
                    core::slice::from_raw_parts_mut(
                        SWAP_COUNT_VADDR as *mut u32,
                        loader::swap::derive_usable_swap(swap_spec.swap_len as usize) / PAGE_SIZE,
                    )
                },
            },
            sram_start: swap_spec.sram_start as usize,
            sram_size: swap_spec.sram_size as usize,
            free_swap_search_origin: 0,
            hard_oom_alloc_heap: None,
            report_full_rpt: true,
            hard_oom_reserved_page: Some(reserved),
            pages_to_free: HARD_OOM_PAGE_TARGET + HARD_OOM_RESERVED_PAGES,
        });
    }
    let ss = sss.inner.as_mut().expect("Shared state should be initialized");

    let op: Option<KernelOp> = FromPrimitive::from_usize(opcode);
    // #[cfg(feature = "debug-verbose")]
    writeln!(DebugUart {}, "got Opcode: {:?}", op).ok();
    match op {
        Some(KernelOp::ReadFromSwap) => {
            let pid = a2 as u8;
            let vaddr_in_pid = a3;
            let vaddr_in_swap = a4;

            if (vaddr_in_pid & xous::arch::MMAP_VIRT_BASE) == xous::arch::MMAP_VIRT_BASE {
                // data is in the SPINOR, which is by definition located at exactly the offset
                // indicated by the offset from MMAP_VIRT_BASE
                // safety: this is only safe because the pointer we're passed from the kernel is guaranteed to
                // be a valid u8-page in memory

                if RENODE_TESTING {
                    let buf = unsafe {
                        core::slice::from_raw_parts_mut(
                            vaddr_in_swap as *mut u32,
                            PAGE_SIZE / core::mem::size_of::<u32>(),
                        )
                    };
                    // return some dummy data for testing
                    writeln!(DebugUart {}, "********** returning dummy data to: {:x}", vaddr_in_pid).ok();
                    let indicator = vaddr_in_pid as usize & 0xF_F000;
                    for (i, d) in buf[0..32].iter_mut().enumerate() {
                        *d = i as u32 | (0xf00f_0000 + indicator as u32);
                    }
                } else {
                    // `buf` is also exactly one PAGE_SIZE in length, so we don't have to zero-ize it before
                    // using it, as all of it will be overwritten.
                    let buf = unsafe { core::slice::from_raw_parts_mut(vaddr_in_swap as *mut u8, PAGE_SIZE) };
                    let offset = vaddr_in_pid & 0x0FFF_FFFF; // mask out the top nibble to derive the offset in SPI flash
                    ss.hal.flash_read(buf, offset);
                    #[cfg(feature = "debug-print-swapper")]
                    writeln!(DebugUart {}, "RF*F* PID{} VA {:x}, {:x?}", pid, vaddr_in_pid, &buf[..8]).ok();
                }
            } else {
                // walk the PT to find the swap data, and remove it from the swap PT
                let paddr_in_swap = match ss.pt_walk(pid as u8, vaddr_in_pid, true) {
                    Some(paddr) => paddr,
                    None => {
                        writeln!(
                            DebugUart {},
                            "Couldn't resolve swapped data. Was the page actually swapped?"
                        )
                        .ok();
                        panic!("Couldn't resolve swapped data. Was the page actually swapped?")
                    }
                };
                // clear the used bit in swap
                ss.sct.counts[paddr_in_swap / PAGE_SIZE] &= !loader::FLG_SWAP_USED;
                #[cfg(feature = "debug-print-swapper")]
                writeln!(
                    DebugUart {},
                    "RFS PID{} VA {:x} PA {:x} counts {:x}",
                    pid,
                    vaddr_in_pid,
                    paddr_in_swap,
                    ss.sct.counts[paddr_in_swap / PAGE_SIZE]
                )
                .ok();

                // safety: this is only safe because the pointer we're passed from the kernel is guaranteed to
                // be a valid u8-page in memory
                let buf = unsafe { core::slice::from_raw_parts_mut(vaddr_in_swap as *mut u8, PAGE_SIZE) };
                // this is in a retry loop because the SPIM interface can timeout during high bus congestion
                // periods.
                const TIMEOUT_RETRIES: usize = 3;
                let mut retries = 0;
                while retries < TIMEOUT_RETRIES {
                    match ss.hal.decrypt_swap_from(
                        buf,
                        ss.sct.counts[paddr_in_swap / PAGE_SIZE],
                        paddr_in_swap,
                        vaddr_in_pid,
                        pid,
                    ) {
                        Ok(_) => {
                            break;
                        }
                        Err(e) => {
                            retries += 1;
                            writeln!(
                                DebugUart {},
                                "Decryption error: swap image corrupted, the tag does not match the data! {:?} (try {}/{})",
                                e,
                                retries,
                                TIMEOUT_RETRIES
                            )
                            .ok();
                            if retries >= TIMEOUT_RETRIES {
                                panic!(
                                    "Decryption error: swap image corrupted, the tag does not match the data; retry count exceeded!"
                                );
                            }
                        }
                    }
                }
                // at this point, the `buf` has our desired data, we're done, modulo updating the count.
            }
        }
        // HardOom handling will evict any and all pages that it can -- it does no filtering.
        Some(KernelOp::HardOom) => {
            // maki: the process that ran out of memory (0 if the kernel didn't say). Its pages
            // go last: otherwise, with pages taken oldest first, a process working through more
            // memory than fits evicts its own working set to make room for itself.
            let needy = a2 as u8;
            forget_ended(ss);
            forget_freed(ss);

            // be sure to allocate some extra space for the handler itself to run the next time!
            let mut pages_to_free = ss.pages_to_free;

            // free memory for the hard-OOM handler to run
            if let Some(reserved_mem) = ss.hard_oom_reserved_page.take() {
                writeln!(
                    DebugUart {},
                    "Entering HARD OOM attempt to free {} pages - scratch memory: {:x?}",
                    pages_to_free,
                    reserved_mem,
                )
                .ok();
                match xous::unmap_memory(reserved_mem) {
                    Ok(_) => {}
                    Err(e) => {
                        // unmap_memory doesn't work in an IRQ context - so this errors out. Let's
                        // just pray we have enough free memory for the handler to do its thing?
                        writeln!(DebugUart {}, "Likely in IRQ context: {:?} ***************", e).ok();
                        // replace the pages because they weren't unmapped
                        ss.hard_oom_reserved_page = Some(reserved_mem);
                    }
                };
            } else {
                // maki: the last round couldn't take its reserve back (too little was free then).
                // Going on without it is safe now that an eviction pays for its own tables; a
                // panic here takes the whole system down.
                writeln!(DebugUart {}, "Entering HARD OOM without reserved pages").ok();
            }
            // recover the RPT from kernel
            let rpt = unsafe {
                core::slice::from_raw_parts(SWAP_RPT_VADDR as *const SwapAlloc, ss.sram_size / PAGE_SIZE)
            };
            let target_pages = pages_to_free;
            let mut errs: usize = 0;
            let mut wired: usize = 0;
            if let Some(mut alloc_heap) = ss.hard_oom_alloc_heap.take() {
                alloc_heap.clear();
                assert!(alloc_heap.len() == 0);
                for (_i, &entry) in rpt.iter().enumerate() {
                    // filter out invalid, wired, or kernel/swapper candidates
                    if (!entry.is_wired() && entry.is_valid() && entry.raw_pid() != 1 && entry.raw_pid() != 2)
                    // report_full_rpt is used to force the heap to reserve all the data we might need in a future oom
                        || ss.report_full_rpt
                    {
                        //  writeln!(DebugUart {}, "Pushing {:x?}", entry).ok();
                        alloc_heap.push(entry);
                    }
                }
                // Inside the interrupt context, evict pages. No progress on any other process is made until
                // this loop is done. The loop is "inside-out" compared to the EvictPage call
                // -- we can't make calls to the kernel that would cause us to re-enter the
                // swap context, because that would overwrite the stored thread `sepc`. The
                // syscalls used here are all "simple calls" that don't require re-entry
                // into the swapper context to handle.

                // the needy process's own candidates, oldest first, in case others' don't suffice
                // (no allocating in here: a fixed array, and past its end they're taken in turn)
                let mut deferred = [SwapAlloc::from(0); 32];
                let mut deferred_len = 0;
                while pages_to_free > 0 {
                    if let Some(candidate) = alloc_heap.pop() {
                        if candidate.is_wired()
                            || !candidate.is_valid()
                            || candidate.raw_pid() == 1
                            || candidate.raw_pid() == 2
                        {
                            wired += 1;
                        } else if needy != 0 && candidate.raw_pid() == needy && deferred_len < deferred.len()
                        {
                            deferred[deferred_len] = candidate;
                            deferred_len += 1;
                        } else {
                            // errors are ignored because the correct behavior on error is to try another page
                            write_to_swap_inner(ss, candidate, &mut errs, &mut pages_to_free).ok();
                        }
                    } else if deferred_len > 0 {
                        for &candidate in deferred[..deferred_len].iter() {
                            if pages_to_free == 0 {
                                break;
                            }
                            write_to_swap_inner(ss, candidate, &mut errs, &mut pages_to_free).ok();
                        }
                        deferred_len = 0;
                    } else {
                        writeln!(
                            DebugUart {},
                            "Ran out of swappable candidates before we could free the requested number of pages!"
                        )
                        .ok();
                        break;
                    }
                }
                // put the alloc heap back into the shared state
                ss.hard_oom_alloc_heap = Some(alloc_heap);
            } else {
                // The heap is made at boot, but a boot racing for RAM can get here first. The
                // handler can't allocate, and mustn't panic (a panic makes syscalls that let
                // other processes run mid-OOM): evict in table order, not oldest first.
                for &entry in rpt.iter() {
                    if pages_to_free == 0 {
                        break;
                    }
                    if entry.is_wired() || !entry.is_valid() || entry.raw_pid() == 1 || entry.raw_pid() == 2 {
                        wired += 1;
                    } else {
                        write_to_swap_inner(ss, entry, &mut errs, &mut pages_to_free).ok();
                    }
                }
            }
            writeln!(
                DebugUart {},
                "Exiting HARD OOM swap free loop: freed {} pages; {} requests rejected, {} wired",
                target_pages - pages_to_free,
                errs,
                wired
            )
            .ok();
            //  Restore some reserved memory for the next hard OOM invocation.
            // maki: only if that much is free: touching it with less would ask the kernel for
            // memory from inside this handler (its nested hard OOM, and a panic). A round that
            // freed too little tries again at the end of the next.
            if ss.hard_oom_reserved_page.is_none() && free_pages_quietly() >= HARD_OOM_RESERVED_PAGES + 2 {
                let mut reserved = xous::map_memory(
                    None,
                    None,
                    PAGE_SIZE * HARD_OOM_RESERVED_PAGES,
                    MemoryFlags::R | MemoryFlags::W | MemoryFlags::RESERVE,
                )
                .expect("could't reserve space for hard OOM handler");
                // *touch* the memory -- otherwise it might not actually be demand-paged
                let reserved_slice: &mut [u32] = unsafe { reserved.as_slice_mut() }; // this is safe because `u32` is fully representable
                reserved_slice.fill(0);
                ss.hard_oom_reserved_page = Some(reserved);
            }
            if ss.report_full_rpt {
                ss.report_full_rpt = false;
            }
        }
        // This just writes data to FLASH, but does not de-allocate the page
        Some(KernelOp::WriteToFlash) => {
            let vaddr_in_swap = a2;
            let flash_offset = a3;

            let buf = unsafe { core::slice::from_raw_parts(vaddr_in_swap as *const u8, PAGE_SIZE) };
            let offset = flash_offset & 0x0FFF_FFFF;
            if !RENODE_TESTING {
                #[cfg(feature = "debug-print-swapper")]
                writeln!(DebugUart {}, "WT*F*: VA {:x} buf {:x?}", offset, &buf[..8]).ok();
                ss.hal.flash_write(buf, offset);
            }
        }
        Some(KernelOp::BulkErase) => {
            let offset = a2;
            let len = a3;
            if !RENODE_TESTING {
                #[cfg(feature = "debug-print-swapper")]
                writeln!(DebugUart {}, "BE: PA {:x} len {:x}", offset, len).ok();
                ss.hal.block_erase(offset, len);
            }
        }
        _ => {
            writeln!(DebugUart {}, "Unimplemented or unknown opcode: {}", opcode).ok();
        }
    }
}

fn main() {
    // maki: the swapper's own panics can't print (its UART is compiled out, and one in a hard OOM
    // happens while nothing else can run): the kernel says where it was, so the one that follows
    // ('Nesting should not happen', as other processes run mid-OOM) isn't all there is to go on
    std::panic::set_hook(Box::new(|info| {
        let line = info.location().map(|l| l.line()).unwrap_or(0) as usize;
        xous::rsyscall(xous::SysCall::SwapOp(SwapAbi::Panicked as usize, line, 0, 0, 0, 0, 0)).ok();
    }));
    let mut sss = Box::new(SharedStateStorage { inner: None });
    sss.init();

    // wait for the share storage to become initialized, happens inside the handler
    // on the first call the kernel makes back. Usually it's done by now (by an alloc
    // advisory), but this check just ensures that happens.
    while sss.inner.is_none() {
        xous::yield_slice();
    }
    // maki: the swap page tables the loader made, now in the swap map: back to the kernel, from
    // here (the handler that made the map can't unmap). The handler never looks at them again.
    let (tables, len) = core::mem::take(&mut sss.inner.as_mut().unwrap().loader_tables);
    if len != 0 {
        // safety: the loader mapped these pages for the swapper alone, and nothing refers to them now
        match xous::unmap_memory(unsafe { MemoryRange::new(tables, len).unwrap() }) {
            Ok(()) => {
                writeln!(DebugUart {}, "gave back {} pages of loader swap tables", len / PAGE_SIZE).ok()
            }
            Err(e) => writeln!(DebugUart {}, "couldn't give back the loader's swap tables: {:?}", e).ok(),
        };
    }
    // measure memory at boot
    get_free_pages();
    let total_ram = sss.inner.as_ref().unwrap().sram_size;
    // Binary heap for storing the view of the memory allocations. Made before anything else,
    // the log server included: a boot with many processes can run out of RAM, and call the hard
    // OOM handler, before the log server is up, and the handler can't allocate this itself.
    sss.inner.as_mut().unwrap().hard_oom_alloc_heap = Some(BinaryHeap::with_capacity(total_ram / PAGE_SIZE));

    // Do a single invocation at boot with 0 pages to free, to ensure that the page maps are set up,
    // and sufficient heap has been allocated for the swapper to run in case of a hard OOM. Failure to
    // do this can lead to missing L1 PT entries for the RPT mapping back into user space if the first
    // hard-OOM happens before the OOM-doom routine can run. All of swapper's memory is `wired`, so,
    // once we've done a dry-run, this memory stays ours forever.
    sss.inner.as_mut().unwrap().report_full_rpt = true;
    sss.inner.as_mut().unwrap().pages_to_free = 2;
    xous::rsyscall(xous::SysCall::SwapOp(SwapAbi::ClearMemoryNow as usize, 0, 0, 0, 0, 0, 0))
        .expect("ClearMemoryNow syscall failed");
    // restore the normal parameters
    sss.inner.as_mut().unwrap().report_full_rpt = false;
    sss.inner.as_mut().unwrap().pages_to_free = HARD_OOM_PAGE_TARGET + HARD_OOM_RESERVED_PAGES;

    // init the log, but this is mostly unused.
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("my PID is {}", xous::process::id());

    // This thread is for testing
    #[cfg(feature = "swap-userspace-testing")]
    std::thread::spawn({
        let conn = conn.clone();
        move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(10_200));
                xous::send_message(
                    conn,
                    xous::Message::new_scalar(Opcode::Test0.to_usize().unwrap(), 0, 0, 0, 0),
                )
                .ok();
            }
        }
    });

    // This thread pings the free memory level and will try to clear memory to avoid OOM
    // This claims sss, and is mutually exclusive with other options that claim sss
    #[cfg(feature = "oom-doom")]
    std::thread::spawn({
        move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(OOM_DOOM_POLL_INTERVAL_MS));
                if get_free_pages() < OOM_DOOM_PAGE_TARGET {
                    sss.inner.as_mut().unwrap().pages_to_free = OOM_DOOM_PAGE_TARGET;
                    xous::rsyscall(xous::SysCall::SwapOp(SwapAbi::ClearMemoryNow as usize, 0, 0, 0, 0, 0, 0))
                        .expect("ClearMemoryNow syscall failed");
                    sss.inner.as_mut().unwrap().pages_to_free = HARD_OOM_PAGE_TARGET;
                }
            }
        }
    });

    let xns = xous_api_names::XousNames::new().unwrap();
    let sid = xns.register_name(xous_swapper::SWAPPER_PUBLIC_NAME, None).unwrap();

    let mut msg_opt = None;
    loop {
        xous::reply_and_receive_next(sid, &mut msg_opt).unwrap();
        let msg = msg_opt.as_mut().unwrap();
        let op: Option<Opcode> = FromPrimitive::from_usize(msg.body.id());
        log::debug!("Swapper got {:x?}", op);
        match op {
            Some(Opcode::GarbageCollect) => {
                if let Some(scalar) = msg.body.scalar_message_mut() {
                    let pages = scalar.arg1;
                    if pages > HARD_OOM_PAGE_TARGET * 2 {
                        log::warn!(
                            "Not honoring excessive GC request, reducing to {} pages",
                            HARD_OOM_PAGE_TARGET * 2
                        );
                    }
                    sss.inner.as_mut().unwrap().pages_to_free = pages.max(HARD_OOM_PAGE_TARGET * 2);
                    xous::rsyscall(xous::SysCall::SwapOp(SwapAbi::ClearMemoryNow as usize, 0, 0, 0, 0, 0, 0))
                        .expect("ClearMemoryNow syscall failed");
                    sss.inner.as_mut().unwrap().pages_to_free = HARD_OOM_PAGE_TARGET;
                    let free_pages = get_free_pages();
                    log::info!("Free pages after GC: {}", free_pages);
                    // return the current free page count
                    scalar.arg1 = free_pages;
                }
            }
            Some(Opcode::WritePage) => {
                let mem_msg = msg.body.memory_message().unwrap();
                let offset = mem_msg.offset.expect("malformed WritePage").get();
                // eliminate the code path entirely to speed things up a bit
                /*
                log::debug!(
                    "WritePage: PID{}, offset {:x}, vaddr_buf {:x}",
                    msg.sender.pid().unwrap().get() as usize,
                    offset,
                    mem_msg.buf.as_ptr() as usize
                ); */
                xous::rsyscall(xous::SysCall::SwapOp(
                    SwapAbi::WritePage as usize,
                    msg.sender.pid().unwrap().get() as usize,
                    offset,
                    mem_msg.buf.as_ptr() as usize,
                    0,
                    0,
                    0,
                ))
                .expect("couldn't WritePage");
            }
            Some(Opcode::BulkErase) => {
                if let Some(scalar) = msg.body.scalar_message_mut() {
                    let block = scalar.arg1;
                    let len = scalar.arg2;
                    xous::rsyscall(xous::SysCall::SwapOp(
                        SwapAbi::BlockErase as usize,
                        msg.sender.pid().unwrap().get() as usize,
                        block,
                        len,
                        0,
                        0,
                        0,
                    ))
                    .expect("couldn't Block Erase region");
                }
            }
            Some(Opcode::DebugServers) => {
                xous::rsyscall(xous::SysCall::SwapOp(SwapAbi::DebugServers as usize, 0, 0, 0, 0, 0, 0))
                    .unwrap();
            }
            #[cfg(feature = "swap-userspace-testing")]
            Some(Opcode::Test0) => {
                log::info!("Free mem: {}kiB", get_free_pages() * PAGE_SIZE / 1024);
            }
            _ => {
                log::info!("Unknown opcode {:?}", op);
            }
        }
    }
}
