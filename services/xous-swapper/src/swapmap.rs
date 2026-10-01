// Added for maki (a fork of Xous: github.com/KaraZajac/maki-firmware) in 2026, under its crate's license.

//! Where each page out in swap belongs: (PID, page) -> its offset in swap.
//!
//! One table, sized by swap and made once, in place of a page table per process: those took a
//! 4 KiB page for every 4 MiB of a process's address space with anything swapped in it, made as
//! pages went out and never freed (all of the swapper's memory is wired), which came to a sixth
//! of RAM, and a page made while evicting. This one holds at most one entry per page of swap, so
//! with twice as many places as swap has pages it never fills, and nothing is made later.
//!
//! Open addressing with linear probing; a removal shifts the entries after it back, so there
//! are no tombstones and lookups stay short however long maki runs.

/// A key: the PID in the top bits, the page's number below. Never 0 (PID 0 owns nothing), which
/// marks an empty place.
fn key(pid: u8, vaddr: usize) -> u32 { (pid as u32) << 20 | (vaddr >> 12) as u32 & 0xF_FFFF }

pub fn pid_of(key: u32) -> u8 { (key >> 20) as u8 }

#[cfg(test)]
pub fn vaddr_of(key: u32) -> usize { ((key & 0xF_FFFF) as usize) << 12 }

pub struct SwapMap {
    keys: &'static mut [u32],
    /// the page's offset in swap
    offsets: &'static mut [u32],
    bits: u32,
}

impl SwapMap {
    /// The number of places for a swap of `pages` pages: twice as many, a power of two.
    pub fn places_for(pages: usize) -> usize { (pages.max(1) * 2).next_power_of_two() }

    /// A map over `keys` and `offsets`, which must be zeroed and the same length, a power of two.
    pub fn new(keys: &'static mut [u32], offsets: &'static mut [u32]) -> SwapMap {
        assert!(keys.len() == offsets.len() && keys.len().is_power_of_two());
        let bits = keys.len().trailing_zeros();
        SwapMap { keys, offsets, bits }
    }

    fn mask(&self) -> usize { self.keys.len() - 1 }

    /// Where a key's search starts (Fibonacci hashing: a page's neighbours land far apart).
    fn home(&self, key: u32) -> usize {
        if self.bits == 0 {
            return 0;
        }
        (key.wrapping_mul(0x9E37_79B9) >> (32 - self.bits)) as usize
    }

    fn find(&self, key: u32) -> Option<usize> {
        let mut i = self.home(key);
        loop {
            match self.keys[i] {
                0 => return None,
                k if k == key => return Some(i),
                _ => i = (i + 1) & self.mask(),
            }
        }
    }

    pub fn get(&self, pid: u8, vaddr: usize) -> Option<u32> {
        self.find(key(pid, vaddr)).map(|i| self.offsets[i])
    }

    /// Records where `pid`'s page at `vaddr` is in swap; the offset it had before, if it had one.
    /// Panics if the map is full, which it can't be while it has more places than swap has pages.
    pub fn insert(&mut self, pid: u8, vaddr: usize, offset: u32) -> Option<u32> {
        let key = key(pid, vaddr);
        assert!(key != 0, "a swap map key can't be 0");
        let mut i = self.home(key);
        for _ in 0..self.keys.len() {
            match self.keys[i] {
                0 => {
                    self.keys[i] = key;
                    self.offsets[i] = offset;
                    return None;
                }
                k if k == key => return Some(core::mem::replace(&mut self.offsets[i], offset)),
                _ => i = (i + 1) & self.mask(),
            }
        }
        panic!("the swap map is full");
    }

    /// Forgets `pid`'s page at `vaddr`; where in swap it was, if it was.
    pub fn remove(&mut self, pid: u8, vaddr: usize) -> Option<u32> {
        let i = self.find(key(pid, vaddr))?;
        let offset = self.offsets[i];
        self.remove_at(i);
        Some(offset)
    }

    /// Empties place `i`, and shifts back the entries after it that searched past it, so every
    /// entry stays reachable from its home with no empty place between.
    fn remove_at(&mut self, mut i: usize) {
        let mask = self.mask();
        let mut j = i;
        loop {
            j = (j + 1) & mask;
            let k = self.keys[j];
            if k == 0 {
                break;
            }
            // the entry at j stays if its home lies cyclically in (i, j]
            let home = self.home(k);
            let stays = if i <= j { i < home && home <= j } else { i < home || home <= j };
            if !stays {
                self.keys[i] = k;
                self.offsets[i] = self.offsets[j];
                i = j;
            }
        }
        self.keys[i] = 0;
        self.offsets[i] = 0;
    }

    /// Forgets every entry whose key `drop` says to, telling `dropped` each offset.
    pub fn forget(&mut self, mut drop: impl FnMut(u32) -> bool, mut dropped: impl FnMut(u32)) {
        let mut i = 0;
        while i < self.keys.len() {
            let k = self.keys[i];
            if k != 0 && drop(k) {
                dropped(self.offsets[i]);
                // an entry shifted back into `i` is looked at next
                self.remove_at(i);
            } else {
                i += 1;
            }
        }
    }

    /// How many pages are out in swap.
    pub fn len(&self) -> usize { self.keys.iter().filter(|&&k| k != 0).count() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(places: usize) -> SwapMap {
        let keys = Box::leak(vec![0u32; places].into_boxed_slice());
        let offsets = Box::leak(vec![0u32; places].into_boxed_slice());
        SwapMap::new(keys, offsets)
    }

    #[test]
    fn keeps_and_forgets_pages_by_process_and_address() {
        let mut m = map(16);
        assert_eq!(m.insert(3, 0x2000_1000, 0x5000), None);
        assert_eq!(m.insert(4, 0x2000_1000, 0x6000), None);
        assert_eq!(m.get(3, 0x2000_1000), Some(0x5000));
        assert_eq!(m.get(4, 0x2000_1abc), Some(0x6000), "the offset in the page doesn't matter");
        assert_eq!(m.insert(3, 0x2000_1000, 0x7000), Some(0x5000), "replaced, saying what it was");
        assert_eq!(m.remove(3, 0x2000_1000), Some(0x7000));
        assert_eq!(m.get(3, 0x2000_1000), None);
        assert_eq!(m.remove(3, 0x2000_1000), None);
        assert_eq!(m.len(), 1);
    }

    // against a plain map, through churn that fills it to half and empties it again, many times:
    // every page findable, and nothing found that isn't there
    #[test]
    fn matches_a_plain_map_through_churn() {
        use std::collections::HashMap;
        let pages = 512;
        let mut m = map(SwapMap::places_for(pages));
        let mut truth: HashMap<(u8, usize), u32> = HashMap::new();
        let mut seed = 0x1234_5678u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        for round in 0..200_000 {
            let pid = (next() % 20 + 1) as u8;
            // addresses that crowd together, as a process's pages do
            let base = if round % 3 == 0 { 0x2000_0000 } else { 0x7fff_0000 };
            let vaddr = base | ((next() % 64) as usize) << 12;
            if next() % 2 == 0 && truth.len() < pages {
                let off = next() & !0xFFF;
                assert_eq!(m.insert(pid, vaddr, off), truth.insert((pid, vaddr), off));
            } else {
                assert_eq!(m.remove(pid, vaddr), truth.remove(&(pid, vaddr)));
            }
            if round % 10_000 == 0 {
                for (&(pid, vaddr), &off) in &truth {
                    assert_eq!(m.get(pid, vaddr), Some(off));
                }
                assert_eq!(m.len(), truth.len());
            }
        }
    }

    #[test]
    fn forgets_a_process_and_keeps_the_rest_findable() {
        let mut m = map(64);
        for p in 1..=6u8 {
            for v in 0..5usize {
                m.insert(p, 0x2000_0000 + (v << 12), (p as u32) << 16 | v as u32);
            }
        }
        let mut freed = Vec::new();
        m.forget(|k| pid_of(k) == 3 || pid_of(k) == 5, |off| freed.push(off));
        freed.sort();
        assert_eq!(freed.len(), 10);
        assert!(freed.iter().all(|off| off >> 16 == 3 || off >> 16 == 5));
        for p in [1u8, 2, 4, 6] {
            for v in 0..5usize {
                assert_eq!(m.get(p, 0x2000_0000 + (v << 12)), Some((p as u32) << 16 | v as u32));
            }
        }
        assert_eq!(m.len(), 20);
    }

    #[test]
    fn keys_say_whose_page_and_where() {
        let k = key(17, 0x7fff_e000);
        assert_eq!((pid_of(k), vaddr_of(k)), (17, 0x7fff_e000));
    }
}
