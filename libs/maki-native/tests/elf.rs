//! The checks maki makes of a native app's ELF.

use maki_native::*;

/// (type, offset, vaddr, filesz, memsz, flags)
type Ph = (u32, u32, u32, u32, u32, u32);

const R: u32 = 4;
const RW: u32 = 6;
const RX: u32 = 5;
const RWX: u32 = 7;

/// A RISC-V executable with these program headers, and `size` bytes in all.
fn elf(entry: u32, headers: &[Ph], size: usize) -> Vec<u8> {
    let mut b = vec![0u8; size.max(52 + 32 * headers.len())];
    b[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
    b[16..18].copy_from_slice(&2u16.to_le_bytes()); // EXEC
    b[18..20].copy_from_slice(&243u16.to_le_bytes()); // RISC-V
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..28].copy_from_slice(&entry.to_le_bytes());
    b[28..32].copy_from_slice(&52u32.to_le_bytes());
    b[36..40].copy_from_slice(&1u32.to_le_bytes()); // RVC
    b[42..44].copy_from_slice(&32u16.to_le_bytes());
    b[44..46].copy_from_slice(&(headers.len() as u16).to_le_bytes());
    for (i, &(t, off, va, fs, ms, fl)) in headers.iter().enumerate() {
        let at = 52 + 32 * i;
        for (j, v) in [t, off, va, va, fs, ms, fl, 0x1000].iter().enumerate() {
            b[at + 4 * j..at + 4 * j + 4].copy_from_slice(&v.to_le_bytes());
        }
    }
    b
}

/// Code at 0x10000 (4 KiB), read-only data after it, then data and zeroed memory.
fn typical() -> Vec<(u32, u32, u32, u32, u32, u32)> {
    vec![
        (1, 0x1000, 0x10000, 0x1000, 0x1000, RX),
        (1, 0x2000, 0x11000, 0x800, 0x800, R),
        (1, 0x2800, 0x12000, 0x100, 0x3000, RW),
        (0x6474_e551, 0, 0, 0, 0, RW), // GNU_STACK
        (0x7000_0003, 0x2900, 0, 0x40, 0x40, R), // RISCV_ATTRIBUTES
    ]
}

#[test]
fn a_typical_program_checks_out() {
    let p = check(&elf(0x10010, &typical(), 0x3000), 64).unwrap();
    assert_eq!(p.entry, 0x10010);
    let segments: Vec<_> = p.segments().collect();
    assert_eq!(segments.len(), 3);
    assert_eq!(*segments[2], Segment { memory: 0x12000..0x15000, file: 0x2800..0x2900, writable: true, executable: false });
    assert_eq!(p.pages(), 5);
    // 20 KiB of pages: not in 16
    assert_eq!(check(&elf(0x10010, &typical(), 0x3000), 16), Err(Error::TooBig(5)));
}

#[test]
fn not_what_maki_runs() {
    let good = elf(0x10010, &typical(), 0x3000);
    assert!(matches!(check(b"MZ not an elf", 64), Err(Error::Format(_))));
    let mut b = good.clone();
    b[4] = 2; // 64-bit
    assert!(matches!(check(&b, 64), Err(Error::Format(_))));
    let mut b = good.clone();
    b[18] = 62; // x86-64
    assert!(matches!(check(&b, 64), Err(Error::Format(_))));
    let mut b = good.clone();
    b[36] = 5; // double-float ABI
    assert!(matches!(check(&b, 64), Err(Error::Format(_))));
    let mut b = good.clone();
    b[16] = 3; // shared object
    assert!(matches!(check(&b, 64), Err(Error::Format(_))));
    // cut short in its headers, and then short of its segments' bytes
    assert_eq!(check(&good[..70], 64), Err(Error::Format("cut short")));
    assert!(matches!(check(&good[..200], 64), Err(Error::Layout(_))));
}

#[test]
fn nothing_dynamic_nor_anything_unknown() {
    for t in [2u32, 3, 7, 0x6000_0000] {
        let mut h = typical();
        h.push((t, 0, 0, 0, 0, R));
        assert_eq!(check(&elf(0x10010, &h, 0x3000), 64), Err(Error::Header(t)));
    }
}

#[test]
fn segments_stay_in_the_app_space_and_apart() {
    let with = |seg: (u32, u32, u32, u32, u32, u32)| {
        let mut h = typical();
        h.push(seg);
        check(&elf(0x10010, &h, 0x3000), 1024)
    };
    // the null page, and past the top
    assert!(matches!(with((1, 0, 0x0, 0x10, 0x10, R)), Err(Error::Layout(_))));
    assert!(matches!(with((1, 0, 0x1fff_f000, 0x10, 0x2000, R)), Err(Error::Layout(_))));
    assert!(matches!(with((1, 0, 0xffff_f000, 0x10, 0x2000, R)), Err(Error::Layout(_))));
    // on a page another has
    assert!(matches!(with((1, 0, 0x12800, 0x10, 0x10, R)), Err(Error::Layout(_))));
    // bytes the file hasn't got
    assert!(matches!(with((1, 0x2f00, 0x40000, 0x200, 0x200, R)), Err(Error::Layout(_))));
    // more in the file than in memory
    assert!(matches!(with((1, 0, 0x40000, 0x20, 0x10, R)), Err(Error::Layout(_))));
    // writable code
    assert_eq!(with((1, 0, 0x40000, 0x10, 0x10, RWX)), Err(Error::WritableCode));
    assert_eq!(with((0x6474_e551, 0, 0, 0, 0, RWX)), Err(Error::WritableCode));
    // a page apart is fine
    assert!(with((1, 0, 0x40000, 0x10, 0x10, R)).is_ok());
}

#[test]
fn the_entry_is_in_code() {
    assert!(matches!(check(&elf(0x11010, &typical(), 0x3000), 64), Err(Error::Format(_)))); // data
    assert!(matches!(check(&elf(0x90000, &typical(), 0x3000), 64), Err(Error::Format(_))));
}

/// A real Xous program, if the firmware has been built: the loader's rules fit what the
/// toolchain makes.
#[test]
fn a_real_xous_program_checks_out() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/riscv32imac-unknown-xous-elf/release/maki-app-host");
    let Ok(bytes) = std::fs::read(path) else { return };
    let p = check(&bytes, 4096).unwrap();
    assert_eq!(p.segments().filter(|s| s.executable).count(), 1);
}

/// Whatever the bytes, the check answers: it never panics, and what it passes is inside the
/// file and the app's space.
#[test]
fn nothing_panics_it() {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut rng = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let base = elf(0x10010, &typical(), 0x3000);
    for _ in 0..100_000 {
        let mut b = base.clone();
        for _ in 0..(rng() % 8 + 1) {
            let at = (rng() % 200) as usize; // the headers, mostly
            b[at] = rng() as u8;
        }
        if rng() % 16 == 0 {
            b.truncate((rng() % b.len() as u64) as usize);
        }
        if let Ok(p) = check(&b, 1 << 20) {
            for s in p.segments() {
                assert!(s.file.end <= b.len());
                assert!(APP_SPACE.start <= s.memory.start && s.memory.end <= APP_SPACE.end);
                assert!(!(s.writable && s.executable));
            }
        }
    }
}
