//! Native maki apps (ARCHITECTURE.md, "One bundle, two kinds of code"): an ordinary Xous
//! program, a static RISC-V ELF, run in a process of its own that the kernel confines. This is
//! what maki checks of the ELF before it installs one or loads it: everything the loader will
//! map comes from here, so nothing it maps is anything this didn't check.
//!
//! The rules: a 32-bit little-endian RISC-V executable, static (no interpreter, nothing
//! dynamic); segments inside the app's address range, not overlapping, none both writable and
//! executable, and their memory within the app's limit; the entry point in an executable one.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod draw;

use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;

/// Where an app's segments may go: above the null page, below where the loader's stub and
/// the app's stack and heap live.
pub const APP_SPACE: Range<u32> = 0x0001_0000..0x2000_0000;
pub const PAGE: u32 = 4096;
/// The most program headers an app's ELF may have.
pub const MAX_HEADERS: usize = 16;

const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const PT_PHDR: u32 = 6;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PT_RISCV_ATTRIBUTES: u32 = 0x7000_0003;

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

const EM_RISCV: u16 = 243;
const ET_EXEC: u16 = 2;
/// RVC, soft float: what riscv32imac builds are.
const EF_ALLOWED: u32 = 0x1;

/// A segment the loader maps: `memory` in the app's address space, the first `file.len()`
/// bytes of it from the ELF, the rest zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub memory: Range<u32>,
    pub file: Range<usize>,
    pub writable: bool,
    pub executable: bool,
}

/// An app's ELF, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub entry: u32,
    pub segments: Vec<Segment>,
}

impl Program {
    /// Memory the segments take, in whole pages.
    pub fn pages(&self) -> u32 {
        self.segments.iter().map(|s| (page_up(s.memory.end) - page_down(s.memory.start)) / PAGE).sum()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not an ELF, cut short, or the wrong kind: what's wrong.
    Format(&'static str),
    /// A program header maki doesn't run: dynamic linking, thread-local storage, anything
    /// it doesn't know.
    Header(u32),
    /// A segment outside the app's space, overlapping another, or with its bytes outside the
    /// file.
    Layout(&'static str),
    /// A segment both writable and executable.
    WritableCode,
    /// More memory than the app's limit allows: the pages it needs.
    TooBig(u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Format(why) => write!(f, "not a native maki app: {why}"),
            Error::Header(t) => write!(f, "a program header maki doesn't run (type {t:#x})"),
            Error::Layout(why) => write!(f, "its segments don't fit: {why}"),
            Error::WritableCode => write!(f, "a segment is both writable and executable"),
            Error::TooBig(pages) => write!(f, "its code and data need {} KiB, more than its memory", pages * 4),
        }
    }
}

fn page_down(a: u32) -> u32 { a & !(PAGE - 1) }

fn page_up(a: u32) -> u32 { a.saturating_add(PAGE - 1) & !(PAGE - 1) }

fn u16_at(b: &[u8], at: usize) -> Result<u16, Error> {
    b.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or(Error::Format("cut short"))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, Error> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or(Error::Format("cut short"))
}

/// Checks `elf` as an app with `memory_kib` of memory; what the loader maps, if it's fine.
pub fn check(elf: &[u8], memory_kib: u32) -> Result<Program, Error> {
    if elf.get(..4) != Some(b"\x7fELF") {
        return Err(Error::Format("not an ELF"));
    }
    if elf.get(4..7) != Some(&[1, 1, 1]) {
        return Err(Error::Format("not a 32-bit little-endian ELF"));
    }
    if u16_at(elf, 16)? != ET_EXEC {
        return Err(Error::Format("not an executable"));
    }
    if u16_at(elf, 18)? != EM_RISCV {
        return Err(Error::Format("not for RISC-V"));
    }
    if u32_at(elf, 36)? & !EF_ALLOWED != 0 {
        return Err(Error::Format("not built for maki's processor (riscv32imac)"));
    }
    let entry = u32_at(elf, 24)?;
    let phoff = u32_at(elf, 28)? as usize;
    let phentsize = u16_at(elf, 42)? as usize;
    let phnum = u16_at(elf, 44)? as usize;
    if phentsize != 32 || phnum == 0 || phnum > MAX_HEADERS {
        return Err(Error::Format("program headers"));
    }
    let mut segments: Vec<Segment> = Vec::new();
    for i in 0..phnum {
        let at = phoff.checked_add(i * 32).ok_or(Error::Format("cut short"))?;
        let kind = u32_at(elf, at)?;
        let (offset, vaddr, filesz, memsz, flags) =
            (u32_at(elf, at + 4)?, u32_at(elf, at + 8)?, u32_at(elf, at + 16)?, u32_at(elf, at + 20)?, u32_at(elf, at + 24)?);
        match kind {
            PT_LOAD => {}
            // read by nothing but the app itself, if anything
            PT_NULL | PT_NOTE | PT_PHDR | PT_GNU_EH_FRAME | PT_GNU_RELRO | PT_RISCV_ATTRIBUTES => continue,
            PT_GNU_STACK if flags & PF_X == 0 => continue,
            PT_GNU_STACK => return Err(Error::WritableCode),
            other => return Err(Error::Header(other)),
        }
        if memsz == 0 {
            continue;
        }
        if filesz > memsz {
            return Err(Error::Layout("more bytes in the file than in memory"));
        }
        let file_end = (offset as usize).checked_add(filesz as usize).ok_or(Error::Layout("bytes outside the file"))?;
        if file_end > elf.len() {
            return Err(Error::Layout("bytes outside the file"));
        }
        let end = vaddr.checked_add(memsz).ok_or(Error::Layout("outside the app's space"))?;
        if vaddr < APP_SPACE.start || end > APP_SPACE.end {
            return Err(Error::Layout("outside the app's space"));
        }
        if flags & PF_W != 0 && flags & PF_X != 0 {
            return Err(Error::WritableCode);
        }
        if flags & (PF_R | PF_W | PF_X) == 0 {
            return Err(Error::Layout("a segment with no access at all"));
        }
        let memory = vaddr..end;
        // whole pages: two segments may not share one
        if segments.iter().any(|s| page_down(s.memory.start) < page_up(end) && page_down(vaddr) < page_up(s.memory.end)) {
            return Err(Error::Layout("segments overlap"));
        }
        segments.push(Segment { memory, file: offset as usize..file_end, writable: flags & PF_W != 0, executable: flags & PF_X != 0 });
    }
    if !segments.iter().any(|s| s.executable && s.memory.contains(&entry)) {
        return Err(Error::Format("the entry point isn't in its code"));
    }
    let program = Program { entry, segments };
    let pages = program.pages();
    if pages * PAGE > memory_kib.saturating_mul(1024) {
        return Err(Error::TooBig(pages));
    }
    Ok(program)
}
