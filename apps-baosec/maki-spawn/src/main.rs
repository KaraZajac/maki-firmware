//! The stub a native maki app starts in (ARCHITECTURE.md, "Native apps: what confinement
//! takes"). maki's app host creates a process from it and lends it the app's ELF
//! (`maki_native::load`); the stub checks it again, maps its segments (code read and execute,
//! nothing both writable and executable), connects to the servers the app may use, sets its
//! heap to what's left of the app's memory, answers, and then confines itself for good
//! (`xous::confine_self`) before it jumps to the app: none of the app's code runs unconfined.
//!
//! No allocator, no statics, no logging: all it has is its stack.

#![no_std]
#![no_main]

use maki_native::load::*;
use maki_native::PAGE;
use xous::{MemoryAddress, MemoryFlags, SID};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { xous::terminate_process(BAD_REQUEST) }

fn u32_at(b: &[u8], at: usize) -> u32 { u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) }

/// What loading needs to carry on once the loader has its answer.
struct Loaded {
    entry: usize,
    budget: usize,
}

/// Maps the app into this process and connects it: the answer for the loader, and what's
/// needed to start the app.
fn load(buf: &mut [u8]) -> Result<Loaded, u32> {
    if buf.len() < HEADER {
        return Err(BAD_REQUEST);
    }
    let memory_kib = u32_at(buf, AT_MEMORY_KIB);
    let elf_len = u32_at(buf, AT_ELF_LEN) as usize;
    let stack_pages = u32_at(buf, AT_STACK_KIB) / 4;
    let elf = buf.get(HEADER..HEADER.checked_add(elf_len).ok_or(BAD_REQUEST)?).ok_or(BAD_REQUEST)?;
    let program = maki_native::check(elf, memory_kib).map_err(|_| BAD_ELF)?;

    // the app's memory: its segments, its stack, and what's left for its heap and anything else
    let pages = (memory_kib / 4).checked_sub(program.pages() + stack_pages).ok_or(NO_ROOM)?;

    for segment in program.segments() {
        let base = segment.memory.start & !(PAGE - 1);
        let end = (segment.memory.end + PAGE - 1) & !(PAGE - 1);
        let mut flags = MemoryFlags::R | MemoryFlags::W;
        if segment.executable {
            flags |= MemoryFlags::X;
        }
        let mut range = xous::map_memory(
            None,
            MemoryAddress::new(base as usize),
            (end - base) as usize,
            flags,
        )
        .map_err(|_| CANT_MAP)?;
        let dest = unsafe { range.as_slice_mut::<u8>() };
        let at = (segment.memory.start - base) as usize;
        let bytes = &elf[segment.file.clone()];
        dest[..at].fill(0);
        dest[at..at + bytes.len()].copy_from_slice(bytes);
        dest[at + bytes.len()..].fill(0);
        // then no longer writable, unless it's data
        if !segment.writable {
            let mut keep = MemoryFlags::R;
            if segment.executable {
                keep |= MemoryFlags::X;
            }
            xous::update_memory_flags(range, keep).map_err(|_| CANT_MAP)?;
        }
    }

    // the servers the app may use: after it's confined, connecting again to one of these
    // returns the connection made here, and nothing else can be connected to
    for sid in [TICKTIMER, LOG, APP_SERVICE] {
        xous::try_connect(SID::from_bytes(&sid).ok_or(CANT_CONNECT)?).map_err(|_| CANT_CONNECT)?;
    }

    // the heap may take what's left: read the limit, then set it
    let heap = pages as usize * PAGE as usize;
    if let Ok(xous::Result::Scalar2(_, current)) = xous::rsyscall(xous::SysCall::AdjustProcessLimit(1, 0, 0)) {
        xous::rsyscall(xous::SysCall::AdjustProcessLimit(1, current, heap)).map_err(|_| NO_ROOM)?;
    }
    Ok(Loaded { entry: program.entry as usize, budget: pages as usize })
}

/// Where the process starts, first in the stub (`link.x`), at `maki_native::load::STUB_ADDRESS`.
#[no_mangle]
#[link_section = ".text.init"]
pub extern "C" fn init(s1: u32, s2: u32, s3: u32, s4: u32) -> ! {
    let server = SID::from_u32(s1, s2, s3, s4);
    loop {
        let Ok(xous::Result::MessageEnvelope(mut envelope)) = xous::rsyscall(xous::SysCall::ReceiveMessage(server))
        else {
            continue;
        };
        if envelope.id() != OP_LOAD {
            continue;
        }
        let Some(memory) = envelope.body.memory_message_mut() else { continue };
        let buf = unsafe { memory.buf.as_slice_mut::<u8>() };
        let loaded = load(buf);
        let answer = match &loaded {
            Ok(_) => LOADED,
            Err(e) => *e,
        };
        if buf.len() >= HEADER {
            buf[AT_ANSWER..AT_ANSWER + 4].copy_from_slice(&answer.to_le_bytes());
        }
        // returns the buffer, and with it the loader's answer
        drop(envelope);
        let Ok(loaded) = loaded else { xous::terminate_process(answer) };
        xous::destroy_server(server).ok();
        // for good, before any of the app's code runs
        if xous::confine_self(loaded.budget).is_err() {
            xous::terminate_process(BAD_REQUEST);
        }
        let start: extern "C" fn(usize, *mut u8) -> ! =
            unsafe { core::mem::transmute(loaded.entry as *const u8) };
        start(0, core::ptr::null_mut());
    }
}

