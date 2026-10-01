//! maki: USB in the emulator. Baomulator's model of the USB controller has a paravirtual pipe at
//! the end of its registers (0x5020_4F00), where the real controller has nothing: a build of this service
//! made with MAKI_EMU_USB, on an emulator that has the pipe, carries its serial port, its FIDO
//! reports and its keystrokes through it instead of the controller. `shot --usb PORT` joins each
//! channel to a TCP stream on the host, so maki desktop and test clients reach the emulated maki
//! as they would a real one. A badge never takes this path: only an emulator build looks for the
//! pipe, and only an emulator answers with its mark.

use core::sync::atomic::{AtomicUsize, Ordering};

/// The pipe's channels.
pub const SERIAL: usize = 0;
pub const FIDO: usize = 1;
pub const KEYBOARD: usize = 2;

/// The pipe, from the start of the controller's registers as usb-bao1x maps them (0x5020_2000):
/// 0x5020_4F00, the end of what it maps.
const MAGIC_OFF: usize = 0x2F00;
const MAGIC: u32 = u32::from_le_bytes(*b"maki");
const CHANNEL_OFF: usize = 0x2F10;
const TX: usize = 0x0;
const RXAVAIL: usize = 0x8;
const RX: usize = 0xC;

/// The pipe, in the controller's register page as this process maps it.
#[derive(Clone, Copy)]
pub struct Pipe {
    base: usize,
}

/// Where the pipe is, for the thread that watches it, once found.
static FOUND: AtomicUsize = AtomicUsize::new(0);

impl Pipe {
    /// The pipe, if this is an emulator build and the emulator has one. `regs` is the controller's
    /// register page, mapped.
    pub fn find(regs: usize) -> Option<Pipe> {
        option_env!("MAKI_EMU_USB")?;
        let pipe = Pipe { base: regs };
        (pipe.read(MAGIC_OFF) == MAGIC).then(|| {
            FOUND.store(regs, Ordering::SeqCst);
            pipe
        })
    }

    fn read(&self, off: usize) -> u32 {
        // safety: inside the controller's register page, which this process mapped
        unsafe { ((self.base + off) as *const u32).read_volatile() }
    }

    fn write(&self, off: usize, val: u32) {
        // safety: as above
        unsafe { ((self.base + off) as *mut u32).write_volatile(val) }
    }

    fn reg(chan: usize, r: usize) -> usize { CHANNEL_OFF + 0x10 * chan + r }

    /// Bytes waiting on a channel.
    pub fn available(&self, chan: usize) -> usize { self.read(Self::reg(chan, RXAVAIL)) as usize }

    /// Send bytes on a channel.
    pub fn send(&self, chan: usize, data: &[u8]) {
        for &b in data {
            self.write(Self::reg(chan, TX), b as u32);
        }
    }

    /// Read what's waiting on a channel, as much as fits.
    pub fn recv(&self, chan: usize, data: &mut [u8]) -> usize {
        let n = self.available(chan).min(data.len());
        for b in data[..n].iter_mut() {
            *b = self.read(Self::reg(chan, RX)) as u8;
        }
        n
    }

    /// A whole 64-byte FIDO report, if one is waiting.
    pub fn fido_report(&self) -> Option<[u8; 64]> {
        if self.available(FIDO) < 64 {
            return None;
        }
        let mut report = [0u8; 64];
        self.recv(FIDO, &mut report);
        Some(report)
    }

    /// Watch the pipe for what the host sends and tell the service, as the controller's interrupt
    /// would: `IrqSerialRx` while serial bytes wait, `IrqFidoRx` while a whole FIDO report does.
    /// Each takes everything waiting, so a ring too many finds nothing, and none is missed. It
    /// looks every few milliseconds while bytes come, and backs off to 50 ms once they stop: a
    /// timer that wakes all the time would cost the emulated maki a fifth of its time, which a
    /// badge never spends.
    pub fn watch(cid: xous::CID) {
        std::thread::spawn(move || {
            let tt = ticktimer::Ticktimer::new().unwrap();
            let pipe = Pipe { base: FOUND.load(Ordering::SeqCst) };
            let ring = |op: crate::api::Opcode| {
                use num_traits::ToPrimitive;
                xous::try_send_message(cid, xous::Message::new_scalar(op.to_usize().unwrap(), 0, 0, 0, 0))
                    .ok();
            };
            let mut quiet = 0u32;
            loop {
                tt.sleep_ms(if quiet < 50 { 2 } else { 50 }).ok();
                let serial = pipe.available(SERIAL) > 0;
                let fido = pipe.available(FIDO) >= 64;
                if serial {
                    ring(crate::api::Opcode::IrqSerialRx);
                }
                if fido {
                    ring(crate::api::Opcode::IrqFidoRx);
                }
                quiet = if serial || fido || pipe.available(FIDO) > 0 { 0 } else { quiet.saturating_add(1) };
            }
        });
    }
}
