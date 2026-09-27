//! maki's app service: what a native app asks of maki, over IPC, in place of the functions a
//! WebAssembly app imports (`maki_wasm::Session` does the work for both). The app connects to
//! `APP_SERVICE` (its stub connected it before it was confined: it's all the app has, beside the
//! ticktimer and the log) and sends:
//!
//! - blocking scalars for what fits in a few words: `WAIT` (arg1: the timeout in milliseconds,
//!   `u32::MAX` for none; the answer's first word is the event's code, as `maki_wasm::Event::code`,
//!   or `EXITED` if it was told to exit already), `MILLIS`, `UNIX_TIME`, `MOTION`;
//! - everything else as a buffer lent mutably: a head of two little-endian u32s, a status and a
//!   length, then the payload. The request's payload goes in; the answer's comes back in its
//!   place, with the status (0, or one of `maki_wasm`'s codes, `REFUSED` among them) and length;
//! - `EXIT` (a plain scalar) when it's done: arg1 0 when it returned, 1 when it crashed (it
//!   sends `LOG` with why first).
//!
//! A request from any process but the app's is refused.

use crate::load::APP_SERVICE;

/// The service's server, a fixed address: the stub connects to it by name.
pub const SID: [u8; 16] = APP_SERVICE;

/// The firmware a native app is built for, as its manifest's `firmware` says: the service's
/// protocol and the kernel's rules. maki refuses an app built for another.
pub const FIRMWARE: &str = "maki-native-1";

/// The head of a lent buffer: status, then length (u32s, little-endian).
pub const HEAD: usize = 8;

// blocking scalars
pub const WAIT: usize = 1;
pub const MILLIS: usize = 2;
pub const UNIX_TIME: usize = 3;
pub const MOTION: usize = 4;
// lent buffers
pub const PRESENT: usize = 10;
pub const TEXT_WIDTH: usize = 11;
pub const MENU: usize = 12;
pub const RANDOM: usize = 13;
pub const LOG: usize = 14;
pub const STORAGE_GET: usize = 15;
pub const STORAGE_SET: usize = 16;
pub const STORAGE_DELETE: usize = 17;
pub const STORAGE_KEY: usize = 18;
pub const ASK: usize = 19;
pub const KEY_SECRET: usize = 20;
pub const KEY_PUBLIC: usize = 21;
pub const KEY_SIGN: usize = 22;
pub const TYPE_TEXT: usize = 23;
pub const LINK_READ: usize = 24;
pub const LINK_REPLY: usize = 25;
pub const SCAN_QR: usize = 26;
// a plain scalar
pub const EXIT: usize = 30;
/// maki's own, from the app host to itself: look at what's waiting (the owner left the app, or
/// its time to exit ran out).
pub const POKE: usize = 0x100;

/// `WAIT`'s answer when the app was told to exit already: it should have returned.
pub const EXITED: usize = usize::MAX;

/// A lent buffer's status and length.
pub fn head(buf: &[u8]) -> (i32, usize) {
    let status = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    (status, len)
}

pub fn set_head(buf: &mut [u8], status: i32, len: usize) {
    buf[..4].copy_from_slice(&status.to_le_bytes());
    buf[4..8].copy_from_slice(&(len as u32).to_le_bytes());
}

/// A lent buffer's payload, as its head says (none if the head doesn't fit the buffer).
pub fn payload(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < HEAD {
        return None;
    }
    let (_, len) = head(buf);
    buf.get(HEAD..HEAD.checked_add(len)?)
}

/// Writes an answer's payload (as much as fits) and its status and whole length.
pub fn answer(buf: &mut [u8], status: i32, bytes: &[u8]) {
    let room = buf.len().saturating_sub(HEAD);
    let n = bytes.len().min(room);
    buf[HEAD..HEAD + n].copy_from_slice(&bytes[..n]);
    set_head(buf, status, bytes.len());
}
