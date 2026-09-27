//! Write apps for maki in Rust.
//!
//! An app is a WebAssembly module that maki's app host runs (ARCHITECTURE.md, "Apps you can
//! install"). It gets the part of the screen below maki's bar, 128 by 110 pixels, one bit
//! each; the three buttons while it's in front (left and right together are maki's, for the
//! app's menu); storage of its own; the time; and random numbers. It draws, then waits for
//! the next event:
//!
//! ```ignore
//! #![no_std]
//! use maki_app::*;
//!
//! fn main() {
//!     loop {
//!         screen::clear(Color::Dark);
//!         screen::text_centred(40, "Hello, maki!", Style::Bold, Color::Light);
//!         screen::present();
//!         if wait(None) == Event::Exit {
//!             return;
//!         }
//!     }
//! }
//! maki_app::main!(main);
//! ```
//!
//! The crate is a `cdylib`. Build it with `cargo build --release --target wasm32-unknown-unknown`, then pack and sign
//! it with `maki pack`, or do both with `maki build`. `maki run` tries it on the computer.

#![no_std]

#[cfg(feature = "std")]
extern crate std;

mod sys {
    #[link(wasm_import_module = "maki")]
    extern "C" {
        pub fn screen_width() -> i32;
        pub fn screen_height() -> i32;
        pub fn clear(color: i32);
        pub fn pixel(x: i32, y: i32, color: i32);
        pub fn line(x0: i32, y0: i32, x1: i32, y1: i32, color: i32);
        pub fn rect(x: i32, y: i32, w: i32, h: i32, color: i32, filled: i32);
        pub fn text(x: i32, y: i32, ptr: *const u8, len: usize, style: i32, color: i32) -> i32;
        pub fn text_width(ptr: *const u8, len: usize, style: i32) -> i32;
        pub fn blit(x: i32, y: i32, w: i32, h: i32, ptr: *const u8, color: i32);
        pub fn qr(x: i32, y: i32, ptr: *const u8, len: usize, size: i32) -> i32;
        pub fn present();
        pub fn wait(timeout_ms: i32) -> i32;
        pub fn menu(ptr: *const u8, len: usize) -> i32;
        pub fn storage_get(kptr: *const u8, klen: usize, vptr: *mut u8, vcap: usize) -> i32;
        pub fn storage_set(kptr: *const u8, klen: usize, vptr: *const u8, vlen: usize) -> i32;
        pub fn storage_delete(kptr: *const u8, klen: usize) -> i32;
        pub fn storage_key(index: i32, ptr: *mut u8, cap: usize) -> i32;
        pub fn millis() -> i64;
        pub fn unix_time() -> i64;
        pub fn time_verified() -> i32;
        pub fn random(ptr: *mut u8, len: usize);
        pub fn log(ptr: *const u8, len: usize);
        pub fn abort(ptr: *const u8, len: usize) -> !;
    }
}

/// The app's part of the screen, in pixels.
pub const WIDTH: i32 = 128;
pub const HEIGHT: i32 = 110;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Color {
    Dark = 0,
    Light = 1,
    /// Flips whatever is there: for selections, and for erasing what you drew.
    Invert = 2,
}

/// maki's fonts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    Regular = 0,
    Bold = 1,
    Small = 2,
    Mono = 3,
    Tall = 4,
}

impl Style {
    /// Height of a line of text in this style.
    pub fn height(self) -> i32 {
        match self {
            Style::Small => 12,
            Style::Tall => 19,
            _ => 15,
        }
    }
}

/// What `wait` returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The wait's time ran out.
    Timeout,
    Left,
    Right,
    Centre,
    /// Back in front after something else was: draw again.
    Shown,
    /// Something else is in front (an ask, the menu): nothing drawn shows until Shown.
    Hidden,
    /// The owner left the app: save what's worth keeping and return from main. Waiting again
    /// after this stops the app.
    Exit,
    /// The owner picked this of the app's menu items (see `menu`).
    Menu(u32),
}

/// Why a maki function failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NotFound,
    /// The app's storage is full.
    Full,
    Invalid,
    TooBig,
    Failed,
}

fn result(code: i32) -> Result<i32, Error> {
    match code {
        -1 => Err(Error::NotFound),
        -2 => Err(Error::Full),
        -3 => Err(Error::Invalid),
        -4 => Err(Error::TooBig),
        n if n < 0 => Err(Error::Failed),
        n => Ok(n),
    }
}

/// Drawing. Nothing shows until `present`.
pub mod screen {
    use super::{sys, Color, Style};

    pub fn width() -> i32 { unsafe { sys::screen_width() } }

    pub fn height() -> i32 { unsafe { sys::screen_height() } }

    pub fn clear(color: Color) { unsafe { sys::clear(color as i32) } }

    pub fn pixel(x: i32, y: i32, color: Color) { unsafe { sys::pixel(x, y, color as i32) } }

    pub fn line(x0: i32, y0: i32, x1: i32, y1: i32, color: Color) { unsafe { sys::line(x0, y0, x1, y1, color as i32) } }

    pub fn rect(x: i32, y: i32, w: i32, h: i32, color: Color) { unsafe { sys::rect(x, y, w, h, color as i32, 0) } }

    pub fn fill_rect(x: i32, y: i32, w: i32, h: i32, color: Color) {
        unsafe { sys::rect(x, y, w, h, color as i32, 1) }
    }

    /// Draws `s` with its top left at (x, y); returns where the next character would go.
    pub fn text(x: i32, y: i32, s: &str, style: Style, color: Color) -> i32 {
        unsafe { sys::text(x, y, s.as_ptr(), s.len(), style as i32, color as i32) }
    }

    pub fn text_width(s: &str, style: Style) -> i32 { unsafe { sys::text_width(s.as_ptr(), s.len(), style as i32) } }

    /// `s` centred across the screen, its top at `y`.
    pub fn text_centred(y: i32, s: &str, style: Style, color: Color) {
        text((super::WIDTH - text_width(s, style)) / 2, y, s, style, color);
    }

    /// A `w` by `h` bitmap, each row `(w + 7) / 8` bytes, the leftmost pixel in the top bit
    /// (as PBM files have it). Set bits are drawn in `color`; the others are left alone.
    pub fn blit(x: i32, y: i32, w: i32, h: i32, bits: &[u8], color: Color) {
        let need = ((w.max(0) + 7) / 8 * h.max(0)) as usize;
        assert!(bits.len() >= need, "blit: {w}x{h} needs {need} bytes");
        unsafe { sys::blit(x, y, w, h, bits.as_ptr(), color as i32) }
    }

    /// `data` as a QR code as big as fits `size` pixels square, top left at (x, y): the side
    /// drawn, or None if it doesn't fit.
    pub fn qr(x: i32, y: i32, data: &[u8], size: i32) -> Option<i32> {
        let side = unsafe { sys::qr(x, y, data.as_ptr(), data.len(), size) };
        (side > 0).then_some(side)
    }

    /// Shows what's been drawn.
    pub fn present() { unsafe { sys::present() } }
}

/// Waits for the next event, at most `timeout_ms` milliseconds (None: until there is one).
/// Apps that work for long without waiting are stopped as not responding: wait with
/// `Some(0)` now and then to show you're alive.
pub fn wait(timeout_ms: Option<u32>) -> Event {
    let t = timeout_ms.map(|t| t.min(i32::MAX as u32) as i32).unwrap_or(-1);
    match unsafe { sys::wait(t) } {
        1 => Event::Left,
        2 => Event::Right,
        3 => Event::Centre,
        4 => Event::Shown,
        5 => Event::Hidden,
        6 => Event::Exit,
        n if n >= 0x100 => Event::Menu((n - 0x100) as u32),
        _ => Event::Timeout,
    }
}

/// The app's own menu items, at most six of up to 24 bytes each, which maki shows (before App
/// info and Exit) when the owner presses left and right together. Picking one sends
/// `Event::Menu` with its index.
pub fn menu(items: &[&str]) -> Result<(), Error> {
    let mut buf = [0u8; 6 * 25];
    let mut len = 0;
    for (i, item) in items.iter().enumerate() {
        let sep = (i > 0) as usize;
        if len + sep + item.len() > buf.len() {
            return Err(Error::TooBig);
        }
        if sep == 1 {
            buf[len] = b'\n';
        }
        buf[len + sep..len + sep + item.len()].copy_from_slice(item.as_bytes());
        len += sep + item.len();
    }
    result(unsafe { sys::menu(buf.as_ptr(), len) }).map(|_| ())
}

/// The app's own storage on maki: keys of up to 48 bytes, values of up to 16 KiB, within the
/// storage its manifest asked for. Only this app can read it; whether it goes in maki's
/// backup is the owner's choice.
pub mod storage {
    use super::{result, sys, Error};

    /// Copies the value into `buf` (as much as fits) and returns its whole length.
    pub fn get(key: &str, buf: &mut [u8]) -> Option<usize> {
        let n = unsafe { sys::storage_get(key.as_ptr(), key.len(), buf.as_mut_ptr(), buf.len()) };
        result(n).ok().map(|n| n as usize)
    }

    pub fn set(key: &str, value: &[u8]) -> Result<(), Error> {
        result(unsafe { sys::storage_set(key.as_ptr(), key.len(), value.as_ptr(), value.len()) }).map(|_| ())
    }

    /// Whether there was such a key.
    pub fn delete(key: &str) -> bool { unsafe { sys::storage_delete(key.as_ptr(), key.len()) == 0 } }

    /// The `index`th key, in sorted order, copied into `buf`.
    pub fn key(index: usize, buf: &mut [u8; 48]) -> Option<&str> {
        let n = unsafe { sys::storage_key(index as i32, buf.as_mut_ptr(), buf.len()) };
        let n = result(n).ok()? as usize;
        core::str::from_utf8(&buf[..n.min(48)]).ok()
    }

    /// A u32, stored little-endian; `default` if there isn't one.
    pub fn get_u32(key: &str, default: u32) -> u32 {
        let mut b = [0u8; 4];
        match get(key, &mut b) {
            Some(4) => u32::from_le_bytes(b),
            _ => default,
        }
    }

    pub fn set_u32(key: &str, value: u32) -> Result<(), Error> { set(key, &value.to_le_bytes()) }
}

/// Milliseconds since the app started.
pub fn millis() -> u64 { unsafe { sys::millis() as u64 } }

/// Seconds since 1970, if maki knows the time. Check `time_verified` before trusting it with
/// anything that matters: unverified time is whatever the computer said.
pub fn unix_time() -> Option<u64> {
    let t = unsafe { sys::unix_time() };
    (t >= 0).then_some(t as u64)
}

/// Whether maki's time was checked against Roughtime servers.
pub fn time_verified() -> bool { unsafe { sys::time_verified() == 1 } }

/// Fills `buf` from maki's true random number generator, 4096 bytes at most.
pub fn random(buf: &mut [u8]) {
    for chunk in buf.chunks_mut(4096) {
        unsafe { sys::random(chunk.as_mut_ptr(), chunk.len()) }
    }
}

/// A random number in `0..n` (0 if n is 0), without bias.
pub fn random_below(n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    let zone = u32::MAX - u32::MAX % n;
    loop {
        let mut b = [0u8; 4];
        random(&mut b);
        let v = u32::from_le_bytes(b);
        if v < zone {
            return v % n;
        }
    }
}

/// A line in maki's debug log (and the simulator's output).
pub fn log(s: &str) { unsafe { sys::log(s.as_ptr(), s.len()) } }

/// Stops the app, showing `why` on maki's screen.
pub fn abort(why: &str) -> ! { unsafe { sys::abort(why.as_ptr(), why.len()) } }

/// A fixed buffer to format into without an allocator: `write!(buf, "{n}")`.
pub struct Buf<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Buf<N> {
    pub const fn new() -> Self { Buf { bytes: [0; N], len: 0 } }

    pub fn as_str(&self) -> &str { core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("") }

    pub fn clear(&mut self) { self.len = 0 }
}

impl<const N: usize> Default for Buf<N> {
    fn default() -> Self { Self::new() }
}

impl<const N: usize> core::fmt::Write for Buf<N> {
    /// Writes what fits, whole characters only, and quietly drops the rest.
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for c in s.chars() {
            let mut b = [0u8; 4];
            let e = c.encode_utf8(&mut b);
            if self.len + e.len() > N {
                break;
            }
            self.bytes[self.len..self.len + e.len()].copy_from_slice(e.as_bytes());
            self.len += e.len();
        }
        Ok(())
    }
}

#[cfg(all(feature = "panic-handler", not(feature = "std")))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    let mut why = Buf::<200>::new();
    let _ = write!(why, "{}", info.message());
    if let Some(at) = info.location() {
        let _ = write!(why, " ({}:{})", at.file(), at.line());
    }
    abort(why.as_str())
}

#[doc(hidden)]
pub fn __start() {
    #[cfg(feature = "std")]
    std::panic::set_hook(std::boxed::Box::new(|info| {
        let why = std::format!("{info}");
        abort(&why)
    }));
}

/// Makes `$f` the app's entry point: `maki_app::main!(main);`
#[macro_export]
macro_rules! main {
    ($f:path) => {
        #[no_mangle]
        pub extern "C" fn maki_main() {
            $crate::__start();
            $f()
        }
    };
}
