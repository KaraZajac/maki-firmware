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
//! The crate is a `cdylib`. Build it with `cargo build --release --target wasm32-unknown-unknown`, then pack
//! and sign it with `maki pack`, or do both with `maki build`. `maki run` tries it on the computer.
//!
//! Some functions need a permission, which the app's `maki.toml` asks for with a line saying
//! why, and the owner sees before installing it: `ask` (maki's own ask screen), `keys`
//! (secrets of the app's own from the recovery phrase), `keyboard` (typing into the computer),
//! `link` (messages with software on the computer, through maki desktop), `camera` (QR codes)
//! and `motion` (the accelerometer). maki refuses an app that calls one without asking for its
//! permission.

#![no_std]
#[cfg(feature = "wallet")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

// A native app (`kind = "native"`) calls the same functions over maki's app service.
#[cfg(target_os = "xous")]
#[doc(hidden)]
pub mod native;
#[cfg(target_os = "xous")]
use native as sys;

#[cfg(not(target_os = "xous"))]
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
        pub fn text_scaled(
            x: i32,
            y: i32,
            ptr: *const u8,
            len: usize,
            style: i32,
            color: i32,
            scale: i32,
        ) -> i32;
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
        pub fn ask(ptr: *const u8, len: usize, timeout_s: i32) -> i32;
        pub fn ask_review(ptr: *const u8, len: usize, timeout_s: i32) -> i32;
        pub fn key_secret(lptr: *const u8, llen: usize, out: *mut u8) -> i32;
        pub fn key_public(lptr: *const u8, llen: usize, out: *mut u8) -> i32;
        pub fn key_sign(lptr: *const u8, llen: usize, mptr: *const u8, mlen: usize, out: *mut u8) -> i32;
        pub fn key_schnorr_public(lptr: *const u8, llen: usize, out: *mut u8) -> i32;
        pub fn key_schnorr_sign(lptr: *const u8, llen: usize, mptr: *const u8, out: *mut u8) -> i32;
        pub fn key_x25519_public(lptr: *const u8, llen: usize, out: *mut u8) -> i32;
        pub fn key_x25519_agree(lptr: *const u8, llen: usize, pptr: *const u8, out: *mut u8) -> i32;
        pub fn type_text(ptr: *const u8, len: usize) -> i32;
        pub fn key_press(code: i32, shift: i32) -> i32;
        pub fn key_chord(code: i32, mods: i32) -> i32;
        pub fn link_read(ptr: *mut u8, cap: usize) -> i32;
        pub fn link_reply(ptr: *const u8, len: usize) -> i32;
        pub fn camera_scan_qr(ptr: *mut u8, cap: usize) -> i32;
        pub fn motion_read(ptr: *mut u8) -> i32;
        pub fn motion_range(g: i32) -> i32;
        pub fn screen_dark(dark: i32);
        #[cfg(feature = "wallet")]
        pub fn wallet_fingerprint(out: *mut u8) -> i32;
        #[cfg(feature = "wallet")]
        pub fn wallet_public(pptr: *const u32, plen: usize, form: i32, out: *mut u8, cap: usize) -> i32;
        #[cfg(feature = "wallet")]
        pub fn wallet_review(tptr: *const u8, tlen: usize, signatures: i32, timeout_s: i32) -> i32;
        #[cfg(feature = "wallet")]
        pub fn wallet_sign(
            pptr: *const u32,
            plen: usize,
            dptr: *const u8,
            scheme: i32,
            out: *mut u8,
            cap: usize,
        ) -> i32;
        #[cfg(feature = "wallet")]
        pub fn wallet_subaddress(pptr: *const u32, plen: usize, major: i32, minor: i32, out: *mut u8) -> i32;
        #[cfg(feature = "wallet")]
        pub fn wallet_show_backup(pptr: *const u32, plen: usize) -> i32;
        #[cfg(feature = "wallet")]
        pub fn wallet_monero_view_key(pptr: *const u32, plen: usize, out: *mut u8) -> i32;
        #[cfg(feature = "wallet")]
        pub fn wallet_monero_key_image(pptr: *const u32, plen: usize, optr: *const u8, out: *mut u8) -> i32;
        #[cfg(feature = "wallet")]
        pub fn wallet_monero_sign(
            pptr: *const u32,
            plen: usize,
            rptr: *const u8,
            rlen: usize,
            out: *mut u8,
            cap: usize,
        ) -> i32;
        #[cfg(feature = "wallet")]
        pub fn wallet_sign_ed25519(
            pptr: *const u32,
            plen: usize,
            mptr: *const u8,
            mlen: usize,
            out: *mut u8,
        ) -> i32;
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
    /// A message from software on the computer (the `link` permission): `link::read` it, and
    /// `link::reply`, before waiting again.
    Message,
    /// The jog dial on maki's side, up or down. Only for an app that says host API 8 or later
    /// (`api` in maki.toml, the SDK's own by default); an older one never gets these.
    Up,
    Down,
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
    /// Not the app's to do: a permission it doesn't have (a native app can call anything), a
    /// wallet path its manifest doesn't name, or a signature the owner didn't say yes to.
    Refused,
    /// maki is locked, or has no recovery phrase yet (host API 3; before, `Failed`).
    Locked,
}

fn result(code: i32) -> Result<i32, Error> {
    match code {
        -1 => Err(Error::NotFound),
        -2 => Err(Error::Full),
        -3 => Err(Error::Invalid),
        -4 => Err(Error::TooBig),
        -6 => Err(Error::Refused),
        -7 => Err(Error::Locked),
        n if n < 0 => Err(Error::Failed),
        n => Ok(n),
    }
}

/// Drawing. Nothing shows until `present`.
pub mod screen {
    use super::{Color, Style, sys};

    pub fn width() -> i32 { unsafe { sys::screen_width() } }

    pub fn height() -> i32 { unsafe { sys::screen_height() } }

    pub fn clear(color: Color) { unsafe { sys::clear(color as i32) } }

    pub fn pixel(x: i32, y: i32, color: Color) { unsafe { sys::pixel(x, y, color as i32) } }

    pub fn line(x0: i32, y0: i32, x1: i32, y1: i32, color: Color) {
        unsafe { sys::line(x0, y0, x1, y1, color as i32) }
    }

    pub fn rect(x: i32, y: i32, w: i32, h: i32, color: Color) {
        unsafe { sys::rect(x, y, w, h, color as i32, 0) }
    }

    pub fn fill_rect(x: i32, y: i32, w: i32, h: i32, color: Color) {
        unsafe { sys::rect(x, y, w, h, color as i32, 1) }
    }

    /// Draws `s` with its top left at (x, y); returns where the next character would go.
    pub fn text(x: i32, y: i32, s: &str, style: Style, color: Color) -> i32 {
        unsafe { sys::text(x, y, s.as_ptr(), s.len(), style as i32, color as i32) }
    }

    pub fn text_width(s: &str, style: Style) -> i32 {
        unsafe { sys::text_width(s.as_ptr(), s.len(), style as i32) }
    }

    /// `s` centred across the screen, its top at `y`.
    pub fn text_centred(y: i32, s: &str, style: Style, color: Color) {
        text((super::WIDTH - text_width(s, style)) / 2, y, s, style, color);
    }

    /// Draws `s` as `text` does, each pixel of the font a `scale` by `scale` square (1 to 8):
    /// maki's own fonts made big, for a name tag or a number read across a room. A line is
    /// `style.height() * scale` tall and `text_scaled_width` wide. Host API 9 (`api = 9` in
    /// maki.toml), and WebAssembly apps only.
    #[cfg(not(target_os = "xous"))]
    pub fn text_scaled(x: i32, y: i32, s: &str, style: Style, scale: i32, color: Color) -> i32 {
        unsafe { sys::text_scaled(x, y, s.as_ptr(), s.len(), style as i32, color as i32, scale.clamp(1, 8)) }
    }

    /// How wide `text_scaled` draws `s`.
    pub fn text_scaled_width(s: &str, style: Style, scale: i32) -> i32 {
        text_width(s, style) * scale.clamp(1, 8)
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

    /// The whole screen dark, maki's bar and all, or lit again (host API 8): for an app that
    /// watches through the night, and shouldn't wear the screen or say it's there. Presses still
    /// reach the app; maki lights the screen to show it's typing, and its own screens show over it.
    pub fn dark(dark: bool) { unsafe { sys::screen_dark(dark as i32) } }

    /// The edge of the screen whoever reads `segments` sits at: `Bottom` as maki is held, `Top`
    /// across a table from them (upside down), `Left` and `Right` at its sides (a quarter turn).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Toward {
        Bottom,
        Top,
        Left,
        Right,
    }

    /// Big digits drawn with bars, as a seven-segment display shows them, for numbers read at a
    /// glance or from across a table: digits, `:`, `.`, `-`, `+` and spaces, `height` pixels tall
    /// (a digit's about half as wide), filling the box at (x, y) that `segments_size` gives, and
    /// reading right to whoever sits at `toward`.
    pub fn segments(x: i32, y: i32, text: &str, height: i32, toward: Toward, color: Color) {
        let (w, h) = (segments_width(text, height), height);
        let gap = segment_sizes(height).2;
        let mut at = 0;
        for c in text.chars() {
            let (bars, n) = segment_bars(c, height);
            for &(bx, by, bw, bh) in &bars[..n] {
                let bx = at + bx;
                let (sx, sy, sw, sh) = match toward {
                    Toward::Bottom => (x + bx, y + by, bw, bh),
                    Toward::Top => (x + w - bx - bw, y + h - by - bh, bw, bh),
                    Toward::Right => (x + by, y + w - bx - bw, bh, bw),
                    Toward::Left => (x + h - by - bh, y + bx, bh, bw),
                };
                fill_rect(sx, sy, sw, sh, color);
            }
            at += segment_width(c, height) + gap;
        }
    }

    /// The box `segments` draws `text` in, as (width, height) on the screen: a quarter turn
    /// swaps them.
    pub fn segments_size(text: &str, height: i32, toward: Toward) -> (i32, i32) {
        let w = segments_width(text, height);
        match toward {
            Toward::Bottom | Toward::Top => (w, height),
            Toward::Left | Toward::Right => (height, w),
        }
    }

    /// Along the text, whichever way it's turned.
    fn segments_width(text: &str, height: i32) -> i32 {
        let gap = segment_sizes(height).2;
        let (mut w, mut n) = (0, 0);
        for c in text.chars() {
            w += segment_width(c, height);
            n += 1;
        }
        w + gap * (n - 1).max(0)
    }

    /// A digit's width, its bars' thickness and the gap between characters, for `height`.
    fn segment_sizes(height: i32) -> (i32, i32, i32) {
        ((height * 9 + 8) / 16, ((height + 4) / 8).max(2), ((height * 3 + 8) / 16).max(2))
    }

    fn segment_width(c: char, height: i32) -> i32 {
        let (w, t, _) = segment_sizes(height);
        if c == ':' || c == '.' { t } else { w }
    }

    /// A character's bars, as (x, y, w, h) in its own box, and how many there are. Segments a to
    /// g (top, top right, bottom right, bottom, bottom left, top left, middle) are bits 0 to 6.
    fn segment_bars(c: char, height: i32) -> ([(i32, i32, i32, i32); 7], usize) {
        const DIGITS: [u8; 10] = [0x3f, 0x06, 0x5b, 0x4f, 0x66, 0x6d, 0x7d, 0x07, 0x7f, 0x6f];
        let (w, t, _) = segment_sizes(height);
        let h = height;
        let (upper, lower) = (h / 2 + t / 2, h - h / 2 + t / 2);
        let mid = h / 2 - t / 2;
        let all = [
            (0, 0, w, t),
            (w - t, 0, t, upper),
            (w - t, mid, t, lower),
            (0, h - t, w, t),
            (0, mid, t, lower),
            (0, 0, t, upper),
            (0, mid, w, t),
        ];
        let mut bars = [(0, 0, 0, 0); 7];
        let mut n = 0;
        let mut add = |bar: (i32, i32, i32, i32)| {
            bars[n] = bar;
            n += 1;
        };
        match c {
            '0'..='9' => {
                let on = DIGITS[c as usize - '0' as usize];
                for (i, bar) in all.iter().enumerate() {
                    if on & (1 << i) != 0 {
                        add(*bar);
                    }
                }
            }
            '-' => add(all[6]),
            '+' => {
                add(all[6]);
                add((w / 2 - t / 2, h / 2 - w / 2, t, w));
            }
            ':' => {
                add((0, h / 3 - t / 2, t, t));
                add((0, h * 2 / 3 - t / 2, t, t));
            }
            '.' => add((0, h - t, t, t)),
            _ => {}
        }
        (bars, n)
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
        7 => Event::Message,
        8 => Event::Up,
        9 => Event::Down,
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
    use super::{Error, result, sys};

    /// Copies the value into `buf` (as much as fits) and returns its whole length.
    pub fn get(key: &str, buf: &mut [u8]) -> Option<usize> {
        let n = unsafe { sys::storage_get(key.as_ptr(), key.len(), buf.as_mut_ptr(), buf.len()) };
        result(n).ok().map(|n| n as usize)
    }

    /// `Error::Full` past the app's storage: its names and values together, in as many keys
    /// as one for each 128 bytes of it (16 at least).
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

/// What the owner answered an `Ask`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Yes,
    No,
    /// They let it time out, or maki couldn't ask (it's locked).
    NoAnswer,
}

/// A question for the owner on maki's own ask screen, under the app's bar (the `ask`
/// permission): `Ask::new("Sign in?").detail("as kara").answers("sign", "cancel").show()`. The
/// app waits for the answer; it gets `Event::Hidden` and then `Event::Shown` around the ask.
#[derive(Clone, Copy, Debug)]
pub struct Ask<'a> {
    question: &'a str,
    detail: &'a str,
    yes: &'a str,
    no: &'a str,
    timeout_s: u32,
}

impl<'a> Ask<'a> {
    /// The question, up to 64 bytes.
    pub fn new(question: &'a str) -> Self { Ask { question, detail: "", yes: "", no: "", timeout_s: 0 } }

    /// A line more about it, up to 128 bytes.
    pub fn detail(self, detail: &'a str) -> Self { Ask { detail, ..self } }

    /// The answers' labels, up to 16 bytes each ("allow" and "deny" if not given).
    pub fn answers(self, yes: &'a str, no: &'a str) -> Self { Ask { yes, no, ..self } }

    /// How long the owner has, 5 to 120 seconds (30 if not given).
    pub fn timeout(self, seconds: u32) -> Self { Ask { timeout_s: seconds, ..self } }

    /// Shows it and waits. `Error::Invalid` for text too long or with control characters.
    pub fn show(self) -> Result<Answer, Error> {
        use core::fmt::Write;
        let mut text = Buf::<{ 64 + 128 + 16 + 16 + 3 }>::new();
        let _ = write!(text, "{}\n{}\n{}\n{}", self.question, self.detail, self.yes, self.no);
        if text.len() != self.question.len() + self.detail.len() + self.yes.len() + self.no.len() + 3 {
            return Err(Error::TooBig);
        }
        let code = unsafe {
            sys::ask(text.as_str().as_ptr(), text.len(), self.timeout_s.min(i32::MAX as u32) as i32)
        };
        result(code).map(|a| match a {
            0 => Answer::Yes,
            1 => Answer::No,
            _ => Answer::NoAnswer,
        })
    }
}

/// A question for the owner on maki's review screen, after pages of what it's about (the `ask`
/// permission, host API 7: say `api = 7` in maki.toml), for what an ask's line can't hold: a
/// whole command line, say. The pages go by a page at a time under the app's bar, as a wallet's
/// review does, then the question; a yes allows no signatures (the app does what it asked
/// about). It builds in bytes the app lends it, with no allocator: a static for a big one, since
/// an app's stack is 16 KiB.
///
/// ```ignore
/// let mut text = [0u8; 1024];
/// let mut review = AskPages::new(&mut text, "Run it as root?", "sudo on laptop", "run", "deny");
/// review.page("Command", "", "/usr/bin/systemctl restart nginx", "");
/// review.page("Asked by", "kara", "", "in /home/kara");
/// let answer = review.timeout(60).show();
/// ```
pub struct AskPages<'a> {
    text: &'a mut [u8],
    len: usize,
    over: bool,
    timeout_s: u32,
}

impl<'a> AskPages<'a> {
    /// In `text`, which must hold all of it: the question (up to 64 bytes), a line more about it
    /// (up to 128; may be empty), and the answers' labels (up to 16 bytes each; empty for
    /// "allow" and "deny").
    pub fn new(text: &'a mut [u8], question: &str, detail: &str, yes: &str, no: &str) -> Self {
        let mut pages = AskPages { text, len: 0, over: false, timeout_s: 0 };
        for (i, part) in [question, detail, yes, no].iter().enumerate() {
            if i > 0 {
                pages.put("\n");
            }
            pages.put(part);
        }
        pages
    }

    fn put(&mut self, s: &str) {
        match self.text.get_mut(self.len..self.len + s.len()) {
            Some(room) => {
                room.copy_from_slice(s.as_bytes());
                self.len += s.len();
            }
            None => self.over = true,
        }
    }

    /// A page: its heading (a few words at the top, up to 32 bytes), its value (the thing to
    /// check, in bold, up to 128), fixed-width text (across as many lines as it takes, up to 4096)
    /// and prose (small words, wrapped, up to 4096). All but the heading may be empty; only the
    /// last two may have newlines.
    pub fn page(&mut self, heading: &str, value: &str, mono: &str, prose: &str) -> &mut Self {
        for (sep, part) in [("\x1e", heading), ("\x1f", value), ("\x1f", mono), ("\x1f", prose)] {
            self.put(sep);
            self.put(part);
        }
        self
    }

    /// How long the owner has, 5 to 300 seconds (120 if not given).
    pub fn timeout(&mut self, seconds: u32) -> &mut Self {
        self.timeout_s = seconds;
        self
    }

    /// Shows it and waits. `Error::TooBig` if it didn't fit its bytes or maki's limits,
    /// `Error::Invalid` for text too long for maki's screen, or with control characters where they
    /// can't be.
    pub fn show(&self) -> Result<Answer, Error> {
        if self.over {
            return Err(Error::TooBig);
        }
        // whole strs, one after another: UTF-8
        let code = unsafe {
            sys::ask_review(self.text.as_ptr(), self.len, self.timeout_s.min(i32::MAX as u32) as i32)
        };
        result(code).map(|a| match a {
            0 => Answer::Yes,
            1 => Answer::No,
            _ => Answer::NoAnswer,
        })
    }
}

/// Secrets of the app's own, from maki's recovery phrase (the `keys` permission): different for
/// every app, developer key and label, and the same on any maki restored from the phrase. A
/// label (up to 32 bytes, "" is one) names one of the app's secrets. They exist only while maki
/// is unlocked and has a phrase: `Error::Failed` otherwise.
///
/// An app that updates keeps its keys only if it's signed with the same developer key.
pub mod keys {
    use super::{Error, result, sys};

    /// The 32-byte secret itself, for the app's own cryptography.
    pub fn secret(label: &str) -> Result<[u8; 32], Error> {
        let mut out = [0u8; 32];
        result(unsafe { sys::key_secret(label.as_ptr(), label.len(), out.as_mut_ptr()) })?;
        Ok(out)
    }

    /// The Ed25519 public key whose private key is the secret for `label`. maki holds the
    /// private key and signs with it (`sign`), so the app needn't.
    pub fn public_key(label: &str) -> Result<[u8; 32], Error> {
        let mut out = [0u8; 32];
        result(unsafe { sys::key_public(label.as_ptr(), label.len(), out.as_mut_ptr()) })?;
        Ok(out)
    }

    /// An Ed25519 signature of `message` (up to 16 KiB) with the key for `label`.
    pub fn sign(label: &str, message: &[u8]) -> Result<[u8; 64], Error> {
        let mut out = [0u8; 64];
        let code = unsafe {
            sys::key_sign(label.as_ptr(), label.len(), message.as_ptr(), message.len(), out.as_mut_ptr())
        };
        result(code)?;
        Ok(out)
    }

    /// The BIP340 (Schnorr, secp256k1) public key for `label`, x-only, as Nostr and Taproot write
    /// keys. maki holds the private key (from the same secret, tagged apart from the Ed25519 one)
    /// and signs with it (`schnorr_sign`). Host API 2: say `api = 2` in maki.toml.
    pub fn schnorr_public_key(label: &str) -> Result<[u8; 32], Error> {
        let mut out = [0u8; 32];
        result(unsafe { sys::key_schnorr_public(label.as_ptr(), label.len(), out.as_mut_ptr()) })?;
        Ok(out)
    }

    /// A BIP340 signature, with the key for `label`, of a 32-byte message: a hash (a Nostr event's
    /// id, say). maki adds fresh randomness from its TRNG, as BIP340 suggests. Host API 2.
    pub fn schnorr_sign(label: &str, message: &[u8; 32]) -> Result<[u8; 64], Error> {
        let mut out = [0u8; 64];
        let code =
            unsafe { sys::key_schnorr_sign(label.as_ptr(), label.len(), message.as_ptr(), out.as_mut_ptr()) };
        result(code)?;
        Ok(out)
    }

    /// The X25519 public key for `label` (RFC 7748), as age writes recipients. maki holds the
    /// private key (from the same secret, tagged apart) and agrees with it (`x25519_agree`).
    /// Host API 2.
    pub fn x25519_public_key(label: &str) -> Result<[u8; 32], Error> {
        let mut out = [0u8; 32];
        result(unsafe { sys::key_x25519_public(label.as_ptr(), label.len(), out.as_mut_ptr()) })?;
        Ok(out)
    }

    /// What the key for `label` and `peer`'s public key agree on (X25519): the shared secret, to
    /// derive a key from (as age does, with HKDF). `Invalid` for a peer of small order, whose
    /// agreement would be all zeros. Host API 2.
    pub fn x25519_agree(label: &str, peer: &[u8; 32]) -> Result<[u8; 32], Error> {
        let mut out = [0u8; 32];
        result(unsafe {
            sys::key_x25519_agree(label.as_ptr(), label.len(), peer.as_ptr(), out.as_mut_ptr())
        })?;
        Ok(out)
    }
}

/// Typing into the computer as a USB keyboard (the `keyboard` permission), only while the app
/// is in front, with "typing" in maki's bar meanwhile: text (`type_text`), a key beyond text
/// (`press`), and a shortcut with Ctrl, Alt or Gui held (`chord`, host API 10). maki warns at
/// install that the permission can press shortcuts and open programs.
pub mod keyboard {
    use super::{Error, result, sys};

    /// Types `text`: printable ASCII, newlines and tabs, up to 1024 bytes. `Error::Failed` if
    /// maki isn't plugged into a computer, or the app isn't in front.
    pub fn type_text(text: &str) -> Result<(), Error> {
        result(unsafe { sys::type_text(text.as_ptr(), text.len()) }).map(|_| ())
    }

    /// The keys beyond text an app can press (host API 8), as their USB HID usage IDs. There's
    /// no Ctrl, Alt or Command: shortcuts are the owner's to press, not an app's.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    pub enum Key {
        Enter = 0x28,
        Escape = 0x29,
        Backspace = 0x2a,
        Tab = 0x2b,
        Space = 0x2c,
        F1 = 0x3a,
        F2 = 0x3b,
        F3 = 0x3c,
        F4 = 0x3d,
        F5 = 0x3e,
        F6 = 0x3f,
        F7 = 0x40,
        F8 = 0x41,
        F9 = 0x42,
        F10 = 0x43,
        F11 = 0x44,
        F12 = 0x45,
        Insert = 0x49,
        Home = 0x4a,
        PageUp = 0x4b,
        Delete = 0x4c,
        End = 0x4d,
        PageDown = 0x4e,
        Right = 0x4f,
        Left = 0x50,
        Down = 0x51,
        Up = 0x52,
    }

    /// Presses `key` and lets it go (host API 8), as `type_text` types: only while the app is
    /// in front, and `Error::Failed` if maki isn't plugged into a computer.
    pub fn press(key: Key) -> Result<(), Error> {
        result(unsafe { sys::key_press(key as i32, 0) }).map(|_| ())
    }

    /// The same with Shift held: Shift+F5, say.
    pub fn press_shifted(key: Key) -> Result<(), Error> {
        result(unsafe { sys::key_press(key as i32, 1) }).map(|_| ())
    }

    /// Modifiers a chord holds (`chord`), as a bitmask. Shift is here too, so one chord names all
    /// of its modifiers; Ctrl, Alt and Gui (the Command or Windows key) are the ones `press` won't
    /// hold. maki warns at install that the keyboard permission can press shortcuts and open
    /// programs.
    pub const SHIFT: u8 = 1;
    pub const CTRL: u8 = 2;
    pub const ALT: u8 = 4;
    pub const GUI: u8 = 8;

    /// Presses a key with `mods` (the `SHIFT`/`CTRL`/`ALT`/`GUI` bits) held and lets it go — a
    /// shortcut such as Gui+R or Ctrl+C (host API 10, `api = 10`). `code` is a USB HID usage ID of
    /// a main-keyboard key: a letter, digit or symbol (`usage` turns a character into one), or a
    /// `Key`. WebAssembly apps only; as `press`, only while the app is in front, and
    /// `Error::Failed` if maki isn't plugged into a computer.
    #[cfg(not(target_os = "xous"))]
    pub fn chord(code: u8, mods: u8) -> Result<(), Error> {
        result(unsafe { sys::key_chord(code as i32, mods as i32) }).map(|_| ())
    }

    /// A chord over a `Key` (an arrow, a function key, Delete): Ctrl+Alt+Delete, Alt+F4, Gui+Space.
    #[cfg(not(target_os = "xous"))]
    pub fn chord_key(key: Key, mods: u8) -> Result<(), Error> { chord(key as u8, mods) }

    /// The USB HID usage ID for a character on a US keyboard, for a chord over it (Gui+R is
    /// `chord(usage('r').unwrap(), GUI)`). Letters (upper or lower: the same physical key, Shift
    /// is a modifier of its own), digits and the common symbols. None for anything else.
    #[cfg(not(target_os = "xous"))]
    pub fn usage(c: char) -> Option<u8> {
        Some(match c.to_ascii_lowercase() {
            'a'..='z' => 0x04 + (c.to_ascii_lowercase() as u8 - b'a'),
            '1'..='9' => 0x1e + (c as u8 - b'1'),
            '0' => 0x27,
            '-' | '_' => 0x2d,
            '=' | '+' => 0x2e,
            '[' | '{' => 0x2f,
            ']' | '}' => 0x30,
            '\\' | '|' => 0x31,
            ';' | ':' => 0x33,
            '\'' | '"' => 0x34,
            '`' | '~' => 0x35,
            ',' | '<' => 0x36,
            '.' | '>' => 0x37,
            '/' | '?' => 0x38,
            ' ' => 0x2c,
            _ => return None,
        })
    }
}

/// Messages with software on the computer, through maki desktop (the `link` permission): the
/// software sends one, the app gets `Event::Message`, reads it and replies, once, before it
/// waits again (waiting again without replying tells the sender the app didn't answer). If the
/// app isn't running, maki starts it without the screen to answer, and ends it once it's had
/// nothing to do for a while; the owner can still open it meanwhile. Messages and replies are
/// up to 4096 bytes, and mean whatever the app and the software agree.
pub mod link {
    use super::{Error, result, sys};

    /// The message, copied into `buf` as far as it fits; its whole length. None if there's
    /// none to read (no `Event::Message`, or it's been answered).
    pub fn read(buf: &mut [u8]) -> Option<usize> {
        result(unsafe { sys::link_read(buf.as_mut_ptr(), buf.len()) }).ok().map(|n| n as usize)
    }

    /// Answers the message.
    pub fn reply(answer: &[u8]) -> Result<(), Error> {
        result(unsafe { sys::link_reply(answer.as_ptr(), answer.len()) }).map(|_| ())
    }
}

/// QR codes through maki's camera (the `camera` permission), with maki's own scanner on screen,
/// while the app is in front.
pub mod camera {
    use super::{result, sys};

    /// Scans until a QR code is read, or the owner presses a button to cancel (None; the press
    /// doesn't reach the app). The text is copied into `buf`; None if it doesn't fit, or isn't
    /// UTF-8.
    pub fn scan_qr(buf: &mut [u8]) -> Option<&str> {
        let n = result(unsafe { sys::camera_scan_qr(buf.as_mut_ptr(), buf.len()) }).ok()? as usize;
        core::str::from_utf8(buf.get(..n)?).ok()
    }
}

/// The accelerometer (the `motion` permission), while the app is in front.
pub mod motion {
    use super::{result, sys};

    /// x, y and z, in thousandths of a g (face up and still: about 0, 0, 1000). None if there's
    /// nothing to read.
    pub fn read() -> Option<(i16, i16, i16)> {
        let mut b = [0u8; 6];
        result(unsafe { sys::motion_read(b.as_mut_ptr()) }).ok()?;
        let at = |i: usize| i16::from_le_bytes([b[i], b[i + 1]]);
        Some((at(0), at(2), at(4)))
    }

    /// The accelerometer's range, ±`g` rounded up to one it has: 2 (maki's own, and the finest),
    /// 4, 8 or 16, for a ride that pulls more (host API 8). It lasts until the app stops. The
    /// range it has now, or None if there's no accelerometer.
    pub fn range(g: u32) -> Option<u32> {
        result(unsafe { sys::motion_range(g.min(16) as i32) }).ok().map(|g| g as u32)
    }
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

/// A fixed buffer to format into without an allocator: `write!(buf, "{n}")`. Two are equal when
/// their text is.
#[derive(Clone)]
pub struct Buf<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> PartialEq for Buf<N> {
    fn eq(&self, other: &Self) -> bool { self.as_str() == other.as_str() }
}

impl<const N: usize> Eq for Buf<N> {}

impl<const N: usize> Buf<N> {
    pub const fn new() -> Self { Buf { bytes: [0; N], len: 0 } }

    pub fn as_str(&self) -> &str { core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("") }

    pub fn len(&self) -> usize { self.len }

    pub fn is_empty(&self) -> bool { self.len == 0 }

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

#[cfg(all(feature = "panic-handler", not(feature = "std"), not(target_os = "xous"), not(test)))]
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

/// Wallets' keys (the `wallet` permission, host API 3: `api = 3`): public keys and signatures on
/// the derivation paths the app's manifest names (`[wallet] paths = ["m/84'/0'"]`), and nowhere
/// else. maki keeps the seed and does the curve's work, at native speed; the app works out what
/// to sign, shows the owner on maki's own review screen (`Review`), and makes as many signatures
/// as it said it would, within two minutes of their yes. `Error::Locked` while maki is locked or
/// has no phrase; `Error::Refused` off its paths, or without a yes.
///
/// With the `wallet` feature, and an allocator (a `std` app has one).
#[cfg(feature = "wallet")]
pub mod wallet {
    use alloc::string::String;
    use alloc::vec::Vec;

    pub use maki_hd::{HARDENED, Public, Tweak, format_path, parse_path};

    use super::{Answer, Error, result, sys};

    const PUBLIC: i32 = maki_hd::op::PUBLIC as i32;
    const UNCOMPRESSED: i32 = maki_hd::op::UNCOMPRESSED as i32;
    const TAPROOT: i32 = maki_hd::op::TAPROOT as i32;
    const SIGN_ECDSA: i32 = maki_hd::op::SIGN_ECDSA as i32;
    const SIGN_SCHNORR: i32 = maki_hd::op::SIGN_SCHNORR as i32;
    const SIGN_TAPROOT: i32 = maki_hd::op::SIGN_TAPROOT as i32;
    const MONERO: i32 = maki_hd::op::MONERO_PUBLIC as i32;
    const ED25519: i32 = maki_hd::op::ED25519_PUBLIC as i32;

    /// The master key's fingerprint, as descriptors and PSBTs name the seed.
    pub fn fingerprint() -> Result<[u8; 4], Error> {
        let mut out = [0u8; 4];
        result(unsafe { sys::wallet_fingerprint(out.as_mut_ptr()) })?;
        Ok(out)
    }

    fn public_form<const N: usize>(path: &[u32], form: i32) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        let n = result(unsafe { sys::wallet_public(path.as_ptr(), path.len(), form, out.as_mut_ptr(), N) })?;
        if n as usize != N {
            return Err(Error::Failed);
        }
        Ok(out)
    }

    /// The public key at `path` (compressed), with its chain code and its parent's fingerprint:
    /// what an extended public key carries.
    pub fn public(path: &[u32]) -> Result<Public, Error> {
        let b: [u8; 69] = public_form(path, PUBLIC)?;
        Ok(Public {
            key: b[..33].try_into().unwrap(),
            chain_code: b[33..65].try_into().unwrap(),
            parent_fingerprint: b[65..].try_into().unwrap(),
        })
    }

    /// The public key at `path`, uncompressed: what an Ethereum address hashes.
    pub fn uncompressed(path: &[u32]) -> Result<[u8; 65], Error> { public_form(path, UNCOMPRESSED) }

    /// The taproot output key the key at `path` makes with no scripts (BIP86), x only.
    pub fn taproot_output(path: &[u32]) -> Result<[u8; 32], Error> { public_form(path, TAPROOT) }

    /// A Monero account's public spend and view keys (host API 4), for the account at `path`,
    /// `m/44'/128'/account'/0/0` (as Ledger's Monero app has it; Monero's coin type alone): its
    /// own address's (`maki_xmr::address`).
    pub fn monero(path: &[u32]) -> Result<([u8; 32], [u8; 32]), Error> {
        let b: [u8; 64] = public_form(path, MONERO)?;
        Ok((b[..32].try_into().unwrap(), b[32..].try_into().unwrap()))
    }

    /// A Monero subaddress's public spend and view keys (host API 4): account `major`'s address
    /// `minor`, of the account at `path` (0 and 0 are the account's own address). maki makes them
    /// with the view key, which it keeps.
    pub fn subaddress(path: &[u32], major: u32, minor: u32) -> Result<([u8; 32], [u8; 32]), Error> {
        let mut out = [0u8; 64];
        result(unsafe {
            sys::wallet_subaddress(path.as_ptr(), path.len(), major as i32, minor as i32, out.as_mut_ptr())
        })?;
        Ok((out[..32].try_into().unwrap(), out[32..].try_into().unwrap()))
    }

    /// Has maki show its owner the backup words of the account at `path` (a Monero wallet's 25,
    /// which restore it in any Monero wallet), on maki's own screens, once they've said they want
    /// them (host API 4). From host API 9, a BIP-85 child seed's too: at
    /// `m/83696968'/39'/0'/{words}'/{index}'`, 12, 18 or 24 words, a phrase of its own for another
    /// wallet, which maki makes from its own. The words never reach the app: `Answer::Yes` once
    /// they were shown. `Error::NotFound` for an account without words of its own.
    pub fn show_backup(path: &[u32]) -> Result<Answer, Error> {
        result(unsafe { sys::wallet_show_backup(path.as_ptr(), path.len()) }).map(|a| match a {
            0 => Answer::Yes,
            1 => Answer::No,
            _ => Answer::NoAnswer,
        })
    }

    /// A Monero account's secret view key (host API 5), for the account at `path`: what a computer
    /// finds the account's outputs with, and can't spend them. It takes one of what the owner's
    /// last yes to a review allows: ask first.
    pub fn monero_view_key(path: &[u32]) -> Result<[u8; 32], Error> {
        let mut out = [0u8; 32];
        result(unsafe { sys::wallet_monero_view_key(path.as_ptr(), path.len(), out.as_mut_ptr()) })?;
        Ok(out)
    }

    /// An output's key image, and what proves it's the image of that output (Monero's ring
    /// signature of one), as a view-only wallet imports them to learn what's spent (host API 5):
    /// the output of the account at `path` with key `key`, output `index` of a transaction with
    /// public key `tx_key` (or the output's own), paid to subaddress `minor` of account `major`.
    /// `Error::Failed` if it isn't the account's.
    pub fn monero_key_image(
        path: &[u32],
        tx_key: &[u8; 32],
        index: u64,
        major: u32,
        minor: u32,
        key: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 64]), Error> {
        let mut output = [0u8; 80];
        output[..32].copy_from_slice(tx_key);
        output[32..40].copy_from_slice(&index.to_le_bytes());
        output[40..44].copy_from_slice(&major.to_le_bytes());
        output[44..48].copy_from_slice(&minor.to_le_bytes());
        output[48..].copy_from_slice(key);
        let mut out = [0u8; 96];
        result(unsafe {
            sys::wallet_monero_key_image(path.as_ptr(), path.len(), output.as_ptr(), out.as_mut_ptr())
        })?;
        Ok((out[..32].try_into().unwrap(), out[32..].try_into().unwrap()))
    }

    /// A Monero transaction made and signed by maki (host API 5), from the account at `path`:
    /// `request` says what it spends and pays (`maki_xmr::request`); maki makes the outputs, the
    /// range proof and a signature for each input, of what the owner's last yes allows. The
    /// signed transaction (`maki_xmr::spend::Signed`'s bytes), or why maki didn't sign.
    pub fn monero_sign(path: &[u32], request: &[u8]) -> Result<Result<Vec<u8>, String>, Error> {
        let mut out = alloc::vec![0u8; request.len() + 8192];
        let n = result(unsafe {
            sys::wallet_monero_sign(
                path.as_ptr(),
                path.len(),
                request.as_ptr(),
                request.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        })? as usize;
        out.truncate(n);
        match out.split_first() {
            Some((0, signed)) => Ok(Ok(signed.to_vec())),
            Some((_, why)) => Ok(Err(String::from_utf8_lossy(why).into_owned())),
            None => Err(Error::Failed),
        }
    }

    /// An Ed25519 public key (host API 6), by SLIP-10 from the phrase, at `path`, every step of it
    /// hardened: a Solana account's address, at `m/44'/501'/account'/0'` (as Phantom, Solflare and
    /// Ledger's app have it).
    pub fn ed25519_public(path: &[u32]) -> Result<[u8; 32], Error> { public_form(path, ED25519) }

    /// An Ed25519 signature (RFC 8032) with the key at `path`, over the whole of `message`, up to
    /// 16 KiB (host API 6): a Solana transaction's message, say. Checked by maki before it's
    /// returned, and one of what the owner's last yes to a review allows.
    pub fn sign_ed25519(path: &[u32], message: &[u8]) -> Result<[u8; 64], Error> {
        let mut out = [0u8; 64];
        result(unsafe {
            sys::wallet_sign_ed25519(
                path.as_ptr(),
                path.len(),
                message.as_ptr(),
                message.len(),
                out.as_mut_ptr(),
            )
        })?;
        Ok(out)
    }

    fn sign<const N: usize>(path: &[u32], digest: &[u8; 32], scheme: i32) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        let n = result(unsafe {
            sys::wallet_sign(path.as_ptr(), path.len(), digest.as_ptr(), scheme, out.as_mut_ptr(), N)
        })?;
        if n as usize != N {
            return Err(Error::Failed);
        }
        Ok(out)
    }

    /// An ECDSA signature over a 32-byte digest with the key at `path`: r and s (s low), and the
    /// recovery ID (0 or 1). Deterministic (RFC 6979), and checked by maki before it's returned.
    pub fn sign_ecdsa(path: &[u32], digest: &[u8; 32]) -> Result<([u8; 64], u8), Error> {
        let b: [u8; 65] = sign(path, digest, SIGN_ECDSA)?;
        Ok((b[..64].try_into().unwrap(), b[64]))
    }

    /// A BIP340 signature over a 32-byte message with the key at `path`, tweaked for a taproot key
    /// spend or not. maki adds fresh randomness from its TRNG.
    pub fn sign_schnorr(path: &[u32], digest: &[u8; 32], tweak: Tweak) -> Result<[u8; 64], Error> {
        sign(path, digest, if tweak == Tweak::Taproot { SIGN_TAPROOT } else { SIGN_SCHNORR })
    }

    /// A page of a review, as maki's review screen lays it out: `heading` (a few words at the top,
    /// up to 32 bytes), `value` (the thing to check, bold), `mono` (fixed-width, across as many
    /// lines as it takes: an address), `prose` (small words, wrapped: what it means).
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Page {
        pub heading: String,
        pub value: String,
        pub mono: String,
        pub prose: String,
    }

    impl Page {
        pub fn new(heading: &str) -> Page { Page { heading: heading.into(), ..Page::default() } }

        pub fn value(self, value: &str) -> Page { Page { value: value.into(), ..self } }

        pub fn mono(self, mono: &str) -> Page { Page { mono: mono.into(), ..self } }

        pub fn prose(self, prose: &str) -> Page { Page { prose: prose.into(), ..self } }
    }

    /// What the owner goes through on maki's own review screen before the app signs, a page at a
    /// time under the app's bar, then its question: `Review::new("Sign and spend?").detail("0.0007
    /// BTC").page(Page::new("Send").value("0.0007 BTC").mono(address)).signatures(2).show()`. A yes
    /// lets the app make `signatures` signatures in the next two minutes; a new review ends what the
    /// last allowed.
    #[derive(Clone, Debug, Default)]
    pub struct Review {
        question: String,
        detail: String,
        yes: String,
        no: String,
        pages: Vec<Page>,
        signatures: u32,
        timeout_s: i32,
    }

    impl Review {
        /// The question, up to 64 bytes.
        pub fn new(question: &str) -> Review {
            Review { question: question.into(), signatures: 1, ..Review::default() }
        }

        /// A line more about it, up to 128 bytes.
        pub fn detail(self, detail: &str) -> Review { Review { detail: detail.into(), ..self } }

        /// The answers' labels, up to 16 bytes each ("sign" and "reject" if not given).
        pub fn answers(self, yes: &str, no: &str) -> Review {
            Review { yes: yes.into(), no: no.into(), ..self }
        }

        pub fn page(mut self, page: Page) -> Review {
            self.pages.push(page);
            self
        }

        /// How many signatures a yes allows (1 if not given).
        pub fn signatures(self, signatures: u32) -> Review { Review { signatures, ..self } }

        /// How long the owner has, 5 to 300 seconds (120 if not given).
        pub fn timeout(self, seconds: u32) -> Review {
            Review { timeout_s: seconds.min(i32::MAX as u32) as i32, ..self }
        }

        /// The text maki's `wallet_review` takes.
        pub fn text(&self) -> String {
            let mut text = alloc::format!("{}\n{}\n{}\n{}", self.question, self.detail, self.yes, self.no);
            for p in &self.pages {
                for (sep, part) in
                    [('\x1e', &p.heading), ('\x1f', &p.value), ('\x1f', &p.mono), ('\x1f', &p.prose)]
                {
                    text.push(sep);
                    text.push_str(part);
                }
            }
            text
        }

        /// Shows it and waits. `Error::Invalid` for text too long for maki's screen, or with
        /// control characters where they can't be.
        pub fn show(self) -> Result<Answer, Error> {
            let text = self.text();
            let code = unsafe {
                sys::wallet_review(text.as_ptr(), text.len(), self.signatures as i32, self.timeout_s)
            };
            result(code).map(|a| match a {
                0 => Answer::Yes,
                1 => Answer::No,
                _ => Answer::NoAnswer,
            })
        }
    }

    /// maki's keys as `maki_hd::Keys`, for maki-btc's and maki-eth's accounts: public keys and
    /// signatures through maki, which checks the paths and the owner's yes.
    pub struct HostKeys;

    fn keys_error(e: Error, refused: maki_hd::Error) -> maki_hd::Error {
        match e {
            Error::Locked => maki_hd::Error::Locked,
            Error::Refused => refused,
            _ => maki_hd::Error::Failed,
        }
    }

    impl maki_hd::Keys for HostKeys {
        fn fingerprint(&self) -> Result<[u8; 4], maki_hd::Error> {
            fingerprint().map_err(|e| keys_error(e, maki_hd::Error::Path))
        }

        fn public(&self, path: &[u32]) -> Result<Public, maki_hd::Error> {
            public(path).map_err(|e| keys_error(e, maki_hd::Error::Path))
        }

        fn uncompressed(&self, path: &[u32]) -> Result<[u8; 65], maki_hd::Error> {
            uncompressed(path).map_err(|e| keys_error(e, maki_hd::Error::Path))
        }

        fn taproot_output(&self, path: &[u32]) -> Result<[u8; 32], maki_hd::Error> {
            taproot_output(path).map_err(|e| keys_error(e, maki_hd::Error::Path))
        }

        fn sign_ecdsa(&self, path: &[u32], digest: &[u8; 32]) -> Result<([u8; 64], u8), maki_hd::Error> {
            sign_ecdsa(path, digest).map_err(|e| keys_error(e, maki_hd::Error::NotAllowed))
        }

        fn sign_schnorr(
            &self,
            path: &[u32],
            digest: &[u8; 32],
            tweak: Tweak,
        ) -> Result<[u8; 64], maki_hd::Error> {
            sign_schnorr(path, digest, tweak).map_err(|e| keys_error(e, maki_hd::Error::NotAllowed))
        }
    }
}
