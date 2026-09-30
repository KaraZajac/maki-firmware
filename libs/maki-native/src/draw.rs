//! A frame's drawing, as a native app sends it to maki's app service with `present`: the same
//! operations a WebAssembly app calls one by one (`maki_wasm::Canvas`), recorded in the app
//! and sent in one message, since each message costs a trip through the kernel. maki draws them
//! into the app's canvas and shows it.
//!
//! Each operation is a byte naming it, then its arguments: coordinates and sizes as i16, colour
//! and style as a byte, text and bytes after a u16 length. Little-endian throughout.

use alloc::vec::Vec;

/// The most a frame's operations may take: a message of 16 KiB.
pub const MAX_FRAME: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Draw<'a> {
    Clear { color: u8 },
    Pixel { x: i16, y: i16, color: u8 },
    Line { x0: i16, y0: i16, x1: i16, y1: i16, color: u8 },
    Rect { x: i16, y: i16, w: i16, h: i16, color: u8, filled: bool },
    Text { x: i16, y: i16, style: u8, color: u8, text: &'a str },
    Blit { x: i16, y: i16, w: i16, h: i16, color: u8, rows: &'a [u8] },
    Qr { x: i16, y: i16, size: i16, data: &'a [u8] },
}

const CLEAR: u8 = 1;
const PIXEL: u8 = 2;
const LINE: u8 = 3;
const RECT: u8 = 4;
const TEXT: u8 = 5;
const BLIT: u8 = 6;
const QR: u8 = 7;

/// A frame being recorded, in the app.
#[derive(Default)]
pub struct Frame {
    bytes: Vec<u8>,
    /// Set once an operation didn't fit: the frame shows what came before it.
    pub full: bool,
}

impl Frame {
    pub fn new() -> Self { Frame::default() }

    pub fn bytes(&self) -> &[u8] { &self.bytes }

    pub fn clear(&mut self) {
        self.bytes.clear();
        self.full = false;
    }

    pub fn push(&mut self, op: &Draw) {
        let mut out = Vec::new();
        let i16s =
            |out: &mut Vec<u8>, vs: &[i16]| vs.iter().for_each(|v| out.extend_from_slice(&v.to_le_bytes()));
        let bytes16 = |out: &mut Vec<u8>, b: &[u8]| {
            let b = &b[..b.len().min(u16::MAX as usize)];
            out.extend_from_slice(&(b.len() as u16).to_le_bytes());
            out.extend_from_slice(b);
        };
        match *op {
            Draw::Clear { color } => out.extend_from_slice(&[CLEAR, color]),
            Draw::Pixel { x, y, color } => {
                out.push(PIXEL);
                i16s(&mut out, &[x, y]);
                out.push(color);
            }
            Draw::Line { x0, y0, x1, y1, color } => {
                out.push(LINE);
                i16s(&mut out, &[x0, y0, x1, y1]);
                out.push(color);
            }
            Draw::Rect { x, y, w, h, color, filled } => {
                out.push(RECT);
                i16s(&mut out, &[x, y, w, h]);
                out.extend_from_slice(&[color, filled as u8]);
            }
            Draw::Text { x, y, style, color, text } => {
                out.push(TEXT);
                i16s(&mut out, &[x, y]);
                out.extend_from_slice(&[style, color]);
                // cut at a character, never inside one
                let mut end = text.len().min(u16::MAX as usize);
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                bytes16(&mut out, &text.as_bytes()[..end]);
            }
            Draw::Blit { x, y, w, h, color, rows } => {
                out.push(BLIT);
                i16s(&mut out, &[x, y, w, h]);
                out.push(color);
                bytes16(&mut out, rows);
            }
            Draw::Qr { x, y, size, data } => {
                out.push(QR);
                i16s(&mut out, &[x, y, size]);
                bytes16(&mut out, data);
            }
        }
        if self.full || self.bytes.len() + out.len() > MAX_FRAME {
            self.full = true;
        } else {
            self.bytes.extend_from_slice(&out);
        }
    }
}

/// Why a frame couldn't be read: it's cut short, or names an operation maki doesn't know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed;

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        let s = self.b.get(self.at..self.at.checked_add(n).ok_or(Malformed)?).ok_or(Malformed)?;
        self.at += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Malformed> { Ok(self.take(1)?[0]) }

    fn i16(&mut self) -> Result<i16, Malformed> {
        let s = self.take(2)?;
        Ok(i16::from_le_bytes([s[0], s[1]]))
    }

    fn bytes16(&mut self) -> Result<&'a [u8], Malformed> {
        let s = self.take(2)?;
        self.take(u16::from_le_bytes([s[0], s[1]]) as usize)
    }
}

/// The operations in a frame, in order; stops at the first that doesn't read.
pub fn read(frame: &[u8]) -> impl Iterator<Item = Result<Draw<'_>, Malformed>> {
    let mut r = Reader { b: frame, at: 0 };
    let mut failed = false;
    core::iter::from_fn(move || {
        if failed || r.at >= r.b.len() {
            return None;
        }
        let op = (|| {
            Ok(match r.u8()? {
                CLEAR => Draw::Clear { color: r.u8()? },
                PIXEL => Draw::Pixel { x: r.i16()?, y: r.i16()?, color: r.u8()? },
                LINE => Draw::Line { x0: r.i16()?, y0: r.i16()?, x1: r.i16()?, y1: r.i16()?, color: r.u8()? },
                RECT => Draw::Rect {
                    x: r.i16()?,
                    y: r.i16()?,
                    w: r.i16()?,
                    h: r.i16()?,
                    color: r.u8()?,
                    filled: r.u8()? != 0,
                },
                TEXT => {
                    let (x, y, style, color) = (r.i16()?, r.i16()?, r.u8()?, r.u8()?);
                    let text = core::str::from_utf8(r.bytes16()?).map_err(|_| Malformed)?;
                    Draw::Text { x, y, style, color, text }
                }
                BLIT => Draw::Blit {
                    x: r.i16()?,
                    y: r.i16()?,
                    w: r.i16()?,
                    h: r.i16()?,
                    color: r.u8()?,
                    rows: r.bytes16()?,
                },
                QR => Draw::Qr { x: r.i16()?, y: r.i16()?, size: r.i16()?, data: r.bytes16()? },
                _ => return Err(Malformed),
            })
        })();
        failed = op.is_err();
        Some(op)
    })
}
