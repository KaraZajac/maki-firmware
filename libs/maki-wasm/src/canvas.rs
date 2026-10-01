//! What an app draws on: the screen below maki's bar, one bit a pixel. Every drawing call is
//! clipped to it and bounded in work, since the app's fuel doesn't pay for what the host does.

use blitstr2::GlyphSprite;

/// The app's part of the screen: all of its width, and what's below maki's bar.
pub const WIDTH: usize = 128;
pub const HEIGHT: usize = 110;
/// Where the app's part starts on maki's screen.
pub const TOP: usize = 18;
const WORDS: usize = WIDTH / 32;
/// Coordinates are clamped to this far off the canvas, which bounds a line's length.
pub(crate) const REACH: i32 = 1024;
/// Most characters one `text` call draws.
const MAX_CHARS: usize = 256;
/// Largest scale `text_scaled` draws at: maki's tallest font eight times over is more than the
/// screen.
pub const MAX_SCALE: i32 = 8;
/// Largest bitmap `blit` takes, each way.
pub const MAX_BLIT: i32 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Color {
    Dark = 0,
    Light = 1,
    /// Flips what's there.
    Invert = 2,
}

impl Color {
    pub fn from_i32(v: i32) -> Option<Color> {
        match v {
            0 => Some(Color::Dark),
            1 => Some(Color::Light),
            2 => Some(Color::Invert),
            _ => None,
        }
    }
}

/// maki's fonts, as the app names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    Regular = 0,
    Bold = 1,
    Small = 2,
    Mono = 3,
    Tall = 4,
}

impl Style {
    pub fn from_i32(v: i32) -> Option<Style> {
        match v {
            0 => Some(Style::Regular),
            1 => Some(Style::Bold),
            2 => Some(Style::Small),
            3 => Some(Style::Mono),
            4 => Some(Style::Tall),
            _ => None,
        }
    }

    /// Height of a line of text in this style.
    pub fn height(self) -> i32 {
        match self {
            Style::Small => 12,
            Style::Tall => 19,
            _ => 15,
        }
    }

    fn glyph(self, c: char) -> Option<GlyphSprite> {
        let lookup = |c| match self {
            Style::Regular => blitstr2::regular_glyph(c),
            Style::Bold => blitstr2::bold_glyph(c),
            Style::Small => blitstr2::small_glyph(c),
            Style::Mono => blitstr2::mono_glyph(c),
            Style::Tall => blitstr2::tall_glyph(c),
        };
        lookup(c).or_else(|_| lookup('\u{fffd}')).ok()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Canvas {
    /// Row-major, four words a row, pixel x at bit x % 32 of word x / 32; a set bit is light.
    bits: [u32; WORDS * HEIGHT],
}

impl Default for Canvas {
    fn default() -> Self { Canvas { bits: [0; WORDS * HEIGHT] } }
}

impl core::fmt::Debug for Canvas {
    /// As text, `#` for light, for tests to show.
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        for y in 0..HEIGHT as i32 {
            for x in 0..WIDTH as i32 {
                f.write_str(if self.get(x, y) { "#" } else { "." })?;
            }
            f.write_str("\n")?;
        }
        Ok(())
    }
}

impl Canvas {
    pub fn get(&self, x: i32, y: i32) -> bool {
        if x < 0 || y < 0 || x >= WIDTH as i32 || y >= HEIGHT as i32 {
            return false;
        }
        let (x, y) = (x as usize, y as usize);
        self.bits[y * WORDS + x / 32] & (1 << (x % 32)) != 0
    }

    fn put(&mut self, x: i32, y: i32, color: Color) {
        if x < 0 || y < 0 || x >= WIDTH as i32 || y >= HEIGHT as i32 {
            return;
        }
        let (x, y) = (x as usize, y as usize);
        let (word, bit) = (&mut self.bits[y * WORDS + x / 32], 1u32 << (x % 32));
        match color {
            Color::Dark => *word &= !bit,
            Color::Light => *word |= bit,
            Color::Invert => *word ^= bit,
        }
    }

    pub fn clear(&mut self, color: Color) {
        match color {
            Color::Dark => self.bits = [0; WORDS * HEIGHT],
            Color::Light => self.bits = [u32::MAX; WORDS * HEIGHT],
            Color::Invert => self.bits.iter_mut().for_each(|w| *w = !*w),
        }
    }

    pub fn pixel(&mut self, x: i32, y: i32, color: Color) { self.put(x, y, color) }

    /// Bresenham's, end points included; each pixel once, so Invert lines come out whole.
    pub fn line(&mut self, x0: i32, y0: i32, x1: i32, y1: i32, color: Color) {
        let c = |v: i32| v.clamp(-REACH, REACH);
        let (mut x, mut y, x1, y1) = (c(x0), c(y0), c(x1), c(y1));
        let (dx, dy) = ((x1 - x).abs(), -(y1 - y).abs());
        let (sx, sy) = (if x < x1 { 1 } else { -1 }, if y < y1 { 1 } else { -1 });
        let mut err = dx + dy;
        loop {
            self.put(x, y, color);
            if x == x1 && y == y1 {
                break;
            }
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                x += sx;
            }
            if e2 <= dx {
                err += dx;
                y += sy;
            }
        }
    }

    /// An outline, or filled; each pixel once.
    pub fn rect(&mut self, x: i32, y: i32, w: i32, h: i32, color: Color, filled: bool) {
        if w <= 0 || h <= 0 {
            return;
        }
        let (x0, y0) = (x.max(0), y.max(0));
        let (x1, y1) = (x.saturating_add(w).min(WIDTH as i32), y.saturating_add(h).min(HEIGHT as i32));
        let (right, bottom) = (x.saturating_add(w - 1), y.saturating_add(h - 1));
        for py in y0..y1 {
            for px in x0..x1 {
                if filled || px == x || px == right || py == y || py == bottom {
                    self.put(px, py, color);
                }
            }
        }
    }

    /// Draws `s` with its top left at (x, y), glyph pixels only; returns where the next
    /// character would go.
    pub fn text(&mut self, x: i32, y: i32, s: &str, style: Style, color: Color) -> i32 {
        self.text_scaled(x, y, s, style, 1, color)
    }

    /// `text` with each pixel of the font a `scale` by `scale` square (1 to `MAX_SCALE`; others
    /// are clamped to it): big text from maki's own fonts, for a name tag or a number read
    /// across a room. `text_width` times `scale` is how wide it is.
    pub fn text_scaled(&mut self, x: i32, y: i32, s: &str, style: Style, scale: i32, color: Color) -> i32 {
        let scale = scale.clamp(1, MAX_SCALE);
        let mut pen = x.clamp(-REACH, REACH);
        let y = y.clamp(-REACH, REACH);
        for c in s.chars().take(MAX_CHARS) {
            let Some(g) = style.glyph(c) else { continue };
            let reach = 32 * scale;
            if pen < WIDTH as i32 && pen + reach > 0 && y < HEIGHT as i32 && y + reach > 0 {
                self.glyph(pen, y, &g, scale, color);
            }
            pen += (g.wide + g.kern) as i32 * scale;
        }
        pen
    }

    pub fn text_width(s: &str, style: Style) -> i32 {
        let mut w = 0;
        for c in s.chars().take(MAX_CHARS) {
            if let Some(g) = style.glyph(c) {
                w += (g.wide + g.kern) as i32;
            }
        }
        // no gap after the last character
        if w > 0 { w - 1 } else { 0 }
    }

    fn glyph(&mut self, x: i32, y: i32, g: &GlyphSprite, scale: i32, color: Color) {
        let dot = |canvas: &mut Canvas, col: i32, row: i32| {
            if scale == 1 {
                canvas.put(x + col, y + row, color);
            } else {
                canvas.rect(x + col * scale, y + row * scale, scale, scale, color, true);
            }
        };
        if g.large {
            // a word a row, 32 pixels wide
            for (row, bits) in g.glyph.iter().enumerate().take(g.high as usize) {
                for col in 0..32 {
                    if bits & (1 << col) != 0 {
                        dot(self, col, row as i32);
                    }
                }
            }
        } else {
            // two 16-pixel rows a word
            for row in 0..(g.high as usize).min(16) {
                let bits = (g.glyph[row >> 1] >> ((row & 1) * 16)) & 0xffff;
                for col in 0..16 {
                    if bits & (1 << col) != 0 {
                        dot(self, col, row as i32);
                    }
                }
            }
        }
    }

    /// A bitmap of `w` by `h` pixels, each row `(w + 7) / 8` bytes, leftmost pixel in the top
    /// bit, as PBM and most 1-bit tools have it. Set bits are drawn in `color`; the rest are
    /// left alone.
    pub fn blit(&mut self, x: i32, y: i32, w: i32, h: i32, rows: &[u8], color: Color) {
        let stride = ((w + 7) / 8) as usize;
        for row in 0..h {
            for col in 0..w {
                let byte = rows[row as usize * stride + (col / 8) as usize];
                if byte & (0x80 >> (col % 8)) != 0 {
                    self.put(x + col, y + row, color);
                }
            }
        }
    }

    /// `data` as a QR code, as big as fits `size` pixels square with its top left at (x, y):
    /// dark modules on light, with a quiet zone. Returns the side drawn, or None if it doesn't
    /// fit or is too much for a QR code.
    pub fn qr(&mut self, x: i32, y: i32, data: &[u8], size: i32) -> Option<i32> {
        let code = qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::L).ok()?;
        let modules = code.width() as i32;
        // two modules of quiet zone, as maki's own codes have
        let quiet = 2;
        let scale = size.min(WIDTH as i32) / (modules + 2 * quiet);
        if scale < 1 {
            return None;
        }
        let side = (modules + 2 * quiet) * scale;
        self.rect(x, y, side, side, Color::Light, true);
        for (i, color) in code.to_colors().iter().enumerate() {
            if *color == qrcode::Color::Dark {
                let (mx, my) = (i as i32 % modules + quiet, i as i32 / modules + quiet);
                self.rect(x + mx * scale, y + my * scale, scale, scale, Color::Dark, true);
            }
        }
        Some(side)
    }

    /// The canvas as maki's display takes a bitmap: 128 pixels a row, a set bit dark.
    pub fn to_display(&self) -> [u32; WORDS * HEIGHT] {
        let mut out = [0u32; WORDS * HEIGHT];
        for (o, w) in out.iter_mut().zip(self.bits.iter()) {
            *o = !*w;
        }
        out
    }

    /// Rows of pixels as bits, a set bit light: for simulators and screenshots.
    pub fn words(&self) -> &[u32; WORDS * HEIGHT] { &self.bits }
}
