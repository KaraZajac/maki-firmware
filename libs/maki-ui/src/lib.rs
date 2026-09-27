//! maki's screen: the keys and the drawing shared by the launcher and every app, so that all of
//! them look and work alike.
//!
//! Everything runs on the three buttons on the badge's face (ARCHITECTURE.md, "Three
//! buttons"): left and right move, the centre confirms what the screen offers, and left and
//! right pressed together open the menu. There is no back button: leaving is always something a
//! screen offers. The jog dial on the side isn't used.
//!
//! A screen has a status bar at the top (`status_bar`, or `titled_bar` with a page's heading)
//! and an action bar at the bottom saying what the centre does (`action_bar`), with arrows when
//! left and right have somewhere to go.

use std::fmt::Write;

use blitstr2::GlyphStyle;
use ux_api::minigfx::*;
use ux_api::platform::{HEIGHT, WIDTH};
use ux_api::service::api::Gid;
use ux_api::service::gfx::Gfx;

pub const W: isize = WIDTH as isize;
pub const H: isize = HEIGHT as isize;
/// A line of regular or fixed-width text.
pub const LINE: isize = 16;
/// A line of small text: the button labels.
pub const SMALL_LINE: isize = 12;
/// Width of the right-hand slot of the status bar (the clock, or an ask's countdown).
const CLOCK_WIDTH: isize = 40;
const NAME: &str = "maki";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    Left,
    Right,
    /// the centre
    Confirm,
    /// left and right together
    Menu,
}

impl Key {
    /// The face buttons. The jog dial's up and down mean nothing here; pressing it in does what
    /// the centre does.
    pub fn from_char(c: char) -> Option<Key> {
        match c {
            '←' => Some(Key::Left),
            '→' => Some(Key::Right),
            '🔥' | '∴' => Some(Key::Confirm),
            bao1x_api::keyboard::MENU => Some(Key::Menu),
            _ => None,
        }
    }
}

pub struct Screen {
    pub gfx: Gfx,
    /// height of the status bar
    pub bar: isize,
}

impl Screen {
    pub fn new(xns: &xous_names::XousNames) -> Self {
        let bar = ux_api::widgets::ScrollableList::default().row_height() as isize;
        Screen { gfx: Gfx::new(xns).unwrap(), bar }
    }

    /// Start a frame: whatever was queued goes out, then a blank screen.
    pub fn begin(&self) {
        self.gfx.flush().ok();
        self.gfx.clear().ok();
    }

    pub fn end(&self) { self.gfx.flush().ok(); }

    /// Text in a band across the screen, light on dark; `highlight` for dark on light, as a
    /// selection is marked. Anything but fixed-width text ends in "…" if it runs long; callers
    /// lay fixed-width text out to fit (a site's end must never be cut).
    pub fn text(&self, top: isize, height: isize, style: GlyphStyle, highlight: bool, centred: bool, s: &str) {
        let band = Rectangle::new(Point::new(0, top), Point::new(W, top + height));
        let mut tv =
            TextView::new(Gid::dummy(), if centred { TextBounds::CenteredTop(band) } else { TextBounds::BoundingBox(band) });
        tv.style = style;
        tv.invert = !highlight;
        tv.draw_border = false;
        tv.ellipsis = style != GlyphStyle::Monospace;
        tv.margin = Point::new(2, 0);
        write!(tv, "{}", s).ok();
        self.gfx.draw_textview(&mut tv).ok();
    }

    fn light() -> DrawStyle { DrawStyle::new(PixelColor::Light, PixelColor::Light, 1) }

    /// The bar across the top: the name on the left, `right` (the clock, or a countdown) on the
    /// right, and a dot between while the desktop app is linked.
    pub fn status_bar(&self, right: &str, linked: bool) { self.titled_bar(NAME, right, linked) }

    /// The bar across the top with a title in place of the name: the heading of a page.
    pub fn titled_bar(&self, title: &str, right: &str, linked: bool) {
        let mut name = TextView::new(
            Gid::dummy(),
            TextBounds::BoundingBox(Rectangle::new(Point::new(0, 0), Point::new(W - CLOCK_WIDTH, self.bar))),
        );
        name.style = GlyphStyle::Bold;
        name.invert = true;
        name.draw_border = false;
        name.ellipsis = true;
        name.margin = Point::new(2, 0);
        write!(name, "{}", title).ok();
        self.gfx.draw_textview(&mut name).ok();

        let mut clock = TextView::new(
            Gid::dummy(),
            TextBounds::CenteredTop(Rectangle::new(Point::new(W - CLOCK_WIDTH, 2), Point::new(W, self.bar))),
        );
        clock.style = GlyphStyle::Small;
        clock.invert = true;
        clock.draw_border = false;
        clock.margin = Point::new(0, 0);
        write!(clock, "{}", right).ok();
        self.gfx.draw_textview(&mut clock).ok();

        if linked {
            self.gfx
                .draw_circle(Circle::new_with_style(
                    Point::new(W - CLOCK_WIDTH - 6, self.bar / 2),
                    2,
                    Self::light(),
                ))
                .ok();
        }
        self.gfx
            .draw_line(Line::new_with_style(Point::new(0, self.bar + 1), Point::new(W, self.bar + 1), Self::light()))
            .ok();
    }

    /// A small arrow, `size` pixels from tip to base, its tip at (x, y).
    pub fn arrow(&self, x: isize, y: isize, size: isize, left: bool) {
        for i in 0..size {
            let col = if left { x + i } else { x - i };
            self.gfx
                .draw_line(Line::new_with_style(Point::new(col, y - i), Point::new(col, y + i), Self::light()))
                .ok();
        }
    }

    /// The bottom line: what a press of the centre does now, boxed, and arrows at the sides
    /// when left and right have somewhere to go. No action, no box.
    pub fn action_bar(&self, action: &str, arrows: bool) {
        let top = H - SMALL_LINE;
        if arrows {
            self.arrow(3, top + SMALL_LINE / 2, 5, true);
            self.arrow(W - 4, top + SMALL_LINE / 2, 5, false);
        }
        if action.is_empty() {
            return;
        }
        let mut tv = TextView::new(
            Gid::dummy(),
            TextBounds::CenteredTop(Rectangle::new(Point::new(12, top), Point::new(W - 12, H))),
        );
        tv.style = GlyphStyle::Small;
        tv.invert = false; // dark on light: the thing the centre does
        tv.draw_border = false;
        tv.ellipsis = true;
        tv.margin = Point::new(3, 0);
        write!(tv, "{}", action).ok();
        self.gfx.draw_textview(&mut tv).ok();
    }

    /// A 64x64 icon (see `maki_icons`) with its top left corner at (x, y).
    pub fn icon(&self, icon: &[u32; 128], x: isize, y: isize) {
        let mut bits = [0u32; 512];
        for row in 0..64 {
            bits[row * 4] = icon[row * 2];
            bits[row * 4 + 1] = icon[row * 2 + 1];
        }
        self.gfx
            .bitmap(&bits, Some(Point::new(x, y)), Some(Rectangle::new(Point::new(0, 0), Point::new(64, 64))))
            .ok();
    }

    /// An app without an icon of its own: its initial in a rounded square.
    pub fn letter_icon(&self, name: &str, x: isize, y: isize) {
        self.gfx
            .draw_rounded_rectangle(RoundedRectangle::new(
                Rectangle::new_with_style(
                    Point::new(x + 4, y + 4),
                    Point::new(x + 60, y + 60),
                    DrawStyle::new(PixelColor::Dark, PixelColor::Light, 3),
                ),
                10,
            ))
            .ok();
        let initial: String = name.chars().next().map(|c| c.to_uppercase().collect()).unwrap_or_default();
        let mut tv = TextView::new(
            Gid::dummy(),
            TextBounds::CenteredTop(Rectangle::new(Point::new(x, y + 22), Point::new(x + 64, y + 44))),
        );
        tv.style = GlyphStyle::Tall;
        tv.invert = true;
        tv.draw_border = false;
        tv.margin = Point::new(0, 0);
        write!(tv, "{}", initial).ok();
        self.gfx.draw_textview(&mut tv).ok();
    }

    /// `text` as a QR code, as big as fits a `size` pixel square centred at `x`, top at `top`,
    /// quiet zone included: dark modules on light, however dark the screen around it. Returns
    /// false if it can't fit (too much text for the room).
    pub fn qr(&self, text: &str, x: isize, top: isize, size: isize) -> bool {
        let Ok(code) = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::L) else {
            return false;
        };
        let modules = code.width() as isize;
        // two modules of quiet zone each side: less than the standard's four, which scanners
        // manage at this size, and it buys a bigger module
        let quiet = 2;
        let scale = size / (modules + 2 * quiet);
        if scale < 1 {
            return false;
        }
        let side = (modules + 2 * quiet) * scale;
        let mut bits = [0u32; 512];
        for (i, color) in code.to_colors().iter().enumerate() {
            if *color != qrcode::Color::Dark {
                continue;
            }
            let (mx, my) = ((i as isize % modules + quiet) * scale, (i as isize / modules + quiet) * scale);
            for y in my..my + scale {
                for x in mx..mx + scale {
                    // a 128-pixel-wide bitmap, a set bit dark
                    bits[(y * 4 + x / 32) as usize] |= 1 << (x % 32);
                }
            }
        }
        self.gfx
            .bitmap(&bits, Some(Point::new(x - side / 2, top)), Some(Rectangle::new(Point::new(0, 0), Point::new(side, side))))
            .ok();
        true
    }

    /// One dot per page, the current one filled, centred at height `y`.
    pub fn dots(&self, count: usize, current: usize, y: isize) {
        if count < 2 {
            return;
        }
        let gap = 8;
        let start = W / 2 - (count as isize - 1) * gap / 2;
        for i in 0..count {
            let style = if i == current {
                Self::light()
            } else {
                DrawStyle::new(PixelColor::Dark, PixelColor::Light, 1)
            };
            self.gfx.draw_circle(Circle::new_with_style(Point::new(start + i as isize * gap, y), 2, style)).ok();
        }
    }
}
