//! The PIN pad (ARCHITECTURE.md, "Boot PIN"): one digit at a time, with the three buttons.
//!
//! Each position starts on a random digit, so the number of presses gives nothing away. Left and
//! right step down and up through 0-9, then delete (once there's a digit to delete) and done
//! (once there are enough digits); the centre confirms and moves on. Entered digits show as dots.

use blitstr2::GlyphStyle;
use ux_api::minigfx::*;

use crate::ui::{Key, LINE, Screen, W};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Opt {
    Digit(u8),
    Delete,
    Done,
}

pub(crate) struct PinPad {
    pub(crate) title: String,
    /// a line under the title: how long a PIN is, or how many tries are left
    pub(crate) note: String,
    entered: Vec<u8>,
    choice: Opt,
}

fn random_digit() -> u8 {
    // a demo build (MAKI_DEMO, for the emulator) starts every position at 0, so a scripted run
    // can type a PIN without seeing the screen
    if option_env!("MAKI_DEMO").is_some() {
        return 0;
    }
    let mut b = [0u8; 1];
    getrandom::getrandom(&mut b).ok();
    b[0] % 10
}

impl PinPad {
    pub(crate) fn new(title: &str, note: &str) -> Self {
        PinPad { title: title.into(), note: note.into(), entered: Vec::new(), choice: Opt::Digit(random_digit()) }
    }

    fn options(&self) -> Vec<Opt> {
        let mut o = Vec::new();
        if self.entered.len() < maki_keys::MAX_PIN {
            o.extend((0..10).map(Opt::Digit));
        }
        if !self.entered.is_empty() {
            o.push(Opt::Delete);
        }
        if self.entered.len() >= maki_keys::MIN_PIN {
            o.push(Opt::Done);
        }
        o
    }

    /// A new position: a random digit, or whatever's left if no more digits fit.
    fn next_position(&mut self) {
        let options = self.options();
        self.choice = if options.contains(&Opt::Digit(0)) { Opt::Digit(random_digit()) } else { options[0] };
    }

    /// Returns the PIN once the owner confirms done.
    pub(crate) fn key(&mut self, key: Key) -> Option<String> {
        let options = self.options();
        let at = options.iter().position(|&o| o == self.choice).unwrap_or(0);
        let n = options.len();
        match key {
            Key::Left => self.choice = options[(at + n - 1) % n],
            Key::Right => self.choice = options[(at + 1) % n],
            Key::Confirm => match self.choice {
                Opt::Digit(d) => {
                    self.entered.push(d);
                    self.next_position();
                }
                Opt::Delete => {
                    self.entered.pop();
                    self.next_position();
                }
                Opt::Done => {
                    let pin: String = self.entered.iter().map(|d| (b'0' + d) as char).collect();
                    self.clear();
                    return Some(pin);
                }
            },
            Key::Menu => {}
        }
        None
    }

    /// Forget the digits.
    pub(crate) fn clear(&mut self) {
        for d in self.entered.iter_mut() {
            *d = 0;
        }
        self.entered.clear();
        self.next_position();
    }

    pub(crate) fn draw(&self, screen: &Screen, clock: &str, linked: bool) {
        screen.begin();
        screen.status_bar(clock, linked);
        let top = screen.bar + 4;
        screen.text(top, LINE, GlyphStyle::Bold, false, true, &self.title);
        screen.text(top + LINE + 2, LINE, GlyphStyle::Small, false, true, &self.note);

        // the row: a dot per digit, the one being chosen, then blanks up to six
        let slots = (self.entered.len() + 1).max(maki_keys::MIN_PIN).min(maki_keys::MAX_PIN);
        let current = self.entered.len();
        // a fixed-width character and a space, narrowing as the PIN grows so twelve digits fit
        let cell = (16isize).min((W - 4) / slots as isize);
        let x0 = (W - cell * slots as isize) / 2;
        let y = top + 2 * LINE + 10;
        for i in 0..slots {
            let x = x0 + i as isize * cell;
            let glyph = if i < current {
                "•".to_string()
            } else if i == current {
                match self.choice {
                    Opt::Digit(d) => d.to_string(),
                    Opt::Delete => "<".into(),
                    Opt::Done => String::new(), // a check mark, drawn below
                }
            } else {
                "_".into()
            };
            if i == current && self.choice == Opt::Done {
                let style = DrawStyle::new(PixelColor::Light, PixelColor::Light, 2);
                let (l, m, r) = (x + cell / 5, x + cell / 2 - 1, x + cell - cell / 6);
                screen.gfx.draw_line(Line::new_with_style(Point::new(l, y + 8), Point::new(m, y + 12), style)).ok();
                screen.gfx.draw_line(Line::new_with_style(Point::new(m, y + 12), Point::new(r, y + 3), style)).ok();
            }
            let mut tv = TextView::new(
                ux_api::service::api::Gid::dummy(),
                TextBounds::CenteredTop(Rectangle::new(Point::new(x, y), Point::new(x + cell, y + LINE))),
            );
            tv.style = GlyphStyle::Monospace;
            tv.invert = true;
            tv.draw_border = false;
            tv.margin = Point::new(0, 0);
            use std::fmt::Write;
            write!(tv, "{}", glyph).ok();
            screen.gfx.draw_textview(&mut tv).ok();
            if i == current {
                // underline the one being chosen
                screen
                    .gfx
                    .draw_line(Line::new_with_style(
                        Point::new(x + 1, y + LINE + 1),
                        Point::new(x + cell - 2, y + LINE + 1),
                        DrawStyle::new(PixelColor::Light, PixelColor::Light, 2),
                    ))
                    .ok();
            }
        }

        let action = match self.choice {
            Opt::Digit(d) => format!("enter {}", d),
            Opt::Delete => "delete a digit".into(),
            Opt::Done => "done".into(),
        };
        screen.action_bar(&action, true);
        screen.end();
    }
}
