//! Child Seeds: new recovery phrases made from maki's by BIP-85, each a wallet of its own (a
//! phone's hot wallet, someone in your family's, a test's). Left and right choose the number, the
//! jog dial on maki's side the length (12, 18 or 24 words), and the centre has maki show the
//! words, itself, once you say so: they never come here. maki makes the same words for the same
//! number from the same phrase, so restoring maki restores every child seed too; the app keeps
//! which numbers you've seen, to find the next.

use core::fmt::Write;

use maki_app::wallet::{self, HARDENED};
use maki_app::*;

/// BIP-85's purpose, its application for BIP39 phrases, and English.
const BIP85: u32 = 83696968 | HARDENED;
const BIP39: u32 = 39 | HARDENED;
const ENGLISH: u32 = HARDENED;
const LENGTHS: [u32; 3] = [12, 18, 24];
/// The highest number a hardened step has.
const MAX_INDEX: u32 = HARDENED - 1;
/// Numbers below this are remembered once seen, for each length.
const REMEMBERED: u32 = 64;

/// A child seed's path: `m/83696968'/39'/0'/{words}'/{index}'`.
fn path(words: u32, index: u32) -> [u32; 5] { [BIP85, BIP39, ENGLISH, words | HARDENED, index | HARDENED] }

struct Choice {
    /// which of `LENGTHS`
    length: usize,
    index: u32,
    /// the numbers seen, a bit each, for each length
    seen: [u64; 3],
}

impl Choice {
    fn load() -> Choice {
        let mut b = [0u8; 29];
        let mut c = Choice { length: 0, index: 0, seen: [0; 3] };
        if storage::get("choice", &mut b) == Some(b.len()) && (b[0] as usize) < LENGTHS.len() {
            c.length = b[0] as usize;
            c.index = u32::from_le_bytes(b[1..5].try_into().unwrap()).min(MAX_INDEX);
            for (i, s) in c.seen.iter_mut().enumerate() {
                *s = u64::from_le_bytes(b[5 + 8 * i..13 + 8 * i].try_into().unwrap());
            }
        }
        c
    }

    fn save(&self) {
        let mut b = [0u8; 29];
        b[0] = self.length as u8;
        b[1..5].copy_from_slice(&self.index.to_le_bytes());
        for (i, s) in self.seen.iter().enumerate() {
            b[5 + 8 * i..13 + 8 * i].copy_from_slice(&s.to_le_bytes());
        }
        let _ = storage::set("choice", &b);
    }

    fn words(&self) -> u32 { LENGTHS[self.length] }

    fn seen(&self) -> bool { self.index < REMEMBERED && self.seen[self.length] & 1 << self.index != 0 }
}

fn draw(c: &Choice, note: Option<&str>) {
    screen::clear(Color::Dark);
    screen::text_centred(0, "number", Style::Small, Color::Light);
    // the number, big, with arrows for left and right
    let mut n = Buf::<12>::new();
    let _ = write!(n, "{}", c.index);
    let width = |scale| screen::text_scaled_width(n.as_str(), Style::Bold, scale);
    let scale = [3, 2].into_iter().find(|&s| width(s) <= WIDTH - 30).unwrap_or(1);
    let y = 36 - Style::Bold.height() * scale / 2;
    screen::text_scaled((WIDTH - width(scale)) / 2, y, n.as_str(), Style::Bold, scale, Color::Light);
    // the arrows' tips, where there's a number that way
    for (tip, dir) in [(4, 1), (WIDTH - 5, -1)] {
        if (dir > 0 && c.index > 0) || (dir < 0 && c.index < MAX_INDEX) {
            for i in 0..5 {
                screen::line(tip + dir * i, 36 - i, tip + dir * i, 36 + i, Color::Light);
            }
        }
    }
    if c.seen() {
        screen::text_centred(60, "seen before", Style::Small, Color::Light);
    }
    // the lengths, the chosen one lit
    for (i, words) in LENGTHS.iter().enumerate() {
        let mut t = Buf::<4>::new();
        let _ = write!(t, "{words}");
        let x = 22 + 30 * i as i32;
        if i == c.length {
            screen::fill_rect(x - 3, 74, 26, 15, Color::Light);
        }
        let tw = screen::text_width(t.as_str(), Style::Bold);
        let ink = if i == c.length { Color::Dark } else { Color::Light };
        screen::text(x + (20 - tw) / 2, 74, t.as_str(), Style::Bold, ink);
    }
    let bottom = note.unwrap_or("centre: show the words");
    screen::text_centred(HEIGHT - 13, bottom, Style::Small, Color::Light);
    screen::present();
}

fn main() {
    let _ = menu(&["12 words", "18 words", "24 words", "Number 0"]);
    let mut c = Choice::load();
    let mut note: Option<&str> = None;
    loop {
        draw(&c, note);
        let event = wait(None);
        if !matches!(event, Event::Shown | Event::Hidden) {
            note = None;
        }
        match event {
            Event::Left => c.index = c.index.saturating_sub(1),
            Event::Right => c.index = (c.index + 1).min(MAX_INDEX),
            Event::Up => c.length = (c.length + LENGTHS.len() - 1) % LENGTHS.len(),
            Event::Down => c.length = (c.length + 1) % LENGTHS.len(),
            Event::Menu(i) if (i as usize) < LENGTHS.len() => c.length = i as usize,
            Event::Menu(3) => c.index = 0,
            Event::Centre => {
                // maki asks, then shows the words itself: they never come here
                note = match wallet::show_backup(&path(c.words(), c.index)) {
                    Ok(Answer::Yes) => {
                        if c.index < REMEMBERED {
                            c.seen[c.length] |= 1 << c.index;
                        }
                        None
                    }
                    Ok(_) => None,
                    Err(Error::Locked) => Some("maki is locked"),
                    Err(Error::NotFound) => Some("this maki makes none"),
                    Err(_) => Some("maki couldn't show it"),
                };
            }
            Event::Exit => {
                c.save();
                return;
            }
            _ => continue,
        }
        c.save();
    }
}

maki_app::main!(main);
