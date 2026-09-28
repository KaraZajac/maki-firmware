//! A sign on maki's screen, big enough to read across the room: Available, Busy, On a call and
//! the like. Left and right go through them; the centre turns the screen light, to be noticed.
//!
//! Software on the computer can set it (the link permission): a message of text shows that text
//! (printable ASCII, up to 40 characters, as big as it fits) and is answered "ok"; the name of
//! one of the signs picks it; an empty message asks what's showing.

#![no_std]

mod font;

use core::fmt::Write;

use font::{BIG, Font, Glyph, MEDIUM, SMALL};
use maki_app::*;

const SIGNS: [&str; 9] =
    ["Available", "Busy", "On a call", "In a meeting", "Do not disturb", "Focusing", "Away", "Lunch", "BRB"];
/// The longest text the computer can set.
const MOST: usize = 40;
/// Left and right show where the sign is among them for this long.
const DOTS_MS: u64 = 1500;

fn glyph(f: &Font, b: u8) -> &Glyph {
    let b = if (32..127).contains(&b) { b } else { b'?' };
    &f.glyphs[(b - 32) as usize]
}

fn width(f: &Font, s: &str) -> i32 { s.bytes().map(|b| glyph(f, b).advance as i32).sum() }

fn line(f: &Font, y: i32, s: &str, color: Color) {
    let mut pen = (WIDTH - width(f, s)) / 2;
    for b in s.bytes() {
        let g = glyph(f, b);
        if g.width > 0 {
            let rows = (g.width as usize).div_ceil(8) * f.height as usize;
            let at = g.at as usize;
            screen::blit(pen + g.left as i32, y, g.width as i32, f.height, &f.bits[at..at + rows], color);
        }
        pen += g.advance as i32;
    }
}

/// `text` in lines no wider than the screen, broken at spaces: how many, or None if a word
/// alone is too wide or it needs more than `lines` holds.
fn wrap<'a>(f: &Font, text: &'a str, lines: &mut [&'a str]) -> Option<usize> {
    let max = WIDTH - 4;
    let mut n = 0;
    let mut start = 0;
    let mut end = 0;
    for (i, _) in text.match_indices(' ').chain(core::iter::once((text.len(), ""))) {
        if width(f, &text[start..i]) <= max {
            end = i;
            continue;
        }
        if end == start || n == lines.len() {
            return None;
        }
        lines[n] = &text[start..end];
        n += 1;
        start = end + 1;
        if width(f, &text[start..i]) > max {
            return None;
        }
        end = i;
    }
    if start < text.len() {
        if n == lines.len() {
            return None;
        }
        lines[n] = &text[start..end];
        n += 1;
    }
    Some(n)
}

fn draw(text: &str, light: bool, dots: Option<(usize, usize)>) {
    let (back, ink) = if light { (Color::Light, Color::Dark) } else { (Color::Dark, Color::Light) };
    screen::clear(back);
    // the biggest letters it fits in: two lines of the big ones, three of the middle, four small
    let mut lines = [""; 4];
    let fits = [(&BIG, 2), (&MEDIUM, 3), (&SMALL, 4)]
        .into_iter()
        .find_map(|(f, most)| wrap(f, text, &mut lines[..most]).map(|n| (f, n)));
    match fits {
        Some((f, n)) => {
            let top = (HEIGHT - n as i32 * f.height) / 2;
            for (i, l) in lines[..n].iter().enumerate() {
                line(f, top + i as i32 * f.height, l, ink);
            }
        }
        // a word too long for any of them: maki's own font, as it comes
        None => screen::text_centred(HEIGHT / 2 - 8, text, Style::Bold, ink),
    }
    if let Some((at, of)) = dots {
        let left = (WIDTH - of as i32 * 6) / 2;
        for i in 0..of {
            let x = left + i as i32 * 6;
            if i == at {
                screen::fill_rect(x, HEIGHT - 5, 4, 4, ink);
            } else {
                screen::rect(x, HEIGHT - 5, 4, 4, ink);
            }
        }
    }
    screen::present();
}

/// What the computer sent, as a sign can show it: printable ASCII, one space between words.
fn tidy(bytes: &[u8], out: &mut Buf<MOST>) {
    out.clear();
    for word in bytes.split(|b| b.is_ascii_whitespace()).filter(|w| !w.is_empty()) {
        if !out.is_empty() && out.len() < MOST {
            let _ = out.write_char(' ');
        }
        for &b in word {
            if out.len() < MOST {
                let _ = out.write_char(if (33..127).contains(&b) { b as char } else { '?' });
            }
        }
    }
}

fn main() {
    let _ = menu(&["Forget the computer's"]);
    // which sign: one of SIGNS, or past them, the text the computer set
    let mut at = storage::get_u32("at", 0) as usize;
    let mut own = Buf::<MOST>::new();
    let mut raw = [0u8; MOST];
    if let Some(n) = storage::get("own", &mut raw) {
        tidy(&raw[..n.min(MOST)], &mut own);
    }
    if at > SIGNS.len() || (at == SIGNS.len() && own.is_empty()) {
        at = 0;
    }
    let mut light = storage::get_u32("light", 0) == 1;
    let mut dots_until = 0;
    loop {
        let signs = SIGNS.len() + usize::from(!own.is_empty());
        let now = millis();
        let text = if at < SIGNS.len() { SIGNS[at] } else { own.as_str() };
        draw(text, light, (now < dots_until).then_some((at, signs)));
        let event = wait((now < dots_until).then(|| (dots_until - now) as u32));
        match event {
            Event::Left | Event::Right => {
                at = if event == Event::Left { (at + signs - 1) % signs } else { (at + 1) % signs };
                let _ = storage::set_u32("at", at as u32);
                dots_until = millis() + DOTS_MS;
            }
            Event::Centre => {
                light = !light;
                let _ = storage::set_u32("light", light as u32);
            }
            Event::Menu(0) => {
                own.clear();
                storage::delete("own");
                if at >= SIGNS.len() {
                    at = 0;
                    let _ = storage::set_u32("at", 0);
                }
            }
            Event::Message => {
                let mut msg = [0u8; 256];
                let n = link::read(&mut msg).unwrap_or(0).min(msg.len());
                let mut said = Buf::<MOST>::new();
                tidy(&msg[..n], &mut said);
                if said.is_empty() {
                    // a question: what's showing
                    let _ = link::reply(text.as_bytes());
                    continue;
                }
                if let Some(i) = SIGNS.iter().position(|s| s.eq_ignore_ascii_case(said.as_str())) {
                    at = i;
                } else {
                    own = said;
                    let _ = storage::set("own", own.as_str().as_bytes());
                    at = SIGNS.len();
                }
                let _ = storage::set_u32("at", at as u32);
                let _ = link::reply(b"ok");
            }
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
