//! Passphrases from maki's random number generator: words from the EFF's long word list, four
//! to eight of them. The centre makes a new one; left and right take a word away or add one.
//! The passphrase is never stored; the menu types it into the computer, with the separator the
//! menu picks.
//!
//! The words are the Electronic Frontier Foundation's long word list (https://www.eff.org/dice),
//! under CC BY 3.0 US: 7,776 of them, so each is worth log2(7776) ≈ 12.925 bits.

#![no_std]

use core::fmt::Write;

use maki_app::*;

const WORDS: &str = include_str!("words.txt");
const LIST: u32 = 7776;
/// Bits a word is worth, in thousandths.
const MILLIBITS: u32 = 12_925;
const FEWEST: usize = 4;
const MOST: usize = 8;
const SEPARATORS: [(&str, &str); 3] = [(" ", "spaces"), ("-", "hyphens"), (".", "dots")];

fn word(i: u32) -> &'static str { WORDS.lines().nth(i as usize).unwrap_or("?") }

fn roll(words: &mut [&str]) {
    for w in words.iter_mut() {
        *w = word(random_below(LIST));
    }
}

fn draw(words: &[&str], note: &str) {
    screen::clear(Color::Dark);
    let n = words.len();
    if n <= 6 {
        // a column, in maki's regular font
        let line = 15;
        let top = (96 - n as i32 * line) / 2;
        for (i, w) in words.iter().enumerate() {
            screen::text_centred(top + i as i32 * line, w, Style::Regular, Color::Light);
        }
    } else {
        // two columns of the small font: down the left, then the right
        let rows = n.div_ceil(2);
        let line = 16;
        let top = (96 - rows as i32 * line) / 2;
        for (i, w) in words.iter().enumerate() {
            let x = if i < rows { 3 } else { 66 };
            screen::text(x, top + (i % rows) as i32 * line, w, Style::Small, Color::Light);
        }
    }
    screen::line(0, 97, WIDTH - 1, 97, Color::Light);
    let mut info = Buf::<48>::new();
    if note.is_empty() {
        let _ = write!(info, "{n} words, {} bits", n as u32 * MILLIBITS / 1000);
    } else {
        let _ = info.write_str(note);
    }
    screen::text_centred(99, info.as_str(), Style::Small, Color::Light);
    screen::present();
}

fn main() {
    let _ = menu(&["Type it", "Separator"]);
    let mut n = (storage::get_u32("words", 6) as usize).clamp(FEWEST, MOST);
    let mut sep = (storage::get_u32("separator", 0) as usize).min(SEPARATORS.len() - 1);
    let mut words = [""; MOST];
    roll(&mut words);
    let mut note = Buf::<48>::new();
    loop {
        draw(&words[..n], note.as_str());
        let event = wait(None);
        note.clear();
        match event {
            Event::Centre => roll(&mut words),
            Event::Left | Event::Right => {
                n = if event == Event::Left { (n - 1).max(FEWEST) } else { (n + 1).min(MOST) };
                roll(&mut words);
                let _ = storage::set_u32("words", n as u32);
            }
            Event::Menu(0) => {
                let mut text = Buf::<96>::new();
                for (i, w) in words[..n].iter().enumerate() {
                    if i > 0 {
                        let _ = text.write_str(SEPARATORS[sep].0);
                    }
                    let _ = text.write_str(w);
                }
                let _ = match keyboard::type_text(text.as_str()) {
                    Ok(()) => write!(note, "typed, with {}", SEPARATORS[sep].1),
                    Err(_) => note.write_str("couldn't type it"),
                };
            }
            Event::Menu(1) => {
                sep = (sep + 1) % SEPARATORS.len();
                let _ = storage::set_u32("separator", sep as u32);
                let _ = write!(note, "typed with {}", SEPARATORS[sep].1);
            }
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
