//! Dice for tabletop games, in the notation players say: 3d6 is three six-sided dice. The jog
//! dial on maki's side picks the die (d2 up to d20), left and right take one away or add one (1 to
//! 20 of them), and the centre rolls. The total shows big, each die's roll beneath it, and a
//! single d20 says when it's a natural 20 or a natural 1. The dice last picked are kept.

#![no_std]

use core::fmt::Write;

use maki_app::*;

/// The dice, smallest to largest.
const SIDES: [u32; 7] = [2, 4, 6, 8, 10, 12, 20];
/// How many at most.
const MOST: usize = 20;

/// Seven-segment digits: segments a to g (top, top right, bottom right, bottom, bottom left,
/// top left, middle) as bits 0 to 6.
const SEGMENTS: [u8; 10] = [0x3f, 0x06, 0x5b, 0x4f, 0x66, 0x6d, 0x7d, 0x07, 0x7f, 0x6f];
const DIGIT_W: i32 = 18;
const DIGIT_H: i32 = 32;
const STROKE: i32 = 4;
const DIGIT_GAP: i32 = 6;

fn digit(x: i32, y: i32, d: u32) {
    let s = SEGMENTS[d as usize % 10];
    let (w, h, t) = (DIGIT_W, DIGIT_H, STROKE);
    let upper = (x, y, h / 2 + t / 2);
    let lower = (x, y + h / 2 - t / 2, h - h / 2 + t / 2);
    let bars = [
        (s & 0x01 != 0, (x, y, w, t)),
        (s & 0x02 != 0, (x + w - t, upper.1, t, upper.2)),
        (s & 0x04 != 0, (x + w - t, lower.1, t, lower.2)),
        (s & 0x08 != 0, (x, y + h - t, w, t)),
        (s & 0x10 != 0, (x, lower.1, t, lower.2)),
        (s & 0x20 != 0, (x, upper.1, t, upper.2)),
        (s & 0x40 != 0, (x, y + h / 2 - t / 2, w, t)),
    ];
    for (on, (bx, by, bw, bh)) in bars {
        if on {
            screen::fill_rect(bx, by, bw, bh, Color::Light);
        }
    }
}

/// A number in big digits, centred across the screen, from `y` down.
fn big_number(y: i32, n: u32) {
    let mut digits = [0u32; 4];
    let mut len = 0;
    let mut rest = n;
    loop {
        digits[len] = rest % 10;
        len += 1;
        rest /= 10;
        if rest == 0 || len == digits.len() {
            break;
        }
    }
    let width = len as i32 * DIGIT_W + (len as i32 - 1) * DIGIT_GAP;
    let mut x = (WIDTH - width) / 2;
    for &d in digits[..len].iter().rev() {
        digit(x, y, d);
        x += DIGIT_W + DIGIT_GAP;
    }
}

/// Each die's roll, as many lines as it takes up to two: "3 + 5 + 1", or just the numbers when
/// that doesn't fit, and ".." at the end of the second line if even they don't.
fn rolls_lines(y: i32, rolls: &[u32]) {
    let mut sum = Buf::<96>::new();
    for (i, r) in rolls.iter().enumerate() {
        let _ = write!(sum, "{}{r}", if i == 0 { "" } else { " + " });
    }
    if screen::text_width(sum.as_str(), Style::Small) <= WIDTH - 4 {
        screen::text_centred(y, sum.as_str(), Style::Small, Color::Light);
        return;
    }
    let mut line = Buf::<48>::new();
    let mut row = 0;
    for (i, r) in rolls.iter().enumerate() {
        let mut word = Buf::<8>::new();
        let _ = write!(word, "{}{r}", if line.as_str().is_empty() { "" } else { " " });
        let mut trial = Buf::<48>::new();
        let _ = write!(trial, "{}{}", line.as_str(), word.as_str());
        if screen::text_width(trial.as_str(), Style::Small) <= WIDTH - 4 {
            line = trial;
            continue;
        }
        if row == 1 {
            let _ = write!(line, " ..");
            break;
        }
        screen::text_centred(y, line.as_str(), Style::Small, Color::Light);
        row += 1;
        line.clear();
        let _ = write!(line, "{r}");
        if i + 1 == rolls.len() {
            break;
        }
    }
    screen::text_centred(y + row * Style::Small.height(), line.as_str(), Style::Small, Color::Light);
}

fn draw(count: usize, sides: u32, rolls: Option<&[u32]>) {
    screen::clear(Color::Dark);
    let mut dice = Buf::<8>::new();
    let _ = write!(dice, "{count}d{sides}");
    screen::text_centred(4, dice.as_str(), Style::Tall, Color::Light);
    match rolls {
        None => {
            screen::text_centred(38, "centre: roll", Style::Regular, Color::Light);
            screen::text_centred(70, "dial: which die", Style::Small, Color::Light);
            screen::text_centred(84, "left, right: how many", Style::Small, Color::Light);
        }
        Some(rolls) => {
            big_number(30, rolls.iter().sum());
            if rolls.len() > 1 {
                rolls_lines(70, rolls);
            } else if sides == 20 && rolls[0] == 20 {
                screen::text_centred(78, "natural 20!", Style::Bold, Color::Light);
            } else if sides == 20 && rolls[0] == 1 {
                screen::text_centred(78, "natural 1", Style::Bold, Color::Light);
            }
        }
    }
    screen::present();
}

fn main() {
    // the dice last picked: how many, and which (its place in SIDES)
    let mut count = (storage::get_u32("count", 1) as usize).clamp(1, MOST);
    let mut die = (storage::get_u32("die", 6) as usize).min(SIDES.len() - 1);
    let mut rolls = [0u32; MOST];
    let mut rolled = false;
    loop {
        draw(count, SIDES[die], rolled.then_some(&rolls[..count]));
        let (was_count, was_die) = (count, die);
        match wait(None) {
            Event::Centre => {
                for r in rolls[..count].iter_mut() {
                    *r = 1 + random_below(SIDES[die]);
                }
                rolled = true;
            }
            Event::Up => die = (die + 1).min(SIDES.len() - 1),
            Event::Down => die = die.saturating_sub(1),
            Event::Right => count = (count + 1).min(MOST),
            Event::Left => count = count.saturating_sub(1).max(1),
            Event::Exit => return,
            _ => {}
        }
        if (count, die) != (was_count, was_die) {
            // other dice: the roll shown was of the ones before
            rolled = false;
            let _ = storage::set_u32("count", count as u32);
            let _ = storage::set_u32("die", die as u32);
        }
    }
}

maki_app::main!(main);
