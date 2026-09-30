//! A tally counter: the centre adds one, left takes one away, right adds ten, and the jog dial on
//! maki's side counts one up or down, for counting with a thumb. The count is kept in storage, so
//! it survives leaving the app and unplugging maki.

#![no_std]

use maki_app::*;

// seven segments: top, top right, bottom right, bottom, bottom left, top left, middle
const DIGITS: [u8; 10] = [0x3f, 0x06, 0x5b, 0x4f, 0x66, 0x6d, 0x7d, 0x07, 0x7f, 0x6f];
const W: i32 = 20;
const H: i32 = 40;
const T: i32 = 4;

fn digit(x: i32, y: i32, d: usize) {
    let s = DIGITS[d];
    let half = H / 2;
    let bars = [
        (x, y, W, T),
        (x + W - T, y, T, half),
        (x + W - T, y + half, T, half),
        (x, y + H - T, W, T),
        (x, y + half, T, half),
        (x, y, T, half),
        (x, y + half - T / 2, W, T),
    ];
    for (i, &(bx, by, bw, bh)) in bars.iter().enumerate() {
        if s & (1 << i) != 0 {
            screen::fill_rect(bx, by, bw, bh, Color::Light);
        }
    }
}

fn draw(count: u32) {
    screen::clear(Color::Dark);
    let mut digits = [0usize; 5];
    let mut n = 0;
    let mut c = count;
    loop {
        digits[n] = (c % 10) as usize;
        n += 1;
        c /= 10;
        if c == 0 || n == digits.len() {
            break;
        }
    }
    let gap = 6;
    let width = n as i32 * W + (n as i32 - 1) * gap;
    let left = (WIDTH - width) / 2;
    for i in 0..n {
        digit(left + i as i32 * (W + gap), 16, digits[n - 1 - i]);
    }
    screen::text_centred(72, "centre +1  right +10", Style::Small, Color::Light);
    screen::text_centred(86, "left -1", Style::Small, Color::Light);
    screen::present();
}

fn main() {
    let _ = menu(&["Reset"]);
    let mut count = storage::get_u32("count", 0);
    loop {
        draw(count);
        let before = count;
        match wait(None) {
            Event::Centre | Event::Up => count = (count + 1).min(99_999),
            Event::Down => count = count.saturating_sub(1),
            Event::Right => count = (count + 10).min(99_999),
            Event::Left => count = count.saturating_sub(1),
            Event::Menu(0) => count = 0,
            Event::Exit => return,
            _ => {}
        }
        if count != before {
            let _ = storage::set_u32("count", count);
        }
    }
}

maki_app::main!(main);
