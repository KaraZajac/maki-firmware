//! Rolls dice: the centre rolls, left and right change how many (one to three). Keeps count
//! of the rolls in storage, which the menu resets.

#![no_std]

use core::fmt::Write;

use maki_app::*;

const SIDE: i32 = 34;

/// Where a die's pips go, as grid cells 0..3 across and down.
fn pips(n: u32) -> &'static [(i32, i32)] {
    match n {
        1 => &[(1, 1)],
        2 => &[(0, 0), (2, 2)],
        3 => &[(0, 0), (1, 1), (2, 2)],
        4 => &[(0, 0), (2, 0), (0, 2), (2, 2)],
        5 => &[(0, 0), (2, 0), (1, 1), (0, 2), (2, 2)],
        _ => &[(0, 0), (2, 0), (0, 1), (2, 1), (0, 2), (2, 2)],
    }
}

fn die(x: i32, y: i32, n: u32) {
    screen::fill_rect(x, y, SIDE, SIDE, Color::Light);
    for &(cx, cy) in pips(n) {
        screen::fill_rect(x + 6 + cx * 9, y + 6 + cy * 9, 5, 5, Color::Dark);
    }
}

fn draw(dice: &[u32], count: u32) {
    screen::clear(Color::Dark);
    let n = dice.len() as i32;
    let gap = 6;
    let left = (WIDTH - n * SIDE - (n - 1) * gap) / 2;
    for (i, &d) in dice.iter().enumerate() {
        die(left + i as i32 * (SIDE + gap), 18, d);
    }
    let total: u32 = dice.iter().sum();
    let mut line = Buf::<32>::new();
    if n > 1 {
        let _ = write!(line, "total {total}");
    }
    screen::text_centred(60, line.as_str(), Style::Regular, Color::Light);
    line.clear();
    let _ = write!(line, "{count} rolls");
    screen::text_centred(78, line.as_str(), Style::Small, Color::Light);
    screen::text_centred(94, "centre: roll", Style::Small, Color::Light);
    screen::present();
}

fn main() {
    let _ = menu(&["Reset count"]);
    let mut dice = [6u32, 6, 6];
    let mut n = 2;
    let mut count = storage::get_u32("rolls", 0);
    loop {
        draw(&dice[..n], count);
        match wait(None) {
            Event::Centre => {
                for d in dice.iter_mut().take(n) {
                    *d = 1 + random_below(6);
                }
                count += 1;
                let _ = storage::set_u32("rolls", count);
            }
            Event::Left if n > 1 => n -= 1,
            Event::Right if n < 3 => n += 1,
            Event::Menu(0) => {
                count = 0;
                storage::delete("rolls");
            }
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
