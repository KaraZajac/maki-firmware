//! The screensaver: after a minute with nothing pressed, maki's own screens give way to a clock
//! that fills the screen, the hours over the minutes, in local time. maki is always plugged in,
//! so there's no power to save; but its screen is an OLED, and anything that stays put burns in,
//! so the clock moves a few pixels every minute. Any key brings back what was there, and does
//! nothing else.

use crate::clock_face::{CELL_H, CELL_W, GLYPHS};

/// How long with nothing pressed before the clock.
pub const AFTER_MS: u64 = 60_000;
/// Whether the screen rests at all. Not in the emulator's demos, unless MAKI_DEMO_SAVER says:
/// while everything waits, the emulator's clock runs far ahead of its instructions, so a minute
/// goes by between one scripted press and the next, and each would only wake the screen.
pub const RESTS: bool = option_env!("MAKI_DEMO").is_none() || option_env!("MAKI_DEMO_SAVER").is_some();
/// Between the two digits of a row, and between the rows.
const GAP: i32 = 4;
const LEAD: i32 = 6;
/// Where the clock sits, minute by minute: a few pixels this way and that, so no pixel is lit
/// for long in one place.
const DRIFT: [(i32, i32); 12] = [
    (0, 0),
    (5, -2),
    (-5, 2),
    (2, 3),
    (-3, -3),
    (7, 1),
    (-7, -1),
    (1, -3),
    (-2, 3),
    (6, 3),
    (-6, -2),
    (3, -1),
];
/// The dash glyph: no time yet.
const DASH: usize = 10;

/// The whole screen, as the graphics server's full-screen bitmap has it: 128 rows of four
/// words, pixel x in bit x % 32 of word x / 32, a set bit dark. `time` is the local hour and
/// minute, None while maki doesn't know it.
pub fn frame(time: Option<(u32, u32)>) -> [u32; 512] {
    let mut screen = [u32::MAX; 512];
    let digits = match time {
        Some((h, m)) => [(h / 10 % 10) as usize, (h % 10) as usize, (m / 10) as usize, (m % 10) as usize],
        None => [DASH; 4],
    };
    let (dx, dy) = DRIFT[time.map(|(h, m)| (h * 60 + m) as usize).unwrap_or(0) % DRIFT.len()];
    let (w, h) = (CELL_W as i32, CELL_H as i32);
    let left = (128 - (2 * w + GAP)) / 2 + dx;
    let top = (128 - (2 * h + LEAD)) / 2 + dy;
    for (i, &d) in digits.iter().enumerate() {
        let (col, row) = (i as i32 % 2, i as i32 / 2);
        let (gx, gy) = (left + col * (w + GAP), top + row * (h + LEAD));
        for (r, bits) in GLYPHS[d].iter().enumerate() {
            let y = gy + r as i32;
            if !(0..128).contains(&y) {
                continue;
            }
            for c in 0..w {
                let x = gx + c;
                if bits >> c & 1 == 1 && (0..128).contains(&x) {
                    screen[y as usize * 4 + x as usize / 32] &= !(1 << (x % 32));
                }
            }
        }
    }
    screen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(screen: &[u32; 512]) -> usize { screen.iter().map(|w| w.count_zeros() as usize).sum() }

    #[test]
    fn the_clock_fills_the_screen_and_moves_each_minute() {
        let a = frame(Some((22, 39)));
        let b = frame(Some((22, 40)));
        assert!(lit(&a) > 2000, "big digits");
        assert_ne!(a, b);
        // the same time, the same place; and something shows without a time
        assert_eq!(a, frame(Some((22, 39))));
        assert!(lit(&frame(None)) > 0);
        // every drift keeps the clock on the screen
        for (dx, dy) in DRIFT {
            let (w, h) = (CELL_W as i32, CELL_H as i32);
            assert!(
                (128 - (2 * w + GAP)) / 2 + dx >= 0 && (128 - (2 * w + GAP)) / 2 + dx + 2 * w + GAP <= 128
            );
            assert!(
                (128 - (2 * h + LEAD)) / 2 + dy >= 0 && (128 - (2 * h + LEAD)) / 2 + dy + 2 * h + LEAD <= 128
            );
        }
    }
}
