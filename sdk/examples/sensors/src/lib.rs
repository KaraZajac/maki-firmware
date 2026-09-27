//! The camera and motion permissions at work: a spirit level from the accelerometer, updated a
//! few times a second, and a QR code reader: the centre scans (with maki's own scanner) and
//! shows what the code says.

#![no_std]

use core::fmt::Write;

use maki_app::*;

/// The level's circle, and where the bubble can go.
const CX: i32 = 40;
const CY: i32 = 44;
const R: i32 = 30;

fn draw(tilt: Option<(i16, i16, i16)>, scanned: &str) {
    screen::clear(Color::Dark);
    // the level: a circle, a cross, and the bubble, which floats to the high side
    for a in 0..64 {
        let (s, c) = SIN_COS[a];
        screen::pixel(CX + (R * c) / 100, CY + (R * s) / 100, Color::Light);
    }
    screen::line(CX - 4, CY, CX + 4, CY, Color::Light);
    screen::line(CX, CY - 4, CX, CY + 4, Color::Light);
    let mut line = Buf::<24>::new();
    match tilt {
        Some((x, y, z)) => {
            let bx = CX - (x as i32 * R / 1000).clamp(-R, R);
            let by = CY + (y as i32 * R / 1000).clamp(-R, R);
            screen::fill_rect(bx - 3, by - 3, 7, 7, Color::Invert);
            for (i, (name, v)) in [("x", x), ("y", y), ("z", z)].iter().enumerate() {
                line.clear();
                let _ = write!(line, "{name} {v}");
                screen::text(80, 16 + i as i32 * 14, line.as_str(), Style::Small, Color::Light);
            }
        }
        None => {
            screen::text(80, 30, "no level", Style::Small, Color::Light);
        }
    }
    screen::text_centred(80, if scanned.is_empty() { "centre: scan a QR code" } else { scanned }, Style::Small, Color::Light);
    screen::present();
}

/// sin and cos (hundredths) every 1/64 turn, for the circle.
const SIN_COS: [(i32, i32); 64] = {
    // a quarter from a small table, the rest by symmetry
    const Q: [i32; 17] = [0, 10, 20, 29, 38, 47, 56, 63, 71, 77, 83, 88, 92, 96, 98, 100, 100];
    let mut t = [(0, 0); 64];
    let mut i = 0;
    while i < 64 {
        let q = i % 16;
        let (s, c) = (Q[q], Q[16 - q]);
        t[i] = match i / 16 {
            0 => (s, c),
            1 => (c, -s),
            2 => (-s, -c),
            _ => (-c, s),
        };
        i += 1;
    }
    t
};

fn main() {
    let mut scanned = Buf::<32>::new();
    loop {
        draw(motion::read(), scanned.as_str());
        // a few times a second, for the level
        match wait(Some(250)) {
            Event::Centre => {
                let mut text = [0u8; 256];
                scanned.clear();
                match camera::scan_qr(&mut text) {
                    Some(t) => {
                        for c in t.chars().take(21) {
                            let _ = scanned.write_char(c);
                        }
                    }
                    None => {
                        let _ = scanned.write_str("nothing scanned");
                    }
                }
            }
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
