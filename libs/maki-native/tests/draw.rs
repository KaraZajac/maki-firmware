//! A frame's drawing, recorded in a native app and read back in maki.

use maki_native::draw::*;

#[test]
fn every_operation_reads_back() {
    let ops = [
        Draw::Clear { color: 1 },
        Draw::Pixel { x: -3, y: 127, color: 0 },
        Draw::Line { x0: 0, y0: 1, x1: 127, y1: 90, color: 1 },
        Draw::Rect { x: 4, y: 5, w: 60, h: 20, color: 1, filled: true },
        Draw::Text { x: 2, y: 30, style: 2, color: 1, text: "maki ✓" },
        Draw::Blit { x: 8, y: 8, w: 16, h: 2, color: 1, rows: &[0xff, 0x0f, 0xf0, 0x00] },
        Draw::Qr { x: 0, y: 0, size: 3, data: b"otpauth://totp/x" },
    ];
    let mut f = Frame::new();
    for op in &ops {
        f.push(op);
    }
    let back: Vec<_> = read(f.bytes()).collect::<Result<_, _>>().unwrap();
    assert_eq!(back, ops);
    assert!(!f.full);
}

#[test]
fn a_frame_stays_within_its_message() {
    let mut f = Frame::new();
    let big = [0u8; 4000];
    for _ in 0..10 {
        f.push(&Draw::Blit { x: 0, y: 0, w: 128, h: 128, color: 1, rows: &big });
    }
    assert!(f.full);
    assert!(f.bytes().len() <= MAX_FRAME);
    // what fitted still reads
    assert_eq!(read(f.bytes()).count(), 4);
    f.clear();
    assert!(!f.full && f.bytes().is_empty());
}

#[test]
fn garbage_stops_the_frame_without_panicking() {
    let mut x: u32 = 0x1234_5678;
    for n in 0..20_000 {
        let bytes: Vec<u8> = (0..(n % 64))
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        let ops: Vec<_> = read(&bytes).collect();
        // at most one error, and it's the last
        assert!(ops.iter().rev().skip(1).all(|o| o.is_ok()));
    }
    assert_eq!(read(&[99]).next(), Some(Err(Malformed)));
    assert_eq!(read(&[TEXT_OP, 0, 0, 0, 0, 0, 0, 2, 0, 0xff, 0xfe]).next(), Some(Err(Malformed)));
}

const TEXT_OP: u8 = 5;
