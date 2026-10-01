//! Name Tag: your name on maki's screen, as big as it fits, with a line under it, and a link of
//! yours as a QR code people can scan. The centre (or left and right) turns between the name and
//! the code. The words come from a QR code you make, scanned from the menu: up to three lines,
//! your name, the line under it and the link (a `|` between them does too, for a QR code maker
//! that won't take new lines). Nothing is sent anywhere.

#![no_std]

use maki_app::*;

/// What a tag may hold: more wouldn't fit on maki's screen anyway.
const MAX_TAG: usize = 200;

/// Sizes a name may be drawn at, biggest first: maki's fonts made bigger (host API 9).
const SIZES: [(Style, i32); 9] = [
    (Style::Bold, 4),
    (Style::Tall, 3),
    (Style::Bold, 3),
    (Style::Tall, 2),
    (Style::Bold, 2),
    (Style::Tall, 1),
    (Style::Bold, 1),
    (Style::Regular, 1),
    (Style::Small, 1),
];

/// The tag's lines: the name, the line under it, the link (each perhaps empty).
fn lines(tag: &str) -> [&str; 3] {
    let mut out = [""; 3];
    let sep = if tag.contains('\n') { '\n' } else { '|' };
    for (slot, line) in out.iter_mut().zip(tag.split(sep)) {
        *slot = line.trim();
    }
    out
}

/// Most lines a name, or the line under it, is drawn on.
const MAX_LINES: usize = 9;

/// Text in lines, each a piece of it.
struct Lines<'a> {
    line: [&'a str; MAX_LINES],
    n: usize,
}

/// Where the first line of `rest` ends: as many words as fit `width` at `size`, or (`by_chars`,
/// when not even one word does) as many characters. None if not one word fits.
fn line_end(rest: &str, (style, scale): (Style, i32), width: i32, by_chars: bool) -> Option<usize> {
    let fits = |end: usize| screen::text_scaled_width(rest[..end].trim_end(), style, scale) <= width;
    let spaces = rest.match_indices(' ').map(|(i, _)| i).chain(core::iter::once(rest.len()));
    let words = spaces.take_while(|&i| fits(i)).last();
    if words.is_some() || !by_chars {
        return words;
    }
    // a character a line at least, however narrow the room
    let chars = rest.char_indices().map(|(i, _)| i).skip(1).chain(core::iter::once(rest.len()));
    chars.take_while(|&i| fits(i)).last().or(rest.chars().next().map(char::len_utf8))
}

/// `text` in at most `max` lines that fit `width` at `size`, broken at spaces (or, `by_chars`,
/// wherever a word won't fit): None if a word won't (and not `by_chars`); and whether all of it
/// made it.
fn wrap(text: &str, size: (Style, i32), width: i32, max: usize, by_chars: bool) -> Option<(Lines<'_>, bool)> {
    let mut out = Lines { line: [""; MAX_LINES], n: 0 };
    let mut rest = text.trim();
    while !rest.is_empty() && out.n < max.min(MAX_LINES) {
        let end = line_end(rest, size, width, by_chars)?;
        out.line[out.n] = rest[..end].trim_end();
        out.n += 1;
        rest = rest[end..].trim_start();
    }
    Some((out, rest.is_empty()))
}

/// `text` as big as it fits `width` by `height`, on as many lines as that takes: the size and
/// the lines. Too long for any size, it's broken where it must be, and what won't fit is left off.
fn fit(text: &str, width: i32, height: i32) -> ((Style, i32), Lines<'_>) {
    for size in SIZES {
        let max = (height / (size.0.height() * size.1)) as usize;
        if let Some((lines, true)) = wrap(text, size, width, max, false) {
            return (size, lines);
        }
    }
    let small = (Style::Small, 1);
    let max = (height / Style::Small.height()).max(1) as usize;
    let lines = wrap(text, small, width, max, true).map(|(l, _)| l);
    (small, lines.unwrap_or(Lines { line: [""; MAX_LINES], n: 0 }))
}

fn centred(y: i32, s: &str, (style, scale): (Style, i32)) {
    let x = (WIDTH - screen::text_scaled_width(s, style, scale)) / 2;
    screen::text_scaled(x, y, s, style, scale, Color::Light);
}

/// The name, and under a rule the line under it in small type (on two lines if it must),
/// together in the middle of the screen.
fn draw_name(name: &str, under: &str) {
    let small = Style::Small.height();
    let (under, _) = wrap(under, (Style::Small, 1), WIDTH - 4, 2, true)
        .unwrap_or((Lines { line: [""; MAX_LINES], n: 0 }, true));
    // the rule and the room around it
    let under_h = if under.n == 0 { 0 } else { under.n as i32 * small + 8 };
    let (size, lines) = fit(name, WIDTH - 4, HEIGHT - under_h);
    let line = size.0.height() * size.1;
    let mut y = (HEIGHT - lines.n as i32 * line - under_h) / 2;
    for l in &lines.line[..lines.n] {
        centred(y, l, size);
        y += line;
    }
    if under.n > 0 {
        screen::fill_rect(WIDTH / 2 - 16, y + 3, 32, 1, Color::Light);
        y += 8;
        for l in &under.line[..under.n] {
            screen::text_centred(y, l, Style::Small, Color::Light);
            y += small;
        }
    }
}

/// The link as a QR code, as big as fits, and the link under it if it fits a line.
fn draw_link(link: &str) {
    let labelled = screen::text_width(link, Style::Small) <= WIDTH;
    let room = if labelled { HEIGHT - Style::Small.height() } else { HEIGHT };
    // drawn once to learn its size, then again in the middle
    match screen::qr(0, 0, link.as_bytes(), room) {
        Some(side) => {
            screen::clear(Color::Dark);
            let _ = screen::qr((WIDTH - side) / 2, (room - side) / 2, link.as_bytes(), room);
            if labelled {
                screen::text_centred(room, link, Style::Small, Color::Light);
            }
        }
        None => {
            screen::text_centred(HEIGHT / 2 - 12, "too long for", Style::Small, Color::Light);
            screen::text_centred(HEIGHT / 2, "a QR code here", Style::Small, Color::Light);
        }
    }
}

fn draw_empty() {
    let says = [
        "Make a QR code of three",
        "lines: your name, a line",
        "under it, and a link.",
        "Then, from the menu:",
    ];
    for (i, line) in says.iter().enumerate() {
        screen::text_centred(18 + 12 * i as i32, line, Style::Small, Color::Light);
    }
    screen::text_centred(72, "Scan your tag", Style::Bold, Color::Light);
}

fn main() {
    let _ = menu(&["Scan your tag", "Clear"]);
    let mut buf = [0u8; MAX_TAG];
    let mut len = storage::get("tag", &mut buf).filter(|&n| n <= MAX_TAG).unwrap_or(0);
    let mut showing_link = false;
    let mut note: Option<&str> = None;
    loop {
        let tag = core::str::from_utf8(&buf[..len]).unwrap_or("");
        let [name, under, link] = lines(tag);
        screen::clear(Color::Dark);
        if name.is_empty() && under.is_empty() && link.is_empty() {
            draw_empty();
        } else if showing_link || (name.is_empty() && under.is_empty()) {
            draw_link(link);
        } else {
            draw_name(name, under);
        }
        if let Some(n) = note {
            screen::fill_rect(0, HEIGHT - 13, WIDTH, 13, Color::Dark);
            screen::text_centred(HEIGHT - 12, n, Style::Small, Color::Light);
        }
        screen::present();
        match wait(None) {
            Event::Centre | Event::Left | Event::Right => {
                note = None;
                showing_link = !showing_link && !link.is_empty();
            }
            Event::Menu(0) => {
                let mut scanned = [0u8; 2 * MAX_TAG];
                note = match camera::scan_qr(&mut scanned) {
                    Some(text) if text.len() > MAX_TAG => Some("that's more than a tag holds"),
                    Some(text) if text.trim().is_empty() => Some("that QR code is empty"),
                    Some(text) => {
                        len = text.len();
                        buf[..len].copy_from_slice(text.as_bytes());
                        showing_link = false;
                        if storage::set("tag", &buf[..len]).is_ok() { None } else { Some("couldn't keep it") }
                    }
                    // cancelled
                    None => None,
                };
            }
            Event::Menu(1) => {
                len = 0;
                showing_link = false;
                note = None;
                storage::delete("tag");
            }
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
