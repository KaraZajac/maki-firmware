//! Scanner: reads a QR code with maki's own scanner and shows what it says, a page at a time
//! (left and right turn them), and types it into the computer when the menu's Type it is picked
//! (the keyboard permission), as a keyboard would. A code's text can press keys a person
//! wouldn't expect, so before typing any that has line breaks or tabs it says how many Enters
//! and Tabs that makes and waits for the centre. What it reads is never stored.

#![no_std]

use core::fmt::Write;

use maki_app::*;

/// More than the most a QR code holds (version 40: 4,296 characters, fewer bytes).
const MOST: usize = 4400;
/// Lines a page shows, under the heading, and where they start.
const LINES: usize = 6;
const TOP: i32 = 17;
/// The most pages a code's text can take: a line break on every line.
const MOST_PAGES: usize = MOST / LINES + 1;
/// What `keyboard::type_text` takes at a time.
const PIECE: usize = 1024;

/// What a code's text is, by how it starts.
fn kind(text: &str) -> &'static str {
    let starts =
        |p: &str| text.len() >= p.len() && text.as_bytes()[..p.len()].eq_ignore_ascii_case(p.as_bytes());
    if starts("https://") || starts("http://") {
        "Link"
    } else if starts("WIFI:") {
        "Wi-Fi network"
    } else if starts("otpauth://") {
        "Authenticator secret"
    } else if starts("mailto:") {
        "Email address"
    } else if starts("tel:") {
        "Phone number"
    } else if starts("bitcoin:") {
        "Bitcoin payment"
    } else if starts("ethereum:") {
        "Ethereum payment"
    } else if starts("monero:") {
        "Monero payment"
    } else if starts("BEGIN:VCARD") {
        "Contact"
    } else {
        "Text"
    }
}

/// How many Enters and Tabs typing `text` presses (a line break is one, however it's written),
/// or None if it has something a keyboard can't type.
fn presses(text: &str) -> Option<(usize, usize)> {
    let (mut enters, mut tabs) = (0, 0);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                enters += 1;
            }
            '\n' => enters += 1,
            '\t' => tabs += 1,
            ' '..='~' => {}
            _ => return None,
        }
    }
    Some((enters, tabs))
}

/// Types `text`, a piece at a time, `\r\n` and a lone `\r` as a newline.
fn type_all(text: &str) -> Result<(), Error> {
    let mut piece = Buf::<PIECE>::new();
    let mut chars = text.chars().peekable();
    while let Some(mut c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            c = '\n';
        }
        if piece.len() == PIECE {
            keyboard::type_text(piece.as_str())?;
            piece.clear();
        }
        let _ = piece.write_char(c);
    }
    if !piece.is_empty() {
        keyboard::type_text(piece.as_str())?;
    }
    Ok(())
}

/// The line of `text` that starts at byte `start`, wrapped to the screen (at a space where it
/// can, anywhere where it can't; a line break ends it): where it ends, and where the next begins.
fn line_at(text: &str, start: usize) -> (usize, usize) {
    let room = WIDTH - 4;
    let mut space: Option<usize> = None;
    let mut iter = text[start..].char_indices().peekable();
    while let Some((i, c)) = iter.next() {
        let at = start + i;
        match c {
            '\n' => return (at, at + 1),
            '\r' => return (at, if iter.peek().map(|&(_, d)| d) == Some('\n') { at + 2 } else { at + 1 }),
            _ => {}
        }
        // measured as it's drawn: the font spaces its letters
        let end = at + c.len_utf8();
        if at > start && screen::text_width(printable(&text[start..end]).as_str(), Style::Small) > room {
            return match space {
                Some(s) => (s, s + 1),
                None => (at, at),
            };
        }
        if c == ' ' {
            space = Some(at);
        }
    }
    (text.len(), text.len())
}

/// Where each page of `text` starts, and how many there are.
fn paginate(text: &str, pages: &mut [u16]) -> usize {
    let (mut n, mut lines, mut start) = (0, 0, 0);
    while start < text.len() && n < pages.len() {
        if lines % LINES == 0 {
            pages[n] = start as u16;
            n += 1;
        }
        start = line_at(text, start).1;
        lines += 1;
    }
    n.max(1)
}

/// A line to draw: tabs as spaces, anything else that isn't printable as a `?`.
fn printable(line: &str) -> Buf<160> {
    let mut out = Buf::new();
    for c in line.chars() {
        let _ = match c {
            '\t' => out.write_str("  "),
            c if c.is_control() => out.write_char('?'),
            c => out.write_char(c),
        };
    }
    out
}

fn draw_idle(note: &str) {
    screen::clear(Color::Dark);
    screen::text_centred(24, "Scanner", Style::Bold, Color::Light);
    screen::text_centred(48, "centre: read a QR code", Style::Small, Color::Light);
    screen::text_centred(62, "menu: Type it", Style::Small, Color::Light);
    screen::text_centred(96, note, Style::Small, Color::Light);
    screen::present();
}

fn draw_text(text: &str, pages: &[u16], page: usize, note: &str) {
    screen::clear(Color::Dark);
    screen::text(2, 0, kind(text), Style::Bold, Color::Light);
    if pages.len() > 1 {
        let mut at = Buf::<12>::new();
        let _ = write!(at, "{}/{}", page + 1, pages.len());
        screen::text(
            WIDTH - 2 - screen::text_width(at.as_str(), Style::Small),
            2,
            at.as_str(),
            Style::Small,
            Color::Light,
        );
    }
    let mut start = pages[page] as usize;
    for row in 0..LINES {
        if start >= text.len() {
            break;
        }
        let (end, next) = line_at(text, start);
        let line = printable(&text[start..end]);
        screen::text(2, TOP + row as i32 * Style::Small.height(), line.as_str(), Style::Small, Color::Light);
        start = next;
    }
    screen::line(0, 97, WIDTH - 1, 97, Color::Light);
    let mut foot = Buf::<48>::new();
    if note.is_empty() {
        let _ = write!(foot, "{} characters", text.chars().count());
    } else {
        let _ = foot.write_str(note);
    }
    screen::text_centred(99, foot.as_str(), Style::Small, Color::Light);
    screen::present();
}

/// Before typing what presses Enter or Tab: how many times, and centre to go on.
fn draw_check(enters: usize, tabs: usize) {
    screen::clear(Color::Dark);
    screen::text_centred(6, "Type it?", Style::Bold, Color::Light);
    let mut line = Buf::<40>::new();
    let mut y = 32;
    for (n, one, many, key) in [(enters, "line break", "line breaks", "Enter"), (tabs, "tab", "tabs", "Tab")]
    {
        if n == 0 {
            continue;
        }
        line.clear();
        let _ = write!(line, "{n} {}: presses {key}", if n == 1 { one } else { many });
        screen::text_centred(y, line.as_str(), Style::Small, Color::Light);
        y += 14;
    }
    screen::text_centred(y + 6, "where your cursor is", Style::Small, Color::Light);
    screen::line(0, 97, WIDTH - 1, 97, Color::Light);
    screen::text_centred(99, "centre: type   left: back", Style::Small, Color::Light);
    screen::present();
}

fn main() {
    let _ = menu(&["Type it"]);
    let mut buf = [0u8; MOST];
    let mut len = 0;
    let mut pages = [0u16; MOST_PAGES];
    let mut n = 1;
    let mut page = 0;
    let mut note = Buf::<48>::new();
    // waiting for the centre before typing what presses Enter or Tab
    let mut checking = false;
    loop {
        let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
        if checking {
            let (enters, tabs) = presses(text).unwrap_or((0, 0));
            draw_check(enters, tabs);
        } else if text.is_empty() {
            draw_idle(note.as_str());
        } else {
            draw_text(text, &pages[..n], page, note.as_str());
        }
        let event = wait(None);
        if checking {
            match event {
                Event::Centre => {
                    checking = false;
                    note.clear();
                    let _ = note.write_str(if type_all(text).is_ok() { "typed" } else { "couldn't type it" });
                }
                Event::Left | Event::Right => checking = false,
                Event::Exit => return,
                _ => {}
            }
            continue;
        }
        note.clear();
        match event {
            Event::Centre => {
                // a scan that doesn't read may still have written over the last: start again
                len = camera::scan_qr(&mut buf).map_or(0, |t| t.len());
                let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                n = paginate(text, &mut pages);
                page = 0;
                if len == 0 {
                    let _ = note.write_str("nothing read");
                }
            }
            Event::Left => page = page.saturating_sub(1),
            Event::Right => page = (page + 1).min(n - 1),
            Event::Menu(0) => match presses(text) {
                _ if text.is_empty() => {
                    let _ = note.write_str("read a code first");
                }
                None => {
                    let _ = note.write_str("it has what a keyboard can't type");
                }
                Some((0, 0)) => {
                    let _ = note.write_str(if type_all(text).is_ok() { "typed" } else { "couldn't type it" });
                }
                Some(_) => checking = true,
            },
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
