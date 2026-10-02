//! Show QR: what the computer sends, on maki's screen as a QR code for a phone to scan (a link, a
//! Wi-Fi network, an address, a short text), and the text itself on a second page: the centre
//! turns between them. maki desktop sends it (the link permission), and so can any program through
//! maki desktop's socket. It's kept until something else is sent, and the last few with it: left
//! and right, or the jog dial, go through them, newest first; on the text page the dial scrolls.
//! The menu deletes one, or all.
//!
//! maki draws its QR codes at the lowest error correction, with two modules of quiet zone, as big
//! as fits, and writes any text as its bytes (digits and capitals more tightly, where there are
//! enough of them together), so a phone reads back just what was sent, in any language. This app
//! takes only what maki's screen, 110 pixels high, shows at two pixels a module or more: QR codes
//! up to version 8, which hold 192 bytes of text (279 characters if they're all capitals, digits,
//! spaces and `$%*+-./:`, 461 digits). That's what phone cameras read off maki's screen, and what
//! maki keeps its own animated codes to (the Bitcoin app's).
//!
//! The link's messages, a byte saying what first:
//! - `S` and the text, UTF-8: show it, and keep it. Answered `0`; or why not: `1` too long for a QR code on
//!   maki's screen, `2` not text it shows (empty, not UTF-8, or with control characters but new lines). (`3`
//!   isn't used.)
//! - `?`: what it's showing: `0` and the text (none, if it has nothing).
//! - Anything else is answered `4`.

#![no_std]

use core::fmt::Write;

use maki_app::*;

const OK: u8 = 0;
const TOO_LONG: u8 = 1;
const NOT_TEXT: u8 = 2;
const UNKNOWN: u8 = 4;

/// The most text a message may carry, in bytes: more than any QR code it shows holds.
const MOST: usize = 512;
/// How many it keeps, newest first.
const KEEP: usize = 5;
/// Where they're kept: each its length (a u16, little-endian), then its text, newest first.
const KEY: &str = "kept";

/// The text page: a line of maki's small font, where the first is (under a heading and a rule),
/// how many show at once, and how wide they may be (a margin at the left, the scroll marks' at the
/// right).
const LINE: i32 = 12;
const TOP: i32 = 14;
const ROWS: usize = 8;
const WRAP: i32 = WIDTH - 2 - 7;
/// The most lines a text is broken into: more than any it takes (192 bytes of text is 193 at most).
const MAX_LINES: usize = 256;

#[derive(Clone, Copy)]
struct Text {
    bytes: [u8; MOST],
    len: usize,
}

impl Text {
    const NONE: Text = Text { bytes: [0; MOST], len: 0 };

    /// `s`, which `readable` took (so it fits).
    fn of(s: &str) -> Text {
        let mut t = Text::NONE;
        t.len = s.len().min(MOST);
        t.bytes[..t.len].copy_from_slice(&s.as_bytes()[..t.len]);
        t
    }

    fn as_str(&self) -> &str { core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("") }
}

/// `bytes` as text this app shows: UTF-8, something besides spaces, and no control characters but
/// new lines. Else why not.
fn readable(bytes: &[u8]) -> Result<&str, u8> {
    if bytes.len() > MOST {
        return Err(TOO_LONG);
    }
    let text = core::str::from_utf8(bytes).map_err(|_| NOT_TEXT)?;
    if text.trim().is_empty() || text.chars().any(|c| c.is_control() && c != '\n') {
        return Err(NOT_TEXT);
    }
    Ok(text)
}

/// `bytes` as a QR code maki's screen shows, which phones read: `readable`, and two pixels a module
/// or more. Else why not.
fn showable(bytes: &[u8]) -> Result<&str, u8> {
    let text = readable(bytes)?;
    // drawn half as high as the screen, it fits a pixel a module or more only if it fits the
    // whole of it at two or more (the screen's drawn afresh before it's shown)
    if screen::qr(0, 0, bytes, HEIGHT / 2).is_none() {
        return Err(TOO_LONG);
    }
    Ok(text)
}

/// What it shows, newest first.
struct Kept {
    list: [Text; KEEP],
    n: usize,
}

impl Kept {
    fn load() -> Kept {
        let mut kept = Kept { list: [Text::NONE; KEEP], n: 0 };
        let mut buf = [0u8; KEEP * (2 + MOST)];
        let Some(got) = storage::get(KEY, &mut buf) else { return kept };
        let mut rest = &buf[..got.min(buf.len())];
        while kept.n < KEEP {
            let Some(&[a, b]) = rest.get(..2) else { break };
            let len = u16::from_le_bytes([a, b]) as usize;
            let Some(text) = rest.get(2..2 + len) else { break };
            rest = &rest[2 + len..];
            // what this version keeps, and nothing else
            if let Ok(text) = readable(text) {
                kept.list[kept.n] = Text::of(text);
                kept.n += 1;
            }
        }
        kept
    }

    fn save(&self) {
        if self.n == 0 {
            storage::delete(KEY);
            return;
        }
        let mut buf = [0u8; KEEP * (2 + MOST)];
        let mut at = 0;
        for t in &self.list[..self.n] {
            buf[at..at + 2].copy_from_slice(&(t.len as u16).to_le_bytes());
            buf[at + 2..at + 2 + t.len].copy_from_slice(&t.bytes[..t.len]);
            at += 2 + t.len;
        }
        let _ = storage::set(KEY, &buf[..at]);
    }

    /// `text` first: the same text again moves there, and the oldest goes past `KEEP`.
    fn add(&mut self, text: &str) {
        if let Some(i) = (0..self.n).find(|&i| self.list[i].as_str() == text) {
            self.remove(i);
        }
        let n = self.n.min(KEEP - 1);
        self.list.copy_within(0..n, 1);
        self.list[0] = Text::of(text);
        self.n = n + 1;
    }

    fn remove(&mut self, i: usize) {
        if i < self.n {
            self.list.copy_within(i + 1..self.n, i);
            self.n -= 1;
        }
    }
}

/// A text's lines, as `wrap` breaks it: each one's start and end.
struct Lines {
    at: [(u16, u16); MAX_LINES],
    n: usize,
}

/// Where the first line of `rest` ends, no wider than `width` in maki's small font: after as many
/// words as fit, else as many characters (one at least).
fn line_end(rest: &str, width: i32) -> usize {
    let fits = |end: usize| screen::text_width(&rest[..end], Style::Small) <= width;
    if fits(rest.len()) {
        return rest.len();
    }
    let spaces = rest.match_indices(' ').map(|(i, _)| i).filter(|&i| i > 0);
    if let Some(end) = spaces.take_while(|&i| fits(i)).last() {
        return end;
    }
    let chars = rest.char_indices().map(|(i, _)| i).skip(1);
    chars
        .take_while(|&i| fits(i))
        .last()
        .unwrap_or_else(|| rest.chars().next().map_or(rest.len(), char::len_utf8))
}

/// `text` in lines no wider than `width`: one at least for each of its own, each broken between
/// words where it's full (the spaces there left out), or in a word too long for a line.
fn wrap(text: &str, width: i32) -> Lines {
    let mut lines = Lines { at: [(0, 0); MAX_LINES], n: 0 };
    let mut start = 0;
    for own in text.split('\n') {
        let (mut rest, mut at) = (own, start);
        while lines.n < MAX_LINES {
            let end = line_end(rest, width);
            lines.at[lines.n] = (at as u16, (at + end) as u16);
            lines.n += 1;
            let next = rest[end..].trim_start_matches(' ');
            at += rest.len() - next.len();
            rest = next;
            if rest.is_empty() {
                break;
            }
        }
        start += own.len() + 1;
    }
    lines
}

/// A small triangle pointing up or down, its top left at (x, y): there's more that way.
fn mark(x: i32, y: i32, up: bool) {
    for i in 0..3 {
        let row = if up { i } else { 2 - i };
        screen::fill_rect(x + 2 - i, y + row, 1 + 2 * i, 1, Color::Light);
    }
}

/// The text, `scroll` lines down, under a heading that says where it's from, and which of those
/// kept it is.
fn draw_text(text: &str, at: usize, n: usize, scroll: usize) {
    let lines = wrap(text, WRAP);
    let top = scroll.min(lines.n.saturating_sub(ROWS));
    screen::text(2, 0, "From the computer", Style::Small, Color::Light);
    if n > 1 {
        let mut which = Buf::<8>::new();
        let _ = write!(which, "{}/{}", at + 1, n);
        let x = WIDTH - 2 - screen::text_width(which.as_str(), Style::Small);
        screen::text(x, 0, which.as_str(), Style::Small, Color::Light);
    }
    screen::fill_rect(0, 12, WIDTH, 1, Color::Light);
    for (row, &(a, b)) in lines.at[top..lines.n].iter().take(ROWS).enumerate() {
        let line = text.get(a as usize..b as usize).unwrap_or("");
        screen::text(2, TOP + row as i32 * LINE, line, Style::Small, Color::Light);
    }
    if top > 0 {
        mark(WIDTH - 6, TOP + 2, true);
    }
    if top + ROWS < lines.n {
        mark(WIDTH - 6, TOP + (ROWS as i32 - 1) * LINE + 5, false);
    }
}

/// The text as a QR code, as big as fits, in the middle; and, when more are kept, which it is: a
/// square for each down the left edge, this one's filled.
fn draw_code(text: &str, at: usize, n: usize) {
    let data = text.as_bytes();
    match screen::qr(0, 0, data, HEIGHT) {
        Some(side) => {
            screen::clear(Color::Dark);
            let _ = screen::qr((WIDTH - side) / 2, (HEIGHT - side) / 2, data, HEIGHT);
        }
        None => {
            // nothing it takes now, but kept by something before it: the text's on the next page
            screen::clear(Color::Dark);
            screen::text_centred(40, "Too long for a QR", Style::Small, Color::Light);
            screen::text_centred(52, "code here: the centre", Style::Small, Color::Light);
            screen::text_centred(64, "shows the text", Style::Small, Color::Light);
        }
    }
    if n > 1 {
        let top = (HEIGHT - (n as i32 * 8 - 4)) / 2;
        for i in 0..n {
            let y = top + i as i32 * 8;
            if i == at {
                screen::fill_rect(3, y, 4, 4, Color::Light);
            } else {
                screen::rect(3, y, 4, 4, Color::Light);
            }
        }
    }
}

fn draw_empty() {
    screen::text_centred(14, "Nothing to show", Style::Bold, Color::Light);
    let says = [
        "Send a link, a network",
        "or some text from maki",
        "desktop (Connections):",
        "it shows here as a QR",
        "code for a phone.",
    ];
    for (i, line) in says.iter().enumerate() {
        screen::text_centred(38 + 12 * i as i32, line, Style::Small, Color::Light);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Code,
    Text,
}

struct App {
    kept: Kept,
    /// which of them shows, and how
    at: usize,
    page: Page,
    /// the text page's first line
    scroll: usize,
    /// why the last thing sent wasn't shown, until the next press or message
    note: &'static str,
}

impl App {
    fn draw(&self) {
        screen::clear(Color::Dark);
        match self.kept.list[..self.kept.n].get(self.at) {
            None => draw_empty(),
            Some(text) if self.page == Page::Code => draw_code(text.as_str(), self.at, self.kept.n),
            Some(text) => draw_text(text.as_str(), self.at, self.kept.n, self.scroll),
        }
        if !self.note.is_empty() {
            screen::fill_rect(0, 44, WIDTH, 20, Color::Dark);
            screen::rect(0, 44, WIDTH, 20, Color::Light);
            screen::text_centred(48, self.note, Style::Small, Color::Light);
        }
        screen::present();
    }

    /// Another of those kept: `by` one newer (-1) or older (1), round from the last to the first.
    fn step(&mut self, by: isize) {
        let n = self.kept.n;
        if n > 1 {
            self.at = (self.at + n).wrapping_add_signed(by) % n;
            self.scroll = 0;
        }
    }

    /// The text page `by` lines further down (or up), as far as its last line.
    fn scroll_by(&mut self, by: isize) {
        let Some(text) = self.kept.list[..self.kept.n].get(self.at) else { return };
        let most = wrap(text.as_str(), WRAP).n.saturating_sub(ROWS);
        self.scroll = self.scroll.min(most).saturating_add_signed(by).min(most);
    }

    /// A message from the computer, answered.
    fn receive(&mut self) {
        let mut message = [0u8; 2 + MOST];
        let Some(n) = link::read(&mut message) else { return };
        let mut answer = [0u8; 1 + MOST];
        let len = match message.get(..n) {
            Some([b'?']) => {
                let shown = self.kept.list[..self.kept.n].get(self.at).map_or(&[][..], |t| &t.bytes[..t.len]);
                answer[1..1 + shown.len()].copy_from_slice(shown);
                1 + shown.len()
            }
            Some([b'S', text @ ..]) => {
                answer[0] = match showable(text) {
                    Ok(text) => {
                        self.kept.add(text);
                        self.kept.save();
                        (self.at, self.page, self.scroll) = (0, Page::Code, 0);
                        OK
                    }
                    Err(why) => why,
                };
                1
            }
            // longer than any it takes
            None if message[0] == b'S' => {
                answer[0] = TOO_LONG;
                1
            }
            _ => {
                answer[0] = UNKNOWN;
                1
            }
        };
        self.note = match answer[0] {
            TOO_LONG => "too long for a QR code",
            NOT_TEXT => "that isn't text to show",
            _ => "",
        };
        let _ = link::reply(&answer[..len]);
    }
}

fn main() {
    let _ = menu(&["Delete this", "Delete all"]);
    let mut app = App { kept: Kept::load(), at: 0, page: Page::Code, scroll: 0, note: "" };
    loop {
        app.draw();
        let event = wait(None);
        app.note = "";
        match event {
            Event::Message => app.receive(),
            Event::Centre if app.kept.n > 0 => {
                app.page = if app.page == Page::Code { Page::Text } else { Page::Code };
                app.scroll = 0;
            }
            Event::Left => app.step(-1),
            Event::Right => app.step(1),
            // the jog dial: through the codes, or down the text
            Event::Up if app.page == Page::Text => app.scroll_by(-1),
            Event::Down if app.page == Page::Text => app.scroll_by(1),
            Event::Up => app.step(-1),
            Event::Down => app.step(1),
            Event::Menu(0) if app.kept.n > 0 => {
                app.kept.remove(app.at);
                app.kept.save();
                app.at = app.at.min(app.kept.n.saturating_sub(1));
                (app.page, app.scroll) = (Page::Code, 0);
            }
            Event::Menu(1) => {
                app.kept.n = 0;
                app.kept.save();
                (app.at, app.page, app.scroll) = (0, Page::Code, 0);
            }
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
