//! Notes: secrets to read on maki, never on the computer again: recovery codes, PINs, a safe's
//! combination, another wallet's words. Each is a title and its text, kept in the app's storage
//! (in maki's own encrypted store, and its backup, which only the recovery phrase opens).
//!
//! A note comes from maki desktop (the link permission), which the owner types it into and which
//! forgets it once maki has it: maki asks first (ask), with its title and length. Or from a QR
//! code (camera): the first line its title, the rest its text. On maki, the list of titles; the
//! centre opens one, a page at a time (left and right); its menu types it into a field on the
//! computer (keyboard), saying first how many Enters and Tabs that presses, or deletes it, once
//! the centre says so. The computer can ask for the titles, never for what a note says.
//!
//! The link's messages, a byte saying what first:
//! - `A`, the title's length (a byte), the title, then the text: a note to keep, once the owner
//!   says yes. Answered `0`, or `1` the owner said no, `2` no answer, `4` not a note it takes, `5`
//!   no room for it.
//! - `L`: the titles, a line each, after `0`.


use maki_app::*;

/// A title's most characters, and a note's most bytes (a stored value holds 16 KiB).
const TITLE: usize = 40;
const TEXT: usize = 8000;
/// Lines of text a page shows, under the title, and where they start.
const LINES: usize = 6;
const TOP: i32 = 17;
/// Titles the list shows at once.
const ROWS: usize = 6;

const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const BAD: u8 = 4;
const FULL: u8 = 5;

struct Note {
    key: String,
    title: String,
}

/// The notes kept, by the order they came in.
fn load() -> Vec<Note> {
    let mut notes = Vec::new();
    let mut name = [0u8; 48];
    let mut i = 0;
    while let Some(key) = storage::key(i, &mut name) {
        i += 1;
        if !key.starts_with("n:") {
            continue;
        }
        let key = key.to_string();
        if let Some(text) = read(&key) {
            let title = text.split('\n').next().unwrap_or("").to_string();
            notes.push(Note { key, title });
        }
    }
    notes.sort_by_key(|n| n.key[2..].parse::<u32>().unwrap_or(0));
    notes
}

/// A note as it's kept: its title, a line break, its text.
fn read(key: &str) -> Option<String> {
    let mut buf = vec![0u8; TITLE * 4 + TEXT + 1];
    let n = storage::get(key, &mut buf)?.min(buf.len());
    String::from_utf8(buf[..n].to_vec()).ok()
}

/// A title the list can show: one line, not empty, not too long.
fn title_ok(t: &str) -> bool { !t.trim().is_empty() && t.chars().count() <= TITLE && !t.chars().any(|c| c.is_control()) }

/// Keeps a note; its key, or why not.
fn keep(title: &str, text: &str) -> Result<String, u8> {
    if !title_ok(title) || text.len() > TEXT {
        return Err(BAD);
    }
    let next = storage::get_u32("next", 1);
    let key = format!("n:{next}");
    storage::set(&key, format!("{title}\n{text}").as_bytes()).map_err(|_| FULL)?;
    let _ = storage::set_u32("next", next + 1);
    Ok(key)
}

/// `text` cut to fit `room` pixels in `style`, with "..." where it's cut.
fn fit(text: &str, style: Style, room: i32) -> String {
    if screen::text_width(text, style) <= room {
        return text.to_string();
    }
    let mut cut: String = text.to_string();
    while !cut.is_empty() && screen::text_width(&format!("{cut}..."), style) > room {
        cut.pop();
    }
    format!("{}...", cut.trim_end())
}

/// A line of text to draw: tabs as spaces, anything else that isn't printable as a `?`.
fn printable(line: &str) -> String {
    line.chars().map(|c| if c == '\t' { ' ' } else if c.is_control() { '?' } else { c }).collect()
}

/// The lines `text` wraps to on the screen (at spaces where it can, anywhere where it can't; a
/// line break ends one), as the small font draws them.
fn wrap(text: &str) -> Vec<String> {
    let room = WIDTH - 4;
    let mut lines = Vec::new();
    for para in text.split('\n') {
        let para = para.strip_suffix('\r').unwrap_or(para);
        let mut line = String::new();
        let mut last_space: Option<usize> = None;
        for c in para.chars() {
            line.push(c);
            if c == ' ' {
                last_space = Some(line.len() - 1);
            }
            if screen::text_width(&printable(&line), Style::Small) > room && line.chars().count() > 1 {
                match last_space {
                    Some(at) if at > 0 => {
                        let rest = line[at + 1..].to_string();
                        line.truncate(at);
                        lines.push(std::mem::take(&mut line));
                        line = rest;
                    }
                    _ => {
                        let c = line.pop().unwrap_or(' ');
                        lines.push(std::mem::take(&mut line));
                        line.push(c);
                    }
                }
                last_space = line.rfind(' ');
            }
        }
        lines.push(line);
    }
    lines
}

/// How many Enters and Tabs typing `text` presses, or None if a keyboard can't type it.
fn presses(text: &str) -> Option<(usize, usize)> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    if !text.chars().all(|c| c == '\n' || c == '\t' || (' '..='~').contains(&c)) {
        return None;
    }
    Some((text.matches('\n').count(), text.matches('\t').count()))
}

fn type_all(text: &str) -> Result<(), Error> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    for piece in text.as_bytes().chunks(1024) {
        keyboard::type_text(std::str::from_utf8(piece).unwrap_or(""))?;
    }
    Ok(())
}

/// What's on the screen.
enum View {
    List,
    /// a note open: its title, its lines, the page
    Note { at: usize, title: String, text: String, lines: Vec<String>, page: usize },
    /// asking before typing what presses Enter or Tab
    Typing { enters: usize, tabs: usize },
    /// asking before deleting the open note
    Deleting,
}

struct App {
    notes: Vec<Note>,
    selected: usize,
    view: View,
    /// the note open when asking before typing or deleting
    open: Option<(usize, String, String, Vec<String>, usize)>,
    note: String,
}

impl App {
    fn draw(&self) {
        screen::clear(Color::Dark);
        match &self.view {
            View::List => {
                if self.notes.is_empty() {
                    screen::text_centred(20, "No notes yet", Style::Bold, Color::Light);
                    screen::text_centred(44, "send one from", Style::Small, Color::Light);
                    screen::text_centred(56, "maki desktop, or", Style::Small, Color::Light);
                    screen::text_centred(68, "menu: Scan a note", Style::Small, Color::Light);
                } else {
                    let first = self.selected.saturating_sub(ROWS - 1);
                    for (row, (i, n)) in self.notes.iter().enumerate().skip(first).take(ROWS).enumerate() {
                        let y = row as i32 * 16;
                        if i == self.selected {
                            screen::fill_rect(0, y, WIDTH, 16, Color::Light);
                        }
                        let color = if i == self.selected { Color::Dark } else { Color::Light };
                        screen::text(3, y, &fit(&n.title, Style::Regular, WIDTH - 6), Style::Regular, color);
                    }
                }
                self.foot();
            }
            View::Note { title, lines, page, .. } => {
                let pages = lines.len().div_ceil(LINES).max(1);
                let mut room = WIDTH - 4;
                if pages > 1 {
                    let at = format!("{}/{}", page + 1, pages);
                    let w = screen::text_width(&at, Style::Small);
                    screen::text(WIDTH - 2 - w, 2, &at, Style::Small, Color::Light);
                    room -= w + 4;
                }
                screen::text(2, 0, &fit(title, Style::Bold, room), Style::Bold, Color::Light);
                for (row, line) in lines.iter().skip(page * LINES).take(LINES).enumerate() {
                    screen::text(2, TOP + row as i32 * Style::Small.height(), &printable(line), Style::Small, Color::Light);
                }
                self.foot();
            }
            View::Typing { enters, tabs } => {
                screen::text_centred(6, "Type it?", Style::Bold, Color::Light);
                let mut y = 32;
                for (n, one, key) in [(*enters, "line break", "Enter"), (*tabs, "tab", "Tab")] {
                    if n > 0 {
                        let s = format!("{n} {one}{}: presses {key}", if n == 1 { "" } else { "s" });
                        screen::text_centred(y, &s, Style::Small, Color::Light);
                        y += 14;
                    }
                }
                screen::text_centred(y + 6, "where your cursor is", Style::Small, Color::Light);
                screen::line(0, 97, WIDTH - 1, 97, Color::Light);
                screen::text_centred(99, "centre: type   left: back", Style::Small, Color::Light);
            }
            View::Deleting => {
                screen::text_centred(20, "Delete it?", Style::Bold, Color::Light);
                if let Some((_, title, ..)) = &self.open {
                    screen::text_centred(44, &fit(title, Style::Regular, WIDTH - 6), Style::Regular, Color::Light);
                }
                screen::text_centred(66, "gone for good", Style::Small, Color::Light);
                screen::line(0, 97, WIDTH - 1, 97, Color::Light);
                screen::text_centred(99, "centre: delete   left: keep", Style::Small, Color::Light);
            }
        }
        screen::present();
    }

    fn foot(&self) {
        screen::line(0, 97, WIDTH - 1, 97, Color::Light);
        let text = if !self.note.is_empty() {
            self.note.clone()
        } else {
            match &self.view {
                View::Note { text, .. } => format!("{} characters", text.chars().count()),
                _ if self.notes.is_empty() => String::new(),
                _ => format!("{} notes, centre: open", self.notes.len()),
            }
        };
        screen::text_centred(99, &text, Style::Small, Color::Light);
    }

    fn open(&mut self, at: usize) {
        let Some(n) = self.notes.get(at) else { return };
        let Some(all) = read(&n.key) else { return };
        let text = all.split_once('\n').map_or("", |(_, t)| t).to_string();
        let lines = wrap(&text);
        self.view = View::Note { at, title: n.title.clone(), text, lines, page: 0 };
    }

    /// A message from maki desktop, and the answer.
    fn handle(&mut self, message: &[u8]) -> Vec<u8> {
        match message.first() {
            Some(b'L') if message.len() == 1 => {
                let mut a = vec![OK];
                for n in &self.notes {
                    a.extend_from_slice(n.title.as_bytes());
                    a.push(b'\n');
                }
                a
            }
            Some(b'A') => {
                let n = message.get(1).copied().unwrap_or(0) as usize;
                let (Some(title), Some(text)) = (message.get(2..2 + n), message.get(2 + n..)) else { return vec![BAD] };
                let (Ok(title), Ok(text)) = (std::str::from_utf8(title), std::str::from_utf8(text)) else { return vec![BAD] };
                if !title_ok(title) || text.len() > TEXT {
                    return vec![BAD];
                }
                let detail = format!("\"{title}\", {} characters", text.chars().count());
                match Ask::new("Keep a note from the computer?").detail(&detail).answers("keep", "no").show() {
                    Ok(Answer::Yes) => {}
                    Ok(Answer::No) => return vec![DENIED],
                    _ => return vec![NO_ANSWER],
                }
                match keep(title, text) {
                    Ok(key) => {
                        self.notes.push(Note { key, title: title.to_string() });
                        self.note = "kept a note".into();
                        vec![OK]
                    }
                    Err(code) => vec![code],
                }
            }
            _ => vec![BAD],
        }
    }

    fn scan(&mut self) {
        let mut buf = vec![0u8; 4400];
        let Some(text) = camera::scan_qr(&mut buf) else {
            self.note = "nothing read".into();
            return;
        };
        // the first line its title and the rest its text; one line, both
        let (first, body) = match text.split_once('\n') {
            Some((first, rest)) => (first, rest.to_string()),
            None => (text, text.to_string()),
        };
        let title: String = first.trim().chars().filter(|c| !c.is_control()).take(TITLE).collect();
        let title = if title.is_empty() { "Scanned".to_string() } else { title };
        match keep(&title, &body) {
            Ok(key) => {
                self.notes.push(Note { key, title });
                self.selected = self.notes.len() - 1;
                self.note = "kept it".into();
            }
            Err(FULL) => self.note = "no room for it".into(),
            Err(_) => self.note = "too long for a note".into(),
        }
    }
}

fn main() {
    let _ = menu(&["Scan a note", "Type it", "Delete it"]);
    let mut app = App { notes: load(), selected: 0, view: View::List, open: None, note: String::new() };
    loop {
        app.draw();
        let event = wait(None);
        if !matches!(event, Event::Message | Event::Hidden | Event::Shown) {
            app.note.clear();
        }
        match event {
            Event::Message => {
                let mut message = vec![0u8; 4096];
                let answer = match link::read(&mut message) {
                    Some(n) if n <= message.len() => app.handle(&message[..n]),
                    _ => vec![BAD],
                };
                let _ = link::reply(&answer);
            }
            Event::Exit => return,
            _ => {}
        }
        let view = std::mem::replace(&mut app.view, View::List);
        app.view = match (view, event) {
            (View::List, Event::Left) => {
                app.selected = app.selected.saturating_sub(1);
                View::List
            }
            (View::List, Event::Right) => {
                app.selected = (app.selected + 1).min(app.notes.len().saturating_sub(1));
                View::List
            }
            (View::List, Event::Centre) => {
                app.open(app.selected);
                continue;
            }
            (View::Note { at, title, text, lines, page }, Event::Left) => View::Note { at, title, text, lines, page: page.saturating_sub(1) },
            (View::Note { at, title, text, lines, page }, Event::Right) => {
                let last = lines.len().div_ceil(LINES).max(1) - 1;
                View::Note { at, title, text, lines, page: (page + 1).min(last) }
            }
            (View::Note { .. }, Event::Centre) => View::List,
            (View::Note { at, title, text, lines, page }, Event::Menu(1)) => match presses(&text) {
                None => {
                    app.note = "it has what a keyboard can't type".into();
                    View::Note { at, title, text, lines, page }
                }
                Some((0, 0)) => {
                    app.note = if type_all(&text).is_ok() { "typed" } else { "couldn't type it" }.into();
                    View::Note { at, title, text, lines, page }
                }
                Some((enters, tabs)) => {
                    app.open = Some((at, title, text, lines, page));
                    View::Typing { enters, tabs }
                }
            },
            (View::Note { at, title, text, lines, page }, Event::Menu(2)) => {
                app.open = Some((at, title, text, lines, page));
                View::Deleting
            }
            (View::Typing { .. }, Event::Centre) => {
                let (at, title, text, lines, page) = app.open.take().expect("a note is open");
                app.note = if type_all(&text).is_ok() { "typed" } else { "couldn't type it" }.into();
                View::Note { at, title, text, lines, page }
            }
            (View::Typing { .. } | View::Deleting, Event::Left | Event::Right) => {
                let (at, title, text, lines, page) = app.open.take().expect("a note is open");
                View::Note { at, title, text, lines, page }
            }
            (View::Deleting, Event::Centre) => {
                let (at, ..) = app.open.take().expect("a note is open");
                let n = app.notes.remove(at);
                storage::delete(&n.key);
                app.selected = app.selected.min(app.notes.len().saturating_sub(1));
                app.note = "deleted".into();
                View::List
            }
            (view @ (View::List | View::Note { .. }), Event::Menu(0)) => {
                drop(view);
                app.scan();
                View::List
            }
            (View::List, Event::Menu(1 | 2)) => {
                app.note = "open a note first".into();
                View::List
            }
            (view, _) => view,
        };
    }
}

maki_app::main!(main);
