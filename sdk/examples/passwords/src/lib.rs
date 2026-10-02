//! Passwords: maki as a password manager with nothing secret to keep. Each password is made by
//! maki from the recovery phrase, as BIP-85 makes them (base64 or base85, 10 to 86 characters, a
//! number for each), so restoring maki restores every one, and anything else that follows BIP-85
//! makes the same: number N in base64 at 21 characters is a Coldcard's Type Passwords' number N.
//! maki types each, or shows it on its own screen, itself, after a yes on maki: it never comes to
//! the app (host API 12).
//!
//! What the app keeps is which password is which: a site's name, its username, the password's
//! number, length and alphabet, and whether Enter follows it. maki desktop adds, changes and
//! removes them over the link, and maki asks first each time. On maki: the list (the centre opens
//! one, and types its password; the menu logs in, types the username, shows the password or
//! deletes the entry), and passwords by number alone, without a list, as a Coldcard has them.
//!
//! The link's messages, a byte saying what first, numbers little-endian:
//! - `L`, the first wanted (u16): `0`, the protocol's version (1), how many there are (u16), then as many
//!   entries as fit from the first wanted, each as `Entry::write` puts it.
//! - `A`, an entry (its id 0): added, once the owner says yes. Answered `0` and its id (u32).
//! - `R`, an entry: the one with its id changed to it, once the owner says yes. `0`.
//! - `D`, an id (u32): that entry removed, once the owner says yes. `0`.
//!
//! Otherwise `1` the owner said no, `2` no answer, `4` not a message it takes (or no such entry),
//! `5` no room for it.

use core::fmt::Write;

use maki_app::keyboard::{self, Key};
use maki_app::wallet::{self, HARDENED, Review};
use maki_app::*;

/// BIP-85's purpose, and its passwords' applications.
const BIP85: u32 = 83696968 | HARDENED;
const BASE64: u32 = 707764 | HARDENED;
const BASE85: u32 = 707785 | HARDENED;
/// The highest number a hardened step has.
const MAX_NUMBER: u32 = HARDENED - 1;
/// A Coldcard's Type Passwords: base64, 21 characters (Coldcard's firmware, `BIP85_PWD_LEN`).
const COLDCARD_LENGTH: u8 = 21;

/// A site's name, in bytes, as maki's review screen heads a page with it; a username, which maki
/// types.
const SITE: usize = 32;
const USER: usize = 64;
/// The most entries kept: all of them in one stored value, which holds 16 KiB.
const MOST: usize = 100;
/// The link protocol's version, in `L`'s answer.
const VERSION: u8 = 1;
/// An entry's most bytes as `Entry::write` puts it.
const ENTRY_BYTES: usize = 13 + SITE + USER;

const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const BAD: u8 = 4;
const FULL: u8 = 5;

/// Rows the list shows at once.
const ROWS: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alphabet {
    Base64,
    Base85,
}

impl Alphabet {
    /// The lengths BIP-85 allows each: short of the padding, and no more than 64 bytes hold.
    fn lengths(self) -> core::ops::RangeInclusive<u8> {
        match self {
            Alphabet::Base64 => 20..=86,
            Alphabet::Base85 => 10..=80,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Alphabet::Base64 => "base64",
            Alphabet::Base85 => "base85",
        }
    }
}

/// Which password is which. Nothing in it is secret: the password is maki's to make from the
/// phrase, at `path`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    /// the app's, for maki desktop to name it by: never 0
    id: u32,
    alphabet: Alphabet,
    length: u8,
    number: u32,
    /// Enter pressed after the password
    enter: bool,
    site: String,
    /// printable ASCII, which maki types: may be empty
    user: String,
}

impl Entry {
    /// `m/83696968'/{707764' or 707785'}/{length}'/{number}'`
    fn path(&self) -> [u32; 4] {
        let app = if self.alphabet == Alphabet::Base64 { BASE64 } else { BASE85 };
        [BIP85, app, self.length as u32 | HARDENED, self.number | HARDENED]
    }

    /// A number's password as a Coldcard's Type Passwords makes it.
    fn coldcard(number: u32) -> Entry {
        Entry {
            id: 0,
            alphabet: Alphabet::Base64,
            length: COLDCARD_LENGTH,
            number,
            enter: true,
            site: String::new(),
            user: String::new(),
        }
    }

    /// The id (u32), the alphabet (0 base64, 1 base85), the length, the number (u32), Enter after
    /// it (0 or 1), the site's length (a byte) and the site, the username's length and the
    /// username.
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.to_le_bytes());
        out.push(self.alphabet as u8);
        out.push(self.length);
        out.extend_from_slice(&self.number.to_le_bytes());
        out.push(self.enter as u8);
        out.push(self.site.len() as u8);
        out.extend_from_slice(self.site.as_bytes());
        out.push(self.user.len() as u8);
        out.extend_from_slice(self.user.as_bytes());
    }

    /// One entry from the front of `bytes`, and what's after it; None for anything `write`
    /// wouldn't put, or maki couldn't make, show or type.
    fn read(bytes: &[u8]) -> Option<(Entry, &[u8])> {
        let id = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
        let alphabet = match bytes.get(4)? {
            0 => Alphabet::Base64,
            1 => Alphabet::Base85,
            _ => return None,
        };
        let length = *bytes.get(5)?;
        let number = u32::from_le_bytes(bytes.get(6..10)?.try_into().ok()?);
        let enter = match bytes.get(10)? {
            0 => false,
            1 => true,
            _ => return None,
        };
        let n = *bytes.get(11)? as usize;
        let site = core::str::from_utf8(bytes.get(12..12 + n)?).ok()?;
        let at = 12 + n;
        let m = *bytes.get(at)? as usize;
        let user = core::str::from_utf8(bytes.get(at + 1..at + 1 + m)?).ok()?;
        let entry = Entry { id, alphabet, length, number, enter, site: site.into(), user: user.into() };
        entry.fine().then_some((entry, &bytes[at + 1 + m..]))
    }

    /// Whether maki can make its password, head a page with its site and type its username.
    fn fine(&self) -> bool {
        self.alphabet.lengths().contains(&self.length)
            && self.number <= MAX_NUMBER
            && !self.site.trim().is_empty()
            && self.site.len() <= SITE
            && !self.site.chars().any(|c| c.is_control())
            && self.user.len() <= USER
            && self.user.bytes().all(|b| (b' '..=b'~').contains(&b))
    }

    /// "21 characters, number 0" and what follows it.
    fn about(&self) -> (String, String) {
        let then = if self.enter { ", then Enter" } else { "" };
        (
            format!("{} characters, number {}", self.length, self.number),
            format!("{}{then}", self.alphabet.name()),
        )
    }
}

/// The entries as they're kept: the format's version (1), the next id (u32), how many (u16), then
/// each as `Entry::write` puts it.
struct Kept {
    entries: Vec<Entry>,
    next: u32,
}

impl Kept {
    fn load() -> Kept {
        let mut buf = vec![0u8; 7 + MOST * ENTRY_BYTES];
        let mut kept = Kept { entries: Vec::new(), next: 1 };
        let Some(n) = storage::get("entries", &mut buf) else { return kept };
        let Some(b) = buf.get(..n) else { return kept };
        if b.len() < 7 || b[0] != 1 {
            return kept;
        }
        kept.next = u32::from_le_bytes(b[1..5].try_into().unwrap()).max(1);
        let count = u16::from_le_bytes([b[5], b[6]]) as usize;
        let mut rest = &b[7..];
        for _ in 0..count.min(MOST) {
            let Some((entry, after)) = Entry::read(rest) else { break };
            kept.entries.push(entry);
            rest = after;
        }
        kept
    }

    fn save(&self) -> Result<(), Error> {
        let mut b = vec![1u8];
        b.extend_from_slice(&self.next.to_le_bytes());
        b.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for e in &self.entries {
            e.write(&mut b);
        }
        storage::set("entries", &b)
    }

    fn at(&self, id: u32) -> Option<usize> { self.entries.iter().position(|e| e.id == id) }
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

/// Why maki didn't type or show it, as the foot says it.
fn why(e: Error) -> &'static str {
    match e {
        Error::Locked => "maki is locked",
        Error::Failed => "not plugged in",
        _ => "maki couldn't",
    }
}

/// What's on the screen.
enum View {
    List,
    /// the selected entry, open
    Entry,
    /// asking before deleting the open entry
    Deleting,
    /// passwords by number, as a Coldcard has them
    Number,
}

struct App {
    kept: Kept,
    selected: usize,
    view: View,
    /// the by-number view's number
    number: u32,
    note: String,
}

impl App {
    fn menu(&self) {
        let _ = match self.view {
            View::List => menu(&["By number"]),
            View::Entry | View::Deleting => menu(&["Log in", "Type username", "Show it", "Delete it"]),
            View::Number => menu(&["Show it", "Your list"]),
        };
    }

    fn draw(&self) {
        screen::clear(Color::Dark);
        match self.view {
            View::List if self.kept.entries.is_empty() => {
                screen::text_centred(14, "No passwords yet", Style::Bold, Color::Light);
                screen::text_centred(40, "add them from", Style::Small, Color::Light);
                screen::text_centred(52, "maki desktop, or", Style::Small, Color::Light);
                screen::text_centred(64, "menu: By number", Style::Small, Color::Light);
                self.foot("");
            }
            View::List => {
                let first = self.selected.saturating_sub(ROWS - 1);
                for (row, (i, e)) in self.kept.entries.iter().enumerate().skip(first).take(ROWS).enumerate() {
                    let y = row as i32 * 16;
                    let ink = if i == self.selected {
                        screen::fill_rect(0, y, WIDTH, 16, Color::Light);
                        Color::Dark
                    } else {
                        Color::Light
                    };
                    screen::text(3, y, &fit(&e.site, Style::Regular, WIDTH - 6), Style::Regular, ink);
                }
                self.foot("centre: open");
            }
            View::Entry => {
                let Some(e) = self.kept.entries.get(self.selected) else { return };
                screen::text(2, 0, &fit(&e.site, Style::Bold, WIDTH - 4), Style::Bold, Color::Light);
                let user = if e.user.is_empty() { "no username" } else { &e.user };
                screen::text(2, 20, &fit(user, Style::Regular, WIDTH - 4), Style::Regular, Color::Light);
                let (size, then) = e.about();
                screen::text(2, 46, &size, Style::Small, Color::Light);
                screen::text(2, 58, &then, Style::Small, Color::Light);
                self.foot("centre: type it");
            }
            View::Deleting => {
                let Some(e) = self.kept.entries.get(self.selected) else { return };
                screen::text_centred(14, "Delete it?", Style::Bold, Color::Light);
                screen::text_centred(
                    38,
                    &fit(&e.site, Style::Regular, WIDTH - 6),
                    Style::Regular,
                    Color::Light,
                );
                // the password itself isn't kept: its number makes it again
                let mut again = String::new();
                let _ = write!(again, "number {} makes it again", e.number);
                screen::text_centred(62, &again, Style::Small, Color::Light);
                screen::line(0, 97, WIDTH - 1, 97, Color::Light);
                screen::text_centred(99, "centre: delete   left: keep", Style::Small, Color::Light);
            }
            View::Number => {
                screen::text_centred(0, "password number", Style::Small, Color::Light);
                let n = self.number.to_string();
                let width = |scale| screen::text_scaled_width(&n, Style::Bold, scale);
                let scale = [3, 2].into_iter().find(|&s| width(s) <= WIDTH - 30).unwrap_or(1);
                let y = 36 - Style::Bold.height() * scale / 2;
                screen::text_scaled((WIDTH - width(scale)) / 2, y, &n, Style::Bold, scale, Color::Light);
                // the arrows' tips, where there's a number that way
                for (tip, dir) in [(4, 1), (WIDTH - 5, -1)] {
                    if (dir > 0 && self.number > 0) || (dir < 0 && self.number < MAX_NUMBER) {
                        for i in 0..5 {
                            screen::line(tip + dir * i, 36 - i, tip + dir * i, 36 + i, Color::Light);
                        }
                    }
                }
                screen::text_centred(64, "base64, 21 characters", Style::Small, Color::Light);
                screen::text_centred(76, "as a Coldcard types it", Style::Small, Color::Light);
                self.foot("centre: type it");
            }
        }
        screen::present();
    }

    /// The bottom line: the last thing that happened, or what the centre does.
    fn foot(&self, hint: &str) {
        screen::line(0, 97, WIDTH - 1, 97, Color::Light);
        let text = if self.note.is_empty() { hint } else { &self.note };
        screen::text_centred(99, text, Style::Small, Color::Light);
    }

    /// Has maki type `e`'s password (after its username and Tab, logging in), once the owner says
    /// so on maki's review screen.
    fn type_it(&mut self, e: &Entry, log_in: bool) {
        let site = if e.site.is_empty() { format!("Number {}", e.number) } else { e.site.clone() };
        let (question, detail) = if log_in {
            ("Log in?", format!("{site}, as {}", e.user))
        } else {
            ("Type its password?", format!("{site}, where your cursor is"))
        };
        match Review::new(question).detail(&detail).answers("type", "don't").signatures(1).show() {
            Ok(Answer::Yes) => {}
            Ok(_) => return,
            Err(e) => {
                self.note = why(e).into();
                return;
            }
        }
        let typed = (|| {
            if log_in {
                keyboard::type_text(&e.user)?;
                keyboard::press(Key::Tab)?;
            }
            wallet::type_password(&e.path())?;
            if e.enter {
                keyboard::press(Key::Enter)?;
            }
            Ok::<(), Error>(())
        })();
        self.note = match typed {
            Ok(()) => "typed".into(),
            Err(e) => why(e).into(),
        };
    }

    /// Has maki show `e`'s password on its own screen, once the owner says so.
    fn show_it(&mut self, e: &Entry) {
        let site = if e.site.is_empty() { format!("Number {}", e.number) } else { e.site.clone() };
        match Review::new("Show its password?").detail(&site).answers("show", "don't").signatures(1).show() {
            Ok(Answer::Yes) => {}
            Ok(_) => return,
            Err(e) => {
                self.note = why(e).into();
                return;
            }
        }
        if let Err(e) = wallet::show_password(&e.path(), &site) {
            self.note = why(e).into();
        }
    }

    /// Asks the owner about a change maki desktop sent: a page saying what it is, then `question`.
    fn ask(question: &str, yes: &str, e: &Entry) -> Result<(), u8> {
        let user = if e.user.is_empty() { "no username" } else { &e.user };
        let (size, then) = e.about();
        let page = wallet::Page::new(&e.site).value(user).prose(&format!("{size}, {then}"));
        match Review::new(question).detail(&e.site).answers(yes, "no").page(page).signatures(0).show() {
            Ok(Answer::Yes) => Ok(()),
            Ok(Answer::No) => Err(DENIED),
            _ => Err(NO_ANSWER),
        }
    }

    /// A message from maki desktop, and the answer.
    fn handle(&mut self, message: &[u8]) -> Vec<u8> {
        match message.split_first() {
            Some((b'L', rest)) if rest.len() == 2 => {
                let first = u16::from_le_bytes([rest[0], rest[1]]) as usize;
                let mut a = vec![OK, VERSION];
                a.extend_from_slice(&(self.kept.entries.len() as u16).to_le_bytes());
                for e in self.kept.entries.iter().skip(first) {
                    let mut one = Vec::new();
                    e.write(&mut one);
                    if a.len() + one.len() > 4096 {
                        break;
                    }
                    a.extend_from_slice(&one);
                }
                a
            }
            Some((b'A', rest)) => {
                let Some((mut e, [])) = Entry::read(rest) else { return vec![BAD] };
                if e.id != 0 {
                    return vec![BAD];
                }
                if self.kept.entries.len() >= MOST {
                    return vec![FULL];
                }
                if let Err(code) = Self::ask("Add a password?", "add", &e) {
                    return vec![code];
                }
                e.id = self.kept.next;
                self.kept.next = self.kept.next.wrapping_add(1).max(1);
                self.kept.entries.push(e.clone());
                if self.kept.save().is_err() {
                    self.kept.entries.pop();
                    return vec![FULL];
                }
                self.note = "added one".into();
                let mut a = vec![OK];
                a.extend_from_slice(&e.id.to_le_bytes());
                a
            }
            Some((b'R', rest)) => {
                let Some((e, [])) = Entry::read(rest) else { return vec![BAD] };
                let Some(at) = self.kept.at(e.id) else { return vec![BAD] };
                if let Err(code) = Self::ask("Change a password?", "change", &e) {
                    return vec![code];
                }
                let old = core::mem::replace(&mut self.kept.entries[at], e);
                if self.kept.save().is_err() {
                    self.kept.entries[at] = old;
                    return vec![FULL];
                }
                self.note = "changed one".into();
                vec![OK]
            }
            Some((b'D', rest)) if rest.len() == 4 => {
                let id = u32::from_le_bytes(rest.try_into().unwrap());
                let Some(at) = self.kept.at(id) else { return vec![BAD] };
                let e = self.kept.entries[at].clone();
                if let Err(code) = Self::ask("Remove a password?", "remove", &e) {
                    return vec![code];
                }
                self.kept.entries.remove(at);
                if self.kept.save().is_err() {
                    self.kept.entries.insert(at, e);
                    return vec![FULL];
                }
                // the one open gone, back to the list; the one selected kept selected
                if at == self.selected && matches!(self.view, View::Entry | View::Deleting) {
                    self.view = View::List;
                }
                if at < self.selected {
                    self.selected -= 1;
                }
                self.selected = self.selected.min(self.kept.entries.len().saturating_sub(1));
                self.note = "removed one".into();
                vec![OK]
            }
            _ => vec![BAD],
        }
    }
}

fn main() {
    let mut app = App {
        kept: Kept::load(),
        selected: 0,
        view: View::List,
        number: storage::get_u32("number", 0).min(MAX_NUMBER),
        note: String::new(),
    };
    app.menu();
    loop {
        app.draw();
        let event = wait(None);
        if !matches!(event, Event::Message | Event::Hidden | Event::Shown) {
            app.note.clear();
        }
        let count = app.kept.entries.len();
        match (&app.view, event) {
            (_, Event::Message) => {
                let mut message = vec![0u8; 4096];
                let answer = match link::read(&mut message) {
                    Some(n) if n <= message.len() => app.handle(&message[..n]),
                    _ => vec![BAD],
                };
                let _ = link::reply(&answer);
            }
            (_, Event::Exit) => {
                let _ = storage::set_u32("number", app.number);
                return;
            }
            (View::List, Event::Left | Event::Up) => app.selected = app.selected.saturating_sub(1),
            (View::List, Event::Right | Event::Down) => {
                app.selected = (app.selected + 1).min(count.saturating_sub(1))
            }
            (View::List, Event::Centre) if count > 0 => app.view = View::Entry,
            (View::List, Event::Menu(0)) => app.view = View::Number,
            (View::Entry, Event::Left) => app.view = View::List,
            (View::Entry, Event::Centre) => {
                let e = app.kept.entries[app.selected].clone();
                app.type_it(&e, false);
            }
            (View::Entry, Event::Menu(0)) => {
                let e = app.kept.entries[app.selected].clone();
                if e.user.is_empty() {
                    app.note = "it has no username".into();
                } else {
                    app.type_it(&e, true);
                }
            }
            (View::Entry, Event::Menu(1)) => {
                let user = app.kept.entries[app.selected].user.clone();
                app.note = if user.is_empty() {
                    "it has no username".into()
                } else {
                    match keyboard::type_text(&user) {
                        Ok(()) => "typed".into(),
                        Err(e) => why(e).into(),
                    }
                };
            }
            (View::Entry, Event::Menu(2)) => {
                let e = app.kept.entries[app.selected].clone();
                app.show_it(&e);
            }
            (View::Entry, Event::Menu(3)) => app.view = View::Deleting,
            (View::Deleting, Event::Centre) => {
                let e = app.kept.entries.remove(app.selected);
                if app.kept.save().is_err() {
                    app.kept.entries.insert(app.selected, e);
                    app.note = "couldn't delete it".into();
                    app.view = View::Entry;
                } else {
                    app.selected = app.selected.min(app.kept.entries.len().saturating_sub(1));
                    app.note = "deleted".into();
                    app.view = View::List;
                }
            }
            (View::Deleting, Event::Left | Event::Right) => app.view = View::Entry,
            (View::Number, Event::Left | Event::Up) => app.number = app.number.saturating_sub(1),
            (View::Number, Event::Right | Event::Down) => app.number = (app.number + 1).min(MAX_NUMBER),
            (View::Number, Event::Centre) => app.type_it(&Entry::coldcard(app.number), false),
            (View::Number, Event::Menu(0)) => app.show_it(&Entry::coldcard(app.number)),
            (View::Number, Event::Menu(1)) => app.view = View::List,
            _ => continue,
        }
        app.menu();
    }
}

maki_app::main!(main);
