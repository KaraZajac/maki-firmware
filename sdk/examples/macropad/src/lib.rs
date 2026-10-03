//! Macro Pad: keystrokes maki types into a computer at the press of a button — text, keys and
//! DuckyScript. Scripts come from maki desktop (the link permission), and maki asks you before it
//! keeps one, replaces one or removes one (the ask permission), the script itself on maki's review
//! screen first. Each is a button on the pad. The centre opens a script, the centre again runs it,
//! with you holding maki and "typing" in its bar: an attended tool, not a hidden implant. A script
//! can press shortcuts (Gui+R, Ctrl+Alt+Delete), so it can open and run programs — run only
//! scripts you trust. maki desktop can read the scripts back, to show and edit them, without
//! asking: they came from a computer, and the pad isn't a place for secrets (Notes is).
//!
//! A script is DuckyScript (1.0, and STRINGLN), or text, typed as it is: printable ASCII, a line
//! break pressing Enter and a tab Tab. The pad holds 12, each a name of up to 24 characters and up
//! to 3900 bytes, 16 KiB of them in all (`Pad`).
//!
//! The link's messages. Numbers are little-endian. Each starts with the version of these messages,
//! 2, then a letter saying what it is; each answer with a status: 0 done, 1 the owner said no, 2
//! nobody answered (or maki couldn't ask), 4 not a message the app takes (why follows, in English),
//! 5 no room for it (why follows), 7 no such script, 8 another script has that name, 9 another
//! version (the one it speaks follows, a byte). A message refused changes nothing.
//! - `L`: the scripts. Answered `0`, the version, how many scripts there are and the most there can be (a
//!   byte each), the bytes used of the pad's room and the room (u32 each), then each script in the pad's
//!   order: its ID (a byte), its kind (0 DuckyScript, 1 text), when it came and when it was last replaced
//!   (u64 each, seconds since 1970; 0 if maki didn't know the time, or it never was), its size (u16, bytes)
//!   and its name (a byte's length, then UTF-8).
//! - `G`, a script's ID: its text. Answered `0`, then the text (UTF-8), or `7`.
//! - `P`, the ID of the script it replaces (0 for a new one), its kind, its name (a byte's length, then
//!   UTF-8: 1 to 24 characters on one line, with no spaces at its ends), then its text (up to 3900 bytes of
//!   UTF-8; a text's printable ASCII, line breaks and tabs): the script kept once the owner says yes. One
//!   replacing another takes its place on the pad; its name may change, but not to another's. Answered `0`
//!   and the script's ID.
//! - `D`, a script's ID: that script removed, once the owner says yes. Answered `0`, or `7`.
//!
//! A message that starts with any other byte below 32 but a tab or a line break is another version's
//! (`9`). Anything else is the first version's, which maki desktop 0.1.5 and before send: a
//! DuckyScript script, its first line its name (cut to 24 characters, "script" if there's none) and
//! the rest its text, kept in place of the script with that name if there is one, once the owner
//! says yes. Its answer is in words: `ok` and how many scripts there are, `full` if there's no room
//! for it, or why not.

use std::fmt::Write as _;

use maki_app::keyboard::{self, Key};
use maki_app::*;

/// The version of the link's messages (the first had none: a script's name and text).
const VERSION: u8 = 2;
/// The most scripts the pad holds, and the longest a name may be, in characters.
const MAX_SCRIPTS: usize = 12;
const MAX_NAME: usize = 24;
/// A script's most bytes: with the longest name (24 characters of 4 bytes) and a message's own 5,
/// it fits the most a message to maki holds.
const MAX_BODY: usize = 3900;
/// The most a message to the app, or its answer, holds.
const MAX_MESSAGE: usize = 4096;
/// The pad's room: `scripts` is one stored value, which holds 16 KiB.
const ROOM: usize = 16 * 1024;
/// The seconds the owner has to answer for a script sent the first version's way: maki desktop
/// 0.1.5 waits 90 for an answer, starting the app included.
const FIRST_TIMEOUT_S: u32 = 60;
/// A guard on a runaway script: the most keystrokes one run makes, and the longest a DELAY waits.
const MAX_ACTIONS: u32 = 5000;
const MAX_DELAY_MS: u32 = 60_000;
/// The most a text is typed at once (maki's keyboard takes 1024 bytes).
const TYPE_PIECE: usize = 1024;

const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const BAD: u8 = 4;
const FULL: u8 = 5;
const NO_SUCH: u8 = 7;
const TAKEN: u8 = 8;
const ANOTHER_VERSION: u8 = 9;

/// Where the pad is kept: `SCRIPTS` as the first version kept it, each script's name and text,
/// each after a u16's length, so a backup of either version restores to either; and `ABOUT`, the
/// rest, for each script its ID, kind and times (`Pad::about_bytes`).
const SCRIPTS: &str = "scripts";
const ABOUT: &str = "about";
const ABOUT_FORMAT: u8 = 1;

/// What a script is, and how it's typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// DuckyScript 1.0, and STRINGLN
    Ducky = 0,
    /// typed as it is
    Text = 1,
}

impl Kind {
    fn from_byte(b: u8) -> Option<Kind> {
        match b {
            0 => Some(Kind::Ducky),
            1 => Some(Kind::Text),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Kind::Ducky => "DuckyScript",
            Kind::Text => "text",
        }
    }

    /// "DuckyScript, 12 lines": what a script is, as maki's screens say it.
    fn about(self, body: &str) -> String {
        match body.lines().count() {
            0 => format!("{}, empty", self.name()),
            1 => format!("{}, 1 line", self.name()),
            n => format!("{}, {n} lines", self.name()),
        }
    }
}

struct Script {
    /// the pad's, for maki desktop to name it by: never 0
    id: u8,
    kind: Kind,
    /// when it came, and when it was last replaced: seconds since 1970, 0 if maki didn't know the
    /// time (or it never was)
    added: u64,
    changed: u64,
    name: String,
    body: String,
}

/// The bytes a script takes of the pad's room: its name and its text, with their lengths.
fn cost(name: &str, body: &str) -> usize { 4 + name.len() + body.len() }

/// A name as the first version made one of the first line of a message: no control characters, no
/// spaces at its ends, 24 characters at most, and "script" if that leaves nothing.
fn tidy(raw: &str) -> String {
    let clean: String = raw.chars().filter(|c| !c.is_control()).collect();
    let name: String = clean.trim().chars().take(MAX_NAME).collect();
    let name = name.trim_end();
    if name.is_empty() { "script".to_string() } else { name.to_string() }
}

/// A name maki desktop may give a script: as `tidy` would leave it, and not empty.
fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= MAX_NAME
        && !name.chars().any(|c| c.is_control())
        && name.trim() == name
}

/// What maki's keyboard types: printable ASCII, line breaks and tabs.
fn typable(text: &str) -> bool { text.chars().all(|c| c == '\n' || c == '\t' || (' '..='~').contains(&c)) }

/// A u16's length, then that many bytes of UTF-8, from `b` at `at`.
fn take_text(b: &[u8], at: &mut usize) -> Option<String> {
    let len = u16::from_le_bytes([*b.get(*at)?, *b.get(*at + 1)?]) as usize;
    let text = core::str::from_utf8(b.get(*at + 2..*at + 2 + len)?).ok()?.to_string();
    *at += 2 + len;
    Some(text)
}

/// What `ABOUT` says of a script.
struct About {
    id: u8,
    kind: Kind,
    added: u64,
    changed: u64,
    name: String,
}

/// One script's entry in `ABOUT`, from `b` at `at`, and its size.
fn read_one(b: &[u8], at: usize) -> Option<(About, usize)> {
    let n = *b.get(at + 18)? as usize;
    let about = About {
        id: *b.get(at)?,
        kind: Kind::from_byte(*b.get(at + 1)?)?,
        added: u64::from_le_bytes(b.get(at + 2..at + 10)?.try_into().ok()?),
        changed: u64::from_le_bytes(b.get(at + 10..at + 18)?.try_into().ok()?),
        name: core::str::from_utf8(b.get(at + 19..at + 19 + n)?).ok()?.to_string(),
    };
    Some((about, 19 + n))
}

/// `ABOUT`'s next ID and what it says of each script, as far as it reads.
fn read_about(b: &[u8]) -> (u8, Vec<About>) {
    let mut out = Vec::new();
    let (Some(&ABOUT_FORMAT), Some(&next), Some(&count)) = (b.first(), b.get(1), b.get(2)) else {
        return (1, out);
    };
    let mut at = 3;
    for _ in 0..(count as usize).min(MAX_SCRIPTS) {
        let Some((about, size)) = read_one(b, at) else { break };
        out.push(about);
        at += size;
    }
    (next, out)
}

/// The scripts, in the pad's order, and the next ID to give: 12 at most (`MAX_SCRIPTS`), their
/// names and texts taking 16 KiB at most (`ROOM`), as `SCRIPTS` keeps them.
struct Pad {
    scripts: Vec<Script>,
    next: u8,
}

impl Pad {
    /// The pad as kept. `SCRIPTS` read as far as it makes sense (anything the app wouldn't have
    /// kept ends it), each script matched by name to what `ABOUT` says of it; one it doesn't name
    /// (the first version kept it, or the app stopped between writing the two) is DuckyScript, of a
    /// time maki doesn't know, with an ID of its own.
    fn load() -> Pad {
        let mut buf = vec![0u8; ROOM];
        let mut kept: Vec<(String, String)> = Vec::new();
        if let Some(n) = storage::get(SCRIPTS, &mut buf) {
            let b = &buf[..n.min(buf.len())];
            let mut at = 0;
            while at < b.len() && kept.len() < MAX_SCRIPTS {
                let (Some(name), Some(body)) = (take_text(b, &mut at), take_text(b, &mut at)) else { break };
                // its text goes back whole in an answer, after the status
                if body.len() >= MAX_MESSAGE {
                    break;
                }
                kept.push((tidy(&name), body));
            }
        }
        let (next, about) = match storage::get(ABOUT, &mut buf) {
            Some(n) => read_about(&buf[..n.min(buf.len())]),
            None => (1, Vec::new()),
        };
        let mut pad = Pad { scripts: Vec::new(), next: next.max(1) };
        let mut matched = vec![false; about.len()];
        for (name, body) in kept {
            let found = about.iter().enumerate().find(|(i, a)| {
                !matched[*i] && a.id != 0 && a.name == name && !pad.scripts.iter().any(|s| s.id == a.id)
            });
            let script = match found {
                Some((i, a)) => {
                    matched[i] = true;
                    // a text has only what maki types; anything else is read as DuckyScript
                    let kind = if a.kind == Kind::Text && !typable(&body) { Kind::Ducky } else { a.kind };
                    Script { id: a.id, kind, added: a.added, changed: a.changed, name, body }
                }
                None => Script { id: 0, kind: Kind::Ducky, added: 0, changed: 0, name, body },
            };
            pad.scripts.push(script);
        }
        // IDs for the rest, once those `ABOUT` gives are all taken
        for i in 0..pad.scripts.len() {
            if pad.scripts[i].id == 0 {
                pad.scripts[i].id = pad.new_id();
            }
        }
        pad
    }

    /// Keeps the pad: `SCRIPTS` first, so a stop between the two leaves a script without what
    /// `ABOUT` says of it (read as DuckyScript), never what it says of another's text. An empty pad
    /// has no `SCRIPTS`, gone once `ABOUT` says so, so a failed write leaves the scripts there.
    fn save(&self) -> Result<(), Error> {
        if self.scripts.is_empty() {
            storage::set(ABOUT, &self.about_bytes())?;
            storage::delete(SCRIPTS);
            return Ok(());
        }
        let mut b = Vec::with_capacity(self.used());
        for s in &self.scripts {
            for part in [s.name.as_str(), s.body.as_str()] {
                b.extend_from_slice(&(part.len() as u16).to_le_bytes());
                b.extend_from_slice(part.as_bytes());
            }
        }
        storage::set(SCRIPTS, &b)?;
        storage::set(ABOUT, &self.about_bytes())
    }

    /// `ABOUT`: its format (1), the next ID, how many scripts, then for each its ID, kind, when it
    /// came and when it was last replaced (u64 each), and its name (a byte's length, then UTF-8),
    /// by which it's matched to its text.
    fn about_bytes(&self) -> Vec<u8> {
        let mut b = vec![ABOUT_FORMAT, self.next, self.scripts.len() as u8];
        for s in &self.scripts {
            b.push(s.id);
            b.push(s.kind as u8);
            b.extend_from_slice(&s.added.to_le_bytes());
            b.extend_from_slice(&s.changed.to_le_bytes());
            b.push(s.name.len() as u8);
            b.extend_from_slice(s.name.as_bytes());
        }
        b
    }

    /// The bytes of the pad's room in use.
    fn used(&self) -> usize { self.scripts.iter().map(|s| cost(&s.name, &s.body)).sum() }

    /// Where script `id` is on the pad.
    fn at(&self, id: u8) -> Option<usize> { self.scripts.iter().position(|s| s.id == id) }

    /// An ID no script has, the next going round 1 to 255 (there are 12 at most), so one just
    /// removed isn't given again at once.
    fn new_id(&mut self) -> u8 {
        let mut id = self.next.max(1);
        while self.scripts.iter().any(|s| s.id == id) {
            id = if id == u8::MAX { 1 } else { id + 1 };
        }
        self.next = if id == u8::MAX { 1 } else { id + 1 };
        id
    }
}

/// Why a run stopped.
enum Ran {
    Done,
    /// maki isn't plugged into a computer (a press failed)
    Unplugged,
    /// the owner left while it ran
    Left,
    /// it hit the keystroke guard
    TooLong,
    /// a text with what maki's keyboard can't type
    Untypable,
}

impl Ran {
    fn note(self) -> &'static str {
        match self {
            Ran::Done => "typed it",
            Ran::Unplugged => "plug maki into a computer",
            Ran::Left => "stopped",
            Ran::TooLong => "too many keystrokes",
            Ran::Untypable => "it has what maki can't type",
        }
    }
}

/// A token of a key line: a modifier, a named key, a character, or something maki can't press.
enum Token {
    Mod(u8),
    Named(Key),
    /// a key the SDK's `Key` doesn't name but a chord can still press, by its HID usage ID
    Raw(u8),
    Char(char),
    Unknown,
}

fn classify(token: &str) -> Token {
    let upper = token.to_ascii_uppercase();
    match upper.as_str() {
        "CTRL" | "CONTROL" => Token::Mod(keyboard::CTRL),
        "ALT" | "OPTION" => Token::Mod(keyboard::ALT),
        "SHIFT" => Token::Mod(keyboard::SHIFT),
        "GUI" | "WINDOWS" | "WIN" | "COMMAND" | "META" | "SUPER" => Token::Mod(keyboard::GUI),
        "ENTER" | "RETURN" => Token::Named(Key::Enter),
        "TAB" => Token::Named(Key::Tab),
        "ESC" | "ESCAPE" => Token::Named(Key::Escape),
        "SPACE" => Token::Named(Key::Space),
        "BACKSPACE" | "BKSP" => Token::Named(Key::Backspace),
        "DELETE" | "DEL" => Token::Named(Key::Delete),
        "INSERT" | "INS" => Token::Named(Key::Insert),
        "HOME" => Token::Named(Key::Home),
        "END" => Token::Named(Key::End),
        "PAGEUP" | "PAGE_UP" => Token::Named(Key::PageUp),
        "PAGEDOWN" | "PAGE_DOWN" => Token::Named(Key::PageDown),
        "UP" | "UPARROW" => Token::Named(Key::Up),
        "DOWN" | "DOWNARROW" => Token::Named(Key::Down),
        "LEFT" | "LEFTARROW" => Token::Named(Key::Left),
        "RIGHT" | "RIGHTARROW" => Token::Named(Key::Right),
        "F1" => Token::Named(Key::F1),
        "F2" => Token::Named(Key::F2),
        "F3" => Token::Named(Key::F3),
        "F4" => Token::Named(Key::F4),
        "F5" => Token::Named(Key::F5),
        "F6" => Token::Named(Key::F6),
        "F7" => Token::Named(Key::F7),
        "F8" => Token::Named(Key::F8),
        "F9" => Token::Named(Key::F9),
        "F10" => Token::Named(Key::F10),
        "F11" => Token::Named(Key::F11),
        "F12" => Token::Named(Key::F12),
        // keys the SDK's Key doesn't name, pressed by their HID usage ID through a chord
        "CAPSLOCK" => Token::Raw(0x39),
        "PRINTSCREEN" | "PRINTSCRN" | "PRINT" => Token::Raw(0x46),
        "SCROLLLOCK" => Token::Raw(0x47),
        "PAUSE" | "BREAK" => Token::Raw(0x48),
        _ => {
            let mut chars = token.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => Token::Char(c),
                _ => Token::Unknown,
            }
        }
    }
}

/// Presses a key line (modifiers and a key: `GUI r`, `CTRL ALT DELETE`, `ENTER`). Whether maki is
/// still plugged in. An unpressable line (a lone modifier, an unknown key) is skipped.
fn press_line(line: &str) -> bool {
    let mut mods = 0u8;
    let mut base: Option<Token> = None;
    for token in line.split(|c: char| c.is_whitespace() || c == '-').filter(|t| !t.is_empty()) {
        match classify(token) {
            Token::Mod(m) => mods |= m,
            other => base = Some(other),
        }
    }
    let ok = |r: Result<(), Error>| !matches!(r, Err(Error::Failed));
    match base {
        Some(Token::Named(key)) if mods == 0 => ok(keyboard::press(key)),
        Some(Token::Named(key)) => ok(keyboard::chord_key(key, mods)),
        Some(Token::Raw(code)) => ok(keyboard::chord(code, mods)),
        Some(Token::Char(c)) if mods == 0 => ok(keyboard::type_text(c.encode_utf8(&mut [0; 4]))),
        Some(Token::Char(c)) => match keyboard::usage(c) {
            Some(code) => ok(keyboard::chord(code, mods)),
            None => true,
        },
        // a lone modifier, or nothing maki can press: skipped, maki stays plugged in
        _ => true,
    }
}

/// Waits `ms`, or stops early if the owner leaves (returns false then).
fn nap(ms: u32) -> bool {
    let end = millis() + ms as u64;
    loop {
        let now = millis();
        if now >= end {
            return true;
        }
        if wait(Some((end - now) as u32)) == Event::Exit {
            return false;
        }
    }
}

/// Runs a DuckyScript body: STRING/STRINGLN, DELAY/DEFAULTDELAY, REM, key and chord lines, and
/// REPEAT of the line before. `progress` counts the actions done.
fn run(body: &str, progress: &mut u32) -> Ran {
    let mut default_delay = 0u32;
    let mut previous: Option<String> = None;
    let lines: Vec<&str> = body.lines().collect();
    let mut idx = 0;
    while idx < lines.len() {
        let line = lines[idx].trim_end_matches('\r');
        idx += 1;
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let (verb, rest) = trimmed.split_once(' ').unwrap_or((trimmed, ""));
        let mut repeats = 1u32;
        let mut this: &str = line;
        // REPEAT n: do the line before, n more times
        if verb.eq_ignore_ascii_case("REPEAT") {
            let Some(prev) = previous.as_deref() else { continue };
            repeats = rest.trim().parse::<u32>().unwrap_or(0).min(MAX_ACTIONS);
            this = prev;
        }
        for _ in 0..repeats {
            if *progress >= MAX_ACTIONS {
                return Ran::TooLong;
            }
            let (verb, rest) = this.trim_start().split_once(' ').unwrap_or((this.trim_start(), ""));
            let plugged = if verb.eq_ignore_ascii_case("REM") {
                true
            } else if verb.eq_ignore_ascii_case("STRING") {
                *progress += 1;
                !matches!(keyboard::type_text(rest), Err(Error::Failed))
            } else if verb.eq_ignore_ascii_case("STRINGLN") {
                *progress += 1;
                !matches!(keyboard::type_text(rest), Err(Error::Failed))
                    && !matches!(keyboard::press(Key::Enter), Err(Error::Failed))
            } else if verb.eq_ignore_ascii_case("DELAY") {
                if !nap(rest.trim().parse::<u32>().unwrap_or(0).min(MAX_DELAY_MS)) {
                    return Ran::Left;
                }
                true
            } else if verb.eq_ignore_ascii_case("DEFAULTDELAY") || verb.eq_ignore_ascii_case("DEFAULT_DELAY")
            {
                default_delay = rest.trim().parse::<u32>().unwrap_or(0).min(MAX_DELAY_MS);
                true
            } else {
                *progress += 1;
                press_line(this)
            };
            if !plugged {
                return Ran::Unplugged;
            }
            if default_delay > 0 && !nap(default_delay) {
                return Ran::Left;
            }
        }
        if !verb.eq_ignore_ascii_case("REPEAT") {
            previous = Some(line.to_string());
        }
    }
    Ran::Done
}

/// Types a text as it is, a piece at a time, the owner free to leave between pieces.
fn type_out(text: &str) -> Ran {
    if !typable(text) {
        return Ran::Untypable;
    }
    // printable ASCII: every byte is a character's boundary
    let mut pieces = text.as_bytes().chunks(TYPE_PIECE).peekable();
    while let Some(piece) = pieces.next() {
        match keyboard::type_text(core::str::from_utf8(piece).unwrap_or("")) {
            Err(Error::Failed) => return Ran::Unplugged,
            Err(_) => return Ran::Untypable,
            Ok(()) => {}
        }
        if pieces.peek().is_some() && wait(Some(0)) == Event::Exit {
            return Ran::Left;
        }
    }
    Ran::Done
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

fn draw_list(scripts: &[Script], selected: usize, note: &str) {
    screen::clear(Color::Dark);
    screen::text_centred(0, "Macro Pad", Style::Bold, Color::Light);
    if scripts.is_empty() {
        screen::text_centred(34, "No scripts yet.", Style::Small, Color::Light);
        screen::text_centred(50, "Send one from", Style::Small, Color::Light);
        screen::text_centred(62, "maki desktop.", Style::Small, Color::Light);
    } else {
        // a window of names around the selected one, the selection filled
        let rows = 6;
        let top = selected.saturating_sub(rows - 1).min(scripts.len().saturating_sub(rows));
        for (row, i) in (top..scripts.len()).take(rows).enumerate() {
            let y = 18 + row as i32 * 15;
            if i == selected {
                screen::fill_rect(0, y - 1, WIDTH, 14, Color::Light);
            }
            let ink = if i == selected { Color::Dark } else { Color::Light };
            screen::text(4, y, &fit(&scripts[i].name, Style::Regular, WIDTH - 8), Style::Regular, ink);
        }
    }
    if !note.is_empty() {
        screen::fill_rect(0, HEIGHT - 13, WIDTH, 13, Color::Dark);
        screen::text_centred(HEIGHT - 12, note, Style::Small, Color::Light);
    }
    screen::present();
}

/// A script open: its name, what it is, and its first few lines, so you see what it'll do.
fn draw_detail(script: &Script, note: &str) {
    screen::clear(Color::Dark);
    screen::text_centred(0, &fit(&script.name, Style::Bold, WIDTH - 4), Style::Bold, Color::Light);
    screen::text_centred(16, &script.kind.about(&script.body), Style::Small, Color::Light);
    for (row, line) in script.body.lines().filter(|l| !l.trim().is_empty()).take(5).enumerate() {
        let shown = fit(line.trim(), Style::Small, WIDTH - 8);
        screen::text(4, 30 + row as i32 * 12, &shown, Style::Small, Color::Light);
    }
    let foot = if note.is_empty() { "centre: type it" } else { note };
    screen::text_centred(HEIGHT - 13, foot, Style::Small, Color::Light);
    screen::present();
}

/// A script as maki's review screen shows it, in fixed-width type: a tab as a space, and anything
/// else that isn't printable but a line break as a `?`.
fn shown(body: &str) -> String {
    body.chars()
        .filter(|&c| c != '\r')
        .map(|c| match c {
            '\t' => ' ',
            '\n' => '\n',
            c if c.is_control() => '?',
            c => c,
        })
        .collect()
}

/// `"name": what`, the name cut to fit an ask's line (128 bytes).
fn quoted(name: &str, what: &str) -> String {
    let tail = format!("\": {what}");
    let mut out = String::from("\"");
    for c in name.chars() {
        if out.len() + c.len_utf8() + tail.len() + 3 > 128 {
            out.push_str("...");
            break;
        }
        out.push(c);
    }
    out.push_str(&tail);
    out
}

/// An answer with its status, and for `BAD` and `FULL`, why.
fn answer(status: u8, why: &str) -> Vec<u8> {
    let mut a = vec![status];
    if status == BAD || status == FULL {
        a.extend_from_slice(why.as_bytes());
    }
    a
}

#[derive(Clone, Copy)]
enum View {
    List,
    /// a script open, by its ID
    Detail(u8),
}

struct App {
    pad: Pad,
    selected: usize,
    view: View,
    /// the last thing that happened, at the foot of the screen
    note: String,
}

impl App {
    /// A message from maki desktop, and the answer.
    fn handle(&mut self, message: &[u8]) -> Vec<u8> {
        match message.split_first() {
            Some((&VERSION, rest)) => self.handle_now(rest),
            // the first version's start with a name, or the spaces before one
            Some((&first, _)) if first < 0x20 && !matches!(first, b'\t' | b'\n' | b'\r') => {
                vec![ANOTHER_VERSION, VERSION]
            }
            _ => self.handle_first(message).into_bytes(),
        }
    }

    /// A message of this version, after its version.
    fn handle_now(&mut self, message: &[u8]) -> Vec<u8> {
        match message {
            [b'L'] => self.list(),
            [b'G', id] => match self.pad.at(*id) {
                Some(at) => [&[OK][..], self.pad.scripts[at].body.as_bytes()].concat(),
                None => vec![NO_SUCH],
            },
            [b'P', id, kind, n, rest @ ..] => self.put(*id, *kind, *n as usize, rest),
            [b'D', id] => self.remove(*id),
            _ => answer(BAD, "not a message Macro Pad takes"),
        }
    }

    /// `L`'s answer.
    fn list(&self) -> Vec<u8> {
        let mut a = vec![OK, VERSION, self.pad.scripts.len() as u8, MAX_SCRIPTS as u8];
        a.extend_from_slice(&(self.pad.used() as u32).to_le_bytes());
        a.extend_from_slice(&(ROOM as u32).to_le_bytes());
        for s in &self.pad.scripts {
            a.push(s.id);
            a.push(s.kind as u8);
            a.extend_from_slice(&s.added.to_le_bytes());
            a.extend_from_slice(&s.changed.to_le_bytes());
            a.extend_from_slice(&(s.body.len() as u16).to_le_bytes());
            a.push(s.name.len() as u8);
            a.extend_from_slice(s.name.as_bytes());
        }
        a
    }

    /// `P`: a script kept, new or in place of script `id`, once the owner says yes.
    fn put(&mut self, id: u8, kind: u8, n: usize, rest: &[u8]) -> Vec<u8> {
        let Some(kind) = Kind::from_byte(kind) else {
            return answer(BAD, "a script is DuckyScript (0) or text (1)");
        };
        let (Some(name), Some(body)) = (rest.get(..n), rest.get(n..)) else {
            return answer(BAD, "its name runs past the end of the message");
        };
        let (Ok(name), Ok(body)) = (core::str::from_utf8(name), core::str::from_utf8(body)) else {
            return answer(BAD, "it isn't UTF-8");
        };
        if !name_ok(name) {
            return answer(BAD, "a name is 1 to 24 characters on one line, with no spaces at its ends");
        }
        if body.len() > MAX_BODY {
            return answer(BAD, &format!("a script is {MAX_BODY} bytes at most"));
        }
        if kind == Kind::Text && !typable(body) {
            return answer(
                BAD,
                "maki types a text's printable ASCII, line breaks and tabs, and nothing else",
            );
        }
        match self.keep(id, kind, name, body, None) {
            Ok(id) => vec![OK, id],
            Err((status, why)) => answer(status, &why),
        }
    }

    /// A script kept, new (`id` 0) or in place of script `id`, once the owner says yes on maki's
    /// review screen (`timeout_s` the seconds they have, if not the review's own). Its ID, or a
    /// status and why.
    fn keep(
        &mut self,
        id: u8,
        kind: Kind,
        name: &str,
        body: &str,
        timeout_s: Option<u32>,
    ) -> Result<u8, (u8, String)> {
        let at = match id {
            0 => None,
            id => Some(self.pad.at(id).ok_or((NO_SUCH, String::new()))?),
        };
        if self.pad.scripts.iter().enumerate().any(|(i, s)| s.name == name && Some(i) != at) {
            return Err((TAKEN, String::new()));
        }
        if let Some(i) = at {
            let s = &self.pad.scripts[i];
            // nothing to change, nothing to ask
            if s.kind == kind && s.name == name && s.body == body {
                return Ok(s.id);
            }
        } else if self.pad.scripts.len() >= MAX_SCRIPTS {
            return Err((FULL, format!("maki keeps {MAX_SCRIPTS} scripts: remove one first")));
        }
        let replaced = at.map_or(0, |i| cost(&self.pad.scripts[i].name, &self.pad.scripts[i].body));
        let free = ROOM.saturating_sub(self.pad.used() - replaced);
        let need = cost(name, body);
        if need > free {
            return Err((FULL, format!("it takes {need} bytes of the pad's room, and {free} are free")));
        }
        self.ask_keep(at, kind, name, body, timeout_s)?;
        let now = unix_time().unwrap_or(0);
        let id = match at {
            None => {
                let id = self.pad.new_id();
                let script =
                    Script { id, kind, added: now, changed: 0, name: name.into(), body: body.into() };
                self.pad.scripts.push(script);
                id
            }
            Some(i) => {
                let s = &mut self.pad.scripts[i];
                (s.kind, s.name, s.body, s.changed) = (kind, name.into(), body.into(), now);
                s.id
            }
        };
        if self.pad.save().is_err() {
            // what's kept is what maki has
            self.pad = Pad::load();
            return Err((FULL, "maki couldn't save the pad".into()));
        }
        self.note = if at.is_none() { "kept a script" } else { "replaced a script" }.into();
        Ok(id)
    }

    /// Asks the owner about a script the computer sent: the one it replaces, if any, then the
    /// script, a line at a time, on maki's review screen; then the question.
    fn ask_keep(
        &self,
        at: Option<usize>,
        kind: Kind,
        name: &str,
        body: &str,
        timeout_s: Option<u32>,
    ) -> Result<(), (u8, String)> {
        let (question, yes) = match at {
            None => ("Keep a script from the computer?", "keep"),
            Some(_) => ("Replace a script?", "replace"),
        };
        let detail = quoted(name, &kind.about(body));
        // the question, its line and answers, a page about the one replaced, and the script's
        let mut text = vec![0u8; 1024 + body.len()];
        let mut review = AskPages::new(&mut text, question, &detail, yes, "no");
        if let Some(i) = at {
            let old = &self.pad.scripts[i];
            let mut prose = format!("In place of the one on maki now: {}.", old.kind.about(&old.body));
            if old.name != name {
                let _ = write!(prose, " Its new name: {name}.");
            }
            review.page("Replacing", &old.name, "", &prose);
        }
        let heading = match kind {
            Kind::Ducky => "DuckyScript",
            Kind::Text => "Text",
        };
        review.page(heading, name, &shown(body), if body.trim().is_empty() { "Nothing in it." } else { "" });
        if let Some(s) = timeout_s {
            review.timeout(s);
        }
        match review.show() {
            Ok(Answer::Yes) => Ok(()),
            Ok(Answer::No) => Err((DENIED, String::new())),
            _ => Err((NO_ANSWER, String::new())),
        }
    }

    /// `D`: script `id` removed, once the owner says yes.
    fn remove(&mut self, id: u8) -> Vec<u8> {
        let Some(at) = self.pad.at(id) else { return vec![NO_SUCH] };
        let s = &self.pad.scripts[at];
        let detail = quoted(&s.name, &s.kind.about(&s.body));
        match Ask::new("Remove a script?").detail(&detail).answers("remove", "keep").show() {
            Ok(Answer::Yes) => {}
            Ok(Answer::No) => return vec![DENIED],
            _ => return vec![NO_ANSWER],
        }
        let gone = self.pad.scripts.remove(at);
        if self.pad.save().is_err() {
            self.pad = Pad::load();
            return answer(FULL, "maki couldn't save the pad");
        }
        // the one open gone, back to the list; the one selected kept selected
        if matches!(self.view, View::Detail(open) if open == gone.id) {
            self.view = View::List;
        }
        if at < self.selected {
            self.selected -= 1;
        }
        self.note = "removed a script".into();
        vec![OK]
    }

    /// A message of the first version: a DuckyScript script, its first line its name. Answered in
    /// words, as the first version answered.
    fn handle_first(&mut self, message: &[u8]) -> String {
        let Ok(text) = core::str::from_utf8(message) else {
            return "not a script: it isn't UTF-8".into();
        };
        if text.is_empty() {
            return "not a script: it's empty".into();
        }
        let (name, body) = text.split_once('\n').unwrap_or((text, ""));
        let name = tidy(name);
        if body.len() > MAX_BODY {
            return format!("too long: a script is {MAX_BODY} bytes at most");
        }
        let id = self.pad.scripts.iter().find(|s| s.name == name).map_or(0, |s| s.id);
        match self.keep(id, Kind::Ducky, &name, body, Some(FIRST_TIMEOUT_S)) {
            Ok(_) => format!("ok {}", self.pad.scripts.len()),
            Err((FULL, _)) => "full".into(),
            Err((DENIED, _)) => "you said no on maki".into(),
            Err((NO_ANSWER, _)) => "nobody answered on maki".into(),
            Err((_, why)) => why,
        }
    }
}

fn main() {
    let _ = menu(&["Delete this", "Clear all"]);
    let mut app = App { pad: Pad::load(), selected: 0, view: View::List, note: String::new() };
    loop {
        if app.selected >= app.pad.scripts.len() {
            app.selected = app.pad.scripts.len().saturating_sub(1);
        }
        match app.view {
            View::List => draw_list(&app.pad.scripts, app.selected, &app.note),
            View::Detail(id) => match app.pad.at(id) {
                Some(at) => draw_detail(&app.pad.scripts[at], &app.note),
                None => {
                    app.view = View::List;
                    continue;
                }
            },
        }
        let event = wait(None);
        // a note stays while something else is in front (an ask), and for the message that set it
        if !matches!(event, Event::Message | Event::Hidden | Event::Shown) {
            app.note.clear();
        }
        match (&app.view, event) {
            (_, Event::Message) => {
                let mut message = vec![0u8; MAX_MESSAGE];
                let reply = match link::read(&mut message) {
                    Some(n) if n <= message.len() => app.handle(&message[..n]),
                    _ => answer(BAD, "a message is 4096 bytes at most"),
                };
                let _ = link::reply(&reply);
            }
            (View::List, Event::Left) | (View::List, Event::Up) => {
                app.selected = app.selected.saturating_sub(1);
            }
            (View::List, Event::Right) | (View::List, Event::Down) => {
                if app.selected + 1 < app.pad.scripts.len() {
                    app.selected += 1;
                }
            }
            (View::List, Event::Centre) => {
                if let Some(s) = app.pad.scripts.get(app.selected) {
                    app.view = View::Detail(s.id);
                }
            }
            (View::List, Event::Menu(0)) => {
                if app.selected < app.pad.scripts.len() {
                    let gone = app.pad.scripts.remove(app.selected);
                    if app.pad.save().is_ok() {
                        app.note = "deleted".into();
                    } else {
                        app.pad.scripts.insert(app.selected, gone);
                        app.note = "couldn't delete it".into();
                    }
                }
            }
            (View::List, Event::Menu(1)) => {
                let all = std::mem::take(&mut app.pad.scripts);
                if app.pad.save().is_ok() {
                    app.note = "cleared".into();
                } else {
                    app.pad.scripts = all;
                    app.note = "couldn't clear it".into();
                }
            }
            (View::Detail(id), Event::Centre) => {
                let id = *id;
                // typing shows on maki's bar; tell the owner it's going
                if let Some(at) = app.pad.at(id) {
                    let s = &app.pad.scripts[at];
                    draw_detail(s, "typing…");
                    let ran = match s.kind {
                        Kind::Ducky => run(&s.body, &mut 0),
                        Kind::Text => type_out(&s.body),
                    };
                    // the owner left while it typed: nothing else to do
                    if matches!(ran, Ran::Left) {
                        return;
                    }
                    app.note = ran.note().into();
                    app.view = View::List;
                    app.selected = at;
                }
            }
            (View::Detail(_), Event::Left) | (View::Detail(_), Event::Right) => {
                app.view = View::List;
            }
            (_, Event::Exit) => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
