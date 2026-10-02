//! Macro Pad: keystrokes maki types into a computer at the press of a button — text, keys and
//! DuckyScript. You send scripts from maki desktop (the link permission); maki keeps them, and
//! each is a button on the pad. The centre opens a script, the centre again runs it, with you
//! holding maki and "typing" in its bar: an attended tool, not a hidden implant. A script can
//! press shortcuts (Gui+R, Ctrl+Alt+Delete), so it can open and run programs — run only scripts
//! you trust. Nothing leaves maki; the computer only sees the keystrokes.

use std::fmt::Write as _;

use maki_app::keyboard::{self, Key};
use maki_app::*;

/// The most scripts the pad holds, and the longest a name may be.
const MAX_SCRIPTS: usize = 12;
const MAX_NAME: usize = 24;
/// A guard on a runaway script: the most keystrokes one run makes, and the longest a DELAY waits.
const MAX_ACTIONS: u32 = 5000;
const MAX_DELAY_MS: u32 = 60_000;

struct Script {
    name: String,
    body: String,
}

/// Everything in `scripts`, as one stored value: for each, the name and the body, each with a
/// little-endian u16 length.
fn load() -> Vec<Script> {
    let mut buf = vec![0u8; MAX_VALUE];
    let Some(n) = storage::get("scripts", &mut buf) else { return Vec::new() };
    let b = &buf[..n.min(buf.len())];
    let mut out = Vec::new();
    let mut i = 0;
    let take = |b: &[u8], i: &mut usize| -> Option<String> {
        let len = u16::from_le_bytes([*b.get(*i)?, *b.get(*i + 1)?]) as usize;
        *i += 2;
        let s = core::str::from_utf8(b.get(*i..*i + len)?).ok()?.to_string();
        *i += len;
        Some(s)
    };
    while i < b.len() && out.len() < MAX_SCRIPTS {
        match (take(b, &mut i), take(b, &mut i)) {
            (Some(name), Some(body)) => out.push(Script { name, body }),
            _ => break,
        }
    }
    out
}

fn save(scripts: &[Script]) {
    let mut b = Vec::new();
    for s in scripts {
        for part in [s.name.as_str(), s.body.as_str()] {
            b.extend_from_slice(&(part.len() as u16).to_le_bytes());
            b.extend_from_slice(part.as_bytes());
        }
    }
    let _ = storage::set("scripts", &b);
}

/// A script sent from maki desktop: the first line is its name, the rest the DuckyScript. A name
/// already on the pad is replaced (so re-sending an edited script updates it). The pad's count,
/// or None if it's full and this is a new name.
fn take_script(scripts: &mut Vec<Script>, message: &str) -> Option<usize> {
    let (name, body) = message.split_once('\n').unwrap_or((message, ""));
    let name: String = name.trim().chars().take(MAX_NAME).collect();
    let name = if name.is_empty() { "script".to_string() } else { name };
    let script = Script { name: name.clone(), body: body.to_string() };
    if let Some(slot) = scripts.iter().position(|s| s.name == name) {
        scripts[slot] = script;
    } else if scripts.len() < MAX_SCRIPTS {
        scripts.push(script);
    } else {
        return None;
    }
    save(scripts);
    Some(scripts.len())
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
        _ if token.chars().count() == 1 => Token::Char(token.chars().next().unwrap()),
        _ => Token::Unknown,
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

fn draw_list(scripts: &[Script], selected: usize, note: Option<&str>) {
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
            screen::text(4, y, &scripts[i].name, Style::Regular, ink);
        }
    }
    if let Some(n) = note {
        screen::fill_rect(0, HEIGHT - 13, WIDTH, 13, Color::Dark);
        screen::text_centred(HEIGHT - 12, n, Style::Small, Color::Light);
    }
    screen::present();
}

fn draw_detail(script: &Script, note: Option<&str>) {
    screen::clear(Color::Dark);
    screen::text_centred(0, &script.name, Style::Bold, Color::Light);
    // the first few lines, so you see what it'll do
    for (row, line) in script.body.lines().filter(|l| !l.trim().is_empty()).take(5).enumerate() {
        let mut shown: String = line.trim().chars().take(24).collect();
        if line.trim().chars().count() > 24 {
            shown.push('…');
        }
        screen::text(4, 18 + row as i32 * 12, &shown, Style::Small, Color::Light);
    }
    screen::text_centred(HEIGHT - 13, note.unwrap_or("centre: type it"), Style::Small, Color::Light);
    screen::present();
}

/// Reads a script sent over the link, keeps it, and answers maki desktop: a note for the screen.
fn receive(scripts: &mut Vec<Script>) -> Option<&'static str> {
    let mut buf = vec![0u8; MAX_MESSAGE];
    let n = link::read(&mut buf)?;
    let text = std::str::from_utf8(&buf[..n.min(buf.len())]).unwrap_or("");
    Some(match take_script(scripts, text) {
        Some(count) => {
            let mut reply = String::from("ok ");
            let _ = write!(reply, "{count}");
            let _ = link::reply(reply.as_bytes());
            "script saved"
        }
        None => {
            let _ = link::reply(b"full");
            "pad is full"
        }
    })
}

const MAX_MESSAGE: usize = 4096;
const MAX_VALUE: usize = 16 * 1024;

enum View {
    List,
    Detail(usize),
}

fn main() {
    let _ = menu(&["Delete this", "Clear all"]);
    let mut scripts = load();
    let mut selected = 0usize;
    let mut view = View::List;
    let mut note: Option<&str> = None;
    loop {
        if selected >= scripts.len() {
            selected = scripts.len().saturating_sub(1);
        }
        match &view {
            View::List => draw_list(&scripts, selected, note),
            View::Detail(i) => match scripts.get(*i) {
                Some(s) => draw_detail(s, note),
                None => {
                    view = View::List;
                    continue;
                }
            },
        }
        note = None;
        let event = wait(None);
        match (&view, event) {
            (_, Event::Message) => {
                note = receive(&mut scripts);
            }
            (View::List, Event::Left) | (View::List, Event::Up) => {
                selected = selected.saturating_sub(1);
            }
            (View::List, Event::Right) | (View::List, Event::Down) => {
                if selected + 1 < scripts.len() {
                    selected += 1;
                }
            }
            (View::List, Event::Centre) => {
                if !scripts.is_empty() {
                    view = View::Detail(selected);
                }
            }
            (View::List, Event::Menu(0)) => {
                if !scripts.is_empty() {
                    scripts.remove(selected);
                    save(&scripts);
                    note = Some("deleted");
                }
            }
            (View::List, Event::Menu(1)) => {
                scripts.clear();
                storage::delete("scripts");
                note = Some("cleared");
            }
            (View::Detail(i), Event::Centre) => {
                let i = *i;
                // typing shows on maki's bar; tell the owner it's going
                if let Some(s) = scripts.get(i) {
                    draw_detail(s, Some("typing…"));
                    let mut progress = 0u32;
                    let outcome = run(&s.body, &mut progress);
                    note = Some(match outcome {
                        Ran::Done => "typed it",
                        Ran::Unplugged => "plug maki into a computer",
                        Ran::Left => "stopped",
                        Ran::TooLong => "too many keystrokes",
                    });
                    view = View::List;
                    selected = i;
                }
            }
            (View::Detail(_), Event::Left) | (View::Detail(_), Event::Right) => {
                view = View::List;
            }
            (_, Event::Exit) => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
