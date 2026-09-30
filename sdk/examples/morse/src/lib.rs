//! Morse: Morse code on the jog dial, which is a paddle: up a dot, down a dash. A letter's done
//! when the dial rests (a second, or as the menu sets), or at the centre; the centre with nothing
//! keyed is a space, and left deletes. As you key, it shows the letter the dots and dashes make so
//! far, and what one more of each would make. Gboard's three are here too: ..-- a space, .-.- a
//! line, ---- deleting; eight dots erase the word.
//!
//! - **Key**: what you key, and typed into the computer as you go if typing's on (the keyboard permission); a
//!   line, which would press Enter, waits for the centre first.
//! - **Learn**, by the Koch method, as LCWO teaches it, with the screen for a signal lamp (maki has no
//!   sound): it flashes a letter at 10 words a minute, you key it back, and the next comes once you have. Two
//!   letters to start, one more each time you're 90% right; a miss shows the letter and its code, and comes
//!   round again.
//! - **Flash it**: what you've keyed, flashed across a room, the dial setting how fast.
//! - **Chart**: every code, the dial scrolling.

use std::collections::VecDeque;
use std::fmt::Write;

use maki_app::keyboard::{self, Key};
use maki_app::*;

/// Letters, digits and ITU's punctuation.
const CODES: &[(char, &str)] = &[
    ('A', ".-"),
    ('B', "-..."),
    ('C', "-.-."),
    ('D', "-.."),
    ('E', "."),
    ('F', "..-."),
    ('G', "--."),
    ('H', "...."),
    ('I', ".."),
    ('J', ".---"),
    ('K', "-.-"),
    ('L', ".-.."),
    ('M', "--"),
    ('N', "-."),
    ('O', "---"),
    ('P', ".--."),
    ('Q', "--.-"),
    ('R', ".-."),
    ('S', "..."),
    ('T', "-"),
    ('U', "..-"),
    ('V', "...-"),
    ('W', ".--"),
    ('X', "-..-"),
    ('Y', "-.--"),
    ('Z', "--.."),
    ('0', "-----"),
    ('1', ".----"),
    ('2', "..---"),
    ('3', "...--"),
    ('4', "....-"),
    ('5', "....."),
    ('6', "-...."),
    ('7', "--..."),
    ('8', "---.."),
    ('9', "----."),
    ('.', ".-.-.-"),
    (',', "--..--"),
    ('?', "..--.."),
    ('\'', ".----."),
    ('!', "-.-.--"),
    ('/', "-..-."),
    ('(', "-.--."),
    (')', "-.--.-"),
    ('&', ".-..."),
    (':', "---..."),
    (';', "-.-.-."),
    ('=', "-...-"),
    ('+', ".-.-."),
    ('-', "-....-"),
    ('_', "..--.-"),
    ('"', ".-..-."),
    ('$', "...-..-"),
    ('@', ".--.-."),
];
/// Gboard's: a space, a line, deleting; and the error sign, which erases the word.
const SPACE: &str = "..--";
const LINE: &str = ".-.-";
const DELETE: &str = "----";
const ERASE: &str = "........";
/// The Koch method's order, as LCWO has it.
const KOCH: &str = "KMURESNAPTLWI.JZ=FOY,VG5/Q92H38B?47C1D60X";
/// Right this often in the last `SPAN` to learn another.
const GOOD: usize = 18;
const SPAN: usize = 20;
/// The lamp: a dot at 10 words a minute while learning.
const LEARN_DOT_MS: u64 = 120;
/// How long the dial rests before a letter's done: the menu goes round these (0: the centre only).
const PAUSES: [u64; 6] = [1000, 1500, 2000, 0, 500, 750];
/// The text kept.
const KEEP: usize = 400;

/// What a code means.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Sym {
    Char(char),
    Space,
    Line,
    Delete,
    Erase,
}

fn decode(code: &str) -> Option<Sym> {
    match code {
        SPACE => Some(Sym::Space),
        LINE => Some(Sym::Line),
        DELETE => Some(Sym::Delete),
        ERASE => Some(Sym::Erase),
        _ => CODES.iter().find(|(_, c)| *c == code).map(|&(ch, _)| Sym::Char(ch)),
    }
}

fn code_of(ch: char) -> &'static str { CODES.iter().find(|(c, _)| *c == ch).map_or("", |(_, code)| code) }

/// The lamp's on and off, in dots, for `text`: a dot on 1, a dash 3, 1 between them, 3 between
/// letters, 7 between words.
fn lamp(text: &str) -> Vec<(bool, u64)> {
    let mut out: Vec<(bool, u64)> = vec![];
    for (w, word) in text.split_whitespace().enumerate() {
        if w > 0 {
            out.push((false, 7));
        }
        for (i, ch) in word.chars().enumerate() {
            if i > 0 {
                out.push((false, 3));
            }
            for (j, e) in code_of(ch.to_ascii_uppercase()).chars().enumerate() {
                if j > 0 {
                    out.push((false, 1));
                }
                out.push((true, if e == '.' { 1 } else { 3 }));
            }
        }
    }
    out
}

/// Where a lamp's run is at `t` dots in: lit, and when (in dots) that changes; None once it's done.
fn lamp_at(run: &[(bool, u64)], t: u64) -> Option<(bool, u64)> {
    let mut at = 0;
    for &(on, n) in run {
        if t < at + n {
            return Some((on, at + n));
        }
        at += n;
    }
    None
}

#[derive(Clone, Copy, PartialEq)]
enum Lesson {
    /// the lamp flashing the letter, since when
    Showing(u64),
    /// the learner keying it back
    Answer,
    /// right or not, shown till then
    Result(bool, u64),
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Key,
    Learn,
    /// flashing what's keyed: since when, at how many words a minute (None: ready)
    Flash(Option<u64>),
    Chart(usize),
}

struct App {
    mode: Mode,
    text: String,
    /// the dots and dashes keyed so far, and when the last was
    code: String,
    last: u64,
    typing: bool,
    pause: usize,
    wpm: u32,
    /// a line keyed while typing: waiting for the centre
    confirm_line: bool,
    note: String,
    note_until: u64,
    /// learning: how many letters, the letter now, the last answers, and where it's at
    level: usize,
    letter: char,
    answers: VecDeque<bool>,
    lesson: Lesson,
}

impl App {
    fn say(&mut self, what: &str, now: u64) {
        self.note = what.into();
        self.note_until = now + 2500;
    }

    fn save(&self) {
        let mut b = vec![self.typing as u8, self.pause as u8, self.wpm as u8, self.level as u8];
        b.extend_from_slice(self.text.as_bytes());
        let _ = storage::set("morse", &b);
    }

    /// A letter's done: what it means is done to the text (and typed, if typing's on).
    fn commit(&mut self, now: u64) {
        let code = std::mem::take(&mut self.code);
        if code.is_empty() {
            return;
        }
        if self.mode == Mode::Learn {
            self.answer(decode(&code), now);
            return;
        }
        match decode(&code) {
            Some(Sym::Char(ch)) => {
                let ch = ch.to_ascii_lowercase();
                self.text.push(ch);
                self.send(&ch.to_string(), now);
            }
            Some(Sym::Space) => self.space(now),
            Some(Sym::Line) if self.typing => self.confirm_line = true,
            Some(Sym::Line) => self.text.push('\n'),
            Some(Sym::Delete) => self.delete(1, now),
            Some(Sym::Erase) => {
                let t = self.text.trim_end_matches(' ');
                let word = t.len() - t.rfind([' ', '\n']).map_or(0, |i| i + 1);
                let n = self.text.len() - t.len() + word;
                self.delete(n, now);
            }
            None => self.say("? not a code", now),
        }
        self.trim();
        self.save();
    }

    fn space(&mut self, now: u64) {
        if !self.text.is_empty() && !self.text.ends_with([' ', '\n']) {
            self.text.push(' ');
            self.send(" ", now);
        }
    }

    fn delete(&mut self, n: usize, now: u64) {
        for _ in 0..n {
            if self.text.pop().is_some() && self.typing && keyboard::press(Key::Backspace).is_err() {
                self.say("not plugged in", now);
            }
        }
    }

    /// Typed into the computer, if typing's on.
    fn send(&mut self, s: &str, now: u64) {
        if self.typing && keyboard::type_text(s).is_err() {
            self.say("not plugged in", now);
        }
    }

    fn trim(&mut self) {
        if self.text.len() > KEEP {
            let cut = self.text.len() - KEEP;
            self.text.drain(..cut);
        }
    }

    /// The letters being learned.
    fn letters(&self) -> &str { &KOCH[..self.level.clamp(2, KOCH.len())] }

    /// The next letter to learn: a miss comes round again; otherwise any, the newest more often.
    fn next_letter(&mut self, now: u64) {
        let set: Vec<char> = self.letters().chars().collect();
        if self.answers.back() != Some(&false) {
            let i = random_below(set.len() as u32 + 2) as usize;
            self.letter = set[i.min(set.len() - 1)];
        }
        self.lesson = Lesson::Showing(now + 400);
    }

    fn answer(&mut self, got: Option<Sym>, now: u64) {
        let right = got == Some(Sym::Char(self.letter));
        self.answers.push_back(right);
        if self.answers.len() > SPAN {
            self.answers.pop_front();
        }
        self.lesson = Lesson::Result(right, now + if right { 800 } else { 2500 });
        if self.answers.len() == SPAN
            && self.answers.iter().filter(|&&a| a).count() >= GOOD
            && self.level < KOCH.len()
        {
            self.level = self.level.max(2) + 1;
            self.answers.clear();
            let new = KOCH.chars().nth(self.level - 1).unwrap_or(' ');
            let mut s = String::new();
            let _ = write!(s, "new letter: {new}");
            self.say(&s, now);
            self.save();
        }
    }

    /// When `wait` should wake: the letter done, the lamp's next change, the note going.
    fn wake(&self, now: u64) -> Option<u32> {
        let at = |t: u64| Some(t.saturating_sub(now).max(1) as u32);
        let pause = PAUSES[self.pause];
        if !self.code.is_empty() && pause > 0 && matches!(self.mode, Mode::Key | Mode::Learn) {
            return at(self.last + pause);
        }
        match (self.mode, self.lesson) {
            (Mode::Learn, Lesson::Showing(from)) => {
                if now < from {
                    return at(from);
                }
                let run = lamp(&self.letter.to_string());
                let t = (now - from) / LEARN_DOT_MS;
                match lamp_at(&run, t) {
                    Some((_, next)) => at(from + next * LEARN_DOT_MS),
                    None => at(now + 1),
                }
            }
            (Mode::Learn, Lesson::Result(_, until)) => at(until),
            (Mode::Flash(Some(from)), _) => {
                let dot = 1200 / self.wpm.max(1) as u64;
                let t = (now.saturating_sub(from)) / dot;
                match lamp_at(&lamp(&self.flash_text()), t) {
                    Some((_, next)) => at(from + next * dot),
                    None => at(now + 1),
                }
            }
            _ if now < self.note_until => at(self.note_until),
            _ => None,
        }
    }

    fn flash_text(&self) -> String {
        let t = self.text.replace('\n', " ");
        if t.trim().is_empty() { "SOS".into() } else { t }
    }
}

/// Dots and dashes, big: a dot a square, a dash three long, centred at `y`.
fn draw_code(code: &str, y: i32, color: Color) {
    let (dot, dash, gap) = (7, 21, 5);
    let w: i32 = code.chars().map(|c| if c == '.' { dot } else { dash }).sum::<i32>()
        + gap * (code.len() as i32 - 1).max(0);
    let mut x = (WIDTH - w) / 2;
    for c in code.chars() {
        let len = if c == '.' { dot } else { dash };
        screen::fill_rect(x, y, len, dot, color);
        x += len + gap;
    }
}

fn sym_text(sym: Option<Sym>) -> String {
    match sym {
        Some(Sym::Char(c)) => c.to_string(),
        Some(Sym::Space) => "space".into(),
        Some(Sym::Line) => "line".into(),
        Some(Sym::Delete) => "delete".into(),
        Some(Sym::Erase) => "erase word".into(),
        None => String::new(),
    }
}

fn draw(app: &App, now: u64) {
    screen::clear(Color::Dark);
    let note = (now < app.note_until).then_some(app.note.as_str());
    match app.mode {
        Mode::Key => {
            // the text's last two lines, a cursor after it
            let mut lines: Vec<String> = vec![String::new()];
            for ch in app.text.chars() {
                if ch == '\n' {
                    lines.push(String::new());
                    continue;
                }
                let last = lines.last_mut().unwrap();
                if screen::text_width(&format!("{last}{ch}_"), Style::Small) > WIDTH - 4 {
                    lines.push(String::new());
                }
                lines.last_mut().unwrap().push(ch);
            }
            lines.last_mut().unwrap().push('_');
            for (i, line) in lines.iter().rev().take(2).rev().enumerate() {
                screen::text(2, i as i32 * 12, line, Style::Small, Color::Light);
            }
            screen::line(0, 26, WIDTH - 1, 26, Color::Light);
            if app.confirm_line {
                screen::text_centred(40, "type a line?", Style::Bold, Color::Light);
                screen::text_centred(60, "it presses Enter", Style::Small, Color::Light);
                screen::line(0, 97, WIDTH - 1, 97, Color::Light);
                screen::text_centred(99, "centre: type   left: no", Style::Small, Color::Light);
            } else if app.code.is_empty() {
                screen::text_centred(38, "dial up: dot", Style::Small, Color::Light);
                screen::text_centred(52, "dial down: dash", Style::Small, Color::Light);
                screen::line(0, 97, WIDTH - 1, 97, Color::Light);
                let foot = note.unwrap_or(if app.typing {
                    "typing   centre: space"
                } else {
                    "centre: space  left: del"
                });
                screen::text_centred(99, foot, Style::Small, Color::Light);
            } else {
                draw_code(&app.code, 32, Color::Light);
                let now_is = sym_text(decode(&app.code));
                let now_is = if now_is.is_empty() { "?".to_string() } else { now_is };
                screen::text_centred(44, &now_is, Style::Tall, Color::Light);
                // what one more of each would make
                let then = |e: char| sym_text(decode(&format!("{}{e}", app.code)));
                let (dot, dash) = (then('.'), then('-'));
                let mut hint = String::new();
                if !dot.is_empty() {
                    let _ = write!(hint, "dot {dot}  ");
                }
                if !dash.is_empty() {
                    let _ = write!(hint, "dash {dash}");
                }
                screen::text_centred(70, hint.trim(), Style::Small, Color::Light);
                screen::line(0, 97, WIDTH - 1, 97, Color::Light);
                screen::text_centred(99, note.unwrap_or("centre: letter now"), Style::Small, Color::Light);
            }
        }
        Mode::Learn => match app.lesson {
            Lesson::Showing(from) => {
                // the lamp: the whole screen
                if now >= from {
                    let run = lamp(&app.letter.to_string());
                    if let Some((true, _)) = lamp_at(&run, (now - from) / LEARN_DOT_MS) {
                        screen::clear(Color::Light);
                    }
                }
            }
            Lesson::Answer => {
                screen::text_centred(4, "Key what it was", Style::Bold, Color::Light);
                if !app.code.is_empty() {
                    draw_code(&app.code, 36, Color::Light);
                }
                let mut s = String::new();
                let _ = write!(s, "letters: {}", app.letters());
                screen::text_centred(62, &s, Style::Small, Color::Light);
                let right = app.answers.iter().filter(|&&a| a).count();
                let mut r = String::new();
                if !app.answers.is_empty() {
                    let _ = write!(r, "{right} of the last {}", app.answers.len());
                }
                screen::text_centred(76, &r, Style::Small, Color::Light);
                screen::line(0, 97, WIDTH - 1, 97, Color::Light);
                screen::text_centred(99, note.unwrap_or("centre: see it again"), Style::Small, Color::Light);
            }
            Lesson::Result(right, _) => {
                let mut s = String::new();
                if right {
                    let _ = write!(s, "{}: right", app.letter);
                    screen::text_centred(30, &s, Style::Tall, Color::Light);
                } else {
                    let _ = write!(s, "it was {}", app.letter);
                    screen::text_centred(20, &s, Style::Tall, Color::Light);
                    draw_code(code_of(app.letter), 52, Color::Light);
                }
                if let Some(n) = note {
                    screen::text_centred(80, n, Style::Small, Color::Light);
                }
            }
        },
        Mode::Flash(None) => {
            screen::text_centred(4, "Flash it", Style::Bold, Color::Light);
            let text = app.flash_text();
            let shown: String = text.chars().rev().take(18).collect::<Vec<_>>().into_iter().rev().collect();
            screen::text_centred(28, &shown, Style::Small, Color::Light);
            let mut s = String::new();
            let _ = write!(s, "{} words a minute", app.wpm);
            screen::text_centred(50, &s, Style::Regular, Color::Light);
            screen::text_centred(70, "across a room, dark", Style::Small, Color::Light);
            screen::line(0, 97, WIDTH - 1, 97, Color::Light);
            screen::text_centred(99, "dial: speed   centre: go", Style::Small, Color::Light);
        }
        Mode::Flash(Some(from)) => {
            let dot = 1200 / app.wpm.max(1) as u64;
            if let Some((true, _)) = lamp_at(&lamp(&app.flash_text()), now.saturating_sub(from) / dot) {
                screen::clear(Color::Light);
            }
        }
        Mode::Chart(top) => {
            for (i, (ch, code)) in CODES.iter().enumerate().skip(top * 2).take(16) {
                let row = (i - top * 2) / 2;
                let x = if i % 2 == 0 { 2 } else { 66 };
                let y = row as i32 * 12;
                screen::text(x, y, &ch.to_string(), Style::Bold, Color::Light);
                screen::text(x + 12, y, code, Style::Small, Color::Light);
            }
            screen::line(0, 97, WIDTH - 1, 97, Color::Light);
            screen::text_centred(99, "dial: scroll   centre: back", Style::Small, Color::Light);
        }
    }
    screen::present();
}

fn set_menu(app: &App) {
    let typing = if app.typing { "Typing: on" } else { "Typing: off" };
    let _ = menu(&["Key", "Learn", "Flash it", "Chart", typing, "Letter pause"]);
}

fn main() {
    let mut b = vec![0u8; KEEP + 8];
    let kept = storage::get("morse", &mut b).filter(|&n| n >= 4 && n <= b.len());
    let mut app = App {
        mode: Mode::Key,
        text: kept.map_or(String::new(), |n| String::from_utf8_lossy(&b[4..n]).into_owned()),
        code: String::new(),
        last: 0,
        typing: kept.is_some() && b[0] != 0,
        pause: if kept.is_some() { (b[1] as usize).min(PAUSES.len() - 1) } else { 0 },
        wpm: if kept.is_some() { (b[2] as u32).clamp(5, 20) } else { 8 },
        confirm_line: false,
        note: String::new(),
        note_until: 0,
        level: if kept.is_some() { (b[3] as usize).clamp(2, KOCH.len()) } else { 2 },
        letter: 'K',
        answers: VecDeque::new(),
        lesson: Lesson::Answer,
    };
    set_menu(&app);
    loop {
        let now = millis();
        draw(&app, now);
        let event = wait(app.wake(now));
        let now = millis();
        match event {
            Event::Exit => {
                app.save();
                return;
            }
            Event::Menu(i) => {
                app.code.clear();
                app.confirm_line = false;
                match i {
                    0 => app.mode = Mode::Key,
                    1 => {
                        app.mode = Mode::Learn;
                        app.answers.clear();
                        app.next_letter(now);
                    }
                    2 => app.mode = Mode::Flash(None),
                    3 => app.mode = Mode::Chart(0),
                    4 => {
                        app.typing = !app.typing;
                        set_menu(&app);
                        app.say(if app.typing { "typing on" } else { "typing off" }, now);
                        app.save();
                    }
                    _ => {
                        app.pause = (app.pause + 1) % PAUSES.len();
                        let mut s = String::new();
                        match PAUSES[app.pause] {
                            0 => s.push_str("letters at the centre"),
                            ms => {
                                let _ = write!(s, "a letter after {:.2} s", ms as f32 / 1000.0);
                            }
                        }
                        let s = s.replace(".00 s", " s").replace("0 s", " s");
                        app.say(&s, now);
                        app.save();
                    }
                }
                continue;
            }
            _ => {}
        }
        match app.mode {
            Mode::Key | Mode::Learn => {
                if app.mode == Mode::Learn && app.lesson != Lesson::Answer {
                    // the lamp and the result pass by themselves; a press shows it again
                    match app.lesson {
                        Lesson::Result(_, until) if now >= until => app.next_letter(now),
                        Lesson::Showing(from) if now >= from => {
                            let run = lamp(&app.letter.to_string());
                            if lamp_at(&run, (now - from) / LEARN_DOT_MS).is_none() {
                                app.lesson = Lesson::Answer;
                            }
                        }
                        _ => {}
                    }
                    if event == Event::Centre && app.lesson == Lesson::Answer {
                        app.lesson = Lesson::Showing(now + 300);
                    }
                    continue;
                }
                match event {
                    Event::Up | Event::Down => {
                        if !app.confirm_line {
                            app.code.push(if event == Event::Up { '.' } else { '-' });
                            app.last = now;
                            if app.code.len() > 8 {
                                app.code.remove(0);
                            }
                        }
                    }
                    Event::Timeout => {
                        let pause = PAUSES[app.pause];
                        if !app.code.is_empty() && pause > 0 && now >= app.last + pause {
                            app.commit(now);
                        }
                    }
                    Event::Centre if app.confirm_line => {
                        app.confirm_line = false;
                        app.text.push('\n');
                        app.send("\n", now);
                        app.save();
                    }
                    Event::Left if app.confirm_line => app.confirm_line = false,
                    Event::Centre if app.mode == Mode::Learn && app.code.is_empty() => {
                        app.lesson = Lesson::Showing(now + 300);
                    }
                    Event::Centre if app.code.is_empty() => {
                        app.space(now);
                        app.save();
                    }
                    Event::Centre => app.commit(now),
                    Event::Left if app.code.is_empty() && app.mode == Mode::Key => {
                        app.delete(1, now);
                        app.save();
                    }
                    Event::Left => {
                        app.code.pop();
                    }
                    _ => {}
                }
            }
            Mode::Flash(running) => match (event, running) {
                (Event::Up, None) => app.wpm = (app.wpm + 1).min(20),
                (Event::Down, None) => app.wpm = app.wpm.saturating_sub(1).max(5),
                (Event::Centre, None) => app.mode = Mode::Flash(Some(now + 500)),
                (Event::Timeout, Some(from)) => {
                    let dot = 1200 / app.wpm.max(1) as u64;
                    if now >= from && lamp_at(&lamp(&app.flash_text()), (now - from) / dot).is_none() {
                        app.mode = Mode::Flash(None);
                        app.save();
                    }
                }
                (Event::Centre | Event::Left | Event::Right, Some(_)) => app.mode = Mode::Flash(None),
                _ => {}
            },
            Mode::Chart(top) => match event {
                Event::Down => app.mode = Mode::Chart((top + 1).min(CODES.len().div_ceil(2) - 8)),
                Event::Up => app.mode = Mode::Chart(top.saturating_sub(1)),
                Event::Centre | Event::Left | Event::Right => app.mode = Mode::Key,
                _ => {}
            },
        }
    }
}

maki_app::main!(main);
