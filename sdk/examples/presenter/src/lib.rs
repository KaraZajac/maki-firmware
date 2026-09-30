//! Presenter: maki as a slide clicker, with a timer to read at a glance. The jog dial on maki's
//! side goes to the next slide or back (right and left do too), as Page Down and Page Up, which
//! PowerPoint, Keynote, Google Slides, Impress, reveal.js and PDF viewers all take; the dial held
//! down steps once, not through the deck. The centre blanks the screen, as B does, and brings it
//! back.
//!
//! The timer starts at the first slide forward: the time left, in digits big enough to read from
//! a stage, the screen flashing at 5 and 2 minutes to go and staying lit for the last two,
//! blinking at zero, then counting the time over. The menu starts the show (F5, or Shift+F5 from
//! the slide showing, for PowerPoint and Impress: Keynote and Google Slides start with shortcuts
//! only their owner should press), ends it (Esc), pauses or resets the timer, and sets the talk's
//! length; with none, the timer counts up.

#![no_std]

use core::fmt::Write;

use maki_app::keyboard::{self, Key};
use maki_app::screen::Toward;
use maki_app::*;

/// A talk's length in minutes, to start with, and the most.
const LENGTH: u32 = 20;
const LONGEST: u32 = 180;
/// Minutes to go when the screen flashes; for the last `LIT`, it stays lit.
const ALERTS: [u32; 2] = [5, 2];
const LIT: u32 = 2;
/// A flash: three times on and off, each this long.
const FLASHES: u64 = 3;
const FLASH_MS: u64 = 300;
/// At zero, it blinks this long, a blink each `BLINK_MS`.
const ZERO_MS: u64 = 10_000;
const BLINK_MS: u64 = 500;
/// The dial held down repeats: turns closer together than this are one.
const REPEAT_MS: u64 = 120;
/// How long a note shows, and how often the screen's looked at while the timer runs.
const NOTE_MS: u64 = 3000;
const TICK_MS: u32 = 100;
/// The time's digits: as tall as fit, from this.
const DIGITS: i32 = 44;

const MENU: [&str; 6] = ["Start show", "Start here", "End show", "Pause timer", "Reset timer", "Talk length"];
const MENU_PAUSED: [&str; 6] =
    ["Start show", "Start here", "End show", "Resume timer", "Reset timer", "Talk length"];

/// The talk's time: when it started (moved on by any time paused), and when it was paused.
#[derive(Default)]
struct Timer {
    start: Option<u64>,
    paused: Option<u64>,
}

impl Timer {
    fn elapsed(&self, now: u64) -> u64 {
        match (self.start, self.paused) {
            (None, _) => 0,
            (Some(s), Some(p)) => p.saturating_sub(s),
            (Some(s), None) => now.saturating_sub(s),
        }
    }

    fn start(&mut self, now: u64) {
        if self.start.is_none() {
            self.start = Some(now);
        }
    }

    fn pause(&mut self, now: u64) {
        if self.start.is_some() && self.paused.is_none() {
            self.paused = Some(now);
        }
    }

    fn resume(&mut self, now: u64) {
        if let (Some(s), Some(p)) = (self.start, self.paused.take()) {
            self.start = Some(s + now.saturating_sub(p));
        }
    }
}

/// What the screen shows, to draw it only when that changes.
#[derive(PartialEq)]
struct Look {
    lit: bool,
    time: Buf<12>,
    top_left: Buf<16>,
    top_right: Buf<16>,
    caption: Buf<32>,
    /// the bar: how far along, in pixels, of a talk this many minutes long
    bar: Option<(i32, u32)>,
    setting: Option<u32>,
}

struct App {
    /// minutes; 0 counts up
    length: u32,
    timer: Timer,
    /// forward presses less back ones, from the first slide
    slide: u32,
    blank: bool,
    note: &'static str,
    note_until: u64,
    /// the dial's last turn: when, and which way
    last_dial: Option<(u64, Event)>,
    /// the alerts given (a bit each), and when the last began
    flashed: u8,
    flash_from: Option<u64>,
    /// setting the talk's length: the minutes so far
    setting: Option<u32>,
}

impl App {
    /// The time left in milliseconds (below 0 when it's over), or None if the timer counts up.
    fn left(&self, now: u64) -> Option<i64> {
        (self.length > 0).then(|| self.length as i64 * 60_000 - self.timer.elapsed(now) as i64)
    }

    fn say(&mut self, what: &'static str, now: u64) {
        self.note = what;
        self.note_until = now + NOTE_MS;
    }

    /// A key to the computer; whether it went.
    fn press(&mut self, key: Key, shift: bool, now: u64) -> bool {
        let pressed = if shift { keyboard::press_shifted(key) } else { keyboard::press(key) };
        if pressed.is_err() {
            self.say("not plugged in", now);
        }
        pressed.is_ok()
    }

    fn step(&mut self, forward: bool, now: u64) {
        if !self.press(if forward { Key::PageDown } else { Key::PageUp }, false, now) {
            return;
        }
        self.slide = if forward { self.slide + 1 } else { self.slide.saturating_sub(1).max(1) };
        self.blank = false;
        if forward {
            self.timer.start(now);
        }
    }

    /// The flashes due: one as the time left passes each alert.
    fn alerts(&mut self, now: u64) {
        let Some(left) = self.left(now) else { return };
        for (i, &at) in ALERTS.iter().enumerate() {
            let at_ms = at as i64 * 60_000;
            if self.flashed & (1 << i) == 0 && self.length > at && left <= at_ms && left > 0 {
                self.flashed |= 1 << i;
                self.flash_from = Some(now);
            }
        }
    }

    /// Whether the screen's lit: flashing, in the last minutes, blinking at zero and lit after.
    fn lit(&self, now: u64) -> bool {
        if let Some(from) = self.flash_from {
            let t = now.saturating_sub(from);
            if t < FLASHES * 2 * FLASH_MS {
                return (t / FLASH_MS).is_multiple_of(2);
            }
        }
        match self.left(now) {
            Some(left) if self.timer.start.is_some() && left <= 0 => {
                let over = (-left) as u64;
                over >= ZERO_MS || (over / BLINK_MS).is_multiple_of(2)
            }
            Some(left) if self.timer.start.is_some() => self.length > LIT && left <= LIT as i64 * 60_000,
            _ => false,
        }
    }

    fn look(&self, now: u64) -> Look {
        let mut look = Look {
            lit: self.lit(now),
            time: Buf::new(),
            top_left: Buf::new(),
            top_right: Buf::new(),
            caption: Buf::new(),
            bar: None,
            setting: self.setting,
        };
        if self.setting.is_some() {
            return look;
        }
        let _ = write!(look.top_left, "slide {}", self.slide);
        let state = if now < self.note_until {
            self.note
        } else if self.blank {
            "BLANK"
        } else if self.timer.paused.is_some() {
            "PAUSED"
        } else {
            ""
        };
        let _ = look.top_right.write_str(state);
        let started = self.timer.start.is_some();
        match self.left(now) {
            None => {
                clock(&mut look.time, self.timer.elapsed(now), false);
                let _ = look.caption.write_str(if started { "elapsed" } else { "next slide starts it" });
            }
            Some(left) if left >= 0 => {
                clock(&mut look.time, left as u64, true);
                if started {
                    let _ = write!(look.caption, "left of {}:00", self.length);
                } else {
                    let _ = look.caption.write_str("next slide starts it");
                }
            }
            Some(left) => {
                let _ = look.time.write_char('+');
                clock(&mut look.time, (-left) as u64, false);
                let _ = look.caption.write_str("over time");
            }
        }
        if started && self.length > 0 {
            let total = self.length as u64 * 60_000;
            look.bar = Some((((self.timer.elapsed(now).min(total) * 116) / total) as i32, self.length));
        }
        look
    }

    /// What `wait` waits for: the timer's next change, or the note going.
    fn wake(&self, now: u64) -> Option<u32> {
        let running = self.timer.start.is_some() && self.timer.paused.is_none();
        let flashing = self.flash_from.is_some_and(|f| now.saturating_sub(f) < FLASHES * 2 * FLASH_MS);
        if running || flashing {
            Some(TICK_MS)
        } else if now < self.note_until {
            Some((self.note_until - now) as u32)
        } else {
            None
        }
    }
}

/// `ms` as M:SS, or H:MM:SS from an hour; `up` rounds up (a countdown shows 0:01 to the end).
fn clock(b: &mut Buf<12>, ms: u64, up: bool) {
    let s = if up { ms.div_ceil(1000) } else { ms / 1000 };
    if s >= 3600 {
        let _ = write!(b, "{}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60);
    } else {
        let _ = write!(b, "{}:{:02}", s / 60, s % 60);
    }
}

/// Digits as tall as fit across the screen, from `DIGITS` down, centred at `y` down.
fn big(y: i32, text: &str, most: i32, color: Color) {
    let mut h = most;
    while h > 16 && screen::segments_size(text, h, Toward::Bottom).0 > WIDTH - 6 {
        h -= 2;
    }
    let (w, _) = screen::segments_size(text, h, Toward::Bottom);
    screen::segments((WIDTH - w) / 2, y + (most - h) / 2, text, h, Toward::Bottom, color);
}

fn draw(look: &Look) {
    let (back, fore) = if look.lit { (Color::Light, Color::Dark) } else { (Color::Dark, Color::Light) };
    screen::clear(back);
    if let Some(minutes) = look.setting {
        screen::text_centred(0, "Talk length", Style::Bold, fore);
        let mut n = Buf::<4>::new();
        let _ = write!(n, "{minutes}");
        big(24, n.as_str(), DIGITS, fore);
        let caption = if minutes == 0 { "none: it counts up" } else { "minutes" };
        screen::text_centred(70, caption, Style::Small, fore);
        screen::text_centred(84, "dial: 1   left, right: 5", Style::Small, fore);
        screen::line(0, 97, WIDTH - 1, 97, fore);
        screen::text_centred(99, "centre: done", Style::Small, fore);
        screen::present();
        return;
    }
    screen::text(2, 0, look.top_left.as_str(), Style::Small, fore);
    let w = screen::text_width(look.top_right.as_str(), Style::Small);
    screen::text(WIDTH - 2 - w, 0, look.top_right.as_str(), Style::Small, fore);
    big(18, look.time.as_str(), DIGITS, fore);
    screen::text_centred(68, look.caption.as_str(), Style::Small, fore);
    if let Some((done, total)) = look.bar {
        // how far along, with a tick where each alert flashes
        screen::rect(5, 90, 118, 9, fore);
        screen::fill_rect(6, 91, done, 7, fore);
        for at in ALERTS.iter().filter(|&&a| a < total) {
            let x = 6 + ((total - at) * 116 / total) as i32;
            screen::line(x, 86, x, 102, fore);
        }
    } else {
        screen::line(0, 97, WIDTH - 1, 97, fore);
        screen::text_centred(99, "dial: slides   centre: blank", Style::Small, fore);
    }
    screen::present();
}

fn main() {
    let _ = menu(&MENU);
    let mut app = App {
        length: storage::get_u32("length", LENGTH).min(LONGEST),
        timer: Timer::default(),
        slide: 1,
        blank: false,
        note: "",
        note_until: 0,
        last_dial: None,
        flashed: 0,
        flash_from: None,
        setting: None,
    };
    let mut shown: Option<Look> = None;
    loop {
        let now = millis();
        app.alerts(now);
        let look = app.look(now);
        if shown.as_ref() != Some(&look) {
            draw(&look);
            shown = Some(look);
        }
        let event = wait(app.wake(now));
        let now = millis();
        if let Some(minutes) = app.setting {
            match event {
                Event::Up => app.setting = Some((minutes + 1).min(LONGEST)),
                Event::Down => app.setting = Some(minutes.saturating_sub(1)),
                Event::Right => app.setting = Some((minutes / 5 * 5 + 5).min(LONGEST)),
                Event::Left => app.setting = Some(minutes.saturating_sub(1) / 5 * 5),
                Event::Centre => {
                    app.length = minutes;
                    let _ = storage::set_u32("length", minutes);
                    app.setting = None;
                }
                Event::Exit => return,
                _ => {}
            }
            continue;
        }
        match event {
            // the dial held down: its repeats, the same way, are one turn
            Event::Up | Event::Down
                if app
                    .last_dial
                    .is_some_and(|(t, way)| way == event && now.saturating_sub(t) < REPEAT_MS) =>
            {
                app.last_dial = Some((now, event));
            }
            Event::Down | Event::Right | Event::Up | Event::Left => {
                if matches!(event, Event::Up | Event::Down) {
                    app.last_dial = Some((now, event));
                }
                app.step(matches!(event, Event::Down | Event::Right), now);
            }
            Event::Centre => {
                if keyboard::type_text("b").is_ok() {
                    app.blank = !app.blank;
                } else {
                    app.say("not plugged in", now);
                }
            }
            Event::Menu(0) | Event::Menu(1) => {
                let here = event == Event::Menu(1);
                if app.press(Key::F5, here, now) {
                    if !here {
                        app.slide = 1;
                    }
                    app.blank = false;
                    app.timer.start(now);
                }
            }
            Event::Menu(2) => {
                if app.press(Key::Escape, false, now) {
                    app.blank = false;
                }
            }
            Event::Menu(3) if app.timer.paused.is_some() => {
                app.timer.resume(now);
                let _ = menu(&MENU);
            }
            Event::Menu(3) if app.timer.start.is_some() => {
                app.timer.pause(now);
                let _ = menu(&MENU_PAUSED);
            }
            Event::Menu(3) => app.say("not started", now),
            Event::Menu(4) => {
                app.timer = Timer::default();
                app.slide = 1;
                app.flashed = 0;
                app.flash_from = None;
                let _ = menu(&MENU);
            }
            Event::Menu(5) => app.setting = Some(app.length),
            Event::Shown => shown = None,
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
