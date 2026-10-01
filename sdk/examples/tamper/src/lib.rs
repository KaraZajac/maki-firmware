//! Tamper Log: leave maki on your closed laptop, and it tells you if anyone moved it. Armed, the
//! whole screen goes dark (maki's bar too: nothing to wear the screen or say it's watching) and it
//! logs each time it's moved (how long, how hard, whether it was left tilted), and every press.
//! Your code, pressed on the dark screen, disarms it and shows what happened while you were away:
//! UNDISTURBED, MOVED, or INTERRUPTED if maki's menu was opened, the app closed or the power lost.
//!
//! Arming: a code of five presses (the dial, left, right, the centre), then 30 seconds to put maki
//! down, and it arms once it's been still two seconds. A bump (a jolt that's over in under a
//! second, maki as it was) is only counted; a move is a second or more of it, or a tilt of 3
//! degrees, and goes on till maki's been still 15 seconds. From the fifth press on, each press is a
//! try of the last five, so pressing on without a pause tries no more codes than pausing does:
//! three wrong tries lock the code out for ten minutes. What happened in the minute before you
//! disarmed is marked as probably you, and the code's own five presses as yours. The log keeps its
//! first 128 events and the last; clearing it, or arming again over it, takes the code. Moves and
//! presses are timed from arming: maki gives apps the time in UTC, which beside maki's own clock
//! (local) would say the wrong hour.

use std::fmt::Write;

use maki_app::*;

/// The code's length; a gap this long ends a burst of presses, which the log keeps as one
/// (pressed by feel on a dark screen: time to find the next key); tries before the lockout, and
/// how long.
const CODE_LEN: usize = 5;
const TRY_GAP_MS: u64 = 5000;
const TRIES: u32 = 3;
const LOCKOUT_MS: u64 = 600_000;
/// Before arming: time to put maki down, then this still.
const COUNTDOWN_MS: u64 = 30_000;
const SETTLE_MS: u64 = 2000;
/// Armed: how often it reads, and how often it says it's still there.
const READ_MS: u32 = 40;
const HEARTBEAT_MS: u64 = 300_000;
/// A jolt, in thousandths of a g, and tilts in degrees: a move's, and back again after a bump.
const JOLT_MG: f32 = 40.0;
const TILT_MOVE: f32 = 3.0;
const TILT_BACK: f32 = 2.0;
/// A bump's longest; still this long ends a move.
const BUMP_MS: u64 = 1000;
const QUIET_MS: u64 = 300;
const SETTLED_MS: u64 = 15_000;
/// What's marked as probably you.
const YOURS_MS: u64 = 60_000;
/// The events kept from the first, the last kept beside them.
const KEPT: usize = 128;

#[derive(Clone, Copy, PartialEq, Debug)]
#[repr(u8)]
enum Kind {
    Moved = 1,
    Pressed = 2,
    Menu = 3,
    Closed = 4,
    Wrong = 5,
    Locked = 6,
    PowerLost = 7,
}

impl Kind {
    fn from(b: u8) -> Option<Kind> {
        Some(match b {
            1 => Kind::Moved,
            2 => Kind::Pressed,
            3 => Kind::Menu,
            4 => Kind::Closed,
            5 => Kind::Wrong,
            6 => Kind::Locked,
            7 => Kind::PowerLost,
            _ => return None,
        })
    }
}

/// An event: when (ms after arming), how long, and for a move, the hardest jolt (mg), the most
/// tilt and the tilt it was left at (tenths of a degree); for presses, how many.
#[derive(Clone, Copy, PartialEq, Debug)]
struct Entry {
    kind: Kind,
    yours: bool,
    at: u32,
    length: u32,
    peak: u16,
    tilt: u16,
    left: u16,
}

impl Entry {
    fn bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0] = self.kind as u8;
        b[1] = self.yours as u8;
        b[2..6].copy_from_slice(&self.at.to_le_bytes());
        b[6..10].copy_from_slice(&self.length.to_le_bytes());
        b[10..12].copy_from_slice(&self.peak.to_le_bytes());
        b[12..14].copy_from_slice(&self.tilt.to_le_bytes());
        b[14..16].copy_from_slice(&self.left.to_le_bytes());
        b
    }

    fn from(b: &[u8]) -> Option<Entry> {
        let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        let u16_at = |i: usize| u16::from_le_bytes(b[i..i + 2].try_into().unwrap());
        Some(Entry {
            kind: Kind::from(b[0])?,
            yours: b[1] != 0,
            at: u32_at(2),
            length: u32_at(6),
            peak: u16_at(10),
            tilt: u16_at(12),
            left: u16_at(14),
        })
    }
}

/// The log: its events (the first `KEPT`, then only the last), how many there were, the bumps,
/// when it was armed (and by the clock), how long it's run, and whether it's armed still.
#[derive(Default)]
struct Log {
    events: Vec<Entry>,
    last: Option<Entry>,
    total: u32,
    bumps: u32,
    arm_unix: Option<u64>,
    alive: u32,
    armed: bool,
    /// the code, the sensitivity (1 normal, 0 low, 2 high), and maki's way down when armed
    code: Vec<u8>,
    sensitivity: u8,
    down: [f32; 3],
}

impl Log {
    fn push(&mut self, e: Entry) {
        self.total += 1;
        if self.events.len() < KEPT { self.events.push(e) } else { self.last = Some(e) }
    }

    fn all(&self) -> impl Iterator<Item = &Entry> { self.events.iter().chain(self.last.iter()) }

    fn save(&self) {
        let mut b = vec![self.armed as u8, self.sensitivity, self.code.len() as u8];
        b.extend_from_slice(&self.code);
        b.extend_from_slice(&self.arm_unix.unwrap_or(0).to_le_bytes());
        b.push(self.arm_unix.is_some() as u8);
        b.extend_from_slice(&self.alive.to_le_bytes());
        b.extend_from_slice(&self.total.to_le_bytes());
        b.extend_from_slice(&self.bumps.to_le_bytes());
        for d in self.down {
            b.extend_from_slice(&d.to_le_bytes());
        }
        b.push(self.last.is_some() as u8);
        for e in self.events.iter().chain(self.last.iter()) {
            b.extend_from_slice(&e.bytes());
        }
        let _ = storage::set("log", &b);
    }

    fn load() -> Log {
        let mut b = vec![0u8; 64 + (KEPT + 1) * 16];
        let fresh = || Log { sensitivity: 1, ..Default::default() };
        let Some(n) = storage::get("log", &mut b).filter(|&n| n <= b.len()) else { return fresh() };
        let b = &b[..n];
        let parse = || -> Option<Log> {
            let codes = *b.get(2)? as usize;
            let mut at = 3 + codes;
            let take = |at: &mut usize, n: usize| -> Option<&[u8]> {
                let s = b.get(*at..*at + n)?;
                *at += n;
                Some(s)
            };
            let code = b.get(3..3 + codes)?.to_vec();
            let unix = u64::from_le_bytes(take(&mut at, 8)?.try_into().ok()?);
            let has_unix = take(&mut at, 1)?[0] != 0;
            let alive = u32::from_le_bytes(take(&mut at, 4)?.try_into().ok()?);
            let total = u32::from_le_bytes(take(&mut at, 4)?.try_into().ok()?);
            let bumps = u32::from_le_bytes(take(&mut at, 4)?.try_into().ok()?);
            let mut down = [0f32; 3];
            for d in down.iter_mut() {
                *d = f32::from_le_bytes(take(&mut at, 4)?.try_into().ok()?);
            }
            let has_last = take(&mut at, 1)?[0] != 0;
            let mut events: Vec<Entry> = b[at..].chunks_exact(16).filter_map(Entry::from).collect();
            let last = if has_last { events.pop() } else { None };
            Some(Log {
                events,
                last,
                total,
                bumps,
                arm_unix: has_unix.then_some(unix),
                alive,
                armed: b[0] != 0,
                code,
                sensitivity: b[1].min(2),
                down,
            })
        };
        parse().unwrap_or_else(fresh)
    }

    /// The verdict: nothing, moved (how often), or interrupted.
    fn verdict(&self) -> String {
        let theirs = |k: Kind| self.all().filter(|e| e.kind == k && !e.yours).count();
        if theirs(Kind::Closed) + theirs(Kind::PowerLost) + theirs(Kind::Menu) > 0 {
            return "INTERRUPTED".into();
        }
        match theirs(Kind::Moved) {
            0 if theirs(Kind::Pressed) + theirs(Kind::Wrong) == 0 => "UNDISTURBED".into(),
            0 => "PRESSED".into(),
            1 => "MOVED".into(),
            n => format!("MOVED x{n}"),
        }
    }
}

/// A key as a code has it.
fn key_code(e: Event) -> Option<u8> {
    match e {
        Event::Up => Some(1),
        Event::Down => Some(2),
        Event::Left => Some(3),
        Event::Right => Some(4),
        Event::Centre => Some(5),
        _ => None,
    }
}

/// A move going on: when it started, the last activity, its hardest jolt, its most tilt.
#[derive(Clone, Copy)]
struct Moving {
    start: u64,
    last: u64,
    peak: f32,
    tilt: f32,
    /// a move, not (yet) only a bump
    real: bool,
}

/// What's on the screen.
#[derive(Clone, PartialEq)]
enum View {
    /// the log (or, empty, how it's used); the row at the top of the list
    Report(usize),
    /// setting the code: the first time through, and what's pressed
    SetCode(Option<Vec<u8>>),
    /// the code, to clear the log (false) or arm again over it (true)
    AskCode(bool),
    /// putting maki down: the countdown's end, and since when it's been still
    Counting(u64, Option<u64>),
    Armed,
}

struct App {
    log: Log,
    view: View,
    pressed: Vec<u8>,
    /// armed: when (millis), the readings smoothed slow and fast, a move going on, the presses in
    /// a try and when the last was, tries wrong, locked until, the last heartbeat
    armed_at: u64,
    slow: [f32; 3],
    fast: [f32; 3],
    /// the way down where maki last settled: bumps and moves are from there
    rest: [f32; 3],
    moving: Option<Moving>,
    /// this burst's presses, and when each was
    burst: Vec<(u8, u64)>,
    burst_start: u64,
    burst_last: u64,
    wrong: u32,
    locked_until: u64,
    beat: u64,
    note: String,
    note_until: u64,
}

fn len(v: [f32; 3]) -> f32 { (v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).sqrt() }

/// Degrees between two directions.
fn angle(a: [f32; 3], b: [f32; 3]) -> f32 {
    let d = (a[0] * b[0] + a[1] * b[1] + a[2] * b[2]) / (len(a) * len(b)).max(1e-6);
    d.clamp(-1.0, 1.0).acos().to_degrees()
}

fn smooth(was: [f32; 3], now: [f32; 3], tau: f32, dt: f32) -> [f32; 3] {
    let k = dt / (tau + dt);
    [was[0] + (now[0] - was[0]) * k, was[1] + (now[1] - was[1]) * k, was[2] + (now[2] - was[2]) * k]
}

fn read() -> Option<[f32; 3]> {
    let (x, y, z) = motion::read()?;
    Some([x as f32 / 1000.0, y as f32 / 1000.0, z as f32 / 1000.0])
}

impl App {
    fn say(&mut self, what: &str, now: u64) {
        self.note = what.into();
        self.note_until = now + 2500;
    }

    fn since_arming(&self, now: u64) -> u32 { now.saturating_sub(self.armed_at).min(u32::MAX as u64) as u32 }

    fn factor(&self) -> f32 { [2.0, 1.0, 0.5][self.log.sensitivity as usize] }

    fn arm(&mut self, now: u64) {
        let (code, sensitivity) = (std::mem::take(&mut self.log.code), self.log.sensitivity);
        self.log = Log { code, sensitivity, ..Default::default() };
        self.log.armed = true;
        self.log.arm_unix = unix_time();
        self.log.down = self.fast;
        self.rest = self.fast;
        self.armed_at = now;
        self.beat = now;
        self.slow = self.fast;
        self.moving = None;
        (self.burst, self.wrong, self.locked_until) = (vec![], 0, 0);
        self.view = View::Armed;
        self.log.save();
        screen::dark(true);
    }

    fn disarm(&mut self, now: u64) {
        self.end_move(now, true);
        // what happened in the minute before is probably you
        let since = self.since_arming(now).saturating_sub(YOURS_MS as u32);
        for e in self.log.events.iter_mut().chain(self.log.last.iter_mut()) {
            if e.at >= since {
                e.yours = true;
            }
        }
        self.log.alive = self.since_arming(now);
        self.log.armed = false;
        self.log.save();
        self.view = View::Report(0);
        screen::dark(false);
    }

    fn record(&mut self, kind: Kind, at: u64, length: u64, now: u64) {
        let e = Entry {
            kind,
            yours: false,
            at: self.since_arming(at),
            length: length.min(u32::MAX as u64) as u32,
            peak: 0,
            tilt: 0,
            left: 0,
        };
        self.log.push(e);
        self.log.alive = self.since_arming(now);
        self.log.save();
    }

    /// A move that's over goes in the log (or is counted, if it was only a bump).
    fn end_move(&mut self, now: u64, force: bool) {
        let Some(m) = self.moving else { return };
        let settled = now.saturating_sub(m.last) >= if m.real { SETTLED_MS } else { QUIET_MS };
        if !settled && !force {
            return;
        }
        self.moving = None;
        // a bump leaves maki as it was; a move may leave it anywhere, and it rests there now
        if !m.real && angle(self.fast, self.rest) < TILT_BACK * self.factor() {
            self.log.bumps += 1;
            return;
        }
        self.rest = self.fast;
        let left = angle(self.fast, self.log.down);
        let e = Entry {
            kind: Kind::Moved,
            yours: false,
            at: self.since_arming(m.start),
            length: m.last.saturating_sub(m.start) as u32,
            peak: (m.peak * 1000.0).min(u16::MAX as f32) as u16,
            tilt: (m.tilt * 10.0).min(u16::MAX as f32) as u16,
            left: (left * 10.0).min(u16::MAX as f32) as u16,
        };
        self.log.push(e);
        self.log.alive = self.since_arming(now);
        self.log.save();
    }

    /// A reading, armed.
    fn watch(&mut self, v: [f32; 3], dt: f32, now: u64) {
        self.slow = smooth(self.slow, v, 2.0, dt);
        self.fast = smooth(self.fast, v, 0.2, dt);
        let f = self.factor();
        // moving: jolted, or turning (its way down changing), wherever it's left
        let jolt = len([v[0] - self.slow[0], v[1] - self.slow[1], v[2] - self.slow[2]]);
        let turning = angle(self.fast, self.slow) > TILT_MOVE * f;
        let tilt = angle(self.fast, self.rest);
        let active = jolt * 1000.0 > JOLT_MG * f || turning;
        if active {
            let m = self.moving.get_or_insert(Moving {
                start: now,
                last: now,
                peak: 0.0,
                tilt: 0.0,
                real: false,
            });
            m.last = now;
            m.peak = m.peak.max(jolt);
            m.tilt = m.tilt.max(tilt);
            if now.saturating_sub(m.start) >= BUMP_MS || tilt > TILT_MOVE * f {
                m.real = true;
            }
        } else {
            self.end_move(now, false);
        }
        if now >= self.beat + HEARTBEAT_MS {
            self.beat = now;
            self.log.alive = self.since_arming(now);
            self.log.save();
        }
    }

    /// A press, armed: logged, and from the code's length on, a try of the last five presses,
    /// right or wrong. Locked out, it's only logged.
    fn press(&mut self, key: u8, now: u64) {
        if !self.burst.is_empty() && now.saturating_sub(self.burst_last) > TRY_GAP_MS {
            self.end_burst();
        }
        if self.burst.is_empty() {
            self.burst_start = now;
        }
        self.burst.push((key, now));
        self.burst_last = now;
        if self.burst.len() < CODE_LEN || now < self.locked_until {
            return;
        }
        let tried = &self.burst[self.burst.len() - CODE_LEN..];
        if tried.iter().map(|&(k, _)| k).eq(self.log.code.iter().copied()) {
            // the code's presses are yours; any before them in the burst aren't
            let code_start = tried[0].1;
            let before = self.burst.len() - CODE_LEN;
            if before > 0 {
                self.log.push(Entry {
                    kind: Kind::Pressed,
                    yours: false,
                    at: self.since_arming(self.burst_start),
                    length: code_start.saturating_sub(self.burst_start) as u32,
                    peak: before as u16,
                    tilt: 0,
                    left: 0,
                });
            }
            self.burst.clear();
            self.log.push(Entry {
                kind: Kind::Pressed,
                yours: true,
                at: self.since_arming(code_start),
                length: now.saturating_sub(code_start) as u32,
                peak: CODE_LEN as u16,
                tilt: 0,
                left: 0,
            });
            self.disarm(now);
            return;
        }
        self.wrong += 1;
        self.record(Kind::Wrong, now, 0, now);
        if self.wrong >= TRIES {
            self.wrong = 0;
            self.locked_until = now + LOCKOUT_MS;
            self.record(Kind::Locked, now, LOCKOUT_MS, now);
        }
    }

    /// A burst of presses over: they go in the log as one (each try in it was counted as it was
    /// made).
    fn end_burst(&mut self) {
        if self.burst.is_empty() {
            return;
        }
        let (start, n) = (self.burst_start, self.burst.len());
        self.burst.clear();
        let e = Entry {
            kind: Kind::Pressed,
            yours: false,
            at: self.since_arming(start),
            length: self.burst_last.saturating_sub(start) as u32,
            peak: n as u16,
            tilt: 0,
            left: 0,
        };
        self.log.push(e);
        self.log.save();
    }
}

/// A time after arming: +42s, +12m, +2h13.
fn after(ms: u32, out: &mut String) {
    let s = ms / 1000;
    let _ = match s {
        0..60 => write!(out, "+{s}s"),
        60..3600 => write!(out, "+{}m", s / 60),
        _ => write!(out, "+{}h{:02}", s / 3600, s / 60 % 60),
    };
}

fn describe(e: &Entry) -> String {
    let mut s = String::new();
    after(e.at, &mut s);
    s.push(' ');
    let _ = match e.kind {
        Kind::Moved if e.left >= 30 => write!(s, "moved {}s, left {}°", e.length.div_ceil(1000), e.left / 10),
        Kind::Moved => write!(s, "moved {}s", e.length.div_ceil(1000).max(1)),
        Kind::Pressed => write!(s, "{} press{}", e.peak, if e.peak == 1 { "" } else { "es" }),
        Kind::Menu => write!(s, "maki's menu"),
        Kind::Closed => write!(s, "app closed"),
        Kind::Wrong => write!(s, "wrong code"),
        Kind::Locked => write!(s, "code locked"),
        Kind::PowerLost => write!(s, "lost power"),
    };
    if e.yours {
        s.push_str(" (you?)");
    }
    s
}

fn draw(app: &App, now: u64) {
    screen::clear(Color::Dark);
    let note = (now < app.note_until).then_some(app.note.as_str());
    match &app.view {
        View::Armed => {}
        View::Report(top) => {
            let log = &app.log;
            if log.total == 0 && log.alive == 0 {
                screen::text_centred(4, "Tamper Log", Style::Bold, Color::Light);
                for (i, line) in
                    ["Leave maki on your", "laptop: armed, it's", "dark and logs every", "move and press."]
                        .iter()
                        .enumerate()
                {
                    screen::text_centred(24 + i as i32 * 13, line, Style::Small, Color::Light);
                }
            } else {
                screen::text_centred(0, &log.verdict(), Style::Bold, Color::Light);
                let mut s = String::new();
                let _ = write!(s, "armed ");
                after(log.alive, &mut s);
                let _ = write!(s, ", {} bump{}", log.bumps, if log.bumps == 1 { "" } else { "s" });
                screen::text_centred(16, &s, Style::Small, Color::Light);
                // the timeline: arming to now, a tick each event, taller for moves
                let span = log.alive.max(1) as i64;
                screen::line(4, 36, WIDTH - 5, 36, Color::Light);
                for e in log.all() {
                    let x = 4 + (e.at as i64 * (WIDTH as i64 - 9) / span) as i32;
                    let h = if e.kind == Kind::Moved { 6 } else { 3 };
                    screen::line(x, 36 - h, x, 36 + h, Color::Light);
                }
                let mut events: Vec<&Entry> = log.all().collect();
                events.sort_by_key(|e| e.at);
                for (row, e) in events.iter().skip(*top).take(4).enumerate() {
                    screen::text(2, 45 + row as i32 * 12, &describe(e), Style::Small, Color::Light);
                }
                if log.total as usize > events.len() {
                    let mut s = String::new();
                    let _ = write!(s, "{} more between", log.total as usize - events.len());
                    screen::text(2, 86, &s, Style::Small, Color::Light);
                }
            }
            screen::line(0, 97, WIDTH - 1, 97, Color::Light);
            let foot =
                note.unwrap_or(if log_empty(log) { "centre: arm" } else { "centre: arm   dial: scroll" });
            screen::text_centred(99, foot, Style::Small, Color::Light);
        }
        View::SetCode(first) => {
            screen::text_centred(
                4,
                if first.is_some() { "Again" } else { "Your code" },
                Style::Bold,
                Color::Light,
            );
            screen::text_centred(24, "five presses: the dial,", Style::Small, Color::Light);
            screen::text_centred(36, "left, right, the centre", Style::Small, Color::Light);
            dots(app.pressed.len(), 60);
            screen::line(0, 97, WIDTH - 1, 97, Color::Light);
            screen::text_centred(99, note.unwrap_or("to disarm it, on the dark"), Style::Small, Color::Light);
        }
        View::AskCode(arm) => {
            screen::text_centred(4, "Your code", Style::Bold, Color::Light);
            screen::text_centred(
                24,
                if *arm { "to arm again over this" } else { "to clear the log" },
                Style::Small,
                Color::Light,
            );
            dots(app.pressed.len(), 60);
            screen::line(0, 97, WIDTH - 1, 97, Color::Light);
            screen::text_centred(99, note.unwrap_or(""), Style::Small, Color::Light);
        }
        View::Counting(until, _) => {
            let left = until.saturating_sub(now).div_ceil(1000);
            let mut n = Buf::<4>::new();
            let _ = write!(n, "{left}");
            let (w, _) = screen::segments_size(n.as_str(), 44, screen::Toward::Bottom);
            if left > 0 {
                screen::segments((WIDTH - w) / 2, 8, n.as_str(), 44, screen::Toward::Bottom, Color::Light);
                screen::text_centred(62, "put maki down", Style::Regular, Color::Light);
            } else {
                screen::text_centred(30, "keep it still", Style::Bold, Color::Light);
            }
            screen::text_centred(80, "it arms once still", Style::Small, Color::Light);
            screen::line(0, 97, WIDTH - 1, 97, Color::Light);
            screen::text_centred(99, "centre: not now", Style::Small, Color::Light);
        }
    }
    screen::present();
}

fn log_empty(log: &Log) -> bool { log.total == 0 && log.alive == 0 }

/// A code's presses so far, as dots.
fn dots(n: usize, y: i32) {
    let x0 = (WIDTH - (CODE_LEN as i32 * 16 - 6)) / 2;
    for i in 0..CODE_LEN as i32 {
        let x = x0 + i * 16;
        if (i as usize) < n {
            screen::fill_rect(x, y, 10, 10, Color::Light);
        } else {
            screen::rect(x, y, 10, 10, Color::Light);
        }
    }
}

fn set_menu(app: &App) {
    let s = ["Sensitivity: low", "Sensitivity: normal", "Sensitivity: high"][app.log.sensitivity as usize];
    let _ = menu(&["Clear the log", "New code", s]);
}

fn main() {
    let mut app = App {
        log: Log::load(),
        view: View::Report(0),
        pressed: vec![],
        armed_at: 0,
        slow: [0.0, 0.0, 1.0],
        fast: [0.0, 0.0, 1.0],
        rest: [0.0, 0.0, 1.0],
        moving: None,
        burst: vec![],
        burst_start: 0,
        burst_last: 0,
        wrong: 0,
        locked_until: 0,
        beat: 0,
        note: String::new(),
        note_until: 0,
    };
    set_menu(&app);
    if app.log.armed {
        // armed when last it ran: it stopped without its code, the power lost or the app closed
        let last_closed = app.log.all().last().is_some_and(|e| e.kind == Kind::Closed);
        if !last_closed {
            let e = Entry {
                kind: Kind::PowerLost,
                yours: false,
                at: app.log.alive,
                length: HEARTBEAT_MS as u32,
                peak: 0,
                tilt: 0,
                left: 0,
            };
            app.log.push(e);
        }
        app.log.armed = false;
        app.log.save();
    }
    if let Some(v) = read() {
        (app.slow, app.fast) = (v, v);
    }
    let mut last = millis();
    loop {
        let now = millis();
        if app.view != View::Armed {
            draw(&app, now);
        }
        let wake = match app.view {
            View::Armed | View::Counting(..) => Some(READ_MS),
            _ if now < app.note_until => Some((app.note_until - now) as u32),
            _ => None,
        };
        let event = wait(wake);
        let now = millis();
        let dt = (now.saturating_sub(last) as f32 / 1000.0).clamp(0.001, 0.5);
        last = now;
        if matches!(app.view, View::Armed | View::Counting(..)) {
            if let Some(v) = read() {
                if app.view == View::Armed {
                    app.watch(v, dt, now);
                } else {
                    app.fast = smooth(app.fast, v, 0.2, dt);
                    app.slow = smooth(app.slow, v, 2.0, dt);
                }
            }
        }
        match app.view.clone() {
            View::Armed => match event {
                Event::Hidden => {
                    app.end_burst();
                    app.record(Kind::Menu, now, 0, now);
                }
                Event::Exit => {
                    app.end_move(now, true);
                    app.end_burst();
                    app.record(Kind::Closed, now, 0, now);
                    return;
                }
                e => {
                    if let Some(k) = key_code(e) {
                        app.press(k, now);
                    } else if !app.burst.is_empty() && now.saturating_sub(app.burst_last) > TRY_GAP_MS {
                        app.end_burst();
                    }
                }
            },
            View::Counting(until, still) => match event {
                Event::Centre | Event::Menu(_) => app.view = View::Report(0),
                Event::Exit => return,
                _ if now >= until => {
                    // armed once it's been still a while
                    let moving = len([
                        app.fast[0] - app.slow[0],
                        app.fast[1] - app.slow[1],
                        app.fast[2] - app.slow[2],
                    ]) > 0.02;
                    match still {
                        _ if moving => app.view = View::Counting(until, None),
                        Some(t) if now >= t + SETTLE_MS => app.arm(now),
                        None => app.view = View::Counting(until, Some(now)),
                        _ => {}
                    }
                }
                _ => {}
            },
            View::SetCode(first) => match event {
                Event::Exit => return,
                Event::Menu(_) => {
                    app.pressed.clear();
                    app.view = View::Report(0);
                }
                e => {
                    let Some(k) = key_code(e) else { continue };
                    app.pressed.push(k);
                    if app.pressed.len() == CODE_LEN {
                        let code = std::mem::take(&mut app.pressed);
                        match first {
                            None => app.view = View::SetCode(Some(code)),
                            Some(f) if f == code => {
                                app.log.code = code;
                                app.log.save();
                                app.view = View::Counting(now + COUNTDOWN_MS, None);
                            }
                            Some(_) => {
                                app.view = View::SetCode(None);
                                app.say("not the same: again", now);
                            }
                        }
                    }
                }
            },
            View::AskCode(arm) => match event {
                Event::Exit => return,
                Event::Menu(_) => {
                    app.pressed.clear();
                    app.view = View::Report(0);
                }
                e => {
                    let Some(k) = key_code(e) else { continue };
                    app.pressed.push(k);
                    if app.pressed.len() == CODE_LEN {
                        let right = app.pressed == app.log.code;
                        app.pressed.clear();
                        if !right {
                            app.view = View::Report(0);
                            app.say("not the code", now);
                        } else if arm {
                            app.view = View::Counting(now + COUNTDOWN_MS, None);
                        } else {
                            let (code, sensitivity) =
                                (std::mem::take(&mut app.log.code), app.log.sensitivity);
                            app.log = Log { code, sensitivity, ..Default::default() };
                            app.log.save();
                            app.view = View::Report(0);
                            app.say("cleared", now);
                        }
                    }
                }
            },
            View::Report(top) => match event {
                Event::Centre if app.log.code.len() != CODE_LEN => app.view = View::SetCode(None),
                Event::Centre if log_empty(&app.log) => app.view = View::Counting(now + COUNTDOWN_MS, None),
                Event::Centre => app.view = View::AskCode(true),
                Event::Down => {
                    let n = app.log.all().count();
                    app.view = View::Report((top + 1).min(n.saturating_sub(4)));
                }
                Event::Up => app.view = View::Report(top.saturating_sub(1)),
                Event::Menu(0) if !log_empty(&app.log) => app.view = View::AskCode(false),
                Event::Menu(0) => app.say("nothing to clear", now),
                Event::Menu(1) if app.log.code.len() == CODE_LEN && !log_empty(&app.log) => {
                    app.say("clear the log first", now)
                }
                Event::Menu(1) => {
                    app.log.code.clear();
                    app.view = View::SetCode(None);
                }
                Event::Menu(2) => {
                    app.log.sensitivity = (app.log.sensitivity + 1) % 3;
                    app.log.save();
                    set_menu(&app);
                }
                Event::Exit => return,
                _ => {}
            },
        }
    }
}

maki_app::main!(main);
