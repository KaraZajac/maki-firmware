//! A focus timer. A filled circle shrinks to a dot while you focus; when it's gone the screen
//! flashes until the centre starts a break, and the dot grows back into the circle while you
//! rest. Then it flashes again, and the centre starts the next focus.
//!
//! Before the first focus, left and right set how long it is. Every fourth break is three
//! times as long. The centre pauses, and the menu skips ahead, starts over or changes the
//! breaks. Leaving the app doesn't stop the timer when maki knows the time: it picks up where
//! it would be when opened again.

#![no_std]

use core::fmt::Write;

use maki_app::*;

/// The circle: its centre, how big it is when whole, and the dot it shrinks to.
const CX: i32 = WIDTH / 2;
const CY: i32 = 49;
const FULL: i32 = 42;
const DOT: i32 = 2;
/// A quarter of the ring of 60 marks around it, from the top, a little outside the whole
/// circle; the other quarters are this one turned.
const RING: [(i32, i32); 15] = [
    (0, -47), (5, -47), (10, -46), (15, -45), (19, -43), (23, -41), (28, -38), (31, -35),
    (35, -31), (38, -28), (41, -24), (43, -19), (45, -15), (46, -10), (47, -5),
];
/// The line of text under it.
const LINE: i32 = HEIGHT - 12;

/// A minute, in maki's milliseconds.
const MINUTE: u64 = 60_000;
/// Minutes: a focus, set in steps before it starts; a break, one of these from the menu.
const FOCUS: u32 = 25;
const FOCUS_STEP: u32 = 5;
const FOCUS_MAX: u32 = 90;
const BREAKS: [u32; 3] = [5, 10, 3];
/// Focuses to a set, after which the break is `LONG` times as long.
const SET: u32 = 4;
const LONG: u32 = 3;

/// How the screen flashes when time's up: on and off for a minute, then a blink now and
/// then until the centre is pressed.
const FLASH: u64 = 500;
const FLASHING: u64 = 60_000;
const BLINK: u64 = 4_000;
const BLINK_ON: u64 = 300;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Focus,
    Break,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    /// Before a focus: the whole circle.
    Ready,
    /// Counting down to `ends` (maki's milliseconds), `total` long.
    Running { phase: Phase, ends: u64, total: u64 },
    Paused { phase: Phase, left: u64, total: u64 },
    /// Over since `since`: flashing until the centre.
    Over { phase: Phase, since: u64 },
}

struct Timer {
    state: State,
    /// Minutes.
    focus: u32,
    rest: u32,
    /// Focuses finished in this set.
    done: u32,
}

/// What's on the screen, to draw again only when it changes.
#[derive(PartialEq, Eq)]
struct Look {
    radius: i32,
    light: bool,
    ready: bool,
    paused: bool,
    done: u32,
    line: [u8; 24],
}

fn isqrt(n: i32) -> i32 {
    if n <= 0 {
        return 0;
    }
    let (mut x, mut y) = (n, (n + 1) / 2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// A filled circle: the rows of pixels within `r` and a half of the centre.
fn disc(r: i32, color: Color) {
    for dy in -r..=r {
        let dx = isqrt(r * r + r - dy * dy);
        screen::fill_rect(CX - dx, CY + dy, 2 * dx + 1, 1, color);
    }
}

fn ring(color: Color) {
    for turn in 0..4 {
        for &(x, y) in &RING {
            let (x, y) = match turn {
                0 => (x, y),
                1 => (-y, x),
                2 => (-x, -y),
                _ => (y, -x),
            };
            screen::pixel(CX + x, CY + y, color);
        }
    }
}

fn minutes(ms: u64) -> u64 { ms.div_ceil(MINUTE) }

impl Timer {
    fn restore(now: u64) -> Timer {
        let rest = storage::get_u32("rest", BREAKS[0]);
        let mut t = Timer {
            state: State::Ready,
            focus: storage::get_u32("focus", FOCUS).clamp(FOCUS_STEP, FOCUS_MAX),
            rest: if BREAKS.contains(&rest) { rest } else { BREAKS[0] },
            done: 0,
        };
        // the timer as it was left: [what, phase, focuses done, 0], then two numbers
        let mut b = [0u8; 20];
        if storage::get("timer", &mut b) != Some(b.len()) {
            return t;
        }
        let number = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        let phase = if b[1] == 1 { Phase::Break } else { Phase::Focus };
        t.done = (b[2] as u32).min(SET);
        let (a, total) = (number(4), number(12));
        t.state = match b[0] {
            // running until `a`, in milliseconds since 1970
            1 => match unix_time() {
                Some(unix) if a > unix * 1000 && a - unix * 1000 <= total => {
                    State::Running { phase, ends: now + (a - unix * 1000), total }
                }
                Some(_) => State::Over { phase, since: now },
                None => State::Paused { phase, left: total, total },
            },
            2 if a <= total => State::Paused { phase, left: a, total },
            3 => State::Over { phase, since: now },
            _ => State::Ready,
        };
        t
    }

    fn save(&self, now: u64) {
        let mut b = [0u8; 20];
        let (what, phase, a, total) = match self.state {
            State::Ready => (0, Phase::Focus, 0, 0),
            State::Running { phase, ends, total } => {
                let left = ends.saturating_sub(now);
                match unix_time() {
                    Some(unix) => (1, phase, unix * 1000 + left, total),
                    // without the time, it can only wait where it is
                    None => (2, phase, left, total),
                }
            }
            State::Paused { phase, left, total } => (2, phase, left, total),
            State::Over { phase, .. } => (3, phase, 0, 0),
        };
        b[0] = what;
        b[1] = (phase == Phase::Break) as u8;
        b[2] = self.done as u8;
        b[4..12].copy_from_slice(&a.to_le_bytes());
        b[12..20].copy_from_slice(&total.to_le_bytes());
        let _ = storage::set("timer", &b);
    }

    fn start(&mut self, phase: Phase, now: u64) {
        let minutes = match phase {
            Phase::Focus => self.focus,
            Phase::Break if self.done >= SET => self.rest * LONG,
            Phase::Break => self.rest,
        };
        let total = minutes as u64 * MINUTE;
        self.state = State::Running { phase, ends: now + total, total };
    }

    /// Ends what has run out.
    fn tick(&mut self, now: u64) {
        if let State::Running { phase, ends, .. } = self.state {
            if now >= ends {
                if phase == Phase::Focus {
                    self.done += 1;
                }
                self.state = State::Over { phase, since: now };
            }
        }
    }

    fn centre(&mut self, now: u64) {
        self.state = match self.state {
            State::Ready => return self.start(Phase::Focus, now),
            State::Running { phase, ends, total } => State::Paused { phase, left: ends.saturating_sub(now), total },
            State::Paused { phase, left, total } => State::Running { phase, ends: now + left, total },
            State::Over { phase: Phase::Focus, .. } => return self.start(Phase::Break, now),
            State::Over { phase: Phase::Break, .. } => return self.next_focus(now),
        };
    }

    fn next_focus(&mut self, now: u64) {
        if self.done >= SET {
            self.done = 0;
        }
        self.start(Phase::Focus, now)
    }

    /// Left and right, before a focus: how long it is.
    fn nudge(&mut self, longer: bool) {
        if self.state != State::Ready {
            return;
        }
        self.focus = if longer { self.focus + FOCUS_STEP } else { self.focus - FOCUS_STEP }.clamp(FOCUS_STEP, FOCUS_MAX);
        let _ = storage::set_u32("focus", self.focus);
    }

    fn menu(&self) {
        let mut rest = Buf::<24>::new();
        let _ = write!(rest, "Breaks: {} min", self.rest);
        let _ = menu(&["Skip ahead", "Start over", rest.as_str()]);
    }

    fn picked(&mut self, item: u32, now: u64) {
        match item {
            // on to what comes next, without counting what was skipped
            0 => match self.state {
                State::Ready => {}
                State::Running { phase: Phase::Focus, .. } | State::Paused { phase: Phase::Focus, .. } => {
                    self.start(Phase::Break, now)
                }
                State::Running { phase: Phase::Break, .. } | State::Paused { phase: Phase::Break, .. } => {
                    self.next_focus(now)
                }
                State::Over { .. } => self.centre(now),
            },
            1 => {
                self.state = State::Ready;
                self.done = 0;
            }
            2 => {
                let at = BREAKS.iter().position(|&b| b == self.rest).unwrap_or(0);
                self.rest = BREAKS[(at + 1) % BREAKS.len()];
                let _ = storage::set_u32("rest", self.rest);
                self.menu();
            }
            _ => {}
        }
    }

    /// How long to wait before something on the screen changes.
    fn wake(&self, now: u64) -> Option<u32> {
        match self.state {
            State::Ready | State::Paused { .. } => None,
            // each second, for the seconds of the last minute and the circle
            State::Running { ends, .. } => {
                let left = ends.saturating_sub(now);
                Some(match left % 1000 {
                    0 => left.min(1000),
                    part => part,
                } as u32)
            }
            State::Over { since, .. } => {
                let t = now - since;
                Some(if t < FLASHING {
                    FLASH - t % FLASH
                } else {
                    let p = (t - FLASHING) % BLINK;
                    if p < BLINK_ON { BLINK_ON - p } else { BLINK - p }
                } as u32)
            }
        }
    }

    fn look(&self, now: u64) -> Look {
        let span = (FULL - DOT) as u64;
        let mut line = Buf::<24>::new();
        let (radius, light, paused) = match self.state {
            State::Ready => {
                let _ = write!(line, "focus {} min", self.focus);
                (FULL, false, false)
            }
            State::Running { phase, ends, total } | State::Paused { phase, left: ends, total } => {
                let paused = matches!(self.state, State::Paused { .. });
                let left = if paused { ends } else { ends.saturating_sub(now) };
                let word = match (paused, phase) {
                    (true, _) => "paused",
                    (false, Phase::Focus) => "focus",
                    (false, Phase::Break) => "break",
                };
                if left < MINUTE {
                    let _ = write!(line, "{word} {} s", left.div_ceil(1000));
                } else {
                    let _ = write!(line, "{word} {} min", minutes(left));
                }
                let total = total.max(1);
                let radius = match phase {
                    // shrinks as it runs out, and is a dot only once it has
                    Phase::Focus => DOT + (span * left).div_ceil(total) as i32,
                    Phase::Break => FULL - (span * left).div_ceil(total) as i32,
                };
                (radius, false, paused)
            }
            State::Over { phase, since } => {
                let t = now - since;
                let light = if t < FLASHING { t / FLASH % 2 == 0 } else { (t - FLASHING) % BLINK < BLINK_ON };
                let _ = write!(line, "{}", if phase == Phase::Focus { "time for a break" } else { "back to it" });
                (if phase == Phase::Focus { DOT } else { FULL }, light, false)
            }
        };
        let mut bytes = [0u8; 24];
        bytes[..line.len()].copy_from_slice(line.as_str().as_bytes());
        Look { radius, light, ready: self.state == State::Ready, paused, done: self.done, line: bytes }
    }
}

fn draw(look: &Look) {
    let (back, fore) = if look.light { (Color::Light, Color::Dark) } else { (Color::Dark, Color::Light) };
    screen::clear(back);
    ring(fore);
    disc(look.radius, fore);
    if look.paused && look.radius >= 10 {
        // two bars cut out of the circle
        let h = look.radius;
        screen::fill_rect(CX - h / 3 - 1, CY - h / 2, h / 4 + 1, h, back);
        screen::fill_rect(CX + h / 3 - h / 4, CY - h / 2, h / 4 + 1, h, back);
    }
    if look.ready {
        // a triangle cut out of it: the centre starts
        let (h, w) = (FULL / 3, FULL * 2 / 3);
        for dy in -h..=h {
            screen::fill_rect(CX - w / 3, CY + dy, w * (h - dy.abs()) / h, 1, back);
        }
    }
    let len = look.line.iter().position(|&b| b == 0).unwrap_or(look.line.len());
    let line = core::str::from_utf8(&look.line[..len]).unwrap_or("");
    screen::text(2, LINE, line, Style::Small, fore);
    // this set's focuses, done and to go
    for i in 0..SET as i32 {
        let x = WIDTH - 2 - (SET as i32 - i) * 7 + 2;
        if (i as u32) < look.done {
            screen::fill_rect(x, LINE + 4, 5, 5, fore);
        } else {
            screen::rect(x, LINE + 4, 5, 5, fore);
        }
    }
    screen::present();
}

fn main() {
    let mut timer = Timer::restore(millis());
    timer.menu();
    let mut shown: Option<Look> = None;
    let mut hidden = false;
    loop {
        let now = millis();
        timer.tick(now);
        if !hidden {
            let look = timer.look(now);
            if shown.as_ref() != Some(&look) {
                draw(&look);
                shown = Some(look);
            }
        }
        let event = wait(timer.wake(now));
        let now = millis();
        match event {
            Event::Centre => timer.centre(now),
            Event::Left => timer.nudge(false),
            Event::Right => timer.nudge(true),
            Event::Menu(item) => timer.picked(item, now),
            Event::Hidden => hidden = true,
            Event::Shown => {
                hidden = false;
                shown = None;
            }
            Event::Exit => {
                timer.save(now);
                return;
            }
            _ => {}
        }
    }
}

maki_app::main!(main);
