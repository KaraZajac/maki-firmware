//! A focus timer, as a pie: whole when a focus starts, it empties clockwise like a clock's hand
//! sweeping round until nothing's left. Then the screen flashes until the centre starts a break,
//! and over the break the pie fills back up, clockwise, until it's whole again; it flashes, and
//! the centre starts the next focus. Nothing else is on the screen while it runs.
//!
//! Before a focus its minutes show on the pie, and left and right set them. The centre pauses
//! (two bars on the pie). Every fourth break is three times as long. The menu skips ahead,
//! starts over or changes the breaks. Leaving the app doesn't stop the timer when maki knows the
//! time: it picks up where it would be when opened again.

#![no_std]

use core::fmt::Write;

use maki_app::*;

/// The pie: its centre and radius, and the twelve marks round it, like a clock's.
const CX: i32 = WIDTH / 2;
const CY: i32 = HEIGHT / 2;
const R: i32 = 45;
const MARKS: i32 = R + 5;
/// A turn, in the steps the pie moves by: half a degree each.
const TURN: i32 = 720;
/// sin of 0, 0.5, 1, ... 90 degrees, times 4096.
const SIN: [i32; 181] = [
    0, 36, 71, 107, 143, 179, 214, 250, 286, 321, 357, 393, 428, 464, 499, 535, 570, 605, 641, 676, 711, 746,
    782, 817, 852, 887, 921, 956, 991, 1026, 1060, 1095, 1129, 1163, 1198, 1232, 1266, 1300, 1334, 1367,
    1401, 1434, 1468, 1501, 1534, 1567, 1600, 1633, 1666, 1699, 1731, 1763, 1796, 1828, 1860, 1891, 1923,
    1954, 1986, 2017, 2048, 2079, 2110, 2140, 2171, 2201, 2231, 2261, 2290, 2320, 2349, 2379, 2408, 2436,
    2465, 2493, 2522, 2550, 2578, 2605, 2633, 2660, 2687, 2714, 2741, 2767, 2793, 2820, 2845, 2871, 2896,
    2921, 2946, 2971, 2996, 3020, 3044, 3068, 3091, 3115, 3138, 3161, 3183, 3206, 3228, 3250, 3271, 3293,
    3314, 3335, 3355, 3376, 3396, 3416, 3435, 3455, 3474, 3492, 3511, 3529, 3547, 3565, 3582, 3600, 3617,
    3633, 3650, 3666, 3681, 3697, 3712, 3727, 3742, 3756, 3770, 3784, 3798, 3811, 3824, 3837, 3849, 3861,
    3873, 3884, 3896, 3906, 3917, 3927, 3937, 3947, 3956, 3966, 3974, 3983, 3991, 3999, 4006, 4014, 4021,
    4027, 4034, 4040, 4046, 4051, 4056, 4061, 4065, 4070, 4074, 4077, 4080, 4083, 4086, 4088, 4090, 4092,
    4094, 4095, 4095, 4096, 4096,
];

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
    Running {
        phase: Phase,
        ends: u64,
        total: u64,
    },
    Paused {
        phase: Phase,
        left: u64,
        total: u64,
    },
    /// Over since `since`: flashing until the centre.
    Over {
        phase: Phase,
        since: u64,
    },
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
    /// How much of the pie there is: `TURN` whole, 0 none.
    pie: i32,
    /// Where it starts: at twelve o'clock (a break filling it), or at its edge, which sweeps
    /// round to twelve as a focus empties it.
    from_top: bool,
    /// Flashing: light, the pie dark.
    light: bool,
    /// Before a focus: its minutes, on the pie.
    ready: Option<u32>,
    paused: bool,
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

/// A direction `step`s clockwise from straight up, as (x, y) on the screen (y down), x4096.
fn hand(step: i32) -> (i32, i32) {
    let s = step.rem_euclid(TURN);
    let (quarter, r) = (s / 180, (s % 180) as usize);
    let (sin, cos) = (SIN[r], SIN[180 - r]);
    match quarter {
        0 => (sin, -cos),
        1 => (cos, sin),
        2 => (-sin, cos),
        _ => (-cos, -sin),
    }
}

/// Whether (x, y), from the centre, is less far round clockwise from straight up than `step`.
/// No angles: which half it's in, and which side of the hand, by their cross product.
fn before(x: i32, y: i32, step: i32) -> bool {
    if step <= 0 {
        return false;
    }
    if step >= TURN {
        return true;
    }
    let (hx, hy) = hand(step);
    let right = x > 0 || (x == 0 && y < 0);
    // the hand is less than half a turn clockwise of the point
    let ahead = x * hy - y * hx > 0;
    if step <= TURN / 2 { right && ahead } else { right || ahead }
}

/// The pie, a row at a time: `pie` steps of it, from twelve o'clock or ending there.
fn pie(pie: i32, from_top: bool, color: Color) {
    for dy in -R..=R {
        let w = isqrt(R * R + R - dy * dy);
        let mut run: Option<i32> = None;
        for dx in -w..=w + 1 {
            let inside = dx <= w && if from_top { before(dx, dy, pie) } else { !before(dx, dy, TURN - pie) };
            match (inside, run) {
                (true, None) => run = Some(dx),
                (false, Some(start)) => {
                    screen::fill_rect(CX + start, CY + dy, dx - start, 1, color);
                    run = None;
                }
                _ => {}
            }
        }
    }
}

/// The pie's edge, a pixel wide, so it shows when there's little or none of it.
fn edge(color: Color) {
    let (mut x, mut y, mut d) = (R, 0, 1 - R);
    while x >= y {
        for (px, py) in [(x, y), (y, x), (-y, x), (-x, y), (-x, -y), (-y, -x), (y, -x), (x, -y)] {
            screen::pixel(CX + px, CY + py, color);
        }
        y += 1;
        if d < 0 {
            d += 2 * y + 1;
        } else {
            x -= 1;
            d += 2 * (y - x) + 1;
        }
    }
}

/// Twelve marks round it, as a clock has: dots, a little bigger at twelve, three, six and nine.
fn marks(color: Color) {
    for hour in 0..12 {
        let (hx, hy) = hand(hour * TURN / 12);
        let (x, y) = (CX + (hx * MARKS + 2048).div_euclid(4096), CY + (hy * MARKS + 2048).div_euclid(4096));
        let big = hour % 3 == 0;
        screen::fill_rect(x - big as i32, y - big as i32, 2 + big as i32, 2 + big as i32, color);
    }
}

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
            State::Running { phase, ends, total } => {
                State::Paused { phase, left: ends.saturating_sub(now), total }
            }
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
        self.focus = if longer { self.focus + FOCUS_STEP } else { self.focus - FOCUS_STEP }
            .clamp(FOCUS_STEP, FOCUS_MAX);
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
            0 => {
                match self.state {
                    State::Ready => {}
                    State::Running { phase: Phase::Focus, .. }
                    | State::Paused { phase: Phase::Focus, .. } => self.start(Phase::Break, now),
                    State::Running { phase: Phase::Break, .. }
                    | State::Paused { phase: Phase::Break, .. } => self.next_focus(now),
                    State::Over { .. } => self.centre(now),
                }
            }
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
            // when the pie next moves a step (or it's over)
            State::Running { ends, total, .. } => {
                let (total, left) = (total.max(1), ends.saturating_sub(now));
                let gone = total - left.min(total);
                let next = (gone * TURN as u64 / total + 1) * total;
                Some((next.div_ceil(TURN as u64) - gone).clamp(1, left.max(1)) as u32)
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
        let plain = Look { pie: TURN, from_top: true, light: false, ready: None, paused: false };
        match self.state {
            State::Ready => Look { ready: Some(self.focus), ..plain },
            State::Running { phase, ends, total } | State::Paused { phase, left: ends, total } => {
                let paused = matches!(self.state, State::Paused { .. });
                let (total, left) = (total.max(1), if paused { ends } else { ends.saturating_sub(now) });
                let gone = (total - left.min(total)) * TURN as u64 / total;
                match phase {
                    // what's left of it, its edge sweeping round to twelve
                    Phase::Focus => Look { pie: TURN - gone as i32, from_top: false, paused, ..plain },
                    // what's gone by, from twelve
                    Phase::Break => Look { pie: gone as i32, paused, ..plain },
                }
            }
            State::Over { phase, since } => {
                let t = now - since;
                let light = if t < FLASHING {
                    (t / FLASH).is_multiple_of(2)
                } else {
                    (t - FLASHING) % BLINK < BLINK_ON
                };
                Look { pie: if phase == Phase::Focus { 0 } else { TURN }, light, ..plain }
            }
        }
    }
}

fn draw(look: &Look) {
    let (back, fore) = if look.light { (Color::Light, Color::Dark) } else { (Color::Dark, Color::Light) };
    screen::clear(back);
    marks(fore);
    edge(fore);
    pie(look.pie, look.from_top, fore);
    // what's said on the pie shows against it, and against the screen where it isn't
    if let Some(minutes) = look.ready {
        let mut n = Buf::<4>::new();
        let _ = write!(n, "{minutes}");
        screen::text_centred(CY - Style::Tall.height() / 2, n.as_str(), Style::Tall, Color::Invert);
    }
    if look.paused {
        // on a disc of its own, so it reads the same wherever the pie has got to
        let r = 14;
        for dy in -r..=r {
            let w = isqrt(r * r + r - dy * dy);
            screen::fill_rect(CX - w, CY + dy, 2 * w + 1, 1, back);
        }
        screen::fill_rect(CX - 6, CY - 7, 4, 15, fore);
        screen::fill_rect(CX + 3, CY - 7, 4, 15, fore);
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
