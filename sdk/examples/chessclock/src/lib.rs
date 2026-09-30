//! Chess Clock: a game clock for two players sitting either side of maki. Each presses their own
//! side's button when they've moved, which stops their time and starts the other's. For chess,
//! Go, Scrabble and board games: sudden death, Fischer increments, Bronstein and US delays, an
//! hourglass, stages (40 moves in 90 minutes, then 30 more), Japanese and Canadian byo-yomi, and
//! Scrabble's time over.
//!
//! Laid flat between the players, each time is turned to face its player; propped up, both read
//! the right way up (the menu turns them). The running side is lit, under ten seconds shows
//! tenths, and a flag shows whose time ran out, both clocks stopping. The centre pauses; paused,
//! left and right pick a side to correct, the dial adds or takes 5 seconds, and the centre goes
//! on. Before a game, the dial picks a time control and the centre makes one's own; the first
//! press starts the other side's clock (Black presses to start White's).
//!
//! maki waits a moment to tell a left or right press from both together (its menu), so a press
//! counts from when it was made, and a flag falls only once a press can't still be on its way.
//! Whatever takes the screen pauses the clock.

#![no_std]

use core::fmt::Write;

use maki_app::screen::Toward;
use maki_app::*;

/// A lone left or right press reaches the app this much later than it was made.
const LATE_MS: u64 = 160;
/// While a clock runs, the screen's looked at this often.
const TICK_MS: u32 = 50;
/// A click of the dial, correcting a paused clock.
const CORRECT_MS: i64 = 5000;
/// Scrabble's clock goes on past zero up to this, and then the game's lost on time.
const SCRABBLE_OVER_MS: i64 = 600_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Method {
    /// the bonus added after each move (none: sudden death)
    Fischer,
    /// the time a move took given back, up to the bonus
    Bronstein,
    /// the clock waits the bonus before it counts each move down
    Delay,
    /// the time one side takes goes to the other
    Hourglass,
    /// the bonus after each move, and `then` more at move `count`
    Stages,
    /// `count` periods of the bonus once the main time's gone, a move within one keeping it
    Byoyomi,
    /// `count` moves in the bonus once the main time's gone, then another such period
    Canadian,
    /// on past zero, up to 10 minutes over
    Scrabble,
}

const METHODS: [Method; 8] = [
    Method::Fischer,
    Method::Bronstein,
    Method::Delay,
    Method::Hourglass,
    Method::Stages,
    Method::Byoyomi,
    Method::Canadian,
    Method::Scrabble,
];

impl Method {
    fn name(self) -> &'static str {
        match self {
            Method::Fischer => "Increment",
            Method::Bronstein => "Bronstein",
            Method::Delay => "Delay",
            Method::Hourglass => "Hourglass",
            Method::Stages => "Stages",
            Method::Byoyomi => "Byo-yomi",
            Method::Canadian => "Canadian",
            Method::Scrabble => "Scrabble",
        }
    }

    /// What the bonus is called, and the count, if it has them.
    fn bonus(self) -> Option<&'static str> {
        match self {
            Method::Fischer | Method::Stages => Some("Bonus, s"),
            Method::Bronstein | Method::Delay => Some("Delay, s"),
            Method::Byoyomi => Some("Period, s"),
            Method::Canadian => Some("Period, min"),
            Method::Hourglass | Method::Scrabble => None,
        }
    }

    fn count(self) -> Option<&'static str> {
        match self {
            Method::Stages => Some("Moves"),
            Method::Byoyomi => Some("Periods"),
            Method::Canadian => Some("Stones"),
            _ => None,
        }
    }
}

/// A time control: seconds of main time each, the bonus (seconds; a Canadian period's minutes),
/// the count, and a stage's time after it.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Control {
    method: Method,
    main_s: u32,
    bonus: u32,
    count: u32,
    then_s: u32,
}

const fn control(method: Method, main_s: u32, bonus: u32, count: u32, then_s: u32) -> Control {
    Control { method, main_s, bonus, count, then_s }
}

const PRESETS: [(&str, Control); 19] = [
    ("1+0 bullet", control(Method::Fischer, 60, 0, 0, 0)),
    ("2+1 bullet", control(Method::Fischer, 120, 1, 0, 0)),
    ("3+0 blitz", control(Method::Fischer, 180, 0, 0, 0)),
    ("3+2 blitz", control(Method::Fischer, 180, 2, 0, 0)),
    ("5+0 blitz", control(Method::Fischer, 300, 0, 0, 0)),
    ("5+3 blitz", control(Method::Fischer, 300, 3, 0, 0)),
    ("10+0 rapid", control(Method::Fischer, 600, 0, 0, 0)),
    ("10+5 rapid", control(Method::Fischer, 600, 5, 0, 0)),
    ("15+10 rapid", control(Method::Fischer, 900, 10, 0, 0)),
    ("25+10 rapid", control(Method::Fischer, 1500, 10, 0, 0)),
    ("30+0 rapid", control(Method::Fischer, 1800, 0, 0, 0)),
    ("G/30 d5", control(Method::Delay, 1800, 5, 0, 0)),
    ("G/60 d5", control(Method::Delay, 3600, 5, 0, 0)),
    ("90+30 classical", control(Method::Fischer, 5400, 30, 0, 0)),
    ("40/90, 30, +30 s", control(Method::Stages, 5400, 30, 40, 1800)),
    ("Go 60 min, 5x30 s", control(Method::Byoyomi, 3600, 30, 5, 0)),
    ("Go 30 min, 20/5 min", control(Method::Canadian, 1800, 5, 20, 0)),
    ("Scrabble 25 min", control(Method::Scrabble, 1500, 0, 0, 0)),
    ("Hourglass 1 min", control(Method::Hourglass, 60, 0, 0, 0)),
];
/// The last in the list, after the presets: the owner's own.
const CUSTOM: usize = PRESETS.len();

/// One side's clock between its turns.
#[derive(Clone, Copy, Default)]
struct Side {
    /// main time left (Scrabble's goes below 0)
    main: i64,
    moves: u32,
    /// byo-yomi's periods left, or the Canadian period's stones left
    periods: u32,
    /// Canadian: in overtime, and the period's time left
    overtime: bool,
    period: i64,
}

/// What a clock shows `used` into its turn.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Shows {
    Time(i64),
    /// in byo-yomi: the period's time left, and periods (or stones) left
    Period(i64, u32),
    /// Scrabble, past zero
    Over(i64),
    Flag,
}

#[derive(Clone, Copy)]
struct Game {
    control: Control,
    sides: [Side; 2],
    /// whose clock runs, and since when (as made, not as heard)
    running: Option<(usize, u64)>,
    /// paused: whose clock it was, and how long its turn had run
    paused: Option<(usize, i64)>,
    flag: Option<usize>,
}

impl Game {
    fn new(control: Control) -> Game {
        let periods = match control.method {
            Method::Byoyomi | Method::Canadian => control.count,
            _ => 0,
        };
        let side = Side { main: control.main_s as i64 * 1000, moves: 0, periods, overtime: false, period: 0 };
        Game { control, sides: [side; 2], running: None, paused: None, flag: None }
    }

    fn started(&self) -> bool {
        self.running.is_some()
            || self.paused.is_some()
            || self.flag.is_some()
            || self.sides.iter().any(|s| s.moves > 0)
    }

    fn bonus_ms(&self) -> i64 {
        let c = &self.control;
        if c.method == Method::Canadian { c.bonus as i64 * 60_000 } else { c.bonus as i64 * 1000 }
    }

    /// What side `s` shows `used` into its turn.
    fn shows(&self, s: usize, used: i64) -> Shows {
        let side = &self.sides[s];
        let bonus = self.bonus_ms();
        let time = |t: i64| if t > 0 { Shows::Time(t) } else { Shows::Flag };
        match self.control.method {
            Method::Delay => time(side.main - (used - bonus).max(0)),
            Method::Byoyomi => {
                let t = side.main - used;
                if t > 0 {
                    return Shows::Time(t);
                }
                let over = -t;
                let gone = if bonus > 0 { (over / bonus) as u32 } else { u32::MAX };
                if gone >= side.periods {
                    Shows::Flag
                } else {
                    Shows::Period(bonus - over % bonus, side.periods - gone)
                }
            }
            Method::Canadian => {
                if side.overtime {
                    let p = side.period - used;
                    return if p > 0 { Shows::Period(p, side.periods) } else { Shows::Flag };
                }
                let t = side.main - used;
                if t > 0 {
                    Shows::Time(t)
                } else if bonus + t > 0 {
                    Shows::Period(bonus + t, side.periods)
                } else {
                    Shows::Flag
                }
            }
            Method::Scrabble => {
                let t = side.main - used;
                if t > 0 {
                    Shows::Time(t)
                } else if -t < SCRABBLE_OVER_MS {
                    Shows::Over(-t)
                } else {
                    Shows::Flag
                }
            }
            _ => time(side.main - used),
        }
    }

    /// Side `s` has moved, `used` into its turn.
    fn moved(&mut self, s: usize, used: i64) {
        let bonus = self.bonus_ms();
        let c = self.control;
        let side = &mut self.sides[s];
        side.moves += 1;
        match c.method {
            Method::Fischer => side.main += bonus - used,
            Method::Bronstein => side.main -= used - used.min(bonus),
            Method::Delay => side.main -= (used - bonus).max(0),
            Method::Hourglass => {
                side.main -= used;
                self.sides[1 - s].main += used;
            }
            Method::Stages => {
                side.main += bonus - used;
                if side.moves == c.count {
                    side.main += c.then_s as i64 * 1000;
                }
            }
            Method::Byoyomi => {
                let t = side.main - used;
                if t > 0 {
                    side.main = t;
                } else {
                    let gone = if bonus > 0 { (-t / bonus) as u32 } else { side.periods };
                    side.periods = side.periods.saturating_sub(gone);
                    side.main = 0;
                }
            }
            Method::Canadian => {
                if !side.overtime {
                    let t = side.main - used;
                    if t > 0 {
                        side.main = t;
                        return;
                    }
                    side.overtime = true;
                    side.main = 0;
                    side.period = bonus + t;
                } else {
                    side.period -= used;
                }
                side.periods = side.periods.saturating_sub(1);
                if side.periods == 0 {
                    side.period = bonus;
                    side.periods = c.count;
                }
            }
            Method::Scrabble => side.main -= used,
        }
    }

    /// How long side `s`'s turn has run.
    fn used(&self, s: usize, now: u64) -> i64 {
        match (self.running, self.paused) {
            (Some((r, since)), _) if r == s => now.saturating_sub(since) as i64,
            (_, Some((p, used))) if p == s => used,
            _ => 0,
        }
    }

    /// A side's button, pressed at `made`.
    fn press(&mut self, s: usize, made: u64) {
        match self.running {
            // the first press starts the other side's clock
            None if !self.started() && self.flag.is_none() => self.running = Some((1 - s, made)),
            Some((r, since)) if r == s => {
                let used = made.saturating_sub(since) as i64;
                if self.shows(s, used) == Shows::Flag {
                    self.flag = Some(s);
                    self.running = None;
                    return;
                }
                self.moved(s, used);
                self.running = Some((1 - s, made.max(since)));
            }
            _ => {}
        }
    }

    /// The running side's flag, once a press can't still be on its way.
    fn check_flag(&mut self, now: u64) {
        if let Some((r, since)) = self.running {
            let used = now.saturating_sub(since + LATE_MS) as i64;
            if self.shows(r, used) == Shows::Flag {
                self.flag = Some(r);
                self.running = None;
            }
        }
    }

    fn pause(&mut self, now: u64) {
        if let Some((r, since)) = self.running.take() {
            self.paused = Some((r, now.saturating_sub(since) as i64));
        }
    }

    fn resume(&mut self, now: u64) {
        if let Some((p, used)) = self.paused.take() {
            self.running = Some((p, now.saturating_sub(used as u64)));
        }
    }

    fn save(&self) {
        let mut b = [0u8; 80];
        let c = &self.control;
        b[0] = METHODS.iter().position(|&m| m == c.method).unwrap_or(0) as u8;
        b[1..5].copy_from_slice(&c.main_s.to_le_bytes());
        b[5..9].copy_from_slice(&c.bonus.to_le_bytes());
        b[9..13].copy_from_slice(&c.count.to_le_bytes());
        b[13..17].copy_from_slice(&c.then_s.to_le_bytes());
        for (i, side) in self.sides.iter().enumerate() {
            let at = 17 + i * 25;
            b[at..at + 8].copy_from_slice(&side.main.to_le_bytes());
            b[at + 8..at + 12].copy_from_slice(&side.moves.to_le_bytes());
            b[at + 12..at + 16].copy_from_slice(&side.periods.to_le_bytes());
            b[at + 16] = side.overtime as u8;
            b[at + 17..at + 25].copy_from_slice(&side.period.to_le_bytes());
        }
        // a clock running when saved comes back paused
        let (whose, used) = self.paused.unwrap_or((0xff, 0));
        b[67] = whose as u8;
        b[68..76].copy_from_slice(&used.to_le_bytes());
        b[76] = self.flag.map_or(0xff, |f| f as u8);
        let _ = storage::set("game", &b[..77]);
    }

    fn load() -> Option<Game> {
        let mut b = [0u8; 80];
        if storage::get("game", &mut b)? != 77 {
            return None;
        }
        let u32_at = |at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
        let i64_at = |at: usize| i64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        let control = Control {
            method: *METHODS.get(b[0] as usize)?,
            main_s: u32_at(1),
            bonus: u32_at(5),
            count: u32_at(9),
            then_s: u32_at(13),
        };
        let mut g = Game::new(control);
        for (i, side) in g.sides.iter_mut().enumerate() {
            let at = 17 + i * 25;
            *side = Side {
                main: i64_at(at),
                moves: u32_at(at + 8),
                periods: u32_at(at + 12),
                overtime: b[at + 16] != 0,
                period: i64_at(at + 17),
            };
        }
        g.paused = (b[67] < 2).then(|| (b[67] as usize, i64_at(68).max(0)));
        g.flag = (b[76] < 2).then_some(b[76] as usize);
        Some(g)
    }
}

/// A control in words, for the list.
fn describe(c: &Control, out: &mut Buf<40>) {
    let mut main = Buf::<12>::new();
    if c.main_s.is_multiple_of(60) {
        let _ = write!(main, "{} min", c.main_s / 60);
    } else {
        let _ = write!(main, "{}:{:02}", c.main_s / 60, c.main_s % 60);
    }
    let m = main.as_str();
    let _ = match c.method {
        Method::Fischer if c.bonus == 0 => write!(out, "{m}, sudden death"),
        Method::Fischer => write!(out, "{m} + {} s a move", c.bonus),
        Method::Bronstein => write!(out, "{m}, {} s back a move", c.bonus),
        Method::Delay => write!(out, "{m}, {} s delay a move", c.bonus),
        Method::Hourglass => write!(out, "{m}, taken goes over"),
        Method::Stages => write!(out, "{m}/{}, +{} min, +{} s", c.count, c.then_s / 60, c.bonus),
        Method::Byoyomi => write!(out, "{m}, then {}x{} s", c.count, c.bonus),
        Method::Canadian => write!(out, "{m}, then {}/{} min", c.count, c.bonus),
        Method::Scrabble => write!(out, "{m}, then 10 over"),
    };
}

/// A clock's time: M:SS, H:MM:SS from an hour, S.t under ten seconds, each counting up to the
/// next (a clock shows 0:01 until it's gone).
fn time_text(ms: i64, out: &mut Buf<12>) {
    let ms = ms.max(0) as u64;
    if ms < 10_000 {
        let tenths = ms.div_ceil(100);
        let _ = write!(out, "{}.{}", tenths / 10, tenths % 10);
        return;
    }
    let s = ms.div_ceil(1000);
    if s >= 3600 {
        let _ = write!(out, "{}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60);
    } else {
        let _ = write!(out, "{}:{:02}", s / 60, s % 60);
    }
}

/// A side of the screen, and the edge its player reads it from.
#[derive(Clone, Copy)]
struct Half {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    toward: Toward,
}

impl Half {
    /// Its size as its player sees it.
    fn size(&self) -> (i32, i32) {
        match self.toward {
            Toward::Left | Toward::Right => (self.h, self.w),
            _ => (self.w, self.h),
        }
    }

    /// A box (x, y, w, h) as the player sees it, where it lands on the screen.
    fn place(&self, x: i32, y: i32, w: i32, h: i32) -> (i32, i32, i32, i32) {
        let (rw, rh) = self.size();
        match self.toward {
            Toward::Bottom => (self.x + x, self.y + y, w, h),
            Toward::Top => (self.x + self.w - x - w, self.y + self.h - y - h, w, h),
            Toward::Left => (self.x + rh - y - h, self.y + x, h, w),
            Toward::Right => (self.x + y, self.y + rw - x - w, h, w),
        }
    }

    fn fill(&self, x: i32, y: i32, w: i32, h: i32, color: Color) {
        let (x, y, w, h) = self.place(x, y, w, h);
        screen::fill_rect(x, y, w, h, color);
    }

    fn digits(&self, x: i32, y: i32, text: &str, height: i32, color: Color) {
        let (w, h) = screen::segments_size(text, height, Toward::Bottom);
        let (x, y, _, _) = self.place(x, y, w, h);
        screen::segments(x, y, text, height, self.toward, color);
    }
}

enum View {
    /// before a game: the time control picked from the list
    Ready,
    /// making one's own: the row picked
    Custom(usize),
    Clock,
}

struct App {
    game: Game,
    /// the list's pick, and the owner's own control
    pick: usize,
    custom: Control,
    view: View,
    /// the clocks read from the sides (flat between the players) or both upright
    facing: bool,
    /// paused, correcting: which side
    correcting: Option<usize>,
}

impl App {
    fn control(&self) -> Control { if self.pick == CUSTOM { self.custom } else { PRESETS[self.pick].1 } }

    fn halves(&self) -> [Half; 2] {
        let h = |x, toward| Half { x, y: 0, w: WIDTH / 2, h: HEIGHT, toward };
        if self.facing {
            [h(0, Toward::Left), h(WIDTH / 2, Toward::Right)]
        } else {
            [h(0, Toward::Bottom), h(WIDTH / 2, Toward::Bottom)]
        }
    }

    fn keep_settings(&self) {
        let c = &self.custom;
        let mut b = [0u8; 19];
        b[0] = self.pick as u8;
        b[1] = self.facing as u8;
        b[2] = METHODS.iter().position(|&m| m == c.method).unwrap_or(0) as u8;
        b[3..7].copy_from_slice(&c.main_s.to_le_bytes());
        b[7..11].copy_from_slice(&c.bonus.to_le_bytes());
        b[11..15].copy_from_slice(&c.count.to_le_bytes());
        b[15..19].copy_from_slice(&c.then_s.to_le_bytes());
        let _ = storage::set("settings", &b);
    }
}

fn draw_side(app: &App, s: usize, half: &Half, now: u64) {
    let g = &app.game;
    // the running side is lit; whose time ran out blinks
    let running = g.running.is_some_and(|(r, _)| r == s);
    let lit = running || (g.flag == Some(s) && (now / 500).is_multiple_of(2));
    let (back, fore) = if lit { (Color::Light, Color::Dark) } else { (Color::Dark, Color::Light) };
    let (rw, rh) = half.size();
    half.fill(0, 0, rw, rh, back);
    let shows = if g.flag == Some(s) { Shows::Flag } else { g.shows(s, g.used(s, now)) };
    let mut t = Buf::<12>::new();
    match shows {
        Shows::Time(ms) | Shows::Period(ms, _) => time_text(ms, &mut t),
        Shows::Over(ms) => {
            let _ = t.write_char('-');
            let s = (ms as u64).div_ceil(1000);
            let _ = write!(t, "{}:{:02}", s / 60, s % 60);
        }
        Shows::Flag => {
            let _ = t.write_str("0.0");
        }
    }
    // the time, as big as fits
    let mut h = (rh - 26).min(46);
    while h > 10 && screen::segments_size(t.as_str(), h, Toward::Bottom).0 > rw - 8 {
        h -= 2;
    }
    let (w, _) = screen::segments_size(t.as_str(), h, Toward::Bottom);
    // a pixel's shift a minute spares the screen
    let shift = (now / 60_000 % 2) as i32;
    half.digits((rw - w) / 2, (rh - h) / 2 + shift, t.as_str(), h, fore);
    // moves made, below; periods or stones left, and the flag, above
    let mut moves = Buf::<8>::new();
    let _ = write!(moves, "{}", g.sides[s].moves);
    half.digits(6, rh - 16, moves.as_str(), 10, fore);
    if let Shows::Period(_, left) = shows {
        let mut n = Buf::<8>::new();
        let _ = write!(n, "{left}");
        let (w, _) = screen::segments_size(n.as_str(), 10, Toward::Bottom);
        half.digits(rw - 6 - w, 6, n.as_str(), 10, fore);
        // a bar under it: in overtime
        half.fill(rw - 6 - w, 18, w, 2, fore);
    }
    if shows == Shows::Flag {
        // a flag: its pole and cloth
        half.fill(8, 4, 3, 20, fore);
        half.fill(11, 4, 14, 9, fore);
    }
    if g.paused.is_some() {
        // paused: two bars
        half.fill(rw / 2 - 6, 5, 4, 12, fore);
        half.fill(rw / 2 + 2, 5, 4, 12, fore);
    }
    if app.correcting == Some(s) {
        let (x, y, w, h) = half.place(1, 1, rw - 2, rh - 2);
        screen::rect(x, y, w, h, fore);
    }
}

fn draw(app: &App, now: u64) {
    screen::clear(Color::Dark);
    match app.view {
        View::Clock => {
            for (s, half) in app.halves().iter().enumerate() {
                draw_side(app, s, half, now);
            }
            screen::line(WIDTH / 2, 0, WIDTH / 2, HEIGHT - 1, Color::Light);
        }
        View::Ready => {
            let name = if app.pick == CUSTOM { "Your own" } else { PRESETS[app.pick].0 };
            screen::text_centred(4, "Time control", Style::Small, Color::Light);
            screen::text_centred(22, name, Style::Bold, Color::Light);
            let mut words = Buf::<40>::new();
            describe(&app.control(), &mut words);
            screen::text_centred(42, words.as_str(), Style::Small, Color::Light);
            screen::text_centred(62, "a player's button starts", Style::Small, Color::Light);
            screen::text_centred(74, "the other's clock", Style::Small, Color::Light);
            screen::line(0, 97, WIDTH - 1, 97, Color::Light);
            screen::text_centred(99, "dial: pick   centre: edit", Style::Small, Color::Light);
        }
        View::Custom(row) => {
            let c = &app.custom;
            screen::text(2, 0, "Your own", Style::Bold, Color::Light);
            screen::line(0, 16, WIDTH - 1, 16, Color::Light);
            let mut rows: [(&str, Buf<12>); 5] = Default::default();
            rows[0].0 = "Method";
            let _ = rows[0].1.write_str(c.method.name());
            rows[1].0 = "Minutes";
            let _ = write!(rows[1].1, "{}", c.main_s / 60);
            let mut n = 2;
            if let Some(name) = c.method.bonus() {
                rows[n].0 = name;
                let _ = write!(rows[n].1, "{}", c.bonus);
                n += 1;
            }
            if let Some(name) = c.method.count() {
                rows[n].0 = name;
                let _ = write!(rows[n].1, "{}", c.count);
                n += 1;
            }
            if c.method == Method::Stages {
                rows[n].0 = "Then, min";
                let _ = write!(rows[n].1, "{}", c.then_s / 60);
                n += 1;
            }
            for (i, (name, value)) in rows.iter().take(n).enumerate() {
                let y = 19 + i as i32 * 15;
                let on = i == row.min(n - 1);
                if on {
                    screen::fill_rect(0, y, WIDTH, 14, Color::Light);
                }
                let fore = if on { Color::Dark } else { Color::Light };
                screen::text(4, y + 1, name, Style::Small, fore);
                let w = screen::text_width(value.as_str(), Style::Small);
                screen::text(WIDTH - 4 - w, y + 1, value.as_str(), Style::Small, fore);
            }
            screen::line(0, 97, WIDTH - 1, 97, Color::Light);
            screen::text_centred(99, "dial: change   centre: done", Style::Small, Color::Light);
        }
    }
    screen::present();
}

/// The custom form's rows for this method: which of main, bonus, count and then each is.
fn custom_rows(c: &Control) -> ([u8; 5], usize) {
    let mut rows = [0u8; 5];
    let mut n = 0;
    let mut add = |r| {
        rows[n] = r;
        n += 1;
    };
    add(0);
    add(1);
    if c.method.bonus().is_some() {
        add(2);
    }
    if c.method.count().is_some() {
        add(3);
    }
    if c.method == Method::Stages {
        add(4);
    }
    (rows, n)
}

fn main() {
    let _ = menu(&["New game", "Turn the digits"]);
    let mut b = [0u8; 19];
    let settings = storage::get("settings", &mut b) == Some(19);
    let custom = if settings {
        let at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        Control {
            method: METHODS.get(b[2] as usize).copied().unwrap_or(Method::Fischer),
            main_s: at(3).clamp(60, 180 * 60),
            bonus: at(7).min(60),
            count: at(11).min(99),
            then_s: at(15).min(180 * 60),
        }
    } else {
        control(Method::Fischer, 600, 5, 0, 0)
    };
    let pick = if settings { (b[0] as usize).min(CUSTOM) } else { 5 };
    let facing = !settings || b[1] != 0;
    let saved = Game::load();
    let mut app = App {
        game: saved.unwrap_or(Game::new(if pick == CUSTOM { custom } else { PRESETS[pick].1 })),
        pick,
        custom,
        view: if saved.is_some_and(|g| g.started()) { View::Clock } else { View::Ready },
        facing,
        correcting: None,
    };
    loop {
        let now = millis();
        app.game.check_flag(now);
        draw(&app, now);
        let busy = app.game.running.is_some() || (app.game.flag.is_some() && matches!(app.view, View::Clock));
        let event =
            wait(if busy { Some(if app.game.running.is_some() { TICK_MS } else { 500 }) } else { None });
        let now = millis();
        match event {
            Event::Exit => {
                app.game.pause(now);
                if app.game.started() {
                    app.game.save();
                }
                return;
            }
            // whatever takes the screen pauses the clock
            Event::Hidden => {
                app.game.pause(now);
                app.game.save();
            }
            Event::Menu(0) => {
                app.game = Game::new(app.control());
                app.view = View::Ready;
                app.correcting = None;
                storage::delete("game");
            }
            Event::Menu(1) => {
                app.facing = !app.facing;
                app.keep_settings();
            }
            _ => {}
        }
        match app.view {
            View::Ready => match event {
                Event::Up | Event::Down => {
                    let n = CUSTOM + 1;
                    app.pick = if event == Event::Down { (app.pick + 1) % n } else { (app.pick + n - 1) % n };
                    app.game = Game::new(app.control());
                    app.keep_settings();
                }
                Event::Centre => app.view = View::Custom(0),
                Event::Left | Event::Right => {
                    app.game = Game::new(app.control());
                    app.game.press(if event == Event::Left { 0 } else { 1 }, now.saturating_sub(LATE_MS));
                    app.view = View::Clock;
                }
                _ => {}
            },
            View::Custom(row) => {
                let (rows, n) = custom_rows(&app.custom);
                let row = row.min(n - 1);
                let c = &mut app.custom;
                match event {
                    Event::Left => app.view = View::Custom((row + n - 1) % n),
                    Event::Right => app.view = View::Custom((row + 1) % n),
                    Event::Up | Event::Down => {
                        let up = event == Event::Up;
                        let step = |v: u32, by: u32, lo: u32, hi: u32| {
                            if up { (v + by).min(hi) } else { v.saturating_sub(by).max(lo) }
                        };
                        match rows[row] {
                            0 => {
                                let i = METHODS.iter().position(|&m| m == c.method).unwrap_or(0);
                                let n = METHODS.len();
                                c.method = METHODS[if up { (i + 1) % n } else { (i + n - 1) % n }];
                                // what each is usually played with
                                (c.bonus, c.count, c.then_s) = match c.method {
                                    Method::Fischer | Method::Stages => (30, 40, 1800),
                                    Method::Bronstein | Method::Delay => (5, 0, 0),
                                    Method::Byoyomi => (30, 5, 0),
                                    Method::Canadian => (5, 20, 0),
                                    Method::Hourglass | Method::Scrabble => (0, 0, 0),
                                };
                            }
                            1 => c.main_s = step(c.main_s / 60, 1, 1, 180) * 60,
                            2 => c.bonus = step(c.bonus, 1, 0, 60),
                            3 => c.count = step(c.count, 1, 1, 99),
                            _ => c.then_s = step(c.then_s / 60, 1, 0, 180) * 60,
                        }
                    }
                    Event::Centre => {
                        if app.custom.method.count().is_some() && app.custom.count == 0 {
                            app.custom.count = 1;
                        }
                        app.pick = CUSTOM;
                        app.game = Game::new(app.custom);
                        app.keep_settings();
                        app.view = View::Ready;
                    }
                    _ => {}
                }
            }
            View::Clock => match event {
                Event::Left | Event::Right => {
                    let s = if event == Event::Left { 0 } else { 1 };
                    if app.game.paused.is_some() {
                        app.correcting = Some(s);
                    } else {
                        app.game.press(s, now.saturating_sub(LATE_MS));
                        app.game.save();
                    }
                }
                Event::Up | Event::Down if app.game.paused.is_some() => {
                    if let Some(s) = app.correcting {
                        let by = if event == Event::Up { CORRECT_MS } else { -CORRECT_MS };
                        let side = &mut app.game.sides[s];
                        side.main = (side.main + by).max(0);
                    }
                }
                Event::Centre if app.game.flag.is_some() => {
                    app.game = Game::new(app.control());
                    app.view = View::Ready;
                    storage::delete("game");
                }
                Event::Centre if app.game.paused.is_some() => {
                    app.game.resume(now);
                    app.correcting = None;
                }
                Event::Centre if app.game.running.is_some() => {
                    app.game.pause(now);
                    app.game.save();
                }
                _ => {}
            },
        }
    }
}

maki_app::main!(main);
