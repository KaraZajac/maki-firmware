//! Life: a life counter for Magic and other games, 2 to 6 players. Left and right pick a player,
//! and the jog dial on maki's side counts their life, a point a click, the change so far showing
//! beside it until the dial rests. Each player's total is big enough to read across the table;
//! two players face each other, the far one's total upside down to read from their side, and
//! with more, the seats go round clockwise, the top row turned to face across too if the game
//! says so.
//!
//! The centre opens the player's counters: poison, and commander damage from each opponent,
//! which takes their life too (unless the game says it's only counted). A player at 0 life, 10
//! poison or 21 damage from one commander is crossed out. The menu starts a new game (players,
//! starting life, which way the far side faces, whether commander damage takes life), picks who
//! starts, gives the picked player the crown, shows the changes so far, undoes the last, and
//! starts over. The game is kept after every change.

#![no_std]

use core::fmt::Write;

use maki_app::screen::Toward;
use maki_app::*;

/// The most players, the starting lives, and the changes kept to look back on or undo.
const MOST: usize = 6;
const LIVES: [i16; 4] = [20, 25, 30, 40];
const HISTORY: usize = 48;
/// A burst of clicks is one change once the dial's rested this long, and the counters go back to
/// the table after this long without a press.
const REST_MS: u64 = 1500;
const IDLE_MS: u64 = 4000;
/// Out: 10 poison, or 21 damage from one commander.
const POISON_OUT: u8 = 10;
const COMMANDER_OUT: u8 = 21;
/// Who starts: the pick goes round this many times, then slows to a stop.
const SPIN_STEPS: u32 = 14;

const MENU: [&str; 6] = ["New game", "Who starts", "Monarch", "History", "Undo", "Reset"];

#[derive(Clone, Copy, PartialEq, Eq)]
struct Settings {
    players: u8,
    life: i16,
    /// the top row faces across the table
    facing: bool,
    /// commander damage takes life too
    takes_life: bool,
}

/// What a change was to: life, poison, or commander damage from another player.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Life,
    Poison,
    From(u8),
}

impl Kind {
    fn code(self) -> u8 {
        match self {
            Kind::Life => 0,
            Kind::Poison => 1,
            Kind::From(p) => 2 + p,
        }
    }

    fn from_code(c: u8) -> Kind {
        match c {
            0 => Kind::Life,
            1 => Kind::Poison,
            c => Kind::From(c - 2),
        }
    }
}

#[derive(Clone, Copy)]
struct Change {
    player: u8,
    kind: Kind,
    delta: i16,
}

struct Game {
    set: Settings,
    life: [i16; MOST],
    poison: [u8; MOST],
    /// commander damage: `damage[to][from]`
    damage: [[u8; MOST]; MOST],
    monarch: Option<u8>,
    history: [Change; HISTORY],
    changes: usize,
}

impl Game {
    fn new(set: Settings) -> Game {
        Game {
            set,
            life: [set.life; MOST],
            poison: [0; MOST],
            damage: [[0; MOST]; MOST],
            monarch: None,
            history: [Change { player: 0, kind: Kind::Life, delta: 0 }; HISTORY],
            changes: 0,
        }
    }

    fn players(&self) -> usize { self.set.players as usize }

    /// Out of the game: no life, 10 poison, or 21 from one commander.
    fn out(&self, p: usize) -> bool {
        self.life[p] <= 0
            || self.poison[p] >= POISON_OUT
            || self.damage[p].iter().any(|&d| d >= COMMANDER_OUT)
    }

    /// Changes a counter by `delta`, commander damage taking life too if the game says so; what
    /// it actually changed by (a counter stops at 0).
    fn apply(&mut self, p: usize, kind: Kind, delta: i16) -> i16 {
        match kind {
            Kind::Life => {
                let was = self.life[p];
                self.life[p] = (was + delta).clamp(-999, 999);
                self.life[p] - was
            }
            Kind::Poison => {
                let was = self.poison[p] as i16;
                self.poison[p] = (was + delta).clamp(0, 99) as u8;
                self.poison[p] as i16 - was
            }
            Kind::From(from) => {
                let d = &mut self.damage[p][from as usize];
                let was = *d as i16;
                *d = (was + delta).clamp(0, 99) as u8;
                let by = *d as i16 - was;
                if self.set.takes_life {
                    self.life[p] = (self.life[p] - by).clamp(-999, 999);
                }
                by
            }
        }
    }

    fn record(&mut self, change: Change) {
        if change.delta == 0 {
            return;
        }
        if self.changes == HISTORY {
            self.history.copy_within(1.., 0);
            self.changes -= 1;
        }
        self.history[self.changes] = change;
        self.changes += 1;
    }

    fn undo(&mut self) -> Option<Change> {
        let c = self.history[..self.changes].last().copied()?;
        self.changes -= 1;
        self.apply(c.player as usize, c.kind, -c.delta);
        Some(c)
    }

    fn save(&self) {
        let mut b = [0u8; 4 + MOST * 2 + MOST + MOST * MOST + 2 + HISTORY * 4];
        b[0] = self.set.players;
        b[1] = self.set.life as u8;
        b[2] = self.set.facing as u8;
        b[3] = self.set.takes_life as u8;
        let mut at = 4;
        for p in 0..MOST {
            b[at..at + 2].copy_from_slice(&self.life[p].to_le_bytes());
            at += 2;
        }
        b[at..at + MOST].copy_from_slice(&self.poison);
        at += MOST;
        for row in &self.damage {
            b[at..at + MOST].copy_from_slice(row);
            at += MOST;
        }
        b[at] = self.monarch.map_or(0xff, |m| m);
        b[at + 1] = self.changes as u8;
        at += 2;
        for c in &self.history[..self.changes] {
            b[at] = c.player;
            b[at + 1] = c.kind.code();
            b[at + 2..at + 4].copy_from_slice(&c.delta.to_le_bytes());
            at += 4;
        }
        let _ = storage::set("game", &b[..at]);
    }

    fn load() -> Game {
        let fresh = Game::new(Settings { players: 2, life: 20, facing: true, takes_life: true });
        let mut b = [0u8; 4 + MOST * 2 + MOST + MOST * MOST + 2 + HISTORY * 4];
        let Some(len) = storage::get("game", &mut b) else { return fresh };
        let head = 4 + MOST * 2 + MOST + MOST * MOST + 2;
        if len < head || len > b.len() || !(2..=MOST as u8).contains(&b[0]) {
            return fresh;
        }
        let mut g = Game::new(Settings {
            players: b[0],
            life: b[1] as i16,
            facing: b[2] != 0,
            takes_life: b[3] != 0,
        });
        let mut at = 4;
        for p in 0..MOST {
            g.life[p] = i16::from_le_bytes([b[at], b[at + 1]]);
            at += 2;
        }
        g.poison.copy_from_slice(&b[at..at + MOST]);
        at += MOST;
        for row in g.damage.iter_mut() {
            row.copy_from_slice(&b[at..at + MOST]);
            at += MOST;
        }
        g.monarch = (b[at] < g.set.players).then_some(b[at]);
        let changes = (b[at + 1] as usize).min(HISTORY).min((len - head) / 4);
        at += 2;
        for _ in 0..changes {
            let (player, kind) = (b[at], Kind::from_code(b[at + 1]));
            let ok = player < g.set.players && !matches!(kind, Kind::From(f) if f >= g.set.players);
            if ok {
                g.history[g.changes] =
                    Change { player, kind, delta: i16::from_le_bytes([b[at + 2], b[at + 3]]) };
                g.changes += 1;
            }
            at += 4;
        }
        g
    }
}

/// A player's place on the screen, and the edge they read it from.
#[derive(Clone, Copy)]
struct Cell {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    toward: Toward,
}

impl Cell {
    /// A box (x, y, w, h) within the cell, as its player sees it, where it lands on the screen.
    fn place(&self, x: i32, y: i32, w: i32, h: i32) -> (i32, i32, i32, i32) {
        match self.toward {
            Toward::Top => (self.x + self.w - x - w, self.y + self.h - y - h, w, h),
            _ => (self.x + x, self.y + y, w, h),
        }
    }

    fn fill(&self, x: i32, y: i32, w: i32, h: i32, color: Color) {
        let (x, y, w, h) = self.place(x, y, w, h);
        screen::fill_rect(x, y, w, h, color);
    }

    /// Digits `height` tall, their top left at (x, y) as the player sees them.
    fn digits(&self, x: i32, y: i32, text: &str, height: i32, color: Color) {
        let (w, h) = screen::segments_size(text, height, Toward::Bottom);
        let (x, y, _, _) = self.place(x, y, w, h);
        screen::segments(x, y, text, height, self.toward, color);
    }
}

/// Where each player is: the seats go round clockwise from the bottom left, the top row turned to
/// face across the table if the game says so.
fn cells(set: &Settings) -> [Cell; MOST] {
    let top = if set.facing { Toward::Top } else { Toward::Bottom };
    let c = |x, y, w, h, toward| Cell { x, y, w, h, toward };
    let none = c(0, 0, 0, 0, Toward::Bottom);
    let (h, b) = (HEIGHT / 2, HEIGHT - HEIGHT / 2);
    match set.players {
        2 => [c(0, h, WIDTH, b, Toward::Bottom), c(0, 0, WIDTH, h, top), none, none, none, none],
        3 => [
            c(0, h, 64, b, Toward::Bottom),
            c(64, h, 64, b, Toward::Bottom),
            c(0, 0, WIDTH, h, top),
            none,
            none,
            none,
        ],
        4 => [
            c(0, h, 64, b, Toward::Bottom),
            c(64, h, 64, b, Toward::Bottom),
            c(64, 0, 64, h, top),
            c(0, 0, 64, h, top),
            none,
            none,
        ],
        5 => [
            c(0, h, 42, b, Toward::Bottom),
            c(42, h, 43, b, Toward::Bottom),
            c(85, h, 43, b, Toward::Bottom),
            c(64, 0, 64, h, top),
            c(0, 0, 64, h, top),
            none,
        ],
        _ => [
            c(0, h, 42, b, Toward::Bottom),
            c(42, h, 43, b, Toward::Bottom),
            c(85, h, 43, b, Toward::Bottom),
            c(85, 0, 43, h, top),
            c(42, 0, 43, h, top),
            c(0, 0, 42, h, top),
        ],
    }
}

/// A burst of clicks not yet a change: whose, what, how much, and when the last was.
#[derive(Clone, Copy)]
struct Pending {
    player: usize,
    kind: Kind,
    delta: i16,
    last: u64,
}

/// What's on the screen.
#[derive(Clone, Copy)]
enum View {
    Table,
    /// a player's counters: the row picked (poison, then commander damage from each other player)
    Counters {
        row: usize,
        since: u64,
    },
    History {
        top: usize,
    },
    NewGame {
        set: Settings,
        row: usize,
    },
    /// who starts: where the pick is, the steps left, when the next is
    Spin {
        at: usize,
        steps: u32,
        next: u64,
    },
}

struct App {
    game: Game,
    view: View,
    picked: usize,
    pending: Option<Pending>,
    /// a line shown over the table for a while
    note: Buf<32>,
    note_until: u64,
}

impl App {
    /// A burst of clicks ends: it goes in the history, and the game is kept.
    fn commit(&mut self) {
        if let Some(p) = self.pending.take() {
            self.game.record(Change { player: p.player as u8, kind: p.kind, delta: p.delta });
            self.game.save();
        }
    }

    /// The dial on a counter: into the burst going, or a new one.
    fn click(&mut self, player: usize, kind: Kind, up: bool, now: u64) {
        if self.pending.is_some_and(|p| p.player != player || p.kind != kind) {
            self.commit();
        }
        let by = self.game.apply(player, kind, if up { 1 } else { -1 });
        let p = self.pending.get_or_insert(Pending { player, kind, delta: 0, last: now });
        p.delta += by;
        p.last = now;
    }

    fn say(&mut self, now: u64, f: impl FnOnce(&mut Buf<32>)) {
        self.note.clear();
        f(&mut self.note);
        self.note_until = now + 3000;
    }

    /// The counters' rows for the picked player: poison, then each other player's commander.
    fn rows(&self) -> ([Kind; MOST], usize) {
        let mut rows = [Kind::Poison; MOST];
        let mut n = 1;
        for from in 0..self.game.players() {
            if from != self.picked {
                rows[n] = Kind::From(from as u8);
                n += 1;
            }
        }
        (rows, n)
    }

    fn wake(&self, now: u64) -> Option<u32> {
        let at = |t: u64| Some(t.saturating_sub(now).max(1) as u32);
        match self.view {
            View::Spin { next, .. } => at(next),
            View::Counters { since, .. } => at(self.pending.map_or(since + IDLE_MS, |p| p.last + REST_MS)),
            _ => match self.pending {
                Some(p) => at(p.last + REST_MS),
                None if now < self.note_until => at(self.note_until),
                None => None,
            },
        }
    }
}

fn label(p: usize) -> Buf<10> {
    let mut b = Buf::new();
    let _ = write!(b, "Player {}", p + 1);
    b
}

fn number(n: i32) -> Buf<8> {
    let mut b = Buf::new();
    let _ = write!(b, "{n}");
    b
}

/// A player's cell: their life as big as fits, their seat's number, the crown, poison and their
/// worst commander damage in the corners; the change going on, lit; crossed out if they're out.
fn draw_cell(app: &App, p: usize, cell: &Cell, spin_at: Option<usize>) {
    let g = &app.game;
    let pending = app.pending.filter(|x| x.player == p && matches!(app.view, View::Table));
    let lit = pending.is_some() || spin_at == Some(p);
    let (back, fore) = if lit { (Color::Light, Color::Dark) } else { (Color::Dark, Color::Light) };
    cell.fill(0, 0, cell.w, cell.h, back);
    if p == app.picked && !lit {
        let (x, y, w, h) = cell.place(1, 1, cell.w - 2, cell.h - 2);
        screen::rect(x, y, w, h, fore);
    }
    // the seat's number, top left
    cell.digits(4, 4, number(p as i32 + 1).as_str(), 9, fore);
    // life, as big as fits; kept clear of the corners' marks when it's as wide as the cell
    let life = number(g.life[p] as i32);
    let fits = |h: i32| {
        let w = screen::segments_size(life.as_str(), h, Toward::Bottom).0;
        w <= cell.w - 8 && (w <= cell.w - 44 || h <= cell.h - 28)
    };
    let mut h = (cell.h - 18).min(40);
    while h > 10 && !fits(h) {
        h -= 2;
    }
    let (w, _) = screen::segments_size(life.as_str(), h, Toward::Bottom);
    cell.digits((cell.w - w) / 2, (cell.h - h) / 2, life.as_str(), h, fore);
    // the change going on, top right
    if let Some(x) = pending.filter(|x| x.kind == Kind::Life) {
        let mut d = Buf::<8>::new();
        let _ = write!(d, "{}{}", if x.delta > 0 { "+" } else { "" }, x.delta);
        let (w, _) = screen::segments_size(d.as_str(), 11, Toward::Bottom);
        cell.digits(cell.w - w - 4, 4, d.as_str(), 11, fore);
    } else if g.monarch == Some(p as u8) {
        // the crown: a band and three points
        cell.fill(cell.w - 17, 9, 13, 3, fore);
        for i in 0..3 {
            cell.fill(cell.w - 17 + i * 5, 3 + (i % 2) * 2, 3, 6 - (i % 2) * 2, fore);
        }
    }
    // poison, bottom left: a drop and the count
    if g.poison[p] > 0 {
        let y = cell.h - 13;
        cell.fill(6, y, 3, 2, fore);
        cell.fill(5, y + 2, 5, 3, fore);
        cell.fill(4, y + 5, 7, 4, fore);
        cell.digits(13, y, number(g.poison[p] as i32).as_str(), 9, fore);
    }
    // the most damage from one commander, bottom right: a sword and the count
    let worst = g.damage[p].iter().copied().max().unwrap_or(0);
    if worst > 0 {
        let n = number(worst as i32);
        let (w, _) = screen::segments_size(n.as_str(), 9, Toward::Bottom);
        let y = cell.h - 13;
        cell.digits(cell.w - 4 - w, y, n.as_str(), 9, fore);
        let x = cell.w - 4 - w - 9;
        cell.fill(x + 2, y, 2, 6, fore);
        cell.fill(x, y + 6, 6, 1, fore);
        cell.fill(x + 2, y + 7, 2, 2, fore);
    }
    if g.out(p) {
        let (x, y, w, h) = cell.place(2, 2, cell.w - 4, cell.h - 4);
        screen::line(x, y, x + w - 1, y + h - 1, fore);
        screen::line(x + w - 1, y, x, y + h - 1, fore);
    }
}

fn draw(app: &App, now: u64) {
    screen::clear(Color::Dark);
    let g = &app.game;
    match &app.view {
        View::Table | View::Spin { .. } => {
            let spin_at = match app.view {
                View::Spin { at, .. } => Some(at),
                _ => None,
            };
            let cells = cells(&g.set);
            for (p, cell) in cells.iter().enumerate().take(g.players()) {
                draw_cell(app, p, cell, spin_at);
            }
            // the lines between them
            screen::line(0, HEIGHT / 2, WIDTH - 1, HEIGHT / 2, Color::Light);
            for cell in cells.iter().take(g.players()) {
                if cell.x > 0 {
                    screen::line(cell.x, cell.y, cell.x, cell.y + cell.h - 1, Color::Light);
                }
            }
            if now < app.note_until {
                let w = screen::text_width(app.note.as_str(), Style::Bold) + 12;
                let x = (WIDTH - w) / 2;
                screen::fill_rect(x, 45, w, 20, Color::Dark);
                screen::rect(x, 45, w, 20, Color::Light);
                screen::text_centred(47, app.note.as_str(), Style::Bold, Color::Light);
            }
        }
        View::Counters { row, .. } => {
            let p = app.picked;
            screen::text(2, 0, label(p).as_str(), Style::Bold, Color::Light);
            let life = number(g.life[p] as i32);
            let w = screen::text_width(life.as_str(), Style::Bold);
            screen::text(WIDTH - 2 - w, 0, life.as_str(), Style::Bold, Color::Light);
            screen::line(0, 16, WIDTH - 1, 16, Color::Light);
            let (rows, n) = app.rows();
            for (i, kind) in rows.iter().take(n).enumerate() {
                let y = 18 + i as i32 * 13;
                let on = i == *row;
                if on {
                    screen::fill_rect(0, y, WIDTH, 13, Color::Light);
                }
                let fore = if on { Color::Dark } else { Color::Light };
                let (name, value, out) = match *kind {
                    Kind::Poison => (Buf::<24>::new(), g.poison[p], POISON_OUT),
                    Kind::From(f) => {
                        let mut b = Buf::<24>::new();
                        let _ = write!(b, "from {}", label(f as usize).as_str());
                        (b, g.damage[p][f as usize], COMMANDER_OUT)
                    }
                    Kind::Life => (Buf::new(), 0, 0),
                };
                let name = if name.is_empty() { "Poison" } else { name.as_str() };
                screen::text(4, y, name, Style::Small, fore);
                let mut v = Buf::<12>::new();
                let _ = write!(v, "{value}{}", if value >= out { " out" } else { "" });
                let w = screen::text_width(v.as_str(), Style::Small);
                screen::text(WIDTH - 4 - w, y, v.as_str(), Style::Small, fore);
            }
            screen::line(0, 97, WIDTH - 1, 97, Color::Light);
            screen::text_centred(99, "dial: count   centre: back", Style::Small, Color::Light);
        }
        View::History { top } => {
            screen::text(2, 0, "Changes", Style::Bold, Color::Light);
            screen::line(0, 16, WIDTH - 1, 16, Color::Light);
            if g.changes == 0 {
                screen::text_centred(40, "none yet", Style::Small, Color::Light);
            }
            for (row, c) in g.history[..g.changes].iter().rev().skip(*top).take(6).enumerate() {
                let mut line = Buf::<40>::new();
                let sign = if c.delta > 0 { "+" } else { "" };
                let _ = match c.kind {
                    Kind::Life => write!(line, "P{} {sign}{} life", c.player + 1, c.delta),
                    Kind::Poison => write!(line, "P{} {sign}{} poison", c.player + 1, c.delta),
                    Kind::From(f) => write!(line, "P{} {sign}{} from P{}", c.player + 1, c.delta, f + 1),
                };
                screen::text(4, 18 + row as i32 * 13, line.as_str(), Style::Small, Color::Light);
            }
            screen::line(0, 97, WIDTH - 1, 97, Color::Light);
            screen::text_centred(99, "dial: scroll   centre: back", Style::Small, Color::Light);
        }
        View::NewGame { set, row } => {
            screen::text(2, 0, "New game", Style::Bold, Color::Light);
            screen::line(0, 16, WIDTH - 1, 16, Color::Light);
            let mut players = Buf::<4>::new();
            let _ = write!(players, "{}", set.players);
            let mut life = Buf::<4>::new();
            let _ = write!(life, "{}", set.life);
            let rows: [(&str, &str); 4] = [
                ("Players", players.as_str()),
                ("Life", life.as_str()),
                ("Far side", if set.facing { "faces across" } else { "this way" }),
                ("Commander", if set.takes_life { "takes life" } else { "counted only" }),
            ];
            for (i, (name, value)) in rows.iter().enumerate() {
                let y = 20 + i as i32 * 15;
                let on = i == *row;
                if on {
                    screen::fill_rect(0, y, WIDTH, 14, Color::Light);
                }
                let fore = if on { Color::Dark } else { Color::Light };
                screen::text(4, y + 1, name, Style::Small, fore);
                let w = screen::text_width(value, Style::Small);
                screen::text(WIDTH - 4 - w, y + 1, value, Style::Small, fore);
            }
            screen::line(0, 97, WIDTH - 1, 97, Color::Light);
            screen::text_centred(99, "dial: change   centre: go", Style::Small, Color::Light);
        }
    }
    screen::present();
}

fn main() {
    let _ = menu(&MENU);
    let mut app = App {
        game: Game::load(),
        view: View::Table,
        picked: 0,
        pending: None,
        note: Buf::new(),
        note_until: 0,
    };
    loop {
        let now = millis();
        draw(&app, now);
        let event = wait(app.wake(now));
        let now = millis();
        let players = app.game.players();
        if event == Event::Exit {
            app.commit();
            return;
        }
        if event == Event::Hidden {
            app.commit();
        }
        match app.view {
            View::Table => match event {
                Event::Up | Event::Down => app.click(app.picked, Kind::Life, event == Event::Up, now),
                Event::Timeout if app.pending.is_some_and(|p| now >= p.last + REST_MS) => app.commit(),
                Event::Left | Event::Right => {
                    app.commit();
                    app.picked = if event == Event::Right {
                        (app.picked + 1) % players
                    } else {
                        (app.picked + players - 1) % players
                    };
                }
                Event::Centre => {
                    app.commit();
                    app.view = View::Counters { row: 0, since: now };
                }
                Event::Menu(i) => {
                    app.commit();
                    menu_item(&mut app, i, now);
                }
                _ => {}
            },
            View::Counters { row, since } => {
                let (rows, n) = app.rows();
                let row = row.min(n - 1);
                let since = if event == Event::Timeout { since } else { now };
                app.view = View::Counters { row, since };
                match event {
                    Event::Up | Event::Down => app.click(app.picked, rows[row], event == Event::Up, now),
                    Event::Left | Event::Right => {
                        app.commit();
                        let row = if event == Event::Right { (row + 1) % n } else { (row + n - 1) % n };
                        app.view = View::Counters { row, since };
                    }
                    Event::Timeout => match app.pending {
                        Some(p) if now >= p.last + REST_MS => app.commit(),
                        None if now >= since + IDLE_MS => app.view = View::Table,
                        _ => {}
                    },
                    Event::Centre => {
                        app.commit();
                        app.view = View::Table;
                    }
                    // an item of the menu, from here too: the table, then the item
                    Event::Menu(i) => {
                        app.commit();
                        app.view = View::Table;
                        menu_item(&mut app, i, now);
                    }
                    _ => {}
                }
            }
            View::History { top } => match event {
                Event::Down => {
                    app.view = View::History { top: (top + 1).min(app.game.changes.saturating_sub(6)) }
                }
                Event::Up => app.view = View::History { top: top.saturating_sub(1) },
                Event::Centre | Event::Left | Event::Right => app.view = View::Table,
                Event::Menu(i) => {
                    app.view = View::Table;
                    menu_item(&mut app, i, now);
                }
                _ => {}
            },
            View::NewGame { mut set, row } => match event {
                Event::Left => app.view = View::NewGame { set, row: (row + 3) % 4 },
                Event::Right => app.view = View::NewGame { set, row: (row + 1) % 4 },
                Event::Up | Event::Down => {
                    let up = event == Event::Up;
                    match row {
                        0 => {
                            let most = MOST as u8;
                            set.players = match (up, set.players) {
                                (true, p) if p >= most => 2,
                                (true, p) => p + 1,
                                (false, p) if p <= 2 => most,
                                (false, p) => p - 1,
                            }
                        }
                        1 => {
                            let i = LIVES.iter().position(|&l| l == set.life).unwrap_or(0);
                            let n = LIVES.len();
                            set.life = LIVES[if up { (i + 1) % n } else { (i + n - 1) % n }];
                        }
                        2 => set.facing = !set.facing,
                        _ => set.takes_life = !set.takes_life,
                    }
                    app.view = View::NewGame { set, row };
                }
                Event::Centre => {
                    app.game = Game::new(set);
                    app.picked = 0;
                    app.game.save();
                    app.view = View::Table;
                }
                Event::Menu(i) => {
                    app.view = View::Table;
                    menu_item(&mut app, i, now);
                }
                _ => {}
            },
            View::Spin { at, steps, next } => match event {
                Event::Timeout if now >= next => {
                    let at = (at + 1) % players;
                    let steps = steps - 1;
                    if steps == 0 {
                        app.picked = at;
                        app.view = View::Table;
                        app.say(now, |b| {
                            let _ = write!(b, "Player {} starts", at + 1);
                        });
                    } else {
                        // slowing to a stop
                        let slow = (SPIN_STEPS.saturating_sub(steps) as u64).pow(2) * 3;
                        app.view = View::Spin { at, steps, next: now + 60 + slow };
                    }
                }
                Event::Timeout => {}
                _ => app.view = View::Table,
            },
        }
    }
}

/// The menu's items, from the table.
fn menu_item(app: &mut App, i: u32, now: u64) {
    let players = app.game.players();
    match i {
        0 => app.view = View::NewGame { set: app.game.set, row: 0 },
        1 => {
            let steps = SPIN_STEPS + random_below(players as u32);
            app.view = View::Spin { at: app.picked, steps, next: now + 60 };
        }
        2 => {
            let p = app.picked as u8;
            app.game.monarch = if app.game.monarch == Some(p) { None } else { Some(p) };
            app.game.save();
        }
        3 => app.view = View::History { top: 0 },
        4 => match app.game.undo() {
            Some(c) => {
                app.game.save();
                app.say(now, |b| {
                    let _ = write!(b, "undid P{} {:+}", c.player + 1, c.delta);
                });
            }
            None => app.say(now, |b| {
                let _ = b.write_str("nothing to undo");
            }),
        },
        5 => {
            app.game = Game::new(app.game.set);
            app.game.save();
        }
        _ => {}
    }
}

maki_app::main!(main);
