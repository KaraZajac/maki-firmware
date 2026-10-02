//! Sudoku: fill the grid so that every row, column and box holds each digit from 1 to 9 once.
//! The puzzles are made on maki from its random number generator, each with one solution alone,
//! at four levels graded by what solving them takes (`puzzle`): easy needs hidden singles alone,
//! medium naked singles too, hard locked candidates and pairs and triples, and expert more than
//! those. One of each is made ahead and kept, while maki has nothing else to do, so a new puzzle
//! is there at once.
//!
//! Left and right and the jog dial on maki's side move; the centre opens the picker beside the
//! grid, whose left column writes a digit and right column pencils marks in, and pressing out of
//! either side closes it. The game you left is kept, the clock stopped while you're away, and
//! your best time at each level; mistakes are shown only when you ask for them (the menu).

#![no_std]

mod puzzle;

use core::fmt::Write;

use maki_app::*;
use puzzle::{Digits, Grid, LEVELS, Level, Maker, PEERS};

/// A cell's inside, in pixels, and the step from one cell to the next: a line between them,
/// solid round the boxes and dotted inside them. The grid is 109 pixels square, with a panel
/// beside it.
const CELL: i32 = 11;
const STEP: i32 = CELL + 1;
const GRID: i32 = 9 * STEP + 1;
/// Where the panel starts: the picker's two columns, or the level, the clock and the marks.
const PANEL: i32 = GRID + 1;
/// A picker row's height and a column's width: ten rows, 1 to 9 and clearing.
const ROW: i32 = 11;
const COLUMN: i32 = 9;
/// maki's fonts draw a digit's top three rows below where they're told: Bold and Regular digits
/// are nine rows tall, Small ones seven.
const ABOVE: i32 = 3;
/// A dotted line across the grid, and one down it, as `screen::blit` takes them.
const DOTS_ACROSS: [u8; 14] = [0xaa; 14];
const DOTS_DOWN: [u8; GRID as usize] = {
    let mut d = [0u8; GRID as usize];
    let mut i = 0;
    while i < GRID as usize {
        d[i] = 0x80;
        i += 2;
    }
    d
};
/// How long the owner's been still before maki makes puzzles ahead, and how long it works on
/// them before it looks for a press again.
const QUIET_MS: u64 = 1500;
const BATCH_MS: u64 = 60;
/// The most steps between looks, whatever the clock says.
const BATCH: u32 = 12;

const NAMES: [&str; 4] = ["Easy", "Medium", "Hard", "Expert"];

/// Where cell `i` of a row or column starts, from the grid's edge.
fn at(i: usize) -> i32 { 1 + i as i32 * STEP }

fn bit(d: u8) -> Digits { 1 << d }

/// "4:05", or "1:02:03" past an hour.
fn clock(seconds: u64, out: &mut Buf<16>) {
    let (h, m, s) = (seconds / 3600, seconds / 60 % 60, seconds % 60);
    let _ = if h > 0 { write!(out, "{h}:{m:02}:{s:02}") } else { write!(out, "{m}:{s:02}") };
}

/// A puzzle being played.
struct Game {
    level: Level,
    solution: Grid,
    /// the clues' digits, 0 elsewhere
    clues: Grid,
    /// the digits written in the other cells, 0 where there's none
    written: Grid,
    /// pencil marks, bit d for d
    marks: [Digits; 81],
    cursor: usize,
    solved: bool,
    /// milliseconds played before `since`, and when the clock last started (while it runs)
    played: u64,
    since: Option<u64>,
}

/// A game, as storage keeps it: the format, the level, the cursor, whether it's solved, the
/// seconds played (u32), the solution, which cells are clues (a bit each, cell 0 the lowest of
/// the first byte), the digits written, and the marks (u16 each).
const GAME: usize = 8 + 81 + 11 + 81 + 162;
const FORMAT: u8 = 1;

/// A puzzle made ahead, as storage keeps it: the solution, and which cells are clues.
const READY: usize = 81 + 11;

fn pack_clues(clues: &Grid, out: &mut [u8]) {
    for (c, &d) in clues.iter().enumerate() {
        if d != 0 {
            out[c / 8] |= 1 << (c % 8);
        }
    }
}

/// The clues of `solution` where `bits` says, if it's a whole sudoku and they're enough to
/// make one (17 at least).
fn unpack(solution: &[u8], bits: &[u8]) -> Option<(Grid, Grid)> {
    let solution: Grid = solution.try_into().ok()?;
    if !puzzle::complete(&solution) {
        return None;
    }
    let mut clues = [0; 81];
    for (c, d) in clues.iter_mut().enumerate() {
        if bits.get(c / 8)? & 1 << (c % 8) != 0 {
            *d = solution[c];
        }
    }
    (clues.iter().filter(|&&d| d != 0).count() >= 17).then_some((clues, solution))
}

impl Game {
    fn new(level: Level, clues: Grid, solution: Grid) -> Game {
        Game {
            level,
            solution,
            clues,
            written: [0; 81],
            marks: [0; 81],
            cursor: 40,
            solved: false,
            played: 0,
            since: None,
        }
    }

    fn load() -> Option<Game> {
        let mut b = [0u8; GAME];
        if storage::get("game", &mut b)? != GAME || b[0] != FORMAT || b[1] > 3 || b[2] > 80 || b[3] > 1 {
            return None;
        }
        let (clues, solution) = unpack(&b[8..89], &b[89..100])?;
        let mut g = Game::new(LEVELS[b[1] as usize], clues, solution);
        g.cursor = b[2] as usize;
        g.solved = b[3] == 1;
        g.played = u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as u64 * 1000;
        for c in 0..81 {
            let (d, m) = (b[100 + c], u16::from_le_bytes([b[181 + 2 * c], b[182 + 2 * c]]));
            if d > 9 || m & !puzzle::ALL != 0 {
                return None;
            }
            // a clue's cell has nothing written or marked
            if clues[c] == 0 {
                g.written[c] = d;
                g.marks[c] = m;
            }
        }
        Some(g)
    }

    fn save(&self) {
        let mut b = [0u8; GAME];
        b[0] = FORMAT;
        b[1] = self.level as u8;
        b[2] = self.cursor as u8;
        b[3] = self.solved as u8;
        b[4..8].copy_from_slice(&(self.seconds().min(u32::MAX as u64) as u32).to_le_bytes());
        b[8..89].copy_from_slice(&self.solution);
        pack_clues(&self.clues, &mut b[89..100]);
        b[100..181].copy_from_slice(&self.written);
        for (c, m) in self.marks.iter().enumerate() {
            b[181 + 2 * c..183 + 2 * c].copy_from_slice(&m.to_le_bytes());
        }
        let _ = storage::set("game", &b);
    }

    fn seconds(&self) -> u64 { (self.played + self.since.map_or(0, |t| millis().saturating_sub(t))) / 1000 }

    fn clock_start(&mut self) {
        if !self.solved && self.since.is_none() {
            self.since = Some(millis());
        }
    }

    fn clock_stop(&mut self) {
        if let Some(t) = self.since.take() {
            self.played += millis().saturating_sub(t);
        }
    }

    /// The digit in cell `c`, a clue or written.
    fn digit(&self, c: usize) -> u8 { self.clues[c] | self.written[c] }

    /// Writes `d` (0 to clear) in the cursor's cell: its marks go, and so does `d` from the marks
    /// of every cell that sees it.
    fn write(&mut self, d: u8) {
        let c = self.cursor;
        if self.clues[c] != 0 || self.solved {
            return;
        }
        self.written[c] = d;
        self.marks[c] = 0;
        if d != 0 {
            for &p in &PEERS[c] {
                self.marks[p as usize] &= !bit(d);
            }
        }
    }

    /// Pencils `d` into the cursor's cell, or out of it; 0 clears them all.
    fn mark(&mut self, d: u8) {
        let c = self.cursor;
        if self.clues[c] != 0 || self.written[c] != 0 || self.solved {
            return;
        }
        self.marks[c] = if d == 0 { 0 } else { self.marks[c] ^ bit(d) };
    }

    fn full(&self) -> bool { (0..81).all(|c| self.digit(c) != 0) }

    fn right(&self) -> bool { (0..81).all(|c| self.digit(c) == self.solution[c]) }

    fn wrong(&self, c: usize) -> bool { self.written[c] != 0 && self.written[c] != self.solution[c] }

    fn walk(&mut self, by: i32) { self.cursor = (self.cursor as i32 + by).rem_euclid(81) as usize; }

    fn walk_rows(&mut self, by: i32) {
        let r = (self.cursor / 9) as i32 + by;
        self.cursor = r.rem_euclid(9) as usize * 9 + self.cursor % 9;
    }
}

/// The puzzle made ahead for `level`, if there is one: its clues and its solution.
fn ready(level: Level) -> Option<(Grid, Grid)> {
    let mut b = [0u8; READY];
    if storage::get(READY_KEYS[level as usize], &mut b)? != READY {
        return None;
    }
    unpack(&b[..81], &b[81..])
}

const READY_KEYS: [&str; 4] = ["ready0", "ready1", "ready2", "ready3"];

fn keep_ready(level: Level, clues: &Grid, solution: &Grid) {
    let mut b = [0u8; READY];
    b[..81].copy_from_slice(solution);
    pack_clues(clues, &mut b[81..]);
    let _ = storage::set(READY_KEYS[level as usize], &b);
}

/// Each level's best time, in seconds (0 for none yet), as storage keeps them: four u32s.
fn best_times() -> [u32; 4] {
    let mut b = [0u8; 16];
    match storage::get("best", &mut b) {
        Some(16) => {
            core::array::from_fn(|i| u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]))
        }
        _ => [0; 4],
    }
}

fn keep_best_times(best: &[u32; 4]) {
    let mut b = [0u8; 16];
    for (i, t) in best.iter().enumerate() {
        b[4 * i..4 * i + 4].copy_from_slice(&t.to_le_bytes());
    }
    let _ = storage::set("best", &b);
}

/// What's on the screen.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Play,
    /// The picker beside the grid: the row picked (0 to 8 the digits, 9 clearing), in the
    /// pencil column or the one that writes.
    Pick {
        row: usize,
        pencil: bool,
    },
    /// A new puzzle's level being chosen (4: back to the one being played).
    Choose(usize),
    /// Waiting for a puzzle at this level to be made.
    Making(Level),
}

struct App {
    game: Option<Game>,
    screen: Screen,
    /// the last digit picked, where the picker opens next
    last: usize,
    /// a note over the grid until the next press: the grid's full but not right
    not_yet: bool,
    show_mistakes: bool,
    /// the levels with a puzzle made ahead
    ready: [bool; 4],
    best: [u32; 4],
    maker: Maker,
    /// when the owner last pressed something
    pressed: u64,
    /// whether the app's in front: something else has the screen between Hidden and Shown
    shown: bool,
    /// the minutes the panel showed when last drawn
    drawn: Option<u64>,
}

impl App {
    fn load() -> App {
        let mut seed = [0u8; 16];
        random(&mut seed);
        let game = Game::load();
        let screen = if game.is_some() { Screen::Play } else { Screen::Choose(0) };
        let mut app = App {
            game,
            screen,
            last: 0,
            not_yet: false,
            show_mistakes: storage::get_u32("mistakes", 0) == 1,
            ready: LEVELS.map(|l| ready(l).is_some()),
            best: best_times(),
            maker: Maker::new(seed, Level::Easy),
            pressed: 0,
            shown: true,
            drawn: None,
        };
        app.sync_clock();
        app
    }

    /// The clock runs while the puzzle's in front and unsolved, and stops otherwise.
    fn sync_clock(&mut self) {
        let playing = self.shown && matches!(self.screen, Screen::Play | Screen::Pick { .. });
        if let Some(g) = self.game.as_mut() {
            if playing {
                g.clock_start();
            } else {
                g.clock_stop();
            }
        }
    }

    fn set_menu(&self) {
        let shown = if self.show_mistakes { "Hide mistakes" } else { "Show mistakes" };
        let _ = menu(&["New puzzle", shown, "Start over", "Forget best times"]);
    }

    /// The level to make a puzzle for next, if any wants one: the one waited for, else the one
    /// picked in the chooser or being played, else the quickest to make.
    fn wanted(&self) -> Option<Level> {
        let first = match self.screen {
            Screen::Making(level) => return Some(level),
            Screen::Choose(i) => LEVELS.get(i).copied(),
            _ => self.game.as_ref().map(|g| g.level),
        };
        first
            .into_iter()
            .chain([Level::Easy, Level::Medium, Level::Expert, Level::Hard])
            .find(|&l| !self.ready[l as usize])
    }

    /// How long to wait for a press: no time at all while a puzzle's waited for, a moment
    /// while there are puzzles to make ahead, and until the clock's next minute while it runs.
    fn timeout(&self) -> Option<u32> {
        let now = millis();
        let work = match (self.screen, self.wanted()) {
            (Screen::Making(_), _) => Some(0),
            (_, Some(_)) => Some((self.pressed + QUIET_MS).saturating_sub(now)),
            _ => None,
        };
        let tick = self.game.as_ref().and_then(|g| {
            let ms = g.played + now.saturating_sub(g.since?);
            Some(60_000 - ms % 60_000)
        });
        match (work, tick) {
            (Some(a), Some(b)) => Some(a.min(b) as u32),
            (a, b) => a.or(b).map(|t| t as u32),
        }
    }

    /// Works on puzzles for a moment: those made ahead are kept, and one waited for is begun.
    /// Whether that changed what's on the screen.
    fn work(&mut self) -> bool {
        let start = millis();
        let mut changed = matches!(self.screen, Screen::Making(_));
        for _ in 0..BATCH {
            let Some(level) = self.wanted() else { break };
            self.maker.make(level);
            if let Some((made, clues, solution)) = self.maker.step() {
                if !self.ready[made as usize] {
                    keep_ready(made, &clues, &solution);
                    self.ready[made as usize] = true;
                    changed |= matches!(self.screen, Screen::Choose(_));
                }
                if self.screen == Screen::Making(made) {
                    self.begin(made);
                    break;
                }
            }
            if millis().saturating_sub(start) >= BATCH_MS {
                break;
            }
        }
        changed
    }

    /// The minutes the panel shows, while it shows them.
    fn minutes(&self) -> Option<u64> {
        let g = self.game.as_ref()?;
        matches!(self.screen, Screen::Play).then(|| g.seconds() / 60)
    }

    /// A new game at `level`, from the puzzle made ahead for it; else waits for one.
    fn begin(&mut self, level: Level) {
        match ready(level) {
            Some((clues, solution)) => {
                storage::delete(READY_KEYS[level as usize]);
                self.ready[level as usize] = false;
                let mut g = Game::new(level, clues, solution);
                g.clock_start();
                g.save();
                self.game = Some(g);
                self.screen = Screen::Play;
                self.not_yet = false;
            }
            None => {
                self.ready[level as usize] = false;
                self.screen = Screen::Making(level);
            }
        }
    }

    /// After a digit's written: solved, or full and not right.
    fn check(&mut self) {
        let Some(g) = self.game.as_mut() else { return };
        if !g.full() {
            return;
        }
        if !g.right() {
            self.not_yet = true;
            return;
        }
        g.clock_stop();
        g.solved = true;
        let (l, s) = (g.level as usize, g.seconds().clamp(1, u32::MAX as u64) as u32);
        if self.best[l] == 0 || s < self.best[l] {
            self.best[l] = s;
            keep_best_times(&self.best);
        }
        g.save();
    }

    fn press(&mut self, event: Event) {
        self.pressed = millis();
        if self.not_yet {
            self.not_yet = false;
            return;
        }
        match self.screen {
            Screen::Play => self.play(event),
            Screen::Pick { row, pencil } => self.pick(event, row, pencil),
            Screen::Choose(i) => {
                let n = if self.game.as_ref().is_some_and(|g| !g.solved) { 5 } else { 4 };
                match event {
                    Event::Left | Event::Up => self.screen = Screen::Choose((i + n - 1) % n),
                    Event::Right | Event::Down => self.screen = Screen::Choose((i + 1) % n),
                    Event::Centre if i == 4 => self.screen = Screen::Play,
                    Event::Centre => self.begin(LEVELS[i.min(3)]),
                    _ => {}
                }
            }
            // the puzzle's still made meanwhile, and begun once the level's chosen again
            Screen::Making(level) => {
                if matches!(event, Event::Centre | Event::Left | Event::Right) {
                    self.screen = Screen::Choose(level as usize);
                }
            }
        }
    }

    fn play(&mut self, event: Event) {
        let Some(g) = self.game.as_mut() else {
            self.screen = Screen::Choose(0);
            return;
        };
        if g.solved {
            if event == Event::Centre {
                self.screen = Screen::Choose(g.level as usize);
            }
            return;
        }
        match event {
            Event::Left => g.walk(-1),
            Event::Right => g.walk(1),
            Event::Up => g.walk_rows(-1),
            Event::Down => g.walk_rows(1),
            Event::Centre if g.clues[g.cursor] == 0 => {
                let d = g.written[g.cursor] as usize;
                self.screen = Screen::Pick { row: if d > 0 { d - 1 } else { self.last }, pencil: false };
            }
            _ => {}
        }
    }

    fn pick(&mut self, event: Event, row: usize, pencil: bool) {
        let Some(g) = self.game.as_mut() else { return };
        match event {
            Event::Up => self.screen = Screen::Pick { row: (row + 9) % 10, pencil },
            Event::Down => self.screen = Screen::Pick { row: (row + 1) % 10, pencil },
            // out of either side closes it
            Event::Left if pencil => self.screen = Screen::Pick { row, pencil: false },
            Event::Right if !pencil => self.screen = Screen::Pick { row, pencil: true },
            Event::Left | Event::Right => self.screen = Screen::Play,
            Event::Centre => {
                let d = if row < 9 { row as u8 + 1 } else { 0 };
                if row < 9 {
                    self.last = row;
                }
                if pencil {
                    g.mark(d);
                } else {
                    g.write(d);
                    self.screen = Screen::Play;
                    self.check();
                }
            }
            _ => {}
        }
    }

    fn draw(&mut self) {
        self.drawn = self.minutes();
        screen::clear(Color::Dark);
        match (self.screen, &self.game) {
            (Screen::Choose(i), _) => draw_choose(self, i),
            (Screen::Making(level), _) => draw_making(level, &self.maker),
            (_, Some(g)) => {
                draw_grid(g, self.show_mistakes, matches!(self.screen, Screen::Pick { .. }));
                match self.screen {
                    Screen::Pick { row, pencil } => draw_picker(g, row, pencil),
                    _ => draw_panel(g),
                }
                if g.solved {
                    let mut line = Buf::<32>::new();
                    let mut t = Buf::<16>::new();
                    clock(g.seconds(), &mut t);
                    let best = self.best[g.level as usize];
                    let _ = if best as u64 >= g.seconds() {
                        write!(line, "{}, your best yet", t.as_str())
                    } else {
                        let mut b = Buf::<16>::new();
                        clock(best as u64, &mut b);
                        write!(line, "{}, best {}", t.as_str(), b.as_str())
                    };
                    note("Solved", line.as_str(), "centre: another");
                } else if self.not_yet {
                    note("Not quite", "a digit's wrong", "any key: back to it");
                }
            }
            _ => {}
        }
        screen::present();
    }
}

fn draw_grid(g: &Game, show_mistakes: bool, picking: bool) {
    for k in 0..10 {
        let p = k * STEP;
        if k % 3 == 0 {
            screen::fill_rect(p, 0, 1, GRID, Color::Light);
            screen::fill_rect(0, p, GRID, 1, Color::Light);
        } else {
            screen::blit(p, 0, 1, GRID, &DOTS_DOWN, Color::Light);
            screen::blit(0, p, GRID, 1, &DOTS_ACROSS, Color::Light);
        }
    }
    for c in 0..81 {
        let (x, y) = (at(c % 9), at(c / 9));
        let d = g.digit(c);
        if d != 0 {
            let mut s = Buf::<2>::new();
            let _ = write!(s, "{d}");
            // the clues bold, what's written plain
            let style = if g.clues[c] != 0 { Style::Bold } else { Style::Regular };
            let w = screen::text_width(s.as_str(), style);
            screen::text(x + (CELL - w + 1) / 2, y + 1 - ABOVE, s.as_str(), style, Color::Light);
            // struck through
            if show_mistakes && g.wrong(c) {
                screen::line(x, y + CELL - 1, x + CELL - 1, y, Color::Invert);
                screen::line(x + 1, y + CELL - 1, x + CELL - 1, y + 1, Color::Invert);
            }
        } else {
            // pencil marks as dots, where the digits are on a phone's keypad
            for m in 1..=9u8 {
                if g.marks[c] & bit(m) != 0 {
                    let i = (m - 1) as i32;
                    screen::fill_rect(x + 2 + i % 3 * 3, y + 2 + i / 3 * 3, 2, 2, Color::Light);
                }
            }
        }
    }
    if !g.solved || picking {
        screen::fill_rect(at(g.cursor % 9), at(g.cursor / 9), CELL, CELL, Color::Invert);
    }
}

/// Small squares for a level, filled as far as it goes: one for easy, four for expert.
fn pips(x: i32, y: i32, size: i32, level: usize, color: Color) {
    for i in 0..4 {
        let px = x + i as i32 * (size + 2);
        if i <= level {
            screen::fill_rect(px, y, size, size, color);
        } else {
            screen::rect(px, y, size, size, color);
        }
    }
}

/// Beside the grid: the level, the minutes played, and the marks of the cursor's cell as
/// digits, where the dots in the cell are.
fn draw_panel(g: &Game) {
    pips(PANEL, 1, 3, g.level as usize, Color::Light);
    let mut line = Buf::<8>::new();
    let m = g.seconds() / 60;
    let _ = if m >= 60 { write!(line, "{}h{:02}", m / 60, m % 60) } else { write!(line, "{m}m") };
    screen::text(PANEL, 8 - ABOVE, line.as_str(), Style::Small, Color::Light);
    let marks = if g.digit(g.cursor) == 0 { g.marks[g.cursor] } else { 0 };
    for d in 1..=9u8 {
        if marks & bit(d) != 0 {
            let i = (d - 1) as i32;
            let mut s = Buf::<2>::new();
            let _ = write!(s, "{d}");
            screen::text(PANEL + i % 3 * 6, 24 + i / 3 * 9 - ABOVE, s.as_str(), Style::Small, Color::Light);
        }
    }
}

/// The picker: the digits to write on the left, those to pencil in on the right, each the
/// cell's own boxed, and an x below each to clear.
fn draw_picker(g: &Game, row: usize, pencil: bool) {
    let c = g.cursor;
    for r in 0..10 {
        let y = r as i32 * ROW;
        for (col, style) in [(0, Style::Regular), (1, Style::Small)] {
            let x = PANEL + col * COLUMN;
            if r == 9 {
                screen::line(x + 2, y + 3, x + 6, y + 7, Color::Light);
                screen::line(x + 2, y + 7, x + 6, y + 3, Color::Light);
            } else {
                let d = r as u8 + 1;
                let mut s = Buf::<2>::new();
                let _ = write!(s, "{d}");
                let w = screen::text_width(s.as_str(), style);
                let dy = if col == 0 { 1 } else { 2 };
                screen::text(x + (COLUMN - w + 1) / 2, y + dy - ABOVE, s.as_str(), style, Color::Light);
                let has = if col == 0 { g.written[c] == d } else { g.marks[c] & bit(d) != 0 };
                if has {
                    screen::rect(x, y, COLUMN, ROW, Color::Light);
                }
            }
            if r == row && (col == 1) == pencil {
                screen::fill_rect(x, y, COLUMN, ROW, Color::Invert);
            }
        }
    }
}

fn draw_choose(app: &App, i: usize) {
    screen::text_centred(0, "New puzzle", Style::Bold, Color::Light);
    let in_progress = app.game.as_ref().is_some_and(|g| !g.solved);
    for (l, name) in NAMES.iter().enumerate() {
        let y = 18 + l as i32 * 16;
        pips(4, y + 6, 4, l, Color::Light);
        screen::text(32, y, name, Style::Regular, Color::Light);
        if app.best[l] > 0 {
            let mut t = Buf::<16>::new();
            clock(app.best[l] as u64, &mut t);
            let w = screen::text_width(t.as_str(), Style::Small);
            screen::text(WIDTH - 4 - w, y + 2, t.as_str(), Style::Small, Color::Light);
        }
    }
    if in_progress {
        screen::text(32, 18 + 4 * 16, "Back to it", Style::Regular, Color::Light);
    }
    screen::fill_rect(0, 17 + i as i32 * 16, WIDTH, 16, Color::Invert);
    let below = match i {
        4 => "the puzzle you left",
        _ if app.ready[i] => "ready",
        _ => "made when you pick it",
    };
    screen::text_centred(HEIGHT - 12, below, Style::Small, Color::Light);
}

fn draw_making(level: Level, maker: &Maker) {
    screen::text_centred(14, "Making one", Style::Bold, Color::Light);
    let name = NAMES[level as usize];
    let w = 28 + screen::text_width(name, Style::Regular);
    pips((WIDTH - w) / 2, 42, 4, level as usize, Color::Light);
    screen::text((WIDTH - w) / 2 + 28, 36, name, Style::Regular, Color::Light);
    screen::rect(14, 60, 100, 6, Color::Light);
    screen::fill_rect(15, 61, maker.tried() as i32 * 98 / 81, 4, Color::Light);
    let mut line = Buf::<24>::new();
    let _ = write!(line, "try {}", maker.tries.max(1));
    screen::text_centred(72, line.as_str(), Style::Small, Color::Light);
    screen::text_centred(HEIGHT - 12, "centre: back", Style::Small, Color::Light);
}

/// A note over the grid: a heading and two small lines.
fn note(top: &str, middle: &str, bottom: &str) {
    screen::fill_rect(6, 30, WIDTH - 12, 52, Color::Dark);
    screen::rect(6, 30, WIDTH - 12, 52, Color::Light);
    screen::text_centred(34, top, Style::Bold, Color::Light);
    screen::text_centred(52, middle, Style::Small, Color::Light);
    screen::text_centred(66, bottom, Style::Small, Color::Light);
}

fn main() {
    let mut app = App::load();
    app.set_menu();
    let mut redraw = true;
    loop {
        if redraw {
            app.draw();
        }
        let event = wait(app.timeout());
        redraw = true;
        match event {
            // puzzles made meanwhile, and the clock's minutes: drawn again only if what's shown
            // changed
            Event::Timeout => {
                let working = matches!(app.screen, Screen::Making(_)) || millis() >= app.pressed + QUIET_MS;
                redraw = working && app.work() || app.minutes() != app.drawn;
            }
            Event::Left | Event::Right | Event::Centre | Event::Up | Event::Down => app.press(event),
            Event::Menu(0) => {
                app.pressed = millis();
                app.not_yet = false;
                app.screen = Screen::Choose(app.game.as_ref().map_or(0, |g| g.level as usize));
            }
            Event::Menu(1) => {
                app.show_mistakes = !app.show_mistakes;
                let _ = storage::set_u32("mistakes", app.show_mistakes as u32);
                app.set_menu();
            }
            Event::Menu(2) => {
                if let Some(g) = app.game.as_mut().filter(|g| !g.solved) {
                    g.written = [0; 81];
                    g.marks = [0; 81];
                    g.save();
                    app.not_yet = false;
                    app.screen = Screen::Play;
                }
            }
            Event::Menu(3) => {
                app.best = [0; 4];
                storage::delete("best");
            }
            Event::Hidden => {
                app.shown = false;
                app.sync_clock();
                if let Some(g) = app.game.as_ref() {
                    g.save();
                }
            }
            Event::Shown => app.shown = true,
            Event::Exit => {
                app.shown = false;
                app.sync_clock();
                if let Some(g) = app.game.as_ref() {
                    g.save();
                }
                return;
            }
            _ => {}
        }
        app.sync_clock();
    }
}

maki_app::main!(main);
