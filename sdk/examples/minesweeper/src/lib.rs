//! Minesweeper: twelve mines hidden in a field of 80. Left and right and the jog dial on maki's
//! side move; the centre steps. A number says how many mines touch its square, and a square with
//! none opens the squares around it. Step on a number whose mines are all flagged, and the rest
//! around it open. Flag a mine from the menu. The first step is always safe; the clock starts
//! with it, and the best time is kept. The game waits for you when you leave.

#![no_std]

use core::fmt::Write;

use maki_app::*;

const COLS: usize = 10;
const ROWS: usize = 8;
const N: usize = COLS * ROWS;
const MINES: usize = 12;
/// A square's side, in pixels: the field fits below a line for the count and the clock.
const CELL: i32 = 12;
const LEFT: i32 = (WIDTH - COLS as i32 * CELL) / 2;
const TOP: i32 = HEIGHT - ROWS as i32 * CELL;

const MINE: u8 = 1;
const OPEN: u8 = 2;
const FLAG: u8 = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    /// no step yet: the mines aren't laid
    Fresh,
    Playing,
    Lost,
    Won,
}

struct Game {
    cells: [u8; N],
    cursor: usize,
    state: State,
    /// the square that was stepped on, when a mine was
    boom: Option<usize>,
    /// milliseconds played before `since`, and when the clock last started (while it runs)
    played: u64,
    since: Option<u64>,
}

fn neighbours(i: usize) -> impl Iterator<Item = usize> {
    let (r, c) = ((i / COLS) as i32, (i % COLS) as i32);
    (-1..=1)
        .flat_map(move |dr| (-1..=1).map(move |dc| (r + dr, c + dc)))
        .filter(move |&(rr, cc)| {
            (rr, cc) != (r, c) && rr >= 0 && cc >= 0 && rr < ROWS as i32 && cc < COLS as i32
        })
        .map(|(rr, cc)| rr as usize * COLS + cc as usize)
}

impl Game {
    fn new() -> Game {
        Game {
            cells: [0; N],
            cursor: N / 2 - COLS / 2,
            state: State::Fresh,
            boom: None,
            played: 0,
            since: None,
        }
    }

    fn mines_around(&self, i: usize) -> usize { neighbours(i).filter(|&n| self.cells[n] & MINE != 0).count() }

    fn flags_around(&self, i: usize) -> usize { neighbours(i).filter(|&n| self.cells[n] & FLAG != 0).count() }

    fn flags(&self) -> usize { self.cells.iter().filter(|&&c| c & FLAG != 0).count() }

    fn seconds(&self) -> u64 { (self.played + self.since.map_or(0, |t| millis().saturating_sub(t))) / 1000 }

    fn clock_stop(&mut self) {
        if let Some(t) = self.since.take() {
            self.played += millis().saturating_sub(t);
        }
    }

    /// Lays the mines anywhere but the first step and the squares around it, so it opens some.
    fn lay(&mut self, first: usize) {
        let mut spare = [0u8; N];
        let mut n = 0;
        for i in 0..N {
            if i != first && !neighbours(first).any(|x| x == i) {
                spare[n] = i as u8;
                n += 1;
            }
        }
        for _ in 0..MINES {
            let k = random_below(n as u32) as usize;
            self.cells[spare[k] as usize] |= MINE;
            spare[k] = spare[n - 1];
            n -= 1;
        }
        self.state = State::Playing;
        self.since = Some(millis());
    }

    /// Opens a square, and around any square with no mines near it.
    fn open(&mut self, i: usize) {
        let mut todo = [0u8; N];
        let (mut n, mut seen) = (0, [false; N]);
        todo[0] = i as u8;
        n += 1;
        seen[i] = true;
        while n > 0 {
            n -= 1;
            let j = todo[n] as usize;
            if self.cells[j] & (OPEN | FLAG) != 0 {
                continue;
            }
            self.cells[j] |= OPEN;
            if self.mines_around(j) == 0 {
                for k in neighbours(j) {
                    if !seen[k] {
                        seen[k] = true;
                        todo[n] = k as u8;
                        n += 1;
                    }
                }
            }
        }
    }

    fn step(&mut self) {
        let i = self.cursor;
        if self.state == State::Fresh {
            self.lay(i);
        }
        let c = self.cells[i];
        if c & FLAG != 0 {
            return;
        }
        let around: &[usize] = &if c & OPEN != 0 {
            // a number with its mines flagged: the rest around it, as if stepped on
            if self.mines_around(i) == 0 || self.flags_around(i) != self.mines_around(i) {
                return;
            }
            let mut ns = [usize::MAX; 8];
            for (k, n) in neighbours(i).enumerate() {
                ns[k] = n;
            }
            ns
        } else {
            let mut ns = [usize::MAX; 8];
            ns[0] = i;
            ns
        };
        for &j in around.iter().filter(|&&j| j != usize::MAX) {
            if self.cells[j] & (OPEN | FLAG) != 0 {
                continue;
            }
            if self.cells[j] & MINE != 0 {
                self.state = State::Lost;
                self.boom = Some(j);
                self.clock_stop();
                return;
            }
            self.open(j);
        }
        if self.cells.iter().all(|&c| c & MINE != 0 || c & OPEN != 0) {
            self.state = State::Won;
            for c in self.cells.iter_mut().filter(|c| **c & MINE != 0) {
                *c |= FLAG;
            }
            self.clock_stop();
        }
    }

    fn flag(&mut self) {
        if matches!(self.state, State::Playing | State::Fresh) && self.cells[self.cursor] & OPEN == 0 {
            self.cells[self.cursor] ^= FLAG;
        }
    }

    fn walk(&mut self, by: i32) { self.cursor = (self.cursor as i32 + by).rem_euclid(N as i32) as usize; }

    fn walk_rows(&mut self, by: i32) {
        let r = (self.cursor / COLS) as i32 + by;
        self.cursor = r.rem_euclid(ROWS as i32) as usize * COLS + self.cursor % COLS;
    }

    // storage: the squares, the cursor, the state, the seconds played
    fn load() -> Game {
        let mut b = [0u8; N + 6];
        match storage::get("game", &mut b) {
            Some(n) if n == b.len() && (b[N] as usize) < N && b[N + 1] <= 3 => {
                let mut g = Game::new();
                g.cells.copy_from_slice(&b[..N]);
                g.cursor = b[N] as usize;
                g.state = [State::Fresh, State::Playing, State::Lost, State::Won][b[N + 1] as usize];
                g.played = u32::from_le_bytes([b[N + 2], b[N + 3], b[N + 4], b[N + 5]]) as u64 * 1000;
                if g.state == State::Playing {
                    g.since = Some(millis());
                }
                g
            }
            _ => Game::new(),
        }
    }

    fn save(&self) {
        let mut b = [0u8; N + 6];
        b[..N].copy_from_slice(&self.cells);
        b[N] = self.cursor as u8;
        b[N + 1] = self.state as u8;
        b[N + 2..].copy_from_slice(&(self.seconds() as u32).to_le_bytes());
        let _ = storage::set("game", &b);
    }
}

fn square(g: &Game, i: usize) {
    let (x, y) = (LEFT + (i % COLS) as i32 * CELL, TOP + (i / COLS) as i32 * CELL);
    let c = g.cells[i];
    let over = matches!(g.state, State::Lost | State::Won);
    let shown_mine = c & MINE != 0 && over && c & FLAG == 0;
    let covered = c & OPEN == 0 && !shown_mine;
    if g.boom == Some(i) {
        screen::fill_rect(x, y, CELL, CELL, Color::Light);
        screen::fill_rect(x + 3, y + 3, CELL - 6, CELL - 6, Color::Dark);
    } else if shown_mine {
        screen::fill_rect(x + 3, y + 3, CELL - 6, CELL - 6, Color::Light);
    } else if covered {
        screen::fill_rect(x + 1, y + 1, CELL - 2, CELL - 2, Color::Light);
        if c & FLAG != 0 {
            screen::fill_rect(x + 7, y + 3, 1, 7, Color::Dark);
            screen::fill_rect(x + 3, y + 3, 4, 3, Color::Dark);
        }
    } else {
        let n = g.mines_around(i);
        if n > 0 {
            let mut d = Buf::<2>::new();
            let _ = write!(d, "{n}");
            let w = screen::text_width(d.as_str(), Style::Small);
            screen::text(x + (CELL - w) / 2, y, d.as_str(), Style::Small, Color::Light);
        }
    }
    if i == g.cursor && !over {
        if covered {
            screen::rect(x + 2, y + 2, CELL - 4, CELL - 4, Color::Dark);
        } else {
            screen::rect(x, y, CELL, CELL, Color::Light);
        }
    }
}

fn note(top: &str, bottom: &str) {
    screen::fill_rect(10, 40, WIDTH - 20, 40, Color::Dark);
    screen::rect(10, 40, WIDTH - 20, 40, Color::Light);
    screen::text_centred(44, top, Style::Bold, Color::Light);
    screen::text_centred(62, bottom, Style::Small, Color::Light);
}

fn draw(g: &Game, best: u32) {
    screen::clear(Color::Dark);
    let mut line = Buf::<24>::new();
    let _ = write!(line, "mines {}", MINES as i32 - g.flags() as i32);
    screen::text(LEFT, 0, line.as_str(), Style::Small, Color::Light);
    line.clear();
    match g.state {
        State::Fresh if best > 0 => {
            let _ = write!(line, "best {best} s");
        }
        State::Fresh => {}
        _ => {
            let _ = write!(line, "{} s", g.seconds());
        }
    }
    screen::text(
        WIDTH - LEFT - screen::text_width(line.as_str(), Style::Small),
        0,
        line.as_str(),
        Style::Small,
        Color::Light,
    );
    for i in 0..N {
        square(g, i);
    }
    match g.state {
        State::Lost => note("Boom", "centre: again"),
        State::Won => {
            line.clear();
            let _ = write!(line, "cleared in {} s", g.seconds());
            note(line.as_str(), "centre: again");
        }
        _ => {}
    }
    screen::present();
}

fn main() {
    let _ = menu(&["Flag", "New game"]);
    let mut best = storage::get_u32("best", 0);
    let mut g = Game::load();
    loop {
        draw(&g, best);
        // while the clock runs, again on the next second
        let wait_ms = g
            .since
            .map(|_| (1000 - (g.played + millis().saturating_sub(g.since.unwrap_or(0))) % 1000) as u32);
        match wait(wait_ms) {
            Event::Left => g.walk(-1),
            Event::Right => g.walk(1),
            Event::Up => g.walk_rows(-1),
            Event::Down => g.walk_rows(1),
            Event::Centre => match g.state {
                State::Lost | State::Won => g = Game::new(),
                _ => {
                    g.step();
                    if g.state == State::Won {
                        let s = g.seconds() as u32;
                        if best == 0 || s < best {
                            best = s.max(1);
                            let _ = storage::set_u32("best", best);
                        }
                    }
                }
            },
            Event::Menu(0) => g.flag(),
            Event::Menu(1) => g = Game::new(),
            Event::Hidden => {
                g.clock_stop();
                g.save();
            }
            Event::Shown => {
                if g.state == State::Playing && g.since.is_none() {
                    g.since = Some(millis());
                }
            }
            Event::Exit => {
                g.save();
                return;
            }
            _ => {}
        }
    }
}

maki_app::main!(main);
