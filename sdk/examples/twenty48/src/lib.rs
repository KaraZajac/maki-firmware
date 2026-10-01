//! 2048: left and right slide the tiles sideways, the jog dial on maki's side slides them up and
//! down. Two of a kind that meet become one, worth both, and every move that moves anything brings
//! a new 2 (a 4, one time in ten). Reach 2048 and keep going if you like; the game is over when no
//! move moves anything. The game waits for you when you leave, with your best score.

#![no_std]

use core::fmt::Write;

use maki_app::*;

const N: usize = 4;
/// A tile's side and the gap between two, in pixels: the grid fits below a line for the score.
const TILE: i32 = 23;
const GAP: i32 = 2;
const GRID: i32 = N as i32 * TILE + (N as i32 - 1) * GAP;
const LEFT: i32 = (WIDTH - GRID) / 2;
const TOP: i32 = HEIGHT - GRID;
/// 2048, as a power of two
const WIN: u8 = 11;

/// The way tiles slide.
#[derive(Clone, Copy)]
enum Way {
    Left,
    Right,
    Up,
    Down,
}

const WAYS: [Way; 4] = [Way::Left, Way::Right, Way::Up, Way::Down];

/// The tiles, as powers of two: 0 is no tile, 1 a 2, 11 a 2048.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Board([[u8; N]; N]);

impl Board {
    /// The `j`th place of the `i`th line, counted from the side the tiles slide to.
    fn place(way: Way, i: usize, j: usize) -> (usize, usize) {
        match way {
            Way::Left => (i, j),
            Way::Right => (i, N - 1 - j),
            Way::Up => (j, i),
            Way::Down => (N - 1 - j, i),
        }
    }

    /// Slides every tile `way`; the points it scored, or None if nothing moved.
    fn slide(&mut self, way: Way) -> Option<u32> {
        let before = *self;
        let mut points = 0;
        for i in 0..N {
            let mut line = [0u8; N];
            for (j, t) in line.iter_mut().enumerate() {
                let (r, c) = Board::place(way, i, j);
                *t = self.0[r][c];
            }
            let (line, p) = merge(line);
            points += p;
            for (j, &t) in line.iter().enumerate() {
                let (r, c) = Board::place(way, i, j);
                self.0[r][c] = t;
            }
        }
        if *self == before { None } else { Some(points) }
    }

    fn free(&self) -> usize { self.0.iter().flatten().filter(|&&t| t == 0).count() }

    /// A new tile in a free place, at random: a 2, or one time in ten a 4.
    fn spawn(&mut self) {
        let free = self.free();
        if free == 0 {
            return;
        }
        let mut n = random_below(free as u32) as usize;
        let tile = if random_below(10) == 0 { 2 } else { 1 };
        for t in self.0.iter_mut().flatten() {
            if *t == 0 {
                if n == 0 {
                    *t = tile;
                    return;
                }
                n -= 1;
            }
        }
    }

    fn can_move(&self) -> bool {
        WAYS.iter().any(|&way| {
            let mut b = *self;
            b.slide(way).is_some()
        })
    }

    fn highest(&self) -> u8 { self.0.iter().flatten().copied().max().unwrap_or(0) }

    fn new_game() -> Board {
        let mut b = Board([[0; N]; N]);
        b.spawn();
        b.spawn();
        b
    }
}

/// One line slid to its start: the tiles close up, and two of a kind that meet become one (a tile
/// joins once a move). The points are what the new tiles are worth.
fn merge(line: [u8; N]) -> ([u8; N], u32) {
    let mut out = [0u8; N];
    let (mut n, mut points, mut joined) = (0, 0u32, false);
    for &t in line.iter().filter(|&&t| t != 0) {
        if n > 0 && out[n - 1] == t && !joined {
            out[n - 1] += 1;
            points += 1 << out[n - 1];
            joined = true;
        } else {
            out[n] = t;
            n += 1;
            joined = false;
        }
    }
    (out, points)
}

/// A game, as storage keeps it: the tiles, the score, and whether 2048's been seen.
struct Game {
    board: Board,
    score: u32,
    won: bool,
}

impl Game {
    fn new() -> Game { Game { board: Board::new_game(), score: 0, won: false } }

    fn load() -> Game {
        let mut b = [0u8; N * N + 5];
        match storage::get("game", &mut b) {
            Some(n) if n == b.len() && b[..N * N].iter().all(|&t| t <= 17) => {
                let mut board = Board([[0; N]; N]);
                for (k, t) in board.0.iter_mut().flatten().enumerate() {
                    *t = b[k];
                }
                let score = u32::from_le_bytes([b[16], b[17], b[18], b[19]]);
                if board.free() == N * N { Game::new() } else { Game { board, score, won: b[20] != 0 } }
            }
            _ => Game::new(),
        }
    }

    fn save(&self) {
        let mut b = [0u8; N * N + 5];
        for (k, &t) in self.board.0.iter().flatten().enumerate() {
            b[k] = t;
        }
        b[16..20].copy_from_slice(&self.score.to_le_bytes());
        b[20] = self.won as u8;
        let _ = storage::set("game", &b);
    }
}

fn tile(x: i32, y: i32, t: u8) {
    if t == 0 {
        screen::fill_rect(x + TILE / 2 - 1, y + TILE / 2 - 1, 3, 3, Color::Light);
        return;
    }
    let mut label = Buf::<8>::new();
    let _ = write!(label, "{}", 1u32 << t);
    if t >= 10 && screen::text_width(label.as_str(), Style::Small) > TILE - 3 {
        label.clear();
        let _ = write!(label, "{}k", 1u32 << (t - 10));
    }
    // the big ones stand out: filled, the number dark
    let ink = if t >= 7 {
        screen::fill_rect(x, y, TILE, TILE, Color::Light);
        Color::Dark
    } else {
        screen::rect(x, y, TILE, TILE, Color::Light);
        Color::Light
    };
    let w = screen::text_width(label.as_str(), Style::Small);
    screen::text(
        x + (TILE - w) / 2,
        y + (TILE - Style::Small.height()) / 2,
        label.as_str(),
        Style::Small,
        ink,
    );
}

/// A note over the middle of the grid, two lines.
fn note(top: &str, bottom: &str) {
    screen::fill_rect(10, 40, WIDTH - 20, 40, Color::Dark);
    screen::rect(10, 40, WIDTH - 20, 40, Color::Light);
    screen::text_centred(44, top, Style::Bold, Color::Light);
    screen::text_centred(62, bottom, Style::Small, Color::Light);
}

fn draw(g: &Game, best: u32, shown: Option<(&str, &str)>) {
    screen::clear(Color::Dark);
    let mut line = Buf::<24>::new();
    let _ = write!(line, "{}", g.score);
    screen::text(LEFT, 0, line.as_str(), Style::Small, Color::Light);
    line.clear();
    let _ = write!(line, "best {}", best.max(g.score));
    screen::text(
        WIDTH - LEFT - screen::text_width(line.as_str(), Style::Small),
        0,
        line.as_str(),
        Style::Small,
        Color::Light,
    );
    for (r, row) in g.board.0.iter().enumerate() {
        for (c, &t) in row.iter().enumerate() {
            tile(LEFT + c as i32 * (TILE + GAP), TOP + r as i32 * (TILE + GAP), t);
        }
    }
    if let Some((top, bottom)) = shown {
        note(top, bottom);
    }
    screen::present();
}

fn main() {
    let _ = menu(&["New game", "Reset best"]);
    let mut best = storage::get_u32("best", 0);
    let mut g = Game::load();
    let mut shown: Option<(&str, &str)> =
        if g.board.can_move() { None } else { Some(("Game over", "centre: again")) };
    loop {
        draw(&g, best, shown);
        let way = match wait(None) {
            Event::Left => Way::Left,
            Event::Right => Way::Right,
            Event::Up => Way::Up,
            Event::Down => Way::Down,
            Event::Centre => {
                if !g.board.can_move() {
                    g = Game::new();
                }
                shown = None;
                continue;
            }
            Event::Menu(0) => {
                g = Game::new();
                shown = None;
                continue;
            }
            Event::Menu(1) => {
                best = 0;
                storage::delete("best");
                continue;
            }
            Event::Hidden => {
                g.save();
                continue;
            }
            Event::Exit => {
                g.save();
                return;
            }
            _ => continue,
        };
        // a note waits for the centre: a slide made blind isn't counted
        if shown.is_some() {
            continue;
        }
        let Some(points) = g.board.slide(way) else { continue };
        g.score += points;
        g.board.spawn();
        if g.score > best {
            best = g.score;
            let _ = storage::set_u32("best", best);
        }
        if !g.won && g.board.highest() >= WIN {
            g.won = true;
            shown = Some(("2048!", "centre: keep going"));
        } else if !g.board.can_move() {
            shown = Some(("Game over", "centre: again"));
        }
        g.save();
    }
}

maki_app::main!(main);
