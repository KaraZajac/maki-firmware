//! Sokoban: push every box onto a goal. Boxes are pushed, never pulled, and one at a time.
//! Left and right and the jog dial on maki's side walk; the centre takes the last move back, as
//! many as the last 255. The levels are David W. Skinner's Microban, 148 of its 155
//! (`microban.txt` begins with where they're from, his terms, and which are left out and why),
//! drawn as big as each fits, the few too big for the screen scrolling with the player. The
//! level you left is kept, moves and all, and each level's fewest moves.

#![no_std]

use core::fmt::Write;

use maki_app::*;

/// David W. Skinner's Microban, as he wrote it: its first lines say where from, and on what terms.
const MICROBAN: &str = include_str!("microban.txt");

/// The most levels the list holds, and cells in a level: every one here fits in 22 by 10.
const MAX_LEVELS: usize = 160;
const MAX_CELLS: usize = 256;
/// Moves remembered for taking back, and the most moves a level counts.
const HISTORY: usize = 255;
const MAX_MOVES: u16 = 9999;
/// Each level's fewest moves, as storage keeps them: a u16 for each number up to this, 0 for
/// not solved yet.
const NUMBERS: usize = 156;

const WALL: u8 = 1;
const GOAL: u8 = 2;
const BOX: u8 = 4;

/// The level's part of the screen, above a line for its number and the moves.
const AREA_H: i32 = 98;
/// Tile sizes, the biggest each level fits drawn at; past the smallest, it scrolls.
const TILES: [i32; 4] = [16, 12, 10, 8];

/// Where a level is in `MICROBAN`: its number, where its rows start and the next level's
/// header (or the end), and its title if it has one.
#[derive(Clone, Copy, Default)]
struct Entry {
    number: u8,
    rows: (usize, usize),
    title: (usize, usize),
}

/// The levels, in the file's order.
struct Levels {
    list: [Entry; MAX_LEVELS],
    n: usize,
}

impl Levels {
    /// Finds each level's header ("; 12", or "; 44 'Duh!'") and where its rows are.
    fn read() -> Levels {
        let mut levels = Levels { list: [Entry::default(); MAX_LEVELS], n: 0 };
        let text = MICROBAN.as_bytes();
        let mut at = 0;
        while at < text.len() {
            let end = text[at..].iter().position(|&b| b == b'\n').map_or(text.len(), |i| at + i);
            let line = &text[at..end];
            // "; 12" or "; 44 'Duh!'": anything else after a semicolon is a comment
            let digits = line.iter().skip(2).take_while(|b| b.is_ascii_digit()).count();
            let header =
                line.starts_with(b"; ") && digits > 0 && matches!(line.get(2 + digits), None | Some(b' '));
            if header && levels.n < MAX_LEVELS {
                let number = line[2..2 + digits].iter().fold(0u32, |n, &d| n * 10 + (d - b'0') as u32);
                let quote = |from_end: bool| {
                    let pos = if from_end {
                        line.iter().rposition(|&b| b == b'\'')
                    } else {
                        line.iter().position(|&b| b == b'\'')
                    };
                    pos.map(|i| at + i)
                };
                let title = match (quote(false), quote(true)) {
                    (Some(a), Some(b)) if b > a => (a + 1, b),
                    _ => (0, 0),
                };
                if let Some(prev) = levels.n.checked_sub(1) {
                    levels.list[prev].rows.1 = at;
                }
                levels.list[levels.n] =
                    Entry { number: number.min(255) as u8, rows: (end.min(text.len()), text.len()), title };
                levels.n += 1;
            }
            at = end + 1;
        }
        levels
    }

    fn title(&self, i: usize) -> &str {
        MICROBAN.get(self.list[i].title.0..self.list[i].title.1).unwrap_or("")
    }

    /// Level `i` as it starts: None if its rows don't make a level that fits.
    fn map(&self, i: usize) -> Option<Map> {
        let e = self.list.get(i)?;
        let rows = MICROBAN.get(e.rows.0..e.rows.1)?;
        let mut map = Map { w: 0, h: 0, cells: [0; MAX_CELLS], player: MAX_CELLS };
        for row in rows.lines().filter(|r| !r.trim().is_empty() && !r.starts_with(';')) {
            map.w = map.w.max(row.trim_end().len());
            map.h += 1;
        }
        if map.w * map.h > MAX_CELLS || map.w == 0 {
            return None;
        }
        for (y, row) in rows.lines().filter(|r| !r.trim().is_empty() && !r.starts_with(';')).enumerate() {
            for (x, ch) in row.trim_end().bytes().enumerate() {
                let c = y * map.w + x;
                map.cells[c] = match ch {
                    b'#' => WALL,
                    b'.' => GOAL,
                    b'$' => BOX,
                    b'*' => BOX | GOAL,
                    b'+' => GOAL,
                    b'@' | b' ' => 0,
                    _ => return None,
                };
                if ch == b'@' || ch == b'+' {
                    map.player = c;
                }
            }
        }
        let boxes = map.cells.iter().filter(|&&c| c & BOX != 0).count();
        let goals = map.cells.iter().filter(|&&c| c & GOAL != 0).count();
        (map.player < MAX_CELLS && boxes > 0 && boxes == goals).then_some(map)
    }

    fn index(&self, number: u8) -> Option<usize> {
        self.list[..self.n].iter().position(|e| e.number == number)
    }
}

/// A level being played: its walls and goals, where the boxes and the player are.
#[derive(Clone, Copy)]
struct Map {
    w: usize,
    h: usize,
    cells: [u8; MAX_CELLS],
    player: usize,
}

/// The ways to walk: up, down, left, right.
const WAYS: [(i32, i32); 4] = [(0, -1), (0, 1), (-1, 0), (1, 0)];

impl Map {
    /// The cell next to `c` going `way`, if it's on the map.
    fn next(&self, c: usize, way: usize) -> Option<usize> {
        let (x, y) = ((c % self.w) as i32 + WAYS[way].0, (c / self.w) as i32 + WAYS[way].1);
        ((0..self.w as i32).contains(&x) && (0..self.h as i32).contains(&y))
            .then(|| y as usize * self.w + x as usize)
    }

    fn solved(&self) -> bool { self.cells.iter().all(|&c| c & BOX == 0 || c & GOAL != 0) }

    fn boxes(&self) -> usize { self.cells.iter().filter(|&&c| c & BOX != 0).count() }
}

/// The level being played, and the moves that brought it here.
struct Game {
    /// which level, in the list
    level: usize,
    map: Map,
    moves: u16,
    /// the last moves, oldest first, each its way and whether it pushed a box (4)
    history: [u8; HISTORY],
    len: usize,
}

const PUSHED: u8 = 4;

impl Game {
    fn start(levels: &Levels, level: usize) -> Option<Game> {
        Some(Game { level, map: levels.map(level)?, moves: 0, history: [0; HISTORY], len: 0 })
    }

    /// Walks `way`, pushing the box there if the cell beyond it is free: whether it moved.
    fn walk(&mut self, way: usize) -> bool {
        let m = &mut self.map;
        let Some(to) = m.next(m.player, way) else { return false };
        if m.cells[to] & WALL != 0 {
            return false;
        }
        let mut entry = way as u8;
        if m.cells[to] & BOX != 0 {
            match m.next(to, way) {
                Some(beyond) if m.cells[beyond] & (WALL | BOX) == 0 => {
                    m.cells[to] &= !BOX;
                    m.cells[beyond] |= BOX;
                    entry |= PUSHED;
                }
                _ => return false,
            }
        }
        m.player = to;
        self.moves = (self.moves + 1).min(MAX_MOVES);
        if self.len == HISTORY {
            self.history.copy_within(1.., 0);
            self.len -= 1;
        }
        self.history[self.len] = entry;
        self.len += 1;
        true
    }

    /// Takes the last move back, pulling back the box it pushed: whether there was one to take.
    fn undo(&mut self) -> bool {
        let Some(last) = self.len.checked_sub(1) else { return false };
        let (way, pushed) = ((self.history[last] & 3) as usize, self.history[last] & PUSHED != 0);
        let m = &mut self.map;
        let from = m.next(m.player, way ^ 1);
        let ahead = m.next(m.player, way);
        match (from, ahead) {
            (Some(from), ahead) if m.cells[from] & (WALL | BOX) == 0 => {
                if pushed {
                    // the box it pushed is just ahead: back to where the player stands
                    let Some(ahead) = ahead.filter(|&a| m.cells[a] & BOX != 0) else {
                        self.len = 0;
                        return false;
                    };
                    m.cells[ahead] &= !BOX;
                    m.cells[m.player] |= BOX;
                }
                m.player = from;
                self.len = last;
                self.moves = self.moves.saturating_sub(1);
                true
            }
            // a history that doesn't fit the map: forgotten, rather than trusted
            _ => {
                self.len = 0;
                false
            }
        }
    }

    // storage: the format, the level's number, the player's cell, how many boxes and their
    // cells, the moves (u16), how many moves are remembered, and those
    fn load(levels: &Levels) -> Option<Game> {
        let mut b = [0u8; 8 + MAX_CELLS + HISTORY];
        let n = storage::get("game", &mut b)?;
        let b = b.get(..n)?;
        if b.first() != Some(&1) {
            return None;
        }
        let level = levels.index(*b.get(1)?)?;
        let mut g = Game::start(levels, level)?;
        let (player, nboxes) = (*b.get(2)? as usize, *b.get(3)? as usize);
        let boxes = b.get(4..4 + nboxes)?;
        let rest = b.get(4 + nboxes..)?;
        let (moves, len) = (u16::from_le_bytes([*rest.first()?, *rest.get(1)?]), *rest.get(2)? as usize);
        let history = rest.get(3..3 + len)?;
        let m = &mut g.map;
        let cells = m.w * m.h;
        if nboxes != m.boxes() || rest.len() != 3 + len || moves > MAX_MOVES {
            return None;
        }
        for c in m.cells.iter_mut() {
            *c &= !BOX;
        }
        for &c in boxes {
            let c = c as usize;
            if c >= cells || m.cells[c] & (WALL | BOX) != 0 {
                return None;
            }
            m.cells[c] |= BOX;
        }
        if player >= cells || m.cells[player] & (WALL | BOX) != 0 || history.iter().any(|&e| e > 7) {
            return None;
        }
        m.player = player;
        g.moves = moves;
        g.history[..len].copy_from_slice(history);
        g.len = len;
        Some(g)
    }

    fn save(&self, levels: &Levels) {
        let mut b = [0u8; 8 + MAX_CELLS + HISTORY];
        b[0] = 1;
        b[1] = levels.list[self.level].number;
        b[2] = self.map.player as u8;
        let mut n = 4;
        for (c, &cell) in self.map.cells[..self.map.w * self.map.h].iter().enumerate() {
            if cell & BOX != 0 {
                b[n] = c as u8;
                n += 1;
            }
        }
        b[3] = (n - 4) as u8;
        b[n..n + 2].copy_from_slice(&self.moves.to_le_bytes());
        b[n + 2] = self.len as u8;
        b[n + 3..n + 3 + self.len].copy_from_slice(&self.history[..self.len]);
        let _ = storage::set("game", &b[..n + 3 + self.len]);
    }
}

/// Each level's fewest moves, by its number: 0 for not solved yet.
fn bests() -> [u16; NUMBERS] {
    let mut b = [0u8; 2 * NUMBERS];
    let mut best = [0u16; NUMBERS];
    if storage::get("best", &mut b) == Some(2 * NUMBERS) {
        for (i, m) in best.iter_mut().enumerate() {
            *m = u16::from_le_bytes([b[2 * i], b[2 * i + 1]]).min(MAX_MOVES);
        }
    }
    best
}

fn keep_bests(best: &[u16; NUMBERS]) {
    let mut b = [0u8; 2 * NUMBERS];
    for (i, m) in best.iter().enumerate() {
        b[2 * i..2 * i + 2].copy_from_slice(&m.to_le_bytes());
    }
    let _ = storage::set("best", &b);
}

/// A brick wall's tile: courses of bricks, their joints staggered, the mortar dark.
fn wall(x: i32, y: i32, t: i32) {
    screen::fill_rect(x, y, t, t, Color::Light);
    let course = if t < 12 {
        t / 2
    } else if t < 16 {
        t / 3
    } else {
        t / 4
    };
    for k in 0..t / course {
        screen::fill_rect(x, y + (k + 1) * course - 1, t, 1, Color::Dark);
        let joint = if k % 2 == 0 { t - 1 } else { t / 2 - 1 };
        screen::fill_rect(x + joint, y + k * course, 1, course, Color::Dark);
    }
}

/// A goal: a small diamond in the middle of the tile.
fn goal(x: i32, y: i32, t: i32, color: Color) {
    let r = (t / 5).max(1);
    let (cx, cy) = (x + t / 2, y + t / 2);
    for dy in -r..r {
        // pixels whose middles are within r of the tile's middle, the diamond's way
        let w = r - (2 * dy + 1).abs() / 2 - 1;
        screen::fill_rect(cx - w - 1, cy + dy, 2 * w + 2, 1, color);
    }
}

/// A box: a crate, its inner edge dark; on a goal, filled, the goal's diamond dark in it.
fn crate_(x: i32, y: i32, t: i32, on_goal: bool) {
    screen::fill_rect(x + 1, y + 1, t - 2, t - 2, Color::Light);
    if on_goal {
        goal(x, y, t, Color::Dark);
    } else {
        screen::rect(x + 2, y + 2, t - 4, t - 4, Color::Dark);
    }
}

/// The player: a round face with two dark eyes.
fn player(x: i32, y: i32, t: i32) {
    // a disc of radius (t - 2) / 2 about the tile's middle, in half pixels
    let r2 = (t - 2) * (t - 2);
    for row in 0..t {
        let dy = 2 * row + 1 - t;
        let half = (0..t).filter(|&col| (2 * col + 1 - t).pow(2) + dy * dy <= r2).count() as i32;
        if half > 0 {
            screen::fill_rect(x + (t - half) / 2, y + row, half, 1, Color::Light);
        }
    }
    let e = (t / 8).max(1);
    let (ex, ey) = (t / 2 - t / 5, t / 2 - t / 6);
    screen::fill_rect(x + ex, y + ey, e, e, Color::Dark);
    screen::fill_rect(x + t - ex - e, y + ey, e, e, Color::Dark);
}

/// The tile size a level's drawn at, and where its top left goes: the biggest that fits,
/// centred; or the smallest, scrolled to keep the player in the middle.
fn view(m: &Map) -> (i32, i32, i32) {
    let (w, h) = (m.w as i32, m.h as i32);
    let t = TILES.iter().copied().find(|&t| w * t <= WIDTH && h * t <= AREA_H).unwrap_or(TILES[3]);
    let place = |cells: i32, room: i32, at: i32| {
        if cells * t <= room {
            (room - cells * t) / 2
        } else {
            (room / 2 - at * t - t / 2).clamp(room - cells * t, 0)
        }
    };
    (t, place(w, WIDTH, (m.player % m.w) as i32), place(h, AREA_H, (m.player / m.w) as i32))
}

fn draw_level(m: &Map, t: i32, ox: i32, oy: i32) {
    for c in 0..m.w * m.h {
        let (x, y) = (ox + (c % m.w) as i32 * t, oy + (c / m.w) as i32 * t);
        if x + t <= 0 || x >= WIDTH || y + t <= 0 || y >= AREA_H {
            continue;
        }
        let cell = m.cells[c];
        if cell & WALL != 0 {
            wall(x, y, t);
        } else if cell & BOX != 0 {
            crate_(x, y, t, cell & GOAL != 0);
        } else if c == m.player {
            player(x, y, t);
        } else if cell & GOAL != 0 {
            goal(x, y, t, Color::Light);
        }
    }
    // the line under the level, if it reaches it
    screen::fill_rect(0, AREA_H, WIDTH, HEIGHT - AREA_H, Color::Dark);
}

/// A small picture of a level, for choosing one: each cell `p` pixels.
fn draw_preview(m: &Map, top: i32, room: i32) {
    let p = (WIDTH / m.w as i32).min(room / m.h as i32).min(6);
    let (ox, oy) = ((WIDTH - m.w as i32 * p) / 2, top + (room - m.h as i32 * p) / 2);
    for c in 0..m.w * m.h {
        let (x, y) = (ox + (c % m.w) as i32 * p, oy + (c / m.w) as i32 * p);
        let cell = m.cells[c];
        if cell & WALL != 0 {
            screen::fill_rect(x, y, p, p, Color::Light);
        } else if cell & BOX != 0 && cell & GOAL != 0 {
            screen::fill_rect(x + 1, y + 1, p - 2, p - 2, Color::Light);
        } else if cell & BOX != 0 {
            screen::rect(x + 1, y + 1, p - 2, p - 2, Color::Light);
        } else if c == m.player {
            screen::fill_rect(x + p / 2 - 1, y + 1, 2, p - 2, Color::Light);
            screen::fill_rect(x + 1, y + p / 2 - 1, p - 2, 2, Color::Light);
        } else if cell & GOAL != 0 {
            screen::fill_rect(x + p / 2 - 1, y + p / 2 - 1, 2, 2, Color::Light);
        }
    }
}

/// What's on the screen: the level being played, or the levels to choose from, at this one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Play,
    Choose(usize),
}

struct App {
    levels: Levels,
    game: Game,
    best: [u16; NUMBERS],
    screen: Screen,
}

impl App {
    fn number(&self, i: usize) -> u8 { self.levels.list[i].number }

    fn best_of(&self, i: usize) -> u16 { self.best.get(self.number(i) as usize).copied().unwrap_or(0) }

    /// Level `i` from its start.
    fn begin(&mut self, i: usize) {
        if let Some(g) = Game::start(&self.levels, i) {
            self.game = g;
            self.game.save(&self.levels);
        }
        self.screen = Screen::Play;
    }

    fn walk(&mut self, way: usize) {
        if self.game.map.solved() || !self.game.walk(way) {
            return;
        }
        if self.game.map.solved() {
            let n = self.number(self.game.level) as usize;
            if let Some(best) = self.best.get_mut(n) {
                if *best == 0 || self.game.moves < *best {
                    *best = self.game.moves;
                    keep_bests(&self.best);
                }
            }
            self.game.save(&self.levels);
        }
    }

    fn press(&mut self, event: Event) {
        match self.screen {
            Screen::Play => match event {
                Event::Up => self.walk(0),
                Event::Down => self.walk(1),
                Event::Left => self.walk(2),
                Event::Right => self.walk(3),
                // solved: on to the next level; else a move taken back
                Event::Centre if self.game.map.solved() => self.begin((self.game.level + 1) % self.levels.n),
                Event::Centre => {
                    self.game.undo();
                }
                _ => {}
            },
            Screen::Choose(i) => {
                let n = self.levels.n;
                match event {
                    Event::Left => self.screen = Screen::Choose((i + n - 1) % n),
                    Event::Right => self.screen = Screen::Choose((i + 1) % n),
                    Event::Up => self.screen = Screen::Choose(i.saturating_sub(10)),
                    Event::Down => self.screen = Screen::Choose((i + 10).min(n - 1)),
                    // the level being played goes on where it was; another starts
                    Event::Centre if i == self.game.level => self.screen = Screen::Play,
                    Event::Centre => self.begin(i),
                    _ => {}
                }
            }
        }
    }

    fn draw(&self) {
        screen::clear(Color::Dark);
        match self.screen {
            Screen::Play => self.draw_play(),
            Screen::Choose(i) => self.draw_choose(i),
        }
        screen::present();
    }

    fn draw_play(&self) {
        let g = &self.game;
        let (t, ox, oy) = view(&g.map);
        draw_level(&g.map, t, ox, oy);
        let mut line = Buf::<24>::new();
        let _ = write!(line, "level {}", self.number(g.level));
        screen::text(2, AREA_H - 2, line.as_str(), Style::Small, Color::Light);
        line.clear();
        let best = self.best_of(g.level);
        let s = if g.moves == 1 { "" } else { "s" };
        if g.moves == 0 {
            let _ = line.write_str("centre: undo");
        } else if best > 0 {
            let _ = write!(line, "{} move{s}, best {best}", g.moves);
        } else {
            let _ = write!(line, "{} move{s}", g.moves);
        }
        let w = screen::text_width(line.as_str(), Style::Small);
        screen::text(WIDTH - 2 - w, AREA_H - 2, line.as_str(), Style::Small, Color::Light);
        if g.map.solved() {
            screen::fill_rect(8, 30, WIDTH - 16, 46, Color::Dark);
            screen::rect(8, 30, WIDTH - 16, 46, Color::Light);
            screen::text_centred(33, "Solved", Style::Bold, Color::Light);
            line.clear();
            let _ = if best == g.moves {
                write!(line, "in {} moves, your best", g.moves)
            } else {
                write!(line, "in {} moves, best {best}", g.moves)
            };
            screen::text_centred(49, line.as_str(), Style::Small, Color::Light);
            screen::text_centred(61, "centre: next level", Style::Small, Color::Light);
        }
    }

    fn draw_choose(&self, i: usize) {
        let mut line = Buf::<40>::new();
        let _ = write!(line, "Microban {}: {}", self.number(i), self.levels.title(i));
        if self.levels.title(i).is_empty() || screen::text_width(line.as_str(), Style::Bold) > WIDTH {
            line.clear();
            let _ = write!(line, "Microban {}", self.number(i));
        }
        screen::text_centred(0, line.as_str(), Style::Bold, Color::Light);
        if let Some(m) = self.levels.map(i) {
            let m = if i == self.game.level { self.game.map } else { m };
            draw_preview(&m, 16, 60);
        }
        line.clear();
        let best = self.best_of(i);
        let solved = (0..self.levels.n).filter(|&k| self.best_of(k) > 0).count();
        let _ = if best > 0 {
            write!(line, "solved in {best} moves")
        } else {
            write!(line, "{solved} of {} solved", self.levels.n)
        };
        screen::text_centred(80, line.as_str(), Style::Small, Color::Light);
        // whose they are, as he asks
        screen::text_centred(HEIGHT - 12, "by David W. Skinner", Style::Small, Color::Light);
    }
}

fn main() {
    let _ = menu(&["Start over", "Levels", "Forget progress"]);
    let levels = Levels::read();
    let Some(first) = Game::start(&levels, 0) else { abort("no levels") };
    let game = Game::load(&levels).unwrap_or(first);
    let mut app = App { levels, game, best: bests(), screen: Screen::Play };
    loop {
        app.draw();
        match wait(None) {
            Event::Exit => {
                app.game.save(&app.levels);
                return;
            }
            Event::Menu(0) => app.begin(app.game.level),
            Event::Menu(1) => {
                app.screen = match app.screen {
                    Screen::Play => Screen::Choose(app.game.level),
                    Screen::Choose(_) => Screen::Play,
                }
            }
            Event::Menu(2) => {
                app.best = [0; NUMBERS];
                storage::delete("best");
            }
            Event::Hidden => app.game.save(&app.levels),
            event => app.press(event),
        }
    }
}

maki_app::main!(main);
