//! Snake, steered the way it's to go: the jog dial on maki's side up or down, left or right with
//! the buttons. The centre pauses. Each thing it eats makes it longer and a little faster; a wall
//! or its own tail ends the game. Two quick presses make a U-turn (up then left, going right).
//! Keeps the best score.

#![no_std]

use core::fmt::Write;

use maki_app::*;

/// A cell's side, in pixels, and the field in cells: 124 by 96 pixels below a line for the score.
const CELL: i32 = 4;
const COLS: i32 = 31;
const ROWS: i32 = 24;
const LEFT: i32 = (WIDTH - COLS * CELL) / 2;
const TOP: i32 = 13;
const CELLS: usize = (COLS * ROWS) as usize;
/// Milliseconds a step, to start with, the least it gets to, and how much faster each bite.
const SLOWEST: u64 = 190;
const FASTEST: u64 = 75;
const FASTER: u64 = 4;
/// Ways pressed ahead of the steps that take them.
const AHEAD: usize = 2;

/// A cell of the field: a byte each way keeps a whole snake small (an app's stack is 16 KiB).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Cell {
    x: u8,
    y: u8,
}

impl Cell {
    fn index(self) -> usize { self.y as usize * COLS as usize + self.x as usize }
}

/// Up, right, down, left (0 to 3): straight back is two on.
const HEADINGS: [(i32, i32); 4] = [(0, -1), (1, 0), (0, 1), (-1, 0)];

struct Game {
    /// The body as a ring: `head` is the newest, the `len` before it the rest.
    body: [Cell; CELLS],
    head: usize,
    len: usize,
    taken: [bool; CELLS],
    heading: usize,
    turns: [u8; AHEAD],
    queued: usize,
    food: Cell,
    eaten: u32,
}

enum Step {
    Moved,
    Ate,
    Died,
}

impl Game {
    fn new() -> Game {
        let mut g = Game {
            body: [Cell { x: 0, y: 0 }; CELLS],
            head: 0,
            len: 0,
            taken: [false; CELLS],
            heading: 1,
            turns: [0; AHEAD],
            queued: 0,
            food: Cell { x: 0, y: 0 },
            eaten: 0,
        };
        for x in 4..8 {
            g.grow(Cell { x, y: ROWS as u8 / 2 });
        }
        g.place_food();
        g
    }

    fn grow(&mut self, c: Cell) {
        self.head = (self.head + 1) % CELLS;
        self.body[self.head] = c;
        self.len += 1;
        self.taken[c.index()] = true;
    }

    fn tail(&self) -> Cell { self.body[(self.head + CELLS + 1 - self.len) % CELLS] }

    /// Somewhere free, at random: the nth free cell.
    fn place_food(&mut self) {
        let free = CELLS - self.len;
        if free == 0 {
            return;
        }
        let mut n = random_below(free as u32) as usize;
        for i in 0..CELLS {
            if !self.taken[i] {
                if n == 0 {
                    self.food = Cell { x: (i % COLS as usize) as u8, y: (i / COLS as usize) as u8 };
                    return;
                }
                n -= 1;
            }
        }
    }

    /// The way pressed, after any pressed ahead of it: none if it's the way the snake will be going
    /// already, or straight back into itself.
    fn steer(&mut self, way: usize) {
        let going = if self.queued > 0 { self.turns[self.queued - 1] as usize } else { self.heading };
        if self.queued < AHEAD && way != going && way != (going + 2) % 4 {
            self.turns[self.queued] = way as u8;
            self.queued += 1;
        }
    }

    fn step(&mut self) -> Step {
        if self.queued > 0 {
            self.heading = self.turns[0] as usize;
            self.turns.copy_within(1.., 0);
            self.queued -= 1;
        }
        let (dx, dy) = HEADINGS[self.heading];
        let h = self.body[self.head];
        let (x, y) = (h.x as i32 + dx, h.y as i32 + dy);
        if x < 0 || y < 0 || x >= COLS || y >= ROWS {
            return Step::Died;
        }
        let next = Cell { x: x as u8, y: y as u8 };
        let eats = next == self.food;
        if !eats {
            // the tail moves on first, so the head may take its place
            let t = self.tail();
            self.taken[t.index()] = false;
            self.len -= 1;
        }
        if self.taken[next.index()] {
            return Step::Died;
        }
        self.grow(next);
        if eats {
            self.eaten += 1;
            self.place_food();
            Step::Ate
        } else {
            Step::Moved
        }
    }

    fn speed(&self) -> u64 { SLOWEST.saturating_sub(self.eaten as u64 * FASTER).max(FASTEST) }
}

fn at(c: Cell) -> (i32, i32) { (LEFT + c.x as i32 * CELL, TOP + c.y as i32 * CELL) }

fn draw(g: &Game, best: u32, paused: bool) {
    screen::clear(Color::Dark);
    let mut line = Buf::<24>::new();
    let _ = write!(line, "{}", g.eaten);
    screen::text(LEFT, 0, line.as_str(), Style::Small, Color::Light);
    line.clear();
    let _ = write!(line, "best {}", best.max(g.eaten));
    screen::text(
        WIDTH - LEFT - screen::text_width(line.as_str(), Style::Small),
        0,
        line.as_str(),
        Style::Small,
        Color::Light,
    );
    screen::rect(LEFT - 1, TOP - 1, COLS * CELL + 2, ROWS * CELL + 2, Color::Light);
    for k in 0..g.len {
        let (x, y) = at(g.body[(g.head + CELLS - k) % CELLS]);
        if k == 0 {
            screen::fill_rect(x, y, CELL, CELL, Color::Light);
        } else {
            screen::fill_rect(x, y, CELL - 1, CELL - 1, Color::Light);
        }
    }
    let (fx, fy) = at(g.food);
    screen::rect(fx, fy, CELL - 1, CELL - 1, Color::Light);
    if paused {
        screen::fill_rect(34, 44, 60, 22, Color::Dark);
        screen::rect(34, 44, 60, 22, Color::Light);
        screen::text_centred(47, "paused", Style::Regular, Color::Light);
    }
    screen::present();
}

fn title(best: u32) {
    screen::clear(Color::Dark);
    screen::text_centred(14, "Snake", Style::Tall, Color::Light);
    // a little snake, and its dinner
    for i in 0..9 {
        screen::fill_rect(34 + i * 5, 44, 4, 4, Color::Light);
    }
    screen::fill_rect(79, 44, 5, 4, Color::Light);
    screen::rect(92, 44, 4, 4, Color::Light);
    screen::text_centred(56, "steer with the dial", Style::Small, Color::Light);
    screen::text_centred(67, "and left and right", Style::Small, Color::Light);
    screen::text_centred(80, "centre: play", Style::Small, Color::Light);
    if best > 0 {
        let mut line = Buf::<24>::new();
        let _ = write!(line, "best {best}");
        screen::text_centred(96, line.as_str(), Style::Small, Color::Light);
    }
    screen::present();
}

fn over(score: u32, best: u32, record: bool) {
    screen::clear(Color::Dark);
    screen::text_centred(18, "Game over", Style::Bold, Color::Light);
    let mut line = Buf::<24>::new();
    let _ = write!(line, "{score}");
    screen::text_centred(40, line.as_str(), Style::Tall, Color::Light);
    line.clear();
    if record {
        let _ = line.write_str("your best yet");
    } else {
        let _ = write!(line, "best {best}");
    }
    screen::text_centred(66, line.as_str(), Style::Small, Color::Light);
    screen::text_centred(88, "centre: again", Style::Small, Color::Light);
    screen::present();
}

/// A game, until it ends (its score) or the owner leaves (None).
fn play(best: u32) -> Option<u32> {
    let mut g = Game::new();
    let mut paused = false;
    let mut next = millis() + g.speed();
    loop {
        draw(&g, best, paused);
        let event = if paused { wait(None) } else { wait(Some(next.saturating_sub(millis()) as u32)) };
        match event {
            Event::Timeout if !paused => {
                match g.step() {
                    Step::Died => return Some(g.eaten),
                    Step::Ate | Step::Moved => {}
                }
                next += g.speed();
                // behind (a busy moment): carry on from now rather than rushing to catch up
                next = next.max(millis());
            }
            Event::Up if !paused => g.steer(0),
            Event::Right if !paused => g.steer(1),
            Event::Down if !paused => g.steer(2),
            Event::Left if !paused => g.steer(3),
            Event::Centre => {
                paused = !paused;
                next = millis() + g.speed();
            }
            // something else has the screen: wait for the owner to come back to it
            Event::Hidden => paused = true,
            Event::Exit => return None,
            _ => {}
        }
    }
}

fn main() {
    let _ = menu(&["Reset best"]);
    let mut best = storage::get_u32("best", 0);
    loop {
        title(best);
        match wait(None) {
            Event::Centre => {}
            Event::Menu(0) => {
                best = 0;
                storage::delete("best");
                continue;
            }
            Event::Exit => return,
            _ => continue,
        }
        let Some(score) = play(best) else { return };
        let record = score > best;
        if record {
            best = score;
            let _ = storage::set_u32("best", best);
        }
        // a moment before a press counts, so the turn that ended it doesn't start the next
        let until = millis() + 600;
        loop {
            over(score, best, record);
            let left = until.saturating_sub(millis());
            match wait(if left > 0 { Some(left as u32) } else { None }) {
                Event::Centre if millis() >= until => break,
                Event::Exit => return,
                _ => {}
            }
        }
    }
}

maki_app::main!(main);
