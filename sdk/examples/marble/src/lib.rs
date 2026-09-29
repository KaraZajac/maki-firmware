//! Marble: a maze, new every time, and a marble that rolls the way maki is tilted (the motion
//! permission), into the hole at the far corner. Walls stop it, and it bounces off them a little;
//! the centre pauses. Keeps how many mazes you've solved and your fastest.

#![no_std]

use core::fmt::Write;

use maki_app::*;

/// A cell's side in pixels, and the maze in cells: 122 by 100 pixels, walls and all.
const CELL: i32 = 11;
const COLS: usize = 11;
const ROWS: usize = 9;
const CELLS: usize = COLS * ROWS;
const LEFT: i32 = (WIDTH - COLS as i32 * CELL) / 2;
const TOP: i32 = (HEIGHT - ROWS as i32 * CELL) / 2;
/// The walls, a bit a pixel, in rows of bytes as `screen::blit` takes them.
const ROW_BYTES: usize = (WIDTH as usize).div_ceil(8);
const PIXELS: usize = ROW_BYTES * HEIGHT as usize;
/// The marble's radius, and the hole's, in pixels.
const R: i32 = 3;
const HOLE: i32 = 4;
/// A step's length, in milliseconds.
const STEP_MS: u32 = 33;
/// Positions and speeds in 256ths of a pixel (speeds a step).
const ONE: i32 = 256;
/// What a tilt of a whole g adds to the speed each step; the fastest it rolls; what's left of its
/// speed after a step (in 256ths), and after it hits a wall, going the other way.
const PUSH: i32 = 90;
const FASTEST: i32 = 3 * ONE;
const ROLL: i32 = 250;
const BOUNCE: i32 = 80;

/// Which ways each cell is open: north, east, south, west.
const N: u8 = 1;
const E: u8 = 2;
const S: u8 = 4;
const W: u8 = 8;

/// A new maze: every cell reached from every other one way only, carved from the start by a
/// walk that goes on to a random unvisited neighbour, and back when there's none.
fn carve(open: &mut [u8; CELLS]) {
    *open = [0; CELLS];
    let mut seen = [false; CELLS];
    let mut path = [0u8; CELLS];
    let mut len = 1;
    seen[0] = true;
    while len > 0 {
        let c = path[len - 1] as usize;
        let (x, y) = (c % COLS, c / COLS);
        let mut ways = [(0usize, 0u8, 0u8); 4];
        let mut n = 0;
        for (ok, next, here, there) in [
            (y > 0, c.wrapping_sub(COLS), N, S),
            (x + 1 < COLS, c + 1, E, W),
            (y + 1 < ROWS, c + COLS, S, N),
            (x > 0, c.wrapping_sub(1), W, E),
        ] {
            if ok && !seen[next] {
                ways[n] = (next, here, there);
                n += 1;
            }
        }
        if n == 0 {
            len -= 1;
            continue;
        }
        let (next, here, there) = ways[random_below(n as u32) as usize];
        open[c] |= here;
        open[next] |= there;
        seen[next] = true;
        path[len] = next as u8;
        len += 1;
    }
}

fn set(px: &mut [u8; PIXELS], x: i32, y: i32) {
    if (0..WIDTH).contains(&x) && (0..HEIGHT).contains(&y) {
        px[y as usize * ROW_BYTES + x as usize / 8] |= 0x80 >> (x % 8);
    }
}

/// A wall there, or off the screen.
fn wall(px: &[u8; PIXELS], x: i32, y: i32) -> bool {
    !(0..WIDTH).contains(&x) || !(0..HEIGHT).contains(&y) || px[y as usize * ROW_BYTES + x as usize / 8] & (0x80 >> (x % 8)) != 0
}

/// The maze's walls as pixels: each cell's north and west, where they're closed, and the far
/// sides of the last row and column (every other wall is a neighbour's north or west).
fn draw_walls(open: &[u8; CELLS], px: &mut [u8; PIXELS]) {
    *px = [0; PIXELS];
    for (c, &ways) in open.iter().enumerate() {
        let (x0, y0) = (LEFT + (c % COLS) as i32 * CELL, TOP + (c / COLS) as i32 * CELL);
        for i in 0..=CELL {
            if ways & N == 0 {
                set(px, x0 + i, y0);
            }
            if ways & W == 0 {
                set(px, x0, y0 + i);
            }
            if c / COLS == ROWS - 1 {
                set(px, x0 + i, y0 + CELL);
            }
            if c % COLS == COLS - 1 {
                set(px, x0 + CELL, y0 + i);
            }
        }
    }
}

/// Where a cell's middle is, in pixels.
fn middle(c: usize) -> (i32, i32) { (LEFT + (c % COLS) as i32 * CELL + CELL / 2, TOP + (c / COLS) as i32 * CELL + CELL / 2) }

fn pixel(v: i32) -> i32 { (v + ONE / 2).div_euclid(ONE) }

/// Whether the marble, centred there, touches a wall.
fn hits(px: &[u8; PIXELS], x: i32, y: i32) -> bool {
    (-R..=R).any(|dy| (-R..=R).any(|dx| dx * dx + dy * dy <= R * R + 1 && wall(px, x + dx, y + dy)))
}

struct Marble {
    x: i32,
    y: i32,
    vx: i32,
    vy: i32,
}

impl Marble {
    fn at(c: usize) -> Marble {
        let (x, y) = middle(c);
        Marble { x: x * ONE, y: y * ONE, vx: 0, vy: 0 }
    }

    /// A step's rolling, tilted by `tilt` (thousandths of a g): whether it's in the hole after.
    fn step(&mut self, tilt: (i16, i16, i16), px: &[u8; PIXELS]) -> bool {
        // downhill: the way the spirit level's bubble isn't
        self.vx = (self.vx * ROLL / ONE + tilt.0 as i32 * PUSH / 1000).clamp(-FASTEST, FASTEST);
        self.vy = (self.vy * ROLL / ONE - tilt.1 as i32 * PUSH / 1000).clamp(-FASTEST, FASTEST);
        // a pixel at a time at most, so it can't pass through a wall
        let n = ((self.vx.abs().max(self.vy.abs()) + ONE - 1) / ONE).max(1);
        for _ in 0..n {
            let x = self.x + self.vx / n;
            if hits(px, pixel(x), pixel(self.y)) {
                self.vx = -self.vx * BOUNCE / ONE;
            } else {
                self.x = x;
            }
            let y = self.y + self.vy / n;
            if hits(px, pixel(self.x), pixel(y)) {
                self.vy = -self.vy * BOUNCE / ONE;
            } else {
                self.y = y;
            }
        }
        let (hx, hy) = middle(CELLS - 1);
        let (dx, dy) = (pixel(self.x) - hx, pixel(self.y) - hy);
        dx * dx + dy * dy <= (HOLE - 1) * (HOLE - 1)
    }
}

fn disc(x: i32, y: i32, r: i32, color: Color) {
    for dy in -r..=r {
        let w = (0..=r).take_while(|dx| dx * dx + dy * dy <= r * r + 1).last().unwrap_or(0);
        screen::fill_rect(x - w, y + dy, 2 * w + 1, 1, color);
    }
}

fn seconds(ms: u32, out: &mut Buf<24>) { let _ = write!(out, "{}.{} s", ms / 1000, ms % 1000 / 100); }

fn draw(px: &[u8; PIXELS], m: &Marble, paused: Option<(u32, u32)>) {
    screen::clear(Color::Dark);
    screen::blit(0, 0, WIDTH, HEIGHT, px, Color::Light);
    let (hx, hy) = middle(CELLS - 1);
    disc(hx, hy, HOLE, Color::Light);
    disc(hx, hy, HOLE - 2, Color::Dark);
    let (x, y) = (pixel(m.x), pixel(m.y));
    disc(x, y, R, Color::Light);
    screen::pixel(x - 1, y - 1, Color::Dark);
    if let Some((maze, ms)) = paused {
        screen::fill_rect(20, 30, 88, 50, Color::Dark);
        screen::rect(20, 30, 88, 50, Color::Light);
        let mut line = Buf::<24>::new();
        let _ = write!(line, "maze {maze}, ");
        seconds(ms, &mut line);
        screen::text_centred(35, "paused", Style::Bold, Color::Light);
        screen::text_centred(52, line.as_str(), Style::Small, Color::Light);
        screen::text_centred(64, "centre: go on", Style::Small, Color::Light);
    }
    screen::present();
}

fn title(solved: u32, fastest: u32, level: bool) {
    screen::clear(Color::Dark);
    screen::text_centred(8, "Marble", Style::Tall, Color::Light);
    // a corner of a maze, and the marble
    screen::line(44, 36, 84, 36, Color::Light);
    screen::line(44, 36, 44, 56, Color::Light);
    screen::line(64, 46, 64, 56, Color::Light);
    disc(54, 49, R, Color::Light);
    let mut line = Buf::<24>::new();
    screen::text_centred(62, if level { "tilt maki to roll it" } else { "no accelerometer here" }, Style::Small, Color::Light);
    screen::text_centred(75, "centre: play", Style::Small, Color::Light);
    if solved > 0 {
        let _ = write!(line, "{solved} solved, best ");
        seconds(fastest, &mut line);
        screen::text_centred(94, line.as_str(), Style::Small, Color::Light);
    }
    screen::present();
}

fn solved(ms: u32, fastest: u32, record: bool) {
    screen::clear(Color::Dark);
    screen::text_centred(14, "Solved", Style::Bold, Color::Light);
    let mut line = Buf::<24>::new();
    seconds(ms, &mut line);
    screen::text_centred(36, line.as_str(), Style::Tall, Color::Light);
    line.clear();
    if record {
        let _ = line.write_str("your fastest yet");
    } else {
        let _ = line.write_str("best ");
        seconds(fastest, &mut line);
    }
    screen::text_centred(62, line.as_str(), Style::Small, Color::Light);
    screen::text_centred(84, "centre: another", Style::Small, Color::Light);
    screen::present();
}

/// How a maze went.
enum End {
    Solved(u32),
    /// The menu's New maze.
    Again,
    Left,
}

/// A maze, played until the marble's in the hole (how long it took), a new one's asked for, or
/// the owner leaves.
fn play(maze: u32) -> End {
    let mut open = [0u8; CELLS];
    carve(&mut open);
    let mut px = [0u8; PIXELS];
    draw_walls(&open, &mut px);
    let mut m = Marble::at(0);
    let mut steps = 0u32;
    let mut paused = false;
    let mut next = millis() + STEP_MS as u64;
    loop {
        draw(&px, &m, paused.then_some((maze, steps * STEP_MS)));
        let event = if paused { wait(None) } else { wait(Some(next.saturating_sub(millis()) as u32)) };
        match event {
            Event::Timeout if !paused => {
                steps += 1;
                if m.step(motion::read().unwrap_or((0, 0, 1000)), &px) {
                    return End::Solved(steps * STEP_MS);
                }
                // behind (a busy moment): carry on from now rather than rushing to catch up
                next = (next + STEP_MS as u64).max(millis());
            }
            Event::Centre => {
                paused = !paused;
                next = millis() + STEP_MS as u64;
            }
            // something else has the screen: wait for the owner to come back to it
            Event::Hidden => paused = true,
            Event::Menu(0) => return End::Again,
            Event::Exit => return End::Left,
            _ => {}
        }
    }
}

fn main() {
    let _ = menu(&["New maze", "Forget scores"]);
    let mut count = storage::get_u32("solved", 0);
    let mut fastest = storage::get_u32("fastest", 0);
    let mut playing = false;
    loop {
        if !playing {
            title(count, fastest, motion::read().is_some());
            match wait(None) {
                Event::Centre | Event::Menu(0) => playing = true,
                Event::Menu(1) => {
                    (count, fastest) = (0, 0);
                    storage::delete("solved");
                    storage::delete("fastest");
                }
                Event::Exit => return,
                _ => {}
            }
            continue;
        }
        let ms = match play(count + 1) {
            End::Solved(ms) => ms,
            End::Again => continue,
            End::Left => return,
        };
        count += 1;
        let record = fastest == 0 || ms < fastest;
        if record {
            fastest = ms;
            let _ = storage::set_u32("fastest", fastest);
        }
        let _ = storage::set_u32("solved", count);
        // a moment before a press counts, so the tilt that finished it doesn't start the next
        let until = millis() + 600;
        loop {
            solved(ms, fastest, record);
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
