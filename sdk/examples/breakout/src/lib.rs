//! Breakout: knock out the wall of bricks with the ball, which bounces off a paddle below that
//! follows as maki is tilted (the motion permission), or that left and right move without an
//! accelerometer. Where the ball meets the paddle sets its angle; the centre serves it, and
//! pauses. Three balls a game, a little faster with each wall cleared; keeps the best score.

#![no_std]

use core::fmt::Write;

use maki_app::*;

/// The wall of bricks: rows and columns, a brick's size and where the first is, every brick a
/// pixel from the next across and two down.
const ROWS: usize = 5;
const COLS: usize = 8;
const BRICK_W: i32 = 15;
const BRICK_H: i32 = 5;
const BRICKS_TOP: i32 = 17;
/// Where the ball bounces at the top, under the score.
const CEILING: i32 = 12;
/// The paddle: its size, and where it runs.
const PADDLE_W: i32 = 22;
const PADDLE_H: i32 = 3;
const PADDLE_Y: i32 = 103;
/// The ball's side, in pixels.
const BALL: i32 = 3;
/// Positions and speeds in 256ths of a pixel (speeds a step).
const ONE: i32 = 256;
/// A step's length, the ball's speed to start with, how much faster each wall makes it (in
/// 256ths), and the fastest it gets.
const STEP_MS: u32 = 33;
const SPEED: i32 = 2 * ONE;
const FASTER: i32 = 30;
const FASTEST: i32 = 4 * ONE;
/// How far the paddle moves in a step at most, a tilt that takes it to either end (thousandths
/// of a g), and a press's move without an accelerometer.
const PADDLE_STEP: i32 = 5;
const FULL_TILT: i32 = 450;
const PRESS: i32 = 12;
const BALLS: u32 = 3;

fn isqrt(n: i32) -> i32 {
    if n <= 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

fn brick_x(c: usize) -> i32 { 1 + c as i32 * (BRICK_W + 1) }

fn brick_y(r: usize) -> i32 { BRICKS_TOP + r as i32 * (BRICK_H + 2) }

struct Game {
    /// A bit a brick still standing, a byte a row.
    bricks: [u8; ROWS],
    /// The paddle's left edge, in pixels.
    paddle: i32,
    /// The ball's top left, and its speed, in 256ths.
    x: i32,
    y: i32,
    vx: i32,
    vy: i32,
    speed: i32,
    /// On the paddle, waiting for the centre.
    serving: bool,
    score: u32,
    balls: u32,
    walls: u32,
}

enum Step {
    Played,
    /// The ball went past the paddle.
    Lost,
}

impl Game {
    fn new() -> Game {
        let mut g = Game {
            bricks: [0xff; ROWS],
            paddle: (WIDTH - PADDLE_W) / 2,
            x: 0,
            y: 0,
            vx: 0,
            vy: 0,
            speed: SPEED,
            serving: true,
            score: 0,
            balls: BALLS,
            walls: 0,
        };
        g.ride();
        g
    }

    /// The ball on the paddle, waiting to be served.
    fn ride(&mut self) {
        self.serving = true;
        self.x = (self.paddle + (PADDLE_W - BALL) / 2) * ONE;
        self.y = (PADDLE_Y - BALL) * ONE;
    }

    fn serve(&mut self) {
        self.serving = false;
        // up, a little to one side or the other
        let side = if random_below(2) == 0 { -1 } else { 1 };
        self.vx = side * self.speed / 3;
        self.vy = -isqrt(self.speed * self.speed - self.vx * self.vx);
    }

    /// The brick at a pixel, if one's standing there.
    fn brick(&self, x: i32, y: i32) -> Option<(usize, usize)> {
        let r = (y - BRICKS_TOP).div_euclid(BRICK_H + 2);
        let c = (x - 1).div_euclid(BRICK_W + 1);
        if !(0..ROWS as i32).contains(&r) || !(0..COLS as i32).contains(&c) {
            return None;
        }
        let (r, c) = (r as usize, c as usize);
        let inside = y < brick_y(r) + BRICK_H && x < brick_x(c) + BRICK_W;
        (inside && self.bricks[r] & (1 << c) != 0).then_some((r, c))
    }

    /// Knocks out a brick the ball, its top left at (x, y) in pixels, touches: whether it hit one.
    fn knock(&mut self, x: i32, y: i32) -> bool {
        for (cx, cy) in [(x, y), (x + BALL - 1, y), (x, y + BALL - 1), (x + BALL - 1, y + BALL - 1)] {
            if let Some((r, c)) = self.brick(cx, cy) {
                self.bricks[r] &= !(1 << c);
                // the rows further up are worth more
                self.score += (ROWS - r) as u32;
                return true;
            }
        }
        false
    }

    /// The paddle towards where the tilt puts it, a step at a time, or moved by a press.
    fn steer(&mut self, tilt: Option<(i16, i16, i16)>, press: i32) {
        let room = WIDTH - PADDLE_W;
        let to = match tilt {
            Some((x, _, _)) => room / 2 + (x as i32).clamp(-FULL_TILT, FULL_TILT) * room / 2 / FULL_TILT,
            None => self.paddle + press,
        };
        let step = if tilt.is_some() { PADDLE_STEP } else { PRESS };
        self.paddle = (self.paddle + (to - self.paddle).clamp(-step, step)).clamp(0, room);
        if self.serving {
            self.ride();
        }
    }

    fn step(&mut self) -> Step {
        if self.serving {
            return Step::Played;
        }
        // a pixel at a time at most, so the ball can't pass through a brick
        let n = ((self.vx.abs().max(self.vy.abs()) + ONE - 1) / ONE).max(1);
        for _ in 0..n {
            let x = self.x + self.vx / n;
            let (px, py) = (x.div_euclid(ONE), self.y.div_euclid(ONE));
            // off a wall, or else a brick: knock takes the brick out, so it's only asked past the walls
            if px < 0 || px + BALL > WIDTH || self.knock(px, py) {
                self.vx = -self.vx;
            } else {
                self.x = x;
            }
            let y = self.y + self.vy / n;
            let (px, py) = (self.x.div_euclid(ONE), y.div_euclid(ONE));
            if py < CEILING || self.knock(px, py) {
                self.vy = -self.vy;
            } else if self.vy > 0
                && py + BALL >= PADDLE_Y
                && py + BALL <= PADDLE_Y + PADDLE_H
                && px + BALL > self.paddle
                && px < self.paddle + PADDLE_W
            {
                // off the paddle: straight up from its middle, more to the side towards its ends
                let off = ((px + BALL / 2) - (self.paddle + PADDLE_W / 2)) * ONE / (PADDLE_W / 2 + 1);
                self.vx = self.speed * off.clamp(-ONE, ONE) * 3 / 4 / ONE;
                self.vy = -isqrt(self.speed * self.speed - self.vx * self.vx);
                self.y = (PADDLE_Y - BALL) * ONE;
            } else {
                self.y = y;
            }
            if self.y.div_euclid(ONE) >= HEIGHT {
                return Step::Lost;
            }
        }
        if self.bricks.iter().all(|&r| r == 0) {
            // a wall cleared: another, a little faster
            self.walls += 1;
            self.bricks = [0xff; ROWS];
            self.speed = (self.speed + self.speed * FASTER / ONE).min(FASTEST);
            self.ride();
        }
        Step::Played
    }
}

fn draw(g: &Game, best: u32, paused: bool) {
    screen::clear(Color::Dark);
    let mut line = Buf::<24>::new();
    let _ = write!(line, "{}", g.score);
    screen::text(1, -1, line.as_str(), Style::Small, Color::Light);
    if best > 0 && g.score <= best {
        line.clear();
        let _ = write!(line, "best {best}");
        screen::text_centred(-1, line.as_str(), Style::Small, Color::Light);
    }
    for i in 0..g.balls.saturating_sub(if g.serving { 1 } else { 0 }) {
        screen::fill_rect(WIDTH - 5 - i as i32 * 6, 3, BALL, BALL, Color::Light);
    }
    screen::line(0, CEILING - 1, WIDTH - 1, CEILING - 1, Color::Light);
    for r in 0..ROWS {
        for c in 0..COLS {
            if g.bricks[r] & (1 << c) != 0 {
                screen::fill_rect(brick_x(c), brick_y(r), BRICK_W, BRICK_H, Color::Light);
            }
        }
    }
    screen::fill_rect(g.paddle, PADDLE_Y, PADDLE_W, PADDLE_H, Color::Light);
    screen::fill_rect(g.x.div_euclid(ONE), g.y.div_euclid(ONE), BALL, BALL, Color::Light);
    if paused || g.serving {
        let what = if paused { "paused: centre" } else { "centre: serve" };
        screen::fill_rect(20, 64, 88, 14, Color::Dark);
        screen::text_centred(65, what, Style::Small, Color::Light);
    }
    screen::present();
}

fn title(best: u32, level: bool) {
    screen::clear(Color::Dark);
    screen::text_centred(8, "Breakout", Style::Tall, Color::Light);
    for c in 0..6 {
        screen::fill_rect(22 + c * 14, 36, 12, 4, Color::Light);
    }
    screen::fill_rect(58, 50, 3, 3, Color::Light);
    screen::fill_rect(52, 58, 22, 3, Color::Light);
    screen::text_centred(
        66,
        if level { "tilt maki: the paddle" } else { "left, right: the paddle" },
        Style::Small,
        Color::Light,
    );
    screen::text_centred(79, "centre: play", Style::Small, Color::Light);
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
    let mut next = millis() + STEP_MS as u64;
    loop {
        draw(&g, best, paused);
        let event = if paused { wait(None) } else { wait(Some(next.saturating_sub(millis()) as u32)) };
        let tilt = motion::read();
        match event {
            Event::Timeout if !paused => {
                g.steer(tilt, 0);
                if let Step::Lost = g.step() {
                    g.balls -= 1;
                    if g.balls == 0 {
                        return Some(g.score);
                    }
                    g.ride();
                }
                // behind (a busy moment): carry on from now rather than rushing to catch up
                next = (next + STEP_MS as u64).max(millis());
            }
            Event::Left | Event::Right if !paused && tilt.is_none() => {
                g.steer(None, if event == Event::Left { -PRESS } else { PRESS })
            }
            Event::Centre if g.serving && !paused => g.serve(),
            Event::Centre => {
                paused = !paused;
                next = millis() + STEP_MS as u64;
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
        title(best, motion::read().is_some());
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
        // a moment before a press counts, so the one that ended it doesn't start the next
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
