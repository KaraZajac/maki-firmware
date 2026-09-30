//! Magic 8-Ball: ask a question, shake maki (the motion permission), and the answer floats up in
//! its triangle: one of the classic twenty, picked by maki's random number generator. Without an
//! accelerometer, or rather than shake, press a button.

#![no_std]

use maki_app::*;

/// The twenty answers, each in the lines it's shown in: ten yes, five maybe, five no.
const ANSWERS: [&[&str]; 20] = [
    &["It is", "certain"],
    &["It is", "decidedly", "so"],
    &["Without", "a doubt"],
    &["Yes,", "definitely"],
    &["You may", "rely on it"],
    &["As I see it,", "yes"],
    &["Most", "likely"],
    &["Outlook", "good"],
    &["Yes"],
    &["Signs point", "to yes"],
    &["Reply hazy,", "try again"],
    &["Ask again", "later"],
    &["Better not", "tell you now"],
    &["Cannot", "predict now"],
    &["Concentrate", "and ask again"],
    &["Don't", "count on it"],
    &["My reply", "is no"],
    &["My sources", "say no"],
    &["Outlook not", "so good"],
    &["Very", "doubtful"],
];

/// The triangle the answer floats up in: its apex, and its base's ends.
const APEX: (i32, i32) = (WIDTH / 2, 4);
const BASE_Y: i32 = HEIGHT - 4;
const BASE_HALF: i32 = 60;
/// How often the accelerometer is read, in milliseconds.
const SAMPLE_MS: u32 = 40;
/// A shake: the acceleration's size well away from 1 g (in thousandths of one) in a few of the
/// samples; the answer comes once maki's been still again for a moment (about a quarter second).
const SHAKEN: i32 = 500;
const SHAKE_SAMPLES: u32 = 3;
const STILL_SAMPLES: u32 = 7;
/// A line of the answer, top to bottom, and the row the answer's lines are centred on (a little
/// below the triangle's middle, where it's wider).
const LINE: i32 = 14;
const ANSWER_MIDDLE: i32 = 81;

/// The triangle's half-width at `y`, `scale` of it (in 16ths), about its middle.
fn half_width(y: i32, scale: i32) -> i32 {
    let (top, bottom) = scaled_rows(scale);
    if y < top || y > bottom {
        return -1;
    }
    (y - top) * BASE_HALF * scale / 16 / (bottom - top).max(1)
}

/// The triangle's top and bottom rows, `scale` of it (in 16ths), about its middle.
fn scaled_rows(scale: i32) -> (i32, i32) {
    let mid = (APEX.1 + BASE_Y) / 2;
    let half = (BASE_Y - APEX.1) / 2 * scale / 16;
    (mid - half, mid + half)
}

/// The triangle, filled, `scale` of it: rising out of the dark, then whole.
fn triangle(scale: i32) {
    let (top, bottom) = scaled_rows(scale);
    for y in top..=bottom {
        let w = half_width(y, scale);
        if w >= 0 {
            screen::line(APEX.0 - w, y, APEX.0 + w, y, Color::Light);
        }
    }
}

/// A disc of radius `r` about (`cx`, `cy`).
fn disc(cx: i32, cy: i32, r: i32, color: Color) {
    for dy in -r..=r {
        let mut w = 0;
        while (w + 1) * (w + 1) + dy * dy <= r * r {
            w += 1;
        }
        screen::line(cx - w, cy + dy, cx + w, cy + dy, color);
    }
}

fn draw_answer(lines: &[&str]) {
    screen::clear(Color::Dark);
    triangle(16);
    // dark on light, in the triangle's wide part
    let top = ANSWER_MIDDLE - (lines.len() as i32 * LINE - 2) / 2;
    for (i, line) in lines.iter().enumerate() {
        let x = APEX.0 - screen::text_width(line, Style::Small) / 2;
        screen::text(x, top + i as i32 * LINE, line, Style::Small, Color::Dark);
    }
    screen::present();
}

fn draw_idle(shake: bool) {
    screen::clear(Color::Dark);
    screen::text_centred(14, "Ask a question,", Style::Regular, Color::Light);
    let then = if shake { "then shake maki" } else { "then press" };
    screen::text_centred(32, then, Style::Regular, Color::Light);
    if shake {
        screen::text_centred(53, "(or press a button)", Style::Small, Color::Light);
    }
    // the ball's window, with its 8
    disc(WIDTH / 2, 86, 13, Color::Light);
    screen::text_centred(86 - Style::Bold.height() / 2, "8", Style::Bold, Color::Dark);
    screen::present();
}

/// The triangle rising, then the answer in it; false if the owner left meanwhile.
fn reveal(answer: usize) -> bool {
    for scale in [4, 8, 12] {
        screen::clear(Color::Dark);
        triangle(scale);
        screen::present();
        if let Event::Exit = wait(Some(60)) {
            return false;
        }
    }
    draw_answer(ANSWERS[answer]);
    true
}

fn main() {
    let shake = motion::read().is_some();
    let mut answer: Option<usize> = None;
    let mut shown = true;
    // samples away from 1 g in this shake, and still ones since the last of them
    let (mut shaken, mut still) = (0u32, 0u32);
    draw_idle(shake);
    loop {
        let event = wait(if shake { Some(SAMPLE_MS) } else { None });
        let ask = match event {
            Event::Left | Event::Right | Event::Centre => true,
            Event::Timeout => {
                let (x, y, z) = motion::read().unwrap_or((0, 0, 1000));
                let (x, y, z) = (x as i32, y as i32, z as i32);
                let size2 = x * x + y * y + z * z;
                if !((1000 - SHAKEN).pow(2)..=(1000 + SHAKEN).pow(2)).contains(&size2) {
                    shaken += 1;
                    still = 0;
                    false
                } else if shaken > 0 {
                    // still again: the answer, if that was a shake and not a bump
                    still += 1;
                    let done = still >= STILL_SAMPLES;
                    let ask = done && shaken >= SHAKE_SAMPLES;
                    if done {
                        (shaken, still) = (0, 0);
                    }
                    ask
                } else {
                    false
                }
            }
            Event::Hidden => {
                shown = false;
                false
            }
            Event::Shown => {
                shown = true;
                match answer {
                    Some(a) => draw_answer(ANSWERS[a]),
                    None => draw_idle(shake),
                }
                false
            }
            Event::Exit => return,
            _ => false,
        };
        if ask && shown {
            let a = random_below(ANSWERS.len() as u32) as usize;
            answer = Some(a);
            if !reveal(a) {
                return;
            }
        }
    }
}

maki_app::main!(main);
