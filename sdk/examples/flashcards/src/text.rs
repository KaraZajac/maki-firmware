//! Text on maki's screen, in maki's fonts: wrapped to fit, as big as fits, cut to a line; and dates.

use std::ops::Range;

use maki_app::*;

/// A size to draw text at: one of maki's fonts, and how many times over (host API 9's
/// `text_scaled`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size(pub Style, pub i32);

/// A word or two, big.
pub const BIG: Size = Size(Style::Bold, 2);
pub const REGULAR: Size = Size(Style::Regular, 1);
pub const SMALL: Size = Size(Style::Small, 1);

/// The most characters a line can hold: every glyph in maki's fonts is at least a pixel wide with
/// a pixel's gap, so more than this never fit the screen (and maki measures 256 at most).
const LINE_CHARS: usize = 64;
/// Room kept at the right for the bar that shows where a long card is scrolled to.
pub const BAR: i32 = 4;

impl Size {
    /// A line's height.
    pub fn height(self) -> i32 { self.0.height() * self.1 }

    pub fn width(self, s: &str) -> i32 { screen::text_scaled_width(s, self.0, self.1) }

    pub fn draw(self, x: i32, y: i32, s: &str, color: Color) {
        if self.1 == 1 {
            screen::text(x, y, s, self.0, color);
        } else {
            screen::text_scaled(x, y, s, self.0, self.1, color);
        }
    }

    /// Whether `s` fits on a line `width` pixels wide.
    fn fits(self, s: &str, width: i32) -> bool { s.chars().count() <= LINE_CHARS && self.width(s) <= width }
}

/// The lines `text` takes at `size` in `width` pixels, each a range of it: broken at spaces where
/// it can, inside a word too wide for a line, and at each line break. The spaces where a line is
/// broken aren't in either line. And whether a word was broken.
pub fn wrap(text: &str, size: Size, width: i32) -> (Vec<Range<usize>>, bool) {
    let mut lines = Vec::new();
    let mut broken = false;
    let mut at = 0;
    for para in text.split('\n') {
        broken |= wrap_para(para, at, size, width, &mut lines);
        at += para.len() + 1;
    }
    (lines, broken)
}

/// One line of `text`'s lines (`wrap`), from `base`; whether a word was broken.
fn wrap_para(para: &str, base: usize, size: Size, width: i32, lines: &mut Vec<Range<usize>>) -> bool {
    if para.trim().is_empty() {
        lines.push(base..base);
        return false;
    }
    let mut broken = false;
    let mut rest = 0;
    while rest < para.len() {
        let line = &para[rest..];
        // as many whole words as fit: wider ones never fit if a narrower one didn't
        let ends = line.match_indices(' ').map(|(i, _)| i).chain(Some(line.len()));
        let mut words = None;
        for end in ends {
            let candidate = line[..end].trim_end();
            if candidate.trim_start().is_empty() {
                continue;
            }
            if !size.fits(candidate, width) {
                break;
            }
            words = Some(end);
        }
        // not even one word: as many characters of it as fit, one at least
        let end = words.unwrap_or_else(|| {
            broken = true;
            let chars: Vec<usize> =
                line.char_indices().map(|(i, _)| i).skip(1).chain(Some(line.len())).collect();
            let fit = chars.partition_point(|&end| size.fits(&line[..end], width));
            chars.get(fit.saturating_sub(1)).copied().unwrap_or(line.len())
        });
        let shown = line[..end].trim_end();
        lines.push(base + rest..base + rest + shown.len());
        rest += end;
        rest += para[rest..].len() - para[rest..].trim_start_matches(' ').len();
    }
    broken
}

/// `text` laid out at a size: the size, and its lines.
pub struct Laid {
    pub size: Size,
    pub lines: Vec<Range<usize>>,
    /// whether it's more than shows at once: it scrolls, its lines narrower by `BAR`
    pub scrolls: bool,
}

/// `text` at the first of `sizes` (biggest first) that shows it whole in `width` by `height`
/// without breaking a word, or at the last if that shows it whole; if none does, at the last, to
/// scroll.
pub fn lay_out(text: &str, sizes: &[Size], width: i32, height: i32) -> Laid {
    let shows = |size: Size| (height / size.height()).max(1) as usize;
    for (i, &size) in sizes.iter().enumerate() {
        let (lines, broken) = wrap(text, size, width);
        if lines.len() <= shows(size) && (!broken || i + 1 == sizes.len()) {
            return Laid { size, lines, scrolls: false };
        }
    }
    let size = sizes.last().copied().unwrap_or(SMALL);
    Laid { size, lines: wrap(text, size, width - BAR).0, scrolls: true }
}

/// The first line of `text`, cut with an ellipsis to fit `width` if it must.
pub fn cut(text: &str, size: Size, width: i32) -> String {
    let line = text.split('\n').next().unwrap_or("");
    if line.len() == text.len() && size.fits(line, width) {
        return line.to_string();
    }
    let mut s: String = line.trim_end().chars().take(LINE_CHARS).collect();
    loop {
        let shown = format!("{}\u{2026}", s.trim_end());
        if s.is_empty() || size.fits(&shown, width) {
            return shown;
        }
        s.pop();
    }
}

/// `s` centred across the screen at `y`.
pub fn centred(y: i32, s: &str, size: Size) { size.draw((WIDTH - size.width(s)) / 2, y, s, Color::Light) }

const MONTHS: [&str; 12] =
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// A day (days since 1970) as a date: "30 Sep". Howard Hinnant's `civil_from_days`.
pub fn date(day: u16) -> String {
    let z = day as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{d} {}", MONTHS[(m - 1) as usize % 12])
}

/// In how many days something is, in words: "today", "tomorrow", "in 3 days".
pub fn days(n: u16) -> String {
    match n {
        0 => "today".into(),
        1 => "tomorrow".into(),
        n => format!("in {n} days"),
    }
}

/// `n` and a noun for it: "1 card", "3 cards".
pub fn count(n: usize, one: &str, many: &str) -> String { format!("{n} {}", if n == 1 { one } else { many }) }
