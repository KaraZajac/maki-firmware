//! Asks: a decision for the owner, shown over whatever is in front (`Launcher::ask`).
//!
//! The screen offers one thing at a time and the centre does it; left and right go between the
//! things on offer. A plain ask offers "allow", then "deny". An ask with choices (two logins for
//! one site) offers each of them, then cancel. An ask with pages (a transaction to sign) goes
//! through them first, the centre moving on, then offers its two answers. The asker's message
//! is held until the owner decides or time runs out, which is what keeps the asker waiting.

use std::collections::VecDeque;

use blitstr2::GlyphStyle;
use xous_ipc::Buffer;

use crate::api::{ANSWER_ALLOWED, ANSWER_DENIED, ANSWER_TIMED_OUT, ASK_APP_SIDELOADED, AskRequest};
use crate::ui::{H, Key, LINE, SMALL_LINE, Screen, W};

/// An ask shows its site in fixed-width type (8 pixels a character), 15 characters to a line,
/// on three lines, or two when there's a list to pick from.
const SITE_WIDTH: usize = 15;
const SITE_LINES: usize = 3;
/// Presses this soon after an ask appears are ignored: one already on its way, meant for what
/// was on screen before, mustn't answer it.
const SETTLE_MS: u64 = 700;

/// A line of a page: fixed-width, small prose, or the space between paragraphs.
enum Row {
    Mono(String),
    Small(String),
    Gap,
}

impl Row {
    fn height(&self) -> isize {
        match self {
            Row::Mono(_) => LINE,
            Row::Small(_) => SMALL_LINE,
            Row::Gap => 4,
        }
    }
}

/// One thing an ask offers: the centre does it.
enum Stop {
    /// a screen of what's being decided; the centre moves on
    Page { heading: String, value: String, rows: Vec<Row> },
    Choice(usize),
    Yes,
    No,
}

/// How wide a line of prose may be: the screen, less the text's margins, and a little room in
/// case the display's text runs wider than the glyphs add up to.
const PROSE_WIDTH: isize = W - 8;

/// Prose in maki's small type, in lines that fit across the screen: at its own line breaks, then
/// between words (a word too long for a line breaks where it has to).
fn prose_lines(text: &str) -> Vec<String> {
    let width = |s: &str| -> isize {
        let w: isize = s.chars().filter_map(|c| blitstr2::small_glyph(c).ok()).map(|g| g.wide as isize + g.kern as isize).sum();
        (w - 1).max(0)
    };
    let mut out = Vec::new();
    for paragraph in text.split('\n') {
        let mut line = String::new();
        for word in paragraph.split(' ').filter(|w| !w.is_empty()) {
            let trial = if line.is_empty() { word.to_string() } else { format!("{line} {word}") };
            if width(&trial) <= PROSE_WIDTH {
                line = trial;
                continue;
            }
            if !line.is_empty() {
                out.push(std::mem::take(&mut line));
            }
            for c in word.chars() {
                line.push(c);
                if width(&line) > PROSE_WIDTH && line.chars().count() > 1 {
                    line.pop();
                    out.push(std::mem::take(&mut line));
                    line.push(c);
                }
            }
        }
        out.push(line);
    }
    out
}

/// Fixed-width text in lines that fit across the screen: at its own line breaks, then every
/// `SITE_WIDTH` characters.
fn mono_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let chars: Vec<char> = line.chars().collect();
        if chars.is_empty() {
            out.push(String::new());
        }
        for piece in chars.chunks(SITE_WIDTH) {
            out.push(piece.iter().collect());
        }
    }
    out
}

impl Stop {
    /// The stops of an ask, in order.
    fn of(req: &AskRequest, screen: &Screen) -> Vec<Stop> {
        let mut stops = Vec::new();
        // the space for text between the heading (or the value) and the bottom line
        let top = screen.bar + 4;
        let bottom = H - SMALL_LINE - 2;
        for page in &req.pages {
            let mut rows: Vec<Row> = mono_lines(&page.mono).into_iter().map(Row::Mono).collect();
            if !page.prose.is_empty() {
                if !rows.is_empty() {
                    rows.push(Row::Gap);
                }
                // an empty line between paragraphs is a gap, not a whole line
                rows.extend(prose_lines(&page.prose).into_iter().map(|l| if l.is_empty() { Row::Gap } else { Row::Small(l) }));
            }
            // as many rows as fit a screen, the value taking room on the first; what doesn't
            // fit goes on screens of its own, under the same heading
            let mut room = bottom - top - if page.value.is_empty() { 0 } else { LINE + 2 };
            let mut screen_rows = Vec::new();
            let mut n = 1;
            for row in rows {
                if row.height() > room && !screen_rows.is_empty() {
                    let heading = if n == 1 { page.heading.clone() } else { format!("{} ({})", page.heading, n) };
                    let value = if n == 1 { page.value.clone() } else { String::new() };
                    stops.push(Stop::Page { heading, value, rows: std::mem::take(&mut screen_rows) });
                    n += 1;
                    room = bottom - top;
                }
                room -= row.height();
                screen_rows.push(row);
            }
            let heading = if n == 1 { page.heading.clone() } else { format!("{} ({})", page.heading, n) };
            let value = if n == 1 { page.value.clone() } else { String::new() };
            stops.push(Stop::Page { heading, value, rows: screen_rows });
        }
        if req.choices.is_empty() {
            stops.push(Stop::Yes);
        } else {
            stops.extend((0..req.choices.len()).map(Stop::Choice));
        }
        stops.push(Stop::No);
        stops
    }
}

pub(crate) struct Prompt {
    /// the asker's message, held until it's answered: the asker stays blocked until then
    msg: xous::MessageEnvelope,
    req: AskRequest,
    stops: Vec<Stop>,
    selected: usize,
    /// ticktimer milliseconds when it gives up. A deadline rather than a count of ticks: ticks
    /// queue up while the launcher is starved, and a burst of them would eat the owner's time.
    deadline_ms: u64,
    /// and when it appeared
    shown_ms: u64,
}

impl Prompt {
    fn remaining_s(&self, now_ms: u64) -> u32 { ((self.deadline_ms.saturating_sub(now_ms) + 999) / 1000) as u32 }

    fn label<'a>(&'a self, custom: &'a str, default: &'a str) -> &'a str {
        if custom.is_empty() { default } else { custom }
    }

    fn draw(&self, screen: &Screen, now_ms: u64, linked: bool) {
        screen.begin();
        let countdown = format!("{}s", self.remaining_s(now_ms));
        let mut y = screen.bar + 4;

        if let Stop::Page { heading, value, rows } = &self.stops[self.selected] {
            screen.titled_bar(heading, &countdown, linked);
            if !value.is_empty() {
                screen.text(y, LINE, GlyphStyle::Bold, false, false, value);
                y += LINE + 2;
            }
            for row in rows {
                match row {
                    Row::Mono(line) => screen.text(y, LINE, GlyphStyle::Monospace, false, false, line),
                    Row::Small(line) => screen.text(y, SMALL_LINE, GlyphStyle::Small, false, false, line),
                    Row::Gap => {}
                }
                y += row.height();
            }
            screen.action_bar("next", true);
            screen.end();
            return;
        }

        if self.req.app != 0 {
            // an app's question: under its own bar, as over the app, with no site in it
            screen.app_bar(&self.req.subject, &countdown, self.req.app == ASK_APP_SIDELOADED);
            screen.text(y, LINE * 2, GlyphStyle::Bold, false, false, &self.req.question);
            y += LINE * 2 + 4;
            screen.text(y, LINE * 3, GlyphStyle::Regular, false, false, &self.req.detail);
            let action = match self.stops[self.selected] {
                Stop::Yes => self.label(&self.req.yes, "allow"),
                _ => self.label(&self.req.no, "deny"),
            };
            screen.action_bar(action, true);
            screen.end();
            return;
        }

        screen.status_bar(&countdown, linked);
        let n = self.req.choices.len();
        let site_lines = if n > 0 { SITE_LINES - 1 } else { SITE_LINES };
        let site = maki_proto::site::lines(&self.req.subject, SITE_WIDTH, site_lines).join("\n");
        screen.text(y, LINE * site_lines as isize + 2, GlyphStyle::Monospace, false, false, &site);
        y += LINE * site_lines as isize + 4;

        match self.stops[self.selected] {
            Stop::Choice(i) => {
                let heading = format!("{} {}/{}", self.req.question, i + 1, n);
                screen.text(y, LINE, GlyphStyle::Regular, false, false, &heading);
                screen.text(y + LINE, LINE, GlyphStyle::Bold, false, false, &self.req.choices[i]);
                screen.action_bar("use this", true);
            }
            Stop::No if n > 0 => {
                screen.text(y, LINE, GlyphStyle::Regular, false, false, &self.req.question);
                screen.text(y + LINE, LINE, GlyphStyle::Bold, false, false, "none of these");
                screen.action_bar(self.label(&self.req.no, "cancel"), true);
            }
            ref stop => {
                screen.text(y, LINE, GlyphStyle::Regular, false, false, &self.req.question);
                screen.text(y + LINE, LINE, GlyphStyle::Bold, false, false, &self.req.detail);
                let action = match stop {
                    Stop::Yes => self.label(&self.req.yes, "allow"),
                    _ => self.label(&self.req.no, "deny"),
                };
                screen.action_bar(action, true);
            }
        }
        screen.end();
    }
}

/// Asks waiting for the owner, and the one on screen.
pub(crate) struct Asking {
    pub(crate) queue: VecDeque<(xous::MessageEnvelope, AskRequest)>,
    current: Option<Prompt>,
    tt: ticktimer_server::Ticktimer,
}

impl Asking {
    pub(crate) fn new() -> Self {
        Asking { queue: VecDeque::new(), current: None, tt: ticktimer_server::Ticktimer::new().unwrap() }
    }

    pub(crate) fn active(&self) -> bool { self.current.is_some() }

    /// Show the next ask waiting, if there is one and none is showing. Returns whether one is.
    pub(crate) fn show_next(&mut self, screen: &Screen, linked: bool) -> bool {
        if self.current.is_none() {
            if let Some((msg, req)) = self.queue.pop_front() {
                let now = self.tt.elapsed_ms();
                let stops = Stop::of(&req, screen);
                let prompt = Prompt {
                    msg,
                    deadline_ms: now + req.timeout_s.max(1) as u64 * 1000,
                    shown_ms: now,
                    req,
                    stops,
                    selected: 0,
                };
                prompt.draw(screen, now, linked);
                self.current = Some(prompt);
            }
        }
        self.current.is_some()
    }

    /// Answer the ask on screen. The caller shows the next one or gives the screen back.
    pub(crate) fn finish(&mut self, answer: u32) {
        if let Some(Prompt { mut msg, mut req, stops, selected, .. }) = self.current.take() {
            log::info!("ask from {} answered {}", req.subject, answer);
            req.answer = answer;
            req.choice = match stops.get(selected) {
                Some(Stop::Choice(i)) => *i as u32,
                _ => 0,
            };
            if let Some(mem) = msg.body.memory_message_mut() {
                let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                buffer.replace(req).ok();
            }
            // dropping `msg` returns it, which unblocks the asker
        }
    }

    /// A button while an ask is on screen: returns the answer once there is one.
    pub(crate) fn key(&mut self, key: Key, screen: &Screen, linked: bool) -> Option<u32> {
        let now = self.tt.elapsed_ms();
        let p = self.current.as_mut()?;
        if now < p.shown_ms + SETTLE_MS {
            return None;
        }
        let stops = p.stops.len();
        match key {
            Key::Left => p.selected = (p.selected + stops - 1) % stops,
            Key::Right => p.selected = (p.selected + 1) % stops,
            Key::Confirm => match p.stops[p.selected] {
                Stop::Page { .. } => p.selected += 1, // a page is never last
                Stop::Choice(_) | Stop::Yes => return Some(ANSWER_ALLOWED),
                Stop::No => return Some(ANSWER_DENIED),
            },
            // no menu over an ask: it has to be answered, or left to time out
            Key::Menu => return None,
        }
        p.draw(screen, now, linked);
        None
    }

    /// Once a second while an ask is on screen: returns an answer when time is up.
    pub(crate) fn tick(&mut self, screen: &Screen, linked: bool) -> Option<u32> {
        let now = self.tt.elapsed_ms();
        let p = self.current.as_mut()?;
        if p.remaining_s(now) == 0 {
            return Some(ANSWER_TIMED_OUT);
        }
        p.draw(screen, now, linked);
        None
    }

    /// Redraw the ask on screen, if any (the link dot changed under it).
    pub(crate) fn redraw(&self, screen: &Screen, linked: bool) {
        if let Some(p) = &self.current {
            p.draw(screen, self.tt.elapsed_ms(), linked);
        }
    }
}
