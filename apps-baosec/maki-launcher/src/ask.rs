//! Asks: a decision for the owner, shown over whatever is in front (`Launcher::ask`).
//!
//! The screen offers one thing at a time and the centre does it. A plain ask offers "allow",
//! and left or right switches to "deny". An ask with choices (two logins for one site) goes
//! through them with left and right, then Cancel. The asker's message is held until the owner
//! decides or time runs out, which is what keeps the asker waiting.

use std::collections::VecDeque;

use blitstr2::GlyphStyle;
use xous_ipc::Buffer;

use crate::api::{ANSWER_ALLOWED, ANSWER_DENIED, ANSWER_TIMED_OUT, AskRequest};
use crate::ui::{Key, LINE, Screen};

/// An ask shows its site in fixed-width type (8 pixels a character), 15 characters to a line,
/// on three lines, or two when there's a list to pick from.
const SITE_WIDTH: usize = 15;
const SITE_LINES: usize = 3;

pub(crate) struct Prompt {
    /// the asker's message, held until it's answered: the asker stays blocked until then
    msg: xous::MessageEnvelope,
    req: AskRequest,
    /// With choices: among them, then Cancel (index `choices.len()`). Plain: 0 allow, 1 deny.
    selected: usize,
    /// ticktimer milliseconds when it gives up. A deadline rather than a count of ticks: ticks
    /// queue up while the launcher is starved, and a burst of them would eat the owner's time.
    deadline_ms: u64,
}

impl Prompt {
    fn remaining_s(&self, now_ms: u64) -> u32 { ((self.deadline_ms.saturating_sub(now_ms) + 999) / 1000) as u32 }

    fn draw(&self, screen: &Screen, now_ms: u64, linked: bool) {
        screen.begin();
        screen.status_bar(&format!("{}s", self.remaining_s(now_ms)), linked);

        let n = self.req.choices.len();
        let site_lines = if n > 0 { SITE_LINES - 1 } else { SITE_LINES };
        let mut y = screen.bar + 4;
        let site = maki_proto::site::lines(&self.req.subject, SITE_WIDTH, site_lines).join("\n");
        screen.text(y, LINE * site_lines as isize + 2, GlyphStyle::Monospace, false, false, &site);
        y += LINE * site_lines as isize + 4;

        if n == 0 {
            screen.text(y, LINE, GlyphStyle::Regular, false, false, &self.req.question);
            screen.text(y + LINE, LINE, GlyphStyle::Bold, false, false, &self.req.detail);
            screen.action_bar(if self.selected == 0 { "allow" } else { "deny" }, true);
        } else if self.selected < n {
            let heading = format!("{} {}/{}", self.req.question, self.selected + 1, n);
            screen.text(y, LINE, GlyphStyle::Regular, false, false, &heading);
            screen.text(y + LINE, LINE, GlyphStyle::Bold, false, false, &self.req.choices[self.selected]);
            screen.action_bar("use this", true);
        } else {
            screen.text(y, LINE, GlyphStyle::Regular, false, false, &self.req.question);
            screen.text(y + LINE, LINE, GlyphStyle::Bold, false, false, "none of these");
            screen.action_bar("cancel", true);
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
                let prompt = Prompt { msg, deadline_ms: now + req.timeout_s.max(1) as u64 * 1000, req, selected: 0 };
                prompt.draw(screen, now, linked);
                self.current = Some(prompt);
            }
        }
        self.current.is_some()
    }

    /// Answer the ask on screen. The caller shows the next one or gives the screen back.
    pub(crate) fn finish(&mut self, answer: u32) {
        if let Some(Prompt { mut msg, mut req, selected, .. }) = self.current.take() {
            log::info!("ask from {} answered {}", req.subject, answer);
            req.answer = answer;
            req.choice = selected as u32;
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
        let n = p.req.choices.len();
        // plain: allow, deny; with choices: each of them, then cancel
        let stops = if n == 0 { 2 } else { n + 1 };
        match key {
            Key::Left => p.selected = (p.selected + stops - 1) % stops,
            Key::Right => p.selected = (p.selected + 1) % stops,
            Key::Confirm if n == 0 => return Some(if p.selected == 0 { ANSWER_ALLOWED } else { ANSWER_DENIED }),
            Key::Confirm => return Some(if p.selected < n { ANSWER_ALLOWED } else { ANSWER_DENIED }),
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
