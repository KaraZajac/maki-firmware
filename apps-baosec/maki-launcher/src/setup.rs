//! The recovery phrase at setup: showing its words, checking them, and typing one in to restore
//! (ARCHITECTURE.md, "One recovery phrase"). Three buttons throughout: left and right move, the
//! centre does what's offered.

use blitstr2::GlyphStyle;

use crate::ui::{Key, LINE, Screen};

fn random(n: usize) -> usize {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).ok();
    u32::from_le_bytes(b) as usize % n.max(1)
}

/// The words, one to a screen, to write down.
pub(crate) struct Phrase {
    pub(crate) words: Vec<String>,
    pub(crate) index: usize,
}

pub(crate) enum PhraseStep {
    Stay,
    /// all read: on to the check
    Check,
}

impl Phrase {
    pub(crate) fn draw(&self, screen: &Screen, clock: &str, linked: bool) {
        screen.begin();
        screen.status_bar(clock, linked);
        let top = screen.bar + 6;
        let n = self.words.len();
        screen.text(top, LINE, GlyphStyle::Small, false, true, &format!("Word {} of {}", self.index + 1, n));
        screen.text(top + 22, 24, GlyphStyle::Tall, false, true, &self.words[self.index]);
        screen.text(top + 56, 13, GlyphStyle::Small, false, true, "Write it down, in order.");
        screen.text(top + 69, 13, GlyphStyle::Small, false, true, "Keep it off computers.");
        let last = self.index + 1 == n;
        screen.action_bar(if last { "I wrote them all" } else { "next word" }, true);
        screen.end();
    }

    pub(crate) fn key(&mut self, key: Key) -> PhraseStep {
        let last = self.words.len() - 1;
        match key {
            Key::Left => self.index = self.index.saturating_sub(1),
            Key::Right => self.index = (self.index + 1).min(last),
            Key::Confirm if self.index == last => return PhraseStep::Check,
            Key::Confirm => self.index += 1,
            Key::Menu => {}
        }
        PhraseStep::Stay
    }
}

/// Asking for three of the words back, each among decoys, to be sure they were written down.
pub(crate) struct PhraseCheck {
    positions: Vec<usize>,
    step: usize,
    options: Vec<String>,
    selected: usize,
}

pub(crate) enum CheckStep {
    Stay,
    Passed,
    /// wrong: this word number (from 1)
    Wrong(usize),
}

impl PhraseCheck {
    pub(crate) fn new(words: &[String]) -> Self {
        let mut positions = Vec::new();
        while positions.len() < 3 {
            let p = random(words.len());
            if !positions.contains(&p) {
                positions.push(p);
            }
        }
        let mut check = PhraseCheck { positions, step: 0, options: Vec::new(), selected: 0 };
        check.deal(words);
        check
    }

    /// The right word and three others, shuffled.
    fn deal(&mut self, words: &[String]) {
        let right = words[self.positions[self.step]].clone();
        let mut options = vec![right.clone()];
        while options.len() < 4 {
            let w = maki_seed::word(random(2048)).unwrap().to_string();
            if !options.contains(&w) {
                options.push(w);
            }
        }
        // a demo build (MAKI_DEMO, for the emulator) leaves the right word first, so a script
        // can pass the check blind
        if option_env!("MAKI_DEMO").is_none() {
            for i in (1..options.len()).rev() {
                options.swap(i, random(i + 1));
            }
        }
        self.options = options;
        self.selected = 0;
    }

    pub(crate) fn draw(&self, screen: &Screen, clock: &str, linked: bool) {
        screen.begin();
        screen.status_bar(clock, linked);
        let top = screen.bar + 6;
        screen.text(top, LINE, GlyphStyle::Bold, false, true, "Check your words");
        let which = format!("Which is word {}?", self.positions[self.step] + 1);
        screen.text(top + LINE + 2, LINE, GlyphStyle::Regular, false, true, &which);
        screen.text(top + 40, 24, GlyphStyle::Tall, false, true, &self.options[self.selected]);
        screen.text(top + 70, 13, GlyphStyle::Small, false, true, &format!("{} of 4", self.selected + 1));
        screen.action_bar("this one", true);
        screen.end();
    }

    pub(crate) fn key(&mut self, key: Key, words: &[String]) -> CheckStep {
        let n = self.options.len();
        match key {
            Key::Left => self.selected = (self.selected + n - 1) % n,
            Key::Right => self.selected = (self.selected + 1) % n,
            Key::Confirm => {
                let position = self.positions[self.step];
                if self.options[self.selected] != words[position] {
                    return CheckStep::Wrong(position + 1);
                }
                self.step += 1;
                if self.step == self.positions.len() {
                    return CheckStep::Passed;
                }
                self.deal(words);
            }
            Key::Menu => {}
        }
        CheckStep::Stay
    }
}

#[derive(Clone, PartialEq, Eq)]
enum Opt {
    Letter(char),
    Word(&'static str),
    Back,
}

/// Typing a phrase in with three buttons: letters until a few words are left, then the word.
/// Every word on the list is fixed by its first four letters.
pub(crate) struct WordEntry {
    count: usize,
    words: Vec<&'static str>,
    prefix: String,
    selected: usize,
}

pub(crate) enum EntryStep {
    Stay,
    Done(Vec<&'static str>),
}

/// When this few words are left, they're offered to pick from.
const PICK_FROM: usize = 8;

impl WordEntry {
    pub(crate) fn new(count: usize) -> Self { WordEntry { count, words: Vec::new(), prefix: String::new(), selected: 0 } }

    fn options(&self) -> Vec<Opt> {
        let matching: Vec<&'static str> = maki_seed::starting_with(&self.prefix).collect();
        let mut o: Vec<Opt> = if !self.prefix.is_empty() && matching.len() <= PICK_FROM {
            matching.into_iter().map(Opt::Word).collect()
        } else {
            let mut letters: Vec<char> =
                matching.iter().filter_map(|w| w[self.prefix.len()..].chars().next()).collect();
            letters.dedup();
            letters.into_iter().map(Opt::Letter).collect()
        };
        if !self.prefix.is_empty() || !self.words.is_empty() {
            o.push(Opt::Back);
        }
        o
    }

    pub(crate) fn draw(&self, screen: &Screen, clock: &str, linked: bool) {
        screen.begin();
        screen.status_bar(clock, linked);
        let top = screen.bar + 6;
        let heading = format!("Word {} of {}", self.words.len() + 1, self.count);
        screen.text(top, LINE, GlyphStyle::Small, false, true, &heading);
        screen.text(top + LINE, LINE + 2, GlyphStyle::Monospace, false, true, &format!("{}_", self.prefix));
        let options = self.options();
        let (big, action) = match options.get(self.selected) {
            Some(Opt::Letter(c)) => (c.to_string(), "add this letter"),
            Some(Opt::Word(w)) => (w.to_string(), "use this word"),
            Some(Opt::Back) => (String::from("back"), if self.prefix.is_empty() { "undo last word" } else { "undo letter" }),
            None => (String::new(), ""),
        };
        screen.text(top + 40, 24, GlyphStyle::Tall, false, true, &big);
        let left = maki_seed::starting_with(&self.prefix).count();
        let note = if left == 1 { "1 word matches".to_string() } else { format!("{} words match", left) };
        screen.text(top + 70, 13, GlyphStyle::Small, false, true, &note);
        screen.action_bar(action, true);
        screen.end();
    }

    pub(crate) fn key(&mut self, key: Key) -> EntryStep {
        let options = self.options();
        let n = options.len().max(1);
        match key {
            Key::Left => self.selected = (self.selected + n - 1) % n,
            Key::Right => self.selected = (self.selected + 1) % n,
            Key::Confirm => {
                match options.get(self.selected).cloned() {
                    Some(Opt::Letter(c)) => self.prefix.push(c),
                    Some(Opt::Word(w)) => {
                        self.words.push(w);
                        self.prefix.clear();
                        if self.words.len() == self.count {
                            return EntryStep::Done(std::mem::take(&mut self.words));
                        }
                    }
                    Some(Opt::Back) => {
                        // back over a letter of the word being typed; once it's empty, the last word
                        let prefix_was_empty = self.prefix.pop().is_none();
                        if prefix_was_empty {
                            self.words.pop();
                        }
                    }
                    None => {}
                }
                self.selected = 0;
            }
            Key::Menu => {}
        }
        EntryStep::Stay
    }
}
