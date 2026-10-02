//! Typing a passphrase with the three buttons and the jog dial, for a passphrase wallet
//! (maki-keys' `OpenWallet`). Left and right go through the characters of a set, then delete,
//! done, the next set and cancel; the jog dial changes the set (a-z, A-Z, 0-9, then the space and the
//! symbols); the centre takes what's chosen. What's typed shows as it's typed, spaces as a dot: a
//! passphrase typed wrong is another wallet, an empty one, so it's better seen.

use blitstr2::GlyphStyle;

use crate::ui::{Key, LINE, Screen};

/// The sets, by name, and their characters: printable ASCII, every one of them.
const SETS: [(&str, &str); 4] = [
    ("abc", "abcdefghijklmnopqrstuvwxyz"),
    ("ABC", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    ("123", "0123456789"),
    ("#+=", " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
];

/// The most of what's typed the screen shows at once (the end of it): the monospace font's
/// characters across the screen.
const SHOWN: usize = 15;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Opt {
    Char(char),
    Delete,
    Done,
    /// on to the next set, for those not using the jog dial
    NextSet,
    Cancel,
}

pub(crate) struct PassphraseEntry {
    typed: String,
    set: usize,
    /// where each set was left: coming back to it finds the same place
    at: [usize; SETS.len()],
}

pub(crate) enum PassphraseStep {
    Stay,
    Done(String),
    Cancel,
}

/// What's typed as the screen shows it: spaces as a middle dot, which no passphrase has (they're
/// ASCII), so a space at either end can't hide.
pub(crate) fn shown(text: &str) -> String { text.chars().map(|c| if c == ' ' { '·' } else { c }).collect() }

impl PassphraseEntry {
    pub(crate) fn new() -> Self {
        // all its room at once: a string that grows leaves copies of its start behind
        let typed = String::with_capacity(maki_keys::MAX_PASSPHRASE);
        PassphraseEntry { typed, set: 0, at: [0; SETS.len()] }
    }

    fn options(&self) -> Vec<Opt> {
        let mut o: Vec<Opt> = Vec::with_capacity(40);
        if self.typed.len() < maki_keys::MAX_PASSPHRASE {
            o.extend(SETS[self.set].1.chars().map(Opt::Char));
        }
        if !self.typed.is_empty() {
            o.push(Opt::Delete);
            o.push(Opt::Done);
        }
        o.push(Opt::NextSet);
        o.push(Opt::Cancel);
        o
    }

    fn choice(&self) -> Opt {
        let options = self.options();
        options[self.at[self.set].min(options.len() - 1)]
    }

    pub(crate) fn key(&mut self, key: Key) -> PassphraseStep {
        let options = self.options();
        let n = options.len();
        let at = self.at[self.set].min(n - 1);
        match key {
            Key::Left => self.at[self.set] = (at + n - 1) % n,
            Key::Right => self.at[self.set] = (at + 1) % n,
            Key::Down => self.set = (self.set + 1) % SETS.len(),
            Key::Up => self.set = (self.set + SETS.len() - 1) % SETS.len(),
            Key::Confirm => match options[at] {
                Opt::Char(c) => {
                    self.typed.push(c);
                    // full: the delete is where the characters were
                    if self.typed.len() == maki_keys::MAX_PASSPHRASE {
                        self.at[self.set] = 0;
                    }
                }
                Opt::Delete => {
                    self.typed.pop();
                    if self.typed.is_empty() {
                        self.at[self.set] = 0;
                    }
                }
                Opt::Done => {
                    let typed =
                        std::mem::replace(&mut self.typed, String::with_capacity(maki_keys::MAX_PASSPHRASE));
                    self.at = [0; SETS.len()];
                    return PassphraseStep::Done(typed);
                }
                Opt::NextSet => self.set = (self.set + 1) % SETS.len(),
                Opt::Cancel => {
                    self.clear();
                    return PassphraseStep::Cancel;
                }
            },
            Key::Menu => {}
        }
        PassphraseStep::Stay
    }

    /// Forget what's typed.
    pub(crate) fn clear(&mut self) {
        let mut bytes =
            std::mem::replace(&mut self.typed, String::with_capacity(maki_keys::MAX_PASSPHRASE)).into_bytes();
        bytes.fill(0);
        self.at = [0; SETS.len()];
    }

    pub(crate) fn draw(&self, screen: &Screen, clock: &str, linked: bool) {
        screen.begin();
        screen.status_bar(clock, linked);
        let top = screen.bar + 4;
        screen.text(top, LINE, GlyphStyle::Bold, false, true, "Passphrase");
        // the sets, the one in use in brackets
        let sets: Vec<String> = SETS
            .iter()
            .enumerate()
            .map(|(i, (name, _))| if i == self.set { format!("[{name}]") } else { name.to_string() })
            .collect();
        screen.text(top + LINE + 2, 13, GlyphStyle::Small, false, true, &sets.join(" "));
        // what's typed, its end if it's long, and where the next goes
        let chars: Vec<char> = self.typed.chars().collect();
        let tail: String = chars[chars.len().saturating_sub(SHOWN - 1)..].iter().collect();
        let more = if chars.len() > SHOWN - 1 { "…" } else { "" };
        screen.text(
            top + LINE + 18,
            LINE + 2,
            GlyphStyle::Monospace,
            false,
            true,
            &format!("{more}{}_", shown(&tail)),
        );
        let (big, action) = match self.choice() {
            Opt::Char(' ') => ("space".to_string(), "add a space".to_string()),
            Opt::Char(c) => (c.to_string(), format!("add {c}")),
            Opt::Delete => ("delete".to_string(), "delete the last".to_string()),
            Opt::Done => ("done".to_string(), format!("{} characters", chars.len())),
            Opt::NextSet => {
                let next = SETS[(self.set + 1) % SETS.len()].0;
                (format!("to {next}"), "the next set".to_string())
            }
            Opt::Cancel => ("cancel".to_string(), "cancel".to_string()),
        };
        screen.text(top + 2 * LINE + 26, 24, GlyphStyle::Tall, false, true, &big);
        screen.action_bar(&action, true);
        screen.end();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type_in(e: &mut PassphraseEntry, text: &str) {
        for c in text.chars() {
            let set = SETS.iter().position(|(_, cs)| cs.contains(c)).unwrap();
            while e.set != set {
                e.key(Key::Down);
            }
            while e.choice() != Opt::Char(c) {
                e.key(Key::Right);
            }
            assert!(matches!(e.key(Key::Confirm), PassphraseStep::Stay));
        }
    }

    fn done(e: &mut PassphraseEntry) -> String {
        while e.choice() != Opt::Done {
            e.key(Key::Left);
        }
        match e.key(Key::Confirm) {
            PassphraseStep::Done(p) => p,
            PassphraseStep::Stay | PassphraseStep::Cancel => panic!("not done"),
        }
    }

    #[test]
    fn every_printable_ascii_character_can_be_typed() {
        let all: String = (0x20u8..0x7f).map(|b| b as char).collect();
        assert_eq!(SETS.iter().map(|(_, cs)| cs.len()).sum::<usize>(), all.len());
        let mut e = PassphraseEntry::new();
        type_in(&mut e, &all);
        assert_eq!(done(&mut e), all);
        assert!(maki_keys::passphrase_is_valid(&all));
    }

    #[test]
    fn delete_and_the_sets_go_round() {
        let mut e = PassphraseEntry::new();
        // nothing typed: no delete, no done; up from the first set is the last
        assert!(!e.options().contains(&Opt::Done));
        e.key(Key::Up);
        assert_eq!(e.set, 3);
        type_in(&mut e, "ab c");
        while e.choice() != Opt::Delete {
            e.key(Key::Right);
        }
        e.key(Key::Confirm);
        assert_eq!(e.typed, "ab ");
        // the next set by its option, as well as the dial
        let set = e.set;
        while e.choice() != Opt::NextSet {
            e.key(Key::Right);
        }
        e.key(Key::Confirm);
        assert_eq!(e.set, (set + 1) % SETS.len());
        type_in(&mut e, "Z9");
        assert_eq!(done(&mut e), "ab Z9");
        // and it starts over
        assert!(e.typed.is_empty());
    }

    #[test]
    fn it_stops_at_the_longest_maki_takes() {
        let mut e = PassphraseEntry::new();
        type_in(&mut e, &"a".repeat(maki_keys::MAX_PASSPHRASE));
        // no characters to choose now: delete, done, the next set, cancel
        assert_eq!(e.options(), [Opt::Delete, Opt::Done, Opt::NextSet, Opt::Cancel]);
        assert_eq!(done(&mut e).len(), maki_keys::MAX_PASSPHRASE);
    }

    #[test]
    fn cancel_forgets_what_was_typed() {
        let mut e = PassphraseEntry::new();
        type_in(&mut e, "secret");
        while e.choice() != Opt::Cancel {
            e.key(Key::Left);
        }
        assert!(matches!(e.key(Key::Confirm), PassphraseStep::Cancel));
        assert!(e.typed.is_empty());
    }

    #[test]
    fn spaces_show_as_dots() {
        assert_eq!(shown(" a b "), "·a·b·");
    }
}
