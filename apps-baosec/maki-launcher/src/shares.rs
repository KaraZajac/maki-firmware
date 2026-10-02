//! Shamir backup's screens (SSKR, maki-keys' shares): choosing how many shares to make and how many
//! of them bring the phrase back, and showing each share's words to write down, eight to a screen,
//! numbered (ByteWords are four letters each: two fit across, a share takes a few screens).

use blitstr2::GlyphStyle;

use crate::ui::{Key, LINE, Screen};

/// The most shares a set has (SSKR's limit), and the fewest it may take: one would be the phrase
/// itself, in every share. maki-keys holds a request to the same.
pub(crate) const MOST: u8 = maki_keys::MAX_SHARES;
pub(crate) const FEWEST_NEEDED: u8 = maki_keys::MIN_NEEDED;

/// Choosing k of n: left and right change the number underlined, the centre goes on to the next,
/// then makes them.
pub(crate) struct SharesPick {
    pub(crate) needed: u8,
    pub(crate) made: u8,
    /// 0: how many it takes; 1: how many there are
    field: u8,
}

pub(crate) enum PickStep {
    Stay,
    Done { needed: u8, made: u8 },
}

impl SharesPick {
    pub(crate) fn new() -> Self { SharesPick { needed: 2, made: 3, field: 0 } }

    pub(crate) fn key(&mut self, key: Key) -> PickStep {
        let step =
            |v: u8, up: bool, lo: u8, hi: u8| if up { (v + 1).min(hi) } else { v.saturating_sub(1).max(lo) };
        match (key, self.field) {
            (Key::Left | Key::Down, 0) => self.needed = step(self.needed, false, FEWEST_NEEDED, MOST),
            (Key::Right | Key::Up, 0) => {
                self.needed = step(self.needed, true, FEWEST_NEEDED, MOST);
                self.made = self.made.max(self.needed);
            }
            (Key::Left | Key::Down, _) => self.made = step(self.made, false, self.needed, MOST),
            (Key::Right | Key::Up, _) => self.made = step(self.made, true, self.needed, MOST),
            (Key::Confirm, 0) => self.field = 1,
            (Key::Confirm, _) => return PickStep::Done { needed: self.needed, made: self.made },
            (Key::Menu, _) => {}
        }
        PickStep::Stay
    }

    pub(crate) fn draw(&self, screen: &Screen, clock: &str, linked: bool) {
        screen.begin();
        screen.status_bar(clock, linked);
        let top = screen.bar + 4;
        screen.text(top, LINE, GlyphStyle::Bold, false, true, "Shares");
        let (k, n) = (self.needed.to_string(), self.made.to_string());
        let line = if self.field == 0 { format!("[{k}] of {n}") } else { format!("{k} of [{n}]") };
        screen.text(top + LINE + 8, 24, GlyphStyle::Tall, false, true, &line);
        screen.text(
            top + LINE + 36,
            13,
            GlyphStyle::Small,
            false,
            true,
            &format!("Any {k} of the {n} bring"),
        );
        screen.text(top + LINE + 49, 13, GlyphStyle::Small, false, true, "your phrase back; fewer");
        screen.text(top + LINE + 62, 13, GlyphStyle::Small, false, true, "show nothing of it.");
        let action = if self.field == 0 { "how many it takes" } else { "make them" };
        screen.action_bar(action, true);
        screen.end();
    }
}

/// Words on a screen: four rows of two.
pub(crate) const PER_SCREEN: usize = 8;

/// Each share's words to write down, a screen of eight at a time; left and right go back and on,
/// the centre on.
pub(crate) struct SharesShow {
    pub(crate) shares: Vec<Vec<String>>,
    share: usize,
    page: usize,
}

pub(crate) enum ShowStep {
    Stay,
    /// all of them gone through
    Done,
}

impl SharesShow {
    pub(crate) fn new(shares: Vec<Vec<String>>) -> Self { SharesShow { shares, share: 0, page: 0 } }

    fn pages(&self, share: usize) -> usize { self.shares[share].len().div_ceil(PER_SCREEN).max(1) }

    fn last(&self) -> bool { self.share + 1 == self.shares.len() && self.page + 1 == self.pages(self.share) }

    /// A screen's rows: the words numbered from 1, two to a row, fifteen characters across (what a
    /// line of the fixed-width font holds).
    fn rows(&self) -> Vec<String> {
        let words = &self.shares[self.share];
        let first = self.page * PER_SCREEN;
        words[first..(first + PER_SCREEN).min(words.len())]
            .chunks(2)
            .enumerate()
            .map(|(r, pair)| {
                let n = first + 2 * r + 1;
                match pair {
                    [a, b] => format!("{n:>2} {a} {:>2} {b}", n + 1),
                    [a] => format!("{n:>2} {a}"),
                    _ => String::new(),
                }
            })
            .collect()
    }

    pub(crate) fn key(&mut self, key: Key) -> ShowStep {
        match key {
            Key::Left if self.page > 0 => self.page -= 1,
            Key::Left if self.share > 0 => {
                self.share -= 1;
                self.page = self.pages(self.share) - 1;
            }
            Key::Right | Key::Confirm if self.last() => {
                if key == Key::Confirm {
                    return ShowStep::Done;
                }
            }
            Key::Right | Key::Confirm if self.page + 1 < self.pages(self.share) => self.page += 1,
            Key::Right | Key::Confirm => {
                self.share += 1;
                self.page = 0;
            }
            _ => {}
        }
        ShowStep::Stay
    }

    pub(crate) fn draw(&self, screen: &Screen, clock: &str, linked: bool) {
        screen.begin();
        screen.status_bar(clock, linked);
        let top = screen.bar + 4;
        let words = self.shares[self.share].len();
        let first = self.page * PER_SCREEN + 1;
        let to = (first + PER_SCREEN - 1).min(words);
        let heading = format!("Share {} of {}: {first}-{to} of {words}", self.share + 1, self.shares.len());
        screen.text(top, 13, GlyphStyle::Small, false, true, &heading);
        for (i, row) in self.rows().iter().enumerate() {
            screen.text(
                top + 15 + i as isize * (LINE + 2),
                LINE + 2,
                GlyphStyle::Monospace,
                false,
                true,
                row,
            );
        }
        let action = if self.last() {
            "I wrote them all"
        } else if self.page + 1 == self.pages(self.share) {
            "next share"
        } else {
            "next words"
        };
        screen.action_bar(action, true);
        screen.end();
    }

    /// Forget the words.
    pub(crate) fn clear(&mut self) {
        for share in self.shares.drain(..) {
            for w in share {
                let mut b = w.into_bytes();
                b.fill(0);
            }
        }
    }
}

fn random(n: usize) -> usize {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).ok();
    u32::from_le_bytes(b) as usize % n.max(1)
}

/// Where a share's value is among its words: the words that differ between a split's shares (its
/// first say what it is, its last four are the checksum). maki's are 29 words (a 12-word phrase's)
/// or 46 (a 24-word one's).
fn value_words(len: usize) -> core::ops::Range<usize> {
    let value = if len >= 46 { 32 } else { 16 };
    len.saturating_sub(4 + value)..len.saturating_sub(4)
}

/// Asking for a word back from each share, among decoys, to be sure they were written down, as the
/// phrase's check does.
pub(crate) struct SharesCheck {
    /// the word asked of each share
    asked: Vec<usize>,
    share: usize,
    options: Vec<String>,
    selected: usize,
}

pub(crate) enum CheckStep {
    Stay,
    Passed,
    /// wrong: this share's word (both from 1)
    Wrong {
        share: usize,
        word: usize,
    },
}

impl SharesCheck {
    pub(crate) fn new(shares: &[Vec<String>]) -> Self {
        let asked = shares
            .iter()
            .map(|s| {
                let r = value_words(s.len());
                r.start + random(r.len())
            })
            .collect();
        let mut check = SharesCheck { asked, share: 0, options: Vec::new(), selected: 0 };
        check.deal(shares);
        check
    }

    /// The right word and three others, shuffled.
    fn deal(&mut self, shares: &[Vec<String>]) {
        let right = shares[self.share][self.asked[self.share]].clone();
        let mut options = vec![right];
        while options.len() < 4 {
            let w = maki_sskr::bytewords::word(random(256) as u8).to_string();
            if !options.contains(&w) {
                options.push(w);
            }
        }
        // a demo build (MAKI_DEMO, for the emulator) leaves the right word first, so a script can
        // pass the check blind
        if option_env!("MAKI_DEMO").is_none() {
            for i in (1..options.len()).rev() {
                options.swap(i, random(i + 1));
            }
        }
        self.options = options;
        self.selected = 0;
    }

    pub(crate) fn key(&mut self, key: Key, shares: &[Vec<String>]) -> CheckStep {
        let n = self.options.len();
        match key {
            Key::Left => self.selected = (self.selected + n - 1) % n,
            Key::Right => self.selected = (self.selected + 1) % n,
            Key::Confirm => {
                let word = self.asked[self.share];
                if self.options[self.selected] != shares[self.share][word] {
                    return CheckStep::Wrong { share: self.share + 1, word: word + 1 };
                }
                self.share += 1;
                if self.share == shares.len() {
                    return CheckStep::Passed;
                }
                self.deal(shares);
            }
            Key::Menu | Key::Up | Key::Down => {}
        }
        CheckStep::Stay
    }

    pub(crate) fn draw(&self, screen: &Screen, clock: &str, linked: bool) {
        screen.begin();
        screen.status_bar(clock, linked);
        let top = screen.bar + 6;
        screen.text(top, LINE, GlyphStyle::Bold, false, true, "Check your shares");
        let which = format!("Share {}, word {}?", self.share + 1, self.asked[self.share] + 1);
        screen.text(top + LINE + 2, LINE, GlyphStyle::Regular, false, true, &which);
        screen.text(top + 40, 24, GlyphStyle::Tall, false, true, &self.options[self.selected]);
        screen.text(top + 70, 13, GlyphStyle::Small, false, true, &format!("{} of 4", self.selected + 1));
        screen.action_bar("this one", true);
        screen.end();
    }
}

/// Typing shares in, to restore the phrase they put back together: each word by its letters until
/// a few words are left, then the word, as the phrase's words are typed. A share's length shows at
/// its fourth or fifth word, and each is read whole once it's all in: its checksum, and whether it's
/// from the same set as the first. Shares go on until as many are in as the first says it takes.
pub(crate) struct ShareEntry {
    /// shares read so far
    shares: Vec<maki_sskr::Share>,
    /// the share being typed: its words as bytes
    words: Vec<u8>,
    /// its length, once its first words say
    total: Option<usize>,
    prefix: String,
    selected: usize,
}

#[derive(Clone, PartialEq, Eq)]
enum Opt {
    Letter(char),
    Word(u8),
    Back,
}

pub(crate) enum EntryStep {
    Stay,
    /// something's wrong, in words: the last word is taken back
    Problem(String),
    /// a share read whole: how many there are, of how many it takes (0: more, from another group
    /// of a split of several)
    ShareRead {
        have: usize,
        need: usize,
    },
    /// enough shares: their words, to put together
    Done(Vec<Vec<String>>),
}

/// When this few words are left, they're offered to pick from (as the phrase's are).
const PICK_FROM: usize = 8;

impl ShareEntry {
    pub(crate) fn new() -> Self {
        ShareEntry { shares: Vec::new(), words: Vec::new(), total: None, prefix: String::new(), selected: 0 }
    }

    fn options(&self) -> Vec<Opt> {
        let matching: Vec<(u8, &'static str)> = maki_sskr::bytewords::starting_with(&self.prefix).collect();
        let mut o: Vec<Opt> = if !self.prefix.is_empty() && matching.len() <= PICK_FROM {
            matching.iter().map(|&(b, _)| Opt::Word(b)).collect()
        } else {
            let mut letters: Vec<char> =
                matching.iter().filter_map(|(_, w)| w[self.prefix.len()..].chars().next()).collect();
            letters.dedup();
            letters.into_iter().map(Opt::Letter).collect()
        };
        if !self.prefix.is_empty() || !self.words.is_empty() {
            o.push(Opt::Back);
        }
        o
    }

    pub(crate) fn key(&mut self, key: Key) -> EntryStep {
        let options = self.options();
        let n = options.len().max(1);
        match key {
            Key::Left => self.selected = (self.selected + n - 1) % n,
            Key::Right => self.selected = (self.selected + 1) % n,
            Key::Confirm => {
                let chosen = options.get(self.selected).cloned();
                self.selected = 0;
                match chosen {
                    Some(Opt::Letter(c)) => self.prefix.push(c),
                    Some(Opt::Back) => {
                        if self.prefix.pop().is_none() {
                            self.words.pop();
                            if self.words.len() < 5 {
                                self.total = None;
                            }
                        }
                    }
                    Some(Opt::Word(b)) => {
                        self.prefix.clear();
                        self.words.push(b);
                        return self.word_added();
                    }
                    None => {}
                }
            }
            Key::Menu | Key::Up | Key::Down => {}
        }
        EntryStep::Stay
    }

    /// After each word: the share's length once its first words say it, and the share read whole
    /// once it's all in.
    fn word_added(&mut self) -> EntryStep {
        match maki_sskr::expected_words(&self.words) {
            Err(e) => {
                self.words.pop();
                return EntryStep::Problem(format!("{e}: word {} can't begin a share", self.words.len() + 1));
            }
            Ok(total) => self.total = total.or(self.total),
        }
        if Some(self.words.len()) != self.total {
            return EntryStep::Stay;
        }
        let share = match maki_sskr::Share::from_word_bytes(&self.words) {
            Ok(s) => s,
            Err(e) => {
                self.words.pop();
                return EntryStep::Problem(format!("{e}"));
            }
        };
        // whether the shares so far are enough, as SSKR puts them together: in any order, from any
        // layout it allows (seedtool's splits of several groups too); a share that doesn't belong
        // with the others is left out, to be typed again or another typed instead
        self.shares.push(share);
        self.words.fill(0);
        self.words.clear();
        self.total = None;
        match maki_sskr::combine(&self.shares) {
            Ok(_) => {
                let words =
                    self.shares.iter().map(|s| s.words().iter().map(String::from).collect()).collect();
                self.clear();
                EntryStep::Done(words)
            }
            Err(maki_sskr::Error::TooFew { need, have }) => EntryStep::ShareRead { have, need },
            Err(maki_sskr::Error::TooFewGroups { .. }) => {
                EntryStep::ShareRead { have: self.shares.len(), need: 0 }
            }
            Err(e) => {
                self.shares.pop();
                EntryStep::Problem(format!("{e}"))
            }
        }
    }

    /// Forget what's typed and read.
    pub(crate) fn clear(&mut self) {
        self.words.fill(0);
        self.words.clear();
        self.shares.clear();
        self.prefix.clear();
        self.total = None;
    }

    pub(crate) fn draw(&self, screen: &Screen, clock: &str, linked: bool) {
        screen.begin();
        screen.status_bar(clock, linked);
        let top = screen.bar + 6;
        let of = self.total.map(|t| t.to_string()).unwrap_or_else(|| "?".into());
        let heading = format!("Share {}: word {} of {of}", self.shares.len() + 1, self.words.len() + 1);
        screen.text(top, LINE, GlyphStyle::Small, false, true, &heading);
        screen.text(top + LINE, LINE + 2, GlyphStyle::Monospace, false, true, &format!("{}_", self.prefix));
        let options = self.options();
        let (big, action) = match options.get(self.selected) {
            Some(Opt::Letter(c)) => (c.to_string(), "add this letter"),
            Some(Opt::Word(b)) => (maki_sskr::bytewords::word(*b).to_string(), "use this word"),
            Some(Opt::Back) => {
                (String::from("back"), if self.prefix.is_empty() { "undo last word" } else { "undo letter" })
            }
            None => (String::new(), ""),
        };
        screen.text(top + 40, 24, GlyphStyle::Tall, false, true, &big);
        let left = maki_sskr::bytewords::starting_with(&self.prefix).count();
        let note = if left == 1 { "1 word matches".to_string() } else { format!("{left} words match") };
        screen.text(top + 70, 13, GlyphStyle::Small, false, true, &note);
        screen.action_bar(action, true);
        screen.end();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k_of_n_within_what_sskr_takes() {
        let mut p = SharesPick::new();
        assert_eq!((p.needed, p.made), (2, 3));
        // never fewer than two needed, never more needed than made
        p.key(Key::Left);
        assert_eq!(p.needed, 2);
        for _ in 0..5 {
            p.key(Key::Right);
        }
        assert_eq!((p.needed, p.made), (7, 7));
        p.key(Key::Confirm);
        p.key(Key::Left);
        assert_eq!(p.made, 7, "not fewer made than needed");
        for _ in 0..20 {
            p.key(Key::Up);
        }
        assert_eq!(p.made, MOST);
        assert!(matches!(p.key(Key::Confirm), PickStep::Done { needed: 7, made: 16 }));
    }

    #[test]
    fn eight_words_a_screen_numbered_two_to_a_row() {
        let share = |n: usize| (0..n).map(|i| format!("w{i:03}")).collect::<Vec<_>>();
        let mut s = SharesShow::new(vec![share(29), share(29)]);
        assert_eq!(s.rows(), [" 1 w000  2 w001", " 3 w002  4 w003", " 5 w004  6 w005", " 7 w006  8 w007"]);
        assert!(s.rows().iter().all(|r| r.chars().count() <= 15));
        // four screens a share: 8, 8, 8, then 5
        let mut screens = 1;
        while !s.last() && screens < 100 {
            assert!(matches!(s.key(Key::Right), ShowStep::Stay));
            screens += 1;
        }
        assert_eq!(screens, 8);
        assert_eq!(s.rows(), ["25 w024 26 w025", "27 w026 28 w027", "29 w028"]);
        // back across into the first share's last screen
        for _ in 0..4 {
            s.key(Key::Left);
        }
        assert_eq!((s.share, s.page), (0, 3));
        // the centre on the very last screen is done
        for _ in 0..4 {
            s.key(Key::Confirm);
        }
        assert!(matches!(s.key(Key::Confirm), ShowStep::Done));
    }

    /// A share's words as maki-sskr writes them: shares of a phrase's entropy, `seed` making the
    /// split's randomness (its identifier among it).
    fn shares_from(seed: u8, k: usize, n: usize) -> Vec<Vec<String>> {
        let mut r = seed;
        maki_sskr::split(&[0x55; 16], k, n, |b| {
            for x in b.iter_mut() {
                r = r.wrapping_mul(31).wrapping_add(17);
                *x = r;
            }
        })
        .unwrap()
        .iter()
        .map(|s| s.words().iter().map(String::from).collect())
        .collect()
    }

    fn shares(k: usize, n: usize) -> Vec<Vec<String>> { shares_from(7, k, n) }

    /// Types `word` in as an owner would: its letters until it's offered, then it.
    fn type_word(e: &mut ShareEntry, word: &str) -> EntryStep {
        for _ in 0..8 {
            let options = e.options();
            if let Some(i) =
                options.iter().position(|o| *o == Opt::Word(maki_sskr::bytewords::byte(word).unwrap()))
            {
                e.selected = i;
                return e.key(Key::Confirm);
            }
            let next = word.chars().nth(e.prefix.len()).unwrap();
            e.selected = options.iter().position(|o| *o == Opt::Letter(next)).unwrap();
            assert!(matches!(e.key(Key::Confirm), EntryStep::Stay));
        }
        panic!("{word} never offered");
    }

    #[test]
    fn shares_typed_in_are_read_whole_and_put_back() {
        let set = shares(2, 3);
        assert_eq!(set[0].len(), 29);
        let mut e = ShareEntry::new();
        let mut last = EntryStep::Stay;
        for (i, w) in set[2].iter().enumerate() {
            last = type_word(&mut e, w);
            if i == 4 {
                assert_eq!(e.total, Some(29), "its length shows by its fifth word");
            }
        }
        assert!(matches!(last, EntryStep::ShareRead { have: 1, need: 2 }));
        // the same share again: refused, and left out
        let mut again = EntryStep::Stay;
        for w in &set[2] {
            again = type_word(&mut e, w);
        }
        assert!(matches!(&again, EntryStep::Problem(p) if p.contains("the same share")));
        for w in &set[0] {
            last = type_word(&mut e, w);
        }
        match last {
            EntryStep::Done(words) => assert_eq!(words, [set[2].clone(), set[0].clone()]),
            _ => panic!("not done"),
        }
        assert!(e.shares.is_empty() && e.words.is_empty(), "forgotten once handed over");
    }

    #[test]
    fn a_wrong_word_or_another_sets_share_is_said() {
        let set = shares(2, 3);
        let other = shares_from(99, 2, 2);
        assert_ne!(set[0][4..6], other[0][4..6], "another identifier");
        // a share from another split (another identifier)
        let mut e = ShareEntry::new();
        for w in &set[0] {
            type_word(&mut e, w);
        }
        let mut last = EntryStep::Stay;
        for w in &other[1] {
            last = type_word(&mut e, w);
        }
        assert!(
            matches!(&last, EntryStep::Problem(p) if p.contains("another split")),
            "{}",
            match &last {
                EntryStep::Problem(p) => p.as_str(),
                _ => "",
            }
        );
        // a word changed: the checksum fails at the end
        let mut e = ShareEntry::new();
        let mut wrong = set[1].clone();
        wrong[12] = if wrong[12] == "able" { "acid".into() } else { "able".into() };
        for w in &wrong {
            last = type_word(&mut e, w);
        }
        assert!(matches!(last, EntryStep::Problem(_)));
        // words no share begins with: said at once
        let mut e = ShareEntry::new();
        assert!(matches!(type_word(&mut e, "zoom"), EntryStep::Problem(_)));
        assert!(e.words.is_empty());
    }

    #[test]
    fn the_check_asks_a_value_word_of_each_share() {
        let set = shares(2, 3);
        let mut c = SharesCheck::new(&set);
        assert!(c.asked.iter().zip(&set).all(|(&a, s)| value_words(s.len()).contains(&a)));
        assert_eq!(value_words(29), 9..25);
        assert_eq!(value_words(46), 10..42);
        let mut step = CheckStep::Stay;
        for _ in 0..set.len() {
            c.selected = c.options.iter().position(|o| *o == set[c.share][c.asked[c.share]]).unwrap();
            step = c.key(Key::Confirm, &set);
        }
        assert!(matches!(step, CheckStep::Passed));
        // a wrong one says which
        let mut c = SharesCheck::new(&set);
        c.selected = c.options.iter().position(|o| *o != set[0][c.asked[0]]).unwrap();
        assert!(matches!(c.key(Key::Confirm, &set), CheckStep::Wrong { share: 1, .. }));
    }
}
