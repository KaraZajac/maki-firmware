//! The link: what maki desktop, or other software on the computer, sends the app, and its answers
//! (the crate's documentation has them byte by byte). Anything that isn't exactly a message the app
//! takes is refused, and changes nothing.

use crate::deck::{self, Deck, Entry, Kept, MAX_DECK, MAX_DECKS, MAX_NAME_BYTES, NotKept, Reader};
use crate::{App, leitner};

/// The version of the messages the app speaks.
pub const VERSION: u8 = 1;
/// A message's most bytes, and an answer's.
pub const MAX_MESSAGE: usize = 4096;

const OK: u8 = 0;
const BAD: u8 = 4;
const FULL: u8 = 5;
const MORE: u8 = 6;
const NOT_FOUND: u8 = 7;
const EXISTS: u8 = 8;
const OTHER_VERSION: u8 = 9;

/// A deck coming in pieces: the deck it replaces (0: none), its whole length, what's come.
pub struct Upload {
    target: u8,
    total: usize,
    data: Vec<u8>,
}

/// `BAD`, and why, for whoever wrote the software sending it.
pub fn bad(why: &str) -> Vec<u8> { [&[BAD][..], why.as_bytes()].concat() }

fn full(why: &str) -> Vec<u8> { [&[FULL][..], why.as_bytes()].concat() }

/// Bytes in KiB, as maki's screens have them: to a tenth below 10, and whole above.
pub fn kib(n: usize) -> String {
    let tenths = (n * 10 + 512) / 1024;
    match tenths {
        0..=99 if !tenths.is_multiple_of(10) => format!("{}.{} KiB", tenths / 10, tenths % 10),
        _ => format!("{} KiB", (tenths + 5) / 10),
    }
}

impl App {
    /// The answer to a message from the computer.
    pub(crate) fn answer(&mut self, m: &[u8]) -> Vec<u8> {
        let [version, op, body @ ..] = m else {
            return bad("a message is its version and what it is, at least");
        };
        if *version != VERSION {
            return vec![OTHER_VERSION, VERSION];
        }
        match (op, body) {
            (b'L', []) => self.list(),
            (b'U', _) => self.upload(body),
            (b'D', [id]) => self.remove(*id),
            _ => bad("not a message this app takes"),
        }
    }

    /// `L`: the decks, as they stand today.
    fn list(&mut self) -> Vec<u8> {
        self.recount();
        let (today, known) = self.day;
        let streak = leitner::streak_now(self.state.studied, self.state.run, today);
        let (used, _) = deck::used();
        let mut a = vec![OK, VERSION];
        a.extend_from_slice(&today.to_le_bytes());
        a.push(known as u8);
        a.extend_from_slice(&streak.to_le_bytes());
        a.extend_from_slice(&self.state.new_a_day.to_le_bytes());
        a.extend_from_slice(&(used as u32).to_le_bytes());
        a.extend_from_slice(&(deck::ROOM as u32).to_le_bytes());
        a.push(self.decks.len() as u8);
        for (e, c) in self.decks.iter().zip(&self.counts) {
            a.push(e.id);
            a.push(e.name.len() as u8);
            a.extend_from_slice(e.name.as_bytes());
            for n in [e.cards, c.new, c.due, c.study] {
                a.extend_from_slice(&n.to_le_bytes());
            }
            a.extend_from_slice(&(deck::deck_size(e) as u32).to_le_bytes());
            for n in c.boxes {
                a.extend_from_slice(&n.to_le_bytes());
            }
        }
        a
    }

    /// `U`: a piece of a deck; the last one keeps it.
    fn upload(&mut self, body: &[u8]) -> Vec<u8> {
        let answer = self.piece(body);
        // an upload that ended without the deck kept, for which a sitting was ended, says so
        if self.upload.is_none() && answer.first() != Some(&OK) && self.coming.take().is_some() {
            self.note = "no new version came".into();
        }
        answer
    }

    fn piece(&mut self, body: &[u8]) -> Vec<u8> {
        let mut r = Reader::new(body);
        let (Some(target), Some(total), Some(offset)) = (r.u8(), r.u32(), r.u32()) else {
            self.upload = None;
            return bad("a piece is the deck it replaces, the deck's length and where it goes, then itself");
        };
        let (total, offset, piece) = (total as usize, offset as usize, r.rest());
        if total == 0 || total > MAX_DECK {
            self.upload = None;
            return bad("a deck is 1 to 65536 bytes");
        }
        if piece.is_empty() {
            self.upload = None;
            return bad("an empty piece");
        }
        if offset == 0 {
            self.upload = None;
            // a new version left unfinished: this one starts afresh
            if self.coming.take().is_some() {
                self.note = "no new version came".into();
            }
            if let Some(no) = self.refuse_at_once(target, total) {
                return no;
            }
            // a sitting of the deck it replaces ends now: it holds that deck's cards, and the
            // memory they take is wanted for the new ones (a big deck takes most of the app's)
            if target != 0 && self.leave_sitting(target) {
                self.note = "a new version is coming".into();
                self.coming = Some(target);
            }
            self.upload = Some(Upload { target, total, data: Vec::with_capacity(total) });
        }
        let Some(up) =
            self.upload.as_mut().filter(|u| (u.target, u.total, u.data.len()) == (target, total, offset))
        else {
            self.upload = None;
            return bad("a piece out of order");
        };
        if offset + piece.len() > total {
            self.upload = None;
            return bad("a piece past the deck's end");
        }
        up.data.extend_from_slice(piece);
        if up.data.len() < total {
            return [&[MORE][..], &(up.data.len() as u32).to_le_bytes()].concat();
        }
        match self.upload.take() {
            Some(up) => self.commit(up.target, &up.data),
            None => bad("a piece out of order"),
        }
    }

    /// What's sure to be refused of a deck `total` bytes long, as its first piece comes, rather than
    /// once all of it has: a deck to replace that isn't there, a ninth deck, or one longer than the
    /// room there is for it (its cards alone are all of it but its name and count).
    fn refuse_at_once(&self, target: u8, total: usize) -> Option<Vec<u8>> {
        let old = match target {
            0 if self.decks.len() >= MAX_DECKS => {
                return Some(full(&format!("maki keeps {MAX_DECKS} decks")));
            }
            0 => None,
            id => match self.decks.iter().find(|e| e.id == id) {
                Some(e) => Some(e),
                None => return Some(vec![NOT_FOUND]),
            },
        };
        let (used, _) = deck::used();
        let free = (deck::ROOM + old.map_or(0, deck::deck_size)).saturating_sub(used);
        let cards = total.saturating_sub(1 + MAX_NAME_BYTES + 2);
        (cards > free).then(|| full(&format!("it's {}, and {} is free", kib(total), kib(free))))
    }

    /// A whole deck, kept as a new deck (`target` 0) or in place of deck `target`.
    fn commit(&mut self, target: u8, data: &[u8]) -> Vec<u8> {
        let deck = match deck::read_deck(data) {
            Ok(deck) => deck,
            Err(why) => return bad(&why),
        };
        let old = match target {
            0 => None,
            id => match self.decks.iter().position(|e| e.id == id) {
                Some(i) => Some(i),
                None => return vec![NOT_FOUND],
            },
        };
        if self.decks.iter().enumerate().any(|(i, e)| Some(i) != old && e.name == deck.name) {
            return vec![EXISTS];
        }
        if old.is_none() && self.decks.len() >= MAX_DECKS {
            return full(&format!("maki keeps {MAX_DECKS} decks"));
        }
        // a sitting of the deck it replaces, begun as it came, ends too
        if old.is_some() && self.leave_sitting(target) {
            self.coming = Some(target);
        }
        let (kept, carried) = match old {
            Some(i) => carry(&self.decks[i], &deck),
            None => (Kept::fresh(deck.ends.len()), 0),
        };
        let id = match old {
            Some(i) => self.decks[i].id,
            None => self.new_id(),
        };
        let was = self.selected_id();
        match deck::keep(&mut self.decks, id, old, &deck, &kept) {
            Ok(()) => {}
            Err(NotKept::Full(need, free)) => {
                return full(&format!("it takes {}, and {} is free", kib(need), kib(free)));
            }
            Err(NotKept::Failed) => {
                self.after_change(was, id);
                return full("maki couldn't keep it");
            }
        }
        if old.is_none() {
            self.state.next_id = id % 255 + 1;
            let _ = self.state.save();
        }
        self.after_change(was, id);
        if self.coming.take().is_some() {
            self.note = "the deck was just replaced".into();
        }
        let mut a = vec![OK, id];
        a.extend_from_slice(&(deck.ends.len() as u16).to_le_bytes());
        a.extend_from_slice(&carried.to_le_bytes());
        a
    }

    /// The ID for a new deck: the next in turn that no deck has.
    fn new_id(&self) -> u8 {
        let mut id = self.state.next_id.max(1);
        while self.decks.iter().any(|e| e.id == id) {
            id = id % 255 + 1;
        }
        id
    }

    /// `D`: deck `id` removed, with its progress.
    fn remove(&mut self, id: u8) -> Vec<u8> {
        let Some(i) = self.decks.iter().position(|e| e.id == id) else { return vec![NOT_FOUND] };
        let was = self.selected_id();
        let removed = deck::remove(&mut self.decks, i);
        self.after_change(was, id);
        match removed {
            Ok(_) => vec![OK],
            Err(_) => full("maki couldn't remove it"),
        }
    }
}

/// A replacing deck's progress, from the deck it replaces: a card whose front that deck had keeps
/// that card's progress (the first not taken yet, for a front it had more than once); the others
/// are new. The day the deck last brought in new cards, and how many, carry over too. How many
/// cards kept progress they had (a card that was new, and is, isn't counted).
fn carry(old: &Entry, new: &Deck) -> (Kept, u16) {
    let before = deck::load_progress(old);
    let fronts = deck::fronts(old);
    let mut taken = vec![false; fronts.len()];
    let mut kept =
        Kept { new_day: before.new_day, brought: before.brought, cards: Vec::with_capacity(new.ends.len()) };
    let mut carried = 0;
    for i in 0..new.ends.len() {
        let hash = deck::fnv(new.front(i));
        let first = fronts.partition_point(|&(h, _)| h < hash);
        let found = (first..fronts.len()).take_while(|&j| fronts[j].0 == hash).find(|&j| !taken[j]);
        let progress = found.and_then(|j| {
            taken[j] = true;
            before.cards.get(fronts[j].1 as usize).copied()
        });
        carried += progress.is_some_and(|p| !p.is_new()) as u16;
        kept.cards.push(progress.unwrap_or_default());
    }
    (kept, carried)
}
