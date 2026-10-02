//! Decks as the link carries them and as maki keeps them, and the rest of what the app keeps.
//!
//! In the app's storage, numbers little-endian and days whole days since 1970 (UTC):
//! - `decks`: the list: a byte for its format (1), then for each deck its ID (a byte), which of its two sets
//!   of keys holds it (a byte: 0 for `a`, 1 for `b`), its name (a byte's length, then UTF-8), how many cards
//!   it has (u16) and how many values hold them (a byte).
//! - `c<ID><a|b>.<n>`: a deck's cards, in values of up to 16 KiB (maki's most for one), each holding whole
//!   cards, in order: each card its front and its back, each a u16's length, then UTF-8.
//! - `p<ID><a|b>`: its progress: the format (1), the day it last brought in new cards and how many (u16
//!   each), then three bytes a card, as the deck has them: its box (0 while it's new) and the day it was last
//!   seen (u16).
//! - `state`: the format (1), the last day maki's clock said, the last day anything was studied, the days in
//!   a row up to it, how many new cards a deck brings in a day (u16 each), and the ID the next new deck gets
//!   (a byte).
//!
//! A deck is listed once all of it is kept, and unlisted before any of it goes; what no listed deck
//! names is tidied away when the app starts. A deck replacing another is kept under the other set
//! of keys, beside it, when there's room for both: the list names the new one in a single write,
//! and the old one goes after, so maki switched off at any moment has one of them whole, with its
//! progress. When there isn't room for both, the old one goes first, and maki switched off before
//! the new one is listed has neither.
//!
//! What's read back is checked as strictly as what comes over the link.

use std::ops::Range;

use maki_app::*;

use crate::leitner::{BOXES, Progress};

/// Up to this many decks, of up to this many cards.
pub const MAX_DECKS: usize = 8;
pub const MAX_CARDS: usize = 1000;
/// A deck's name, a card's front and its back, at most, in characters.
pub const MAX_NAME: usize = 32;
pub const MAX_FRONT: usize = 200;
pub const MAX_BACK: usize = 500;
/// The app's storage, as its manifest asks for it (`storage = 64`): what it keeps shares it.
pub const ROOM: usize = 64 * 1024;
/// The most a deck can be on the link: more never fits.
pub const MAX_DECK: usize = ROOM;
/// The most bytes a name takes: four for each character.
pub const MAX_NAME_BYTES: usize = 4 * MAX_NAME;
/// maki's most for a stored value.
const VALUE: usize = 16 * 1024;
/// maki's most keys for the app's storage: one for each 128 bytes of it.
const MAX_KEYS: usize = ROOM / 128;
/// What the values start with, for a later version to tell them apart.
const FORMAT: u8 = 1;
/// How many new cards a deck brings in a day, to choose from; and at first.
pub const NEW_A_DAY: [u16; 5] = [5, 10, 20, 50, 100];
const NEW_AT_FIRST: u16 = 20;

/// Reads little-endian numbers, and bytes, off the front of a message or a value.
pub struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self { Reader { b, at: 0 } }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }

    pub fn u8(&mut self) -> Option<u8> { self.take(1).map(|b| b[0]) }

    pub fn u16(&mut self) -> Option<u16> { self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]])) }

    pub fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// UTF-8 of a byte's length.
    pub fn str8(&mut self) -> Option<&'a str> {
        let n = self.u8()? as usize;
        std::str::from_utf8(self.take(n)?).ok()
    }

    /// What's left.
    pub fn rest(&mut self) -> &'a [u8] {
        let rest = &self.b[self.at.min(self.b.len())..];
        self.at = self.b.len();
        rest
    }

    pub fn done(&self) -> bool { self.at >= self.b.len() }
}

/// Why a side isn't one maki takes, if it isn't: it's blank, longer than `max` characters, or has
/// a control character (but a line break, if it may have `lines`).
pub fn check(text: &str, max: usize, lines: bool) -> Result<(), &'static str> {
    if text.trim().is_empty() {
        return Err("is empty");
    }
    if text.chars().count() > max {
        return Err("is too long");
    }
    if text.chars().any(|c| c.is_control() && !(lines && c == '\n')) {
        return Err("has a control character");
    }
    Ok(())
}

/// Why a deck's name isn't one maki takes, if it isn't: as `check` says for a line of up to 32
/// characters, and no spaces at its ends (two names that look the same are the same).
pub fn check_name(name: &str) -> Result<(), &'static str> {
    check(name, MAX_NAME, false)?;
    if name.trim() != name {
        return Err("starts or ends with a space");
    }
    Ok(())
}

/// The card at `at` in `records` (cards as they're kept): where its front and back are, and where
/// the next card starts; or what's wrong with it. Each side is checked: UTF-8, not blank, not too
/// long, no control characters but line breaks.
pub fn card_at(records: &[u8], at: usize) -> Result<(Range<usize>, Range<usize>, usize), String> {
    let side = |at: usize, max: usize, which: &str| -> Result<(Range<usize>, usize), String> {
        let why = |why: &str| format!("its {which} {why}");
        let n = records.get(at..at.saturating_add(2)).ok_or_else(|| why("is cut short"))?;
        let end = at + 2 + u16::from_le_bytes([n[0], n[1]]) as usize;
        let text = records.get(at + 2..end).ok_or_else(|| why("is cut short"))?;
        check(std::str::from_utf8(text).map_err(|_| why("isn't UTF-8"))?, max, true).map_err(why)?;
        Ok((at + 2..end, end))
    };
    let (front, at) = side(at, MAX_FRONT, "front")?;
    let (back, at) = side(at, MAX_BACK, "back")?;
    Ok((front, back, at))
}

/// A deck as the link carries it, read and checked whole.
pub struct Deck<'a> {
    pub name: &'a str,
    /// its cards, as they're kept
    pub records: &'a [u8],
    /// where each card ends in `records`
    pub ends: Vec<usize>,
}

impl Deck<'_> {
    /// Card `i`'s front, as its bytes.
    pub fn front(&self, i: usize) -> &[u8] {
        let start = if i == 0 { 0 } else { self.ends[i - 1] };
        match card_at(self.records, start) {
            Ok((front, _, _)) => &self.records[front],
            Err(_) => &[],
        }
    }
}

/// A deck from the link: its name (a byte's length, then UTF-8), how many cards (u16), then the
/// cards as they're kept; nothing after. Or why it isn't one.
pub fn read_deck(data: &[u8]) -> Result<Deck<'_>, String> {
    let mut r = Reader::new(data);
    let name = r.str8().ok_or("its name is cut short or isn't UTF-8")?;
    check_name(name).map_err(|why| format!("its name {why}"))?;
    let n = r.u16().ok_or("it's cut short")? as usize;
    if n == 0 || n > MAX_CARDS {
        return Err(format!("a deck has 1 to {MAX_CARDS} cards"));
    }
    let records = r.rest();
    let mut ends = Vec::with_capacity(n);
    let mut at = 0;
    for i in 0..n {
        let (_, _, next) = card_at(records, at).map_err(|why| format!("card {}: {why}", i + 1))?;
        at = next;
        ends.push(at);
    }
    if at != records.len() {
        return Err("there's more after its last card".into());
    }
    Ok(Deck { name, records, ends })
}

/// Where cards are cut into values of up to 16 KiB, each holding whole cards: the end of each,
/// given where each card ends. (A card is 2804 bytes at most, so each holds one at least.)
pub fn cuts(ends: &[usize]) -> Vec<usize> {
    let mut cuts = Vec::new();
    let (mut start, mut last) = (0, 0);
    for &end in ends {
        if end - start > VALUE {
            cuts.push(last);
            start = last;
        }
        last = end;
    }
    if last > start {
        cuts.push(last);
    }
    cuts
}

/// A deck in the list: its ID, its name, and how it's kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub id: u8,
    /// which of its two sets of keys holds it: 0 (`a`) or 1 (`b`)
    pub set: u8,
    pub name: String,
    pub cards: u16,
    /// how many values hold its cards
    pub pieces: u8,
}

fn set_letter(set: u8) -> char { if set == 0 { 'a' } else { 'b' } }

fn piece_key(e: &Entry, n: u8) -> String { format!("c{}{}.{n}", e.id, set_letter(e.set)) }

fn progress_key(e: &Entry) -> String { format!("p{}{}", e.id, set_letter(e.set)) }

/// The decks, and whether the list read whole (what no listed deck names is tidied away only then).
pub fn load_decks() -> (Vec<Entry>, bool) {
    let mut b = vec![0u8; 1 + MAX_DECKS * (1 + 1 + 1 + MAX_NAME_BYTES + 2 + 1)];
    let Some(n) = storage::get("decks", &mut b) else { return (Vec::new(), true) };
    let mut r = Reader::new(b.get(..n).unwrap_or(&[]));
    if r.u8() != Some(FORMAT) {
        return (Vec::new(), false);
    }
    let mut decks: Vec<Entry> = Vec::new();
    while !r.done() {
        let entry = (|| {
            let (id, set) = (r.u8()?, r.u8()?);
            let name = r.str8()?.to_string();
            let (cards, pieces) = (r.u16()?, r.u8()?);
            let ok = id != 0
                && set <= 1
                && check_name(&name).is_ok()
                && (1..=MAX_CARDS as u16).contains(&cards)
                && pieces >= 1
                && !decks.iter().any(|d| d.id == id || d.name == name);
            ok.then_some(Entry { id, set, name, cards, pieces })
        })();
        match entry {
            Some(e) if decks.len() < MAX_DECKS => decks.push(e),
            _ => return (decks, false),
        }
    }
    (decks, true)
}

fn decks_value(decks: &[Entry]) -> Vec<u8> {
    let mut b = vec![FORMAT];
    for d in decks {
        b.extend_from_slice(&[d.id, d.set, d.name.len() as u8]);
        b.extend_from_slice(d.name.as_bytes());
        b.extend_from_slice(&d.cards.to_le_bytes());
        b.push(d.pieces);
    }
    b
}

/// Keeps the list (none: no `decks` at all).
pub fn save_decks(decks: &[Entry]) -> Result<(), Error> {
    if decks.is_empty() {
        storage::delete("decks");
        return Ok(());
    }
    storage::set("decks", &decks_value(decks))
}

/// What the list takes in storage, its name and all.
fn decks_size(decks: &[Entry]) -> usize {
    if decks.is_empty() { 0 } else { "decks".len() + decks_value(decks).len() }
}

/// A deck's cards, read back to study: their text, and where each card starts in it.
pub struct Text {
    bytes: Vec<u8>,
    starts: Vec<u32>,
}

impl Text {
    fn sides(&self, i: usize) -> (&str, &str) {
        let at = self.starts.get(i).map_or(usize::MAX, |&s| s as usize);
        match card_at(&self.bytes, at) {
            Ok((f, b, _)) => (
                std::str::from_utf8(&self.bytes[f]).unwrap_or(""),
                std::str::from_utf8(&self.bytes[b]).unwrap_or(""),
            ),
            Err(_) => ("", ""),
        }
    }

    pub fn front(&self, i: usize) -> &str { self.sides(i).0 }

    pub fn back(&self, i: usize) -> &str { self.sides(i).1 }
}

/// How long each value holding a deck's cards is; None if one is missing or longer than maki keeps.
fn piece_lengths(e: &Entry) -> Option<Vec<usize>> {
    (0..e.pieces).map(|n| storage::get(&piece_key(e, n), &mut []).filter(|&len| len <= VALUE)).collect()
}

/// Whether `piece` is whole cards.
fn whole_cards(piece: &[u8]) -> bool {
    let mut at = 0;
    while at < piece.len() {
        match card_at(piece, at) {
            Ok((_, _, next)) => at = next,
            Err(_) => return false,
        }
    }
    true
}

/// Each value holding a deck's cards, in turn, each whole cards; None if one is missing or isn't,
/// or `each` says so. Read into memory of just its size, one at a time.
fn pieces(e: &Entry, mut each: impl FnMut(&[u8]) -> Option<()>) -> Option<()> {
    for (n, len) in piece_lengths(e)?.into_iter().enumerate() {
        let mut piece = vec![0u8; len];
        if storage::get(&piece_key(e, n as u8), &mut piece) != Some(len) || !whole_cards(&piece) {
            return None;
        }
        each(&piece)?;
    }
    Some(())
}

/// A deck's cards, to study; None if what's kept isn't what the list says. Read straight into
/// memory of the deck's size: a big deck takes most of the app's, and twice it wouldn't fit.
pub fn load_text(e: &Entry) -> Option<Text> {
    let lengths = piece_lengths(e)?;
    let mut bytes = vec![0u8; lengths.iter().sum()];
    let mut at = 0;
    for (n, len) in lengths.into_iter().enumerate() {
        let piece = &mut bytes[at..at + len];
        if storage::get(&piece_key(e, n as u8), piece) != Some(len) || !whole_cards(piece) {
            return None;
        }
        at += len;
    }
    let mut starts = Vec::with_capacity(e.cards as usize);
    let mut at = 0;
    while at < bytes.len() {
        starts.push(at as u32);
        at = card_at(&bytes, at).ok()?.2;
    }
    (starts.len() == e.cards as usize).then_some(Text { bytes, starts })
}

/// A hash of each of a deck's fronts, as (hash, card), sorted: to find a card's progress again
/// when the deck is replaced. Empty if the deck can't be read.
pub fn fronts(e: &Entry) -> Vec<(u64, u16)> {
    let mut out = Vec::with_capacity(e.cards as usize);
    let read = pieces(e, |piece| {
        let mut at = 0;
        while at < piece.len() {
            let (front, _, next) = card_at(piece, at).ok()?;
            out.push((fnv(&piece[front]), out.len() as u16));
            at = next;
        }
        Some(())
    });
    if read.is_none() || out.len() != e.cards as usize {
        return Vec::new();
    }
    out.sort_unstable();
    out
}

/// FNV-1a, 64 bits: telling fronts apart, not keeping secrets.
pub fn fnv(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf2_9ce4_8422_2325, |h, &x| (h ^ x as u64).wrapping_mul(0x0000_0100_0000_01b3))
}

/// A deck's progress: the day it last brought in new cards, how many it did, and each card's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kept {
    pub new_day: u16,
    pub brought: u16,
    pub cards: Vec<Progress>,
}

impl Kept {
    /// Every card new.
    pub fn fresh(cards: usize) -> Kept {
        Kept { new_day: 0, brought: 0, cards: vec![Progress::default(); cards] }
    }

    fn value(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Kept::size(self.cards.len()));
        b.push(FORMAT);
        b.extend_from_slice(&self.new_day.to_le_bytes());
        b.extend_from_slice(&self.brought.to_le_bytes());
        for p in &self.cards {
            b.push(p.boxed);
            b.extend_from_slice(&p.seen.to_le_bytes());
        }
        b
    }

    fn size(cards: usize) -> usize { 5 + 3 * cards }
}

/// Deck `e`'s progress: every card new if there's none, or it isn't for as many cards as the deck
/// has; a card in a box there isn't, new.
pub fn load_progress(e: &Entry) -> Kept {
    let cards = e.cards as usize;
    let mut b = vec![0u8; Kept::size(cards)];
    let n = storage::get(&progress_key(e), &mut b);
    let mut r = Reader::new(&b);
    if n != Some(b.len()) || r.u8() != Some(FORMAT) {
        return Kept::fresh(cards);
    }
    let (new_day, brought) = (r.u16().unwrap_or(0), r.u16().unwrap_or(0));
    let mut kept = Kept { new_day, brought, cards: Vec::with_capacity(cards) };
    while let (Some(boxed), Some(seen)) = (r.u8(), r.u16()) {
        let boxed = if boxed as usize > BOXES { 0 } else { boxed };
        kept.cards.push(Progress { boxed, seen });
    }
    kept
}

/// Keeps deck `e`'s progress: the same size every time, so there's always room.
pub fn save_progress(e: &Entry, kept: &Kept) -> Result<(), Error> {
    storage::set(&progress_key(e), &kept.value())
}

/// What the app keeps besides its decks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    /// the last day maki's clock said (0: it never has)
    pub last_day: u16,
    /// the last day anything was studied, and the days in a row up to it
    pub studied: u16,
    pub run: u16,
    /// how many new cards a deck brings in a day
    pub new_a_day: u16,
    /// the ID the next new deck gets, if no deck has it: IDs go round 1 to 255 rather than the
    /// lowest free one coming back at once, so software holding a deck's ID from before it was
    /// removed doesn't find another deck there
    pub next_id: u8,
}

impl State {
    const SIZE: usize = 10;

    /// As kept; kept now if it wasn't, so the room it takes is spoken for before decks fill it.
    pub fn load() -> State {
        let mut b = [0u8; State::SIZE];
        if storage::get("state", &mut b) == Some(b.len()) && b[0] == FORMAT {
            let n = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
            let new_a_day = if NEW_A_DAY.contains(&n(7)) { n(7) } else { NEW_AT_FIRST };
            return State { last_day: n(1), studied: n(3), run: n(5), new_a_day, next_id: b[9].max(1) };
        }
        let s = State { last_day: 0, studied: 0, run: 0, new_a_day: NEW_AT_FIRST, next_id: 1 };
        let _ = s.save();
        s
    }

    pub fn save(&self) -> Result<(), Error> {
        let mut b = vec![FORMAT];
        for n in [self.last_day, self.studied, self.run, self.new_a_day] {
            b.extend_from_slice(&n.to_le_bytes());
        }
        b.push(self.next_id);
        storage::set("state", &b)
    }
}

/// Each of the app's keys, as maki lists them.
fn keys() -> Vec<String> {
    let mut out = Vec::new();
    let mut name = [0u8; 48];
    while let Some(key) = storage::key(out.len(), &mut name) {
        out.push(key.to_string());
    }
    out
}

/// What a key takes of the app's storage, as maki counts it: its name and its value.
fn size_of(key: &str) -> usize { storage::get(key, &mut []).map_or(0, |n| key.len() + n) }

/// What the app's storage holds, in bytes, and in how many keys.
pub fn used() -> (usize, usize) {
    let keys = keys();
    (keys.iter().map(|k| size_of(k)).sum(), keys.len())
}

/// What deck `e` takes: its cards and its progress, names and all.
pub fn deck_size(e: &Entry) -> usize {
    (0..e.pieces).map(|n| size_of(&piece_key(e, n))).sum::<usize>() + size_of(&progress_key(e))
}

/// The deck a key is part of: its ID, its set of keys, and which piece (None: its progress).
/// `c3a.1` is deck 3's second piece in set `a`, `p3a` its progress.
fn owner(key: &str) -> Option<(u8, u8, Option<u8>)> {
    let (deck, piece) = if let Some(rest) = key.strip_prefix('c') {
        let (deck, n) = rest.split_once('.')?;
        (deck, Some(n.parse().ok()?))
    } else {
        (key.strip_prefix('p')?, None)
    };
    let set = match deck.as_bytes().last()? {
        b'a' => 0,
        b'b' => 1,
        _ => return None,
    };
    Some((deck[..deck.len() - 1].parse().ok()?, set, piece))
}

/// Deletes what no listed deck names: what was left behind when maki was switched off while a
/// deck was being kept, replaced or removed.
pub fn tidy(decks: &[Entry]) {
    for key in keys() {
        if let Some((id, set, piece)) = owner(&key) {
            let listed =
                decks.iter().any(|d| d.id == id && d.set == set && piece.is_none_or(|n| n < d.pieces));
            if !listed {
                storage::delete(&key);
            }
        }
    }
}

/// Why a deck couldn't be kept.
pub enum NotKept {
    /// no room: how much it needs, and how much there is once what it replaces is gone
    Full(usize, usize),
    /// maki wouldn't keep it
    Failed,
}

/// Deletes deck `e`'s keys.
fn forget(e: &Entry) {
    for n in 0..e.pieces {
        storage::delete(&piece_key(e, n));
    }
    storage::delete(&progress_key(e));
}

/// Keeps `deck` as deck `id` with progress `kept`: in place of the deck at `old` in `decks` if it
/// replaces one, else last. Beside the old one, in its other set of keys, if there's room for both
/// (the list then names the new one in one write, and the old one goes); else the old one goes
/// first. Nothing is touched unless there's room for it.
pub fn keep(
    decks: &mut Vec<Entry>,
    id: u8,
    old: Option<usize>,
    deck: &Deck,
    kept: &Kept,
) -> Result<(), NotKept> {
    let cuts = cuts(&deck.ends);
    let set = old.map_or(0, |i| decks[i].set ^ 1);
    let entry = Entry {
        id,
        set,
        name: deck.name.to_string(),
        cards: deck.ends.len() as u16,
        pieces: cuts.len() as u8,
    };
    let mut listed = decks.clone();
    match old {
        Some(i) => listed[i] = entry.clone(),
        None => listed.push(entry.clone()),
    }
    // what the new deck takes, and what the list grows by
    let mut adds = progress_key(&entry).len() + Kept::size(deck.ends.len());
    let mut start = 0;
    for (n, &end) in cuts.iter().enumerate() {
        adds += piece_key(&entry, n as u8).len() + end - start;
        start = end;
    }
    let (list_now, list_after) = (decks_size(decks), decks_size(&listed));
    let new_keys = cuts.len() + 1 + decks.is_empty() as usize;
    let (old_size, old_keys) = old.map_or((0, 0), |i| (deck_size(&decks[i]), decks[i].pieces as usize + 1));
    let (used, keys) = used();
    // the new one beside the old, the list in place: the most it holds is with both and the
    // longer list
    let both = used + adds + list_after.saturating_sub(list_now) <= ROOM && keys + new_keys <= MAX_KEYS;
    let free = (ROOM + old_size + list_now).saturating_sub(used);
    if !both && (adds + list_after > free || keys + new_keys > MAX_KEYS + old_keys) {
        return Err(NotKept::Full(adds + list_after.saturating_sub(list_now), free.saturating_sub(list_now)));
    }
    let gone = match old {
        Some(i) if !both => {
            // no room for both: the old one goes first
            let mut without = decks.clone();
            let gone = without.remove(i);
            save_decks(&without).map_err(|_| NotKept::Failed)?;
            forget(&gone);
            *decks = without;
            None
        }
        Some(i) => Some(decks[i].clone()),
        None => None,
    };
    let written = (|| {
        let mut start = 0;
        for (n, &end) in cuts.iter().enumerate() {
            storage::set(&piece_key(&entry, n as u8), &deck.records[start..end])?;
            start = end;
        }
        save_progress(&entry, kept)?;
        save_decks(&listed)
    })();
    if written.is_err() {
        // what was written of it goes; the old one, if it's still listed, stays
        forget(&entry);
        return Err(NotKept::Failed);
    }
    *decks = listed;
    if let Some(gone) = gone {
        forget(&gone);
    }
    Ok(())
}

/// Removes the deck at `i`: unlisted first, then its cards and progress.
pub fn remove(decks: &mut Vec<Entry>, i: usize) -> Result<Entry, Error> {
    let mut after = decks.clone();
    let gone = after.remove(i);
    save_decks(&after)?;
    *decks = after;
    forget(&gone);
    Ok(gone)
}
