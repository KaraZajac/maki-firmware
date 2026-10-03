//! Flashcards: decks studied on maki, a card at a time. maki desktop sends the decks (the link
//! permission), from a CSV or tab-separated file, pasted text, or Anki's plain text export; and
//! reads them back, with how each card stands, to show them and to send them again changed.
//!
//! On maki, the decks, each with how many cards it has for today; the centre opens one, and again
//! starts studying it. A card's front shows, the centre turns it over, and then left says you
//! didn't know it ("again") and right that you did ("knew it"). Text is drawn in maki's own fonts,
//! as big as fits: a word or two twice over, longer text smaller, broken between words; what's
//! still too long to show at once scrolls with the jog dial on maki's side. maki's fonts draw
//! printable ASCII, Latin-1 (Western Europe's accented letters, and its signs), Œ and œ, the curly
//! quotes, daggers and bullet, the ellipsis and the euro sign; anything else shows as a box with a
//! question mark, and maki desktop says what it'll change, or leave out, before it sends a deck.
//!
//! When a card comes back is Leitner's system (`leitner`): seven boxes, a card in box n coming back
//! 2^(n-1) days after it was last seen; one you knew goes up a box, one you didn't back to box 1.
//! A card you didn't know comes round again in the same sitting, three cards on, until you know
//! it (only a card's first answer in a sitting moves it). A deck brings in 20 new cards a day, as
//! it has them, after the cards due; the menu changes how many, from 5 to 100. The days in a row
//! you've studied show under the list once there are two.
//!
//! Days are maki's clock's (`unix_time`), whole days since 1970 in UTC: maki doesn't tell apps
//! its time zone, so a day turns at midnight UTC (5 pm in Las Vegas in summer). Whether the time
//! was verified doesn't matter here. Without the time (maki loses it when it's switched off, until
//! maki desktop sets it again), the app takes the day to be the last one it knew, and says so under
//! its list: what you study is scheduled from that day, so cards come back no later than they
//! should; the new cards it brings in count as that day's; and the days in a row wait for the date.
//! With no day known at all, that's day 0, and everything studied comes back as soon as maki knows
//! the date.
//!
//! The app keeps up to 8 decks of up to 1000 cards each, in its 64 KiB of storage (`deck` says
//! how; "Room on maki" in the menu says what's used): a thousand cards of a word or two each side
//! take about 30 KiB. A deck's name has up to 32 characters, a card's front up to 200 and its back
//! up to 500, and line breaks may be in either. A deck being studied that the computer replaces or
//! removes is left for its page, or the list, which say why: a sitting ends as the first piece of
//! its deck's new version comes, since a big deck takes most of the app's memory, and twice over
//! wouldn't fit (256 KiB; the most it needs, replacing the biggest deck there's room for while
//! it's studied and read by the computer, is 192).
//!
//! The link's messages (`wire`). Numbers are little-endian. Each message starts with the version
//! of these messages, 1, then a letter saying what it is; each answer with a status: 0 done, 4
//! not a message the app takes (why follows, in English), 5 no room for it (why follows), 6 a
//! piece taken (how much of the deck it has follows, u32), 7 no such deck, 8 another deck has that
//! name, 9 another version (the one it speaks follows, a byte), 10 the deck doesn't read whole (what
//! maki keeps of it is damaged: it's to be sent again). A message refused changes nothing, but for
//! a piece or a read: one refused ends the upload, or the read, under way.
//! - `L`: the decks. Answered `0`; the version; today (u16, days since 1970) and whether maki knows it (a
//!   byte; if not, today is the last day it knew); the days in a row (u16); new cards a day (u16); the bytes
//!   used and the room (u32 each); how many decks (a byte); then each deck: its ID (a byte), its name (a
//!   byte's length, then UTF-8), its cards, those new, those due today, and those a sitting would hold today
//!   (u16 each), its size in storage (u32), and how many cards are in each box, 1 to 7 (u16 each).
//! - `U`, the deck it replaces (a byte: its ID, or 0 for a new deck), the deck's length (u32), where this
//!   piece goes (u32), then the piece: a deck, in as many pieces as it takes (a message holds 4096 bytes).
//!   The first piece goes at 0, which starts it afresh, and is refused at once if there's no such deck to
//!   replace, no room for another deck, or no room for one that long; each next piece goes where the last
//!   ended, and any other is refused. Each piece but the last is answered `6`; the last `0`, the deck's ID (a
//!   byte), its cards, and how many cards kept the progress they had (u16 each). A deck is its name (a byte's
//!   length, then UTF-8, with no spaces at its ends), how many cards it has (u16), then each card's front and
//!   back (each a u16's length, then UTF-8), 64 KiB at most. A deck replacing another keeps the progress of
//!   each card whose front the old deck had (the first not taken yet, for a front it had more than once), and
//!   takes its place in the list; its name may change, but not to another deck's. A new deck's ID is one no
//!   deck has had for a while: IDs go round from 1 to 255.
//! - `R`, a deck's ID (a byte), where to read from (u32): a piece of the deck as `U` carries it, followed by
//!   each card's progress, in the deck's order: its box (a byte, 0 while it's new) and the day it's next due
//!   (u16, days since 1970; 0 while it's new). Answered `0`, how long all of that is (u32), then as much of
//!   it from there as a message holds (4091 bytes), or as is left. The first read is at 0, which starts it
//!   afresh, the progress as it stands then; each next read goes where the last ended, and any other is
//!   refused (`4`), as is the next once the deck has been kept anew or removed (`7` if it's gone). `7` for no
//!   such deck, `10` if its cards don't read whole. New in the app's 1.1, the messages' version still 1: 1.0
//!   answers it `4`, as any message it doesn't take.
//! - `D`, a deck's ID (a byte): that deck removed, and its progress. Answered `0`, or `7`.

use std::collections::VecDeque;

use maki_app::*;

mod deck;
mod leitner;
mod text;
mod wire;

use deck::{Entry, Kept, State};
use leitner::Counts;
use text::{BIG, Laid, REGULAR, SMALL, Size};

/// Where the footer's rule is; its line of small text goes under it, down to the screen's last row.
const FOOT: i32 = 96;
/// Decks the list shows at once, a row each.
const ROWS: usize = 6;
const ROW: i32 = 16;
/// A card you didn't know comes back after this many others.
const AGAIN_AFTER: usize = 3;
/// A card's text, as big as fits: a word or two big, then regular, then small (which scrolls).
const SIZES: [Size; 3] = [BIG, REGULAR, SMALL];
const BOLD: Size = Size(Style::Bold, 1);

/// What's on the screen.
enum View {
    /// the decks, and how many cards each has for today
    List,
    /// the selected deck: what it has for today, and its boxes
    Deck,
    /// studying the selected deck
    Study(Box<Sitting>),
    /// a sitting's end: how many cards were studied, how many weren't known
    Done { seen: u16, again: u16 },
    /// asking before deleting the selected deck
    Delete,
    /// the room on maki, and its limits; then back to the deck (`true`) or the list
    Room(bool),
}

/// A deck being studied: its cards for today, in order, the one showing first.
struct Sitting {
    deck: Entry,
    text: deck::Text,
    kept: Kept,
    queue: VecDeque<u16>,
    /// the cards answered in this sitting: only a card's first answer moves it
    answered: Vec<bool>,
    /// its back showing; how far it's scrolled, in lines
    turned: bool,
    scroll: usize,
    /// the side showing, laid out
    laid: Laid,
    /// cards answered, and those not known the first time
    seen: u16,
    again: u16,
}

impl Sitting {
    /// The card showing, as the deck has it.
    fn card(&self) -> usize { self.queue.front().copied().unwrap_or(0) as usize }

    /// The side showing: its text, and where it goes on the screen (its top and height).
    fn side(&self) -> (&str, i32, i32) {
        if self.turned {
            (self.text.back(self.card()), 16, FOOT - 16)
        } else {
            (self.text.front(self.card()), 14, FOOT - 14)
        }
    }

    /// The side showing laid out afresh, from its top: when the card or the side changes.
    fn show(&mut self) {
        let (side, _, height) = self.side();
        self.laid = text::lay_out(side, &SIZES, WIDTH - 4, height);
        self.scroll = 0;
    }

    /// How far the side showing can scroll, in lines.
    fn most_scroll(&self) -> usize {
        let (_, _, height) = self.side();
        self.laid.lines.len().saturating_sub((height / self.laid.size.height()) as usize)
    }
}

pub(crate) struct App {
    pub(crate) decks: Vec<Entry>,
    pub(crate) state: State,
    /// each deck's counts for today, as `decks` has them
    pub(crate) counts: Vec<Counts>,
    /// today, and whether maki knows it (`today`)
    pub(crate) day: (u16, bool),
    selected: usize,
    view: View,
    /// the menu's items as they were last set
    menu: Vec<String>,
    /// a line for the footer, until the next press
    note: String,
    pub(crate) upload: Option<wire::Upload>,
    /// a deck being read by the computer, a piece at a time
    pub(crate) reading: Option<wire::Reading>,
    /// the deck a new version of is coming, whose sitting was ended for it
    coming: Option<u8>,
}

impl App {
    fn open() -> App {
        let (decks, whole) = deck::load_decks();
        if whole {
            deck::tidy(&decks);
        }
        let state = State::load();
        let mut app = App {
            decks,
            state,
            counts: Vec::new(),
            day: (state.last_day, false),
            selected: 0,
            view: View::List,
            menu: Vec::new(),
            note: String::new(),
            upload: None,
            reading: None,
            coming: None,
        };
        app.recount();
        app
    }

    /// Today, from maki's clock: days since 1970 (UTC), and whether maki knows it. Without the
    /// time, the last day the app knew, which it keeps for that.
    pub(crate) fn today(&mut self) -> (u16, bool) {
        let Some(t) = unix_time() else { return (self.state.last_day, false) };
        let day = (t / 86_400).min(u16::MAX as u64) as u16;
        if day != self.state.last_day {
            self.state.last_day = day;
            let _ = self.state.save();
        }
        (day, true)
    }

    /// Each deck's counts, as they stand today.
    pub(crate) fn recount(&mut self) {
        self.day = self.today();
        let (today, per_day) = (self.day.0, self.state.new_a_day);
        self.counts = self
            .decks
            .iter()
            .map(|e| {
                let k = deck::load_progress(e);
                leitner::counts(&k.cards, today, leitner::new_left(k.new_day, k.brought, today, per_day))
            })
            .collect();
    }

    /// The selected deck's ID, to find it again once the decks have changed.
    pub(crate) fn selected_id(&self) -> Option<u8> { self.decks.get(self.selected).map(|e| e.id) }

    /// After deck `id` was kept, replaced or removed from the computer: the selected deck found
    /// again; a deck being studied, or asked about, that's been replaced or removed, left; a read
    /// of it ended.
    pub(crate) fn after_change(&mut self, was: Option<u8>, id: u8) {
        self.end_read(id);
        match was.and_then(|w| self.decks.iter().position(|e| e.id == w)) {
            Some(at) => self.selected = at,
            None => {
                self.selected = self.selected.min(self.decks.len().saturating_sub(1));
                if !matches!(self.view, View::List) {
                    self.view = View::List;
                    self.note = "that deck was removed".into();
                }
            }
        }
        if matches!(&self.view, View::Study(s) if s.deck.id == id) {
            self.view = View::Deck;
            self.note = "the deck was just replaced".into();
        }
        self.recount();
    }

    /// Ends a sitting of deck `id`, if one is under way, for the deck's page: the deck is being
    /// replaced, and its cards' memory is wanted for the new ones. Whether it did.
    pub(crate) fn leave_sitting(&mut self, id: u8) -> bool {
        let studying = matches!(&self.view, View::Study(s) if s.deck.id == id);
        if studying {
            self.view = View::Deck;
        }
        studying
    }

    fn menu_items(&self) -> Vec<String> {
        let new = format!("New cards a day: {}", self.state.new_a_day);
        match self.view {
            View::List => vec![new, "Room on maki".into()],
            View::Deck | View::Done { .. } => vec!["Delete this deck".into(), new, "Room on maki".into()],
            View::Study(_) => vec!["Stop studying".into()],
            View::Delete | View::Room(_) => vec![],
        }
    }

    fn set_menu(&mut self) {
        let items = self.menu_items();
        if items != self.menu {
            let _ = menu(&items.iter().map(String::as_str).collect::<Vec<_>>());
            self.menu = items;
        }
    }

    fn pick(&mut self, item: u32) {
        let on_deck = matches!(self.view, View::Deck | View::Done { .. });
        match (&self.view, item) {
            (View::List, 0) | (View::Deck | View::Done { .. }, 1) => {
                let at = deck::NEW_A_DAY.iter().position(|&n| n == self.state.new_a_day).unwrap_or(0);
                self.state.new_a_day = deck::NEW_A_DAY[(at + 1) % deck::NEW_A_DAY.len()];
                let _ = self.state.save();
                self.recount();
                self.note = format!("{} new cards a day", self.state.new_a_day);
            }
            (View::List, 1) | (View::Deck | View::Done { .. }, 2) => self.view = View::Room(on_deck),
            (View::Deck | View::Done { .. }, 0) => self.view = View::Delete,
            (View::Study(_), 0) => {
                self.recount();
                self.view = View::Deck;
            }
            _ => {}
        }
    }

    fn press(&mut self, event: Event) {
        let last = self.decks.len().saturating_sub(1);
        let view = std::mem::replace(&mut self.view, View::List);
        self.view = match (view, event) {
            // the list: left and right, or the dial, go deck to deck; the centre opens one
            (View::List, Event::Left | Event::Up) => {
                self.selected = self.selected.saturating_sub(1);
                View::List
            }
            (View::List, Event::Right | Event::Down) => {
                self.selected = (self.selected + 1).min(last);
                View::List
            }
            (View::List, Event::Centre) if !self.decks.is_empty() => View::Deck,
            // a deck's page: the dial goes deck to deck, the centre studies, left goes back
            (View::Deck, Event::Up) => {
                self.selected = self.selected.saturating_sub(1);
                View::Deck
            }
            (View::Deck, Event::Down) => {
                self.selected = (self.selected + 1).min(last);
                View::Deck
            }
            (View::Deck, Event::Centre) => self.study(),
            (View::Deck, Event::Left) => View::List,
            (View::Study(s), event) => self.studying(s, event),
            (View::Done { .. }, Event::Centre | Event::Left | Event::Right) => View::Deck,
            (View::Delete, Event::Centre) => {
                match deck::remove(&mut self.decks, self.selected) {
                    Ok(gone) => {
                        self.end_read(gone.id);
                        self.note = format!("deleted {}", gone.name);
                    }
                    Err(_) => self.note = "maki couldn't delete it".into(),
                }
                self.selected = self.selected.min(self.decks.len().saturating_sub(1));
                self.recount();
                View::List
            }
            (View::Delete, Event::Left | Event::Right) => View::Deck,
            (View::Room(true), Event::Centre | Event::Left | Event::Right) => View::Deck,
            (View::Room(false), Event::Centre | Event::Left | Event::Right) => View::List,
            (view, _) => view,
        };
    }

    /// A sitting of the selected deck: the cards due today, then new ones; or a note why not.
    fn study(&mut self) -> View {
        let Some(e) = self.decks.get(self.selected).cloned() else { return View::List };
        let Some(text) = deck::load_text(&e) else {
            self.note = "it's damaged: send it again".into();
            return View::Deck;
        };
        let kept = deck::load_progress(&e);
        let (today, _) = self.today();
        let new = leitner::new_left(kept.new_day, kept.brought, today, self.state.new_a_day);
        let queue: VecDeque<u16> = leitner::sitting(&kept.cards, today, new).into();
        if queue.is_empty() {
            self.note = "nothing for today".into();
            return View::Deck;
        }
        let answered = vec![false; kept.cards.len()];
        let laid = Laid { size: SMALL, lines: Vec::new(), scrolls: false };
        let mut s = Sitting {
            deck: e,
            text,
            kept,
            queue,
            answered,
            turned: false,
            scroll: 0,
            laid,
            seen: 0,
            again: 0,
        };
        s.show();
        View::Study(Box::new(s))
    }

    /// A press while studying: the centre turns the card over (and back), the dial scrolls it, and
    /// once it's turned, left and right answer it.
    fn studying(&mut self, mut s: Box<Sitting>, event: Event) -> View {
        match event {
            Event::Centre => {
                s.turned = !s.turned;
                s.show();
            }
            Event::Up => s.scroll = s.scroll.saturating_sub(1),
            Event::Down => s.scroll = (s.scroll + 1).min(s.most_scroll()),
            Event::Left | Event::Right if s.turned => return self.answered(s, event == Event::Right),
            _ => {}
        }
        View::Study(s)
    }

    /// The card showing answered: moved to its box if it's its first answer in this sitting, and
    /// if it wasn't known, back in the queue a few cards on.
    fn answered(&mut self, mut s: Box<Sitting>, knew: bool) -> View {
        let Some(card) = s.queue.pop_front() else { return View::Deck };
        let i = card as usize;
        if !s.answered.get(i).copied().unwrap_or(true) {
            s.answered[i] = true;
            let (today, known) = self.today();
            let p = s.kept.cards[i];
            if p.is_new() {
                if s.kept.new_day != today {
                    s.kept.new_day = today;
                    s.kept.brought = 0;
                }
                s.kept.brought = s.kept.brought.saturating_add(1);
            }
            s.kept.cards[i] = p.answered(knew, today);
            if deck::save_progress(&s.deck, &s.kept).is_err() {
                self.note = "maki couldn't keep that".into();
            }
            if known && self.state.studied != today {
                self.state.run = leitner::streak_after(self.state.studied, self.state.run, today);
                self.state.studied = today;
                let _ = self.state.save();
            }
            s.seen += 1;
            s.again += !knew as u16;
        }
        if !knew {
            s.queue.insert(AGAIN_AFTER.min(s.queue.len()), card);
        }
        s.turned = false;
        if s.queue.is_empty() {
            self.recount();
            return View::Done { seen: s.seen, again: s.again };
        }
        s.show();
        View::Study(s)
    }

    fn draw(&mut self) {
        screen::clear(Color::Dark);
        let view = std::mem::replace(&mut self.view, View::List);
        match &view {
            View::List => self.draw_list(),
            View::Deck => self.draw_deck(),
            View::Study(s) => self.draw_card(s),
            View::Done { seen, again } => self.draw_done(*seen, *again),
            View::Delete => self.draw_delete(),
            View::Room(_) => self.draw_room(),
        }
        self.view = view;
        screen::present();
    }

    /// The footer: a rule, and under it the note if there is one, or `says`; nothing if neither
    /// has anything to say.
    fn foot(&self, says: &str) {
        let says = if self.note.is_empty() { says } else { &self.note };
        if !says.is_empty() {
            screen::line(0, FOOT, WIDTH - 1, FOOT, Color::Light);
            text::centred(FOOT + 2, &text::cut(says, SMALL, WIDTH - 2), SMALL);
        }
    }

    fn draw_list(&self) {
        let (today, known) = self.day;
        if self.decks.is_empty() {
            text::centred(8, "No decks yet", BOLD);
            let says = [
                "Send decks from maki",
                "desktop's Flashcards",
                "page. maki keeps 8, of",
                "up to 1000 cards each,",
                "in 64 KiB.",
            ];
            for (i, line) in says.iter().enumerate() {
                text::centred(30 + 12 * i as i32, line, SMALL);
            }
        }
        let first = self.selected.saturating_sub(ROWS - 1);
        for (row, (i, (e, c))) in
            self.decks.iter().zip(&self.counts).enumerate().skip(first).take(ROWS).enumerate()
        {
            let y = row as i32 * ROW;
            let ink = if i == self.selected {
                screen::fill_rect(0, y, WIDTH, ROW, Color::Light);
                Color::Dark
            } else {
                Color::Light
            };
            // how many cards it has for today, if any
            let n = if c.study > 0 { c.study.to_string() } else { String::new() };
            let w = REGULAR.width(&n);
            REGULAR.draw(WIDTH - 3 - w, y, &n, ink);
            REGULAR.draw(3, y, &text::cut(&e.name, REGULAR, WIDTH - 12 - w), ink);
        }
        let streak = leitner::streak_now(self.state.studied, self.state.run, today);
        let says = if !known && self.state.last_day == 0 {
            "maki doesn't know the date".into()
        } else if !known {
            format!("no date: as if {}", text::date(today))
        } else if streak >= 2 {
            format!("{streak} days in a row")
        } else if self.decks.is_empty() {
            String::new()
        } else {
            "centre: open".into()
        };
        self.foot(&says);
    }

    /// A deck's page: what it has for today, how its cards stand in the boxes, and when it has more.
    fn draw_deck(&self) {
        let (Some(e), Some(c)) = (self.decks.get(self.selected), self.counts.get(self.selected)) else {
            return;
        };
        text::centred(0, &text::cut(&e.name, BOLD, WIDTH - 4), BOLD);
        let new = c.study - c.due;
        let today = match (c.due, new) {
            (0, 0) => "nothing for today".to_string(),
            (due, 0) => format!("{due} due today"),
            (0, new) => format!("{new} new today"),
            (due, new) => format!("{due} due, {new} new today"),
        };
        text::centred(17, &today, SMALL);
        // the boxes: a bar each, as tall as it's full against the fullest
        let most = c.boxes.iter().copied().max().unwrap_or(0).max(1) as i32;
        for (b, &n) in c.boxes.iter().enumerate() {
            let x = 9 + b as i32 * 16;
            let h = if n == 0 { 0 } else { (n as i32 * 36 / most).max(1) };
            screen::fill_rect(x, 69 - h, 14, h, Color::Light);
            screen::line(x, 69, x + 13, 69, Color::Light);
            let label = (b + 1).to_string();
            SMALL.draw(x + (14 - SMALL.width(&label)) / 2, 71, &label, Color::Light);
        }
        let after = match c.next {
            Some(days) if c.study == 0 => format!("more {}", text::days(days)),
            _ => text::count(e.cards as usize, "card", "cards") + &format!(", {} new", c.new),
        };
        text::centred(84, &after, SMALL);
        self.foot(if c.study > 0 { "centre: study" } else { "left: decks" });
    }

    /// The card showing: its front, or its back under a line of its front, as big as fits.
    fn draw_card(&self, s: &Sitting) {
        let p = s.kept.cards.get(s.card()).copied().unwrap_or_default();
        let (side, top, height) = s.side();
        if s.turned {
            SMALL.draw(2, 0, &text::cut(s.text.front(s.card()), SMALL, WIDTH - 4), Color::Light);
            screen::line(0, 13, WIDTH - 1, 13, Color::Light);
        } else {
            let at = if p.is_new() { "new".to_string() } else { format!("box {}", p.boxed) };
            SMALL.draw(2, 0, &at, Color::Light);
            let left = format!("{} left", s.queue.len());
            SMALL.draw(WIDTH - 2 - SMALL.width(&left), 0, &left, Color::Light);
        }
        let (size, lines) = (s.laid.size, &s.laid.lines);
        let shows = (height / size.height()).max(1) as usize;
        let y = if s.laid.scrolls { top } else { top + (height - lines.len() as i32 * size.height()) / 2 };
        let width = if s.laid.scrolls { WIDTH - 4 - text::BAR } else { WIDTH - 4 };
        for (row, line) in lines.iter().skip(s.scroll).take(shows).enumerate() {
            let line = side.get(line.clone()).unwrap_or("");
            size.draw(2 + (width - size.width(line)) / 2, y + row as i32 * size.height(), line, Color::Light);
        }
        if s.laid.scrolls {
            // where it's scrolled to: a bar at the right, as long as the part showing
            let total = lines.len().max(1) as i32;
            let from = top + height * s.scroll as i32 / total;
            let to = top + height * (s.scroll + shows).min(lines.len()) as i32 / total;
            screen::fill_rect(WIDTH - 2, from, 2, (to - from).max(2), Color::Light);
        }
        if s.turned && self.note.is_empty() {
            screen::line(0, FOOT, WIDTH - 1, FOOT, Color::Light);
            SMALL.draw(2, FOOT + 2, "again", Color::Light);
            SMALL.draw(WIDTH - 2 - SMALL.width("knew it"), FOOT + 2, "knew it", Color::Light);
        } else {
            self.foot("centre: turn over");
        }
    }

    fn draw_done(&self, seen: u16, again: u16) {
        let (today, _) = self.day;
        text::centred(12, "Done for today", BOLD);
        let how = match again {
            0 => format!("{}, all known", text::count(seen as usize, "card", "cards")),
            n => format!("{}, {n} again", text::count(seen as usize, "card", "cards")),
        };
        text::centred(36, &how, SMALL);
        let streak = leitner::streak_now(self.state.studied, self.state.run, today);
        if streak >= 2 {
            text::centred(50, &format!("{streak} days in a row"), SMALL);
        }
        if let Some(days) = self.counts.get(self.selected).and_then(|c| c.next) {
            text::centred(64, &format!("more {}", text::days(days)), SMALL);
        }
        self.foot("centre: back");
    }

    fn draw_delete(&self) {
        let Some(e) = self.decks.get(self.selected) else { return };
        text::centred(16, "Delete this deck?", BOLD);
        text::centred(40, &text::cut(&e.name, REGULAR, WIDTH - 6), REGULAR);
        text::centred(62, "its cards and progress", SMALL);
        text::centred(74, "go for good", SMALL);
        self.foot("centre: delete   left: keep");
    }

    /// What's used of the app's room, and the limits.
    fn draw_room(&self) {
        let (used, _) = deck::used();
        let cards: usize = self.decks.iter().map(|e| e.cards as usize).sum();
        text::centred(0, "Room on maki", BOLD);
        text::centred(20, &format!("{} of {} used", wire::kib(used), wire::kib(deck::ROOM)), REGULAR);
        let decks = format!(
            "{} of {} decks, {}",
            self.decks.len(),
            deck::MAX_DECKS,
            text::count(cards, "card", "cards")
        );
        text::centred(40, &decks, SMALL);
        let limits = [
            format!("Up to {} cards a deck,", deck::MAX_CARDS),
            format!("{} characters a front,", deck::MAX_FRONT),
            format!("{} a back.", deck::MAX_BACK),
        ];
        for (i, line) in limits.iter().enumerate() {
            text::centred(58 + 12 * i as i32, line, SMALL);
        }
        self.foot("centre: back");
    }
}

fn main() {
    let mut app = App::open();
    loop {
        if app.today() != app.day {
            app.recount();
        }
        app.set_menu();
        app.draw();
        let event = wait(None);
        if !matches!(event, Event::Message | Event::Hidden | Event::Shown | Event::Timeout) {
            app.note.clear();
        }
        match event {
            Event::Message => {
                let mut message = vec![0u8; wire::MAX_MESSAGE];
                let answer = match link::read(&mut message) {
                    Some(n) if n <= message.len() => app.answer(&message[..n]),
                    _ => wire::bad("more than a message holds"),
                };
                let _ = link::reply(&answer);
            }
            Event::Exit => return,
            Event::Menu(item) => app.pick(item),
            Event::Left | Event::Right | Event::Centre | Event::Up | Event::Down => app.press(event),
            _ => {}
        }
    }
}

maki_app::main!(main);
