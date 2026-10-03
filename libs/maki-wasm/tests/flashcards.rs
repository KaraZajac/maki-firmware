//! The Flashcards example (sdk/examples/flashcards), as `maki build` packed it and maki runs it:
//! decks sent from the computer in pieces and kept within the app's 64 KiB, listed on maki and over
//! the link, and read back by the computer a piece at a time with each card's box and when it's
//! due; cards studied a press at a time, drawn as big as they fit without breaking a word, a long
//! one scrolled with the jog dial; Leitner's boxes over the days of maki's clock, and without it; a
//! deck replaced keeping the progress of the cards it still has, whether or not there's room for
//! both at once; and every message, and everything read back from storage, that isn't what the app
//! takes, refused. Rebuild the fixture after changing the app: `maki build
//! sdk/examples/flashcards`, then copy `sdk/target/maki/com.leviathan.maki.flashcards.maki` to
//! `tests/fixtures/flashcards.maki`.

mod harness;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;

use harness::*;
use maki_wasm::*;

/// A day of maki's clock, in days since 1970: Friday 4 October 2024.
const DAY: u16 = 20_000;
/// The version of the app's messages.
const V: u8 = 1;
/// The app's 64 KiB.
const ROOM: usize = 64 * 1024;

/// Noon (UTC) on `day`, as maki's clock says it.
fn noon(day: u16) -> Option<u64> { Some(day as u64 * 86_400 + 43_200) }

/// The tests' maki, with a clock: `times[0]` until the first event, `times[1]` after it, and so on,
/// the last for the rest (None: maki doesn't know the time).
struct Clocked {
    script: Script,
    times: Vec<Option<u64>>,
    waits: usize,
}

impl Platform for Clocked {
    fn wait(&mut self, timeout: Option<Duration>) -> Event {
        self.waits += 1;
        self.script.wait(timeout)
    }

    fn present(&mut self, canvas: &Canvas) { self.script.present(canvas) }

    fn set_menu(&mut self, items: &[String]) { self.script.set_menu(items) }

    fn millis(&self) -> u64 { self.script.millis() }

    fn unix_time(&self) -> Option<(u64, bool)> {
        let at = self.waits.min(self.times.len().saturating_sub(1));
        self.times.get(at).copied().flatten().map(|t| (t, false))
    }

    fn random(&mut self, buf: &mut [u8]) { self.script.random(buf) }

    fn log(&mut self, line: &str) { self.script.log(line) }

    fn storage_get(&mut self, key: &str) -> Option<Vec<u8>> { self.script.storage_get(key) }

    fn storage_set(&mut self, key: &str, value: &[u8]) -> Result<(), ()> {
        self.script.storage_set(key, value)
    }

    fn storage_delete(&mut self, key: &str) -> bool { self.script.storage_delete(key) }

    fn storage_keys(&mut self) -> Vec<String> { self.script.storage_keys() }

    fn message(&mut self) -> Option<Vec<u8>> { self.script.message() }

    fn reply(&mut self, reply: &[u8]) -> bool { self.script.reply(reply) }
}

type Storage = BTreeMap<String, Vec<u8>>;

/// The app run as maki runs it (its manifest's memory and storage), on `events` (a `Message`
/// delivering the next of `inbox`), from `storage`, maki's clock saying `times` (`Clocked`).
fn run_at(times: &[Option<u64>], events: &[Event], inbox: &[Vec<u8>], storage: Storage) -> Record {
    let bytes =
        std::fs::read(format!("{}/tests/fixtures/flashcards.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let record = Rc::new(RefCell::new(Record {
        events: events.iter().copied().collect(),
        inbox: inbox.iter().cloned().collect(),
        storage,
        ..Default::default()
    }));
    let mut loaded = load_installed(&bundle.manifest, bundle.code).unwrap();
    loaded.limits = limits;
    let stop =
        loaded.run(Box::new(Clocked { script: Script(record.clone()), times: times.to_vec(), waits: 0 }));
    assert_eq!(stop, Stop::Finished);
    Rc::try_unwrap(record).ok().unwrap().into_inner()
}

/// The same, on `DAY` all along.
fn run(events: &[Event], inbox: &[Vec<u8>], storage: Storage) -> Record {
    run_at(&[noon(DAY)], events, inbox, storage)
}

/// Each card's sides as the app keeps them: each a u16's length, then UTF-8.
fn records<S: AsRef<str>>(cards: &[(S, S)]) -> Vec<u8> {
    let mut b = Vec::new();
    for (front, back) in cards {
        for side in [front.as_ref(), back.as_ref()] {
            b.extend((side.len() as u16).to_le_bytes());
            b.extend(side.as_bytes());
        }
    }
    b
}

/// A deck as the link carries it: its name, how many cards, then the cards.
fn deck<S: AsRef<str>>(name: &str, cards: &[(S, S)]) -> Vec<u8> {
    let mut b = vec![name.len() as u8];
    b.extend(name.as_bytes());
    b.extend((cards.len() as u16).to_le_bytes());
    b.extend(records(cards));
    b
}

/// `n` cards, made up of `make`.
fn cards(n: usize, make: impl Fn(usize) -> (String, String)) -> Vec<(String, String)> {
    (0..n).map(make).collect()
}

/// `deck` sent in place of deck `target` (0: as a new one), in pieces of `size` bytes.
fn upload_in(target: u8, deck: &[u8], size: usize) -> Vec<Vec<u8>> {
    deck.chunks(size)
        .enumerate()
        .map(|(i, piece)| {
            let mut m = vec![V, b'U', target];
            m.extend((deck.len() as u32).to_le_bytes());
            m.extend(((i * size) as u32).to_le_bytes());
            m.extend(piece);
            m
        })
        .collect()
}

/// In as few pieces as the link carries: 4096 bytes a message, eleven of them the piece's header.
fn upload(target: u8, deck: &[u8]) -> Vec<Vec<u8>> { upload_in(target, deck, 4096 - 11) }

fn list() -> Vec<u8> { vec![V, b'L'] }

/// `R`: deck `id` read from `at`.
fn read(id: u8, at: usize) -> Vec<u8> {
    let mut m = vec![V, b'R', id];
    m.extend((at as u32).to_le_bytes());
    m
}

/// A read's answer: how long all there is to read is, and the piece.
fn piece(a: &[u8]) -> (usize, &[u8]) {
    assert_eq!(a[0], 0, "{a:?}");
    assert!(a.len() <= 4096);
    (u32::from_le_bytes([a[1], a[2], a[3], a[4]]) as usize, &a[5..])
}

/// The reads that take all of a deck `len` bytes long with `cards` cards, each where the last ended:
/// the deck, then three bytes a card, 4091 bytes at a time.
fn reads(id: u8, len: usize, cards: usize) -> Vec<Vec<u8>> {
    (0..len + 3 * cards).step_by(4091).map(|at| read(id, at)).collect()
}

/// Each card's progress as a read has it: its box (0 while it's new) and the day it's next due.
fn due(cards: &[(u8, u16)]) -> Vec<u8> {
    cards.iter().flat_map(|&(boxed, day)| [boxed, day as u8, (day >> 8) as u8]).collect()
}

fn delete(id: u8) -> Vec<u8> { vec![V, b'D', id] }

/// The answer to a deck's last piece: kept as deck `id`, its cards, and how many kept their progress.
fn kept(id: u8, cards: u16, carried: u16) -> Vec<u8> {
    let mut a = vec![0, id];
    a.extend(cards.to_le_bytes());
    a.extend(carried.to_le_bytes());
    a
}

/// The answer to a piece that isn't the last: how much of the deck the app has.
fn more(have: usize) -> Vec<u8> { [&[6][..], &(have as u32).to_le_bytes()].concat() }

/// A refusal: its status and why.
fn refused(status: u8, why: &str) -> Vec<u8> { [&[status][..], why.as_bytes()].concat() }

/// Storage with these decks sent, as new ones, on `DAY`.
fn with_decks(decks: &[Vec<u8>]) -> Storage {
    let inbox: Vec<Vec<u8>> = decks.iter().flat_map(|d| upload(0, d)).collect();
    let r = run(&vec![Event::Message; inbox.len()], &inbox, BTreeMap::new());
    assert!(r.replies.iter().all(|a| a[0] == 0 || a[0] == 6), "{:?}", r.replies);
    r.storage
}

/// A deck's progress as the app keeps it: the day it last brought in new cards and how many, then
/// each card's box and the day it was last seen.
fn progress(new_day: u16, brought: u16, cards: &[(u8, u16)]) -> Vec<u8> {
    let mut b = vec![1];
    b.extend(new_day.to_le_bytes());
    b.extend(brought.to_le_bytes());
    for &(boxed, seen) in cards {
        b.push(boxed);
        b.extend(seen.to_le_bytes());
    }
    b
}

/// What the storage holds, as maki counts it: names and values.
fn used(storage: &Storage) -> usize { storage.iter().map(|(k, v)| k.len() + v.len()).sum() }

#[derive(Debug, PartialEq)]
struct Listed {
    id: u8,
    name: String,
    cards: u16,
    new: u16,
    due: u16,
    study: u16,
    size: u32,
    boxes: [u16; 7],
}

#[derive(Debug)]
struct Listing {
    today: u16,
    known: bool,
    streak: u16,
    new_a_day: u16,
    used: u32,
    room: u32,
    decks: Vec<Listed>,
}

/// The answer to `L`, read as the app documents it; all of it, and nothing after.
fn listing(a: &[u8]) -> Listing {
    assert_eq!(&a[..2], &[0, V], "{a:?}");
    let u16_at = |i: usize| u16::from_le_bytes([a[i], a[i + 1]]);
    let u32_at = |i: usize| u32::from_le_bytes([a[i], a[i + 1], a[i + 2], a[i + 3]]);
    assert!(a[4] <= 1);
    let mut l = Listing {
        today: u16_at(2),
        known: a[4] == 1,
        streak: u16_at(5),
        new_a_day: u16_at(7),
        used: u32_at(9),
        room: u32_at(13),
        decks: Vec::new(),
    };
    let mut at = 18;
    for _ in 0..a[17] {
        let (id, len) = (a[at], a[at + 1] as usize);
        let name = String::from_utf8(a[at + 2..at + 2 + len].to_vec()).unwrap();
        at += 2 + len;
        let mut boxes = [0; 7];
        for (b, n) in boxes.iter_mut().enumerate() {
            *n = u16_at(at + 12 + 2 * b);
        }
        let (cards, new, due, study, size) =
            (u16_at(at), u16_at(at + 2), u16_at(at + 4), u16_at(at + 6), u32_at(at + 8));
        l.decks.push(Listed { id, name, cards, new, due, study, size, boxes });
        at += 26;
    }
    assert_eq!(at, a.len(), "nothing after the decks");
    l
}

/// Whether `frame` shows `text` with its top left at (x, y), `scale` times over, light on dark (or
/// dark on light, `on_light`), and nothing else in the box it takes.
fn shows_scaled(
    frame: &Canvas,
    x: i32,
    y: i32,
    text: &str,
    style: Style,
    scale: i32,
    on_light: bool,
) -> bool {
    let mut want = Canvas::default();
    want.text_scaled(0, 0, text, style, scale, Color::Light);
    let (w, h) = (Canvas::text_width(text, style) * scale, style.height() * scale);
    (0..h).all(|j| (0..w).all(|i| frame.get(x + i, y + j) == (want.get(i, j) != on_light)))
}

fn shows(frame: &Canvas, x: i32, y: i32, text: &str, style: Style) -> bool {
    shows_scaled(frame, x, y, text, style, 1, false)
}

/// Whether `frame` shows `text` centred across the screen, its top at `y`.
fn centred(frame: &Canvas, y: i32, text: &str, style: Style) -> bool {
    shows(frame, (WIDTH as i32 - Canvas::text_width(text, style)) / 2, y, text, style)
}

/// Whether the footer says `text`: a rule across the screen, and the line under it.
fn footer(frame: &Canvas, text: &str) -> bool {
    (0..WIDTH as i32).all(|x| frame.get(x, 96)) && centred(frame, 98, text, Style::Small)
}

/// Whether there's nothing where the footer goes.
fn no_footer(frame: &Canvas) -> bool {
    (96..HEIGHT as i32).all(|y| (0..WIDTH as i32).all(|x| !frame.get(x, y)))
}

/// Whether `frame` shows a side of a card: `lines` at `style`, `scale` times over, each centred,
/// together in the middle of the side's room (the front's, or under the front's line, the back's).
fn side(frame: &Canvas, back: bool, lines: &[&str], style: Style, scale: i32) -> bool {
    let (top, height) = if back { (16, 80) } else { (14, 82) };
    let h = style.height() * scale;
    let y = top + (height - lines.len() as i32 * h) / 2;
    lines.iter().enumerate().all(|(i, line)| {
        let x = 2 + (WIDTH as i32 - 4 - Canvas::text_width(line, style) * scale) / 2;
        shows_scaled(frame, x, y + i as i32 * h, line, style, scale, false)
    })
}

/// Whether `frame` shows the top of a card's front: its box (or "new") and how many are left.
fn front_head(frame: &Canvas, boxed: &str, left: usize) -> bool {
    let left = format!("{left} left");
    shows(frame, 2, 0, boxed, Style::Small)
        && shows(frame, WIDTH as i32 - 2 - Canvas::text_width(&left, Style::Small), 0, &left, Style::Small)
}

/// Whether `frame` shows the top of a card's back: its front's line, and a rule under it.
fn back_head(frame: &Canvas, front: &str) -> bool {
    shows(frame, 2, 0, front, Style::Small) && (0..WIDTH as i32).all(|x| frame.get(x, 13))
}

/// Whether `frame` says "again" and "knew it" at the left and right of its footer.
fn answers(frame: &Canvas) -> bool {
    let knew = WIDTH as i32 - 2 - Canvas::text_width("knew it", Style::Small);
    shows(frame, 2, 98, "again", Style::Small) && shows(frame, knew, 98, "knew it", Style::Small)
}

/// Whether row `row` of the list shows deck `name`, with `count` for today at the right (none if
/// blank), selected (dark on light) or not.
fn row(frame: &Canvas, row: i32, name: &str, count: &str, selected: bool) -> bool {
    let x = WIDTH as i32 - 3 - Canvas::text_width(count, Style::Regular);
    shows_scaled(frame, 3, row * 16, name, Style::Regular, 1, selected)
        && (count.is_empty() || shows_scaled(frame, x, row * 16, count, Style::Regular, 1, selected))
}

fn spanish() -> Vec<u8> {
    deck("Spanish", &[("hola", "hello"), ("gracias", "thank you"), ("el perro", "the dog")])
}

/// `text` in lines no wider than `width` pixels of `style`, `scale` times over, broken between
/// words: for texts whose words each fit a line.
fn wrapped(text: &str, style: Style, scale: i32, width: i32) -> Vec<String> {
    let fits = |s: &str| Canvas::text_width(s, style) * scale <= width;
    let mut lines = Vec::new();
    for own in text.split('\n') {
        let mut line = String::new();
        for word in own.split(' ') {
            let with = if line.is_empty() { word.to_string() } else { format!("{line} {word}") };
            if line.is_empty() || fits(&with) {
                line = with;
            } else {
                lines.push(std::mem::replace(&mut line, word.to_string()));
            }
        }
        lines.push(line);
    }
    lines
}

/// The centre opening the selected deck, and again to study it.
const OPEN_AND_STUDY: [Event; 2] = [Event::Centre, Event::Centre];

/// The presses that answer cards: each turned over, then known or not.
fn answer_cards(knew: &[bool]) -> Vec<Event> {
    knew.iter().flat_map(|&k| [Event::Centre, if k { Event::Right } else { Event::Left }]).collect()
}

#[test]
fn flashcards_starts_with_no_decks_and_says_where_they_come_from() {
    let r = run(&[Event::Message, Event::Menu(1), Event::Centre], &[list()], BTreeMap::new());
    assert_eq!(r.menu, ["New cards a day: 20", "Room on maki"]);
    let f = &r.frames[0];
    assert!(centred(f, 8, "No decks yet", Style::Bold));
    let says = [
        "Send decks from maki",
        "desktop's Flashcards",
        "page. maki keeps 8, of",
        "up to 1000 cards each,",
        "in 64 KiB.",
    ];
    for (i, line) in says.iter().enumerate() {
        assert!(centred(f, 30 + 12 * i as i32, line, Style::Small), "{line}");
    }
    assert!(no_footer(f));
    // what it keeps besides decks, kept at once so its room is spoken for: the format, the day maki
    // said, the day last studied and the run up to it, new cards a day, the next new deck's ID
    assert_eq!(r.storage["state"], [1, 0x20, 0x4e, 0, 0, 0, 0, 20, 0, 1]);
    let l = listing(&r.replies[0]);
    assert_eq!((l.today, l.known, l.streak, l.new_a_day), (DAY, true, 0, 20));
    assert_eq!((l.used, l.room, l.decks.len()), (15, ROOM as u32, 0));
    // the room on maki, and its limits, from the menu
    let room = &r.frames[2];
    assert!(centred(room, 0, "Room on maki", Style::Bold));
    assert!(centred(room, 20, "0 KiB of 64 KiB used", Style::Regular));
    assert!(centred(room, 40, "0 of 8 decks, 0 cards", Style::Small));
    assert!(centred(room, 58, "Up to 1000 cards a deck,", Style::Small));
    assert!(centred(room, 70, "200 characters a front,", Style::Small));
    assert!(centred(room, 82, "500 a back.", Style::Small));
    assert!(footer(room, "centre: back"));
    assert_eq!(r.frames[3], r.frames[0]);
}

#[test]
fn a_deck_sent_is_kept_and_listed_on_maki_and_over_the_link() {
    let r =
        run(&[Event::Message, Event::Message], &[upload(0, &spanish())[0].clone(), list()], BTreeMap::new());
    assert_eq!(r.replies[0], kept(1, 3, 0));
    // the list, the cards in a value of their own, and the progress, every card new
    let mut decks = vec![1, 1, 0, 7];
    decks.extend(b"Spanish");
    decks.extend([3, 0, 1]);
    assert_eq!(r.storage["decks"], decks);
    let spanish_cards = records(&[("hola", "hello"), ("gracias", "thank you"), ("el perro", "the dog")]);
    assert_eq!(r.storage["c1a.0"], spanish_cards);
    assert_eq!(r.storage["p1a"], progress(0, 0, &[(0, 0); 3]));
    let l = listing(&r.replies[1]);
    let size = ("c1a.0".len() + spanish_cards.len() + "p1a".len() + 14) as u32;
    assert_eq!(
        l.decks,
        [Listed { id: 1, name: "Spanish".into(), cards: 3, new: 3, due: 0, study: 3, size, boxes: [0; 7] }]
    );
    assert_eq!(l.used as usize, used(&r.storage));
    // on maki: its name, selected, and the 3 it has for today
    let f = &r.frames[1];
    assert!(row(f, 0, "Spanish", "3", true));
    assert!(footer(f, "centre: open"));
    // and still there when the app is opened again
    let again = run(&[], &[], r.storage.clone());
    assert_eq!(again.frames[0], r.frames[1]);
    assert_eq!(again.storage, r.storage);
}

#[test]
fn a_big_deck_comes_in_pieces_and_is_kept_in_values_of_whole_cards() {
    let many =
        cards(1000, |i| (format!("word {i:04}"), format!("the meaning of word {i:04}, at some length")));
    let d = deck("Many", &many);
    let pieces = upload(0, &d);
    assert_eq!(pieces.len(), 13);
    let mut inbox = pieces.clone();
    inbox.push(list());
    let r = run(&vec![Event::Message; inbox.len()], &inbox, BTreeMap::new());
    for (i, a) in r.replies[..12].iter().enumerate() {
        assert_eq!(a, &more((i + 1) * 4085));
    }
    assert_eq!(r.replies[12], kept(1, 1000, 0));
    // in values of up to 16 KiB, each of whole cards, together the deck's cards
    let values: Vec<&Vec<u8>> = (0..4).map(|n| &r.storage[&format!("c1a.{n}")]).collect();
    assert!(!r.storage.contains_key("c1a.4"));
    let per = 16 * 1024 / records(&many[..1]).len();
    for (n, v) in values.iter().enumerate() {
        assert!(v.len() <= 16 * 1024);
        let from = n * per;
        assert_eq!(**v, records(&many[from..(from + per).min(1000)]), "value {n}");
    }
    let l = listing(&r.replies[13]);
    assert_eq!((l.decks[0].cards, l.decks[0].new, l.decks[0].study), (1000, 1000, 20));
    assert_eq!(l.used as usize, used(&r.storage));
    // and studied from them: the first card, and one in the last value
    let r = run(&OPEN_AND_STUDY, &[], r.storage);
    assert!(centred(&r.frames[1], 17, "20 new today", Style::Small));
    assert!(centred(&r.frames[1], 84, "1000 cards, 1000 new", Style::Small));
    assert!(side(&r.frames[2], false, &["word", "0000"], Style::Bold, 2));
    let mut storage = with_decks(&[d]);
    storage.insert("p1a".into(), progress(DAY, 0, &[(1, DAY - 1); 1000]));
    let mut events = OPEN_AND_STUDY.to_vec();
    events.extend([Event::Centre, Event::Right].repeat(999));
    let r = run(&events, &[], storage);
    assert!(side(r.frames.last().unwrap(), false, &["word", "0999"], Style::Bold, 2));
}

#[test]
fn pieces_out_of_order_or_past_the_deck_s_end_are_refused_and_end_the_upload() {
    use Event::*;
    let d = deck("Many", &cards(300, |i| (format!("word {i}"), format!("meaning {i}"))));
    let p = upload(0, &d);
    assert_eq!(p.len(), 2);
    let with = |m: &[u8], at: usize, b: u8| -> Vec<u8> {
        let mut m = m.to_vec();
        m[at] = b;
        m
    };
    // a deck of 5000 bytes whose second piece runs past its end
    let past = upload_in(0, &[7; 5100], 4085);
    let past = [with(&with(&past[0], 3, 0x88), 4, 0x13), with(&with(&past[1], 3, 0x88), 4, 0x13)];
    let inbox = vec![
        p[1].clone(),      // no upload under way
        p[0].clone(),      // 6
        p[0].clone(),      // the first again starts it afresh: 6
        list(),            // something else between pieces leaves it be
        with(&p[1], 2, 3), // another deck to replace
        p[1].clone(),      // and so the upload is over
        p[0].clone(),      // 6
        with(&p[1], 3, 0), // another length
        p[0].clone(),      // 6
        with(&p[1], 7, 0), // another place
        past[0].clone(),   // 6
        past[1].clone(),   // past the end
        p[0].clone(),      // 6
        p[1].clone(),      // and at last, whole
        list(),
    ];
    let r = run(&vec![Message; inbox.len()], &inbox, BTreeMap::new());
    let order = refused(4, "a piece out of order");
    let want = [
        order.clone(),
        more(4085),
        more(4085),
        r.replies[3].clone(),
        order.clone(),
        order.clone(),
        more(4085),
        order.clone(),
        more(4085),
        order.clone(),
        more(4085),
        refused(4, "a piece past the deck's end"),
        more(4085),
        kept(1, 300, 0),
    ];
    assert_eq!(r.replies[..want.len()], want);
    assert!(listing(&r.replies[3]).decks.is_empty());
    assert_eq!(listing(&r.replies[14]).decks.len(), 1);
}

#[test]
fn studying_turns_each_card_over_and_moves_it_by_its_first_answer() {
    use Event::*;
    let storage = with_decks(&[spanish()]);
    // hola known; gracias not, so it comes round again; el perro known; gracias known at last;
    // and once, the centre turns a card back
    let mut events = OPEN_AND_STUDY.to_vec();
    events.extend([Centre, Right, Centre, Left, Centre, Centre, Centre, Right, Centre, Right]);
    let r = run(&events, &[], storage);
    let f = &r.frames;
    // the deck's page: what it has for today, and its cards
    assert!(centred(&f[1], 0, "Spanish", Style::Bold));
    assert!(centred(&f[1], 17, "3 new today", Style::Small));
    assert!(centred(&f[1], 84, "3 cards, 3 new", Style::Small));
    assert!(footer(&f[1], "centre: study"));
    assert_eq!(r.menu, ["Delete this deck", "New cards a day: 20", "Room on maki"]);
    // a front, as big as it fits; then its back under its front's line
    assert!(front_head(&f[2], "new", 3) && side(&f[2], false, &["hola"], Style::Bold, 2));
    assert!(footer(&f[2], "centre: turn over"));
    assert!(back_head(&f[3], "hola") && side(&f[3], true, &["hello"], Style::Bold, 2) && answers(&f[3]));
    assert!(front_head(&f[4], "new", 2) && side(&f[4], false, &["gracias"], Style::Bold, 2));
    assert!(back_head(&f[5], "gracias") && side(&f[5], true, &["thank you"], Style::Bold, 2));
    // gracias wasn't known: el perro, then gracias again, from box 1
    assert!(front_head(&f[6], "new", 2) && side(&f[6], false, &["el perro"], Style::Bold, 2));
    assert!(back_head(&f[7], "el perro") && side(&f[7], true, &["the dog"], Style::Bold, 2));
    assert_eq!(f[8], f[6], "the centre turns it back");
    assert!(front_head(&f[10], "box 1", 1) && side(&f[10], false, &["gracias"], Style::Bold, 2));
    // the end of the sitting: what was studied, and when there's more
    let done = &f[12];
    assert!(centred(done, 12, "Done for today", Style::Bold));
    assert!(centred(done, 36, "3 cards, 1 again", Style::Small));
    assert!(centred(done, 64, "more tomorrow", Style::Small));
    assert!(footer(done, "centre: back"));
    // known the first time, box 2; not, box 1, however it went after; three brought in today
    assert_eq!(r.storage["p1a"], progress(DAY, 3, &[(2, DAY), (1, DAY), (2, DAY)]));
    // studied today, the first day in a row
    assert_eq!(r.storage["state"][3..7], [0x20, 0x4e, 1, 0]);
    let r = run(&[Centre, Centre, Message], &[list()], r.storage);
    assert!(centred(&r.frames[1], 17, "nothing for today", Style::Small));
    assert!(centred(&r.frames[1], 84, "more tomorrow", Style::Small));
    assert!(footer(&r.frames[1], "left: decks"));
    assert!(footer(&r.frames[2], "nothing for today"));
    let l = listing(&r.replies[0]);
    assert_eq!(
        (l.decks[0].new, l.decks[0].due, l.decks[0].study, l.decks[0].boxes),
        (0, 0, 0, [1, 2, 0, 0, 0, 0, 0])
    );
}

#[test]
fn cards_come_back_as_leitner_s_boxes_say_the_longest_due_first() {
    use Event::*;
    let boxes: Vec<(String, String)> =
        (1..=7).map(|b| (format!("c{b}"), format!("b{b}"))).chain([("new".into(), "card".into())]).collect();
    let mut storage = with_decks(&[deck("Boxes", &boxes)]);
    // a card in each box, seen on DAY, and one new
    let seen: Vec<(u8, u16)> = (1..=7).map(|b| (b, DAY)).chain([(0, 0)]).collect();
    storage.insert("p1a".into(), progress(DAY, 0, &seen));
    // a card in box n comes back 2^(n-1) days after it was seen
    for k in [0u16, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 1000] {
        let r = run_at(&[noon(DAY + k)], &[Message], &[list()], storage.clone());
        let d = &listing(&r.replies[0]).decks[0];
        let due = (1..=7).filter(|b| 1u16 << (b - 1) <= k).count() as u16;
        assert_eq!((d.due, d.new, d.study, d.boxes), (due, 1, due + 1, [1; 7]), "day {k}");
    }
    // 64 days on, all of them, longest due first, then the new one; box 1's card known goes to 2,
    // box 2's not known back to 1, box 7's known stays in 7
    let mut events = OPEN_AND_STUDY.to_vec();
    events.extend(answer_cards(&[true, false, true, true, true, true, true, true]));
    events.extend(answer_cards(&[true]));
    let r = run_at(&[noon(DAY + 64)], &events, &[], storage.clone());
    let fronts: Vec<usize> = (0..9)
        .map(|i| {
            (1..=8).find(|&c| side(&r.frames[2 + 2 * i], false, &[&boxes[c - 1].0], Style::Bold, 2)).unwrap()
        })
        .collect();
    assert_eq!(fronts, [1, 2, 3, 4, 5, 2, 6, 7, 8]);
    let after: Vec<(u8, u16)> = [2, 1, 4, 5, 6, 7, 7, 2].iter().map(|&b| (b, DAY + 64)).collect();
    assert_eq!(r.storage["p1a"], progress(DAY + 64, 1, &after));
    // a card seen after today (maki's clock was wrong then, or is now) is due, until today is that
    // day, from which its box's wait counts
    storage.insert(
        "p1a".into(),
        progress(0, 0, &[(1, DAY + 5), (7, DAY + 300), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0)]),
    );
    for (k, due) in [(0, 2), (4, 2), (5, 1), (6, 2), (299, 2), (300, 1), (363, 1), (364, 2)] {
        let r = run_at(&[noon(DAY + k)], &[Message], &[list()], storage.clone());
        assert_eq!(listing(&r.replies[0]).decks[0].due, due, "day {k}");
    }
}

#[test]
fn a_deck_brings_in_twenty_new_cards_a_day_and_the_menu_says_how_many() {
    use Event::*;
    let storage = with_decks(&[deck("Thirty", &cards(30, |i| (format!("n{i:02}"), format!("b{i:02}"))))]);
    let mut events = OPEN_AND_STUDY.to_vec();
    events.extend(answer_cards(&[true; 20]));
    events.push(Message);
    let r = run(&events, &[list()], storage);
    assert!(front_head(&r.frames[2], "new", 20));
    assert!(centred(&r.frames[42], 36, "20 cards, all known", Style::Small));
    let d = &listing(&r.replies[0]).decks[0];
    assert_eq!((d.new, d.due, d.study), (10, 0, 0));
    // the next day, the ten left; the day after, the twenty due and the ten
    for (k, study) in [(1, 10), (2, 30)] {
        let r = run_at(&[noon(DAY + k)], &[Message], &[list()], r.storage.clone());
        assert_eq!(listing(&r.replies[0]).decks[0].study, study, "day {k}");
    }
    // the menu goes round 20, 50, 100, 5, 10 and 20 again, and says so
    let r =
        run(&[Menu(0), Message, Menu(0), Menu(0), Menu(0), Menu(0), Message], &[list(), list()], r.storage);
    assert!(footer(&r.frames[1], "50 new cards a day"));
    assert_eq!(listing(&r.replies[0]).new_a_day, 50);
    assert_eq!(listing(&r.replies[0]).decks[0].study, 10);
    assert!(footer(&r.frames[3], "100 new cards a day") && footer(&r.frames[4], "5 new cards a day"));
    assert_eq!(listing(&r.replies[1]).new_a_day, 20);
    assert_eq!(r.menu, ["New cards a day: 20", "Room on maki"]);
    assert_eq!(r.storage["state"][7..9], [20, 0]);
}

#[test]
fn without_the_date_it_studies_as_on_the_last_day_it_knew_and_says_so() {
    use Event::*;
    let storage = with_decks(&[spanish()]);
    // maki has lost its clock: the app takes it to be the last day it knew, and says so
    let mut events = OPEN_AND_STUDY.to_vec();
    events.extend(answer_cards(&[true, false]));
    events.push(Message);
    let r = run_at(&[None], &events, &[list()], storage);
    assert!(footer(&r.frames[0], "no date: as if 4 Oct"));
    let l = listing(&r.replies[0]);
    assert_eq!((l.today, l.known), (DAY, false));
    assert_eq!(r.storage["p1a"], progress(DAY, 2, &[(2, DAY), (1, DAY), (0, 0)]));
    // and doesn't count it among the days in a row: it can't say which day it is
    assert_eq!(r.storage["state"][3..7], [0, 0, 0, 0]);
    // gracias waits for the next day, and the last new card for maki's clock... or the next day
    let d = &l.decks[0];
    assert_eq!((d.due, d.new, d.study), (0, 1, 1));
    let r = run_at(&[noon(DAY + 1)], &[Message], &[list()], r.storage);
    let d = &listing(&r.replies[0]).decks[0];
    assert_eq!((d.due, d.study), (1, 2));

    // a maki that has never known the date: day 0, and what's studied then comes back as soon as it
    // does
    let mut events = vec![Message];
    events.extend(OPEN_AND_STUDY);
    events.extend(answer_cards(&[true, true, true]));
    let r = run_at(&[None], &events, &upload(0, &spanish()), BTreeMap::new());
    assert!(footer(&r.frames[0], "maki doesn't know the date") || no_footer(&r.frames[0]));
    assert!(footer(&r.frames[1], "maki doesn't know the date"));
    assert_eq!(r.storage["p1a"], progress(0, 3, &[(2, 0); 3]));
    let r = run_at(&[noon(DAY)], &[Message], &[list()], r.storage);
    let d = &listing(&r.replies[0]).decks[0];
    assert_eq!((d.due, d.study), (3, 3));
}

#[test]
fn the_days_in_a_row_show_once_there_are_two() {
    use Event::*;
    let storage = with_decks(&[deck("Two", &[("one", "1"), ("two", "2")])]);
    let mut events = OPEN_AND_STUDY.to_vec();
    events.extend(answer_cards(&[true]));
    events.push(Menu(0)); // Stop studying
    events.extend([Left, Message]);
    let r = run(&events, &[list()], storage);
    assert_eq!(listing(&r.replies[0]).streak, 1);
    assert!(footer(r.frames.last().unwrap(), "centre: open"));
    // the next day too: two in a row, under the list and when the sitting's done
    let mut events = OPEN_AND_STUDY.to_vec();
    events.extend(answer_cards(&[true]));
    events.extend([Centre, Left, Message]);
    let r = run_at(&[noon(DAY + 1)], &events, &[list()], r.storage);
    assert!(centred(&r.frames[4], 50, "2 days in a row", Style::Small));
    assert!(footer(r.frames.last().unwrap(), "2 days in a row"));
    assert_eq!(listing(&r.replies[0]).streak, 2);
    // still two the day after, until it's studied; gone the day after that
    for (k, streak) in [(2, 2), (3, 0)] {
        let r = run_at(&[noon(DAY + k)], &[Message], &[list()], r.storage.clone());
        assert_eq!(listing(&r.replies[0]).streak, streak, "day {k}");
        let says = if streak == 2 { "2 days in a row" } else { "centre: open" };
        assert!(footer(&r.frames[0], says));
    }
}

#[test]
fn a_deck_replaced_keeps_the_progress_of_the_cards_it_still_has() {
    let numbers =
        deck("Numbers", &[("one", "1"), ("two", "2"), ("three", "3"), ("two", "2 again"), ("four", "4")]);
    let mut storage = with_decks(&[spanish(), numbers]);
    storage.insert(
        "p2a".into(),
        progress(DAY - 1, 4, &[(3, DAY - 2), (2, DAY - 1), (1, DAY - 1), (5, DAY - 9), (0, 0)]),
    );
    let new = [
        ("three", "III"),
        ("five", "5"),
        ("two", "dos"),
        ("one", "uno"),
        ("two", "second two"),
        ("two", "third two"),
    ];
    let mut inbox = upload(2, &deck("Numbers, again", &new));
    inbox.push(list());
    let r = run(&[Event::Message, Event::Message], &inbox, storage);
    // three, the first two, one and the second two kept theirs; five and the third two are new
    assert_eq!(r.replies[0], kept(2, 6, 4));
    assert_eq!(
        r.storage["p2b"],
        progress(DAY - 1, 4, &[(1, DAY - 1), (0, 0), (2, DAY - 1), (3, DAY - 2), (5, DAY - 9), (0, 0)])
    );
    assert_eq!(r.storage["c2b.0"], records(&new));
    // kept beside the old one, which is gone now; in its place in the list, with its ID
    assert!(!r.storage.contains_key("c2a.0") && !r.storage.contains_key("p2a"));
    let l = listing(&r.replies[1]);
    let names: Vec<(u8, &str)> = l.decks.iter().map(|d| (d.id, d.name.as_str())).collect();
    assert_eq!(names, [(1, "Spanish"), (2, "Numbers, again")]);
    assert_eq!(l.decks[1].boxes, [1, 1, 1, 0, 1, 0, 0]);
    assert_eq!(l.used as usize, used(&r.storage));
    // replaced again, it goes back to its first set of keys
    let r = run(&[Event::Message], &upload(2, &deck("Numbers", &new)), r.storage);
    assert_eq!(r.replies[0], kept(2, 6, 4));
    assert!(
        r.storage.contains_key("c2a.0") && !r.storage.contains_key("c2b.0") && !r.storage.contains_key("p2b")
    );
    // but not under another deck's name, nor in place of a deck that isn't there
    let mut inbox = upload(2, &deck("Spanish", &new));
    inbox.extend(upload(9, &deck("Numbers", &new)));
    inbox.extend(upload(0, &deck("Numbers", &new)));
    let r2 = run(&[Event::Message; 3], &inbox, r.storage.clone());
    assert_eq!(r2.replies, [vec![8], vec![7], vec![8]]);
    assert_eq!(r2.storage, r.storage);
}

#[test]
fn the_deck_being_studied_is_replaced_even_without_room_for_both_at_once() {
    use Event::*;
    // a deck of a thousand cards that takes most of the room: there's no room for another like it
    let big = cards(1000, |i| (format!("w{i:04}"), format!("{i:04} {}", "x".repeat(45))));
    let mut storage = with_decks(&[deck("Big", &big)]);
    assert_eq!(used(&storage), 62058);
    storage.insert("p1a".into(), progress(DAY, 0, &[(1, DAY - 1); 1000]));
    // three cards studied, then the deck replaced while it's studied, a card's back changed
    let mut changed = big.clone();
    changed[500].1 = format!("0500 {}", "y".repeat(45));
    let pieces = upload(1, &deck("Big", &changed));
    let mut events = OPEN_AND_STUDY.to_vec();
    events.extend(answer_cards(&[true, true, false]));
    events.extend(vec![Message; pieces.len()]);
    let r = run(&events, &pieces, storage);
    assert_eq!(r.replies.last().unwrap(), &kept(1, 1000, 1000));
    // the sitting is over: the deck's page, saying why
    let f = r.frames.last().unwrap();
    assert!(centred(f, 0, "Big", Style::Bold) && footer(f, "the deck was just replaced"));
    // what was studied kept, in the other set of keys, the first set gone
    assert!(
        r.storage.keys().all(|k| !k.ends_with("a.0") && k != "p1a"),
        "{:?}",
        r.storage.keys().collect::<Vec<_>>()
    );
    let p = &r.storage["p1b"];
    assert_eq!(p[5..14], [2, 0x20, 0x4e, 2, 0x20, 0x4e, 1, 0x20, 0x4e]);
    assert_eq!(p[14..17], [1, 0x1f, 0x4e]);
    assert!(used(&r.storage) <= ROOM);
}

#[test]
fn a_ninth_deck_and_decks_too_big_for_the_room_left_are_refused_with_why() {
    // a deck that leaves 3478 bytes
    let big = cards(1000, |i| (format!("w{i:04}"), format!("{i:04} {}", "x".repeat(45))));
    let storage = with_decks(&[deck("Big", &big)]);
    assert_eq!(ROOM - used(&storage), 3478);
    let tiny = |n: usize| deck("Tiny", &vec![("a", "b"); n]);
    let mut inbox = vec![upload(0, &tiny(700))[0].clone()];
    inbox.extend(upload(0, &tiny(500)));
    inbox.extend(upload(0, &tiny(380)));
    inbox.push(list());
    let r = run(&[Event::Message; 4], &inbox, storage.clone());
    // too long to fit, at once; then, all of it come, more than there's room for with what keeping
    // it takes besides; then one that fits
    assert_eq!(r.replies[0], refused(5, "it's 4.1 KiB, and 3.4 KiB is free"));
    assert_eq!(r.replies[1], refused(5, "it takes 4.4 KiB, and 3.4 KiB is free"));
    assert_eq!(r.replies[2], kept(2, 380, 0));
    assert_eq!(ROOM - used(&r.storage), 3478 - (380 * 9 + 23));
    assert_eq!(listing(&r.replies[3]).decks.len(), 2);

    // eight decks are as many as it keeps
    let eight: Vec<Vec<u8>> = (1..=8).map(|i| deck(&format!("Deck {i}"), &[("front", "back")])).collect();
    let storage = with_decks(&eight);
    let r =
        run(&[Event::Message, Event::Message], &[upload(0, &tiny(1))[0].clone(), list()], storage.clone());
    assert_eq!(r.replies[0], refused(5, "maki keeps 8 decks"));
    assert_eq!(listing(&r.replies[1]).decks.len(), 8);
    assert_eq!(r.storage, storage);
}

#[test]
fn every_message_and_deck_it_does_not_take_is_refused_and_changes_nothing() {
    let card = |front: &str, back: &str| deck("Deck", &[(front, back)]);
    let named = |name: &[u8]| {
        let mut d = vec![name.len() as u8];
        d.extend(name);
        d.extend([1, 0]);
        d.extend(records(&[("a", "b")]));
        d
    };
    let whole = |d: &[u8]| upload(0, d)[0].clone();
    let cases: Vec<(Vec<u8>, Vec<u8>)> = vec![
        // not a message
        (vec![], refused(4, "a message is its version and what it is, at least")),
        (vec![V], refused(4, "a message is its version and what it is, at least")),
        (vec![2, b'L'], vec![9, V]),
        (vec![0, b'L'], vec![9, V]),
        (vec![V, b'X'], refused(4, "not a message this app takes")),
        (vec![V, b'l'], refused(4, "not a message this app takes")),
        (vec![V, b'L', 0], refused(4, "not a message this app takes")),
        (vec![V, b'D'], refused(4, "not a message this app takes")),
        (vec![V, b'D', 1, 0], refused(4, "not a message this app takes")),
        (vec![V, b'D', 1], vec![7]),
        (
            vec![V, b'U', 0, 5, 0, 0],
            refused(4, "a piece is the deck it replaces, the deck's length and where it goes, then itself"),
        ),
        (vec![V, b'U', 0, 5, 0, 0, 0, 0, 0, 0, 0], refused(4, "an empty piece")),
        (vec![V, b'U', 0, 0, 0, 0, 0, 0, 0, 0, 0, 7], refused(4, "a deck is 1 to 65536 bytes")),
        (vec![V, b'U', 0, 1, 0, 1, 0, 0, 0, 0, 0, 7], refused(4, "a deck is 1 to 65536 bytes")),
        // not a deck it keeps: its name
        (whole(&named(b"")), refused(4, "its name is empty")),
        (whole(&named(b"   ")), refused(4, "its name is empty")),
        (whole(&named("x".repeat(33).as_bytes())), refused(4, "its name is too long")),
        (whole(&named(b"two\nlines")), refused(4, "its name has a control character")),
        (whole(&named(b"tab\there")), refused(4, "its name has a control character")),
        (whole(&named(b" Spanish")), refused(4, "its name starts or ends with a space")),
        (whole(&named("Spanish\u{a0}".as_bytes())), refused(4, "its name starts or ends with a space")),
        (whole(&named(b"\xffbad")), refused(4, "its name is cut short or isn't UTF-8")),
        (whole(&[9, b'S', b'p']), refused(4, "its name is cut short or isn't UTF-8")),
        // its cards
        (whole(&[2, b'N', b'o', 0, 0]), refused(4, "a deck has 1 to 1000 cards")),
        (whole(&[2, b'N', b'o', 0xe9, 0x03]), refused(4, "a deck has 1 to 1000 cards")),
        (whole(&[2, b'N', b'o', 1]), refused(4, "it's cut short")),
        (whole(&card("", "back")), refused(4, "card 1: its front is empty")),
        (whole(&card("front", " \n ")), refused(4, "card 1: its back is empty")),
        (whole(&card(&"f".repeat(201), "back")), refused(4, "card 1: its front is too long")),
        (whole(&card("front", &"é".repeat(501))), refused(4, "card 1: its back is too long")),
        (whole(&card("tab\there", "back")), refused(4, "card 1: its front has a control character")),
        (whole(&card("front", "windows\r\nline")), refused(4, "card 1: its back has a control character")),
        (whole(&card("front", "bell\x07")), refused(4, "card 1: its back has a control character")),
        (
            whole(&[&card("front", "back")[..7], &[2, 0], &[0xc3, 0x28], &[4, 0], b"back"].concat()),
            refused(4, "card 1: its front isn't UTF-8"),
        ),
        (whole(&card("front", "back")[..14]), refused(4, "card 1: its back is cut short")),
        (whole(&[&card("front", "back")[..], &[1]].concat()), refused(4, "there's more after its last card")),
        (
            whole(
                &[
                    &deck("Deck", &[("a", "b"), ("c", "d")])[..5],
                    &[3, 0],
                    &records(&[("a", "b"), ("c", "d")]),
                ]
                .concat(),
            ),
            refused(4, "card 3: its front is cut short"),
        ),
    ];
    let mut inbox: Vec<Vec<u8>> = cases.iter().map(|(m, _)| m.clone()).collect();
    inbox.push(list());
    let r = run(&vec![Event::Message; inbox.len()], &inbox, BTreeMap::new());
    for (i, ((m, want), got)) in cases.iter().zip(&r.replies).enumerate() {
        assert_eq!(got, want, "case {i}: {m:?}");
    }
    assert!(listing(&r.replies[cases.len()]).decks.is_empty());
    assert_eq!(r.storage.keys().collect::<Vec<_>>(), ["state"]);
    // and the longest of each, and line breaks in the sides, are taken
    let longest = deck(
        &"é".repeat(32),
        &[("f".repeat(200), "€".repeat(500)), ("two\nlines".into(), "and\n\nmore".into())],
    );
    let r = run(&[Event::Message], &upload(0, &longest), BTreeMap::new());
    assert_eq!(r.replies, [kept(1, 2, 0)]);
}

#[test]
fn a_deck_goes_from_the_computer_or_from_maki_s_menu() {
    use Event::*;
    let storage = with_decks(&[spanish(), deck("Numbers", &[("one", "1")])]);
    let r = run(&[Message, Message, Message], &[delete(1), delete(1), list()], storage.clone());
    assert_eq!(r.replies[..2], [vec![0], vec![7]]);
    let l = listing(&r.replies[2]);
    assert_eq!(l.decks.iter().map(|d| d.id).collect::<Vec<_>>(), [2]);
    assert!(r.storage.keys().all(|k| !k.starts_with("c1") && !k.starts_with("p1")));
    // on maki: open it, Delete this deck, left keeps it; again, and the centre deletes it
    let r = run(&[Centre, Menu(0), Left, Menu(0), Centre, Message], &[list()], storage);
    let ask = &r.frames[2];
    assert!(
        centred(ask, 16, "Delete this deck?", Style::Bold) && centred(ask, 40, "Spanish", Style::Regular)
    );
    assert!(
        centred(ask, 62, "its cards and progress", Style::Small)
            && centred(ask, 74, "go for good", Style::Small)
    );
    assert!(footer(ask, "centre: delete   left: keep"));
    assert_eq!(r.frames[3], r.frames[1]);
    assert!(row(&r.frames[5], 0, "Numbers", "1", true) && footer(&r.frames[5], "deleted Spanish"));
    assert_eq!(listing(&r.replies[0]).decks.len(), 1);
    // the last deck gone, nothing of them is left
    let r = run(&[Message], &[delete(2)], r.storage);
    assert_eq!(r.storage.keys().collect::<Vec<_>>(), ["state"]);
}

#[test]
fn a_new_deck_s_id_is_one_no_deck_has_had_for_a_while() {
    let storage = with_decks(&[spanish()]);
    let mut inbox = vec![delete(1)];
    inbox.extend(upload(0, &deck("French", &[("bonjour", "hello")])));
    inbox.push(delete(1));
    inbox.push(list());
    let r = run(&[Event::Message; 4], &inbox, storage);
    assert_eq!(r.replies[..3], [vec![0], kept(2, 1, 0), vec![7]]);
    assert_eq!(listing(&r.replies[3]).decks[0].id, 2);
    // round from 255 to 1, past those in use
    let mut storage = r.storage;
    storage.get_mut("state").unwrap()[9] = 255;
    let mut inbox = upload(0, &deck("German", &[("hallo", "hello")]));
    inbox.extend(upload(0, &deck("Italian", &[("ciao", "hello")])));
    inbox.extend(upload(0, &deck("Dutch", &[("hoi", "hello")])));
    let r = run(&[Event::Message; 3], &inbox, storage);
    assert_eq!(r.replies, [kept(255, 1, 0), kept(1, 1, 0), kept(3, 1, 0)]);
}

#[test]
fn a_card_is_drawn_as_big_as_it_fits_without_breaking_a_word() {
    let fronts = [
        // big, a line or two
        ("thank you", vec!["thank you"], Style::Bold, 2),
        ("el perro grande", vec!["el perro", "grande"], Style::Bold, 2),
        // too wide for big but for broken in two: a line of maki's regular font
        ("unbelievable", vec!["unbelievable"], Style::Regular, 1),
        ("Donaudampfschifffahrt", vec!["Donaudampfschifffahrt"], Style::Regular, 1),
        // too wide for that too: small
        ("Streichholzschächtelchen", vec!["Streichholzschächtelchen"], Style::Small, 1),
        // a sentence, in lines of regular: more than two lines big
        (
            "The quick brown fox jumps over the lazy dog",
            vec!["The quick brown fox", "jumps over the lazy", "dog"],
            Style::Regular,
            1,
        ),
        // line breaks kept, a blank line among them
        ("one\n\nthree", vec!["one", "", "three"], Style::Regular, 1),
        // what maki's fonts don't draw shows as a box with a question mark
        ("\u{416}\u{443}\u{43a}", vec!["\u{fffd}\u{fffd}\u{fffd}"], Style::Bold, 2),
    ];
    let cards: Vec<(&str, &str)> = fronts.iter().map(|(f, ..)| (*f, "back")).collect();
    let storage = with_decks(&[deck("Sizes", &cards)]);
    let mut events = OPEN_AND_STUDY.to_vec();
    events.extend(answer_cards(&vec![true; cards.len()]));
    let r = run(&events, &[], storage);
    for (i, (front, lines, style, scale)) in fronts.iter().enumerate() {
        assert!(
            side(&r.frames[2 + 2 * i], false, lines, *style, *scale),
            "{front:?}\n{:?}",
            r.frames[2 + 2 * i]
        );
    }
}

#[test]
fn a_long_side_scrolls_with_the_jog_dial_as_far_as_its_last_line() {
    use Event::*;
    let words = "the quick brown fox jumps over the lazy dog ".repeat(11);
    let back = words.trim_end();
    assert!(back.chars().count() <= 500);
    let storage = with_decks(&[deck("Long", &[("long", back)])]);
    let mut events = OPEN_AND_STUDY.to_vec();
    events.extend([Centre, Down, Down, Up]);
    events.extend([Down; 40]);
    let r = run(&events, &[], storage);
    let f = &r.frames;
    // in maki's small font, six lines at a time, a bar at the right saying where
    let bar = |c: &Canvas| -> (i32, i32) {
        let lit: Vec<i32> = (16..96).filter(|&y| c.get(WIDTH as i32 - 1, y)).collect();
        (lit[0], *lit.last().unwrap())
    };
    let text = |c: &Canvas, from: i32, rows: i32| -> Vec<bool> {
        (from..from + rows)
            .flat_map(|y| (0..WIDTH as i32 - 4).map(move |x| (x, y)))
            .map(|(x, y)| c.get(x, y))
            .collect()
    };
    assert_eq!(bar(&f[3]).0, 16);
    // a line down: what was the second line is the first
    assert_eq!(text(&f[4], 16, 5 * 12), text(&f[3], 28, 5 * 12));
    assert!(bar(&f[4]).0 > 16);
    assert_eq!(text(&f[5], 16, 4 * 12), text(&f[3], 40, 4 * 12));
    assert_eq!(f[6], f[4], "and back up");
    // as far as its last line, and no further
    let last = f.len() - 1;
    assert_eq!(f[last], f[last - 1]);
    assert_eq!(bar(&f[last]).1, 95);
    // its first lines, then its last, each centred in the room the bar leaves
    let lines = wrapped(back, Style::Small, 1, WIDTH as i32 - 8);
    assert_eq!(lines.len(), 22);
    let at = |c: &Canvas, first: usize| {
        lines[first..first + 6].iter().enumerate().all(|(i, l)| {
            let x = 2 + (WIDTH as i32 - 8 - Canvas::text_width(l, Style::Small)) / 2;
            shows(c, x, 16 + 12 * i as i32, l, Style::Small)
        })
    };
    assert!(at(&f[3], 0) && at(&f[4], 1) && at(&f[last], 16));
}

#[test]
fn a_deck_studied_that_is_replaced_or_removed_from_the_computer_is_left() {
    use Event::*;
    let storage = with_decks(&[spanish(), deck("Numbers", &[("one", "1")])]);
    // replaced while it's studied: its page, saying why
    let mut events = OPEN_AND_STUDY.to_vec();
    events.extend([Message, Centre]);
    let r = run(&events, &upload(1, &deck("Spanish", &[("hola", "hello")])), storage.clone());
    assert!(footer(&r.frames[3], "the deck was just replaced"));
    assert!(centred(&r.frames[3], 0, "Spanish", Style::Bold));
    assert!(front_head(&r.frames[4], "new", 1));
    // a new version in pieces: the sitting ends as it starts to come, its memory wanted for the new
    // one, and the page says how it went
    let two = upload(1, &deck("Spanish", &cards(300, |i| (format!("word {i}"), format!("meaning {i}")))));
    assert_eq!(two.len(), 2);
    let r = run(&[Centre, Centre, Message, Message], &two, storage.clone());
    assert!(
        centred(&r.frames[3], 0, "Spanish", Style::Bold) && footer(&r.frames[3], "a new version is coming")
    );
    assert!(footer(&r.frames[4], "the deck was just replaced"));
    assert_eq!(r.replies[1], kept(1, 300, 0));
    let mut wrong = two[1].clone();
    wrong[7] = 0;
    let r = run(&[Centre, Centre, Message, Message, Centre], &[two[0].clone(), wrong], storage.clone());
    assert!(footer(&r.frames[4], "no new version came"));
    assert!(front_head(&r.frames[5], "new", 3), "the old one, studied again");
    let r = run(
        &[Centre, Centre, Message, Message],
        &[two[0].clone(), upload(0, &deck("French", &[("oui", "yes")]))[0].clone()],
        storage.clone(),
    );
    assert!(footer(&r.frames[4], "no new version came"));
    assert_eq!(r.replies[1], kept(3, 1, 0));
    // another deck removed: it goes on
    let r = run(&[Centre, Centre, Message, Centre], &[delete(2)], storage.clone());
    assert!(front_head(&r.frames[3], "new", 3) && back_head(&r.frames[4], "hola"));
    // the one studied, removed: back to the list, saying why
    let r = run(&[Centre, Centre, Message], &[delete(1)], storage.clone());
    assert!(row(&r.frames[3], 0, "Numbers", "1", true) && footer(&r.frames[3], "that deck was removed"));
    // a deck added while one's studied: it goes on, the same deck selected after
    let r = run(
        &[Down, Centre, Centre, Message, Menu(0), Left],
        &upload(0, &deck("French", &[("oui", "yes")])),
        storage,
    );
    assert!(front_head(&r.frames[4], "new", 1));
    assert!(row(&r.frames[6], 1, "Numbers", "1", true) && row(&r.frames[6], 2, "French", "1", false));
}

#[test]
fn what_it_keeps_is_read_back_strictly_and_what_s_left_over_is_tidied() {
    use Event::*;
    let storage = with_decks(&[spanish()]);
    // pieces and progress no listed deck names, from a deck half kept or half removed, go; others
    // stay
    let mut left_over = storage.clone();
    for key in ["c9a.0", "p9b", "c1b.0", "p1b", "c1a.1"] {
        left_over.insert(key.into(), vec![1, 2, 3]);
    }
    left_over.insert("other".into(), vec![1]);
    let r = run(&[], &[], left_over);
    let mut want: Vec<&str> = storage.keys().map(String::as_str).collect();
    want.push("other");
    want.sort();
    assert_eq!(r.storage.keys().collect::<Vec<_>>(), want);
    // a list it can't read: no decks, and nothing tidied away
    for list in [
        vec![2, 1, 0, 1, b'S', 1, 0, 1],
        vec![1, 1, 0, 1, b'S', 1, 0],
        vec![1, 1, 2, 1, b'S', 1, 0, 1],
        vec![1, 0, 0, 1, b'S', 1, 0, 1],
    ] {
        let mut s = storage.clone();
        s.insert("decks".into(), list.clone());
        let r = run(&[Message], &[vec![V, b'L']], s.clone());
        assert!(listing(&r.replies[0]).decks.is_empty(), "{list:?}");
        assert_eq!(r.storage, s);
    }
    // a deck whose cards are missing: listed, and it says so when it's studied
    let mut s = storage.clone();
    s.remove("c1a.0");
    let r = run(&OPEN_AND_STUDY, &[], s);
    assert!(footer(&r.frames[2], "it's damaged: send it again"));
    // progress for another number of cards, or in a box there isn't: new
    for p in [progress(DAY, 1, &[(2, DAY); 2]), progress(DAY, 1, &[(9, DAY), (2, DAY), (2, DAY)])] {
        let mut s = storage.clone();
        s.insert("p1a".into(), p);
        let r = run(&[Message], &[list()], s);
        let d = &listing(&r.replies[0]).decks[0];
        assert!(d.new >= 1, "{d:?}");
    }
    // what it keeps besides decks, unreadable: as at first
    let mut s = storage.clone();
    s.insert("state".into(), vec![1, 2, 3]);
    let r = run(&[Message], &[list()], s);
    assert_eq!(listing(&r.replies[0]).new_a_day, 20);
    assert_eq!(r.storage["state"], [1, 0x20, 0x4e, 0, 0, 0, 0, 20, 0, 1]);
}

#[test]
fn a_deck_is_read_back_as_it_was_sent_with_each_card_s_box_and_when_it_s_due() {
    let five = deck("Five", &[("one", "1"), ("two", "2"), ("three", "3"), ("four", "4"), ("five", "5")]);
    let mut storage = with_decks(&[spanish(), five.clone()]);
    // box 2 seen yesterday; new; box 5 seen twenty days ago; box 3 seen after today (maki's clock was
    // wrong then); box 7 seen today
    storage.insert(
        "p2a".into(),
        progress(DAY - 1, 3, &[(2, DAY - 1), (0, 0), (5, DAY - 20), (3, DAY + 5), (7, DAY)]),
    );
    let r = run(&[Event::Message, Event::Message], &[read(2, 0), read(1, 0)], storage.clone());
    // the deck as it was sent, then each card's box and the day it's next due: box n waits 2^(n-1)
    // days from when it was seen; one seen after today is due today; a new one has neither
    let mut want = five.clone();
    want.extend(due(&[(2, DAY + 1), (0, 0), (5, DAY - 4), (3, DAY), (7, DAY + 64)]));
    assert_eq!(piece(&r.replies[0]), (want.len(), &want[..]));
    let mut want = spanish();
    want.extend(due(&[(0, 0); 3]));
    assert_eq!(piece(&r.replies[1]), (want.len(), &want[..]));
    // reading changes nothing
    assert_eq!(r.storage, storage);

    // a thousand cards, in values of 16 KiB: a piece at a time, each where the last ended, all of
    // them 4091 bytes but the last; a deck's own pieces as they come off maki, its progress after
    let many =
        cards(1000, |i| (format!("word {i:04}"), format!("the meaning of word {i:04}, at some length")));
    let d = deck("Many", &many);
    let mut storage = with_decks(std::slice::from_ref(&d));
    let seen: Vec<(u8, u16)> = (0..1000).map(|i| ((i % 8) as u8, if i % 8 == 0 { 0 } else { DAY })).collect();
    storage.insert("p1a".into(), progress(DAY, 0, &seen));
    let inbox = reads(1, d.len(), 1000);
    assert_eq!(inbox.len(), 14);
    let r = run(&vec![Event::Message; inbox.len()], &inbox, storage.clone());
    let mut got: Vec<u8> = Vec::new();
    for (i, a) in r.replies.iter().enumerate() {
        let (total, bytes) = piece(a);
        assert_eq!(total, d.len() + 3000);
        assert_eq!(bytes.len(), if i < 13 { 4091 } else { total - 13 * 4091 }, "piece {i}");
        got.extend(bytes);
    }
    let mut want = d.clone();
    let wait = |b: u8| if b == 0 { 0 } else { DAY + (1 << (b - 1)) };
    want.extend(due(&seen.iter().map(|&(b, _)| (b, wait(b))).collect::<Vec<_>>()));
    assert_eq!(got, want);
    assert_eq!(r.storage, storage);
    // and from the start again, part of the way through
    let again = [&inbox[..5], &inbox[..]].concat();
    let r = run(&vec![Event::Message; again.len()], &again, storage);
    assert_eq!(r.replies[..5], r.replies[5..10]);
    let got: Vec<u8> = r.replies[5..].iter().flat_map(|a| piece(a).1.to_vec()).collect();
    assert_eq!(got, want);
}

#[test]
fn a_read_is_where_the_last_ended_and_of_a_deck_as_it_was() {
    use Event::*;
    let three = cards(300, |i| (format!("word {i}"), format!("meaning {i}")));
    let d = deck("Three hundred", &three);
    let storage = with_decks(&[spanish(), d.clone()]);
    let whole = reads(2, d.len(), 300);
    assert_eq!(whole.len(), 2);
    let order = refused(4, "a read out of order");
    let inbox = vec![
        whole[1].clone(), // no read under way
        whole[0].clone(),
        read(2, 100),     // not where the last ended
        whole[1].clone(), // and so the read is over
        whole[0].clone(),
        read(1, 4091),    // another deck's
        whole[1].clone(), // over too
        whole[0].clone(),
        list(),           // something else between reads leaves it be
        whole[1].clone(), // the rest
        whole[1].clone(), // all of it read, the read is over
        read(2, d.len() + 900),
        read(9, 0),
        read(0, 0),
        whole[0].clone(),
        read(9, 4091), // a read refused ends the one under way
        whole[1].clone(),
    ];
    let r = run(&vec![Message; inbox.len()], &inbox, storage.clone());
    let first = &r.replies[1];
    assert_eq!(piece(first).1.len(), 4091);
    let rest = &r.replies[9];
    assert_eq!(piece(rest).1.len(), d.len() + 900 - 4091);
    let want = [
        order.clone(),
        first.clone(),
        order.clone(),
        order.clone(),
        first.clone(),
        order.clone(),
        order.clone(),
        first.clone(),
        r.replies[8].clone(),
        rest.clone(),
        order.clone(),
        order.clone(),
        vec![7],
        vec![7],
        first.clone(),
        vec![7],
        order.clone(),
    ];
    assert_eq!(r.replies, want);
    assert_eq!(listing(&r.replies[8]).decks.len(), 2);
    assert_eq!(r.storage, storage);
    // what isn't a read: no deck, no place, too short or too long a place
    let cases = [vec![V, b'R'], vec![V, b'R', 2], vec![V, b'R', 2, 0, 0, 0], vec![V, b'R', 2, 0, 0, 0, 0, 0]];
    let r = run(&[Message; 4], &cases, storage.clone());
    assert_eq!(r.replies, vec![refused(4, "not a message this app takes"); 4]);

    // the deck kept anew while it's read: the next read is refused, and one from the start reads
    // the new one
    let new = deck("Three hundred", &three[..299]);
    let mut inbox = vec![whole[0].clone()];
    inbox.extend(upload(2, &new));
    inbox.push(whole[1].clone());
    inbox.extend(reads(2, new.len(), 299));
    let r = run(&vec![Message; inbox.len()], &inbox, storage.clone());
    assert_eq!(r.replies[1..4], [more(4085), kept(2, 299, 0), order.clone()]);
    let got: Vec<u8> = r.replies[4..].iter().flat_map(|a| piece(a).1.to_vec()).collect();
    assert_eq!(got, [new.clone(), due(&[(0, 0); 299])].concat());
    // removed from the computer, or from maki's menu: it's gone
    let r = run(&[Message; 3], &[whole[0].clone(), delete(2), whole[1].clone()], storage.clone());
    assert_eq!(r.replies[1..], [vec![0], vec![7]]);
    let r = run(
        &[Message, Right, Centre, Menu(0), Centre, Message],
        &[whole[0].clone(), whole[1].clone()],
        storage.clone(),
    );
    assert!(footer(&r.frames[5], "deleted Three hundred"));
    assert_eq!(r.replies[1], vec![7]);
    // another deck kept, or removed, while it's read: the read goes on
    let mut inbox = vec![whole[0].clone()];
    inbox.extend(upload(0, &deck("French", &[("oui", "yes")])));
    inbox.extend([delete(1), whole[1].clone()]);
    let r = run(&[Message; 4], &inbox, storage.clone());
    assert_eq!(r.replies[1..3], [kept(3, 1, 0), vec![0]]);
    assert_eq!(r.replies[3], rest.clone());
    // studied on maki while it's read: the read has the progress it began with
    let r = run(&[Message, Right, Centre, Centre, Centre, Right, Message], &whole, storage.clone());
    assert_eq!(r.storage["p2a"][5..8], [2, 0x20, 0x4e], "the first card known, in box 2");
    assert_eq!(r.replies, [first.clone(), rest.clone()]);
    assert!(piece(rest).1.ends_with(&due(&[(0, 0); 300])));
    let r = run(&[Message; 2], &whole, r.storage);
    let mut progress = due(&[(2, DAY + 2)]);
    progress.extend(due(&[(0, 0); 299]));
    assert!(piece(&r.replies[1]).1.ends_with(&progress));
}

#[test]
fn a_deck_that_does_not_read_whole_is_not_read() {
    let storage = with_decks(&[spanish()]);
    let spanish_cards = records(&[("hola", "hello"), ("gracias", "thank you"), ("el perro", "the dog")]);
    let mut damaged = Vec::new();
    // its cards missing; a value of them cut short, so not whole cards; fewer cards than the list says
    let mut s = storage.clone();
    s.remove("c1a.0");
    damaged.push(s);
    let mut s = storage.clone();
    s.insert("c1a.0".into(), spanish_cards[..spanish_cards.len() - 1].to_vec());
    damaged.push(s);
    let mut s = storage.clone();
    s.insert("c1a.0".into(), records(&[("hola", "hello"), ("gracias", "thank you")]));
    damaged.push(s);
    let mut s = storage.clone();
    s.insert("c1a.0".into(), records(&[("hola", "hello"), ("", "thank you"), ("el perro", "the dog")]));
    damaged.push(s);
    for (i, s) in damaged.into_iter().enumerate() {
        let r = run(&[Event::Message, Event::Message], &[read(1, 0), list()], s.clone());
        assert_eq!(r.replies[0], [10], "case {i}");
        // still listed, and nothing changed
        assert_eq!(listing(&r.replies[1]).decks.len(), 1);
        assert_eq!(r.storage, s);
    }
}

#[test]
fn the_biggest_deck_studied_read_and_replaced_at_once_fits_the_app_s_memory() {
    use Event::*;
    // the biggest deck there's room for, studied, read part of the way (a value of its cards held
    // for the next piece), then replaced: within the memory the manifest asks for
    let big = cards(1000, |i| (format!("w{i:04}"), format!("{i:04} {}", "x".repeat(45))));
    let mut storage = with_decks(&[deck("Big", &big)]);
    storage.insert("p1a".into(), progress(DAY, 0, &[(1, DAY - 1); 1000]));
    let mut changed = big.clone();
    changed[500].1 = format!("0500 {}", "y".repeat(45));
    let pieces = upload(1, &deck("Big", &changed));
    let mut events = OPEN_AND_STUDY.to_vec();
    events.extend(answer_cards(&[true, true]));
    events.extend(vec![Message; 2 + pieces.len()]);
    let mut inbox = vec![read(1, 0), read(1, 4091)];
    inbox.extend(pieces);
    let r = run(&events, &inbox, storage);
    assert_eq!(piece(&r.replies[1]).1.len(), 4091);
    assert_eq!(r.replies.last().unwrap(), &kept(1, 1000, 1000));
    assert!(used(&r.storage) <= ROOM);
}
