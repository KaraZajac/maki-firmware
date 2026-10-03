//! The Macro Pad example (sdk/examples/macropad), as `maki build` packed it and maki runs it:
//! scripts from maki desktop kept, replaced and removed once the owner says yes on maki's own
//! screens, listed and read back over the link; the first version's messages and storage still
//! taken; DuckyScript and text typed out of maki's keyboard; and every message, and everything read
//! back from storage, that isn't what the app takes, refused. Rebuild the fixture after changing
//! the app: `maki build examples/macropad --key ~/.keys/maki/developer.key` in sdk/, then copy
//! `sdk/target/maki/com.leviathan.maki.macropad.maki` to `tests/fixtures/macropad.maki`.

mod harness;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;

use harness::*;
use maki_wasm::*;

/// The version of the app's messages.
const V: u8 = 2;
/// maki's clock: Monday 21 September 2026, and a day later.
const NOW: u64 = 1_790_000_000;
const LATER: u64 = NOW + 86_400;
/// The pad's room, and a script's most bytes.
const ROOM: u32 = 16 * 1024;
const MAX_BODY: usize = 3900;

const ENTER: u8 = 0x28;
const OPEN_TERMINAL: &str = "GUI r\nDELAY 300\nSTRING cmd\nENTER";

type Storage = BTreeMap<String, Vec<u8>>;

/// The tests' maki, with a clock (None: maki doesn't know the time), whose storage may refuse
/// every write.
struct Timed {
    script: Script,
    now: Option<u64>,
    broken: bool,
}

impl Platform for Timed {
    fn wait(&mut self, timeout: Option<Duration>) -> Event { self.script.wait(timeout) }

    fn present(&mut self, canvas: &Canvas) { self.script.present(canvas) }

    fn set_menu(&mut self, items: &[String]) { self.script.set_menu(items) }

    fn millis(&self) -> u64 { self.script.millis() }

    fn unix_time(&self) -> Option<(u64, bool)> { self.now.map(|t| (t, true)) }

    fn random(&mut self, buf: &mut [u8]) { self.script.random(buf) }

    fn log(&mut self, line: &str) { self.script.log(line) }

    fn storage_get(&mut self, key: &str) -> Option<Vec<u8>> { self.script.storage_get(key) }

    fn storage_set(&mut self, key: &str, value: &[u8]) -> Result<(), ()> {
        if self.broken {
            return Err(());
        }
        self.script.storage_set(key, value)
    }

    fn storage_delete(&mut self, key: &str) -> bool { self.script.storage_delete(key) }

    fn storage_keys(&mut self) -> Vec<String> { self.script.storage_keys() }

    fn ask(&mut self, ask: &Ask) -> Answer { self.script.ask(ask) }

    fn review(&mut self, review: &Review) -> Answer { self.script.review(review) }

    fn type_text(&mut self, text: &str) -> bool { self.script.type_text(text) }

    fn press_key(&mut self, code: u8, mods: u8) -> bool { self.script.press_key(code, mods) }

    fn message(&mut self) -> Option<Vec<u8>> { self.script.message() }

    fn reply(&mut self, reply: &[u8]) -> bool { self.script.reply(reply) }
}

/// The app run as maki runs it (its manifest's memory, storage and permissions), maki's clock at
/// `now`, on `events` (a `Message` delivering the next of `inbox`), the owner answering `answers`.
fn run_at(
    now: Option<u64>,
    events: &[Event],
    inbox: &[Vec<u8>],
    answers: &[Answer],
    storage: Storage,
    broken: bool,
) -> Record {
    let bytes =
        std::fs::read(format!("{}/tests/fixtures/macropad.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let record = Rc::new(RefCell::new(Record {
        events: events.iter().copied().collect(),
        inbox: inbox.iter().cloned().collect(),
        answers: answers.iter().copied().collect(),
        storage,
        ..Default::default()
    }));
    let mut loaded = load_installed(&bundle.manifest, bundle.code).unwrap();
    loaded.limits = limits;
    let stop = loaded.run(Box::new(Timed { script: Script(record.clone()), now, broken }));
    assert_eq!(stop, Stop::Finished);
    Rc::try_unwrap(record).ok().unwrap().into_inner()
}

/// The app sent `inbox`, a message at a time, at `NOW`.
fn talk(inbox: &[Vec<u8>], answers: &[Answer], storage: Storage) -> Record {
    let events: Vec<Event> = inbox.iter().map(|_| Event::Message).collect();
    run_at(Some(NOW), &events, inbox, answers, storage, false)
}

/// The same, on `events`.
fn press(events: &[Event], inbox: &[Vec<u8>], answers: &[Answer], storage: Storage) -> Record {
    run_at(Some(NOW), events, inbox, answers, storage, false)
}

fn list() -> Vec<u8> { vec![V, b'L'] }

fn get(id: u8) -> Vec<u8> { vec![V, b'G', id] }

fn remove(id: u8) -> Vec<u8> { vec![V, b'D', id] }

/// `P`: a script of `kind` (0 DuckyScript, 1 text), new (`id` 0) or in place of script `id`.
fn put(id: u8, kind: u8, name: &str, body: &str) -> Vec<u8> {
    let mut m = vec![V, b'P', id, kind, name.len() as u8];
    m.extend_from_slice(name.as_bytes());
    m.extend_from_slice(body.as_bytes());
    m
}

/// A script as `L` lists it.
#[derive(Debug, PartialEq)]
struct Listed {
    id: u8,
    kind: u8,
    added: u64,
    changed: u64,
    size: u16,
    name: String,
}

fn listed(id: u8, kind: u8, added: u64, changed: u64, name: &str, body: &str) -> Listed {
    Listed { id, kind, added, changed, size: body.len() as u16, name: name.into() }
}

/// `L`'s answer: how many, the most, the room used and the room, and the scripts.
fn read_list(a: &[u8]) -> (u8, u8, u32, u32, Vec<Listed>) {
    assert_eq!(&a[..2], [0, V], "{a:?}");
    let (count, most) = (a[2], a[3]);
    let used = u32::from_le_bytes(a[4..8].try_into().unwrap());
    let room = u32::from_le_bytes(a[8..12].try_into().unwrap());
    let mut scripts = Vec::new();
    let mut at = 12;
    while at < a.len() {
        let n = a[at + 20] as usize;
        scripts.push(Listed {
            id: a[at],
            kind: a[at + 1],
            added: u64::from_le_bytes(a[at + 2..at + 10].try_into().unwrap()),
            changed: u64::from_le_bytes(a[at + 10..at + 18].try_into().unwrap()),
            size: u16::from_le_bytes(a[at + 18..at + 20].try_into().unwrap()),
            name: String::from_utf8(a[at + 21..at + 21 + n].to_vec()).unwrap(),
        });
        at += 21 + n;
    }
    assert_eq!(scripts.len(), count as usize);
    (count, most, used, room, scripts)
}

/// The scripts, as the first version kept them: each a u16-length name and body.
fn first_version(scripts: &[(&str, &str)]) -> Storage {
    BTreeMap::from([("scripts".to_string(), scripts_bytes(scripts))])
}

fn scripts_bytes(scripts: &[(&str, &str)]) -> Vec<u8> {
    let mut b = Vec::new();
    for (name, body) in scripts {
        for part in [name.as_bytes(), body.as_bytes()] {
            b.extend_from_slice(&(part.len() as u16).to_le_bytes());
            b.extend_from_slice(part);
        }
    }
    b
}

/// `about` as the app keeps it: its format (1), the next ID, how many, then each script's ID,
/// kind, times and name.
fn about(next: u8, scripts: &[(u8, u8, u64, u64, &str)]) -> Vec<u8> {
    let mut b = vec![1, next, scripts.len() as u8];
    for (id, kind, added, changed, name) in scripts {
        b.extend_from_slice(&[*id, *kind]);
        b.extend_from_slice(&added.to_le_bytes());
        b.extend_from_slice(&changed.to_le_bytes());
        b.push(name.len() as u8);
        b.extend_from_slice(name.as_bytes());
    }
    b
}

/// Storage with these scripts sent from maki desktop, the owner saying yes to each.
fn with_scripts(scripts: &[(u8, &str, &str)]) -> Storage {
    let inbox: Vec<Vec<u8>> = scripts.iter().map(|(kind, name, body)| put(0, *kind, name, body)).collect();
    let yes: Vec<Answer> = scripts.iter().map(|_| Answer::Yes).collect();
    let r = talk(&inbox, &yes, BTreeMap::new());
    assert!(r.replies.iter().all(|a| a[0] == 0), "{:?}", r.replies);
    r.storage
}

fn said(a: &[u8]) -> String { String::from_utf8(a.to_vec()).unwrap() }

#[test]
fn it_is_version_2_and_asks_to_ask() {
    let bytes =
        std::fs::read(format!("{}/tests/fixtures/macropad.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let m = maki_bundle::read(&bytes).unwrap().manifest;
    assert_eq!(
        (m.id.as_str(), m.version, m.label.as_str(), m.api),
        ("com.leviathan.maki.macropad", 2, "1.1", 10)
    );
    let mut asks: Vec<maki_bundle::Permission> = m.permissions.iter().map(|(p, _)| *p).collect();
    asks.sort_by_key(|p| *p as u8);
    use maki_bundle::Permission::*;
    assert_eq!(asks, [Ask, Link, Keyboard]);
}

#[test]
fn maki_desktop_sends_a_script_and_maki_keeps_it_once_the_owner_says_yes() {
    let address = "1 Main St\n\tSpringfield\n";
    let r = talk(
        &[put(0, 0, "Open terminal", OPEN_TERMINAL), put(0, 1, "Address", address), list(), get(1), get(2)],
        &[Answer::Yes, Answer::Yes],
        BTreeMap::new(),
    );
    assert_eq!(r.menu, ["Delete this", "Clear all"]);
    // kept, as scripts 1 and 2
    assert_eq!(r.replies[0], [0, 1]);
    assert_eq!(r.replies[1], [0, 2]);
    // the owner read each on maki's review screen first: its kind, its name, every line of it
    let review = &r.reviews[0];
    assert_eq!(review.question, "Keep a script from the computer?");
    assert_eq!(review.detail, "\"Open terminal\": DuckyScript, 4 lines");
    assert_eq!((review.yes.as_str(), review.no.as_str()), ("keep", "no"));
    assert_eq!(review.pages.len(), 1);
    let page = &review.pages[0];
    assert_eq!((page.heading.as_str(), page.value.as_str()), ("DuckyScript", "Open terminal"));
    assert_eq!((page.mono.as_str(), page.prose.as_str()), (OPEN_TERMINAL, ""));
    assert_eq!(review.timeout_s, 120, "maki's review's own time to read it");
    // a text's tabs show as spaces in fixed-width type
    let text = &r.reviews[1];
    assert_eq!(text.detail, "\"Address\": text, 2 lines");
    assert_eq!(
        (text.pages[0].heading.as_str(), text.pages[0].mono.as_str()),
        ("Text", "1 Main St\n Springfield\n")
    );
    assert!(r.asks.is_empty());
    // listed, in the order they came, with when they came
    let (count, most, used, room, scripts) = read_list(&r.replies[2]);
    assert_eq!((count, most, room), (2, 12, ROOM));
    assert_eq!(used as usize, 4 + 13 + OPEN_TERMINAL.len() + 4 + 7 + address.len());
    assert_eq!(
        scripts,
        [listed(1, 0, NOW, 0, "Open terminal", OPEN_TERMINAL), listed(2, 1, NOW, 0, "Address", address)]
    );
    // and given back whole
    assert_eq!(r.replies[3], [&[0][..], OPEN_TERMINAL.as_bytes()].concat());
    assert_eq!(r.replies[4], [&[0][..], address.as_bytes()].concat());
    // kept as the first version kept them, and the rest beside them
    assert_eq!(
        r.storage["scripts"],
        scripts_bytes(&[("Open terminal", OPEN_TERMINAL), ("Address", address)])
    );
    assert_eq!(r.storage["about"], about(3, &[(1, 0, NOW, 0, "Open terminal"), (2, 1, NOW, 0, "Address")]));
    // nothing typed: only the owner runs a script, on maki
    assert!(r.typed.is_empty() && r.pressed.is_empty());
}

#[test]
fn the_owner_says_no_or_nothing_and_nothing_changes() {
    let r = talk(
        &[put(0, 0, "x", "STRING x"), put(0, 0, "x", "STRING x"), list()],
        &[Answer::No],
        BTreeMap::new(),
    );
    assert_eq!(r.replies[0], [1]);
    assert_eq!(r.replies[1], [2]);
    assert_eq!(read_list(&r.replies[2]).4, []);
    assert_eq!(r.reviews.len(), 2);
    assert!(r.storage.is_empty());
    // maki didn't know the time: a script kept then says so
    let r = run_at(
        None,
        &[Event::Message, Event::Message],
        &[put(0, 0, "x", "STRING x"), list()],
        &[Answer::Yes],
        BTreeMap::new(),
        false,
    );
    assert_eq!(read_list(&r.replies[1]).4, [listed(1, 0, 0, 0, "x", "STRING x")]);
}

#[test]
fn a_script_replaced_keeps_its_place_and_its_id_and_may_be_renamed() {
    let kept = with_scripts(&[(0, "Open terminal", OPEN_TERMINAL), (0, "Hi", "STRING hi")]);
    let newer = "GUI r\nDELAY 500\nSTRING powershell\nENTER\nSTRINGLN echo hi";
    let r = run_at(
        Some(LATER),
        &[Event::Message, Event::Message, Event::Message],
        &[put(1, 0, "Open terminal", newer), put(1, 1, "Run box", "hello"), list()],
        &[Answer::Yes, Answer::Yes],
        kept,
        false,
    );
    assert_eq!(r.replies[0], [0, 1]);
    assert_eq!(r.replies[1], [0, 1]);
    // what it replaces, then the new one, line by line
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Replace a script?", "replace", "no")
    );
    assert_eq!(review.detail, "\"Open terminal\": DuckyScript, 5 lines");
    let old = &review.pages[0];
    assert_eq!(
        (old.heading.as_str(), old.value.as_str(), old.mono.as_str()),
        ("Replacing", "Open terminal", "")
    );
    assert_eq!(old.prose, "In place of the one on maki now: DuckyScript, 4 lines.");
    assert_eq!((review.pages[1].value.as_str(), review.pages[1].mono.as_str()), ("Open terminal", newer));
    // renamed, and a text now: the review says so
    let renamed = &r.reviews[1];
    assert_eq!(renamed.detail, "\"Run box\": text, 1 line");
    assert_eq!(
        renamed.pages[0].prose,
        "In place of the one on maki now: DuckyScript, 5 lines. Its new name: Run box."
    );
    assert_eq!(renamed.pages[1].heading, "Text");
    // in its place, its ID and when it came kept, when it changed new
    let scripts = read_list(&r.replies[2]).4;
    assert_eq!(
        scripts,
        [listed(1, 1, NOW, LATER, "Run box", "hello"), listed(2, 0, NOW, 0, "Hi", "STRING hi")]
    );
    assert_eq!(r.storage["scripts"], scripts_bytes(&[("Run box", "hello"), ("Hi", "STRING hi")]));
}

#[test]
fn names_are_one_a_script_and_a_script_unchanged_isnt_asked_about() {
    let kept = with_scripts(&[(0, "A", "STRING a"), (0, "B", "STRING b")]);
    let r = talk(
        &[
            put(1, 0, "B", "STRING a"),
            put(0, 0, "A", "STRING new"),
            put(1, 0, "A", "STRING a"),
            put(9, 0, "Z", "STRING z"),
        ],
        &[],
        kept.clone(),
    );
    // another script has that name, whether it's new or replacing one
    assert_eq!(r.replies[0], [8]);
    assert_eq!(r.replies[1], [8]);
    // the same again: done, nothing asked
    assert_eq!(r.replies[2], [0, 1]);
    // no such script to replace
    assert_eq!(r.replies[3], [7]);
    assert!(r.reviews.is_empty() && r.asks.is_empty());
    assert_eq!(r.storage, kept);
}

#[test]
fn scripts_are_removed_once_the_owner_says_yes() {
    let kept = with_scripts(&[(0, "Open terminal", OPEN_TERMINAL), (1, "Hi", "hi")]);
    let r =
        talk(&[remove(1), remove(1), remove(2), remove(2), list()], &[Answer::Yes, Answer::No], kept.clone());
    assert_eq!(r.replies[0], [0]);
    // gone already
    assert_eq!(r.replies[1], [7]);
    // the owner said no; then nobody answered
    assert_eq!(r.replies[2], [1]);
    assert_eq!(r.replies[3], [2]);
    let ask = &r.asks[0];
    assert_eq!(
        (ask.question.as_str(), ask.detail.as_str()),
        ("Remove a script?", "\"Open terminal\": DuckyScript, 4 lines")
    );
    assert_eq!((ask.yes.as_str(), ask.no.as_str()), ("remove", "keep"));
    assert_eq!(r.asks[1].detail, "\"Hi\": text, 1 line");
    assert_eq!(read_list(&r.replies[4]).4, [listed(2, 1, NOW, 0, "Hi", "hi")]);
    // the last one gone: no scripts kept, and the next ID still known
    let r = talk(&[remove(2)], &[Answer::Yes], r.storage);
    assert_eq!(r.replies[0], [0]);
    assert!(!r.storage.contains_key("scripts"));
    assert_eq!(r.storage["about"], about(3, &[]));
}

#[test]
fn ids_go_round_and_one_removed_isnt_given_again_at_once() {
    let kept = with_scripts(&[(0, "A", "STRING a"), (0, "B", "STRING b")]);
    let r = talk(&[remove(1), put(0, 0, "C", "STRING c"), list()], &[Answer::Yes, Answer::Yes], kept);
    assert_eq!(r.replies[1], [0, 3]);
    let ids: Vec<u8> = read_list(&r.replies[2]).4.iter().map(|s| s.id).collect();
    assert_eq!(ids, [2, 3]);
    // from 255 back to 1, past those in use
    let mut storage = first_version(&[("A", "STRING a"), ("B", "STRING b")]);
    storage.insert("about".into(), about(255, &[(1, 0, 0, 0, "A"), (255, 0, 0, 0, "B")]));
    let r = talk(&[put(0, 0, "C", "STRING c"), list()], &[Answer::Yes], storage);
    assert_eq!(r.replies[0], [0, 2]);
    assert_eq!(r.storage["about"][1], 3, "the next after it");
}

#[test]
fn every_message_it_doesnt_take_is_refused_and_changes_nothing() {
    let kept = with_scripts(&[(0, "A", "STRING a")]);
    let bad = |why: &str| [&[4][..], why.as_bytes()].concat();
    let name_rule = bad("a name is 1 to 24 characters on one line, with no spaces at its ends");
    let mut not_utf8_name = put(0, 0, "ab", "STRING x");
    not_utf8_name[5] = 0xff;
    let mut not_utf8_body = put(0, 0, "ab", "STRING x");
    not_utf8_body[8] = 0xc3;
    let mut runs_past = put(0, 0, "ab", "");
    runs_past[4] = 3;
    let cases: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (vec![V], bad("not a message Macro Pad takes")),
        (vec![V, b'L', 0], bad("not a message Macro Pad takes")),
        (vec![V, b'G'], bad("not a message Macro Pad takes")),
        (vec![V, b'G', 1, 0], bad("not a message Macro Pad takes")),
        (vec![V, b'D'], bad("not a message Macro Pad takes")),
        (vec![V, b'D', 1, 0], bad("not a message Macro Pad takes")),
        (vec![V, b'X', 1], bad("not a message Macro Pad takes")),
        (vec![V, b'P', 0, 0], bad("not a message Macro Pad takes")),
        (put(0, 2, "B", "STRING b"), bad("a script is DuckyScript (0) or text (1)")),
        (runs_past, bad("its name runs past the end of the message")),
        (not_utf8_name, bad("it isn't UTF-8")),
        (not_utf8_body, bad("it isn't UTF-8")),
        (put(0, 0, "", "STRING b"), name_rule.clone()),
        (put(0, 0, " B", "STRING b"), name_rule.clone()),
        (put(0, 0, "B ", "STRING b"), name_rule.clone()),
        (put(0, 0, "B\tC", "STRING b"), name_rule.clone()),
        (put(0, 0, &"b".repeat(25), "STRING b"), name_rule.clone()),
        (put(0, 0, "B", &"b".repeat(MAX_BODY + 1)), bad("a script is 3900 bytes at most")),
        (
            put(0, 1, "B", "café"),
            bad("maki types a text's printable ASCII, line breaks and tabs, and nothing else"),
        ),
        (
            put(0, 1, "B", "a\r\nb"),
            bad("maki types a text's printable ASCII, line breaks and tabs, and nothing else"),
        ),
        (get(2), vec![7]),
        (get(0), vec![7]),
        (remove(0), vec![7]),
        // other versions' messages
        (vec![1, b'L'], vec![9, V]),
        (vec![3, b'L'], vec![9, V]),
        (vec![0], vec![9, V]),
        (vec![0x1f, b'A'], vec![9, V]),
        (vec![0x0b, b'A'], vec![9, V]),
    ];
    let inbox: Vec<Vec<u8>> = cases.iter().map(|(m, _)| m.clone()).collect();
    let r = talk(&inbox, &[Answer::Yes; 8], kept.clone());
    for ((m, want), got) in cases.iter().zip(&r.replies) {
        assert_eq!(got, want, "{m:?}: {}", String::from_utf8_lossy(got));
    }
    assert_eq!(r.replies.len(), cases.len());
    assert!(r.reviews.is_empty() && r.asks.is_empty(), "nobody asked");
    assert_eq!(r.storage, kept);
}

#[test]
fn the_longest_name_and_script_fit_and_so_do_the_answers() {
    // 24 characters of four bytes each, and 3900 bytes: the most a message holds is 4096
    let name = "\u{1F980}".repeat(24);
    let body = "x".repeat(MAX_BODY);
    let m = put(0, 0, &name, &body);
    assert_eq!(m.len(), 5 + 96 + MAX_BODY);
    let r = talk(&[m, get(1), list()], &[Answer::Yes], BTreeMap::new());
    assert_eq!(r.replies[0], [0, 1]);
    assert_eq!(r.replies[1].len(), 1 + MAX_BODY);
    assert_eq!(read_list(&r.replies[2]).4, [listed(1, 0, NOW, 0, &name, &body)]);
    // the review's line (128 bytes at most) and its page hold the whole name
    let detail = &r.reviews[0].detail;
    assert_eq!(*detail, format!("\"{name}\": DuckyScript, 1 line"));
    assert!(detail.len() <= 128);
    assert_eq!(r.reviews[0].pages[0].value, name);
}

#[test]
fn twelve_scripts_or_16_kib_and_no_more() {
    let names: Vec<String> = (0..12).map(|i| format!("s{i}")).collect();
    let scripts: Vec<(u8, &str, &str)> = names.iter().map(|n| (0, n.as_str(), "STRING x")).collect();
    let kept = with_scripts(&scripts);
    // a thirteenth: no room; one in place of another: room enough
    let r = talk(&[put(0, 0, "new", "STRING y"), put(3, 0, "s2", "STRING y")], &[Answer::Yes], kept);
    assert_eq!(r.replies[0], [&[5][..], b"maki keeps 12 scripts: remove one first"].concat());
    assert_eq!(r.replies[1], [0, 3]);
    assert_eq!(r.reviews.len(), 1);
    // 16 KiB in all: four of 3900 bytes take 15,620, and a fifth doesn't fit
    let big = "x".repeat(MAX_BODY);
    let kept = with_scripts(&[(0, "a", &big), (0, "b", &big), (0, "c", &big), (0, "d", &big)]);
    let r = talk(&[put(0, 0, "e", &big), put(0, 0, "e", &"x".repeat(700)), list()], &[Answer::Yes], kept);
    assert_eq!(said(&r.replies[0][1..]), "it takes 3905 bytes of the pad's room, and 764 are free");
    assert_eq!(r.replies[0][0], 5);
    assert_eq!(r.replies[1], [0, 5]);
    let (_, _, used, room, _) = read_list(&r.replies[2]);
    assert_eq!((used, room), (4 * 3905 + 705, ROOM));
}

#[test]
fn storage_that_fails_leaves_the_pad_as_it_was() {
    let kept = with_scripts(&[(0, "A", "STRING a")]);
    let r = run_at(
        Some(NOW),
        &[Event::Message, Event::Message, Event::Message, Event::Message],
        &[put(0, 0, "B", "STRING b"), put(1, 0, "A", "STRING z"), remove(1), list()],
        &[Answer::Yes, Answer::Yes, Answer::Yes],
        kept.clone(),
        true,
    );
    let failed = [&[5][..], b"maki couldn't save the pad"].concat();
    assert_eq!(r.replies[..3], [failed.clone(), failed.clone(), failed]);
    assert_eq!(read_list(&r.replies[3]).4, [listed(1, 0, NOW, 0, "A", "STRING a")]);
    assert_eq!(r.storage, kept);
}

#[test]
fn maki_desktop_0_1_5s_messages_still_work_and_maki_asks_about_them_too() {
    // the first version's: a name, then DuckyScript
    let r = talk(
        &[
            b"Login\nSTRING hi\nENTER".to_vec(),
            b"Login\nSTRING bye".to_vec(),
            b"Other\nSTRING x".to_vec(),
            b"Other\nSTRING x".to_vec(),
        ],
        &[Answer::Yes, Answer::Yes, Answer::No],
        BTreeMap::new(),
    );
    assert_eq!(said(&r.replies[0]), "ok 1");
    // the same name again replaces it, not adds
    assert_eq!(said(&r.replies[1]), "ok 1");
    assert_eq!(said(&r.replies[2]), "you said no on maki");
    assert_eq!(said(&r.replies[3]), "nobody answered on maki");
    assert_eq!(r.reviews[0].question, "Keep a script from the computer?");
    assert_eq!(r.reviews[1].question, "Replace a script?");
    // in time for maki desktop 0.1.5, which waits 90 seconds
    assert!(r.reviews.iter().all(|v| v.timeout_s == 60));
    assert_eq!(r.storage["scripts"], scripts_bytes(&[("Login", "STRING bye")]));
    // its names as it made them: one line, no spaces at its ends, 24 characters, "script" for none
    let r = talk(
        &[
            b" \x01My script \nSTRING x".to_vec(),
            b"\nSTRING y".to_vec(),
            format!("{}\nSTRING z", "n".repeat(30)).into_bytes(),
            list(),
        ],
        &[Answer::Yes; 3],
        BTreeMap::new(),
    );
    assert_eq!(r.replies[..3], [b"ok 1".to_vec(), b"ok 2".to_vec(), b"ok 3".to_vec()]);
    let names: Vec<String> = read_list(&r.replies[3]).4.into_iter().map(|s| s.name).collect();
    assert_eq!(names, ["My script", "script", &"n".repeat(24)]);
    // and its refusals, in words
    let many: Vec<String> = (0..12).map(|i| format!("s{i}")).collect();
    let scripts: Vec<(u8, &str, &str)> = many.iter().map(|n| (0, n.as_str(), "STRING x")).collect();
    let r = talk(
        &[
            b"new\nSTRING x".to_vec(),
            b"s3\nSTRING y".to_vec(),
            vec![b'a', b'\n', 0xff],
            vec![],
            format!("long\n{}", "x".repeat(MAX_BODY + 1)).into_bytes(),
        ],
        &[Answer::Yes],
        with_scripts(&scripts),
    );
    let words: Vec<String> = r.replies.iter().map(|a| said(a)).collect();
    assert_eq!(
        words,
        [
            "full",
            "ok 12",
            "not a script: it isn't UTF-8",
            "not a script: it's empty",
            "too long: a script is 3900 bytes at most"
        ]
    );
}

#[test]
fn the_first_versions_pad_is_read_as_it_was_kept() {
    let old = first_version(&[("Login", "STRING hi\nENTER"), ("Run", "GUI r")]);
    let r = talk(&[list(), get(2), put(0, 0, "New", "STRING new")], &[Answer::Yes], old);
    // DuckyScript, of a time maki doesn't know, by the order they're in
    assert_eq!(
        read_list(&r.replies[0]).4,
        [listed(1, 0, 0, 0, "Login", "STRING hi\nENTER"), listed(2, 0, 0, 0, "Run", "GUI r")]
    );
    assert_eq!(r.replies[1], [&[0][..], b"GUI r"].concat());
    assert_eq!(r.replies[2], [0, 3]);
    // still kept as the first version kept it, which reads it all
    assert_eq!(
        r.storage["scripts"],
        scripts_bytes(&[("Login", "STRING hi\nENTER"), ("Run", "GUI r"), ("New", "STRING new")])
    );
    assert_eq!(
        r.storage["about"],
        about(4, &[(1, 0, 0, 0, "Login"), (2, 0, 0, 0, "Run"), (3, 0, NOW, 0, "New")])
    );
}

#[test]
fn what_about_says_is_matched_to_each_script_by_name() {
    let mut storage = first_version(&[("A", "STRING a"), ("B", "STRING b"), ("C", "hi\n"), ("D", "café")]);
    // C and A as it knows them, D as a text (which it can't be), an entry with no script, and B unknown
    let said_about =
        about(10, &[(5, 1, 7, 8, "C"), (3, 0, 1, 2, "A"), (9, 0, 0, 0, "gone"), (6, 1, 0, 0, "D")]);
    storage.insert("about".into(), said_about);
    let r = talk(&[list()], &[], storage.clone());
    assert_eq!(
        read_list(&r.replies[0]).4,
        [
            listed(3, 0, 1, 2, "A", "STRING a"),
            listed(10, 0, 0, 0, "B", "STRING b"),
            listed(5, 1, 7, 8, "C", "hi\n"),
            listed(6, 0, 0, 0, "D", "café"),
        ]
    );
    // what it can't read of it, it does without
    storage.insert("about".into(), vec![7, 1, 1]);
    let r = talk(&[list()], &[], storage.clone());
    let ids: Vec<(u8, u8)> = read_list(&r.replies[0]).4.iter().map(|s| (s.id, s.kind)).collect();
    assert_eq!(ids, [(1, 0), (2, 0), (3, 0), (4, 0)]);
    let mut cut = about(10, &[(5, 1, 7, 8, "C"), (3, 0, 1, 2, "A")]);
    cut.truncate(cut.len() - 1);
    storage.insert("about".into(), cut);
    let r = talk(&[list()], &[], storage.clone());
    let ids: Vec<(u8, u8)> = read_list(&r.replies[0]).4.iter().map(|s| (s.id, s.kind)).collect();
    assert_eq!(ids, [(10, 0), (11, 0), (5, 1), (12, 0)], "C as it knew it; the rest given IDs from the next");
    // a script's text that a message couldn't carry back ends what it reads
    let mut storage = first_version(&[("A", "STRING a"), ("B", &"b".repeat(4096)), ("C", "STRING c")]);
    storage.remove("about");
    let r = talk(&[list()], &[], storage);
    assert_eq!(read_list(&r.replies[0]).4, [listed(1, 0, 0, 0, "A", "STRING a")]);
}

#[test]
fn it_types_text_presses_keys_and_chords() {
    use Event::*;
    // open the one script (Centre on the list), then run it (Centre on its page)
    let body = "REM a comment\nSTRING hello\nENTER\nGUI r\nCTRL ALT DELETE\nREPEAT 2";
    let r = press(&[Centre, Centre], &[], &[], first_version(&[("Demo", body)]));
    assert_eq!(r.typed, ["hello"]);
    // Enter (no mods); Gui+R; Ctrl+Alt+Delete, then REPEAT does that line twice more
    assert_eq!(
        r.pressed,
        [
            (ENTER, 0),
            (0x15, MOD_GUI),
            (0x4c, MOD_CTRL | MOD_ALT),
            (0x4c, MOD_CTRL | MOD_ALT),
            (0x4c, MOD_CTRL | MOD_ALT),
        ]
    );
}

#[test]
fn it_waits_for_delays_and_stringln_adds_enter() {
    use Event::*;
    // DELAY needs maki's clock: one Timeout lets the whole wait pass
    let r = Record {
        events: [Centre, Centre, Timeout].into(),
        clock: true,
        storage: first_version(&[("d", "DELAY 50\nSTRINGLN hey")]),
        ..Default::default()
    };
    let (stop, r) = run_record("macropad", r);
    assert_eq!(stop, Stop::Finished);
    assert_eq!(r.typed, ["hey"]);
    assert_eq!(r.pressed, [(ENTER, 0)], "STRINGLN pressed Enter");
    assert!(r.now >= 50, "it waited the DELAY: {} ms", r.now);
}

#[test]
fn it_skips_what_it_cannot_press_and_carries_on() {
    use Event::*;
    // a lone modifier and an unknown key maki can't press are skipped; Caps Lock and Print Screen
    // it can (through a chord, no modifiers); the STRING still types
    let body = "GUI\nNUMLOCK\nCAPSLOCK\nPRINTSCREEN\nSTRING ok";
    let r = press(&[Centre, Centre], &[], &[], first_version(&[("x", body)]));
    assert_eq!(r.typed, ["ok"]);
    assert_eq!(r.pressed, [(0x39, 0), (0x46, 0)], "Caps Lock and Print Screen");
}

#[test]
fn a_text_is_typed_as_it_is_a_piece_at_a_time() {
    use Event::*;
    // DuckyScript's words are only words in a text
    let note = "Dear Kara,\n\tGUI r is a shortcut.\nENTER\n";
    let r = press(&[Centre, Centre], &[], &[], with_scripts(&[(1, "Note", note)]));
    assert_eq!(r.typed, [note]);
    assert!(r.pressed.is_empty());
    // a long one, 1024 bytes at a time, the owner free to leave between them
    let long: String = (0..2500).map(|i| (b'a' + (i % 26) as u8) as char).collect();
    let kept = with_scripts(&[(1, "Long", &long)]);
    let r = press(&[Centre, Centre, Timeout, Timeout], &[], &[], kept.clone());
    assert_eq!(r.typed, [&long[..1024], &long[1024..2048], &long[2048..]]);
    let r = press(&[Centre, Centre, Exit], &[], &[], kept);
    assert_eq!(r.typed, [&long[..1024]]);
}

#[test]
fn a_scripts_page_on_maki_says_what_it_is() {
    use Event::*;
    let ducky = press(&[Centre], &[], &[], with_scripts(&[(0, "x", "hello")]));
    let text = press(&[Centre], &[], &[], with_scripts(&[(1, "x", "hello")]));
    // the list the same; the page says DuckyScript or text
    assert_eq!(ducky.frames[0], text.frames[0]);
    assert_ne!(ducky.frames[1], text.frames[1]);
}

#[test]
fn a_script_removed_while_its_open_goes_back_to_the_list() {
    use Event::*;
    let kept = with_scripts(&[(0, "A", "STRING a"), (0, "B", "STRING b")]);
    // B open; the computer removes it; the centre opens A, then runs it
    let r = press(&[Right, Centre, Message, Centre, Centre], &[remove(2)], &[Answer::Yes], kept.clone());
    assert_eq!(r.replies, [vec![0]]);
    assert_eq!(r.typed, ["a"]);
    // and one replaced while it's open shows as it is now, and runs so
    let r = press(&[Centre, Message, Centre], &[put(1, 0, "A", "STRING z")], &[Answer::Yes], kept);
    assert_eq!(r.replies, [vec![0, 1]]);
    assert_eq!(r.typed, ["z"]);
}

#[test]
fn the_pad_can_be_emptied_on_maki() {
    use Event::*;
    let kept = with_scripts(&[(0, "A", "STRING a"), (0, "B", "STRING b"), (0, "C", "STRING c")]);
    // Delete this takes the one selected
    let r = press(&[Right, Menu(0), Message], &[list()], &[], kept.clone());
    let names: Vec<String> = read_list(&r.replies[0]).4.into_iter().map(|s| s.name).collect();
    assert_eq!(names, ["A", "C"]);
    // Clear all empties the pad, and the next ID stays known
    let r = press(&[Menu(1)], &[], &[], kept);
    assert!(!r.storage.contains_key("scripts"));
    assert_eq!(r.storage["about"], about(4, &[]));
}
