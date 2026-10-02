//! Password Maker (sdk/examples/passwords), run as maki runs it: entries from maki desktop once the
//! owner says yes, and passwords typed and shown by maki itself, never handed to the app. The
//! passwords here are the BIP39 test phrase's, as an independent BIP-32 and BIP-85 (Python's
//! hashlib and base64, from the BIP's text) makes them.

mod harness;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use harness::*;
use maki_wasm::*;

/// `m/83696968'/707764'/21'/0'`, `/21'/3'` and `m/83696968'/707785'/30'/7'` from the test phrase.
const NUMBER_0: &str = "d3PQpHTKg65rkcsFXL7eU";
const NUMBER_3: &str = "Zrj5UE+TY3lp7uFCFJSeS";
const BASE85_30_7: &str = "+#7MT!H2dYF=)?BS2>6-&GU2pHxi`;";

const ENTER: u8 = 0x28;
const TAB: u8 = 0x2b;

/// An entry as the link carries it.
fn entry(id: u32, alphabet: u8, length: u8, number: u32, enter: bool, site: &str, user: &str) -> Vec<u8> {
    let mut b = id.to_le_bytes().to_vec();
    b.push(alphabet);
    b.push(length);
    b.extend_from_slice(&number.to_le_bytes());
    b.push(enter as u8);
    b.push(site.len() as u8);
    b.extend_from_slice(site.as_bytes());
    b.push(user.len() as u8);
    b.extend_from_slice(user.as_bytes());
    b
}

fn message(op: u8, body: &[u8]) -> Vec<u8> { [&[op][..], body].concat() }

fn list(first: u16) -> Vec<u8> { message(b'L', &first.to_le_bytes()) }

/// Runs it as maki does, with these events, messages (a `Message` event delivers the next), answers
/// and storage.
fn run(
    events: Vec<Event>,
    inbox: Vec<Vec<u8>>,
    answers: Vec<Answer>,
    storage: BTreeMap<String, Vec<u8>>,
    locked: bool,
) -> Record {
    let bytes =
        std::fs::read(format!("{}/tests/fixtures/passwords.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let record = Rc::new(RefCell::new(Record {
        events: events.into(),
        inbox: inbox.into(),
        answers: answers.into(),
        storage,
        locked,
        ..Default::default()
    }));
    let mut loaded = load_installed(&bundle.manifest, bundle.code).unwrap();
    loaded.limits = limits;
    assert_eq!(loaded.run(Box::new(Script(record.clone()))), Stop::Finished);
    Rc::try_unwrap(record).ok().unwrap().into_inner()
}

/// Storage with these entries added, as maki desktop adds them.
fn with_entries(entries: &[Vec<u8>]) -> BTreeMap<String, Vec<u8>> {
    let r = run(
        entries.iter().map(|_| Event::Message).collect(),
        entries.iter().map(|e| message(b'A', e)).collect(),
        entries.iter().map(|_| Answer::Yes).collect(),
        BTreeMap::new(),
        false,
    );
    assert!(r.replies.iter().all(|a| a[0] == 0), "{:?}", r.replies);
    r.storage
}

#[test]
fn it_asks_for_the_wallet_paths_of_bip85_passwords_alone_on_host_api_12() {
    let bytes =
        std::fs::read(format!("{}/tests/fixtures/passwords.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let m = &bundle.manifest;
    assert_eq!((m.id.as_str(), m.api), ("com.leviathan.maki.passwords", 12));
    let wallet = m.wallet.as_ref().unwrap();
    assert_eq!(wallet.curve, maki_bundle::Curve::Secp256k1);
    let paths: Vec<String> = wallet.paths.iter().map(|p| maki_hd::format_path(p)).collect();
    assert_eq!(paths, ["m/83696968'/707764'", "m/83696968'/707785'"]);
    assert_eq!(maki_hd::coin(&wallet.paths[0]), Some("passwords"));
}

#[test]
fn maki_desktop_adds_an_entry_once_the_owner_says_yes() {
    let github = entry(0, 0, 21, 0, true, "github.com", "kara");
    let r = run(
        vec![Event::Message, Event::Message, Event::Message, Event::Message],
        vec![message(b'A', &github), message(b'A', &github), message(b'A', &github), list(0)],
        vec![Answer::Yes, Answer::No],
        BTreeMap::new(),
        false,
    );
    // added, as number 1; no; no answer
    assert_eq!(r.replies[0], [0, 1, 0, 0, 0]);
    assert_eq!(r.replies[1], [1]);
    assert_eq!(r.replies[2], [2]);
    // the owner saw what it is first, and nothing a yes would let the app type
    let review = &r.reviews[0];
    assert_eq!((review.question.as_str(), review.detail.as_str()), ("Add a password?", "github.com"));
    assert_eq!(review.pages[0].heading, "github.com");
    assert_eq!(review.pages[0].value, "kara");
    assert_eq!(review.pages[0].prose, "21 characters, number 0, base64, then Enter");
    // the list: the version, one entry, with its id
    let mut want = vec![0, 1, 1, 0];
    want.extend_from_slice(&entry(1, 0, 21, 0, true, "github.com", "kara"));
    assert_eq!(r.replies[3], want);
    assert!(r.typed.is_empty());
}

#[test]
fn it_refuses_entries_maki_couldnt_make_show_or_type() {
    let bad = [
        entry(0, 2, 21, 0, true, "github.com", "kara"), // no such alphabet
        entry(0, 0, 19, 0, true, "github.com", "kara"), // base64 too short
        entry(0, 0, 87, 0, true, "github.com", "kara"), // too long
        entry(0, 1, 9, 0, true, "github.com", "kara"),  // base85 too short
        entry(0, 1, 81, 0, true, "github.com", "kara"), // too long
        entry(0, 0, 21, 1 << 31, true, "github.com", "kara"), // not a hardened step's number
        entry(0, 0, 21, 0, true, "", "kara"),           // no site
        entry(0, 0, 21, 0, true, "   ", "kara"),        // nor blank
        entry(0, 0, 21, 0, true, "git\nhub", "kara"),   // two lines
        entry(0, 0, 21, 0, true, &"x".repeat(33), "kara"), // longer than a page's heading
        entry(0, 0, 21, 0, true, "github.com", "kära"), // a username maki can't type
        entry(0, 0, 21, 0, true, "github.com", "ka\tra"),
        entry(0, 0, 21, 0, true, "github.com", &"k".repeat(65)),
        entry(7, 0, 21, 0, true, "github.com", "kara"), // an id is maki's to give
    ];
    let mut inbox: Vec<Vec<u8>> = bad.iter().map(|e| message(b'A', e)).collect();
    let mut enter_2 = entry(0, 0, 21, 0, true, "github.com", "kara");
    enter_2[10] = 2;
    inbox.push(message(b'A', &enter_2));
    // cut short, or more after it
    let good = entry(0, 0, 21, 0, true, "github.com", "kara");
    inbox.push(message(b'A', &good[..good.len() - 1]));
    inbox.push(message(b'A', &[&good[..], &[0][..]].concat()));
    inbox.extend([vec![], vec![b'L'], message(b'L', &[0, 0, 0]), message(b'D', &[1, 0, 0]), vec![b'X']]);
    let n = inbox.len();
    let r = run(vec![Event::Message; n], inbox, vec![Answer::Yes; n], BTreeMap::new(), false);
    for (i, reply) in r.replies.iter().enumerate() {
        assert_eq!(reply, &[4], "{i}");
    }
    assert!(r.reviews.is_empty(), "nothing asked about");
    // and the longest that fit: 32 bytes of site, 64 of username, 86 and 80 characters
    let longest = [
        entry(0, 0, 86, (1 << 31) - 1, false, &"é".repeat(16), &"~".repeat(64)),
        entry(0, 1, 80, 0, true, "a", ""),
        entry(0, 0, 20, 0, true, "a", ""),
        entry(0, 1, 10, 0, true, "a", ""),
    ];
    let r = run(
        vec![Event::Message; 4],
        longest.iter().map(|e| message(b'A', e)).collect(),
        vec![Answer::Yes; 4],
        BTreeMap::new(),
        false,
    );
    assert_eq!(r.replies.iter().map(|a| a[0]).collect::<Vec<_>>(), [0; 4]);
}

#[test]
fn the_centre_has_maki_type_its_password_after_a_yes() {
    let storage = with_entries(&[entry(0, 0, 21, 0, true, "github.com", "kara")]);
    // opened, then typed: a yes, then maki types it and Enter after
    let r = run(vec![Event::Centre, Event::Centre], vec![], vec![Answer::Yes], storage.clone(), false);
    let review = &r.reviews[0];
    assert_eq!(review.question, "Type its password?");
    assert_eq!(review.detail, "github.com, where your cursor is");
    assert_eq!(r.typed, [NUMBER_0]);
    assert_eq!(r.pressed, [(ENTER, 0)]);
    // a no, or no answer: nothing typed
    for answer in [Answer::No, Answer::NoAnswer] {
        let r = run(vec![Event::Centre, Event::Centre], vec![], vec![answer], storage.clone(), false);
        assert!(r.typed.is_empty() && r.pressed.is_empty());
    }
    // locked: maki makes none
    let r = run(vec![Event::Centre, Event::Centre], vec![], vec![Answer::Yes], storage, true);
    assert!(r.typed.is_empty());
}

#[test]
fn logging_in_types_the_username_tab_then_the_password() {
    let storage = with_entries(&[
        entry(0, 0, 21, 0, true, "github.com", "kara"),
        entry(0, 1, 30, 7, false, "bank", "k.z@example.com"),
        entry(0, 0, 21, 3, true, "no username", ""),
    ]);
    // the first: Log in (menu 0)
    let r = run(vec![Event::Centre, Event::Menu(0)], vec![], vec![Answer::Yes], storage.clone(), false);
    assert_eq!(
        (r.reviews[0].question.as_str(), r.reviews[0].detail.as_str()),
        ("Log in?", "github.com, as kara")
    );
    assert_eq!(r.typed, ["kara", NUMBER_0]);
    assert_eq!(r.pressed, [(TAB, 0), (ENTER, 0)]);
    // the second, base85 without Enter, by the jog dial
    let r = run(
        vec![Event::Down, Event::Centre, Event::Menu(0)],
        vec![],
        vec![Answer::Yes],
        storage.clone(),
        false,
    );
    assert_eq!(r.typed, ["k.z@example.com", BASE85_30_7]);
    assert_eq!(r.pressed, [(TAB, 0)]);
    // the username alone (menu 1), no question asked: it isn't secret
    let r = run(vec![Event::Right, Event::Centre, Event::Menu(1)], vec![], vec![], storage.clone(), false);
    assert_eq!(r.typed, ["k.z@example.com"]);
    assert!(r.reviews.is_empty());
    // none to log in with: nothing asked, nothing typed
    let events = vec![Event::Down, Event::Down, Event::Centre, Event::Menu(0), Event::Menu(1)];
    let r = run(events, vec![], vec![Answer::Yes], storage, false);
    assert!(r.reviews.is_empty() && r.typed.is_empty());
}

#[test]
fn show_it_has_maki_show_the_password_never_the_app() {
    let storage = with_entries(&[entry(0, 0, 21, 0, true, "github.com", "kara")]);
    let r = run(vec![Event::Centre, Event::Menu(2)], vec![], vec![Answer::Yes], storage.clone(), false);
    assert_eq!(r.reviews[0].question, "Show its password?");
    assert_eq!(r.passwords, [("github.com".to_string(), NUMBER_0.to_string())]);
    assert!(r.typed.is_empty());
    let r = run(vec![Event::Centre, Event::Menu(2)], vec![], vec![Answer::No], storage, false);
    assert!(r.passwords.is_empty());
}

#[test]
fn by_number_as_a_coldcard_types_them() {
    // menu: By number, then 3, the centre and a yes: base64, 21 characters, then Enter
    let events =
        vec![Event::Menu(0), Event::Right, Event::Right, Event::Up, Event::Down, Event::Down, Event::Centre];
    let r = run(events, vec![], vec![Answer::Yes], BTreeMap::new(), false);
    assert_eq!(r.reviews[0].detail, "Number 3, where your cursor is");
    assert_eq!(r.typed, [NUMBER_3]);
    assert_eq!(r.pressed, [(ENTER, 0)]);
    // the number kept for next time, and shown from the menu
    assert_eq!(r.storage["number"], 3u32.to_le_bytes());
    let r = run(vec![Event::Menu(0), Event::Menu(0)], vec![], vec![Answer::Yes], r.storage, false);
    assert_eq!(r.passwords, [("Number 3".to_string(), NUMBER_3.to_string())]);
    // and never below 0
    let r = run(
        vec![Event::Menu(0), Event::Left, Event::Centre],
        vec![],
        vec![Answer::Yes],
        BTreeMap::new(),
        false,
    );
    assert_eq!(r.typed, [NUMBER_0]);
}

#[test]
fn changed_and_removed_once_the_owner_says_yes() {
    let storage = with_entries(&[
        entry(0, 0, 21, 0, true, "github.com", "kara"),
        entry(0, 0, 21, 3, true, "mail", "kara"),
    ]);
    let changed = entry(2, 1, 30, 7, false, "mail", "kz");
    let r = run(
        vec![Event::Message; 6],
        vec![
            message(b'R', &changed),
            message(b'R', &entry(9, 0, 21, 0, true, "nope", "")),
            message(b'D', &1u32.to_le_bytes()),
            message(b'D', &1u32.to_le_bytes()),
            message(b'D', &9u32.to_le_bytes()),
            list(0),
        ],
        vec![Answer::Yes, Answer::No, Answer::Yes],
        storage,
        false,
    );
    assert_eq!(r.replies[0], [0]);
    assert_eq!(r.replies[1], [4], "no such entry");
    assert_eq!(r.replies[2], [1], "the owner said no");
    assert_eq!(r.replies[3], [0]);
    assert_eq!(r.replies[4], [4]);
    assert_eq!(
        r.reviews.iter().map(|v| v.question.as_str()).collect::<Vec<_>>(),
        ["Change a password?", "Remove a password?", "Remove a password?"]
    );
    let mut want = vec![0, 1, 1, 0];
    want.extend_from_slice(&changed);
    assert_eq!(r.replies[5], want);
    // and so it types now: the changed entry's
    let r = run(vec![Event::Centre, Event::Centre], vec![], vec![Answer::Yes], r.storage, false);
    assert_eq!(r.typed, [BASE85_30_7]);
    assert!(r.pressed.is_empty());
}

#[test]
fn a_hundred_entries_kept_and_listed_a_page_at_a_time() {
    // the most it keeps, each as long as it can be
    let entries: Vec<Vec<u8>> =
        (0..100).map(|i| entry(0, 0, 86, i, true, &format!("{i:0>32}"), &"u".repeat(64))).collect();
    let storage = with_entries(&entries);
    let r = run(
        vec![Event::Message, Event::Message],
        vec![message(b'A', &entries[0]), list(0)],
        vec![Answer::Yes],
        storage.clone(),
        false,
    );
    assert_eq!(r.replies[0], [5], "no room for a hundred and first");
    assert!(r.reviews.is_empty());
    // a page at a time, each within a message's 4096 bytes
    let mut seen = Vec::new();
    let mut first = 0u16;
    while (first as usize) < 100 {
        let r = run(vec![Event::Message], vec![list(first)], vec![], storage.clone(), false);
        let a = &r.replies[0];
        assert!(a.len() <= 4096);
        assert_eq!(&a[..4], &[0, 1, 100, 0]);
        let n = (a.len() - 4) / entries[0].len();
        assert!(n > 0);
        for (i, e) in a[4..].chunks(entries[0].len()).enumerate() {
            let mut want = entries[first as usize + i].clone();
            want[..4].copy_from_slice(&(first as u32 + i as u32 + 1).to_le_bytes());
            assert_eq!(e, want);
        }
        seen.push(n);
        first += n as u16;
    }
    assert_eq!(seen.iter().sum::<usize>(), 100);
    // past the end: none
    let r = run(vec![Event::Message], vec![list(100)], vec![], storage.clone(), false);
    assert_eq!(r.replies[0], [0, 1, 100, 0]);
    // and the last one types its own password, kept across the restarts
    let mut events = vec![Event::Up; 1];
    events.extend(std::iter::repeat(Event::Down).take(99));
    events.extend([Event::Centre, Event::Centre]);
    let r = run(events, vec![], vec![Answer::Yes], storage, false);
    assert_eq!(r.reviews[0].detail, format!("{:0>32}, where your cursor is", 99));
    assert_eq!(r.typed[0].len(), 86);
}

#[test]
fn deleted_on_maki_once_the_centre_says_so() {
    let storage = with_entries(&[
        entry(0, 0, 21, 0, true, "github.com", "kara"),
        entry(0, 0, 21, 3, true, "mail", "kara"),
    ]);
    // open the first, Delete it (menu 3), left keeps it; again, the centre deletes it
    let events = vec![
        Event::Centre,
        Event::Menu(3),
        Event::Left,
        Event::Menu(3),
        Event::Centre,
        Event::Centre,
        Event::Centre,
    ];
    let r = run(events, vec![], vec![Answer::Yes], storage, false);
    // what's left is mail's, which the centre opened and typed
    assert_eq!(r.typed, [NUMBER_3]);
    let r = run(vec![Event::Message], vec![list(0)], vec![], r.storage, false);
    assert_eq!(&r.replies[0][..4], &[0, 1, 1, 0]);
}
