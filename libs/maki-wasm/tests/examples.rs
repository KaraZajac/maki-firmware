//! The SDK's example apps (sdk/examples), as `maki build` packed them: they read, maki takes
//! them, and they behave, run by the same host code maki runs them with. Rebuild the fixtures
//! after changing the examples or the SDK: `maki build sdk/examples/NAME`, then copy
//! `sdk/target/maki/com.leviathan.maki.NAME.maki` to `tests/fixtures/NAME.maki`.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use std::time::Duration;

use maki_wasm::*;

#[derive(Default)]
struct Record {
    events: VecDeque<Event>,
    frames: Vec<Canvas>,
    menu: Vec<String>,
    storage: BTreeMap<String, Vec<u8>>,
    answers: VecDeque<Answer>,
    asks: Vec<Ask>,
    typed: Vec<String>,
    inbox: VecDeque<Vec<u8>>,
    current: Option<Vec<u8>>,
    replies: Vec<Vec<u8>>,
    qr: Option<String>,
    motion: Option<[i16; 3]>,
    /// maki is locked: no wallet keys
    locked: bool,
    /// what wallet apps put on maki's review screen
    reviews: Vec<Review>,
    /// backup words maki showed its owner (never the app)
    backups: Vec<String>,
}

/// The BIP39 test phrase's seed: wallet apps' keys here, as on a maki set up with it.
fn test_seed() -> [u8; 64] {
    let words: Vec<&str> = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(' ').collect();
    maki_seed::seed(&words, "")
}

struct Script(Rc<RefCell<Record>>);

impl Platform for Script {
    fn wait(&mut self, _: Option<Duration>) -> Event {
        let mut r = self.0.borrow_mut();
        let event = r.events.pop_front().unwrap_or(Event::Exit);
        if event == Event::Message {
            r.current = r.inbox.pop_front();
        }
        event
    }
    fn present(&mut self, canvas: &Canvas) { self.0.borrow_mut().frames.push(canvas.clone()) }
    fn set_menu(&mut self, items: &[String]) { self.0.borrow_mut().menu = items.to_vec() }
    fn millis(&self) -> u64 { 0 }
    fn unix_time(&self) -> Option<(u64, bool)> { None }
    fn random(&mut self, buf: &mut [u8]) {
        // counting bytes: the dice come up 1 + (n % 6)
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
    }
    fn log(&mut self, _: &str) {}
    fn storage_get(&mut self, key: &str) -> Option<Vec<u8>> { self.0.borrow().storage.get(key).cloned() }
    fn storage_set(&mut self, key: &str, value: &[u8]) -> Result<(), ()> {
        self.0.borrow_mut().storage.insert(key.into(), value.into());
        Ok(())
    }
    fn storage_delete(&mut self, key: &str) -> bool { self.0.borrow_mut().storage.remove(key).is_some() }
    fn storage_keys(&mut self) -> Vec<String> { self.0.borrow().storage.keys().cloned().collect() }
    fn ask(&mut self, ask: &Ask) -> Answer {
        let mut r = self.0.borrow_mut();
        r.asks.push(ask.clone());
        r.answers.pop_front().unwrap_or(Answer::NoAnswer)
    }
    fn app_secret(&mut self, _: &str) -> Option<[u8; 32]> { Some([7; 32]) }
    fn type_text(&mut self, text: &str) -> bool {
        self.0.borrow_mut().typed.push(text.into());
        true
    }
    fn message(&mut self) -> Option<Vec<u8>> { self.0.borrow().current.clone() }
    fn scan_qr(&mut self) -> Option<String> { self.0.borrow_mut().qr.take() }
    fn motion(&mut self) -> Option<[i16; 3]> { self.0.borrow().motion }
    fn reply(&mut self, reply: &[u8]) -> bool {
        let mut r = self.0.borrow_mut();
        if r.current.take().is_none() {
            return false;
        }
        r.replies.push(reply.to_vec());
        true
    }
    fn wallet(&mut self, op: u8, path: &[u32], digest: &[u8]) -> Result<Vec<u8>, i32> {
        if self.0.borrow().locked {
            return Err(LOCKED);
        }
        let keys = maki_hd::seed::SeedKeys::from_seed(&test_seed()).unwrap();
        // no randomness in Schnorr signatures: the same as maki-btc's fixtures
        maki_hd::seed::answer(&keys, op, path, digest, &[0; 32]).map_err(|e| match e {
            maki_hd::Error::Path => REFUSED,
            _ => FAILED,
        })
    }
    fn review(&mut self, review: &Review) -> Answer {
        let mut r = self.0.borrow_mut();
        r.reviews.push(review.clone());
        r.answers.pop_front().unwrap_or(Answer::NoAnswer)
    }
    fn show_backup(&mut self, path: &[u32]) -> Result<Answer, i32> {
        let mut r = self.0.borrow_mut();
        if r.locked {
            return Err(LOCKED);
        }
        // the owner's say first, as maki asks it; then maki shows the words, here noted
        let answer = r.answers.pop_front().unwrap_or(Answer::NoAnswer);
        if answer == Answer::Yes {
            let keys = maki_hd::seed::SeedKeys::from_seed(&test_seed()).unwrap();
            let words = maki_hd::seed::answer(&keys, maki_hd::op::MONERO_WORDS, path, &[], &[0; 32]).map_err(|_| NOT_FOUND)?;
            r.backups.push(String::from_utf8(words).unwrap());
        }
        Ok(answer)
    }
}

fn run_fixture(name: &str, events: &[Event], storage: BTreeMap<String, Vec<u8>>) -> (Stop, Record) {
    run_answering(name, events, storage, &[])
}

fn run_answering(name: &str, events: &[Event], storage: BTreeMap<String, Vec<u8>>, answers: &[Answer]) -> (Stop, Record) {
    let bytes = std::fs::read(format!("{}/tests/fixtures/{name}.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let record = Rc::new(RefCell::new(Record {
        events: events.iter().copied().collect(),
        storage,
        answers: answers.iter().copied().collect(),
        ..Default::default()
    }));
    let stop = run(bundle.code, Box::new(Script(record.clone())), limits);
    (stop, Rc::try_unwrap(record).ok().unwrap().into_inner())
}

fn lit(c: &Canvas) -> usize { (0..HEIGHT as i32).flat_map(|y| (0..WIDTH as i32).map(move |x| (x, y))).filter(|&(x, y)| c.get(x, y)).count() }

#[test]
fn hello_says_hello_and_leaves_when_told() {
    let (stop, r) = run_fixture("hello", &[Event::Left, Event::Menu(0)], BTreeMap::new());
    assert_eq!(stop, Stop::Finished);
    // a frame to start, and one after each event before Exit
    assert_eq!(r.frames.len(), 3);
    assert!(lit(&r.frames[0]) > 100);
}

#[test]
fn dice_rolls_counts_and_resets() {
    let (stop, r) = run_fixture("dice", &[Event::Centre, Event::Centre, Event::Right], BTreeMap::new());
    assert_eq!(stop, Stop::Finished);
    assert_eq!(r.menu, ["Reset count"]);
    assert_eq!(r.storage["rolls"], 2u32.to_le_bytes());
    // the count carries over, and the menu's Reset clears it
    let (_, r) = run_fixture("dice", &[Event::Centre], r.storage);
    assert_eq!(r.storage["rolls"], 3u32.to_le_bytes());
    let (_, r) = run_fixture("dice", &[Event::Menu(0)], r.storage);
    assert!(!r.storage.contains_key("rolls"));
    // different dice draw differently
    let (_, a) = run_fixture("dice", &[Event::Right], BTreeMap::new());
    assert_ne!(a.frames[0], a.frames[1]);
}

#[test]
fn tally_counts_and_keeps_the_count() {
    let (stop, r) = run_fixture("tally", &[Event::Centre, Event::Centre, Event::Right, Event::Left], BTreeMap::new());
    assert_eq!(stop, Stop::Finished);
    assert_eq!(r.storage["count"], 11u32.to_le_bytes());
    let (_, r) = run_fixture("tally", &[Event::Left], r.storage);
    assert_eq!(r.storage["count"], 10u32.to_le_bytes());
    let (_, r) = run_fixture("tally", &[Event::Menu(0)], r.storage);
    assert_eq!(r.storage["count"], 0u32.to_le_bytes());
}

#[test]
fn a_loaded_app_runs_again_and_again() {
    let bytes = std::fs::read(format!("{}/tests/fixtures/tally.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let loaded = load(&bundle.manifest, bundle.code).unwrap();
    let mut storage = BTreeMap::new();
    for n in 1..=3u32 {
        let record = Rc::new(RefCell::new(Record { events: [Event::Centre].into(), storage, ..Default::default() }));
        assert_eq!(loaded.run(Box::new(Script(record.clone()))), Stop::Finished);
        storage = Rc::try_unwrap(record).ok().unwrap().into_inner().storage;
        assert_eq!(storage["count"], n.to_le_bytes());
    }
}

#[test]
fn signer_asks_before_it_signs_and_types_from_its_menu() {
    use maki_bundle::Permission;
    let bytes = std::fs::read(format!("{}/tests/fixtures/signer.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let m = maki_bundle::read(&bytes).unwrap().manifest;
    let asked: Vec<Permission> = m.permissions.iter().map(|(p, _)| *p).collect();
    assert_eq!(asked, [Permission::Ask, Permission::Keys, Permission::Keyboard]);

    let events = [Event::Centre, Event::Menu(0), Event::Centre];
    let (stop, r) = run_answering("signer", &events, BTreeMap::new(), &[Answer::Yes, Answer::No]);
    assert_eq!(stop, Stop::Finished);
    assert_eq!(r.menu, ["Type a test line"]);
    assert_eq!(r.asks.len(), 2);
    assert_eq!(r.asks[0].question, "Sign a test message?");
    assert_eq!((r.asks[0].yes.as_str(), r.asks[0].no.as_str()), ("sign", "cancel"));
    assert_eq!(r.typed, ["hello from maki\n"]);
    // a frame each time: the start, each answer, the typing, and the second answer
    assert_eq!(r.frames.len(), 4);
    assert_ne!(r.frames[0], r.frames[1]);
}

/// SSH wire encoding, for the agent's messages.
fn ssh_string(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn read_string(b: &[u8]) -> (&[u8], &[u8]) {
    let n = u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
    (&b[4..4 + n], &b[4 + n..])
}

fn agent(conn: u32, kind: u8, body: &[u8]) -> Vec<u8> {
    let mut m = conn.to_be_bytes().to_vec();
    m.push(kind);
    m.extend_from_slice(body);
    m
}

fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

#[test]
fn the_ssh_app_is_an_agent_that_asks_before_signing() {
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    use sha2::{Digest, Sha256};

    let public = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let mut blob = Vec::new();
    ssh_string(&mut blob, b"ssh-ed25519");
    ssh_string(&mut blob, public.as_bytes());

    // what ssh signs to sign in: the session, then the request (RFC 4252)
    let userauth = |session: &[u8], user: &[u8], key: &[u8]| {
        let mut d = Vec::new();
        ssh_string(&mut d, session);
        d.push(50);
        ssh_string(&mut d, user);
        ssh_string(&mut d, b"ssh-connection");
        ssh_string(&mut d, b"publickey");
        d.push(1);
        ssh_string(&mut d, b"ssh-ed25519");
        ssh_string(&mut d, key);
        d
    };
    let sign_request = |conn: u32, data: &[u8]| {
        let mut body = Vec::new();
        ssh_string(&mut body, &blob);
        ssh_string(&mut body, data);
        body.extend_from_slice(&0u32.to_be_bytes());
        agent(conn, 13, &body)
    };
    let sign_in = userauth(&[0xaa; 32], b"kara", &blob);
    // a session bound to a server's host key, then a sign-in in it
    let host_key = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20HOSTKEYHOSTKEYHOSTKEYHOSTKEY1234";
    let mut bind = Vec::new();
    ssh_string(&mut bind, b"session-bind@openssh.com");
    ssh_string(&mut bind, host_key);
    ssh_string(&mut bind, &[0xbb; 32]);
    ssh_string(&mut bind, b"signature");
    bind.push(0);
    let bound_sign_in = userauth(&[0xbb; 32], b"git", &blob);
    // git's signature: SSHSIG, the namespace, the hash
    let mut sshsig = b"SSHSIG".to_vec();
    ssh_string(&mut sshsig, b"git");
    ssh_string(&mut sshsig, b"");
    ssh_string(&mut sshsig, b"sha512");
    ssh_string(&mut sshsig, &[0x55; 64]);
    // for another key, or not what maki signs: refused without asking
    let other_key = userauth(&[0xaa; 32], b"kara", b"not this key");
    let arbitrary = b"sign this for me".to_vec();

    let messages = vec![
        agent(1, 11, &[]),
        sign_request(1, &sign_in),
        agent(2, 27, &bind),
        sign_request(2, &bound_sign_in),
        sign_request(2, &sshsig),
        sign_request(1, &sign_in),
        sign_request(1, &other_key),
        sign_request(1, &arbitrary),
        agent(1, 17, &[]),
    ];
    let events: Vec<Event> = messages.iter().map(|_| Event::Message).collect();
    let bytes = std::fs::read(format!("{}/tests/fixtures/ssh.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let record = Rc::new(RefCell::new(Record {
        events: events.into(),
        inbox: messages.into(),
        answers: [Answer::Yes, Answer::Yes, Answer::Yes, Answer::No].into(),
        ..Default::default()
    }));
    let stop = run(bundle.code, Box::new(Script(record.clone())), limits);
    assert_eq!(stop, Stop::Finished);
    let r = record.borrow();
    assert_eq!(r.replies.len(), 9);

    // its one key, as ssh lists it
    let answer = &r.replies[0];
    assert_eq!(answer[..5], [12, 0, 0, 0, 1]);
    let (listed, rest) = read_string(&answer[5..]);
    assert_eq!(listed, &blob[..]);
    assert_eq!(read_string(rest).0, b"maki");

    // a sign-in, signed once the owner said yes
    let verify = |answer: &[u8], data: &[u8]| {
        assert_eq!(answer[0], 14, "{answer:?}");
        let (sig_blob, _) = read_string(&answer[1..]);
        let (kind, rest) = read_string(sig_blob);
        assert_eq!(kind, b"ssh-ed25519");
        let (sig, _) = read_string(rest);
        public.verify(data, &Signature::from_slice(sig).unwrap()).unwrap();
    };
    verify(&r.replies[1], &sign_in);
    assert_eq!(r.asks[0].question, "SSH sign-in?");
    assert_eq!(r.asks[0].detail, "as kara");
    // the bound session shows its host
    assert_eq!(r.replies[2], [6]);
    verify(&r.replies[3], &bound_sign_in);
    let host_fp = format!("SHA256:{}", b64(&Sha256::digest(host_key)));
    assert_eq!(r.asks[1].detail, format!("as git, host {}", &host_fp[..19]));
    verify(&r.replies[4], &sshsig);
    assert_eq!((r.asks[2].question.as_str(), r.asks[2].detail.as_str()), ("Sign for git?", "a commit or a tag"));
    // the owner said no
    assert_eq!(r.replies[5], [5]);
    // refused without asking: another key, something that isn't a sign-in, and what an
    // agent that holds its keys doesn't do (adding one)
    assert_eq!(r.replies[6..], [vec![5], vec![5], vec![5]]);
    assert_eq!(r.asks.len(), 4);
    // it keeps count of what it signed
    assert_eq!(r.storage["signed"], 3u32.to_le_bytes());
}

#[test]
fn sensors_levels_and_scans() {
    use maki_bundle::Permission;
    let bytes = std::fs::read(format!("{}/tests/fixtures/sensors.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let asked: Vec<Permission> = bundle.manifest.permissions.iter().map(|(p, _)| *p).collect();
    assert_eq!(asked, [Permission::Camera, Permission::Motion]);
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let run_with = |motion: Option<[i16; 3]>, qr: Option<&str>, events: &[Event]| {
        let record = Rc::new(RefCell::new(Record {
            events: events.iter().copied().collect(),
            motion,
            qr: qr.map(String::from),
            ..Default::default()
        }));
        let stop = run(bundle.code, Box::new(Script(record.clone())), limits);
        assert_eq!(stop, Stop::Finished);
        Rc::try_unwrap(record).ok().unwrap().into_inner()
    };
    // level and still, then tilted: the bubble moves, so the frames differ
    let flat = run_with(Some([0, 0, 1000]), None, &[Event::Timeout]);
    let tilted = run_with(Some([400, -300, 850]), None, &[Event::Timeout]);
    assert_ne!(flat.frames[0], tilted.frames[0]);
    // a scan shows what it read; a cancelled one says so, and neither is the same as before
    let scanned = run_with(Some([0, 0, 1000]), Some("test://baomulator"), &[Event::Centre]);
    let cancelled = run_with(Some([0, 0, 1000]), None, &[Event::Centre]);
    assert_ne!(scanned.frames[1], flat.frames[0]);
    assert_ne!(scanned.frames[1], cancelled.frames[1]);
    // and without an accelerometer, it says so rather than stopping
    let none = run_with(None, None, &[Event::Timeout]);
    assert_eq!(none.frames.len(), 2);
}

#[test]
fn scanner_shows_what_it_read_and_types_it_checking_first_what_presses_keys() {
    use maki_bundle::Permission;
    let bytes = std::fs::read(format!("{}/tests/fixtures/scanner.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let asked: Vec<Permission> = bundle.manifest.permissions.iter().map(|(p, _)| *p).collect();
    assert_eq!(asked, [Permission::Keyboard, Permission::Camera]);
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let run_with = |qr: Option<&str>, events: &[Event]| {
        let record = Rc::new(RefCell::new(Record {
            events: events.iter().copied().collect(),
            qr: qr.map(String::from),
            ..Default::default()
        }));
        assert_eq!(run(bundle.code, Box::new(Script(record.clone())), limits), Stop::Finished);
        Rc::try_unwrap(record).ok().unwrap().into_inner()
    };
    // read, then typed as it is
    let link = "https://github.com/KaraZajac/maki";
    let r = run_with(Some(link), &[Event::Centre, Event::Menu(0)]);
    assert_eq!(r.menu, ["Type it"]);
    assert_eq!(r.typed, [link]);
    // what presses Enter or Tab waits for the centre: left goes back without typing
    let lines = "echo hello\r\nrm -rf ~\tnow\n";
    let r = run_with(Some(lines), &[Event::Centre, Event::Menu(0), Event::Left]);
    assert!(r.typed.is_empty());
    let r = run_with(Some(lines), &[Event::Centre, Event::Menu(0), Event::Centre]);
    assert_eq!(r.typed, ["echo hello\nrm -rf ~\tnow\n"]);
    // the check is its own screen
    assert_ne!(r.frames[2], r.frames[1]);
    // long text in pieces a keyboard takes at once, and pages to read it by
    let long: String = (0..2100).map(|i| (b'a' + (i % 26) as u8) as char).chain(" end".chars()).collect();
    let r = run_with(Some(&long), &[Event::Centre, Event::Right, Event::Right, Event::Menu(0)]);
    assert_eq!(r.typed.iter().map(|t| t.len()).collect::<Vec<_>>(), [1024, 1024, 56]);
    assert_eq!(r.typed.concat(), long);
    assert_ne!(r.frames[2], r.frames[1]);
    // what no keyboard types isn't typed at all, and a cancelled scan leaves nothing to type
    let r = run_with(Some("café"), &[Event::Centre, Event::Menu(0)]);
    assert!(r.typed.is_empty());
    let r = run_with(None, &[Event::Centre, Event::Menu(0)]);
    assert!(r.typed.is_empty());
}

#[test]
fn marble_rolls_the_way_maki_tilts_and_pauses() {
    use maki_bundle::Permission;
    let bytes = std::fs::read(format!("{}/tests/fixtures/marble.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let asked: Vec<Permission> = bundle.manifest.permissions.iter().map(|(p, _)| *p).collect();
    assert_eq!(asked, [Permission::Motion]);
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let run_with = |motion: Option<[i16; 3]>, events: &[Event]| {
        let record = Rc::new(RefCell::new(Record { events: events.iter().copied().collect(), motion, ..Default::default() }));
        assert_eq!(run(bundle.code, Box::new(Script(record.clone())), limits), Stop::Finished);
        Rc::try_unwrap(record).ok().unwrap().into_inner()
    };
    let steps = |n: usize| -> Vec<Event> { std::iter::once(Event::Centre).chain(std::iter::repeat(Event::Timeout).take(n)).collect() };
    // level, the marble stays at the start; tilted, it rolls
    let flat = run_with(Some([0, 0, 1000]), &steps(20));
    assert_eq!(flat.frames.len(), 22);
    assert_eq!(flat.frames[1], flat.frames[21]);
    let tilted = run_with(Some([600, -600, 500]), &steps(20));
    assert_eq!(tilted.frames[1], flat.frames[1]);
    assert_ne!(tilted.frames[1], tilted.frames[21]);
    // the centre pauses, and the time stands still while it is
    let mut events = steps(5);
    events.extend([Event::Centre, Event::Timeout, Event::Centre]);
    let paused = run_with(Some([600, -600, 500]), &events);
    assert_ne!(paused.frames[7], paused.frames[6]);
    assert_eq!(paused.frames[8], paused.frames[7]);
    // no accelerometer: the title says so
    let none = run_with(None, &[]);
    assert_ne!(none.frames[0], flat.frames[0]);
    assert!(none.storage.is_empty());
}

#[test]
fn breakout_serves_from_a_paddle_that_follows_the_tilt() {
    use maki_bundle::Permission;
    let bytes = std::fs::read(format!("{}/tests/fixtures/breakout.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let asked: Vec<Permission> = bundle.manifest.permissions.iter().map(|(p, _)| *p).collect();
    assert_eq!(asked, [Permission::Motion]);
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let run_with = |motion: Option<[i16; 3]>, events: &[Event]| {
        let record = Rc::new(RefCell::new(Record { events: events.iter().copied().collect(), motion, ..Default::default() }));
        assert_eq!(run(bundle.code, Box::new(Script(record.clone())), limits), Stop::Finished);
        Rc::try_unwrap(record).ok().unwrap().into_inner()
    };
    let then = |first: &[Event], n: usize| -> Vec<Event> { first.iter().copied().chain(std::iter::repeat(Event::Timeout).take(n)).collect() };
    // on the paddle until served, then off it
    let waiting = run_with(Some([0, 0, 1000]), &then(&[Event::Centre], 10));
    assert_eq!(waiting.frames[1], waiting.frames[11]);
    let served = run_with(Some([0, 0, 1000]), &then(&[Event::Centre, Event::Centre], 10));
    assert_ne!(served.frames[2], served.frames[12]);
    // tilted one way or the other, the paddle (and the ball on it) goes that way
    let left = run_with(Some([-400, 0, 900]), &then(&[Event::Centre], 10));
    let right = run_with(Some([400, 0, 900]), &then(&[Event::Centre], 10));
    assert_ne!(left.frames[11], right.frames[11]);
    assert_ne!(left.frames[11], waiting.frames[11]);
    // without an accelerometer, left and right move it
    let pressed = run_with(None, &[Event::Centre, Event::Left, Event::Left]);
    assert_ne!(pressed.frames[1], pressed.frames[3]);
}

#[test]
fn minisign_signs_a_hash_and_its_own_trusted_comment_once_asked() {
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    let bytes = std::fs::read(format!("{}/tests/fixtures/minisign.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    // every label's secret is [7; 32] here: the key, and the ID from its own label
    let public = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let hash = [0x5au8; 64];
    let sign = |name: &str, comment: &str| {
        let mut m = vec![b'S'];
        m.extend_from_slice(&hash);
        m.extend_from_slice(&1_234_567u64.to_le_bytes());
        m.push(name.len() as u8);
        m.extend_from_slice(name.as_bytes());
        m.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        m.extend_from_slice(comment.as_bytes());
        m
    };
    let inbox = vec![b"P".to_vec(), sign("maki-0.2.0.tar.gz", ""), sign("notes.txt", "release 0.2"), sign("other.bin", ""), sign("../etc/passwd", "")];
    let record = Rc::new(RefCell::new(Record {
        events: std::iter::repeat(Event::Message).take(inbox.len()).collect(),
        inbox: inbox.into_iter().collect(),
        answers: [Answer::Yes, Answer::Yes, Answer::No].into_iter().collect(),
        ..Default::default()
    }));
    assert_eq!(run(bundle.code, Box::new(Script(record.clone())), limits), Stop::Finished);
    let r = record.borrow();
    // the public key and its ID
    assert_eq!(r.replies[0][0], 0);
    assert_eq!(&r.replies[0][1..33], public.as_bytes());
    assert_eq!(&r.replies[0][33..], &[7; 8]);
    // signed: the hash, then the signature with the trusted comment, as minisign checks them
    let check = |reply: &[u8]| -> String {
        assert_eq!(reply[0], 0, "{reply:?}");
        assert_eq!(&reply[1..9], &[7; 8]);
        let sig = Signature::from_slice(&reply[9..73]).unwrap();
        public.verify(&hash, &sig).unwrap();
        let n = u16::from_le_bytes([reply[73], reply[74]]) as usize;
        let comment = std::str::from_utf8(&reply[75..75 + n]).unwrap().to_string();
        let global = Signature::from_slice(&reply[75 + n..]).unwrap();
        public.verify(&[&reply[9..73], comment.as_bytes()].concat(), &global).unwrap();
        comment
    };
    // maki's own comment (no clock here, so no timestamp), or the signer's
    assert_eq!(check(&r.replies[1]), "file:maki-0.2.0.tar.gz\thashed");
    assert_eq!(check(&r.replies[2]), "release 0.2");
    // what the owner read first
    assert_eq!(r.asks[0].question, "Sign maki-0.2.0.tar.gz?");
    assert_eq!(r.asks[0].detail, "1.2 MB, BLAKE2b 5a5a5a5a5a5a...");
    assert_eq!(r.asks[1].detail, "1.2 MB, BLAKE2b 5a5a5a5a5a5a..., comment: release 0.2");
    // a no is a no, and a name with a path isn't asked about at all
    assert_eq!(r.replies[3], [1]);
    assert_eq!(r.replies[4], [4]);
    assert_eq!(r.asks.len(), 3);
    assert_eq!(r.storage.get("signed").unwrap(), &2u32.to_le_bytes());
}

fn words_list() -> Vec<String> {
    std::fs::read_to_string(format!("{}/../../sdk/examples/passphrase/src/words.txt", env!("CARGO_MANIFEST_DIR")))
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

#[test]
fn passphrase_types_words_from_the_list_as_many_as_asked() {
    let events = [
        Event::Menu(0),
        Event::Right,
        Event::Menu(1),
        Event::Menu(0),
        Event::Left,
        Event::Left,
        Event::Left,
        Event::Left,
        Event::Left,
        Event::Menu(0),
    ];
    let (stop, r) = run_fixture("passphrase", &events, BTreeMap::new());
    assert_eq!(stop, Stop::Finished);
    assert_eq!(r.menu, ["Type it", "Separator"]);
    let list = words_list();
    assert_eq!(list.len(), 7776);
    let typed: Vec<Vec<&str>> = r
        .typed
        .iter()
        .zip([" ", "-", "-"])
        .map(|(t, sep)| t.split(sep).collect())
        .collect();
    // six to start with, then one more, then down to the fewest, four
    assert_eq!(typed.iter().map(|w| w.len()).collect::<Vec<_>>(), [6, 7, 4]);
    assert!(typed.iter().flatten().all(|w| list.iter().any(|l| l == w)), "{typed:?}");
    // the count and the separator are kept; the passphrase isn't
    assert_eq!(r.storage.get("words").unwrap(), &4u32.to_le_bytes());
    assert_eq!(r.storage.get("separator").unwrap(), &1u32.to_le_bytes());
    assert_eq!(r.storage.len(), 2);
}

#[test]
fn snake_eats_grows_and_ends_at_the_wall() {
    // the counting random puts the first food 25 free cells in: the top row, 25 across. The
    // snake starts heading right from 7 across, 12 down: right to 25, up to the top, and on
    let mut events = vec![Event::Centre];
    events.extend([Event::Timeout; 18]);
    events.push(Event::Left);
    events.extend([Event::Timeout; 13]);
    let (stop, r) = run_fixture("snake", &events, BTreeMap::new());
    assert_eq!(stop, Stop::Finished);
    // it ate once before the wall: its best is 1
    assert_eq!(r.storage.get("best").unwrap(), &1u32.to_le_bytes());
    // five cells long at the end, not four: the field (below the score) of the last frame of
    // play has one cell more lit than the first, 3 by 3 pixels
    let field = |c: &Canvas| (12..HEIGHT as i32).flat_map(|y| (0..WIDTH as i32).map(move |x| (x, y))).filter(|&(x, y)| c.get(x, y)).count();
    let frames = &r.frames;
    assert_eq!(field(&frames[frames.len() - 2]), field(&frames[2]) + 9);

    // no food, no best: straight into the wall
    let mut events = vec![Event::Centre];
    events.extend([Event::Timeout; 25]);
    let (_, r) = run_fixture("snake", &events, BTreeMap::new());
    assert!(r.storage.get("best").is_none());
}

#[test]
fn status_shows_what_the_computer_says_and_says_what_it_shows() {
    let msg = |s: &str| s.as_bytes().to_vec();
    let events = [Event::Message, Event::Message, Event::Message, Event::Message, Event::Right, Event::Centre, Event::Message];
    let record = Rc::new(RefCell::new(Record {
        events: events.iter().copied().collect(),
        inbox: [msg("on A call"), msg(""), msg("  Back \n at\t3 "), msg("")].into_iter().chain([msg("")]).collect(),
        ..Default::default()
    }));
    let bytes = std::fs::read(format!("{}/tests/fixtures/status.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let stop = run(bundle.code, Box::new(Script(record.clone())), limits);
    assert_eq!(stop, Stop::Finished);
    let r = record.borrow();
    let replies: Vec<&str> = r.replies.iter().map(|b| std::str::from_utf8(b).unwrap()).collect();
    // a sign by name, whatever its capitals; its own text, tidied; and what's showing, when asked
    assert_eq!(replies, ["ok", "On a call", "ok", "Back at 3", "Available"]);
    assert_eq!(r.storage.get("own").unwrap(), b"Back at 3");
    // right from its own text goes round to the first sign; the centre lights the screen
    assert_eq!(r.storage.get("at").unwrap(), &0u32.to_le_bytes());
    assert_eq!(r.storage.get("light").unwrap(), &1u32.to_le_bytes());
    let last = r.frames.last().unwrap();
    assert!(lit(last) > (WIDTH * HEIGHT) as usize / 2, "light: more lit than not");
}

#[test]
fn nostr_shows_its_key_and_signs_events_as_nip01_hashes_them() {
    use k256::schnorr::{Signature, VerifyingKey};
    use sha2::{Digest, Sha256};
    let site = b"example.com";
    let mut key_msg = vec![1u8, site.len() as u8];
    key_msg.extend_from_slice(site);
    let (tags, content) = (r#"[["t","maki"]]"#, "gm \"maki\"\n");
    let mut sign_msg = vec![2u8, site.len() as u8];
    sign_msg.extend_from_slice(site);
    sign_msg.extend_from_slice(&1_790_000_000u64.to_be_bytes());
    sign_msg.extend_from_slice(&1u32.to_be_bytes());
    sign_msg.extend_from_slice(&(tags.len() as u32).to_be_bytes());
    sign_msg.extend_from_slice(tags.as_bytes());
    sign_msg.extend_from_slice(&(content.len() as u32).to_be_bytes());
    sign_msg.extend_from_slice(content.as_bytes());
    let record = Rc::new(RefCell::new(Record {
        events: [Event::Message, Event::Message, Event::Message].into_iter().collect(),
        inbox: [key_msg.clone(), sign_msg, key_msg].into_iter().collect(),
        // the first site asks to see the key: yes; then to sign: yes
        answers: [Answer::Yes, Answer::Yes].into_iter().collect(),
        ..Default::default()
    }));
    let bytes = std::fs::read(format!("{}/tests/fixtures/nostr.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    assert_eq!(bundle.manifest.api, 2);
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    assert_eq!(run(bundle.code, Box::new(Script(record.clone())), limits), Stop::Finished);
    let r = record.borrow();
    // asked once to see the key (the site is remembered), once to sign
    assert_eq!(r.asks.len(), 2, "{:?}", r.asks);
    assert_eq!(r.asks[0].question, "Let it see your Nostr key?");
    assert_eq!(r.asks[1].question, "Sign a Nostr note?");
    assert!(r.asks[1].detail.starts_with("example.com: gm \"maki\""), "{}", r.asks[1].detail);
    let [key, signed, again] = [&r.replies[0], &r.replies[1], &r.replies[2]];
    assert_eq!((key[0], key.len(), signed[0], signed.len()), (0, 33, 0, 97));
    assert_eq!(key, again);
    // the id: NIP-01's serialization, hashed, from the fields sent; the signature, BIP340's
    let pubkey: String = key[1..].iter().map(|b| format!("{b:02x}")).collect();
    let serialized = format!(r#"[0,"{pubkey}",1790000000,1,{tags},"gm \"maki\"\n"]"#);
    assert_eq!(&signed[1..33], Sha256::digest(serialized.as_bytes()).as_slice());
    let vk = VerifyingKey::from_bytes(&key[1..]).unwrap();
    vk.verify_raw(&signed[1..33], &Signature::try_from(&signed[33..97]).unwrap()).unwrap();
}

/// A file key wrapped for `recipient` as age's X25519 stanza is: the ephemeral share and the body.
fn age_stanza(recipient: &[u8; 32], file_key: &[u8; 16], ephemeral: [u8; 32]) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    let secret = x25519_dalek::StaticSecret::from(ephemeral);
    let share = x25519_dalek::PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*recipient));
    let salt = [share.as_slice(), recipient.as_slice()].concat();
    let mut wrap = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), shared.as_bytes()).expand(b"age-encryption.org/v1/X25519", &mut wrap).unwrap();
    let body = chacha20poly1305::ChaCha20Poly1305::new(&wrap.into()).encrypt(&Default::default(), file_key.as_slice()).unwrap();
    [share.to_vec(), body].concat()
}

#[test]
fn age_finds_its_stanza_and_unwraps_it_once_asked() {
    let bytes = std::fs::read(format!("{}/tests/fixtures/age.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let run_with = |inbox: Vec<Vec<u8>>, answers: Vec<Answer>| {
        let record = Rc::new(RefCell::new(Record {
            events: inbox.iter().map(|_| Event::Message).collect(),
            inbox: inbox.into_iter().collect(),
            answers: answers.into_iter().collect(),
            ..Default::default()
        }));
        let limits = admit(&bundle.manifest, bundle.code).unwrap();
        assert_eq!(run(bundle.code, Box::new(Script(record.clone())), limits), Stop::Finished);
        Rc::try_unwrap(record).ok().unwrap().into_inner()
    };
    // its recipient
    let r = run_with(vec![vec![1]], vec![]);
    assert_eq!((r.replies[0][0], r.replies[0].len()), (0, 33));
    let recipient: [u8; 32] = r.replies[0][1..].try_into().unwrap();

    // a file for someone else, and one for this key: it says which is its own without asking
    let file_key = [0x5a; 16];
    let theirs = age_stanza(&[9; 32], &file_key, [1; 32]);
    let mine = age_stanza(&recipient, &file_key, [2; 32]);
    let find = [vec![2, 2], theirs.clone(), mine.clone()].concat();
    let unwrap = |stanza: &[u8]| [&[3u8][..], stanza, &[3], b"age"].concat();
    let r = run_with(vec![find, unwrap(&mine), unwrap(&theirs), unwrap(&mine)], vec![Answer::Yes, Answer::No]);
    assert_eq!(r.replies[0], [0, 1]);
    // asked, and yes: the file key
    assert_eq!(r.replies[1], [&[0u8][..], &file_key].concat());
    assert_eq!(r.asks[0].question, "Decrypt a file with your age key?");
    assert_eq!(r.asks[0].detail, "for age, on this computer");
    // someone else's: not its own, and nobody's asked
    assert_eq!(r.replies[2], [4]);
    // asked again, and no
    assert_eq!(r.replies[3], [1]);
    assert_eq!(r.asks.len(), 2);
}

#[test]
fn wifi_keeps_networks_from_the_camera_and_the_computer() {
    let bytes = std::fs::read(format!("{}/tests/fixtures/wifi.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let msg = |s: &str| s.as_bytes().to_vec();
    let record = Rc::new(RefCell::new(Record {
        // scan one; one from the computer; the names; something that isn't a network; forget
        // the one showing (the computer's); the names again
        events: [Event::Menu(0), Event::Message, Event::Message, Event::Message, Event::Menu(2), Event::Message]
            .into_iter()
            .collect(),
        qr: Some("WIFI:T:WPA;S:maki guests;P:correct horse;;".into()),
        inbox: [msg(r"WIFI:S:Cafe\;Bar;T:nopass;;"), msg(""), msg("hello"), msg("")].into_iter().collect(),
        ..Default::default()
    }));
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    assert_eq!(run(bundle.code, Box::new(Script(record.clone())), limits), Stop::Finished);
    let r = record.borrow();
    assert_eq!(r.menu, ["Scan a network", "Show the password", "Forget this one"]);
    let replies: Vec<&str> = r.replies.iter().map(|b| std::str::from_utf8(b).unwrap()).collect();
    assert_eq!(replies, ["ok", "maki guests\nCafe;Bar\n", "that isn't a network: a WIFI: text with a name", "maki guests\n"]);
    // kept as its QR code had it, for the next time
    assert_eq!(r.storage.get("networks").unwrap(), b"WIFI:T:WPA;S:maki guests;P:correct horse;;\n");
}

/// A wallet app, run as maki runs it (its manifest's paths and all), on these messages and
/// answers.
fn run_wallet(name: &str, inbox: Vec<Vec<u8>>, answers: Vec<Answer>, locked: bool) -> Record {
    let events = inbox.iter().map(|_| Event::Message).collect();
    run_wallet_with(name, events, inbox, answers, locked)
}

/// The same, on these events (a `Message` delivers the next message).
fn run_wallet_with(name: &str, events: Vec<Event>, inbox: Vec<Vec<u8>>, answers: Vec<Answer>, locked: bool) -> Record {
    let bytes = std::fs::read(format!("{}/tests/fixtures/{name}.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let record = Rc::new(RefCell::new(Record {
        events: events.into(),
        inbox: inbox.into_iter().collect(),
        answers: answers.into_iter().collect(),
        locked,
        ..Default::default()
    }));
    let loaded = load(&bundle.manifest, bundle.code).unwrap();
    assert_eq!(loaded.run(Box::new(Script(record.clone()))), Stop::Finished);
    Rc::try_unwrap(record).ok().unwrap().into_inner()
}

/// An answer's fields after the status: strings (a u16 length, then the bytes).
fn texts(answer: &[u8]) -> Vec<String> {
    let (mut out, mut at) = (Vec::new(), 1);
    while at + 2 <= answer.len() {
        let n = u16::from_le_bytes([answer[at], answer[at + 1]]) as usize;
        out.push(String::from_utf8(answer[at + 2..at + 2 + n].to_vec()).unwrap());
        at += 2 + n;
    }
    out
}

const BTC_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../maki-btc/tests/fixtures");

/// A PSBT sent to the Bitcoin app in pieces, as maki desktop sends it: `P` messages, then the
/// signed one fetched with `G`s (the number of those is a guess: enough for these fixtures).
fn psbt_messages(network: u8, psbt: &[u8], fetches: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for (i, piece) in psbt.chunks(4000).enumerate() {
        let mut m = vec![b'P', network];
        m.extend_from_slice(&(psbt.len() as u32).to_le_bytes());
        m.extend_from_slice(&((i * 4000) as u32).to_le_bytes());
        m.extend_from_slice(piece);
        out.push(m);
    }
    for i in 0..fetches {
        let mut m = vec![b'G'];
        m.extend_from_slice(&((i * 4000) as u32).to_le_bytes());
        out.push(m);
    }
    out
}

/// The signed PSBT the `G` answers put together.
fn fetched(replies: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for r in replies {
        assert_eq!(r[0], 0);
        let total = u32::from_le_bytes(r[1..5].try_into().unwrap()) as usize;
        let offset = u32::from_le_bytes(r[5..9].try_into().unwrap()) as usize;
        assert_eq!(offset, out.len());
        out.extend_from_slice(&r[9..]);
        if out.len() == total {
            break;
        }
    }
    out
}

#[test]
fn bitcoin_shares_its_account_and_compares_addresses_once_asked() {
    // BIP84's test vectors: the account key and first address the phrase makes everywhere
    let r = run_wallet("bitcoin", vec![vec![b'A', 0, 0], vec![b'A', 0, 0], vec![b'D', 0, 0, 0, 0, 0, 0, 0]], vec![Answer::Yes, Answer::No, Answer::Yes], false);
    assert_eq!(r.replies[0][0], 0);
    let [zpub, descriptor] = <[String; 2]>::try_from(texts(&r.replies[0])).unwrap();
    assert_eq!(zpub, "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs");
    assert!(descriptor.starts_with("wpkh([73c5da0a/84h/0h/0h]xpub"), "{descriptor}");
    assert_eq!(r.reviews[0].question, "Share account?");
    assert_eq!(r.replies[1], [1], "the owner said no: nothing");
    assert_eq!(r.replies[2][0], 0);
    assert_eq!(texts(&r.replies[2]), ["bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"]);
    assert_eq!(r.reviews[2].question, "Same on computer?");
    assert_eq!(r.reviews[2].pages[0].mono.replace('\n', ""), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    // taproot's first address (BIP86's vector), and a locked maki
    let r = run_wallet("bitcoin", vec![vec![b'D', 0, 1, 0, 0, 0, 0, 0]], vec![Answer::Yes], false);
    assert_eq!(texts(&r.replies[0]), ["bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"]);
    let r = run_wallet("bitcoin", vec![vec![b'A', 0, 0]], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
    assert!(r.reviews.is_empty());
}

#[test]
fn bitcoin_signs_what_the_owner_reviewed_as_maki_always_has() {
    for (unsigned, signed) in [("abandon-unsigned.psbt", "abandon-signed.psbt"), ("abandon-taproot-unsigned.psbt", "abandon-taproot-signed.psbt")] {
        let psbt = std::fs::read(format!("{BTC_FIXTURES}/{unsigned}")).unwrap();
        let expected = std::fs::read(format!("{BTC_FIXTURES}/{signed}")).unwrap();
        let fetches = expected.len().div_ceil(4000);
        let pieces = psbt.len().div_ceil(4000);
        let r = run_wallet("bitcoin", psbt_messages(0, &psbt, fetches), vec![Answer::Yes], false);
        for more in &r.replies[..pieces - 1] {
            assert_eq!(more, &[6], "{unsigned}: a piece taken");
        }
        let done = &r.replies[pieces - 1];
        assert_eq!((done[0], u32::from_le_bytes(done[1..5].try_into().unwrap()) as usize), (0, expected.len()), "{unsigned}");
        // the very bytes maki's wallet code signs: rust-bitcoin's, byte for byte
        assert_eq!(fetched(&r.replies[pieces..]), expected, "{unsigned}");
        let review = &r.reviews[0];
        assert_eq!(review.question, "Sign and spend");
        // each payment, the change and the fee (this fixture's is flagged: 24 sat/vB)
        let headings: Vec<&str> = review.pages.iter().map(|p| p.heading.as_str()).collect();
        assert!(headings.contains(&"Change") && (headings.contains(&"Fee") || headings.contains(&"High fee!")), "{headings:?}");
        assert_eq!(review.timeout_s, 300);
    }
    // a no signs nothing, and there's nothing to fetch
    let psbt = std::fs::read(format!("{BTC_FIXTURES}/abandon-unsigned.psbt")).unwrap();
    let r = run_wallet("bitcoin", psbt_messages(0, &psbt, 1), vec![Answer::No], false);
    assert_eq!(r.replies[psbt.len().div_ceil(4000) - 1], [1]);
    assert_eq!(r.replies.last().unwrap(), &[4]);
    // on the test networks' accounts it isn't this wallet's, and says why
    let r = run_wallet("bitcoin", psbt_messages(1, &psbt, 0), vec![Answer::Yes], false);
    let last = r.replies.last().unwrap();
    assert_eq!(last[0], 5);
    assert!(texts(last)[0].contains("isn't this wallet's"), "{:?}", texts(last));
    assert!(r.reviews.is_empty(), "nothing shown for what can't be signed");
    // what isn't a PSBT
    let r = run_wallet("bitcoin", psbt_messages(0, b"not a psbt", 0), vec![], false);
    assert!(texts(&r.replies[0])[0].starts_with("not a PSBT maki can read"));
}

const ETH_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../maki-eth/tests/fixtures");

/// The Ethereum app's header for account `index` from `site`, after the message's kind.
fn eth_head(kind: u8, index: u32, site: &str) -> Vec<u8> {
    let mut m = vec![kind];
    m.extend_from_slice(&index.to_le_bytes());
    m.push(site.len() as u8);
    m.extend_from_slice(site.as_bytes());
    m
}

/// A transaction (`T`) or typed data (`Y`) in pieces, as maki desktop sends them.
fn eth_pieces(kind: u8, site: &str, bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for (i, piece) in bytes.chunks(4000).enumerate() {
        let mut m = vec![kind];
        m.extend_from_slice(&0u32.to_le_bytes());
        m.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        m.extend_from_slice(&((i * 4000) as u32).to_le_bytes());
        m.push(site.len() as u8);
        m.extend_from_slice(site.as_bytes());
        m.extend_from_slice(piece);
        out.push(m);
    }
    out
}

#[test]
fn ethereum_connects_sites_the_owner_lets_in() {
    let r = run_wallet("ethereum", vec![eth_head(b'A', 0, "app.example"), eth_head(b'A', 0, "app.example")], vec![Answer::Yes, Answer::No], false);
    // MetaMask's and Ledger's first account for the phrase
    assert_eq!(r.replies[0][0], 0);
    assert_eq!(texts(&r.replies[0]), ["0x9858EfFD232B4033E47d90003D41EC34EcaEda94"]);
    assert_eq!(r.reviews[0].question, "Connect wallet?");
    assert_eq!((r.reviews[0].pages[0].heading.as_str(), r.reviews[0].pages[0].mono.as_str()), ("Asked by", "app.example"));
    assert_eq!(r.replies[1], [1]);
    let r = run_wallet("ethereum", vec![eth_head(b'A', 0, "app.example")], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3], "locked");
    // what maki shows must mean what it says: plain hostnames only, as for logins
    for site in ["App.Example", "аpp.example", "app..example", ".example", "app example"] {
        let r = run_wallet("ethereum", vec![eth_head(b'A', 0, site)], vec![Answer::Yes], false);
        assert_eq!(r.replies[0], [4], "{site}");
        assert!(r.reviews.is_empty(), "{site}");
    }
}

#[test]
fn ethereum_signs_what_the_owner_read_as_maki_always_has() {
    // a sign-in message: the signature maki's code makes, and alloy agrees
    let sig = std::fs::read(format!("{ETH_FIXTURES}/abandon-message.sig")).unwrap();
    let message = [eth_head(b'M', 0, "demo.maki"), b"Sign in to demo.maki".to_vec()].concat();
    // and one that's a sign-in for another site than the one asking
    let phish = [eth_head(b'M', 0, "demo.maki"), b"evil.example wants you to sign in with your Ethereum account:\n0x9858".to_vec()].concat();
    let r = run_wallet("ethereum", vec![message, phish], vec![Answer::Yes, Answer::No], false);
    assert_eq!(r.replies[0], [&[0u8][..], &sig].concat());
    assert_eq!(r.reviews[0].question, "Sign message?");
    assert_eq!(r.reviews[1].pages[1].heading, "Wrong site!");
    assert_eq!(r.replies[1], [1]);

    // a transaction: pieces, then the signed one fetched
    let unsigned = std::fs::read(format!("{ETH_FIXTURES}/abandon-tx-unsigned.bin")).unwrap();
    let signed = std::fs::read(format!("{ETH_FIXTURES}/abandon-tx-signed.bin")).unwrap();
    let mut inbox = eth_pieces(b'T', "demo.maki", &unsigned);
    let pieces = inbox.len();
    for i in 0..signed.len().div_ceil(4000) {
        inbox.push([&[b'G'][..], &((i * 4000) as u32).to_le_bytes()].concat());
    }
    let r = run_wallet("ethereum", inbox, vec![Answer::Yes], false);
    let done = &r.replies[pieces - 1];
    assert_eq!((done[0], u32::from_le_bytes(done[1..5].try_into().unwrap()) as usize), (0, signed.len()));
    assert_eq!(fetched(&r.replies[pieces..]), signed);
    assert_eq!(r.reviews[0].question, "Sign and send");
    assert_eq!(r.reviews[0].pages[0].mono, "demo.maki");

    // typed data (a permit): its signature, from the values shown
    let json = std::fs::read(format!("{ETH_FIXTURES}/abandon-typed.json")).unwrap();
    let sig = std::fs::read(format!("{ETH_FIXTURES}/abandon-typed.sig")).unwrap();
    let r = run_wallet("ethereum", eth_pieces(b'Y', "demo.maki", &json), vec![Answer::Yes], false);
    assert_eq!(r.replies.last().unwrap(), &[&[0u8][..], &sig].concat());
    assert!(r.reviews[0].pages.len() > 1);

    // what isn't a transaction: refused, with why, and nothing shown
    let r = run_wallet("ethereum", eth_pieces(b'T', "demo.maki", b"\x02not rlp"), vec![], false);
    assert_eq!(r.replies[0][0], 5);
    assert!(r.reviews.is_empty());
}

/// A Monero app's `D`: an address to compare, on a network (0 Monero, 1 testnet, 2 stagenet).
fn xmr_address(net: u8, major: u32, minor: u32) -> Vec<u8> { [&[b'D', net][..], &major.to_le_bytes(), &minor.to_le_bytes()].concat() }

#[test]
fn monero_shows_the_addresses_every_wallet_makes() {
    // the test phrase's: as Ledger's Monero app and monero-python make them
    let inbox = vec![xmr_address(0, 0, 0), xmr_address(2, 0, 0), xmr_address(0, 0, 1), xmr_address(0, 0, 2), xmr_address(0, 2, 7), xmr_address(1, 0, 1)];
    let answers = vec![Answer::Yes, Answer::Yes, Answer::Yes, Answer::No, Answer::Yes, Answer::NoAnswer];
    let r = run_wallet("monero", inbox, answers, false);
    let expected = [
        "49vDbkSo7eve3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVF2N4Zn",
        "5A8FgbMkmG2e3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVHCRUaE",
        "8AB7PQPtducdkghYFN2prK3rZ7zPeL9f2REEdqE4WXYbSZr3797Aqti5xAjRsVy4jTdcwMW11GWejQtqk2kNXxj2QZxJwPZ",
        "8696JpJ6Yvw8VtJqpQ7V8gNLBdgwLK5xYLQPfE7DpzdQGo4gKPWMJSubTt8rvvTrWagePa2q1P3k3TvRkGiHZGGUL1cuAwo",
        "85mwm6zoWkeAydxd69jdubASfvsVFhy3f9Jt8a4FiNmKfzNd9epYvpTAkFQz33F97YLqKpUCGKCdk7DHBBVriZtyFxJFEoS",
    ];
    for (i, address) in expected.iter().enumerate() {
        // compared on maki's screen, whole, and handed over once the owner has
        assert_eq!(r.reviews[i].question, "Same on computer?");
        assert_eq!(r.reviews[i].pages[0].mono, *address);
        assert_eq!(texts(&r.replies[i]), [*address], "{i}");
    }
    assert_eq!(r.replies[..3].iter().map(|a| a[0]).collect::<Vec<_>>(), [0, 0, 0]);
    assert_eq!(r.replies[3][0], 1, "doesn't match: the computer's copy isn't to be trusted");
    assert_eq!(r.replies[5], [2], "no answer");
    let headings: Vec<&str> = r.reviews.iter().map(|v| v.pages[0].heading.as_str()).collect();
    assert_eq!(headings, ["Primary address", "Primary address, stagenet", "Subaddress 1", "Subaddress 2", "Subaddress 2/7", "Subaddress 1, testnet"]);
    // locked; a network there isn't; not a message it takes
    let r = run_wallet("monero", vec![xmr_address(0, 0, 0)], vec![], true);
    assert_eq!(r.replies, [vec![3u8]]);
    let r = run_wallet("monero", vec![xmr_address(9, 0, 0), vec![b'X'], vec![b'D', 0]], vec![], false);
    assert_eq!(r.replies, [vec![4u8], vec![4], vec![4]]);
    assert!(r.reviews.is_empty());
}

#[test]
fn monero_has_maki_show_its_backup_and_never_sees_it() {
    let r = run_wallet_with("monero", vec![Event::Menu(0), Event::Menu(0), Event::Centre], vec![], vec![Answer::Yes, Answer::No], false);
    // maki showed the 25 words Monero wallets restore from once, when the owner said to
    assert_eq!(
        r.backups,
        [concat!(
            "tavern judge beyond bifocals deepest mural onward dummy eagle diode gained vacation rally cause firm idled jerseys ",
            "moat vigilant upload bobsled jobs cunning doing jobs"
        )]
    );
    assert_eq!(r.menu, ["Backup words", "Network"]);
    // and the app drew its address all along: a QR code, then as text
    assert!(r.frames.len() >= 3 && r.frames.iter().all(|f| lit(f) > 500));
}

/// An output paid to the test phrase's Monero account (its subaddress `minor`), as a sender
/// makes one, in a ring of 16 made-up members: what maki desktop asks the Monero app to spend.
fn xmr_input(seed: u64, minor: u32, amount: u64) -> maki_xmr::request::Input {
    use maki_xmr::sign::{self, Scalar, G};
    let keys = maki_hd::seed::SeedKeys::from_seed(&test_seed()).unwrap();
    let account = maki_hd::parse_path("m/44'/128'/0'/0/0").unwrap();
    let pair = maki_hd::seed::answer(&keys, maki_hd::op::MONERO_SUBADDRESS, &account, &[0, 0, 0, 0, minor as u8, 0, 0, 0], &[0; 32]).unwrap();
    let (spend, view) = (sign::point(&pair[..32].try_into().unwrap()).unwrap(), sign::point(&pair[32..].try_into().unwrap()).unwrap());
    let scalar = |n: u64| Scalar::from_bytes_mod_order(maki_xmr::keccak(&(seed * 1000 + n).to_le_bytes()));
    let r = scalar(0);
    let tx_key = if minor == 0 { G * r } else { spend * r };
    let out = sign::pay(&r, &view, &spend, 2, amount);
    let ring = (0..16u64)
        .map(|i| maki_xmr::request::Member {
            global: 5000 + 7 * i,
            key: if i == 9 { out.key } else { (G * scalar(i + 1)).compress().to_bytes() },
            commitment: if i == 9 { out.commitment } else { sign::commit(&scalar(i + 100), i).compress().to_bytes() },
        })
        .collect();
    maki_xmr::request::Input { amount, tx_key: tx_key.compress().to_bytes(), index: 2, subaddress: minor, real: 9, ring }
}

/// An output of the test phrase's account as `K` asks about it: its transaction key, index,
/// subaddress and key.
fn xmr_output(input: &maki_xmr::request::Input) -> Vec<u8> {
    [&input.tx_key[..], &input.index.to_le_bytes(), &0u32.to_le_bytes(), &input.subaddress.to_le_bytes(), &input.ring[input.real].key].concat()
}

#[test]
fn monero_lets_a_computer_watch_once_its_owner_says_so() {
    let (a, b) = (xmr_input(1, 0, 10), xmr_input(2, 4, 20));
    let images = [&[b'K', 2][..], &xmr_output(&a), &xmr_output(&b)].concat();
    let inbox = vec![images.clone(), vec![b'W', 0], vec![b'W', 0], images.clone(), [&[b'K', 1][..], &xmr_output(&xmr_input(3, 1, 5))[4..], &[0; 4]].concat()];
    let r = run_wallet("monero", inbox, vec![Answer::No, Answer::Yes], false);
    // no key images until a computer may watch
    assert_eq!(r.replies[0][0], 5);
    assert_eq!(texts(&r.replies[0]), ["let maki desktop watch this wallet first"]);
    // the owner's no, then yes: the address and the view key
    assert_eq!(r.replies[1], [1]);
    assert_eq!(r.reviews[0].question, "Let computer watch?");
    assert_eq!(r.reviews[1].pages[0].mono, "49vDbkSo7eve3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVF2N4Zn");
    let watch = &r.replies[2];
    assert_eq!((watch[0], watch.len()), (0, 1 + 2 + 95 + 32));
    let view: String = watch[98..].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(view, "0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201");
    // then key images, each with its proof, as the account makes them
    let keys = maki_xmr::Keys::from_spend(maki_xmr::sign::Scalar::from_bytes_mod_order(
        (0..32).map(|i| u8::from_str_radix(&"3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109"[2 * i..2 * i + 2], 16).unwrap()).collect::<Vec<u8>>().try_into().unwrap(),
    ));
    let images = &r.replies[3];
    assert_eq!((images[0], images.len()), (0, 1 + 2 * 96));
    for (i, input) in [&a, &b].into_iter().enumerate() {
        let tx_key = maki_xmr::sign::point(&input.tx_key).unwrap();
        let (image, proof) = keys.key_image_proof(&tx_key, input.index, 0, input.subaddress, &input.ring[input.real].key, &[0; 32]).unwrap();
        assert_eq!(images[1 + 96 * i..1 + 96 * i + 32], image);
        assert_eq!(images[1 + 96 * i + 32..1 + 96 * (i + 1)], proof);
    }
    // an output that isn't the account's gets none
    assert_eq!(r.replies[4][0], 5);
}

/// A Monero request sent to the app in pieces, as maki desktop sends it: `S` messages, then the
/// signed transaction fetched with `G`s.
fn xmr_messages(request: &[u8], fetches: usize) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = request
        .chunks(4000)
        .enumerate()
        .map(|(i, piece)| [&[b'S', 0][..], &(request.len() as u32).to_le_bytes(), &((i * 4000) as u32).to_le_bytes(), piece].concat())
        .collect();
    out.extend((0..fetches).map(|i| [&[b'G'][..], &((i * 4000) as u32).to_le_bytes()].concat()));
    out
}

#[test]
fn monero_signs_what_its_owner_saw() {
    use maki_xmr::request::{read_destination, Payment, Request};
    let to = "8AB7PQPtducdkghYFN2prK3rZ7zPeL9f2REEdqE4WXYbSZr3797Aqti5xAjRsVy4jTdcwMW11GWejQtqk2kNXxj2QZxJwPZ";
    let request = Request {
        network: maki_xmr::Network::Mainnet,
        account: 0,
        fee: 30_000_000,
        change: 470_000_000,
        payments: vec![Payment { address: to.into(), amount: 1_500_000_000_000, destination: read_destination(to).unwrap().1 }],
        inputs: vec![xmr_input(4, 0, 1_000_000_000_000), xmr_input(5, 2, 500_500_000_000)],
    };
    let bytes = request.to_bytes();
    assert!(bytes.len() > 2400);
    let r = run_wallet("monero", xmr_messages(&bytes, 1), vec![Answer::Yes], false);
    let review = &r.reviews[0];
    assert_eq!((review.question.as_str(), review.detail.as_str()), ("Sign and spend", "Total 1.50003 XMR"));
    let pages: Vec<(&str, &str, &str)> = review.pages.iter().map(|p| (p.heading.as_str(), p.value.as_str(), p.mono.as_str())).collect();
    assert_eq!(pages, [("Send", "1.5 XMR", to), ("Change", "0.00047 XMR", "back to you"), ("Fee", "0.00003 XMR", "")]);
    // taken whole, signed, and fetched
    let signed_size = u32::from_le_bytes(r.replies[0][1..5].try_into().unwrap()) as usize;
    assert_eq!(r.replies[0][0], 0);
    let fetched = &r.replies[1];
    assert_eq!((fetched[0], u32::from_le_bytes(fetched[1..5].try_into().unwrap()) as usize), (0, signed_size));
    let signed = maki_xmr::spend::Signed::from_bytes(&fetched[9..]).unwrap();
    let tx = maki_xmr::tx::Transaction::from_bytes(&signed.transaction).unwrap();
    assert_eq!((tx.prefix.inputs.len(), tx.prefix.outputs.len(), tx.base.fee), (2, 2, 30_000_000));
    assert_eq!(signed.own.len(), 1, "the change's key image");

    // a no signs nothing; an output that isn't the account's, maki says so
    let r = run_wallet("monero", xmr_messages(&bytes, 0), vec![Answer::No], false);
    assert_eq!(r.replies, [vec![1u8]]);
    let mut theirs = request.clone();
    theirs.inputs[1].subaddress = 3;
    let r = run_wallet("monero", xmr_messages(&theirs.to_bytes(), 0), vec![Answer::Yes], false);
    assert_eq!((r.replies[0][0], texts(&r.replies[0])), (5, vec!["input 2 isn't this wallet's".to_string()]));
    // not a request: refused before the owner sees anything
    let r = run_wallet("monero", xmr_messages(&bytes[..bytes.len() - 1], 0), vec![Answer::Yes], false);
    assert_eq!((r.replies[0][0], texts(&r.replies[0])), (5, vec!["not a request maki can read".to_string()]));
    assert!(r.reviews.is_empty());
}
