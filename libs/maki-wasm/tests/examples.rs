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
