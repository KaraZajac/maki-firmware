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
    /// keys beyond text pressed, and whether with Shift
    pressed: Vec<(u8, bool)>,
    inbox: VecDeque<Vec<u8>>,
    current: Option<Vec<u8>>,
    replies: Vec<Vec<u8>>,
    qr: Option<String>,
    /// codes the camera reads after `qr`, one a scan
    qrs: VecDeque<String>,
    motion: Option<[i16; 3]>,
    /// readings the accelerometer gives before `motion`, one a read
    motions: VecDeque<[i16; 3]>,
    /// the accelerometer's range, if the app set one
    range: u8,
    /// maki is locked: no wallet keys
    locked: bool,
    /// what wallet apps put on maki's review screen
    reviews: Vec<Review>,
    /// backup words maki showed its owner (never the app)
    backups: Vec<String>,
}

/// The BIP39 test phrase's seed: wallet apps' keys here, as on a maki set up with it.
fn test_seed() -> [u8; 64] {
    let words: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' ')
            .collect();
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

    // the same for every label but the SSH app's certificate authority's, which must differ
    fn app_secret(&mut self, label: &str) -> Option<[u8; 32]> {
        Some(if label == "ssh-ca" { [9; 32] } else { [7; 32] })
    }

    fn type_text(&mut self, text: &str) -> bool {
        self.0.borrow_mut().typed.push(text.into());
        true
    }

    fn press_key(&mut self, code: u8, shift: bool) -> bool {
        self.0.borrow_mut().pressed.push((code, shift));
        true
    }

    fn message(&mut self) -> Option<Vec<u8>> { self.0.borrow().current.clone() }

    fn scan_qr(&mut self) -> Option<String> {
        let mut r = self.0.borrow_mut();
        r.qr.take().or_else(|| r.qrs.pop_front())
    }

    fn motion(&mut self) -> Option<[i16; 3]> {
        let mut r = self.0.borrow_mut();
        r.motions.pop_front().or(r.motion)
    }

    fn motion_range(&mut self, g: u8) -> Option<u8> {
        self.0.borrow_mut().range = g;
        Some(g)
    }

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
            let words = maki_hd::seed::answer(&keys, maki_hd::op::MONERO_WORDS, path, &[], &[0; 32])
                .map_err(|_| NOT_FOUND)?;
            r.backups.push(String::from_utf8(words).unwrap());
        }
        Ok(answer)
    }
}

fn run_fixture(name: &str, events: &[Event], storage: BTreeMap<String, Vec<u8>>) -> (Stop, Record) {
    run_answering(name, events, storage, &[])
}

fn run_answering(
    name: &str,
    events: &[Event],
    storage: BTreeMap<String, Vec<u8>>,
    answers: &[Answer],
) -> (Stop, Record) {
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

fn lit(c: &Canvas) -> usize {
    (0..HEIGHT as i32)
        .flat_map(|y| (0..WIDTH as i32).map(move |x| (x, y)))
        .filter(|&(x, y)| c.get(x, y))
        .count()
}

#[test]
fn hello_says_hello_and_leaves_when_told() {
    let (stop, r) = run_fixture("hello", &[Event::Left, Event::Menu(0)], BTreeMap::new());
    assert_eq!(stop, Stop::Finished);
    // a frame to start, and one after each event before Exit
    assert_eq!(r.frames.len(), 3);
    assert!(lit(&r.frames[0]) > 100);
}

#[test]
fn dice_takes_the_die_from_the_dial_and_how_many_from_left_and_right() {
    // 1d20 at first; the dial down three (d8), two more (3d8), and roll
    let events = [Event::Down, Event::Down, Event::Down, Event::Right, Event::Right, Event::Centre];
    let (stop, r) = run_fixture("dice", &events, BTreeMap::new());
    assert_eq!(stop, Stop::Finished);
    assert_eq!(r.storage["count"], 3u32.to_le_bytes());
    assert_eq!(r.storage["die"], 3u32.to_le_bytes()); // d8: the fourth of d2, d4, d6, d8 ... d20
    // a frame at the start and after each event; the roll's is the dice's with a total
    assert_eq!(r.frames.len(), events.len() + 1);
    assert_ne!(r.frames[5], r.frames[6]);
    // the dice picked are kept: they're what it opens with next time
    let (_, again) = run_fixture("dice", &[], r.storage.clone());
    assert_eq!(again.frames[0], r.frames[5]);
    // the dial stops at d20 and at d2, how many at 1 and at 20
    let (_, top) = run_fixture("dice", &[Event::Up, Event::Left], BTreeMap::new());
    assert!(!top.storage.contains_key("die"), "1d20 stays 1d20");
    let many: Vec<Event> =
        std::iter::repeat_n(Event::Right, 25).chain(std::iter::repeat_n(Event::Down, 9)).collect();
    let (_, r) = run_fixture("dice", &many, BTreeMap::new());
    assert_eq!(r.storage["count"], 20u32.to_le_bytes());
    assert_eq!(r.storage["die"], 0u32.to_le_bytes()); // d2
}

/// Initiative's table as it keeps it: the round, whose turn, whether a turn has passed, and each
/// combatant (name, which of that name, hit points, their most, initiative), in order.
type Fight = (u16, u8, bool, Vec<(u8, u8, u16, u16, u8)>);

fn fight(storage: &BTreeMap<String, Vec<u8>>) -> Fight {
    let b = &storage["table"];
    let all = b[5..]
        .chunks_exact(7)
        .map(|c| (c[0], c[1], u16::from_le_bytes([c[2], c[3]]), u16::from_le_bytes([c[4], c[5]]), c[6]))
        .collect::<Vec<_>>();
    assert_eq!(all.len(), b[4] as usize);
    (u16::from_le_bytes([b[0], b[1]]), b[2], b[3] != 0, all)
}

fn keep_fight(f: &Fight) -> BTreeMap<String, Vec<u8>> {
    let mut b = f.0.to_le_bytes().to_vec();
    b.extend([f.1, f.2 as u8, f.3.len() as u8]);
    for &(name, n, hp, max, init) in &f.3 {
        b.extend([name, n]);
        b.extend(hp.to_le_bytes());
        b.extend(max.to_le_bytes());
        b.push(init);
    }
    BTreeMap::from([("table".to_string(), b)])
}

const FIGHTER: u8 = 0;
const GOBLIN: u8 = 12;
const ORC: u8 = 14;

#[test]
fn initiative_adds_people_in_order_and_rolls_for_them() {
    use Event::*;
    // a Fighter (the form's first name, 10 hit points, a d20 rolled: the counting random's 6);
    // then a Goblin, the dial on from the Fighter, its hit points 7 on the wheels; then another,
    // which the form starts on
    let mut events = vec![Menu(0), Centre, Menu(0)];
    events.extend([Up; 12]);
    events.extend([Right, Right, Down, Right, Down, Down, Down, Centre, Menu(0), Centre]);
    let (stop, r) = run_fixture("initiative", &events, BTreeMap::new());
    assert_eq!(stop, Stop::Finished);
    let (round, turn, passed, all) = fight(&r.storage);
    assert_eq!((round, turn, passed), (1, 0, false));
    // equal initiative: who came first goes first
    assert_eq!(all, [(FIGHTER, 1, 10, 10, 6), (GOBLIN, 1, 7, 7, 6), (GOBLIN, 2, 7, 7, 6)]);
    // the Goblin 2 goes to the top with initiative 16; until a turn has passed, the turn is the top's
    let (_, r) = run_fixture(
        "initiative",
        &[Right, Right, Menu(1), Right, Right, Right, Right, Up, Centre],
        r.storage,
    );
    let (_, turn, _, all) = fight(&r.storage);
    assert_eq!(turn, 0);
    assert_eq!(all[0], (GOBLIN, 2, 7, 7, 16));
    // a Goblin made an Orc is Orc (1); cancel leaves the form with nothing added
    let (_, r) = run_fixture("initiative", &[Right, Right, Menu(1), Up, Up, Centre], r.storage);
    assert_eq!(fight(&r.storage).3[2], (ORC, 1, 7, 7, 6));
    let mut cancel = vec![Menu(0)];
    cancel.extend([Right; 6]);
    cancel.push(Centre);
    let (_, again) = run_fixture("initiative", &cancel, r.storage.clone());
    assert_eq!(fight(&again.storage).3.len(), 3);
    // rolling gives everyone a d20, in order, from the top of round 1
    let (_, r) = run_fixture("initiative", &[Centre, Menu(3)], r.storage);
    let (round, turn, passed, all) = fight(&r.storage);
    assert_eq!((round, turn, passed), (1, 0, false));
    assert!(all.iter().all(|c| c.4 == 6));
}

#[test]
fn initiative_passes_the_turn_and_the_dial_hurts_and_heals() {
    use Event::*;
    let table = (1, 0, false, vec![(FIGHTER, 1, 10, 10, 15), (GOBLIN, 1, 7, 7, 12), (GOBLIN, 2, 7, 7, 8)]);
    // the Fighter (whose turn it is, picked) takes 3 and heals 1; the Goblin takes 9, which is 7
    let mut events = vec![Down, Down, Down, Up, Right];
    events.extend([Down; 9]);
    events.push(Timeout);
    let (stop, r) = run_fixture("initiative", &events, keep_fight(&table));
    assert_eq!(stop, Stop::Finished);
    let (_, _, _, all) = fight(&r.storage);
    assert_eq!((all[0].2, all[1].2, all[2].2), (8, 0, 7));
    // the turn: past the dead Goblin to Goblin 2, then round 2 from the top
    let (_, r) = run_fixture("initiative", &[Centre], r.storage);
    let (round, turn, passed, _) = fight(&r.storage);
    assert_eq!((round, turn, passed), (1, 2, true));
    let (_, r) = run_fixture("initiative", &[Centre], r.storage);
    let (round, turn, passed, _) = fight(&r.storage);
    assert_eq!((round, turn, passed), (2, 0, true));
    // a new fight: the monsters go, the Fighter stays as they are; a long rest heals them
    let (_, r) = run_fixture("initiative", &[Menu(4)], r.storage);
    assert_eq!(fight(&r.storage), (1, 0, false, vec![(FIGHTER, 1, 8, 10, 15)]));
    let (_, r) = run_fixture("initiative", &[Menu(5)], r.storage);
    assert_eq!(fight(&r.storage).3, [(FIGHTER, 1, 10, 10, 15)]);
    // removing whoever's picked; with no one there, the menu's others wait for someone to be added
    let (_, r) = run_fixture("initiative", &[Menu(2)], r.storage);
    assert!(fight(&r.storage).3.is_empty());
    let (_, r) = run_fixture("initiative", &[Menu(3), Menu(4), Menu(5)], r.storage);
    assert_eq!(fight(&r.storage), (1, 0, false, vec![]));
}

#[test]
fn tally_counts_and_keeps_the_count() {
    let (stop, r) =
        run_fixture("tally", &[Event::Centre, Event::Centre, Event::Right, Event::Left], BTreeMap::new());
    assert_eq!(stop, Stop::Finished);
    assert_eq!(r.storage["count"], 11u32.to_le_bytes());
    let (_, r) = run_fixture("tally", &[Event::Left], r.storage);
    assert_eq!(r.storage["count"], 10u32.to_le_bytes());
    // the jog dial counts one up or down
    let (_, r) = run_fixture("tally", &[Event::Up, Event::Up, Event::Down], r.storage);
    assert_eq!(r.storage["count"], 11u32.to_le_bytes());
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
        let record =
            Rc::new(RefCell::new(Record { events: [Event::Centre].into(), storage, ..Default::default() }));
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
    assert_eq!(
        (r.asks[2].question.as_str(), r.asks[2].detail.as_str()),
        ("Sign for git?", "a commit or a tag")
    );
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
        let record = Rc::new(RefCell::new(Record {
            events: events.iter().copied().collect(),
            motion,
            ..Default::default()
        }));
        assert_eq!(run(bundle.code, Box::new(Script(record.clone())), limits), Stop::Finished);
        Rc::try_unwrap(record).ok().unwrap().into_inner()
    };
    let steps = |n: usize| -> Vec<Event> {
        std::iter::once(Event::Centre).chain(std::iter::repeat_n(Event::Timeout, n)).collect()
    };
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
    let bytes =
        std::fs::read(format!("{}/tests/fixtures/breakout.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let asked: Vec<Permission> = bundle.manifest.permissions.iter().map(|(p, _)| *p).collect();
    assert_eq!(asked, [Permission::Motion]);
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let run_with = |motion: Option<[i16; 3]>, events: &[Event]| {
        let record = Rc::new(RefCell::new(Record {
            events: events.iter().copied().collect(),
            motion,
            ..Default::default()
        }));
        assert_eq!(run(bundle.code, Box::new(Script(record.clone())), limits), Stop::Finished);
        Rc::try_unwrap(record).ok().unwrap().into_inner()
    };
    let then = |first: &[Event], n: usize| -> Vec<Event> {
        first.iter().copied().chain(std::iter::repeat_n(Event::Timeout, n)).collect()
    };
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
fn the_eight_ball_answers_a_shake_or_a_press_but_not_a_bump() {
    use maki_bundle::Permission;
    let bytes =
        std::fs::read(format!("{}/tests/fixtures/eightball.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let asked: Vec<Permission> = bundle.manifest.permissions.iter().map(|(p, _)| *p).collect();
    assert_eq!(asked, [Permission::Motion]);
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let run_with = |motion: Option<[i16; 3]>, motions: &[[i16; 3]], events: &[Event]| {
        let record = Rc::new(RefCell::new(Record {
            events: events.iter().copied().collect(),
            motion,
            motions: motions.iter().copied().collect(),
            ..Default::default()
        }));
        assert_eq!(run(bundle.code, Box::new(Script(record.clone())), limits), Stop::Finished);
        Rc::try_unwrap(record).ok().unwrap().into_inner()
    };
    let (level, shaken) = ([0, 0, 1000], [1800, 200, 900]);
    let timeouts = |n: usize| vec![Event::Timeout; n];
    // a press: the triangle rises in three frames, and the answer's in it
    let pressed = run_with(Some(level), &[], &[vec![Event::Centre], timeouts(3)].concat());
    assert_eq!(pressed.frames.len(), 5);
    let answer = &pressed.frames[4];
    assert!(
        lit(&pressed.frames[1]) < lit(&pressed.frames[2])
            && lit(&pressed.frames[2]) < lit(&pressed.frames[3])
    );
    assert!(answer.get(64, 10) && answer.get(10, 105) && answer.get(117, 105) && !answer.get(10, 10));
    assert!((68..94).any(|y| (40..88).any(|x| !answer.get(x, y))));
    // a shake (read at the start, then shaken for four readings and still for seven): the same
    // answer, from the same random numbers
    let mut motions = vec![level];
    motions.extend([shaken; 4]);
    motions.extend([level; 7]);
    let shook = run_with(Some(level), &motions, &timeouts(14));
    assert_eq!(shook.frames.len(), 5);
    assert_eq!(&shook.frames[4], answer);
    // a bump, one reading, is no shake
    let bumped = run_with(Some(level), &[level, shaken], &timeouts(14));
    assert_eq!(bumped.frames.len(), 1);
    // hidden, a press asks nothing; shown again, the answer's back
    let hidden = run_with(Some(level), &[], &[Event::Hidden, Event::Centre, Event::Shown]);
    assert_eq!(hidden.frames.len(), 2);
    assert_eq!(hidden.frames[0], hidden.frames[1]);
    let back = run_with(
        Some(level),
        &[],
        &[vec![Event::Centre], timeouts(3), vec![Event::Hidden, Event::Shown]].concat(),
    );
    assert_eq!(back.frames.len(), 6);
    assert_eq!(&back.frames[5], answer);
    // without an accelerometer, it says to press, and a press answers
    let none = run_with(None, &[], &[vec![Event::Left], timeouts(3)].concat());
    assert_ne!(none.frames[0], pressed.frames[0]);
    assert_eq!(&none.frames[4], answer);
}

/// A command for the Sudo app to approve, as maki desktop's sudo plugin sends it (after its `R`).
#[allow(clippy::too_many_arguments)]
fn sudo_request(
    nonce: u8,
    runas: &[u8],
    group: &[u8],
    tty: &[u8],
    sudoedit: u8,
    command: &[u8],
    argv: &[&[u8]],
    env: &[&[u8]],
) -> Vec<u8> {
    let s8 = |out: &mut Vec<u8>, b: &[u8]| {
        out.push(b.len() as u8);
        out.extend(b);
    };
    let s16 = |out: &mut Vec<u8>, b: &[u8]| {
        out.extend((b.len() as u16).to_le_bytes());
        out.extend(b);
    };
    let mut out = vec![nonce; 32];
    for part in [&b"laptop"[..], b"kara", runas, group] {
        s8(&mut out, part);
    }
    s16(&mut out, b"/home/kara");
    s16(&mut out, b"");
    s8(&mut out, tty);
    out.extend([sudoedit.min(1), sudoedit]);
    s16(&mut out, command);
    for list in [argv, env] {
        out.push(list.len() as u8);
        for item in list {
            s16(&mut out, item);
        }
    }
    out
}

#[test]
fn sudo_shows_each_command_whole_and_signs_the_request_once_asked() {
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let signed = |body: &[u8]| [&b"maki sudo approval\0"[..], body].concat();
    let asked = |messages: &[Vec<u8>], answers: &[Answer]| {
        let record = Rc::new(RefCell::new(Record {
            events: messages.iter().map(|_| Event::Message).collect(),
            inbox: messages.iter().cloned().collect(),
            answers: answers.iter().copied().collect(),
            ..Default::default()
        }));
        let bytes =
            std::fs::read(format!("{}/tests/fixtures/sudo.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let bundle = maki_bundle::read(&bytes).unwrap();
        assert_eq!(bundle.manifest.api, 7);
        let limits = admit(&bundle.manifest, bundle.code).unwrap();
        assert_eq!(run(bundle.code, Box::new(Script(record.clone())), limits), Stop::Finished);
        Rc::try_unwrap(record).ok().unwrap().into_inner()
    };
    let r = |body: &[u8]| [&b"R"[..], body].concat();

    // its key, for the plugin's key file
    let got = asked(&[b"P".to_vec()], &[]);
    assert_eq!(got.replies[0], [&[0u8][..], key.as_bytes()].concat());

    // a command, shown whole, and signed with the request once the owner says yes
    let plain = sudo_request(
        1,
        b"root",
        b"",
        b"/dev/pts/3",
        0,
        b"/usr/bin/systemctl",
        &[b"systemctl", b"restart", b"nginx"],
        &[],
    );
    let got = asked(&[r(&plain)], &[Answer::Yes]);
    let review = &got.reviews[0];
    assert_eq!((review.question.as_str(), review.detail.as_str()), ("Run it as root?", "sudo on laptop"));
    assert_eq!((review.yes.as_str(), review.no.as_str(), review.timeout_s), ("run", "deny", 60));
    assert_eq!(
        review.pages,
        [
            Page {
                heading: "Command".into(),
                value: "systemctl".into(),
                mono: "/usr/bin/systemctl restart nginx".into(),
                prose: String::new()
            },
            Page {
                heading: "Asked by".into(),
                value: "kara".into(),
                prose: "on laptop, in /home/kara, at /dev/pts/3".into(),
                ..Page::default()
            },
        ]
    );
    assert_eq!((got.replies[0][0], got.replies[0].len()), (0, 65));
    let signature = Signature::from_slice(&got.replies[0][1..]).unwrap();
    key.verify(&signed(&plain), &signature).unwrap();
    // it's of that request: another nonce, another command, and it isn't
    let other = sudo_request(
        2,
        b"root",
        b"",
        b"/dev/pts/3",
        0,
        b"/usr/bin/systemctl",
        &[b"systemctl", b"restart", b"nginx"],
        &[],
    );
    assert!(key.verify(&signed(&other), &signature).is_err());
    assert_eq!(got.storage["approved"], 1u32.to_le_bytes());

    // what it's given to run with; anything that isn't plain, quoted as a shell would take it
    // back; and what a login shell's told it's called
    let preload =
        sudo_request(3, b"root", b"", b"", 0, b"/usr/bin/true", &[b"true"], &[b"LD_PRELOAD=/tmp/x.so"]);
    let odd = sudo_request(
        4,
        b"root",
        b"wheel",
        b"",
        0,
        b"/usr/bin/rm",
        &[b"rm", b"-rf", b"it's here", b"a\nb\xc3\xa9", b""],
        &[],
    );
    let shell = sudo_request(5, b"postgres", b"", b"", 0, b"/bin/bash", &[b"-bash"], &[]);
    let edit = sudo_request(
        6,
        b"root",
        b"",
        b"",
        2,
        b"/usr/bin/vi",
        &[b"vi", b"--", b"/etc/hosts", b"/etc/my file"],
        &[],
    );
    let got = asked(
        &[r(&preload), r(&odd), r(&shell), r(&edit)],
        &[Answer::Yes, Answer::No, Answer::NoAnswer, Answer::Yes],
    );
    assert_eq!(
        got.reviews[0].pages[1],
        Page {
            heading: "Given".into(),
            mono: "LD_PRELOAD=/tmp/x.so".into(),
            prose: "set for it, beyond what every command gets".into(),
            ..Page::default()
        }
    );
    assert_eq!(got.reviews[1].pages[0].mono, r#"/usr/bin/rm -rf 'it'\''s here' $'a\nb\xc3\xa9' ''"#);
    assert_eq!(got.reviews[1].pages[1].prose, "on laptop, in /home/kara; with the group wheel");
    assert_eq!(got.reviews[2].question, "Run it as postgres?");
    assert_eq!(got.reviews[2].pages[0].prose, "It's told it's called -bash.");
    assert_eq!((got.reviews[3].question.as_str(), got.reviews[3].yes.as_str()), ("Edit as root?", "edit"));
    assert_eq!(
        got.reviews[3].pages[0],
        Page {
            heading: "Edit".into(),
            mono: "/etc/hosts\n'/etc/my file'".into(),
            prose: "Copied for kara to edit with vi, then back.".into(),
            ..Page::default()
        }
    );
    // a yes, a no, no answer, a yes
    assert_eq!(got.replies.iter().map(|a| a[0]).collect::<Vec<_>>(), [0, 1, 2, 0]);
    key.verify(&signed(&preload), &Signature::from_slice(&got.replies[0][1..]).unwrap()).unwrap();
    key.verify(&signed(&edit), &Signature::from_slice(&got.replies[3][1..]).unwrap()).unwrap();
    assert_eq!(got.replies[1].len(), 1);

    // what it can't read, or can't show whole, it turns down without asking
    let mut long = vec![&b"rm"[..]];
    long.extend(std::iter::repeat_n(&[1u8; 10][..], 250));
    let too_long = sudo_request(7, b"root", b"", b"", 0, b"/usr/bin/rm", &long, &[]);
    let mut trailing = plain.clone();
    trailing.push(0);
    let bad = [
        r(&too_long),
        r(&trailing),
        r(&plain[..plain.len() - 1]),
        r(&sudo_request(8, b"root", b"", b"", 0, b"/usr/bin/true", &[], &[])),
        r(&sudo_request(8, b"", b"", b"", 0, b"/usr/bin/true", &[b"true"], &[])),
        r(&sudo_request(8, b"root", b"", b"", 1, b"/usr/bin/vi", &[b"vi"], &[])),
        b"Q".to_vec(),
        b"PP".to_vec(),
    ];
    let got = asked(&bad, &[Answer::Yes; 8]);
    assert!(got.reviews.is_empty(), "{:?}", got.reviews);
    assert!(got.replies.iter().all(|a| a[..] == [4]), "{:?}", got.replies);
}

#[test]
fn minisign_signs_a_hash_and_its_own_trusted_comment_once_asked() {
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    let bytes =
        std::fs::read(format!("{}/tests/fixtures/minisign.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
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
    let inbox = vec![
        b"P".to_vec(),
        sign("maki-0.2.0.tar.gz", ""),
        sign("notes.txt", "release 0.2"),
        sign("other.bin", ""),
        sign("../etc/passwd", ""),
    ];
    let record = Rc::new(RefCell::new(Record {
        events: std::iter::repeat_n(Event::Message, inbox.len()).collect(),
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

#[test]
fn the_ssh_app_signs_certificates_with_its_ca_key_once_that_is_on() {
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(format!("{}/tests/fixtures/ssh.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let blob_of = |k: &SigningKey| {
        let mut b = Vec::new();
        ssh_string(&mut b, b"ssh-ed25519");
        ssh_string(&mut b, k.verifying_key().as_bytes());
        b
    };
    let (user, ca) = (SigningKey::from_bytes(&[7; 32]), SigningKey::from_bytes(&[9; 32]));
    let (user_blob, ca_blob) = (blob_of(&user), blob_of(&ca));
    // a user certificate for someone's key, for kara and root, until 1 Jan 2027, signed by the CA
    let cert = |signer: &[u8], principals: &[&str], options: &[u8]| {
        let mut c = Vec::new();
        ssh_string(&mut c, b"ssh-ed25519-cert-v01@openssh.com");
        ssh_string(&mut c, &[1; 32]);
        ssh_string(&mut c, &[5; 32]);
        c.extend_from_slice(&7u64.to_be_bytes());
        c.extend_from_slice(&1u32.to_be_bytes());
        ssh_string(&mut c, b"laptop");
        let mut p = Vec::new();
        for name in principals {
            ssh_string(&mut p, name.as_bytes());
        }
        ssh_string(&mut c, &p);
        c.extend_from_slice(&0u64.to_be_bytes());
        c.extend_from_slice(&1_798_761_600u64.to_be_bytes());
        ssh_string(&mut c, options);
        ssh_string(&mut c, b"");
        ssh_string(&mut c, b"");
        ssh_string(&mut c, signer);
        c
    };
    let sign = |key: &[u8], data: &[u8]| {
        let mut body = Vec::new();
        ssh_string(&mut body, key);
        ssh_string(&mut body, data);
        body.extend_from_slice(&0u32.to_be_bytes());
        agent(3, 13, &body)
    };
    let mut forced = Vec::new();
    ssh_string(&mut forced, b"force-command");
    ssh_string(&mut forced, b"\0\0\0\x04true");
    let inbox = vec![
        // before the CA key is on: it isn't offered, and doesn't sign
        agent(3, 11, &[]),
        sign(&ca_blob, &cert(&ca_blob, &["kara", "root"], b"")),
        agent(3, 11, &[]),
        sign(&ca_blob, &cert(&ca_blob, &["kara", "root"], b"")),
        sign(&ca_blob, &cert(&ca_blob, &[], &forced)),
        // not certificates, or not the CA's: refused without asking
        sign(&ca_blob, b"SSHSIG anything"),
        sign(&ca_blob, &cert(&user_blob, &["kara"], b"")),
    ];
    let record = Rc::new(RefCell::new(Record {
        events: [Event::Message, Event::Message, Event::Menu(1)]
            .into_iter()
            .chain(std::iter::repeat_n(Event::Message, 5))
            .collect(),
        inbox: inbox.into_iter().collect(),
        answers: [Answer::Yes, Answer::Yes].into_iter().collect(),
        ..Default::default()
    }));
    assert_eq!(run(bundle.code, Box::new(Script(record.clone())), limits), Stop::Finished);
    let r = record.borrow();
    assert_eq!(r.menu, ["Show the key", "Show the CA key", "Stop the CA key"]);
    assert_eq!(r.storage["ca"], 1u32.to_le_bytes());
    // off: one key; on: the CA's too, named apart
    assert_eq!(&r.replies[0][..5], &[12, 0, 0, 0, 1]);
    assert_eq!(r.replies[1], [5]);
    assert_eq!(&r.replies[2][..5], &[12, 0, 0, 0, 2]);
    let (_, rest) = read_string(&r.replies[2][5..]);
    let (_, rest) = read_string(rest);
    let (listed, rest) = read_string(rest);
    assert_eq!(listed, &ca_blob[..]);
    assert_eq!(read_string(rest).0, b"maki CA");
    // signed with the CA's key, once the owner read it
    let verify = |answer: &[u8], data: &[u8]| {
        assert_eq!(answer[0], 14, "{answer:?}");
        let (sig_blob, _) = read_string(&answer[1..]);
        let (_, rest) = read_string(sig_blob);
        ca.verifying_key().verify(data, &Signature::from_slice(read_string(rest).0).unwrap()).unwrap();
    };
    verify(&r.replies[3], &cert(&ca_blob, &["kara", "root"], b""));
    assert_eq!(r.asks[0].question, "Sign a user certificate?");
    let key_fp = {
        let mut b = Vec::new();
        ssh_string(&mut b, b"ssh-ed25519");
        ssh_string(&mut b, &[5; 32]);
        format!("SHA256:{}", b64(&Sha256::digest(&b)))
    };
    assert_eq!(r.asks[0].detail, format!("for kara,root (laptop), until 1 Jan 2027, key {}", &key_fp[..19]));
    // no principals is anyone at all, and restrictions are said
    verify(&r.replies[4], &cert(&ca_blob, &[], &forced));
    assert!(
        r.asks[1].detail.starts_with("for EVERY user (laptop), until 1 Jan 2027, restricted, key"),
        "{}",
        r.asks[1].detail
    );
    assert_eq!(r.replies[5..], [vec![5], vec![5]]);
    assert_eq!(r.asks.len(), 2);
}

#[test]
fn the_ssh_app_signs_a_commit_it_was_sent_whole_showing_what_it_is() {
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    use sha2::Digest;
    let bytes = std::fs::read(format!("{}/tests/fixtures/ssh.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let public = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let commit = format!(
        "tree {}\nparent {}\nauthor Kara Zajac <kara@soulstone.org> 1790000000 -0400\ncommitter Kara Zajac <kara@soulstone.org> 1790000000 -0400\n\nFix the fee's rounding\n\n{}",
        "a".repeat(40),
        "b".repeat(40),
        "A long body. ".repeat(500)
    );
    let tag = "object 0123456789012345678901234567890123456789\ntype commit\ntag v1.0\ntagger Kara Zajac <kara@soulstone.org> 1790000000 -0400\n\nmaki 1.0\n";
    // the pieces maki-ssh-keygen sends: the namespace, the whole length, where each starts
    let pieces = |namespace: &str, whole: &[u8], size: usize| -> Vec<Vec<u8>> {
        whole
            .chunks(size)
            .enumerate()
            .map(|(i, piece)| {
                let mut body = Vec::new();
                ssh_string(&mut body, namespace.as_bytes());
                body.extend_from_slice(&(whole.len() as u32).to_be_bytes());
                body.extend_from_slice(&((i * size) as u32).to_be_bytes());
                body.extend_from_slice(piece);
                agent(0, 240, &body)
            })
            .collect()
    };
    let mut inbox = pieces("git", commit.as_bytes(), 3000);
    let n = inbox.len();
    inbox.extend(pieces("git", tag.as_bytes(), 3000));
    // a piece out of its place ends it
    let mut wrong = pieces("git", tag.as_bytes(), 40);
    wrong.remove(1);
    inbox.extend(wrong.into_iter().take(2));
    let record = Rc::new(RefCell::new(Record {
        events: std::iter::repeat_n(Event::Message, inbox.len()).collect(),
        inbox: inbox.into_iter().collect(),
        answers: [Answer::Yes, Answer::Yes].into_iter().collect(),
        ..Default::default()
    }));
    assert_eq!(run(bundle.code, Box::new(Script(record.clone())), limits), Stop::Finished);
    let r = record.borrow();
    // each piece but the last taken; the last signed, as ssh-keygen -Y sign signs
    for reply in &r.replies[..n - 1] {
        assert_eq!(reply, &[6]);
    }
    let sshsig = |message: &[u8]| {
        let mut d = b"SSHSIG".to_vec();
        ssh_string(&mut d, b"git");
        ssh_string(&mut d, b"");
        ssh_string(&mut d, b"sha512");
        ssh_string(&mut d, &sha2::Sha512::digest(message));
        d
    };
    let verify = |answer: &[u8], data: &[u8]| {
        assert_eq!(answer[0], 14, "{answer:?}");
        let (sig_blob, _) = read_string(&answer[1..]);
        let (_, rest) = read_string(sig_blob);
        public.verify(data, &Signature::from_slice(read_string(rest).0).unwrap()).unwrap();
    };
    verify(&r.replies[n - 1], &sshsig(commit.as_bytes()));
    assert_eq!(
        (r.asks[0].question.as_str(), r.asks[0].detail.as_str()),
        ("Sign this commit?", "\"Fix the fee's rounding\" by Kara Zajac")
    );
    verify(&r.replies[n], &sshsig(tag.as_bytes()));
    assert_eq!(
        (r.asks[1].question.as_str(), r.asks[1].detail.as_str()),
        ("Sign tag v1.0?", "\"maki 1.0\" by Kara Zajac")
    );
    assert_eq!(r.replies[n + 1..], [vec![6], vec![5]]);
    assert_eq!(r.asks.len(), 2);
}

#[test]
fn notes_keeps_what_its_owner_says_yes_to_and_shows_it_on_maki_alone() {
    let bytes = std::fs::read(format!("{}/tests/fixtures/notes.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let add = |title: &str, text: &str| {
        [&[b'A', title.len() as u8][..], title.as_bytes(), text.as_bytes()].concat()
    };
    let run_with = |events: Vec<Event>,
                    inbox: Vec<Vec<u8>>,
                    answers: Vec<Answer>,
                    qr: Option<&str>,
                    storage: BTreeMap<String, Vec<u8>>| {
        let record = Rc::new(RefCell::new(Record {
            events: events.into_iter().collect(),
            inbox: inbox.into_iter().collect(),
            answers: answers.into_iter().collect(),
            qr: qr.map(String::from),
            storage,
            ..Default::default()
        }));
        assert_eq!(run(bundle.code, Box::new(Script(record.clone())), limits), Stop::Finished);
        Rc::try_unwrap(record).ok().unwrap().into_inner()
    };
    // from the computer: kept once the owner says yes, and listed by title alone
    let r = run_with(
        vec![Event::Message; 6],
        vec![
            b"L".to_vec(),
            add("Bank PIN", "1234\n5678"),
            add("Safe", "12-34-56"),
            add("", "x"),
            add("Bad\ttitle", "x"),
            b"L".to_vec(),
        ],
        vec![Answer::Yes, Answer::No],
        None,
        BTreeMap::new(),
    );
    assert_eq!(r.menu, ["Scan a note", "Type it", "Delete it"]);
    assert_eq!(r.replies, [vec![0], vec![0], vec![1], vec![4], vec![4], b"\0Bank PIN\n".to_vec()]);
    assert_eq!(r.asks.len(), 2);
    assert_eq!(
        (r.asks[0].question.as_str(), r.asks[0].detail.as_str()),
        ("Keep a note from the computer?", "\"Bank PIN\", 9 characters")
    );
    assert_eq!(r.storage["n:1"], b"Bank PIN\n1234\n5678");
    // opened on maki, and typed into a field once the centre says so: it presses Enter once
    let kept = r.storage.clone();
    let r = run_with(vec![Event::Centre, Event::Menu(1), Event::Centre], vec![], vec![], None, kept.clone());
    assert_eq!(r.typed, ["1234\n5678"]);
    assert_ne!(r.frames[2], r.frames[1]);
    // deleted, once the centre says so; left keeps it
    let r = run_with(vec![Event::Centre, Event::Menu(2), Event::Left], vec![], vec![], None, kept.clone());
    assert!(r.storage.contains_key("n:1"));
    let r = run_with(vec![Event::Centre, Event::Menu(2), Event::Centre], vec![], vec![], None, kept);
    assert!(!r.storage.contains_key("n:1"));
    // scanned: one line is its title and its text; more, the first line its title
    let r = run_with(vec![Event::Menu(0)], vec![], vec![], Some("ABCD-EFGH-IJKL"), BTreeMap::new());
    assert_eq!(r.storage["n:1"], b"ABCD-EFGH-IJKL\nABCD-EFGH-IJKL");
    let r = run_with(
        vec![Event::Menu(0)],
        vec![],
        vec![],
        Some("GitHub codes\nabcd-1234\nefgh-5678"),
        BTreeMap::new(),
    );
    assert_eq!(r.storage["n:1"], b"GitHub codes\nabcd-1234\nefgh-5678");
}

/// RFC 9285's base45, as maki cards' QR codes carry them.
fn base45(data: &[u8]) -> String {
    const B45: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    let mut out = String::new();
    for pair in data.chunks(2) {
        let (mut n, digits) =
            if pair.len() == 2 { ((pair[0] as u32) << 8 | pair[1] as u32, 3) } else { (pair[0] as u32, 2) };
        for _ in 0..digits {
            out.push(B45[(n % 45) as usize] as char);
            n /= 45;
        }
    }
    out
}

/// The QR code on an app's screen, read as maki's camera reads one (rqrr, as bao-video has it).
fn read_qr(c: &Canvas) -> Option<String> {
    let scale = 4;
    let margin = 16;
    let (w, h) = (WIDTH * scale + 2 * margin, HEIGHT * scale + 2 * margin);
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| {
        let (x, y) = (x as i32 - margin as i32, y as i32 - margin as i32);
        // a lit pixel is light: a QR code's dark modules are the unlit ones
        let lit = x >= 0 && y >= 0 && c.get(x / scale as i32, y / scale as i32);
        if lit || x < 0 || y < 0 || x >= (WIDTH * scale) as i32 || y >= (HEIGHT * scale) as i32 {
            255
        } else {
            0
        }
    });
    let grids = img.detect_grids();
    grids.first()?.decode().ok().map(|(_, text)| text)
}

#[test]
fn contacts_swaps_signed_cards_and_keeps_who_you_met() {
    use ed25519_dalek::{Signer, SigningKey};
    let bytes =
        std::fs::read(format!("{}/tests/fixtures/contacts.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let card = |name: &str, lines: &[&str]| {
        let mut b = vec![1, name.len() as u8];
        b.extend_from_slice(name.as_bytes());
        b.push(lines.len() as u8);
        for l in lines {
            b.push(l.len() as u8);
            b.extend_from_slice(l.as_bytes());
        }
        b
    };
    // someone else's maki card, as their maki signs it
    let theirs = SigningKey::from_bytes(&[3; 32]);
    let signed_code = |body: &[u8]| {
        let mut b = body.to_vec();
        b.extend_from_slice(theirs.verifying_key().as_bytes());
        let sig = theirs.sign(&b);
        b.extend_from_slice(&sig.to_bytes());
        format!("MAKI1:{}", base45(&b))
    };
    let alex = card("Alex Chen", &["@alex@hackers.town", "alex.example"]);
    let run_with = |events: Vec<Event>,
                    inbox: Vec<Vec<u8>>,
                    answers: Vec<Answer>,
                    qr: Option<String>,
                    storage: BTreeMap<String, Vec<u8>>| {
        let record = Rc::new(RefCell::new(Record {
            events: events.into_iter().collect(),
            inbox: inbox.into_iter().collect(),
            answers: answers.into_iter().collect(),
            qr,
            storage,
            ..Default::default()
        }));
        assert_eq!(run(bundle.code, Box::new(Script(record.clone())), limits), Stop::Finished);
        Rc::try_unwrap(record).ok().unwrap().into_inner()
    };
    // your card, from maki desktop, once you say yes
    let mine = card("Kara Zajac", &["kara@soulstone.org"]);
    let r = run_with(
        vec![Event::Message],
        vec![[&[b'C'][..], &mine].concat()],
        vec![Answer::Yes],
        None,
        BTreeMap::new(),
    );
    assert_eq!(r.replies, [vec![0]]);
    assert_eq!(
        (r.asks[0].question.as_str(), r.asks[0].detail.as_str()),
        ("Make this your card?", "Kara Zajac: kara@soulstone.org")
    );
    assert_eq!(r.storage["card"], mine);
    // shown as a QR code another maki reads, and keeps as signed by this one's key
    let code = read_qr(r.frames.last().unwrap()).expect("a QR code maki's camera reads");
    assert!(code.starts_with("MAKI1:"), "{code}");
    let r2 = run_with(vec![Event::Menu(0)], vec![], vec![], Some(code), BTreeMap::new());
    let (_, kept) = r2.storage.iter().find(|(k, _)| k.starts_with("p:")).expect("kept");
    assert_eq!(kept[0], 1);
    assert_eq!(&kept[11 + mine.len()..], SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes());
    // a maki card, checked and kept as signed; a changed one, not at all
    let r = run_with(vec![Event::Menu(0)], vec![], vec![], Some(signed_code(&alex)), BTreeMap::new());
    let (key, kept) = r.storage.iter().find(|(k, _)| k.starts_with("p:")).expect("kept");
    assert_eq!(
        key,
        &format!(
            "p:{}",
            theirs.verifying_key().as_bytes()[..8].iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    );
    assert_eq!(kept[0], 1);
    assert_eq!(&kept[11..11 + alex.len()], &alex[..]);
    assert_eq!(&kept[11 + alex.len()..], theirs.verifying_key().as_bytes());
    let people = r.storage.clone();
    let mut changed = signed_code(&alex).into_bytes();
    changed[10] = if changed[10] == b'A' { b'B' } else { b'A' };
    let r = run_with(
        vec![Event::Menu(0)],
        vec![],
        vec![],
        Some(String::from_utf8(changed).unwrap()),
        BTreeMap::new(),
    );
    assert!(!r.storage.keys().any(|k| k.starts_with("p:")));
    // a phone's vCard, kept as unsigned
    let vcard = "BEGIN:VCARD\nVERSION:3.0\nN:Doe;Jane\nTEL:+1 555 0100\nEMAIL:jane@example.org\nEND:VCARD";
    let r = run_with(vec![Event::Menu(0)], vec![], vec![], Some(vcard.into()), people.clone());
    let jane = r.storage.iter().find(|(k, _)| k.starts_with("p:u")).expect("kept").1;
    assert_eq!(jane[0], 0);
    assert_eq!(&jane[11..], &card("Jane Doe", &["+1 555 0100", "jane@example.org"])[..]);
    // who you met, for the computer, once you say yes
    let everyone = r.storage.clone();
    let r = run_with(
        vec![Event::Message, Event::Message],
        vec![b"P".to_vec(), b"P".to_vec()],
        vec![Answer::No, Answer::Yes],
        None,
        everyone.clone(),
    );
    assert_eq!(r.replies[0], [1]);
    assert_eq!(r.replies[1][0], 0);
    assert_eq!(
        r.replies[1].len(),
        1 + (11 + alex.len() + 32) + (11 + card("Jane Doe", &["+1 555 0100", "jane@example.org"]).len())
    );
    assert_eq!(r.asks[1].question, "Share who you met with the computer?");
    // forgotten, from the menu, with someone open
    let r = run_with(vec![Event::Centre, Event::Centre, Event::Menu(3)], vec![], vec![], None, everyone);
    assert_eq!(r.storage.keys().filter(|k| k.starts_with("p:")).count(), 1);
}

#[test]
fn openpgp_names_its_key_and_signs_a_commit_it_was_sent_whole() {
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(format!("{}/tests/fixtures/openpgp.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let commit = b"tree 0123456789012345678901234567890123456789\nauthor Kara Zajac <kara@example.org> 1790000000 +0000\ncommitter Kara Zajac <kara@example.org> 1790000000 +0000\n\nSign with OpenPGP on maki\n";
    let sign = [&b"S"[..], &(commit.len() as u32).to_le_bytes(), &0u32.to_le_bytes(), &commit[..]].concat();
    // a session key packet for another key: refused without asking
    let other = [&b"D\x03"[..], &[9; 8], &[18, 1, 7], &[0x40; 33], &[40], &[0; 40]].concat();
    let inbox = vec![
        b"K".to_vec(),
        b"UKara Zajac <kara@example.org>".to_vec(),
        b"K".to_vec(),
        b"F".to_vec(),
        sign,
        other,
    ];
    let record = Rc::new(RefCell::new(Record {
        events: std::iter::repeat_n(Event::Message, inbox.len()).collect(),
        inbox: inbox.into_iter().collect(),
        answers: [Answer::Yes, Answer::Yes].into_iter().collect(),
        ..Default::default()
    }));
    assert_eq!(run(bundle.code, Box::new(Script(record.clone())), limits), Stop::Finished);
    let r = record.borrow();
    // no name, no key to hand out; named once the owner says so
    assert_eq!(r.replies[0], [5]);
    assert_eq!(r.replies[1], [0]);
    assert_eq!(
        (r.asks[0].question.as_str(), r.asks[0].detail.as_str()),
        ("Name your OpenPGP key?", "Kara Zajac <kara@example.org>")
    );
    let key = &r.replies[2];
    assert_eq!(key[0], 0);
    // the public key packet first (new format, tag 6): Ed25519's, dated 2026-01-01, maki's key
    assert_eq!(&key[1..4], &[0xc6, 51, 4]);
    assert_eq!(&key[4..8], &1_767_225_600u32.to_be_bytes());
    let public = SigningKey::from_bytes(&[7; 32]).verifying_key();
    // after the version, the date, the algorithm, the curve and the key's bit count: 0x40, then the key
    assert_eq!(&key[21..54], &[&[0x40][..], public.as_bytes()].concat()[..]);
    // its fingerprint, as SHA-1 of the key packet says
    let body = &key[3..3 + 51];
    let mut h = sha1_smol::Sha1::new();
    h.update(&[0x99, 0, 51]);
    h.update(body);
    assert_eq!(&r.replies[3][1..21], &h.digest().bytes());
    // the commit, read on maki by its subject, signed as OpenPGP signs a binary document
    assert_eq!(
        (r.asks[1].question.as_str(), r.asks[1].detail.as_str()),
        ("Sign this commit?", "\"Sign with OpenPGP on maki\" by Kara Zajac")
    );
    let sig = &r.replies[4];
    assert_eq!(sig[0], 0);
    let p = &sig[1..];
    let (len, at) = if p[1] < 192 { (p[1] as usize, 2) } else { panic!("a short signature") };
    let body = &p[at..at + len];
    assert_eq!(&body[..4], &[4, 0x00, 22, 8]);
    let hashed_len = u16::from_be_bytes([body[4], body[5]]) as usize;
    let head = &body[..6 + hashed_len];
    let mut digest = Sha256::new();
    digest.update(commit);
    digest.update(head);
    digest.update([0x04, 0xff]);
    digest.update((head.len() as u32).to_be_bytes());
    let digest = digest.finalize();
    let unhashed_len = u16::from_be_bytes([body[6 + hashed_len], body[7 + hashed_len]]) as usize;
    let rest = &body[8 + hashed_len + unhashed_len..];
    assert_eq!(&rest[..2], &digest[..2]);
    // r and s, 256 bits each (or fewer, their leading zeros left off)
    let rn = (u16::from_be_bytes([rest[2], rest[3]]) as usize).div_ceil(8);
    let r_bytes = &rest[4..4 + rn];
    let sn = (u16::from_be_bytes([rest[4 + rn], rest[5 + rn]]) as usize).div_ceil(8);
    let s_bytes = &rest[6 + rn..6 + rn + sn];
    let pad = |b: &[u8]| [vec![0; 32 - b.len()], b.to_vec()].concat();
    let signature = Signature::from_slice(&[pad(r_bytes), pad(s_bytes)].concat()).unwrap();
    public.verify(&digest, &signature).unwrap();
    // not for this key: no ask
    assert_eq!(r.replies[5], [4]);
    assert_eq!(r.asks.len(), 2);
}

fn words_list() -> Vec<String> {
    std::fs::read_to_string(format!(
        "{}/../../sdk/examples/passphrase/src/words.txt",
        env!("CARGO_MANIFEST_DIR")
    ))
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
    let typed: Vec<Vec<&str>> =
        r.typed.iter().zip([" ", "-", "-"]).map(|(t, sep)| t.split(sep).collect()).collect();
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
    events.push(Event::Up);
    events.extend([Event::Timeout; 13]);
    let (stop, r) = run_fixture("snake", &events, BTreeMap::new());
    assert_eq!(stop, Stop::Finished);
    // it ate once before the wall: its best is 1
    assert_eq!(r.storage.get("best").unwrap(), &1u32.to_le_bytes());
    // five cells long at the end, not four: the field (below the score) of the last frame of
    // play has one cell more lit than the first, 3 by 3 pixels
    let field = |c: &Canvas| {
        (12..HEIGHT as i32)
            .flat_map(|y| (0..WIDTH as i32).map(move |x| (x, y)))
            .filter(|&(x, y)| c.get(x, y))
            .count()
    };
    let frames = &r.frames;
    assert_eq!(field(&frames[frames.len() - 2]), field(&frames[2]) + 9);

    // no food, no best: straight into the wall
    let mut events = vec![Event::Centre];
    events.extend([Event::Timeout; 25]);
    let (_, r) = run_fixture("snake", &events, BTreeMap::new());
    assert!(!r.storage.contains_key("best"));
}

#[test]
fn snake_goes_the_way_pressed_but_never_straight_back() {
    // going right, head at 10 across: left (straight back) is no turn; two on, down then left
    // make a U-turn onto the row below, and it's still going
    let mut events = vec![Event::Centre];
    events.extend([Event::Timeout; 3]);
    events.push(Event::Left);
    events.extend([Event::Timeout; 2]);
    events.extend([Event::Down, Event::Left]);
    events.extend([Event::Timeout; 4]);
    let (stop, r) = run_fixture("snake", &events, BTreeMap::new());
    assert_eq!(stop, Stop::Finished);
    // the last frame of play: all four cells on row 13, 9 to 12 across, none left on row 12
    let last = &r.frames[r.frames.len() - 1];
    let cell = |x: i32, y: i32| last.get(2 + x * 4, 13 + y * 4);
    assert!((9..=12).all(|x| cell(x, 13)));
    assert!(!cell(8, 13) && !cell(13, 13) && (4..=13).all(|x| !cell(x, 12)));
}

#[test]
fn status_shows_what_the_computer_says_and_says_what_it_shows() {
    let msg = |s: &str| s.as_bytes().to_vec();
    let events = [
        Event::Message,
        Event::Message,
        Event::Message,
        Event::Message,
        Event::Right,
        Event::Centre,
        Event::Message,
    ];
    let record = Rc::new(RefCell::new(Record {
        events: events.iter().copied().collect(),
        inbox: [msg("on A call"), msg(""), msg("  Back \n at\t3 "), msg("")]
            .into_iter()
            .chain([msg("")])
            .collect(),
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
    assert!(lit(last) > (WIDTH * HEIGHT) / 2, "light: more lit than not");
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
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), shared.as_bytes())
        .expand(b"age-encryption.org/v1/X25519", &mut wrap)
        .unwrap();
    let body = chacha20poly1305::ChaCha20Poly1305::new(&wrap.into())
        .encrypt(&Default::default(), file_key.as_slice())
        .unwrap();
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
    let r =
        run_with(vec![find, unwrap(&mine), unwrap(&theirs), unwrap(&mine)], vec![Answer::Yes, Answer::No]);
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
        events: [
            Event::Menu(0),
            Event::Message,
            Event::Message,
            Event::Message,
            Event::Menu(2),
            Event::Message,
        ]
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
    assert_eq!(
        replies,
        ["ok", "maki guests\nCafe;Bar\n", "that isn't a network: a WIFI: text with a name", "maki guests\n"]
    );
    // kept as its QR code had it, for the next time
    assert_eq!(r.storage.get("networks").unwrap(), b"WIFI:T:WPA;S:maki guests;P:correct horse;;\n");
}

#[test]
fn bitcoin_signs_a_psbt_read_off_a_screen_and_shows_it_back() {
    let psbt = std::fs::read(format!("{BTC_FIXTURES}/abandon-unsigned.psbt")).unwrap();
    let expected = std::fs::read(format!("{BTC_FIXTURES}/abandon-signed.psbt")).unwrap();
    // as Sparrow shows it: a crypto-psbt's parts in turn, in capitals
    let cbor = |b: &[u8]| {
        let mut c = vec![0x59, (b.len() >> 8) as u8, b.len() as u8];
        c.extend_from_slice(b);
        c
    };
    let mut encoder = ur::Encoder::new(&cbor(&psbt), 60, "crypto-psbt").unwrap();
    let n = encoder.fragment_count();
    let mut parts: Vec<String> = (0..n + 3).map(|_| encoder.next_part().unwrap().to_uppercase()).collect();
    // a part missed (the fountain's later ones make up for it), and one read twice
    parts.remove(1);
    parts.insert(3, parts[2].clone());
    let bytes = std::fs::read(format!("{}/tests/fixtures/bitcoin.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let record = Rc::new(RefCell::new(Record {
        // Sign from a QR code; then the signed PSBT's parts shown in turn, until the centre
        events: std::iter::once(Event::Menu(3))
            .chain(std::iter::repeat_n(Event::Timeout, 40))
            .chain([Event::Centre])
            .collect(),
        qrs: parts.into_iter().collect(),
        answers: [Answer::Yes].into_iter().collect(),
        ..Default::default()
    }));
    let loaded = load(&bundle.manifest, bundle.code).unwrap();
    assert_eq!(loaded.run(Box::new(Script(record.clone()))), Stop::Finished);
    let r = record.borrow();
    assert_eq!(
        r.menu,
        [
            "Taproot or SegWit",
            "Bitcoin or testnet",
            "Account key",
            "Sign from a QR code",
            "Multisig key",
            "Add a multisig"
        ]
    );
    assert_eq!(r.reviews[0].question, "Sign and spend");
    // read off maki's screen as the wallet's camera would, the signed PSBT: the same bytes as ever
    let mut decoder = ur::Decoder::default();
    for frame in &r.frames {
        if let Some(text) = read_qr(frame) {
            if text.starts_with("UR:CRYPTO-PSBT/") {
                decoder.receive(&text.to_lowercase()).unwrap();
            }
        }
    }
    assert!(decoder.complete(), "the signed PSBT's parts, from maki's screen");
    assert_eq!(decoder.message().unwrap().unwrap(), cbor(&expected));
}

#[test]
fn bitcoin_shows_its_descriptor_for_sparrow_to_scan() {
    let r = run_wallet_with("bitcoin", vec![Event::Menu(2), Event::Menu(2)], vec![], vec![], false);
    // an address, the account key, then the descriptor: as the link has shared it
    assert_eq!(
        read_qr(r.frames.last().unwrap()).unwrap(),
        "wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/<0;1>/*)#qf45pmyh"
    );
}

/// eth-sign-requests as MetaMask's QR-code keyring makes them: made with Keystone's
/// @keystonehq/bc-ur-registry-eth 0.22.1 (EthSignRequest.constructETHRequest, as
/// @keystonehq/metamask-airgapped-keyring calls it) for the test phrase's first account, the
/// transactions with @ethereumjs/tx 10.1.3.
fn metamask_requests() -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(format!(
        "{}/../maki-eth/tests/fixtures/metamask-requests.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    text.lines()
        .filter_map(|l| {
            let (k, v) = l.trim().trim_end_matches(',').split_once(": ")?;
            Some((k.trim_matches('"').to_string(), v.trim_matches('"').to_string()))
        })
        .collect()
}

/// A UR's CBOR, single-part.
fn ur_cbor(text: &str) -> Vec<u8> { ur::ur::decode(&text.to_lowercase()).unwrap().1 }

#[test]
fn ethereum_signs_what_metamask_shows_it_by_qr_code() {
    let requests = metamask_requests();
    let keys = maki_hd::seed::SeedKeys::from_seed(&test_seed()).unwrap();
    let account = maki_eth::Account::new(&keys, 0).unwrap();
    // what maki's Ethereum code signs for each, on this computer
    let data = |name: &str| {
        let cbor = ur_cbor(&requests[name]);
        let mut d = minicbor::Decoder::new(&cbor);
        let n = d.map().unwrap().unwrap();
        let mut out = Vec::new();
        for _ in 0..n {
            match d.u32().unwrap() {
                2 => out = d.bytes().unwrap().to_vec(),
                _ => d.skip().unwrap(),
            }
        }
        out
    };
    let expected = |name: &str| -> Vec<u8> {
        let d = data(name);
        match name {
            "message" => account.sign_message(&d).unwrap().to_vec(),
            "typed" => account
                .sign_typed(&maki_eth::TypedData::parse(std::str::from_utf8(&d).unwrap()).unwrap())
                .unwrap()
                .to_vec(),
            _ => maki_eth::Tx::parse(&d).unwrap().signature(&account).unwrap(),
        }
    };
    // the eth-signature on maki's screen: its request's ID, and the signature
    let answered = |scans: Vec<String>| -> (Vec<u8>, Vec<u8>, Record) {
        let r =
            run_wallet_scanning("ethereum", vec![Event::Menu(1), Event::Centre], scans, vec![Answer::Yes]);
        let shown = r
            .frames
            .iter()
            .rev()
            .filter_map(read_qr)
            .find(|t| t.starts_with("UR:ETH-SIGNATURE/"))
            .expect("the signature as a QR code");
        assert!(shown.starts_with("UR:ETH-SIGNATURE/"), "{shown}");
        let cbor = ur_cbor(&shown);
        let mut d = minicbor::Decoder::new(&cbor);
        let (mut id, mut sig) = (Vec::new(), Vec::new());
        for _ in 0..d.map().unwrap().unwrap() {
            match d.u32().unwrap() {
                1 => {
                    d.tag().unwrap();
                    id = d.bytes().unwrap().to_vec();
                }
                2 => sig = d.bytes().unwrap().to_vec(),
                _ => d.skip().unwrap(),
            }
        }
        (id, sig, r)
    };
    for (name, n, title) in [
        ("message", 1, "Sign message?"),
        ("typed", 2, "Sign typed data?"),
        ("eip1559", 3, "Sign and send"),
        ("legacy", 4, "Sign and send"),
    ] {
        let (id, sig, r) = answered(vec![requests[name].clone()]);
        // 00000000-0000-4000-8000-00000000000n
        assert_eq!(
            id,
            [&[0u8; 6][..], &[0x40, 0, 0x80], &[0; 6], &[n]].concat(),
            "{name}: the request's ID back"
        );
        assert_eq!(sig, expected(name), "{name}");
        if let Ok(dir) = std::env::var("MAKI_DUMP_QR") {
            // for checking against MetaMask's own keyring, by hand
            let shown = r
                .frames
                .iter()
                .rev()
                .filter_map(read_qr)
                .find(|t| t.starts_with("UR:ETH-SIGNATURE/"))
                .unwrap();
            std::fs::write(format!("{dir}/signature-{name}.txt"), shown).unwrap();
        }
        assert_eq!(r.reviews[0].pages[0].heading, "Asked by", "{name}");
        if name != "typed" {
            assert_eq!(r.reviews[0].question, title, "{name}");
        }
    }
    // an EIP-1559 signature's v is its parity; a legacy one's is EIP-155's (on Ethereum, 37 or 38)
    assert!(expected("eip1559")[64] <= 1 && expected("eip1559").len() == 65);
    assert!([37, 38].contains(&expected("legacy")[64]));
    // typed data in parts, as MetaMask shows a long request
    let mut encoder = ur::Encoder::new(&ur_cbor(&requests["typed"]), 120, "eth-sign-request").unwrap();
    let parts: Vec<String> =
        (0..encoder.fragment_count() + 2).map(|_| encoder.next_part().unwrap().to_uppercase()).collect();
    assert!(parts.len() > 3);
    assert_eq!(answered(parts).1, expected("typed"));
    // for another wallet (its fingerprint), refused before anything's shown
    let other = requests["message"].to_lowercase();
    let mut cbor = ur_cbor(&other);
    let at = cbor.windows(5).position(|w| w == [0x02, 0x1a, 0x73, 0xc5, 0xda]).unwrap();
    cbor[at + 2] ^= 1;
    let changed = ur::ur::encode(&cbor, &ur::ur::Type::Custom("eth-sign-request")).to_uppercase();
    let r = run_wallet_scanning("ethereum", vec![Event::Menu(1), Event::Centre], vec![changed], vec![]);
    assert!(r.reviews.is_empty());
}

#[test]
fn ethereum_shows_its_account_for_metamask_to_add() {
    let r = run_wallet_scanning("ethereum", vec![Event::Menu(0), Event::Centre], vec![], vec![]);
    assert_eq!(r.menu, ["Account for MetaMask", "Sign from a QR code"]);
    let shown = r
        .frames
        .iter()
        .rev()
        .filter_map(read_qr)
        .find(|t| t.starts_with("UR:CRYPTO-HDKEY/"))
        .expect("the account as a QR code");
    assert!(shown.starts_with("UR:CRYPTO-HDKEY/"), "{shown}");
    let cbor = ur_cbor(&shown);
    let keys = maki_hd::seed::SeedKeys::from_seed(&test_seed()).unwrap();
    let public = maki_hd::Keys::public(&keys, &[44 | 0x8000_0000, 60 | 0x8000_0000, 0x8000_0000]).unwrap();
    let mut d = minicbor::Decoder::new(&cbor);
    let (mut key, mut chain, mut fingerprint, mut note) = (Vec::new(), Vec::new(), 0u32, String::new());
    for _ in 0..d.map().unwrap().unwrap() {
        match d.u32().unwrap() {
            3 => key = d.bytes().unwrap().to_vec(),
            4 => chain = d.bytes().unwrap().to_vec(),
            6 => {
                d.tag().unwrap();
                for _ in 0..d.map().unwrap().unwrap() {
                    match d.u32().unwrap() {
                        2 => fingerprint = d.u32().unwrap(),
                        _ => d.skip().unwrap(),
                    }
                }
            }
            10 => note = d.str().unwrap().to_string(),
            _ => d.skip().unwrap(),
        }
    }
    assert_eq!((key, chain), (public.key.to_vec(), public.chain_code.to_vec()));
    assert_eq!(fingerprint, 0x73c5_da0a);
    assert_eq!(note, "account.standard");
    if let Ok(dir) = std::env::var("MAKI_DUMP_QR") {
        // for checking against MetaMask's own keyring, by hand
        std::fs::write(format!("{dir}/hdkey.txt"), &shown).unwrap();
    }
}

/// A wallet app run with these codes for its camera to read, one a scan.
fn run_wallet_scanning(name: &str, events: Vec<Event>, scans: Vec<String>, answers: Vec<Answer>) -> Record {
    let bytes = std::fs::read(format!("{}/tests/fixtures/{name}.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let record = Rc::new(RefCell::new(Record {
        events: events.into(),
        qrs: scans.into_iter().collect(),
        answers: answers.into_iter().collect(),
        ..Default::default()
    }));
    let loaded = load(&bundle.manifest, bundle.code).unwrap();
    assert_eq!(loaded.run(Box::new(Script(record.clone()))), Stop::Finished);
    Rc::try_unwrap(record).ok().unwrap().into_inner()
}

/// A wallet app, run as maki runs it (its manifest's paths and all), on these messages and
/// answers.
fn run_wallet(name: &str, inbox: Vec<Vec<u8>>, answers: Vec<Answer>, locked: bool) -> Record {
    let events = inbox.iter().map(|_| Event::Message).collect();
    run_wallet_with(name, events, inbox, answers, locked)
}

/// The same, on these events (a `Message` delivers the next message).
fn run_wallet_with(
    name: &str,
    events: Vec<Event>,
    inbox: Vec<Vec<u8>>,
    answers: Vec<Answer>,
    locked: bool,
) -> Record {
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
    let r = run_wallet(
        "bitcoin",
        vec![vec![b'A', 0, 0], vec![b'A', 0, 0], vec![b'D', 0, 0, 0, 0, 0, 0, 0]],
        vec![Answer::Yes, Answer::No, Answer::Yes],
        false,
    );
    assert_eq!(r.replies[0][0], 0);
    let [zpub, descriptor] = <[String; 2]>::try_from(texts(&r.replies[0])).unwrap();
    assert_eq!(
        zpub,
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
    );
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
    for (unsigned, signed) in [
        ("abandon-unsigned.psbt", "abandon-signed.psbt"),
        ("abandon-taproot-unsigned.psbt", "abandon-taproot-signed.psbt"),
    ] {
        let psbt = std::fs::read(format!("{BTC_FIXTURES}/{unsigned}")).unwrap();
        let expected = std::fs::read(format!("{BTC_FIXTURES}/{signed}")).unwrap();
        let fetches = expected.len().div_ceil(4000);
        let pieces = psbt.len().div_ceil(4000);
        let r = run_wallet("bitcoin", psbt_messages(0, &psbt, fetches), vec![Answer::Yes], false);
        for more in &r.replies[..pieces - 1] {
            assert_eq!(more, &[6], "{unsigned}: a piece taken");
        }
        let done = &r.replies[pieces - 1];
        assert_eq!(
            (done[0], u32::from_le_bytes(done[1..5].try_into().unwrap()) as usize),
            (0, expected.len()),
            "{unsigned}"
        );
        // the very bytes maki's wallet code signs: rust-bitcoin's, byte for byte
        assert_eq!(fetched(&r.replies[pieces..]), expected, "{unsigned}");
        let review = &r.reviews[0];
        assert_eq!(review.question, "Sign and spend");
        // each payment, the change and the fee (this fixture's is flagged: 24 sat/vB)
        let headings: Vec<&str> = review.pages.iter().map(|p| p.heading.as_str()).collect();
        assert!(
            headings.contains(&"Change") && (headings.contains(&"Fee") || headings.contains(&"High fee!")),
            "{headings:?}"
        );
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

/// A string16, as the Bitcoin app's messages have them.
fn str16(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

#[test]
fn bitcoin_adds_a_multisig_wallet_its_owner_went_through_and_signs_for_it() {
    let descriptor = std::fs::read_to_string(format!("{BTC_FIXTURES}/multisig.txt")).unwrap();
    let coldcard = std::fs::read_to_string(format!("{BTC_FIXTURES}/multisig-coldcard.txt")).unwrap();
    let unsigned = std::fs::read(format!("{BTC_FIXTURES}/multisig-unsigned.psbt")).unwrap();
    let signed = std::fs::read(format!("{BTC_FIXTURES}/multisig-signed.psbt")).unwrap();
    let register = |text: &str| {
        let mut m = vec![b'M', 1];
        str16(&mut m, "vault");
        str16(&mut m, text);
        m
    };
    // maki's key for it, as Sparrow scans a cosigner's; then the wallet, gone through and added;
    // its first address, compared on maki's screen
    use sha2::{Digest, Sha256};
    let id: Vec<u8> = Sha256::digest(descriptor.as_bytes())[..4].to_vec();
    let mut inbox =
        vec![vec![b'K', 1], register(&descriptor), vec![b'W'], [&[b'E'][..], &id, &[0, 0, 0, 0, 0]].concat()];
    inbox.extend(psbt_messages(1, &unsigned, 1));
    let r = run_wallet("bitcoin", inbox.clone(), vec![Answer::Yes; 4], false);
    assert_eq!(r.replies[0][0], 0);
    let key = &texts(&r.replies[0])[0];
    assert!(key.starts_with("[73c5da0a/48h/1h/0h/2h]Vpub5n95dMZrDHj6"), "{key}");
    assert_eq!(r.reviews[0].question, "Share multisig key?");
    let added = &r.reviews[1];
    assert_eq!((added.question.as_str(), added.detail.as_str()), ("Add this multisig?", "vault, 2 of 3"));
    let headings: Vec<&str> = added.pages.iter().map(|p| p.heading.as_str()).collect();
    assert_eq!(headings, ["Wallet", "Key 1/3", "Key 2/3", "Key 3/3"]);
    assert_eq!(added.pages[0].prose, "2 of its 3 keys sign; native SegWit (P2WSH), testnet");
    assert_eq!(added.pages[1].value, "73C5DA0A (maki)");
    assert_eq!(added.pages[2].value, "0EBCE71A");
    assert!(added.pages[3].mono.starts_with("tpubDEBbc4DHf8iY"), "{}", added.pages[3].mono);
    assert_eq!(r.replies[1][1..5], id[..], "its ID: its descriptor's hash");
    assert_eq!((r.replies[1][0], texts(&r.replies[1][4..])), (0, vec!["vault".to_string()]));
    assert!(
        r.storage.contains_key(&format!("ms{}", id.iter().map(|b| format!("{b:02x}")).collect::<String>()))
    );
    // listed: its ID, the test networks, 2 of 3, its name
    assert_eq!(&r.replies[2][..9], &[&[0u8, 1][..], &id, &[1, 2, 3]].concat()[..]);
    let address = &texts(&r.replies[3])[0];
    assert!(address.starts_with("tb1q") && address.len() == 62, "{address}");
    assert_eq!(
        (r.reviews[2].detail.as_str(), r.reviews[2].pages[0].heading.as_str()),
        ("vault", "Receive #0")
    );
    // and a PSBT spending from it: where it's from first, then as any other; signed as maki-btc signs
    let pieces = unsigned.len().div_ceil(4000);
    let done = &r.replies[4 + pieces - 1];
    assert_eq!(done[0], 0, "{:?}", texts(done));
    assert_eq!(fetched(&r.replies[4 + pieces..]), signed);
    let review = &r.reviews[3];
    assert_eq!((review.pages[0].heading.as_str(), review.pages[0].value.as_str()), ("From", "vault"));
    assert!(
        review.pages.iter().any(|p| p.heading == "Change" && p.prose == "back to vault (2 of 3)"),
        "{:?}",
        review.pages
    );
    assert_eq!(review.pages[0].prose, "a 2 of 3 multisig wallet; maki signs as one of its keys");

    // the same wallet from Coldcard's file (Sparrow's export), named by it; asked about once
    let r = run_wallet("bitcoin", vec![register(&coldcard), register(&descriptor)], vec![Answer::Yes], false);
    assert_eq!(texts(&r.replies[0][4..]), ["Family vault"]);
    assert_eq!(r.replies[0][1..5], id[..], "the same wallet, however it came");
    assert_eq!(r.replies[1][0], 0);
    assert_eq!(r.reviews.len(), 1, "already added: not asked again");

    // not added: a PSBT from it isn't signed; a no adds nothing; a wallet without maki's key isn't taken
    let r = run_wallet("bitcoin", psbt_messages(1, &unsigned, 0), vec![Answer::Yes], false);
    assert!(
        texts(r.replies.last().unwrap())[0].contains("add it on maki first"),
        "{:?}",
        texts(r.replies.last().unwrap())
    );
    assert!(r.reviews.is_empty());
    let r = run_wallet("bitcoin", vec![register(&descriptor), vec![b'W']], vec![Answer::No], false);
    assert_eq!((r.replies[0].as_slice(), r.replies[1].as_slice()), (&[1u8][..], &[0u8, 0][..]));
    let strangers = descriptor.replace("73c5da0a/", "73c5da0b/");
    let r =
        run_wallet("bitcoin", vec![register(strangers.split('#').next().unwrap())], vec![Answer::Yes], false);
    assert_eq!(r.replies[0][0], 5);
    assert!(texts(&r.replies[0])[0].contains("isn't one of its keys"), "{:?}", texts(&r.replies[0]));
    assert!(r.reviews.is_empty());
}

#[test]
fn bitcoin_adds_a_multisig_off_the_coordinators_screen_and_shows_its_key_for_it() {
    let coldcard = std::fs::read_to_string(format!("{BTC_FIXTURES}/multisig-coldcard.txt")).unwrap();
    // the menu's Network (to testnet), then Add a multisig, reading Sparrow's file as text
    let events = vec![Event::Menu(1), Event::Menu(5), Event::Centre, Event::Menu(4)];
    let r = run_wallet_scanning("bitcoin", events, vec![coldcard], vec![Answer::Yes]);
    assert_eq!(r.reviews[0].question, "Add this multisig?");
    assert!(r.storage.keys().any(|k| k.starts_with("ms")));
    // Multisig key: maki's key for one, as a QR code
    let code = read_qr(r.frames.last().unwrap()).unwrap();
    assert!(code.starts_with("[73c5da0a/48h/1h/0h/2h]Vpub"), "{code}");
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
    let r = run_wallet(
        "ethereum",
        vec![eth_head(b'A', 0, "app.example"), eth_head(b'A', 0, "app.example")],
        vec![Answer::Yes, Answer::No],
        false,
    );
    // MetaMask's and Ledger's first account for the phrase
    assert_eq!(r.replies[0][0], 0);
    assert_eq!(texts(&r.replies[0]), ["0x9858EfFD232B4033E47d90003D41EC34EcaEda94"]);
    assert_eq!(r.reviews[0].question, "Connect wallet?");
    assert_eq!(
        (r.reviews[0].pages[0].heading.as_str(), r.reviews[0].pages[0].mono.as_str()),
        ("Asked by", "app.example")
    );
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
    let phish = [
        eth_head(b'M', 0, "demo.maki"),
        b"evil.example wants you to sign in with your Ethereum account:\n0x9858".to_vec(),
    ]
    .concat();
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
fn xmr_address(net: u8, major: u32, minor: u32) -> Vec<u8> {
    [&[b'D', net][..], &major.to_le_bytes(), &minor.to_le_bytes()].concat()
}

#[test]
fn monero_shows_the_addresses_every_wallet_makes() {
    // the test phrase's: as Ledger's Monero app and monero-python make them
    let inbox = vec![
        xmr_address(0, 0, 0),
        xmr_address(2, 0, 0),
        xmr_address(0, 0, 1),
        xmr_address(0, 0, 2),
        xmr_address(0, 2, 7),
        xmr_address(1, 0, 1),
    ];
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
    assert_eq!(
        headings,
        [
            "Primary address",
            "Primary address, stagenet",
            "Subaddress 1",
            "Subaddress 2",
            "Subaddress 2/7",
            "Subaddress 1, testnet"
        ]
    );
    // locked; a network there isn't; not a message it takes
    let r = run_wallet("monero", vec![xmr_address(0, 0, 0)], vec![], true);
    assert_eq!(r.replies, [vec![3u8]]);
    let r = run_wallet("monero", vec![xmr_address(9, 0, 0), vec![b'X'], vec![b'D', 0]], vec![], false);
    assert_eq!(r.replies, [vec![4u8], vec![4], vec![4]]);
    assert!(r.reviews.is_empty());
}

#[test]
fn monero_has_maki_show_its_backup_and_never_sees_it() {
    let r = run_wallet_with(
        "monero",
        vec![Event::Menu(0), Event::Menu(0), Event::Centre],
        vec![],
        vec![Answer::Yes, Answer::No],
        false,
    );
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
    use maki_xmr::sign::{self, G, Scalar};
    let keys = maki_hd::seed::SeedKeys::from_seed(&test_seed()).unwrap();
    let account = maki_hd::parse_path("m/44'/128'/0'/0/0").unwrap();
    let pair = maki_hd::seed::answer(
        &keys,
        maki_hd::op::MONERO_SUBADDRESS,
        &account,
        &[0, 0, 0, 0, minor as u8, 0, 0, 0],
        &[0; 32],
    )
    .unwrap();
    let (spend, view) = (
        sign::point(&pair[..32].try_into().unwrap()).unwrap(),
        sign::point(&pair[32..].try_into().unwrap()).unwrap(),
    );
    let scalar = |n: u64| Scalar::from_bytes_mod_order(maki_xmr::keccak(&(seed * 1000 + n).to_le_bytes()));
    let r = scalar(0);
    let tx_key = if minor == 0 { G * r } else { spend * r };
    let out = sign::pay(&r, &view, &spend, 2, amount);
    let ring = (0..16u64)
        .map(|i| maki_xmr::request::Member {
            global: 5000 + 7 * i,
            key: if i == 9 { out.key } else { (G * scalar(i + 1)).compress().to_bytes() },
            commitment: if i == 9 {
                out.commitment
            } else {
                sign::commit(&scalar(i + 100), i).compress().to_bytes()
            },
        })
        .collect();
    maki_xmr::request::Input {
        amount,
        tx_key: tx_key.compress().to_bytes(),
        index: 2,
        subaddress: minor,
        real: 9,
        ring,
    }
}

/// An output of the test phrase's account as `K` asks about it: its transaction key, index,
/// subaddress and key.
fn xmr_output(input: &maki_xmr::request::Input) -> Vec<u8> {
    [
        &input.tx_key[..],
        &input.index.to_le_bytes(),
        &0u32.to_le_bytes(),
        &input.subaddress.to_le_bytes(),
        &input.ring[input.real].key,
    ]
    .concat()
}

#[test]
fn monero_lets_a_computer_watch_once_its_owner_says_so() {
    let (a, b) = (xmr_input(1, 0, 10), xmr_input(2, 4, 20));
    let images = [&[b'K', 2][..], &xmr_output(&a), &xmr_output(&b)].concat();
    let inbox = vec![
        images.clone(),
        vec![b'W', 0],
        vec![b'W', 0],
        images.clone(),
        [&[b'K', 1][..], &xmr_output(&xmr_input(3, 1, 5))[4..], &[0; 4]].concat(),
    ];
    let r = run_wallet("monero", inbox, vec![Answer::No, Answer::Yes], false);
    // no key images until a computer may watch
    assert_eq!(r.replies[0][0], 5);
    assert_eq!(texts(&r.replies[0]), ["let maki desktop watch this wallet first"]);
    // the owner's no, then yes: the address and the view key
    assert_eq!(r.replies[1], [1]);
    assert_eq!(r.reviews[0].question, "Let computer watch?");
    assert_eq!(
        r.reviews[1].pages[0].mono,
        "49vDbkSo7eve3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVF2N4Zn"
    );
    let watch = &r.replies[2];
    assert_eq!((watch[0], watch.len()), (0, 1 + 2 + 95 + 32));
    let view: String = watch[98..].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(view, "0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201");
    // then key images, each with its proof, as the account makes them
    let keys = maki_xmr::Keys::from_spend(maki_xmr::sign::Scalar::from_bytes_mod_order(
        (0..32)
            .map(|i| {
                u8::from_str_radix(
                    &"3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109"[2 * i..2 * i + 2],
                    16,
                )
                .unwrap()
            })
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap(),
    ));
    let images = &r.replies[3];
    assert_eq!((images[0], images.len()), (0, 1 + 2 * 96));
    for (i, input) in [&a, &b].into_iter().enumerate() {
        let tx_key = maki_xmr::sign::point(&input.tx_key).unwrap();
        let (image, proof) = keys
            .key_image_proof(&tx_key, input.index, 0, input.subaddress, &input.ring[input.real].key, &[0; 32])
            .unwrap();
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
        .map(|(i, piece)| {
            [&[b'S', 0][..], &(request.len() as u32).to_le_bytes(), &((i * 4000) as u32).to_le_bytes(), piece]
                .concat()
        })
        .collect();
    out.extend((0..fetches).map(|i| [&[b'G'][..], &((i * 4000) as u32).to_le_bytes()].concat()));
    out
}

#[test]
fn monero_signs_what_its_owner_saw() {
    use maki_xmr::request::{Payment, Request, read_destination};
    let to =
        "8AB7PQPtducdkghYFN2prK3rZ7zPeL9f2REEdqE4WXYbSZr3797Aqti5xAjRsVy4jTdcwMW11GWejQtqk2kNXxj2QZxJwPZ";
    let request = Request {
        network: maki_xmr::Network::Mainnet,
        account: 0,
        fee: 30_000_000,
        change: 470_000_000,
        payments: vec![Payment {
            address: to.into(),
            amount: 1_500_000_000_000,
            destination: read_destination(to).unwrap().1,
        }],
        inputs: vec![xmr_input(4, 0, 1_000_000_000_000), xmr_input(5, 2, 500_500_000_000)],
    };
    let bytes = request.to_bytes();
    assert!(bytes.len() > 2400);
    let r = run_wallet("monero", xmr_messages(&bytes, 1), vec![Answer::Yes], false);
    let review = &r.reviews[0];
    assert_eq!((review.question.as_str(), review.detail.as_str()), ("Sign and spend", "Total 1.50003 XMR"));
    let pages: Vec<(&str, &str, &str)> =
        review.pages.iter().map(|p| (p.heading.as_str(), p.value.as_str(), p.mono.as_str())).collect();
    assert_eq!(
        pages,
        [("Send", "1.5 XMR", to), ("Change", "0.00047 XMR", "back to you"), ("Fee", "0.00003 XMR", "")]
    );
    // taken whole, signed, and fetched
    let signed_size = u32::from_le_bytes(r.replies[0][1..5].try_into().unwrap()) as usize;
    assert_eq!(r.replies[0][0], 0);
    let fetched = &r.replies[1];
    assert_eq!(
        (fetched[0], u32::from_le_bytes(fetched[1..5].try_into().unwrap()) as usize),
        (0, signed_size)
    );
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

const SOL_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../maki-sol/tests/fixtures");

/// A transaction web3.js made (`maki-sol/tests/fixtures/make.mjs`): its message, and web3.js's
/// signature for the test phrase's first Solana account.
fn sol_fixture(name: &str) -> (Vec<u8>, Vec<u8>) {
    let text = std::fs::read_to_string(format!("{SOL_FIXTURES}/transactions.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let f = json.as_array().unwrap().iter().find(|f| f["name"] == name).unwrap();
    let unhex = |s: &str| {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect::<Vec<u8>>()
    };
    (unhex(f["message"].as_str().unwrap()), f["signature"].as_str().map(unhex).unwrap_or_default())
}

#[test]
fn solana_shows_and_connects_phantoms_account() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    // Phantom's and Solflare's first account for the phrase
    const ME: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
    let r = run_wallet_with(
        "solana",
        vec![Event::Right, Event::Left, Event::Centre, Event::Exit],
        vec![],
        vec![],
        false,
    );
    assert_eq!(read_qr(&r.frames[0]).as_deref(), Some(ME));
    assert_eq!(
        read_qr(&r.frames[1]).as_deref(),
        Some("Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb"),
        "account #1"
    );
    assert!(read_qr(&r.frames[3]).is_none(), "as text");
    let r = run_wallet(
        "solana",
        vec![eth_head(b'A', 0, "app.example"), eth_head(b'A', 0, "app.example")],
        vec![Answer::Yes, Answer::No],
        false,
    );
    assert_eq!(r.replies[0].len(), 33);
    assert_eq!(maki_sol::address(&r.replies[0][1..].try_into().unwrap()), ME);
    assert_eq!(
        (r.reviews[0].question.as_str(), r.reviews[0].pages[0].mono.as_str()),
        ("Connect wallet?", "app.example")
    );
    assert_eq!(r.replies[1], [1]);
    let r = run_wallet("solana", vec![eth_head(b'A', 0, "app.example")], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3], "locked");
    let r = run_wallet("solana", vec![eth_head(b'A', 0, "App.Example")], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], [4]);
    // a message: a sign-in, read and signed
    let sign_in = format!("app.example wants you to sign in with your Solana account:\n{ME}\n\nNonce: 1");
    let r = run_wallet(
        "solana",
        vec![[eth_head(b'M', 0, "app.example"), sign_in.clone().into_bytes()].concat()],
        vec![Answer::Yes],
        false,
    );
    assert_eq!(r.reviews[0].question, "Sign message?");
    assert_eq!(r.reviews[0].pages[1].mono, sign_in);
    let key = VerifyingKey::from_bytes(&maki_sol::base58::decode_key(ME).unwrap()).unwrap();
    key.verify(sign_in.as_bytes(), &Signature::from_bytes(r.replies[0][1..].try_into().unwrap())).unwrap();
}

#[test]
fn solana_signs_what_the_owner_read_as_web3js_signs_it() {
    let (usdc, signature) = sol_fixture("usdc");
    let r = run_wallet(
        "solana",
        vec![[eth_head(b'T', 0, "jup.ag"), usdc.clone()].concat()],
        vec![Answer::Yes],
        false,
    );
    assert_eq!(r.replies[0], [&[0u8][..], &signature].concat());
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str()),
        ("Sign and send", "sends 5.25 USDC; fee up to 0.00000506 SOL")
    );
    let pages: Vec<(&str, &str, &str)> =
        review.pages.iter().map(|p| (p.heading.as_str(), p.value.as_str(), p.mono.as_str())).collect();
    assert_eq!(
        pages,
        [
            ("Asked by", "", "jup.ag"),
            ("New token account", "USDC", "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"),
            ("Send", "5.25 USDC", "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"),
            ("Max fee", "0.00000506 SOL", "")
        ]
    );
    // a no, a transaction this account doesn't sign, a transaction as a message, not a transaction
    let (not_mine, _) = sol_fixture("not-mine");
    let r = run_wallet(
        "solana",
        vec![
            [eth_head(b'T', 0, "jup.ag"), usdc.clone()].concat(),
            [eth_head(b'T', 0, "jup.ag"), not_mine].concat(),
            [eth_head(b'M', 0, "jup.ag"), usdc.clone()].concat(),
            [eth_head(b'T', 0, "jup.ag"), vec![1, 2, 3]].concat(),
        ],
        vec![Answer::No],
        false,
    );
    assert_eq!(r.replies[0], [1]);
    assert_eq!(
        (r.replies[1][0], texts(&r.replies[1])),
        (5, vec!["this account doesn't sign it".to_string()])
    );
    assert_eq!(
        (r.replies[2][0], texts(&r.replies[2])),
        (5, vec!["that's a transaction, not a message: maki won't sign it as one".to_string()])
    );
    assert_eq!(r.replies[3][0], 5);
    assert_eq!(r.reviews.len(), 1, "only the first was shown");
    // every fixture this account signs, signed as web3.js signs it
    let text = std::fs::read_to_string(format!("{SOL_FIXTURES}/transactions.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    for f in json.as_array().unwrap().iter().filter(|f| f["signature"].is_string()) {
        let (message, signature) = sol_fixture(f["name"].as_str().unwrap());
        let r = run_wallet(
            "solana",
            vec![[eth_head(b'T', 0, "jup.ag"), message].concat()],
            vec![Answer::Yes],
            false,
        );
        assert_eq!(r.replies[0], [&[0u8][..], &signature].concat(), "{}", f["name"]);
    }
}
