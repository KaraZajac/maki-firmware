//! What the example apps' tests share: an app run as maki runs it, by the host code maki runs it
//! with, against a scripted maki (`Script`) that records what the app did (`Record`): its frames,
//! what it stored, asked, typed and replied, and what it put on maki's review screen; wallet apps'
//! keys are the BIP39 test phrase's. Each test file takes it with `mod harness;`.

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use std::time::Duration;

use maki_wasm::*;

#[derive(Default)]
pub struct Record {
    pub events: VecDeque<Event>,
    pub frames: Vec<Canvas>,
    pub menu: Vec<String>,
    pub storage: BTreeMap<String, Vec<u8>>,
    pub answers: VecDeque<Answer>,
    pub asks: Vec<Ask>,
    pub typed: Vec<String>,
    /// keys pressed and the modifiers held (`MOD_*`)
    pub pressed: Vec<(u8, u8)>,
    pub inbox: VecDeque<Vec<u8>>,
    pub current: Option<Vec<u8>>,
    pub replies: Vec<Vec<u8>>,
    pub qr: Option<String>,
    /// codes the camera reads after `qr`, one a scan
    pub qrs: VecDeque<String>,
    pub motion: Option<[i16; 3]>,
    /// readings the accelerometer gives before `motion`, one a read
    pub motions: VecDeque<[i16; 3]>,
    /// the accelerometer's range, if the app set one
    pub range: u8,
    /// the app asked for the screen dark
    pub dark: bool,
    /// maki is locked: no wallet keys
    pub locked: bool,
    /// maki's clock, in millis, and whether it runs: then a timeout lets the whole of its wait
    /// pass (for apps that keep time; otherwise it stays at 0)
    pub now: u64,
    pub clock: bool,
    /// what wallet apps put on maki's review screen
    pub reviews: Vec<Review>,
    /// backup words maki showed its owner (never the app)
    pub backups: Vec<String>,
}

/// The BIP39 test phrase's seed: wallet apps' keys here, as on a maki set up with it.
pub fn test_seed() -> [u8; 64] {
    let words: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' ')
            .collect();
    maki_seed::seed(&words, "")
}

pub struct Script(pub Rc<RefCell<Record>>);

impl Platform for Script {
    fn wait(&mut self, timeout: Option<Duration>) -> Event {
        let mut r = self.0.borrow_mut();
        let event = r.events.pop_front().unwrap_or(Event::Exit);
        if event == Event::Timeout && r.clock {
            r.now += timeout.map_or(0, |t| t.as_millis() as u64);
        }
        if event == Event::Message {
            r.current = r.inbox.pop_front();
        }
        event
    }

    fn present(&mut self, canvas: &Canvas) { self.0.borrow_mut().frames.push(canvas.clone()) }

    fn set_menu(&mut self, items: &[String]) { self.0.borrow_mut().menu = items.to_vec() }

    fn millis(&self) -> u64 { self.0.borrow().now }

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

    fn press_key(&mut self, code: u8, mods: u8) -> bool {
        self.0.borrow_mut().pressed.push((code, mods));
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

    fn set_dark(&mut self, dark: bool) { self.0.borrow_mut().dark = dark; }

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
            let words = maki_hd::seed::answer(&keys, maki_hd::words_op(path), path, &[], &[0; 32])
                .map_err(|_| NOT_FOUND)?;
            r.backups.push(String::from_utf8(words).unwrap());
        }
        Ok(answer)
    }
}

pub fn run_fixture(name: &str, events: &[Event], storage: BTreeMap<String, Vec<u8>>) -> (Stop, Record) {
    run_answering(name, events, storage, &[])
}

pub fn run_answering(
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
    // as maki opens an installed app: lazily, each function compiled when it's first called
    let mut loaded = load_installed(&bundle.manifest, bundle.code).unwrap();
    loaded.limits = limits;
    let stop = loaded.run(Box::new(Script(record.clone())));
    (stop, Rc::try_unwrap(record).ok().unwrap().into_inner())
}

/// Runs a fixture with a record made to measure (a clock, messages, answers).
pub fn run_record(name: &str, record: Record) -> (Stop, Record) {
    let bytes = std::fs::read(format!("{}/tests/fixtures/{name}.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let record = Rc::new(RefCell::new(record));
    // as maki opens an installed app: lazily, each function compiled when it's first called
    let mut loaded = load_installed(&bundle.manifest, bundle.code).unwrap();
    loaded.limits = limits;
    let stop = loaded.run(Box::new(Script(record.clone())));
    (stop, Rc::try_unwrap(record).ok().unwrap().into_inner())
}

pub fn lit(c: &Canvas) -> usize {
    (0..HEIGHT as i32)
        .flat_map(|y| (0..WIDTH as i32).map(move |x| (x, y)))
        .filter(|&(x, y)| c.get(x, y))
        .count()
}

/// The QR code on an app's screen, read as maki's camera reads one (rqrr, as bao-video has it).
pub fn read_qr(c: &Canvas) -> Option<String> {
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

/// A wallet app run with these codes for its camera to read, one a scan.
pub fn run_wallet_scanning(
    name: &str,
    events: Vec<Event>,
    scans: Vec<String>,
    answers: Vec<Answer>,
) -> Record {
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
pub fn run_wallet(name: &str, inbox: Vec<Vec<u8>>, answers: Vec<Answer>, locked: bool) -> Record {
    let events = inbox.iter().map(|_| Event::Message).collect();
    run_wallet_with(name, events, inbox, answers, locked)
}

/// The same, on these events (a `Message` delivers the next message).
pub fn run_wallet_with(
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
pub fn texts(answer: &[u8]) -> Vec<String> {
    let (mut out, mut at) = (Vec::new(), 1);
    while at + 2 <= answer.len() {
        let n = u16::from_le_bytes([answer[at], answer[at + 1]]) as usize;
        out.push(String::from_utf8(answer[at + 2..at + 2 + n].to_vec()).unwrap());
        at += 2 + n;
    }
    out
}
