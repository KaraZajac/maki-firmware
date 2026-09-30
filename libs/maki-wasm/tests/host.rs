//! The host runs whatever a bundle carries: apps get maki's functions and nothing else, and
//! whatever an app does, maki's host carries on.

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
    logs: Vec<String>,
    storage: BTreeMap<String, Vec<u8>>,
    waits: Vec<Option<Duration>>,
    asks: Vec<Ask>,
    answers: VecDeque<Answer>,
    typed: Vec<String>,
    /// keys beyond text pressed, and whether with Shift
    pressed: Vec<(u8, bool)>,
    /// maki is locked: no secrets, and nothing typed
    locked: bool,
    /// messages from the computer, each delivered with an Event::Message
    inbox: VecDeque<Vec<u8>>,
    /// the one being answered, and the answers
    current: Option<Vec<u8>>,
    replies: Vec<Vec<u8>>,
    /// what the camera sees next (None: the owner cancels)
    qr: Option<String>,
    scans: usize,
    motion: Option<[i16; 3]>,
    /// the accelerometer's range, if the app set one
    range: u8,
    /// the app asked for the screen dark
    dark: bool,
    /// maki's clock, in millis (5 s after boot, unless a test moves it)
    now: u64,
    /// what wallet apps put on maki's review screen
    reviews: Vec<Review>,
    /// the wallet ops maki did for the app: which, on what path
    wallet_calls: Vec<(u8, Vec<u32>)>,
    /// backup words maki showed its owner (never the app)
    backups: Vec<String>,
}

/// The BIP39 test phrase's seed: wallet apps' keys in these tests.
fn test_seed() -> [u8; 64] {
    let words: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' ')
            .collect();
    maki_seed::seed(&words, "")
}

/// The test platform's secret for a label: made up, different for each label.
fn secret_for(label: &str) -> [u8; 32] {
    let mut s = [0x42u8; 32];
    for (i, b) in label.bytes().enumerate() {
        s[i % 32] ^= b.wrapping_add(i as u8);
    }
    s
}

/// Hands out scripted events (Exit once they run out) and records what the app does.
struct Script(Rc<RefCell<Record>>);

impl Platform for Script {
    fn wait(&mut self, timeout: Option<Duration>) -> Event {
        let mut r = self.0.borrow_mut();
        r.waits.push(timeout);
        let event = r.events.pop_front().unwrap_or(Event::Exit);
        if event == Event::Message {
            r.current = r.inbox.pop_front();
        }
        event
    }

    fn present(&mut self, canvas: &Canvas) { self.0.borrow_mut().frames.push(canvas.clone()) }

    fn set_menu(&mut self, items: &[String]) { self.0.borrow_mut().menu = items.to_vec() }

    fn millis(&self) -> u64 { self.0.borrow().now.max(5_000) }

    fn unix_time(&self) -> Option<(u64, bool)> { Some((1_790_000_000, true)) }

    fn random(&mut self, buf: &mut [u8]) { buf.iter_mut().for_each(|b| *b = 0x5a) }

    fn log(&mut self, line: &str) { self.0.borrow_mut().logs.push(line.into()) }

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

    fn app_secret(&mut self, label: &str) -> Option<[u8; 32]> {
        (!self.0.borrow().locked).then(|| secret_for(label))
    }

    fn type_text(&mut self, text: &str) -> bool {
        let mut r = self.0.borrow_mut();
        if r.locked {
            return false;
        }
        r.typed.push(text.into());
        true
    }

    fn press_key(&mut self, code: u8, shift: bool) -> bool {
        let mut r = self.0.borrow_mut();
        if r.locked {
            return false;
        }
        r.pressed.push((code, shift));
        true
    }

    fn scan_qr(&mut self) -> Option<String> {
        let mut r = self.0.borrow_mut();
        r.scans += 1;
        r.qr.clone()
    }

    fn motion(&mut self) -> Option<[i16; 3]> { self.0.borrow().motion }

    fn motion_range(&mut self, g: u8) -> Option<u8> {
        self.0.borrow_mut().range = g;
        Some(g)
    }

    fn set_dark(&mut self, dark: bool) { self.0.borrow_mut().dark = dark; }

    fn wallet(&mut self, op: u8, path: &[u32], digest: &[u8]) -> Result<Vec<u8>, i32> {
        let mut r = self.0.borrow_mut();
        if r.locked {
            return Err(LOCKED);
        }
        r.wallet_calls.push((op, path.to_vec()));
        let keys = maki_hd::seed::SeedKeys::from_seed(&test_seed()).unwrap();
        // as maki's app host has maki-keys' answers
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
        // the owner's say first, as maki asks it
        let answer = r.answers.pop_front().unwrap_or(Answer::NoAnswer);
        if answer == Answer::Yes {
            let keys = maki_hd::seed::SeedKeys::from_seed(&test_seed()).unwrap();
            let words = maki_hd::seed::answer(&keys, maki_hd::op::MONERO_WORDS, path, &[], &[0; 32])
                .map_err(|e| match e {
                    maki_hd::Error::Path => NOT_FOUND,
                    _ => FAILED,
                })?;
            r.backups.push(String::from_utf8(words).unwrap());
        }
        Ok(answer)
    }

    fn message(&mut self) -> Option<Vec<u8>> { self.0.borrow().current.clone() }

    fn reply(&mut self, reply: &[u8]) -> bool {
        let mut r = self.0.borrow_mut();
        if r.current.take().is_none() {
            return false;
        }
        r.replies.push(reply.to_vec());
        true
    }
}

const LIMITS: Limits = Limits { memory: 256 * 1024, storage: 1024, fuel: 1_000_000, granted: Granted::NONE };

fn with(permissions: &[maki_bundle::Permission]) -> Limits {
    Limits { granted: Granted::of(permissions), ..LIMITS }
}

fn module(body: &str) -> Vec<u8> { wat::parse_str(body).unwrap() }

/// Runs `wat` with `events`, returning why it stopped and what it did.
fn run_with(wat: &str, events: &[Event], limits: Limits) -> (Stop, Record) {
    let record =
        Rc::new(RefCell::new(Record { events: events.iter().copied().collect(), ..Default::default() }));
    let stop = run(&module(wat), Box::new(Script(record.clone())), limits);
    let r = Rc::try_unwrap(record).ok().unwrap().into_inner();
    (stop, r)
}

/// An app that logs every event's code, as decimal, and returns on Exit.
const ECHO: &str = r#"
(module
  (import "maki" "wait" (func $wait (param i32) (result i32)))
  (import "maki" "log" (func $log (param i32 i32)))
  (memory (export "memory") 1)
  (func $digits (param $n i32) (result i32)
    ;; writes $n in decimal at 100, returns its length
    (local $len i32) (local $i i32) (local $m i32)
    (local.set $m (local.get $n))
    (loop $count
      (local.set $len (i32.add (local.get $len) (i32.const 1)))
      (local.set $m (i32.div_u (local.get $m) (i32.const 10)))
      (br_if $count (local.get $m)))
    (local.set $i (local.get $len))
    (loop $write
      (local.set $i (i32.sub (local.get $i) (i32.const 1)))
      (i32.store8 (i32.add (i32.const 100) (local.get $i))
        (i32.add (i32.const 48) (i32.rem_u (local.get $n) (i32.const 10))))
      (local.set $n (i32.div_u (local.get $n) (i32.const 10)))
      (br_if $write (local.get $i)))
    (local.get $len))
  (func (export "maki_main")
    (local $e i32)
    (loop $events
      (local.set $e (call $wait (i32.const 250)))
      (call $log (i32.const 100) (call $digits (local.get $e)))
      (br_if $events (i32.ne (local.get $e) (i32.const 6))))))
"#;

#[test]
fn events_reach_the_app_as_codes() {
    let events = [
        Event::Left,
        Event::Right,
        Event::Centre,
        Event::Menu(2),
        Event::Hidden,
        Event::Shown,
        Event::Timeout,
    ];
    let (stop, r) = run_with(ECHO, &events, LIMITS);
    assert_eq!(stop, Stop::Finished);
    assert_eq!(r.logs, ["1", "2", "3", "258", "5", "4", "0", "6"]);
    assert!(r.waits.iter().all(|w| *w == Some(Duration::from_millis(250))));
}

#[test]
fn drawing_reaches_the_screen_when_presented() {
    let wat = r#"
    (module
      (import "maki" "text" (func $text (param i32 i32 i32 i32 i32 i32) (result i32)))
      (import "maki" "rect" (func $rect (param i32 i32 i32 i32 i32 i32)))
      (import "maki" "present" (func $present))
      (import "maki" "screen_width" (func $w (result i32)))
      (import "maki" "screen_height" (func $h (result i32)))
      (import "maki" "wait" (func $wait (param i32) (result i32)))
      (memory (export "memory") 1)
      (data (i32.const 16) "Hi")
      (func (export "maki_main")
        (drop (call $text (i32.const 0) (i32.const 0) (i32.const 16) (i32.const 2) (i32.const 1) (i32.const 1)))
        (call $rect (i32.const 100) (i32.const 90) (call $w) (call $h) (i32.const 1) (i32.const 1))
        (call $present)
        (drop (call $wait (i32.const -1)))))
    "#;
    let (stop, r) = run_with(wat, &[], LIMITS);
    assert_eq!(stop, Stop::Finished);
    assert_eq!(r.frames.len(), 1);
    let f = &r.frames[0];
    let lit = |x0, y0, x1, y1| {
        (y0..y1).flat_map(|y| (x0..x1).map(move |x| (x, y))).filter(|&(x, y)| f.get(x, y)).count()
    };
    assert!(lit(0, 0, 20, 15) > 10, "no text:\n{f:?}");
    assert_eq!(lit(100, 90, 128, 110), 28 * 20);
    assert_eq!(lit(30, 30, 90, 80), 0);
    assert_eq!(r.waits, [None]);
}

#[test]
fn an_app_that_never_waits_is_stopped() {
    let wat = r#"(module (memory (export "memory") 1) (func (export "maki_main") (loop $l (br $l))))"#;
    assert_eq!(run_with(wat, &[], LIMITS).0, Stop::NotResponding);
}

#[test]
fn waiting_refuels() {
    // spins for about half its fuel between waits, ten times over
    let wat = r#"
    (module
      (import "maki" "wait" (func $wait (param i32) (result i32)))
      (memory (export "memory") 1)
      (func (export "maki_main")
        (local $round i32) (local $i i32)
        (loop $rounds
          (local.set $i (i32.const 100000))
          (loop $spin (local.set $i (i32.sub (local.get $i) (i32.const 1))) (br_if $spin (local.get $i)))
          (drop (call $wait (i32.const 0)))
          (local.set $round (i32.add (local.get $round) (i32.const 1)))
          (br_if $rounds (i32.lt_u (local.get $round) (i32.const 10))))))
    "#;
    let events = [Event::Timeout; 10];
    assert_eq!(run_with(wat, &events, LIMITS).0, Stop::Finished);
}

#[test]
fn waiting_after_exit_stops_the_app() {
    let wat = r#"
    (module
      (import "maki" "wait" (func $wait (param i32) (result i32)))
      (memory (export "memory") 1)
      (func (export "maki_main") (loop $l (drop (call $wait (i32.const -1))) (br $l))))
    "#;
    assert_eq!(run_with(wat, &[Event::Left], LIMITS).0, Stop::Exited);
}

#[test]
fn abort_says_why() {
    let wat = r#"
    (module
      (import "maki" "abort" (func $abort (param i32 i32)))
      (memory (export "memory") 1)
      (data (i32.const 0) "out of dice")
      (func (export "maki_main") (call $abort (i32.const 0) (i32.const 11))))
    "#;
    assert_eq!(run_with(wat, &[], LIMITS).0, Stop::Aborted("out of dice".into()));
}

#[test]
fn traps_and_bad_arguments_stop_the_app_not_maki() {
    let cases = [
        // text from beyond the end of memory
        (
            r#"(drop (call $text (i32.const 0) (i32.const 0) (i32.const 65530) (i32.const 10) (i32.const 0) (i32.const 1)))"#,
            "text: bad pointer",
        ),
        // a length that wraps around
        (
            r#"(drop (call $text (i32.const 0) (i32.const 0) (i32.const 16) (i32.const -1) (i32.const 0) (i32.const 1)))"#,
            "more than",
        ),
        (
            r#"(drop (call $text (i32.const 0) (i32.const 0) (i32.const 16) (i32.const 2) (i32.const 9) (i32.const 1)))"#,
            "no text style 9",
        ),
        (
            r#"(drop (call $text (i32.const 0) (i32.const 0) (i32.const 16) (i32.const 2) (i32.const 0) (i32.const 3)))"#,
            "no color 3",
        ),
        (
            r#"(call $blit (i32.const 0) (i32.const 0) (i32.const 1000) (i32.const 1) (i32.const 0) (i32.const 1))"#,
            "bigger than",
        ),
        (
            r#"(call $blit (i32.const 0) (i32.const 0) (i32.const 256) (i32.const 256) (i32.const 60000) (i32.const 1))"#,
            "blit: bad pointer",
        ),
        (r#"(call $random (i32.const 65535) (i32.const 2))"#, "random: bad pointer"),
        (r#"(drop (i32.load (i32.const 70000)))"#, "out of bounds"),
        (r#"unreachable"#, "unreachable"),
        (r#"(call $deep)"#, "stack"),
    ];
    for (body, why) in cases {
        let wat = format!(
            r#"(module
              (import "maki" "text" (func $text (param i32 i32 i32 i32 i32 i32) (result i32)))
              (import "maki" "blit" (func $blit (param i32 i32 i32 i32 i32 i32)))
              (import "maki" "random" (func $random (param i32 i32)))
              (memory (export "memory") 1)
              (data (i32.const 16) "Hi")
              (func $deep (call $deep))
              (func (export "maki_main") {body}))"#
        );
        match run_with(&wat, &[], LIMITS).0 {
            Stop::Crashed(message) => assert!(message.contains(why), "{body}: {message}"),
            other => panic!("{body}: {other:?}"),
        }
    }
}

#[test]
fn only_maki_functions_can_be_imported() {
    let cases = [
        (
            r#"(import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32)))"#,
            "wasi_snapshot_preview1.fd_write",
        ),
        (r#"(import "maki" "read_phrase" (func))"#, "read_phrase"),
        (r#"(import "maki" "clear" (func (param i64)))"#, "clear"),
        (r#"(import "maki" "memory" (memory 1))"#, "memory"),
    ];
    for (import, why) in cases {
        let wat = format!(r#"(module {import} (memory (export "memory") 1) (func (export "maki_main")))"#);
        let err = check(&module(&wat), LIMITS).unwrap_err();
        assert!(err.contains(why), "{import}: {err}");
    }
}

#[test]
fn what_check_requires() {
    let ok = r#"(module (memory (export "memory") 1) (func (export "maki_main")))"#;
    check(&module(ok), LIMITS).unwrap();
    let cases = [
        (
            r#"(module (memory (export "memory") 1) (func $s) (start $s) (func (export "maki_main")))"#,
            "start",
        ),
        (r#"(module (memory (export "memory") 1) (func (export "main")))"#, "maki_main"),
        (r#"(module (memory (export "memory") 1) (func (export "maki_main") (param i32)))"#, "maki_main"),
        (r#"(module (func (export "maki_main")))"#, "memory"),
        // five pages, 320 KiB, more than the limit
        (r#"(module (memory (export "memory") 5) (func (export "maki_main")))"#, "start"),
    ];
    for (wat, why) in cases {
        let err = check(&module(wat), LIMITS).unwrap_err();
        assert!(err.contains(why), "{wat}: {err}");
    }
    assert!(check(b"\0asm\x01\0\0\0garbage", LIMITS).unwrap_err().contains("not WebAssembly"));
    assert!(check(b"MZ", LIMITS).is_err());
}

#[test]
fn memory_grows_only_to_the_limit() {
    // four pages is 256 KiB, the limit: growing by one more fails, and the app sees -1
    let wat = r#"
    (module
      (import "maki" "log" (func $log (param i32 i32)))
      (memory (export "memory") 1)
      (data (i32.const 0) "grew" "limit")
      (func (export "maki_main")
        (if (i32.ne (memory.grow (i32.const 3)) (i32.const -1)) (then (call $log (i32.const 0) (i32.const 4))))
        (if (i32.eq (memory.grow (i32.const 1)) (i32.const -1)) (then (call $log (i32.const 4) (i32.const 5))))))
    "#;
    let (stop, r) = run_with(wat, &[], LIMITS);
    assert_eq!(stop, Stop::Finished);
    assert_eq!(r.logs, ["grew", "limit"]);
}

/// Imports for storage tests, and a helper that logs a result code.
const STORAGE: &str = r#"
  (import "maki" "storage_get" (func $get (param i32 i32 i32 i32) (result i32)))
  (import "maki" "storage_set" (func $set (param i32 i32 i32 i32) (result i32)))
  (import "maki" "storage_delete" (func $del (param i32 i32) (result i32)))
  (import "maki" "storage_key" (func $key (param i32 i32 i32) (result i32)))
  (import "maki" "log" (func $log (param i32 i32)))
  (memory (export "memory") 1)
  (func $say (param $n i32)
    ;; logs the result code as one character: "a" + (n + 5) for -5..20
    (i32.store8 (i32.const 900) (i32.add (i32.const 97) (i32.add (local.get $n) (i32.const 5))))
    (call $log (i32.const 900) (i32.const 1)))
"#;

fn code(n: i32) -> String { ((b'a' as i32 + n + 5) as u8 as char).to_string() }

#[test]
fn storage_keeps_values_within_the_quota() {
    let wat = format!(
        r#"(module {STORAGE}
          (data (i32.const 0) "score")
          (data (i32.const 8) "42")
          (data (i32.const 16) "name")
          (data (i32.const 24) "Kara")
          (func (export "maki_main")
            (call $say (call $get (i32.const 0) (i32.const 5) (i32.const 100) (i32.const 10)))   ;; not found
            (call $say (call $set (i32.const 0) (i32.const 5) (i32.const 8) (i32.const 2)))      ;; 0
            (call $say (call $set (i32.const 16) (i32.const 4) (i32.const 24) (i32.const 4)))    ;; 0
            (call $say (call $get (i32.const 0) (i32.const 5) (i32.const 100) (i32.const 1)))    ;; 2, one byte copied
            (call $log (i32.const 100) (i32.const 2))
            (call $say (call $key (i32.const 0) (i32.const 200) (i32.const 10)))                 ;; "name": 4
            (call $log (i32.const 200) (i32.const 4))
            (call $say (call $key (i32.const 2) (i32.const 200) (i32.const 10)))                 ;; not found
            (call $say (call $set (i32.const 0) (i32.const 5) (i32.const 0) (i32.const 1100)))   ;; over the quota
            (call $say (call $set (i32.const 0) (i32.const 0) (i32.const 8) (i32.const 2)))      ;; empty key
            (call $say (call $set (i32.const 0) (i32.const 5) (i32.const 0) (i32.const 20000)))  ;; too big
            (call $say (call $del (i32.const 16) (i32.const 4)))                                 ;; 0
            (call $say (call $del (i32.const 16) (i32.const 4)))))                               ;; not found
        "#
    );
    let (stop, r) = run_with(&wat, &[], LIMITS);
    assert_eq!(stop, Stop::Finished);
    let expected: Vec<String> = [
        code(NOT_FOUND),
        code(0),
        code(0),
        code(2),
        "4\0".into(),
        code(4),
        "name".into(),
        code(NOT_FOUND),
        code(FULL),
        code(INVALID),
        code(TOO_BIG),
        code(0),
        code(NOT_FOUND),
    ]
    .into();
    assert_eq!(r.logs, expected);
    assert_eq!(r.storage.get("score").unwrap(), b"42");
    assert!(!r.storage.contains_key("name"));
}

#[test]
fn the_quota_counts_what_was_stored_before() {
    let wat = format!(
        r#"(module {STORAGE}
          (data (i32.const 0) "b")
          (func (export "maki_main")
            (call $say (call $set (i32.const 0) (i32.const 1) (i32.const 0) (i32.const 100)))))"#
    );
    let record = Rc::new(RefCell::new(Record::default()));
    record.borrow_mut().storage.insert("a".into(), vec![0; 950]);
    let stop = run(&module(&wat), Box::new(Script(record.clone())), LIMITS);
    assert_eq!(stop, Stop::Finished);
    assert_eq!(record.borrow().logs, [code(FULL)]);
}

#[test]
fn menus_are_checked() {
    let wat = r#"
    (module
      (import "maki" "menu" (func $menu (param i32 i32) (result i32)))
      (import "maki" "log" (func $log (param i32 i32)))
      (memory (export "memory") 1)
      (data (i32.const 0) "Roll again\nReset")
      (data (i32.const 100) "fine" "bad")
      (data (i32.const 200) "one\n\nthree")
      (func (export "maki_main")
        (if (i32.eqz (call $menu (i32.const 0) (i32.const 16))) (then (call $log (i32.const 100) (i32.const 4))))
        (if (i32.eq (call $menu (i32.const 200) (i32.const 10)) (i32.const -3)) (then (call $log (i32.const 104) (i32.const 3))))))
    "#;
    let (stop, r) = run_with(wat, &[], LIMITS);
    assert_eq!(stop, Stop::Finished);
    assert_eq!(r.logs, ["fine", "bad"]);
    assert_eq!(r.menu, ["Roll again", "Reset"]);
}

#[test]
fn time_and_randomness() {
    let wat = r#"
    (module
      (import "maki" "unix_time" (func $unix (result i64)))
      (import "maki" "time_verified" (func $verified (result i32)))
      (import "maki" "millis" (func $millis (result i64)))
      (import "maki" "random" (func $random (param i32 i32)))
      (import "maki" "log" (func $log (param i32 i32)))
      (memory (export "memory") 1)
      (data (i32.const 0) "time" "rand")
      (func (export "maki_main")
        (if (i32.and
              (i64.eq (call $unix) (i64.const 1790000000))
              (i32.and (call $verified) (i64.eq (call $millis) (i64.const 0))))
          (then (call $log (i32.const 0) (i32.const 4))))
        (call $random (i32.const 100) (i32.const 4))
        (if (i32.eq (i32.load (i32.const 100)) (i32.const 0x5a5a5a5a)) (then (call $log (i32.const 4) (i32.const 4))))))
    "#;
    let (stop, r) = run_with(wat, &[], LIMITS);
    assert_eq!(stop, Stop::Finished);
    assert_eq!(r.logs, ["time", "rand"]);
}

#[test]
fn canvas_drawing_is_exact_and_clipped() {
    let mut c = Canvas::default();
    c.line(0, 0, 3, 3, Color::Light);
    assert!((0..4).all(|i| c.get(i, i)) && !c.get(1, 0));
    c.rect(10, 10, 4, 3, Color::Light, false);
    assert!(c.get(10, 10) && c.get(13, 12) && !c.get(11, 11));
    c.rect(10, 10, 4, 3, Color::Invert, true);
    assert!(!c.get(10, 10) && c.get(11, 11));
    // extremes don't panic and don't take forever
    c.line(i32::MIN, i32::MIN, i32::MAX, i32::MAX, Color::Invert);
    c.rect(i32::MIN, i32::MIN, i32::MAX, i32::MAX, Color::Light, true);
    c.text(i32::MAX, i32::MIN, "far away", Style::Tall, Color::Light);
    c.clear(Color::Dark);
    assert_eq!(c.words().iter().filter(|w| **w != 0).count(), 0);
    // blit: the top bit is the leftmost pixel
    c.blit(0, 0, 9, 2, &[0b1000_0001, 0b1000_0000, 0, 0x80], Color::Light);
    assert!(c.get(0, 0) && c.get(7, 0) && c.get(8, 0) && c.get(8, 1) && !c.get(1, 0) && !c.get(0, 1));
    // the display wants set bits dark
    assert_eq!(c.to_display()[0] & 1, 0);
    assert_eq!(c.to_display()[4] & 1, 1);
}

#[test]
fn text_width_matches_what_text_draws() {
    for style in [Style::Regular, Style::Bold, Style::Small, Style::Mono, Style::Tall] {
        let mut c = Canvas::default();
        let end = c.text(3, 5, "Dice 42!", style, Color::Light);
        let w = Canvas::text_width("Dice 42!", style);
        assert_eq!(end - 3 - 1, w, "{style:?}");
        let rightmost = (0..128).rev().find(|&x| (0..110).any(|y| c.get(x, y))).unwrap();
        assert!(rightmost <= 3 + w, "{style:?}: drawn to {rightmost}, width {w}");
        assert!(Style::Regular.height() > 0);
    }
    // unknown characters draw as the replacement character, not nothing
    assert!(Canvas::text_width("\u{e000}", Style::Regular) > 0);
}

#[test]
fn qr_codes_fit_or_say_so() {
    let mut c = Canvas::default();
    let side = c.qr(0, 0, b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 100).unwrap();
    assert!(side <= 100 && side > 50);
    // quiet zone light, a finder pattern's corner dark
    assert!(c.get(0, 0) && c.get(1, 1));
    let scale = side / 29;
    assert!(!c.get(2 * scale, 2 * scale));
    // too much for the room, or for any QR code
    assert_eq!(c.qr(0, 0, &[b'x'; 900], 60), None);
    assert_eq!(c.qr(0, 0, &[b'x'; 3000], 110), None);
}

#[test]
fn admit_says_what_maki_takes() {
    use maki_bundle::{Kind, Manifest};
    let ok = module(r#"(module (memory (export "memory") 1) (func (export "maki_main")))"#);
    let m = Manifest {
        id: "com.example.ok".into(),
        name: "OK".into(),
        version: 1,
        label: String::new(),
        kind: Kind::Wasm,
        api: 1,
        firmware: String::new(),
        permissions: vec![],
        storage_kib: 4,
        memory_kib: 64,
        backup: true,
        description: String::new(),
        wallet: None,
    };
    let limits = admit(&m, &ok).unwrap();
    assert_eq!((limits.memory, limits.storage), (64 * 1024, 4 * 1024));
    let refusals = [
        (Manifest { kind: Kind::Native, api: 0, firmware: "x".into(), ..m.clone() }, "native"),
        (Manifest { api: API_VERSION + 1, ..m.clone() }, "newer maki"),
        (Manifest { memory_kib: MAX_MEMORY_KIB + 1, ..m.clone() }, "memory"),
        (Manifest { storage_kib: MAX_STORAGE_KIB + 1, ..m.clone() }, "storage"),
        (Manifest { memory_kib: 32, ..m.clone() }, "can't start"),
    ];
    for (manifest, why) in refusals {
        let err = admit(&manifest, &ok).unwrap_err();
        assert!(err.contains(why), "{why}: {err}");
    }
}

/// A native app built for either app service maki runs gets in, and one built for another
/// doesn't. The jog dial goes only to apps that know it: native ones built for maki-native-2, and
/// WebAssembly ones of host API 8 or later.
#[test]
fn native_apps_of_either_service_get_in_and_the_dial_goes_to_apps_that_know_it() {
    use maki_bundle::{Kind, Manifest};
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../maki-native/tests/fixtures/hello-native.maki"
    ))
    .unwrap();
    let b = maki_bundle::read(&bytes).unwrap();
    assert_eq!(b.manifest.firmware, "maki-native-1");
    assert!(admit(&b.manifest, b.code).is_ok());
    assert!(!knows_jog(&b.manifest));
    let newer = Manifest { firmware: "maki-native-2".into(), ..b.manifest.clone() };
    assert!(admit(&newer, b.code).is_ok());
    assert!(knows_jog(&newer));
    for firmware in ["maki-native-3", ""] {
        let err = admit(&Manifest { firmware: firmware.into(), ..b.manifest.clone() }, b.code).unwrap_err();
        assert!(err.contains("this maki runs maki-native-1 and maki-native-2"), "{err}");
    }
    let wasm = Manifest { kind: Kind::Wasm, api: API_JOG - 1, firmware: String::new(), ..b.manifest.clone() };
    assert!(!knows_jog(&wasm));
    assert!(knows_jog(&Manifest { api: API_JOG, ..wasm }));
}

/// Runs an app calling one of maki's functions, with `data` at 0, and keeping the function's
/// result (4 bytes, little-endian) in storage as "r": `call` is the call's WAT, which leaves
/// the result on the stack.
fn call_with(imports: &str, data: &str, call: &str, record: Record, limits: Limits) -> (Stop, Record) {
    let wat = format!(
        r#"(module
          {imports}
          (import "maki" "storage_set" (func $set (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "{data}")
          (data (i32.const 1000) "r")
          (func (export "maki_main")
            (i32.store (i32.const 1004) {call})
            (drop (call $set (i32.const 1000) (i32.const 1) (i32.const 1004) (i32.const 4)))))"#
    );
    let record = Rc::new(RefCell::new(record));
    let stop = run(&module(&wat), Box::new(Script(record.clone())), limits);
    let r = Rc::try_unwrap(record).ok().unwrap().into_inner();
    (stop, r)
}

fn result_of(r: &Record) -> i32 { i32::from_le_bytes(r.storage["r"][..4].try_into().unwrap()) }

#[test]
fn gated_functions_need_their_permission() {
    use maki_bundle::Permission;
    let signatures = [
        ("ask", "(param i32 i32 i32) (result i32)"),
        ("ask_review", "(param i32 i32 i32) (result i32)"),
        ("key_secret", "(param i32 i32 i32) (result i32)"),
        ("key_public", "(param i32 i32 i32) (result i32)"),
        ("key_sign", "(param i32 i32 i32 i32 i32) (result i32)"),
        ("key_schnorr_public", "(param i32 i32 i32) (result i32)"),
        ("key_schnorr_sign", "(param i32 i32 i32 i32) (result i32)"),
        ("key_x25519_public", "(param i32 i32 i32) (result i32)"),
        ("key_x25519_agree", "(param i32 i32 i32 i32) (result i32)"),
        ("type_text", "(param i32 i32) (result i32)"),
        ("key_press", "(param i32 i32) (result i32)"),
        ("link_read", "(param i32 i32) (result i32)"),
        ("link_reply", "(param i32 i32) (result i32)"),
        ("camera_scan_qr", "(param i32 i32) (result i32)"),
        ("motion_read", "(param i32) (result i32)"),
        ("motion_range", "(param i32) (result i32)"),
        ("wallet_fingerprint", "(param i32) (result i32)"),
        ("wallet_public", "(param i32 i32 i32 i32 i32) (result i32)"),
        ("wallet_review", "(param i32 i32 i32 i32) (result i32)"),
        ("wallet_sign", "(param i32 i32 i32 i32 i32 i32) (result i32)"),
        ("wallet_subaddress", "(param i32 i32 i32 i32 i32) (result i32)"),
        ("wallet_show_backup", "(param i32 i32) (result i32)"),
        ("wallet_monero_view_key", "(param i32 i32 i32) (result i32)"),
        ("wallet_monero_key_image", "(param i32 i32 i32 i32) (result i32)"),
        ("wallet_monero_sign", "(param i32 i32 i32 i32 i32 i32) (result i32)"),
        ("wallet_sign_ed25519", "(param i32 i32 i32 i32 i32) (result i32)"),
    ];
    assert_eq!(signatures.len(), GATED.len());
    for (name, signature) in signatures {
        let (_, p) = GATED.iter().find(|(n, _)| *n == name).unwrap();
        let wat = format!(
            r#"(module (import "maki" "{name}" (func {signature})) (memory (export "memory") 1) (func (export "maki_main")))"#
        );
        let err = check(&module(&wat), LIMITS).unwrap_err();
        assert!(err.contains(&format!("needs the {} permission", p.name())), "{name}: {err}");
        check(&module(&wat), with(&[*p])).unwrap();
        // one permission doesn't stand in for another
        let other = if *p == Permission::Keys { Permission::Ask } else { Permission::Keys };
        assert!(check(&module(&wat), with(&[other])).is_err(), "{name}");
    }
}

#[test]
fn an_apps_keys_are_its_secret_and_the_ed25519_key_from_it() {
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    use maki_bundle::Permission;
    let wat = r#"(module
      (import "maki" "key_secret" (func $secret (param i32 i32 i32) (result i32)))
      (import "maki" "key_public" (func $public (param i32 i32 i32) (result i32)))
      (import "maki" "key_sign" (func $sign (param i32 i32 i32 i32 i32) (result i32)))
      (import "maki" "storage_set" (func $set (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1)
      (data (i32.const 0) "ssh")
      (data (i32.const 16) "sign this")
      (data (i32.const 32) "spg")
      (func (export "maki_main")
        (drop (call $secret (i32.const 0) (i32.const 3) (i32.const 100)))
        (drop (call $public (i32.const 0) (i32.const 3) (i32.const 200)))
        (drop (call $sign (i32.const 0) (i32.const 3) (i32.const 16) (i32.const 9) (i32.const 300)))
        (drop (call $set (i32.const 32) (i32.const 1) (i32.const 100) (i32.const 32)))
        (drop (call $set (i32.const 33) (i32.const 1) (i32.const 200) (i32.const 32)))
        (drop (call $set (i32.const 34) (i32.const 1) (i32.const 300) (i32.const 64)))))"#;
    let record = Rc::new(RefCell::new(Record::default()));
    let stop = run(&module(wat), Box::new(Script(record.clone())), with(&[Permission::Keys]));
    assert_eq!(stop, Stop::Finished);
    let r = record.borrow();
    let secret = secret_for("ssh");
    assert_eq!(r.storage["s"], secret);
    let public = SigningKey::from_bytes(&secret).verifying_key();
    assert_eq!(r.storage["p"], public.to_bytes());
    let signature = Signature::from_slice(&r.storage["g"]).unwrap();
    public.verify(b"sign this", &signature).unwrap();
    assert!(public.verify(b"sign that", &signature).is_err());

    // locked: no secret, and the app is told so
    let imports = r#"(import "maki" "key_sign" (func $sign (param i32 i32 i32 i32 i32) (result i32)))"#;
    let call = "(call $sign (i32.const 0) (i32.const 3) (i32.const 0) (i32.const 3) (i32.const 100))";
    let (stop, r) = call_with(
        imports,
        "ssh",
        call,
        Record { locked: true, ..Default::default() },
        with(&[Permission::Keys]),
    );
    assert_eq!((stop, result_of(&r)), (Stop::Finished, FAILED));
    // a label with a control character isn't one
    let call = "(call $sign (i32.const 0) (i32.const 4) (i32.const 0) (i32.const 3) (i32.const 100))";
    let (_, r) = call_with(imports, "ss\\0ah", call, Record::default(), with(&[Permission::Keys]));
    assert_eq!(result_of(&r), INVALID);
    // too much to sign
    let call = format!(
        "(call $sign (i32.const 0) (i32.const 3) (i32.const 0) (i32.const {}) (i32.const 100))",
        MAX_SIGN + 1
    );
    let (_, r) = call_with(imports, "ssh", &call, Record::default(), with(&[Permission::Keys]));
    assert_eq!(result_of(&r), TOO_BIG);
    // a label longer than there can be stops the app
    let call = format!(
        "(call $sign (i32.const 0) (i32.const {}) (i32.const 0) (i32.const 3) (i32.const 100))",
        MAX_LABEL + 1
    );
    let (stop, _) = call_with(imports, "ssh", &call, Record::default(), with(&[Permission::Keys]));
    assert!(matches!(stop, Stop::Crashed(_)), "{stop:?}");
}

#[test]
fn asks_reach_the_owner_and_bring_back_the_answer() {
    use maki_bundle::Permission;
    let imports = r#"(import "maki" "ask" (func $ask (param i32 i32 i32) (result i32)))"#;
    let text = "Sign in?\\0aas kara@example\\0asign\\0acancel";
    let len = "Sign in?\nas kara@example\nsign\ncancel".len();
    let call = format!("(call $ask (i32.const 0) (i32.const {len}) (i32.const 0))");
    for (answer, code) in [(Answer::Yes, 0), (Answer::No, 1), (Answer::NoAnswer, 2)] {
        let record = Record { answers: [answer].into(), ..Default::default() };
        let (stop, r) = call_with(imports, text, &call, record, with(&[Permission::Ask]));
        assert_eq!((stop, result_of(&r)), (Stop::Finished, code));
        assert_eq!(
            r.asks,
            [Ask {
                question: "Sign in?".into(),
                detail: "as kara@example".into(),
                yes: "sign".into(),
                no: "cancel".into(),
                timeout_s: ASK_TIMEOUT_S
            }]
        );
    }
    // just a question, and how long to wait, within what maki allows
    for (timeout, expect) in [(10, 10), (1, 5), (1000, MAX_ASK_TIMEOUT_S), (-1, ASK_TIMEOUT_S)] {
        let call = format!("(call $ask (i32.const 0) (i32.const 8) (i32.const {timeout}))");
        let (_, r) = call_with(imports, "Proceed?", &call, Record::default(), with(&[Permission::Ask]));
        assert_eq!(
            r.asks[0],
            Ask {
                question: "Proceed?".into(),
                detail: "".into(),
                yes: "".into(),
                no: "".into(),
                timeout_s: expect
            }
        );
    }
    // what isn't an ask never reaches the owner
    let too_long = "q".repeat(MAX_QUESTION + 1);
    for bad in ["", "\\0adetail", "a\\0ab\\0ac\\0ad\\0ae", "tab\\09in", too_long.as_str()] {
        let len = bad.replace("\\0a", "\n").replace("\\09", "\t").len();
        let call = format!("(call $ask (i32.const 0) (i32.const {len}) (i32.const 0))");
        let (_, r) = call_with(imports, bad, &call, Record::default(), with(&[Permission::Ask]));
        assert_eq!(result_of(&r), INVALID, "{bad:?}");
        assert!(r.asks.is_empty());
    }
}

#[test]
fn typing_takes_plain_text_only() {
    use maki_bundle::Permission;
    let imports = r#"(import "maki" "type_text" (func $type (param i32 i32) (result i32)))"#;
    let call = |len: usize| format!("(call $type (i32.const 0) (i32.const {len}))");
    let (_, r) =
        call_with(imports, "ls -la\\0a\\09x", &call(9), Record::default(), with(&[Permission::Keyboard]));
    assert_eq!((result_of(&r), r.typed.clone()), (0, vec!["ls -la\n\tx".to_string()]));
    // not ASCII, or a control character: nothing typed
    for bad in ["caf\\c3\\a9", "bell\\07"] {
        // five bytes each once WAT decodes the escapes: "caf" + é (two), "bell" + BEL (one)
        let len = 5;
        let (_, r) = call_with(imports, bad, &call(len), Record::default(), with(&[Permission::Keyboard]));
        assert_eq!(result_of(&r), INVALID, "{bad}");
        assert!(r.typed.is_empty());
    }
    let (_, r) =
        call_with(imports, "x", &call(MAX_TYPE + 1), Record::default(), with(&[Permission::Keyboard]));
    assert_eq!(result_of(&r), TOO_BIG);
    // maki couldn't type (not plugged in, or not in front)
    let (_, r) = call_with(
        imports,
        "hi",
        &call(2),
        Record { locked: true, ..Default::default() },
        with(&[Permission::Keyboard]),
    );
    assert_eq!(result_of(&r), FAILED);
}

#[test]
fn keys_beyond_text_are_pressed_and_shortcuts_are_not() {
    use maki_bundle::Permission;
    let imports = r#"(import "maki" "key_press" (func $press (param i32 i32) (result i32)))"#;
    let press = |code: i32, shift: i32| format!("(call $press (i32.const {code}) (i32.const {shift}))");
    // Page Down, and Shift+F5
    for (code, shift) in [(0x4e, 0), (0x3e, 1)] {
        let (_, r) =
            call_with(imports, "", &press(code, shift), Record::default(), with(&[Permission::Keyboard]));
        assert_eq!((result_of(&r), r.pressed.clone()), (0, vec![(code as u8, shift != 0)]));
    }
    // letters are type_text's; Caps Lock, Print Screen, the keypad, Power, and Ctrl, Alt and
    // Command (0xe0 on) are no app's to press
    for code in [0x04, 0x39, 0x46, 0x53, 0x66, 0xe0, 0xe3, 0x14e, -1] {
        let (_, r) =
            call_with(imports, "", &press(code, 0), Record::default(), with(&[Permission::Keyboard]));
        assert_eq!(result_of(&r), INVALID, "{code:#x}");
        assert!(r.pressed.is_empty());
    }
    // maki couldn't press it (not plugged in, or not in front)
    let (_, r) = call_with(
        imports,
        "",
        &press(0x4e, 0),
        Record { locked: true, ..Default::default() },
        with(&[Permission::Keyboard]),
    );
    assert_eq!(result_of(&r), FAILED);
}

#[test]
fn an_app_can_have_the_whole_screen_dark() {
    let imports = r#"(import "maki" "screen_dark" (func $dark (param i32)))"#;
    let wat = format!(
        r#"(module {imports} (memory (export "memory") 1)
            (func (export "maki_main") (call $dark (i32.const 1))))"#
    );
    let record = Rc::new(RefCell::new(Record::default()));
    run(&module(&wat), Box::new(Script(record.clone())), with(&[]));
    assert!(record.borrow().dark);
}

#[test]
fn the_accelerometers_range_is_one_it_has() {
    use maki_bundle::Permission;
    let imports = r#"(import "maki" "motion_range" (func $range (param i32) (result i32)))"#;
    for (asked, got) in [(0, 2), (2, 2), (3, 4), (6, 8), (16, 16), (100, 16), (-5, 2)] {
        let call = format!("(call $range (i32.const {asked}))");
        let (_, r) = call_with(imports, "", &call, Record::default(), with(&[Permission::Motion]));
        assert_eq!((result_of(&r), r.range), (got, got as u8), "{asked}");
    }
}

#[test]
fn messages_come_with_an_event_and_get_one_answer_each() {
    use maki_bundle::Permission;
    // an app that answers each message with it reversed, and says -1 to a second answer
    let wat = r#"(module
      (import "maki" "wait" (func $wait (param i32) (result i32)))
      (import "maki" "link_read" (func $read (param i32 i32) (result i32)))
      (import "maki" "link_reply" (func $reply (param i32 i32) (result i32)))
      (import "maki" "log" (func $log (param i32 i32)))
      (memory (export "memory") 1)
      (data (i32.const 900) "second answer refused")
      (func (export "maki_main")
        (local $n i32) (local $i i32)
        (loop $events
          (if (i32.eq (call $wait (i32.const -1)) (i32.const 7))
            (then
              ;; the message at 0, at most 64 bytes of it; its reverse at 100
              (local.set $n (call $read (i32.const 0) (i32.const 64)))
              (local.set $i (i32.const 0))
              (block $done
                (loop $rev
                  (br_if $done (i32.ge_s (local.get $i) (local.get $n)))
                  (i32.store8 (i32.add (i32.const 100) (local.get $i))
                    (i32.load8_u (i32.sub (i32.sub (local.get $n) (i32.const 1)) (local.get $i))))
                  (local.set $i (i32.add (local.get $i) (i32.const 1)))
                  (br $rev)))
              (drop (call $reply (i32.const 100) (local.get $n)))
              (if (i32.eq (call $reply (i32.const 100) (local.get $n)) (i32.const -1))
                (then (call $log (i32.const 900) (i32.const 21))))
              (br $events)))
          (br_if $events (i32.const 0))))
    )"#;
    let record = Record {
        events: [Event::Message, Event::Message, Event::Exit].into(),
        inbox: [b"hello".to_vec(), b"maki".to_vec()].into(),
        ..Default::default()
    };
    let record = Rc::new(RefCell::new(record));
    let stop = run(&module(wat), Box::new(Script(record.clone())), with(&[Permission::Link]));
    assert_eq!(stop, Stop::Finished);
    let r = record.borrow();
    assert_eq!(r.replies, [b"olleh".to_vec(), b"ikam".to_vec()]);
    assert_eq!(r.logs, ["second answer refused", "second answer refused"]);

    // nothing to read before a message comes
    let imports = r#"(import "maki" "link_read" (func $read (param i32 i32) (result i32)))"#;
    let (_, r) = call_with(
        imports,
        "",
        "(call $read (i32.const 0) (i32.const 64))",
        Record::default(),
        with(&[Permission::Link]),
    );
    assert_eq!(result_of(&r), NOT_FOUND);
    // too big an answer
    let imports = r#"(import "maki" "link_reply" (func $reply (param i32 i32) (result i32)))"#;
    let call = format!("(call $reply (i32.const 0) (i32.const {}))", MAX_MESSAGE + 1);
    let (_, r) = call_with(
        imports,
        "",
        &call,
        Record { current: Some(vec![1]), ..Default::default() },
        with(&[Permission::Link]),
    );
    assert_eq!(result_of(&r), TOO_BIG);
}

#[test]
fn the_camera_scans_qr_codes_and_motion_reads_the_accelerometer() {
    use maki_bundle::Permission;
    let imports = r#"(import "maki" "camera_scan_qr" (func $scan (param i32 i32) (result i32)))"#;
    let call = "(call $scan (i32.const 0) (i32.const 8))";
    let wat_with = |imports: &str, call: &str| (imports.to_string(), call.to_string());
    let (i, c) = wat_with(imports, call);
    let (_, r) = call_with(
        &i,
        "",
        &c,
        Record { qr: Some("otpauth://totp/x".into()), ..Default::default() },
        with(&[Permission::Camera]),
    );
    // its whole length, as far as it fits
    assert_eq!((result_of(&r), r.scans), (16, 1));
    let (_, r) = call_with(&i, "", &c, Record::default(), with(&[Permission::Camera]));
    assert_eq!(result_of(&r), NOT_FOUND);

    let imports = r#"(import "maki" "motion_read" (func $read (param i32) (result i32)))"#;
    let (_, r) = call_with(
        imports,
        "",
        "(call $read (i32.const 0))",
        Record { motion: Some([12, -980, 1000]), ..Default::default() },
        with(&[Permission::Motion]),
    );
    assert_eq!(result_of(&r), 0);
    let (_, r) =
        call_with(imports, "", "(call $read (i32.const 0))", Record::default(), with(&[Permission::Motion]));
    assert_eq!(result_of(&r), FAILED);
    // what it read, laid out as the SDK reads it
    let wat = r#"(module
      (import "maki" "motion_read" (func $read (param i32) (result i32)))
      (import "maki" "storage_set" (func $set (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1)
      (data (i32.const 100) "m")
      (func (export "maki_main")
        (drop (call $read (i32.const 0)))
        (drop (call $set (i32.const 100) (i32.const 1) (i32.const 0) (i32.const 6)))))"#;
    let record = Rc::new(RefCell::new(Record { motion: Some([12, -980, 1000]), ..Default::default() }));
    run(&module(wat), Box::new(Script(record.clone())), with(&[Permission::Motion]));
    assert_eq!(record.borrow().storage["m"], [12, 0, 0x2c, 0xfc, 0xe8, 0x03]);
}

/// A native app's requests go straight to a `Session`, whatever their size (no WebAssembly
/// memory bounds them): too long a menu or ask is refused before it's split up.
#[test]
fn a_session_refuses_text_too_long_before_splitting_it() {
    let record = Rc::new(RefCell::new(Record::default()));
    let mut session = Session::new(Box::new(Script(record.clone())), with(&[maki_bundle::Permission::Ask]));
    assert_eq!(session.menu(&"Go\n".repeat(200_000)), INVALID);
    assert_eq!(session.ask(&"Sure?\n".repeat(200_000), 30), TOO_BIG);
    session.log(&"é".repeat(10_000));
    {
        let r = record.borrow();
        assert!(r.menu.is_empty() && r.asks.is_empty());
        assert!(r.logs[0].len() <= MAX_LOG && r.logs[0].chars().all(|c| c == 'é'));
    }
    // within the bounds, as before
    assert_eq!(session.menu(&["Go"; MAX_MENU_ITEMS].join("\n")), 0);
    assert_eq!(record.borrow().menu.len(), MAX_MENU_ITEMS);
}

#[test]
fn an_app_calling_what_came_later_says_so_in_its_manifest() {
    let wat = r#"(module (import "maki" "key_schnorr_sign" (func (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1) (func (export "maki_main")))"#;
    let code = module(wat);
    let manifest = |api: u16| maki_bundle::Manifest {
        id: "org.example.later".into(),
        name: "Later".into(),
        version: 1,
        label: "1.0".into(),
        kind: maki_bundle::Kind::Wasm,
        api,
        firmware: String::new(),
        permissions: vec![(maki_bundle::Permission::Keys, "for a key".into())],
        storage_kib: 1,
        memory_kib: 64,
        backup: true,
        description: String::new(),
        wallet: None,
    };
    let err = admit(&manifest(1), &code).unwrap_err();
    assert!(err.contains("key_schnorr_sign, which came with host API 2, and its manifest says 1"), "{err}");
    admit(&manifest(2), &code).unwrap();
    // and an older maki says it needs a newer one
    assert!(admit(&manifest(API_VERSION + 1), &code).unwrap_err().contains("needs a newer maki"));
}

fn path(p: &str) -> Vec<u32> { maki_hd::parse_path(p).unwrap() }

/// A session for a wallet app with these paths, on a platform whose keys are the test phrase's.
fn wallet_session(paths: &[&str], permissions: &[maki_bundle::Permission]) -> (Session, Rc<RefCell<Record>>) {
    wallet_session_on(maki_bundle::Curve::Secp256k1, paths, permissions)
}

fn wallet_session_on(
    curve: maki_bundle::Curve,
    paths: &[&str],
    permissions: &[maki_bundle::Permission],
) -> (Session, Rc<RefCell<Record>>) {
    let record = Rc::new(RefCell::new(Record::default()));
    let mut s = Session::new(Box::new(Script(record.clone())), with(permissions));
    s.wallet = Some(maki_bundle::Wallet { curve, paths: paths.iter().map(|p| path(p)).collect() });
    (s, record)
}

const REVIEW: &str = "Sign and spend?\n0.0007 BTC in all\x1eSend 1 of 1\x1f0.0007 BTC\x1fbc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu\x1eFee\x1f0.00005 BTC\x1f\x1f24 sat/vB";

#[test]
fn a_wallet_app_gets_its_own_paths_and_no_others() {
    use maki_bundle::Permission;
    use maki_hd::Keys;
    let keys = maki_hd::seed::SeedKeys::from_seed(&test_seed()).unwrap();
    let (mut s, _) = wallet_session(&["m/84'/0'", "m/84'/1'"], &[Permission::Wallet]);
    assert_eq!(s.wallet_fingerprint().unwrap(), keys.fingerprint().unwrap());
    let p = path("m/84'/0'/0'/0/0");
    let public = s.wallet_public(&p, WALLET_PUBLIC).unwrap();
    let theirs = keys.public(&p).unwrap();
    assert_eq!(public[..33], theirs.key);
    assert_eq!(public[33..65], theirs.chain_code);
    assert_eq!(public[65..], theirs.parent_fingerprint);
    assert_eq!(s.wallet_public(&p, WALLET_UNCOMPRESSED).unwrap(), keys.uncompressed(&p).unwrap());
    assert_eq!(s.wallet_public(&path("m/84'/1'/0'"), WALLET_PUBLIC).unwrap().len(), 69);
    // another purpose, another coin, above its paths, or the master key: refused
    for other in ["m/86'/0'/0'/0/0", "m/44'/60'/0'/0/0", "m/84'", "m"] {
        assert_eq!(s.wallet_public(&path(other), WALLET_PUBLIC), Err(REFUSED), "{other}");
    }
    assert_eq!(s.wallet_public(&p, 9), Err(INVALID));
    // no permission, no keys, paths or not
    let (mut s, _) = wallet_session(&["m/84'/0'"], &[Permission::Keys]);
    assert_eq!(s.wallet_public(&p, WALLET_PUBLIC), Err(REFUSED));
    assert_eq!(s.wallet_fingerprint(), Err(REFUSED));
}

#[test]
fn a_signature_needs_a_yes_to_a_review_on_makis_screen() {
    use maki_bundle::Permission;
    let (mut s, record) = wallet_session(&["m/84'/0'", "m/86'/0'"], &[Permission::Wallet]);
    let (p, digest) = (path("m/84'/0'/0'/0/0"), [7u8; 32]);
    // nothing asked yet
    assert_eq!(s.wallet_sign(&p, &digest, WALLET_SIGN_ECDSA), Err(REFUSED));
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(s.wallet_review(REVIEW, 2, 0), 0);
    let review = record.borrow().reviews[0].clone();
    assert_eq!((review.question.as_str(), review.detail.as_str()), ("Sign and spend?", "0.0007 BTC in all"));
    assert_eq!(review.pages.len(), 2);
    assert_eq!(
        review.pages[0],
        Page {
            heading: "Send 1 of 1".into(),
            value: "0.0007 BTC".into(),
            mono: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu".into(),
            prose: String::new()
        }
    );
    assert_eq!((review.pages[1].mono.as_str(), review.pages[1].prose.as_str()), ("", "24 sat/vB"));
    assert_eq!(review.timeout_s, REVIEW_TIMEOUT_S);
    // two signatures, as it said; the third isn't allowed
    let sig = s.wallet_sign(&p, &digest, WALLET_SIGN_ECDSA).unwrap();
    assert_eq!(sig.len(), 65);
    let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(
        &digest,
        &k256::ecdsa::Signature::from_slice(&sig[..64]).unwrap(),
        k256::ecdsa::RecoveryId::from_byte(sig[64]).unwrap(),
    )
    .unwrap();
    assert_eq!(recovered.to_sec1_bytes()[..], s.wallet_public(&p, WALLET_PUBLIC).unwrap()[..33]);
    let tp = path("m/86'/0'/0'/0/0");
    let sig = s.wallet_sign(&tp, &digest, WALLET_SIGN_TAPROOT).unwrap();
    let output = s.wallet_public(&tp, WALLET_TAPROOT).unwrap();
    let key = k256::schnorr::VerifyingKey::from_bytes(&output).unwrap();
    key.verify_raw(&digest, &k256::schnorr::Signature::try_from(&sig[..]).unwrap()).unwrap();
    assert_eq!(s.wallet_sign(&p, &digest, WALLET_SIGN_ECDSA), Err(REFUSED));
    // off its paths, even with a yes
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(s.wallet_review(REVIEW, 1, 0), 0);
    assert_eq!(s.wallet_sign(&path("m/44'/60'/0'/0/0"), &digest, WALLET_SIGN_ECDSA), Err(REFUSED));
    // a no, or no answer, allows nothing; and a new review ends what the last one allowed
    record.borrow_mut().answers.push_back(Answer::No);
    assert_eq!(s.wallet_review(REVIEW, 5, 0), 1);
    assert_eq!(s.wallet_sign(&p, &digest, WALLET_SIGN_ECDSA), Err(REFUSED));
    assert_eq!(s.wallet_review(REVIEW, 5, 0), 2);
    assert_eq!(s.wallet_sign(&p, &digest, WALLET_SIGN_ECDSA), Err(REFUSED));
    // a yes lasts two minutes
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(s.wallet_review(REVIEW, 3, 0), 0);
    record.borrow_mut().now = 5_000 + ALLOWANCE_MS + 1;
    assert_eq!(s.wallet_sign(&p, &digest, WALLET_SIGN_ECDSA), Err(REFUSED));
    // a digest is 32 bytes, and the schemes are three
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(s.wallet_review(REVIEW, 3, 0), 0);
    assert_eq!(s.wallet_sign(&p, &[1; 31], WALLET_SIGN_ECDSA), Err(INVALID));
    assert_eq!(s.wallet_sign(&p, &digest, WALLET_PUBLIC), Err(INVALID));
}

#[test]
fn any_app_that_may_ask_can_ask_after_pages_but_a_yes_signs_nothing() {
    use maki_bundle::Permission;
    let text = "Run it as root?\nsudo on laptop\x1eCommand\x1f\x1f/usr/bin/systemctl restart nginx\x1eAsked by\x1fkara\x1f\x1fin /home/kara";
    // an app with the ask permission, and no wallet
    let record = Rc::new(RefCell::new(Record::default()));
    let mut s = Session::new(Box::new(Script(record.clone())), with(&[Permission::Ask]));
    record.borrow_mut().answers.extend([Answer::Yes, Answer::No]);
    assert_eq!(s.ask_review(text, 0), 0);
    assert_eq!(s.ask_review(text, 9999), 1);
    assert_eq!(s.ask_review(text, 0), 2);
    let reviews = record.borrow().reviews.clone();
    assert_eq!(
        (reviews[0].question.as_str(), reviews[0].detail.as_str()),
        ("Run it as root?", "sudo on laptop")
    );
    assert_eq!(
        reviews[0].pages,
        [
            Page {
                heading: "Command".into(),
                mono: "/usr/bin/systemctl restart nginx".into(),
                ..Page::default()
            },
            Page {
                heading: "Asked by".into(),
                value: "kara".into(),
                prose: "in /home/kara".into(),
                ..Page::default()
            },
        ]
    );
    // an ask's answers unless the app names its own, and a review's time
    assert_eq!((reviews[0].yes.as_str(), reviews[0].no.as_str()), ("allow", "deny"));
    assert_eq!((reviews[0].timeout_s, reviews[1].timeout_s), (REVIEW_TIMEOUT_S, MAX_REVIEW_TIMEOUT_S));
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(s.ask_review("Run it?\n\nrun\ndon't\x1eCommand\x1f\x1fls", 60), 0);
    let last = record.borrow().reviews.last().unwrap().clone();
    assert_eq!((last.yes.as_str(), last.no.as_str(), last.timeout_s), ("run", "don't", 60));
    // what doesn't fit a review doesn't fit here either, and needs the permission
    assert_eq!(s.ask_review("Run?\x1e \x1fno heading", 0), INVALID);
    assert_eq!(s.ask_review(&"x".repeat(MAX_REVIEW + 1), 0), TOO_BIG);
    let mut none =
        Session::new(Box::new(Script(Rc::new(RefCell::new(Record::default())))), with(&[Permission::Keys]));
    assert_eq!(none.ask_review(text, 0), REFUSED);
    // a wallet app's yes to one allows no signature
    let (mut s, record) = wallet_session(&["m/84'/0'"], &[Permission::Wallet, Permission::Ask]);
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(s.ask_review(REVIEW, 0), 0);
    assert_eq!(s.wallet_sign(&path("m/84'/0'/0'/0/0"), &[7; 32], WALLET_SIGN_ECDSA), Err(REFUSED));
}

#[test]
fn reviews_must_fit_makis_screen() {
    use maki_bundle::Permission;
    let (mut s, record) = wallet_session(&["m/84'/0'"], &[Permission::Wallet]);
    let long = "x".repeat(MAX_PAGE_VALUE + 1);
    let longer = "x".repeat(MAX_PAGE_TEXT + 1);
    let heading = "h".repeat(MAX_HEADING + 1);
    let many: String = (0..=MAX_PAGES).map(|_| "\x1eA\x1fb").collect();
    for bad in [
        String::new(),
        "\nno question".into(),
        "Sign?\x1eno value".into(),
        "Sign?\x1ea\x1fb\x1fc\x1fd\x1fe".into(),
        "Sign?\x1e \x1fno heading".into(),
        "Sign?\x1ea\x1fbold\nover lines".into(),
        format!("Sign?\x1ea\x1fb\x1f{longer}"),
        format!("Sign?\x1ea\x1f{long}"),
        format!("Sign?\x1e{heading}\x1fv"),
        format!("Sign?{many}"),
        "Sign?\ta tab".into(),
    ] {
        assert_eq!(s.wallet_review(&bad, 1, 0), INVALID, "{bad:?}");
    }
    assert_eq!(s.wallet_review(REVIEW, MAX_SIGNATURES + 1, 0), INVALID);
    assert_eq!(s.wallet_review(&"x".repeat(MAX_REVIEW + 1), 1, 0), TOO_BIG);
    assert!(record.borrow().reviews.is_empty(), "none reached the screen");
    // a value may run over lines, and a timeout is kept within bounds
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(s.wallet_review("Sign?\x1eData\x1f\x1fline one\nline two\x1fwhat it is", 0, 9999), 0);
    assert_eq!(record.borrow().reviews[0].timeout_s, MAX_REVIEW_TIMEOUT_S);
    // a locked maki has no keys to give
    record.borrow_mut().locked = true;
    assert_eq!(s.wallet_public(&path("m/84'/0'/0'"), WALLET_PUBLIC), Err(LOCKED));
}

#[test]
fn wallet_functions_came_with_host_api_3() {
    let code = module(
        r#"(module (import "maki" "wallet_fingerprint" (func (param i32) (result i32))) (memory (export "memory") 1) (func (export "maki_main")))"#,
    );
    let manifest = |api: u16| maki_bundle::Manifest {
        id: "org.example.wallet".into(),
        name: "Wallet".into(),
        version: 1,
        label: "1.0".into(),
        kind: maki_bundle::Kind::Wasm,
        api,
        firmware: String::new(),
        permissions: vec![(maki_bundle::Permission::Wallet, "to sign".into())],
        storage_kib: 1,
        memory_kib: 64,
        backup: true,
        description: String::new(),
        wallet: Some(maki_bundle::Wallet {
            curve: maki_bundle::Curve::Secp256k1,
            paths: vec![path("m/84'/0'")],
        }),
    };
    let err = admit(&manifest(2), &code).unwrap_err();
    assert!(err.contains("wallet_fingerprint, which came with host API 3, and its manifest says 2"), "{err}");
    admit(&manifest(3), &code).unwrap();
    assert_eq!(load(&manifest(3), &code).unwrap().wallet, manifest(3).wallet);
}

#[test]
fn monero_keys_and_backup_come_from_maki_on_its_coin_alone() {
    use maki_bundle::Permission;
    use maki_xmr::{Kind, Network, address};
    let (mut s, record) = wallet_session(&["m/44'/128'"], &[Permission::Wallet]);
    let p = path("m/44'/128'/0'/0/0");
    // the public spend and view keys: the account's own address
    let keys = s.wallet_public(&p, WALLET_MONERO).unwrap();
    let (spend, view): ([u8; 32], [u8; 32]) =
        (keys[..32].try_into().unwrap(), keys[32..].try_into().unwrap());
    assert_eq!(
        address(Network::Mainnet, Kind::Standard, &spend, &view),
        "49vDbkSo7eve3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVF2N4Zn"
    );
    // subaddresses, the account's own (0, 0) among them
    let sub = s.wallet_subaddress(&p, 0, 1).unwrap();
    assert_eq!(
        address(
            Network::Mainnet,
            Kind::Subaddress,
            &sub[..32].try_into().unwrap(),
            &sub[32..].try_into().unwrap()
        ),
        "8AB7PQPtducdkghYFN2prK3rZ7zPeL9f2REEdqE4WXYbSZr3797Aqti5xAjRsVy4jTdcwMW11GWejQtqk2kNXxj2QZxJwPZ"
    );
    assert_eq!(s.wallet_subaddress(&p, 0, 0).unwrap()[..], keys[..]);
    // off its paths: refused
    assert_eq!(s.wallet_subaddress(&path("m/44'/60'/0'/0/0"), 0, 1), Err(REFUSED));
    // the backup: maki asks, then shows the words itself; the app hears only the answer
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(s.wallet_show_backup(&p), 0);
    assert_eq!(
        record.borrow().backups,
        [concat!(
            "tavern judge beyond bifocals deepest mural onward dummy eagle diode gained vacation rally cause firm idled jerseys ",
            "moat vigilant upload bobsled jobs cunning doing jobs"
        )]
    );
    record.borrow_mut().answers.push_back(Answer::No);
    assert_eq!(s.wallet_show_backup(&p), 1);
    assert_eq!(s.wallet_show_backup(&p), 2, "no answer");
    assert_eq!(record.borrow().backups.len(), 1);
    assert_eq!(s.wallet_show_backup(&path("m/44'/60'/0'/0/0")), REFUSED);
    // Monero's keys are Monero's coin type's alone: a Bitcoin app gets none from its own paths
    let (mut b, record) = wallet_session(&["m/84'/0'"], &[Permission::Wallet]);
    assert_eq!(b.wallet_public(&path("m/84'/0'/0'/0/0"), WALLET_MONERO), Err(REFUSED));
    assert_eq!(b.wallet_subaddress(&path("m/84'/0'/0'/0/0"), 0, 1), Err(REFUSED));
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(b.wallet_show_backup(&path("m/84'/0'/0'/0/0")), NOT_FOUND);
    assert!(record.borrow().backups.is_empty());
    // and locked, nothing
    record.borrow_mut().locked = true;
    let (mut s, record) = wallet_session(&["m/44'/128'"], &[Permission::Wallet]);
    record.borrow_mut().locked = true;
    assert_eq!(s.wallet_public(&p, WALLET_MONERO), Err(LOCKED));
    assert_eq!(s.wallet_show_backup(&p), LOCKED);
}

#[test]
fn moneros_functions_came_with_host_api_4() {
    let code = module(
        r#"(module (import "maki" "wallet_subaddress" (func (param i32 i32 i32 i32 i32) (result i32))) (memory (export "memory") 1) (func (export "maki_main")))"#,
    );
    let manifest = |api: u16| maki_bundle::Manifest {
        id: "org.example.monero".into(),
        name: "Monero".into(),
        version: 1,
        label: "1.0".into(),
        kind: maki_bundle::Kind::Wasm,
        api,
        firmware: String::new(),
        permissions: vec![(maki_bundle::Permission::Wallet, "to show addresses".into())],
        storage_kib: 1,
        memory_kib: 64,
        backup: true,
        description: String::new(),
        wallet: Some(maki_bundle::Wallet {
            curve: maki_bundle::Curve::Secp256k1,
            paths: vec![path("m/44'/128'")],
        }),
    };
    let err = admit(&manifest(3), &code).unwrap_err();
    assert!(err.contains("wallet_subaddress, which came with host API 4, and its manifest says 3"), "{err}");
    admit(&manifest(4), &code).unwrap();
}

/// An output paid to the test phrase's Monero account (its subaddress `minor`), in a ring of 16
/// made-up members: what maki desktop asks maki to spend.
fn monero_input(seed: u64, minor: u32, amount: u64) -> maki_xmr::request::Input {
    use maki_xmr::sign::{self, G, Scalar};
    let keys = maki_hd::seed::SeedKeys::from_seed(&test_seed()).unwrap();
    let pair = maki_hd::seed::answer(
        &keys,
        maki_hd::op::MONERO_SUBADDRESS,
        &path("m/44'/128'/0'/0/0"),
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
    let out = sign::pay(&r, &view, &spend, 1, amount);
    let ring = (0..16u64)
        .map(|i| {
            if i == 5 {
                maki_xmr::request::Member { global: 100 + i, key: out.key, commitment: out.commitment }
            } else {
                maki_xmr::request::Member {
                    global: 100 + i,
                    key: (G * scalar(i + 1)).compress().to_bytes(),
                    commitment: sign::commit(&scalar(i + 100), i).compress().to_bytes(),
                }
            }
        })
        .collect();
    maki_xmr::request::Input {
        amount,
        tx_key: tx_key.compress().to_bytes(),
        index: 1,
        subaddress: minor,
        real: 5,
        ring,
    }
}

#[test]
fn spending_monero_needs_a_yes_and_maki_makes_the_transaction() {
    use maki_bundle::Permission;
    use maki_xmr::request::{Payment, Request, read_destination};
    let (mut s, record) = wallet_session(&["m/44'/128'"], &[Permission::Wallet]);
    let p = path("m/44'/128'/0'/0/0");

    // the view key: after a yes, once
    assert_eq!(s.wallet_monero_view_key(&p), Err(REFUSED));
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(s.wallet_review("Watch on computer?\nit can't spend", 1, 0), 0);
    let view = s.wallet_monero_view_key(&p).unwrap();
    assert_eq!(
        view.to_vec(),
        (0..32)
            .map(|i| u8::from_str_radix(
                &"0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201"[2 * i..2 * i + 2],
                16
            )
            .unwrap())
            .collect::<Vec<u8>>()
    );
    assert_eq!(s.wallet_monero_view_key(&p), Err(REFUSED), "one yes, one key");

    // a key image, for the account's outputs alone, with no yes
    let input = monero_input(1, 3, 5_000);
    let real = input.ring[input.real];
    let mut output = input.tx_key.to_vec();
    output.extend_from_slice(&input.index.to_le_bytes());
    output.extend_from_slice(&[0, 0, 0, 0, 3, 0, 0, 0]);
    output.extend_from_slice(&real.key);
    let proof = s.wallet_monero_key_image(&p, &output).unwrap();
    assert_eq!(proof.len(), 96);
    output[44] = 4;
    assert_eq!(s.wallet_monero_key_image(&p, &output), Err(FAILED), "another subaddress's");
    assert_eq!(s.wallet_monero_key_image(&p, &output[..79]), Err(INVALID));

    // a transaction: a signature for each input, of what the yes allowed
    let them =
        "49vDbkSo7eve3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVF2N4Zn";
    let request = Request {
        network: maki_xmr::Network::Mainnet,
        account: 0,
        fee: 1_000,
        change: 2_000,
        payments: vec![Payment {
            address: them.into(),
            amount: 12_000,
            destination: read_destination(them).unwrap().1,
        }],
        inputs: vec![monero_input(2, 0, 10_000), monero_input(3, 1, 5_000)],
    };
    let bytes = request.to_bytes();
    assert_eq!(s.wallet_monero_sign(&p, &bytes), Err(REFUSED));
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(s.wallet_review("Sign and spend?\nTotal 0.000000013 XMR", 1, 0), 0);
    assert_eq!(s.wallet_monero_sign(&p, &bytes), Err(REFUSED), "two inputs, one signature allowed");
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(s.wallet_review("Sign and spend?\nTotal 0.000000013 XMR", 2, 0), 0);
    let answer = s.wallet_monero_sign(&p, &bytes).unwrap();
    assert_eq!(answer[0], 0);
    let signed = maki_xmr::spend::Signed::from_bytes(&answer[1..]).unwrap();
    let tx = maki_xmr::tx::Transaction::from_bytes(&signed.transaction).unwrap();
    assert_eq!((tx.prefix.inputs.len(), tx.prefix.outputs.len(), tx.base.fee), (2, 2, 1_000));
    assert_eq!(s.wallet_monero_sign(&p, &bytes), Err(REFUSED), "used up");
    // what maki won't sign, it says why: a lie about an amount
    let mut lie = request.clone();
    lie.inputs[0].amount += 1;
    lie.fee += 1;
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(s.wallet_review("Sign and spend?\nx", 2, 0), 0);
    let answer = s.wallet_monero_sign(&p, &lie.to_bytes()).unwrap();
    assert_eq!(
        (answer[0], String::from_utf8_lossy(&answer[1..]).into_owned()),
        (1, "input 1's amount isn't what the chain has".into())
    );
    // not a request, or off its paths
    assert_eq!(s.wallet_monero_sign(&p, &bytes[..bytes.len() - 1]), Err(INVALID));
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(s.wallet_review("Sign and spend?\nx", 2, 0), 0);
    assert_eq!(s.wallet_monero_sign(&path("m/44'/60'/0'/0/0"), &bytes), Err(REFUSED));
}

#[test]
fn spending_monero_came_with_host_api_5() {
    let code = module(
        r#"(module (import "maki" "wallet_monero_sign" (func (param i32 i32 i32 i32 i32 i32) (result i32))) (memory (export "memory") 1) (func (export "maki_main")))"#,
    );
    let manifest = |api: u16| maki_bundle::Manifest {
        id: "org.example.monero".into(),
        name: "Monero".into(),
        version: 1,
        label: "1.0".into(),
        kind: maki_bundle::Kind::Wasm,
        api,
        firmware: String::new(),
        permissions: vec![(maki_bundle::Permission::Wallet, "to spend".into())],
        storage_kib: 1,
        memory_kib: 64,
        backup: true,
        description: String::new(),
        wallet: Some(maki_bundle::Wallet {
            curve: maki_bundle::Curve::Secp256k1,
            paths: vec![path("m/44'/128'")],
        }),
    };
    let err = admit(&manifest(4), &code).unwrap_err();
    assert!(err.contains("wallet_monero_sign, which came with host API 5, and its manifest says 4"), "{err}");
    admit(&manifest(5), &code).unwrap();
}

#[test]
fn an_ed25519_wallet_has_ed25519_keys_on_its_paths_alone() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use maki_bundle::{Curve, Permission};
    let (mut s, record) = wallet_session_on(Curve::Ed25519, &["m/44'/501'"], &[Permission::Wallet]);
    let p = path("m/44'/501'/0'/0'");
    let public: [u8; 32] = s.wallet_public(&p, WALLET_ED25519).unwrap().try_into().unwrap();
    // the test phrase's first Solana account, as Phantom has it
    // (HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk)
    let hex: String = public.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7");
    // not secp256k1's keys, or Monero's; not off its paths; and SLIP-10's are hardened
    for form in [WALLET_PUBLIC, WALLET_UNCOMPRESSED, WALLET_TAPROOT, WALLET_MONERO] {
        assert_eq!(s.wallet_public(&p, form), Err(REFUSED), "{form}");
    }
    assert_eq!(s.wallet_public(&path("m/44'/60'/0'/0'"), WALLET_ED25519), Err(REFUSED));
    assert_eq!(s.wallet_public(&path("m/44'/501'/0'/0"), WALLET_ED25519), Err(REFUSED));
    // a signature over the whole message, one for each a yes allows
    let message = [5u8; 1232];
    assert_eq!(s.wallet_sign_ed25519(&p, &message), Err(REFUSED));
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(s.wallet_review("Sign?\x1eSend\x1f1 SOL", 1, 0), 0);
    let sig = s.wallet_sign_ed25519(&p, &message).unwrap();
    VerifyingKey::from_bytes(&public).unwrap().verify(&message, &Signature::from_bytes(&sig)).unwrap();
    assert_eq!(s.wallet_sign_ed25519(&p, &message), Err(REFUSED));
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(s.wallet_review("Sign?\x1eSend\x1f1 SOL", 2, 0), 0);
    assert_eq!(s.wallet_sign_ed25519(&p, &vec![0; MAX_SIGN + 1]), Err(TOO_BIG));
    assert_eq!(s.wallet_sign(&p, &[7; 32], WALLET_SIGN_ECDSA), Err(REFUSED));
    assert_eq!(s.wallet_sign_ed25519(&p, &[]).map(|s| s.len()), Ok(64));
    // and a secp256k1 wallet, on the same paths, has no Ed25519 keys
    let (mut s, record) = wallet_session(&["m/44'/501'"], &[Permission::Wallet]);
    assert_eq!(s.wallet_public(&p, WALLET_ED25519), Err(REFUSED));
    record.borrow_mut().answers.push_back(Answer::Yes);
    assert_eq!(s.wallet_review("Sign?\x1eSend\x1f1 SOL", 1, 0), 0);
    assert_eq!(s.wallet_sign_ed25519(&p, &message), Err(REFUSED));
}

#[test]
fn ed25519_wallets_came_with_host_api_6() {
    let code = module(
        r#"(module (import "maki" "wallet_sign_ed25519" (func (param i32 i32 i32 i32 i32) (result i32))) (memory (export "memory") 1) (func (export "maki_main")))"#,
    );
    let manifest = |api: u16| maki_bundle::Manifest {
        id: "org.example.solana".into(),
        name: "Solana".into(),
        version: 1,
        label: "1.0".into(),
        kind: maki_bundle::Kind::Wasm,
        api,
        firmware: String::new(),
        permissions: vec![(maki_bundle::Permission::Wallet, "to sign".into())],
        storage_kib: 1,
        memory_kib: 64,
        backup: true,
        description: String::new(),
        wallet: Some(maki_bundle::Wallet {
            curve: maki_bundle::Curve::Ed25519,
            paths: vec![path("m/44'/501'")],
        }),
    };
    let err = admit(&manifest(5), &code).unwrap_err();
    assert!(
        err.contains("wallet_sign_ed25519, which came with host API 6, and its manifest says 5"),
        "{err}"
    );
    admit(&manifest(6), &code).unwrap();
}
