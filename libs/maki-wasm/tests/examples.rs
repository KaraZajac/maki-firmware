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
}

struct Script(Rc<RefCell<Record>>);

impl Platform for Script {
    fn wait(&mut self, _: Option<Duration>) -> Event { self.0.borrow_mut().events.pop_front().unwrap_or(Event::Exit) }
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
}

fn run_fixture(name: &str, events: &[Event], storage: BTreeMap<String, Vec<u8>>) -> (Stop, Record) {
    let bytes = std::fs::read(format!("{}/tests/fixtures/{name}.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let record = Rc::new(RefCell::new(Record { events: events.iter().copied().collect(), storage, ..Default::default() }));
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
