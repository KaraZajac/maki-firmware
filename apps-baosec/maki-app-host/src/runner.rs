//! The thread that runs apps, one at a time, each in maki-wasm: it hands the app the events the
//! main thread sends, draws its frames below maki's bar, keeps its storage in the PDDB, and
//! shows App info and "stopped" screens itself.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use blitstr2::GlyphStyle;
use maki_launcher::Answer;
use maki_ui::{Key, Screen, LINE};
use maki_wasm::{Canvas, Event, Platform, Stop, HEIGHT, TOP, WIDTH};
use ux_api::minigfx::{Point, Rectangle};

use crate::store::{Record, Store};

/// How long the owner has to answer (the emulator skips through idle time: longer there).
pub const ASK_TIMEOUT_S: u32 = if option_env!("MAKI_DEMO").is_some() { 600 } else { 30 };

pub enum ToRunner {
    /// The launcher put this slot's app in front: start it, or show it again.
    Open(usize),
    Key(usize, Key),
    /// Something else is in front for now: an ask, or the app's menu.
    Hidden(usize),
    /// The owner left it from its menu.
    Exited(usize),
    /// Picked from its menu: one of its own items, or App info just after them.
    Menu(usize, usize),
    /// maki locked, or the app is being replaced or removed: end it.
    Stop,
    /// An app just installed, checked and compiled: kept, so it opens at once.
    Loaded(String, u32, Arc<maki_wasm::Loaded>),
}

/// An installed app the launcher knows, by slot.
#[derive(Clone, Debug)]
pub struct Slot {
    pub id: String,
    pub name: String,
}

/// What the main thread and the runner share.
#[derive(Default)]
pub struct Shared {
    pub slots: Vec<Option<Slot>>,
    /// Each running app's own menu items.
    pub menus: HashMap<usize, Vec<String>>,
    pub running: Option<usize>,
    /// 0 unset, 1 unverified, 2 verified, as maki-link says.
    pub time_state: u8,
}

/// Apps compiled this session, by ID, with the version compiled: a few, for memory's sake.
const KEEP_LOADED: usize = 3;

struct Ctx {
    loaded: RefCell<Vec<(String, u32, Arc<maki_wasm::Loaded>)>>,
    screen: Screen,
    store: Store,
    keys: maki_keys::Keys,
    launcher: maki_launcher::Launcher,
    time_conn: xous::CID,
    shared: Arc<Mutex<Shared>>,
    rx: Receiver<ToRunner>,
}

impl Ctx {
    fn unlocked(&self) -> bool { self.keys.status().0 == maki_keys::State::Unlocked }

    fn keep(&self, id: String, version: u32, app: Arc<maki_wasm::Loaded>) {
        let mut loaded = self.loaded.borrow_mut();
        loaded.retain(|(i, _, _)| *i != id);
        loaded.insert(0, (id, version, app));
        loaded.truncate(KEEP_LOADED);
    }

    fn kept(&self, id: &str, version: u32) -> Option<Arc<maki_wasm::Loaded>> {
        self.loaded.borrow().iter().find(|(i, v, _)| i == id && *v == version).map(|(_, _, a)| a.clone())
    }

    fn clock(&self) -> String { crate::clock_text(self.time_conn, self.shared.lock().unwrap().time_state == 2) }
}

/// What App info shows, a page at a time.
#[derive(Clone, Copy, PartialEq, Eq)]
enum InfoPage {
    About,
    From,
    Developer,
    Permissions,
    Storage,
    Backup,
    Remove,
}

const INFO_PAGES: [InfoPage; 7] = [
    InfoPage::About,
    InfoPage::From,
    InfoPage::Developer,
    InfoPage::Permissions,
    InfoPage::Storage,
    InfoPage::Backup,
    InfoPage::Remove,
];

/// What happens to an app while it runs, which the runner reads once it stops.
struct RunState {
    front: bool,
    /// App info is up, on this page.
    info: Option<usize>,
    /// Another app was opened meanwhile.
    pending: Option<usize>,
    /// Removed while it ran: nothing more is stored.
    removed: bool,
    /// Told to stop: every wait from now on says Exit.
    stopping: bool,
    last: Canvas,
}

struct Device {
    ctx: Rc<Ctx>,
    slot: usize,
    id: String,
    name: String,
    sideloaded: bool,
    record: Record,
    manifest: maki_bundle::Manifest,
    storage_quota: usize,
    state: Rc<RefCell<RunState>>,
}

impl Device {
    fn draw_frame(&self) {
        let st = self.state.borrow();
        if !st.front || st.info.is_some() {
            return;
        }
        let s = &self.ctx.screen;
        s.begin();
        s.app_bar(&self.name, &self.ctx.clock(), self.sideloaded);
        s.gfx
            .bitmap(
                &st.last.to_display(),
                Some(Point::new(0, TOP as isize)),
                Some(Rectangle::new(Point::new(0, 0), Point::new(WIDTH as isize, HEIGHT as isize))),
            )
            .ok();
        s.end();
    }

    fn draw_info(&self, page: usize) {
        let s = &self.ctx.screen;
        let m = &self.manifest;
        let used = self.ctx.store.data_used(&self.id);
        let (heading, value, lines, action): (&str, String, Vec<String>, &str) = match INFO_PAGES[page] {
            InfoPage::About => (
                "App info",
                m.name.clone(),
                vec![if m.label.is_empty() { format!("version {}", m.version) } else { m.label.clone() }, m.id.clone()],
                "back",
            ),
            InfoPage::From => {
                if self.sideloaded {
                    ("Where from", "Sideloaded".into(), vec!["nobody has reviewed it".into()], "back")
                } else {
                    ("Where from", "maki store".into(), vec!["reviewed".into()], "back")
                }
            }
            InfoPage::Developer => {
                let f = maki_bundle::fingerprint(&self.record.developer);
                ("Developer key", String::new(), vec![f[..14].to_string(), f[15..].to_string()], "back")
            }
            InfoPage::Permissions => (
                "Permissions",
                if m.permissions.is_empty() { "Only the basics".into() } else { format!("{}", m.permissions.len()) },
                m.permissions.iter().map(|(p, _)| p.title().to_string()).collect(),
                "back",
            ),
            InfoPage::Storage => (
                "Storage",
                format!("{:.1} KiB used", used as f32 / 1024.0),
                vec![format!("of {} KiB", m.storage_kib)],
                "back",
            ),
            InfoPage::Backup => (
                "In the backup",
                if self.record.backup { "Yes".into() } else { "No".into() },
                vec![if self.record.backup { "its data is backed up" } else { "its data stays on maki" }.into()],
                if self.record.backup { "leave it out" } else { "back it up" },
            ),
            InfoPage::Remove => ("Remove", m.name.clone(), vec!["and its data".into()], "remove"),
        };
        s.begin();
        s.app_bar(&self.name, "", self.sideloaded);
        let top = s.bar + 6;
        s.text(top, 13, GlyphStyle::Small, false, true, heading);
        s.text(top + 15, LINE, GlyphStyle::Bold, false, true, &value);
        let mono = INFO_PAGES[page] == InfoPage::Developer;
        for (i, line) in lines.iter().take(3).enumerate() {
            let style = if mono { GlyphStyle::Monospace } else { GlyphStyle::Small };
            s.text(top + 34 + i as isize * 14, 14, style, false, true, line);
        }
        s.dots(INFO_PAGES.len(), page, top + 82);
        s.action_bar(action, true);
        s.end();
    }

    /// A key while App info is up: returns what the app gets, if anything.
    fn info_key(&mut self, key: Key) -> Option<Event> {
        let page = self.state.borrow().info?;
        let n = INFO_PAGES.len();
        match key {
            Key::Left => self.state.borrow_mut().info = Some((page + n - 1) % n),
            Key::Right => self.state.borrow_mut().info = Some((page + 1) % n),
            Key::Confirm => match INFO_PAGES[page] {
                InfoPage::Backup => {
                    self.record.backup = !self.record.backup;
                    if self.ctx.unlocked() {
                        self.ctx.store.put_record(&self.id, &self.record).ok();
                    }
                }
                InfoPage::Remove => return self.remove(),
                _ => {
                    self.state.borrow_mut().info = None;
                    return Some(Event::Shown);
                }
            },
            Key::Menu => {}
        }
        let page = self.state.borrow().info;
        if let Some(page) = page {
            if self.state.borrow().front {
                self.draw_info(page);
            }
        }
        None
    }

    /// Asks the owner, then removes the app and its data: the app is told to exit.
    fn remove(&mut self) -> Option<Event> {
        let detail = if self.record.backup { "its data goes too" } else { "its data isn't backed up" };
        let answer = self.ctx.launcher.ask(&self.name, "Remove app?", detail, &[], ASK_TIMEOUT_S);
        if !matches!(answer, Ok(Answer::Allowed(_))) || !self.ctx.unlocked() {
            return None;
        }
        crate::remove_app(&self.ctx.store, &self.ctx.launcher, &self.ctx.shared, &self.id);
        log::info!("{} removed from App info", self.id);
        let mut st = self.state.borrow_mut();
        st.removed = true;
        st.info = None;
        st.front = false;
        Some(Event::Exit)
    }
}

impl Platform for Device {
    fn wait(&mut self, timeout: Option<Duration>) -> Event {
        if self.state.borrow().stopping {
            return Event::Exit;
        }
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            let msg = match deadline {
                // while App info is up, the app's own timers wait
                Some(d) if self.state.borrow().info.is_none() => {
                    match self.ctx.rx.recv_timeout(d.saturating_duration_since(Instant::now())) {
                        Ok(m) => m,
                        Err(RecvTimeoutError::Timeout) => return Event::Timeout,
                        Err(RecvTimeoutError::Disconnected) => return Event::Exit,
                    }
                }
                _ => match self.ctx.rx.recv() {
                    Ok(m) => m,
                    Err(_) => return Event::Exit,
                },
            };
            match msg {
                ToRunner::Stop => {
                    self.state.borrow_mut().stopping = true;
                    return Event::Exit;
                }
                ToRunner::Loaded(id, version, app) => self.ctx.keep(id, version, app),
                ToRunner::Open(s) if s != self.slot => {
                    self.state.borrow_mut().pending = Some(s);
                    self.state.borrow_mut().stopping = true;
                    return Event::Exit;
                }
                ToRunner::Open(_) => {
                    self.state.borrow_mut().front = true;
                    let info = self.state.borrow().info;
                    match info {
                        Some(page) => self.draw_info(page),
                        None => {
                            self.draw_frame();
                            return Event::Shown;
                        }
                    }
                }
                ToRunner::Hidden(s) if s == self.slot => {
                    self.state.borrow_mut().front = false;
                    if self.state.borrow().info.is_none() {
                        return Event::Hidden;
                    }
                }
                ToRunner::Exited(s) if s == self.slot => {
                    let mut st = self.state.borrow_mut();
                    st.front = false;
                    st.info = None;
                    st.stopping = true;
                    return Event::Exit;
                }
                ToRunner::Key(s, key) if s == self.slot && self.state.borrow().front => {
                    if self.state.borrow().info.is_some() {
                        if let Some(e) = self.info_key(key) {
                            if e == Event::Shown {
                                self.draw_frame();
                            }
                            return e;
                        }
                        continue;
                    }
                    match key {
                        Key::Left => return Event::Left,
                        Key::Right => return Event::Right,
                        Key::Confirm => return Event::Centre,
                        Key::Menu => {}
                    }
                }
                ToRunner::Menu(s, i) if s == self.slot => {
                    let items = self.ctx.shared.lock().unwrap().menus.get(&self.slot).map(|m| m.len()).unwrap_or(0);
                    if i < items {
                        return Event::Menu(i as u32);
                    }
                    // App info: shown when the launcher puts the app back in front
                    self.state.borrow_mut().info = Some(0);
                }
                _ => {}
            }
        }
    }

    fn present(&mut self, canvas: &Canvas) {
        self.state.borrow_mut().last = canvas.clone();
        self.draw_frame();
    }

    fn set_menu(&mut self, items: &[String]) { self.ctx.shared.lock().unwrap().menus.insert(self.slot, items.to_vec()); }

    fn millis(&self) -> u64 { crate::tt().elapsed_ms() }

    fn unix_time(&self) -> Option<(u64, bool)> {
        let ms = crate::utc_ms(self.ctx.time_conn)?;
        Some((ms / 1000, self.ctx.shared.lock().unwrap().time_state == 2))
    }

    fn random(&mut self, buf: &mut [u8]) { getrandom::getrandom(buf).expect("no randomness") }

    fn log(&mut self, line: &str) { log::info!("{}: {}", self.id, line) }

    fn storage_get(&mut self, key: &str) -> Option<Vec<u8>> {
        if !self.ctx.unlocked() {
            return None;
        }
        self.ctx.store.data_get(&self.id, key)
    }

    fn storage_set(&mut self, key: &str, value: &[u8]) -> Result<(), ()> {
        if self.state.borrow().removed || !self.ctx.unlocked() || value.len() > self.storage_quota {
            return Err(());
        }
        self.ctx.store.data_set(&self.id, key, value).map_err(|e| log::warn!("{}: storing {key}: {e:?}", self.id))
    }

    fn storage_delete(&mut self, key: &str) -> bool {
        if self.state.borrow().removed || !self.ctx.unlocked() {
            return false;
        }
        self.ctx.store.data_delete(&self.id, key)
    }

    fn storage_keys(&mut self) -> Vec<String> {
        if !self.ctx.unlocked() {
            return Vec::new();
        }
        self.ctx.store.data_keys(&self.id)
    }
}

/// A screen for an app that stopped, until the owner moves on.
fn stopped(ctx: &Ctx, name: &str, sideloaded: bool, why: &str) {
    let s = &ctx.screen;
    s.begin();
    s.app_bar(name, "", sideloaded);
    let top = s.bar + 8;
    s.text(top, LINE, GlyphStyle::Bold, false, true, &format!("{name} stopped"));
    // the reason, in lines that fit
    let mut lines: Vec<String> = Vec::new();
    for word in why.split_whitespace() {
        match lines.last_mut() {
            Some(l) if l.len() + 1 + word.len() <= 22 => {
                l.push(' ');
                l.push_str(word);
            }
            _ => lines.push(word.chars().take(22).collect()),
        }
    }
    for (i, line) in lines.iter().take(5).enumerate() {
        s.text(top + LINE + 6 + i as isize * 13, 13, GlyphStyle::Small, false, true, line);
    }
    s.action_bar("ok", false);
    s.end();
}

/// Runs the app in `slot` until it stops. Returns a slot opened meanwhile, to run next.
fn run(ctx: &Rc<Ctx>, slot: usize) -> Option<usize> {
    let Some(info) = ctx.shared.lock().unwrap().slots.get(slot).cloned().flatten() else {
        ctx.launcher.home().ok();
        return None;
    };
    if !ctx.unlocked() {
        ctx.launcher.home().ok();
        return None;
    }
    let (Some(record), Some(bytes)) = (ctx.store.record(&info.id), ctx.store.bundle(&info.id)) else {
        stopped(ctx, &info.name, true, "it isn't installed any more");
        wait_to_leave(ctx, slot);
        return None;
    };
    // checked when it was installed: compiled once a session, kept for the next time
    let started = crate::tt().elapsed_ms();
    let loaded = maki_bundle::read_stored(&bytes).map_err(|e| e.to_string()).and_then(|b| {
        let app = match ctx.kept(&info.id, b.manifest.version) {
            Some(app) => app,
            None => {
                let app = Arc::new(maki_wasm::load(&b.manifest, b.code)?);
                ctx.keep(info.id.clone(), b.manifest.version, app.clone());
                app
            }
        };
        Ok((b.manifest, app))
    });
    let (manifest, app) = match loaded {
        Ok(ok) => ok,
        Err(why) => {
            log::warn!("{} can't run: {why}", info.id);
            stopped(ctx, &info.name, !record.from_store, &why);
            wait_to_leave(ctx, slot);
            return None;
        }
    };
    log::info!("{} ready to run ({} ms)", info.id, crate::tt().elapsed_ms() - started);
    let limits = app.limits;
    let state = Rc::new(RefCell::new(RunState {
        front: true,
        info: None,
        pending: None,
        removed: false,
        stopping: false,
        last: Canvas::default(),
    }));
    let device = Device {
        ctx: ctx.clone(),
        slot,
        id: info.id.clone(),
        name: info.name.clone(),
        sideloaded: !record.from_store,
        storage_quota: limits.storage,
        manifest,
        record,
        state: state.clone(),
    };
    // the bar goes up at once, before the app's first frame
    device.draw_frame();
    ctx.shared.lock().unwrap().running = Some(slot);
    log::info!("running {}", info.id);
    let stop = app.run(Box::new(device));
    {
        let mut shared = ctx.shared.lock().unwrap();
        shared.running = None;
        shared.menus.remove(&slot);
    }
    log::info!("{} stopped: {:?}", info.id, stop);
    let st = state.borrow();
    let why = match &stop {
        Stop::Finished | Stop::Exited => None,
        Stop::NotResponding => Some("it stopped responding".to_string()),
        Stop::Aborted(why) => Some(why.clone()),
        Stop::Crashed(why) => Some(format!("it crashed: {why}")),
    };
    if st.front {
        match why {
            Some(why) => {
                stopped(ctx, &info.name, true, &why);
                drop(st);
                wait_to_leave(ctx, slot);
            }
            // it finished on its own: home
            None => {
                ctx.launcher.home().ok();
            }
        }
        return None;
    }
    st.pending
}

/// Waits for the owner to press the centre (or leave some other way), then goes home.
fn wait_to_leave(ctx: &Ctx, slot: usize) {
    loop {
        match ctx.rx.recv() {
            Ok(ToRunner::Key(s, Key::Confirm)) if s == slot => break,
            Ok(ToRunner::Hidden(s) | ToRunner::Exited(s)) if s == slot => return,
            Ok(ToRunner::Stop) | Err(_) => break,
            Ok(ToRunner::Open(s)) if s != slot => return,
            _ => {}
        }
    }
    ctx.launcher.home().ok();
}

pub fn runner(rx: Receiver<ToRunner>, shared: Arc<Mutex<Shared>>) {
    let xns = xous_names::XousNames::new().unwrap();
    let ctx = Rc::new(Ctx {
        loaded: RefCell::new(Vec::new()),
        screen: Screen::new(&xns),
        store: Store::new(),
        keys: maki_keys::Keys::new(&xns).expect("couldn't connect to maki-keys"),
        launcher: maki_launcher::Launcher::new(&xns).expect("couldn't connect to the launcher"),
        time_conn: crate::time_conn(),
        shared,
        rx,
    });
    let mut next = None;
    loop {
        let slot = match next.take() {
            Some(s) => s,
            None => match ctx.rx.recv() {
                Ok(ToRunner::Open(s)) => s,
                Ok(ToRunner::Loaded(id, version, app)) => {
                    ctx.keep(id, version, app);
                    continue;
                }
                Ok(_) => continue,
                Err(_) => return,
            },
        };
        next = run(&ctx, slot);
    }
}
