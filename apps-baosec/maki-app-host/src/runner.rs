//! The thread that runs apps, one at a time: a WebAssembly app in maki-wasm, a native app in a
//! process of its own (`native`). It hands the app the events the main thread sends, draws its
//! frames below maki's bar, keeps its storage in the PDDB, and shows App info and "stopped"
//! screens itself.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use blitstr2::GlyphStyle;
use maki_app_host_api::{
    AppMessage, RESULT_BUSY, RESULT_DENIED, RESULT_FAILED, RESULT_OK, RESULT_REFUSED, RESULT_TIMED_OUT,
};
use maki_launcher::Answer;
use maki_ui::{Key, LINE, Screen};
use maki_wasm::{Ask, Canvas, Event, HEIGHT, Platform, Review, Stop, TOP, WIDTH};
use ux_api::minigfx::{Point, Rectangle};

use crate::store::{Record, Store};

/// How long the owner has to answer (the emulator skips through idle time: longer there).
pub const ASK_TIMEOUT_S: u32 = maki_launcher::ask_timeout(30);

pub enum ToRunner {
    /// The launcher put this slot's app in front: start it, or show it again.
    Open(usize),
    Key(usize, Key),
    /// The jog dial on maki's side: up (true) or down. Only apps that say host API 8 get it.
    Jog(usize, bool),
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
    /// A message from the computer for this slot's app (the link permission), with the message
    /// to answer (`answer`) once the app does.
    Message(usize, xous::MessageEnvelope, Vec<u8>),
}

/// Sends the runner something; if a native app is running, pokes its service too, in case the
/// app isn't waiting for events (a WebAssembly app's host is always either waiting or running
/// out of fuel).
pub fn tell(to_runner: &std::sync::mpsc::Sender<ToRunner>, shared: &Mutex<Shared>, m: ToRunner) {
    to_runner.send(m).ok();
    if shared.lock().unwrap().native.is_some() {
        crate::native::poke();
    }
}

/// How long a message waits for the app to get to it.
const MESSAGE_WAIT: Duration = Duration::from_secs(60);
/// How long an app started for a message runs with nothing more to do.
const HEADLESS_IDLE: Duration = Duration::from_secs(30);
/// How long such an app keeps maki after each message when another app's is waiting: long
/// enough for the next of its own exchange (a PSBT's pieces, then the signed one), which comes
/// at once. Then it ends, and the other app runs for its message.
const HEADLESS_HOLD: Duration = Duration::from_secs(5);

/// Answers a message from maki-link: dropping it hands the buffer back.
pub fn answer(mut msg: xous::MessageEnvelope, result: u32, answer: &[u8]) {
    if let Some(mem) = msg.body.memory_message_mut() {
        let mut buffer = unsafe { xous_ipc::Buffer::from_memory_message_mut(mem) };
        if let Ok(mut req) = buffer.to_original::<AppMessage, _>() {
            req.result = result;
            req.message.clear();
            req.answer = answer.to_vec();
            buffer.replace(req).ok();
        }
    }
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
    /// The running app has the wallet permission: it ends when the wallet changes (a passphrase
    /// wallet opened or closed), so that nothing it worked out from the other one stays on screen.
    pub running_wallet: bool,
    /// 0 unset, 1 unverified, 2 verified, as maki-link says.
    pub time_state: u8,
    /// maki is unlocked, as maki-keys last told the worker. Kept here so an app's storage calls
    /// don't each ask maki-keys (which asks the PDDB); after a lock, the secret basis is closed
    /// anyway.
    pub unlocked: bool,
    /// The running app's process, if it's a native one: the main thread pokes its service
    /// whenever it sends the runner something, in case the app isn't waiting for events.
    pub native: Option<xous::PID>,
    /// The slot the launcher has in front, as its last focus message said. The runner learns
    /// of a change only between an app's calls; this is up to date even while it's busy in one
    /// (a scan the launcher ended to ask something), so it never draws over what took the screen.
    pub front: Option<usize>,
}

/// Apps compiled this session, by ID, with the version compiled: a few, for memory's sake.
const KEEP_LOADED: usize = 3;

pub(crate) struct Ctx {
    loaded: RefCell<Vec<(String, u32, Arc<maki_wasm::Loaded>)>>,
    screen: Screen,
    store: Store,
    launcher: maki_launcher::Launcher,
    /// for apps' secrets (the keys permission): the app host's role, claimed at boot
    keys: maki_keys::Keys,
    /// for typing (the keyboard permission)
    usb: usb_bao1x::UsbHid,
    /// the accelerometer (the motion permission), set up the first time an app reads it: None
    /// until then, Some(None) if there's none; and whether the app running changed its range
    #[cfg(feature = "board-baosec")]
    accel: RefCell<Option<Option<(bao1x_hal::i2c::I2c, bao1x_hal::lis2dh12::Lis2dh12)>>>,
    #[cfg(feature = "board-baosec")]
    accel_ranged: Cell<bool>,
    time_conn: xous::CID,
    pub(crate) shared: Arc<Mutex<Shared>>,
    rx: Receiver<ToRunner>,
    /// The app service native apps talk to (`maki_native::service`).
    pub(crate) service: xous::SID,
}

impl Ctx {
    fn unlocked(&self) -> bool { self.shared.lock().unwrap().unlocked }

    /// x, y and z in milli-g.
    #[cfg(feature = "board-baosec")]
    fn motion(&self) -> Option<[i16; 3]> {
        let (x, y, z) = self.accel(|i2c, driver| driver.read_accel_mg(i2c).ok())?;
        let fit = |v: i32| v.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        Some([fit(x), fit(y), fit(z)])
    }

    /// The accelerometer's range, ±`g` (2, 4, 8 or 16), until the app stops.
    #[cfg(feature = "board-baosec")]
    fn motion_range(&self, g: u8) -> Option<u8> {
        use bao1x_hal::lis2dh12::FullScale;
        let scale = match g {
            2 => FullScale::G2,
            4 => FullScale::G4,
            8 => FullScale::G8,
            _ => FullScale::G16,
        };
        self.accel(|i2c, driver| driver.set_full_scale(i2c, scale).ok())?;
        self.accel_ranged.set(scale != FullScale::G2);
        Some(g)
    }

    /// Back to ±2 g for the next app, if the last changed it.
    #[cfg(feature = "board-baosec")]
    fn motion_reset(&self) {
        if self.accel_ranged.replace(false) {
            self.motion_range(2);
        }
    }

    /// The accelerometer, set up the first time it's wanted: ±2 g, 12 bits.
    #[cfg(feature = "board-baosec")]
    fn accel<T>(
        &self,
        f: impl FnOnce(&mut bao1x_hal::i2c::I2c, &mut bao1x_hal::lis2dh12::Lis2dh12) -> Option<T>,
    ) -> Option<T> {
        use bao1x_hal::lis2dh12::{Lis2dh12, OperatingMode};
        let mut accel = self.accel.borrow_mut();
        if accel.is_none() {
            let mut i2c = bao1x_hal::i2c::I2c::new();
            *accel = Some(match Lis2dh12::new(&mut i2c) {
                Ok(mut driver) => {
                    if let Err(e) = driver.set_operating_mode(&mut i2c, OperatingMode::HighResolution) {
                        log::warn!("the accelerometer stays at 10 bits: {e:?}");
                    }
                    Some((i2c, driver))
                }
                Err(e) => {
                    log::warn!("no accelerometer to read: {e:?}");
                    None
                }
            });
        }
        let (i2c, driver) = accel.as_mut()?.as_mut()?;
        f(i2c, driver)
    }

    #[cfg(not(feature = "board-baosec"))]
    fn motion(&self) -> Option<[i16; 3]> { None }

    #[cfg(not(feature = "board-baosec"))]
    fn motion_range(&self, _g: u8) -> Option<u8> { None }

    #[cfg(not(feature = "board-baosec"))]
    fn motion_reset(&self) {}

    fn keep(&self, id: String, version: u32, app: Arc<maki_wasm::Loaded>) {
        let mut loaded = self.loaded.borrow_mut();
        loaded.retain(|(i, _, _)| *i != id);
        loaded.insert(0, (id, version, app));
        loaded.truncate(KEEP_LOADED);
    }

    fn kept(&self, id: &str, version: u32) -> Option<Arc<maki_wasm::Loaded>> {
        self.loaded.borrow().iter().find(|(i, v, _)| i == id && *v == version).map(|(_, _, a)| a.clone())
    }

    fn clock(&self) -> String {
        crate::clock_text(self.time_conn, self.shared.lock().unwrap().time_state == 2)
    }
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
    /// When it was opened, until its first frame (which the log times).
    opened_ms: Option<u64>,
    /// Typing into the computer: maki's bar says so meanwhile.
    typing: bool,
    /// The app asked for the whole screen dark (host API 8), bar and all.
    dark: bool,
    /// Presses until then aren't the app's: the one that cancelled a scan.
    quiet_until: Option<Instant>,
    /// Messages from the computer the app hasn't been given yet, with when they came.
    inbox: VecDeque<(xous::MessageEnvelope, Vec<u8>, Instant)>,
    /// The one it was given, until it answers.
    current: Option<(xous::MessageEnvelope, Vec<u8>)>,
    /// Started for a message, and not opened by the owner: it ends once idle a while.
    headless: bool,
    /// Another app's message, which this one (started for a message) gives way to once its own
    /// exchange is over: that app runs next, for it.
    handover: Option<(usize, xous::MessageEnvelope, Vec<u8>)>,
    idle_since: Instant,
    /// What the main thread sent that a native app hasn't waited for yet: looked through for an
    /// exit while it's busy (`ExitWatch::exit_waiting`), then handed to its next wait.
    deferred: VecDeque<ToRunner>,
}

impl RunState {
    /// Every message the app didn't answer gets an answer anyway: it stopped.
    fn answer_all(&mut self) {
        if let Some((msg, _)) = self.current.take() {
            answer(msg, RESULT_DENIED, &[]);
        }
        for (msg, _, _) in self.inbox.drain(..) {
            answer(msg, RESULT_FAILED, &[]);
        }
    }
}

pub(crate) struct Device {
    ctx: Rc<Ctx>,
    slot: usize,
    id: String,
    name: String,
    sideloaded: bool,
    record: Record,
    manifest: maki_bundle::Manifest,
    storage_quota: usize,
    /// It has the link permission: messages reach it.
    may_link: bool,
    state: Rc<RefCell<RunState>>,
}

impl Device {
    fn draw_frame(&self) {
        let st = self.state.borrow();
        if !st.front || st.info.is_some() || self.ctx.shared.lock().unwrap().front != Some(self.slot) {
            return;
        }
        let s = &self.ctx.screen;
        s.begin();
        if st.dark && !st.typing {
            // nothing at all, maki's bar neither: a dark screen can't pass for maki's own
            s.end();
            return;
        }
        let right = if st.typing { String::from("typing") } else { self.ctx.clock() };
        s.app_bar(&self.name, &right, self.sideloaded);
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
                vec![
                    if m.label.is_empty() { format!("version {}", m.version) } else { m.label.clone() },
                    m.id.clone(),
                ],
                "back",
            ),
            InfoPage::From => {
                let revoked = self.ctx.store.revocations().and_then(|r| {
                    r.check(&self.id, self.record.version, &self.record.developer).map(String::from)
                });
                if let Some(why) = revoked {
                    let words: Vec<String> = why.split_whitespace().map(String::from).collect();
                    // three short lines of why, the most App info shows
                    let mut lines = vec![String::new()];
                    for w in words {
                        let last = lines.last_mut().unwrap();
                        if last.len() + w.len() + 1 > 20 && !last.is_empty() {
                            lines.push(w);
                        } else {
                            if !last.is_empty() {
                                last.push(' ');
                            }
                            last.push_str(&w);
                        }
                    }
                    ("Revoked", "by the maki store".into(), lines, "back")
                } else if self.sideloaded {
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
                if m.permissions.is_empty() {
                    "Only the basics".into()
                } else {
                    format!("{}", m.permissions.len())
                },
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
                vec![
                    if self.record.backup { "its data is backed up" } else { "its data stays on maki" }
                        .into(),
                ],
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
            Key::Menu | Key::Up | Key::Down => {}
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

/// Looks, for a native app that isn't waiting for events, at what the main thread has sent.
pub(crate) struct ExitWatch {
    ctx: Rc<Ctx>,
    state: Rc<RefCell<RunState>>,
    slot: usize,
}

impl ExitWatch {
    /// Whether the owner left the app, maki is stopping it, or another app is being opened.
    /// What else there is waits for the app's next wait.
    pub(crate) fn exit_waiting(&self) -> bool {
        while let Ok(m) = self.ctx.rx.try_recv() {
            self.state.borrow_mut().deferred.push_back(m);
        }
        let st = self.state.borrow();
        st.stopping
            || st.deferred.iter().any(|m| match m {
                ToRunner::Exited(s) => *s == self.slot,
                ToRunner::Open(s) => *s != self.slot,
                ToRunner::Stop => true,
                _ => false,
            })
    }
}

impl Device {
    pub(crate) fn watch(&self) -> ExitWatch {
        ExitWatch { ctx: self.ctx.clone(), state: self.state.clone(), slot: self.slot }
    }

    pub(crate) fn id(&self) -> &str { &self.id }

    /// The next message waiting for the app, if any, which becomes the one it answers. One
    /// that waited too long is answered as timed out instead.
    fn next_message(&self) -> Option<Event> {
        let mut st = self.state.borrow_mut();
        while let Some((msg, bytes, came)) = st.inbox.pop_front() {
            if came.elapsed() > MESSAGE_WAIT {
                answer(msg, RESULT_TIMED_OUT, &[]);
                continue;
            }
            st.current = Some((msg, bytes));
            st.idle_since = Instant::now();
            return Some(Event::Message);
        }
        None
    }
}

impl Device {
    /// The wallet permission's paths, from the app's manifest.
    pub(crate) fn wallet(&self) -> Option<maki_bundle::Wallet> { self.manifest.wallet.clone() }
}

impl Platform for Device {
    fn wait(&mut self, timeout: Option<Duration>) -> Event {
        if self.state.borrow().stopping {
            return Event::Exit;
        }
        // a message it was given and didn't answer: it went on without answering
        if let Some((msg, _)) = self.state.borrow_mut().current.take() {
            answer(msg, RESULT_DENIED, &[]);
        }
        if let Some(e) = self.next_message() {
            return e;
        }
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            // started for a message and left alone since: it ends, sooner if another app's
            // message is waiting for it to
            let idle_end = {
                let st = self.state.borrow();
                st.headless.then(|| {
                    st.idle_since + if st.handover.is_some() { HEADLESS_HOLD } else { HEADLESS_IDLE }
                })
            };
            // while App info is up, the app's own timers wait
            let timer = deadline.filter(|_| self.state.borrow().info.is_none());
            let wake = match (timer, idle_end) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            let deferred = self.state.borrow_mut().deferred.pop_front();
            let msg = match (deferred, wake) {
                (Some(m), _) => m,
                (None, Some(w)) => {
                    match self.ctx.rx.recv_timeout(w.saturating_duration_since(Instant::now())) {
                        Ok(m) => m,
                        Err(RecvTimeoutError::Timeout) if idle_end.is_some_and(|e| Instant::now() >= e) => {
                            log::info!("{}: nothing more to do: ending it", self.id);
                            self.state.borrow_mut().stopping = true;
                            return Event::Exit;
                        }
                        Err(RecvTimeoutError::Timeout) => return Event::Timeout,
                        Err(RecvTimeoutError::Disconnected) => return Event::Exit,
                    }
                }
                (None, None) => match self.ctx.rx.recv() {
                    Ok(m) => m,
                    Err(_) => return Event::Exit,
                },
            };
            match msg {
                ToRunner::Message(s, msg, bytes) if s == self.slot => {
                    if !self.may_link {
                        answer(msg, RESULT_REFUSED, &[]);
                        continue;
                    }
                    self.state.borrow_mut().inbox.push_back((msg, bytes, Instant::now()));
                    if let Some(e) = self.next_message() {
                        return e;
                    }
                }
                // another app's: one started for a message gives way once its own exchange is
                // over, and that app runs next for it; one the owner opened keeps maki
                ToRunner::Message(s, msg, bytes)
                    if self.state.borrow().headless && self.state.borrow().handover.is_none() =>
                {
                    log::info!("{}: another app's message waits for it", self.id);
                    self.state.borrow_mut().handover = Some((s, msg, bytes));
                }
                ToRunner::Message(_, msg, _) => answer(msg, RESULT_BUSY, &[]),
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
                    {
                        let mut st = self.state.borrow_mut();
                        st.front = true;
                        // the owner opened it: it stays until they leave, and keeps maki
                        st.headless = false;
                        if let Some((_, msg, _)) = st.handover.take() {
                            answer(msg, RESULT_BUSY, &[]);
                        }
                    }
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
                ToRunner::Key(s, _)
                    if s == self.slot
                        && self.state.borrow().quiet_until.is_some_and(|q| Instant::now() < q) => {}
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
                        Key::Menu | Key::Up | Key::Down => {}
                    }
                }
                ToRunner::Jog(s, _)
                    if s == self.slot
                        && self.state.borrow().quiet_until.is_some_and(|q| Instant::now() < q) => {}
                // the jog dial, for an app that says it knows it: an older one would take it for a
                // timeout (and App info is the launcher's, not the app's)
                ToRunner::Jog(s, up)
                    if s == self.slot
                        && self.state.borrow().front
                        && self.state.borrow().info.is_none()
                        && maki_wasm::knows_jog(&self.manifest) =>
                {
                    return if up { Event::Up } else { Event::Down };
                }
                ToRunner::Menu(s, i) if s == self.slot => {
                    let items =
                        self.ctx.shared.lock().unwrap().menus.get(&self.slot).map(|m| m.len()).unwrap_or(0);
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

    fn message(&mut self) -> Option<Vec<u8>> {
        self.state.borrow().current.as_ref().map(|(_, bytes)| bytes.clone())
    }

    fn reply(&mut self, reply: &[u8]) -> bool {
        let current = self.state.borrow_mut().current.take();
        match current {
            Some((msg, _)) => {
                answer(msg, RESULT_OK, reply);
                self.state.borrow_mut().idle_since = Instant::now();
                true
            }
            None => false,
        }
    }

    fn present(&mut self, canvas: &Canvas) {
        self.state.borrow_mut().last = canvas.clone();
        self.draw_frame();
        if let Some(opened) = self.state.borrow_mut().opened_ms.take() {
            log::info!("{}: first frame after {} ms", self.id, crate::tt().elapsed_ms() - opened);
        }
    }

    fn set_menu(&mut self, items: &[String]) {
        self.ctx.shared.lock().unwrap().menus.insert(self.slot, items.to_vec());
    }

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
        self.ctx
            .store
            .data_set(&self.id, key, value)
            .map_err(|e| log::warn!("{}: storing {key}: {e:?}", self.id))
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

    /// maki's own ask screen, under the app's bar: the app waits for the answer. The launcher
    /// puts the app in the background meanwhile, and brings it back after.
    fn ask(&mut self, ask: &Ask) -> maki_wasm::Answer {
        if !self.ctx.unlocked() {
            return maki_wasm::Answer::NoAnswer;
        }
        let timeout = maki_launcher::ask_timeout(ask.timeout_s);
        match self.ctx.launcher.ask_app(
            &self.name,
            self.sideloaded,
            &ask.question,
            &ask.detail,
            &ask.yes,
            &ask.no,
            timeout,
        ) {
            Ok(Answer::Allowed(_)) => maki_wasm::Answer::Yes,
            Ok(Answer::Denied) => maki_wasm::Answer::No,
            _ => maki_wasm::Answer::NoAnswer,
        }
    }

    /// From maki-keys, which derives it from the phrase for this app's ID and developer key.
    fn app_secret(&mut self, label: &str) -> Option<[u8; 32]> {
        if !self.ctx.unlocked() {
            return None;
        }
        self.ctx.keys.app_secret(&self.id, &self.record.developer, label).ok()
    }

    /// A wallet app's key work, by maki-keys, which keeps the seed. The session has held the path
    /// to the app's own, and a signature to the owner's yes to a review.
    fn wallet(&mut self, op: u8, path: &[u32], digest: &[u8]) -> Result<Vec<u8>, i32> {
        if !self.ctx.unlocked() {
            return Err(maki_wasm::LOCKED);
        }
        match self.ctx.keys.wallet(op, path, digest) {
            Ok(answer) => Ok(answer),
            Err(maki_keys::RESULT_NOT_NOW | maki_keys::RESULT_NO_PHRASE) => Err(maki_wasm::LOCKED),
            Err(maki_keys::RESULT_REFUSED) => Err(maki_wasm::REFUSED),
            Err(_) => Err(maki_wasm::FAILED),
        }
    }

    /// maki's own review screen, a page at a time under the app's bar, then its question: the
    /// app waits for the answer, as it does for an ask.
    fn review(&mut self, review: &Review) -> maki_wasm::Answer {
        if !self.ctx.unlocked() {
            return maki_wasm::Answer::NoAnswer;
        }
        let pages = review
            .pages
            .iter()
            .map(|p| maki_launcher::Page {
                heading: p.heading.clone(),
                value: p.value.clone(),
                mono: p.mono.clone(),
                prose: p.prose.clone(),
            })
            .collect();
        let yes = if review.yes.is_empty() { "sign" } else { &review.yes };
        let no = if review.no.is_empty() { "reject" } else { &review.no };
        let timeout = maki_launcher::ask_timeout(review.timeout_s);
        log::info!("{}: a review of {} pages", self.id, review.pages.len());
        match self.ctx.launcher.review_app(
            &self.name,
            self.sideloaded,
            &review.question,
            &review.detail,
            pages,
            yes,
            no,
            timeout,
        ) {
            Ok(Answer::Allowed(_)) => maki_wasm::Answer::Yes,
            Ok(Answer::Denied) => maki_wasm::Answer::No,
            _ => maki_wasm::Answer::NoAnswer,
        }
    }

    /// A wallet's backup words (a Monero wallet's 25, or a BIP-85 child seed's), on maki's own
    /// screens: maki asks first, then shows them a word to a screen under its own bar, and forgets
    /// them. The app hears only whether they were shown, and nothing says them in the log.
    fn show_backup(&mut self, path: &[u32]) -> Result<maki_wasm::Answer, i32> {
        use zeroize::Zeroize;
        if !self.ctx.unlocked() {
            return Err(maki_wasm::LOCKED);
        }
        // what they are: a phrase of its own for another wallet (BIP-85), or this wallet's
        let coin = maki_hd::coin(path).unwrap_or("wallet");
        let child = maki_hd::child_seed(path);
        let (op, subject, question, detail, title, prose) = match child {
            Some((words, index)) => (
                maki_keys::WALLET_BIP85_WORDS,
                "Child seed",
                "Show a child seed?",
                format!("{words} words, number {index}"),
                "Child seed".to_string(),
                "Write it down, in order: it's a whole wallet's key.",
            ),
            None => (
                maki_keys::WALLET_MONERO_WORDS,
                coin,
                "Show backup words?",
                "keep them secret".to_string(),
                format!("{coin} backup"),
                "Write it down, in order. Keep it off computers.",
            ),
        };
        let asked = self.ctx.launcher.review(
            subject,
            question,
            &detail,
            Vec::new(),
            "show",
            "don't",
            maki_launcher::ask_timeout(60),
        );
        match asked {
            Ok(Answer::Allowed(_)) => {}
            Ok(Answer::Denied) => return Ok(maki_wasm::Answer::No),
            _ => return Ok(maki_wasm::Answer::NoAnswer),
        }
        let mut words = match self.ctx.keys.wallet(op, path, &[]) {
            Ok(w) => w,
            Err(maki_keys::RESULT_NOT_NOW | maki_keys::RESULT_NO_PHRASE) => return Err(maki_wasm::LOCKED),
            // no words of its own: not a Monero account, or a child seed's path
            Err(maki_keys::RESULT_REFUSED) => return Err(maki_wasm::NOT_FOUND),
            Err(_) => return Err(maki_wasm::FAILED),
        };
        let n = words.split(|b| *b == b' ').count();
        let pages: Vec<maki_launcher::Page> = words
            .split(|b| *b == b' ')
            .enumerate()
            .map(|(i, w)| maki_launcher::Page {
                // "Word 10 of 25" is more than the bar holds
                heading: format!("Word {}/{n}", i + 1),
                value: String::from_utf8_lossy(w).into_owned(),
                mono: String::new(),
                prose: prose.into(),
            })
            .collect();
        words.zeroize();
        log::info!(
            "{}: showing {}",
            self.id,
            if child.is_some() { "a child seed" } else { "its account's backup words" }
        );
        let shown = self.ctx.launcher.review(
            &title,
            "Wrote them down?",
            &format!("{n} words, in order"),
            pages,
            "done",
            "close",
            maki_launcher::ask_timeout(900),
        );
        match shown {
            Ok(Answer::Allowed(_) | Answer::Denied) => Ok(maki_wasm::Answer::Yes),
            _ => Ok(maki_wasm::Answer::NoAnswer),
        }
    }

    /// A BIP-85 password, made by maki-keys and typed as `type_text` types (for the app in front,
    /// "typing" in maki's bar), then forgotten: the app never has it, and nothing says it in the
    /// log.
    fn type_password(&mut self, path: &[u32]) -> Result<bool, i32> {
        use zeroize::Zeroize;
        let mut password = self.wallet(maki_keys::WALLET_BIP85_PASSWORD, path, &[])?;
        if !self.state.borrow().front {
            password.zeroize();
            return Ok(false);
        }
        {
            let mut st = self.state.borrow_mut();
            st.typing = true;
            st.dark = false;
        }
        self.draw_frame();
        // ASCII, as BIP-85 writes it: nothing to lose
        let text = core::str::from_utf8(&password).unwrap_or_default();
        let typed = matches!(self.ctx.usb.send_str(text), Ok(n) if n == text.len());
        password.zeroize();
        log::info!("{}: typed a password: {}", self.id, if typed { "done" } else { "not plugged in" });
        self.state.borrow_mut().typing = false;
        self.draw_frame();
        Ok(typed)
    }

    /// A BIP-85 password on maki's own review screen, under the app's bar and the app's name for
    /// it, in fixed-width type, until the owner closes it: forgotten then, and nothing says it in
    /// the log.
    fn show_password(&mut self, path: &[u32], label: &str) -> Result<maki_wasm::Answer, i32> {
        use zeroize::Zeroize;
        let (_, len, index) = maki_hd::bip85_password(path).ok_or(maki_wasm::INVALID)?;
        let mut password = self.wallet(maki_keys::WALLET_BIP85_PASSWORD, path, &[])?;
        let page = maki_launcher::Page {
            heading: if label.is_empty() { "Password".into() } else { label.into() },
            value: String::new(),
            mono: String::from_utf8_lossy(&password).into_owned(),
            prose: format!("{len} characters, number {index}"),
        };
        password.zeroize();
        log::info!("{}: showing a password", self.id);
        let shown = self.ctx.launcher.review_app(
            &self.name,
            self.sideloaded,
            "Done with it?",
            label,
            vec![page],
            "done",
            "close",
            maki_launcher::ask_timeout(300),
        );
        match shown {
            Ok(Answer::Allowed(_) | Answer::Denied) => Ok(maki_wasm::Answer::Yes),
            _ => Ok(maki_wasm::Answer::NoAnswer),
        }
    }

    /// maki's own scanner, for the app in front: the camera's view takes the screen until a QR
    /// code is read or the owner presses a button.
    fn scan_qr(&mut self) -> Option<String> {
        if !self.state.borrow().front || !self.ctx.unlocked() {
            return None;
        }
        #[cfg(feature = "board-baosec")]
        let scanned = self.ctx.screen.gfx.acquire_qr().ok().and_then(|q| q.content);
        #[cfg(not(feature = "board-baosec"))]
        let scanned: Option<String> = None;
        // the press that cancelled it reached the app too: it isn't the app's
        self.state.borrow_mut().quiet_until = Some(Instant::now() + Duration::from_millis(500));
        log::info!("{}: scanned {}", self.id, if scanned.is_some() { "a QR code" } else { "nothing" });
        self.draw_frame();
        scanned
    }

    /// For the app in front.
    fn motion(&mut self) -> Option<[i16; 3]> {
        if !self.state.borrow().front {
            return None;
        }
        self.ctx.motion()
    }

    /// For the app running, in front or not: it's the one reading it.
    fn motion_range(&mut self, g: u8) -> Option<u8> { self.ctx.motion_range(g) }

    fn set_dark(&mut self, dark: bool) {
        self.state.borrow_mut().dark = dark;
        self.draw_frame();
    }

    /// Only for the app in front, with "typing" in maki's bar while it does.
    fn type_text(&mut self, text: &str) -> bool {
        if !self.state.borrow().front || !self.ctx.unlocked() {
            return false;
        }
        {
            // typing always shows: a dark screen lights for it
            let mut st = self.state.borrow_mut();
            st.typing = true;
            st.dark = false;
        }
        self.draw_frame();
        // unplugged, the service says it sent nothing rather than failing
        let typed = matches!(self.ctx.usb.send_str(text), Ok(n) if n == text.chars().count());
        log::info!(
            "{}: typed {} characters: {}",
            self.id,
            text.len(),
            if typed { "done" } else { "not plugged in" }
        );
        self.state.borrow_mut().typing = false;
        self.draw_frame();
        typed
    }

    fn press_key(&mut self, code: u8, mods: u8) -> bool {
        use usb_bao1x::UsbKeyCode;
        if !self.state.borrow().front || !self.ctx.unlocked() {
            return false;
        }
        let mut codes = vec![UsbKeyCode::from(code)];
        for (bit, key) in [
            (maki_wasm::MOD_SHIFT, UsbKeyCode::LeftShift),
            (maki_wasm::MOD_CTRL, UsbKeyCode::LeftControl),
            (maki_wasm::MOD_ALT, UsbKeyCode::LeftAlt),
            (maki_wasm::MOD_GUI, UsbKeyCode::LeftGUI),
        ] {
            if mods & bit != 0 {
                codes.push(key);
            }
        }
        {
            // typing always shows: a dark screen lights for it
            let mut st = self.state.borrow_mut();
            st.typing = true;
            st.dark = false;
        }
        self.draw_frame();
        let pressed = self.ctx.usb.send_keycode(codes, true).is_ok();
        let held = [
            (maki_wasm::MOD_CTRL, "Ctrl"),
            (maki_wasm::MOD_ALT, "Alt"),
            (maki_wasm::MOD_GUI, "GUI"),
            (maki_wasm::MOD_SHIFT, "Shift"),
        ]
        .iter()
        .filter(|(bit, _)| mods & bit != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>();
        log::info!(
            "{}: pressed key {code:#04x}{}: {}",
            self.id,
            if held.is_empty() { String::new() } else { format!(" with {}", held.join("+")) },
            if pressed { "done" } else { "not plugged in" }
        );
        self.state.borrow_mut().typing = false;
        self.draw_frame();
        pressed
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
        // a word longer than a line (where a panic was, say) goes on over the next
        let chars: Vec<char> = word.chars().collect();
        for piece in chars.chunks(22) {
            let piece: String = piece.iter().collect();
            match lines.last_mut() {
                Some(l) if l.chars().count() + 1 + piece.chars().count() <= 22 => {
                    l.push(' ');
                    l.push_str(&piece);
                }
                _ => lines.push(piece),
            }
        }
    }
    for (i, line) in lines.iter().take(5).enumerate() {
        s.text(top + LINE + 6 + i as isize * 13, 13, GlyphStyle::Small, false, true, line);
    }
    s.action_bar("ok", false);
    s.end();
}

/// What runs next: an app, and the message it's started for, if it is.
type Next = Option<(usize, Option<(xous::MessageEnvelope, Vec<u8>)>)>;

/// Runs the app in `slot` until it stops, opened by the owner, or without the screen for a
/// message from the computer (`message`). Returns what runs next: an app opened meanwhile, or
/// another app's message this one gave way to.
fn run(ctx: &Rc<Ctx>, slot: usize, message: Option<(xous::MessageEnvelope, Vec<u8>)>) -> Next {
    let opened = crate::tt().elapsed_ms();
    let headless = message.is_some();
    // the message gets an answer whatever happens: unanswered, it says why
    let mut message = message;
    let mut refuse = |result: u32| {
        if let Some((msg, _)) = message.take() {
            answer(msg, result, &[]);
        }
    };
    let Some(info) = ctx.shared.lock().unwrap().slots.get(slot).cloned().flatten() else {
        refuse(maki_app_host_api::RESULT_NO_APP);
        if !headless {
            ctx.launcher.home().ok();
        }
        return None;
    };
    if !ctx.unlocked() {
        refuse(maki_app_host_api::RESULT_LOCKED);
        if !headless {
            ctx.launcher.home().ok();
        }
        return None;
    }
    let gone = |refuse: &mut dyn FnMut(u32)| {
        refuse(maki_app_host_api::RESULT_NO_APP);
        if !headless {
            stopped(ctx, &info.name, true, "it isn't installed any more");
            wait_to_leave(ctx, slot);
        }
    };
    let Some(record) = ctx.store.record(&info.id) else {
        gone(&mut refuse);
        return None;
    };
    // checked when it was installed: a WebAssembly app compiled once a session (lazily, each
    // function when it's first called: all of it was validated at install) and kept, with its
    // manifest, for the next time, which then reads nothing of its bundle; a native app's ELF
    // checked again, to be loaded into a process of its own
    let started = crate::tt().elapsed_ms();
    let kept =
        ctx.kept(&info.id, record.version).and_then(|app| Some((app.manifest.clone()?, Code::Wasm(app))));
    let loaded = match kept {
        Some(kept) => Ok(kept),
        None => {
            let Some(bytes) = ctx.store.bundle(&info.id) else {
                gone(&mut refuse);
                return None;
            };
            maki_bundle::read_stored(&bytes).map_err(|e| e.to_string()).and_then(|b| {
                if b.manifest.kind == maki_bundle::Kind::Native {
                    let limits = crate::native::admit(&b.manifest, b.code)?;
                    return Ok((b.manifest.clone(), Code::Native(b.code.to_vec(), limits)));
                }
                let app = Arc::new(maki_wasm::load_installed(&b.manifest, b.code)?);
                ctx.keep(info.id.clone(), b.manifest.version, app.clone());
                Ok((b.manifest, Code::Wasm(app)))
            })
            // what's needed of the bundle is in `loaded`: the rest isn't kept through the run
        }
    };
    let (manifest, code) = match loaded {
        Ok(ok) => ok,
        Err(why) => {
            log::warn!("{} can't run: {why}", info.id);
            refuse(RESULT_FAILED);
            if !headless {
                stopped(ctx, &info.name, !record.from_store, &why);
                wait_to_leave(ctx, slot);
            }
            return None;
        }
    };
    let may_link = manifest.permissions.iter().any(|(p, _)| *p == maki_bundle::Permission::Link);
    if headless && !may_link {
        refuse(RESULT_REFUSED);
        return None;
    }
    // revoked by the store since it was installed: never in the background, and opened only if
    // the owner says so, each time
    let revoked = ctx
        .store
        .revocations()
        .and_then(|r| r.check(&info.id, manifest.version, &record.developer).map(String::from));
    if let Some(why) = revoked {
        log::warn!("{} is revoked: {why}", info.id);
        if headless {
            refuse(RESULT_REFUSED);
            return None;
        }
        // the store's reason on a page of its own, where it has room, then the choice
        let pages = vec![maki_launcher::Page {
            heading: "Revoked".into(),
            value: "by the maki store".into(),
            mono: String::new(),
            prose: format!("{why}\n\nOpen it only if you're sure; App info can remove it."),
        }];
        let answer = ctx.launcher.review(
            &info.name,
            "Open it anyway?",
            "revoked",
            pages,
            "open anyway",
            "don't",
            ASK_TIMEOUT_S,
        );
        if !matches!(answer, Ok(Answer::Allowed(_))) {
            ctx.launcher.home().ok();
            return None;
        }
    }
    log::info!(
        "{} ready to run ({} ms){}",
        info.id,
        crate::tt().elapsed_ms() - started,
        if headless { ", for a message" } else { "" }
    );
    let limits = match &code {
        Code::Wasm(app) => app.limits,
        Code::Native(_, limits) => *limits,
    };
    let inbox: VecDeque<_> =
        message.take().map(|(msg, bytes)| (msg, bytes, Instant::now())).into_iter().collect();
    let state = Rc::new(RefCell::new(RunState {
        front: !headless,
        info: None,
        pending: None,
        removed: false,
        stopping: false,
        last: Canvas::default(),
        opened_ms: if headless { None } else { Some(opened) },
        typing: false,
        dark: false,
        quiet_until: None,
        inbox,
        current: None,
        headless,
        handover: None,
        idle_since: Instant::now(),
        deferred: VecDeque::new(),
    }));
    let device = Device {
        ctx: ctx.clone(),
        slot,
        id: info.id.clone(),
        name: info.name.clone(),
        sideloaded: !record.from_store,
        storage_quota: limits.storage,
        may_link,
        manifest,
        record,
        state: state.clone(),
    };
    // the bar goes up at once, before the app's first frame (if it's on screen)
    device.draw_frame();
    {
        let mut shared = ctx.shared.lock().unwrap();
        shared.running = Some(slot);
        shared.running_wallet = device.wallet().is_some();
    }
    log::info!("running {}", info.id);
    let stop = match code {
        Code::Wasm(app) => app.run(Box::new(device)),
        Code::Native(elf, limits) => crate::native::run(ctx, device, elf, limits),
    };
    ctx.motion_reset();
    {
        let mut shared = ctx.shared.lock().unwrap();
        shared.running = None;
        shared.running_wallet = false;
        shared.menus.remove(&slot);
    }
    log::info!("{} stopped: {:?}", info.id, stop);
    state.borrow_mut().answer_all();
    let mut st = state.borrow_mut();
    let why = match &stop {
        Stop::Finished | Stop::Exited => None,
        Stop::NotResponding => Some("it stopped responding".to_string()),
        Stop::Aborted(why) | Stop::Failed(why) => Some(why.clone()),
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
    // an app the owner opened meanwhile comes first: another app's message waits no longer
    match (st.pending, st.handover.take()) {
        (Some(s), handover) => {
            if let Some((_, msg, _)) = handover {
                answer(msg, RESULT_BUSY, &[]);
            }
            Some((s, None))
        }
        (None, Some((s, msg, bytes))) => Some((s, Some((msg, bytes)))),
        (None, None) => None,
    }
}

/// An app's code, ready to run.
enum Code {
    Wasm(Arc<maki_wasm::Loaded>),
    /// A native app's ELF, and what it may use.
    Native(Vec<u8>, maki_wasm::Limits),
}

/// Waits for the owner to press the centre (or leave some other way), then goes home.
fn wait_to_leave(ctx: &Ctx, slot: usize) {
    loop {
        match ctx.rx.recv() {
            Ok(ToRunner::Key(s, Key::Confirm)) if s == slot => break,
            Ok(ToRunner::Hidden(s) | ToRunner::Exited(s)) if s == slot => return,
            Ok(ToRunner::Stop) | Err(_) => break,
            Ok(ToRunner::Open(s)) if s != slot => return,
            Ok(ToRunner::Message(_, msg, _)) => answer(msg, RESULT_BUSY, &[]),
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
        launcher: maki_launcher::Launcher::new(&xns).expect("couldn't connect to the launcher"),
        keys: maki_keys::Keys::new(&xns).expect("couldn't connect to maki-keys"),
        usb: usb_bao1x::UsbHid::new(),
        #[cfg(feature = "board-baosec")]
        accel: RefCell::new(None),
        #[cfg(feature = "board-baosec")]
        accel_ranged: Cell::new(false),
        time_conn: crate::time_conn(),
        shared,
        rx,
        service: xous::create_server_with_address(&maki_native::service::SID).expect("the app service"),
    });
    let mut next: Next = None;
    loop {
        let (slot, message) = match next.take() {
            Some(n) => n,
            None => match ctx.rx.recv() {
                Ok(ToRunner::Open(s)) => (s, None),
                // no app running: start this one without the screen, for the message
                Ok(ToRunner::Message(s, msg, bytes)) => (s, Some((msg, bytes))),
                Ok(ToRunner::Loaded(id, version, app)) => {
                    ctx.keep(id, version, app);
                    continue;
                }
                Ok(_) => continue,
                Err(_) => return,
            },
        };
        next = run(&ctx, slot, message);
    }
}
