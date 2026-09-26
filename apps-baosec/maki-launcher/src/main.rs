//! maki launcher: the boot image, the home screen, the owner of input focus, and the screens
//! that belong to maki rather than an app: asks, menus.
//!
//! The launcher is the only process that registers with bao-video for key presses. While an app
//! is in front, keys are relayed to that app and nowhere else, except left and right pressed
//! together, which open the app's menu here. Apps join the home screen by registering at startup (see
//! `lib.rs`), so nothing here is specific to any one app.
//!
//! Every screen follows the three-button model (ARCHITECTURE.md): left and right move, the
//! centre confirms what's offered, left and right together open the menu, and there's no back
//! button. An ask (`Launcher::ask`) goes over whatever is on screen and gives it back after.

mod api;
mod ask;
mod menu;
mod pin;
mod setup;
mod splash;
use maki_ui as ui;

use api::*;
use ask::Asking;
use blitstr2::GlyphStyle;
use maki_keys::{Keys, PinResult, State};
use menu::Menu;
use num_traits::{FromPrimitive, ToPrimitive};
use pin::PinPad;
use setup::{CheckStep, EntryStep, Phrase, PhraseCheck, PhraseStep, WordEntry};
use ui::{Key, LINE, Screen, W};
use xous_ipc::Buffer;

/// The boot image stays up at least this long, so a fast mount doesn't just flash it.
const SPLASH_MIN_MS: u64 = 1500;

struct App {
    name: String,
    conn: xous::CID,
    key_op: usize,
    focus_op: usize,
    menu_op: usize,
    icon: Option<[u32; 128]>,
}

/// Overwrite a PIN before letting it go.
fn forget(pin: String) {
    let mut bytes = pin.into_bytes();
    bytes.fill(0);
}

fn set_focus(app: &App, focus: Focus) {
    xous::send_message(app.conn, xous::Message::new_scalar(app.focus_op, focus.to_usize().unwrap(), 0, 0, 0)).ok();
}

/// The app's own menu items, which it fills in when asked. An app without a menu has none.
fn app_menu_items(app: &App) -> Vec<String> {
    if app.menu_op == 0 {
        return Vec::new();
    }
    let Ok(mut buf) = Buffer::into_buf(AppMenu::default()) else { return Vec::new() };
    if buf.lend_mut(app.conn, app.menu_op as u32).is_err() {
        return Vec::new();
    }
    buf.to_original::<AppMenu, _>().map(|m| m.items).unwrap_or_default()
}

/// Local wall-clock time as `HH:MM`, or `--:--` until something has set it. The module has no
/// battery, so the clock starts unset on every boot. A trailing `?` marks a time that nothing
/// has verified (the desktop app's own clock, or the vault's QR code).
#[cfg(feature = "board-baosec")]
fn clock_text(time_conn: xous::CID, verified: bool) -> String {
    use bao1x_hal_service::api::TimeOp;
    let is_set = matches!(
        xous::send_message(
            time_conn,
            xous::Message::new_blocking_scalar(TimeOp::WallClockTimeInit.to_usize().unwrap(), 0, 0, 0, 0),
        ),
        Ok(xous::Result::Scalar2(_, 1))
    );
    if !is_set {
        return String::from("--:--");
    }
    match xous::send_message(
        time_conn,
        xous::Message::new_blocking_scalar(TimeOp::GetLocalTimeMs.to_usize().unwrap(), 0, 0, 0, 0),
    ) {
        Ok(xous::Result::Scalar2(lo, hi)) => {
            let ms = ((hi as u64) << 32) | lo as u64;
            let secs = (ms / 1000) % 86_400;
            format!("{:02}:{:02}{}", secs / 3600, (secs % 3600) / 60, if verified { "" } else { "?" })
        }
        _ => String::from("--:--"),
    }
}

#[cfg(not(feature = "board-baosec"))]
fn clock_text(_time_conn: xous::CID, _verified: bool) -> String { String::from("--:--") }

/// Whose menu is open.
enum MenuFor {
    Maki,
    App(usize),
}

/// What a PIN pad is for.
enum PinFor {
    /// unlocking, at boot
    Enter,
    /// the first PIN, at setup
    Choose,
    /// the same again, to be sure of it
    Confirm(String),
}

/// Where a page of text goes when the owner confirms it.
#[derive(Clone, Copy)]
enum Next {
    Home,
    ChoosePin,
    /// choose a PIN, then type in a recovery phrase instead of making one
    Restore,
    /// make the recovery phrase and show it
    ShowPhrase,
    /// back to the phrase's first word, after a wrong answer in the check
    ReviewPhrase,
    /// type in a phrase of this many words
    Words(usize),
}

/// What's on screen. Asks go over any of these, once maki is unlocked.
enum View {
    Splash,
    Home,
    Menu(Menu, MenuFor),
    /// a page of text, and what the centre can do from it (left and right choose, if more than one)
    Info { title: String, lines: Vec<String>, actions: Vec<(&'static str, Next)>, selected: usize },
    Pin(PinPad, PinFor),
    /// the recovery phrase's words, to write down
    Phrase(Phrase),
    PhraseCheck(PhraseCheck),
    /// typing a recovery phrase in, to restore
    WordEntry(WordEntry),
    /// an app is in front and draws for itself
    App(usize),
}

/// maki's own menu. Change PIN and backup join it with the recovery phrase.
const MAKI_MENU: [&str; 3] = ["Lock", "About", "Close"];

struct System {
    screen: Screen,
    apps: Vec<App>,
    /// the app the home screen is showing
    selected: usize,
    view: View,
    asking: Asking,
    /// the app that was in front when an ask took the screen: it gets it back after
    paused: Option<usize>,
    ready: bool,
    time_verified: bool,
    linked: bool,
    clock: String,
    time_conn: xous::CID,
    keys: Option<Keys>,
    /// the PIN has been entered: apps and asks may have the screen
    unlocked: bool,
    /// Home has been reached since the PIN: asks wait until then. During setup the owner is
    /// writing down or typing in the phrase, and a press meant for that could answer an ask.
    asks_open: bool,
    /// setting up to restore a phrase rather than make one
    restoring: bool,
    /// the phrase being shown and checked, at setup
    phrase: Option<Vec<String>>,
}

impl System {
    fn draw_home(&self) {
        let s = &self.screen;
        s.begin();
        s.status_bar(&self.clock, self.linked);
        let top = s.bar + 6;
        match self.apps.get(self.selected) {
            None => s.text(top + 24, LINE, GlyphStyle::Regular, false, true, "Starting…"),
            Some(app) => {
                match &app.icon {
                    Some(icon) => s.icon(icon, W / 2 - 32, top),
                    None => s.letter_icon(&app.name, W / 2 - 32, top),
                }
                if self.apps.len() > 1 {
                    s.arrow(4, top + 32, 6, true);
                    s.arrow(W - 5, top + 32, 6, false);
                }
                s.text(top + 66, LINE, GlyphStyle::Bold, false, true, &app.name);
                s.dots(self.apps.len(), self.selected, top + 66 + LINE + 6);
                s.action_bar("open", false);
            }
        }
        s.end();
    }

    fn draw_info(&self, title: &str, lines: &[String], action: &str, arrows: bool) {
        let s = &self.screen;
        s.begin();
        s.status_bar(&self.clock, self.linked);
        let top = s.bar + 6;
        s.text(top, LINE, GlyphStyle::Bold, false, true, title);
        for (i, line) in lines.iter().enumerate() {
            s.text(top + LINE + 6 + i as isize * 13, 13, GlyphStyle::Small, false, true, line);
        }
        if !action.is_empty() {
            s.action_bar(action, arrows);
        }
        s.end();
    }

    fn info(&mut self, title: &str, lines: &[&str], action: &'static str, next: Next) {
        self.choose(title, lines, vec![(action, next)]);
    }

    /// A page of text offering more than one thing: left and right go between them.
    fn choose(&mut self, title: &str, lines: &[&str], actions: Vec<(&'static str, Next)>) {
        let actions = actions.into_iter().filter(|(a, _)| !a.is_empty()).collect();
        self.view = View::Info { title: title.into(), lines: lines.iter().map(|l| l.to_string()).collect(), actions, selected: 0 };
        self.redraw();
    }

    fn forget_phrase(&mut self) {
        if let Some(words) = self.phrase.take() {
            for w in words {
                forget(w);
            }
        }
    }

    /// The phrase comes after the PIN: made and shown, or typed in to restore.
    fn phrase_step(&mut self) {
        if self.restoring {
            self.choose(
                "Restore",
                &["How many words is", "your recovery phrase?"],
                vec![("24 words", Next::Words(24)), ("12 words", Next::Words(12))],
            );
        } else {
            self.info(
                "Recovery phrase",
                &["24 words that bring back", "your wallet and backups if", "maki is lost or wiped.", "Have paper and a pen."],
                "show my words",
                Next::ShowPhrase,
            );
        }
    }

    fn setup_done(&mut self) {
        self.forget_phrase();
        self.restoring = false;
        self.info("maki is ready", &["Enter your PIN after", "plugging maki in."], "continue", Next::Home);
    }

    /// Something slow is happening (the PIN's key derivation): say so first.
    fn busy(&self, title: &str) { self.draw_info(title, &[], "", false); }

    fn pin_pad(&mut self, title: &str, note: &str, purpose: PinFor) {
        self.view = View::Pin(PinPad::new(title, note), purpose);
        self.redraw();
    }

    /// After the boot image: set up, unlock, or straight home.
    fn first_screen(&mut self) {
        let status = self.keys.as_ref().map(|k| k.status()).unwrap_or((State::Unlocked, 0));
        match status {
            (State::Unset, _) => self.choose(
                "Welcome to maki",
                &["Choose a PIN to start.", "You'll enter it each time", "maki is plugged in."],
                vec![("set up maki", Next::ChoosePin), ("restore from phrase", Next::Restore)],
            ),
            (State::Locked, left) if left < maki_keys::MAX_TRIES => {
                self.pin_pad("Enter your PIN", &format!("{} tries left", left), PinFor::Enter)
            }
            (State::Locked, _) => self.pin_pad("Enter your PIN", "", PinFor::Enter),
            (State::Unlocked, _) => self.now_unlocked(),
        }
    }

    fn now_unlocked(&mut self) {
        self.unlocked = true;
        // a setup cut short before its phrase: finish it first
        if !self.keys.as_ref().map(|k| k.has_phrase()).unwrap_or(true) {
            return self.choose(
                "No phrase yet",
                &["Setup stopped before the", "recovery phrase was made."],
                vec![("make one now", Next::ShowPhrase), ("restore mine", Next::Words(24))],
            );
        }
        self.go_home();
        self.start_asking();
    }

    /// The PIN pad handed over a PIN.
    fn pin_entered(&mut self, pin: String, purpose: PinFor) {
        let Some(keys) = self.keys.as_ref() else { return };
        match purpose {
            PinFor::Enter => {
                self.busy("Checking…");
                let result = keys.unlock(&pin);
                forget(pin);
                match result {
                    PinResult::Ok => self.now_unlocked(),
                    PinResult::Wrong(left) => {
                        let note = if left == 1 { "Wrong PIN. Last try!".to_string() } else { format!("Wrong PIN. {} tries left", left) };
                        self.pin_pad("Enter your PIN", &note, PinFor::Enter)
                    }
                    PinResult::Wiped => self.info(
                        "Too many tries",
                        &["maki's secrets were wiped.", "Choose a new PIN, then", "restore from your backup."],
                        "continue",
                        Next::ChoosePin,
                    ),
                    _ => self.info("Couldn't check it", &["Unplug maki and try again."], "", Next::Home),
                }
            }
            PinFor::Choose => self.pin_pad("Enter it again", "to be sure of it", PinFor::Confirm(pin)),
            PinFor::Confirm(first) => {
                let same = first == pin;
                forget(first);
                if !same {
                    forget(pin);
                    return self.info("PINs didn't match", &["Choose one again."], "try again", Next::ChoosePin);
                }
                self.busy("Setting up…");
                let result = keys.set_pin(&pin);
                forget(pin);
                match result {
                    PinResult::Ok => {
                        self.unlocked = true;
                        self.phrase_step()
                    }
                    _ => self.info("Couldn't set the PIN", &["Try again."], "try again", Next::ChoosePin),
                }
            }
        }
    }

    /// Draw whatever the launcher itself is showing; an app draws for itself.
    fn redraw(&self) {
        if !self.ready || self.asking.active() {
            return;
        }
        match &self.view {
            View::Splash | View::App(_) => {}
            View::Home => self.draw_home(),
            View::Menu(menu, _) => menu.draw(&self.screen, &self.clock, self.linked),
            View::Info { title, lines, actions, selected } => {
                let action = actions.get(*selected).map(|a| a.0).unwrap_or("");
                self.draw_info(title, lines, action, actions.len() > 1)
            }
            View::Pin(pad, _) => pad.draw(&self.screen, &self.clock, self.linked),
            View::Phrase(p) => p.draw(&self.screen, &self.clock, self.linked),
            View::PhraseCheck(c) => c.draw(&self.screen, &self.clock, self.linked),
            View::WordEntry(e) => e.draw(&self.screen, &self.clock, self.linked),
        }
    }

    /// Take the screen for the next ask waiting, if any. Not before the PIN, nothing being asked
    /// of a maki that hasn't been unlocked, and not during setup: once Home is reached.
    fn start_asking(&mut self) {
        if !self.ready || !self.unlocked || !self.asks_open || self.asking.active() || self.asking.queue.is_empty() {
            return;
        }
        if let View::App(i) = self.view {
            set_focus(&self.apps[i], Focus::Background);
            self.paused = Some(i);
        }
        self.asking.show_next(&self.screen, self.linked);
    }

    /// An ask was answered: the next one, or the screen goes back to what was there.
    fn after_ask(&mut self) {
        if self.asking.show_next(&self.screen, self.linked) {
            return;
        }
        match self.paused.take() {
            Some(i) => self.open_app(i),
            None => self.redraw(),
        }
    }

    /// Hand the screen to an app. It starts blank: apps don't all paint every pixel, and what
    /// the launcher drew mustn't show through.
    fn open_app(&mut self, i: usize) {
        log::info!("bringing '{}' to the front", self.apps[i].name);
        self.view = View::App(i);
        self.screen.begin();
        self.screen.end();
        set_focus(&self.apps[i], Focus::Foreground);
    }

    fn go_home(&mut self) {
        self.asks_open = self.unlocked;
        self.view = View::Home;
        self.clock = clock_text(self.time_conn, self.time_verified);
        self.redraw();
    }

    fn open_app_menu(&mut self, i: usize) {
        // the app stops drawing before the menu goes up
        set_focus(&self.apps[i], Focus::Background);
        let mut items = app_menu_items(&self.apps[i]);
        items.push("Exit".into());
        self.view = View::Menu(Menu::new(&self.apps[i].name, items), MenuFor::App(i));
        self.redraw();
    }

    /// Go where a page's action leads.
    fn follow(&mut self, next: Next) {
        match next {
            Next::Home if self.unlocked => {
                self.go_home();
                self.start_asking();
            }
            Next::Home => self.first_screen(),
            Next::ChoosePin => self.pin_pad("Choose a PIN", "6 to 12 digits", PinFor::Choose),
            Next::Restore => {
                self.restoring = true;
                self.pin_pad("Choose a PIN", "6 to 12 digits", PinFor::Choose)
            }
            Next::ShowPhrase => {
                self.busy("One moment…");
                match self.keys.as_ref().and_then(|k| k.new_phrase()) {
                    Some(words) => {
                        self.phrase = Some(words.clone());
                        self.view = View::Phrase(Phrase { words, index: 0 });
                        self.redraw();
                    }
                    None => self.info("Couldn't make it", &["Unplug maki and try again."], "", Next::Home),
                }
            }
            Next::ReviewPhrase => match self.phrase.clone() {
                Some(words) => {
                    self.view = View::Phrase(Phrase { words, index: 0 });
                    self.redraw();
                }
                None => self.first_screen(),
            },
            Next::Words(n) => {
                self.view = View::WordEntry(WordEntry::new(n));
                self.redraw();
            }
        }
    }

    fn key(&mut self, key: Key) {
        match &mut self.view {
            View::Splash | View::App(_) => {}
            View::Home => match key {
                Key::Left | Key::Right if !self.apps.is_empty() => {
                    let n = self.apps.len();
                    self.selected =
                        if key == Key::Left { (self.selected + n - 1) % n } else { (self.selected + 1) % n };
                    self.redraw();
                }
                Key::Confirm if self.selected < self.apps.len() => self.open_app(self.selected),
                Key::Menu => {
                    let items = MAKI_MENU.iter().map(|s| s.to_string()).collect();
                    self.view = View::Menu(Menu::new("maki", items), MenuFor::Maki);
                    self.redraw();
                }
                _ => {}
            },
            View::Info { actions, selected, .. } => {
                let n = actions.len();
                match key {
                    Key::Left | Key::Right if n > 1 => {
                        *selected = if key == Key::Left { (*selected + n - 1) % n } else { (*selected + 1) % n };
                        self.redraw();
                    }
                    Key::Confirm if n > 0 => {
                        let next = actions[*selected].1;
                        self.follow(next);
                    }
                    _ => {}
                }
            }
            View::Phrase(p) => match p.key(key) {
                PhraseStep::Stay => self.redraw(),
                PhraseStep::Check => {
                    if let Some(words) = &self.phrase {
                        self.view = View::PhraseCheck(PhraseCheck::new(words));
                        self.redraw();
                    }
                }
            },
            View::PhraseCheck(c) => {
                let Some(words) = self.phrase.clone() else { return };
                match c.key(key, &words) {
                    CheckStep::Stay => self.redraw(),
                    CheckStep::Passed => self.setup_done(),
                    CheckStep::Wrong(n) => {
                        let title = format!("That's not word {}", n);
                        self.info(&title, &["Look at what you wrote,", "then check again."], "see the words", Next::ReviewPhrase)
                    }
                }
                for w in words {
                    forget(w);
                }
            }
            View::WordEntry(e) => match e.key(key) {
                EntryStep::Stay => self.redraw(),
                EntryStep::Done(words) => {
                    self.busy("Checking…");
                    let count = words.len();
                    let result = self.keys.as_ref().map(|k| k.restore_phrase(&words)).unwrap_or(maki_keys::RESULT_FAILED);
                    match result {
                        maki_keys::RESULT_OK => {
                            self.restoring = false;
                            self.info(
                                "Phrase restored",
                                &["Your wallet keys are back.", "Restore logins and codes", "from maki desktop."],
                                "continue",
                                Next::Home,
                            )
                        }
                        maki_keys::RESULT_BAD_PHRASE => self.info(
                            "Words don't check out",
                            &["A word is wrong, or two", "are swapped."],
                            "enter them again",
                            Next::Words(count),
                        ),
                        _ => self.info("Couldn't save it", &["Unplug maki and try again."], "", Next::Home),
                    }
                }
            },
            View::Pin(pad, _) => {
                if let Some(pin) = pad.key(key) {
                    let View::Pin(_, purpose) = std::mem::replace(&mut self.view, View::Splash) else { return };
                    self.pin_entered(pin, purpose);
                } else {
                    self.redraw();
                }
            }
            View::Menu(menu, whose) => {
                let picked = menu.key(key);
                let last = menu.items.len().saturating_sub(1);
                let app = match whose {
                    MenuFor::Maki => None,
                    MenuFor::App(i) => Some(*i),
                };
                match (picked, app) {
                    (None, _) => self.redraw(),
                    (Some(p), None) => self.maki_menu(p),
                    (Some(p), Some(i)) if p == last => {
                        log::info!("'{}' exited from its menu", self.apps[i].name);
                        self.go_home();
                    }
                    (Some(p), Some(i)) => {
                        let app = &self.apps[i];
                        xous::send_message(app.conn, xous::Message::new_scalar(app.menu_op, p, 0, 0, 0)).ok();
                        self.open_app(i);
                    }
                }
            }
        }
    }

    fn maki_menu(&mut self, picked: usize) {
        match MAKI_MENU.get(picked) {
            Some(&"Lock") => {
                if self.keys.as_ref().map(|k| k.lock()).unwrap_or(false) {
                    self.unlocked = false;
                    self.asks_open = false;
                    self.pin_pad("Enter your PIN", "", PinFor::Enter);
                } else {
                    self.go_home();
                }
            }
            Some(&"About") => {
                let version = format!("firmware {}", env!("CARGO_PKG_VERSION"));
                let lines = [
                    version.as_str(),
                    if self.linked { "desktop linked" } else { "desktop not linked" },
                    if self.time_verified { "clock verified" } else { "clock not verified" },
                ];
                self.info("maki", &lines, "close", Next::Home);
            }
            _ => self.go_home(),
        }
    }
}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("maki launcher PID is {}", xous::process::id());

    let xns = xous_names::XousNames::new().unwrap();
    let sid = xns.register_name(SERVER_NAME_LAUNCHER, None).expect("can't register server");
    let conn = xous::connect(sid).unwrap();

    let screen = Screen::new(&xns);
    screen.gfx.bitmap(&splash::BITMAP, None, None).ok();
    screen.gfx.flush().ok();

    #[cfg(feature = "board-baosec")]
    let time_conn =
        xous::connect(xous::SID::from_bytes(bao1x_hal_service::api::TIME_SERVER_PUBLIC).unwrap()).unwrap();
    #[cfg(not(feature = "board-baosec"))]
    let time_conn: xous::CID = 0;

    screen.gfx.register_listener(SERVER_NAME_LAUNCHER, LauncherOp::KeyPress.to_usize().unwrap());

    // The PDDB's first-boot format prompt is a modal; drawing the home screen before the mount
    // finishes would paint over it. Wait on a helper thread rather than here: apps register
    // before the mount is triggered, so blocking the main loop would deadlock the boot.
    std::thread::spawn(move || {
        let tt = ticktimer_server::Ticktimer::new().unwrap();
        let start = tt.elapsed_ms();
        pddb::Pddb::new().is_mounted_blocking();
        let shown = tt.elapsed_ms() - start;
        if shown < SPLASH_MIN_MS {
            tt.sleep_ms((SPLASH_MIN_MS - shown) as usize).ok();
        }
        xous::send_message(conn, xous::Message::new_scalar(LauncherOp::Ready.to_usize().unwrap(), 0, 0, 0, 0))
            .ok();
    });

    // keeps the clock current; the main loop only redraws when the minute changes
    std::thread::spawn(move || {
        let tt = ticktimer_server::Ticktimer::new().unwrap();
        loop {
            tt.sleep_ms(1000).ok();
            xous::send_message(conn, xous::Message::new_scalar(LauncherOp::Tick.to_usize().unwrap(), 0, 0, 0, 0))
                .ok();
        }
    });

    let mut sys = System {
        screen,
        apps: Vec::new(),
        selected: 0,
        view: View::Splash,
        asking: Asking::new(),
        paused: None,
        ready: false,
        time_verified: false,
        linked: false,
        clock: String::from("--:--"),
        time_conn,
        keys: None,
        unlocked: false,
        asks_open: false,
        restoring: false,
        phrase: None,
    };

    loop {
        let msg = xous::receive_message(sid).unwrap();
        match FromPrimitive::from_usize(msg.body.id()) {
            Some(LauncherOp::Register) => {
                let buffer = unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                let reg = match buffer.to_original::<AppRegistration, _>() {
                    Ok(reg) => reg,
                    Err(_) => {
                        log::error!("malformed app registration");
                        continue;
                    }
                };
                match xns.request_connection_blocking(&reg.server_name) {
                    Ok(app_conn) => {
                        log::info!("registered app '{}' ({})", reg.name, reg.server_name);
                        // in alphabetical order, whichever started first: the home screen is
                        // the same every time
                        let key = reg.name.to_lowercase();
                        let pos = sys.apps.iter().position(|a| a.name.to_lowercase() > key).unwrap_or(sys.apps.len());
                        sys.apps.insert(pos, App {
                            name: reg.name,
                            conn: app_conn,
                            key_op: reg.key_op as usize,
                            focus_op: reg.focus_op as usize,
                            menu_op: reg.menu_op as usize,
                            icon: reg.icon.as_slice().try_into().ok(),
                        });
                        // apps are known by position: move along those after it
                        let shift = |i: &mut usize| {
                            if *i >= pos {
                                *i += 1
                            }
                        };
                        if let View::App(i) | View::Menu(_, MenuFor::App(i)) = &mut sys.view {
                            shift(i);
                        }
                        if let Some(i) = &mut sys.paused {
                            shift(i);
                        }
                        // the one the owner is looking at stays put (before that, the first)
                        if sys.unlocked && sys.apps.len() > 1 {
                            shift(&mut sys.selected);
                        }
                        if matches!(sys.view, View::Home) {
                            sys.redraw();
                        }
                    }
                    Err(e) => log::error!("couldn't connect to app server {}: {:?}", reg.server_name, e),
                }
            }
            Some(LauncherOp::Ready) => {
                sys.ready = true;
                sys.clock = clock_text(time_conn, sys.time_verified);
                sys.keys = Keys::new(&xns).ok();
                // the screen's role: only the launcher may enter the PIN or see the phrase
                if !sys.keys.as_ref().map(|k| k.claim()).unwrap_or(false) {
                    log::error!("another process claimed maki-keys' screen role first");
                }
                sys.first_screen();
            }
            Some(LauncherOp::Tick) => {
                if sys.asking.active() {
                    if let Some(answer) = sys.asking.tick(&sys.screen, sys.linked) {
                        sys.asking.finish(answer);
                        sys.after_ask();
                    }
                } else if sys.ready {
                    let now = clock_text(time_conn, sys.time_verified);
                    if now != sys.clock {
                        sys.clock = now;
                        sys.redraw();
                    }
                }
            }
            Some(LauncherOp::Ask) => {
                let request = {
                    let buffer = unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                    buffer.to_original::<AskRequest, _>()
                };
                match request {
                    Ok(req) => {
                        log::info!("ask from {}", req.subject);
                        sys.asking.queue.push_back((msg, req));
                        sys.start_asking();
                    }
                    // dropping the message answers it as it came: timed out
                    Err(_) => log::error!("malformed ask"),
                }
            }
            Some(LauncherOp::KeyPress) => xous::msg_scalar_unpack!(msg, k1, k2, k3, k4, {
                let chars: Vec<char> = [k1, k2, k3, k4]
                    .iter()
                    .filter_map(|&k| char::from_u32(k as u32))
                    .filter(|&c| c != '\u{0}')
                    .collect();
                for c in chars {
                    let key = Key::from_char(c);
                    log::debug!("key {:?} ({:?})", c, key);
                    if sys.asking.active() {
                        if let Some(k) = key {
                            if let Some(answer) = sys.asking.key(k, &sys.screen, sys.linked) {
                                sys.asking.finish(answer);
                                sys.after_ask();
                                break; // the rest belonged to this ask
                            }
                        }
                    } else if let View::App(i) = sys.view {
                        if key == Some(Key::Menu) {
                            sys.open_app_menu(i);
                            break;
                        }
                        // everything else is the app's, the jog dial included
                        let app = &sys.apps[i];
                        xous::try_send_message(app.conn, xous::Message::new_scalar(app.key_op, c as usize, 0, 0, 0))
                            .ok();
                    } else if sys.ready {
                        if let Some(k) = key {
                            sys.key(k);
                        }
                    }
                }
            }),
            Some(LauncherOp::Home) => {
                if let View::App(i) = sys.view {
                    log::info!("'{}' returned to the home screen", sys.apps[i].name);
                    set_focus(&sys.apps[i], Focus::Background);
                    if sys.paused == Some(i) {
                        // it went home while an ask had the screen: home is where the screen goes after
                        sys.paused = None;
                    }
                    sys.view = View::Home;
                    if !sys.asking.active() {
                        sys.go_home();
                    }
                }
            }
            Some(LauncherOp::TimeState) => xous::msg_scalar_unpack!(msg, state, _, _, _, {
                sys.time_verified = state == 2;
                sys.clock = clock_text(time_conn, sys.time_verified);
                sys.redraw();
            }),
            Some(LauncherOp::LinkState) => xous::msg_scalar_unpack!(msg, linked, _, _, _, {
                sys.linked = linked != 0;
                if sys.asking.active() {
                    sys.asking.redraw(&sys.screen, sys.linked);
                } else {
                    sys.redraw();
                }
            }),
            None => log::error!("unknown launcher opcode {}", msg.body.id()),
        }
    }
}
