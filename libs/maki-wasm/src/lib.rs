//! maki's app host core: runs a `.maki` app's WebAssembly with wasmi, giving it maki's
//! functions and nothing else (ARCHITECTURE.md, "The host"). The same code runs on maki and in
//! the simulator; each supplies a `Platform`.
//!
//! An app exports `memory` and `maki_main`, imports only from the `maki` module (the functions
//! `link` defines, API version 1), and has no start function. `maki_main` runs until it
//! returns, or until the app stops: it runs out of fuel between two waits (not responding),
//! traps, calls `abort`, or waits again after being told to exit.
//!
//! Some functions need a permission (`GATED`): an app may import them only if its manifest
//! asks for that permission, and maki refuses one that imports them without.

mod canvas;

use std::collections::BTreeMap;
use std::time::Duration;

pub use canvas::{Canvas, Color, Style, HEIGHT, MAX_BLIT, TOP, WIDTH};
use ed25519_dalek::Signer;
use maki_bundle::{Kind, Manifest, Permission};
use wasmi::{Caller, Config, Engine, Error, Extern, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder};

/// The functions this host offers apps.
pub const API_VERSION: u16 = 1;

/// What maki's functions return for failures they report (rather than stopping the app).
pub const NOT_FOUND: i32 = -1;
pub const FULL: i32 = -2;
pub const INVALID: i32 = -3;
pub const TOO_BIG: i32 = -4;
pub const FAILED: i32 = -5;

/// Longest storage key, in bytes.
pub const MAX_KEY: usize = 48;
/// Largest stored value.
pub const MAX_VALUE: usize = 16 * 1024;
/// An app's own menu items, before App info and Exit.
pub const MAX_MENU_ITEMS: usize = 6;
pub const MAX_MENU_ITEM: usize = 24;
const MAX_TEXT: usize = 1024;
const MAX_LOG: usize = 256;
const MAX_RANDOM: usize = 4096;
const MAX_QR: usize = 1024;
/// A secret's label: the app's name for one of its secrets.
pub const MAX_LABEL: usize = 32;
/// The most an app has signed at once.
pub const MAX_SIGN: usize = 16 * 1024;
/// The most an app types at once.
pub const MAX_TYPE: usize = 1024;
/// The biggest message to or from an app over the link.
pub const MAX_MESSAGE: usize = 4096;
/// An ask's question, detail and answer labels, in bytes.
pub const MAX_QUESTION: usize = 64;
pub const MAX_DETAIL: usize = 128;
pub const MAX_ANSWER_LABEL: usize = 16;
/// How long an ask waits, if the app doesn't say, and the most it may.
pub const ASK_TIMEOUT_S: u32 = 30;
pub const MAX_ASK_TIMEOUT_S: u32 = 120;

/// maki's functions that need a permission, and which.
pub const GATED: &[(&str, Permission)] = &[
    ("ask", Permission::Ask),
    ("key_secret", Permission::Keys),
    ("key_public", Permission::Keys),
    ("key_sign", Permission::Keys),
    ("type_text", Permission::Keyboard),
    ("link_read", Permission::Link),
    ("link_reply", Permission::Link),
    ("camera_scan_qr", Permission::Camera),
    ("motion_read", Permission::Motion),
];

/// What `wait` hands the app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The wait's time ran out.
    Timeout,
    Left,
    Right,
    Centre,
    /// Back in front: draw again.
    Shown,
    /// Something else is in front: stop drawing until Shown.
    Hidden,
    /// The owner left the app: save what's worth saving and return from `maki_main`.
    Exit,
    /// The owner picked this of the app's menu items.
    Menu(u32),
    /// A message from software on the computer (the link permission): read it, and reply,
    /// before waiting again.
    Message,
}

impl Event {
    pub fn code(self) -> i32 {
        match self {
            Event::Timeout => 0,
            Event::Left => 1,
            Event::Right => 2,
            Event::Centre => 3,
            Event::Shown => 4,
            Event::Hidden => 5,
            Event::Exit => 6,
            Event::Message => 7,
            Event::Menu(i) => 0x100 + i.min(0xff) as i32,
        }
    }
}

/// A question for the owner, on maki's own screen (the ask permission).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ask {
    pub question: String,
    /// A line more about it; may be empty.
    pub detail: String,
    /// The answers' labels; empty for "allow" and "deny".
    pub yes: String,
    pub no: String,
    pub timeout_s: u32,
}

/// What the owner said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Yes,
    No,
    /// They didn't answer in time, or maki couldn't ask (it's locked).
    NoAnswer,
}

impl Answer {
    pub fn code(self) -> i32 {
        match self {
            Answer::Yes => 0,
            Answer::No => 1,
            Answer::NoAnswer => 2,
        }
    }
}

/// Where an app runs: maki's app host, or a simulator on a computer.
pub trait Platform {
    /// The next event, waiting at most `timeout` (`None`: as long as it takes).
    fn wait(&mut self, timeout: Option<Duration>) -> Event;
    /// Shows the canvas below maki's bar, if the app is in front.
    fn present(&mut self, canvas: &Canvas);
    /// The app's own menu items, which maki shows before App info and Exit.
    fn set_menu(&mut self, items: &[String]);
    /// Milliseconds from some fixed point.
    fn millis(&self) -> u64;
    /// Unix seconds and whether they're verified, or `None` if maki doesn't know the time.
    fn unix_time(&self) -> Option<(u64, bool)>;
    fn random(&mut self, buf: &mut [u8]);
    fn log(&mut self, line: &str);
    fn storage_get(&mut self, key: &str) -> Option<Vec<u8>>;
    fn storage_set(&mut self, key: &str, value: &[u8]) -> Result<(), ()>;
    /// Whether there was such a key.
    fn storage_delete(&mut self, key: &str) -> bool;
    fn storage_keys(&mut self) -> Vec<String>;
    /// Asks the owner (the ask permission) and waits for the answer. A platform that can't
    /// ask gets no answer.
    fn ask(&mut self, _ask: &Ask) -> Answer { Answer::NoAnswer }
    /// The app's secret for `label` (the keys permission): from the recovery phrase, different
    /// for every app, developer and label, and the same on any maki restored from the phrase.
    /// `None` if there's none to have (maki is locked, or has no phrase yet).
    fn app_secret(&mut self, _label: &str) -> Option<[u8; 32]> { None }
    /// Types `text` (printable ASCII, newlines and tabs) into the computer as a USB keyboard
    /// (the keyboard permission). Whether it did: maki types only for the app in front, and
    /// only when plugged into a computer.
    fn type_text(&mut self, _text: &str) -> bool { false }
    /// The message the last `Event::Message` brought (the link permission), until it's
    /// answered.
    fn message(&mut self) -> Option<Vec<u8>> { None }
    /// Answers that message. Whether there was one to answer.
    fn reply(&mut self, _reply: &[u8]) -> bool { false }
    /// A QR code's text, from maki's own scanner (the camera permission), while the app is in
    /// front: `None` if the owner cancelled (any button), or there's no camera.
    fn scan_qr(&mut self) -> Option<String> { None }
    /// The accelerometer (the motion permission), while the app is in front: x, y and z in
    /// thousandths of a g. `None` if there's none to read.
    fn motion(&mut self) -> Option<[i16; 3]> { None }
}

/// Permissions an app has: those its manifest asks for (each of which maki offers).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Granted(u8);

impl Granted {
    pub const NONE: Granted = Granted(0);

    pub fn of(permissions: &[Permission]) -> Granted {
        Granted(permissions.iter().fold(0, |bits, p| bits | 1 << (*p as u8)))
    }

    pub fn has(self, p: Permission) -> bool { self.0 & 1 << (p as u8) != 0 }
}

/// What an app may use.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Linear memory, bytes.
    pub memory: usize,
    /// Keys and values stored, bytes.
    pub storage: usize,
    /// Work between two waits; running out means the app isn't responding.
    pub fuel: u64,
    /// What it may do beyond what every app may.
    pub granted: Granted,
}

/// The most memory maki gives an app, whatever its manifest asks for.
pub const MAX_MEMORY_KIB: u32 = 1024;
/// The most storage.
pub const MAX_STORAGE_KIB: u32 = 256;
/// Work an app may do between two waits, in wasmi's fuel (about an instruction each): a few
/// seconds on maki. To measure on the badge.
pub const FUEL: u64 = 100_000_000;

impl Limits {
    /// What maki gives an app whose manifest asks for this much, or why it won't.
    pub fn for_app(memory_kib: u32, storage_kib: u32) -> Result<Limits, String> {
        if memory_kib > MAX_MEMORY_KIB {
            return Err(format!("asks for {memory_kib} KiB of memory; maki gives an app {MAX_MEMORY_KIB} KiB at most"));
        }
        if storage_kib > MAX_STORAGE_KIB {
            return Err(format!("asks for {storage_kib} KiB of storage; maki gives an app {MAX_STORAGE_KIB} KiB at most"));
        }
        Ok(Limits { memory: memory_kib as usize * 1024, storage: storage_kib as usize * 1024, fuel: FUEL, granted: Granted::NONE })
    }
}

/// The permissions this host can give, beyond what every app has. The rest come with the
/// functions that use them.
pub const PERMISSIONS: &[Permission] = &Permission::ALL;

/// Whether maki takes this app, and what it gives it if so: a WebAssembly app for a host API
/// this maki has, asking only for permissions it offers and for no more than it gives an app,
/// whose code passes `check`. What's wrong if not, for the owner or developer to read.
pub fn admit(manifest: &Manifest, code: &[u8]) -> Result<Limits, String> { load(manifest, code).map(|l| l.limits) }

/// An app maki has taken (see `admit`), its code checked and compiled once, ready to run each
/// time it's opened.
#[derive(Clone)]
pub struct Loaded {
    engine: Engine,
    module: Module,
    pub limits: Limits,
}

/// What `admit` checks, keeping the compiled code to run.
pub fn load(manifest: &Manifest, code: &[u8]) -> Result<Loaded, String> {
    if manifest.kind != Kind::Wasm {
        return Err("it's a native app, and maki doesn't take those yet".into());
    }
    if manifest.api > API_VERSION {
        return Err(format!("it needs a newer maki (host API {}; this maki has {API_VERSION})", manifest.api));
    }
    if let Some((p, _)) = manifest.permissions.iter().find(|(p, _)| !PERMISSIONS.contains(p)) {
        return Err(format!("it asks to {}, which this maki doesn't offer yet", p.title().to_lowercase()));
    }
    let mut limits = Limits::for_app(manifest.memory_kib, manifest.storage_kib)?;
    let asked: Vec<Permission> = manifest.permissions.iter().map(|(p, _)| *p).collect();
    limits.granted = Granted::of(&asked);
    let loaded = compile(code, limits)?;
    instantiate(&loaded, Box::new(Nothing))?;
    Ok(loaded)
}

impl Loaded {
    /// Runs the app until it stops, and says why it did.
    pub fn run(&self, platform: Box<dyn Platform>) -> Stop {
        match instantiate(self, platform) {
            Ok((store, main)) => finish(store, main),
            Err(e) => Stop::Crashed(e),
        }
    }
}

/// Why an app stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    /// `maki_main` returned.
    Finished,
    /// Told to exit, it asked for another event instead of returning.
    Exited,
    /// It worked too long without waiting for an event.
    NotResponding,
    /// It called `abort`, saying this.
    Aborted(String),
    /// It trapped, or passed a maki function something it can't take: what happened.
    Crashed(String),
}

struct State {
    platform: Box<dyn Platform>,
    canvas: Canvas,
    memory: Option<Memory>,
    limiter: StoreLimits,
    limits: Limits,
    /// Stored keys and the length of each value, read on first use, for the quota.
    sizes: Option<BTreeMap<String, usize>>,
    started: u64,
    exit_sent: bool,
    exited: bool,
    aborted: Option<String>,
}

impl State {
    fn sizes(&mut self) -> &mut BTreeMap<String, usize> {
        if self.sizes.is_none() {
            let mut sizes = BTreeMap::new();
            for key in self.platform.storage_keys() {
                let len = self.platform.storage_get(&key).map(|v| v.len()).unwrap_or(0);
                sizes.insert(key, len);
            }
            self.sizes = Some(sizes);
        }
        self.sizes.as_mut().unwrap()
    }
}

fn engine() -> Engine {
    let mut config = Config::default();
    config
        .consume_fuel(true)
        .allow_start_fn(false)
        .set_max_recursion_depth(512)
        .set_max_stack_height(256 * 1024);
    Engine::new(&config)
}

fn trap(what: impl core::fmt::Display) -> Error { Error::new(format!("{what}")) }

fn memory(caller: &Caller<'_, State>) -> Result<Memory, Error> {
    caller.data().memory.ok_or_else(|| trap("no memory"))
}

/// `len` bytes of the app's memory at `ptr`, at most `max`; a bad pointer stops the app.
fn read(caller: &Caller<'_, State>, ptr: i32, len: i32, max: usize, what: &str) -> Result<Vec<u8>, Error> {
    let (ptr, len) = (ptr as u32 as usize, len as u32 as usize);
    if len > max {
        return Err(trap(format_args!("{what}: {len} bytes is more than {max}")));
    }
    let data = memory(caller)?.data(caller);
    let end = ptr.checked_add(len).ok_or_else(|| trap(format_args!("{what}: bad pointer")))?;
    data.get(ptr..end).map(|s| s.to_vec()).ok_or_else(|| trap(format_args!("{what}: bad pointer")))
}

fn read_str(caller: &Caller<'_, State>, ptr: i32, len: i32, max: usize, what: &str) -> Result<String, Error> {
    Ok(String::from_utf8_lossy(&read(caller, ptr, len, max, what)?).into_owned())
}

fn write(caller: &mut Caller<'_, State>, ptr: i32, bytes: &[u8], what: &str) -> Result<(), Error> {
    let ptr = ptr as u32 as usize;
    let mem = memory(caller)?;
    let data = mem.data_mut(caller);
    let end = ptr.checked_add(bytes.len()).ok_or_else(|| trap(format_args!("{what}: bad pointer")))?;
    data.get_mut(ptr..end)
        .ok_or_else(|| trap(format_args!("{what}: bad pointer")))?
        .copy_from_slice(bytes);
    Ok(())
}

fn color(v: i32) -> Result<Color, Error> { Color::from_i32(v).ok_or_else(|| trap(format_args!("no color {v}"))) }

fn style(v: i32) -> Result<Style, Error> { Style::from_i32(v).ok_or_else(|| trap(format_args!("no text style {v}"))) }

fn key_ok(key: &str) -> bool { !key.is_empty() && key.len() <= MAX_KEY && !key.chars().any(|c| c.is_control()) }

/// A gated function called without its permission. `compile` refuses apps that import one
/// they didn't ask for, so this is a second line.
fn permitted(c: &Caller<'_, State>, p: Permission, what: &str) -> Result<(), Error> {
    if c.data().limits.granted.has(p) {
        Ok(())
    } else {
        Err(trap(format_args!("{what} needs the {} permission", p.name())))
    }
}

/// A secret's label, or `None` if it's not one (control characters).
fn label(c: &Caller<'_, State>, ptr: i32, len: i32, what: &str) -> Result<Option<String>, Error> {
    let label = read_str(c, ptr, len, MAX_LABEL, what)?;
    Ok((!label.chars().any(|ch| ch.is_control())).then_some(label))
}

/// "question\ndetail\nyes\nno", the last three optional, as `ask` takes it.
fn parse_ask(text: &str, timeout_s: i32) -> Option<Ask> {
    let parts: Vec<&str> = text.split('\n').collect();
    if parts.len() > 4 || parts.iter().any(|p| p.chars().any(|ch| ch.is_control())) {
        return None;
    }
    let part = |i: usize| parts.get(i).copied().unwrap_or("").to_string();
    let ask = Ask {
        question: part(0),
        detail: part(1),
        yes: part(2),
        no: part(3),
        timeout_s: if timeout_s <= 0 { ASK_TIMEOUT_S } else { (timeout_s as u32).clamp(5, MAX_ASK_TIMEOUT_S) },
    };
    let fits = !ask.question.trim().is_empty()
        && ask.question.len() <= MAX_QUESTION
        && ask.detail.len() <= MAX_DETAIL
        && ask.yes.len() <= MAX_ANSWER_LABEL
        && ask.no.len() <= MAX_ANSWER_LABEL;
    fits.then_some(ask)
}

/// The app's Ed25519 key for `label`: its secret for that label is the key's seed.
fn signing_key(platform: &mut dyn Platform, label: &str) -> Option<ed25519_dalek::SigningKey> {
    let mut secret = platform.app_secret(label)?;
    let key = ed25519_dalek::SigningKey::from_bytes(&secret);
    zeroize::Zeroize::zeroize(&mut secret);
    Some(key)
}

/// maki's functions, as the `maki` import module.
fn link(linker: &mut Linker<State>) -> Result<(), Error> {
    const M: &str = "maki";
    linker.func_wrap(M, "screen_width", || WIDTH as i32)?;
    linker.func_wrap(M, "screen_height", || HEIGHT as i32)?;
    linker.func_wrap(M, "clear", |mut c: Caller<'_, State>, col: i32| -> Result<(), Error> {
        let col = color(col)?;
        c.data_mut().canvas.clear(col);
        Ok(())
    })?;
    linker.func_wrap(M, "pixel", |mut c: Caller<'_, State>, x: i32, y: i32, col: i32| -> Result<(), Error> {
        let col = color(col)?;
        c.data_mut().canvas.pixel(x, y, col);
        Ok(())
    })?;
    linker.func_wrap(
        M,
        "line",
        |mut c: Caller<'_, State>, x0: i32, y0: i32, x1: i32, y1: i32, col: i32| -> Result<(), Error> {
            let col = color(col)?;
            c.data_mut().canvas.line(x0, y0, x1, y1, col);
            Ok(())
        },
    )?;
    linker.func_wrap(
        M,
        "rect",
        |mut c: Caller<'_, State>, x: i32, y: i32, w: i32, h: i32, col: i32, filled: i32| -> Result<(), Error> {
            let col = color(col)?;
            c.data_mut().canvas.rect(x, y, w, h, col, filled != 0);
            Ok(())
        },
    )?;
    linker.func_wrap(
        M,
        "text",
        |mut c: Caller<'_, State>, x: i32, y: i32, ptr: i32, len: i32, sty: i32, col: i32| -> Result<i32, Error> {
            let (sty, col) = (style(sty)?, color(col)?);
            let s = read_str(&c, ptr, len, MAX_TEXT, "text")?;
            Ok(c.data_mut().canvas.text(x, y, &s, sty, col))
        },
    )?;
    linker.func_wrap(M, "text_width", |c: Caller<'_, State>, ptr: i32, len: i32, sty: i32| -> Result<i32, Error> {
        let sty = style(sty)?;
        let s = read_str(&c, ptr, len, MAX_TEXT, "text_width")?;
        Ok(Canvas::text_width(&s, sty))
    })?;
    linker.func_wrap(
        M,
        "blit",
        |mut c: Caller<'_, State>, x: i32, y: i32, w: i32, h: i32, ptr: i32, col: i32| -> Result<(), Error> {
            let col = color(col)?;
            if w <= 0 || h <= 0 {
                return Ok(());
            }
            if w > MAX_BLIT || h > MAX_BLIT {
                return Err(trap(format_args!("blit: {w}x{h} is bigger than {MAX_BLIT}x{MAX_BLIT}")));
            }
            let rows = read(&c, ptr, (w + 7) / 8 * h, usize::MAX, "blit")?;
            c.data_mut().canvas.blit(x, y, w, h, &rows, col);
            Ok(())
        },
    )?;
    linker.func_wrap(
        M,
        "qr",
        |mut c: Caller<'_, State>, x: i32, y: i32, ptr: i32, len: i32, size: i32| -> Result<i32, Error> {
            let data = read(&c, ptr, len, MAX_QR, "qr")?;
            Ok(c.data_mut().canvas.qr(x, y, &data, size).unwrap_or(TOO_BIG))
        },
    )?;
    linker.func_wrap(M, "present", |mut c: Caller<'_, State>| {
        let State { platform, canvas, .. } = c.data_mut();
        platform.present(canvas);
    })?;
    linker.func_wrap(M, "wait", |mut c: Caller<'_, State>, timeout_ms: i32| -> Result<i32, Error> {
        let st = c.data_mut();
        if st.exit_sent {
            st.exited = true;
            return Err(trap("waited after being told to exit"));
        }
        let timeout = (timeout_ms >= 0).then(|| Duration::from_millis(timeout_ms as u64));
        let event = st.platform.wait(timeout);
        st.exit_sent = event == Event::Exit;
        let fuel = st.limits.fuel;
        c.set_fuel(fuel)?;
        Ok(event.code())
    })?;
    linker.func_wrap(M, "menu", |mut c: Caller<'_, State>, ptr: i32, len: i32| -> Result<i32, Error> {
        let s = read_str(&c, ptr, len, (MAX_MENU_ITEM + 1) * MAX_MENU_ITEMS, "menu")?;
        let items: Vec<String> = if s.is_empty() { vec![] } else { s.split('\n').map(String::from).collect() };
        if items.len() > MAX_MENU_ITEMS
            || items.iter().any(|i| i.trim().is_empty() || i.len() > MAX_MENU_ITEM || i.chars().any(|c| c.is_control()))
        {
            return Ok(INVALID);
        }
        c.data_mut().platform.set_menu(&items);
        Ok(0)
    })?;
    linker.func_wrap(
        M,
        "storage_get",
        |mut c: Caller<'_, State>, kptr: i32, klen: i32, vptr: i32, vcap: i32| -> Result<i32, Error> {
            let key = read_str(&c, kptr, klen, MAX_KEY, "storage_get")?;
            if !key_ok(&key) {
                return Ok(INVALID);
            }
            let Some(value) = c.data_mut().platform.storage_get(&key) else { return Ok(NOT_FOUND) };
            let n = value.len().min(vcap.max(0) as usize);
            write(&mut c, vptr, &value[..n], "storage_get")?;
            Ok(value.len() as i32)
        },
    )?;
    linker.func_wrap(
        M,
        "storage_set",
        |mut c: Caller<'_, State>, kptr: i32, klen: i32, vptr: i32, vlen: i32| -> Result<i32, Error> {
            let key = read_str(&c, kptr, klen, MAX_KEY, "storage_set")?;
            if !key_ok(&key) {
                return Ok(INVALID);
            }
            if vlen as u32 as usize > MAX_VALUE {
                return Ok(TOO_BIG);
            }
            let value = read(&c, vptr, vlen, MAX_VALUE, "storage_set")?;
            let st = c.data_mut();
            let quota = st.limits.storage;
            let sizes = st.sizes();
            let used: usize = sizes.iter().map(|(k, v)| k.len() + v).sum();
            let old = sizes.get(&key).map(|v| key.len() + v).unwrap_or(0);
            if used - old + key.len() + value.len() > quota {
                return Ok(FULL);
            }
            if st.platform.storage_set(&key, &value).is_err() {
                return Ok(FAILED);
            }
            st.sizes().insert(key, value.len());
            Ok(0)
        },
    )?;
    linker.func_wrap(M, "storage_delete", |mut c: Caller<'_, State>, kptr: i32, klen: i32| -> Result<i32, Error> {
        let key = read_str(&c, kptr, klen, MAX_KEY, "storage_delete")?;
        if !key_ok(&key) {
            return Ok(INVALID);
        }
        let st = c.data_mut();
        st.sizes();
        if !st.platform.storage_delete(&key) {
            return Ok(NOT_FOUND);
        }
        st.sizes().remove(&key);
        Ok(0)
    })?;
    linker.func_wrap(
        M,
        "storage_key",
        |mut c: Caller<'_, State>, index: i32, ptr: i32, cap: i32| -> Result<i32, Error> {
            let Some(key) = c.data_mut().sizes().keys().nth(index.max(0) as usize).cloned() else {
                return Ok(NOT_FOUND);
            };
            if index < 0 {
                return Ok(NOT_FOUND);
            }
            let n = key.len().min(cap.max(0) as usize);
            write(&mut c, ptr, &key.as_bytes()[..n], "storage_key")?;
            Ok(key.len() as i32)
        },
    )?;
    linker.func_wrap(M, "millis", |c: Caller<'_, State>| -> i64 {
        let st = c.data();
        st.platform.millis().saturating_sub(st.started) as i64
    })?;
    linker.func_wrap(M, "unix_time", |c: Caller<'_, State>| -> i64 {
        c.data().platform.unix_time().map(|(t, _)| t as i64).unwrap_or(-1)
    })?;
    linker.func_wrap(M, "time_verified", |c: Caller<'_, State>| -> i32 {
        matches!(c.data().platform.unix_time(), Some((_, true))) as i32
    })?;
    linker.func_wrap(M, "random", |mut c: Caller<'_, State>, ptr: i32, len: i32| -> Result<(), Error> {
        let len = len as u32 as usize;
        if len > MAX_RANDOM {
            return Err(trap(format_args!("random: {len} bytes is more than {MAX_RANDOM}")));
        }
        let mut buf = vec![0u8; len];
        c.data_mut().platform.random(&mut buf);
        write(&mut c, ptr, &buf, "random")
    })?;
    linker.func_wrap(M, "log", |mut c: Caller<'_, State>, ptr: i32, len: i32| -> Result<(), Error> {
        let line = read_str(&c, ptr, len.min(MAX_LOG as i32), MAX_LOG, "log")?;
        c.data_mut().platform.log(&line);
        Ok(())
    })?;
    linker.func_wrap(M, "abort", |mut c: Caller<'_, State>, ptr: i32, len: i32| -> Result<(), Error> {
        let message = read_str(&c, ptr, len.min(MAX_LOG as i32), MAX_LOG, "abort")?;
        c.data_mut().aborted = Some(message);
        Err(trap("aborted"))
    })?;
    // the ask permission: "question\ndetail\nyes\nno" (the last three optional), and how long
    // to wait (0 or less: 30 s; at most 120). 0 yes, 1 no, 2 no answer.
    linker.func_wrap(M, "ask", |mut c: Caller<'_, State>, ptr: i32, len: i32, timeout_s: i32| -> Result<i32, Error> {
        permitted(&c, Permission::Ask, "ask")?;
        let most = MAX_QUESTION + MAX_DETAIL + 2 * MAX_ANSWER_LABEL + 3;
        let text = read_str(&c, ptr, len, most, "ask")?;
        let Some(ask) = parse_ask(&text, timeout_s) else { return Ok(INVALID) };
        let answer = c.data_mut().platform.ask(&ask);
        // the owner's time isn't the app's work
        let fuel = c.data().limits.fuel;
        c.set_fuel(fuel)?;
        Ok(answer.code())
    })?;
    // the keys permission: the app's 32-byte secret for a label, and the Ed25519 key made from
    // it, which maki holds and signs with, so the app needn't carry the key itself
    linker.func_wrap(
        M,
        "key_secret",
        |mut c: Caller<'_, State>, lptr: i32, llen: i32, out: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Keys, "key_secret")?;
            let Some(label) = label(&c, lptr, llen, "key_secret")? else { return Ok(INVALID) };
            let Some(mut secret) = c.data_mut().platform.app_secret(&label) else { return Ok(FAILED) };
            let written = write(&mut c, out, &secret, "key_secret");
            zeroize::Zeroize::zeroize(&mut secret);
            written.map(|_| 0)
        },
    )?;
    linker.func_wrap(
        M,
        "key_public",
        |mut c: Caller<'_, State>, lptr: i32, llen: i32, out: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Keys, "key_public")?;
            let Some(label) = label(&c, lptr, llen, "key_public")? else { return Ok(INVALID) };
            let Some(key) = signing_key(c.data_mut().platform.as_mut(), &label) else { return Ok(FAILED) };
            write(&mut c, out, &key.verifying_key().to_bytes(), "key_public").map(|_| 0)
        },
    )?;
    linker.func_wrap(
        M,
        "key_sign",
        |mut c: Caller<'_, State>, lptr: i32, llen: i32, mptr: i32, mlen: i32, out: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Keys, "key_sign")?;
            let Some(label) = label(&c, lptr, llen, "key_sign")? else { return Ok(INVALID) };
            if mlen as u32 as usize > MAX_SIGN {
                return Ok(TOO_BIG);
            }
            let message = read(&c, mptr, mlen, MAX_SIGN, "key_sign")?;
            let Some(key) = signing_key(c.data_mut().platform.as_mut(), &label) else { return Ok(FAILED) };
            write(&mut c, out, &key.sign(&message).to_bytes(), "key_sign").map(|_| 0)
        },
    )?;
    // the keyboard permission: printable ASCII, newlines and tabs
    linker.func_wrap(M, "type_text", |mut c: Caller<'_, State>, ptr: i32, len: i32| -> Result<i32, Error> {
        permitted(&c, Permission::Keyboard, "type_text")?;
        if len as u32 as usize > MAX_TYPE {
            return Ok(TOO_BIG);
        }
        let text = read_str(&c, ptr, len, MAX_TYPE, "type_text")?;
        if !text.chars().all(|ch| ch == '\n' || ch == '\t' || (' '..='~').contains(&ch)) {
            return Ok(INVALID);
        }
        Ok(if c.data_mut().platform.type_text(&text) { 0 } else { FAILED })
    })?;
    // the link permission: the message the last Message event brought, copied into the app's
    // buffer as far as it fits (its whole length returned), and the app's answer to it
    linker.func_wrap(M, "link_read", |mut c: Caller<'_, State>, ptr: i32, cap: i32| -> Result<i32, Error> {
        permitted(&c, Permission::Link, "link_read")?;
        let Some(message) = c.data_mut().platform.message() else { return Ok(NOT_FOUND) };
        let n = message.len().min(cap.max(0) as usize);
        write(&mut c, ptr, &message[..n], "link_read")?;
        Ok(message.len() as i32)
    })?;
    linker.func_wrap(M, "link_reply", |mut c: Caller<'_, State>, ptr: i32, len: i32| -> Result<i32, Error> {
        permitted(&c, Permission::Link, "link_reply")?;
        if len as u32 as usize > MAX_MESSAGE {
            return Ok(TOO_BIG);
        }
        let reply = read(&c, ptr, len, MAX_MESSAGE, "link_reply")?;
        Ok(if c.data_mut().platform.reply(&reply) { 0 } else { NOT_FOUND })
    })?;
    // the camera permission: a QR code's text from maki's scanner, copied into the app's
    // buffer as far as it fits (its whole length returned); NOT_FOUND if there was none
    linker.func_wrap(M, "camera_scan_qr", |mut c: Caller<'_, State>, ptr: i32, cap: i32| -> Result<i32, Error> {
        permitted(&c, Permission::Camera, "camera_scan_qr")?;
        let text = c.data_mut().platform.scan_qr();
        // the owner's time isn't the app's work
        let fuel = c.data().limits.fuel;
        c.set_fuel(fuel)?;
        let Some(text) = text else { return Ok(NOT_FOUND) };
        let n = text.len().min(cap.max(0) as usize);
        write(&mut c, ptr, &text.as_bytes()[..n], "camera_scan_qr")?;
        Ok(text.len() as i32)
    })?;
    // the motion permission: x, y and z (milli-g), three little-endian i16s
    linker.func_wrap(M, "motion_read", |mut c: Caller<'_, State>, ptr: i32| -> Result<i32, Error> {
        permitted(&c, Permission::Motion, "motion_read")?;
        let Some(xyz) = c.data_mut().platform.motion() else { return Ok(FAILED) };
        let mut bytes = [0u8; 6];
        for (i, v) in xyz.iter().enumerate() {
            bytes[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
        }
        write(&mut c, ptr, &bytes, "motion_read").map(|_| 0)
    })?;
    Ok(())
}

struct Nothing;

impl Platform for Nothing {
    fn wait(&mut self, _: Option<Duration>) -> Event { Event::Exit }
    fn present(&mut self, _: &Canvas) {}
    fn set_menu(&mut self, _: &[String]) {}
    fn millis(&self) -> u64 { 0 }
    fn unix_time(&self) -> Option<(u64, bool)> { None }
    fn random(&mut self, _: &mut [u8]) {}
    fn log(&mut self, _: &str) {}
    fn storage_get(&mut self, _: &str) -> Option<Vec<u8>> { None }
    fn storage_set(&mut self, _: &str, _: &[u8]) -> Result<(), ()> { Err(()) }
    fn storage_delete(&mut self, _: &str) -> bool { false }
    fn storage_keys(&mut self) -> Vec<String> { vec![] }
}

/// With the `trace` feature, a clock (milliseconds) to time each step of loading an app with.
#[cfg(feature = "trace")]
pub static CLOCK: std::sync::OnceLock<fn() -> u64> = std::sync::OnceLock::new();

fn step(what: &str, since: &mut u64) {
    #[cfg(feature = "trace")]
    if let Some(clock) = CLOCK.get() {
        let now = clock();
        log::info!("wasm {what}: {} ms", now - *since);
        *since = now;
    }
    #[cfg(not(feature = "trace"))]
    let _ = (what, since);
}

fn now() -> u64 {
    #[cfg(feature = "trace")]
    if let Some(clock) = CLOCK.get() {
        return clock();
    }
    0
}

/// Validates and compiles `code`, which may import only from `maki`.
fn compile(code: &[u8], limits: Limits) -> Result<Loaded, String> {
    let mut t = now();
    let engine = engine();
    step("engine", &mut t);
    let module = Module::new(&engine, code).map_err(|e| format!("not WebAssembly maki can run: {e}"))?;
    step("module", &mut t);
    for import in module.imports() {
        if import.module() != "maki" {
            return Err(format!("uses {}.{}, which maki doesn't have", import.module(), import.name()));
        }
        if let Some((name, p)) = GATED.iter().find(|(name, _)| *name == import.name()) {
            if !limits.granted.has(*p) {
                return Err(format!(
                    "uses maki.{name}, which needs the {} permission, and its manifest doesn't ask for it",
                    p.name()
                ));
            }
        }
    }
    Ok(Loaded { engine, module, limits })
}

/// A fresh instance of a compiled app, linked to maki's functions on `platform`.
fn instantiate(loaded: &Loaded, platform: Box<dyn Platform>) -> Result<(Store<State>, wasmi::TypedFunc<(), ()>), String> {
    let Loaded { engine, module, limits } = loaded;
    let limits = *limits;
    let mut t = now();
    let started = platform.millis();
    let state = State {
        platform,
        canvas: Canvas::default(),
        memory: None,
        limiter: StoreLimitsBuilder::new().memory_size(limits.memory).instances(1).memories(1).tables(4).build(),
        limits,
        sizes: None,
        started,
        exit_sent: false,
        exited: false,
        aborted: None,
    };
    let mut store = Store::new(engine, state);
    store.limiter(|st| &mut st.limiter);
    store.set_fuel(limits.fuel).map_err(|e| e.to_string())?;
    step("store", &mut t);
    let mut linker = Linker::new(engine);
    link(&mut linker).map_err(|e| e.to_string())?;
    step("link", &mut t);
    let instance = linker.instantiate_and_start(&mut store, module).map_err(|e| {
        // the limiter refuses memory beyond the limit
        format!("can't start: {e}")
    })?;
    step("instantiate", &mut t);
    let Some(Extern::Memory(memory)) = instance.get_export(&store, "memory") else {
        return Err("exports no memory".into());
    };
    store.data_mut().memory = Some(memory);
    let main = instance
        .get_typed_func::<(), ()>(&store, "maki_main")
        .map_err(|_| String::from("exports no maki_main taking and returning nothing"))?;
    Ok((store, main))
}

/// Whether maki can run `code` within `limits`: WebAssembly it can validate, that imports only
/// maki's functions with the right types, has no start function, starts within its memory and
/// exports `memory` and `maki_main`. What's wrong if not, for the owner or developer to read.
pub fn check(code: &[u8], limits: Limits) -> Result<(), String> {
    instantiate(&compile(code, limits)?, Box::new(Nothing)).map(|_| ())
}

/// Checks, compiles and runs `code` until it stops, and says why it did. (maki itself loads an
/// app once with `load` and runs the `Loaded` each time it's opened.)
pub fn run(code: &[u8], platform: Box<dyn Platform>, limits: Limits) -> Stop {
    match compile(code, limits) {
        Ok(loaded) => loaded.run(platform),
        Err(e) => Stop::Crashed(e),
    }
}

fn finish(mut store: Store<State>, main: wasmi::TypedFunc<(), ()>) -> Stop {
    let result = main.call(&mut store, ());
    let st = store.data();
    match result {
        Ok(()) => Stop::Finished,
        Err(_) if st.exited => Stop::Exited,
        Err(_) if st.aborted.is_some() => Stop::Aborted(st.aborted.clone().unwrap()),
        Err(e) if e.as_trap_code() == Some(wasmi::TrapCode::OutOfFuel) => Stop::NotResponding,
        Err(e) => Stop::Crashed(e.to_string()),
    }
}
