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
mod session;

use std::time::Duration;

pub use canvas::{Canvas, Color, HEIGHT, MAX_BLIT, Style, TOP, WIDTH};
use maki_bundle::{Kind, Manifest, Permission};
pub use session::{REFUSED, Session};
use wasmi::{
    Caller, Config, Engine, Error, Extern, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder,
};

/// The functions this host offers apps.
pub const API_VERSION: u16 = 8;

/// Host API 8: the jog dial on maki's side, up and down (`Event::Up`, `Event::Down`). Only an app
/// that says this API or later gets them: an older one would read them as a timeout.
pub const API_JOG: u16 = 8;

/// Functions that came after host API 1, and with which: an app calling one says that API or later.
pub const SINCE: &[(&str, u16)] = &[
    ("key_schnorr_public", 2),
    ("key_schnorr_sign", 2),
    ("key_x25519_public", 2),
    ("key_x25519_agree", 2),
    ("wallet_fingerprint", 3),
    ("wallet_public", 3),
    ("wallet_review", 3),
    ("wallet_sign", 3),
    ("wallet_subaddress", 4),
    ("wallet_show_backup", 4),
    ("wallet_monero_view_key", 5),
    ("wallet_monero_key_image", 5),
    ("wallet_monero_sign", 5),
    ("wallet_sign_ed25519", 6),
    ("ask_review", 7),
];

/// What maki's functions return for failures they report (rather than stopping the app).
pub const NOT_FOUND: i32 = -1;
pub const FULL: i32 = -2;
pub const INVALID: i32 = -3;
pub const TOO_BIG: i32 = -4;
pub const FAILED: i32 = -5;
/// Host API 3: maki is locked, or has no recovery phrase yet (a wallet's keys wait for both).
pub const LOCKED: i32 = -7;

/// Longest storage key, in bytes.
pub const MAX_KEY: usize = 48;
/// Largest stored value.
pub const MAX_VALUE: usize = 16 * 1024;
/// An app's own menu items, before App info and Exit.
pub const MAX_MENU_ITEMS: usize = 6;
pub const MAX_MENU_ITEM: usize = 24;
pub const MAX_TEXT: usize = 1024;
pub const MAX_LOG: usize = 256;
pub const MAX_RANDOM: usize = 4096;
pub const MAX_QR: usize = 1024;
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
/// The most `menu`'s text can be: every item, and a newline after each.
pub const MENU_TEXT: usize = (MAX_MENU_ITEM + 1) * MAX_MENU_ITEMS;
/// The most `ask`'s text can be: "question\ndetail\nyes\nno".
pub const ASK_TEXT: usize = MAX_QUESTION + MAX_DETAIL + 2 * MAX_ANSWER_LABEL + 3;
/// How long an ask waits, if the app doesn't say, and the most it may.
pub const ASK_TIMEOUT_S: u32 = 30;
pub const MAX_ASK_TIMEOUT_S: u32 = 120;

/// The wallet permission (host API 3). What `wallet_public` gives, and `wallet_sign` makes (as
/// maki-keys' `WALLET_*`): a public key with its chain code and parent's fingerprint (69 bytes),
/// uncompressed (65), a taproot output key (32); an ECDSA signature and its recovery ID (65),
/// BIP340 (64), BIP340 tweaked for a taproot key spend (64).
pub const WALLET_PUBLIC: u8 = maki_hd::op::PUBLIC;
pub const WALLET_UNCOMPRESSED: u8 = maki_hd::op::UNCOMPRESSED;
pub const WALLET_TAPROOT: u8 = maki_hd::op::TAPROOT;
pub const WALLET_SIGN_ECDSA: u8 = maki_hd::op::SIGN_ECDSA;
pub const WALLET_SIGN_SCHNORR: u8 = maki_hd::op::SIGN_SCHNORR;
pub const WALLET_SIGN_TAPROOT: u8 = maki_hd::op::SIGN_TAPROOT;
/// Host API 4: Monero's public spend and view keys (64 bytes), from `wallet_public`; on Monero's
/// coin type alone.
pub const WALLET_MONERO: u8 = maki_hd::op::MONERO_PUBLIC;
/// Host API 5: a Monero output, as `wallet_monero_key_image` takes it: its transaction's key, its
/// index there, the subaddress it was paid to (account and index) and its key.
pub const MONERO_OUTPUT: usize = 32 + 8 + 4 + 4 + 32;
/// The biggest transaction `wallet_monero_sign` takes to sign (`maki_xmr::request`): 16 inputs.
pub const MAX_MONERO_REQUEST: usize = 64 * 1024;
/// Host API 6: an Ed25519 public key (32 bytes), from `wallet_public`, by SLIP-10 (every step of
/// the path hardened), as Solana's wallets derive them; `wallet_sign_ed25519` signs with it, over
/// a whole message of up to `MAX_SIGN` bytes (Ed25519 hashes what it signs itself).
pub const WALLET_ED25519: u8 = maki_hd::op::ED25519_PUBLIC;
/// A review's text, pages, and each page's parts, in bytes. A page's text runs on over as many
/// screens as it takes ("Message (2)"): a message to sign can be 4 KiB, and a transaction 64
/// payments, their change and the fee.
pub const MAX_REVIEW: usize = 16 * 1024;
pub const MAX_PAGES: usize = 128;
pub const MAX_HEADING: usize = 32;
pub const MAX_PAGE_VALUE: usize = 128;
pub const MAX_PAGE_TEXT: usize = 4096;
/// How long a review waits, if the app doesn't say, and the most it may: time to read every
/// page, carefully.
pub const REVIEW_TIMEOUT_S: u32 = 120;
pub const MAX_REVIEW_TIMEOUT_S: u32 = 300;
/// The most signatures one yes allows, and how long it allows them for.
pub const MAX_SIGNATURES: u32 = 256;
pub const ALLOWANCE_MS: u64 = 120_000;

/// maki's functions that need a permission, and which.
pub const GATED: &[(&str, Permission)] = &[
    ("ask", Permission::Ask),
    ("ask_review", Permission::Ask),
    ("key_secret", Permission::Keys),
    ("key_public", Permission::Keys),
    ("key_sign", Permission::Keys),
    ("key_schnorr_public", Permission::Keys),
    ("key_schnorr_sign", Permission::Keys),
    ("key_x25519_public", Permission::Keys),
    ("key_x25519_agree", Permission::Keys),
    ("type_text", Permission::Keyboard),
    ("link_read", Permission::Link),
    ("link_reply", Permission::Link),
    ("camera_scan_qr", Permission::Camera),
    ("motion_read", Permission::Motion),
    ("wallet_fingerprint", Permission::Wallet),
    ("wallet_public", Permission::Wallet),
    ("wallet_review", Permission::Wallet),
    ("wallet_sign", Permission::Wallet),
    ("wallet_subaddress", Permission::Wallet),
    ("wallet_show_backup", Permission::Wallet),
    ("wallet_monero_view_key", Permission::Wallet),
    ("wallet_monero_key_image", Permission::Wallet),
    ("wallet_monero_sign", Permission::Wallet),
    ("wallet_sign_ed25519", Permission::Wallet),
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
    /// The jog dial on maki's side, up or down (host API 8, `API_JOG`).
    Up,
    Down,
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
            Event::Up => 8,
            Event::Down => 9,
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

/// What an app shows the owner on maki's own review screen, a page at a time, before its question:
/// a wallet app's before it signs (`wallet_review`), or any app's with the ask permission
/// (`ask_review`, host API 7). The pages are the app's words, headed with its name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Review {
    pub question: String,
    /// A line more about it; may be empty.
    pub detail: String,
    /// The answers' labels; empty for "sign" and "reject".
    pub yes: String,
    pub no: String,
    pub pages: Vec<Page>,
    pub timeout_s: u32,
}

/// A review's page, as maki's review screen lays it out: a few words at the top, the thing to
/// check in bold, then fixed-width type across as many lines as it takes (an address), then small
/// words wrapped to fit (what something means). Any may be empty but the heading.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    pub heading: String,
    pub value: String,
    pub mono: String,
    pub prose: String,
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
    // The only way this fails is no room, which the app is told as a status: `()` says it all.
    #[allow(clippy::result_unit_err)]
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
    /// A wallet app's key work (the wallet permission), done by maki, which keeps the seed: the
    /// master key's fingerprint (`op` 0, no path), a public key at `path` (`WALLET_PUBLIC`..), or
    /// a signature over `digest` (`WALLET_SIGN_*`). The session has held the path to the app's
    /// own, and a signature to the owner's yes. `LOCKED` while maki is.
    fn wallet(&mut self, _op: u8, _path: &[u32], _digest: &[u8]) -> Result<Vec<u8>, i32> { Err(FAILED) }
    /// Puts a review on maki's own screen (the wallet permission), headed with the app's name,
    /// and waits for the answer. A platform that can't show one gets no answer.
    fn review(&mut self, _review: &Review) -> Answer { Answer::NoAnswer }
    /// Shows the owner the backup words of the account at `path` (a Monero wallet's 25), on
    /// maki's own screens, once they've said they want them (host API 4): the words never reach
    /// the app, which hears only whether they were shown. The session has held the path to the
    /// app's own. `LOCKED` while maki is; `NOT_FOUND` for an account without words of its own.
    fn show_backup(&mut self, _path: &[u32]) -> Result<Answer, i32> { Err(FAILED) }
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
            return Err(format!(
                "asks for {memory_kib} KiB of memory; maki gives an app {MAX_MEMORY_KIB} KiB at most"
            ));
        }
        if storage_kib > MAX_STORAGE_KIB {
            return Err(format!(
                "asks for {storage_kib} KiB of storage; maki gives an app {MAX_STORAGE_KIB} KiB at most"
            ));
        }
        Ok(Limits {
            memory: memory_kib as usize * 1024,
            storage: storage_kib as usize * 1024,
            fuel: FUEL,
            granted: Granted::NONE,
        })
    }
}

/// The permissions this host can give, beyond what every app has. The rest come with the
/// functions that use them.
pub const PERMISSIONS: &[Permission] = &Permission::ALL;

/// Whether maki takes this app, and what it gives it if so: asking only for permissions it
/// offers and for no more than it gives an app, and either a WebAssembly app for a host API this
/// maki has whose code passes `check`, or a native app built for this firmware's app service
/// whose ELF the loader maps, its code, data and stack within its memory. What's wrong if not,
/// for the owner or developer to read.
pub fn admit(manifest: &Manifest, code: &[u8]) -> Result<Limits, String> {
    match manifest.kind {
        Kind::Wasm => load(manifest, code).map(|l| l.limits),
        Kind::Native => admit_native(manifest, code),
    }
}

fn admit_native(manifest: &Manifest, elf: &[u8]) -> Result<Limits, String> {
    use maki_native::{load::STACK_KIB, service::FIRMWARE};
    if manifest.firmware != FIRMWARE {
        return Err(format!(
            "it's built for other firmware ({}; this maki runs {FIRMWARE})",
            if manifest.firmware.is_empty() { "unnamed" } else { &manifest.firmware }
        ));
    }
    let limits = limits(manifest)?;
    let program = maki_native::check(elf, manifest.memory_kib).map_err(|e| e.to_string())?;
    let needs = (program.pages() + STACK_KIB / 4) * 4;
    if needs > manifest.memory_kib {
        return Err(format!(
            "its code, data and {STACK_KIB} KiB of stack take {needs} KiB, more than its memory"
        ));
    }
    Ok(limits)
}

/// What an app gets, given what its manifest asks for: permissions this maki offers, memory
/// and storage within what it gives.
fn limits(manifest: &Manifest) -> Result<Limits, String> {
    if let Some((p, _)) = manifest.permissions.iter().find(|(p, _)| !PERMISSIONS.contains(p)) {
        return Err(format!("it asks to {}, which this maki doesn't offer yet", p.title().to_lowercase()));
    }
    let mut limits = Limits::for_app(manifest.memory_kib, manifest.storage_kib)?;
    let asked: Vec<Permission> = manifest.permissions.iter().map(|(p, _)| *p).collect();
    limits.granted = Granted::of(&asked);
    Ok(limits)
}

/// An app maki has taken (see `admit`), its code checked and compiled once, ready to run each
/// time it's opened.
#[derive(Clone)]
pub struct Loaded {
    engine: Engine,
    module: Module,
    pub limits: Limits,
    /// The wallet permission's paths, from the manifest.
    pub wallet: Option<maki_bundle::Wallet>,
}

/// What `admit` checks, keeping the compiled code to run.
pub fn load(manifest: &Manifest, code: &[u8]) -> Result<Loaded, String> {
    if manifest.kind != Kind::Wasm {
        return Err("it's a native app: maki runs those in a process of their own".into());
    }
    if manifest.api > API_VERSION {
        return Err(format!(
            "it needs a newer maki (host API {}; this maki has {API_VERSION})",
            manifest.api
        ));
    }
    let limits = limits(manifest)?;
    let loaded = compile(code, limits)?;
    // what it calls: nothing newer than the API its manifest says, so an older maki can say why
    for import in loaded.module.imports() {
        if let Some((name, since)) = SINCE.iter().find(|(n, _)| *n == import.name()) {
            if *since > manifest.api {
                return Err(format!(
                    "it calls {name}, which came with host API {since}, and its manifest says {}",
                    manifest.api
                ));
            }
        }
    }
    instantiate(&loaded, Box::new(Nothing))?;
    Ok(Loaded { wallet: manifest.wallet.clone(), ..loaded })
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
    /// maki couldn't run it (a native app's process couldn't be started, say): why.
    Failed(String),
}

struct State {
    session: Session,
    memory: Option<Memory>,
    limiter: StoreLimits,
    exited: bool,
    aborted: Option<String>,
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
    data.get_mut(ptr..end).ok_or_else(|| trap(format_args!("{what}: bad pointer")))?.copy_from_slice(bytes);
    Ok(())
}

fn color(v: i32) -> Result<Color, Error> {
    Color::from_i32(v).ok_or_else(|| trap(format_args!("no color {v}")))
}

fn style(v: i32) -> Result<Style, Error> {
    Style::from_i32(v).ok_or_else(|| trap(format_args!("no text style {v}")))
}

/// A derivation path from the app's memory: `len` little-endian u32s, at most `maki_hd::MAX_DEPTH`
/// of them (None if more, or fewer than none).
fn read_path(caller: &Caller<'_, State>, ptr: i32, len: i32, what: &str) -> Result<Option<Vec<u32>>, Error> {
    let Ok(n) = usize::try_from(len) else { return Ok(None) };
    if n > maki_hd::MAX_DEPTH {
        return Ok(None);
    }
    let bytes = read(caller, ptr, (n * 4) as i32, maki_hd::MAX_DEPTH * 4, what)?;
    Ok(Some(bytes.chunks_exact(4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).collect()))
}

/// `bytes` into the app's buffer of `cap` bytes at `out`: its length, or `TOO_BIG` if it doesn't
/// fit.
fn written(
    caller: &mut Caller<'_, State>,
    out: i32,
    cap: i32,
    bytes: &[u8],
    what: &str,
) -> Result<i32, Error> {
    if bytes.len() > cap.max(0) as usize {
        return Ok(TOO_BIG);
    }
    write(caller, out, bytes, what)?;
    Ok(bytes.len() as i32)
}

/// A gated function called without its permission. `compile` refuses apps that import one
/// they didn't ask for, so this is a second line.
fn permitted(c: &Caller<'_, State>, p: Permission, what: &str) -> Result<(), Error> {
    if c.data().session.permitted(p) {
        Ok(())
    } else {
        Err(trap(format_args!("{what} needs the {} permission", p.name())))
    }
}

/// maki's functions, as the `maki` import module: each reads its arguments from the app's
/// memory, calls the `Session`, and writes back what it returns. A function the app hasn't
/// the permission for traps (maki refuses an app that imports one without).
fn link(linker: &mut Linker<State>) -> Result<(), Error> {
    const M: &str = "maki";
    linker.func_wrap(M, "screen_width", || WIDTH as i32)?;
    linker.func_wrap(M, "screen_height", || HEIGHT as i32)?;
    linker.func_wrap(M, "clear", |mut c: Caller<'_, State>, col: i32| -> Result<(), Error> {
        let col = color(col)?;
        c.data_mut().session.canvas.clear(col);
        Ok(())
    })?;
    linker.func_wrap(
        M,
        "pixel",
        |mut c: Caller<'_, State>, x: i32, y: i32, col: i32| -> Result<(), Error> {
            let col = color(col)?;
            c.data_mut().session.canvas.pixel(x, y, col);
            Ok(())
        },
    )?;
    linker.func_wrap(
        M,
        "line",
        |mut c: Caller<'_, State>, x0: i32, y0: i32, x1: i32, y1: i32, col: i32| -> Result<(), Error> {
            let col = color(col)?;
            c.data_mut().session.canvas.line(x0, y0, x1, y1, col);
            Ok(())
        },
    )?;
    linker.func_wrap(
        M,
        "rect",
        |mut c: Caller<'_, State>,
         x: i32,
         y: i32,
         w: i32,
         h: i32,
         col: i32,
         filled: i32|
         -> Result<(), Error> {
            let col = color(col)?;
            c.data_mut().session.canvas.rect(x, y, w, h, col, filled != 0);
            Ok(())
        },
    )?;
    linker.func_wrap(
        M,
        "text",
        |mut c: Caller<'_, State>,
         x: i32,
         y: i32,
         ptr: i32,
         len: i32,
         sty: i32,
         col: i32|
         -> Result<i32, Error> {
            let (sty, col) = (style(sty)?, color(col)?);
            let s = read_str(&c, ptr, len, MAX_TEXT, "text")?;
            Ok(c.data_mut().session.canvas.text(x, y, &s, sty, col))
        },
    )?;
    linker.func_wrap(
        M,
        "text_width",
        |c: Caller<'_, State>, ptr: i32, len: i32, sty: i32| -> Result<i32, Error> {
            let sty = style(sty)?;
            let s = read_str(&c, ptr, len, MAX_TEXT, "text_width")?;
            Ok(Canvas::text_width(&s, sty))
        },
    )?;
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
            c.data_mut().session.canvas.blit(x, y, w, h, &rows, col);
            Ok(())
        },
    )?;
    linker.func_wrap(
        M,
        "qr",
        |mut c: Caller<'_, State>, x: i32, y: i32, ptr: i32, len: i32, size: i32| -> Result<i32, Error> {
            let data = read(&c, ptr, len, MAX_QR, "qr")?;
            Ok(c.data_mut().session.canvas.qr(x, y, &data, size).unwrap_or(TOO_BIG))
        },
    )?;
    linker.func_wrap(M, "present", |mut c: Caller<'_, State>| c.data_mut().session.present())?;
    linker.func_wrap(M, "wait", |mut c: Caller<'_, State>, timeout_ms: i32| -> Result<i32, Error> {
        let st = c.data_mut();
        let Some(event) = st.session.wait(timeout_ms) else {
            st.exited = true;
            return Err(trap("waited after being told to exit"));
        };
        let fuel = st.session.limits.fuel;
        c.set_fuel(fuel)?;
        Ok(event)
    })?;
    linker.func_wrap(M, "menu", |mut c: Caller<'_, State>, ptr: i32, len: i32| -> Result<i32, Error> {
        let s = read_str(&c, ptr, len, MENU_TEXT, "menu")?;
        Ok(c.data_mut().session.menu(&s))
    })?;
    linker.func_wrap(
        M,
        "storage_get",
        |mut c: Caller<'_, State>, kptr: i32, klen: i32, vptr: i32, vcap: i32| -> Result<i32, Error> {
            let key = read_str(&c, kptr, klen, MAX_KEY, "storage_get")?;
            let value = match c.data_mut().session.storage_get(&key) {
                Ok(v) => v,
                Err(code) => return Ok(code),
            };
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
            if !session::key_ok(&key) {
                return Ok(INVALID);
            }
            if vlen as u32 as usize > MAX_VALUE {
                return Ok(TOO_BIG);
            }
            let value = read(&c, vptr, vlen, MAX_VALUE, "storage_set")?;
            Ok(c.data_mut().session.storage_set(&key, &value))
        },
    )?;
    linker.func_wrap(
        M,
        "storage_delete",
        |mut c: Caller<'_, State>, kptr: i32, klen: i32| -> Result<i32, Error> {
            let key = read_str(&c, kptr, klen, MAX_KEY, "storage_delete")?;
            Ok(c.data_mut().session.storage_delete(&key))
        },
    )?;
    linker.func_wrap(
        M,
        "storage_key",
        |mut c: Caller<'_, State>, index: i32, ptr: i32, cap: i32| -> Result<i32, Error> {
            let key = match c.data_mut().session.storage_key(index) {
                Ok(k) => k,
                Err(code) => return Ok(code),
            };
            let n = key.len().min(cap.max(0) as usize);
            write(&mut c, ptr, &key.as_bytes()[..n], "storage_key")?;
            Ok(key.len() as i32)
        },
    )?;
    linker.func_wrap(M, "millis", |c: Caller<'_, State>| -> i64 { c.data().session.millis() })?;
    linker.func_wrap(M, "unix_time", |c: Caller<'_, State>| -> i64 { c.data().session.unix_time() })?;
    linker
        .func_wrap(M, "time_verified", |c: Caller<'_, State>| -> i32 { c.data().session.time_verified() })?;
    linker.func_wrap(M, "random", |mut c: Caller<'_, State>, ptr: i32, len: i32| -> Result<(), Error> {
        let len = len as u32 as usize;
        let Ok(buf) = c.data_mut().session.random(len) else {
            return Err(trap(format_args!("random: {len} bytes is more than {MAX_RANDOM}")));
        };
        write(&mut c, ptr, &buf, "random")
    })?;
    linker.func_wrap(M, "log", |mut c: Caller<'_, State>, ptr: i32, len: i32| -> Result<(), Error> {
        let line = read_str(&c, ptr, len.min(MAX_LOG as i32), MAX_LOG, "log")?;
        c.data_mut().session.log(&line);
        Ok(())
    })?;
    linker.func_wrap(M, "abort", |mut c: Caller<'_, State>, ptr: i32, len: i32| -> Result<(), Error> {
        let message = read_str(&c, ptr, len.min(MAX_LOG as i32), MAX_LOG, "abort")?;
        c.data_mut().aborted = Some(message);
        Err(trap("aborted"))
    })?;
    linker.func_wrap(
        M,
        "ask",
        |mut c: Caller<'_, State>, ptr: i32, len: i32, timeout_s: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Ask, "ask")?;
            let text = read_str(&c, ptr, len, ASK_TEXT, "ask")?;
            let answer = c.data_mut().session.ask(&text, timeout_s);
            // the owner's time isn't the app's work
            let fuel = c.data().session.limits.fuel;
            c.set_fuel(fuel)?;
            Ok(answer)
        },
    )?;
    linker.func_wrap(
        M,
        "ask_review",
        |mut c: Caller<'_, State>, tptr: i32, tlen: i32, timeout_s: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Ask, "ask_review")?;
            if tlen as u32 as usize > MAX_REVIEW {
                return Ok(TOO_BIG);
            }
            let text = read_str(&c, tptr, tlen, MAX_REVIEW, "ask_review")?;
            let answer = c.data_mut().session.ask_review(&text, timeout_s);
            let fuel = c.data().session.limits.fuel;
            c.set_fuel(fuel)?;
            Ok(answer)
        },
    )?;
    linker.func_wrap(
        M,
        "key_secret",
        |mut c: Caller<'_, State>, lptr: i32, llen: i32, out: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Keys, "key_secret")?;
            let label = read_str(&c, lptr, llen, MAX_LABEL, "key_secret")?;
            let mut secret = match c.data_mut().session.key_secret(&label) {
                Ok(s) => s,
                Err(code) => return Ok(code),
            };
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
            let label = read_str(&c, lptr, llen, MAX_LABEL, "key_public")?;
            match c.data_mut().session.key_public(&label) {
                Ok(key) => write(&mut c, out, &key, "key_public").map(|_| 0),
                Err(code) => Ok(code),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "key_sign",
        |mut c: Caller<'_, State>,
         lptr: i32,
         llen: i32,
         mptr: i32,
         mlen: i32,
         out: i32|
         -> Result<i32, Error> {
            permitted(&c, Permission::Keys, "key_sign")?;
            let label = read_str(&c, lptr, llen, MAX_LABEL, "key_sign")?;
            if mlen as u32 as usize > MAX_SIGN {
                return Ok(TOO_BIG);
            }
            let message = read(&c, mptr, mlen, MAX_SIGN, "key_sign")?;
            match c.data_mut().session.key_sign(&label, &message) {
                Ok(sig) => write(&mut c, out, &sig, "key_sign").map(|_| 0),
                Err(code) => Ok(code),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "key_schnorr_public",
        |mut c: Caller<'_, State>, lptr: i32, llen: i32, out: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Keys, "key_schnorr_public")?;
            let label = read_str(&c, lptr, llen, MAX_LABEL, "key_schnorr_public")?;
            match c.data_mut().session.key_schnorr_public(&label) {
                Ok(key) => write(&mut c, out, &key, "key_schnorr_public").map(|_| 0),
                Err(code) => Ok(code),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "key_schnorr_sign",
        |mut c: Caller<'_, State>, lptr: i32, llen: i32, mptr: i32, out: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Keys, "key_schnorr_sign")?;
            let label = read_str(&c, lptr, llen, MAX_LABEL, "key_schnorr_sign")?;
            let message = read(&c, mptr, 32, 32, "key_schnorr_sign")?;
            match c.data_mut().session.key_schnorr_sign(&label, &message) {
                Ok(sig) => write(&mut c, out, &sig, "key_schnorr_sign").map(|_| 0),
                Err(code) => Ok(code),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "key_x25519_public",
        |mut c: Caller<'_, State>, lptr: i32, llen: i32, out: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Keys, "key_x25519_public")?;
            let label = read_str(&c, lptr, llen, MAX_LABEL, "key_x25519_public")?;
            match c.data_mut().session.key_x25519_public(&label) {
                Ok(key) => write(&mut c, out, &key, "key_x25519_public").map(|_| 0),
                Err(code) => Ok(code),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "key_x25519_agree",
        |mut c: Caller<'_, State>, lptr: i32, llen: i32, pptr: i32, out: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Keys, "key_x25519_agree")?;
            let label = read_str(&c, lptr, llen, MAX_LABEL, "key_x25519_agree")?;
            let peer = read(&c, pptr, 32, 32, "key_x25519_agree")?;
            let mut shared = match c.data_mut().session.key_x25519_agree(&label, &peer) {
                Ok(s) => s,
                Err(code) => return Ok(code),
            };
            let written = write(&mut c, out, &shared, "key_x25519_agree");
            zeroize::Zeroize::zeroize(&mut shared);
            written.map(|_| 0)
        },
    )?;
    linker.func_wrap(
        M,
        "wallet_fingerprint",
        |mut c: Caller<'_, State>, out: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Wallet, "wallet_fingerprint")?;
            match c.data_mut().session.wallet_fingerprint() {
                Ok(fp) => write(&mut c, out, &fp, "wallet_fingerprint").map(|_| 0),
                Err(code) => Ok(code),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "wallet_public",
        |mut c: Caller<'_, State>,
         pptr: i32,
         plen: i32,
         form: i32,
         out: i32,
         cap: i32|
         -> Result<i32, Error> {
            permitted(&c, Permission::Wallet, "wallet_public")?;
            let Some(path) = read_path(&c, pptr, plen, "wallet_public")? else { return Ok(INVALID) };
            let form = u8::try_from(form).unwrap_or(0);
            match c.data_mut().session.wallet_public(&path, form) {
                Ok(bytes) => written(&mut c, out, cap, &bytes, "wallet_public"),
                Err(code) => Ok(code),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "wallet_review",
        |mut c: Caller<'_, State>,
         tptr: i32,
         tlen: i32,
         signatures: i32,
         timeout_s: i32|
         -> Result<i32, Error> {
            permitted(&c, Permission::Wallet, "wallet_review")?;
            if tlen as u32 as usize > MAX_REVIEW {
                return Ok(TOO_BIG);
            }
            let text = read_str(&c, tptr, tlen, MAX_REVIEW, "wallet_review")?;
            let Ok(signatures) = u32::try_from(signatures) else { return Ok(INVALID) };
            Ok(c.data_mut().session.wallet_review(&text, signatures, timeout_s))
        },
    )?;
    linker.func_wrap(
        M,
        "wallet_sign",
        |mut c: Caller<'_, State>,
         pptr: i32,
         plen: i32,
         dptr: i32,
         scheme: i32,
         out: i32,
         cap: i32|
         -> Result<i32, Error> {
            permitted(&c, Permission::Wallet, "wallet_sign")?;
            let Some(path) = read_path(&c, pptr, plen, "wallet_sign")? else { return Ok(INVALID) };
            let digest = read(&c, dptr, 32, 32, "wallet_sign")?;
            let scheme = u8::try_from(scheme).unwrap_or(0);
            match c.data_mut().session.wallet_sign(&path, &digest, scheme) {
                Ok(sig) => written(&mut c, out, cap, &sig, "wallet_sign"),
                Err(code) => Ok(code),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "wallet_subaddress",
        |mut c: Caller<'_, State>,
         pptr: i32,
         plen: i32,
         major: i32,
         minor: i32,
         out: i32|
         -> Result<i32, Error> {
            permitted(&c, Permission::Wallet, "wallet_subaddress")?;
            let Some(path) = read_path(&c, pptr, plen, "wallet_subaddress")? else { return Ok(INVALID) };
            // the indices are u32s, as Monero has them
            match c.data_mut().session.wallet_subaddress(&path, major as u32, minor as u32) {
                Ok(keys) => write(&mut c, out, &keys, "wallet_subaddress").map(|_| 0),
                Err(code) => Ok(code),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "wallet_show_backup",
        |mut c: Caller<'_, State>, pptr: i32, plen: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Wallet, "wallet_show_backup")?;
            let Some(path) = read_path(&c, pptr, plen, "wallet_show_backup")? else { return Ok(INVALID) };
            Ok(c.data_mut().session.wallet_show_backup(&path))
        },
    )?;
    linker.func_wrap(
        M,
        "wallet_monero_view_key",
        |mut c: Caller<'_, State>, pptr: i32, plen: i32, out: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Wallet, "wallet_monero_view_key")?;
            let Some(path) = read_path(&c, pptr, plen, "wallet_monero_view_key")? else { return Ok(INVALID) };
            match c.data_mut().session.wallet_monero_view_key(&path) {
                Ok(mut key) => {
                    let written = write(&mut c, out, &key, "wallet_monero_view_key");
                    zeroize::Zeroize::zeroize(&mut key);
                    written.map(|_| 0)
                }
                Err(code) => Ok(code),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "wallet_monero_key_image",
        |mut c: Caller<'_, State>, pptr: i32, plen: i32, optr: i32, out: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Wallet, "wallet_monero_key_image")?;
            let Some(path) = read_path(&c, pptr, plen, "wallet_monero_key_image")? else {
                return Ok(INVALID);
            };
            let output = read(&c, optr, MONERO_OUTPUT as i32, MONERO_OUTPUT, "wallet_monero_key_image")?;
            match c.data_mut().session.wallet_monero_key_image(&path, &output) {
                Ok(image) => write(&mut c, out, &image, "wallet_monero_key_image").map(|_| 0),
                Err(code) => Ok(code),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "wallet_monero_sign",
        |mut c: Caller<'_, State>,
         pptr: i32,
         plen: i32,
         rptr: i32,
         rlen: i32,
         out: i32,
         cap: i32|
         -> Result<i32, Error> {
            permitted(&c, Permission::Wallet, "wallet_monero_sign")?;
            let Some(path) = read_path(&c, pptr, plen, "wallet_monero_sign")? else { return Ok(INVALID) };
            if rlen as u32 as usize > MAX_MONERO_REQUEST {
                return Ok(TOO_BIG);
            }
            let request = read(&c, rptr, rlen, MAX_MONERO_REQUEST, "wallet_monero_sign")?;
            let signed = c.data_mut().session.wallet_monero_sign(&path, &request);
            // maki's time, not the app's
            let fuel = c.data().session.limits.fuel;
            c.set_fuel(fuel)?;
            match signed {
                Ok(bytes) => written(&mut c, out, cap, &bytes, "wallet_monero_sign"),
                Err(code) => Ok(code),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "wallet_sign_ed25519",
        |mut c: Caller<'_, State>,
         pptr: i32,
         plen: i32,
         mptr: i32,
         mlen: i32,
         out: i32|
         -> Result<i32, Error> {
            permitted(&c, Permission::Wallet, "wallet_sign_ed25519")?;
            let Some(path) = read_path(&c, pptr, plen, "wallet_sign_ed25519")? else { return Ok(INVALID) };
            if mlen as u32 as usize > MAX_SIGN {
                return Ok(TOO_BIG);
            }
            let message = read(&c, mptr, mlen, MAX_SIGN, "wallet_sign_ed25519")?;
            match c.data_mut().session.wallet_sign_ed25519(&path, &message) {
                Ok(sig) => write(&mut c, out, &sig, "wallet_sign_ed25519").map(|_| 0),
                Err(code) => Ok(code),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "type_text",
        |mut c: Caller<'_, State>, ptr: i32, len: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Keyboard, "type_text")?;
            if len as u32 as usize > MAX_TYPE {
                return Ok(TOO_BIG);
            }
            let text = read_str(&c, ptr, len, MAX_TYPE, "type_text")?;
            Ok(c.data_mut().session.type_text(&text))
        },
    )?;
    linker.func_wrap(
        M,
        "link_read",
        |mut c: Caller<'_, State>, ptr: i32, cap: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Link, "link_read")?;
            let message = match c.data_mut().session.link_read() {
                Ok(m) => m,
                Err(code) => return Ok(code),
            };
            let n = message.len().min(cap.max(0) as usize);
            write(&mut c, ptr, &message[..n], "link_read")?;
            Ok(message.len() as i32)
        },
    )?;
    linker.func_wrap(
        M,
        "link_reply",
        |mut c: Caller<'_, State>, ptr: i32, len: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Link, "link_reply")?;
            if len as u32 as usize > MAX_MESSAGE {
                return Ok(TOO_BIG);
            }
            let reply = read(&c, ptr, len, MAX_MESSAGE, "link_reply")?;
            Ok(c.data_mut().session.link_reply(&reply))
        },
    )?;
    linker.func_wrap(
        M,
        "camera_scan_qr",
        |mut c: Caller<'_, State>, ptr: i32, cap: i32| -> Result<i32, Error> {
            permitted(&c, Permission::Camera, "camera_scan_qr")?;
            let text = c.data_mut().session.scan_qr();
            // the owner's time isn't the app's work
            let fuel = c.data().session.limits.fuel;
            c.set_fuel(fuel)?;
            let text = match text {
                Ok(t) => t,
                Err(code) => return Ok(code),
            };
            let n = text.len().min(cap.max(0) as usize);
            write(&mut c, ptr, &text.as_bytes()[..n], "camera_scan_qr")?;
            Ok(text.len() as i32)
        },
    )?;
    linker.func_wrap(M, "motion_read", |mut c: Caller<'_, State>, ptr: i32| -> Result<i32, Error> {
        permitted(&c, Permission::Motion, "motion_read")?;
        let xyz = match c.data_mut().session.motion() {
            Ok(v) => v,
            Err(code) => return Ok(code),
        };
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
    Ok(Loaded { engine, module, limits, wallet: None })
}

/// A fresh instance of a compiled app, linked to maki's functions on `platform`.
fn instantiate(
    loaded: &Loaded,
    platform: Box<dyn Platform>,
) -> Result<(Store<State>, wasmi::TypedFunc<(), ()>), String> {
    let Loaded { engine, module, limits, wallet } = loaded;
    let limits = *limits;
    let mut t = now();
    let mut session = Session::new(platform, limits);
    session.wallet = wallet.clone();
    let state = State {
        session,
        memory: None,
        limiter: StoreLimitsBuilder::new()
            .memory_size(limits.memory)
            .instances(1)
            .memories(1)
            .tables(4)
            .build(),
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
