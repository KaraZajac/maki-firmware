//! A host stand-in for maki: the real protocol logic behind a TCP socket.
//!
//!     cargo run -p maki-proto --features fake --example fake_maki -- \
//!         [ADDR] [--deny | --ask] [--totp SITE=BASE32]... [--clock-verified] [--phrase "WORDS"] \
//!         [--store-root FILE]
//!
//! ADDR defaults to 127.0.0.1:7878. Logins and TOTP secrets live in memory; SAVE_LOGIN adds to them.
//! The Bitcoin wallet comes from `--phrase`, or else the BIP39 test phrase ("abandon" eleven times,
//! then "about"), which everyone knows: never send real coins to either.
//! Approvals are automatic unless `--deny` (refuse everything) or `--ask` (ask on this terminal).
//! Codes need a verified clock, as on the badge: sync through Roughtime first, or start with
//! `--clock-verified` to take this computer's clock as verified (tests, offline work).
//! Everything maki-link does on the device happens here too, except the USB hop, the Xous clock and
//! maki's own screen. State survives reconnects, like a badge that stays plugged in. Installed apps
//! answer APP_MESSAGE as on maki: each runs (with maki's own host code) without a screen, its
//! asks answered as above, its keys from the phrase, until it's had nothing to do for a while.
//! Native apps install as on maki, but don't run here: they're machine code for maki's processor.
//! The maki store's records are checked as maki does, starting from the root the firmware
//! carries, or the one in `--store-root` (a test store's).

use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use maki_btc::psbt::Psbt;
use maki_btc::{display, wallet, Account, Network};
use maki_proto::device::{
    reply, AppEntry, AppSpace, Approval, Apps, Ask, Backup, Bitcoin, Device, Ethereum, Handled, Platform, StoreState, TimeState,
    ACCOUNT_TAPROOT, BACKUP_PIECE, PSBT_PIECE, TX_PIECE,
};
use maki_proto::frame::{self, Deframer};
use maki_proto::site;

struct Host {
    start: Instant,
    clock: Option<(u64, Instant)>,
}

fn host_utc_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64 }

impl Platform for Host {
    fn fill_random(&mut self, buf: &mut [u8]) {
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).expect("no /dev/urandom");
    }

    fn uptime_ms(&self) -> u64 { self.start.elapsed().as_millis() as u64 }

    fn utc_ms(&self) -> Option<u64> { self.clock.map(|(t, at)| t + at.elapsed().as_millis() as u64) }

    fn set_time(&mut self, utc_ms: u64, tz_offset_s: i32) {
        let drift = utc_ms as i64 - host_utc_ms() as i64;
        println!("  clock set: {utc_ms} ms UTC, tz {tz_offset_s:+} s ({drift:+} ms from this computer)");
        self.clock = Some((utc_ms, Instant::now()));
    }

    fn time_state_changed(&mut self, state: TimeState) { println!("  time is now {state:?}"); }
}

#[derive(Clone, Copy, PartialEq)]
enum Policy {
    Approve,
    Deny,
    Ask,
}

#[derive(Default)]
struct Store {
    logins: Vec<(String, String, String)>,
    totp: Vec<(String, Vec<u8>)>,
    /// the backup being read out, and one coming in
    sealed: Vec<u8>,
    incoming: Vec<u8>,
    /// installed apps by ID
    apps: std::collections::BTreeMap<String, Installed>,
    /// a bundle coming in
    app_incoming: Vec<u8>,
    /// each app's storage, by ID
    app_data: std::collections::BTreeMap<String, std::collections::BTreeMap<String, Vec<u8>>>,
    /// the maki store's root maki trusts (set at start), its revocation list, and a record
    /// coming in
    store_root: Option<maki_store::Root>,
    revocations: Option<maki_store::SignedRevocations>,
    store_incoming: Vec<u8>,
}

/// maki's room for apps, as its app host has it (`maki-app-host-api`).
const MAX_APPS: usize = 32;
const APP_SPACE: u32 = 2 * 1024 * 1024;

/// What an app takes of maki's room for apps: its bundle, and the storage it asks for.
fn takes(bundle: &[u8]) -> u32 {
    let storage = maki_bundle::read(bundle).map(|b| b.manifest.storage_kib).unwrap_or(0);
    bundle.len() as u32 + storage * 1024
}

#[derive(Clone)]
struct Installed {
    bundle: Vec<u8>,
    /// whether its data goes in the backup
    backup: bool,
    /// its stamp checked out
    from_store: bool,
}

impl Store {
    fn root(&self) -> &maki_store::Root { self.store_root.as_ref().expect("the store root is set at start") }

    fn space(&self) -> AppSpace {
        AppSpace {
            apps: self.apps.len() as u32,
            max_apps: MAX_APPS as u32,
            space: APP_SPACE,
            taken: self.apps.values().map(|a| takes(&a.bundle)).sum(),
        }
    }

    fn store_state(&self) -> StoreState {
        let list = self.revocations.as_ref().map(|r| &r.list);
        StoreState {
            root: self.root().version,
            revocations: list.map(|l| l.version).unwrap_or(0),
            revocations_expires: list.map(|l| l.expires).unwrap_or(0),
        }
    }
}

/// The store root the firmware carries: the development store's until the real one opens.
const FIRST_ROOT: &[u8] = include_bytes!("../../maki-store/dev-store/roots/1.bin");

/// Where an app's answer to a message goes.
type ReplyTo = std::sync::mpsc::Sender<(Approval, Vec<u8>)>;
/// Where a running app's next message goes, with where its answer goes.
type Inbox = std::sync::mpsc::Sender<(Vec<u8>, ReplyTo)>;

/// How long an app started for a message runs with nothing to do, as on maki.
const APP_IDLE: Duration = Duration::from_secs(30);

/// What a running app has instead of maki's app host: messages from the computer, asks answered
/// by the fake's policy, keys from its phrase, and storage in memory. No screen.
struct FakeApp {
    id: String,
    name: String,
    developer: [u8; 32],
    seed: [u8; 64],
    policy: Policy,
    inbox: std::sync::mpsc::Receiver<(Vec<u8>, ReplyTo)>,
    current: Option<(Vec<u8>, ReplyTo)>,
    store: Arc<Mutex<Store>>,
    start: Instant,
}

impl maki_wasm::Platform for FakeApp {
    fn wait(&mut self, timeout: Option<Duration>) -> maki_wasm::Event {
        if let Some((_, reply_to)) = self.current.take() {
            println!("  {} went on without answering", self.name);
            reply_to.send((Approval::Denied, Vec::new())).ok();
        }
        let wait = timeout.map_or(APP_IDLE, |t| t.min(APP_IDLE));
        match self.inbox.recv_timeout(wait) {
            Ok(m) => {
                self.current = Some(m);
                maki_wasm::Event::Message
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) if timeout.is_some_and(|t| t < APP_IDLE) => {
                maki_wasm::Event::Timeout
            }
            // nothing to do for a while: it ends
            Err(_) => maki_wasm::Event::Exit,
        }
    }
    fn present(&mut self, _: &maki_wasm::Canvas) {}
    fn set_menu(&mut self, _: &[String]) {}
    fn millis(&self) -> u64 { self.start.elapsed().as_millis() as u64 }
    fn unix_time(&self) -> Option<(u64, bool)> { Some((host_utc_ms() / 1000, false)) }
    fn random(&mut self, buf: &mut [u8]) {
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).expect("no /dev/urandom");
    }
    fn log(&mut self, line: &str) { println!("  {}: {line}", self.name) }
    fn storage_get(&mut self, key: &str) -> Option<Vec<u8>> {
        self.store.lock().unwrap().app_data.get(&self.id).and_then(|d| d.get(key).cloned())
    }
    fn storage_set(&mut self, key: &str, value: &[u8]) -> Result<(), ()> {
        self.store.lock().unwrap().app_data.entry(self.id.clone()).or_default().insert(key.into(), value.into());
        Ok(())
    }
    fn storage_delete(&mut self, key: &str) -> bool {
        self.store.lock().unwrap().app_data.get_mut(&self.id).is_some_and(|d| d.remove(key).is_some())
    }
    fn storage_keys(&mut self) -> Vec<String> {
        self.store.lock().unwrap().app_data.get(&self.id).map(|d| d.keys().cloned().collect()).unwrap_or_default()
    }
    fn ask(&mut self, ask: &maki_wasm::Ask) -> maki_wasm::Answer {
        match approve(self.policy, &format!("{}: {} {}", self.name, ask.question, ask.detail)) {
            Approval::Approved => maki_wasm::Answer::Yes,
            _ => maki_wasm::Answer::No,
        }
    }
    fn app_secret(&mut self, label: &str) -> Option<[u8; 32]> { maki_seed::app_secret(&self.seed, &self.id, &self.developer, label) }
    fn type_text(&mut self, text: &str) -> bool {
        println!("  {} would type {text:?}", self.name);
        true
    }
    fn message(&mut self) -> Option<Vec<u8>> { self.current.as_ref().map(|(m, _)| m.clone()) }
    fn reply(&mut self, reply: &[u8]) -> bool {
        match self.current.take() {
            Some((_, reply_to)) => {
                reply_to.send((Approval::Approved, reply.to_vec())).ok();
                true
            }
            None => false,
        }
    }
}

/// A message for an installed app, answered as maki's host would: started if it isn't running.
fn app_message(
    app: &str,
    message: Vec<u8>,
    store: &Arc<Mutex<Store>>,
    running: &Arc<Mutex<std::collections::BTreeMap<String, Inbox>>>,
    seed: [u8; 64],
    policy: Policy,
) -> (Approval, Vec<u8>) {
    let Some(Installed { bundle, .. }) = store.lock().unwrap().apps.get(app).cloned() else {
        return (Approval::NoMatch, Vec::new());
    };
    let b = maki_bundle::read(&bundle).expect("installed bundles read");
    if !b.manifest.permissions.iter().any(|(p, _)| *p == maki_bundle::Permission::Link) {
        return (Approval::Refused, Vec::new());
    }
    // machine code for maki's processor: installed here as on maki, but not run
    if b.manifest.kind == maki_bundle::Kind::Native {
        println!("  {app} is a native app: the fake maki doesn't run those");
        return (Approval::Unavailable, Vec::new());
    }
    // twice: an app that ended just as the message came gets started again
    for _ in 0..2 {
        let inbox = {
            let mut r = running.lock().unwrap();
            r.entry(app.to_string()).or_insert_with(|| start_app(bundle.clone(), store.clone(), seed, policy)).clone()
        };
        let (reply_to, answer) = std::sync::mpsc::channel();
        if inbox.send((message.clone(), reply_to)).is_err() {
            running.lock().unwrap().remove(app);
            continue;
        }
        match answer.recv_timeout(Duration::from_secs(90)) {
            Ok(answer) => return answer,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return (Approval::TimedOut, Vec::new()),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                running.lock().unwrap().remove(app);
            }
        }
    }
    (Approval::Unavailable, Vec::new())
}

/// Runs an installed app without a screen, on its own thread, until it's had nothing to do for
/// a while.
fn start_app(bundle: Vec<u8>, store: Arc<Mutex<Store>>, seed: [u8; 64], policy: Policy) -> Inbox {
    let (inbox, messages) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let b = maki_bundle::read(&bundle).expect("installed bundles read");
        let limits = maki_wasm::admit(&b.manifest, b.code).expect("installed apps are admitted");
        println!("  {} started for a message", b.manifest.name);
        let app = FakeApp {
            id: b.manifest.id.clone(),
            name: b.manifest.name.clone(),
            developer: b.developer,
            seed,
            policy,
            inbox: messages,
            current: None,
            store,
            start: Instant::now(),
        };
        let stop = maki_wasm::run(b.code, Box::new(app), limits);
        println!("  {} stopped: {stop:?}", b.manifest.name);
    });
    inbox
}

/// The fake's wallet, and the PSBT coming in and the one it last signed; the same for Ethereum.
struct Wallet {
    accounts: [Account; 2],
    /// taproot's (BIP86), bitcoin's and the test networks'
    taproot: [Account; 2],
    incoming: Vec<u8>,
    signed: Vec<u8>,
    seed: [u8; 64],
    eth_incoming: Vec<u8>,
    eth_signed: Vec<u8>,
    typed_incoming: Vec<u8>,
}

const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

impl Wallet {
    fn new(phrase: &str) -> Wallet {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        maki_seed::to_entropy(&words).expect("--phrase isn't a BIP39 phrase");
        let seed = maki_seed::seed(&words, "");
        let account = |n| Account::from_seed(&seed, n).expect("keys");
        let taproot = |n| Account::new(&seed, n, maki_btc::Kind::Taproot).expect("keys");
        Wallet {
            accounts: [account(Network::Bitcoin), account(Network::Testnet)],
            taproot: [taproot(Network::Bitcoin), taproot(Network::Testnet)],
            incoming: Vec::new(),
            signed: Vec::new(),
            seed,
            eth_incoming: Vec::new(),
            eth_signed: Vec::new(),
            typed_incoming: Vec::new(),
        }
    }
}

/// Everything maki-keys does with a finished PSBT, minus the screen: check it, show it, sign it.
fn finish_signing(psbt: Vec<u8>, accounts: &[Account], wallet: &Mutex<Wallet>, policy: Policy) -> (u8, Vec<u8>) {
    let mut psbt = match Psbt::parse(&psbt) {
        Ok(p) => p,
        Err(e) => return reply::btc_sign(true, Approval::Refused, 0, &format!("not a PSBT maki can read: {e}")),
    };
    let review = match wallet::review(&psbt, accounts) {
        Ok(r) => r,
        Err(e) => {
            println!("  refused: {e}");
            return reply::btc_sign(true, Approval::Refused, 0, &e.to_string());
        }
    };
    for p in review.pages() {
        println!("  maki shows: {:12} {:18} {}", p.heading, p.value, p.mono);
    }
    let a = approve(policy, &format!("sign the transaction? {}", review.summary()));
    if a != Approval::Approved {
        return reply::btc_sign(true, a, 0, "");
    }
    // no randomness for taproot's signatures: the fake's come out the same every time, for tests
    if let Err(e) = wallet::sign(&mut psbt, accounts, &[0; 32]) {
        return reply::btc_sign(true, Approval::Refused, 0, &e.to_string());
    }
    let signed = psbt.serialize();
    let total = signed.len() as u32;
    wallet.lock().unwrap().signed = signed;
    reply::btc_sign(true, Approval::Approved, total, "")
}

/// Everything maki-keys does with a finished Ethereum transaction, minus the screen.
fn finish_eth(tx: Vec<u8>, site: &str, account: &maki_eth::Account, wallet: &Mutex<Wallet>, policy: Policy) -> (u8, Vec<u8>) {
    let tx = match maki_eth::Tx::parse(&tx) {
        Ok(t) => t,
        Err(e) => return reply::eth_sign(true, Approval::Refused, 0, &e.to_string()),
    };
    let (pages, summary) = match maki_eth::display::review(&tx) {
        Ok(r) => r,
        Err(e) => return reply::eth_sign(true, Approval::Refused, 0, &e.to_string()),
    };
    for p in pages {
        println!("  maki shows: {:14} {:22} {}", p.heading, p.value, p.mono.replace('\n', " "));
    }
    let a = approve(policy, &format!("{site}: sign and send, {summary}?"));
    if a != Approval::Approved {
        return reply::eth_sign(true, a, 0, "");
    }
    match tx.sign(account) {
        Ok(signed) => {
            let total = signed.len() as u32;
            wallet.lock().unwrap().eth_signed = signed;
            reply::eth_sign(true, Approval::Approved, total, "")
        }
        Err(e) => reply::eth_sign(true, Approval::Refused, 0, &e.to_string()),
    }
}

/// Everything maki-keys does with finished typed data (EIP-712), minus the screen: read it,
/// show it, sign it.
fn finish_typed(bytes: Vec<u8>, site: &str, account: &maki_eth::Account, policy: Policy) -> (u8, Vec<u8>) {
    let refused = |why: String| reply::eth_typed(true, Approval::Refused, &[], &why);
    let Ok(text) = String::from_utf8(bytes) else { return refused("not typed data maki can read: not UTF-8".into()) };
    let typed = match maki_eth::TypedData::parse(&text) {
        Ok(t) => t,
        Err(e) => return refused(e.to_string()),
    };
    let (pages, title, line) = match maki_eth::display::typed_review(&typed) {
        Ok(r) => r,
        Err(e) => return refused(e.to_string()),
    };
    for p in pages {
        println!("  maki shows: {:14} {:22} {}", p.heading, p.value, p.mono.replace('\n', " "));
    }
    let a = approve(policy, &format!("{site}: {} ({line})", title.to_lowercase()));
    if a != Approval::Approved {
        return reply::eth_typed(true, a, &[], "");
    }
    match account.sign_typed(&typed) {
        Ok(signature) => reply::eth_typed(true, Approval::Approved, &signature, ""),
        Err(e) => refused(e.to_string()),
    }
}

/// The fake's backup: its store as lines of text, not encrypted (the badge's is; the desktop
/// can't tell the difference, which is the point).
const FAKE_MAGIC: &[u8] = b"FAKEBAK1\n";

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn fake_backup(st: &Store) -> Vec<u8> {
    let mut out = FAKE_MAGIC.to_vec();
    for (site, user, pass) in &st.logins {
        out.extend(format!("L\t{}\t{}\t{}\n", hex(site.as_bytes()), hex(user.as_bytes()), hex(pass.as_bytes())).bytes());
    }
    for (site, secret) in &st.totp {
        out.extend(format!("T\t{}\t{}\n", hex(site.as_bytes()), hex(secret)).bytes());
    }
    out
}

/// A backup's logins and codes, if it's one of the fake's.
fn parse_fake(blob: &[u8]) -> Option<(Vec<(String, String, String)>, Vec<(String, Vec<u8>)>)> {
    let text = std::str::from_utf8(blob.strip_prefix(FAKE_MAGIC)?).ok()?;
    let (mut logins, mut totp) = (Vec::new(), Vec::new());
    let s = |h: &str| unhex(h).and_then(|b| String::from_utf8(b).ok());
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["L", a, b, c] => logins.push((s(a)?, s(b)?, s(c)?)),
            ["T", a, b] => totp.push((s(a)?, unhex(b)?)),
            _ => return None,
        }
    }
    Some((logins, totp))
}

/// The last piece of a restore: open it, ask, add what's missing.
fn finish_restore(blob: Vec<u8>, store: &Mutex<Store>, policy: Policy) -> (u8, Vec<u8>) {
    let Some((logins, totp)) = parse_fake(&blob) else { return reply::restore_piece(true, Approval::NotYours, 0, 0, 0) };
    let (new_logins, new_totp): (Vec<_>, Vec<_>) = {
        let st = store.lock().unwrap();
        (
            logins.into_iter().filter(|l| !st.logins.iter().any(|x| x.0 == l.0 && x.1 == l.1)).collect(),
            totp.into_iter().filter(|t| !st.totp.iter().any(|x| x.0 == t.0)).collect(),
        )
    };
    let (l, t) = (new_logins.len() as u16, new_totp.len() as u16);
    if l + t == 0 {
        return reply::restore_piece(true, Approval::Approved, 0, 0, 0);
    }
    let a = approve(policy, &format!("restore backup? {l} logins, {t} codes"));
    if a == Approval::Approved {
        let mut st = store.lock().unwrap();
        st.logins.extend(new_logins);
        st.totp.extend(new_totp);
    }
    reply::restore_piece(true, a, l, t, 0)
}

fn base32(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut bits, mut n, mut out) = (0u64, 0, Vec::new());
    for c in s.trim_end_matches('=').bytes().map(|c| c.to_ascii_uppercase()) {
        bits = (bits << 5) | ALPHABET.iter().position(|&a| a == c)? as u64;
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    Some(out)
}

/// RFC 6238 with HMAC-SHA1, 30 s steps, 6 digits: what the vault computes for a default entry.
fn totp(secret: &[u8], unix_s: u64) -> (String, u8) {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret).unwrap();
    mac.update(&(unix_s / 30).to_be_bytes());
    let h = mac.finalize().into_bytes();
    let o = (h[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]);
    (format!("{:06}", bin % 1_000_000), (30 - unix_s % 30) as u8)
}

fn approve(policy: Policy, prompt: &str) -> Approval {
    match policy {
        Policy::Approve => {
            println!("  maki would ask: {prompt}  -> approved (automatic)");
            std::thread::sleep(Duration::from_millis(300)); // the owner reading the screen
            Approval::Approved
        }
        Policy::Deny => {
            println!("  maki would ask: {prompt}  -> denied (--deny)");
            Approval::Denied
        }
        Policy::Ask => {
            print!("  maki asks: {prompt} [y/N] ");
            std::io::stdout().flush().ok();
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line).ok();
            if line.trim().eq_ignore_ascii_case("y") { Approval::Approved } else { Approval::Denied }
        }
    }
}

/// What maki's app host does with a bundle that's all arrived: checks it as the host does, then
/// asks the owner. `now`: verified unix seconds, for the store's stamp.
fn finish_install(bundle: Vec<u8>, store: &Mutex<Store>, policy: Policy, now: Option<u64>) -> (u8, Vec<u8>) {
    let refused = |why: &str| {
        println!("  install refused: {why}");
        reply::app_install(true, Approval::Refused, why)
    };
    let b = match maki_bundle::read(&bundle) {
        Ok(b) => b,
        Err(e) => return refused(&e.to_string()),
    };
    if let Err(e) = maki_wasm::admit(&b.manifest, b.code) {
        return refused(&format!("maki won't install it: {e}"));
    }
    let m = &b.manifest;
    let from_store = match b.stamp {
        None => false,
        Some(raw) => {
            let checked = {
                let st = store.lock().unwrap();
                maki_store::SignedStamp::decode(raw).and_then(|stamp| stamp.check(st.root(), now, &b))
            };
            if let Err(e) = checked {
                return refused(&format!("its maki store stamp doesn't check out: {e}"));
            }
            true
        }
    };
    let revoked = {
        let st = store.lock().unwrap();
        st.revocations.as_ref().and_then(|r| r.list.check(&m.id, m.version, &b.developer).map(String::from))
    };
    if let Some(why) = revoked {
        return refused(&format!("the maki store revoked it: {why}"));
    }
    let installed = store.lock().unwrap().apps.get(&m.id).cloned();
    if let Some(old) = &installed {
        let old_b = maki_bundle::read(&old.bundle).expect("installed bundles read");
        if let Err(e) = maki_bundle::may_update(&old_b.developer, old_b.manifest.version, &b) {
            return refused(&e);
        }
    } else if store.lock().unwrap().apps.len() >= MAX_APPS {
        return refused(&format!("maki has room for {MAX_APPS} apps: remove one first"));
    }
    // the room it takes, less what the version it replaces took
    let free = {
        let space = store.lock().unwrap().space();
        let freed = installed.as_ref().map(|old| takes(&old.bundle)).unwrap_or(0);
        space.space.saturating_sub(space.taken - freed)
    };
    if takes(&bundle) > free {
        return refused(&format!("maki hasn't the room: it needs {} KiB, and {} KiB is free", takes(&bundle).div_ceil(1024), free / 1024));
    }
    let replacing = if installed.as_ref().is_some_and(|old| old.from_store) && !from_store {
        ", replacing the store's app"
    } else {
        ""
    };
    let a = approve(
        policy,
        &format!(
            "install {} {} ({}{replacing}, developer {})?",
            m.name,
            m.label,
            if from_store { "from the maki store" } else { "sideloaded" },
            maki_bundle::fingerprint(&b.developer)
        ),
    );
    if a == Approval::Approved {
        // the owner's choice of backup survives updates
        let backup = installed.map(|old| old.backup).unwrap_or(m.backup);
        store.lock().unwrap().apps.insert(m.id.clone(), Installed { bundle: bundle.clone(), backup, from_store });
    }
    reply::app_install(true, a, "")
}

/// What maki's app host does with a store record: its pieces in order, then checked against the
/// root maki trusts and kept if it's newer. Nobody's asked. `total` 0 just asks what maki has.
fn store_update(store: &Mutex<Store>, total: u32, offset: u32, data: Vec<u8>, now: Option<u64>) -> (u8, Vec<u8>) {
    let mut st = store.lock().unwrap();
    let mut done = true;
    let (status, reason) = if total == 0 {
        (Approval::Approved, String::new())
    } else {
        if offset == 0 {
            st.store_incoming.clear();
        }
        if offset as usize != st.store_incoming.len() {
            st.store_incoming.clear();
            (Approval::Refused, "pieces out of order".to_string())
        } else {
            st.store_incoming.extend_from_slice(&data);
            if st.store_incoming.len() < total as usize {
                done = false;
                (Approval::Approved, String::new())
            } else {
                let record = std::mem::take(&mut st.store_incoming);
                match take_store_record(&mut st, &record, now) {
                    Ok(()) => (Approval::Approved, String::new()),
                    Err(why) => {
                        println!("  store record refused: {why}");
                        (Approval::Refused, why)
                    }
                }
            }
        }
    };
    reply::store_update(done, status, st.store_state(), &reason)
}

/// A newer root, signed by the threshold of the current root's keys and of its own, or a newer
/// revocation list, signed by the catalogue key while that's current: as maki's app host takes
/// them.
fn take_store_record(st: &mut Store, bytes: &[u8], now: Option<u64>) -> Result<(), String> {
    if let Ok(root) = maki_store::SignedRoot::decode(bytes) {
        let next = root.replaces(st.root()).map_err(|e| format!("the store's root: {e}"))?.clone();
        println!("  maki store root {} taken", next.version);
        st.store_root = Some(next);
        return Ok(());
    }
    let list = maki_store::SignedRevocations::decode(bytes).map_err(|e| format!("not a store record: {e}"))?;
    list.replaces(st.root(), now, st.revocations.as_ref()).map_err(|e| format!("the revocation list: {e}"))?;
    println!("  maki store revocation list {} taken ({} entries)", list.list.version, list.list.entries.len());
    st.revocations = Some(list);
    Ok(())
}

/// Verified time, unix seconds, or `None` unless the clock is verified: the store's checks take
/// nothing less.
fn verified_now(device: &Mutex<Device<Host>>) -> Option<u64> {
    let d = device.lock().unwrap();
    if d.state() != TimeState::Verified {
        return None;
    }
    d.platform().utc_ms().map(|ms| ms / 1000)
}

fn app_entry(app: &Installed) -> AppEntry {
    let b = maki_bundle::read(&app.bundle).expect("installed bundles read");
    AppEntry {
        id: b.manifest.id.clone(),
        name: b.manifest.name.clone(),
        version: b.manifest.version,
        label: b.manifest.label.clone(),
        developer: b.developer.to_vec(),
        from_store: app.from_store,
        backup: app.backup,
        used: 0,
        icon: b.icon.map(|i| i.iter().flat_map(|w| w.to_le_bytes()).collect()).unwrap_or_default(),
        bundle: app.bundle.len() as u32,
        storage: b.manifest.storage_kib * 1024,
    }
}

/// What the vault does on the badge, minus the screen.
fn answer(ask: Ask, store: &Mutex<Store>, policy: Policy) -> (u8, Vec<u8>) {
    match ask {
        Ask::Login { site: s } => {
            let found = store.lock().unwrap().logins.iter().find(|(saved, _, _)| site::covers(saved, &s)).cloned();
            match found {
                None => reply::login(Approval::NoMatch, "", ""),
                Some((_, user, pass)) => {
                    reply::login(approve(policy, &format!("log in to {s} as {user}?")), &user, &pass)
                }
            }
        }
        Ask::Totp { site: s } => {
            let found = store.lock().unwrap().totp.iter().find(|(saved, _)| site::covers(saved, &s)).cloned();
            match found {
                None => reply::totp(Approval::NoMatch, "", 0),
                Some((_, secret)) => {
                    let a = approve(policy, &format!("code for {s}?"));
                    let (code, left) = totp(&secret, host_utc_ms() / 1000);
                    reply::totp(a, &code, left)
                }
            }
        }
        Ask::SaveLogin { site: s, username, password } => {
            let a = approve(policy, &format!("save a login for {s} as {username}?"));
            if a == Approval::Approved {
                let mut st = store.lock().unwrap();
                st.logins.retain(|(saved, user, _)| !(site::covers(saved, &s) && *user == username));
                st.logins.push((s, username, password));
            }
            reply::save(a)
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let addr = args.iter().find(|a| !a.starts_with("--") && a.contains(':')).cloned().unwrap_or("127.0.0.1:7878".into());
    let policy = if args.iter().any(|a| a == "--deny") {
        Policy::Deny
    } else if args.iter().any(|a| a == "--ask") {
        Policy::Ask
    } else {
        Policy::Approve
    };
    let store = Arc::new(Mutex::new(Store::default()));
    let first_root = match args.windows(2).find(|w| w[0] == "--store-root") {
        Some(w) => std::fs::read(&w[1]).expect("--store-root FILE"),
        None => FIRST_ROOT.to_vec(),
    };
    let first_root = maki_store::SignedRoot::decode(&first_root).and_then(|r| r.trust_first().cloned());
    store.lock().unwrap().store_root = Some(first_root.expect("the first store root checks out"));
    let running = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    let phrase = args.windows(2).find(|w| w[0] == "--phrase").map(|w| w[1].clone()).unwrap_or(TEST_PHRASE.into());
    let wallet = Arc::new(Mutex::new(Wallet::new(&phrase)));
    for pair in args.windows(2).filter(|w| w[0] == "--totp").map(|w| &w[1]) {
        let (s, secret) = pair.split_once('=').expect("--totp SITE=BASE32");
        store.lock().unwrap().totp.push((s.to_string(), base32(secret).expect("bad base32")));
    }

    let listener = TcpListener::bind(&addr).expect("bind");
    // print the bound address, so a caller that asked for port 0 learns the real one
    println!("fake maki listening on {}", listener.local_addr().unwrap());
    let mut device = Device::new(Host { start: Instant::now(), clock: None }, "maki", "0.2.0-fake".into());
    if args.iter().any(|a| a == "--clock-verified") {
        device.handle(&frame::Packet {
            kind: maki_proto::kind::TIME_UNVERIFIED,
            id: 0,
            body: maki_proto::wire::Writer::new().u64(host_utc_ms()).i32(0).finish(),
        });
        device.trust_platform_clock(0);
    }
    let device = Arc::new(Mutex::new(device));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        println!("connected: {:?}", stream.peer_addr());
        let writer: Arc<Mutex<TcpStream>> = Arc::new(Mutex::new(stream.try_clone().unwrap()));
        let mut deframer = Deframer::default();
        let mut buf = [0u8; 4096];
        loop {
            let n = match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            for packet in deframer.push(&buf[..n]) {
                let packet = match packet {
                    Ok(p) => p,
                    Err(e) => {
                        println!("  bad frame: {e:?}");
                        continue;
                    }
                };
                let handled = device.lock().unwrap().handle(&packet);
                match handled {
                    Handled::Reply(kind, body) => {
                        println!("  0x{:02x}#{} -> 0x{:02x} ({} bytes)", packet.kind, packet.id, kind, body.len());
                        writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                    }
                    Handled::Backup(Backup::Get { offset }) => {
                        let mut st = store.lock().unwrap();
                        if offset == 0 || st.sealed.is_empty() {
                            st.sealed = fake_backup(&st);
                        }
                        let start = (offset as usize).min(st.sealed.len());
                        let end = (start + BACKUP_PIECE).min(st.sealed.len());
                        let (kind, body) = reply::backup_piece(Approval::Approved, st.sealed.len() as u32, offset, &st.sealed[start..end]);
                        writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                    }
                    Handled::Backup(Backup::Put { total, offset, data }) => {
                        let finished = {
                            let mut st = store.lock().unwrap();
                            if offset == 0 {
                                st.incoming.clear();
                            }
                            if offset as usize != st.incoming.len() {
                                st.incoming.clear();
                                None
                            } else {
                                st.incoming.extend_from_slice(&data);
                                Some(st.incoming.len() as u32 == total)
                            }
                        };
                        match finished {
                            None => {
                                let (kind, body) = reply::restore_piece(true, Approval::Unavailable, 0, 0, 0);
                                writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                            }
                            Some(false) => {
                                let (kind, body) = reply::restore_piece(false, Approval::Approved, 0, 0, 0);
                                writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                            }
                            // like an ask: answered once the owner decides, from another thread
                            Some(true) => {
                                let blob = std::mem::take(&mut store.lock().unwrap().incoming);
                                let (writer, store, id) = (writer.clone(), store.clone(), packet.id);
                                std::thread::spawn(move || {
                                    let (kind, body) = finish_restore(blob, &store, policy);
                                    writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                                });
                            }
                        }
                    }
                    Handled::Apps(Apps::Space) => {
                        let space = store.lock().unwrap().space();
                        let (kind, body) = reply::app_space(Approval::Approved, &space);
                        writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                    }
                    Handled::Apps(Apps::List { index }) => {
                        let st = store.lock().unwrap();
                        let entry = st.apps.values().nth(index as usize).map(app_entry);
                        let (kind, body) = reply::app_list(Approval::Approved, st.apps.len() as u32, entry.as_ref());
                        writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                    }
                    Handled::Apps(Apps::Install { total, offset, data }) => {
                        let finished = {
                            let mut st = store.lock().unwrap();
                            if offset == 0 {
                                st.app_incoming.clear();
                            }
                            if offset as usize != st.app_incoming.len() {
                                st.app_incoming.clear();
                                None
                            } else {
                                st.app_incoming.extend_from_slice(&data);
                                Some(st.app_incoming.len() as u32 == total)
                            }
                        };
                        match finished {
                            None => {
                                let (kind, body) = reply::app_install(true, Approval::Refused, "pieces out of order");
                                writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                            }
                            Some(false) => {
                                let (kind, body) = reply::app_install(false, Approval::Approved, "");
                                writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                            }
                            Some(true) => {
                                let bundle = std::mem::take(&mut store.lock().unwrap().app_incoming);
                                let (writer, store, id) = (writer.clone(), store.clone(), packet.id);
                                let now = verified_now(&device);
                                std::thread::spawn(move || {
                                    let (kind, body) = finish_install(bundle, &store, policy, now);
                                    writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                                });
                            }
                        }
                    }
                    Handled::Apps(Apps::Message { id: app, message }) => {
                        println!("  0x{:02x}#{} -> app message for {app} ({} bytes)", packet.kind, packet.id, message.len());
                        let (writer, store, running, id) = (writer.clone(), store.clone(), running.clone(), packet.id);
                        let seed = wallet.lock().unwrap().seed;
                        std::thread::spawn(move || {
                            let (status, answer) = app_message(&app, message, &store, &running, seed, policy);
                            let (kind, body) = reply::app_message(status, &answer);
                            writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                        });
                    }
                    Handled::Apps(Apps::StoreUpdate { total, offset, data }) => {
                        let (kind, body) = store_update(&store, total, offset, data, verified_now(&device));
                        println!("  0x{:02x}#{} -> store update ({} bytes)", packet.kind, packet.id, body.len());
                        writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                    }
                    Handled::Apps(Apps::Remove { id: app }) => {
                        let (writer, store, id) = (writer.clone(), store.clone(), packet.id);
                        std::thread::spawn(move || {
                            let name = store.lock().unwrap().apps.get(&app).map(|a| app_entry(a).name);
                            let (kind, body) = match name {
                                None => reply::app_remove(Approval::NoMatch),
                                Some(name) => {
                                    let a = approve(policy, &format!("remove {name} and its data?"));
                                    if a == Approval::Approved {
                                        store.lock().unwrap().apps.remove(&app);
                                    }
                                    reply::app_remove(a)
                                }
                            };
                            writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                        });
                    }
                    Handled::Bitcoin(request) => {
                        println!("  0x{:02x}#{} -> bitcoin", packet.kind, packet.id);
                        let id = packet.id;
                        let account = |network: u8, account: u8| {
                            let w = wallet.lock().unwrap();
                            let n = network.min(1) as usize;
                            if account == ACCOUNT_TAPROOT { w.taproot[n].clone() } else { w.accounts[n].clone() }
                        };
                        let immediate = match request {
                            // these wait for the owner: answered from another thread
                            Bitcoin::Account { network, account: which } => {
                                let (account, writer) = (account(network, which), writer.clone());
                                std::thread::spawn(move || {
                                    let a = approve(policy, "share the bitcoin account with this computer?");
                                    let (kind, body) = reply::btc_account(a, &account.zpub(), &account.descriptor());
                                    writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                                });
                                None
                            }
                            Bitcoin::Address { network, change, index, account: which } => {
                                let (account, writer) = (account(network, which), writer.clone());
                                std::thread::spawn(move || {
                                    let address = account.address(change, index).unwrap_or_default();
                                    let page = display::address_page(&address, change, index, account.network);
                                    println!("  maki shows: {:12} {:18} {}", page.heading, page.value, page.mono);
                                    let a = approve(policy, "does it match the computer's?");
                                    let (kind, body) = reply::btc_address(a, &address);
                                    writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                                });
                                None
                            }
                            Bitcoin::Sign { network, total, offset, data } => {
                                let mut w = wallet.lock().unwrap();
                                if offset == 0 {
                                    w.incoming.clear();
                                }
                                if offset as usize != w.incoming.len() {
                                    w.incoming.clear();
                                    Some(reply::btc_sign(true, Approval::Unavailable, 0, ""))
                                } else {
                                    w.incoming.extend_from_slice(&data);
                                    if (w.incoming.len() as u32) < total {
                                        Some(reply::btc_sign(false, Approval::Approved, 0, ""))
                                    } else {
                                        let psbt = std::mem::take(&mut w.incoming);
                                        let n = network.min(1) as usize;
                                        let accounts = vec![w.accounts[n].clone(), w.taproot[n].clone()];
                                        drop(w);
                                        let (writer, wallet) = (writer.clone(), wallet.clone());
                                        std::thread::spawn(move || {
                                            let (kind, body) = finish_signing(psbt, &accounts, &wallet, policy);
                                            writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                                        });
                                        None
                                    }
                                }
                            }
                            Bitcoin::Signed { offset } => {
                                let w = wallet.lock().unwrap();
                                if w.signed.is_empty() {
                                    Some(reply::btc_signed(Approval::Unavailable, 0, offset, &[]))
                                } else {
                                    let start = (offset as usize).min(w.signed.len());
                                    let end = (start + PSBT_PIECE).min(w.signed.len());
                                    Some(reply::btc_signed(Approval::Approved, w.signed.len() as u32, offset, &w.signed[start..end]))
                                }
                            }
                        };
                        if let Some((kind, body)) = immediate {
                            writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                        }
                    }
                    Handled::Ethereum(request) => {
                        println!("  0x{:02x}#{} -> ethereum", packet.kind, packet.id);
                        let id = packet.id;
                        let eth_account = |index: u32| {
                            let seed = wallet.lock().unwrap().seed;
                            maki_eth::Account::from_seed(&seed, index).expect("keys")
                        };
                        let immediate = match request {
                            Ethereum::Account { site, index } => {
                                let (account, writer) = (eth_account(index), writer.clone());
                                std::thread::spawn(move || {
                                    let a = approve(policy, &format!("connect {site} to your ethereum account?"));
                                    let (kind, body) = reply::eth_account(a, &account.address_string());
                                    writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                                });
                                None
                            }
                            Ethereum::Message { site, index, message } => {
                                let (account, writer) = (eth_account(index), writer.clone());
                                std::thread::spawn(move || {
                                    for page in maki_eth::display::message_pages(&site, &message) {
                                        println!("  maki shows: {} {} {}", page.heading, page.value, page.mono.replace('\n', " "));
                                    }
                                    let a = approve(policy, &format!("{site}: sign this message?"));
                                    let signature = account.sign_message(&message).map(|s| s.to_vec()).unwrap_or_default();
                                    let (kind, body) = reply::eth_message(a, &signature);
                                    writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                                });
                                None
                            }
                            Ethereum::Sign { site, index, total, offset, data } => {
                                let mut w = wallet.lock().unwrap();
                                if offset == 0 {
                                    w.eth_incoming.clear();
                                }
                                if offset as usize != w.eth_incoming.len() {
                                    w.eth_incoming.clear();
                                    Some(reply::eth_sign(true, Approval::Unavailable, 0, ""))
                                } else {
                                    w.eth_incoming.extend_from_slice(&data);
                                    if (w.eth_incoming.len() as u32) < total {
                                        Some(reply::eth_sign(false, Approval::Approved, 0, ""))
                                    } else {
                                        let tx = std::mem::take(&mut w.eth_incoming);
                                        drop(w);
                                        let account = eth_account(index);
                                        let (writer, wallet) = (writer.clone(), wallet.clone());
                                        std::thread::spawn(move || {
                                            let (kind, body) = finish_eth(tx, &site, &account, &wallet, policy);
                                            writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                                        });
                                        None
                                    }
                                }
                            }
                            Ethereum::Typed { site, index, total, offset, data } => {
                                let mut w = wallet.lock().unwrap();
                                if offset == 0 {
                                    w.typed_incoming.clear();
                                }
                                if offset as usize != w.typed_incoming.len() {
                                    w.typed_incoming.clear();
                                    Some(reply::eth_typed(true, Approval::Unavailable, &[], ""))
                                } else {
                                    w.typed_incoming.extend_from_slice(&data);
                                    if (w.typed_incoming.len() as u32) < total {
                                        Some(reply::eth_typed(false, Approval::Approved, &[], ""))
                                    } else {
                                        let bytes = std::mem::take(&mut w.typed_incoming);
                                        drop(w);
                                        let (account, writer) = (eth_account(index), writer.clone());
                                        std::thread::spawn(move || {
                                            let (kind, body) = finish_typed(bytes, &site, &account, policy);
                                            writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                                        });
                                        None
                                    }
                                }
                            }
                            Ethereum::Signed { offset } => {
                                let w = wallet.lock().unwrap();
                                if w.eth_signed.is_empty() {
                                    Some(reply::eth_signed(Approval::Unavailable, 0, offset, &[]))
                                } else {
                                    let start = (offset as usize).min(w.eth_signed.len());
                                    let end = (start + TX_PIECE).min(w.eth_signed.len());
                                    Some(reply::eth_signed(Approval::Approved, w.eth_signed.len() as u32, offset, &w.eth_signed[start..end]))
                                }
                            }
                        };
                        if let Some((kind, body)) = immediate {
                            writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                        }
                    }
                    // answered from another thread, like the vault on the badge: the link keeps
                    // serving heartbeats while the owner decides
                    Handled::Ask(ask) => {
                        println!("  0x{:02x}#{} -> asking the owner: {ask:?}", packet.kind, packet.id);
                        let (writer, store, id) = (writer.clone(), store.clone(), packet.id);
                        std::thread::spawn(move || {
                            let (kind, body) = answer(ask, &store, policy);
                            writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                        });
                    }
                }
            }
        }
        println!("disconnected");
    }
}
