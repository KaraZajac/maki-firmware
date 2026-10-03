//! A host stand-in for maki: the real protocol logic behind a TCP socket.
//!
//!     cargo run -p maki-proto --features fake --example fake_maki -- \
//!         [ADDR] [--deny | --ask] [--totp SITE=BASE32]... [--clock-verified] [--phrase "WORDS"] \
//!         [--store-root FILE] [--name NAME] [--app FILE.maki]...
//!
//! ADDR defaults to 127.0.0.1:7878. Logins and TOTP secrets live in memory; SAVE_LOGIN adds to them.
//! Its recovery phrase is `--phrase`, or else the BIP39 test phrase ("abandon" eleven times, then
//! "about"), which everyone knows: never send real coins to either's wallets. Wallet apps (the
//! store's Bitcoin, Ethereum and Monero) get their keys from it, as on maki.
//! Approvals are automatic unless `--deny` (refuse everything) or `--ask` (ask on this terminal).
//! Imports from other password managers (IMPORT_PUT) are read and checked as maki does, and what
//! the fake hasn't got kept in memory beside the rest, by the same rules; VAULT_STATUS counts it.
//! It calls itself a maki roll, picked at random as a badge picks its name, unless `--name` says.
//! Codes need a verified clock, as on the badge: sync through Roughtime first, or start with
//! `--clock-verified` to take this computer's clock as verified (tests, offline work).
//! Everything maki-link does on the device happens here too, except the USB hop, the Xous clock and
//! maki's own screen. State survives reconnects, like a badge that stays plugged in. Installed apps
//! answer APP_MESSAGE as on maki: each runs (with maki's own host code) without a screen, its
//! asks and reviews answered as above (a review's pages printed), its keys from the phrase, until
//! it's had nothing to do for a while.
//! Native apps install as on maki, but don't run here: they're machine code for maki's processor.
//! `--app` installs a bundle at start, as if the owner had said yes to it before (with `--deny`, for
//! a maki whose owner turns down what an app asks).
//! The maki store's records are checked as maki does, starting from the root the firmware
//! carries, or the one in `--store-root` (a test store's).

use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use maki_proto::device::{
    AppEntry, AppSpace, Approval, Apps, Ask, BACKUP_PIECE, Backup, Device, Handled, ImportAdded, Platform,
    StoreState, TimeState, VaultCounts, WalletKind, reply,
};
use maki_proto::frame::{self, Deframer};
use maki_proto::import::{self, opensk, vault};
use maki_proto::site;

struct Host {
    start: Instant,
    clock: Option<(u64, Instant)>,
    /// which wallet wallet apps have: the phrase's own, or `--passphrase`'s
    wallet: (WalletKind, u32),
    /// what the vault holds, for VAULT_STATUS
    store: Arc<Mutex<Store>>,
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

    fn time_state_changed(&mut self, state: TimeState) {
        println!("  time is now {state:?}");
    }

    fn wallet(&mut self) -> (WalletKind, u32) { self.wallet }

    /// Always unlocked, with a phrase: the counts.
    fn vault(&mut self) -> Option<(Approval, VaultCounts)> {
        let st = self.store.lock().unwrap();
        let counts = VaultCounts {
            logins: st.logins.len() as u32,
            codes: (st.totp.len() + st.codes.len()) as u32,
            passkeys: (st.passkeys.len() + st.imported.len()) as u32,
            imported: st.imported.len() as u32,
        };
        Some((Approval::Approved, counts))
    }
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
    /// the sites (RP IDs) maki holds a passkey for (`--passkey`)
    passkeys: Vec<String>,
    totp: Vec<(String, Vec<u8>)>,
    /// codes an import gave it, as the Authenticator keeps them
    codes: Vec<Code>,
    /// passkeys an import gave it: each one's site (RP ID), credential ID and user handle
    imported: Vec<(String, Vec<u8>, Vec<u8>)>,
    /// an import coming in
    import_incoming: Vec<u8>,
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

/// A code from an import: the name it shows under, how it's made, and the site it was picked for
/// (none until a site asks, as on maki).
struct Code {
    name: String,
    issuer: String,
    secret: Vec<u8>,
    algorithm: import::Algorithm,
    digits: u8,
    period_s: u16,
    site: Option<String>,
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

/// The phrase's secrets: its seed, and its entropy (up to 32 bytes; `len` of them), which
/// Cardano's keys come from (Icarus) where everything else comes from the seed. With
/// `--passphrase`, wallet apps have a passphrase wallet, as on a maki where one's open: its seed,
/// and its passphrase (`passphrase_len` bytes) for Cardano's; maki's own keys stay the phrase's.
#[derive(Clone, Copy)]
struct Secrets {
    seed: [u8; 64],
    entropy: [u8; 32],
    len: usize,
    wallet_seed: [u8; 64],
    passphrase: [u8; maki_keys_api_max::MAX_PASSPHRASE],
    passphrase_len: usize,
}

/// maki-keys' limit, which the fake holds `--passphrase` to.
mod maki_keys_api_max {
    pub const MAX_PASSPHRASE: usize = 100;
}

/// What a running app has instead of maki's app host: messages from the computer, asks answered
/// by the fake's policy, keys from its phrase, and storage in memory. No screen.
struct FakeApp {
    id: String,
    name: String,
    developer: [u8; 32],
    secrets: Secrets,
    policy: Policy,
    inbox: std::sync::mpsc::Receiver<(Vec<u8>, ReplyTo)>,
    current: Option<(Vec<u8>, ReplyTo)>,
    store: Arc<Mutex<Store>>,
    start: Instant,
    /// The wallet's keys, from the phrase, once the app asks for one.
    keys: Option<maki_hd::seed::SeedKeys>,
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
        self.store
            .lock()
            .unwrap()
            .app_data
            .entry(self.id.clone())
            .or_default()
            .insert(key.into(), value.into());
        Ok(())
    }

    fn storage_delete(&mut self, key: &str) -> bool {
        self.store.lock().unwrap().app_data.get_mut(&self.id).is_some_and(|d| d.remove(key).is_some())
    }

    fn storage_keys(&mut self) -> Vec<String> {
        self.store
            .lock()
            .unwrap()
            .app_data
            .get(&self.id)
            .map(|d| d.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn ask(&mut self, ask: &maki_wasm::Ask) -> maki_wasm::Answer {
        match approve(self.policy, &format!("{}: {} {}", self.name, ask.question, ask.detail)) {
            Approval::Approved => maki_wasm::Answer::Yes,
            _ => maki_wasm::Answer::No,
        }
    }

    /// A review: its pages printed, as maki would show them, and answered by the policy.
    fn review(&mut self, review: &maki_wasm::Review) -> maki_wasm::Answer {
        for p in &review.pages {
            println!(
                "  {} shows [{}] {} {} {}",
                self.name,
                p.heading,
                p.value,
                p.mono.replace('\n', " "),
                p.prose.replace('\n', " ")
            );
        }
        match approve(self.policy, &format!("{}: {} {}", self.name, review.question, review.detail)) {
            Approval::Approved => maki_wasm::Answer::Yes,
            Approval::TimedOut => maki_wasm::Answer::NoAnswer,
            _ => maki_wasm::Answer::No,
        }
    }

    /// What maki-keys answers the app host, from the phrase: the host has checked the path. No
    /// randomness in its Schnorr signatures, as in the simulator: the same every time, so tests
    /// can hold them to the fixtures' (maki adds fresh randomness, as BIP340 advises).
    fn wallet(&mut self, op: u8, path: &[u32], digest: &[u8]) -> Result<Vec<u8>, i32> {
        let refused = |e| match e {
            maki_hd::Error::Path => maki_wasm::REFUSED,
            _ => maki_wasm::FAILED,
        };
        // BIP-85's child seeds and passwords are the phrase's alone, whichever wallet is open
        if matches!(op, maki_hd::op::BIP85_WORDS | maki_hd::op::BIP85_PASSWORD) {
            let keys =
                maki_hd::seed::SeedKeys::from_seed(&self.secrets.seed).map_err(|_| maki_wasm::FAILED)?;
            return maki_hd::seed::answer(&keys, op, path, digest, &[0; 32]).map_err(refused);
        }
        if self.keys.is_none() {
            let s = &self.secrets;
            let mut keys =
                maki_hd::seed::SeedKeys::from_seed(&s.wallet_seed).map_err(|_| maki_wasm::FAILED)?;
            keys.with_cardano_passphrase(&s.entropy[..s.len], &s.passphrase[..s.passphrase_len]);
            self.keys = Some(keys);
        }
        maki_hd::seed::answer(self.keys.as_ref().unwrap(), op, path, digest, &[0; 32]).map_err(refused)
    }

    /// A wallet's backup words: asked about by the policy, then "shown" (the fake has no screen,
    /// and doesn't print them: its phrase can be someone's). The app hears only the answer.
    fn show_backup(&mut self, path: &[u32]) -> Result<maki_wasm::Answer, i32> {
        let words = self.wallet(maki_hd::words_op(path), path, &[]).map_err(|e| match e {
            maki_wasm::REFUSED => maki_wasm::NOT_FOUND,
            e => e,
        })?;
        match approve(self.policy, &format!("{}: show its backup words?", self.name)) {
            Approval::Approved => {
                println!("  maki shows its owner {} backup words", words.split(|b| *b == b' ').count());
                Ok(maki_wasm::Answer::Yes)
            }
            Approval::TimedOut => Ok(maki_wasm::Answer::NoAnswer),
            _ => Ok(maki_wasm::Answer::No),
        }
    }

    /// A BIP-85 password: "typed" (the fake has no keyboard, and doesn't print it: its phrase can
    /// be someone's).
    fn type_password(&mut self, path: &[u32]) -> Result<bool, i32> {
        let password = self.wallet(maki_hd::op::BIP85_PASSWORD, path, &[])?;
        println!("  {} would type a password of {} characters", self.name, password.len());
        Ok(true)
    }

    /// A BIP-85 password: "shown", as `type_password` types it.
    fn show_password(&mut self, path: &[u32], label: &str) -> Result<maki_wasm::Answer, i32> {
        let password = self.wallet(maki_hd::op::BIP85_PASSWORD, path, &[])?;
        println!("  maki shows its owner {label:?}'s password, {} characters", password.len());
        Ok(maki_wasm::Answer::Yes)
    }

    fn app_secret(&mut self, label: &str) -> Option<[u8; 32]> {
        maki_seed::app_secret(&self.secrets.seed, &self.id, &self.developer, label)
    }

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
    secrets: Secrets,
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
            r.entry(app.to_string())
                .or_insert_with(|| start_app(bundle.clone(), store.clone(), secrets, policy))
                .clone()
        };
        let (reply_to, answer) = std::sync::mpsc::channel();
        if inbox.send((message.clone(), reply_to)).is_err() {
            running.lock().unwrap().remove(app);
            continue;
        }
        // as long as the longest review an app may ask for, and a little
        match answer.recv_timeout(Duration::from_secs(maki_wasm::MAX_REVIEW_TIMEOUT_S as u64 + 30)) {
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
fn start_app(bundle: Vec<u8>, store: Arc<Mutex<Store>>, secrets: Secrets, policy: Policy) -> Inbox {
    let (inbox, messages) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let b = maki_bundle::read(&bundle).expect("installed bundles read");
        // loaded as maki loads it: the manifest's wallet paths come with it
        let loaded = maki_wasm::load(&b.manifest, b.code).expect("installed apps are admitted");
        println!("  {} started for a message", b.manifest.name);
        let app = FakeApp {
            id: b.manifest.id.clone(),
            name: b.manifest.name.clone(),
            developer: b.developer,
            secrets,
            policy,
            inbox: messages,
            current: None,
            store,
            start: Instant::now(),
            keys: None,
        };
        let stop = loaded.run(Box::new(app));
        println!("  {} stopped: {stop:?}", b.manifest.name);
    });
    inbox
}

const TEST_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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
        out.extend(
            format!("L\t{}\t{}\t{}\n", hex(site.as_bytes()), hex(user.as_bytes()), hex(pass.as_bytes()))
                .bytes(),
        );
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
    let Some((logins, totp)) = parse_fake(&blob) else {
        return reply::restore_piece(true, Approval::NotYours, 0, 0, 0);
    };
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
    code_at(secret, import::Algorithm::Sha1, 6, 30, unix_s)
}

/// RFC 6238, as the vault computes a code of any algorithm, length and period: the code, and the
/// seconds it's good for (at most 255).
fn code_at(
    secret: &[u8],
    algorithm: import::Algorithm,
    digits: u8,
    period_s: u16,
    unix_s: u64,
) -> (String, u8) {
    let step = (unix_s / period_s as u64).to_be_bytes();
    let h: Vec<u8> = match algorithm {
        import::Algorithm::Sha1 => {
            let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret).unwrap();
            mac.update(&step);
            mac.finalize().into_bytes().to_vec()
        }
        import::Algorithm::Sha256 => {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret).unwrap();
            mac.update(&step);
            mac.finalize().into_bytes().to_vec()
        }
        import::Algorithm::Sha512 => {
            let mut mac = Hmac::<sha2::Sha512>::new_from_slice(secret).unwrap();
            mac.update(&step);
            mac.finalize().into_bytes().to_vec()
        }
    };
    let o = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]);
    let code = format!("{:0width$}", bin % 10u32.pow(digits as u32), width = digits as usize);
    (code, (period_s as u64 - unix_s % period_s as u64).min(255) as u8)
}

/// What maki says of imported passkeys before its owner says yes to them (maki-keys' words).
const PASSKEYS: &str = "Their keys were made elsewhere and have been in a file on this computer. They don’t come \
                        from maki’s recovery phrase, so only a backup brings them back to a restored maki.";

/// What the fake's vault has, as an import's plan needs it, its records counted as maki writes
/// them.
fn have_of(st: &Store) -> import::Have {
    let mut have = import::Have::default();
    for (site, user, pass) in &st.logins {
        have.logins.insert((site::normalize(site), user.clone()));
        have.login_keys.insert(vault::login_key(site, user));
        let login = import::Login {
            site: site.clone(),
            username: user.clone(),
            password: pass.clone(),
            title: String::new(),
        };
        have.used += import::cost(vault::login_record(&login, 0).len());
    }
    let code = |secret: &[u8], algorithm, digits, period_s| import::Code {
        issuer: String::new(),
        account: String::new(),
        secret: secret.to_vec(),
        algorithm,
        digits,
        period_s,
    };
    for (site, secret) in &st.totp {
        have.code_keys.insert(vault::code_key(site));
        have.code_secrets.push(secret.clone());
        let record = vault::code_record(site, &code(secret, import::Algorithm::Sha1, 6, 30), 0);
        have.used += import::cost(record.len());
    }
    for c in &st.codes {
        have.code_keys.insert(vault::code_key(&c.name));
        have.code_secrets.push(c.secret.clone());
        let record = vault::code_record(&c.name, &code(&c.secret, c.algorithm, c.digits, c.period_s), 0);
        have.used += import::cost(record.len());
    }
    for (rp_id, id, handle) in &st.imported {
        have.credential_ids.insert(id.clone());
        have.accounts.insert((rp_id.clone(), handle.clone()));
        let passkey = import::Passkey {
            rp_id: rp_id.clone(),
            credential_id: id.clone(),
            user_handle: handle.clone(),
            user_name: String::new(),
            display_name: String::new(),
            private_key: [1; 32],
        };
        have.used += import::cost(opensk::credential(&passkey, 0).len()) + import::cost(id.len());
    }
    have.passkey_room = import::MAX_PASSKEYS.saturating_sub(st.passkeys.len() + st.imported.len());
    have
}

/// The last piece of an import: read and checked as maki does, every record; then, if there's
/// anything new, the owner asked (the question maki shows printed), and what's new kept.
fn finish_import(mut blob: Vec<u8>, store: &Mutex<Store>, policy: Policy) -> (u8, Vec<u8>) {
    let parsed = import::parse(&blob);
    blob.fill(0);
    let refused = |why: String| {
        println!("  import refused: {why}");
        reply::import_piece(true, Approval::Refused, ImportAdded::default(), &why)
    };
    let import = match parsed {
        Ok(import) => import,
        Err(why) => return refused(why),
    };
    let have = have_of(&store.lock().unwrap());
    let plan = import::plan(&import, &have);
    if let Err(why) = import::check_room(&plan, &have) {
        return refused(why);
    }
    let n = |v: usize| v.min(u16::MAX as usize) as u16;
    let skipped = n(plan.skipped as usize);
    if plan.is_empty() {
        println!("  import from {}: nothing new, {} records it has", import.source, plan.skipped);
        return reply::import_piece(
            true,
            Approval::Approved,
            ImportAdded { skipped, ..Default::default() },
            "",
        );
    }
    let count = |n: usize, one: &str| format!("{n} {one}{}", if n == 1 { "" } else { "s" });
    let what: Vec<String> =
        [(plan.logins.len(), "login"), (plan.codes.len(), "code"), (plan.passkeys.len(), "passkey")]
            .into_iter()
            .filter(|(n, _)| *n > 0)
            .map(|(n, one)| count(n, one))
            .collect();
    println!(
        "  maki shows [Import] from {} {} ({} records it has)",
        import.source,
        what.join(", "),
        plan.skipped
    );
    if !plan.passkeys.is_empty() {
        println!("  maki shows [Passkeys] made elsewhere: {PASSKEYS}");
    }
    let a = approve(policy, &format!("Import from {}: {}?", import.source, what.join(", ")));
    if a != Approval::Approved {
        return reply::import_piece(true, a, ImportAdded::default(), "");
    }
    let mut st = store.lock().unwrap();
    for l in &plan.logins {
        st.logins.push((l.site.clone(), l.username.clone(), l.password.clone()));
    }
    for (name, c) in &plan.codes {
        st.codes.push(Code {
            name: name.clone(),
            issuer: c.issuer.clone(),
            secret: c.secret.clone(),
            algorithm: c.algorithm,
            digits: c.digits,
            period_s: c.period_s,
            site: None,
        });
    }
    for p in &plan.passkeys {
        st.imported.push((p.rp_id.clone(), p.credential_id.clone(), p.user_handle.clone()));
    }
    let added = ImportAdded {
        logins: n(plan.logins.len()),
        codes: n(plan.codes.len()),
        passkeys: n(plan.passkeys.len()),
        skipped,
    };
    reply::import_piece(true, Approval::Approved, added, "")
}

/// A code from an import, for `site`: the one picked for it before, or, the first time, the one
/// the owner picks of them all, which maki lists the likeliest first (a name that mentions the
/// site), and keeps for the site from then on. None if an import gave none.
fn imported_code(s: &str, store: &Mutex<Store>, policy: Policy) -> Option<(u8, Vec<u8>)> {
    let mut st = store.lock().unwrap();
    if st.codes.is_empty() {
        return None;
    }
    let bound = st.codes.iter().position(|c| c.site.as_deref().is_some_and(|b| site::covers(b, s)));
    let i = match bound {
        Some(i) => i,
        None => {
            let host = site::normalize(s);
            let labels: Vec<&str> = host.split('.').collect();
            let words: Vec<&str> =
                labels[..labels.len().saturating_sub(1)].iter().copied().filter(|l| l.len() >= 3).collect();
            let score = |c: &Code| {
                let text = format!("{} {}", c.name, c.issuer).to_ascii_lowercase();
                words.iter().filter(|w| text.contains(*w)).count()
            };
            (0..st.codes.len())
                .max_by(|&a, &b| {
                    score(&st.codes[a])
                        .cmp(&score(&st.codes[b]))
                        .then(st.codes[b].name.cmp(&st.codes[a].name))
                })
                .unwrap_or(0)
        }
    };
    let question = if bound.is_some() {
        format!("code for {s}?")
    } else {
        format!("code for {s} from {}?", st.codes[i].name)
    };
    let a = approve(policy, &question);
    if a == Approval::Approved && bound.is_none() {
        st.codes[i].site = Some(s.to_string());
    }
    let c = &st.codes[i];
    let (code, left) = code_at(&c.secret, c.algorithm, c.digits, c.period_s, host_utc_ms() / 1000);
    Some(reply::totp(a, &code, left))
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
        return refused(&format!(
            "maki hasn't the room: it needs {} KiB, and {} KiB is free",
            takes(&bundle).div_ceil(1024),
            free / 1024
        ));
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
        store
            .lock()
            .unwrap()
            .apps
            .insert(m.id.clone(), Installed { bundle: bundle.clone(), backup, from_store });
    }
    reply::app_install(true, a, "")
}

/// What maki's app host does with a store record: its pieces in order, then checked against the
/// root maki trusts and kept if it's newer. Nobody's asked. `total` 0 just asks what maki has.
fn store_update(
    store: &Mutex<Store>,
    total: u32,
    offset: u32,
    data: Vec<u8>,
    now: Option<u64>,
) -> (u8, Vec<u8>) {
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
    let list =
        maki_store::SignedRevocations::decode(bytes).map_err(|e| format!("not a store record: {e}"))?;
    list.replaces(st.root(), now, st.revocations.as_ref())
        .map_err(|e| format!("the revocation list: {e}"))?;
    println!(
        "  maki store revocation list {} taken ({} entries)",
        list.list.version,
        list.list.entries.len()
    );
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
        Ask::Login { site: s, even_with_passkey } => {
            let (found, passkey) = {
                let st = store.lock().unwrap();
                (
                    st.logins.iter().find(|(saved, _, _)| site::covers(saved, &s)).cloned(),
                    st.passkeys.iter().any(|rp| site::covers(rp, &s))
                        || st.imported.iter().any(|(rp, _, _)| site::covers(rp, &s)),
                )
            };
            match found {
                None => reply::login(Approval::NoMatch, "", ""),
                Some(_) if passkey && !even_with_passkey => reply::login(Approval::Passkey, "", ""),
                Some((_, user, pass)) => {
                    reply::login(approve(policy, &format!("log in to {s} as {user}?")), &user, &pass)
                }
            }
        }
        Ask::Totp { site: s } => {
            let found = store.lock().unwrap().totp.iter().find(|(saved, _)| site::covers(saved, &s)).cloned();
            match found {
                None => {
                    imported_code(&s, store, policy).unwrap_or_else(|| reply::totp(Approval::NoMatch, "", 0))
                }
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
        // a fake has no update mode to restart into: it says what maki would do
        Ask::UpdateMode { label } => {
            let a = approve(policy, &format!("restart into update mode for {label}?"));
            if a == Approval::Approved {
                println!("maki would restart into update mode now, for maki desktop to install {label}");
            }
            reply::update_mode(a)
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let addr = args
        .iter()
        .find(|a| !a.starts_with("--") && a.contains(':'))
        .cloned()
        .unwrap_or("127.0.0.1:7878".into());
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
    let phrase =
        args.windows(2).find(|w| w[0] == "--phrase").map(|w| w[1].clone()).unwrap_or(TEST_PHRASE.into());
    let secrets = {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let entropy = maki_seed::to_entropy(&words).expect("--phrase isn't a BIP39 phrase");
        let mut e = [0u8; 32];
        e[..entropy.len()].copy_from_slice(&entropy);
        // a passphrase wallet open: --passphrase TEXT
        let passphrase =
            args.windows(2).find(|w| w[0] == "--passphrase").map(|w| w[1].clone()).unwrap_or_default();
        assert!(
            passphrase.len() <= maki_keys_api_max::MAX_PASSPHRASE
                && passphrase.bytes().all(|b| (0x20..0x7f).contains(&b)),
            "--passphrase: up to 100 printable ASCII characters"
        );
        let mut p = [0u8; maki_keys_api_max::MAX_PASSPHRASE];
        p[..passphrase.len()].copy_from_slice(passphrase.as_bytes());
        Secrets {
            seed: maki_seed::seed(&words, ""),
            entropy: e,
            len: entropy.len(),
            wallet_seed: maki_seed::seed(&words, &passphrase),
            passphrase: p,
            passphrase_len: passphrase.len(),
        }
    };
    let wallet = {
        use maki_hd::Keys;
        let keys = maki_hd::seed::SeedKeys::from_seed(&secrets.wallet_seed).expect("the wallet's keys");
        let fp = u32::from_be_bytes(keys.fingerprint().expect("its fingerprint"));
        let kind = if secrets.passphrase_len > 0 { WalletKind::Passphrase } else { WalletKind::Standard };
        println!(
            "wallet apps have {} wallet {fp:08x}",
            if kind == WalletKind::Passphrase { "the passphrase's" } else { "the phrase's own" }
        );
        (kind, fp)
    };
    // a passkey for a site, which its login request is answered with: --passkey github.com
    for rp in args.windows(2).filter(|w| w[0] == "--passkey").map(|w| &w[1]) {
        store.lock().unwrap().passkeys.push(rp.clone());
    }
    for pair in args.windows(2).filter(|w| w[0] == "--totp").map(|w| &w[1]) {
        let (s, secret) = pair.split_once('=').expect("--totp SITE=BASE32");
        store.lock().unwrap().totp.push((s.to_string(), base32(secret).expect("bad base32")));
    }
    // an app's storage as its owner left it (a setting from its menu, say): APP:KEY=HEX
    for set in args.windows(2).filter(|w| w[0] == "--storage").map(|w| &w[1]) {
        let (app, rest) = set.split_once(':').expect("--storage APP:KEY=HEX");
        let (key, value) = rest.split_once('=').expect("--storage APP:KEY=HEX");
        let value = (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("--storage: hex"))
            .collect();
        store.lock().unwrap().app_data.entry(app.into()).or_default().insert(key.into(), value);
    }
    // apps installed before this start, as if the owner had said yes then: checked as ever
    for path in args.windows(2).filter(|w| w[0] == "--app").map(|w| &w[1]) {
        let bundle = std::fs::read(path).unwrap_or_else(|e| panic!("--app {path}: {e}"));
        let (_, body) = finish_install(bundle, &store, Policy::Approve, None);
        assert_eq!(body.get(1), Some(&(Approval::Approved as u8)), "--app {path}: maki wouldn't install it");
    }

    let listener = TcpListener::bind(&addr).expect("bind");
    // print the bound address, so a caller that asked for port 0 learns the real one
    println!("fake maki listening on {}", listener.local_addr().unwrap());
    // a maki roll, as a badge picks one the first time it starts (`--name` to choose)
    let name =
        args.iter().position(|a| a == "--name").and_then(|i| args.get(i + 1)).cloned().unwrap_or_else(|| {
            // any byte will do for a name: the clock's
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            maki_proto::names::pick((nanos >> 10) as u8).to_string()
        });
    println!("this maki is {name}");
    let host = Host { start: Instant::now(), clock: None, wallet, store: store.clone() };
    let mut device = Device::new(host, name, "0.2.0-fake".into());
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
                        println!(
                            "  0x{:02x}#{} -> 0x{:02x} ({} bytes)",
                            packet.kind,
                            packet.id,
                            kind,
                            body.len()
                        );
                        writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                    }
                    Handled::Backup(Backup::Get { offset }) => {
                        let mut st = store.lock().unwrap();
                        if offset == 0 || st.sealed.is_empty() {
                            st.sealed = fake_backup(&st);
                        }
                        let start = (offset as usize).min(st.sealed.len());
                        let end = (start + BACKUP_PIECE).min(st.sealed.len());
                        let (kind, body) = reply::backup_piece(
                            Approval::Approved,
                            st.sealed.len() as u32,
                            offset,
                            &st.sealed[start..end],
                        );
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
                    Handled::Import { total, offset, data } => {
                        let finished = {
                            let mut st = store.lock().unwrap();
                            if offset == 0 {
                                st.import_incoming.fill(0);
                                st.import_incoming.clear();
                            }
                            if offset as usize != st.import_incoming.len() {
                                st.import_incoming.fill(0);
                                st.import_incoming.clear();
                                None
                            } else {
                                st.import_incoming.extend_from_slice(&data);
                                Some(st.import_incoming.len() as u32 == total)
                            }
                        };
                        let answer = |done, a| reply::import_piece(done, a, ImportAdded::default(), "");
                        match finished {
                            None => {
                                let (kind, body) = answer(true, Approval::Unavailable);
                                writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                            }
                            Some(false) => {
                                let (kind, body) = answer(false, Approval::Approved);
                                writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                            }
                            // like an ask: answered once the owner decides, from another thread
                            Some(true) => {
                                let blob = std::mem::take(&mut store.lock().unwrap().import_incoming);
                                let (writer, store, id) = (writer.clone(), store.clone(), packet.id);
                                std::thread::spawn(move || {
                                    let (kind, body) = finish_import(blob, &store, policy);
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
                        let (kind, body) =
                            reply::app_list(Approval::Approved, st.apps.len() as u32, entry.as_ref());
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
                                let (kind, body) =
                                    reply::app_install(true, Approval::Refused, "pieces out of order");
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
                        println!(
                            "  0x{:02x}#{} -> app message for {app} ({} bytes)",
                            packet.kind,
                            packet.id,
                            message.len()
                        );
                        let (writer, store, running, id) =
                            (writer.clone(), store.clone(), running.clone(), packet.id);
                        std::thread::spawn(move || {
                            let (status, answer) =
                                app_message(&app, message, &store, &running, secrets, policy);
                            let (kind, body) = reply::app_message(status, &answer);
                            writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                        });
                    }
                    Handled::Apps(Apps::StoreUpdate { total, offset, data }) => {
                        let (kind, body) = store_update(&store, total, offset, data, verified_now(&device));
                        println!(
                            "  0x{:02x}#{} -> store update ({} bytes)",
                            packet.kind,
                            packet.id,
                            body.len()
                        );
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
