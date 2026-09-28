//! maki-link: the desktop app's way in, over the USB serial port.
//!
//! Frames arrive on the CDC-ACM serial interface, `maki_proto::device` decides what to do with
//! them, and this process supplies the badge-specific parts: the TRNG, the uptime counter, the RTC,
//! and telling the launcher whether its clock can be trusted. Requests for logins and codes go to
//! the vault, which asks the owner on screen; a worker waits on those, so heartbeats keep being
//! answered meanwhile. Protocol: libs/maki-proto/PROTOCOL.md.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use maki_app_host_api as app_host;
use maki_proto::device::{
    reply, AppEntry, Apps, Approval, Ask, Backup, Bitcoin, Device, Ethereum, Handled, Platform, StoreState, TimeState,
};
use maki_proto::frame::{self, Deframer};
use num_traits::ToPrimitive;

/// The desktop app sends a heartbeat every 10 s; this long without a valid frame means it's gone.
const LINK_TIMEOUT_MS: u32 = 25_000;
/// Requests for the owner that may wait at once; more are turned away as unavailable.
const MAX_WAITING_ASKS: u32 = 3;

/// Send a whole frame. Replies come from two threads, so the lock keeps frames from
/// interleaving if the USB side takes one in pieces.
fn send(usb: &usb_bao1x::UsbHid, lock: &Mutex<()>, bytes: &[u8]) {
    let _guard = lock.lock().unwrap();
    let mut sent = 0;
    for _ in 0..50 {
        match usb.serial_send(&bytes[sent..]) {
            Ok(n) => sent += n,
            Err(e) => {
                log::warn!("serial send failed: {:?}", e);
                return;
            }
        }
        if sent >= bytes.len() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    log::warn!("gave up on a frame after {} of {} bytes", sent, bytes.len());
}

/// A refusal, for when the vault can't take another request or maki is locked.
fn refused(ask: &Ask, why: Approval) -> (u8, Vec<u8>) {
    match ask {
        Ask::Login { .. } => reply::login(why, "", ""),
        Ask::Totp { .. } => reply::totp(why, "", 0),
        Ask::SaveLogin { .. } => reply::save(why),
    }
}

fn unavailable(ask: &Ask) -> (u8, Vec<u8>) { refused(ask, Approval::Unavailable) }

fn locked(ask: &Ask) -> (u8, Vec<u8>) { refused(ask, Approval::Locked) }

/// What the worker does: a request for the owner, the last piece of a restore (which asks the
/// owner too), a wallet request that waits for them, an app to install or remove, or a message
/// for an app (which may ask the owner before it answers).
enum Work {
    Ask(u16, Ask),
    Restore { id: u16, total: u32, offset: u32, data: Vec<u8> },
    Bitcoin(u16, Bitcoin),
    Ethereum(u16, Ethereum),
    AppInstall { id: u16, total: u32, offset: u32, data: Vec<u8> },
    AppRemove { id: u16, app: String },
    AppMessage { id: u16, app: String, message: Vec<u8> },
}

/// The app host's answers, as the protocol's.
fn app_approval(result: u32) -> Approval {
    match result {
        app_host::RESULT_OK => Approval::Approved,
        app_host::RESULT_DENIED => Approval::Denied,
        app_host::RESULT_TIMED_OUT => Approval::TimedOut,
        app_host::RESULT_REFUSED => Approval::Refused,
        app_host::RESULT_LOCKED => Approval::Locked,
        app_host::RESULT_NO_APP => Approval::NoMatch,
        _ => Approval::Unavailable,
    }
}

/// A piece of a bundle, handed to the app host (None: an image without one).
fn app_install(host: Option<app_host::AppHost>, total: u32, offset: u32, data: Vec<u8>) -> (u8, Vec<u8>) {
    let Some(host) = host else { return reply::app_install(true, Approval::Unavailable, "") };
    let r = host.install(total, offset, data);
    reply::app_install(r.done, app_approval(r.result), &r.reason)
}

/// A piece of a store record, or (`total` 0) a question, handed to the app host, which checks
/// and keeps records itself without asking the owner.
fn store_update(host: Option<app_host::AppHost>, total: u32, offset: u32, data: Vec<u8>) -> (u8, Vec<u8>) {
    let Some(host) = host else {
        return reply::store_update(true, Approval::Unavailable, StoreState::default(), "");
    };
    let r = host.store_update(total, offset, data);
    let state = StoreState {
        root: r.root_version,
        revocations: r.revocations_version,
        revocations_expires: r.revocations_expires,
    };
    reply::store_update(r.done, app_approval(r.result), state, &r.reason)
}

/// The installed app at `index`, and how many there are.
fn app_list(host: Option<app_host::AppHost>, index: u32) -> (u8, Vec<u8>) {
    let Some(host) = host else { return reply::app_list(Approval::Unavailable, 0, None) };
    let list = host.list();
    if list.result != app_host::RESULT_OK {
        return reply::app_list(app_approval(list.result), 0, None);
    }
    let entry = list.apps.get(index as usize).map(|a| AppEntry {
        id: a.id.clone(),
        name: a.name.clone(),
        version: a.version,
        label: a.label.clone(),
        developer: a.developer.clone(),
        from_store: a.from_store,
        backup: a.backup,
        used: a.used,
        icon: a.icon.iter().flat_map(|w| w.to_le_bytes()).collect(),
    });
    reply::app_list(Approval::Approved, list.apps.len() as u32, entry.as_ref())
}

/// maki-keys' answers, as the protocol's.
fn approval(result: u32) -> Approval {
    match result {
        maki_keys::RESULT_OK => Approval::Approved,
        maki_keys::RESULT_DENIED => Approval::Denied,
        maki_keys::RESULT_TIMED_OUT => Approval::TimedOut,
        maki_keys::RESULT_NOT_NOW => Approval::Locked,
        maki_keys::RESULT_NOT_YOURS => Approval::NotYours,
        maki_keys::RESULT_NO_PHRASE => Approval::NoPhrase,
        maki_keys::RESULT_REFUSED => Approval::Refused,
        _ => Approval::Unavailable,
    }
}

/// Takes requests for the owner to the vault (and restores to maki-keys), one at a time, and
/// sends each answer back with its request's id. Connects to the vault at boot: the vault
/// accepts one connection only.
fn vault_worker(work: mpsc::Receiver<Work>, waiting: Arc<AtomicU32>, send_lock: Arc<Mutex<()>>) {
    let xns = xous_names::XousNames::new().unwrap();
    let vault = maki_vault_api::VaultLink::new(&xns).expect("couldn't connect to the vault");
    let keys = maki_keys::Keys::new(&xns).expect("couldn't connect to maki-keys");
    let usb = usb_bao1x::UsbHid::new();
    for item in work {
        let (id, ask) = match item {
            Work::Ask(id, ask) => (id, ask),
            Work::Restore { id, total, offset, data } => {
                let c = keys.restore_chunk(total, offset, data);
                let (kind, body) =
                    reply::restore_piece(true, approval(c.result), c.logins as u16, c.codes as u16, c.passkeys as u16);
                waiting.fetch_sub(1, Ordering::SeqCst);
                send(&usb, &send_lock, &frame::encode(kind, id, &body));
                continue;
            }
            Work::Bitcoin(id, request) => {
                let (kind, body) = bitcoin(&keys, request);
                waiting.fetch_sub(1, Ordering::SeqCst);
                send(&usb, &send_lock, &frame::encode(kind, id, &body));
                continue;
            }
            Work::Ethereum(id, request) => {
                let (kind, body) = ethereum(&keys, request);
                waiting.fetch_sub(1, Ordering::SeqCst);
                send(&usb, &send_lock, &frame::encode(kind, id, &body));
                continue;
            }
            Work::AppInstall { id, total, offset, data } => {
                let (kind, body) = app_install(app_host::AppHost::try_new(&xns), total, offset, data);
                waiting.fetch_sub(1, Ordering::SeqCst);
                send(&usb, &send_lock, &frame::encode(kind, id, &body));
                continue;
            }
            Work::AppRemove { id, app } => {
                let (kind, body) = match app_host::AppHost::try_new(&xns) {
                    Some(host) => reply::app_remove(app_approval(host.remove(&app))),
                    None => reply::app_remove(Approval::Unavailable),
                };
                waiting.fetch_sub(1, Ordering::SeqCst);
                send(&usb, &send_lock, &frame::encode(kind, id, &body));
                continue;
            }
            Work::AppMessage { id, app, message } => {
                let (kind, body) = match app_host::AppHost::try_new(&xns) {
                    Some(host) => {
                        let r = host.message(&app, message);
                        reply::app_message(app_approval(r.result), &r.answer)
                    }
                    None => reply::app_message(Approval::Unavailable, &[]),
                };
                waiting.fetch_sub(1, Ordering::SeqCst);
                send(&usb, &send_lock, &frame::encode(kind, id, &body));
                continue;
            }
        };
        let (kind, body) = match &ask {
            Ask::Login { site } => {
                let (approval, username, password) = vault.login(site);
                reply::login(approval, &username, &password)
            }
            Ask::Totp { site } => {
                let (approval, code, valid_for_s) = vault.totp(site);
                reply::totp(approval, &code, valid_for_s)
            }
            Ask::SaveLogin { site, username, password } => reply::save(vault.save_login(site, username, password)),
        };
        waiting.fetch_sub(1, Ordering::SeqCst);
        send(&usb, &send_lock, &frame::encode(kind, id, &body));
    }
}

/// A Bitcoin request, through maki-keys, which asks the owner where it must.
fn bitcoin(keys: &maki_keys::Keys, request: Bitcoin) -> (u8, Vec<u8>) {
    match request {
        Bitcoin::Account { network } => {
            let w = keys.btc_account(network, true);
            reply::btc_account(approval(w.result), &w.text, &w.descriptor)
        }
        Bitcoin::Address { network, change, index } => {
            let w = keys.btc_address(network, change, index, true);
            reply::btc_address(approval(w.result), &w.text)
        }
        Bitcoin::Sign { network, total, offset, data } => {
            let c = keys.btc_sign_chunk(network, total, offset, data);
            reply::btc_sign(c.done, approval(c.result), if c.done { c.total } else { 0 }, &c.reason)
        }
        Bitcoin::Signed { offset } => {
            let c = keys.btc_signed_chunk(offset);
            reply::btc_signed(approval(c.result), c.total, offset, &c.data)
        }
    }
}

/// An Ethereum request, through maki-keys, which asks the owner.
fn ethereum(keys: &maki_keys::Keys, request: Ethereum) -> (u8, Vec<u8>) {
    match request {
        Ethereum::Account { site, index } => {
            let r = keys.eth_account(&site, index, true);
            reply::eth_account(approval(r.result), &r.address)
        }
        Ethereum::Sign { site, index, total, offset, data } => {
            let c = keys.eth_sign_chunk(&site, index, total, offset, data);
            reply::eth_sign(c.done, approval(c.result), if c.done { c.total } else { 0 }, &c.reason)
        }
        Ethereum::Signed { offset } => {
            let c = keys.eth_signed_chunk(offset);
            reply::eth_signed(approval(c.result), c.total, offset, &c.data)
        }
        Ethereum::Message { site, index, message } => {
            let m = keys.eth_message(&site, index, &message);
            reply::eth_message(approval(m.result), &m.signature)
        }
        Ethereum::Typed { site, index, total, offset, data } => {
            let c = keys.eth_typed_chunk(&site, index, total, offset, data);
            reply::eth_typed(c.done, approval(c.result), &c.data, &c.reason)
        }
    }
}

/// Whether an Ethereum request waits for the owner: then the worker takes it.
fn eth_waits(request: &Ethereum) -> bool {
    match request {
        Ethereum::Account { .. } | Ethereum::Message { .. } => true,
        Ethereum::Sign { total, offset, data, .. } | Ethereum::Typed { total, offset, data, .. } => {
            *offset as usize + data.len() >= *total as usize
        }
        Ethereum::Signed { .. } => false,
    }
}

/// Whether a request waits for the owner: then the worker takes it.
fn waits(request: &Bitcoin) -> bool {
    match request {
        Bitcoin::Account { .. } | Bitcoin::Address { .. } => true,
        Bitcoin::Sign { total, offset, data, .. } => *offset as usize + data.len() >= *total as usize,
        Bitcoin::Signed { .. } => false,
    }
}

struct Badge {
    tt: ticktimer_server::Ticktimer,
    launcher: maki_launcher::Launcher,
    /// The clock's state, which a thread passes on to the app host (see `main`).
    time_state: Arc<AtomicU32>,
    #[cfg(feature = "board-baosec")]
    time_conn: xous::CID,
}

#[cfg(feature = "board-baosec")]
fn time_scalar(conn: xous::CID, op: bao1x_hal_service::api::TimeOp, hi: usize, lo: usize) -> Option<xous::Result> {
    xous::send_message(conn, xous::Message::new_blocking_scalar(op.to_usize().unwrap(), hi, lo, 0, 0)).ok()
}

impl Platform for Badge {
    fn fill_random(&mut self, buf: &mut [u8]) { getrandom::getrandom(buf).expect("TRNG unavailable"); }

    fn uptime_ms(&self) -> u64 { self.tt.elapsed_ms() }

    #[cfg(feature = "board-baosec")]
    fn utc_ms(&self) -> Option<u64> {
        use bao1x_hal_service::api::TimeOp;
        match time_scalar(self.time_conn, TimeOp::WallClockTimeInit, 0, 0) {
            Some(xous::Result::Scalar2(_, 1)) => {}
            _ => return None,
        }
        match time_scalar(self.time_conn, TimeOp::GetUtcTimeMs, 0, 0) {
            Some(xous::Result::Scalar2(lo, hi)) => Some(((hi as u64) << 32) | lo as u64),
            _ => None,
        }
    }

    #[cfg(not(feature = "board-baosec"))]
    fn utc_ms(&self) -> Option<u64> { None }

    fn set_time(&mut self, _utc_ms: u64, _tz_offset_s: i32) {
        // both calls take the high word first; the offset is signed milliseconds
        #[cfg(feature = "board-baosec")]
        {
            use bao1x_hal_service::api::TimeOp;
            let tz_ms = _tz_offset_s as i64 * 1000;
            time_scalar(self.time_conn, TimeOp::SetUtcTimeMs, (_utc_ms >> 32) as usize, _utc_ms as u32 as usize);
            time_scalar(self.time_conn, TimeOp::SetTzOffsetMs, (tz_ms >> 32) as u32 as usize, tz_ms as u32 as usize);
        }
    }

    fn time_state_changed(&mut self, state: TimeState) {
        log::info!("time is now {:?}", state);
        self.launcher.set_time_state(state as u8).ok();
        self.time_state.store(state as u32, Ordering::SeqCst);
    }
}

/// For the emulator's demos (MAKI_DEMO_APP, MAKI_DEMO_PERMS): the app host, once maki has
/// its PIN and phrase, and a minute after (so the work unlocking starts is done first).
fn demo_host() -> app_host::AppHost {
    let xns = xous_names::XousNames::new().unwrap();
    let keys = maki_keys::Keys::new(&xns).expect("maki-keys");
    keys.wait_phrase();
    ticktimer_server::Ticktimer::new().unwrap().sleep_ms(60_000).ok();
    log::warn!("demo: waiting for the app host");
    let host = app_host::AppHost::new(&xns).expect("the app host");
    log::warn!("demo: installing");
    host
}

/// A store record handed to the app host as maki desktop would, a piece at a time.
fn demo_store_update(host: &app_host::AppHost, bytes: &[u8]) -> app_host::StoreUpdate {
    let mut r = app_host::StoreUpdate::default();
    for (i, piece) in bytes.chunks(4096).enumerate() {
        r = host.store_update(bytes.len() as u32, (i * 4096) as u32, piece.to_vec());
        if r.done {
            break;
        }
    }
    r
}

/// A bundle handed to the app host as maki desktop would, a piece at a time.
fn demo_install(host: &app_host::AppHost, bytes: &[u8]) -> app_host::Install {
    let mut r = app_host::Install::default();
    for (i, piece) in bytes.chunks(4096).enumerate() {
        r = host.install(bytes.len() as u32, (i * 4096) as u32, piece.to_vec());
        if r.done {
            break;
        }
    }
    r
}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("maki-link PID is {}", xous::process::id());

    let xns = xous_names::XousNames::new().unwrap();
    let time_state = Arc::new(AtomicU32::new(0));
    let badge = Badge {
        tt: ticktimer_server::Ticktimer::new().unwrap(),
        launcher: maki_launcher::Launcher::new(&xns).expect("couldn't connect to the launcher"),
        time_state: time_state.clone(),
        #[cfg(feature = "board-baosec")]
        time_conn: xous::connect(xous::SID::from_bytes(bao1x_hal_service::api::TIME_SERVER_PUBLIC).unwrap())
            .unwrap(),
    };
    let mut device = Device::new(badge, "maki", env!("CARGO_PKG_VERSION").into());

    // "linked" means a valid frame arrived recently. The main loop raises it on contact; the
    // watcher lowers it when the host goes quiet, so both ends agree without extra messages.
    // No 64-bit atomics on this core: uptime is kept as wrapping u32 milliseconds (49 days).
    let last_contact = Arc::new(AtomicU32::new(0));
    let linked = Arc::new(AtomicBool::new(false));
    // Also tells the app host whether the time is verified (for apps): it may start after us,
    // or not be in the image at all, so connect when it appears and pass on every change. One
    // thread for both, with a small stack.
    std::thread::Builder::new().stack_size(32 * 1024).spawn({
        let (last_contact, linked, time_state) = (last_contact.clone(), linked.clone(), time_state.clone());
        move || {
            let xns = xous_names::XousNames::new().unwrap();
            let launcher = maki_launcher::Launcher::new(&xns).expect("couldn't connect to the launcher");
            let tt = ticktimer_server::Ticktimer::new().unwrap();
            let mut host = None;
            let mut told = u32::MAX;
            loop {
                // not often: when RAM is short, every wake-up pages this process back in
                tt.sleep_ms(5_000).ok();
                if host.is_none() {
                    host = app_host::AppHost::try_new(&xns);
                }
                let now = time_state.load(Ordering::SeqCst);
                if let Some(h) = host.filter(|_| now != told) {
                    h.set_time_state(now as u8);
                    told = now;
                }
                let quiet = (tt.elapsed_ms() as u32).wrapping_sub(last_contact.load(Ordering::SeqCst));
                if quiet > LINK_TIMEOUT_MS && linked.swap(false, Ordering::SeqCst) {
                    log::info!("desktop app gone quiet: unlinked");
                    launcher.set_link_state(false).ok();
                }
            }
        }
    })
    .unwrap();
    let tt = ticktimer_server::Ticktimer::new().unwrap();
    let launcher = maki_launcher::Launcher::new(&xns).expect("couldn't connect to the launcher");

    let keys = maki_keys::Keys::new(&xns).expect("couldn't connect to maki-keys");
    let send_lock = Arc::new(Mutex::new(()));
    let waiting = Arc::new(AtomicU32::new(0));
    let (to_vault, asks) = mpsc::channel::<Work>();
    std::thread::spawn({
        let (waiting, send_lock) = (waiting.clone(), send_lock.clone());
        move || vault_worker(asks, waiting, send_lock)
    });

    // The emulator has no USB. Built with MAKI_DEMO_ASKS set, maki-link queues a few requests
    // at boot as if the desktop app had sent them, so the approval screens can be seen and
    // pressed there. Never set for a badge.
    if option_env!("MAKI_DEMO_ASKS").is_some() {
        log::warn!("demo requests queued (MAKI_DEMO_ASKS build)");
        let demo = [
            Ask::SaveLogin { site: "github.com".into(), username: "kara".into(), password: "correct horse".into() },
            Ask::SaveLogin { site: "github.com".into(), username: "kara-work".into(), password: "battery staple".into() },
            Ask::Login { site: "gist.github.com".into() },
            Ask::SaveLogin {
                site: "accounts.a-rather-long-subdomain.login.example.co.uk".into(),
                username: "kara@example.com".into(),
                password: "pw".into(),
            },
        ];
        for (i, ask) in demo.into_iter().enumerate() {
            waiting.fetch_add(1, Ordering::SeqCst);
            to_vault.send(Work::Ask(0xd000 + i as u16, ask)).ok();
        }
    }

    // The emulator again: built with MAKI_DEMO_BACKUP, once maki is set up (PIN and phrase),
    // take a backup through maki-keys and restore it, and log how that went. The restore has
    // nothing new to add, so it asks nothing; it proves the sealing, the phrase's key and the
    // pieces on real firmware.
    if option_env!("MAKI_DEMO_BACKUP").is_some() {
        std::thread::spawn(|| {
            let xns = xous_names::XousNames::new().unwrap();
            let keys = maki_keys::Keys::new(&xns).expect("maki-keys");
            let tt = ticktimer_server::Ticktimer::new().unwrap();
            while !(keys.status().0 == maki_keys::State::Unlocked && keys.has_phrase()) {
                tt.sleep_ms(500).ok();
            }
            tt.sleep_ms(20_000).ok(); // let any demo asks be answered first
            let mut blob = Vec::new();
            let mut result;
            loop {
                let c = keys.backup_chunk(blob.len() as u32);
                result = c.result;
                if c.result != maki_keys::RESULT_OK {
                    break;
                }
                blob.extend_from_slice(&c.data);
                if blob.len() >= c.total as usize || c.data.is_empty() {
                    break;
                }
            }
            log::warn!("demo backup: {} bytes sealed (result {})", blob.len(), result);
            let mut offset = 0usize;
            loop {
                let end = (offset + maki_keys::CHUNK).min(blob.len());
                let c = keys.restore_chunk(blob.len() as u32, offset as u32, blob[offset..end].to_vec());
                offset = end;
                if c.done || c.result != maki_keys::RESULT_OK || offset >= blob.len() {
                    log::warn!(
                        "demo restore: result {} done {} ({} logins, {} codes, {} passkeys added)",
                        c.result,
                        c.done,
                        c.logins,
                        c.codes,
                        c.passkeys
                    );
                    break;
                }
            }
        });
    }

    // The emulator has no USB for maki desktop to install apps over. Built with MAKI_DEMO_APP,
    // once maki is unlocked, maki-link hands the app host two of the SDK's examples as if the
    // desktop had sent them (each asks the owner), then one changed after it was signed (which
    // maki refuses), and lists what's installed.
    if option_env!("MAKI_DEMO_APP").is_some() {
        std::thread::spawn(|| {
            let host = demo_host();
            let bundles: [(&str, &[u8]); 2] = [
                ("dice", include_bytes!("../../../libs/maki-wasm/tests/fixtures/dice.maki")),
                ("tally", include_bytes!("../../../libs/maki-wasm/tests/fixtures/tally.maki")),
            ];
            for (name, bytes) in bundles {
                let r = demo_install(&host, bytes);
                log::warn!("demo app install {name}: result {} '{}'", r.result, r.reason);
            }
            let mut tampered = include_bytes!("../../../libs/maki-wasm/tests/fixtures/hello.maki").to_vec();
            tampered[40] ^= 1;
            let r = demo_install(&host, &tampered);
            log::warn!(
                "demo app install tampered: result {} '{}', as expected: {}",
                r.result,
                r.reason,
                r.result == app_host::RESULT_REFUSED
            );
            let list = host.list();
            let names: Vec<String> = list.apps.iter().map(|a| format!("{} {}", a.id, a.version)).collect();
            log::warn!("demo app list: result {} {:?}", list.result, names);
        });
    }

    // The camera and the accelerometer: built with MAKI_DEMO_SENSORS, maki-link installs the
    // SDK's Sensors example (it asks, with a page for each). Opened, its level shows what the
    // accelerometer reads, and its centre scans a QR code (the emulator's camera shows one).
    if option_env!("MAKI_DEMO_SENSORS").is_some() {
        std::thread::spawn(|| {
            let host = demo_host();
            let r = demo_install(&host, include_bytes!("../../../libs/maki-wasm/tests/fixtures/sensors.maki"));
            log::warn!("demo sensors install: result {} '{}'", r.result, r.reason);
        });
    }

    // A native app: built with MAKI_DEMO_NATIVE, maki-link installs the SDK's Hello Native (the
    // Hello example built for maki's processor). Opened, it runs in a process of its own, loaded
    // by the stub and confined before its code runs, and talks to maki's app service.
    if option_env!("MAKI_DEMO_NATIVE").is_some() {
        std::thread::spawn(|| {
            let host = demo_host();
            let r = demo_install(&host, include_bytes!("../../../libs/maki-native/tests/fixtures/hello-native.maki"));
            log::warn!("demo native install: result {} '{}'", r.result, r.reason);
        });
    }

    // The permissions, the same way: built with MAKI_DEMO_PERMS, maki-link installs Signer and
    // SSH (each asks the owner, with a page for each permission), then does what maki desktop's
    // SSH agent does: asks the SSH app (started without the screen) for its key, then to sign
    // a sign-in, which it asks the owner about first.
    if option_env!("MAKI_DEMO_PERMS").is_some() {
        std::thread::spawn(|| {
            let host = demo_host();
            let bundles: [(&str, &[u8]); 2] = [
                ("signer", include_bytes!("../../../libs/maki-wasm/tests/fixtures/signer.maki")),
                ("ssh", include_bytes!("../../../libs/maki-wasm/tests/fixtures/ssh.maki")),
            ];
            for (name, bytes) in bundles {
                let r = demo_install(&host, bytes);
                log::warn!("demo perms install {name}: result {} '{}'", r.result, r.reason);
            }
            const SSH: &str = "com.leviathan.maki.ssh";
            let agent = |kind: u8, body: &[u8]| {
                let mut m = 1u32.to_be_bytes().to_vec();
                m.push(kind);
                m.extend_from_slice(body);
                m
            };
            let string = |out: &mut Vec<u8>, b: &[u8]| {
                out.extend_from_slice(&(b.len() as u32).to_be_bytes());
                out.extend_from_slice(b);
            };
            let r = host.message(SSH, agent(11, &[]));
            log::warn!("demo perms ssh keys: result {} answer {:02x?}", r.result, r.answer);
            // the key's blob, from the answer: type 12, one key, its blob
            let blob = r.answer.get(9..9 + 51).map(|b| b.to_vec()).unwrap_or_default();
            let mut data = Vec::new();
            string(&mut data, &[0xaa; 32]);
            data.push(50);
            string(&mut data, b"kara");
            string(&mut data, b"ssh-connection");
            string(&mut data, b"publickey");
            data.push(1);
            string(&mut data, b"ssh-ed25519");
            string(&mut data, &blob);
            let mut body = Vec::new();
            string(&mut body, &blob);
            string(&mut body, &data);
            body.extend_from_slice(&0u32.to_be_bytes());
            let r = host.message(SSH, agent(13, &body));
            log::warn!(
                "demo perms ssh sign: result {}, {} bytes, a signature: {}",
                r.result,
                r.answer.len(),
                r.answer.first() == Some(&14)
            );
        });
    }

    // The maki store: built with MAKI_DEMO_STORE, maki-link does what maki desktop does with
    // the development store (libs/maki-store/dev-store) once linked. It sets maki's clock and
    // calls it verified (standing in for the Roughtime sync, which needs the desktop's network),
    // hands over root 2, which replaces the catalogue key, installs Sensors from the store
    // (stamped: "maki store") and Tally sideloaded, then hands over the revocation list, which
    // revokes Tally: maki warns before opening it, and won't install it again.
    if option_env!("MAKI_DEMO_STORE").is_some() {
        let time_state = time_state.clone();
        std::thread::spawn(move || {
            let host = demo_host();
            // a day after the development store was made
            const DEMO_UTC_MS: u64 = 1_790_600_000_000;
            #[cfg(feature = "board-baosec")]
            {
                use bao1x_hal_service::api::{TimeOp, TIME_SERVER_PUBLIC};
                let conn = xous::connect(xous::SID::from_bytes(TIME_SERVER_PUBLIC).unwrap()).unwrap();
                time_scalar(conn, TimeOp::SetUtcTimeMs, (DEMO_UTC_MS >> 32) as usize, DEMO_UTC_MS as u32 as usize);
            }
            time_state.store(TimeState::Verified as u32, Ordering::SeqCst);
            host.set_time_state(TimeState::Verified as u8);
            let xns = xous_names::XousNames::new().unwrap();
            maki_launcher::Launcher::new(&xns).unwrap().set_time_state(TimeState::Verified as u8).ok();
            log::warn!("demo store: clock set and called verified");

            let r = demo_store_update(&host, include_bytes!("../../../libs/maki-store/dev-store/roots/2.bin"));
            log::warn!("demo store root 2: result {} '{}', root now {}", r.result, r.reason, r.root_version);
            let bundles: [(&str, &[u8]); 2] = [
                (
                    "sensors from the store",
                    include_bytes!("../../../libs/maki-store/dev-store/apps/com.leviathan.maki.sensors/1.maki"),
                ),
                ("tally sideloaded", include_bytes!("../../../libs/maki-wasm/tests/fixtures/tally.maki")),
            ];
            for (name, bytes) in bundles {
                let r = demo_install(&host, bytes);
                log::warn!("demo store install {name}: result {} '{}'", r.result, r.reason);
            }
            let r = demo_store_update(&host, include_bytes!("../../../libs/maki-store/dev-store/revocations.bin"));
            log::warn!(
                "demo store revocations: result {} '{}', list {} until {}",
                r.result,
                r.reason,
                r.revocations_version,
                r.revocations_expires
            );
            // the same list again: nothing newer
            let r = demo_store_update(&host, include_bytes!("../../../libs/maki-store/dev-store/revocations.bin"));
            log::warn!("demo store revocations again: result {} '{}'", r.result, r.reason);
            let r = demo_install(&host, include_bytes!("../../../libs/maki-wasm/tests/fixtures/tally.maki"));
            log::warn!("demo store install tally again: result {} '{}'", r.result, r.reason);
            let list = host.list();
            let names: Vec<String> = list.apps.iter().map(|a| format!("{} store: {}", a.id, a.from_store)).collect();
            log::warn!("demo store list: {:?}", names);
        });
    }

    // The emulator again: built with MAKI_DEMO_BTC, once maki is unlocked with a phrase, go
    // through what the desktop's wallet section does, as maki-link would for it: share the
    // account, show an address, and sign a PSBT, then check the signature against the one maki's
    // wallet code makes on a computer. The PSBT is the test phrase's ("abandon" eleven times,
    // then "about"): restore that phrase at setup, or signing is refused as not this wallet's.
    if option_env!("MAKI_DEMO_BTC").is_some() {
        std::thread::spawn(|| {
            let unsigned: &[u8] = include_bytes!("../../../libs/maki-btc/tests/fixtures/abandon-unsigned.psbt");
            let expected: &[u8] = include_bytes!("../../../libs/maki-btc/tests/fixtures/abandon-signed.psbt");
            let xns = xous_names::XousNames::new().unwrap();
            let keys = maki_keys::Keys::new(&xns).expect("maki-keys");
            let tt = ticktimer_server::Ticktimer::new().unwrap();
            while !(keys.status().0 == maki_keys::State::Unlocked && keys.has_phrase()) {
                tt.sleep_ms(500).ok();
            }
            tt.sleep_ms(3_000).ok();
            let w = keys.btc_account(maki_keys::NETWORK_BITCOIN, true);
            log::warn!("demo btc account: result {} {} {}", w.result, w.text, w.descriptor);
            let w = keys.btc_address(maki_keys::NETWORK_BITCOIN, false, 0, true);
            log::warn!("demo btc address: result {} {}", w.result, w.text);
            let mut c = maki_keys::Chunk::default();
            let mut offset = 0;
            while offset < unsigned.len() {
                let end = (offset + maki_keys::CHUNK).min(unsigned.len());
                c = keys.btc_sign_chunk(
                    maki_keys::NETWORK_BITCOIN,
                    unsigned.len() as u32,
                    offset as u32,
                    unsigned[offset..end].to_vec(),
                );
                offset = end;
                if c.done {
                    break;
                }
            }
            log::warn!("demo btc sign: result {} total {} reason '{}'", c.result, c.total, c.reason);
            if c.result == maki_keys::RESULT_OK {
                let mut signed = Vec::new();
                while signed.len() < c.total as usize {
                    let p = keys.btc_signed_chunk(signed.len() as u32);
                    if p.result != maki_keys::RESULT_OK || p.data.is_empty() {
                        break;
                    }
                    signed.extend_from_slice(&p.data);
                }
                log::warn!("demo btc signed: {} bytes, as expected: {}", signed.len(), signed == expected);
            }
        });
    }

    // The emulator again: built with MAKI_DEMO_ETH, once maki is unlocked with a phrase, do what
    // the browser extension's Ethereum provider does for a site, "demo.maki": connect, sign a
    // message, sign a transaction (0.05 ETH on Ethereum), and sign typed data (a permit for 1
    // USDC), then check the signatures against the ones maki's code makes on a computer for the
    // BIP39 test phrase: restore that at setup.
    if option_env!("MAKI_DEMO_ETH").is_some() {
        std::thread::spawn(|| {
            let unsigned: &[u8] = include_bytes!("../../../libs/maki-eth/tests/fixtures/abandon-tx-unsigned.bin");
            let expected: &[u8] = include_bytes!("../../../libs/maki-eth/tests/fixtures/abandon-tx-signed.bin");
            let expected_sig: &[u8] = include_bytes!("../../../libs/maki-eth/tests/fixtures/abandon-message.sig");
            let xns = xous_names::XousNames::new().unwrap();
            let keys = maki_keys::Keys::new(&xns).expect("maki-keys");
            let tt = ticktimer_server::Ticktimer::new().unwrap();
            while !(keys.status().0 == maki_keys::State::Unlocked && keys.has_phrase()) {
                tt.sleep_ms(500).ok();
            }
            tt.sleep_ms(3_000).ok();
            let a = keys.eth_account("demo.maki", 0, true);
            log::warn!("demo eth account: result {} {}", a.result, a.address);
            let m = keys.eth_message("demo.maki", 0, b"Sign in to demo.maki");
            log::warn!("demo eth message: result {}, as expected: {}", m.result, m.signature == expected_sig);
            let c = keys.eth_sign_chunk("demo.maki", 0, unsigned.len() as u32, 0, unsigned.to_vec());
            log::warn!("demo eth sign: result {} total {} reason '{}'", c.result, c.total, c.reason);
            if c.result == maki_keys::RESULT_OK {
                let p = keys.eth_signed_chunk(0);
                log::warn!("demo eth signed: {} bytes, as expected: {}", p.data.len(), p.data == expected);
            }
            let typed: &[u8] = include_bytes!("../../../libs/maki-eth/tests/fixtures/abandon-typed.json");
            let typed_sig: &[u8] = include_bytes!("../../../libs/maki-eth/tests/fixtures/abandon-typed.sig");
            let t = keys.eth_typed_chunk("demo.maki", 0, typed.len() as u32, 0, typed.to_vec());
            log::warn!("demo eth typed: result {}, as expected: {} reason '{}'", t.result, t.data == typed_sig, t.reason);
        });
    }

    let usb = usb_bao1x::UsbHid::new();
    let mut deframer = Deframer::default();
    loop {
        // returns as soon as anything arrives, including bytes queued while we were busy
        let data = usb.serial_wait_binary();
        for packet in deframer.push(&data) {
            match packet {
                Ok(packet) => {
                    last_contact.store(tt.elapsed_ms() as u32, Ordering::SeqCst);
                    if !linked.swap(true, Ordering::SeqCst) {
                        log::info!("desktop app linked");
                        launcher.set_link_state(true).ok();
                    }
                    let (kind, body) = match device.handle(&packet) {
                        Handled::Reply(kind, body) => (kind, body),
                        // the backup: maki-keys seals it, and says if maki is locked or has no phrase
                        Handled::Backup(Backup::Get { offset }) => {
                            let c = keys.backup_chunk(offset);
                            reply::backup_piece(approval(c.result), c.total, offset, &c.data)
                        }
                        Handled::Backup(Backup::Put { total, offset, data }) => {
                            if offset as usize + data.len() < total as usize {
                                let c = keys.restore_chunk(total, offset, data);
                                reply::restore_piece(c.done, approval(c.result), 0, 0, 0)
                            } else if waiting.fetch_add(1, Ordering::SeqCst) >= MAX_WAITING_ASKS {
                                waiting.fetch_sub(1, Ordering::SeqCst);
                                reply::restore_piece(true, Approval::Unavailable, 0, 0, 0)
                            } else {
                                // the last piece asks the owner: the worker answers
                                match to_vault.send(Work::Restore { id: packet.id, total, offset, data }) {
                                    Ok(()) => continue,
                                    Err(_) => {
                                        waiting.fetch_sub(1, Ordering::SeqCst);
                                        reply::restore_piece(true, Approval::Unavailable, 0, 0, 0)
                                    }
                                }
                            }
                        }
                        Handled::Apps(Apps::List { index }) => app_list(app_host::AppHost::try_new(&xns), index),
                        Handled::Apps(Apps::StoreUpdate { total, offset, data }) => {
                            store_update(app_host::AppHost::try_new(&xns), total, offset, data)
                        }
                        // pieces go straight to the host; the last one waits for the owner
                        Handled::Apps(Apps::Install { total, offset, data })
                            if offset as usize + data.len() < total as usize =>
                        {
                            app_install(app_host::AppHost::try_new(&xns), total, offset, data)
                        }
                        Handled::Apps(request) => {
                            // the reply if it can't be done now, of the request's own kind
                            let unavailable = match &request {
                                Apps::Remove { .. } => reply::app_remove(Approval::Unavailable),
                                Apps::Message { .. } => reply::app_message(Approval::Unavailable, &[]),
                                _ => reply::app_install(true, Approval::Unavailable, ""),
                            };
                            if waiting.fetch_add(1, Ordering::SeqCst) >= MAX_WAITING_ASKS {
                                waiting.fetch_sub(1, Ordering::SeqCst);
                                log::warn!("too many requests waiting on the owner");
                                unavailable
                            } else {
                                let work = match request {
                                    Apps::Install { total, offset, data } => {
                                        Work::AppInstall { id: packet.id, total, offset, data }
                                    }
                                    Apps::Remove { id } => Work::AppRemove { id: packet.id, app: id },
                                    Apps::Message { id, message } => Work::AppMessage { id: packet.id, app: id, message },
                                    Apps::List { .. } | Apps::StoreUpdate { .. } => unreachable!(),
                                };
                                match to_vault.send(work) {
                                    Ok(()) => continue,
                                    Err(_) => {
                                        log::error!("the worker is gone");
                                        waiting.fetch_sub(1, Ordering::SeqCst);
                                        unavailable
                                    }
                                }
                            }
                        }
                        Handled::Bitcoin(request) if !waits(&request) => bitcoin(&keys, request),
                        Handled::Bitcoin(request) => {
                            if waiting.fetch_add(1, Ordering::SeqCst) >= MAX_WAITING_ASKS {
                                waiting.fetch_sub(1, Ordering::SeqCst);
                                log::warn!("too many requests waiting on the owner");
                                match request {
                                    Bitcoin::Account { .. } => reply::btc_account(Approval::Unavailable, "", ""),
                                    Bitcoin::Address { .. } => reply::btc_address(Approval::Unavailable, ""),
                                    _ => reply::btc_sign(true, Approval::Unavailable, 0, ""),
                                }
                            } else {
                                match to_vault.send(Work::Bitcoin(packet.id, request)) {
                                    Ok(()) => continue,
                                    Err(_) => {
                                        log::error!("the worker is gone");
                                        waiting.fetch_sub(1, Ordering::SeqCst);
                                        reply::btc_sign(true, Approval::Unavailable, 0, "")
                                    }
                                }
                            }
                        }
                        Handled::Ethereum(request) if !eth_waits(&request) => ethereum(&keys, request),
                        Handled::Ethereum(request) => {
                            let busy = |request: &Ethereum| match request {
                                Ethereum::Account { .. } => reply::eth_account(Approval::Unavailable, ""),
                                Ethereum::Message { .. } => reply::eth_message(Approval::Unavailable, &[]),
                                Ethereum::Typed { .. } => reply::eth_typed(true, Approval::Unavailable, &[], ""),
                                _ => reply::eth_sign(true, Approval::Unavailable, 0, ""),
                            };
                            if waiting.fetch_add(1, Ordering::SeqCst) >= MAX_WAITING_ASKS {
                                waiting.fetch_sub(1, Ordering::SeqCst);
                                log::warn!("too many requests waiting on the owner");
                                busy(&request)
                            } else {
                                match to_vault.send(Work::Ethereum(packet.id, request)) {
                                    Ok(()) => continue,
                                    Err(mpsc::SendError(Work::Ethereum(_, request))) => {
                                        log::error!("the worker is gone");
                                        waiting.fetch_sub(1, Ordering::SeqCst);
                                        busy(&request)
                                    }
                                    Err(_) => unreachable!(),
                                }
                            }
                        }
                        // nothing is asked of a maki that hasn't had its PIN
                        Handled::Ask(ask) if keys.status().0 != maki_keys::State::Unlocked => locked(&ask),
                        Handled::Ask(ask) => {
                            if waiting.fetch_add(1, Ordering::SeqCst) >= MAX_WAITING_ASKS {
                                waiting.fetch_sub(1, Ordering::SeqCst);
                                log::warn!("too many requests waiting on the owner");
                                unavailable(&ask)
                            } else {
                                match to_vault.send(Work::Ask(packet.id, ask)) {
                                    // the worker answers, once the owner decides
                                    Ok(()) => continue,
                                    Err(mpsc::SendError(Work::Ask(_, ask))) => {
                                        log::error!("the vault worker is gone");
                                        waiting.fetch_sub(1, Ordering::SeqCst);
                                        unavailable(&ask)
                                    }
                                    Err(_) => unreachable!(),
                                }
                            }
                        }
                    };
                    send(&usb, &send_lock, &frame::encode(kind, packet.id, &body));
                }
                Err(e) => log::warn!("dropped a bad frame: {:?}", e),
            }
        }
    }
}
