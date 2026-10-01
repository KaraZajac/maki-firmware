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
    AppEntry, AppSpace, Approval, Apps, Ask, Backup, Device, Handled, Platform, StoreState, TimeState, reply,
};
use maki_proto::frame::{self, Deframer};
use num_traits::ToPrimitive;

/// The desktop app sends a heartbeat every 10 s; this long without a valid frame means it's gone.
const LINK_TIMEOUT_MS: u32 = 25_000;
/// Requests for the owner that may wait at once; more are turned away as unavailable.
const MAX_WAITING_ASKS: u32 = 3;

/// Send a whole frame. Replies come from two threads, so the lock keeps frames from
/// interleaving if the USB side takes one in pieces. Each starts with a delimiter (an empty frame
/// to the host, which skips it): if one before was given up halfway, its piece ends there rather
/// than spoiling this one too.
fn send(usb: &usb_bao1x::UsbHid, lock: &Mutex<()>, frame: &[u8]) {
    let _guard = lock.lock().unwrap();
    let mut bytes = Vec::with_capacity(frame.len() + 1);
    bytes.push(0);
    bytes.extend_from_slice(frame);
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
        Ask::UpdateMode { .. } => reply::update_mode(why),
    }
}

fn unavailable(ask: &Ask) -> (u8, Vec<u8>) { refused(ask, Approval::Unavailable) }

fn locked(ask: &Ask) -> (u8, Vec<u8>) { refused(ask, Approval::Locked) }

/// What the worker does: a request for the owner, the last piece of a restore (which asks the
/// owner too), an app to install or remove, or a message for an app (which may ask the owner
/// before it answers: wallet apps among them).
enum Work {
    Ask(u16, Ask),
    /// The last piece of a restore, or of a bundle: `tail` is up while it waits, and goes down
    /// once it's been answered (see `restore_tail` in `main`)
    Restore {
        id: u16,
        total: u32,
        offset: u32,
        data: Vec<u8>,
        tail: Arc<AtomicBool>,
    },
    AppInstall {
        id: u16,
        total: u32,
        offset: u32,
        data: Vec<u8>,
        tail: Arc<AtomicBool>,
    },
    AppRemove {
        id: u16,
        app: String,
    },
    AppMessage {
        id: u16,
        app: String,
        message: Vec<u8>,
    },
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
        bundle: a.bundle,
        storage: a.storage,
    });
    reply::app_list(Approval::Approved, list.apps.len() as u32, entry.as_ref())
}

/// maki's room for apps, and what the ones installed take of it.
fn app_space(host: Option<app_host::AppHost>) -> (u8, Vec<u8>) {
    let Some(host) = host else { return reply::app_space(Approval::Unavailable, &AppSpace::default()) };
    let list = host.list();
    if list.result != app_host::RESULT_OK {
        return reply::app_space(app_approval(list.result), &AppSpace::default());
    }
    let space = AppSpace {
        apps: list.apps.len() as u32,
        max_apps: app_host::MAX_APPS as u32,
        space: app_host::APP_SPACE,
        taken: list.apps.iter().map(|a| a.bundle + a.storage).sum(),
    };
    reply::app_space(Approval::Approved, &space)
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
            Work::Restore { id, total, offset, data, tail } => {
                let c = keys.restore_chunk(total, offset, data);
                tail.store(false, Ordering::SeqCst);
                let (kind, body) = reply::restore_piece(
                    true,
                    approval(c.result),
                    c.logins as u16,
                    c.codes as u16,
                    c.passkeys as u16,
                );
                waiting.fetch_sub(1, Ordering::SeqCst);
                send(&usb, &send_lock, &frame::encode(kind, id, &body));
                continue;
            }
            Work::AppInstall { id, total, offset, data, tail } => {
                let (kind, body) = app_install(app_host::AppHost::try_new(&xns), total, offset, data);
                tail.store(false, Ordering::SeqCst);
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
            Ask::Login { site, even_with_passkey } => {
                let (approval, username, password) = vault.login(site, *even_with_passkey);
                reply::login(approval, &username, &password)
            }
            Ask::Totp { site } => {
                let (approval, code, valid_for_s) = vault.totp(site);
                reply::totp(approval, &code, valid_for_s)
            }
            Ask::SaveLogin { site, username, password } => {
                reply::save(vault.save_login(site, username, password))
            }
            // maki-keys asks the owner, and restarts maki once this answer has gone
            Ask::UpdateMode { label } => reply::update_mode(approval(keys.update_mode(label))),
        };
        waiting.fetch_sub(1, Ordering::SeqCst);
        send(&usb, &send_lock, &frame::encode(kind, id, &body));
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
fn time_scalar(
    conn: xous::CID,
    op: bao1x_hal_service::api::TimeOp,
    hi: usize,
    lo: usize,
) -> Option<xous::Result> {
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
            time_scalar(
                self.time_conn,
                TimeOp::SetUtcTimeMs,
                (_utc_ms >> 32) as usize,
                _utc_ms as u32 as usize,
            );
            time_scalar(
                self.time_conn,
                TimeOp::SetTzOffsetMs,
                (tz_ms >> 32) as u32 as usize,
                tz_ms as u32 as usize,
            );
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
    // this maki's own name, which HELLO gives the computer (maki-keys answers once the PDDB is
    // mounted: the first time, it picks one)
    let name = maki_keys::Keys::new(&xns).map(|k| k.device_name()).unwrap_or_else(|_| "maki".into());
    log::info!("this maki is {name}");
    // the firmware's build, as `git describe` named it when it was built (xtask): maki desktop
    // tells from it whether there's newer firmware
    let build = badge.tt.get_version().lines().next().unwrap_or_default().trim().to_string();
    let version = if build.is_empty() { env!("CARGO_PKG_VERSION").to_string() } else { build };
    log::info!("this firmware is {version}");
    let mut device = Device::new(badge, name, version);

    // "linked" means a valid frame arrived recently. The main loop raises it on contact; the
    // watcher lowers it when the host goes quiet, so both ends agree without extra messages.
    // No 64-bit atomics on this core: uptime is kept as wrapping u32 milliseconds (49 days).
    let last_contact = Arc::new(AtomicU32::new(0));
    let linked = Arc::new(AtomicBool::new(false));
    // Also tells the app host whether the time is verified (for apps): it may start after us,
    // or not be in the image at all, so connect when it appears and pass on every change. One
    // thread for both, with a small stack.
    std::thread::Builder::new()
        .stack_size(32 * 1024)
        .spawn({
            let (last_contact, linked, time_state) =
                (last_contact.clone(), linked.clone(), time_state.clone());
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
    // A restore's or a bundle's last piece waits in the worker's queue, maybe behind an ask; a
    // host that gave up meanwhile and starts again would have its new pieces spoiled when the old
    // last one arrives (out of order, so both are dropped). While one waits, the pieces of
    // another are turned away as unavailable: the host tries again later.
    let restore_tail = Arc::new(AtomicBool::new(false));
    // maki's lock state, followed by a thread that waits on maki-keys for each change: the link's
    // loop never waits on maki-keys to know it, which a long job there (a Monero signature) would
    // otherwise make it, the heartbeats with it
    let unlocked = Arc::new(AtomicBool::new(false));
    std::thread::spawn({
        let unlocked = unlocked.clone();
        move || {
            let xns = xous_names::XousNames::new().unwrap();
            let keys = maki_keys::Keys::new(&xns).expect("couldn't connect to maki-keys");
            let mut seen = keys.status().0;
            loop {
                unlocked.store(seen == maki_keys::State::Unlocked, Ordering::SeqCst);
                let now = keys.wait_change(seen);
                if now == seen {
                    // maki-keys couldn't be waited on: not a busy loop
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
                seen = now;
            }
        }
    });
    let install_tail = Arc::new(AtomicBool::new(false));
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
            Ask::SaveLogin {
                site: "github.com".into(),
                username: "kara".into(),
                password: "correct horse".into(),
            },
            Ask::SaveLogin {
                site: "github.com".into(),
                username: "kara-work".into(),
                password: "battery staple".into(),
            },
            Ask::Login { site: "gist.github.com".into(), even_with_passkey: false },
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

    // Update mode, in the emulator: built with MAKI_DEMO_UPDATE, once maki is unlocked, maki-link
    // asks maki-keys to restart into update mode as if maki desktop had, so the question can be
    // seen and answered there, and the restart (and the flag cleared at the next start) logged.
    if option_env!("MAKI_DEMO_UPDATE").is_some() {
        let to_vault = to_vault.clone();
        let waiting = waiting.clone();
        std::thread::spawn(move || {
            let xns = xous_names::XousNames::new().unwrap();
            let keys = maki_keys::Keys::new(&xns).expect("maki-keys");
            keys.wait_unlocked();
            log::warn!("demo update: asking to restart into update mode");
            waiting.fetch_add(1, Ordering::SeqCst);
            to_vault.send(Work::Ask(0xd100, Ask::UpdateMode { label: "preview-2026-10-01".into() })).ok();
        });
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
            let r =
                demo_install(&host, include_bytes!("../../../libs/maki-wasm/tests/fixtures/sensors.maki"));
            log::warn!("demo sensors install: result {} '{}'", r.result, r.reason);
        });
    }

    // The newest examples: built with MAKI_DEMO_EXAMPLES, maki-link installs the SDK's Status (a
    // sign in big letters it draws itself, with the link permission) and Passphrase (words from
    // the EFF's list, with the keyboard permission); each asks, with a page for its permission.
    if option_env!("MAKI_DEMO_EXAMPLES").is_some() {
        std::thread::spawn(|| {
            let host = demo_host();
            let bundles: [(&str, &[u8]); 2] = [
                ("status", include_bytes!("../../../libs/maki-wasm/tests/fixtures/status.maki")),
                ("passphrase", include_bytes!("../../../libs/maki-wasm/tests/fixtures/passphrase.maki")),
            ];
            for (name, bytes) in bundles {
                let r = demo_install(&host, bytes);
                log::warn!("demo examples install {name}: result {} '{}'", r.result, r.reason);
            }
        });
    }

    // More apps than one answer to a list holds: built with MAKI_DEMO_MANY, maki-link installs
    // every WebAssembly example in `libs/maki-wasm/tests/fixtures` (each asks), then lists them,
    // and asks for the last one as maki desktop's Apps page does, one at a time.
    if option_env!("MAKI_DEMO_MANY").is_some() {
        std::thread::spawn(|| {
            let host = demo_host();
            let bundles: [(&str, &[u8]); 23] = [
                ("age", include_bytes!("../../../libs/maki-wasm/tests/fixtures/age.maki")),
                ("bitcoin", include_bytes!("../../../libs/maki-wasm/tests/fixtures/bitcoin.maki")),
                ("breakout", include_bytes!("../../../libs/maki-wasm/tests/fixtures/breakout.maki")),
                ("contacts", include_bytes!("../../../libs/maki-wasm/tests/fixtures/contacts.maki")),
                ("dice", include_bytes!("../../../libs/maki-wasm/tests/fixtures/dice.maki")),
                ("ethereum", include_bytes!("../../../libs/maki-wasm/tests/fixtures/ethereum.maki")),
                ("hello", include_bytes!("../../../libs/maki-wasm/tests/fixtures/hello.maki")),
                ("marble", include_bytes!("../../../libs/maki-wasm/tests/fixtures/marble.maki")),
                ("minisign", include_bytes!("../../../libs/maki-wasm/tests/fixtures/minisign.maki")),
                ("monero", include_bytes!("../../../libs/maki-wasm/tests/fixtures/monero.maki")),
                ("nostr", include_bytes!("../../../libs/maki-wasm/tests/fixtures/nostr.maki")),
                ("notes", include_bytes!("../../../libs/maki-wasm/tests/fixtures/notes.maki")),
                ("openpgp", include_bytes!("../../../libs/maki-wasm/tests/fixtures/openpgp.maki")),
                ("passphrase", include_bytes!("../../../libs/maki-wasm/tests/fixtures/passphrase.maki")),
                ("scanner", include_bytes!("../../../libs/maki-wasm/tests/fixtures/scanner.maki")),
                ("sensors", include_bytes!("../../../libs/maki-wasm/tests/fixtures/sensors.maki")),
                ("signer", include_bytes!("../../../libs/maki-wasm/tests/fixtures/signer.maki")),
                ("snake", include_bytes!("../../../libs/maki-wasm/tests/fixtures/snake.maki")),
                ("solana", include_bytes!("../../../libs/maki-wasm/tests/fixtures/solana.maki")),
                ("ssh", include_bytes!("../../../libs/maki-wasm/tests/fixtures/ssh.maki")),
                ("status", include_bytes!("../../../libs/maki-wasm/tests/fixtures/status.maki")),
                ("tally", include_bytes!("../../../libs/maki-wasm/tests/fixtures/tally.maki")),
                ("wifi", include_bytes!("../../../libs/maki-wasm/tests/fixtures/wifi.maki")),
            ];
            for (name, bytes) in bundles {
                let r = demo_install(&host, bytes);
                log::warn!("demo many install {name}: result {} '{}'", r.result, r.reason);
            }
            let list = host.list();
            log::warn!(
                "demo many list: result {}, {} of {} apps, as expected: {}",
                list.result,
                list.apps.len(),
                list.total,
                list.result == app_host::RESULT_OK && list.apps.len() == bundles.len()
            );
            let names: Vec<&str> = list.apps.iter().map(|a| a.name.as_str()).collect();
            log::warn!("demo many names: {names:?}");
            let xns = xous_names::XousNames::new().unwrap();
            let (kind, reply) = app_list(app_host::AppHost::new(&xns).ok(), bundles.len() as u32 - 1);
            log::warn!(
                "demo many last: reply {kind:#04x}, {} bytes, approved: {}",
                reply.len(),
                reply.first() == Some(&(Approval::Approved as u8))
            );
        });
    }

    // A native app: built with MAKI_DEMO_NATIVE, maki-link installs the SDK's Hello Native (the
    // Hello example built for maki's processor). Opened, it runs in a process of its own, loaded
    // by the stub and confined before its code runs, and talks to maki's app service.
    if option_env!("MAKI_DEMO_NATIVE").is_some() {
        std::thread::spawn(|| {
            let host = demo_host();
            let r = demo_install(
                &host,
                include_bytes!("../../../libs/maki-native/tests/fixtures/hello-native.maki"),
            );
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

    // The wallets: built with MAKI_DEMO_WALLET, once maki has its PIN and phrase, maki-link
    // installs the SDK's Bitcoin, Ethereum, Monero and Solana apps (each asks, with a page for each
    // permission; the wallet's names the accounts it may sign for), then does what maki desktop
    // does with them: shares the Bitcoin account, shows address #0 to compare, has the fixture PSBT
    // reviewed and signed and checks it against the one maki's wallet code makes on a computer,
    // then the same for the taproot account; then connects a site, demo.maki, to the Ethereum
    // app, and has it sign a message, a transaction (0.05 ETH on Ethereum) and typed data (a
    // permit to spend 1 USDC), each checked the same way; then the Monero app shows three of its
    // addresses to compare, checked against Ledger's and monero-python's, and spends; then the
    // Solana app connects demo.maki and signs a USDC payment, checked against web3.js's
    // signature. The fixtures belong to the BIP39 test phrase: restore that at setup. It logs
    // `demo wallet ...` lines.
    if option_env!("MAKI_DEMO_WALLET").is_some() {
        std::thread::spawn(|| {
            const BTC: &str = "com.leviathan.maki.bitcoin";
            const ETH: &str = "com.leviathan.maki.ethereum";
            let host = demo_host();
            const XMR: &str = "com.leviathan.maki.monero";
            const SOL: &str = "com.leviathan.maki.solana";
            let bundles: [(&str, &[u8]); 4] = [
                ("bitcoin", include_bytes!("../../../libs/maki-wasm/tests/fixtures/bitcoin.maki")),
                ("ethereum", include_bytes!("../../../libs/maki-wasm/tests/fixtures/ethereum.maki")),
                ("monero", include_bytes!("../../../libs/maki-wasm/tests/fixtures/monero.maki")),
                ("solana", include_bytes!("../../../libs/maki-wasm/tests/fixtures/solana.maki")),
            ];
            for (name, bytes) in bundles {
                let r = demo_install(&host, bytes);
                log::warn!("demo wallet install {name}: result {} '{}'", r.result, r.reason);
            }
            // an answer's strings, after its status: each a u16 length, then the bytes
            let texts = |a: &[u8]| -> Vec<String> {
                let (mut out, mut i) = (Vec::new(), 1);
                while let Some(n) = a.get(i..i + 2).map(|n| u16::from_le_bytes([n[0], n[1]]) as usize) {
                    let Some(s) = a.get(i + 2..i + 2 + n) else { break };
                    out.push(String::from_utf8_lossy(s).into_owned());
                    i += 2 + n;
                }
                out
            };
            let ask = |id: &str, m: Vec<u8>| {
                let r = host.message(id, m);
                if r.result == app_host::RESULT_OK { r.answer } else { vec![0xf0 | r.result as u8] }
            };
            // something big, in the pieces maki desktop sends: `head`, the total and the
            // offset, `tail`, then the piece; the last piece's answer
            let pieces = |id: &str, head: &[u8], tail: &[u8], bytes: &[u8]| -> Vec<u8> {
                let mut last = Vec::new();
                for (i, piece) in bytes.chunks(4000).enumerate() {
                    let mut m = head.to_vec();
                    m.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                    m.extend_from_slice(&((i * 4000) as u32).to_le_bytes());
                    m.extend_from_slice(tail);
                    m.extend_from_slice(piece);
                    last = ask(id, m);
                    // 6: taken, send the next
                    if last.first() != Some(&6) {
                        break;
                    }
                }
                last
            };
            // what was signed, fetched a piece at a time: None if it wasn't
            let signed = |id: &str, answer: &[u8]| -> Option<Vec<u8>> {
                let total = match answer {
                    [0, n @ ..] if n.len() == 4 => u32::from_le_bytes(n.try_into().unwrap()) as usize,
                    _ => return None,
                };
                let mut out = Vec::new();
                while out.len() < total {
                    let a = ask(id, [&[b'G'][..], &(out.len() as u32).to_le_bytes()].concat());
                    if a.len() <= 9 || a[0] != 0 {
                        return None;
                    }
                    out.extend_from_slice(&a[9..]);
                }
                Some(out)
            };

            let unsigned: &[u8] =
                include_bytes!("../../../libs/maki-btc/tests/fixtures/abandon-unsigned.psbt");
            let expected: &[u8] = include_bytes!("../../../libs/maki-btc/tests/fixtures/abandon-signed.psbt");
            let tap_unsigned: &[u8] =
                include_bytes!("../../../libs/maki-btc/tests/fixtures/abandon-taproot-unsigned.psbt");
            let tap_expected: &[u8] =
                include_bytes!("../../../libs/maki-btc/tests/fixtures/abandon-taproot-signed.psbt");
            // taproot's signatures take fresh randomness: compare all but them (a key
            // signature's pair: key 0x13, 64 bytes)
            let blank = |b: &[u8]| {
                let (mut v, mut i) = (b.to_vec(), 0);
                while i + 3 + 64 <= v.len() {
                    if v[i..i + 3] == [0x01, 0x13, 0x40] {
                        v[i + 3..i + 3 + 64].fill(0);
                        i += 3 + 64;
                    } else {
                        i += 1;
                    }
                }
                v
            };
            for (kind, name, unsigned, expected) in
                [(0u8, "", unsigned, expected), (1, " taproot", tap_unsigned, tap_expected)]
            {
                let a = ask(BTC, vec![b'A', 0, kind]);
                log::warn!("demo wallet btc{name} account: status {:?} {:?}", a.first(), texts(&a));
                let a = ask(BTC, [&[b'D', 0, kind, 0][..], &0u32.to_le_bytes()].concat());
                log::warn!("demo wallet btc{name} address: status {:?} {:?}", a.first(), texts(&a));
                let a = pieces(BTC, &[b'P', 0], &[], unsigned);
                // 5: refused, with why
                let why = if a.first() == Some(&5) { texts(&a) } else { Vec::new() };
                log::warn!("demo wallet btc{name} sign: status {:?} {why:?}", a.first());
                if let Some(s) = signed(BTC, &a) {
                    log::warn!(
                        "demo wallet btc{name} signed: {} bytes, as expected: {}, but for fresh signatures: {}",
                        s.len(),
                        s == expected,
                        blank(&s) == blank(expected)
                    );
                }
            }

            let tx: &[u8] = include_bytes!("../../../libs/maki-eth/tests/fixtures/abandon-tx-unsigned.bin");
            let tx_signed: &[u8] =
                include_bytes!("../../../libs/maki-eth/tests/fixtures/abandon-tx-signed.bin");
            let message_sig: &[u8] =
                include_bytes!("../../../libs/maki-eth/tests/fixtures/abandon-message.sig");
            let typed: &[u8] = include_bytes!("../../../libs/maki-eth/tests/fixtures/abandon-typed.json");
            let typed_sig: &[u8] = include_bytes!("../../../libs/maki-eth/tests/fixtures/abandon-typed.sig");
            // account 0, and the site asking
            let head = |kind: u8| [&[kind][..], &0u32.to_le_bytes()].concat();
            let site = [&[9u8][..], b"demo.maki"].concat();
            let a = ask(ETH, [head(b'A'), site.clone()].concat());
            log::warn!("demo wallet eth account: status {:?} {:?}", a.first(), texts(&a));
            let a = ask(ETH, [head(b'M'), site.clone(), b"Sign in to demo.maki".to_vec()].concat());
            log::warn!(
                "demo wallet eth message: status {:?}, as expected: {}",
                a.first(),
                a.get(1..) == Some(message_sig)
            );
            let a = pieces(ETH, &head(b'T'), &site, tx);
            let why = if a.first() == Some(&5) { texts(&a) } else { Vec::new() };
            log::warn!("demo wallet eth sign: status {:?} {why:?}", a.first());
            if let Some(s) = signed(ETH, &a) {
                log::warn!("demo wallet eth signed: {} bytes, as expected: {}", s.len(), s == tx_signed);
            }
            let a = pieces(ETH, &head(b'Y'), &site, typed);
            log::warn!(
                "demo wallet eth typed: status {:?}, as expected: {}",
                a.first(),
                a.get(1..) == Some(typed_sig)
            );

            // Monero's addresses, as Ledger's Monero app and monero-python make them for the test
            // phrase: the primary address, on Monero and stagenet, and subaddress 1
            for (net, minor, expected) in [
                (
                    0u8,
                    0u32,
                    "49vDbkSo7eve3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVF2N4Zn",
                ),
                (
                    2,
                    0,
                    "5A8FgbMkmG2e3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVHCRUaE",
                ),
                (
                    0,
                    1,
                    "8AB7PQPtducdkghYFN2prK3rZ7zPeL9f2REEdqE4WXYbSZr3797Aqti5xAjRsVy4jTdcwMW11GWejQtqk2kNXxj2QZxJwPZ",
                ),
            ] {
                let a = ask(XMR, [&[b'D', net][..], &0u32.to_le_bytes(), &minor.to_le_bytes()].concat());
                log::warn!(
                    "demo wallet xmr address {net}/{minor}: status {:?}, as expected: {}",
                    a.first(),
                    texts(&a).first().map(String::as_str) == Some(expected)
                );
            }
            // then as maki desktop spends: the view key, once the owner lets it watch (the test
            // phrase's, as every Monero wallet makes it from the spend key); an output's key
            // image; and a transaction (two of the wallet's outputs, 1.5 XMR paid, the change
            // back) made and signed by maki
            const VIEW_KEY: [u8; 32] = [
                0x0f, 0x3f, 0xe2, 0x5d, 0x0c, 0x6d, 0x4c, 0x94, 0xdd, 0xe0, 0xc0, 0xbc, 0xc2, 0x14, 0xb2,
                0x33, 0xe9, 0xc7, 0x29, 0x27, 0xf8, 0x13, 0x72, 0x8b, 0x0f, 0x01, 0xf2, 0x8f, 0x9d, 0x5e,
                0x12, 0x01,
            ];
            let a = ask(XMR, vec![b'W', 0]);
            log::warn!(
                "demo wallet xmr watch: status {:?}, the view key as expected: {}",
                a.first(),
                a.ends_with(&VIEW_KEY)
            );
            let output: &[u8] = include_bytes!("../../../libs/maki-xmr/tests/fixtures/abandon-output.bin");
            let a = ask(XMR, [&[b'K', 1][..], output].concat());
            log::warn!("demo wallet xmr key image: status {:?}, {} bytes", a.first(), a.len());
            let request: &[u8] = include_bytes!("../../../libs/maki-xmr/tests/fixtures/abandon-request.bin");
            let a = pieces(XMR, &[b'S', 0], &[], request);
            let why = if a.first() == Some(&5) { texts(&a) } else { Vec::new() };
            log::warn!("demo wallet xmr sign: status {:?} {why:?}", a.first());
            if let Some(s) = signed(XMR, &a) {
                // the transaction's length, then it: version 2, two inputs
                let tx = s.get(4..).unwrap_or_default();
                log::warn!(
                    "demo wallet xmr signed: {} bytes, a transaction of two inputs: {}",
                    s.len(),
                    tx.starts_with(&[2, 0, 2])
                );
            }

            // Solana: the account Phantom makes from the test phrase (SLIP-10's Ed25519 key at
            // m/44'/501'/0'/0'), connected to demo.maki, and a USDC payment web3.js made, read,
            // shown and signed as web3.js signs it
            const PHANTOM: [u8; 32] = [
                0xf0, 0x36, 0x27, 0x62, 0x46, 0xa7, 0x5b, 0x9d, 0xe3, 0x34, 0x9e, 0xd4, 0x2b, 0x15, 0xe2,
                0x32, 0xf6, 0x51, 0x8f, 0xc2, 0x0f, 0x5f, 0xcd, 0x4f, 0x1d, 0x64, 0xe8, 0x1f, 0x9b, 0xd2,
                0x58, 0xf7,
            ];
            let a = ask(SOL, [head(b'A'), site.clone()].concat());
            log::warn!(
                "demo wallet sol account: status {:?}, Phantom's: {}",
                a.first(),
                a.get(1..) == Some(&PHANTOM[..])
            );
            let usdc: &[u8] = include_bytes!("../../../libs/maki-sol/tests/fixtures/usdc.bin");
            let usdc_sig: &[u8] = include_bytes!("../../../libs/maki-sol/tests/fixtures/usdc.sig");
            let a = ask(SOL, [head(b'T'), site.clone(), usdc.to_vec()].concat());
            let why = if a.first() == Some(&5) { texts(&a) } else { Vec::new() };
            log::warn!(
                "demo wallet sol sign: status {:?} {why:?}, as web3.js signs it: {}",
                a.first(),
                a.get(1..) == Some(usdc_sig)
            );
        });
    }

    // This session's apps: built with MAKI_DEMO_SUDO, once maki has its PIN and phrase, maki-link
    // installs the Sudo and Bitcoin apps, then does what maki desktop's sudo plugin and its Bitcoin
    // page do: asks about a command (with an LD_PRELOAD set on its command line, which maki
    // shows), adds the fixture multisig wallet (libs/maki-btc/tests/fixtures: 2 of 3, maki's key
    // among them), and has its PSBT signed, checked against maki-btc's signature.
    if option_env!("MAKI_DEMO_SUDO").is_some() {
        std::thread::spawn(|| {
            const SUDO: &str = "com.leviathan.maki.sudo";
            const BTC: &str = "com.leviathan.maki.bitcoin";
            let host = demo_host();
            let bundles: [(&str, &[u8]); 2] = [
                ("sudo", include_bytes!("../../../libs/maki-wasm/tests/fixtures/sudo.maki")),
                ("bitcoin", include_bytes!("../../../libs/maki-wasm/tests/fixtures/bitcoin.maki")),
            ];
            for (name, bytes) in bundles {
                let r = demo_install(&host, bytes);
                log::warn!("demo sudo install {name}: result {} '{}'", r.result, r.reason);
            }
            let ask = |id: &str, m: Vec<u8>| {
                let r = host.message(id, m);
                if r.result == app_host::RESULT_OK { r.answer } else { vec![0xf0 | r.result as u8] }
            };
            // the sudo plugin's request: a nonce, who asks where, the command, its arguments and
            // what it's given (the SDK's examples/sudo has the layout)
            let mut r = vec![b'R'];
            r.extend_from_slice(&[0x5a; 32]);
            for s in [&b"laptop"[..], b"kara", b"root", b""] {
                r.push(s.len() as u8);
                r.extend_from_slice(s);
            }
            for s in [&b"/home/kara"[..], b""] {
                r.extend_from_slice(&(s.len() as u16).to_le_bytes());
                r.extend_from_slice(s);
            }
            r.push(10);
            r.extend_from_slice(b"/dev/pts/3");
            r.extend_from_slice(&[0, 0]);
            let command: &[u8] = b"/usr/bin/systemctl";
            r.extend_from_slice(&(command.len() as u16).to_le_bytes());
            r.extend_from_slice(command);
            let argv: [&[u8]; 3] = [b"systemctl", b"restart", b"nginx"];
            let env: [&[u8]; 1] = [b"LD_PRELOAD=/tmp/evil.so"];
            for list in [&argv[..], &env[..]] {
                r.push(list.len() as u8);
                for item in list {
                    r.extend_from_slice(&(item.len() as u16).to_le_bytes());
                    r.extend_from_slice(item);
                }
            }
            let a = ask(SUDO, r);
            log::warn!("demo sudo approve: status {:?}, signed: {}", a.first(), a.len() == 65);
            // the multisig wallet, added once the owner has gone through its keys
            let descriptor: &[u8] = include_bytes!("../../../libs/maki-btc/tests/fixtures/multisig.txt");
            let mut m = vec![b'M', 1];
            for s in [&b"Family vault"[..], descriptor] {
                m.extend_from_slice(&(s.len() as u16).to_le_bytes());
                m.extend_from_slice(s);
            }
            let a = ask(BTC, m);
            log::warn!("demo sudo multisig add: status {:?}", a.first());
            let unsigned: &[u8] =
                include_bytes!("../../../libs/maki-btc/tests/fixtures/multisig-unsigned.psbt");
            let expected: &[u8] =
                include_bytes!("../../../libs/maki-btc/tests/fixtures/multisig-signed.psbt");
            let mut p = vec![b'P', 1];
            p.extend_from_slice(&(unsigned.len() as u32).to_le_bytes());
            p.extend_from_slice(&0u32.to_le_bytes());
            p.extend_from_slice(unsigned);
            let a = ask(BTC, p);
            let mut signed = Vec::new();
            if let [0, n @ ..] = a.as_slice() {
                let total = u32::from_le_bytes(n[..4].try_into().unwrap_or([0; 4])) as usize;
                while signed.len() < total {
                    let g = ask(BTC, [&[b'G'][..], &(signed.len() as u32).to_le_bytes()].concat());
                    if g.len() <= 9 || g[0] != 0 {
                        break;
                    }
                    signed.extend_from_slice(&g[9..]);
                }
            }
            log::warn!(
                "demo sudo multisig sign: status {:?}, as expected: {}",
                a.first(),
                signed == expected
            );
        });
    }

    // The clock: built with MAKI_DEMO_CLOCK, maki-link sets maki's clock at boot to a fixed
    // evening, as maki desktop would (Sunday 27 September 2026, 22:38 at UTC-4), and calls it
    // verified: the bar's clock and the screensaver have a time to show.
    if option_env!("MAKI_DEMO_CLOCK").is_some() {
        let mut badge = Badge {
            tt: ticktimer_server::Ticktimer::new().unwrap(),
            launcher: maki_launcher::Launcher::new(&xns).expect("couldn't connect to the launcher"),
            time_state: time_state.clone(),
            #[cfg(feature = "board-baosec")]
            time_conn: xous::connect(
                xous::SID::from_bytes(bao1x_hal_service::api::TIME_SERVER_PUBLIC).unwrap(),
            )
            .unwrap(),
        };
        const DEMO_UTC_MS: u64 = 1_790_563_080_000;
        badge.set_time(DEMO_UTC_MS, -4 * 3600);
        badge.time_state_changed(TimeState::Verified);
        log::warn!("demo clock: set to 22:38 and called verified");
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
                use bao1x_hal_service::api::{TIME_SERVER_PUBLIC, TimeOp};
                let conn = xous::connect(xous::SID::from_bytes(TIME_SERVER_PUBLIC).unwrap()).unwrap();
                time_scalar(
                    conn,
                    TimeOp::SetUtcTimeMs,
                    (DEMO_UTC_MS >> 32) as usize,
                    DEMO_UTC_MS as u32 as usize,
                );
            }
            time_state.store(TimeState::Verified as u32, Ordering::SeqCst);
            host.set_time_state(TimeState::Verified as u8);
            let xns = xous_names::XousNames::new().unwrap();
            maki_launcher::Launcher::new(&xns).unwrap().set_time_state(TimeState::Verified as u8).ok();
            log::warn!("demo store: clock set and called verified");

            let r =
                demo_store_update(&host, include_bytes!("../../../libs/maki-store/dev-store/roots/2.bin"));
            log::warn!("demo store root 2: result {} '{}', root now {}", r.result, r.reason, r.root_version);
            let bundles: [(&str, &[u8]); 2] = [
                (
                    "sensors from the store",
                    include_bytes!(
                        "../../../libs/maki-store/dev-store/apps/com.leviathan.maki.sensors/1.maki"
                    ),
                ),
                ("tally sideloaded", include_bytes!("../../../libs/maki-wasm/tests/fixtures/tally.maki")),
            ];
            for (name, bytes) in bundles {
                let r = demo_install(&host, bytes);
                log::warn!("demo store install {name}: result {} '{}'", r.result, r.reason);
            }
            let r = demo_store_update(
                &host,
                include_bytes!("../../../libs/maki-store/dev-store/revocations.bin"),
            );
            log::warn!(
                "demo store revocations: result {} '{}', list {} until {}",
                r.result,
                r.reason,
                r.revocations_version,
                r.revocations_expires
            );
            // the same list again: nothing newer
            let r = demo_store_update(
                &host,
                include_bytes!("../../../libs/maki-store/dev-store/revocations.bin"),
            );
            log::warn!("demo store revocations again: result {} '{}'", r.result, r.reason);
            let r = demo_install(&host, include_bytes!("../../../libs/maki-wasm/tests/fixtures/tally.maki"));
            log::warn!("demo store install tally again: result {} '{}'", r.result, r.reason);
            let list = host.list();
            let names: Vec<String> =
                list.apps.iter().map(|a| format!("{} store: {}", a.id, a.from_store)).collect();
            log::warn!("demo store list: {:?}", names);
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
                        Handled::Backup(Backup::Put { .. }) if restore_tail.load(Ordering::SeqCst) => {
                            reply::restore_piece(true, Approval::Unavailable, 0, 0, 0)
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
                                restore_tail.store(true, Ordering::SeqCst);
                                let tail = restore_tail.clone();
                                match to_vault.send(Work::Restore {
                                    id: packet.id,
                                    total,
                                    offset,
                                    data,
                                    tail,
                                }) {
                                    Ok(()) => continue,
                                    Err(_) => {
                                        restore_tail.store(false, Ordering::SeqCst);
                                        waiting.fetch_sub(1, Ordering::SeqCst);
                                        reply::restore_piece(true, Approval::Unavailable, 0, 0, 0)
                                    }
                                }
                            }
                        }
                        Handled::Apps(Apps::List { index }) => {
                            app_list(app_host::AppHost::try_new(&xns), index)
                        }
                        Handled::Apps(Apps::Space) => app_space(app_host::AppHost::try_new(&xns)),
                        Handled::Apps(Apps::StoreUpdate { total, offset, data }) => {
                            store_update(app_host::AppHost::try_new(&xns), total, offset, data)
                        }
                        Handled::Apps(Apps::Install { .. }) if install_tail.load(Ordering::SeqCst) => {
                            reply::app_install(true, Approval::Unavailable, "")
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
                                let installing = matches!(request, Apps::Install { .. });
                                let work = match request {
                                    Apps::Install { total, offset, data } => {
                                        install_tail.store(true, Ordering::SeqCst);
                                        let tail = install_tail.clone();
                                        Work::AppInstall { id: packet.id, total, offset, data, tail }
                                    }
                                    Apps::Remove { id } => Work::AppRemove { id: packet.id, app: id },
                                    Apps::Message { id, message } => {
                                        Work::AppMessage { id: packet.id, app: id, message }
                                    }
                                    Apps::List { .. } | Apps::StoreUpdate { .. } | Apps::Space => {
                                        unreachable!()
                                    }
                                };
                                match to_vault.send(work) {
                                    Ok(()) => continue,
                                    Err(_) => {
                                        log::error!("the worker is gone");
                                        if installing {
                                            install_tail.store(false, Ordering::SeqCst);
                                        }
                                        waiting.fetch_sub(1, Ordering::SeqCst);
                                        unavailable
                                    }
                                }
                            }
                        }
                        // nothing is asked of a maki that hasn't had its PIN
                        Handled::Ask(ask) if !unlocked.load(Ordering::SeqCst) => locked(&ask),
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
