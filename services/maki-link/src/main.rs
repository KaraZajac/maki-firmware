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

use maki_proto::device::{reply, Approval, Ask, Backup, Bitcoin, Device, Handled, Platform, TimeState};
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
/// owner too), or a Bitcoin request that waits for them.
enum Work {
    Ask(u16, Ask),
    Restore { id: u16, total: u32, offset: u32, data: Vec<u8> },
    Bitcoin(u16, Bitcoin),
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
    }
}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("maki-link PID is {}", xous::process::id());

    let xns = xous_names::XousNames::new().unwrap();
    let badge = Badge {
        tt: ticktimer_server::Ticktimer::new().unwrap(),
        launcher: maki_launcher::Launcher::new(&xns).expect("couldn't connect to the launcher"),
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
    std::thread::spawn({
        let (last_contact, linked) = (last_contact.clone(), linked.clone());
        move || {
            let xns = xous_names::XousNames::new().unwrap();
            let launcher = maki_launcher::Launcher::new(&xns).expect("couldn't connect to the launcher");
            let tt = ticktimer_server::Ticktimer::new().unwrap();
            loop {
                tt.sleep_ms(2_000).ok();
                let quiet = (tt.elapsed_ms() as u32).wrapping_sub(last_contact.load(Ordering::SeqCst));
                if quiet > LINK_TIMEOUT_MS && linked.swap(false, Ordering::SeqCst) {
                    log::info!("desktop app gone quiet: unlinked");
                    launcher.set_link_state(false).ok();
                }
            }
        }
    });
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
