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

use maki_proto::device::{reply, Approval, Ask, Device, Handled, Platform, TimeState};
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

/// Answers for when the vault can't take another request.
fn unavailable(ask: &Ask) -> (u8, Vec<u8>) {
    match ask {
        Ask::Login { .. } => reply::login(Approval::Unavailable, "", ""),
        Ask::Totp { .. } => reply::totp(Approval::Unavailable, "", 0),
        Ask::SaveLogin { .. } => reply::save(Approval::Unavailable),
    }
}

/// Takes requests for the owner to the vault, one at a time, and sends each answer back with
/// its request's id. Connects to the vault at boot: the vault accepts one connection only.
fn vault_worker(asks: mpsc::Receiver<(u16, Ask)>, waiting: Arc<AtomicU32>, send_lock: Arc<Mutex<()>>) {
    let xns = xous_names::XousNames::new().unwrap();
    let vault = maki_vault_api::VaultLink::new(&xns).expect("couldn't connect to the vault");
    let usb = usb_bao1x::UsbHid::new();
    for (id, ask) in asks {
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

    let send_lock = Arc::new(Mutex::new(()));
    let waiting = Arc::new(AtomicU32::new(0));
    let (to_vault, asks) = mpsc::channel::<(u16, Ask)>();
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
            to_vault.send((0xd000 + i as u16, ask)).ok();
        }
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
                        Handled::Ask(ask) => {
                            if waiting.fetch_add(1, Ordering::SeqCst) >= MAX_WAITING_ASKS {
                                waiting.fetch_sub(1, Ordering::SeqCst);
                                log::warn!("too many requests waiting on the owner");
                                unavailable(&ask)
                            } else {
                                match to_vault.send((packet.id, ask)) {
                                    // the worker answers, once the owner decides
                                    Ok(()) => continue,
                                    Err(mpsc::SendError((_, ask))) => {
                                        log::error!("the vault worker is gone");
                                        waiting.fetch_sub(1, Ordering::SeqCst);
                                        unavailable(&ask)
                                    }
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
