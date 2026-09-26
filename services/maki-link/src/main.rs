//! maki-link: the desktop app's way in, over the USB serial port.
//!
//! Frames arrive on the CDC-ACM serial interface, `maki_proto::device` decides what to do with
//! them, and this process supplies the badge-specific parts: the TRNG, the uptime counter, the RTC,
//! and telling the launcher whether its clock can be trusted. Protocol: libs/maki-proto/PROTOCOL.md.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use maki_proto::device::{reply, Approval, Ask, Device, Handled, Platform, TimeState};
use maki_proto::frame::{self, Deframer};
use num_traits::ToPrimitive;

/// The desktop app sends a heartbeat every 10 s; this long without a valid frame means it's gone.
const LINK_TIMEOUT_MS: u32 = 25_000;

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
                        // not wired to the vault yet: say so rather than hang the host
                        Handled::Ask(Ask::Login { .. }) => reply::login(Approval::Unavailable, "", ""),
                        Handled::Ask(Ask::Totp { .. }) => reply::totp(Approval::Unavailable, "", 0),
                        Handled::Ask(Ask::SaveLogin { .. }) => reply::save(Approval::Unavailable),
                    };
                    if usb.serial_send(&frame::encode(kind, packet.id, &body)).is_err() {
                        log::warn!("couldn't send reply 0x{:02x}", kind);
                    }
                }
                Err(e) => log::warn!("dropped a bad frame: {:?}", e),
            }
        }
    }
}
