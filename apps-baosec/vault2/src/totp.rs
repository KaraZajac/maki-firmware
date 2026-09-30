// Changed for maki (a fork of Xous: github.com/KaraZajac/maki-firmware) in 2026; its git history says what.
use std::sync::{Arc, Mutex};
use std::thread;
use std::{
    convert::TryFrom,
    time::{SystemTime, SystemTimeError},
};

use hmac::{Hmac, Mac};
use locales::t;
use num_traits::*;
use sha1::Sha1;
use xous::{Message, send_message};

use crate::VaultMode;

// Derived from https://github.com/blakesmith/xous-core/blob/xtotp-time/apps/xtotp/src/main.rs
#[derive(Clone, Copy)]
pub enum TotpAlgorithm {
    HmacSha1,
    HmacSha256,
    HmacSha512,
    None,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TotpError {
    BadRecord,
}

impl Default for TotpAlgorithm {
    fn default() -> Self { Self::None }
}

impl std::fmt::Debug for TotpAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            TotpAlgorithm::HmacSha1 => write!(f, "SHA1"),
            TotpAlgorithm::HmacSha256 => write!(f, "SHA256"),
            TotpAlgorithm::HmacSha512 => write!(f, "SHA512"),
            TotpAlgorithm::None => write!(f, "None"),
        }
    }
}

impl TryFrom<&str> for TotpAlgorithm {
    type Error = xous::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "SHA1" => Ok(TotpAlgorithm::HmacSha1),
            "SHA256" => Ok(TotpAlgorithm::HmacSha256),
            "SHA512" => Ok(TotpAlgorithm::HmacSha512),
            _ => Err(xous::Error::InvalidString),
        }
    }
}
impl core::fmt::Display for TotpAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            TotpAlgorithm::HmacSha1 => write!(f, "SHA1"),
            TotpAlgorithm::HmacSha256 => write!(f, "SHA256"),
            TotpAlgorithm::HmacSha512 => write!(f, "SHA512"),
            TotpAlgorithm::None => write!(f, "None"),
        }
    }
}

#[derive(Debug)]
pub struct TotpEntry {
    pub step_seconds: u64,
    pub shared_secret: Vec<u8>,
    pub digit_count: u8,
    pub algorithm: TotpAlgorithm,
}

pub fn get_current_unix_time() -> Result<u64, SystemTimeError> {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|duration| duration.as_secs())
}

fn unpack_u64(v: u64) -> [u8; 8] {
    let mask = 0x00000000000000ff;
    let mut bytes: [u8; 8] = [0; 8];
    (0..8).for_each(|i| bytes[7 - i] = (mask & (v >> (i * 8))) as u8);
    bytes
}

fn generate_hmac_bytes(unix_timestamp: u64, totp_entry: &TotpEntry) -> Result<Vec<u8>, xous::Error> {
    let mut computed_hmac = Vec::new();
    let checked_step = if totp_entry.step_seconds == 0 {
        log::warn!(
            "totp step_seconds was 0, this would cause a div-by-zero; forcing to 1. Check that this is not an HOTP record?"
        );
        1
    } else {
        totp_entry.step_seconds
    };
    match totp_entry.algorithm {
        // The OpenTitan HMAC core does not support hmac-sha1. Fall back to
        // a software implementation.
        TotpAlgorithm::HmacSha1 => {
            let mut mac: Hmac<Sha1> =
                Hmac::new_from_slice(&totp_entry.shared_secret).map_err(|_| xous::Error::InternalError)?;
            mac.update(&unpack_u64(unix_timestamp / checked_step));
            let hash: &[u8] = &mac.finalize().into_bytes();
            computed_hmac.extend_from_slice(hash);
        }
        // note: sha256/sha512 implementations not yet tested, as we have yet to find a site that uses this to
        // test against.
        TotpAlgorithm::HmacSha256 => {
            let mut mac: Hmac<sha2::Sha256> =
                Hmac::new_from_slice(&totp_entry.shared_secret).map_err(|_| xous::Error::InternalError)?;
            mac.update(&unpack_u64(unix_timestamp / checked_step));
            let hash: &[u8] = &mac.finalize().into_bytes();
            computed_hmac.extend_from_slice(hash);
        }
        TotpAlgorithm::HmacSha512 => {
            let mut mac: Hmac<sha2::Sha512> =
                Hmac::new_from_slice(&totp_entry.shared_secret).map_err(|_| xous::Error::InternalError)?;
            mac.update(&unpack_u64(unix_timestamp / checked_step));
            let hash: &[u8] = &mac.finalize().into_bytes();
            computed_hmac.extend_from_slice(hash);
        }
        TotpAlgorithm::None => {
            panic!("cannot generate hmac bytes for None algorithm")
        }
    }

    Ok(computed_hmac)
}

pub fn generate_totp_code(unix_timestamp: u64, totp_entry: &TotpEntry) -> Result<String, xous::Error> {
    let hash = generate_hmac_bytes(unix_timestamp, totp_entry)?;
    let offset: usize = (hash.last().unwrap_or(&0) & 0xf) as usize;
    let binary: u64 = (((hash[offset] & 0x7f) as u64) << 24)
        | ((hash[offset + 1] as u64) << 16)
        | ((hash[offset + 2] as u64) << 8)
        | (hash[offset + 3] as u64);

    let truncated_code = format!(
        "{:01$}",
        binary % (10_u64.pow(totp_entry.digit_count as u32)),
        totp_entry.digit_count as usize
    );

    Ok(truncated_code)
}

#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub(crate) enum PumpOp {
    Pump,
    Quit,
}

/// maki: the codes tick only while the vault is in front. The pump used to run from boot, four
/// times a second whether anything showed or not, and on maki, whose RAM is short, every
/// wake-up pages the vault back in at the expense of whatever is on screen.
#[derive(Default)]
pub(crate) struct Pace {
    /// the vault is in front
    pub(crate) focused: std::sync::atomic::AtomicBool,
    /// a pump is going round
    running: std::sync::atomic::AtomicBool,
}

impl Pace {
    /// Start the codes ticking, unless they already are.
    pub(crate) fn start(&self, pump_conn: xous::CID) {
        if !self.running.swap(true, std::sync::atomic::Ordering::SeqCst) {
            send_message(pump_conn, Message::new_scalar(PumpOp::Pump.to_usize().unwrap(), 0, 0, 0, 0)).ok();
        }
    }
}

pub(crate) fn pumper(
    mode: Arc<Mutex<VaultMode>>,
    sid: xous::SID,
    main_conn: xous::CID,
    allow_totp_rendering: Arc<core::sync::atomic::AtomicBool>,
    pace: Arc<Pace>,
) {
    // maki: a small stack, as it only pumps redraws
    let _ = thread::Builder::new().stack_size(32 * 1024).spawn({
        move || {
            let tt = ticktimer_server::Ticktimer::new().unwrap();
            let self_conn = xous::connect(sid).unwrap();
            loop {
                let msg = xous::receive_message(sid).unwrap();
                let opcode: Option<PumpOp> = FromPrimitive::from_usize(msg.body.id());
                log::trace!("{:?}", opcode);
                match opcode {
                    Some(PumpOp::Pump) => {
                        if allow_totp_rendering.load(core::sync::atomic::Ordering::SeqCst) {
                            // don't redraw if we're in host access mode
                            xous::try_send_message(
                                main_conn,
                                Message::new_scalar(crate::VaultOp::Redraw.to_usize().unwrap(), 0, 0, 0, 0),
                            )
                            .ok(); // don't panic if the queue overflows
                        }
                        // (the mode's lock is let go of straight away)
                        let go_on = || {
                            *mode.lock().unwrap() == VaultMode::Totp
                                && pace.focused.load(core::sync::atomic::Ordering::SeqCst)
                        };
                        if go_on() {
                            tt.sleep_ms(250).unwrap();
                            send_message(
                                self_conn,
                                Message::new_scalar(PumpOp::Pump.to_usize().unwrap(), 0, 0, 0, 0),
                            )
                            .expect("couldn't restart pump");
                        } else {
                            // out of Totp mode or out of sight, the restart message doesn't go
                            // through, and the redraws stop; unless the vault came back in front
                            // since the check
                            pace.running.store(false, core::sync::atomic::Ordering::SeqCst);
                            if go_on() {
                                pace.start(self_conn);
                            }
                        }
                    }
                    Some(PumpOp::Quit) => {
                        break;
                    }
                    _ => log::warn!("couldn't parse message: {:?}", msg),
                }
            }
            xous::destroy_server(sid).ok();
        }
    })
    .unwrap();
}

pub(crate) fn db_str_to_code(db_str: &str) -> Result<String, TotpError> {
    let fields = db_str.split(':').collect::<Vec<&str>>();
    if fields.len() == 5 {
        let shared_secret =
            base32::decode(base32::Alphabet::RFC4648 { padding: false }, fields[0]).unwrap_or(vec![]);
        let digit_count = u8::from_str_radix(fields[1], 10).unwrap_or(6);
        let step_seconds = u64::from_str_radix(fields[2], 10).unwrap_or(30);
        let algorithm = TotpAlgorithm::try_from(fields[3]).unwrap_or(TotpAlgorithm::HmacSha1);
        let is_hotp = fields[4].to_uppercase() == "HOTP";
        let totp = TotpEntry {
            step_seconds: if !is_hotp { step_seconds } else { 1 }, /* step_seconds is re-used
                                                                    * by hotp as the code. */
            shared_secret,
            digit_count,
            algorithm,
        };
        let code = if !is_hotp {
            generate_totp_code(get_current_unix_time().unwrap_or(0), &totp)
                .unwrap_or(t!("vault.error.record_error", locales::LANG).to_string())
        } else {
            generate_totp_code(step_seconds, &totp)
                .unwrap_or(t!("vault.error.record_error", locales::LANG).to_string())
        };
        Ok(code)
    } else {
        Err(TotpError::BadRecord)
    }
}
