//! maki-keys: the boot PIN, and the secrets it guards (ARCHITECTURE.md, "Boot PIN").
//!
//! maki's secrets (the vault's passwords and codes, passkeys, the wallet) live in a PDDB secret
//! basis. A random 32-byte key opens it; that key is kept wrapped under one derived from the PIN,
//! so a PIN can be checked, and changed, without touching the basis. Five wrong PINs in a row
//! destroy the wrapped key: the basis can't be opened again, and maki is set up anew. The launcher
//! draws the PIN screens; this process holds the state.

use num_traits::ToPrimitive;
use xous_ipc::Buffer;

pub const SERVER_NAME_KEYS: &str = "_maki keys_";

/// PINs are digits, this many of them.
pub const MIN_PIN: usize = 6;
pub const MAX_PIN: usize = 12;
/// Wrong PINs in a row before the secrets are wiped.
pub const MAX_TRIES: u32 = 5;

#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub enum KeysOp {
    /// Blocking scalar: returns (`State`, tries left).
    Status = 0,
    /// Memory message (mutable lend) with a `PinRequest`: set the first PIN, while `Unset`.
    SetPin = 1,
    /// Memory message (mutable lend) with a `PinRequest`: unlock, while `Locked`.
    Unlock = 2,
    /// Blocking scalar: close the secret basis until the PIN is entered again.
    Lock = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub enum State {
    /// No PIN yet: first boot, or after a wipe.
    Unset = 0,
    /// Waiting for the PIN.
    Locked = 1,
    /// The secrets are open, until maki is unplugged.
    Unlocked = 2,
}

/// A PIN, and on the way back what became of it (`PinResult`).
#[derive(Debug, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PinRequest {
    pub pin: String,
    pub result: u32,
    pub tries_left: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinResult {
    Ok,
    /// Wrong; this many tries left before the wipe.
    Wrong(u32),
    /// That was the last try: the secrets are gone, and maki is back to `Unset`.
    Wiped,
    /// Not the moment for it (setting a PIN that's already set, unlocking what's open).
    NotNow,
    /// Not six to twelve digits.
    BadPin,
    Failed,
}

/// `PinRequest::result` codes.
pub const RESULT_OK: u32 = 0;
pub const RESULT_WRONG: u32 = 1;
pub const RESULT_WIPED: u32 = 2;
pub const RESULT_NOT_NOW: u32 = 3;
pub const RESULT_BAD_PIN: u32 = 4;
pub const RESULT_FAILED: u32 = 5;

/// Six to twelve digits.
pub fn pin_is_valid(pin: &str) -> bool {
    (MIN_PIN..=MAX_PIN).contains(&pin.len()) && pin.bytes().all(|b| b.is_ascii_digit())
}

pub struct Keys {
    conn: xous::CID,
}

impl Keys {
    /// Blocks until maki-keys is running.
    pub fn new(xns: &xous_names::XousNames) -> Result<Self, xous::Error> {
        Ok(Keys { conn: xns.request_connection_blocking(SERVER_NAME_KEYS)? })
    }

    pub fn status(&self) -> (State, u32) {
        match xous::send_message(
            self.conn,
            xous::Message::new_blocking_scalar(KeysOp::Status.to_usize().unwrap(), 0, 0, 0, 0),
        ) {
            Ok(xous::Result::Scalar2(state, tries)) => {
                (num_traits::FromPrimitive::from_usize(state).unwrap_or(State::Locked), tries as u32)
            }
            _ => (State::Locked, 0),
        }
    }

    /// Returns once the secrets are open. For processes that mustn't touch storage before then.
    pub fn wait_unlocked(&self) {
        let tt = ticktimer_server::Ticktimer::new().unwrap();
        while self.status().0 != State::Unlocked {
            tt.sleep_ms(250).ok();
        }
    }

    fn call(&self, op: KeysOp, pin: &str) -> PinResult {
        let request = PinRequest { pin: pin.into(), result: RESULT_FAILED, tries_left: 0 };
        let Ok(mut buf) = Buffer::into_buf(request) else { return PinResult::Failed };
        if buf.lend_mut(self.conn, op.to_u32().unwrap()).is_err() {
            return PinResult::Failed;
        }
        let Ok(answer) = buf.to_original::<PinRequest, _>() else { return PinResult::Failed };
        match answer.result {
            RESULT_OK => PinResult::Ok,
            RESULT_WRONG => PinResult::Wrong(answer.tries_left),
            RESULT_WIPED => PinResult::Wiped,
            RESULT_NOT_NOW => PinResult::NotNow,
            RESULT_BAD_PIN => PinResult::BadPin,
            _ => PinResult::Failed,
        }
    }

    /// Set the first PIN, which also makes the secret basis and opens it.
    pub fn set_pin(&self, pin: &str) -> PinResult { self.call(KeysOp::SetPin, pin) }

    /// Try a PIN. Slow on purpose: the key derivation takes about a second.
    pub fn unlock(&self, pin: &str) -> PinResult { self.call(KeysOp::Unlock, pin) }

    /// Close the secrets until the PIN is entered again. Returns whether they were open.
    pub fn lock(&self) -> bool {
        matches!(
            xous::send_message(self.conn, xous::Message::new_blocking_scalar(KeysOp::Lock.to_usize().unwrap(), 0, 0, 0, 0)),
            Ok(xous::Result::Scalar1(1))
        )
    }
}
