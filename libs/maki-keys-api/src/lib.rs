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
    /// Blocking scalar: the first process to call this is the screen (the launcher), and only it
    /// may set or enter the PIN, lock, or see and restore the recovery phrase. Returns 1 to it.
    Claim = 4,
    /// Memory message (mutable lend) with a `PhraseRequest`: make the recovery phrase, once, and
    /// hand its words back to be shown.
    NewPhrase = 5,
    /// Memory message (mutable lend) with a `PhraseRequest`: keep these words as the phrase.
    RestorePhrase = 6,
    /// Memory message (mutable lend) with a `Chunk`: a piece of the backup. Offset 0 seals a
    /// fresh one: the vault's logins and codes, encrypted with a key from the recovery phrase.
    BackupChunk = 7,
    /// Memory message (mutable lend) with a `Chunk`: a piece of a backup to restore. The last
    /// piece opens it, asks the owner on screen, and adds what maki doesn't have.
    RestoreChunk = 8,
    /// Memory message (mutable lend) with a `Wallet`: the Bitcoin account for wallet software
    /// (its zpub and descriptor). With `ask`, once the owner agrees on screen.
    BtcAccount = 9,
    /// Memory message (mutable lend) with a `Wallet`: an address. With `ask`, it's put on screen
    /// for the owner to compare with the computer's, and the answer says whether it matched.
    BtcAddress = 10,
    /// Memory message (mutable lend) with a `Chunk`: a piece of a PSBT to sign. The last piece
    /// checks it, shows the owner what it does, and signs it if they say so.
    BtcSign = 11,
    /// Memory message (mutable lend) with a `Chunk`: a piece of the PSBT last signed.
    BtcSigned = 12,
    /// Memory message (mutable lend) with a `PinRequest` (`pin` the current one, `new_pin`),
    /// from the screen, while unlocked. A wrong current PIN counts toward the wipe.
    ChangePin = 13,
    /// Blocking scalar: the first process to call this is the FIDO authenticator (the vault, at
    /// boot), and only it may have `FidoKeys`. Returns 1 to it.
    ClaimFido = 14,
    /// Memory message (mutable lend) with a `FidoSecret`: the authenticator's secrets, derived
    /// from the recovery phrase (`maki_seed::fido_keys`), for the FIDO process, once there's a
    /// phrase and maki is unlocked.
    FidoKeys = 15,
    /// Scalar: something changed the FIDO store behind the vault's back (the Passkeys app
    /// deleted one): bumps the store generation in `Status`, so the vault re-reads it.
    FidoStoreChanged = 16,
}

/// `FidoKeys`' answer: `keys` is 128 bytes (encryption, authentication, CredRandom).
#[derive(Debug, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FidoSecret {
    pub result: u32,
    pub keys: Vec<u8>,
}

/// Backups and PSBTs travel in pieces this big, here and over USB.
pub const CHUNK: usize = 4096;
/// Bigger than any vault maki could hold, and a bound on what a restore will take in.
pub const MAX_BACKUP: usize = 512 * 1024;
/// The biggest PSBT maki takes in.
pub const MAX_PSBT: usize = 512 * 1024;

/// A piece of a backup or a PSBT, either way. On the way back: `result` (`RESULT_*`), `total`,
/// and for a finished restore, what it added; for a finished signing, the signed PSBT's size.
#[derive(Debug, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Chunk {
    pub offset: u32,
    pub total: u32,
    pub data: Vec<u8>,
    pub result: u32,
    /// a restore or a signing: whether that was the last piece
    pub done: bool,
    pub logins: u32,
    pub codes: u32,
    pub passkeys: u32,
    /// a PSBT: `NETWORK_*`
    pub network: u8,
    /// a PSBT refused (`RESULT_REFUSED`): why, for the computer to show
    pub reason: String,
}

/// Bitcoin itself, and its test networks (testnet, signet), which share addresses.
pub const NETWORK_BITCOIN: u8 = 0;
pub const NETWORK_TESTNET: u8 = 1;

/// A question about the Bitcoin account, and its answer.
#[derive(Debug, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Wallet {
    /// `NETWORK_*`
    pub network: u8,
    /// an address: on the change chain or the receiving one, at this index
    pub change: bool,
    pub index: u32,
    /// Ask the owner first: for what goes to the computer. An app on maki that shows the answer
    /// on maki's own screen doesn't. (Every process on maki is maki's own firmware; third-party
    /// apps will need this narrowed.)
    pub ask: bool,
    pub result: u32,
    /// the account's zpub, or the address
    pub text: String,
    /// the account's output descriptor
    pub descriptor: String,
}

/// A recovery phrase, one way or the other, and what became of it (`RESULT_*`).
#[derive(Debug, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PhraseRequest {
    pub words: Vec<String>,
    pub result: u32,
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
    /// `ChangePin`: the one to change to
    pub new_pin: String,
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
/// Words that aren't a recovery phrase: a word not on the list, or a checksum that fails.
pub const RESULT_BAD_PHRASE: u32 = 6;
/// The owner said no, or didn't answer.
pub const RESULT_DENIED: u32 = 7;
pub const RESULT_TIMED_OUT: u32 = 8;
/// A backup this phrase can't open: another maki's, or damaged.
pub const RESULT_NOT_YOURS: u32 = 9;
/// No recovery phrase yet, so nothing to back up with.
pub const RESULT_NO_PHRASE: u32 = 10;
/// A PSBT maki won't sign (not this wallet's, or missing what it needs to check it): `reason`
/// says why. The owner wasn't asked.
pub const RESULT_REFUSED: u32 = 11;

/// Set in the second word of `Status`'s answer when a recovery phrase exists.
pub const HAS_PHRASE: usize = 1 << 16;
/// Bits of `Status`' second word counting restores, which may write to the FIDO store behind
/// the vault's back: when it changes, the vault re-reads the store.
pub const STORE_GENERATION_SHIFT: usize = 20;
pub const STORE_GENERATION_MASK: usize = 0xfff;

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

    fn status_raw(&self) -> (State, usize) {
        match xous::send_message(
            self.conn,
            xous::Message::new_blocking_scalar(KeysOp::Status.to_usize().unwrap(), 0, 0, 0, 0),
        ) {
            Ok(xous::Result::Scalar2(state, rest)) => {
                (num_traits::FromPrimitive::from_usize(state).unwrap_or(State::Locked), rest)
            }
            _ => (State::Locked, 0),
        }
    }

    /// The state, and how many wrong PINs are left before the wipe.
    pub fn status(&self) -> (State, u32) {
        let (state, rest) = self.status_raw();
        (state, (rest & 0xffff) as u32)
    }

    /// The state, and the FIDO store's generation (see `STORE_GENERATION_SHIFT`).
    pub fn status_and_generation(&self) -> (State, u32) {
        let (state, rest) = self.status_raw();
        (state, ((rest >> STORE_GENERATION_SHIFT) & STORE_GENERATION_MASK) as u32)
    }

    /// Whether a recovery phrase has been made (or restored). Known only while unlocked.
    pub fn has_phrase(&self) -> bool { self.status_raw().1 & HAS_PHRASE != 0 }

    /// Take the screen's role (the launcher, at boot). See `KeysOp::Claim`.
    pub fn claim(&self) -> bool {
        matches!(
            xous::send_message(self.conn, xous::Message::new_blocking_scalar(KeysOp::Claim.to_usize().unwrap(), 0, 0, 0, 0)),
            Ok(xous::Result::Scalar1(1))
        )
    }

    fn phrase_call(&self, op: KeysOp, words: Vec<String>) -> (u32, Vec<String>) {
        let Ok(mut buf) = Buffer::into_buf(PhraseRequest { words, result: RESULT_FAILED }) else {
            return (RESULT_FAILED, Vec::new());
        };
        if buf.lend_mut(self.conn, op.to_u32().unwrap()).is_err() {
            return (RESULT_FAILED, Vec::new());
        }
        match buf.to_original::<PhraseRequest, _>() {
            Ok(r) => (r.result, r.words),
            Err(_) => (RESULT_FAILED, Vec::new()),
        }
    }

    /// Make the recovery phrase and get its words, to show. Only once: None if there is one.
    pub fn new_phrase(&self) -> Option<Vec<String>> {
        match self.phrase_call(KeysOp::NewPhrase, Vec::new()) {
            (RESULT_OK, words) if !words.is_empty() => Some(words),
            _ => None,
        }
    }

    /// Keep these words as the recovery phrase (a restore). A `RESULT_*` code.
    pub fn restore_phrase(&self, words: &[&str]) -> u32 {
        self.phrase_call(KeysOp::RestorePhrase, words.iter().map(|w| w.to_string()).collect()).0
    }

    fn chunk_call(&self, op: KeysOp, request: Chunk) -> Chunk {
        let failed = Chunk { result: RESULT_FAILED, ..Default::default() };
        // `into_buf` sizes the buffer by the struct, one page, and a piece doesn't fit in one
        // with the rest: take two, for the piece either way
        let mut buf = Buffer::new(2 * CHUNK);
        if buf.replace(request).is_err() {
            return failed;
        }
        if buf.lend_mut(self.conn, op.to_u32().unwrap()).is_err() {
            return failed;
        }
        buf.to_original::<Chunk, _>().unwrap_or(failed)
    }

    /// A piece of the backup, starting at `offset`; 0 seals a fresh one.
    pub fn backup_chunk(&self, offset: u32) -> Chunk {
        self.chunk_call(KeysOp::BackupChunk, Chunk { offset, ..Default::default() })
    }

    /// A piece of a backup to restore. The last one blocks while the owner decides.
    pub fn restore_chunk(&self, total: u32, offset: u32, data: Vec<u8>) -> Chunk {
        self.chunk_call(KeysOp::RestoreChunk, Chunk { offset, total, data, ..Default::default() })
    }

    fn wallet_call(&self, op: KeysOp, request: Wallet) -> Wallet {
        let failed = Wallet { result: RESULT_FAILED, ..Default::default() };
        let Ok(mut buf) = Buffer::into_buf(request) else { return failed };
        if buf.lend_mut(self.conn, op.to_u32().unwrap()).is_err() {
            return failed;
        }
        buf.to_original::<Wallet, _>().unwrap_or(failed)
    }

    /// The Bitcoin account's zpub (`text`) and descriptor. With `ask`, once the owner agrees,
    /// blocking while they decide.
    pub fn btc_account(&self, network: u8, ask: bool) -> Wallet {
        self.wallet_call(KeysOp::BtcAccount, Wallet { network, ask, ..Default::default() })
    }

    /// An address (`text`). With `ask`, the owner compares it on screen first (blocking while
    /// they do), and `result` says whether it matched.
    pub fn btc_address(&self, network: u8, change: bool, index: u32, ask: bool) -> Wallet {
        self.wallet_call(KeysOp::BtcAddress, Wallet { network, change, index, ask, ..Default::default() })
    }

    /// A piece of a PSBT to sign. The last one blocks while the owner reviews it; its answer's
    /// `total` is the signed PSBT's size, or `reason` says why it was refused.
    pub fn btc_sign_chunk(&self, network: u8, total: u32, offset: u32, data: Vec<u8>) -> Chunk {
        self.chunk_call(KeysOp::BtcSign, Chunk { offset, total, data, network, ..Default::default() })
    }

    /// A piece of the PSBT last signed, from `offset`.
    pub fn btc_signed_chunk(&self, offset: u32) -> Chunk {
        self.chunk_call(KeysOp::BtcSigned, Chunk { offset, ..Default::default() })
    }

    /// Take the FIDO authenticator's role (the vault, at boot). See `KeysOp::ClaimFido`.
    pub fn claim_fido(&self) -> bool {
        matches!(
            xous::send_message(self.conn, xous::Message::new_blocking_scalar(KeysOp::ClaimFido.to_usize().unwrap(), 0, 0, 0, 0)),
            Ok(xous::Result::Scalar1(1))
        )
    }

    /// The FIDO authenticator's secrets, from the phrase: encryption key, authentication key,
    /// CredRandom (32 + 32 + 64 bytes). None unless this is the FIDO process and maki is unlocked
    /// with a phrase. Overwrite them when done with them.
    pub fn fido_keys(&self) -> Option<Vec<u8>> {
        let Ok(mut buf) = Buffer::into_buf(FidoSecret { result: RESULT_FAILED, keys: Vec::new() }) else { return None };
        buf.lend_mut(self.conn, KeysOp::FidoKeys.to_u32().unwrap()).ok()?;
        let answer = buf.to_original::<FidoSecret, _>().ok()?;
        (answer.result == RESULT_OK && answer.keys.len() == 128).then_some(answer.keys)
    }

    /// Tell the vault the FIDO store changed behind its back. See `KeysOp::FidoStoreChanged`.
    pub fn fido_store_changed(&self) {
        xous::send_message(
            self.conn,
            xous::Message::new_scalar(KeysOp::FidoStoreChanged.to_usize().unwrap(), 0, 0, 0, 0),
        )
        .ok();
    }

    /// Returns once the secrets are open and there's a recovery phrase: what the passkeys come
    /// from. (During setup, the PIN opens the secrets before the phrase is made.)
    pub fn wait_phrase(&self) {
        let tt = ticktimer_server::Ticktimer::new().unwrap();
        while !(self.status().0 == State::Unlocked && self.has_phrase()) {
            tt.sleep_ms(250).ok();
        }
    }

    /// Returns once the secrets are open. For processes that mustn't touch storage before then.
    pub fn wait_unlocked(&self) {
        let tt = ticktimer_server::Ticktimer::new().unwrap();
        while self.status().0 != State::Unlocked {
            tt.sleep_ms(250).ok();
        }
    }

    fn call(&self, op: KeysOp, pin: &str) -> PinResult { self.call_with(op, pin, "") }

    fn call_with(&self, op: KeysOp, pin: &str, new_pin: &str) -> PinResult {
        let request = PinRequest { pin: pin.into(), new_pin: new_pin.into(), result: RESULT_FAILED, tries_left: 0 };
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

    /// Change the PIN: the current one, checked like an unlock (a wrong one counts toward the
    /// wipe), then the new one. Twice as slow as an unlock.
    pub fn change_pin(&self, current: &str, new: &str) -> PinResult { self.call_with(KeysOp::ChangePin, current, new) }

    /// Close the secrets until the PIN is entered again. Returns whether they were open.
    pub fn lock(&self) -> bool {
        matches!(
            xous::send_message(self.conn, xous::Message::new_blocking_scalar(KeysOp::Lock.to_usize().unwrap(), 0, 0, 0, 0)),
            Ok(xous::Result::Scalar1(1))
        )
    }
}
