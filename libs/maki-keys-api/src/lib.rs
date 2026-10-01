//! maki-keys: the boot PIN, and the secrets it guards (ARCHITECTURE.md, "Boot PIN").
//!
//! maki's secrets (the vault's passwords and codes, passkeys, the recovery phrase) live in a PDDB secret
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

/// How the tries are counted: in the chip, where a copy of the flash put back can't undo them.
pub mod tries;

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
    /// Blocking scalar: answered once the secrets are open, and with `arg1` = 1, once there's a
    /// recovery phrase too. Held rather than polled for.
    WaitUnlocked = 21,
    /// Blocking scalar with the `State` last seen in `arg1`: answered with the state once it's
    /// different. Held rather than polled for.
    WaitChange = 22,
    /// Blocking scalar: the first process to call this is the app host (at boot), and only it
    /// may have `AppSecret`. Returns 1 to it.
    ClaimApps = 23,
    /// Memory message (mutable lend) with an `AppSecretRequest`: an installed app's secret
    /// from the recovery phrase (`maki_seed::app_secret`), for the app host, once there's a
    /// phrase and maki is unlocked.
    AppSecret = 24,
    /// Blocking scalar: this maki's name, a maki roll it picked the first time it started
    /// (`maki_proto::names`), which it keeps through wipes. Returns its length and its bytes in
    /// four words, little-endian.
    DeviceName = 26,
    /// Memory message (mutable lend) with a `WalletRequest`: a wallet app's key at a path, or a
    /// signature with it (ARCHITECTURE.md, "Wallets are apps"). Only for the app host, which holds
    /// each app to the paths its manifest names and signs only after the owner's yes; here, every
    /// path must start with a hardened purpose and coin type. Once unlocked with a phrase.
    Wallet = 27,
    /// Memory message (mutable lend) with an `UpdateModeRequest`, from maki-link for maki
    /// desktop: once unlocked, maki asks its owner on screen whether to restart into update mode,
    /// where boot1 takes new firmware on its USB drive. On a yes, it answers, then restarts there.
    UpdateMode = 28,
    /// Scalar from maki-keys itself, once its owner said yes to `UpdateMode`: boot1 is to wait
    /// for new firmware at the next start (its bootwait flag), and maki restarts. Whoever installs
    /// the firmware turns the flag off on boot1's console, and maki-keys does when it starts.
    EnterUpdateMode = 29,
}

/// `FidoKeys`' answer: `keys` is 128 bytes (encryption, authentication, CredRandom).
#[derive(Debug, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FidoSecret {
    pub result: u32,
    pub keys: Vec<u8>,
}

/// Backups travel in pieces this big, here and over USB.
pub const CHUNK: usize = 4096;
/// Bigger than any vault maki could hold, and a bound on what a restore will take in.
pub const MAX_BACKUP: usize = 512 * 1024;

/// `UpdateMode`'s request: what maki desktop will install, for the owner to read (the desktop's
/// word for it: maki can't see the files), and on the way back, `result` (`RESULT_*`).
#[derive(Debug, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct UpdateModeRequest {
    pub label: String,
    pub result: u32,
}

/// A piece of a backup, either way. On the way back: `result` (`RESULT_*`), `total`, and for a
/// finished restore, what it added.
#[derive(Debug, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Chunk {
    pub offset: u32,
    pub total: u32,
    pub data: Vec<u8>,
    pub result: u32,
    /// a restore: whether that was the last piece
    pub done: bool,
    pub logins: u32,
    pub codes: u32,
    pub passkeys: u32,
}

/// `WalletRequest::op`: what's wanted of the key at `path` (`maki_hd::op`).
pub const WALLET_FINGERPRINT: u8 = 0;
pub const WALLET_PUBLIC: u8 = 1;
pub const WALLET_UNCOMPRESSED: u8 = 2;
pub const WALLET_TAPROOT: u8 = 3;
pub const WALLET_SIGN_ECDSA: u8 = 4;
pub const WALLET_SIGN_SCHNORR: u8 = 5;
pub const WALLET_SIGN_TAPROOT: u8 = 6;
/// Monero's public spend and view keys, on its coin type alone.
pub const WALLET_MONERO_PUBLIC: u8 = 7;
/// A Monero subaddress's public keys; `digest` is its account and index (u32s, little-endian).
pub const WALLET_MONERO_SUBADDRESS: u8 = 8;
/// The Monero spend key's 25 words, for the app host to have maki show its owner: never an app.
pub const WALLET_MONERO_WORDS: u8 = 9;
/// The Monero account's secret view key, once the owner has said yes to sharing it.
pub const WALLET_MONERO_VIEW_KEY: u8 = 10;
/// An output's key image and its proof; `digest` is the output (`maki_hd::op::MONERO_KEY_IMAGE`).
pub const WALLET_MONERO_KEY_IMAGE: u8 = 11;
/// A Monero transaction signed; `digest` is the request (`maki_xmr::request`), up to 64 KiB.
pub const WALLET_MONERO_SIGN: u8 = 12;
/// An Ed25519 public key by SLIP-10 (Solana's), every step of the path hardened.
pub const WALLET_ED25519_PUBLIC: u8 = 13;
/// An Ed25519 signature; `digest` is the whole message, up to 16 KiB.
pub const WALLET_ED25519_SIGN: u8 = 14;

/// A wallet app's request, through the app host, and its answer (`answer`, when `result` is
/// `RESULT_OK`).
#[derive(Debug, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct WalletRequest {
    pub op: u8,
    pub path: Vec<u32>,
    /// 32 bytes, to sign; or what's asked, whole (a Monero output or transaction, a message
    /// for Ed25519)
    pub digest: Vec<u8>,
    pub result: u32,
    pub answer: Vec<u8>,
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
    /// The storage is sealed to the chip's collateral, and that's gone (the release build without
    /// maki's boot updater, or with other firmware put on after it): nothing can be opened, so
    /// nothing is asked for.
    Sealed = 3,
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

/// An app's secret: which app (its ID and developer key) and which of its secrets (a label of
/// the app's choosing); on the way back, the secret.
#[derive(Debug, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct AppSecretRequest {
    pub id: String,
    /// 32 bytes
    pub developer: Vec<u8>,
    pub label: String,
    /// 32 bytes, when `result` is `RESULT_OK`
    pub secret: Vec<u8>,
    pub result: u32,
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

    /// This maki's name: a maki roll, picked the first time it started.
    pub fn device_name(&self) -> String {
        let named = xous::send_message(
            self.conn,
            xous::Message::new_blocking_scalar(KeysOp::DeviceName.to_usize().unwrap(), 0, 0, 0, 0),
        );
        match named {
            Ok(xous::Result::Scalar5(len, a, b, c, d)) => {
                let bytes: Vec<u8> = [a, b, c, d].iter().flat_map(|w| (*w as u32).to_le_bytes()).collect();
                String::from_utf8_lossy(&bytes[..len.min(bytes.len())]).into_owned()
            }
            _ => String::from("maki"),
        }
    }

    /// Take the screen's role (the launcher, at boot). See `KeysOp::Claim`.
    pub fn claim(&self) -> bool {
        matches!(
            xous::send_message(
                self.conn,
                xous::Message::new_blocking_scalar(KeysOp::Claim.to_usize().unwrap(), 0, 0, 0, 0)
            ),
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

    /// Restart into update mode for maki desktop to install `label`, if the owner says yes on
    /// screen: blocks while they decide. `RESULT_OK` (maki restarts in a moment), `RESULT_DENIED`,
    /// `RESULT_TIMED_OUT`, or `RESULT_NOT_NOW` while maki is locked.
    pub fn update_mode(&self, label: &str) -> u32 {
        let request = UpdateModeRequest { label: label.into(), result: RESULT_FAILED };
        let Ok(mut buf) = Buffer::into_buf(request) else { return RESULT_FAILED };
        if buf.lend_mut(self.conn, KeysOp::UpdateMode.to_u32().unwrap()).is_err() {
            return RESULT_FAILED;
        }
        buf.to_original::<UpdateModeRequest, _>().map(|r| r.result).unwrap_or(RESULT_FAILED)
    }

    /// A piece of the backup, starting at `offset`; 0 seals a fresh one.
    pub fn backup_chunk(&self, offset: u32) -> Chunk {
        self.chunk_call(KeysOp::BackupChunk, Chunk { offset, ..Default::default() })
    }

    /// A piece of a backup to restore. The last one blocks while the owner decides.
    pub fn restore_chunk(&self, total: u32, offset: u32, data: Vec<u8>) -> Chunk {
        self.chunk_call(KeysOp::RestoreChunk, Chunk { offset, total, data, ..Default::default() })
    }

    /// Take the FIDO authenticator's role (the vault, at boot). See `KeysOp::ClaimFido`.
    pub fn claim_fido(&self) -> bool {
        matches!(
            xous::send_message(
                self.conn,
                xous::Message::new_blocking_scalar(KeysOp::ClaimFido.to_usize().unwrap(), 0, 0, 0, 0)
            ),
            Ok(xous::Result::Scalar1(1))
        )
    }

    /// Take the app host's role (at boot). See `KeysOp::ClaimApps`.
    pub fn claim_apps(&self) -> bool {
        matches!(
            xous::send_message(
                self.conn,
                xous::Message::new_blocking_scalar(KeysOp::ClaimApps.to_usize().unwrap(), 0, 0, 0, 0)
            ),
            Ok(xous::Result::Scalar1(1))
        )
    }

    /// An installed app's secret: for the app with this ID and developer key, and the app's own
    /// label. The error is a `RESULT_` code: `RESULT_NOT_NOW` if maki is locked or this isn't the
    /// app host, `RESULT_NO_PHRASE` before there's a phrase. Overwrite it when done with it.
    pub fn app_secret(&self, id: &str, developer: &[u8; 32], label: &str) -> Result<[u8; 32], u32> {
        let request = AppSecretRequest {
            id: id.into(),
            developer: developer.to_vec(),
            label: label.into(),
            secret: Vec::new(),
            result: RESULT_FAILED,
        };
        let mut buf = Buffer::into_buf(request).map_err(|_| RESULT_FAILED)?;
        buf.lend_mut(self.conn, KeysOp::AppSecret.to_u32().unwrap()).map_err(|_| RESULT_FAILED)?;
        let answer = buf.to_original::<AppSecretRequest, _>().map_err(|_| RESULT_FAILED)?;
        match answer.result {
            RESULT_OK => answer.secret.as_slice().try_into().map_err(|_| RESULT_FAILED),
            code => Err(code),
        }
    }

    /// The FIDO authenticator's secrets, from the phrase: encryption key, authentication key,
    /// CredRandom (32 + 32 + 64 bytes). None unless this is the FIDO process and maki is unlocked
    /// with a phrase. Overwrite them when done with them.
    pub fn fido_keys(&self) -> Option<Vec<u8>> {
        let Ok(mut buf) = Buffer::into_buf(FidoSecret { result: RESULT_FAILED, keys: Vec::new() }) else {
            return None;
        };
        buf.lend_mut(self.conn, KeysOp::FidoKeys.to_u32().unwrap()).ok()?;
        let answer = buf.to_original::<FidoSecret, _>().ok()?;
        (answer.result == RESULT_OK && answer.keys.len() == 128).then_some(answer.keys)
    }

    /// A wallet app's key at `path`, or a signature over `digest` with it (`WALLET_*`), for the
    /// app host: the answer's bytes, or a `RESULT_*` code.
    pub fn wallet(&self, op: u8, path: &[u32], digest: &[u8]) -> Result<Vec<u8>, u32> {
        let request = WalletRequest {
            op,
            path: path.to_vec(),
            digest: digest.to_vec(),
            result: RESULT_FAILED,
            answer: Vec::new(),
        };
        // a page holds a key or a signature; a Monero transaction to sign, and the signed one
        // coming back (maki-keys sends the request back empty), take more
        let mut buf = if digest.len() > 1024 {
            let mut buf = Buffer::new(digest.len() * 2 + 8192);
            buf.replace(request).map_err(|_| RESULT_FAILED)?;
            buf
        } else {
            Buffer::into_buf(request).map_err(|_| RESULT_FAILED)?
        };
        buf.lend_mut(self.conn, KeysOp::Wallet.to_u32().unwrap()).map_err(|_| RESULT_FAILED)?;
        let answer = buf.to_original::<WalletRequest, _>().map_err(|_| RESULT_FAILED)?;
        match answer.result {
            RESULT_OK => Ok(answer.answer),
            code => Err(code),
        }
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
    pub fn wait_phrase(&self) { self.wait(true) }

    /// Returns once the secrets are open. For processes that mustn't touch storage before then.
    pub fn wait_unlocked(&self) { self.wait(false) }

    /// Returns the state once it's no longer `seen`: maki locked, unlocked, or was wiped.
    pub fn wait_change(&self, seen: State) -> State {
        match xous::send_message(
            self.conn,
            xous::Message::new_blocking_scalar(
                KeysOp::WaitChange.to_usize().unwrap(),
                seen as usize,
                0,
                0,
                0,
            ),
        ) {
            Ok(xous::Result::Scalar1(s)) => num_traits::FromPrimitive::from_usize(s).unwrap_or(State::Locked),
            _ => self.status().0,
        }
    }

    /// maki-keys answers when it's so. Polling for it woke both processes a few times a second,
    /// all through setup, and RAM is short: every wake-up pages a process back in.
    fn wait(&self, phrase: bool) {
        xous::send_message(
            self.conn,
            xous::Message::new_blocking_scalar(
                KeysOp::WaitUnlocked.to_usize().unwrap(),
                phrase as usize,
                0,
                0,
                0,
            ),
        )
        .ok();
    }

    fn call(&self, op: KeysOp, pin: &str) -> PinResult { self.call_with(op, pin, "") }

    fn call_with(&self, op: KeysOp, pin: &str, new_pin: &str) -> PinResult {
        let request =
            PinRequest { pin: pin.into(), new_pin: new_pin.into(), result: RESULT_FAILED, tries_left: 0 };
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
    pub fn change_pin(&self, current: &str, new: &str) -> PinResult {
        self.call_with(KeysOp::ChangePin, current, new)
    }

    /// Close the secrets until the PIN is entered again. Returns whether they were open.
    pub fn lock(&self) -> bool {
        matches!(
            xous::send_message(
                self.conn,
                xous::Message::new_blocking_scalar(KeysOp::Lock.to_usize().unwrap(), 0, 0, 0, 0)
            ),
            Ok(xous::Result::Scalar1(1))
        )
    }
}
