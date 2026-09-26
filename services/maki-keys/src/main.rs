//! maki-keys server. See lib.rs for what it keeps and why.
//!
//! In the system basis (open whenever the PDDB is mounted), dictionary `maki.keys`:
//!   - `lock`: which secret basis is maki's, the salt and round count for the PIN's key
//!     derivation, and the basis key wrapped under that derived key (AES-GCM-SIV);
//!   - `tries`: wrong PINs since the last right one, written before each try is checked, so
//!     pulling the plug mid-check doesn't give a free guess.
//! The secret basis gets a fresh random name at each setup: after a wipe, the old one can't be
//! opened (its key is gone), and its name mustn't collide with the new one.

use std::io::{Read, Write};

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use maki_keys_api::*;
use num_traits::FromPrimitive;
use pddb::{BasisRetentionPolicy, Pddb, PDDB_DEFAULT_SYSTEM_BASIS};
use xous_ipc::Buffer;
use zeroize::Zeroize;

const DICT: &str = "maki.keys";
const KEY_LOCK: &str = "lock";
const KEY_TRIES: &str = "tries";
/// In the secret basis: the recovery phrase's entropy.
const SEED_DICT: &str = "maki.seed";
const KEY_ENTROPY: &str = "entropy";

/// What a backup holds: the vault's dictionaries, record by record, as the vault stores them.
/// (Passkeys will join when they come from the phrase.)
const BACKUP_DICTS: [&str; 2] = ["vault.passwords", "vault.totp"];
const BACKUP_MAGIC: &[u8; 8] = b"MAKIBAK1";
const BACKUP_HEADER: &[u8] = b"maki backup 1\n";

/// A backup's plaintext: each record with the dictionary it came from.
struct Entry {
    dict: u8,
    key: String,
    value: Vec<u8>,
}

fn gather(store: &Store, basis: &str) -> Vec<u8> {
    let mut out = BACKUP_HEADER.to_vec();
    for (id, dict) in BACKUP_DICTS.iter().enumerate() {
        let Ok(keys) = store.pddb.list_keys(dict, Some(basis)) else { continue };
        for key in keys {
            let Ok(mut k) = store.pddb.get(dict, &key, Some(basis), false, false, None, None::<fn()>) else { continue };
            let mut value = Vec::new();
            if k.read_to_end(&mut value).is_err() {
                continue;
            }
            out.push(id as u8);
            out.extend_from_slice(&(key.len() as u16).to_le_bytes());
            out.extend_from_slice(key.as_bytes());
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(&value);
            value.zeroize();
        }
    }
    out
}

fn parse(plain: &[u8]) -> Option<Vec<Entry>> {
    let mut rest = plain.strip_prefix(BACKUP_HEADER)?;
    let mut entries = Vec::new();
    let mut take = |n: usize, rest: &mut &[u8]| -> Option<Vec<u8>> {
        let (a, b) = (rest.get(..n)?, rest.get(n..)?);
        *rest = b;
        Some(a.to_vec())
    };
    while !rest.is_empty() {
        let dict = take(1, &mut rest)?[0];
        let klen = u16::from_le_bytes(take(2, &mut rest)?.try_into().ok()?) as usize;
        let key = String::from_utf8(take(klen, &mut rest)?).ok()?;
        let vlen = u32::from_le_bytes(take(4, &mut rest)?.try_into().ok()?) as usize;
        let value = take(vlen, &mut rest)?;
        if (dict as usize) < BACKUP_DICTS.len() {
            entries.push(Entry { dict, key, value });
        }
    }
    Some(entries)
}

fn seal(key: &[u8; 32], plain: &[u8]) -> Option<Vec<u8>> {
    let nonce: [u8; 12] = random();
    let cipher = Aes256GcmSiv::new_from_slice(key).ok()?;
    let sealed = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad: BACKUP_MAGIC }).ok()?;
    let mut out = BACKUP_MAGIC.to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Some(out)
}

fn open(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    let rest = blob.strip_prefix(BACKUP_MAGIC)?;
    let (nonce, sealed) = (rest.get(..12)?, rest.get(12..)?);
    let cipher = Aes256GcmSiv::new_from_slice(key).ok()?;
    cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad: BACKUP_MAGIC }).ok()
}

/// The backup key, from the phrase: words, seed, then HKDF (maki_seed::backup_key).
fn backup_key(store: &Store, basis: &str) -> Option<[u8; 32]> {
    let mut entropy = store.entropy(basis)?;
    let words = maki_seed::to_words(&entropy);
    entropy.zeroize();
    let mut seed = maki_seed::seed(&words, "");
    let key = maki_seed::backup_key(&seed);
    seed.zeroize();
    Some(key)
}

/// Add the records maki doesn't have; returns (logins, codes) added.
fn restore(store: &Store, basis: &str, entries: &[Entry]) -> (u32, u32) {
    let (mut logins, mut codes) = (0, 0);
    for e in entries {
        let dict = BACKUP_DICTS[e.dict as usize];
        if store.pddb.get(dict, &e.key, Some(basis), false, false, None, None::<fn()>).is_ok() {
            continue; // maki has it already: keep maki's
        }
        let Ok(mut k) = store.pddb.get(dict, &e.key, Some(basis), true, true, Some(e.value.len()), None::<fn()>) else {
            continue;
        };
        if k.write_all(&e.value).is_ok() {
            if e.dict == 0 {
                logins += 1;
            } else {
                codes += 1;
            }
        }
    }
    store.pddb.sync().ok();
    (logins, codes)
}

/// What a restore would add, before asking.
fn missing(store: &Store, basis: &str, entries: &[Entry]) -> (u32, u32) {
    entries
        .iter()
        .filter(|e| store.pddb.get(BACKUP_DICTS[e.dict as usize], &e.key, Some(basis), false, false, None, None::<fn()>).is_err())
        .fold((0, 0), |(l, c), e| if e.dict == 0 { (l + 1, c) } else { (l, c + 1) })
}
/// PBKDF2-HMAC-SHA256 rounds for the PIN. Around a second on the badge is the aim: slow for
/// guessing, tolerable at boot. To be measured on hardware; it's stored, so it can change.
const ROUNDS: u32 = 20_000;

/// What `lock` holds.
struct Lock {
    basis: String,
    rounds: u32,
    salt: [u8; 16],
    nonce: [u8; 12],
    wrapped: Vec<u8>,
}

impl Lock {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![1u8]; // format version
        out.extend_from_slice(&self.rounds.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.push(self.basis.len() as u8);
        out.extend_from_slice(self.basis.as_bytes());
        out.push(self.wrapped.len() as u8);
        out.extend_from_slice(&self.wrapped);
        out
    }

    fn from_bytes(b: &[u8]) -> Option<Lock> {
        let mut at = 0usize;
        let mut take = |n: usize| -> Option<&[u8]> {
            let s = b.get(at..at + n)?;
            at += n;
            Some(s)
        };
        if take(1)? != [1u8] {
            return None;
        }
        let rounds = u32::from_le_bytes(take(4)?.try_into().ok()?);
        let salt = take(16)?.try_into().ok()?;
        let nonce = take(12)?.try_into().ok()?;
        let n = take(1)?[0] as usize;
        let basis = String::from_utf8(take(n)?.to_vec()).ok()?;
        let n = take(1)?[0] as usize;
        let wrapped = take(n)?.to_vec();
        Some(Lock { basis, rounds, salt, nonce, wrapped })
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("TRNG unavailable");
    b
}

/// The key the PIN unlocks.
fn derive(pin: &str, salt: &[u8; 16], rounds: u32) -> [u8; 32] {
    let mut kek = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pin.as_bytes(), salt, rounds, &mut kek);
    kek
}

struct Store {
    pddb: Pddb,
}

impl Store {
    fn read(&self, key: &str) -> Option<Vec<u8>> {
        let mut k = self.pddb.get(DICT, key, Some(PDDB_DEFAULT_SYSTEM_BASIS), false, false, None, None::<fn()>).ok()?;
        let mut v = Vec::new();
        k.read_to_end(&mut v).ok()?;
        Some(v)
    }

    /// Replace a key's value in the system basis, and make sure it's on flash.
    fn write(&self, key: &str, value: &[u8]) -> std::io::Result<()> {
        self.pddb.delete_key(DICT, key, Some(PDDB_DEFAULT_SYSTEM_BASIS)).ok();
        let mut k =
            self.pddb.get(DICT, key, Some(PDDB_DEFAULT_SYSTEM_BASIS), true, true, Some(value.len()), None::<fn()>)?;
        k.write_all(value)?;
        drop(k);
        self.pddb.sync()
    }

    fn lock(&self) -> Option<Lock> { self.read(KEY_LOCK).and_then(|b| Lock::from_bytes(&b)) }

    /// The recovery phrase's entropy, from the secret basis (open only while unlocked).
    fn entropy(&self, basis: &str) -> Option<Vec<u8>> {
        let mut k = self.pddb.get(SEED_DICT, KEY_ENTROPY, Some(basis), false, false, None, None::<fn()>).ok()?;
        let mut v = Vec::new();
        k.read_to_end(&mut v).ok()?;
        (!v.is_empty()).then_some(v)
    }

    fn set_entropy(&self, basis: &str, entropy: &[u8]) -> std::io::Result<()> {
        self.pddb.delete_key(SEED_DICT, KEY_ENTROPY, Some(basis)).ok();
        let mut k = self.pddb.get(SEED_DICT, KEY_ENTROPY, Some(basis), true, true, Some(entropy.len()), None::<fn()>)?;
        k.write_all(entropy)?;
        drop(k);
        self.pddb.sync()
    }

    fn tries(&self) -> u32 {
        self.read(KEY_TRIES).and_then(|b| b.get(..4).map(|s| u32::from_le_bytes(s.try_into().unwrap()))).unwrap_or(0)
    }

    fn set_tries(&self, n: u32) -> std::io::Result<()> { self.write(KEY_TRIES, &n.to_le_bytes()) }

    /// Destroy the wrapped key: the secret basis can't be opened again by anyone who asks
    /// this firmware. (Its pages stay allocated; the PDDB can only delete a basis that's open.)
    fn wipe(&self) {
        self.pddb.delete_key(DICT, KEY_LOCK, Some(PDDB_DEFAULT_SYSTEM_BASIS)).ok();
        self.pddb.delete_key(DICT, KEY_TRIES, Some(PDDB_DEFAULT_SYSTEM_BASIS)).ok();
        self.pddb.sync().ok();
    }
}

fn set_pin(store: &Store, pin: &str) -> Result<(), u32> {
    if !pin_is_valid(pin) {
        return Err(RESULT_BAD_PIN);
    }
    let mut basis_key: [u8; 32] = random();
    let salt: [u8; 16] = random();
    let nonce: [u8; 12] = random();
    let suffix: [u8; 4] = random();
    let basis = format!("maki-{:02x}{:02x}{:02x}{:02x}", suffix[0], suffix[1], suffix[2], suffix[3]);
    let mut kek = derive(pin, &salt, ROUNDS);
    let cipher = Aes256GcmSiv::new_from_slice(&kek).map_err(|_| RESULT_FAILED)?;
    kek.zeroize();
    let wrapped = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &basis_key, aad: basis.as_bytes() })
        .map_err(|_| RESULT_FAILED)?;
    let made = store.pddb.create_basis(&basis, &basis_key).and_then(|_| {
        store.pddb.unlock_basis(&basis, &basis_key, Some(BasisRetentionPolicy::Persist))
    });
    basis_key.zeroize();
    if let Err(e) = made {
        log::error!("couldn't make the secret basis: {:?}", e);
        return Err(RESULT_FAILED);
    }
    let lock = Lock { basis, rounds: ROUNDS, salt, nonce, wrapped };
    store.write(KEY_LOCK, &lock.to_bytes()).map_err(|_| RESULT_FAILED)?;
    store.set_tries(0).ok();
    log::info!("PIN set; secret basis {} made and open", lock.basis);
    Ok(())
}

/// Ok(()) unlocked; Err((result, tries left)).
fn unlock(store: &Store, pin: &str) -> Result<(), (u32, u32)> {
    let Some(lock) = store.lock() else { return Err((RESULT_NOT_NOW, 0)) };
    // counted before it's checked
    let tries = store.tries() + 1;
    if store.set_tries(tries).is_err() {
        return Err((RESULT_FAILED, 0));
    }
    let mut kek = derive(pin, &lock.salt, lock.rounds);
    let opened = Aes256GcmSiv::new_from_slice(&kek).ok().and_then(|c| {
        c.decrypt(Nonce::from_slice(&lock.nonce), Payload { msg: &lock.wrapped, aad: lock.basis.as_bytes() }).ok()
    });
    kek.zeroize();
    match opened {
        Some(mut basis_key) if basis_key.len() == 32 => {
            let key: [u8; 32] = basis_key[..].try_into().unwrap();
            basis_key.zeroize();
            let mut key = key;
            let result = store.pddb.unlock_basis(&lock.basis, &key, Some(BasisRetentionPolicy::Persist));
            key.zeroize();
            match result {
                Ok(()) => {
                    store.set_tries(0).ok();
                    log::info!("unlocked");
                    Ok(())
                }
                Err(e) => {
                    log::error!("the PIN was right but the basis wouldn't open: {:?}", e);
                    Err((RESULT_FAILED, MAX_TRIES.saturating_sub(tries)))
                }
            }
        }
        _ if tries >= MAX_TRIES => {
            log::warn!("{} wrong PINs: wiping", tries);
            store.wipe();
            Err((RESULT_WIPED, 0))
        }
        _ => Err((RESULT_WRONG, MAX_TRIES - tries)),
    }
}


fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("maki-keys PID is {}", xous::process::id());

    let xns = xous_names::XousNames::new().unwrap();
    let sid = xns.register_name(SERVER_NAME_KEYS, None).expect("can't register server");
    let store = Store { pddb: Pddb::new() };
    store.pddb.is_mounted_blocking();

    let mut state = if store.lock().is_some() { State::Locked } else { State::Unset };
    log::info!("starting {:?}", state);
    // the screen (the launcher), which alone may use the PIN and the phrase
    let mut screen: Option<xous::PID> = None;
    // the backup being read out, and one being restored
    let mut sealed: Option<Vec<u8>> = None;
    let mut incoming: Vec<u8> = Vec::new();
    let mut incoming_total: u32 = 0;

    loop {
        let mut msg = xous::receive_message(sid).unwrap();
        let from_screen = screen.is_some() && msg.sender.pid() == screen;
        match FromPrimitive::from_usize(msg.body.id()) {
            Some(KeysOp::Status) => {
                let tries_left = if state == State::Locked { MAX_TRIES.saturating_sub(store.tries()) } else { MAX_TRIES };
                let has_phrase = state == State::Unlocked
                    && store.lock().map(|l| store.entropy(&l.basis).is_some()).unwrap_or(false);
                let rest = tries_left as usize | if has_phrase { HAS_PHRASE } else { 0 };
                xous::return_scalar2(msg.sender, state as usize, rest).ok();
            }
            Some(KeysOp::BackupChunk) => {
                let Some(mem) = msg.body.memory_message_mut() else { continue };
                let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                let Ok(mut req) = buffer.to_original::<Chunk, _>() else { continue };
                req.data.clear();
                req.result = match (state, store.lock()) {
                    (State::Unlocked, Some(lock)) => {
                        if req.offset == 0 || sealed.is_none() {
                            sealed = backup_key(&store, &lock.basis).and_then(|mut key| {
                                let mut plain = gather(&store, &lock.basis);
                                let blob = seal(&key, &plain);
                                plain.zeroize();
                                key.zeroize();
                                blob
                            });
                        }
                        match &sealed {
                            None if store.entropy(&lock.basis).is_none() => RESULT_NO_PHRASE,
                            None => RESULT_FAILED,
                            Some(blob) => {
                                let start = (req.offset as usize).min(blob.len());
                                let end = (start + CHUNK).min(blob.len());
                                req.total = blob.len() as u32;
                                req.data.extend_from_slice(&blob[start..end]);
                                RESULT_OK
                            }
                        }
                    }
                    _ => RESULT_NOT_NOW,
                };
                buffer.replace(req).ok();
            }
            Some(KeysOp::RestoreChunk) => {
                let lock = store.lock();
                let (ok_state, basis) = match (state, lock) {
                    (State::Unlocked, Some(l)) => (true, l.basis),
                    _ => (false, String::new()),
                };
                let Some(mem) = msg.body.memory_message_mut() else { continue };
                let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                let Ok(mut req) = buffer.to_original::<Chunk, _>() else { continue };
                if req.offset == 0 {
                    incoming.zeroize();
                    incoming.clear();
                    incoming_total = req.total;
                }
                let in_order = req.offset as usize == incoming.len()
                    && req.total == incoming_total
                    && req.total as usize <= MAX_BACKUP
                    && incoming.len() + req.data.len() <= req.total as usize;
                if !ok_state || !in_order {
                    incoming.zeroize();
                    incoming.clear();
                    req.result = if ok_state { RESULT_FAILED } else { RESULT_NOT_NOW };
                    req.done = true;
                    req.data.clear();
                    buffer.replace(req).ok();
                    continue;
                }
                incoming.extend_from_slice(&req.data);
                req.data.clear();
                if incoming.len() < incoming_total as usize {
                    req.result = RESULT_OK;
                    req.done = false;
                    buffer.replace(req).ok();
                    continue;
                }
                // the last piece: open it, then ask on a thread, so status keeps being answered
                let blob = std::mem::take(&mut incoming);
                let opened = backup_key(&store, &basis).and_then(|mut key| {
                    let plain = open(&key, &blob);
                    key.zeroize();
                    plain
                });
                let Some(mut plain) = opened else {
                    req.result = if store.entropy(&basis).is_none() { RESULT_NO_PHRASE } else { RESULT_NOT_YOURS };
                    req.done = true;
                    buffer.replace(req).ok();
                    continue;
                };
                let entries = parse(&plain);
                plain.zeroize();
                let Some(entries) = entries else {
                    req.result = RESULT_NOT_YOURS;
                    req.done = true;
                    buffer.replace(req).ok();
                    continue;
                };
                drop(buffer);
                std::thread::spawn(move || {
                    let mut msg = msg;
                    let store = Store { pddb: Pddb::new() };
                    let (logins, codes) = missing(&store, &basis, &entries);
                    let (result, added) = if logins + codes == 0 {
                        (RESULT_OK, (0, 0))
                    } else {
                        let xns = xous_names::XousNames::new().unwrap();
                        let detail = format!("{} logins, {} codes", logins, codes);
                        match maki_launcher::Launcher::new(&xns)
                            .map(|l| l.ask("maki desktop", "Restore backup?", &detail, &[], 30))
                        {
                            Ok(Ok(maki_launcher::Answer::Allowed(_))) => (RESULT_OK, restore(&store, &basis, &entries)),
                            Ok(Ok(maki_launcher::Answer::Denied)) => (RESULT_DENIED, (0, 0)),
                            Ok(Ok(maki_launcher::Answer::TimedOut)) => (RESULT_TIMED_OUT, (0, 0)),
                            _ => (RESULT_FAILED, (0, 0)),
                        }
                    };
                    log::info!("restore: {} ({} logins, {} codes added)", result, added.0, added.1);
                    if let Some(mem) = msg.body.memory_message_mut() {
                        let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                        if let Ok(mut req) = buffer.to_original::<Chunk, _>() {
                            req.result = result;
                            req.done = true;
                            req.logins = added.0;
                            req.codes = added.1;
                            buffer.replace(req).ok();
                        }
                    }
                });
            }
            Some(KeysOp::Claim) => {
                if screen.is_none() {
                    screen = msg.sender.pid();
                    log::info!("the screen is PID {:?}", screen);
                }
                xous::return_scalar(msg.sender, (msg.sender.pid() == screen) as usize).ok();
            }
            Some(op @ (KeysOp::NewPhrase | KeysOp::RestorePhrase)) => {
                let Some(mem) = msg.body.memory_message_mut() else { continue };
                let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                let Ok(mut req) = buffer.to_original::<PhraseRequest, _>() else { continue };
                let lock = store.lock();
                let (result, words) = match (op, lock) {
                    _ if !from_screen || state != State::Unlocked => (RESULT_NOT_NOW, Vec::new()),
                    (_, None) => (RESULT_NOT_NOW, Vec::new()),
                    (KeysOp::NewPhrase, Some(lock)) => {
                        if store.entropy(&lock.basis).is_some() {
                            (RESULT_NOT_NOW, Vec::new())
                        } else {
                            let mut entropy: [u8; 32] = random();
                            let words: Vec<String> = maki_seed::to_words(&entropy).iter().map(|w| w.to_string()).collect();
                            let stored = store.set_entropy(&lock.basis, &entropy);
                            entropy.zeroize();
                            match stored {
                                Ok(()) => {
                                    log::info!("recovery phrase made");
                                    (RESULT_OK, words)
                                }
                                Err(_) => (RESULT_FAILED, Vec::new()),
                            }
                        }
                    }
                    (_, Some(lock)) => {
                        let words: Vec<&str> = req.words.iter().map(|w| w.as_str()).collect();
                        match maki_seed::to_entropy(&words) {
                            Ok(mut entropy) => {
                                let stored = store.set_entropy(&lock.basis, &entropy);
                                entropy.zeroize();
                                match stored {
                                    Ok(()) => {
                                        log::info!("recovery phrase restored");
                                        (RESULT_OK, Vec::new())
                                    }
                                    Err(_) => (RESULT_FAILED, Vec::new()),
                                }
                            }
                            Err(_) => (RESULT_BAD_PHRASE, Vec::new()),
                        }
                    }
                };
                for w in req.words.iter_mut() {
                    w.zeroize();
                }
                req.words = words;
                req.result = result;
                buffer.replace(req).ok();
            }
            Some(KeysOp::SetPin | KeysOp::Unlock | KeysOp::Lock) if !from_screen => {
                log::warn!("PIN request from {:?}, which isn't the screen", msg.sender.pid());
                if let Some(mem) = msg.body.memory_message_mut() {
                    let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                    if let Ok(mut req) = buffer.to_original::<PinRequest, _>() {
                        req.pin.zeroize();
                        req.result = RESULT_NOT_NOW;
                        buffer.replace(req).ok();
                    }
                } else {
                    xous::return_scalar(msg.sender, 0).ok();
                }
            }
            Some(op @ (KeysOp::SetPin | KeysOp::Unlock)) => {
                let Some(mem) = msg.body.memory_message_mut() else { continue };
                let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                let Ok(mut req) = buffer.to_original::<PinRequest, _>() else { continue };
                let (result, tries_left) = match (op, state) {
                    (KeysOp::SetPin, State::Unset) => match set_pin(&store, &req.pin) {
                        Ok(()) => {
                            state = State::Unlocked;
                            (RESULT_OK, MAX_TRIES)
                        }
                        Err(code) => (code, MAX_TRIES),
                    },
                    (KeysOp::Unlock, State::Locked) => match unlock(&store, &req.pin) {
                        Ok(()) => {
                            state = State::Unlocked;
                            (RESULT_OK, MAX_TRIES)
                        }
                        Err((code, left)) => {
                            if code == RESULT_WIPED {
                                state = State::Unset;
                            }
                            (code, left)
                        }
                    },
                    _ => (RESULT_NOT_NOW, 0),
                };
                req.pin.zeroize();
                req.result = result;
                req.tries_left = tries_left;
                buffer.replace(req).ok();
            }
            Some(KeysOp::Lock) => {
                let closed = match (state, store.lock()) {
                    (State::Unlocked, Some(lock)) => match store.pddb.lock_basis(&lock.basis) {
                        Ok(()) => {
                            state = State::Locked;
                            if let Some(mut b) = sealed.take() {
                                b.zeroize();
                            }
                            log::info!("locked");
                            true
                        }
                        Err(e) => {
                            log::warn!("couldn't close the secret basis: {:?}", e);
                            false
                        }
                    },
                    _ => false,
                };
                xous::return_scalar(msg.sender, closed as usize).ok();
            }
            _ => log::warn!("unknown opcode {}", msg.body.id()),
        }
    }
}
