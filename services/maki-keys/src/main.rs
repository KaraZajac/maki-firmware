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
use maki_keys::*;
use num_traits::FromPrimitive;
use pddb::{BasisRetentionPolicy, Pddb, PDDB_DEFAULT_SYSTEM_BASIS};
use xous_ipc::Buffer;
use zeroize::Zeroize;

const DICT: &str = "maki.keys";
const KEY_LOCK: &str = "lock";
const KEY_TRIES: &str = "tries";
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

    loop {
        let mut msg = xous::receive_message(sid).unwrap();
        match FromPrimitive::from_usize(msg.body.id()) {
            Some(KeysOp::Status) => {
                let tries_left = if state == State::Locked { MAX_TRIES.saturating_sub(store.tries()) } else { MAX_TRIES };
                xous::return_scalar2(msg.sender, state as usize, tries_left as usize).ok();
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
