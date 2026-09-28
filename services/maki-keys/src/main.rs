//! maki-keys server. See lib.rs for what it keeps and why.
//!
//! In the system basis (open whenever the PDDB is mounted), dictionary `maki.keys`:
//!   - `lock`: which secret basis is maki's, the salt and round count for the PIN's key
//!     derivation, and the basis key wrapped under that derived key (AES-GCM-SIV);
//!   - `tries`: wrong PINs since the last right one, written before each try is checked, so
//!     pulling the plug mid-check doesn't give a free guess.
//! The secret basis gets a fresh random name at each setup: after a wipe, the old one can't be
//! opened (its key is gone), and its name mustn't collide with the new one.

mod passkeys;

use std::io::{Read, Write};
use std::sync::atomic::Ordering;

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use maki_keys_api::*;
use num_traits::FromPrimitive;
use pddb::{BasisRetentionPolicy, Pddb, PDDB_DEFAULT_SYSTEM_BASIS};
use xous_ipc::Buffer;
use zeroize::Zeroize;

const DICT: &str = "maki.keys";
const KEY_LOCK: &str = "lock";
/// A PIN change writes its record here first, then over `lock`: cut the power between the two
/// and either PIN still opens maki (whichever does becomes the only record).
const KEY_LOCK_NEXT: &str = "lock.next";
const KEY_TRIES: &str = "tries";
/// This maki's name (`maki_proto::names`): picked the first time it starts, kept through wipes,
/// which forget only the lock.
const KEY_NAME: &str = "name";
/// In the secret basis: the recovery phrase's entropy.
const SEED_DICT: &str = "maki.seed";
const KEY_ENTROPY: &str = "entropy";

/// What a backup holds: the vault's dictionaries, record by record, as the vault stores them, and
/// the FIDO authenticator's resident credentials and signature counter (see passkeys.rs). An
/// older firmware restoring a newer backup skips the dictionaries it doesn't know.
const BACKUP_DICTS: [&str; 3] = ["vault.passwords", "vault.totp", passkeys::DICT];
/// Installed apps whose data the owner keeps in the backup (ARCHITECTURE.md, "Storage and
/// backups"): each app's record, keyed by its ID, so a restore knows whose data it is; then its
/// data, keyed `ID\tkey`. Not the apps themselves: the whole backup is made in maki's RAM.
const APP_RECORD: u8 = 3;
const APP_DATA: u8 = 4;
use maki_app_host_api::RESTORED;
const BACKUP_MAGIC: &[u8; 8] = b"MAKIBAK1";
const RESTORE_TIMEOUT_S: u32 = maki_launcher::ask_timeout(60);
const BACKUP_HEADER: &[u8] = b"maki backup 1\n";

/// A backup's plaintext: each record with the dictionary it came from.
struct Entry {
    dict: u8,
    key: String,
    value: Vec<u8>,
}

fn entry(out: &mut Vec<u8>, dict: u8, key: &str, value: &[u8]) {
    out.push(dict);
    out.extend_from_slice(&(key.len() as u16).to_le_bytes());
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

/// Each app the owner keeps in the backup, record then data, as long as the backup stays
/// within what maki can seal and send: an app that doesn't fit is left out whole.
fn gather_apps(store: &Store, basis: &str, out: &mut Vec<u8>) {
    let room = MAX_BACKUP - 1024;
    let Ok(ids) = store.pddb.list_keys(maki_app_host_api::APPS, Some(basis)) else { return };
    for id in ids {
        let Some(bytes) = read_key(store, maki_app_host_api::APPS, &id, basis) else { continue };
        if !maki_app_host_api::Record::decode(&bytes).map(|r| r.backup).unwrap_or(false) {
            continue;
        }
        let mut app = Vec::new();
        entry(&mut app, APP_RECORD, &id, &bytes);
        let dict = maki_app_host_api::data_dict(&id);
        for key in store.pddb.list_keys(&dict, Some(basis)).unwrap_or_default() {
            if let Some(mut value) = read_key(store, &dict, &key, basis) {
                entry(&mut app, APP_DATA, &format!("{id}\t{key}"), &value);
                value.zeroize();
            }
        }
        if out.len() + app.len() > room {
            log::warn!("backup: {id}'s data left out: the backup would be too big");
        } else {
            out.extend_from_slice(&app);
        }
        app.zeroize();
    }
}

fn gather(store: &Store, basis: &str) -> Vec<u8> {
    let mut out = BACKUP_HEADER.to_vec();
    for (id, dict) in BACKUP_DICTS.iter().enumerate() {
        let Ok(keys) = store.pddb.list_keys(dict, Some(basis)) else { continue };
        for key in keys {
            if *dict == passkeys::DICT && !passkeys::backed_up(&key) {
                continue;
            }
            let Ok(mut k) = store.pddb.get(dict, &key, Some(basis), false, false, None, None::<fn()>) else { continue };
            let mut value = Vec::new();
            if k.read_to_end(&mut value).is_err() {
                continue;
            }
            entry(&mut out, id as u8, &key, &value);
            value.zeroize();
        }
    }
    gather_apps(store, basis, &mut out);
    out
}

fn parse(plain: &[u8]) -> Option<Vec<Entry>> {
    let mut rest = plain.strip_prefix(BACKUP_HEADER)?;
    let mut entries = Vec::new();
    let take = |n: usize, rest: &mut &[u8]| -> Option<Vec<u8>> {
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
        if (dict as usize) < BACKUP_DICTS.len() || dict == APP_RECORD || dict == APP_DATA {
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

/// The BIP39 seed, made once per unlock and kept until Lock: PBKDF2 over the phrase is slow on
/// maki's core, and wallet apps' keys, apps' secrets, the passkeys' keys and the backup key all
/// start from it.
struct SeedCache(Option<[u8; 64]>);

impl SeedCache {
    fn get(&mut self, store: &Store, state: State) -> Option<[u8; 64]> {
        if self.0.is_none() {
            let lock = store.lock().filter(|_| state == State::Unlocked)?;
            let mut entropy = store.entropy(&lock.basis)?;
            let words = maki_seed::to_words(&entropy);
            entropy.zeroize();
            self.0 = Some(maki_seed::seed(&words, ""));
        }
        self.0
    }

    fn forget(&mut self) {
        if let Some(mut s) = self.0.take() {
            s.zeroize();
        }
    }
}

/// The backup key, from the seed (maki_seed::backup_key).
fn backup_key(seed: Option<[u8; 64]>) -> Option<[u8; 32]> {
    let mut seed = seed?;
    let key = maki_seed::backup_key(&seed);
    seed.zeroize();
    Some(key)
}

/// What a restore adds, or would add.
#[derive(Default, Clone, Copy)]
struct Added {
    logins: u32,
    codes: u32,
    passkeys: u32,
    /// apps whose data came back
    apps: u32,
}

fn read_key(store: &Store, dict: &str, key: &str, basis: &str) -> Option<Vec<u8>> {
    let mut k = store.pddb.get(dict, key, Some(basis), false, false, None, None::<fn()>).ok()?;
    let mut v = Vec::new();
    k.read_to_end(&mut v).ok()?;
    Some(v)
}

/// The resident credentials maki has: the slot of each, and its credential ID.
fn credentials(store: &Store, basis: &str) -> Vec<(usize, Vec<u8>)> {
    let Ok(keys) = store.pddb.list_keys(passkeys::DICT, Some(basis)) else { return Vec::new() };
    keys.iter()
        .filter_map(|k| k.parse::<usize>().ok().filter(|n| passkeys::CREDENTIALS.contains(n)))
        .filter_map(|slot| {
            let mut value = read_key(store, passkeys::DICT, &slot.to_string(), basis)?;
            let id = passkeys::credential_id(&value).map(|id| id.to_vec());
            value.zeroize();
            Some((slot, id?))
        })
        .collect()
}

/// Add what maki doesn't have (or with `write` false, count it): logins and codes by their
/// record's name, passkeys by credential ID, each into a free slot. The signature counter only
/// ever goes up, so sites never see it go back.
fn restore(store: &Store, basis: &str, entries: &[Entry], write: bool) -> Added {
    let mut added = Added::default();
    let mut have = credentials(store, basis);
    let mut free = passkeys::CREDENTIALS.filter(|n| !have.iter().any(|(slot, _)| slot == n)).collect::<Vec<_>>().into_iter();
    let put = |dict: &str, key: &str, value: &[u8]| -> bool {
        store
            .pddb
            .get(dict, key, Some(basis), true, true, Some(value.len()), None::<fn()>)
            .and_then(|mut k| k.write_all(value))
            .is_ok()
    };
    // apps' data comes back into the same developer's app: installed now, or later (the app
    // host keeps it then, or drops it for another developer's app of the same ID)
    let theirs = |id: &str| -> Option<maki_app_host_api::Record> {
        entries
            .iter()
            .find(|e| e.dict == APP_RECORD && e.key == id)
            .and_then(|e| maki_app_host_api::Record::decode(&e.value))
    };
    let installed = |id: &str| {
        read_key(store, maki_app_host_api::APPS, id, basis).and_then(|b| maki_app_host_api::Record::decode(&b))
    };
    let mut apps_back: Vec<String> = Vec::new();
    for e in entries.iter().filter(|e| e.dict == APP_DATA) {
        let Some((id, key)) = e.key.split_once('\t') else { continue };
        let Some(record) = theirs(id) else { continue };
        match installed(id) {
            Some(now) if now.developer != record.developer => continue,
            Some(_) => {}
            // not installed: the data waits, with whose it is
            None => match read_key(store, RESTORED, id, basis).and_then(|b| maki_app_host_api::Record::decode(&b)) {
                // another developer's data already waits under this ID: leave it be
                Some(waiting) if waiting.developer != record.developer => continue,
                Some(_) => {}
                None if write => {
                    put(RESTORED, id, &record.encode());
                }
                None => {}
            },
        }
        let dict = maki_app_host_api::data_dict(id);
        if read_key(store, &dict, key, basis).is_some() {
            continue; // maki has it already: keep maki's
        }
        if (!write || put(&dict, key, &e.value)) && !apps_back.iter().any(|a| a == id) {
            apps_back.push(id.to_string());
        }
    }
    added.apps = apps_back.len() as u32;
    for e in entries.iter().filter(|e| (e.dict as usize) < BACKUP_DICTS.len()) {
        let dict = BACKUP_DICTS[e.dict as usize];
        if dict == passkeys::DICT {
            if e.key == passkeys::COUNTER.to_string() {
                let theirs = e.value.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
                let ours = read_key(store, dict, &e.key, basis)
                    .and_then(|v| v.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap())))
                    .unwrap_or(0);
                if let Some(theirs) = theirs.filter(|&t| t > ours) {
                    if write {
                        store.pddb.delete_key(dict, &e.key, Some(basis)).ok();
                        put(dict, &e.key, &theirs.to_le_bytes());
                    }
                }
                continue;
            }
            let Some(id) = passkeys::credential_id(&e.value) else { continue };
            if have.iter().any(|(_, have)| have == id) {
                continue; // maki has it already: keep maki's
            }
            let Some(slot) = free.next() else { continue }; // no room left
            if !write || put(dict, &slot.to_string(), &e.value) {
                have.push((slot, id.to_vec()));
                added.passkeys += 1;
            }
            continue;
        }
        if read_key(store, dict, &e.key, basis).is_some() {
            continue; // maki has it already: keep maki's
        }
        if !write || put(dict, &e.key, &e.value) {
            if e.dict == 0 {
                added.logins += 1;
            } else {
                added.codes += 1;
            }
        }
    }
    if write {
        store.pddb.sync().ok();
    }
    added
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

/// A wallet op on the keys (`KeysOp::Wallet`). Every path starts with a hardened purpose and
/// coin type (the app host holds each app to its own paths too); the fingerprint's takes none.
fn wallet_op(keys: &maki_hd::seed::SeedKeys, op: u8, path: &[u32], digest: &[u8]) -> Result<Vec<u8>, maki_hd::Error> {
    if op != WALLET_FINGERPRINT && (!maki_hd::prefix_ok(&path[..path.len().min(2)]) || path.len() > maki_hd::MAX_DEPTH) {
        return Err(maki_hd::Error::Path);
    }
    // fresh randomness in each Schnorr signature, as BIP340 advises
    maki_hd::seed::answer(keys, op, path, digest, &random())
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

    /// maki's lock record: `lock`, or a PIN change's if that's all there is.
    fn lock(&self) -> Option<Lock> { self.primary_lock().or_else(|| self.next_lock()) }

    fn primary_lock(&self) -> Option<Lock> { self.read(KEY_LOCK).and_then(|b| Lock::from_bytes(&b)) }

    fn next_lock(&self) -> Option<Lock> { self.read(KEY_LOCK_NEXT).and_then(|b| Lock::from_bytes(&b)) }

    /// Make `lock` the only record.
    fn keep_lock(&self, lock: &Lock) -> std::io::Result<()> {
        self.write(KEY_LOCK, &lock.to_bytes())?;
        self.pddb.delete_key(DICT, KEY_LOCK_NEXT, Some(PDDB_DEFAULT_SYSTEM_BASIS)).ok();
        self.pddb.sync()
    }

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

    /// This maki's name: the one it picked, or a new pick the first time.
    fn name(&self) -> String {
        if let Some(name) = self.read(KEY_NAME).and_then(|b| String::from_utf8(b).ok()) {
            if maki_proto::names::valid(&name) {
                return name;
            }
        }
        let name = maki_proto::names::pick(random::<1>()[0]).to_string();
        match self.write(KEY_NAME, name.as_bytes()) {
            Ok(()) => log::info!("this maki is {name}"),
            Err(e) => log::error!("couldn't keep its name: {e:?}"),
        }
        name
    }

    /// Destroy the wrapped key: the secret basis can't be opened again by anyone who asks
    /// this firmware. (Its pages stay allocated; the PDDB can only delete a basis that's open.)
    fn wipe(&self) {
        self.pddb.delete_key(DICT, KEY_LOCK, Some(PDDB_DEFAULT_SYSTEM_BASIS)).ok();
        self.pddb.delete_key(DICT, KEY_LOCK_NEXT, Some(PDDB_DEFAULT_SYSTEM_BASIS)).ok();
        self.pddb.delete_key(DICT, KEY_TRIES, Some(PDDB_DEFAULT_SYSTEM_BASIS)).ok();
        self.pddb.sync().ok();
    }
}

/// The basis key, if `pin` opens `lock`.
fn open_lock(lock: &Lock, pin: &str) -> Option<[u8; 32]> {
    let mut kek = derive(pin, &lock.salt, lock.rounds);
    let opened = Aes256GcmSiv::new_from_slice(&kek).ok().and_then(|c| {
        c.decrypt(Nonce::from_slice(&lock.nonce), Payload { msg: &lock.wrapped, aad: lock.basis.as_bytes() }).ok()
    });
    kek.zeroize();
    let mut opened = opened?;
    let key = (opened.len() == 32).then(|| <[u8; 32]>::try_from(&opened[..]).unwrap());
    opened.zeroize();
    key
}

/// A lock record: the basis key wrapped under a key from `pin`, with a fresh salt and nonce.
fn seal_lock(basis: &str, basis_key: &[u8; 32], pin: &str) -> Result<Lock, u32> {
    let salt: [u8; 16] = random();
    let nonce: [u8; 12] = random();
    let mut kek = derive(pin, &salt, ROUNDS);
    let cipher = Aes256GcmSiv::new_from_slice(&kek).map_err(|_| RESULT_FAILED)?;
    kek.zeroize();
    let wrapped = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: basis_key, aad: basis.as_bytes() })
        .map_err(|_| RESULT_FAILED)?;
    Ok(Lock { basis: basis.to_string(), rounds: ROUNDS, salt, nonce, wrapped })
}

fn set_pin(store: &Store, pin: &str) -> Result<(), u32> {
    if !pin_is_valid(pin) {
        return Err(RESULT_BAD_PIN);
    }
    let mut basis_key: [u8; 32] = random();
    let suffix: [u8; 4] = random();
    let basis = format!("maki-{:02x}{:02x}{:02x}{:02x}", suffix[0], suffix[1], suffix[2], suffix[3]);
    let lock = seal_lock(&basis, &basis_key, pin);
    let made = store.pddb.create_basis(&basis, &basis_key).and_then(|_| {
        store.pddb.unlock_basis(&basis, &basis_key, Some(BasisRetentionPolicy::Persist))
    });
    basis_key.zeroize();
    let lock = lock?;
    if let Err(e) = made {
        log::error!("couldn't make the secret basis: {:?}", e);
        return Err(RESULT_FAILED);
    }
    store.keep_lock(&lock).map_err(|_| RESULT_FAILED)?;
    store.set_tries(0).ok();
    log::info!("PIN set; secret basis {} made and open", lock.basis);
    Ok(())
}

/// Count a try, then see whether `pin` opens maki: the basis key, and the record it opened.
/// Err((result, tries left)): wrong, or wiped on the last try.
fn try_pin(store: &Store, pin: &str) -> Result<([u8; 32], Lock), (u32, u32)> {
    let records: Vec<Lock> = [store.primary_lock(), store.next_lock()].into_iter().flatten().collect();
    if records.is_empty() {
        return Err((RESULT_NOT_NOW, 0));
    }
    // counted before it's checked
    let tries = store.tries() + 1;
    if store.set_tries(tries).is_err() {
        return Err((RESULT_FAILED, 0));
    }
    for lock in records {
        if let Some(key) = open_lock(&lock, pin) {
            store.set_tries(0).ok();
            return Ok((key, lock));
        }
    }
    if tries >= MAX_TRIES {
        log::warn!("{} wrong PINs: wiping", tries);
        store.wipe();
        return Err((RESULT_WIPED, 0));
    }
    Err((RESULT_WRONG, MAX_TRIES - tries))
}

/// Ok(()) unlocked; Err((result, tries left)).
fn unlock(store: &Store, pin: &str) -> Result<(), (u32, u32)> {
    let (mut key, lock) = try_pin(store, pin)?;
    let result = store.pddb.unlock_basis(&lock.basis, &key, Some(BasisRetentionPolicy::Persist));
    key.zeroize();
    match result {
        Ok(()) => {
            // after a PIN change cut short, the record this PIN opened becomes the only one
            if store.next_lock().is_some() {
                store.keep_lock(&lock).ok();
            }
            log::info!("unlocked");
            Ok(())
        }
        Err(e) => {
            log::error!("the PIN was right but the basis wouldn't open: {:?}", e);
            Err((RESULT_FAILED, MAX_TRIES))
        }
    }
}

/// Ok(()) changed; Err((result, tries left)).
fn change_pin(store: &Store, current: &str, new: &str) -> Result<(), (u32, u32)> {
    if !pin_is_valid(new) {
        return Err((RESULT_BAD_PIN, MAX_TRIES.saturating_sub(store.tries())));
    }
    let (mut key, lock) = try_pin(store, current)?;
    let next = seal_lock(&lock.basis, &key, new);
    key.zeroize();
    let next = next.map_err(|code| (code, MAX_TRIES))?;
    // the new record goes beside the old before it replaces it
    store.write(KEY_LOCK_NEXT, &next.to_bytes()).map_err(|_| (RESULT_FAILED, MAX_TRIES))?;
    store.keep_lock(&next).map_err(|_| (RESULT_FAILED, MAX_TRIES))?;
    log::info!("PIN changed");
    Ok(())
}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("maki-keys PID is {}", xous::process::id());

    let xns = xous_names::XousNames::new().unwrap();
    let sid = xns.register_name(SERVER_NAME_KEYS, None).expect("can't register server");
    let store = Store { pddb: Pddb::new() };
    store.pddb.is_mounted_blocking();
    // this maki's name, once it's been read (or picked)
    let mut name_known: Option<String> = None;

    let mut state = if store.lock().is_some() { State::Locked } else { State::Unset };
    log::info!("starting {:?}", state);
    // the screen (the launcher), which alone may use the PIN and the phrase
    let mut screen: Option<xous::PID> = None;
    // the FIDO authenticator (the vault), which alone may have the passkeys' secrets
    let mut fido: Option<xous::PID> = None;
    // the app host, which alone may have apps' secrets
    let mut apps: Option<xous::PID> = None;
    // the backup being read out, and one being restored
    let mut sealed: Option<Vec<u8>> = None;
    let mut incoming: Vec<u8> = Vec::new();
    let mut incoming_total: u32 = 0;
    let mut seed = SeedCache(None);
    // wallet apps' keys (maki_hd), from the seed, while unlocked
    let mut wallet: Option<maki_hd::seed::SeedKeys> = None;
    // bumped when a restore writes to the FIDO store behind the vault's back
    let generation = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    // who's waiting for the secrets to open (and whether for the phrase too): see `WaitUnlocked`
    let mut waiting: Vec<(xous::MessageSender, bool)> = Vec::new();
    // and who's waiting for the state to change from the one they saw: see `WaitChange`
    let mut watching: Vec<(xous::MessageSender, usize)> = Vec::new();
    // whether there's a recovery phrase, and the wrong PINs so far: worked out when asked, and
    // forgotten after anything that could change them. Status checks used to read the PDDB
    // every time, waking it.
    let mut phrase_known: Option<bool> = None;
    let mut tries_known: Option<u32> = None;
    let phrase_made = |known: &mut Option<bool>| {
        *known.get_or_insert_with(|| store.lock().map(|l| store.entropy(&l.basis).is_some()).unwrap_or(false))
    };

    loop {
        let mut msg = xous::receive_message(sid).unwrap();
        let from_screen = screen.is_some() && msg.sender.pid() == screen;
        let op = FromPrimitive::from_usize(msg.body.id());
        if !matches!(op, Some(KeysOp::Status | KeysOp::WaitUnlocked | KeysOp::WaitChange)) {
            phrase_known = None;
            tries_known = None;
        }
        match op {
            Some(KeysOp::DeviceName) => {
                let name = name_known.get_or_insert_with(|| store.name());
                let bytes = &name.as_bytes()[..name.len().min(maki_proto::names::MAX_NAME)];
                let mut words = [0usize; 4];
                for (w, chunk) in words.iter_mut().zip(bytes.chunks(4)) {
                    let mut b = [0u8; 4];
                    b[..chunk.len()].copy_from_slice(chunk);
                    *w = u32::from_le_bytes(b) as usize;
                }
                xous::return_scalar5(msg.sender, bytes.len(), words[0], words[1], words[2], words[3]).ok();
            }
            Some(KeysOp::Status) => {
                // wrong PINs count while unlocked too: changing the PIN checks the current one
                let tries_left = if state == State::Unset {
                    MAX_TRIES
                } else {
                    MAX_TRIES.saturating_sub(*tries_known.get_or_insert_with(|| store.tries()))
                };
                let has_phrase = state == State::Unlocked && phrase_made(&mut phrase_known);
                let rest = tries_left as usize
                    | if has_phrase { HAS_PHRASE } else { 0 }
                    | (generation.load(Ordering::SeqCst) as usize & STORE_GENERATION_MASK) << STORE_GENERATION_SHIFT;
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
                            let planted = option_env!("MAKI_DEMO_BACKUP").is_some() && passkeys::plant_demo(&store.pddb, &lock.basis);
                            sealed = backup_key(seed.get(&store, state)).and_then(|mut key| {
                                let mut plain = gather(&store, &lock.basis);
                                let blob = seal(&key, &plain);
                                log::debug!("backup: {} bytes of records, sealed {:?}", plain.len(), blob.as_ref().map(|b| b.len()));
                                plain.zeroize();
                                key.zeroize();
                                blob
                            });
                            if planted {
                                passkeys::unplant_demo(&store.pddb, &lock.basis);
                            }
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
                let opened = backup_key(seed.get(&store, state)).and_then(|mut key| {
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
                let generation = generation.clone();
                std::thread::spawn(move || {
                    let mut msg = msg;
                    let store = Store { pddb: Pddb::new() };
                    let would = restore(&store, &basis, &entries, false);
                    let (result, added) = if would.logins + would.codes + would.passkeys + would.apps == 0 {
                        // nothing new; a higher signature counter still comes across
                        (RESULT_OK, restore(&store, &basis, &entries, true))
                    } else {
                        let xns = xous_names::XousNames::new().unwrap();
                        let count = |n: u32, one: &str| format!("{} {}{}", n, one, if n == 1 { "" } else { "s" });
                        let mut what = [count(would.logins, "login"), count(would.codes, "code"), count(would.passkeys, "passkey")]
                            .join("\n");
                        if would.apps > 0 {
                            what.push_str(&format!("\n{}'s data", count(would.apps, "app")));
                        }
                        let page = maki_launcher::Page { heading: "Restore".into(), value: "from a backup".into(), mono: what, prose: String::new() };
                        match maki_launcher::Launcher::new(&xns).map(|l| {
                            l.review("maki desktop", "Restore backup?", "adds what's missing", vec![page], "restore", "cancel", RESTORE_TIMEOUT_S)
                        }) {
                            Ok(Ok(maki_launcher::Answer::Allowed(_))) => (RESULT_OK, restore(&store, &basis, &entries, true)),
                            Ok(Ok(maki_launcher::Answer::Denied)) => (RESULT_DENIED, Added::default()),
                            Ok(Ok(maki_launcher::Answer::TimedOut)) => (RESULT_TIMED_OUT, Added::default()),
                            _ => (RESULT_FAILED, Added::default()),
                        }
                    };
                    // the FIDO store changed behind the vault's back: it re-reads it
                    generation.fetch_add(1, Ordering::SeqCst);
                    log::info!(
                        "restore: {} ({} logins, {} codes, {} passkeys, {} apps' data added)",
                        result,
                        added.logins,
                        added.codes,
                        added.passkeys,
                        added.apps
                    );
                    if let Some(mem) = msg.body.memory_message_mut() {
                        let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                        if let Ok(mut req) = buffer.to_original::<Chunk, _>() {
                            req.result = result;
                            req.done = true;
                            req.logins = added.logins;
                            req.codes = added.codes;
                            req.passkeys = added.passkeys;
                            buffer.replace(req).ok();
                        }
                    }
                });
            }
            Some(KeysOp::FidoStoreChanged) => {
                generation.fetch_add(1, Ordering::SeqCst);
            }
            Some(KeysOp::ClaimFido) => {
                if fido.is_none() {
                    fido = msg.sender.pid();
                    log::info!("the FIDO authenticator is PID {:?}", fido);
                }
                xous::return_scalar(msg.sender, (msg.sender.pid() == fido) as usize).ok();
            }
            Some(KeysOp::ClaimApps) => {
                if apps.is_none() {
                    apps = msg.sender.pid();
                    log::info!("the app host is PID {:?}", apps);
                }
                xous::return_scalar(msg.sender, (msg.sender.pid() == apps) as usize).ok();
            }
            Some(KeysOp::AppSecret) => {
                let Some(mem) = msg.body.memory_message_mut() else { continue };
                let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                let Ok(mut req) = buffer.to_original::<AppSecretRequest, _>() else { continue };
                req.secret.clear();
                let authorized = apps.is_some() && msg.sender.pid() == apps;
                let developer: Option<[u8; 32]> = req.developer.as_slice().try_into().ok();
                req.result = match if authorized { seed.get(&store, state) } else { None } {
                    _ if !authorized => RESULT_NOT_NOW,
                    None if state == State::Unlocked => RESULT_NO_PHRASE,
                    None => RESULT_NOT_NOW,
                    Some(mut s) => {
                        let secret = developer.and_then(|d| maki_seed::app_secret(&s, &req.id, &d, &req.label));
                        s.zeroize();
                        match secret {
                            Some(mut secret) => {
                                req.secret.extend_from_slice(&secret);
                                secret.zeroize();
                                RESULT_OK
                            }
                            None => RESULT_FAILED,
                        }
                    }
                };
                buffer.replace(req).ok();
            }
            Some(KeysOp::Wallet) => {
                let Some(mem) = msg.body.memory_message_mut() else { continue };
                let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                let Ok(mut req) = buffer.to_original::<WalletRequest, _>() else { continue };
                req.answer.clear();
                let authorized = apps.is_some() && msg.sender.pid() == apps;
                req.result = if !authorized {
                    RESULT_NOT_NOW
                } else {
                    if wallet.is_none() {
                        if let Some(mut s) = seed.get(&store, state) {
                            wallet = maki_hd::seed::SeedKeys::from_seed(&s).ok();
                            s.zeroize();
                        }
                    }
                    match &wallet {
                        None if state == State::Unlocked => RESULT_NO_PHRASE,
                        None => RESULT_NOT_NOW,
                        Some(keys) => match wallet_op(keys, req.op, &req.path, &req.digest) {
                            Ok(answer) => {
                                req.answer = answer;
                                RESULT_OK
                            }
                            Err(maki_hd::Error::Path) => RESULT_REFUSED,
                            Err(_) => RESULT_FAILED,
                        },
                    }
                };
                buffer.replace(req).ok();
            }
            Some(KeysOp::FidoKeys) => {
                let Some(mem) = msg.body.memory_message_mut() else { continue };
                let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                let Ok(mut req) = buffer.to_original::<FidoSecret, _>() else { continue };
                req.keys.clear();
                let authorized = fido.is_some() && msg.sender.pid() == fido;
                req.result = match if authorized { seed.get(&store, state) } else { None } {
                    _ if !authorized => RESULT_NOT_NOW,
                    None if state == State::Unlocked => RESULT_NO_PHRASE,
                    None => RESULT_NOT_NOW,
                    Some(mut s) => {
                        let keys = maki_seed::fido_keys(&s);
                        s.zeroize();
                        req.keys.extend_from_slice(&keys.encryption);
                        req.keys.extend_from_slice(&keys.authentication);
                        req.keys.extend_from_slice(&keys.cred_random);
                        RESULT_OK
                    }
                };
                buffer.replace(req).ok();
            }
            Some(KeysOp::Claim) => {
                if screen.is_none() {
                    screen = msg.sender.pid();
                    log::info!("the screen is PID {:?}", screen);
                }
                xous::return_scalar(msg.sender, (msg.sender.pid() == screen) as usize).ok();
            }
            Some(op @ (KeysOp::NewPhrase | KeysOp::RestorePhrase)) => {
                // whatever was derived before comes from another phrase, if any
                seed.forget();
                wallet = None;
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
            Some(KeysOp::ChangePin) => {
                let Some(mem) = msg.body.memory_message_mut() else { continue };
                let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                let Ok(mut req) = buffer.to_original::<PinRequest, _>() else { continue };
                let (result, tries_left) = if !from_screen || state != State::Unlocked {
                    (RESULT_NOT_NOW, 0)
                } else {
                    let basis = store.lock().map(|l| l.basis);
                    match change_pin(&store, &req.pin, &req.new_pin) {
                        Ok(()) => (RESULT_OK, MAX_TRIES),
                        Err((RESULT_WIPED, _)) => {
                            // the key is gone: close what's open, and start over
                            if let Some(basis) = basis {
                                store.pddb.lock_basis(&basis).ok();
                            }
                            if let Some(mut b) = sealed.take() {
                                b.zeroize();
                            }
                            wallet = None;
                            seed.forget();
                            state = State::Unset;
                            (RESULT_WIPED, 0)
                        }
                        Err(e) => e,
                    }
                };
                req.pin.zeroize();
                req.new_pin.zeroize();
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
                            wallet = None;
                            seed.forget();
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
            Some(KeysOp::WaitUnlocked) => {
                let phrase = msg.body.scalar_message().map(|m| m.arg1 != 0).unwrap_or(false);
                waiting.push((msg.sender, phrase));
            }
            Some(KeysOp::WaitChange) => {
                let seen = msg.body.scalar_message().map(|m| m.arg1).unwrap_or(usize::MAX);
                watching.push((msg.sender, seen));
            }
            _ => log::warn!("unknown opcode {}", msg.body.id()),
        }
        // answer whoever was waiting for what just happened (or was so already)
        if state == State::Unlocked && !waiting.is_empty() {
            let has_phrase = phrase_made(&mut phrase_known);
            waiting.retain(|&(sender, phrase)| {
                if phrase && !has_phrase {
                    return true;
                }
                xous::return_scalar(sender, 1).ok();
                false
            });
        }
        watching.retain(|&(sender, seen)| {
            if state as usize == seen {
                return true;
            }
            xous::return_scalar(sender, state as usize).ok();
            false
        });
    }
}
