//! What the host keeps, all in the secret basis (so nothing is there until maki is unlocked,
//! and the five-try wipe takes it all): each app's record in `maki.apps`, keyed by its ID; its
//! bundle, as installed, in `maki.app.<id>`; its data in `maki.data.<id>`, keyed as the app
//! keys it. PDDB calls without a basis use the latest opened, the secret basis once unlocked;
//! callers write only while maki is unlocked.

use std::io::{Read, Write};

pub use maki_app_host_api::{data_dict, Record, APPS, RESTORED};

const BUNDLE: &str = "bundle";

/// The maki store's newest root and revocation list that maki has taken (`maki_store`). Nothing
/// there: the root the firmware carries, and no list yet.
const STORE: &str = "maki.store";
const STORE_ROOT: &str = "root";
const STORE_REVOCATIONS: &str = "revocations";

/// The root this firmware carries: the store's first. The development store's until the real
/// one opens (DEVELOPMENT.md, "The store's keys").
const FIRST_ROOT: &[u8] = include_bytes!("../../../libs/maki-store/dev-store/roots/1.bin");

fn bundle_dict(id: &str) -> String { format!("maki.app.{id}") }

pub struct Store {
    pddb: pddb::Pddb,
}

impl Store {
    pub fn new() -> Store { Store { pddb: pddb::Pddb::new() } }

    fn read(&self, dict: &str, key: &str) -> Option<Vec<u8>> {
        let mut k = self.pddb.get(dict, key, None, false, false, None, None::<fn()>).ok()?;
        let mut v = Vec::new();
        k.read_to_end(&mut v).ok()?;
        Some(v)
    }

    fn write(&self, dict: &str, key: &str, value: &[u8]) -> std::io::Result<()> {
        self.pddb.delete_key(dict, key, None).ok();
        let mut k = self.pddb.get(dict, key, None, true, true, Some(value.len().max(1)), None::<fn()>)?;
        k.write_all(value)?;
        drop(k);
        self.pddb.sync()
    }

    /// Installed apps, by ID.
    pub fn records(&self) -> Vec<(String, Record)> {
        let mut out: Vec<(String, Record)> = self
            .pddb
            .list_keys(APPS, None)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|id| Some((id.clone(), self.record(&id)?)))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    pub fn record(&self, id: &str) -> Option<Record> { Record::decode(&self.read(APPS, id)?) }

    pub fn put_record(&self, id: &str, record: &Record) -> std::io::Result<()> { self.write(APPS, id, &record.encode()) }

    pub fn bundle(&self, id: &str) -> Option<Vec<u8>> { self.read(&bundle_dict(id), BUNDLE) }

    /// The bundle first, then the record, which is what makes it installed.
    pub fn install(&self, id: &str, record: &Record, bundle: &[u8]) -> std::io::Result<()> {
        self.write(&bundle_dict(id), BUNDLE, bundle)?;
        self.put_record(id, record)
    }

    /// The record first, so a half-finished removal leaves nothing that looks installed.
    pub fn remove(&self, id: &str) {
        self.pddb.delete_key(APPS, id, None).ok();
        self.pddb.delete_dict(&bundle_dict(id), None).ok();
        self.pddb.delete_dict(&data_dict(id), None).ok();
        self.pddb.sync().ok();
    }

    /// The root maki trusts: the newest it took, else its firmware's.
    pub fn store_root(&self) -> maki_store::Root {
        let taken = self.read(STORE, STORE_ROOT).and_then(|b| maki_store::SignedRoot::decode(&b).ok());
        match taken.as_ref().map(|s| s.trust_first()) {
            Some(Ok(root)) => root.clone(),
            _ => maki_store::SignedRoot::decode(FIRST_ROOT)
                .ok()
                .and_then(|s| s.trust_first().ok().cloned())
                .expect("the firmware's store root checks out"),
        }
    }

    pub fn put_store_root(&self, bytes: &[u8]) -> std::io::Result<()> { self.write(STORE, STORE_ROOT, bytes) }

    /// The newest revocation list maki took, with its signature, if any.
    pub fn signed_revocations(&self) -> Option<maki_store::SignedRevocations> {
        self.read(STORE, STORE_REVOCATIONS).and_then(|b| maki_store::SignedRevocations::decode(&b).ok())
    }

    /// The newest revocation list maki took, if any.
    pub fn revocations(&self) -> Option<maki_store::Revocations> { self.signed_revocations().map(|s| s.list) }

    pub fn put_revocations(&self, bytes: &[u8]) -> std::io::Result<()> { self.write(STORE, STORE_REVOCATIONS, bytes) }

    /// What a restore left for an app of this ID that wasn't installed then.
    pub fn restored(&self, id: &str) -> Option<Record> { Record::decode(&self.read(RESTORED, id)?) }

    pub fn forget_restored(&self, id: &str) {
        self.pddb.delete_key(RESTORED, id, None).ok();
        self.pddb.sync().ok();
    }

    /// An app's data, gone: before a new app of its ID starts, unless it's the same developer's.
    pub fn drop_data(&self, id: &str) {
        self.pddb.delete_dict(&data_dict(id), None).ok();
        self.pddb.sync().ok();
    }

    pub fn data_get(&self, id: &str, key: &str) -> Option<Vec<u8>> { self.read(&data_dict(id), key) }

    pub fn data_set(&self, id: &str, key: &str, value: &[u8]) -> std::io::Result<()> {
        self.write(&data_dict(id), key, value)
    }

    pub fn data_delete(&self, id: &str, key: &str) -> bool {
        let gone = self.pddb.delete_key(&data_dict(id), key, None).is_ok();
        if gone {
            self.pddb.sync().ok();
        }
        gone
    }

    pub fn data_keys(&self, id: &str) -> Vec<String> {
        let mut keys = self.pddb.list_keys(&data_dict(id), None).unwrap_or_default();
        keys.sort();
        keys
    }

    /// Bytes of storage an app uses, counted as the app's quota counts them.
    pub fn data_used(&self, id: &str) -> u32 {
        self.data_keys(id)
            .iter()
            .map(|k| k.len() + self.data_get(id, k).map(|v| v.len()).unwrap_or(0))
            .sum::<usize>() as u32
    }
}
