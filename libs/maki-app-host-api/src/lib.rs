//! Client side of maki's app host (ARCHITECTURE.md, "Apps you can install"): what maki-link
//! uses to install, list and remove apps for maki desktop, to hand apps messages from the
//! computer, and to tell the host whether the clock is verified.
//!
//! The host checks every bundle itself and asks the owner before installing or removing
//! anything, so whoever calls these can't install or remove an app on their own.

use num_traits::ToPrimitive;
use xous_ipc::Buffer;

/// xous-names name of the host's server.
pub const SERVER_NAME_APP_HOST: &str = "_maki app host_";

#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub enum HostOp {
    /// Memory message (mutable lend) carrying an `Install`: a piece of a bundle, in order. The
    /// last is answered once the owner decides.
    Install = 1,
    /// Memory message (mutable lend) carrying an `AppList` with its `start`, filled in: the
    /// apps from there on, `LIST_PAGE` at most.
    List = 2,
    /// Memory message (mutable lend) carrying a `Remove`, answered once the owner decides.
    Remove = 3,
    /// Scalar from maki-link: `arg1` is 0 (unset), 1 (unverified) or 2 (verified).
    TimeState = 4,
    /// Memory message (mutable lend) carrying an `AppMessage`, answered with the app's answer
    /// (the link permission). The host starts the app without the screen if it isn't running.
    Message = 5,
    /// Memory message (mutable lend) carrying a `StoreUpdate`: a piece of one of the maki store's
    /// records (a root or a revocation list), in order. The last is checked and, if it's newer
    /// and signed as it must be, kept. Empty (`total` 0): just what maki has.
    StoreUpdate = 6,
}

/// Each installed app's key, focus and menu opcodes: `APP_OPS + 4 * slot` and on.
pub const APP_OPS: usize = 0x100;

pub const RESULT_OK: u32 = 0;
pub const RESULT_DENIED: u32 = 1;
pub const RESULT_TIMED_OUT: u32 = 2;
/// maki won't install it, and says why; the owner wasn't asked.
pub const RESULT_REFUSED: u32 = 3;
pub const RESULT_LOCKED: u32 = 4;
pub const RESULT_FAILED: u32 = 5;
/// No such app.
pub const RESULT_NO_APP: u32 = 6;
/// Another app is open on maki.
pub const RESULT_BUSY: u32 = 7;

/// The biggest message to or from an app.
pub const MAX_MESSAGE: usize = 4096;

/// A piece of a bundle, and what became of it.
#[derive(Debug, Clone, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Install {
    pub total: u32,
    pub offset: u32,
    pub data: Vec<u8>,
    /// Set by the host: whether this was the last piece.
    pub done: bool,
    pub result: u32,
    /// Why maki refused it.
    pub reason: String,
}

#[derive(Debug, Clone, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct AppInfo {
    pub id: String,
    pub name: String,
    pub version: u32,
    pub label: String,
    pub developer: Vec<u8>,
    pub from_store: bool,
    pub backup: bool,
    /// Bytes of storage used.
    pub used: u32,
    /// 64x64, `maki_icons` form, or empty.
    pub icon: Vec<u32>,
    /// Bytes its bundle takes.
    pub bundle: u32,
    /// Bytes of storage its manifest asks for, kept for it.
    pub storage: u32,
}

#[derive(Debug, Clone, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct AppList {
    /// Asked for: the first app wanted, counting from 0 in the host's order (by ID).
    pub start: u32,
    pub apps: Vec<AppInfo>,
    /// Set by the host: how many apps there are in all.
    pub total: u32,
    pub result: u32,
}

/// The most apps in one answer to `List`. xous-ipc serializes with 256 bytes of scratch space,
/// and a list takes 20 of them for each app in it: 13 apps couldn't be sent at once.
pub const LIST_PAGE: usize = 8;

#[derive(Debug, Clone, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Remove {
    pub id: String,
    pub result: u32,
}

/// A message for an app, and its answer. `result`: `RESULT_OK` (answered), `RESULT_DENIED`
/// (the app went on without answering), `RESULT_NO_APP`, `RESULT_TIMED_OUT`, `RESULT_BUSY`,
/// `RESULT_LOCKED`, `RESULT_REFUSED` (it hasn't the link permission), `RESULT_FAILED` (it stopped).
#[derive(Debug, Clone, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct AppMessage {
    pub id: String,
    pub message: Vec<u8>,
    pub answer: Vec<u8>,
    pub result: u32,
}

/// A piece of a store record, and on the way back what maki has: the root's version, and the
/// revocation list's version and expiry (0 for none).
#[derive(Debug, Clone, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct StoreUpdate {
    pub total: u32,
    pub offset: u32,
    pub data: Vec<u8>,
    /// Set by the host: whether this was the last piece.
    pub done: bool,
    pub result: u32,
    /// Why maki refused it.
    pub reason: String,
    pub root_version: u32,
    pub revocations_version: u32,
    pub revocations_expires: u64,
}

/// The biggest store record maki takes.
pub const MAX_STORE_RECORD: usize = 64 * 1024;

/// The most apps maki keeps.
pub const MAX_APPS: usize = 32;

/// The room apps have in maki's encrypted database, which they share with its logins, codes and
/// passkeys: their bundles, and the storage each asks for, kept for it whether it's used or not.
/// (The database won't say how much of it is free, by design: that would say how much is hidden
/// in it.)
pub const APP_SPACE: u32 = 2 * 1024 * 1024;

#[derive(Clone, Copy)]
pub struct AppHost {
    conn: xous::CID,
}

impl AppHost {
    /// Blocks until the host is running.
    pub fn new(xns: &xous_names::XousNames) -> Result<Self, xous::Error> {
        Ok(AppHost { conn: xns.request_connection_blocking(SERVER_NAME_APP_HOST)? })
    }

    /// The host, if it's running: an image can be built without it.
    pub fn try_new(xns: &xous_names::XousNames) -> Option<Self> {
        xns.request_connection(SERVER_NAME_APP_HOST).ok().map(|conn| AppHost { conn })
    }

    /// Hands over a piece of a bundle. Pieces come in order, each up to 4096 bytes; the last
    /// returns once the owner decides.
    pub fn install(&self, total: u32, offset: u32, data: Vec<u8>) -> Install {
        let failed = Install { result: RESULT_FAILED, done: true, ..Default::default() };
        let request =
            Install { total, offset, data, done: false, result: RESULT_FAILED, reason: String::new() };
        let mut buf = Buffer::new(8192);
        if buf.replace(request).is_err()
            || buf.lend_mut(self.conn, HostOp::Install.to_u32().unwrap()).is_err()
        {
            return failed;
        }
        buf.to_original::<Install, _>().unwrap_or(failed)
    }

    /// Every installed app, asked for `LIST_PAGE` at a time.
    pub fn list(&self) -> AppList {
        let failed = AppList { result: RESULT_FAILED, ..Default::default() };
        let mut list = AppList { result: RESULT_OK, ..Default::default() };
        loop {
            // room for a page of apps with their icons
            let mut buf = Buffer::new((LIST_PAGE * 768 + 4096).next_multiple_of(4096));
            let ask = AppList { start: list.apps.len() as u32, ..Default::default() };
            if buf.replace(ask).is_err() || buf.lend_mut(self.conn, HostOp::List.to_u32().unwrap()).is_err() {
                return failed;
            }
            let Ok(page) = buf.to_original::<AppList, _>() else { return failed };
            if page.result != RESULT_OK {
                return page;
            }
            let more = !page.apps.is_empty();
            list.apps.extend(page.apps);
            list.total = page.total;
            // all of them, or as many as maki keeps (were apps installed as it went)
            if !more || list.apps.len() >= page.total as usize || list.apps.len() > MAX_APPS {
                return list;
            }
        }
    }

    /// Removes an app and its data, once the owner says so on maki.
    pub fn remove(&self, id: &str) -> u32 {
        let Ok(mut buf) = Buffer::into_buf(Remove { id: id.into(), result: RESULT_FAILED }) else {
            return RESULT_FAILED;
        };
        if buf.lend_mut(self.conn, HostOp::Remove.to_u32().unwrap()).is_err() {
            return RESULT_FAILED;
        }
        buf.to_original::<Remove, _>().map(|r| r.result).unwrap_or(RESULT_FAILED)
    }

    /// Hands `message` to the app with this ID, and returns once it has answered (which may
    /// take as long as the owner does, if it asks them).
    pub fn message(&self, id: &str, message: Vec<u8>) -> AppMessage {
        let failed = AppMessage { result: RESULT_FAILED, ..Default::default() };
        let request = AppMessage { id: id.into(), message, answer: Vec::new(), result: RESULT_FAILED };
        // room for the message and the answer
        let mut buf = Buffer::new(3 * 4096);
        if buf.replace(request).is_err()
            || buf.lend_mut(self.conn, HostOp::Message.to_u32().unwrap()).is_err()
        {
            return failed;
        }
        buf.to_original::<AppMessage, _>().unwrap_or(failed)
    }

    /// Hands over a piece of a store record; the last is checked and kept if it's newer.
    pub fn store_update(&self, total: u32, offset: u32, data: Vec<u8>) -> StoreUpdate {
        let failed = StoreUpdate { result: RESULT_FAILED, done: true, ..Default::default() };
        let request = StoreUpdate { total, offset, data, result: RESULT_FAILED, ..Default::default() };
        let mut buf = Buffer::new(8192);
        if buf.replace(request).is_err()
            || buf.lend_mut(self.conn, HostOp::StoreUpdate.to_u32().unwrap()).is_err()
        {
            return failed;
        }
        buf.to_original::<StoreUpdate, _>().unwrap_or(failed)
    }

    pub fn set_time_state(&self, state: u8) {
        xous::send_message(
            self.conn,
            xous::Message::new_scalar(HostOp::TimeState.to_usize().unwrap(), state as usize, 0, 0, 0),
        )
        .ok();
    }
}

/// PDDB dictionary (secret basis) of installed apps' records, keyed by app ID. maki-keys reads
/// it for backups.
pub const APPS: &str = "maki.apps";

/// PDDB dictionary (secret basis) of apps a restore brought data back for but that aren't
/// installed: their records, keyed by ID, until an app of that ID is. Its data stays only if
/// the same developer signed it.
pub const RESTORED: &str = "maki.restored";

/// PDDB dictionary (secret basis) of an app's own storage, keyed as the app keys it.
pub fn data_dict(id: &str) -> String { format!("maki.data.{id}") }

/// What the host remembers about an installed app, to list it and put it on the home screen
/// without reading its bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub version: u32,
    /// Whether its data goes in the backup: the manifest's default until the owner says.
    pub backup: bool,
    pub from_store: bool,
    pub developer: [u8; 32],
    pub name: String,
    pub label: String,
    pub icon: Option<[u32; 128]>,
    /// Bytes its bundle takes, and of storage its manifest asks for: what it takes of
    /// `APP_SPACE`. Records from before maki kept these (in backups) have 0; installing sets
    /// them.
    pub bundle: u32,
    pub storage: u32,
}

impl Record {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48 + self.name.len() + self.label.len() + 512);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(self.backup as u8);
        out.push(self.from_store as u8);
        out.extend_from_slice(&self.developer);
        for s in [&self.name, &self.label] {
            out.push(s.len().min(255) as u8);
            out.extend_from_slice(&s.as_bytes()[..s.len().min(255)]);
        }
        match &self.icon {
            Some(icon) => {
                out.push(1);
                icon.iter().for_each(|w| out.extend_from_slice(&w.to_le_bytes()));
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.bundle.to_le_bytes());
        out.extend_from_slice(&self.storage.to_le_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Option<Record> {
        let mut at = 0;
        let mut take = |n: usize| {
            let s = b.get(at..at + n)?;
            at += n;
            Some(s)
        };
        let version = u32::from_le_bytes(take(4)?.try_into().ok()?);
        let backup = take(1)?[0] != 0;
        let from_store = take(1)?[0] != 0;
        let developer: [u8; 32] = take(32)?.try_into().ok()?;
        let len = take(1)?[0] as usize;
        let name = String::from_utf8(take(len)?.to_vec()).ok()?;
        let len = take(1)?[0] as usize;
        let label = String::from_utf8(take(len)?.to_vec()).ok()?;
        let icon = match take(1)?[0] {
            0 => None,
            _ => {
                let raw = take(512)?;
                let mut icon = [0u32; 128];
                for (w, c) in icon.iter_mut().zip(raw.chunks_exact(4)) {
                    *w = u32::from_le_bytes(c.try_into().unwrap());
                }
                Some(icon)
            }
        };
        let sizes = take(8);
        let (bundle, storage) = match (sizes, b.len() - at) {
            (Some(s), 0) => {
                (u32::from_le_bytes(s[..4].try_into().ok()?), u32::from_le_bytes(s[4..].try_into().ok()?))
            }
            (None, 0) => (0, 0),
            _ => return None,
        };
        Some(Record { version, backup, from_store, developer, name, label, icon, bundle, storage })
    }
}

#[cfg(test)]
mod tests {
    use core::mem::MaybeUninit;

    use rkyv::rancor::Failure;
    use rkyv::ser::allocator::SubAllocator;
    use rkyv::ser::writer::Buffer as Writer;

    use super::*;

    #[test]
    fn records_round_trip_and_refuse_what_they_cut() {
        let r = Record {
            version: 7,
            backup: true,
            from_store: false,
            developer: [9; 32],
            name: "Dice".into(),
            label: "1.2".into(),
            icon: Some(core::array::from_fn(|i| i as u32)),
            bundle: 9417,
            storage: 1024,
        };
        let b = r.encode();
        assert_eq!(Record::decode(&b), Some(r.clone()));
        // a record from before maki kept the sizes, as a backup may hold one
        let old = b.len() - 8;
        assert_eq!(Record::decode(&b[..old]), Some(Record { bundle: 0, storage: 0, ..r.clone() }));
        for len in (0..b.len()).filter(|&len| len != old) {
            assert_eq!(Record::decode(&b[..len]), None, "cut to {len}");
        }
        let mut longer = b.clone();
        longer.push(0);
        assert_eq!(Record::decode(&longer), None);
        let plain = Record { icon: None, label: String::new(), ..r };
        assert_eq!(Record::decode(&plain.encode()), Some(plain));
    }

    /// Whether it serializes as xous-ipc's `Buffer::replace` does it: with 256 bytes of scratch.
    fn goes_through_ipc(list: &AppList) -> bool {
        let mut out = vec![0u8; 64 * 1024];
        let mut scratch = [MaybeUninit::<u8>::uninit(); 256];
        rkyv::api::low::to_bytes_in_with_alloc::<_, _, Failure>(
            list,
            Writer::from(&mut out[..]),
            SubAllocator::new(&mut scratch),
        )
        .is_ok()
    }

    #[test]
    fn a_page_of_apps_goes_through_ipc_and_all_of_them_wouldnt() {
        let app = AppInfo {
            id: "com.leviathan.maki.passphrase".into(),
            name: "Passphrase".into(),
            label: "Leviathan Security".into(),
            developer: vec![7; 32],
            icon: vec![0x5555_5555; 32],
            ..Default::default()
        };
        let list = |n| AppList { apps: vec![app.clone(); n], total: MAX_APPS as u32, ..Default::default() };
        assert!(goes_through_ipc(&list(LIST_PAGE)));
        // why they're paged
        assert!(!goes_through_ipc(&list(MAX_APPS)));
    }
}
