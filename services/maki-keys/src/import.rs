//! Imports from other password managers on the badge (IMPORT_PUT), and what the vault holds
//! (VAULT_STATUS): the vault read from the PDDB, the owner's question, and what's added, written
//! as the vault and its FIDO authenticator write their own records (`maki_proto::import` has the
//! formats, the checks and the rules, which the fake maki shares).

use std::collections::HashSet;
use std::io::Write;
use std::time::Duration;

use maki_keys_api::*;
use maki_launcher::{Answer, Page};
use maki_proto::import::{self, Have, Plan, opensk, vault};
use zeroize::Zeroize;

use crate::{Store, has_key, passkeys, read_key};

// maki_proto's limit is the authenticator's
const _: () = assert!(passkeys::CREDENTIALS.end - passkeys::CREDENTIALS.start == import::MAX_PASSKEYS);

/// How long the owner has to answer.
const IMPORT_TIMEOUT_S: u32 = maki_launcher::ask_timeout(60);
/// Records written between syncs: the PDDB keeps what's written in its memory until it syncs.
const SYNC_EVERY: usize = 32;
/// A write the PDDB turns down is tried this many times, a little later each time.
const WRITE_TRIES: u64 = 3;
/// What maki says of imported passkeys before its owner says yes to them.
const PASSKEYS: &str = "Their keys were made elsewhere and have been in a file on this computer. They don’t \
                        come from maki’s recovery phrase, so only a backup brings them back to a restored \
                        maki.";

/// What an import came to: maki-keys' answer to its last piece.
#[derive(Default)]
pub(crate) struct Outcome {
    pub result: u32,
    pub logins: u32,
    pub codes: u32,
    pub passkeys: u32,
    pub skipped: u32,
    pub reason: String,
}

/// A dictionary's keys in the secret basis: none if it doesn't exist yet (nothing of that kind
/// kept so far), Err if it couldn't be listed.
fn keys(store: &Store, dict: &str, basis: &str) -> Result<Vec<String>, ()> {
    match store.pddb.list_keys(dict, Some(basis)) {
        Ok(keys) => Ok(keys),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => {
            log::warn!("import: couldn't list {dict}: {e:?}");
            Err(())
        }
    }
}

/// The authenticator's slots in use, of those maki uses.
fn slots(keys: &[String]) -> Vec<usize> {
    keys.iter()
        .filter_map(|k| k.parse::<usize>().ok())
        .filter(|n| passkeys::CREDENTIALS.contains(n))
        .collect()
}

/// What the vault holds, for VAULT_STATUS: its logins, its codes (the vault's records of each),
/// its passkeys, and of those, how many maki was given in an import (marked, and still there).
pub(crate) fn counts(store: &Store, basis: &str) -> Result<VaultCounts, ()> {
    let logins = keys(store, vault::LOGINS, basis)?.len() as u32;
    let codes = keys(store, vault::CODES, basis)?.len() as u32;
    let taken = slots(&keys(store, passkeys::DICT, basis)?);
    let marks: HashSet<String> = keys(store, vault::IMPORTED, basis)?.into_iter().collect();
    let mut imported = 0;
    // a passkey's record has its private key: read only when there's a mark to find
    for slot in taken.iter().filter(|_| !marks.is_empty()) {
        if let Some(mut record) = read_key(store, passkeys::DICT, &slot.to_string(), basis) {
            if passkeys::credential_id(&record).is_some_and(|id| marks.contains(&vault::mark_key(id))) {
                imported += 1;
            }
            record.zeroize();
        }
    }
    Ok(VaultCounts { result: RESULT_OK, logins, codes, passkeys: taken.len() as u32, imported })
}

/// What the vault holds, as an import needs it: what it has, the authenticator's free slots, and
/// the creation order a new passkey gets (one past the newest, as OpenSK gives one).
struct Holding {
    have: Have,
    free: Vec<usize>,
    next_order: u64,
}

fn read_vault(store: &Store, basis: &str) -> Result<Holding, ()> {
    let mut have = Have::default();
    for key in keys(store, vault::LOGINS, basis)? {
        let record = read_key(store, vault::LOGINS, &key, basis);
        have.used += import::cost(record.as_ref().map_or(0, |r| r.len()));
        if let Some(mut record) = record {
            if let Some((site, username)) = vault::login_fields(&record) {
                have.logins.insert((maki_proto::site::normalize(&site), username));
            }
            record.zeroize();
        }
        have.login_keys.insert(key);
    }
    for key in keys(store, vault::CODES, basis)? {
        let record = read_key(store, vault::CODES, &key, basis);
        have.used += import::cost(record.as_ref().map_or(0, |r| r.len()));
        if let Some(mut record) = record {
            if let Some(secret) = vault::code_secret(&record) {
                have.code_secrets.push(secret);
            }
            record.zeroize();
        }
        have.code_keys.insert(key);
    }
    let taken = slots(&keys(store, passkeys::DICT, basis)?);
    let mut next_order = 0u64;
    for slot in &taken {
        let Some(mut record) = read_key(store, passkeys::DICT, &slot.to_string(), basis) else { continue };
        have.used += import::cost(record.len());
        if let Some(held) = opensk::read(&record) {
            next_order = next_order.max(held.creation_order.saturating_add(1));
            have.credential_ids.insert(held.credential_id);
            have.accounts.insert((held.rp_id, held.user_handle));
        }
        record.zeroize();
    }
    // the marks hold credential IDs, of 16 to 255 bytes: counted as the longest
    have.used += keys(store, vault::IMPORTED, basis)?.len() as u64 * import::cost(255);
    let free: Vec<usize> = passkeys::CREDENTIALS.filter(|n| !taken.contains(n)).collect();
    have.passkey_room = free.len();
    Ok(Holding { have, free, next_order })
}

enum Wrote {
    Added,
    /// a record by that name was there already: left as it was
    There,
    Failed,
}

/// Write a record maki doesn't have, never over one it has. A record half written is taken out
/// again: the vault would pass over one it can't read, but OpenSK reads every passkey for each
/// request, and one it couldn't read would fail them all.
fn add(store: &Store, dict: &str, key: &str, value: &[u8], basis: &str) -> Wrote {
    if has_key(store, dict, key, basis) {
        log::warn!("import: {dict} has a record by that name already: left as it is");
        return Wrote::There;
    }
    for attempt in 1..=WRITE_TRIES {
        let written = store
            .pddb
            .get(dict, key, Some(basis), true, true, Some(value.len()), None::<fn()>)
            .and_then(|mut k| k.write_all(value));
        match written {
            Ok(()) => return Wrote::Added,
            Err(e) => {
                log::warn!("import: couldn't write to {dict} (try {attempt} of {WRITE_TRIES}): {e:?}");
                std::thread::sleep(Duration::from_millis(200 * attempt));
            }
        }
    }
    store.pddb.delete_key(dict, key, Some(basis)).ok();
    Wrote::Failed
}

fn now_s() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Add what `plan` says is new: logins, codes, then passkeys, each passkey's mark before it. At
/// the first write that fails (the database full, or failing) maki stops, and says exactly what
/// it added: nothing is left half written.
fn write(store: &Store, basis: &str, plan: &Plan, holding: &Holding, outcome: &mut Outcome) {
    // why the rest wasn't added, said with what was: the PDDB won't say how full it is (that would
    // say how much is hidden in it), so a full one is found writing
    const FULL: &str = "its database is full, and the rest wasn\u{2019}t added";
    let ctime = now_s();
    let mut unsynced = 0;
    let written = |unsynced: &mut usize| {
        *unsynced += 1;
        if *unsynced >= SYNC_EVERY {
            store.pddb.sync().ok();
            *unsynced = 0;
        }
    };
    'adding: {
        for login in &plan.logins {
            let mut record = vault::login_record(login, ctime);
            let key = vault::login_key(&login.site, &login.username);
            let wrote = add(store, vault::LOGINS, &key, &record, basis);
            record.zeroize();
            match wrote {
                Wrote::Added => {
                    outcome.logins += 1;
                    written(&mut unsynced);
                }
                Wrote::There => {}
                Wrote::Failed => {
                    outcome.reason = FULL.into();
                    break 'adding;
                }
            }
        }
        for (name, code) in &plan.codes {
            let mut record = vault::code_record(name, code, ctime);
            let wrote = add(store, vault::CODES, &vault::code_key(name), &record, basis);
            record.zeroize();
            match wrote {
                Wrote::Added => {
                    outcome.codes += 1;
                    written(&mut unsynced);
                }
                Wrote::There => {}
                Wrote::Failed => {
                    outcome.reason = FULL.into();
                    break 'adding;
                }
            }
        }
        let mut free = holding.free.iter();
        let mut order = holding.next_order;
        for passkey in &plan.passkeys {
            // the mark first: one left without its passkey counts for nothing, where a passkey
            // without its mark would pass for one made on maki
            let mark = vault::mark_key(&passkey.credential_id);
            if let Wrote::Failed = add(store, vault::IMPORTED, &mark, &passkey.credential_id, basis) {
                outcome.reason = FULL.into();
                break 'adding;
            }
            let mut record = opensk::credential(passkey, order);
            let mut placed = false;
            for slot in free.by_ref() {
                match add(store, passkeys::DICT, &slot.to_string(), &record, basis) {
                    Wrote::Added => {
                        placed = true;
                        break;
                    }
                    // a passkey a site made there meanwhile: the next free slot
                    Wrote::There => {}
                    Wrote::Failed => break,
                }
            }
            record.zeroize();
            if !placed {
                outcome.reason = FULL.into();
                break 'adding;
            }
            outcome.passkeys += 1;
            order = order.saturating_add(1);
            written(&mut unsynced);
        }
    }
    if let Err(e) = store.pddb.sync() {
        log::error!("import: couldn't sync what was added: {e:?}");
    }
}

fn count(n: usize, one: &str) -> String { format!("{n} {one}{}", if n == 1 { "" } else { "s" }) }

/// The owner's question, on maki's screen over whatever is in front: where the import is from,
/// how many of each it adds, and, when there are passkeys, what's different about them.
fn ask(source: &str, plan: &Plan) -> Result<Answer, xous::Error> {
    let mut what = Vec::new();
    for (n, one) in
        [(plan.logins.len(), "login"), (plan.codes.len(), "code"), (plan.passkeys.len(), "passkey")]
    {
        if n > 0 {
            what.push(count(n, one));
        }
    }
    // "from" and the source, in bold, take one line: a longer name is cut there with "…", so it's
    // in the small type below as well, whole
    let mut prose = if source.chars().count() > 12 { format!("From {source}. ") } else { String::new() };
    match plan.skipped {
        0 => {}
        1 => prose.push_str("maki has one of its records already, and keeps its own."),
        n => prose.push_str(&format!("maki has {n} of its records already, and keeps its own.")),
    }
    let prose = prose.trim_end().to_string();
    let mut pages = vec![Page {
        heading: "Import".into(),
        value: format!("from {source}"),
        mono: what.join("\n"),
        prose,
    }];
    if !plan.passkeys.is_empty() {
        pages.push(Page {
            heading: "Passkeys".into(),
            value: "made elsewhere".into(),
            mono: String::new(),
            prose: PASSKEYS.into(),
        });
    }
    let xns = xous_names::XousNames::new()?;
    maki_launcher::Launcher::new(&xns)?.review(
        "maki desktop",
        "Import these?",
        &format!("from {source}"),
        pages,
        "import",
        "cancel",
        IMPORT_TIMEOUT_S,
    )
}

/// An import, whole: read and checked, every record, before anything's asked; refused with the
/// reason if a record won't do or maki hasn't the room; asked of the owner if there's anything
/// new; and what's new added. The import as it came is wiped once it's read: its records are
/// what's kept while the owner decides.
pub(crate) fn run(store: &Store, basis: &str, blob: zeroize::Zeroizing<Vec<u8>>) -> Outcome {
    let refused = |reason: String| {
        log::info!("import refused: {reason}");
        Outcome { result: RESULT_REFUSED, reason, ..Default::default() }
    };
    let parsed = import::parse(&blob);
    drop(blob);
    let import = match parsed {
        Ok(import) => import,
        Err(why) => return refused(why),
    };
    let Ok(holding) = read_vault(store, basis) else {
        return Outcome { result: RESULT_FAILED, ..Default::default() };
    };
    let plan = import::plan(&import, &holding.have);
    if let Err(why) = import::check_room(&plan, &holding.have) {
        return refused(why);
    }
    let mut outcome = Outcome { skipped: plan.skipped, ..Default::default() };
    if plan.clashes > 0 {
        log::warn!("import: {} records the vault can't keep beside its own, left out", plan.clashes);
    }
    // nothing new: nothing to ask
    if plan.is_empty() {
        log::info!("import from {}: nothing new, {} records maki has", import.source, plan.skipped);
        outcome.result = RESULT_OK;
        return outcome;
    }
    log::info!(
        "import from {}: {} logins, {} codes, {} passkeys? ({} records maki has)",
        import.source,
        plan.logins.len(),
        plan.codes.len(),
        plan.passkeys.len(),
        plan.skipped
    );
    outcome.result = match ask(&import.source, &plan) {
        Ok(Answer::Allowed(_)) => RESULT_OK,
        Ok(Answer::Denied) => RESULT_DENIED,
        Ok(Answer::TimedOut) => RESULT_TIMED_OUT,
        Err(e) => {
            log::error!("import: couldn't ask: {e:?}");
            RESULT_FAILED
        }
    };
    if outcome.result == RESULT_OK {
        write(store, basis, &plan, &holding, &mut outcome);
        log::info!(
            "import from {}: {} logins, {} codes, {} passkeys added",
            import.source,
            outcome.logins,
            outcome.codes,
            outcome.passkeys
        );
    }
    outcome
}
