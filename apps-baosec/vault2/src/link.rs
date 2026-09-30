//! Browser requests, by way of maki desktop and maki-link: find what's saved for a site, ask the
//! owner on screen, answer. The launcher draws the question over whatever is in front, so this
//! works whether the vault is open or not. Every secret that leaves goes past the owner, with the
//! site that asked for it on the screen.

use std::thread;

use locales::t;
use maki_launcher::{Answer, Launcher};
use maki_proto::site;
use maki_vault_api::{ASK_TIMEOUT_S, Approval, Kind, Request, SERVER_NAME_VAULT_LINK, VaultLinkOp};
use num_traits::{FromPrimitive, ToPrimitive};
use xous_ipc::Buffer;

use crate::VaultOp;
use crate::storage::{self, ContentKind, PasswordRecord, StorageContent, TotpRecord};
use crate::totp::{TotpEntry, generate_totp_code, get_current_unix_time};

pub(crate) fn start(main_conn: xous::CID) {
    // maki's requests: a smaller stack than the default (128 KiB), which is plenty
    thread::Builder::new().stack_size(64 * 1024).spawn(move || {
        let xns = xous_names::XousNames::new().unwrap();
        // one connection, which maki-link makes at boot: no app can reach this
        let sid = xns.register_name(SERVER_NAME_VAULT_LINK, Some(1)).expect("can't register the vault link");
        let launcher = Launcher::new(&xns).expect("couldn't connect to the launcher");
        pddb::Pddb::new().is_mounted_blocking();
        // maki-link answers "locked" until the PIN is in; this is belt and braces
        maki_keys::Keys::new(&xns).expect("couldn't connect to maki-keys").wait_unlocked();
        let mut storage = storage::Manager::new(&xns);
        loop {
            let mut msg = xous::receive_message(sid).unwrap();
            match FromPrimitive::from_usize(msg.body.id()) {
                Some(VaultLinkOp::Request) => {
                    let Some(mem) = msg.body.memory_message_mut() else { continue };
                    let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                    let Ok(mut request) = buffer.to_original::<Request, _>() else {
                        log::warn!("vault link: malformed request");
                        continue;
                    };
                    let changed = answer(&mut request, &mut storage, &launcher);
                    log::info!("vault link: {} for {}: {}", kind_name(&request), request.site, request.approval);
                    buffer.replace(request).ok();
                    if changed {
                        // the vault's own lists are cached: bring them up to date
                        xous::send_message(
                            main_conn,
                            xous::Message::new_scalar(VaultOp::ReloadDbAndFullRedraw.to_usize().unwrap(), 0, 0, 0, 0),
                        )
                        .ok();
                    }
                }
                None => log::warn!("vault link: unknown opcode {}", msg.body.id()),
            }
        }
    })
    .unwrap();
}

fn kind_name(r: &Request) -> &'static str {
    match r.kind() {
        Some(Kind::Login) => "login",
        Some(Kind::Totp) => "code",
        Some(Kind::SaveLogin) => "save",
        None => "?",
    }
}

/// Fill in the answer to a request. Returns whether the vault's records changed.
fn answer(r: &mut Request, storage: &mut storage::Manager, launcher: &Launcher) -> bool {
    // maki-link checked the site; nothing unchecked goes on screen all the same
    let outcome = if !site::valid(&r.site) {
        Err(Approval::Unavailable)
    } else {
        match r.kind() {
            Some(Kind::Login) => login(r, storage, launcher),
            Some(Kind::Totp) => totp(r, storage, launcher),
            Some(Kind::SaveLogin) => save(r, storage, launcher),
            None => Err(Approval::Unavailable),
        }
    };
    let changed = match outcome {
        Ok(changed) => {
            r.approval = Approval::Approved as u8;
            changed
        }
        Err(approval) => {
            r.approval = approval as u8;
            r.username.clear();
            r.code.clear();
            false
        }
    };
    // nothing goes back that the host didn't need
    if r.kind() != Some(Kind::Login) || r.approval != Approval::Approved as u8 {
        r.password.clear();
    }
    changed
}

/// Ask the owner; with choices, which one. Anything but a yes becomes the approval to report.
fn ask(launcher: &Launcher, site: &str, question: &str, detail: &str, choices: &[String]) -> Result<usize, Approval> {
    match launcher.ask(site, question, detail, choices, TIMEOUT_S) {
        Ok(Answer::Allowed(i)) if choices.is_empty() || i < choices.len() => Ok(i),
        Ok(Answer::Allowed(_)) => Err(Approval::Unavailable),
        Ok(Answer::Denied) => Err(Approval::Denied),
        Ok(Answer::TimedOut) => Err(Approval::TimedOut),
        Err(_) => Err(Approval::Unavailable),
    }
}

fn now_s() -> u64 { get_current_unix_time().unwrap_or(0) }

/// How long the owner has. The emulator skips ahead through idle time, so a demo build
/// (MAKI_DEMO, see maki-link) waits long enough to be pressed there.
const TIMEOUT_S: u32 = maki_launcher::ask_timeout(ASK_TIMEOUT_S);

/// Everything of one kind in the vault. A vault that has never held any has no dictionary for
/// it yet, which means nothing saved; and the vault's own screen may be reading the same list,
/// which the PDDB turns away for a moment.
fn all<T: StorageContent + Default>(storage: &storage::Manager, kind: ContentKind) -> Result<Vec<T>, Approval> {
    use std::io::ErrorKind;
    for _ in 0..5 {
        match storage.all::<T>(kind.clone()) {
            Ok(records) => return Ok(records),
            Err(storage::Error::IoError(e)) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(storage::Error::IoError(e)) if e.kind() == ErrorKind::PermissionDenied => {
                thread::sleep(std::time::Duration::from_millis(100))
            }
            Err(e) => {
                log::warn!("vault link: couldn't read the vault: {:?}", e);
                return Err(Approval::Unavailable);
            }
        }
    }
    Err(Approval::Unavailable)
}

fn login(r: &mut Request, storage: &mut storage::Manager, launcher: &Launcher) -> Result<bool, Approval> {
    let mut found: Vec<PasswordRecord> = all::<PasswordRecord>(storage, ContentKind::Password)?
        .into_iter()
        .filter(|p| site::covers(&p.description, &r.site))
        .collect();
    if found.is_empty() {
        return Err(Approval::NoMatch);
    }
    found.sort_by_key(|p| std::cmp::Reverse(p.atime)); // the one used last, first
    let i = if found.len() == 1 {
        ask(launcher, &r.site, "Fill login?", &found[0].username, &[])?
    } else {
        let names: Vec<String> = found.iter().map(|p| p.username.clone()).collect();
        ask(launcher, &r.site, "Which login?", "", &names)?
    };
    let mut pw = found.swap_remove(i);
    r.username = pw.username.clone();
    r.password = pw.password.clone();
    // a use, as typing it out from the vault's own screen is
    let key = storage::hex(pw.hash());
    pw.count += 1;
    pw.atime = now_s();
    Ok(storage.update(&ContentKind::Password, &key, &mut pw).is_ok())
}

/// Entries whose name or issuer mentions the site ("GitHub" for github.com) go first.
fn likely_first(site: &str, entries: &[TotpRecord], mut order: Vec<usize>) -> Vec<usize> {
    let host = site::normalize(site);
    let labels: Vec<&str> = host.split('.').collect();
    let words: Vec<&str> = labels[..labels.len().saturating_sub(1)].iter().copied().filter(|l| l.len() >= 3).collect();
    let score = |t: &TotpRecord| {
        let text = format!("{} {}", t.name, t.notes).to_ascii_lowercase();
        words.iter().filter(|w| text.contains(*w)).count()
    };
    order.sort_by(|&a, &b| score(&entries[b]).cmp(&score(&entries[a])).then(entries[a].name.cmp(&entries[b].name)));
    order
}

fn totp(r: &mut Request, storage: &mut storage::Manager, launcher: &Launcher) -> Result<bool, Approval> {
    let entries: Vec<TotpRecord> =
        all::<TotpRecord>(storage, ContentKind::TOTP)?.into_iter().filter(|t| !t.is_hotp).collect();
    if entries.is_empty() {
        return Err(Approval::NoMatch);
    }
    let bound: Vec<usize> =
        (0..entries.len()).filter(|&i| entries[i].sites().any(|s| site::covers(s, &r.site))).collect();
    let (i, newly_bound) = match bound.len() {
        1 => (ask(launcher, &r.site, "Send code?", &entries[bound[0]].name, &[]).map(|_| bound[0])?, false),
        n if n > 1 => {
            let names: Vec<String> = bound.iter().map(|&i| entries[i].name.clone()).collect();
            (ask(launcher, &r.site, "Which code?", "", &names).map(|c| bound[c])?, false)
        }
        // none for this site yet: the owner picks one, once
        _ => {
            let order = likely_first(&r.site, &entries, (0..entries.len()).collect());
            let names: Vec<String> = order.iter().map(|&i| entries[i].name.clone()).collect();
            (ask(launcher, &r.site, "Code from?", "", &names).map(|c| order[c])?, true)
        }
    };
    let mut t = entries.into_iter().nth(i).ok_or(Approval::Unavailable)?;
    let step = if t.timestep == 0 { 30 } else { t.timestep };
    let secret = t.secret.to_ascii_uppercase().replace(' ', "");
    let entry = TotpEntry {
        step_seconds: step,
        shared_secret: base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret.trim_end_matches('='))
            .ok_or(Approval::Unavailable)?,
        digit_count: if t.digits == 0 { 6 } else { t.digits as u8 },
        algorithm: t.algorithm,
    };
    let now = now_s();
    r.code = generate_totp_code(now, &entry).map_err(|_| Approval::Unavailable)?;
    r.valid_for_s = (step - now % step).min(255) as u8;
    if newly_bound {
        let key = storage::hex(t.hash());
        t.add_site(&r.site);
        return Ok(storage.update(&ContentKind::TOTP, &key, &mut t).is_ok());
    }
    Ok(false)
}

fn save(r: &mut Request, storage: &mut storage::Manager, launcher: &Launcher) -> Result<bool, Approval> {
    let here = site::normalize(&r.site);
    let same_account = all::<PasswordRecord>(storage, ContentKind::Password)?
        .into_iter()
        .find(|p| site::normalize(&p.description) == here && p.username == r.username);
    match same_account {
        // already kept: nothing to ask
        Some(p) if p.password == r.password => Ok(false),
        Some(mut p) => {
            ask(launcher, &r.site, "Update password?", &r.username, &[])?;
            let key = storage::hex(p.hash());
            // keep the one it replaces in the notes, unless they hold something of the owner's:
            // a password change the site didn't take shouldn't lose the password that works
            let placeholder = t!("vault.notes", locales::LANG);
            if p.notes.is_empty() || p.notes == placeholder || p.notes.starts_with("previous password: ") {
                p.notes = format!("previous password: {}", p.password);
            }
            p.password = r.password.clone();
            storage.update(&ContentKind::Password, &key, &mut p).map_err(|_| Approval::Unavailable)?;
            Ok(true)
        }
        None => {
            ask(launcher, &r.site, "Keep new login?", &r.username, &[])?;
            let mut record = PasswordRecord {
                version: storage::VAULT_PASSWORD_REC_VERSION,
                description: r.site.clone(),
                username: r.username.clone(),
                password: r.password.clone(),
                notes: t!("vault.notes", locales::LANG).to_string(),
                ctime: 0, // set on write
                atime: 0,
                count: 0,
            };
            storage.new_record(&mut record, None, false).map_err(|_| Approval::Unavailable)?;
            Ok(true)
        }
    }
}
