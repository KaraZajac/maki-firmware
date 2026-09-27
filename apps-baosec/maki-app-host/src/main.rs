//! maki's app host (ARCHITECTURE.md, "Apps you can install"): one process that installs
//! `.maki` bundles, keeps them and their data in the secret basis, puts each on the home screen
//! and runs the one in front in maki-wasm. The main thread takes messages (the launcher's
//! keys, focus and menus for each app; installs, lists and removals from maki-link); the runner
//! thread runs apps; a watcher registers the installed apps once maki is unlocked and ends the
//! running app when it locks.

mod runner;
mod store;

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use maki_app_host_api::*;
use maki_launcher::{Answer, Focus, MenuMessage, Page};
use maki_ui::Key;
use num_traits::{FromPrimitive, ToPrimitive};
use runner::{Shared, Slot, ToRunner, ASK_TIMEOUT_S};
use store::{Record, Store};
use xous_ipc::Buffer;

pub(crate) fn tt() -> &'static ticktimer_server::Ticktimer {
    static TT: std::sync::OnceLock<ticktimer_server::Ticktimer> = std::sync::OnceLock::new();
    TT.get_or_init(|| ticktimer_server::Ticktimer::new().unwrap())
}

#[cfg(feature = "board-baosec")]
pub(crate) fn time_conn() -> xous::CID {
    xous::connect(xous::SID::from_bytes(bao1x_hal_service::api::TIME_SERVER_PUBLIC).unwrap()).unwrap()
}

#[cfg(not(feature = "board-baosec"))]
pub(crate) fn time_conn() -> xous::CID { 0 }

#[cfg(feature = "board-baosec")]
fn time_ms(time_conn: xous::CID, op: bao1x_hal_service::api::TimeOp) -> Option<u64> {
    use bao1x_hal_service::api::TimeOp;
    let set = matches!(
        xous::send_message(
            time_conn,
            xous::Message::new_blocking_scalar(TimeOp::WallClockTimeInit.to_usize().unwrap(), 0, 0, 0, 0),
        ),
        Ok(xous::Result::Scalar2(_, 1))
    );
    if !set {
        return None;
    }
    match xous::send_message(time_conn, xous::Message::new_blocking_scalar(op.to_usize().unwrap(), 0, 0, 0, 0)) {
        Ok(xous::Result::Scalar2(lo, hi)) => Some(((hi as u64) << 32) | lo as u64),
        _ => None,
    }
}

/// UTC, in milliseconds since 1970, if something has set the clock.
#[cfg(feature = "board-baosec")]
pub(crate) fn utc_ms(time_conn: xous::CID) -> Option<u64> {
    time_ms(time_conn, bao1x_hal_service::api::TimeOp::GetUtcTimeMs)
}

#[cfg(not(feature = "board-baosec"))]
pub(crate) fn utc_ms(_: xous::CID) -> Option<u64> { None }

/// Local time as `HH:MM`, a `?` after it if unverified, as the home screen shows it.
#[cfg(feature = "board-baosec")]
pub(crate) fn clock_text(time_conn: xous::CID, verified: bool) -> String {
    match time_ms(time_conn, bao1x_hal_service::api::TimeOp::GetLocalTimeMs) {
        Some(ms) => {
            let secs = (ms / 1000) % 86_400;
            format!("{:02}:{:02}{}", secs / 3600, (secs % 3600) / 60, if verified { "" } else { "?" })
        }
        None => String::from("--:--"),
    }
}

#[cfg(not(feature = "board-baosec"))]
pub(crate) fn clock_text(_: xous::CID, _: bool) -> String { String::from("--:--") }

fn key_op(slot: usize) -> u32 { (APP_OPS + slot * 4) as u32 }

/// Words in lines of at most `width` characters, for the ask's fixed-width lines.
fn wrap(text: &str, width: usize) -> String {
    let mut lines: Vec<String> = Vec::new();
    for word in text.split_whitespace() {
        match lines.last_mut() {
            Some(l) if l.chars().count() + 1 + word.chars().count() <= width => {
                l.push(' ');
                l.push_str(word);
            }
            _ => lines.push(word.to_string()),
        }
    }
    lines.join("\n")
}

/// Takes an app off the home screen and out of storage.
pub(crate) fn remove_app(store: &Store, launcher: &maki_launcher::Launcher, shared: &Mutex<Shared>, id: &str) {
    store.remove(id);
    let slot = {
        let mut sh = shared.lock().unwrap();
        let slot = sh.slots.iter().position(|s| s.as_ref().map(|s| s.id == id).unwrap_or(false));
        if let Some(slot) = slot {
            sh.slots[slot] = None;
        }
        slot
    };
    if let Some(slot) = slot {
        launcher.unregister(SERVER_NAME_APP_HOST, key_op(slot)).ok();
    }
}

/// Puts the installed apps on the home screen, and takes off any that are gone: after unlocking,
/// installing, and removing.
fn sync_home(store: &Store, launcher: &maki_launcher::Launcher, shared: &Mutex<Shared>) {
    let records = store.records();
    log::info!("{} apps installed", records.len());
    let mut unregister = Vec::new();
    let mut register = Vec::new();
    {
        let mut sh = shared.lock().unwrap();
        for (slot, s) in sh.slots.iter_mut().enumerate() {
            let current = s.as_ref().and_then(|s| records.iter().find(|(id, _)| *id == s.id));
            match (s.as_ref(), current) {
                (Some(_), None) => {
                    unregister.push(slot);
                    *s = None;
                }
                // renamed by an update: on again under the new name
                (Some(slot_app), Some((_, r))) if slot_app.name != r.name => {
                    unregister.push(slot);
                    *s = None;
                }
                _ => {}
            }
        }
        for (id, record) in &records {
            if sh.slots.iter().flatten().any(|s| s.id == *id) {
                continue;
            }
            let slot = sh.slots.iter().position(|s| s.is_none()).unwrap_or_else(|| {
                sh.slots.push(None);
                sh.slots.len() - 1
            });
            sh.slots[slot] = Some(Slot { id: id.clone(), name: record.name.clone() });
            register.push((slot, record.clone()));
        }
    }
    for slot in unregister {
        launcher.unregister(SERVER_NAME_APP_HOST, key_op(slot)).ok();
    }
    for (slot, record) in register {
        let op = key_op(slot);
        log::info!("{} on the home screen", record.name);
        launcher.register(&record.name, SERVER_NAME_APP_HOST, op, op + 1, op + 2, record.icon.as_ref()).ok();
    }
}

/// Ends the app with this ID if it's running, and waits for it (not long: an app that ignores
/// Exit is stopped at its next wait, and one that never waits runs out of fuel).
fn stop_if_running(shared: &Mutex<Shared>, to_runner: &Sender<ToRunner>, id: &str) {
    let running = |sh: &Shared| sh.running.and_then(|r| sh.slots.get(r).cloned().flatten()).map(|s| s.id == id).unwrap_or(false);
    if !running(&shared.lock().unwrap()) {
        return;
    }
    to_runner.send(ToRunner::Stop).ok();
    for _ in 0..100 {
        tt().sleep_ms(100).ok();
        if shared.lock().unwrap().running.is_none() {
            return;
        }
    }
    log::warn!("{id} didn't stop");
}

/// What the worker has to hand: connections made once.
struct Worker {
    keys: maki_keys::Keys,
    launcher: maki_launcher::Launcher,
    store: Store,
    shared: Arc<Mutex<Shared>>,
    to_runner: Sender<ToRunner>,
}

/// What the main thread passes the worker, with the message to answer when it's done; and
/// maki locking or unlocking.
enum Work {
    Install(xous::MessageEnvelope, Install, Vec<u8>),
    Remove(xous::MessageEnvelope, Remove),
    Unlocked(bool),
}

/// Checks a bundle that's all arrived, asks the owner, and installs it: the result, and why if
/// maki refused it.
fn install(w: &Worker, bytes: Vec<u8>) -> (u32, String) {
    let (keys, launcher, store, shared, to_runner) = (&w.keys, &w.launcher, &w.store, &*w.shared, &w.to_runner);
    if keys.status().0 != maki_keys::State::Unlocked {
        return (RESULT_LOCKED, String::new());
    }
    let start = tt().elapsed_ms();
    log::info!("a bundle of {} bytes to install", bytes.len());
    let b = match maki_bundle::read(&bytes) {
        Ok(b) => b,
        Err(e) => return (RESULT_REFUSED, e.to_string()),
    };
    log::info!("{}: signature checked ({} ms)", b.manifest.id, tt().elapsed_ms() - start);
    let loaded = match maki_wasm::load(&b.manifest, b.code) {
        Ok(loaded) => std::sync::Arc::new(loaded),
        Err(e) => return (RESULT_REFUSED, format!("maki won't install it: {e}")),
    };
    log::info!("{}: code checked ({} ms)", b.manifest.id, tt().elapsed_ms() - start);
    let m = &b.manifest;
    let installed = store.record(&m.id);
    log::info!("{}: installed before: {}", m.id, installed.is_some());
    match &installed {
        Some(old) => {
            if let Err(e) = maki_bundle::may_update(&old.developer, old.version, &b) {
                return (RESULT_REFUSED, e);
            }
        }
        None if store.records().len() >= MAX_APPS => {
            return (RESULT_REFUSED, format!("maki has room for {MAX_APPS} apps: remove one first"));
        }
        None => {}
    }

    // the owner decides, having seen everything
    let version = if m.label.is_empty() { format!("version {}", m.version) } else { m.label.clone() };
    let mut pages = vec![
        Page {
            heading: if installed.is_some() { "Update".into() } else { "Install".into() },
            value: m.name.clone(),
            mono: format!("{version}\n{}", m.id),
        },
        Page {
            heading: "Where from".into(),
            value: "Sideloaded".into(),
            mono: wrap("Nobody has reviewed it. Install apps only from people you trust.", 15),
        },
        Page {
            heading: "Developer key".into(),
            value: String::new(),
            mono: {
                let f = maki_bundle::fingerprint(&b.developer);
                format!("{}\n{}\n\n{}", &f[..14], &f[15..], wrap("maki desktop shows it too, to compare.", 15))
            },
        },
    ];
    for (p, reason) in &m.permissions {
        let mut mono = wrap(p.warning(), 15);
        if !reason.is_empty() {
            mono.push_str("\n\n");
            mono.push_str(&wrap(&format!("The developer says: {reason}"), 15));
        }
        pages.push(Page { heading: "It asks to".into(), value: p.title().into(), mono });
    }
    pages.push(Page {
        heading: "It needs".into(),
        value: String::new(),
        mono: format!("{} KiB storage\n{} KiB memory\nbackup: {}", m.storage_kib, m.memory_kib, if m.backup { "yes" } else { "no" }),
    });
    let (question, yes) = if installed.is_some() { ("Update app?", "update") } else { ("Install app?", "install") };
    log::info!("asking the owner to install {}", m.id);
    match launcher.review(&m.name, question, &version, pages, yes, "cancel", ASK_TIMEOUT_S) {
        Ok(Answer::Allowed(_)) => {}
        Ok(Answer::Denied) => return (RESULT_DENIED, String::new()),
        _ => return (RESULT_TIMED_OUT, String::new()),
    }
    if keys.status().0 != maki_keys::State::Unlocked {
        return (RESULT_LOCKED, String::new());
    }
    stop_if_running(shared, to_runner, &m.id);
    // a new app: data a restore brought back for its ID is its own only if the same developer
    // signed it; anything else under its ID goes, so no app starts with another's data
    let mut backup = installed.as_ref().map(|r| r.backup).unwrap_or(m.backup);
    if installed.is_none() {
        match store.restored(&m.id) {
            Some(r) if r.developer == b.developer => {
                log::info!("{}: keeping the data a restore brought back", m.id);
                backup = r.backup;
            }
            _ => store.drop_data(&m.id),
        }
        store.forget_restored(&m.id);
    }
    let record = Record {
        version: m.version,
        // the owner's choice survives updates, and restores
        backup,
        from_store: false,
        developer: b.developer,
        name: m.name.clone(),
        label: m.label.clone(),
        icon: b.icon,
    };
    if let Err(e) = store.install(&m.id, &record, &bytes) {
        log::error!("couldn't store {}: {:?}", m.id, e);
        return (RESULT_FAILED, String::new());
    }
    log::info!("installed {} {} ({})", m.id, version, maki_bundle::fingerprint(&b.developer));
    // compiled already: the runner keeps it, so the first open is quick
    to_runner.send(ToRunner::Loaded(m.id.clone(), m.version, loaded)).ok();
    sync_home(&store, &launcher, shared);
    (RESULT_OK, String::new())
}

/// Asks the owner, then removes the app and its data.
fn remove(w: &Worker, id: &str) -> u32 {
    let (keys, launcher, store, shared, to_runner) = (&w.keys, &w.launcher, &w.store, &*w.shared, &w.to_runner);
    if keys.status().0 != maki_keys::State::Unlocked {
        return RESULT_LOCKED;
    }
    let Some(record) = store.record(id) else { return RESULT_NO_APP };
    let detail = if record.backup { "its data goes too" } else { "its data isn't backed up" };
    match launcher.ask(&record.name, "Remove app?", detail, &[], ASK_TIMEOUT_S) {
        Ok(Answer::Allowed(_)) => {}
        Ok(Answer::Denied) => return RESULT_DENIED,
        _ => return RESULT_TIMED_OUT,
    }
    if keys.status().0 != maki_keys::State::Unlocked {
        return RESULT_LOCKED;
    }
    stop_if_running(shared, to_runner, id);
    remove_app(store, launcher, shared, id);
    log::info!("removed {id}");
    RESULT_OK
}

/// Installs and removes apps, one at a time, answering each message once it's done; and
/// between times puts the installed apps on the home screen whenever maki is unlocked, and
/// ends the running app when it locks.
fn worker(work: Receiver<Work>, shared: Arc<Mutex<Shared>>, to_runner: Sender<ToRunner>) {
    let xns = xous_names::XousNames::new().unwrap();
    let w = Worker {
        keys: maki_keys::Keys::new(&xns).expect("couldn't connect to maki-keys"),
        launcher: maki_launcher::Launcher::new(&xns).expect("couldn't connect to the launcher"),
        store: Store::new(),
        shared,
        to_runner,
    };
    let mut unlocked = false;
    loop {
        match work.recv() {
            Ok(Work::Install(mut msg, mut req, bytes)) => {
                let (result, reason) = install(&w, bytes);
                req.result = result;
                req.reason = reason;
                if let Some(mem) = msg.body.memory_message_mut() {
                    let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                    buffer.replace(req).ok();
                }
            }
            Ok(Work::Remove(mut msg, mut req)) => {
                req.result = remove(&w, &req.id);
                if let Some(mem) = msg.body.memory_message_mut() {
                    let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                    buffer.replace(req).ok();
                }
            }
            Ok(Work::Unlocked(now)) => {
                w.shared.lock().unwrap().unlocked = now;
                if now && !unlocked {
                    sync_home(&w.store, &w.launcher, &w.shared);
                }
                if !now && unlocked {
                    log::info!("maki locked: the running app, if any, ends");
                    w.to_runner.send(ToRunner::Stop).ok();
                }
                unlocked = now;
            }
            Err(_) => return,
        }
    }
}

/// Tells the worker when maki locks or unlocks. maki-keys answers when it happens: polling for
/// it woke three processes every time (this one, maki-keys and the PDDB), and RAM is short.
fn watch_lock(to_worker: Sender<Work>) {
    let xns = xous_names::XousNames::new().unwrap();
    let keys = maki_keys::Keys::new(&xns).expect("couldn't connect to maki-keys");
    let mut seen = keys.status().0;
    loop {
        if to_worker.send(Work::Unlocked(seen == maki_keys::State::Unlocked)).is_err() {
            return;
        }
        seen = keys.wait_change(seen);
    }
}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("maki app host PID is {}", xous::process::id());

    let xns = xous_names::XousNames::new().unwrap();
    let sid = xns.register_name(SERVER_NAME_APP_HOST, None).expect("can't register server");
    log::info!("app host ready");
    let shared = Arc::new(Mutex::new(Shared::default()));
    // the app host's role with maki-keys, before anything else can claim it: only it may have
    // apps' secrets
    if !maki_keys::Keys::new(&xns).map(|k| k.claim_apps()).unwrap_or(false) {
        log::error!("another process claimed the app host's role with maki-keys first");
    }
    let (to_runner, from_main) = mpsc::channel();
    // Three threads besides this one, each with a small stack.
    std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn({
            let shared = shared.clone();
            move || runner::runner(from_main, shared)
        })
        .unwrap();
    let (to_worker, work) = mpsc::channel();
    std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn({
            let (shared, to_runner) = (shared.clone(), to_runner.clone());
            move || worker(work, shared, to_runner)
        })
        .unwrap();
    std::thread::Builder::new()
        .stack_size(32 * 1024)
        .spawn({
            let to_worker = to_worker.clone();
            move || watch_lock(to_worker)
        })
        .unwrap();

    // the bundle coming in
    let mut incoming: Vec<u8> = Vec::new();
    loop {
        let mut msg = xous::receive_message(sid).unwrap();
        let op = msg.body.id();
        if op >= APP_OPS {
            let (slot, which) = ((op - APP_OPS) / 4, (op - APP_OPS) % 4);
            match which {
                0 => {
                    let keys: Vec<Key> = msg
                        .body
                        .scalar_message()
                        .map(|s| {
                            [s.arg1, s.arg2, s.arg3, s.arg4]
                                .iter()
                                .filter_map(|&k| char::from_u32(k as u32).and_then(Key::from_char))
                                .collect()
                        })
                        .unwrap_or_default();
                    for k in keys {
                        to_runner.send(ToRunner::Key(slot, k)).ok();
                    }
                }
                1 => {
                    let focus = msg.body.scalar_message().and_then(|s| Focus::from_usize(s.arg1));
                    let m = match focus {
                        Some(Focus::Foreground) => ToRunner::Open(slot),
                        Some(Focus::Exited) => ToRunner::Exited(slot),
                        _ => ToRunner::Hidden(slot),
                    };
                    to_runner.send(m).ok();
                }
                2 => match MenuMessage::of(&msg) {
                    Some(MenuMessage::Fill) => {
                        let mut items = shared.lock().unwrap().menus.get(&slot).cloned().unwrap_or_default();
                        items.push("App info".into());
                        let items: Vec<&str> = items.iter().map(String::as_str).collect();
                        MenuMessage::fill(&mut msg, &items);
                    }
                    Some(MenuMessage::Picked(i)) => {
                        to_runner.send(ToRunner::Menu(slot, i)).ok();
                    }
                    None => {}
                },
                _ => {}
            }
            continue;
        }
        match FromPrimitive::from_usize(op) {
            Some(HostOp::Install) => {
                let request = {
                    let buffer = unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                    buffer.to_original::<Install, _>()
                };
                let Ok(mut req) = request else { continue };
                if req.offset == 0 {
                    incoming.clear();
                }
                let last = req.offset as usize + req.data.len() >= req.total as usize;
                let out_of_order = req.offset as usize != incoming.len()
                    || req.total as usize > maki_bundle::MAX_BUNDLE
                    || req.offset as usize + req.data.len() > req.total as usize;
                req.done = true;
                if out_of_order {
                    incoming.clear();
                    req.result = RESULT_REFUSED;
                    req.reason = "pieces out of order".into();
                } else if !last {
                    incoming.extend_from_slice(&req.data);
                    req.done = false;
                    req.result = RESULT_OK;
                } else {
                    incoming.extend_from_slice(&req.data);
                    let bytes = std::mem::take(&mut incoming);
                    req.data.clear();
                    // answered by the worker, once the owner decides
                    to_worker.send(Work::Install(msg, req, bytes)).ok();
                    continue;
                }
                req.data.clear();
                if let Some(mem) = msg.body.memory_message_mut() {
                    let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                    buffer.replace(req).ok();
                }
            }
            Some(HostOp::List) => {
                let keys = maki_keys::Keys::new(&xns).expect("couldn't connect to maki-keys");
                let list = if keys.status().0 != maki_keys::State::Unlocked {
                    AppList { apps: Vec::new(), result: RESULT_LOCKED }
                } else {
                    let store = Store::new();
                    let apps = store
                        .records()
                        .into_iter()
                        .map(|(id, r)| AppInfo {
                            used: store.data_used(&id),
                            id,
                            name: r.name,
                            version: r.version,
                            label: r.label,
                            developer: r.developer.to_vec(),
                            from_store: r.from_store,
                            backup: r.backup,
                            icon: r.icon.map(|i| i.to_vec()).unwrap_or_default(),
                        })
                        .collect();
                    AppList { apps, result: RESULT_OK }
                };
                if let Some(mem) = msg.body.memory_message_mut() {
                    let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                    buffer.replace(list).ok();
                }
            }
            Some(HostOp::Remove) => {
                let request = {
                    let buffer = unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                    buffer.to_original::<Remove, _>()
                };
                let Ok(req) = request else { continue };
                // answered by the worker, once the owner decides
                to_worker.send(Work::Remove(msg, req)).ok();
            }
            Some(HostOp::Message) => {
                let request = {
                    let buffer = unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                    buffer.to_original::<AppMessage, _>()
                };
                let Ok(req) = request else { continue };
                let (unlocked, slot) = {
                    let sh = shared.lock().unwrap();
                    (sh.unlocked, sh.slots.iter().position(|s| s.as_ref().is_some_and(|s| s.id == req.id)))
                };
                match slot {
                    _ if !unlocked => runner::answer(msg, RESULT_LOCKED, &[]),
                    None => runner::answer(msg, RESULT_NO_APP, &[]),
                    // answered once the app does: the runner starts it if need be
                    Some(slot) => {
                        to_runner.send(ToRunner::Message(slot, msg, req.message)).ok();
                    }
                }
            }
            Some(HostOp::TimeState) => {
                if let Some(s) = msg.body.scalar_message() {
                    shared.lock().unwrap().time_state = s.arg1 as u8;
                }
            }
            None => log::warn!("unknown opcode {op}"),
        }
    }
}
