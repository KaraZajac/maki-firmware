//! Native apps (ARCHITECTURE.md, "Native apps: what confinement takes"): each runs in a process
//! of its own, started from the stub (`apps-baosec/maki-spawn`, embedded as `spawn.bin`), which
//! loads the app's ELF and confines itself before any of the app's code runs. The runner then
//! serves what the app asks of maki (`maki_native::service`) with the same `Session` a
//! WebAssembly app's imports use: the same rules, the same permissions. The app's process ends
//! when the app does, when it doesn't return in time after the owner leaves it, or when maki
//! stops it: the host created it, so the host can end it (`xous::terminate_child`).

use std::rc::Rc;
use std::time::{Duration, Instant};

use maki_native::load::{self, STACK_KIB};
use maki_native::service;
use maki_wasm::{Color, Limits, Session, Stop, Style};
use xous::{MemoryAddress, MemoryFlags, MemorySize};

use crate::runner::{Ctx, Device, ExitWatch};

/// The stub: `apps-baosec/maki-spawn`, built by its `build-stub.sh`.
const SPAWN: &[u8] = include_bytes!("spawn.bin");
/// How long an app told to exit has to return before its process is ended.
const EXIT_GRACE: Duration = Duration::from_secs(2);

/// Whether maki runs this native app, and what it gives it (`maki_wasm::admit`).
pub fn admit(manifest: &maki_bundle::Manifest, elf: &[u8]) -> Result<Limits, String> { maki_wasm::admit(manifest, elf) }

fn why(answer: u32) -> &'static str {
    match answer {
        load::BAD_ELF => "its code isn't what maki checked",
        load::NO_ROOM => "it needs more memory than it asks for",
        load::CANT_MAP => "maki couldn't make room for it",
        load::CANT_CONNECT => "maki's app service isn't there",
        load::NOT_ANSWERED => "the loader didn't answer",
        _ => "the loader refused it",
    }
}

/// A process from the stub, the app loaded into it and confined: its PID.
fn start(elf: &[u8], memory_kib: u32) -> Result<xous::PID, String> {
    let at = MemoryAddress::new(load::STUB_ADDRESS).unwrap();
    let args = xous::ProcessArgs::new(SPAWN, at, at).stack_size(MemorySize::new(STACK_KIB as usize * 1024).unwrap());
    let child = xous::create_process(args).map_err(|e| format!("maki couldn't start it: {e:?}"))?;
    let loaded = lend_elf(child.cid, elf, memory_kib);
    // the stub's server is gone (it destroyed it, loaded or not). The connection is freed, or
    // each app started would take one of this process's 32 for good. SAFETY: create_process
    // made it for this call alone; nothing else here has it.
    unsafe { xous::disconnect(child.cid).ok() };
    match loaded {
        Ok(()) => Ok(child.pid),
        Err(why) => {
            xous::terminate_child(child.pid).ok();
            Err(format!("maki couldn't load it: {why}"))
        }
    }
}

/// Lends the stub the app's ELF, with what it needs to know, and reads its answer.
fn lend_elf(cid: xous::CID, elf: &[u8], memory_kib: u32) -> Result<(), &'static str> {
    let len = load::HEADER + elf.len();
    let mut range = xous::map_memory(None, None, len.next_multiple_of(4096), MemoryFlags::R | MemoryFlags::W)
        .map_err(|_| "there's no memory to load it with")?;
    {
        let buf = unsafe { range.as_slice_mut::<u8>() };
        let put = |buf: &mut [u8], at: usize, v: u32| buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
        put(buf, load::AT_MEMORY_KIB, memory_kib);
        put(buf, load::AT_ELF_LEN, elf.len() as u32);
        put(buf, load::AT_STACK_KIB, STACK_KIB);
        put(buf, load::AT_ANSWER, load::NOT_ANSWERED);
        buf[load::HEADER..len].copy_from_slice(elf);
    }
    let sent = xous::send_message(cid, xous::Message::new_lend_mut(load::OP_LOAD, range, None, MemorySize::new(len)));
    let answer = {
        let buf = unsafe { range.as_slice::<u8>() };
        u32::from_le_bytes(buf[load::AT_ANSWER..load::AT_ANSWER + 4].try_into().unwrap())
    };
    xous::unmap_memory(range).ok();
    match (sent, answer) {
        (Ok(_), load::LOADED) => Ok(()),
        _ => Err(why(answer)),
    }
}

/// Pokes the app service from this process: the runner looks at what's waiting.
pub fn poke() {
    if let Some(sid) = xous::SID::from_bytes(&service::SID) {
        if let Ok(cid) = xous::connect(sid) {
            xous::try_send_message(cid, xous::Message::new_scalar(service::POKE, 0, 0, 0, 0)).ok();
        }
    }
}

/// Starts the app in a process of its own and serves it until it stops; then its process ends.
pub fn run(ctx: &Rc<Ctx>, device: Device, elf: Vec<u8>, limits: Limits) -> Stop {
    let id = device.id().to_string();
    let watch = device.watch();
    let started = start(&elf, (limits.memory / 1024) as u32);
    // the app's process has its code now
    drop(elf);
    let pid = match started {
        Ok(pid) => pid,
        Err(why) => return Stop::Failed(why),
    };
    log::info!("{id}: running in PID {}, confined", pid.get());
    ctx.shared.lock().unwrap().native = Some(pid);
    let wallet = device.wallet();
    let mut session = Session::new(Box::new(device), limits);
    session.wallet = wallet;
    let stop = serve(ctx, &mut session, &watch, pid);
    // whatever it's doing: its process ends here, if it hasn't ended itself
    xous::terminate_child(pid).ok();
    ctx.shared.lock().unwrap().native = None;
    stop
}

/// When an app told to exit must have returned by; the service is poked then, in case the
/// app isn't asking anything.
fn grace() -> Instant {
    std::thread::Builder::new()
        .stack_size(16 * 1024)
        .spawn(|| {
            std::thread::sleep(EXIT_GRACE);
            poke();
        })
        .ok();
    Instant::now() + EXIT_GRACE
}

/// The kernel ends a process that faults, without a word to anyone: the app's crash comes to
/// light when maki next looks (`SysCall::ChildRunning`).
fn gone(pid: xous::PID) -> bool { !xous::child_running(pid).unwrap_or(true) }

const GONE: &str = "its process ended without saying why";

fn millis_words(v: u64) -> (usize, usize) { (v as u32 as usize, (v >> 32) as u32 as usize) }

/// What the app asks, from its process, until it stops.
fn serve(ctx: &Ctx, session: &mut Session, watch: &ExitWatch, pid: xous::PID) -> Stop {
    let me = xous::process::id();
    // when it was told to exit, and must have returned by
    let mut exit_by: Option<Instant> = None;
    let mut last_log = String::new();
    loop {
        let Ok(mut msg) = xous::receive_message(ctx.service) else { return Stop::Failed("maki's app service failed".into()) };
        let sender = msg.sender.pid();
        let id = msg.body.id();
        if id == service::POKE && sender.map(|p| p.get() as u32) == Some(me) {
            if exit_by.is_some_and(|t| Instant::now() >= t) {
                return Stop::Exited;
            }
            if gone(pid) {
                return after_gone(ctx, pid, session.exit_sent, last_log);
            }
            // the owner left it (or maki's stopping it) while it wasn't waiting for events: it
            // sees Exit at its next wait, and has as long to return as if it had been waiting
            if exit_by.is_none() && watch.exit_waiting() {
                exit_by = Some(grace());
            }
            continue;
        }
        if sender != Some(pid) {
            refuse(&mut msg);
            continue;
        }
        match id {
            service::WAIT => {
                let arg = msg.body.scalar_message().map(|s| s.arg1).unwrap_or(0);
                let timeout = if arg as u32 == u32::MAX { -1 } else { (arg as u32).min(i32::MAX as u32) as i32 };
                let code = session.wait(timeout);
                if xous::return_scalar(msg.sender, code.map(|c| c as u32 as usize).unwrap_or(service::EXITED)).is_err()
                    && gone(pid)
                {
                    return after_gone(ctx, pid, session.exit_sent, last_log);
                }
                if session.exit_sent && exit_by.is_none() {
                    exit_by = Some(grace());
                }
            }
            service::MILLIS => {
                let (lo, hi) = millis_words(session.millis().max(0) as u64);
                xous::return_scalar2(msg.sender, lo, hi).ok();
            }
            service::UNIX_TIME => {
                let t = session.unix_time();
                let (lo, hi) = millis_words(t.max(0) as u64);
                xous::return_scalar5(msg.sender, lo, hi, session.time_verified() as usize, (t >= 0) as usize, 0).ok();
            }
            service::MOTION => {
                let (status, xyz) = match session.motion() {
                    Ok(v) => (0, v),
                    Err(code) => (code, [0; 3]),
                };
                let w = |v: i16| v as i32 as u32 as usize;
                xous::return_scalar5(msg.sender, status as u32 as usize, w(xyz[0]), w(xyz[1]), w(xyz[2]), 0).ok();
            }
            service::EXIT => return exit(&msg, session.exit_sent, last_log),
            _ => {
                let Some(mem) = msg.body.memory_message_mut() else { continue };
                let buf = unsafe { mem.buf.as_slice_mut::<u8>() };
                // read where it lies, never copied: the app makes the buffer as big as it likes
                let Some((status, reply)) = service::payload(buf).map(|request| lent(session, id, request, &mut last_log))
                else {
                    continue;
                };
                service::answer(buf, status, &reply);
            }
        }
    }
}

/// How the app says it stopped (`service::EXIT`): returning, or crashing after it logged why.
fn exit(msg: &xous::MessageEnvelope, exit_sent: bool, last_log: String) -> Stop {
    if msg.body.scalar_message().is_some_and(|s| s.arg1 != 0) {
        Stop::Crashed(if last_log.is_empty() { "it gave no reason".into() } else { last_log })
    } else if exit_sent {
        Stop::Exited
    } else {
        Stop::Finished
    }
}

/// Its process is gone. A scalar outlasts its sender, so if it said it was stopping, that's
/// waiting still, behind whatever came first; if not, it crashed.
fn after_gone(ctx: &Ctx, pid: xous::PID, exit_sent: bool, last_log: String) -> Stop {
    while let Ok(Some(mut msg)) = xous::try_receive_message(ctx.service) {
        if msg.sender.pid() == Some(pid) && msg.body.id() == service::EXIT {
            return exit(&msg, exit_sent, last_log);
        }
        refuse(&mut msg);
    }
    Stop::Crashed(GONE.into())
}

/// A message the app service won't act on: answered, so no sender is left waiting.
fn refuse(msg: &mut xous::MessageEnvelope) {
    if let Some(mem) = msg.body.memory_message_mut() {
        let buf = unsafe { mem.buf.as_slice_mut::<u8>() };
        if buf.len() >= service::HEAD {
            service::set_head(buf, maki_wasm::REFUSED, 0);
        }
    } else if msg.body.is_blocking() {
        xous::return_scalar(msg.sender, service::EXITED).ok();
    }
}

/// A request in a lent buffer: its status and what goes back.
fn lent(session: &mut Session, id: usize, request: &[u8], last_log: &mut String) -> (i32, Vec<u8>) {
    let text = || core::str::from_utf8(request).ok();
    // a request that starts with one length byte, then that much text, then the rest
    let split = || -> Option<(&str, &[u8])> {
        let n = *request.first()? as usize;
        let label = core::str::from_utf8(request.get(1..1 + n)?).ok()?;
        Some((label, &request[1 + n..]))
    };
    match id {
        service::PRESENT => {
            for op in maki_native::draw::read(request) {
                let Ok(op) = op else { break };
                draw(session, op);
            }
            session.present();
            (0, vec![])
        }
        service::TEXT_WIDTH => {
            let (Some(&style), Some(Ok(s))) = (request.first(), request.get(1..).map(core::str::from_utf8)) else {
                return (maki_wasm::INVALID, vec![]);
            };
            let Some(style) = Style::from_i32(style as i32) else { return (maki_wasm::INVALID, vec![]) };
            if s.len() > maki_wasm::MAX_TEXT {
                return (maki_wasm::TOO_BIG, vec![]);
            }
            (0, maki_wasm::Canvas::text_width(s, style).to_le_bytes().to_vec())
        }
        service::MENU => match text() {
            Some(s) => (session.menu(s), vec![]),
            None => (maki_wasm::INVALID, vec![]),
        },
        service::RANDOM => {
            let n = request.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize).unwrap_or(0);
            match session.random(n) {
                Ok(bytes) => (0, bytes),
                Err(code) => (code, vec![]),
            }
        }
        service::LOG => {
            let line = String::from_utf8_lossy(&request[..request.len().min(maki_wasm::MAX_LOG)]);
            session.log(&line);
            *last_log = line.into_owned();
            (0, vec![])
        }
        service::WALLET_FINGERPRINT => match session.wallet_fingerprint() {
            Ok(fp) => (0, fp.to_vec()),
            Err(code) => (code, vec![]),
        },
        service::WALLET_PUBLIC => match request.split_first().and_then(|(form, rest)| path_of(rest).map(|p| (*form, p))) {
            Some((form, path)) => match session.wallet_public(&path, form) {
                Ok(key) => (0, key),
                Err(code) => (code, vec![]),
            },
            None => (maki_wasm::INVALID, vec![]),
        },
        service::WALLET_REVIEW => {
            let parsed = (request.len() >= 8).then(|| {
                let signatures = u32::from_le_bytes(request[..4].try_into().unwrap());
                let timeout = i32::from_le_bytes(request[4..8].try_into().unwrap());
                (signatures, timeout, std::str::from_utf8(&request[8..]).ok())
            });
            match parsed {
                Some((signatures, timeout, Some(text))) => (session.wallet_review(text, signatures, timeout), vec![]),
                _ => (maki_wasm::INVALID, vec![]),
            }
        }
        service::WALLET_SIGN => {
            let parsed = (request.len() >= 33).then(|| (request[0], &request[1..33], path_of(&request[33..])));
            match parsed {
                Some((scheme, digest, Some(path))) => match session.wallet_sign(&path, digest, scheme) {
                    Ok(sig) => (0, sig),
                    Err(code) => (code, vec![]),
                },
                _ => (maki_wasm::INVALID, vec![]),
            }
        }
        service::WALLET_SUBADDRESS => {
            let parsed = (request.len() >= 8).then(|| {
                let major = u32::from_le_bytes(request[..4].try_into().unwrap());
                let minor = u32::from_le_bytes(request[4..8].try_into().unwrap());
                (major, minor, path_of(&request[8..]))
            });
            match parsed {
                Some((major, minor, Some(path))) => match session.wallet_subaddress(&path, major, minor) {
                    Ok(keys) => (0, keys.to_vec()),
                    Err(code) => (code, vec![]),
                },
                _ => (maki_wasm::INVALID, vec![]),
            }
        }
        service::WALLET_SHOW_BACKUP => match path_of(request) {
            Some(path) => (session.wallet_show_backup(&path), vec![]),
            None => (maki_wasm::INVALID, vec![]),
        },
        service::WALLET_MONERO_VIEW_KEY => match path_of(request).map(|p| session.wallet_monero_view_key(&p)) {
            Some(Ok(key)) => (0, key.to_vec()),
            Some(Err(code)) => (code, vec![]),
            None => (maki_wasm::INVALID, vec![]),
        },
        service::WALLET_MONERO_KEY_IMAGE => {
            let parsed = (request.len() >= maki_wasm::MONERO_OUTPUT)
                .then(|| (&request[..maki_wasm::MONERO_OUTPUT], path_of(&request[maki_wasm::MONERO_OUTPUT..])));
            match parsed {
                Some((output, Some(path))) => match session.wallet_monero_key_image(&path, output) {
                    Ok(image) => (0, image.to_vec()),
                    Err(code) => (code, vec![]),
                },
                _ => (maki_wasm::INVALID, vec![]),
            }
        }
        service::WALLET_MONERO_SIGN => {
            let parsed = request.get(..4).map(|n| u32::from_le_bytes(n.try_into().unwrap()) as usize).and_then(|n| {
                let asked = request.get(4..4 + n)?;
                Some((asked, path_of(&request[4 + n..])))
            });
            match parsed {
                Some((asked, Some(path))) => match session.wallet_monero_sign(&path, asked) {
                    Ok(signed) => (0, signed),
                    Err(code) => (code, vec![]),
                },
                _ => (maki_wasm::INVALID, vec![]),
            }
        }
        service::WALLET_SIGN_ED25519 => {
            let parsed = request.get(..4).map(|n| u32::from_le_bytes(n.try_into().unwrap()) as usize).and_then(|n| {
                let message = request.get(4..4 + n)?;
                Some((message, path_of(&request[4 + n..])))
            });
            match parsed {
                Some((message, Some(path))) => match session.wallet_sign_ed25519(&path, message) {
                    Ok(sig) => (0, sig.to_vec()),
                    Err(code) => (code, vec![]),
                },
                _ => (maki_wasm::INVALID, vec![]),
            }
        }
        service::STORAGE_GET => match text().map(|k| session.storage_get(k)) {
            Some(Ok(v)) => (0, v),
            Some(Err(code)) => (code, vec![]),
            None => (maki_wasm::INVALID, vec![]),
        },
        service::STORAGE_SET => match split() {
            Some((key, value)) => (session.storage_set(key, value), vec![]),
            None => (maki_wasm::INVALID, vec![]),
        },
        service::STORAGE_DELETE => match text() {
            Some(key) => (session.storage_delete(key), vec![]),
            None => (maki_wasm::INVALID, vec![]),
        },
        service::STORAGE_KEY => {
            let index = request.get(..4).map(|b| i32::from_le_bytes(b.try_into().unwrap())).unwrap_or(-1);
            match session.storage_key(index) {
                Ok(key) => (0, key.into_bytes()),
                Err(code) => (code, vec![]),
            }
        }
        service::ASK => {
            let timeout = request.get(..4).map(|b| i32::from_le_bytes(b.try_into().unwrap())).unwrap_or(0);
            match request.get(4..).map(core::str::from_utf8) {
                Some(Ok(text)) => (session.ask(text, timeout), vec![]),
                _ => (maki_wasm::INVALID, vec![]),
            }
        }
        service::ASK_REVIEW => {
            let timeout = request.get(..4).map(|b| i32::from_le_bytes(b.try_into().unwrap())).unwrap_or(0);
            match request.get(4..).map(core::str::from_utf8) {
                Some(Ok(text)) => (session.ask_review(text, timeout), vec![]),
                _ => (maki_wasm::INVALID, vec![]),
            }
        }
        service::KEY_SECRET | service::KEY_PUBLIC => match text() {
            Some(label) => {
                let key = if id == service::KEY_SECRET { session.key_secret(label) } else { session.key_public(label) };
                match key {
                    Ok(k) => (0, k.to_vec()),
                    Err(code) => (code, vec![]),
                }
            }
            None => (maki_wasm::INVALID, vec![]),
        },
        service::KEY_SIGN => match split() {
            Some((label, message)) => match session.key_sign(label, message) {
                Ok(sig) => (0, sig.to_vec()),
                Err(code) => (code, vec![]),
            },
            None => (maki_wasm::INVALID, vec![]),
        },
        service::KEY_SCHNORR_PUBLIC => match text() {
            Some(label) => match session.key_schnorr_public(label) {
                Ok(k) => (0, k.to_vec()),
                Err(code) => (code, vec![]),
            },
            None => (maki_wasm::INVALID, vec![]),
        },
        service::KEY_SCHNORR_SIGN => match split() {
            Some((label, message)) => match session.key_schnorr_sign(label, message) {
                Ok(sig) => (0, sig.to_vec()),
                Err(code) => (code, vec![]),
            },
            None => (maki_wasm::INVALID, vec![]),
        },
        service::KEY_X25519_PUBLIC => match text() {
            Some(label) => match session.key_x25519_public(label) {
                Ok(k) => (0, k.to_vec()),
                Err(code) => (code, vec![]),
            },
            None => (maki_wasm::INVALID, vec![]),
        },
        service::KEY_X25519_AGREE => match split() {
            Some((label, peer)) => match session.key_x25519_agree(label, peer) {
                Ok(shared) => (0, shared.to_vec()),
                Err(code) => (code, vec![]),
            },
            None => (maki_wasm::INVALID, vec![]),
        },
        service::TYPE_TEXT => match text() {
            Some(t) => (session.type_text(t), vec![]),
            None => (maki_wasm::INVALID, vec![]),
        },
        service::LINK_READ => match session.link_read() {
            Ok(m) => (0, m),
            Err(code) => (code, vec![]),
        },
        service::LINK_REPLY => (session.link_reply(request), vec![]),
        service::SCAN_QR => match session.scan_qr() {
            Ok(t) => (0, t.into_bytes()),
            Err(code) => (code, vec![]),
        },
        _ => (maki_wasm::INVALID, vec![]),
    }
}

/// One of a frame's operations, on the app's canvas: those that don't make sense are skipped.
fn draw(session: &mut Session, op: maki_native::draw::Draw) {
    use maki_native::draw::Draw;
    let color = |c: u8| Color::from_i32(c as i32);
    let canvas = &mut session.canvas;
    match op {
        Draw::Clear { color: c } => {
            if let Some(c) = color(c) {
                canvas.clear(c)
            }
        }
        Draw::Pixel { x, y, color: c } => {
            if let Some(c) = color(c) {
                canvas.pixel(x as i32, y as i32, c)
            }
        }
        Draw::Line { x0, y0, x1, y1, color: c } => {
            if let Some(c) = color(c) {
                canvas.line(x0 as i32, y0 as i32, x1 as i32, y1 as i32, c)
            }
        }
        Draw::Rect { x, y, w, h, color: c, filled } => {
            if let Some(c) = color(c) {
                canvas.rect(x as i32, y as i32, w as i32, h as i32, c, filled)
            }
        }
        Draw::Text { x, y, style, color: c, text } => {
            if let (true, Some(s), Some(c)) = (text.len() <= maki_wasm::MAX_TEXT, Style::from_i32(style as i32), color(c)) {
                canvas.text(x as i32, y as i32, text, s, c);
            }
        }
        Draw::Blit { x, y, w, h, color: c, rows } => {
            let (w, h) = (w as i32, h as i32);
            let fits = w > 0 && h > 0 && w <= maki_wasm::MAX_BLIT && h <= maki_wasm::MAX_BLIT;
            if let (true, Some(c)) = (fits && rows.len() >= ((w + 7) / 8 * h) as usize, color(c)) {
                canvas.blit(x as i32, y as i32, w, h, rows, c);
            }
        }
        Draw::Qr { x, y, size, data } => {
            if data.len() <= maki_wasm::MAX_QR {
                canvas.qr(x as i32, y as i32, data, size as i32);
            }
        }
    }
}

/// A derivation path, as a native app sends it: little-endian u32s, at most `maki_hd::MAX_DEPTH`.
fn path_of(bytes: &[u8]) -> Option<Vec<u32>> {
    if bytes.len() % 4 != 0 || bytes.len() / 4 > maki_hd::MAX_DEPTH {
        return None;
    }
    Some(bytes.chunks_exact(4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).collect())
}
