//! A host stand-in for maki: the real protocol logic behind a TCP socket.
//!
//!     cargo run -p maki-proto --features fake --example fake_maki -- \
//!         [ADDR] [--deny | --ask] [--totp SITE=BASE32]... [--clock-verified]
//!
//! ADDR defaults to 127.0.0.1:7878. Logins and TOTP secrets live in memory; SAVE_LOGIN adds to them.
//! Approvals are automatic unless `--deny` (refuse everything) or `--ask` (ask on this terminal).
//! Codes need a verified clock, as on the badge: sync through Roughtime first, or start with
//! `--clock-verified` to take this computer's clock as verified (tests, offline work).
//! Everything maki-link does on the device happens here too, except the USB hop, the Xous clock and
//! maki's own screen. State survives reconnects, like a badge that stays plugged in.

use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use maki_proto::device::{reply, Approval, Ask, Device, Handled, Platform, TimeState};
use maki_proto::frame::{self, Deframer};
use maki_proto::site;

struct Host {
    start: Instant,
    clock: Option<(u64, Instant)>,
}

fn host_utc_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64 }

impl Platform for Host {
    fn fill_random(&mut self, buf: &mut [u8]) {
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).expect("no /dev/urandom");
    }

    fn uptime_ms(&self) -> u64 { self.start.elapsed().as_millis() as u64 }

    fn utc_ms(&self) -> Option<u64> { self.clock.map(|(t, at)| t + at.elapsed().as_millis() as u64) }

    fn set_time(&mut self, utc_ms: u64, tz_offset_s: i32) {
        let drift = utc_ms as i64 - host_utc_ms() as i64;
        println!("  clock set: {utc_ms} ms UTC, tz {tz_offset_s:+} s ({drift:+} ms from this computer)");
        self.clock = Some((utc_ms, Instant::now()));
    }

    fn time_state_changed(&mut self, state: TimeState) { println!("  time is now {state:?}"); }
}

#[derive(Clone, Copy, PartialEq)]
enum Policy {
    Approve,
    Deny,
    Ask,
}

#[derive(Default)]
struct Store {
    logins: Vec<(String, String, String)>,
    totp: Vec<(String, Vec<u8>)>,
}

fn base32(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut bits, mut n, mut out) = (0u64, 0, Vec::new());
    for c in s.trim_end_matches('=').bytes().map(|c| c.to_ascii_uppercase()) {
        bits = (bits << 5) | ALPHABET.iter().position(|&a| a == c)? as u64;
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    Some(out)
}

/// RFC 6238 with HMAC-SHA1, 30 s steps, 6 digits: what the vault computes for a default entry.
fn totp(secret: &[u8], unix_s: u64) -> (String, u8) {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret).unwrap();
    mac.update(&(unix_s / 30).to_be_bytes());
    let h = mac.finalize().into_bytes();
    let o = (h[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]);
    (format!("{:06}", bin % 1_000_000), (30 - unix_s % 30) as u8)
}

fn approve(policy: Policy, prompt: &str) -> Approval {
    match policy {
        Policy::Approve => {
            println!("  maki would ask: {prompt}  -> approved (automatic)");
            std::thread::sleep(Duration::from_millis(300)); // the owner reading the screen
            Approval::Approved
        }
        Policy::Deny => {
            println!("  maki would ask: {prompt}  -> denied (--deny)");
            Approval::Denied
        }
        Policy::Ask => {
            print!("  maki asks: {prompt} [y/N] ");
            std::io::stdout().flush().ok();
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line).ok();
            if line.trim().eq_ignore_ascii_case("y") { Approval::Approved } else { Approval::Denied }
        }
    }
}

/// What the vault does on the badge, minus the screen.
fn answer(ask: Ask, store: &Mutex<Store>, policy: Policy) -> (u8, Vec<u8>) {
    match ask {
        Ask::Login { site: s } => {
            let found = store.lock().unwrap().logins.iter().find(|(saved, _, _)| site::covers(saved, &s)).cloned();
            match found {
                None => reply::login(Approval::NoMatch, "", ""),
                Some((_, user, pass)) => {
                    reply::login(approve(policy, &format!("log in to {s} as {user}?")), &user, &pass)
                }
            }
        }
        Ask::Totp { site: s } => {
            let found = store.lock().unwrap().totp.iter().find(|(saved, _)| site::covers(saved, &s)).cloned();
            match found {
                None => reply::totp(Approval::NoMatch, "", 0),
                Some((_, secret)) => {
                    let a = approve(policy, &format!("code for {s}?"));
                    let (code, left) = totp(&secret, host_utc_ms() / 1000);
                    reply::totp(a, &code, left)
                }
            }
        }
        Ask::SaveLogin { site: s, username, password } => {
            let a = approve(policy, &format!("save a login for {s} as {username}?"));
            if a == Approval::Approved {
                let mut st = store.lock().unwrap();
                st.logins.retain(|(saved, user, _)| !(site::covers(saved, &s) && *user == username));
                st.logins.push((s, username, password));
            }
            reply::save(a)
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let addr = args.iter().find(|a| !a.starts_with("--") && a.contains(':')).cloned().unwrap_or("127.0.0.1:7878".into());
    let policy = if args.iter().any(|a| a == "--deny") {
        Policy::Deny
    } else if args.iter().any(|a| a == "--ask") {
        Policy::Ask
    } else {
        Policy::Approve
    };
    let store = Arc::new(Mutex::new(Store::default()));
    for pair in args.windows(2).filter(|w| w[0] == "--totp").map(|w| &w[1]) {
        let (s, secret) = pair.split_once('=').expect("--totp SITE=BASE32");
        store.lock().unwrap().totp.push((s.to_string(), base32(secret).expect("bad base32")));
    }

    let listener = TcpListener::bind(&addr).expect("bind");
    // print the bound address, so a caller that asked for port 0 learns the real one
    println!("fake maki listening on {}", listener.local_addr().unwrap());
    let mut device = Device::new(Host { start: Instant::now(), clock: None }, "maki", "0.2.0-fake".into());
    if args.iter().any(|a| a == "--clock-verified") {
        device.handle(&frame::Packet {
            kind: maki_proto::kind::TIME_UNVERIFIED,
            id: 0,
            body: maki_proto::wire::Writer::new().u64(host_utc_ms()).i32(0).finish(),
        });
        device.trust_platform_clock(0);
    }
    let device = Arc::new(Mutex::new(device));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        println!("connected: {:?}", stream.peer_addr());
        let writer: Arc<Mutex<TcpStream>> = Arc::new(Mutex::new(stream.try_clone().unwrap()));
        let mut deframer = Deframer::default();
        let mut buf = [0u8; 4096];
        loop {
            let n = match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            for packet in deframer.push(&buf[..n]) {
                let packet = match packet {
                    Ok(p) => p,
                    Err(e) => {
                        println!("  bad frame: {e:?}");
                        continue;
                    }
                };
                let handled = device.lock().unwrap().handle(&packet);
                match handled {
                    Handled::Reply(kind, body) => {
                        println!("  0x{:02x}#{} -> 0x{:02x} ({} bytes)", packet.kind, packet.id, kind, body.len());
                        writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                    }
                    // answered from another thread, like the vault on the badge: the link keeps
                    // serving heartbeats while the owner decides
                    Handled::Ask(ask) => {
                        println!("  0x{:02x}#{} -> asking the owner: {ask:?}", packet.kind, packet.id);
                        let (writer, store, id) = (writer.clone(), store.clone(), packet.id);
                        std::thread::spawn(move || {
                            let (kind, body) = answer(ask, &store, policy);
                            writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                        });
                    }
                }
            }
        }
        println!("disconnected");
    }
}
