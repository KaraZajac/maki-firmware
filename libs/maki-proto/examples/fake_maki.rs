//! A host stand-in for maki: the real protocol logic behind a TCP socket.
//!
//!     cargo run -p maki-proto --features fake --example fake_maki -- \
//!         [ADDR] [--deny | --ask] [--totp SITE=BASE32]... [--clock-verified] [--phrase "WORDS"]
//!
//! ADDR defaults to 127.0.0.1:7878. Logins and TOTP secrets live in memory; SAVE_LOGIN adds to them.
//! The Bitcoin wallet comes from `--phrase`, or else the BIP39 test phrase ("abandon" eleven times,
//! then "about"), which everyone knows: never send real coins to either.
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
use maki_btc::psbt::Psbt;
use maki_btc::{display, wallet, Account, Network};
use maki_proto::device::{
    reply, Approval, Ask, Backup, Bitcoin, Device, Handled, Platform, TimeState, BACKUP_PIECE, PSBT_PIECE,
};
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
    /// the backup being read out, and one coming in
    sealed: Vec<u8>,
    incoming: Vec<u8>,
}

/// The fake's wallet, and the PSBT coming in and the one it last signed.
struct Wallet {
    accounts: [Account; 2],
    incoming: Vec<u8>,
    signed: Vec<u8>,
}

const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

impl Wallet {
    fn new(phrase: &str) -> Wallet {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        maki_seed::to_entropy(&words).expect("--phrase isn't a BIP39 phrase");
        let seed = maki_seed::seed(&words, "");
        let account = |n| Account::from_seed(&seed, n).expect("keys");
        Wallet { accounts: [account(Network::Bitcoin), account(Network::Testnet)], incoming: Vec::new(), signed: Vec::new() }
    }
}

/// Everything maki-keys does with a finished PSBT, minus the screen: check it, show it, sign it.
fn finish_signing(psbt: Vec<u8>, account: &Account, wallet: &Mutex<Wallet>, policy: Policy) -> (u8, Vec<u8>) {
    let mut psbt = match Psbt::parse(&psbt) {
        Ok(p) => p,
        Err(e) => return reply::btc_sign(true, Approval::Refused, 0, &format!("not a PSBT maki can read: {e}")),
    };
    let review = match wallet::review(&psbt, account) {
        Ok(r) => r,
        Err(e) => {
            println!("  refused: {e}");
            return reply::btc_sign(true, Approval::Refused, 0, &e.to_string());
        }
    };
    for p in review.pages() {
        println!("  maki shows: {:12} {:18} {}", p.heading, p.value, p.mono);
    }
    let a = approve(policy, &format!("sign the transaction? {}", review.summary()));
    if a != Approval::Approved {
        return reply::btc_sign(true, a, 0, "");
    }
    if let Err(e) = wallet::sign(&mut psbt, account) {
        return reply::btc_sign(true, Approval::Refused, 0, &e.to_string());
    }
    let signed = psbt.serialize();
    let total = signed.len() as u32;
    wallet.lock().unwrap().signed = signed;
    reply::btc_sign(true, Approval::Approved, total, "")
}

/// The fake's backup: its store as lines of text, not encrypted (the badge's is; the desktop
/// can't tell the difference, which is the point).
const FAKE_MAGIC: &[u8] = b"FAKEBAK1\n";

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn fake_backup(st: &Store) -> Vec<u8> {
    let mut out = FAKE_MAGIC.to_vec();
    for (site, user, pass) in &st.logins {
        out.extend(format!("L\t{}\t{}\t{}\n", hex(site.as_bytes()), hex(user.as_bytes()), hex(pass.as_bytes())).bytes());
    }
    for (site, secret) in &st.totp {
        out.extend(format!("T\t{}\t{}\n", hex(site.as_bytes()), hex(secret)).bytes());
    }
    out
}

/// A backup's logins and codes, if it's one of the fake's.
fn parse_fake(blob: &[u8]) -> Option<(Vec<(String, String, String)>, Vec<(String, Vec<u8>)>)> {
    let text = std::str::from_utf8(blob.strip_prefix(FAKE_MAGIC)?).ok()?;
    let (mut logins, mut totp) = (Vec::new(), Vec::new());
    let s = |h: &str| unhex(h).and_then(|b| String::from_utf8(b).ok());
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["L", a, b, c] => logins.push((s(a)?, s(b)?, s(c)?)),
            ["T", a, b] => totp.push((s(a)?, unhex(b)?)),
            _ => return None,
        }
    }
    Some((logins, totp))
}

/// The last piece of a restore: open it, ask, add what's missing.
fn finish_restore(blob: Vec<u8>, store: &Mutex<Store>, policy: Policy) -> (u8, Vec<u8>) {
    let Some((logins, totp)) = parse_fake(&blob) else { return reply::restore_piece(true, Approval::NotYours, 0, 0) };
    let (new_logins, new_totp): (Vec<_>, Vec<_>) = {
        let st = store.lock().unwrap();
        (
            logins.into_iter().filter(|l| !st.logins.iter().any(|x| x.0 == l.0 && x.1 == l.1)).collect(),
            totp.into_iter().filter(|t| !st.totp.iter().any(|x| x.0 == t.0)).collect(),
        )
    };
    let (l, t) = (new_logins.len() as u16, new_totp.len() as u16);
    if l + t == 0 {
        return reply::restore_piece(true, Approval::Approved, 0, 0);
    }
    let a = approve(policy, &format!("restore backup? {l} logins, {t} codes"));
    if a == Approval::Approved {
        let mut st = store.lock().unwrap();
        st.logins.extend(new_logins);
        st.totp.extend(new_totp);
    }
    reply::restore_piece(true, a, l, t)
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
    let phrase = args.windows(2).find(|w| w[0] == "--phrase").map(|w| w[1].clone()).unwrap_or(TEST_PHRASE.into());
    let wallet = Arc::new(Mutex::new(Wallet::new(&phrase)));
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
                    Handled::Backup(Backup::Get { offset }) => {
                        let mut st = store.lock().unwrap();
                        if offset == 0 || st.sealed.is_empty() {
                            st.sealed = fake_backup(&st);
                        }
                        let start = (offset as usize).min(st.sealed.len());
                        let end = (start + BACKUP_PIECE).min(st.sealed.len());
                        let (kind, body) = reply::backup_piece(Approval::Approved, st.sealed.len() as u32, offset, &st.sealed[start..end]);
                        writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                    }
                    Handled::Backup(Backup::Put { total, offset, data }) => {
                        let finished = {
                            let mut st = store.lock().unwrap();
                            if offset == 0 {
                                st.incoming.clear();
                            }
                            if offset as usize != st.incoming.len() {
                                st.incoming.clear();
                                None
                            } else {
                                st.incoming.extend_from_slice(&data);
                                Some(st.incoming.len() as u32 == total)
                            }
                        };
                        match finished {
                            None => {
                                let (kind, body) = reply::restore_piece(true, Approval::Unavailable, 0, 0);
                                writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                            }
                            Some(false) => {
                                let (kind, body) = reply::restore_piece(false, Approval::Approved, 0, 0);
                                writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                            }
                            // like an ask: answered once the owner decides, from another thread
                            Some(true) => {
                                let blob = std::mem::take(&mut store.lock().unwrap().incoming);
                                let (writer, store, id) = (writer.clone(), store.clone(), packet.id);
                                std::thread::spawn(move || {
                                    let (kind, body) = finish_restore(blob, &store, policy);
                                    writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                                });
                            }
                        }
                    }
                    Handled::Bitcoin(request) => {
                        println!("  0x{:02x}#{} -> bitcoin", packet.kind, packet.id);
                        let id = packet.id;
                        let account = |network: u8| wallet.lock().unwrap().accounts[network.min(1) as usize].clone();
                        let immediate = match request {
                            // these wait for the owner: answered from another thread
                            Bitcoin::Account { network } => {
                                let (account, writer) = (account(network), writer.clone());
                                std::thread::spawn(move || {
                                    let a = approve(policy, "share the bitcoin account with this computer?");
                                    let (kind, body) = reply::btc_account(a, &account.zpub(), &account.descriptor());
                                    writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                                });
                                None
                            }
                            Bitcoin::Address { network, change, index } => {
                                let (account, writer) = (account(network), writer.clone());
                                std::thread::spawn(move || {
                                    let address = account.address(change, index).unwrap_or_default();
                                    let page = display::address_page(&address, change, index, account.network);
                                    println!("  maki shows: {:12} {:18} {}", page.heading, page.value, page.mono);
                                    let a = approve(policy, "does it match the computer's?");
                                    let (kind, body) = reply::btc_address(a, &address);
                                    writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                                });
                                None
                            }
                            Bitcoin::Sign { network, total, offset, data } => {
                                let mut w = wallet.lock().unwrap();
                                if offset == 0 {
                                    w.incoming.clear();
                                }
                                if offset as usize != w.incoming.len() {
                                    w.incoming.clear();
                                    Some(reply::btc_sign(true, Approval::Unavailable, 0, ""))
                                } else {
                                    w.incoming.extend_from_slice(&data);
                                    if (w.incoming.len() as u32) < total {
                                        Some(reply::btc_sign(false, Approval::Approved, 0, ""))
                                    } else {
                                        let psbt = std::mem::take(&mut w.incoming);
                                        let account = w.accounts[network.min(1) as usize].clone();
                                        drop(w);
                                        let (writer, wallet) = (writer.clone(), wallet.clone());
                                        std::thread::spawn(move || {
                                            let (kind, body) = finish_signing(psbt, &account, &wallet, policy);
                                            writer.lock().unwrap().write_all(&frame::encode(kind, id, &body)).ok();
                                        });
                                        None
                                    }
                                }
                            }
                            Bitcoin::Signed { offset } => {
                                let w = wallet.lock().unwrap();
                                if w.signed.is_empty() {
                                    Some(reply::btc_signed(Approval::Unavailable, 0, offset, &[]))
                                } else {
                                    let start = (offset as usize).min(w.signed.len());
                                    let end = (start + PSBT_PIECE).min(w.signed.len());
                                    Some(reply::btc_signed(Approval::Approved, w.signed.len() as u32, offset, &w.signed[start..end]))
                                }
                            }
                        };
                        if let Some((kind, body)) = immediate {
                            writer.lock().unwrap().write_all(&frame::encode(kind, packet.id, &body)).ok();
                        }
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
