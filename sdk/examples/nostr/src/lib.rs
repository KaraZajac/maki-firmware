//! Your Nostr key, from maki's recovery phrase: the app's BIP340 (Schnorr) key for "nostr" (the
//! keys permission), which maki holds and signs with. Sites use it through the maki extension's
//! `window.nostr` (NIP-07),
//! which maki desktop hands to this app (the link permission): maki asks before a site first sees
//! the key, and before each event it signs, showing the site, what kind of event it is and how it
//! begins. The app works out the event's id itself (NIP-01's serialization, hashed), from the
//! fields it shows, so what it signs is what the owner saw. Opened, it shows the key's npub as a
//! QR code, to share with a phone.
//!
//! Messages (maki desktop's `src/shared/nostr.ts` makes them), numbers big-endian:
//!
//! - `1, site` (a byte of length, then the site): the public key. Answer: `0` and the 32-byte
//!   x-only key, or `1` if the owner said no.
//! - `2, site, created_at (8 bytes), kind (4), tags (4 bytes of length, then JSON: an array of
//!   arrays of strings, as JSON.stringify writes it), content (4 bytes of length, then UTF-8)`:
//!   a signature. Answer: `0`, the event's 32-byte id and the 64-byte signature; or `1`.
//!
//! Anything else is answered `2`, and `3` means the key isn't there (maki is locked).

#![no_std]

use core::fmt::Write;

use maki_app::*;
use sha2::{Digest, Sha256};

const LABEL: &str = "nostr";
const OK: u8 = 0;
const NO: u8 = 1;
const BAD: u8 = 2;
const LOCKED: u8 = 3;
/// The sites the owner has let see the key, a line each.
const SITES: &str = "sites";
const MAX_SITES: usize = 2048;

/// The key's public half, x-only; None while maki is locked.
fn key() -> Option<[u8; 32]> { keys::schnorr_public_key(LABEL).ok() }

fn hex32(bytes: &[u8], out: &mut Buf<64>) {
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
}

/// Bech32 (BIP173), as Nostr writes keys: `hrp`, then `data` in fives, then the checksum.
fn bech32<const N: usize>(hrp: &str, data: &[u8], out: &mut Buf<N>) {
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    fn polymod(values: impl Iterator<Item = u8>) -> u32 {
        const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        let mut chk = 1u32;
        for v in values {
            let top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v as u32;
            for (i, g) in GEN.iter().enumerate() {
                if (top >> i) & 1 == 1 {
                    chk ^= g;
                }
            }
        }
        chk
    }
    // the data in five-bit groups
    let mut fives = [0u8; 64];
    let mut n = 0;
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            fives[n] = ((acc >> bits) & 31) as u8;
            n += 1;
        }
    }
    if bits > 0 {
        fives[n] = ((acc << (5 - bits)) & 31) as u8;
        n += 1;
    }
    let expanded = hrp.bytes().map(|c| c >> 5).chain([0]).chain(hrp.bytes().map(|c| c & 31));
    let pm = polymod(expanded.chain(fives[..n].iter().copied()).chain([0; 6])) ^ 1;
    let _ = out.write_str(hrp);
    let _ = out.write_char('1');
    for &f in &fives[..n] {
        let _ = out.write_char(CHARSET[f as usize] as char);
    }
    for i in 0..6 {
        let _ = out.write_char(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
}

/// The sites let see the key.
fn sites(buf: &mut [u8; MAX_SITES]) -> &str {
    let n = storage::get(SITES, buf).unwrap_or(0).min(MAX_SITES);
    core::str::from_utf8(&buf[..n]).unwrap_or("")
}

fn allowed(site: &str) -> bool {
    let mut buf = [0u8; MAX_SITES];
    sites(&mut buf).lines().any(|s| s == site)
}

fn allow(site: &str) {
    let mut buf = [0u8; MAX_SITES];
    let n = sites(&mut buf).len();
    if n + site.len() + 1 > MAX_SITES {
        return; // full: it asks again next time
    }
    let mut all = [0u8; MAX_SITES];
    all[..n].copy_from_slice(&buf[..n]);
    all[n..n + site.len()].copy_from_slice(site.as_bytes());
    all[n + site.len()] = b'\n';
    let _ = storage::set(SITES, &all[..n + site.len() + 1]);
}

/// A kind of event, as people call it.
fn kind_name(kind: u32) -> Option<&'static str> {
    Some(match kind {
        0 => "profile",
        1 => "note",
        3 => "follow list",
        4 => "direct message",
        5 => "deletion",
        6 => "repost",
        7 => "reaction",
        9734 => "zap request",
        10002 => "relay list",
        22242 => "relay login",
        24133 => "remote signer message",
        27235 => "web login",
        30023 => "article",
        _ => return None,
    })
}

/// `s` as JSON writes a string's inside (JSON.stringify's escapes, as NIP-01 serializes content).
fn escaped(s: &str, h: &mut Sha256) {
    let mut start = 0;
    for (i, c) in s.char_indices() {
        let esc: Option<&[u8]> = match c {
            '"' => Some(b"\\\""),
            '\\' => Some(b"\\\\"),
            '\n' => Some(b"\\n"),
            '\r' => Some(b"\\r"),
            '\t' => Some(b"\\t"),
            '\u{8}' => Some(b"\\b"),
            '\u{c}' => Some(b"\\f"),
            _ => None,
        };
        if esc.is_none() && c >= ' ' {
            continue;
        }
        h.update(&s.as_bytes()[start..i]);
        match esc {
            Some(e) => h.update(e),
            None => {
                let mut u = Buf::<8>::new();
                let _ = write!(u, "\\u{:04x}", c as u32);
                h.update(u.as_str().as_bytes());
            }
        }
        start = i + c.len_utf8();
    }
    h.update(&s.as_bytes()[start..]);
}

/// Up to `max` bytes of `s` on one line, cut at a character and marked if cut.
fn preview<const N: usize>(s: &str, max: usize, out: &mut Buf<N>) {
    let mut used = 0;
    for c in s.chars() {
        let c = if c.is_control() { ' ' } else { c };
        if used + c.len_utf8() > max {
            let _ = out.write_char('…');
            return;
        }
        let _ = out.write_char(c);
        used += c.len_utf8();
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }

    fn u32(&mut self) -> Option<u32> { self.take(4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]])) }

    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    fn str8(&mut self) -> Option<&'a str> {
        let n = self.take(1)?[0] as usize;
        core::str::from_utf8(self.take(n)?).ok()
    }

    fn str32(&mut self) -> Option<&'a str> {
        let n = self.u32()? as usize;
        core::str::from_utf8(self.take(n)?).ok()
    }
}

/// A site's request: the answer to it.
fn answer(msg: &[u8], out: &mut [u8; 97]) -> usize {
    let mut r = Reader(msg);
    let (Some(op), Some(site)) = (r.take(1).map(|b| b[0]), r.str8()) else {
        out[0] = BAD;
        return 1;
    };
    let Some(public) = key() else {
        out[0] = LOCKED;
        return 1;
    };
    match op {
        1 => {
            if !allowed(site) {
                let mut npub = Buf::<72>::new();
                bech32("npub", &public, &mut npub);
                let mut detail = Buf::<128>::new();
                let _ = write!(detail, "{site} as {}…{}", &npub.as_str()[..12], &npub.as_str()[npub.len() - 6..]);
                let asked = Ask::new("Let it see your Nostr key?").detail(detail.as_str()).answers("let it", "don't").show();
                if asked != Ok(Answer::Yes) {
                    out[0] = NO;
                    return 1;
                }
                allow(site);
            }
            out[0] = OK;
            out[1..33].copy_from_slice(&public);
            33
        }
        2 => {
            let (Some(created_at), Some(kind), Some(tags), Some(content)) = (r.u64(), r.u32(), r.str32(), r.str32()) else {
                out[0] = BAD;
                return 1;
            };
            // tags as JSON writes them: an array (of arrays of strings), nothing around it
            if !(tags.starts_with('[') && tags.ends_with(']')) || !r.0.is_empty() {
                out[0] = BAD;
                return 1;
            }
            let mut question = Buf::<64>::new();
            match kind_name(kind) {
                Some(name) => {
                    let _ = write!(question, "Sign a Nostr {name}?");
                }
                None => {
                    let _ = write!(question, "Sign a Nostr event (kind {kind})?");
                }
            }
            let mut detail = Buf::<128>::new();
            let _ = write!(detail, "{site}: ");
            let room = 120 - detail.len().min(120);
            if content.is_empty() {
                let _ = detail.write_str("(nothing written)");
            } else {
                preview(content, room, &mut detail);
            }
            let asked = Ask::new(question.as_str()).detail(detail.as_str()).answers("sign", "cancel").timeout(60).show();
            if asked != Ok(Answer::Yes) {
                out[0] = NO;
                return 1;
            }
            if !allowed(site) {
                allow(site);
            }
            // NIP-01: [0, pubkey, created_at, kind, tags, content], hashed
            let mut h = Sha256::new();
            let mut hex = Buf::<64>::new();
            hex32(&public, &mut hex);
            let mut head = Buf::<128>::new();
            let _ = write!(head, "[0,\"{}\",{created_at},{kind},", hex.as_str());
            h.update(head.as_str().as_bytes());
            h.update(tags.as_bytes());
            h.update(b",\"");
            escaped(content, &mut h);
            h.update(b"\"]");
            let id: [u8; 32] = h.finalize().into();
            let Ok(sig) = keys::schnorr_sign(LABEL, &id) else {
                out[0] = LOCKED;
                return 1;
            };
            out[0] = OK;
            out[1..33].copy_from_slice(&id);
            out[33..97].copy_from_slice(&sig);
            97
        }
        _ => {
            out[0] = BAD;
            1
        }
    }
}

fn draw() {
    screen::clear(Color::Dark);
    let Some(public) = key() else {
        screen::text_centred(40, "maki is locked", Style::Regular, Color::Light);
        screen::text_centred(58, "enter its PIN first", Style::Small, Color::Light);
        screen::present();
        return;
    };
    let mut npub = Buf::<72>::new();
    bech32("npub", &public, &mut npub);
    let mut uri = Buf::<80>::new();
    let _ = write!(uri, "nostr:{}", npub.as_str());
    let side = screen::qr(0, 0, uri.as_str().as_bytes(), 94).unwrap_or(0);
    // centred across, what it came to
    if side > 0 && side < WIDTH {
        screen::clear(Color::Dark);
        screen::qr((WIDTH - side) / 2, 0, uri.as_str().as_bytes(), 94);
    }
    let mut short = Buf::<24>::new();
    let _ = write!(short, "{}…{}", &npub.as_str()[..10], &npub.as_str()[npub.len() - 6..]);
    screen::text_centred(97, short.as_str(), Style::Small, Color::Light);
    screen::present();
}

fn main() {
    let _ = menu(&["Forget sites"]);
    loop {
        draw();
        match wait(None) {
            Event::Message => {
                let mut msg = [0u8; 4096];
                let n = link::read(&mut msg).unwrap_or(0).min(msg.len());
                let mut out = [0u8; 97];
                let len = answer(&msg[..n], &mut out);
                let _ = link::reply(&out[..len]);
            }
            Event::Menu(0) => {
                storage::delete(SITES);
            }
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
