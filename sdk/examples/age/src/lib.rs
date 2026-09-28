//! Your age key, from maki's recovery phrase: the app's X25519 key for "age" (the keys
//! permission), which maki holds. Its public half is an ordinary age recipient (`age1…`), so
//! anyone encrypts to it with age as it is; decrypting asks maki, through maki desktop's
//! `age-plugin-maki` (the link permission), and the app asks its owner before it hands over a
//! file's key (the ask permission). Opened, it shows the recipient as a QR code.
//!
//! Messages (maki desktop's `src/main/age-plugin.ts` makes them):
//!
//! - `1`: the recipient. Answer: `0` and its 32 bytes.
//! - `2, n, n × (share, body)` (32 bytes each): which of a file's X25519 stanzas are this key's, without
//!   asking (a file's stanzas don't say who they're for). Answer: `0` and the index of the first that is, or
//!   `4` if none.
//! - `3, share, body, program` (a byte of length, then its name): the file key, once the owner says so.
//!   Answer: `0` and the 16-byte file key; `1` if the owner said no; `4` if it isn't this key's after all.
//!
//! Anything else is answered `2`, and `3` means the key isn't there (maki is locked).

#![no_std]

use core::fmt::Write;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use hkdf::Hkdf;
use maki_app::*;
use sha2::Sha256;

const LABEL: &str = "age";
const OK: u8 = 0;
const NO: u8 = 1;
const BAD: u8 = 2;
const LOCKED: u8 = 3;
const NOT_MINE: u8 = 4;
/// age's X25519 stanza (c2sp.org/age): the key that wraps the file key comes from this.
const INFO: &[u8] = b"age-encryption.org/v1/X25519";

fn recipient() -> Option<[u8; 32]> { keys::x25519_public_key(LABEL).ok() }

/// A stanza's file key, if it was wrapped for this key: X25519 with the ephemeral share (maki's
/// part), then HKDF and ChaCha20-Poly1305 as age has them.
fn unwrap(public: &[u8; 32], share: &[u8; 32], body: &[u8; 32]) -> Option<[u8; 16]> {
    // a share of small order agrees on nothing: maki refuses it, as age says to
    let shared = keys::x25519_agree(LABEL, share).ok()?;
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(share);
    salt[32..].copy_from_slice(public);
    let mut wrap = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), &shared).expand(INFO, &mut wrap).ok()?;
    let mut key = [0u8; 16];
    key.copy_from_slice(&body[..16]);
    let tag = Tag::from_slice(&body[16..]);
    ChaCha20Poly1305::new(&wrap.into())
        .decrypt_in_place_detached(&Nonce::default(), b"", &mut key, tag)
        .ok()?;
    Some(key)
}

fn pair(bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut share = [0u8; 32];
    let mut body = [0u8; 32];
    share.copy_from_slice(&bytes[..32]);
    body.copy_from_slice(&bytes[32..64]);
    (share, body)
}

/// A request from the computer: the answer to it.
fn answer(msg: &[u8], out: &mut [u8; 33]) -> usize {
    let Some(public) = recipient() else {
        out[0] = LOCKED;
        return 1;
    };
    match msg {
        [1] => {
            out[0] = OK;
            out[1..33].copy_from_slice(&public);
            33
        }
        [2, n, stanzas @ ..] if stanzas.len() == *n as usize * 64 => {
            for (i, s) in stanzas.chunks(64).enumerate() {
                let (share, body) = pair(s);
                if unwrap(&public, &share, &body).is_some() {
                    out[0] = OK;
                    out[1] = i as u8;
                    return 2;
                }
            }
            out[0] = NOT_MINE;
            1
        }
        [3, rest @ ..] if rest.len() > 64 && rest.len() == 65 + rest[64] as usize => {
            let (share, body) = pair(rest);
            let Some(mut key) = unwrap(&public, &share, &body) else {
                out[0] = NOT_MINE;
                return 1;
            };
            let program = core::str::from_utf8(&rest[65..]).unwrap_or("a program");
            let mut detail = Buf::<128>::new();
            let _ = write!(detail, "for {program}, on this computer");
            let asked = Ask::new("Decrypt a file with your age key?")
                .detail(detail.as_str())
                .answers("decrypt", "don't")
                .show();
            if asked != Ok(Answer::Yes) {
                key.fill(0);
                out[0] = NO;
                return 1;
            }
            out[0] = OK;
            out[1..17].copy_from_slice(&key);
            key.fill(0);
            17
        }
        _ => {
            out[0] = BAD;
            1
        }
    }
}

/// Bech32 (BIP173), as age writes recipients.
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

fn draw(as_text: bool) {
    screen::clear(Color::Dark);
    let Some(public) = recipient() else {
        screen::text_centred(40, "maki is locked", Style::Regular, Color::Light);
        screen::text_centred(58, "enter its PIN first", Style::Small, Color::Light);
        screen::present();
        return;
    };
    let mut r = Buf::<72>::new();
    bech32("age", &public, &mut r);
    if as_text {
        // the whole of it, in lines of the monospace font
        screen::text_centred(4, "Your age recipient", Style::Small, Color::Light);
        let s = r.as_str();
        for (i, start) in (0..s.len()).step_by(14).enumerate() {
            screen::text_centred(
                22 + i as i32 * 15,
                &s[start..(start + 14).min(s.len())],
                Style::Mono,
                Color::Light,
            );
        }
    } else {
        let side = screen::qr(0, 0, s_bytes(&r), 94).unwrap_or(0);
        if side > 0 && side < WIDTH {
            screen::clear(Color::Dark);
            screen::qr((WIDTH - side) / 2, 0, s_bytes(&r), 94);
        }
        let mut short = Buf::<24>::new();
        let _ = write!(short, "{}…{}", &r.as_str()[..9], &r.as_str()[r.len() - 6..]);
        screen::text_centred(97, short.as_str(), Style::Small, Color::Light);
    }
    screen::present();
}

fn s_bytes<const N: usize>(b: &Buf<N>) -> &[u8] { b.as_str().as_bytes() }

fn main() {
    let mut as_text = false;
    loop {
        draw(as_text);
        match wait(None) {
            Event::Message => {
                let mut msg = [0u8; 4096];
                let n = link::read(&mut msg).unwrap_or(0).min(msg.len());
                let mut out = [0u8; 33];
                let len = answer(&msg[..n], &mut out);
                let _ = link::reply(&out[..len]);
                out.fill(0);
            }
            Event::Centre => as_text = !as_text,
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
