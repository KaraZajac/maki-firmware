//! OpenPGP: an OpenPGP key from the recovery phrase, for gpg and git through maki desktop's
//! `maki-gpg`. The primary key signs (Ed25519, OpenPGP's EdDSA: the keys permission's Ed25519
//! key, which maki holds); a subkey decrypts (Curve25519 ECDH: host API 2's X25519 key). Both are
//! dated 1 January 2026 on every maki, so the phrase gives the same key, and fingerprint,
//! wherever it's restored.
//!
//! maki sees what it signs, as maki's rule is: a card for gpg would be handed a hash, so instead
//! maki-gpg hands this the whole of what's signed (a git commit, say), in pieces. It hashes it
//! itself, shows what it is (a commit's subject and author, from the same bytes), and makes the
//! signature (RFC 4880, a v4 signature dated by maki's clock) once its owner says yes. A message
//! sent to the key is opened the same way: maki-gpg hands this its session key as the sender
//! wrapped it (RFC 6637), and it unwraps it once its owner says yes; the rest is the computer's.
//! The key's name (a user ID, "Name <email>") is certified on maki too, once, when it's given.
//!
//! The link's messages, a byte saying what first; each answer a status first (`0` done, `1` the
//! owner said no, `2` no answer, `3` maki is locked, `4` not something it takes, `5` no name yet,
//! `6` a piece taken: send the next):
//! - `F`: the key's fingerprint (20 bytes) and the subkey's ID (8), name or no name.
//! - `U`, then a user ID: the key's name from now on, once the owner says yes.
//! - `K`: the key as `gpg --export` gives it: the public key, its name and its certification, the subkey and
//!   its binding.
//! - `S`, the whole length and where this piece starts (u32s, little-endian), and the piece: the last piece
//!   shown and signed, answered with a signature packet.
//! - `D`, then a public-key encrypted session key packet's body: the session key (its algorithm, then the
//!   key), once the owner says yes.

use maki_app::*;
use sha1::Sha1;
use sha2::{Digest, Sha256};

const SIGN: &str = "openpgp";
const CRYPT: &str = "openpgp-encrypt";
/// 2026-01-01 00:00 UTC: every maki's key is made then.
const CREATED: u32 = 1_767_225_600;

const ED25519: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];
const CV25519: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
/// ECDH's key derivation: SHA-256, and AES-256 to wrap.
const KDF: [u8; 4] = [0x03, 0x01, 0x08, 0x09];
const EDDSA: u8 = 22;
const ECDH: u8 = 18;
const SHA256: u8 = 8;

const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;
const NO_NAME: u8 = 5;
const MORE: u8 = 6;
/// The most it signs whole, and keeps of its start to show.
const MOST: u32 = 64 << 20;
const HEAD: usize = 2048;

/// A multiprecision integer (RFC 4880 3.2): its length in bits, then its bytes, less leading zeros.
fn mpi(bytes: &[u8]) -> Vec<u8> {
    let b = &bytes[bytes.iter().position(|&x| x != 0).unwrap_or(bytes.len())..];
    let bits = b.first().map_or(0, |&x| (b.len() - 1) * 8 + (8 - x.leading_zeros() as usize));
    [&(bits as u16).to_be_bytes()[..], b].concat()
}

/// A packet, its header in the new format.
fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let n = body.len();
    let mut out = vec![0xc0 | tag];
    match n {
        0..=191 => out.push(n as u8),
        192..=8383 => out.extend_from_slice(&[((n - 192) >> 8) as u8 + 192, (n - 192) as u8]),
        _ => {
            out.push(0xff);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
    out.extend_from_slice(body);
    out
}

fn subpacket(kind: u8, data: &[u8]) -> Vec<u8> {
    let n = data.len() + 1;
    let mut out = match n {
        0..=191 => vec![n as u8],
        _ => vec![((n - 192) >> 8) as u8 + 192, (n - 192) as u8],
    };
    out.push(kind);
    out.extend_from_slice(data);
    out
}

/// The keys, as their packets' bodies have them, and the primary's fingerprint.
struct Keys {
    primary: Vec<u8>,
    subkey: Vec<u8>,
    fingerprint: [u8; 20],
    subkey_id: [u8; 8],
}

fn fingerprint(body: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update([0x99]);
    h.update((body.len() as u16).to_be_bytes());
    h.update(body);
    h.finalize().into()
}

fn keys() -> Option<Keys> {
    let sign = keys::public_key(SIGN).ok()?;
    let crypt = keys::x25519_public_key(CRYPT).ok()?;
    let head =
        |algo: u8, oid: &[u8]| [&[4u8][..], &CREATED.to_be_bytes(), &[algo, oid.len() as u8], oid].concat();
    let primary = [head(EDDSA, ED25519), mpi(&[&[0x40][..], &sign].concat())].concat();
    let subkey = [head(ECDH, CV25519), mpi(&[&[0x40][..], &crypt].concat()), KDF.to_vec()].concat();
    let sub_fpr = fingerprint(&subkey);
    Some(Keys {
        fingerprint: fingerprint(&primary),
        primary,
        subkey,
        subkey_id: sub_fpr[12..].try_into().ok()?,
    })
}

/// A key's body, hashed as signatures over it take it.
fn key_hashed(h: &mut Sha256, body: &[u8]) {
    h.update([0x99]);
    h.update((body.len() as u16).to_be_bytes());
    h.update(body);
}

/// A v4 signature packet (RFC 4880 5.2.3) by the primary key: `h` has what it covers already;
/// maki hashes the signature's own fields and the trailer after, and signs the digest (EdDSA).
fn signature(mut h: Sha256, sig_type: u8, hashed: &[u8], keys: &Keys) -> Option<Vec<u8>> {
    let mut head = vec![4, sig_type, EDDSA, SHA256];
    head.extend_from_slice(&(hashed.len() as u16).to_be_bytes());
    head.extend_from_slice(hashed);
    h.update(&head);
    h.update([0x04, 0xff]);
    h.update((head.len() as u32).to_be_bytes());
    let digest: [u8; 32] = h.finalize().into();
    let sig = keys::sign(SIGN, &digest).ok()?;
    let unhashed = subpacket(16, &keys.fingerprint[12..]);
    let mut body = head;
    body.extend_from_slice(&(unhashed.len() as u16).to_be_bytes());
    body.extend_from_slice(&unhashed);
    body.extend_from_slice(&digest[..2]);
    body.extend_from_slice(&mpi(&sig[..32]));
    body.extend_from_slice(&mpi(&sig[32..]));
    Some(packet(2, &body))
}

fn now() -> u32 { unix_time().map_or(CREATED, |t| t as u32).max(CREATED) }

/// The hashed subpackets every signature has: when (maki's clock), and by whom.
fn when_and_who(keys: &Keys) -> Vec<u8> {
    [subpacket(2, &now().to_be_bytes()), subpacket(33, &[&[4u8][..], &keys.fingerprint].concat())].concat()
}

/// The key's name certified, and the subkey bound: what `K` hands out with them.
fn certify(keys: &Keys, uid: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut h = Sha256::new();
    key_hashed(&mut h, &keys.primary);
    h.update([0xb4]);
    h.update((uid.len() as u32).to_be_bytes());
    h.update(uid.as_bytes());
    // certifies and signs; AES, SHA-2, compression and MDC, as gpg's own keys say
    let hashed = [
        when_and_who(keys),
        subpacket(27, &[0x03]),
        subpacket(11, &[9, 8, 7]),
        subpacket(21, &[10, 9, 8]),
        subpacket(22, &[2, 3, 1]),
        subpacket(30, &[0x01]),
    ]
    .concat();
    let cert = signature(h, 0x13, &hashed, keys)?;
    let mut h = Sha256::new();
    key_hashed(&mut h, &keys.primary);
    key_hashed(&mut h, &keys.subkey);
    // the subkey encrypts
    let bind = signature(h, 0x18, &[when_and_who(keys), subpacket(27, &[0x0c])].concat(), keys)?;
    Some((cert, bind))
}

/// AES key unwrap (RFC 3394), as RFC 6637 wraps a session key.
fn unwrap(kek: &[u8; 32], wrapped: &[u8]) -> Option<Vec<u8>> {
    use aes::cipher::{BlockDecrypt, KeyInit};
    if !wrapped.len().is_multiple_of(8) || wrapped.len() < 24 {
        return None;
    }
    let n = wrapped.len() / 8 - 1;
    let cipher = aes::Aes256::new(kek.into());
    let mut a: [u8; 8] = wrapped[..8].try_into().ok()?;
    let mut r: Vec<[u8; 8]> = wrapped[8..].chunks(8).map(|c| c.try_into().unwrap()).collect();
    for j in (0..6).rev() {
        for i in (1..=n).rev() {
            let t = ((n * j + i) as u64).to_be_bytes();
            let mut b = [0u8; 16];
            for k in 0..8 {
                b[k] = a[k] ^ t[k];
            }
            b[8..].copy_from_slice(&r[i - 1]);
            let mut block = b.into();
            cipher.decrypt_block(&mut block);
            a.copy_from_slice(&block[..8]);
            r[i - 1].copy_from_slice(&block[8..]);
        }
    }
    (a == [0xa6; 8]).then(|| r.concat())
}

/// A session key from a public-key encrypted session key packet's body (v3, ECDH, to the
/// subkey): its algorithm and key, as the owner's yes lets it out. None if it isn't for this key,
/// or doesn't unwrap.
fn session_key(keys: &Keys, pkesk: &[u8]) -> Option<(Vec<u8>, bool)> {
    let (&[3], id, &[ECDH]) = (pkesk.get(..1)?, pkesk.get(1..9)?, pkesk.get(9..10)?) else { return None };
    // this subkey's, or any (gpg's --throw-keyids)
    let ours = id == keys.subkey_id || id == [0; 8];
    let bits = u16::from_be_bytes(pkesk.get(10..12)?.try_into().ok()?) as usize;
    let point = pkesk.get(12..12 + bits.div_ceil(8))?;
    let at = 12 + bits.div_ceil(8);
    let n = *pkesk.get(at)? as usize;
    let wrapped = pkesk.get(at + 1..at + 1 + n)?;
    if point.len() != 33 || point[0] != 0x40 || at + 1 + n != pkesk.len() {
        return None;
    }
    Some(([point, wrapped].concat(), ours))
}

fn open(keys: &Keys, point_wrapped: &[u8]) -> Option<Vec<u8>> {
    let (point, wrapped) = point_wrapped.split_at(33);
    let shared = keys::x25519_agree(CRYPT, point[1..].try_into().ok()?).ok()?;
    // RFC 6637's KDF: SHA-256 of a counter, the shared secret and what the key is for
    let mut h = Sha256::new();
    h.update([0, 0, 0, 1]);
    h.update(shared);
    h.update([CV25519.len() as u8]);
    h.update(CV25519);
    h.update([ECDH]);
    h.update(KDF);
    h.update(b"Anonymous Sender    ");
    h.update(fingerprint(&keys.subkey));
    let kek: [u8; 32] = h.finalize().into();
    let m = unwrap(&kek, wrapped)?;
    // its algorithm, the key, a checksum, and PKCS #5 padding
    let pad = *m.last()? as usize;
    if pad == 0 || pad > 8 || pad > m.len() || !m[m.len() - pad..].iter().all(|&b| b as usize == pad) {
        return None;
    }
    let m = &m[..m.len() - pad];
    let (key, sum) = m.get(1..m.len().checked_sub(2)?).zip(m.get(m.len() - 2..))?;
    let check = key.iter().fold(0u16, |s, &b| s.wrapping_add(b as u16));
    // 7 to 9: AES-128, -192 or -256
    (check.to_be_bytes() == sum && matches!(m[0], 7..=9)).then(|| m[..m.len() - 2].to_vec())
}

/// A header line's value in a git object, before the message.
fn header<'a>(object: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    for line in object.split(|&b| b == b'\n') {
        if line.is_empty() {
            return None;
        }
        if let Some(rest) = line.strip_prefix(name).and_then(|r| r.strip_prefix(b" ")) {
            return Some(rest);
        }
    }
    None
}

fn shown(bytes: &[u8], most: usize) -> String {
    let mut s: String =
        String::from_utf8_lossy(bytes).chars().map(|c| if c.is_control() { '?' } else { c }).collect();
    if s.chars().count() > most {
        s = s.chars().take(most).collect::<String>() + "...";
    }
    s
}

/// What the owner is asked, for something signed whole: what it is, from its bytes.
fn what(head: &[u8], total: u32) -> (String, String) {
    let person = |line: &[u8]| {
        shown(&line[..line.iter().position(|&b| b == b'<').unwrap_or(line.len())], 40).trim().to_string()
    };
    let subject = || {
        let at = head.windows(2).position(|w| w == b"\n\n").map_or(head.len(), |i| i + 2);
        let message = &head[at..];
        shown(&message[..message.iter().position(|&b| b == b'\n').unwrap_or(message.len())], 64)
    };
    if header(head, b"tree").is_some() {
        let parents = head
            .split(|&b| b == b'\n')
            .take_while(|l| !l.is_empty())
            .filter(|l| l.starts_with(b"parent "))
            .count();
        let q = if parents > 1 { "Sign this merge?" } else { "Sign this commit?" };
        (
            q.into(),
            format!("\"{}\" by {}", subject(), header(head, b"author").map(person).unwrap_or_default()),
        )
    } else if header(head, b"object").is_some() {
        let tag = shown(header(head, b"tag").unwrap_or(b"?"), 40);
        (
            format!("Sign tag {tag}?"),
            format!("\"{}\" by {}", subject(), header(head, b"tagger").map(person).unwrap_or_default()),
        )
    } else {
        ("Sign with your OpenPGP key?".into(), format!("{total} bytes"))
    }
}

/// Something being signed whole, as its pieces come.
struct Whole {
    hash: Sha256,
    total: u32,
    got: u32,
    head: Vec<u8>,
}

struct App {
    uid: Option<String>,
    whole: Option<Whole>,
    signed: u32,
    note: String,
    showing_key: bool,
}

fn asked(question: &str, detail: &str, yes: &str) -> Result<(), u8> {
    match Ask::new(question).detail(detail).answers(yes, "no").show() {
        Ok(Answer::Yes) => Ok(()),
        Ok(Answer::No) => Err(DENIED),
        _ => Err(NO_ANSWER),
    }
}

fn fit(s: &str, most: usize) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if out.len() + c.len_utf8() > most {
            break;
        }
        out.push(c);
    }
    out
}

impl App {
    fn handle(&mut self, m: &[u8]) -> Vec<u8> {
        let Some(keys) = keys() else { return vec![LOCKED] };
        match m.first() {
            Some(b'F') if m.len() == 1 => [&[OK][..], &keys.fingerprint, &keys.subkey_id].concat(),
            Some(b'U') => {
                let Ok(uid) = std::str::from_utf8(&m[1..]) else { return vec![BAD] };
                if uid.trim().is_empty() || uid.len() > 128 || uid.chars().any(|c| c.is_control()) {
                    return vec![BAD];
                }
                if let Err(code) = asked("Name your OpenPGP key?", &fit(uid, 120), "name it") {
                    return vec![code];
                }
                let Some((cert, bind)) = certify(&keys, uid) else { return vec![LOCKED] };
                let _ = storage::set("uid", uid.as_bytes());
                let _ = storage::set("cert", &cert);
                let _ = storage::set("bind", &bind);
                self.uid = Some(uid.to_string());
                self.note = "named".into();
                vec![OK]
            }
            Some(b'K') if m.len() == 1 => {
                let (Some(uid), Some(cert), Some(bind)) = (self.uid.as_ref(), read("cert"), read("bind"))
                else {
                    return vec![NO_NAME];
                };
                let mut out = vec![OK];
                out.extend_from_slice(&packet(6, &keys.primary));
                out.extend_from_slice(&packet(13, uid.as_bytes()));
                out.extend_from_slice(&cert);
                out.extend_from_slice(&packet(14, &keys.subkey));
                out.extend_from_slice(&bind);
                out
            }
            Some(b'S') => self.sign_piece(&keys, &m[1..]),
            Some(b'D') => {
                let Some((point_wrapped, ours)) = session_key(&keys, &m[1..]) else { return vec![BAD] };
                if !ours {
                    return vec![BAD];
                }
                let to = self.uid.clone().unwrap_or_else(|| "your key".into());
                if let Err(code) = asked("Open a message?", &format!("sent to {}", fit(&to, 110)), "open it")
                {
                    return vec![code];
                }
                match open(&keys, &point_wrapped) {
                    Some(key) => {
                        self.note = "opened a message".into();
                        [&[OK][..], &key].concat()
                    }
                    None => vec![BAD],
                }
            }
            _ => vec![BAD],
        }
    }

    fn sign_piece(&mut self, keys: &Keys, m: &[u8]) -> Vec<u8> {
        let (Some(total), Some(offset)) = (m.get(..4), m.get(4..8)) else { return vec![BAD] };
        let (total, offset) =
            (u32::from_le_bytes(total.try_into().unwrap()), u32::from_le_bytes(offset.try_into().unwrap()));
        let piece = &m[8..];
        if offset == 0 {
            if total == 0 || total > MOST {
                return vec![BAD];
            }
            self.whole = Some(Whole { hash: Sha256::new(), total, got: 0, head: Vec::new() });
        }
        let Some(w) = self.whole.as_mut() else { return vec![BAD] };
        if offset != w.got || total != w.total || piece.len() as u32 > total - offset {
            self.whole = None;
            return vec![BAD];
        }
        w.hash.update(piece);
        let room = HEAD.saturating_sub(w.head.len());
        w.head.extend_from_slice(&piece[..piece.len().min(room)]);
        w.got += piece.len() as u32;
        if w.got < w.total {
            return vec![MORE];
        }
        let w = self.whole.take().unwrap();
        let (question, detail) = what(&w.head, w.total);
        if let Err(code) = asked(&question, &fit(&detail, 120), "sign") {
            return vec![code];
        }
        // a signature of a binary document, dated by maki's clock
        match signature(w.hash, 0x00, &when_and_who(keys), keys) {
            Some(sig) => {
                self.signed += 1;
                let _ = storage::set_u32("signed", self.signed);
                self.note = "signed".into();
                [&[OK][..], &sig].concat()
            }
            None => vec![LOCKED],
        }
    }

    fn draw(&self) {
        screen::clear(Color::Dark);
        let Some(keys) = keys() else {
            screen::text_centred(30, "Unlock maki to", Style::Regular, Color::Light);
            screen::text_centred(45, "use its OpenPGP key", Style::Regular, Color::Light);
            screen::present();
            return;
        };
        let hex: String = keys.fingerprint.iter().map(|b| format!("{b:02X}")).collect();
        if self.showing_key {
            // as OpenKeychain and the like scan a key's fingerprint
            let code = format!("OPENPGP4FPR:{hex}");
            let side = screen::qr(0, 0, code.as_bytes(), HEIGHT).unwrap_or(0);
            screen::clear(Color::Dark);
            screen::qr((WIDTH - side) / 2, (HEIGHT - side) / 2, code.as_bytes(), HEIGHT);
            screen::present();
            return;
        }
        let name = self.uid.clone().unwrap_or_else(|| "no name yet".into());
        screen::text(2, 0, &fit(&name, 40), Style::Small, Color::Light);
        for (i, row) in hex.as_bytes().chunks(20).enumerate() {
            let groups: Vec<&str> = row.chunks(4).map(|g| std::str::from_utf8(g).unwrap_or("")).collect();
            screen::text_centred(18 + i as i32 * 15, &groups.join(" "), Style::Mono, Color::Light);
        }
        let line =
            if self.note.is_empty() { format!("signed {} times", self.signed) } else { self.note.clone() };
        screen::text_centred(62, &line, Style::Small, Color::Light);
        screen::text_centred(94, "menu: show the key", Style::Small, Color::Light);
        screen::present();
    }
}

fn read(key: &str) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 1024];
    let n = storage::get(key, &mut buf)?;
    buf.truncate(n.min(buf.len()));
    Some(buf)
}

fn main() {
    let _ = menu(&["Show the key"]);
    let uid = read("uid").and_then(|b| String::from_utf8(b).ok());
    let mut app = App {
        uid,
        whole: None,
        signed: storage::get_u32("signed", 0),
        note: String::new(),
        showing_key: false,
    };
    loop {
        app.draw();
        match wait(None) {
            Event::Message => {
                let mut message = vec![0u8; 4096];
                let answer = match link::read(&mut message) {
                    Some(n) if n <= message.len() => app.handle(&message[..n]),
                    _ => vec![BAD],
                };
                let _ = link::reply(&answer);
            }
            Event::Menu(0) => app.showing_key = !app.showing_key,
            Event::Centre | Event::Left | Event::Right if app.showing_key => app.showing_key = false,
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
