//! Minisign: a minisign key from maki's recovery phrase (the keys permission's Ed25519 key, which
//! maki holds and signs with), for signing files as minisign does (jedisct1.github.io/minisign),
//! through maki desktop's `maki-minisign`. It hashes the file (BLAKE2b-512: minisign's prehashed
//! signatures) and asks here, over the link; the app asks the owner, with the file's name and
//! size and the start of its hash as the computer says them, then signs the hash, and the
//! trusted comment, which says when maki signed it by its own clock. Anyone checks the signature
//! with minisign itself and the public key this shows. Opened, it shows the key's ID and how many
//! files it has signed; from its menu, the public key as a QR code, as `minisign -P` takes it.
//!
//! The link's messages, a byte saying what first:
//! - `P`: the public key: `0`, its 32 bytes, and its 8-byte ID.
//! - `S`: a file to sign: its BLAKE2b-512 hash (64 bytes), its size (u64, little-endian), its
//!   name (a byte's length, then UTF-8), and a trusted comment of the signer's (a u16's length,
//!   little-endian, then UTF-8; empty for maki's own). Answered `0`, the key ID, the signature
//!   (64), the trusted comment (a u16's length, then it) and the global signature (64); or `1`
//!   the owner said no, `2` no answer, `3` maki is locked, `4` not a request it takes.

#![no_std]

use core::fmt::Write;

use maki_app::*;

const LABEL: &str = "minisign";
/// The key's ID comes from a secret of its own: the same on every maki with the phrase.
const ID_LABEL: &str = "minisign key id";

const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;

/// The longest trusted comment it signs, and file name it shows.
const MOST_COMMENT: usize = 512;
const MOST_NAME: usize = 255;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64<const N: usize>(out: &mut Buf<N>, data: &[u8]) {
    for chunk in data.chunks(3) {
        let b = [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            let _ = out.write_char(if i <= chunk.len() { B64[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
}

/// The public key, and its ID: none while maki is locked.
fn key() -> Option<([u8; 32], [u8; 8])> {
    let public = keys::public_key(LABEL).ok()?;
    let secret = keys::secret(ID_LABEL).ok()?;
    let mut id = [0u8; 8];
    id.copy_from_slice(&secret[..8]);
    Some((public, id))
}

/// The key's ID as minisign prints it: the 8 bytes as a little-endian number, in hex.
fn id_hex(id: &[u8; 8]) -> Buf<16> {
    let mut out = Buf::new();
    let _ = write!(out, "{:016X}", u64::from_le_bytes(*id));
    out
}

/// A size as a person reads it.
fn size<const N: usize>(out: &mut Buf<N>, bytes: u64) {
    const UNITS: [&str; 5] = ["bytes", "KB", "MB", "GB", "TB"];
    if bytes < 1000 {
        let _ = write!(out, "{bytes} bytes");
        return;
    }
    let mut unit = 0;
    let mut tenths = bytes * 10;
    while tenths >= 10_000 && unit < UNITS.len() - 1 {
        tenths /= 1000;
        unit += 1;
    }
    let _ = write!(out, "{}.{} {}", tenths / 10, tenths % 10, UNITS[unit]);
}

/// A day and time from seconds since 1970, in UTC (the civil calendar from days since then).
fn date<const N: usize>(out: &mut Buf<N>, secs: u64) {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let days = (secs / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    let _ = write!(out, "{day} {} {year} {:02}:{:02}", MONTHS[month as usize - 1], secs % 86_400 / 3600, secs % 3600 / 60);
}

/// Bytes, without an allocator: what fits.
struct Bytes<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> Bytes<N> {
    fn new() -> Self { Bytes { buf: [0; N], len: 0 } }

    fn extend(&mut self, b: &[u8]) {
        let n = b.len().min(N - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
    }

    fn push(&mut self, b: u8) { self.extend(&[b]) }

    fn as_slice(&self) -> &[u8] { &self.buf[..self.len] }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (a, b) = (self.0.get(..n)?, self.0.get(n..)?);
        self.0 = b;
        Some(a)
    }
}

/// The trusted comment maki signs: the signer's, or when and what, as minisign's own says it.
fn trusted<const N: usize>(out: &mut Buf<N>, theirs: &str, name: &str) {
    if !theirs.is_empty() {
        let _ = out.write_str(theirs);
        return;
    }
    if let Some(t) = unix_time() {
        let _ = write!(out, "timestamp:{t}\t");
    }
    let _ = write!(out, "file:{name}\thashed");
}

struct App {
    signed: u32,
    status: Buf<48>,
    showing_key: bool,
}

impl App {
    fn note(&mut self, what: &str) {
        self.status.clear();
        let _ = self.status.write_str(what);
    }

    /// A message from maki-minisign, and the answer.
    fn handle(&mut self, message: &[u8], answer: &mut Bytes<1024>) {
        let Some((public, id)) = key() else {
            answer.push(LOCKED);
            return;
        };
        match message.first() {
            Some(b'P') if message.len() == 1 => {
                answer.push(OK);
                answer.extend(&public);
                answer.extend(&id);
            }
            Some(b'S') => self.sign(&message[1..], &id, answer),
            _ => answer.push(BAD),
        }
    }

    fn sign(&mut self, message: &[u8], id: &[u8; 8], answer: &mut Bytes<1024>) {
        let mut r = Reader(message);
        let parsed = (|| {
            let hash = r.take(64)?;
            let bytes = u64::from_le_bytes(r.take(8)?.try_into().ok()?);
            let n = r.take(1)?[0] as usize;
            let name = core::str::from_utf8(r.take(n)?).ok()?;
            let n = u16::from_le_bytes(r.take(2)?.try_into().ok()?) as usize;
            let theirs = core::str::from_utf8(r.take(n)?).ok()?;
            Some((hash, bytes, name, theirs))
        })();
        let Some((hash, bytes, name, theirs)) = parsed else {
            answer.push(BAD);
            return;
        };
        // one line each, as minisign writes them, and a name with no path in it
        let one_line = |s: &str| !s.chars().any(|c| c.is_control() && c != '\t');
        if !r.0.is_empty() || name.is_empty() || name.len() > MOST_NAME || name.contains('/') || !one_line(name) || theirs.len() > MOST_COMMENT || !one_line(theirs) {
            answer.push(BAD);
            return;
        }
        let mut comment = Buf::<{ MOST_COMMENT + MOST_NAME + 40 }>::new();
        trusted(&mut comment, theirs, name);
        let mut question = Buf::<64>::new();
        let _ = question.write_str("Sign ");
        for c in name.chars() {
            if question.len() + c.len_utf8() > 56 {
                let _ = question.write_str("...");
                break;
            }
            let _ = question.write_char(c);
        }
        let _ = question.write_char('?');
        let mut detail = Buf::<128>::new();
        size(&mut detail, bytes);
        let _ = detail.write_str(", BLAKE2b ");
        for b in &hash[..6] {
            let _ = write!(detail, "{b:02x}");
        }
        let _ = detail.write_str("...");
        if !theirs.is_empty() {
            let _ = detail.write_str(", comment: ");
            for c in theirs.chars() {
                if detail.len() + c.len_utf8() > 124 {
                    let _ = detail.write_str("...");
                    break;
                }
                let _ = detail.write_char(c);
            }
        } else if let Some(t) = unix_time() {
            let _ = detail.write_str(", ");
            date(&mut detail, t);
        }
        match Ask::new(question.as_str()).detail(detail.as_str()).answers("sign", "deny").show() {
            Ok(Answer::Yes) => {}
            Ok(Answer::No) => {
                self.note("you said no");
                answer.push(DENIED);
                return;
            }
            _ => {
                self.note("no answer");
                answer.push(NO_ANSWER);
                return;
            }
        }
        // the hash, then the signature and the trusted comment together: minisign's two
        let Ok(signature) = keys::sign(LABEL, hash) else {
            answer.push(LOCKED);
            return;
        };
        let mut both = Bytes::<{ 64 + MOST_COMMENT + MOST_NAME + 40 }>::new();
        both.extend(&signature);
        both.extend(comment.as_str().as_bytes());
        let Ok(global) = keys::sign(LABEL, both.as_slice()) else {
            answer.push(LOCKED);
            return;
        };
        self.signed += 1;
        let _ = storage::set_u32("signed", self.signed);
        self.note("signed");
        answer.push(OK);
        answer.extend(id);
        answer.extend(&signature);
        answer.extend(&(comment.len() as u16).to_le_bytes());
        answer.extend(comment.as_str().as_bytes());
        answer.extend(&global);
    }

    fn draw(&self) {
        screen::clear(Color::Dark);
        match key() {
            None => {
                screen::text_centred(30, "Unlock maki to", Style::Regular, Color::Light);
                screen::text_centred(45, "use its minisign key", Style::Regular, Color::Light);
            }
            Some((public, id)) if self.showing_key => {
                // as minisign.pub has it, and `minisign -P` takes it
                let mut blob = [0u8; 42];
                blob[..2].copy_from_slice(b"Ed");
                blob[2..10].copy_from_slice(&id);
                blob[10..].copy_from_slice(&public);
                let mut line = Buf::<64>::new();
                base64(&mut line, &blob);
                let side = screen::qr(0, 0, line.as_str().as_bytes(), 110).unwrap_or(0);
                screen::clear(Color::Dark);
                screen::qr((WIDTH - side) / 2, (HEIGHT - side) / 2, line.as_str().as_bytes(), 110);
            }
            Some((_, id)) => {
                screen::text(2, 2, "Your minisign key", Style::Small, Color::Light);
                screen::text(2, 18, "ID", Style::Small, Color::Light);
                screen::text(2, 32, id_hex(&id).as_str(), Style::Mono, Color::Light);
                let mut line = Buf::<48>::new();
                if self.status.is_empty() {
                    let _ = write!(line, "signed {} files", self.signed);
                } else {
                    let _ = line.write_str(self.status.as_str());
                }
                screen::text_centred(70, line.as_str(), Style::Small, Color::Light);
                screen::text_centred(94, "menu: show the key", Style::Small, Color::Light);
            }
        }
        screen::present();
    }
}

fn main() {
    let _ = menu(&["Show the key"]);
    let mut app = App { signed: storage::get_u32("signed", 0), status: Buf::new(), showing_key: false };
    loop {
        app.draw();
        match wait(None) {
            Event::Message => {
                let mut message = [0u8; 4096];
                let mut answer = Bytes::<1024>::new();
                match link::read(&mut message) {
                    Some(n) if n <= message.len() => app.handle(&message[..n], &mut answer),
                    _ => answer.push(BAD),
                }
                let _ = link::reply(answer.as_slice());
            }
            Event::Menu(0) => app.showing_key = !app.showing_key,
            Event::Centre | Event::Left | Event::Right if app.showing_key => app.showing_key = false,
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
