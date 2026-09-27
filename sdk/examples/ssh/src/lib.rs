//! An SSH key from the recovery phrase, answering maki desktop's SSH agent (the link
//! permission). The key is maki's (keys): the app gets signatures, never the key. Every
//! sign-in and every signature waits for the owner's yes on maki's ask screen (ask).
//!
//! maki desktop runs the agent ssh and git talk to, and hands each of its requests here as a
//! message: a connection number (4 bytes, big-endian), then the agent message (its type, then
//! its body, draft-miller-ssh-agent). The answer is the agent's reply, the same way. What's to
//! be signed is read here, on maki, to show the owner: an SSH sign-in (the user, and the
//! server's host key if the SSH client bound its session to one) or an SSHSIG signature (git's
//! commits and tags, `ssh-keygen -Y sign`). Anything else is refused without asking.

#![no_std]

use core::fmt::Write;

use maki_app::*;
use sha2::{Digest, Sha256};

/// Which of the app's keys: its one.
const LABEL: &str = "ssh";
/// How ssh lists the key.
const COMMENT: &[u8] = b"maki";

// the agent protocol's message numbers
const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const EXTENSION: u8 = 27;
/// A sign-in's request, in the data ssh signs (RFC 4252, section 7).
const USERAUTH_REQUEST: u8 = 50;

/// Reading an SSH message: big-endian numbers, strings after their length.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (taken, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(taken)
    }

    fn u8(&mut self) -> Option<u8> { self.take(1).map(|b| b[0]) }

    fn u32(&mut self) -> Option<u32> { self.take(4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]])) }

    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    fn done(&self) -> bool { self.0.is_empty() }
}

/// Writing one, into a buffer big enough for any answer here.
struct Writer {
    buf: [u8; 256],
    len: usize,
}

impl Writer {
    fn new() -> Self { Writer { buf: [0; 256], len: 0 } }

    fn bytes(mut self, b: &[u8]) -> Self {
        let n = b.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
        self
    }

    fn u8(self, v: u8) -> Self { self.bytes(&[v]) }

    fn u32(self, v: u32) -> Self { self.bytes(&v.to_be_bytes()) }

    fn string(self, b: &[u8]) -> Self { self.u32(b.len() as u32).bytes(b) }

    fn as_slice(&self) -> &[u8] { &self.buf[..self.len] }
}

fn failure() -> Writer { Writer::new().u8(FAILURE) }

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64<const N: usize>(out: &mut Buf<N>, data: &[u8], pad: bool) {
    for chunk in data.chunks(3) {
        let b = [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                let _ = out.write_char(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else if pad {
                let _ = out.write_char('=');
            }
        }
    }
}

/// As ssh shows a key: "SHA256:" and the hash of its blob.
fn fingerprint(hash: &[u8; 32]) -> Buf<52> {
    let mut out = Buf::new();
    let _ = write!(out, "SHA256:");
    base64(&mut out, hash, false);
    out
}

fn sha256(data: &[u8]) -> [u8; 32] { Sha256::digest(data).into() }

/// Text from the computer, shown as it is if it's printable, cut to fit.
fn shown<const N: usize>(out: &mut Buf<N>, bytes: &[u8], most: usize) {
    for (i, &b) in bytes.iter().enumerate() {
        if i == most {
            let _ = out.write_str("...");
            break;
        }
        let _ = out.write_char(if (0x20..0x7f).contains(&b) { b as char } else { '?' });
    }
}

/// What a sign request would sign.
enum Signing<'a> {
    /// An SSH sign-in, by this user, in this session.
    SignIn { user: &'a [u8], session: &'a [u8] },
    /// An SSHSIG signature: git's commits and tags, or a file.
    Sig { namespace: &'a [u8] },
}

/// Only what these say they are, signed with this key: anything else, maki won't sign.
fn signing<'a>(data: &'a [u8], blob: &[u8]) -> Option<Signing<'a>> {
    if let Some(sig) = data.strip_prefix(b"SSHSIG") {
        let mut r = Reader(sig);
        let namespace = r.string()?;
        r.string()?; // reserved
        let hash = r.string()?;
        r.string()?; // the message's hash
        return (r.done() && (hash == b"sha256" || hash == b"sha512")).then_some(Signing::Sig { namespace });
    }
    let mut r = Reader(data);
    let session = r.string()?;
    if r.u8()? != USERAUTH_REQUEST {
        return None;
    }
    let user = r.string()?;
    r.string()?; // the service
    if r.string()? != b"publickey" || r.u8()? != 1 || r.string()? != b"ssh-ed25519" || r.string()? != blob {
        return None;
    }
    r.done().then_some(Signing::SignIn { user, session })
}

/// A session an SSH client bound to a server's host key (session-bind@openssh.com). The host
/// key is what the computer says: maki can't check it.
#[derive(Clone, Copy)]
struct Bound {
    conn: u32,
    /// the session identifier's hash
    session: [u8; 32],
    /// the host key's hash, its fingerprint
    host: [u8; 32],
}

struct App {
    /// the key's blob, once maki is unlocked
    blob: Option<Writer>,
    bound: [Option<Bound>; 8],
    next: usize,
    signed: u32,
    status: Buf<48>,
    showing_key: bool,
}

impl App {
    fn blob(&mut self) -> Option<&[u8]> {
        if self.blob.is_none() {
            let public = keys::public_key(LABEL).ok()?;
            self.blob = Some(Writer::new().string(b"ssh-ed25519").string(&public));
        }
        self.blob.as_ref().map(|b| b.as_slice())
    }

    fn note(&mut self, what: &str) {
        self.status.clear();
        let _ = self.status.write_str(what);
    }

    /// The agent message, and the agent's answer.
    fn handle(&mut self, message: &[u8]) -> Writer {
        let mut r = Reader(message);
        let (Some(conn), Some(kind)) = (r.u32(), r.u8()) else { return failure() };
        match kind {
            REQUEST_IDENTITIES => match self.blob() {
                Some(blob) => Writer::new().u8(IDENTITIES_ANSWER).u32(1).string(blob).string(COMMENT),
                // locked: no key to offer
                None => Writer::new().u8(IDENTITIES_ANSWER).u32(0),
            },
            SIGN_REQUEST => self.sign(conn, &mut r),
            EXTENSION => self.extension(conn, &mut r),
            _ => failure(),
        }
    }

    fn sign(&mut self, conn: u32, r: &mut Reader) -> Writer {
        let (Some(key), Some(data), Some(_flags)) = (r.string(), r.string(), r.u32()) else { return failure() };
        let Some(blob) = self.blob().map(|b| {
            let mut copy = [0u8; 51];
            copy.copy_from_slice(&b[..51]);
            copy
        }) else {
            return failure();
        };
        if key != blob || !r.done() {
            return failure();
        }
        let Some(what) = signing(data, &blob) else {
            self.note("refused: not a sign-in");
            return failure();
        };
        let mut question = Buf::<64>::new();
        let mut detail = Buf::<128>::new();
        match what {
            Signing::SignIn { user, session } => {
                let _ = question.write_str("SSH sign-in?");
                let _ = detail.write_str("as ");
                shown(&mut detail, user, 32);
                let session = sha256(session);
                let host = self.bound.iter().flatten().find(|b| b.conn == conn && b.session == session).map(|b| b.host);
                if let Some(host) = host {
                    let _ = detail.write_str(", host ");
                    // enough of the fingerprint to compare with ssh's
                    let _ = detail.write_str(&fingerprint(&host).as_str()[..19]);
                }
            }
            Signing::Sig { namespace } if namespace == b"git" => {
                let _ = question.write_str("Sign for git?");
                let _ = detail.write_str("a commit or a tag");
            }
            Signing::Sig { namespace } => {
                let _ = question.write_str("Sign with SSH key?");
                let _ = detail.write_str("for ");
                shown(&mut detail, namespace, 40);
            }
        }
        match Ask::new(question.as_str()).detail(detail.as_str()).answers("sign", "deny").show() {
            Ok(Answer::Yes) => {}
            Ok(Answer::No) => {
                self.note("you said no");
                return failure();
            }
            _ => {
                self.note("no answer");
                return failure();
            }
        }
        match keys::sign(LABEL, data) {
            Ok(signature) => {
                self.signed += 1;
                let _ = storage::set_u32("signed", self.signed);
                self.note("signed");
                let sig = Writer::new().string(b"ssh-ed25519").string(&signature);
                Writer::new().u8(SIGN_RESPONSE).string(sig.as_slice())
            }
            Err(_) => failure(),
        }
    }

    fn extension(&mut self, conn: u32, r: &mut Reader) -> Writer {
        if r.string() != Some(&b"session-bind@openssh.com"[..]) {
            return failure();
        }
        let (Some(host), Some(session), Some(_signature), Some(_forwarding)) = (r.string(), r.string(), r.string(), r.u8())
        else {
            return failure();
        };
        self.bound[self.next] = Some(Bound { conn, session: sha256(session), host: sha256(host) });
        self.next = (self.next + 1) % self.bound.len();
        Writer::new().u8(SUCCESS)
    }

    fn draw(&mut self) {
        screen::clear(Color::Dark);
        let blob = self.blob().map(|b| {
            let mut copy = [0u8; 51];
            copy.copy_from_slice(&b[..51]);
            copy
        });
        match blob {
            None => {
                screen::text_centred(30, "Unlock maki to", Style::Regular, Color::Light);
                screen::text_centred(45, "use its SSH key", Style::Regular, Color::Light);
            }
            Some(blob) if self.showing_key => {
                // the public key as ssh writes it, to scan into authorized_keys
                let mut line = Buf::<96>::new();
                let _ = line.write_str("ssh-ed25519 ");
                base64(&mut line, &blob, true);
                let _ = line.write_str(" maki");
                let side = screen::qr(0, 0, line.as_str().as_bytes(), 110).unwrap_or(0);
                if side > 0 {
                    // centred across
                    screen::clear(Color::Dark);
                    screen::qr((WIDTH - side) / 2, (HEIGHT - side) / 2, line.as_str().as_bytes(), 110);
                }
            }
            Some(blob) => {
                screen::text(2, 2, "Your SSH key", Style::Small, Color::Light);
                let fp = fingerprint(&sha256(&blob));
                let fp = fp.as_str();
                screen::text(2, 16, &fp[..7], Style::Mono, Color::Light);
                for (i, part) in fp.as_bytes()[7..].chunks(16).enumerate() {
                    let part = core::str::from_utf8(part).unwrap_or("");
                    screen::text(2, 31 + i as i32 * 14, part, Style::Mono, Color::Light);
                }
                let mut line = Buf::<48>::new();
                if self.status.is_empty() {
                    let _ = write!(line, "signed {} times", self.signed);
                } else {
                    let _ = line.write_str(self.status.as_str());
                }
                screen::text_centred(78, line.as_str(), Style::Small, Color::Light);
                screen::text_centred(94, "menu: show the key", Style::Small, Color::Light);
            }
        }
        screen::present();
    }
}

fn main() {
    let _ = menu(&["Show the key"]);
    let mut app = App {
        blob: None,
        bound: [None; 8],
        next: 0,
        signed: storage::get_u32("signed", 0),
        status: Buf::new(),
        showing_key: false,
    };
    loop {
        app.draw();
        match wait(None) {
            Event::Message => {
                let mut message = [0u8; 4096];
                let answer = match link::read(&mut message) {
                    Some(n) if n <= message.len() => app.handle(&message[..n]),
                    _ => failure(),
                };
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
