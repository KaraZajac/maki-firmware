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
//!
//! Two more of maki's own:
//! - A certificate authority's key, from the phrase too, which the agent offers once it's turned on in the
//!   menu, for `ssh-keygen -s ca.pub -U` to sign SSH certificates with. It signs nothing else, and each
//!   certificate is read here first: user or host, for whom, until when, with what restrictions, and the key
//!   it certifies.
//! - Something signed whole, as `ssh-keygen -Y sign` signs it (maki desktop's maki-ssh-keygen, which git runs
//!   to sign commits and tags): message type 240 (`SIGN_WHOLE`), its namespace (a string), its whole length
//!   and where this piece starts (u32s), and the piece. The app hashes it as the pieces come (SHA-512),
//!   answers SUCCESS until the last, then shows what it is from the same bytes (a commit's subject and
//!   author, a tag's name) and signs SSHSIG's data for it: SIGN_RESPONSE and the signature, or FAILURE.

#![no_std]

use core::fmt::Write;

use maki_app::*;
use sha2::{Digest, Sha256, Sha512};

/// Which of the app's keys: its one, and the certificate authority's.
const LABEL: &str = "ssh";
const CA_LABEL: &str = "ssh-ca";
/// How ssh lists them.
const COMMENT: &[u8] = b"maki";
const CA_COMMENT: &[u8] = b"maki CA";

// the agent protocol's message numbers
const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const EXTENSION: u8 = 27;
/// maki's own: something signed whole, in pieces (above).
const SIGN_WHOLE: u8 = 240;
/// A sign-in's request, in the data ssh signs (RFC 4252, section 7).
const USERAUTH_REQUEST: u8 = 50;
/// The most it signs whole: far more than any commit.
const MOST_WHOLE: u32 = 16 << 20;
/// What it keeps of the start of something signed whole, to show: a commit's headers and
/// subject (an app's stack is 16 KiB, so no more).
const HEAD: usize = 1024;

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

    fn u64(&mut self) -> Option<u64> { self.take(8).map(|b| u64::from_be_bytes(b.try_into().unwrap())) }

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

/// A day from seconds since 1970, in UTC (the civil calendar from days since then).
fn date<const N: usize>(out: &mut Buf<N>, secs: u64) {
    const MONTHS: [&str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    let _ = write!(out, "{day} {} {year}", MONTHS[month as usize - 1]);
}

/// What a sign request would sign.
enum Signing<'a> {
    /// An SSH sign-in, by this user, in this session; to this server, when the sign-in names
    /// its host key (OpenSSH's publickey-hostbound-v00@openssh.com, which it uses with an agent
    /// that takes session binding, as maki desktop's does).
    SignIn { user: &'a [u8], session: &'a [u8], host: Option<&'a [u8]> },
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
    let hostbound = match r.string()? {
        b"publickey" => false,
        b"publickey-hostbound-v00@openssh.com" => true,
        _ => return None,
    };
    if r.u8()? != 1 || r.string()? != b"ssh-ed25519" || r.string()? != blob {
        return None;
    }
    // the server's host key, signed with the rest
    let host = if hostbound { Some(r.string()?) } else { None };
    r.done().then_some(Signing::SignIn { user, session, host })
}

/// An SSH certificate to be signed (PROTOCOL.certkeys): all of it but the signature.
struct Certificate<'a> {
    host: bool,
    /// the certified key's fingerprint
    key: [u8; 32],
    id: &'a [u8],
    /// its principals, as strings one after another; none means any
    principals: &'a [u8],
    after: u64,
    before: u64,
    /// critical options (force-command, source-address, ...), as strings in pairs
    options: &'a [u8],
}

/// A certificate for the certificate authority's key to sign, and nothing else.
fn certificate<'a>(data: &'a [u8], ca: &[u8]) -> Option<Certificate<'a>> {
    let mut r = Reader(data);
    let kind = r.string()?;
    // the certified key's own fields, as its public key blob has them after its type
    let (base, fields): (&[u8], usize) = match kind {
        b"ssh-ed25519-cert-v01@openssh.com" => (b"ssh-ed25519", 1),
        b"sk-ssh-ed25519-cert-v01@openssh.com" => (b"sk-ssh-ed25519@openssh.com", 2),
        b"ecdsa-sha2-nistp256-cert-v01@openssh.com" => (b"ecdsa-sha2-nistp256", 2),
        b"ecdsa-sha2-nistp384-cert-v01@openssh.com" => (b"ecdsa-sha2-nistp384", 2),
        b"ecdsa-sha2-nistp521-cert-v01@openssh.com" => (b"ecdsa-sha2-nistp521", 2),
        b"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" => (b"sk-ecdsa-sha2-nistp256@openssh.com", 3),
        b"ssh-rsa-cert-v01@openssh.com" => (b"ssh-rsa", 2),
        _ => return None,
    };
    r.string()?; // the nonce
    let start = r.0;
    for _ in 0..fields {
        r.string()?;
    }
    let own = &start[..start.len() - r.0.len()];
    let mut key = Sha256::new();
    key.update((base.len() as u32).to_be_bytes());
    key.update(base);
    key.update(own);
    r.u64()?; // the serial
    let host = match r.u32()? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let id = r.string()?;
    let principals = r.string()?;
    let (after, before) = (r.u64()?, r.u64()?);
    let options = r.string()?;
    r.string()?; // extensions: what a user's certificate allows, pty and the like
    r.string()?; // reserved
    let signer = r.string()?;
    (signer == ca && r.done()).then_some(Certificate {
        host,
        key: key.finalize().into(),
        id,
        principals,
        after,
        before,
        options,
    })
}

/// Something being signed whole, as its pieces come.
struct Whole {
    namespace: [u8; 64],
    namespace_len: usize,
    total: u32,
    got: u32,
    hash: Sha512,
    head: [u8; HEAD],
}

impl Whole {
    fn namespace(&self) -> &[u8] { &self.namespace[..self.namespace_len] }

    fn head(&self) -> &[u8] { &self.head[..(self.got as usize).min(HEAD)] }
}

/// A header line's value in a git object, before the message ("author", "tag"...).
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

/// A person as git writes one ("Name <email> 1700000000 +0000"): the name.
fn person(line: &[u8]) -> &[u8] {
    let end = line.iter().position(|&b| b == b'<').unwrap_or(line.len());
    line[..end].strip_suffix(b" ").unwrap_or(&line[..end])
}

/// A git object's subject: its message's first line (after the headers and a blank line).
fn subject(object: &[u8]) -> Option<&[u8]> {
    let at = object.windows(2).position(|w| w == b"\n\n")? + 2;
    let message = &object[at..];
    Some(&message[..message.iter().position(|&b| b == b'\n').unwrap_or(message.len())])
}

/// What the owner is asked, for something signed whole: what it is, from its bytes.
fn whole_ask(w: &Whole, question: &mut Buf<64>, detail: &mut Buf<128>) {
    let head = w.head();
    let git = w.namespace() == b"git";
    let quoted = |detail: &mut Buf<128>, text: &[u8], by: Option<&[u8]>| {
        let _ = detail.write_char('"');
        shown(detail, text, 64);
        let _ = detail.write_char('"');
        if let Some(by) = by {
            let _ = detail.write_str(" by ");
            shown(detail, by, 40);
        }
    };
    if git && header(head, b"tree").is_some() {
        let parents = head
            .split(|&b| b == b'\n')
            .take_while(|l| !l.is_empty())
            .filter(|l| l.starts_with(b"parent "))
            .count();
        let _ = question.write_str(if parents > 1 { "Sign this merge?" } else { "Sign this commit?" });
        quoted(detail, subject(head).unwrap_or(b"?"), header(head, b"author").map(person));
    } else if git && header(head, b"object").is_some() {
        let _ = question.write_str("Sign tag ");
        shown(question, header(head, b"tag").unwrap_or(b"?"), 40);
        let _ = question.write_char('?');
        quoted(detail, subject(head).unwrap_or(b"?"), header(head, b"tagger").map(person));
    } else if git && head.starts_with(b"certificate version ") {
        let _ = question.write_str("Sign this push?");
        let _ = detail.write_str("by ");
        shown(detail, header(head, b"pusher").map(person).unwrap_or(b"?"), 40);
        let _ = detail.write_str(" to ");
        shown(detail, header(head, b"pushee").unwrap_or(b"?"), 60);
    } else {
        let _ = question.write_str("Sign with SSH key?");
        let _ = write!(detail, "{} bytes, for ", w.total);
        shown(detail, w.namespace(), 40);
    }
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

/// A key's blob, as ssh writes it.
type Blob = [u8; 51];

struct App {
    /// the keys' blobs, once maki is unlocked
    user: Option<Blob>,
    ca_key: Option<Blob>,
    /// whether the agent offers the certificate authority's key
    ca: bool,
    bound: [Option<Bound>; 8],
    next: usize,
    whole: Option<Whole>,
    signed: u32,
    status: Buf<48>,
    showing: Showing,
}

#[derive(Clone, Copy, PartialEq)]
enum Showing {
    Home,
    Key,
    CaKey,
}

fn blob_for(label: &str) -> Option<Blob> {
    let public = keys::public_key(label).ok()?;
    let w = Writer::new().string(b"ssh-ed25519").string(&public);
    w.as_slice().try_into().ok()
}

impl App {
    fn user(&mut self) -> Option<Blob> {
        if self.user.is_none() {
            self.user = blob_for(LABEL);
        }
        self.user
    }

    /// The certificate authority's key, if the owner has turned it on.
    fn ca(&mut self) -> Option<Blob> {
        if !self.ca {
            return None;
        }
        if self.ca_key.is_none() {
            self.ca_key = blob_for(CA_LABEL);
        }
        self.ca_key
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
            REQUEST_IDENTITIES => {
                let (user, ca) = (self.user(), self.ca());
                // locked: no keys to offer
                let n = user.is_some() as u32 + ca.is_some() as u32;
                let mut w = Writer::new().u8(IDENTITIES_ANSWER).u32(n);
                if let Some(b) = user {
                    w = w.string(&b).string(COMMENT);
                }
                if let Some(b) = ca {
                    w = w.string(&b).string(CA_COMMENT);
                }
                w
            }
            SIGN_REQUEST => self.sign(conn, &mut r),
            EXTENSION => self.extension(conn, &mut r),
            SIGN_WHOLE => self.sign_whole(&mut r),
            _ => failure(),
        }
    }

    /// The owner's yes, or a note why not.
    fn asked(&mut self, question: &str, detail: &str) -> bool {
        match Ask::new(question).detail(detail).answers("sign", "deny").show() {
            Ok(Answer::Yes) => true,
            Ok(Answer::No) => {
                self.note("you said no");
                false
            }
            _ => {
                self.note("no answer");
                false
            }
        }
    }

    /// Signs `data` with the key under `label`, as the agent answers.
    fn signature(&mut self, label: &str, data: &[u8]) -> Writer {
        match keys::sign(label, data) {
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

    fn sign(&mut self, conn: u32, r: &mut Reader) -> Writer {
        let (Some(key), Some(data), Some(_flags)) = (r.string(), r.string(), r.u32()) else {
            return failure();
        };
        if !r.done() {
            return failure();
        }
        if let Some(ca) = self.ca().filter(|ca| key == ca) {
            return self.sign_certificate(data, &ca);
        }
        let Some(blob) = self.user().filter(|b| key == b) else { return failure() };
        let Some(what) = signing(data, &blob) else {
            self.note("refused: not a sign-in");
            return failure();
        };
        let mut question = Buf::<64>::new();
        let mut detail = Buf::<128>::new();
        match what {
            Signing::SignIn { user, session, host } => {
                let _ = question.write_str("SSH sign-in?");
                let _ = detail.write_str("as ");
                shown(&mut detail, user, 32);
                // the host key the sign-in names, or else the one the session was bound to
                let session = sha256(session);
                let host = host.map(sha256).or_else(|| {
                    self.bound
                        .iter()
                        .flatten()
                        .find(|b| b.conn == conn && b.session == session)
                        .map(|b| b.host)
                });
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
        if !self.asked(question.as_str(), detail.as_str()) {
            return failure();
        }
        self.signature(LABEL, data)
    }

    /// A certificate, read here and shown before the certificate authority's key signs it.
    fn sign_certificate(&mut self, data: &[u8], ca: &Blob) -> Writer {
        let Some(c) = certificate(data, ca) else {
            self.note("refused: not a certificate");
            return failure();
        };
        let mut question = Buf::<64>::new();
        let _ =
            question.write_str(if c.host { "Sign a host certificate?" } else { "Sign a user certificate?" });
        let mut detail = Buf::<128>::new();
        if c.principals.is_empty() {
            let _ = detail.write_str(if c.host { "for ANY host" } else { "for EVERY user" });
        } else {
            let _ = detail.write_str("for ");
            let mut r = Reader(c.principals);
            let mut first = true;
            while let Some(p) = r.string() {
                if !first {
                    let _ = detail.write_char(',');
                }
                first = false;
                shown(&mut detail, p, 24);
            }
        }
        let _ = detail.write_str(" (");
        shown(&mut detail, c.id, 20);
        let _ = detail.write_str("), ");
        if c.before == u64::MAX {
            let _ = detail.write_str("forever");
        } else {
            let _ = detail.write_str("until ");
            date(&mut detail, c.before);
        }
        if c.after > 0 && c.after != u64::MAX {
            let _ = detail.write_str(" from ");
            date(&mut detail, c.after);
        }
        if !c.options.is_empty() {
            let _ = detail.write_str(", restricted");
        }
        let _ = detail.write_str(", key ");
        let _ = detail.write_str(&fingerprint(&c.key).as_str()[..19]);
        if !self.asked(question.as_str(), detail.as_str()) {
            return failure();
        }
        self.signature(CA_LABEL, data)
    }

    /// A piece of something signed whole; when it's all come, what it is shown and signed.
    fn sign_whole(&mut self, r: &mut Reader) -> Writer {
        let (Some(namespace), Some(total), Some(offset)) = (r.string(), r.u32(), r.u32()) else {
            return failure();
        };
        let piece = r.0;
        if offset == 0 {
            if total == 0 || total > MOST_WHOLE || namespace.is_empty() || namespace.len() > 64 {
                return failure();
            }
            let mut w = Whole {
                namespace: [0; 64],
                namespace_len: namespace.len(),
                total,
                got: 0,
                hash: Sha512::new(),
                head: [0; HEAD],
            };
            w.namespace[..namespace.len()].copy_from_slice(namespace);
            self.whole = Some(w);
        }
        let Some(w) = self.whole.as_mut() else { return failure() };
        if offset != w.got
            || total != w.total
            || namespace != w.namespace()
            || piece.len() as u32 > total - offset
        {
            self.whole = None;
            return failure();
        }
        w.hash.update(piece);
        let at = offset as usize;
        if at < HEAD {
            let n = piece.len().min(HEAD - at);
            w.head[at..at + n].copy_from_slice(&piece[..n]);
        }
        w.got += piece.len() as u32;
        if w.got < w.total {
            return Writer::new().u8(SUCCESS);
        }
        if self.user().is_none() {
            self.whole = None;
            return failure();
        }
        let mut question = Buf::<64>::new();
        let mut detail = Buf::<128>::new();
        // SSHSIG's data for it (PROTOCOL.sshsig): what ssh-keygen -Y sign has signed
        let data = match self.whole.as_ref() {
            Some(w) => {
                whole_ask(w, &mut question, &mut detail);
                let digest: [u8; 64] = w.hash.clone().finalize().into();
                Writer::new()
                    .bytes(b"SSHSIG")
                    .string(w.namespace())
                    .string(b"")
                    .string(b"sha512")
                    .string(&digest)
            }
            None => return failure(),
        };
        self.whole = None;
        if !self.asked(question.as_str(), detail.as_str()) {
            return failure();
        }
        self.signature(LABEL, data.as_slice())
    }

    fn extension(&mut self, conn: u32, r: &mut Reader) -> Writer {
        if r.string() != Some(&b"session-bind@openssh.com"[..]) {
            return failure();
        }
        let (Some(host), Some(session), Some(_signature), Some(_forwarding)) =
            (r.string(), r.string(), r.string(), r.u8())
        else {
            return failure();
        };
        self.bound[self.next] = Some(Bound { conn, session: sha256(session), host: sha256(host) });
        self.next = (self.next + 1) % self.bound.len();
        Writer::new().u8(SUCCESS)
    }

    fn draw(&mut self) {
        screen::clear(Color::Dark);
        let showing = self.showing;
        let (user, ca) = (self.user(), if showing == Showing::CaKey { self.ca() } else { None });
        match (showing, user, ca) {
            (_, None, _) => {
                screen::text_centred(30, "Unlock maki to", Style::Regular, Color::Light);
                screen::text_centred(45, "use its SSH key", Style::Regular, Color::Light);
            }
            (Showing::Key, Some(blob), _) | (Showing::CaKey, _, Some(blob)) => {
                // the public key as ssh writes it, to scan into authorized_keys (or, the
                // certificate authority's, into TrustedUserCAKeys or known_hosts)
                let mut line = Buf::<96>::new();
                let _ = line.write_str("ssh-ed25519 ");
                base64(&mut line, &blob, true);
                let _ = line.write_str(if showing == Showing::CaKey { " maki-ca" } else { " maki" });
                let side = screen::qr(0, 0, line.as_str().as_bytes(), 110).unwrap_or(0);
                if side > 0 {
                    // centred across
                    screen::clear(Color::Dark);
                    screen::qr((WIDTH - side) / 2, (HEIGHT - side) / 2, line.as_str().as_bytes(), 110);
                }
            }
            (_, Some(blob), _) => {
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
                screen::text_centred(
                    94,
                    if self.ca { "certificate authority: on" } else { "menu: show the key" },
                    Style::Small,
                    Color::Light,
                );
            }
        }
        screen::present();
    }
}

fn main() {
    let mut app = App {
        user: None,
        ca_key: None,
        ca: storage::get_u32("ca", 0) == 1,
        bound: [None; 8],
        next: 0,
        whole: None,
        signed: storage::get_u32("signed", 0),
        status: Buf::new(),
        showing: Showing::Home,
    };
    let items = |ca: bool| {
        if ca {
            ["Show the key", "Show the CA key", "Stop the CA key"]
        } else {
            ["Show the key", "Certificate authority", ""]
        }
    };
    let set_menu = |ca: bool| {
        let all = items(ca);
        let _ = menu(if ca { &all[..] } else { &all[..2] });
    };
    set_menu(app.ca);
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
            Event::Menu(0) => {
                app.showing = if app.showing == Showing::Key { Showing::Home } else { Showing::Key }
            }
            Event::Menu(1) if app.ca => {
                app.showing = if app.showing == Showing::CaKey { Showing::Home } else { Showing::CaKey }
            }
            // the certificate authority's key: offered to ssh-keygen once turned on
            Event::Menu(1) | Event::Menu(2) => {
                app.ca = !app.ca;
                let _ = storage::set_u32("ca", app.ca as u32);
                app.note(if app.ca { "CA key on: see ssh-add -L" } else { "CA key off" });
                app.showing = if app.ca { Showing::CaKey } else { Showing::Home };
                set_menu(app.ca);
            }
            Event::Centre | Event::Left | Event::Right if app.showing != Showing::Home => {
                app.showing = Showing::Home
            }
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
