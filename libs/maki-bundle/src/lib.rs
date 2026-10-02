//! `.maki` app bundles: one app's manifest, code and icon, signed by its developer
//! (ARCHITECTURE.md, "Apps you can install").
//!
//! A bundle is `MAKI`, the format version (1), then sections, each a tag byte, a little-endian
//! u32 length and that many bytes, in this order and no other:
//!
//! - **manifest** (1): fields, each a tag byte, a little-endian u16 length and the value, in increasing tag
//!   order, each once except permissions, which come in increasing order;
//! - **code** (2): a WebAssembly module, or a Xous ELF for a native app;
//! - **icon** (3), optional: 64x64 pixels in `maki_icons` form, 128 little-endian words;
//! - **signature** (255), last: the developer's Ed25519 public key (32 bytes) and their signature (64 bytes)
//!   over `maki bundle v1\0` and the SHA-256 of everything before this section.
//!
//! Nothing may follow the signature. Bundles come from anywhere, so `read` checks everything
//! and turns away what it doesn't understand, including fields a newer maki might add.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub use ed25519_dalek::SigningKey as DeveloperKey;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 4] = b"MAKI";
pub const FORMAT: u8 = 1;
/// The largest bundle maki takes.
pub const MAX_BUNDLE: usize = 512 * 1024;
/// Words in an icon: 64 rows of two.
pub const ICON_WORDS: usize = 128;
const DOMAIN: &[u8] = b"maki bundle v1\0";

const SECTION_MANIFEST: u8 = 1;
const SECTION_CODE: u8 = 2;
const SECTION_ICON: u8 = 3;
const SECTION_SIGNATURE: u8 = 255;
/// The maki store's stamp (`maki_store`), after the developer's signature and not covered by it:
/// the store adds it to the bundle the developer signed.
const SECTION_STAMP: u8 = 254;
const SIGNATURE_LEN: usize = 32 + 64;

const FIELD_ID: u8 = 1;
const FIELD_NAME: u8 = 2;
const FIELD_VERSION: u8 = 3;
const FIELD_LABEL: u8 = 4;
const FIELD_KIND: u8 = 5;
const FIELD_API: u8 = 6;
const FIELD_FIRMWARE: u8 = 7;
const FIELD_PERMISSION: u8 = 8;
const FIELD_STORAGE: u8 = 9;
const FIELD_MEMORY: u8 = 10;
const FIELD_BACKUP: u8 = 11;
const FIELD_DESCRIPTION: u8 = 12;
/// The wallet permission's paths: the curve (1, secp256k1; 2, Ed25519), how many, then each as its
/// depth and that many little-endian u32s (a hardened one with the top bit set).
const FIELD_WALLET: u8 = 13;

/// A wallet app names at most this many derivation paths.
pub const MAX_WALLET_PATHS: usize = 8;

/// Longest app ID, in bytes: `maki.app.` and the ID must make a PDDB dictionary name.
pub const MAX_ID: usize = 64;
/// Longest name, in bytes; the home screen shortens what doesn't fit.
pub const MAX_NAME: usize = 24;
pub const MAX_LABEL: usize = 16;
pub const MAX_FIRMWARE: usize = 64;
/// Longest reason a developer can give for a permission, in bytes.
pub const MAX_REASON: usize = 100;
pub const MAX_DESCRIPTION: usize = 300;
/// Limits on what a manifest can ask for; the host sets its own, lower ones.
pub const MAX_STORAGE_KIB: u32 = 16 * 1024;
pub const MAX_MEMORY_KIB: u32 = 16 * 1024;

/// What kind of code a bundle carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A WebAssembly module, run by maki's app host.
    Wasm = 1,
    /// A Xous program, run as a process of its own. maki doesn't take these yet.
    Native = 2,
}

/// What an app can ask for beyond the basics (its screen, buttons, storage, the time, random
/// numbers and timers, which every app has).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    Ask = 1,
    Link = 2,
    Keys = 3,
    Keyboard = 4,
    Camera = 5,
    Motion = 6,
    Wallet = 7,
}

impl Permission {
    pub const ALL: [Permission; 7] = [
        Permission::Ask,
        Permission::Link,
        Permission::Keys,
        Permission::Keyboard,
        Permission::Camera,
        Permission::Motion,
        Permission::Wallet,
    ];

    pub fn from_u8(b: u8) -> Option<Permission> { Permission::ALL.iter().copied().find(|p| *p as u8 == b) }

    /// As written in `maki.toml`.
    pub fn name(self) -> &'static str {
        match self {
            Permission::Ask => "ask",
            Permission::Link => "link",
            Permission::Keys => "keys",
            Permission::Keyboard => "keyboard",
            Permission::Camera => "camera",
            Permission::Motion => "motion",
            Permission::Wallet => "wallet",
        }
    }

    pub fn from_name(name: &str) -> Option<Permission> {
        Permission::ALL.iter().copied().find(|p| p.name() == name)
    }

    /// A few words, as the install screen heads the permission's page.
    pub fn title(self) -> &'static str {
        match self {
            Permission::Ask => "Ask you anytime",
            Permission::Link => "Talk to your computer",
            Permission::Keys => "Keys of its own",
            Permission::Keyboard => "Type on your computer",
            Permission::Camera => "Use the camera",
            Permission::Motion => "Sense motion",
            Permission::Wallet => "Sign for your wallets",
        }
    }

    /// What the app could do with it, whatever the developer says it's for.
    pub fn warning(self) -> &'static str {
        match self {
            Permission::Ask => "It can put questions to you on maki's screen, even while it isn't open.",
            Permission::Link => {
                "It can send and receive messages through maki desktop. Your computer sees what it sends."
            }
            Permission::Keys => {
                "It gets secrets made from your recovery phrase, for this app only: never your wallets' or passkeys'."
            }
            Permission::Keyboard => {
                "It can type anything into your computer while it's open, and press shortcuts: it could open and run programs."
            }
            Permission::Camera => "It can see what the camera sees while it's open.",
            Permission::Motion => "It can read the accelerometer, which can pick up typing nearby.",
            Permission::Wallet => {
                "It can sign for the accounts named next, once you say yes on maki: it could spend what they hold."
            }
        }
    }
}

/// What a bundle says about its app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// Reverse-DNS, lower case: `org.example.dice`.
    pub id: String,
    /// As the home screen shows it.
    pub name: String,
    /// Only ever goes up from one version to the next.
    pub version: u32,
    /// The version as people write it: "1.2.0". May be empty.
    pub label: String,
    pub kind: Kind,
    /// The app host API version a WebAssembly app needs; 0 for a native app.
    pub api: u16,
    /// The firmware a native app was built for; empty for a WebAssembly app.
    pub firmware: String,
    /// What it asks for, each with the developer's reason, in `Permission` order.
    pub permissions: Vec<(Permission, String)>,
    /// Storage it needs, KiB.
    pub storage_kib: u32,
    /// Memory it needs, KiB.
    pub memory_kib: u32,
    /// Whether its data goes in maki's backup unless the owner says otherwise.
    pub backup: bool,
    /// For maki desktop to show. May be empty.
    pub description: String,
    /// With the wallet permission: the derivation paths it may use (ARCHITECTURE.md, "Wallets
    /// are apps").
    pub wallet: Option<Wallet>,
}

impl Manifest {
    pub fn wants(&self, p: Permission) -> bool { self.permissions.iter().any(|(q, _)| *q == p) }
}

/// The curve a wallet's keys are on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Curve {
    /// BIP32 on secp256k1: Bitcoin's, Ethereum's (and Monero's, from the key at its path).
    Secp256k1 = 1,
    /// SLIP-10 on Ed25519, every step hardened: Solana's (host API 6).
    Ed25519 = 2,
}

/// What a wallet app may use: paths on a curve, each a purpose and a coin type at least, both
/// hardened, and everything under them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wallet {
    pub curve: Curve,
    pub paths: Vec<Vec<u32>>,
}

impl Wallet {
    /// Whether the app may use `path`: it's under one of its paths.
    pub fn allows(&self, path: &[u32]) -> bool { self.paths.iter().any(|p| maki_hd::under(path, p)) }

    /// The coins its paths name (SLIP-44), each once, as the install screen says them: from the
    /// paths themselves, never the app's say-so.
    pub fn coins(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for p in &self.paths {
            let name = match maki_hd::coin(p) {
                Some(n) => String::from(n),
                None => alloc::format!("coin type {}", p[1] & !maki_hd::HARDENED),
            };
            if !out.contains(&name) {
                out.push(name);
            }
        }
        out
    }
}

/// A bundle that `read` found well formed and signed by `developer`.
#[derive(Clone, Debug)]
pub struct Bundle<'a> {
    pub manifest: Manifest,
    pub code: &'a [u8],
    pub icon: Option<[u32; ICON_WORDS]>,
    /// The developer's Ed25519 public key.
    pub developer: [u8; 32],
    /// SHA-256 of the bundle as its developer signed it, signature included (and the store's
    /// stamp not): what the store stamps.
    pub hash: [u8; 32],
    /// The store's stamp, if it has one (`maki_store::SignedStamp`, unchecked here).
    pub stamp: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    TooBig,
    NotABundle,
    /// A format this maki doesn't read, probably newer.
    Format(u8),
    Truncated,
    /// Sections missing, repeated, out of order or unknown, or bytes after the signature (but
    /// the store's stamp).
    Sections,
    /// A manifest field that's missing, repeated, out of order, unknown or out of range: which.
    Manifest(&'static str),
    Icon,
    /// The signature doesn't check out: the bundle was changed after it was signed.
    Signature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::TooBig => write!(f, "bigger than maki takes ({} KiB)", MAX_BUNDLE / 1024),
            Error::NotABundle => write!(f, "not a .maki bundle"),
            Error::Format(v) => write!(f, "bundle format {v}, newer than this maki reads"),
            Error::Truncated => write!(f, "cut short"),
            Error::Sections => write!(f, "sections missing, repeated or out of order"),
            Error::Manifest(what) => write!(f, "manifest: {what}"),
            Error::Icon => write!(f, "the icon isn't 64x64"),
            Error::Signature => write!(f, "the signature doesn't match: changed since it was signed"),
        }
    }
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or(Error::Truncated)?;
        let s = self.b.get(self.at..end).ok_or(Error::Truncated)?;
        self.at = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Error> { Ok(self.take(1)?[0]) }

    fn u16(&mut self) -> Result<u16, Error> { Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap())) }

    fn u32(&mut self) -> Result<u32, Error> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }

    fn done(&self) -> bool { self.at == self.b.len() }
}

/// Reads and checks a bundle: its form, its manifest and its signature. The developer key is
/// whatever key signed it; whether to trust that key is the caller's decision.
pub fn read(bytes: &[u8]) -> Result<Bundle<'_>, Error> { read_checked(bytes, true) }

/// Reads a bundle maki checked with `read` when it installed it and has kept in its own
/// storage since: everything but the signature, which is slow on maki and was checked then.
/// Never for a bundle from anywhere else.
pub fn read_stored(bytes: &[u8]) -> Result<Bundle<'_>, Error> { read_checked(bytes, false) }

fn read_checked(bytes: &[u8], verify: bool) -> Result<Bundle<'_>, Error> {
    if bytes.len() > MAX_BUNDLE {
        return Err(Error::TooBig);
    }
    if bytes.len() < 5 || &bytes[..4] != MAGIC {
        return Err(Error::NotABundle);
    }
    if bytes[4] != FORMAT {
        return Err(Error::Format(bytes[4]));
    }
    let mut r = Reader { b: bytes, at: 5 };
    let manifest_bytes = read_section(&mut r, SECTION_MANIFEST)?;
    let code = read_section(&mut r, SECTION_CODE)?;
    let mut icon = None;
    if r.b.get(r.at) == Some(&SECTION_ICON) {
        let raw = read_section(&mut r, SECTION_ICON)?;
        if raw.len() != ICON_WORDS * 4 {
            return Err(Error::Icon);
        }
        let mut words = [0u32; ICON_WORDS];
        for (w, c) in words.iter_mut().zip(raw.chunks_exact(4)) {
            *w = u32::from_le_bytes(c.try_into().unwrap());
        }
        icon = Some(words);
    }
    let signed_len = r.at;
    let sig = read_section(&mut r, SECTION_SIGNATURE)?;
    let developer_signed = r.at;
    let stamp =
        if r.b.get(r.at) == Some(&SECTION_STAMP) { Some(read_section(&mut r, SECTION_STAMP)?) } else { None };
    if sig.len() != SIGNATURE_LEN || !r.done() {
        return Err(Error::Sections);
    }
    let developer: [u8; 32] = sig[..32].try_into().unwrap();
    let signature: [u8; 64] = sig[32..].try_into().unwrap();
    if verify {
        let key = VerifyingKey::from_bytes(&developer).map_err(|_| Error::Signature)?;
        key.verify_strict(&message(&bytes[..signed_len]), &Signature::from_bytes(&signature))
            .map_err(|_| Error::Signature)?;
    }

    // the signature is good, but the developer may still have written nonsense
    let manifest = manifest(manifest_bytes)?;
    if code.is_empty() {
        return Err(Error::Sections);
    }
    Ok(Bundle {
        manifest,
        code,
        icon,
        developer,
        hash: Sha256::digest(&bytes[..developer_signed]).into(),
        stamp,
    })
}

fn read_section<'a>(r: &mut Reader<'a>, tag: u8) -> Result<&'a [u8], Error> {
    if r.u8()? != tag {
        return Err(Error::Sections);
    }
    let len = r.u32()? as usize;
    r.take(len)
}

/// What the developer signs: the domain, then the hash of the bundle up to the signature.
fn message(signed: &[u8]) -> [u8; DOMAIN.len() + 32] {
    let mut m = [0u8; DOMAIN.len() + 32];
    m[..DOMAIN.len()].copy_from_slice(DOMAIN);
    m[DOMAIN.len()..].copy_from_slice(&Sha256::digest(signed));
    m
}

fn text(v: &[u8], max: usize, what: &'static str) -> Result<String, Error> {
    let s = core::str::from_utf8(v).map_err(|_| Error::Manifest(what))?;
    if s.len() > max || s.chars().any(|c| c.is_control()) {
        return Err(Error::Manifest(what));
    }
    Ok(String::from(s))
}

fn int<const N: usize>(v: &[u8], what: &'static str) -> Result<[u8; N], Error> {
    v.try_into().map_err(|_| Error::Manifest(what))
}

/// Reverse-DNS: lower-case letters, digits, hyphens and dots, at least one dot, no empty part.
pub fn id_ok(id: &str) -> bool {
    id.len() >= 3
        && id.len() <= MAX_ID
        && id.contains('.')
        && id.split('.').all(|part| {
            !part.is_empty()
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn manifest(b: &[u8]) -> Result<Manifest, Error> {
    let mut r = Reader { b, at: 0 };
    let mut last = 0u8;
    let (mut id, mut name, mut version, mut kind, mut storage, mut memory, mut backup) =
        (None, None, None, None, None, None, None);
    let (mut label, mut api, mut firmware, mut description) =
        (String::new(), 0u16, String::new(), String::new());
    let mut wallet: Option<Wallet> = None;
    let mut permissions: Vec<(Permission, String)> = Vec::new();
    while !r.done() {
        let tag = r.u8()?;
        let len = r.u16()? as usize;
        let v = r.take(len)?;
        if tag < last || (tag == last && tag != FIELD_PERMISSION) {
            return Err(Error::Manifest("fields out of order or repeated"));
        }
        last = tag;
        match tag {
            FIELD_ID => {
                let s = text(v, MAX_ID, "id")?;
                if !id_ok(&s) {
                    return Err(Error::Manifest("id"));
                }
                id = Some(s);
            }
            FIELD_NAME => {
                let s = text(v, MAX_NAME, "name")?;
                if s.trim().is_empty() || s.trim() != s {
                    return Err(Error::Manifest("name"));
                }
                name = Some(s);
            }
            FIELD_VERSION => {
                let n = u32::from_le_bytes(int(v, "version")?);
                if n == 0 {
                    return Err(Error::Manifest("version"));
                }
                version = Some(n);
            }
            FIELD_LABEL => label = text(v, MAX_LABEL, "label")?,
            FIELD_KIND => {
                kind = Some(match int::<1>(v, "kind")?[0] {
                    1 => Kind::Wasm,
                    2 => Kind::Native,
                    _ => return Err(Error::Manifest("kind")),
                })
            }
            FIELD_API => {
                api = u16::from_le_bytes(int(v, "api")?);
                if api == 0 {
                    return Err(Error::Manifest("api"));
                }
            }
            FIELD_FIRMWARE => {
                firmware = text(v, MAX_FIRMWARE, "firmware")?;
                if firmware.is_empty() {
                    return Err(Error::Manifest("firmware"));
                }
            }
            FIELD_PERMISSION => {
                let (&which, reason) = v.split_first().ok_or(Error::Manifest("permission"))?;
                let p = Permission::from_u8(which)
                    .ok_or(Error::Manifest("a permission this maki doesn't know"))?;
                if permissions.last().is_some_and(|(q, _)| *q >= p) {
                    return Err(Error::Manifest("permissions out of order or repeated"));
                }
                permissions.push((p, text(reason, MAX_REASON, "permission reason")?));
            }
            FIELD_STORAGE => {
                let n = u32::from_le_bytes(int(v, "storage")?);
                if n > MAX_STORAGE_KIB {
                    return Err(Error::Manifest("storage"));
                }
                storage = Some(n);
            }
            FIELD_MEMORY => {
                let n = u32::from_le_bytes(int(v, "memory")?);
                if n == 0 || n > MAX_MEMORY_KIB {
                    return Err(Error::Manifest("memory"));
                }
                memory = Some(n);
            }
            FIELD_BACKUP => {
                backup = Some(match int::<1>(v, "backup")?[0] {
                    0 => false,
                    1 => true,
                    _ => return Err(Error::Manifest("backup")),
                })
            }
            FIELD_DESCRIPTION => description = text(v, MAX_DESCRIPTION, "description")?,
            FIELD_WALLET => wallet = Some(wallet_field(v)?),
            _ => return Err(Error::Manifest("a field this maki doesn't know")),
        }
    }
    let kind = kind.ok_or(Error::Manifest("no kind"))?;
    // paths go with the wallet permission, and only with it
    if wallet.is_some() != permissions.iter().any(|(p, _)| *p == Permission::Wallet) {
        return Err(Error::Manifest("wallet paths without the wallet permission, or the other way round"));
    }
    match kind {
        Kind::Wasm if api == 0 || !firmware.is_empty() => return Err(Error::Manifest("api")),
        Kind::Native if api != 0 || firmware.is_empty() => return Err(Error::Manifest("firmware")),
        _ => {}
    }
    Ok(Manifest {
        id: id.ok_or(Error::Manifest("no id"))?,
        name: name.ok_or(Error::Manifest("no name"))?,
        version: version.ok_or(Error::Manifest("no version"))?,
        label,
        kind,
        api,
        firmware,
        permissions,
        storage_kib: storage.ok_or(Error::Manifest("no storage"))?,
        memory_kib: memory.ok_or(Error::Manifest("no memory"))?,
        backup: backup.ok_or(Error::Manifest("no backup"))?,
        description,
        wallet,
    })
}

/// The wallet field: a curve maki knows, and 1 to `MAX_WALLET_PATHS` paths, each a purpose and a
/// coin type at least (both hardened), none repeated.
fn wallet_field(v: &[u8]) -> Result<Wallet, Error> {
    let bad = || Error::Manifest("wallet paths");
    let mut r = Reader { b: v, at: 0 };
    let curve = match r.u8()? {
        1 => Curve::Secp256k1,
        2 => Curve::Ed25519,
        _ => return Err(Error::Manifest("a wallet curve this maki doesn't know")),
    };
    let n = r.u8()? as usize;
    if n == 0 || n > MAX_WALLET_PATHS {
        return Err(bad());
    }
    let mut paths: Vec<Vec<u32>> = Vec::with_capacity(n);
    for _ in 0..n {
        let depth = r.u8()? as usize;
        let mut path = Vec::with_capacity(depth);
        for _ in 0..depth {
            path.push(u32::from_le_bytes(r.take(4)?.try_into().unwrap()));
        }
        if !maki_hd::prefix_ok(&path) || paths.contains(&path) {
            return Err(bad());
        }
        paths.push(path);
    }
    if !r.done() {
        return Err(bad());
    }
    Ok(Wallet { curve, paths })
}

fn field(out: &mut Vec<u8>, tag: u8, v: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&(v.len() as u16).to_le_bytes());
    out.extend_from_slice(v);
}

/// A manifest as bundles carry it. Doesn't check it: `write` does, by reading back.
pub fn encode_manifest(m: &Manifest) -> Vec<u8> {
    let mut out = Vec::new();
    field(&mut out, FIELD_ID, m.id.as_bytes());
    field(&mut out, FIELD_NAME, m.name.as_bytes());
    field(&mut out, FIELD_VERSION, &m.version.to_le_bytes());
    if !m.label.is_empty() {
        field(&mut out, FIELD_LABEL, m.label.as_bytes());
    }
    field(&mut out, FIELD_KIND, &[m.kind as u8]);
    if m.kind == Kind::Wasm {
        field(&mut out, FIELD_API, &m.api.to_le_bytes());
    } else {
        field(&mut out, FIELD_FIRMWARE, m.firmware.as_bytes());
    }
    for (p, reason) in &m.permissions {
        let mut v = Vec::with_capacity(1 + reason.len());
        v.push(*p as u8);
        v.extend_from_slice(reason.as_bytes());
        field(&mut out, FIELD_PERMISSION, &v);
    }
    field(&mut out, FIELD_STORAGE, &m.storage_kib.to_le_bytes());
    field(&mut out, FIELD_MEMORY, &m.memory_kib.to_le_bytes());
    field(&mut out, FIELD_BACKUP, &[m.backup as u8]);
    if !m.description.is_empty() {
        field(&mut out, FIELD_DESCRIPTION, m.description.as_bytes());
    }
    if let Some(w) = &m.wallet {
        let mut v = alloc::vec![w.curve as u8, w.paths.len() as u8];
        for p in &w.paths {
            v.push(p.len() as u8);
            for i in p {
                v.extend_from_slice(&i.to_le_bytes());
            }
        }
        field(&mut out, FIELD_WALLET, &v);
    }
    out
}

fn section(out: &mut Vec<u8>, tag: u8, v: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&(v.len() as u32).to_le_bytes());
    out.extend_from_slice(v);
}

/// A bundle as its developer signed it, with the store's stamp added (replacing any it had).
pub fn with_stamp(bundle: &[u8], stamp: &[u8]) -> Result<Vec<u8>, Error> {
    let b = read(bundle)?;
    let signed = bundle.len() - b.stamp.map(|s| s.len() + 5).unwrap_or(0);
    let mut out = bundle[..signed].to_vec();
    section(&mut out, SECTION_STAMP, stamp);
    if out.len() > MAX_BUNDLE {
        return Err(Error::TooBig);
    }
    Ok(out)
}

/// Packs and signs a bundle, then reads it back, so what it returns is what maki accepts.
pub fn write(
    m: &Manifest,
    code: &[u8],
    icon: Option<&[u32; ICON_WORDS]>,
    key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(FORMAT);
    section(&mut out, SECTION_MANIFEST, &encode_manifest(m));
    section(&mut out, SECTION_CODE, code);
    if let Some(icon) = icon {
        let raw: Vec<u8> = icon.iter().flat_map(|w| w.to_le_bytes()).collect();
        section(&mut out, SECTION_ICON, &raw);
    }
    let signature = key.sign(&message(&out));
    let mut sig = Vec::with_capacity(SIGNATURE_LEN);
    sig.extend_from_slice(key.verifying_key().as_bytes());
    sig.extend_from_slice(&signature.to_bytes());
    section(&mut out, SECTION_SIGNATURE, &sig);
    let back = read(&out)?;
    if &back.manifest != m {
        return Err(Error::Manifest("doesn't survive being read back"));
    }
    Ok(out)
}

/// Whether `new` may replace an installed app that `developer` signed at `version`: only its
/// developer can update an app, and only forwards. Why not, if not.
pub fn may_update(developer: &[u8; 32], version: u32, new: &Bundle) -> Result<(), String> {
    if &new.developer != developer {
        return Err(String::from(
            "an app with this ID from a different developer is installed: remove it first",
        ));
    }
    if new.manifest.version <= version {
        return Err(alloc::format!("version {} is installed, and this is {}", version, new.manifest.version));
    }
    Ok(())
}

/// A developer key as people compare it: the first 12 bytes of its SHA-256, in six groups
/// of four hex digits.
pub fn fingerprint(key: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hash = Sha256::digest(key);
    let mut s = String::with_capacity(29);
    for (i, b) in hash[..12].iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            s.push(' ');
        }
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}
