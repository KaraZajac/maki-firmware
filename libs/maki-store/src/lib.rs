//! The maki store's signed records, and the checks maki makes of them itself (ARCHITECTURE.md,
//! "The store"). maki desktop fetches them and passes them along; it's as untrusted as the rest
//! of the computer, so everything here is checked on maki against keys it already trusts.
//!
//! - The **root** names the root keys (offline, any `threshold` of them sign it) and the **catalogue key**,
//!   which does the everyday signing until it expires. maki starts from the root its firmware carries, and
//!   moves to a newer one only if `threshold` of the old root keys and `threshold` of the new ones signed it.
//! - A **stamp**, from the catalogue key, is what makes a bundle "from the maki store": it names the app's
//!   ID, version, developer key and permissions and the bundle's hash, so it vouches for exactly that bundle.
//!   It travels in the bundle, after the developer's signature (`maki_bundle`, `Bundle::stamp`): a store app
//!   is signed twice.
//! - The **revocation list**, from the catalogue key, names apps, versions and developer keys found to be
//!   bad, with the reason, and expires within weeks; its version only goes up, so an older one can't be
//!   replayed.
//!
//! - The **index** lists the store's apps for maki desktop to show: JSON, signed by the catalogue key with a
//!   detached signature (`sign_index`). maki never reads it: the stamp in each bundle is what it checks.
//!
//! Every record is a magic, a format byte, its fields (little-endian integers, UTF-8 strings
//! after a length byte) and then its signatures, over a domain string and everything before.
//!
//! A store publishes these as files, anywhere maki desktop can fetch them from:
//!
//! ```text
//! roots/1.bin, roots/2.bin, ...   every root, each signed to replace the one before
//! revocations.bin                 the newest revocation list
//! index.json, index.sig           the apps, and the catalogue key's signature over the file
//! apps/ID/VERSION.maki            the stamped bundles the index names
//! ```

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use maki_bundle::{Bundle, Permission};
use sha2::{Digest, Sha256};

/// Most root keys a root names.
pub const MAX_ROOT_KEYS: usize = 8;
/// Most entries a revocation list holds.
pub const MAX_REVOKED: usize = 4096;

const ROOT_MAGIC: &[u8; 8] = b"MAKIROOT";
const STAMP_MAGIC: &[u8; 8] = b"MAKISTMP";
const REVOKED_MAGIC: &[u8; 8] = b"MAKIREVO";
const FORMAT: u8 = 1;

const ROOT_DOMAIN: &[u8] = b"maki store root v1\0";
const STAMP_DOMAIN: &[u8] = b"maki store stamp v1\0";
const REVOKED_DOMAIN: &[u8] = b"maki store revocations v1\0";
const INDEX_DOMAIN: &[u8] = b"maki store index v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not the record it should be, cut short, or with bytes after it.
    Malformed,
    /// A format this maki doesn't read, probably newer.
    Format(u8),
    /// Signed by the wrong keys, not enough of them, or changed since.
    Signature,
    /// Not newer than what maki has.
    Rollback,
    /// The catalogue key has expired, or a revocation list has.
    Expired,
    /// maki's clock isn't verified, and this needs it to be.
    TimeUnverified,
    /// The stamp is for another bundle: which field differs.
    Mismatch(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Malformed => write!(f, "not a store record maki can read"),
            Error::Format(v) => write!(f, "store record format {v}, newer than this maki reads"),
            Error::Signature => write!(f, "not signed by the maki store"),
            Error::Rollback => write!(f, "older than what maki has"),
            Error::Expired => write!(f, "the store's signing key has expired: update maki desktop"),
            Error::TimeUnverified => write!(f, "maki's clock isn't verified: link to maki desktop first"),
            Error::Mismatch(what) => write!(f, "the store's stamp is for another bundle ({what})"),
        }
    }
}

fn signed(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(domain.len() + 32);
    m.extend_from_slice(domain);
    m.extend_from_slice(&Sha256::digest(body));
    m
}

fn verify(key: &[u8; 32], domain: &[u8], body: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(key)
        .and_then(|k| k.verify_strict(&signed(domain, body), &Signature::from_bytes(signature)))
        .is_ok()
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self { Reader { b, at: 0 } }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or(Error::Malformed)?;
        let s = self.b.get(self.at..end).ok_or(Error::Malformed)?;
        self.at = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Error> { Ok(self.take(1)?[0]) }

    fn u16(&mut self) -> Result<u16, Error> { Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap())) }

    fn u32(&mut self) -> Result<u32, Error> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }

    fn u64(&mut self) -> Result<u64, Error> { Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap())) }

    fn key(&mut self) -> Result<[u8; 32], Error> { Ok(self.take(32)?.try_into().unwrap()) }

    fn sig(&mut self) -> Result<[u8; 64], Error> { Ok(self.take(64)?.try_into().unwrap()) }

    fn str8(&mut self) -> Result<String, Error> {
        let n = self.u8()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| Error::Malformed)
    }

    fn header(&mut self, magic: &[u8; 8]) -> Result<(), Error> {
        if self.take(8)? != magic {
            return Err(Error::Malformed);
        }
        match self.u8()? {
            FORMAT => Ok(()),
            v => Err(Error::Format(v)),
        }
    }

    fn end(&self) -> Result<(), Error> {
        if self.at == self.b.len() { Ok(()) } else { Err(Error::Malformed) }
    }
}

fn str8(out: &mut Vec<u8>, s: &str) {
    let s = &s.as_bytes()[..s.len().min(255)];
    out.push(s.len() as u8);
    out.extend_from_slice(s);
}

// ------------------------------------------------------------------------------------------
// The root

/// Who the store is: the root keys, how many of them must sign a root, and the catalogue key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    /// Only goes up.
    pub version: u32,
    pub threshold: u8,
    pub keys: Vec<[u8; 32]>,
    /// Signs stamps and revocation lists.
    pub catalogue: [u8; 32],
    /// Unix seconds: after this, maki takes nothing new the catalogue key signed.
    pub catalogue_expires: u64,
}

/// A root with its signatures, each with the root key that made it. A root is signed by its own
/// keys, and, to replace another, by that one's too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRoot {
    pub root: Root,
    /// (the signing key itself, the signature)
    pub signatures: Vec<([u8; 32], [u8; 64])>,
}

impl Root {
    fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.keys.len() * 32);
        out.extend_from_slice(ROOT_MAGIC);
        out.push(FORMAT);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(self.threshold);
        out.push(self.keys.len() as u8);
        for k in &self.keys {
            out.extend_from_slice(k);
        }
        out.extend_from_slice(&self.catalogue);
        out.extend_from_slice(&self.catalogue_expires.to_le_bytes());
        out
    }

    /// A threshold that can be met, and no key twice.
    fn sane(&self) -> bool {
        let n = self.keys.len();
        let distinct = self.keys.iter().enumerate().all(|(i, k)| !self.keys[..i].contains(k));
        self.threshold >= 1 && (self.threshold as usize) <= n && n <= MAX_ROOT_KEYS && distinct
    }

    /// How many of this root's keys signed `body` among `signatures`, each counted once.
    fn signers(&self, body: &[u8], signatures: &[([u8; 32], [u8; 64])]) -> usize {
        self.keys
            .iter()
            .filter(|k| signatures.iter().any(|(key, sig)| key == *k && verify(key, ROOT_DOMAIN, body, sig)))
            .count()
    }

    /// Whether the catalogue key may still sign, `now` being verified unix seconds.
    pub fn catalogue_current(&self, now: Option<u64>) -> Result<(), Error> {
        match now {
            None => Err(Error::TimeUnverified),
            Some(t) if t >= self.catalogue_expires => Err(Error::Expired),
            Some(_) => Ok(()),
        }
    }
}

impl SignedRoot {
    /// Signs `root` with each of `keys` (root keys: its own, and to replace another, that one's).
    pub fn sign(root: Root, keys: &[&SigningKey]) -> SignedRoot {
        let body = root.body();
        let signatures = keys
            .iter()
            .map(|k| (k.verifying_key().to_bytes(), k.sign(&signed(ROOT_DOMAIN, &body)).to_bytes()))
            .collect();
        SignedRoot { root, signatures }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.root.body();
        out.push(self.signatures.len() as u8);
        for (key, sig) in &self.signatures {
            out.extend_from_slice(key);
            out.extend_from_slice(sig);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<SignedRoot, Error> {
        let mut r = Reader::new(bytes);
        r.header(ROOT_MAGIC)?;
        let version = r.u32()?;
        let threshold = r.u8()?;
        let n = r.u8()? as usize;
        if n > MAX_ROOT_KEYS {
            return Err(Error::Malformed);
        }
        let keys = (0..n).map(|_| r.key()).collect::<Result<Vec<_>, _>>()?;
        let catalogue = r.key()?;
        let catalogue_expires = r.u64()?;
        let sigs = r.u8()? as usize;
        if sigs > 2 * MAX_ROOT_KEYS {
            return Err(Error::Malformed);
        }
        let signatures = (0..sigs).map(|_| Ok((r.key()?, r.sig()?))).collect::<Result<Vec<_>, Error>>()?;
        r.end()?;
        Ok(SignedRoot { root: Root { version, threshold, keys, catalogue, catalogue_expires }, signatures })
    }

    /// The first root maki trusts (its firmware's): sane, and signed by `threshold` of its own
    /// keys.
    pub fn trust_first(&self) -> Result<&Root, Error> {
        if !self.root.sane() {
            return Err(Error::Malformed);
        }
        if self.root.signers(&self.root.body(), &self.signatures) < self.root.threshold as usize {
            return Err(Error::Signature);
        }
        Ok(&self.root)
    }

    /// Whether this root may replace `current`: newer, sane, and signed by `threshold` of the
    /// current root's keys and `threshold` of its own.
    pub fn replaces(&self, current: &Root) -> Result<&Root, Error> {
        if self.root.version <= current.version {
            return Err(Error::Rollback);
        }
        self.trust_first()?;
        if current.signers(&self.root.body(), &self.signatures) < current.threshold as usize {
            return Err(Error::Signature);
        }
        Ok(&self.root)
    }
}

// ------------------------------------------------------------------------------------------
// Stamps

/// The store's word for one bundle: reviewed, and built from its source by the store's CI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub id: String,
    pub version: u32,
    /// The bundle's hash as its developer signed it (`Bundle::hash`).
    pub bundle: [u8; 32],
    pub developer: [u8; 32],
    /// What it asks for, as its manifest says: the review covered exactly these.
    pub permissions: Vec<Permission>,
    /// Unix seconds.
    pub issued: u64,
}

/// A stamp with the catalogue key's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedStamp {
    pub stamp: Stamp,
    pub signature: [u8; 64],
}

impl Stamp {
    fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.id.len());
        out.extend_from_slice(STAMP_MAGIC);
        out.push(FORMAT);
        str8(&mut out, &self.id);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.bundle);
        out.extend_from_slice(&self.developer);
        out.push(self.permissions.len() as u8);
        out.extend(self.permissions.iter().map(|p| *p as u8));
        out.extend_from_slice(&self.issued.to_le_bytes());
        out
    }

    /// The stamp for `bundle`, as its developer signed it.
    pub fn of(bundle: &Bundle, issued: u64) -> Stamp {
        let m = &bundle.manifest;
        Stamp {
            id: m.id.clone(),
            version: m.version,
            bundle: bundle.hash,
            developer: bundle.developer,
            permissions: m.permissions.iter().map(|(p, _)| *p).collect(),
            issued,
        }
    }

    /// Whether this stamp is for `bundle`: every field it names.
    pub fn matches(&self, bundle: &Bundle) -> Result<(), Error> {
        let m = &bundle.manifest;
        let mut asked: Vec<u8> = m.permissions.iter().map(|(p, _)| *p as u8).collect();
        let mut stamped: Vec<u8> = self.permissions.iter().map(|p| *p as u8).collect();
        asked.sort_unstable();
        stamped.sort_unstable();
        if self.id != m.id {
            Err(Error::Mismatch("ID"))
        } else if self.version != m.version {
            Err(Error::Mismatch("version"))
        } else if self.developer != bundle.developer {
            Err(Error::Mismatch("developer"))
        } else if asked != stamped {
            Err(Error::Mismatch("permissions"))
        } else if self.bundle != bundle.hash {
            Err(Error::Mismatch("contents"))
        } else {
            Ok(())
        }
    }
}

impl SignedStamp {
    pub fn sign(stamp: Stamp, catalogue: &SigningKey) -> SignedStamp {
        let signature = catalogue.sign(&signed(STAMP_DOMAIN, &stamp.body())).to_bytes();
        SignedStamp { stamp, signature }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.stamp.body();
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<SignedStamp, Error> {
        let mut r = Reader::new(bytes);
        r.header(STAMP_MAGIC)?;
        let id = r.str8()?;
        let version = r.u32()?;
        let bundle = r.key()?;
        let developer = r.key()?;
        let n = r.u8()? as usize;
        let permissions = (0..n)
            .map(|_| r.u8().and_then(|b| Permission::from_u8(b).ok_or(Error::Malformed)))
            .collect::<Result<Vec<_>, _>>()?;
        let issued = r.u64()?;
        let signature = r.sig()?;
        r.end()?;
        Ok(SignedStamp { stamp: Stamp { id, version, bundle, developer, permissions, issued }, signature })
    }

    /// Whether the store stamped `bundle`: the catalogue key of `root` signed this stamp, the
    /// key hasn't expired (`now`: verified unix seconds), and the stamp names this bundle.
    pub fn check(&self, root: &Root, now: Option<u64>, bundle: &Bundle) -> Result<(), Error> {
        if !verify(&root.catalogue, STAMP_DOMAIN, &self.stamp.body(), &self.signature) {
            return Err(Error::Signature);
        }
        root.catalogue_current(now)?;
        self.stamp.matches(bundle)
    }
}

// ------------------------------------------------------------------------------------------
// Revocations

/// What the store says not to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Revoked {
    /// Every version of the app with this ID.
    App(String),
    /// This version of it and every one before.
    UpTo(String, u32),
    /// Everything this developer key signed, from the store or sideloaded.
    Developer([u8; 32]),
}

impl Revoked {
    fn covers(&self, id: &str, version: u32, developer: &[u8; 32]) -> bool {
        match self {
            Revoked::App(a) => a == id,
            Revoked::UpTo(a, v) => a == id && version <= *v,
            Revoked::Developer(d) => d == developer,
        }
    }
}

/// The revocation list: what's revoked, and why, in words for the owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revocations {
    /// Only goes up.
    pub version: u32,
    /// Unix seconds: after this the list is stale (maki keeps using it, and says so).
    pub expires: u64,
    pub entries: Vec<(Revoked, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRevocations {
    pub list: Revocations,
    pub signature: [u8; 64],
}

impl Revocations {
    fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(REVOKED_MAGIC);
        out.push(FORMAT);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.expires.to_le_bytes());
        out.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for (what, why) in &self.entries {
            match what {
                Revoked::App(id) => {
                    out.push(1);
                    str8(&mut out, id);
                }
                Revoked::UpTo(id, v) => {
                    out.push(2);
                    str8(&mut out, id);
                    out.extend_from_slice(&v.to_le_bytes());
                }
                Revoked::Developer(key) => {
                    out.push(3);
                    out.extend_from_slice(key);
                }
            }
            str8(&mut out, why);
        }
        out
    }

    /// Why the app with this ID, version and developer is revoked, if it is.
    pub fn check(&self, id: &str, version: u32, developer: &[u8; 32]) -> Option<&str> {
        self.entries.iter().find(|(what, _)| what.covers(id, version, developer)).map(|(_, why)| why.as_str())
    }
}

impl SignedRevocations {
    pub fn sign(list: Revocations, catalogue: &SigningKey) -> SignedRevocations {
        let signature = catalogue.sign(&signed(REVOKED_DOMAIN, &list.body())).to_bytes();
        SignedRevocations { list, signature }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.list.body();
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<SignedRevocations, Error> {
        let mut r = Reader::new(bytes);
        r.header(REVOKED_MAGIC)?;
        let version = r.u32()?;
        let expires = r.u64()?;
        let n = r.u16()? as usize;
        if n > MAX_REVOKED {
            return Err(Error::Malformed);
        }
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let what = match r.u8()? {
                1 => Revoked::App(r.str8()?),
                2 => Revoked::UpTo(r.str8()?, r.u32()?),
                3 => Revoked::Developer(r.key()?),
                _ => return Err(Error::Malformed),
            };
            entries.push((what, r.str8()?));
        }
        let signature = r.sig()?;
        r.end()?;
        Ok(SignedRevocations { list: Revocations { version, expires, entries }, signature })
    }

    /// Whether maki takes this list in place of `current`: signed by `root`'s catalogue key
    /// while that's current (`now`: verified unix seconds), and newer than `current`, unless an
    /// earlier root's catalogue key signed that one. A new root's key replaces what the old one
    /// signed whatever its version, so a stolen catalogue key can't block every list after it
    /// with a huge version. (An expired list is still better than an older one: maki takes it
    /// and says it's stale.)
    pub fn replaces(
        &self,
        root: &Root,
        now: Option<u64>,
        current: Option<&SignedRevocations>,
    ) -> Result<&Revocations, Error> {
        if !self.signed_by(root) {
            return Err(Error::Signature);
        }
        root.catalogue_current(now)?;
        if current.is_some_and(|c| c.signed_by(root) && self.list.version <= c.list.version) {
            return Err(Error::Rollback);
        }
        Ok(&self.list)
    }

    fn signed_by(&self, root: &Root) -> bool {
        verify(&root.catalogue, REVOKED_DOMAIN, &self.list.body(), &self.signature)
    }
}

// ------------------------------------------------------------------------------------------
// The index

/// The catalogue key's signature over an index file, exactly as published.
pub fn sign_index(index: &[u8], catalogue: &SigningKey) -> [u8; 64] {
    catalogue.sign(&signed(INDEX_DOMAIN, index)).to_bytes()
}

/// Whether `root`'s catalogue key signed this index file.
pub fn index_signed(root: &Root, index: &[u8], signature: &[u8; 64]) -> bool {
    verify(&root.catalogue, INDEX_DOMAIN, index, signature)
}
