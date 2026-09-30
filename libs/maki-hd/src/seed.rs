//! The keys themselves, from a BIP39 seed (BIP32 on secp256k1, and SLIP-10 on Ed25519): maki-keys',
//! the fake maki's, the simulator's and tests'. Every signature is checked before it's returned:
//! one a fault spoiled can give the key away.

use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use ed25519_dalek::{Signer, Verifier};
use hmac::{Hmac, Mac};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, PublicKey, Scalar, SecretKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use crate::{Error, HARDENED, Keys, MAX_DEPTH, Public, Tweak, op};

/// How many derived keys `SeedKeys` keeps: a wallet's accounts and their chains, so a key under
/// one costs a single step rather than the whole path from the master key.
const KEEP: usize = 8;
/// Keys this deep or shallower are kept: accounts (3) and chains (4), not every address.
const KEEP_DEPTH: usize = 4;

type HmacSha512 = Hmac<Sha512>;

fn hmac512(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

fn hash160(data: &[u8]) -> [u8; 20] { Ripemd160::digest(Sha256::digest(data)).into() }

/// BIP340's tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || data)`.
fn tagged(tag: &str, data: &[u8]) -> [u8; 32] {
    let t = Sha256::digest(tag.as_bytes());
    Sha256::new().chain_update(t).chain_update(t).chain_update(data).finalize().into()
}

fn compressed(key: &PublicKey) -> [u8; 33] {
    let mut out = [0u8; 33];
    out.copy_from_slice(key.to_encoded_point(true).as_bytes());
    out
}

/// An extended private key (BIP32).
#[derive(Clone)]
struct Xpriv {
    parent_fingerprint: [u8; 4],
    chain_code: [u8; 32],
    key: SecretKey,
    /// compressed; made once, since a curve multiplication is what costs on maki's core
    public: [u8; 33],
}

impl Xpriv {
    fn master(seed: &[u8]) -> Result<Xpriv, Error> {
        let mut i = hmac512(b"Bitcoin seed", &[seed]);
        let key = SecretKey::from_slice(&i[..32]).map_err(|_| Error::Key);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        i.zeroize();
        let key = key?;
        let public = compressed(&key.public_key());
        Ok(Xpriv { parent_fingerprint: [0; 4], chain_code, key, public })
    }

    fn fingerprint(&self) -> [u8; 4] {
        let h = hash160(&self.public);
        [h[0], h[1], h[2], h[3]]
    }

    /// The child at `index` (at or above `HARDENED` for a hardened one). A key outside the
    /// curve's order, which BIP32 says to skip, is refused: the odds are below 2^-127.
    fn child(&self, index: u32) -> Result<Xpriv, Error> {
        let mut secret = self.key.to_bytes();
        let mut i = if index >= HARDENED {
            hmac512(&self.chain_code, &[&[0u8], &secret, &index.to_be_bytes()])
        } else {
            hmac512(&self.chain_code, &[&self.public, &index.to_be_bytes()])
        };
        secret.zeroize();
        let mut il = [0u8; 32];
        il.copy_from_slice(&i[..32]);
        let tweak: Option<Scalar> = Scalar::from_repr(il.into()).into();
        il.zeroize();
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        i.zeroize();
        let tweak = tweak.ok_or(Error::Key)?;
        let mut child = (tweak + *self.key.to_nonzero_scalar()).to_bytes();
        let key = SecretKey::from_bytes(&child).map_err(|_| Error::Key);
        child.zeroize();
        let key = key?;
        let public = compressed(&key.public_key());
        Ok(Xpriv { parent_fingerprint: self.fingerprint(), chain_code, key, public })
    }
}

/// BIP86's tweak for an internal key with no script tree: `H_TapTweak(P)`.
fn tap_tweak(internal: &[u8; 32]) -> Result<Scalar, Error> {
    Option::from(Scalar::from_repr(tagged("TapTweak", internal).into())).ok_or(Error::Key)
}

fn x_only(public: &[u8; 33]) -> [u8; 32] { public[1..].try_into().unwrap() }

/// The output key (x only) an internal key makes with no scripts (BIP86): the key with its y
/// even, plus the tweak times G.
fn taproot_output_of(public: &[u8; 33]) -> Result<[u8; 32], Error> {
    let internal = x_only(public);
    let mut even = [0x02u8; 33];
    even[1..].copy_from_slice(&internal);
    let p = PublicKey::from_sec1_bytes(&even).map_err(|_| Error::Key)?;
    let q = (ProjectivePoint::from(*p.as_affine()) + ProjectivePoint::GENERATOR * tap_tweak(&internal)?)
        .to_affine();
    let q = PublicKey::from_affine(q).map_err(|_| Error::Key)?;
    Ok(x_only(&compressed(&q)))
}

fn ecdsa(key: &SecretKey, digest: &[u8; 32]) -> Result<([u8; 64], u8), Error> {
    let signer = SigningKey::from(key);
    let (mut sig, mut recid): (Signature, RecoveryId) =
        signer.sign_prehash_recoverable(digest).map_err(|_| Error::Key)?;
    if let Some(low) = sig.normalize_s() {
        // the other s is the same point's other y
        sig = low;
        recid = RecoveryId::new(!recid.is_y_odd(), recid.is_x_reduced());
    }
    signer.verifying_key().verify_prehash(digest, &sig).map_err(|_| Error::Key)?;
    // and the recovery ID gives this key back, as a verifier using it will need
    let recovered =
        k256::ecdsa::VerifyingKey::recover_from_prehash(digest, &sig, recid).map_err(|_| Error::Key)?;
    if recovered != *signer.verifying_key() {
        return Err(Error::Key);
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig.to_bytes());
    Ok((out, recid.to_byte()))
}

fn schnorr(key: &SecretKey, digest: &[u8; 32], tweak: Tweak, aux: &[u8; 32]) -> Result<[u8; 64], Error> {
    let signer = match tweak {
        Tweak::None => k256::schnorr::SigningKey::from(key.clone()),
        Tweak::Taproot => {
            // the secret, negated if its point's y is odd, plus the tweak; the Schnorr key then
            // takes its own point's y even, as BIP340 has it
            let public = compressed(&key.public_key());
            let mut d = *key.to_nonzero_scalar();
            if public[0] == 0x03 {
                d = -d;
            }
            let mut bytes = (d + tap_tweak(&x_only(&public))?).to_bytes();
            let signer = k256::schnorr::SigningKey::from_bytes(&bytes).map_err(|_| Error::Key);
            bytes.zeroize();
            signer?
        }
    };
    let sig = signer.sign_raw(digest, aux).map_err(|_| Error::Key)?;
    signer.verifying_key().verify_raw(digest, &sig).map_err(|_| Error::Key)?;
    Ok(sig.to_bytes())
}

/// An Ed25519 key by SLIP-10: the key (an RFC 8032 secret key) and its chain code. Its children
/// are hardened only; there are no others for Ed25519.
struct Slip10 {
    key: [u8; 32],
    chain_code: [u8; 32],
}

impl Drop for Slip10 {
    fn drop(&mut self) {
        self.key.zeroize();
        self.chain_code.zeroize();
    }
}

impl Slip10 {
    fn from_hmac(mut i: [u8; 64]) -> Slip10 {
        let mut k = Slip10 { key: [0; 32], chain_code: [0; 32] };
        k.key.copy_from_slice(&i[..32]);
        k.chain_code.copy_from_slice(&i[32..]);
        i.zeroize();
        k
    }

    fn master(seed: &[u8]) -> Slip10 { Slip10::from_hmac(hmac512(b"ed25519 seed", &[seed])) }

    fn child(&self, index: u32) -> Result<Slip10, Error> {
        if index < HARDENED {
            return Err(Error::Path);
        }
        Ok(Slip10::from_hmac(hmac512(&self.chain_code, &[&[0u8], &self.key, &index.to_be_bytes()])))
    }
}

/// Keys derived before, by path (the most recent last), behind a spin lock: `Keys` are shared
/// between threads, and this is `no_std`. Held only while a path is derived.
struct Kept {
    busy: AtomicBool,
    keys: UnsafeCell<Vec<(Vec<u32>, Xpriv)>>,
}

// SAFETY: `keys` is only reached through `with`, which holds `busy` for the whole of it.
unsafe impl Sync for Kept {}

impl Kept {
    fn with<R>(&self, f: impl FnOnce(&mut Vec<(Vec<u32>, Xpriv)>) -> R) -> R {
        while self.busy.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        // SAFETY: `busy` is ours until it's released below
        let r = f(unsafe { &mut *self.keys.get() });
        self.busy.store(false, Ordering::Release);
        r
    }
}

/// The range proofs' generators, made the first time Monero is spent and kept for the next:
/// making them takes longer than a proof. Behind a spin lock, as `Kept` is.
struct Generators {
    busy: AtomicBool,
    generators: UnsafeCell<maki_xmr::bulletproof::Generators>,
}

// SAFETY: `generators` is only reached through `with`, which holds `busy` for the whole of it.
unsafe impl Sync for Generators {}

impl Generators {
    fn with<R>(&self, f: impl FnOnce(&mut maki_xmr::bulletproof::Generators) -> R) -> R {
        while self.busy.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        // SAFETY: `busy` is ours until it's released below
        let r = f(unsafe { &mut *self.generators.get() });
        self.busy.store(false, Ordering::Release);
        r
    }
}

/// The keys a seed makes.
pub struct SeedKeys {
    master: Xpriv,
    /// SLIP-10's Ed25519 master key: an HMAC of the seed, as BIP32's is, under another name
    ed25519: Slip10,
    kept: Kept,
    generators: Generators,
}

impl SeedKeys {
    pub fn from_seed(seed: &[u8]) -> Result<SeedKeys, Error> {
        Ok(SeedKeys {
            master: Xpriv::master(seed)?,
            ed25519: Slip10::master(seed),
            kept: Kept { busy: AtomicBool::new(false), keys: UnsafeCell::new(Vec::new()) },
            generators: Generators {
                busy: AtomicBool::new(false),
                generators: UnsafeCell::new(maki_xmr::bulletproof::Generators::new()),
            },
        })
    }

    /// The key at `path`, from the deepest key kept on the way to it.
    fn derive(&self, path: &[u32]) -> Result<Xpriv, Error> {
        if path.len() > MAX_DEPTH {
            return Err(Error::Path);
        }
        self.kept.with(|kept| self.derive_from(kept, path))
    }

    fn derive_from(&self, kept: &mut Vec<(Vec<u32>, Xpriv)>, path: &[u32]) -> Result<Xpriv, Error> {
        let (mut key, from) =
            match kept.iter().filter(|(p, _)| crate::under(path, p)).max_by_key(|(p, _)| p.len()) {
                Some((p, k)) => (k.clone(), p.len()),
                None => (self.master.clone(), 0),
            };
        for depth in from..path.len() {
            key = key.child(path[depth])?;
            // the key at path[..=depth], depth + 1 deep
            if depth < KEEP_DEPTH && !kept.iter().any(|(p, _)| p[..] == path[..=depth]) {
                if kept.len() == KEEP {
                    kept.remove(0);
                }
                kept.push((path[..=depth].to_vec(), key.clone()));
            }
        }
        Ok(key)
    }

    /// The Monero keys of the account at `path` (`m/44'/128'/account'/0/0`): Monero's coin type
    /// alone, so no other coin's key is hashed into one.
    fn monero(&self, path: &[u32]) -> Result<maki_xmr::Keys, Error> {
        if path.get(1) != Some(&(HARDENED | 128)) {
            return Err(Error::Path);
        }
        let mut secret: [u8; 32] = self.derive(path)?.key.to_bytes().into();
        let keys = maki_xmr::Keys::from_bip32(&secret);
        secret.zeroize();
        Ok(keys)
    }

    /// The Ed25519 key at `path` (SLIP-10), every step hardened. Each is a single HMAC: nothing
    /// to keep.
    fn ed25519_key(&self, path: &[u32]) -> Result<ed25519_dalek::SigningKey, Error> {
        if path.len() > MAX_DEPTH {
            return Err(Error::Path);
        }
        let mut child: Option<Slip10> = None;
        for &i in path {
            child = Some(child.as_ref().unwrap_or(&self.ed25519).child(i)?);
        }
        Ok(ed25519_dalek::SigningKey::from_bytes(&child.as_ref().unwrap_or(&self.ed25519).key))
    }

    /// The Ed25519 public key at `path` (SLIP-10): a Solana account's address, at
    /// `m/44'/501'/account'/0'`.
    pub fn ed25519_public(&self, path: &[u32]) -> Result<[u8; 32], Error> {
        Ok(self.ed25519_key(path)?.verifying_key().to_bytes())
    }

    /// An Ed25519 signature (RFC 8032) over the whole of `message` with the key at `path`.
    pub fn sign_ed25519(&self, path: &[u32], message: &[u8]) -> Result<[u8; 64], Error> {
        let key = self.ed25519_key(path)?;
        let sig = key.sign(message);
        key.verifying_key().verify(message, &sig).map_err(|_| Error::Key)?;
        Ok(sig.to_bytes())
    }

    /// A BIP340 signature with `aux` as its auxiliary randomness: fresh random bytes, on maki,
    /// so a signature doesn't depend on the key and message alone. (Through `Keys` it's zero,
    /// which BIP340 allows, for signatures tests can compare.)
    pub fn sign_schnorr_with(
        &self,
        path: &[u32],
        digest: &[u8; 32],
        tweak: Tweak,
        aux: &[u8; 32],
    ) -> Result<[u8; 64], Error> {
        schnorr(&self.derive(path)?.key, digest, tweak, aux)
    }
}

impl Keys for SeedKeys {
    fn fingerprint(&self) -> Result<[u8; 4], Error> { Ok(self.master.fingerprint()) }

    fn public(&self, path: &[u32]) -> Result<Public, Error> {
        let k = self.derive(path)?;
        Ok(Public { key: k.public, chain_code: k.chain_code, parent_fingerprint: k.parent_fingerprint })
    }

    fn uncompressed(&self, path: &[u32]) -> Result<[u8; 65], Error> {
        let k = self.derive(path)?;
        let mut out = [0u8; 65];
        out.copy_from_slice(k.key.public_key().to_encoded_point(false).as_bytes());
        Ok(out)
    }

    fn taproot_output(&self, path: &[u32]) -> Result<[u8; 32], Error> {
        taproot_output_of(&self.derive(path)?.public)
    }

    fn sign_ecdsa(&self, path: &[u32], digest: &[u8; 32]) -> Result<([u8; 64], u8), Error> {
        ecdsa(&self.derive(path)?.key, digest)
    }

    fn sign_schnorr(&self, path: &[u32], digest: &[u8; 32], tweak: Tweak) -> Result<[u8; 64], Error> {
        self.sign_schnorr_with(path, digest, tweak, &[0u8; 32])
    }
}

/// One bare private key at every path: for tests with keys other software made. maki's own come
/// from the phrase.
#[derive(Clone)]
pub struct OneKey {
    key: SecretKey,
}

impl OneKey {
    pub fn new(secret: &[u8; 32]) -> Result<OneKey, Error> {
        Ok(OneKey { key: SecretKey::from_slice(secret).map_err(|_| Error::Key)? })
    }
}

impl Keys for OneKey {
    fn fingerprint(&self) -> Result<[u8; 4], Error> {
        let h = hash160(&compressed(&self.key.public_key()));
        Ok([h[0], h[1], h[2], h[3]])
    }

    fn public(&self, _path: &[u32]) -> Result<Public, Error> {
        Ok(Public {
            key: compressed(&self.key.public_key()),
            chain_code: [0; 32],
            parent_fingerprint: [0; 4],
        })
    }

    fn uncompressed(&self, _path: &[u32]) -> Result<[u8; 65], Error> {
        let mut out = [0u8; 65];
        out.copy_from_slice(self.key.public_key().to_encoded_point(false).as_bytes());
        Ok(out)
    }

    fn taproot_output(&self, _path: &[u32]) -> Result<[u8; 32], Error> {
        taproot_output_of(&compressed(&self.key.public_key()))
    }

    fn sign_ecdsa(&self, _path: &[u32], digest: &[u8; 32]) -> Result<([u8; 64], u8), Error> {
        ecdsa(&self.key, digest)
    }

    fn sign_schnorr(&self, _path: &[u32], digest: &[u8; 32], tweak: Tweak) -> Result<[u8; 64], Error> {
        schnorr(&self.key, digest, tweak, &[0u8; 32])
    }
}

/// A numbered request (`crate::op`) on `keys`, as maki-keys answers the app host (and the fake
/// maki and the simulator answer apps): the answer's bytes. `aux` is BIP340's auxiliary
/// randomness for a Schnorr signature. Which paths an app may use is the caller's to check.
pub fn answer(
    keys: &SeedKeys,
    which: u8,
    path: &[u32],
    digest: &[u8],
    aux: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    // what's asked, whole: a Monero output, a transaction to sign, a message for Ed25519
    let asked = digest;
    let indices = || -> Result<(u32, u32), Error> {
        let d: &[u8; 8] = digest.try_into().map_err(|_| Error::Failed)?;
        Ok((u32::from_le_bytes(d[..4].try_into().unwrap()), u32::from_le_bytes(d[4..].try_into().unwrap())))
    };
    let digest = || -> Result<[u8; 32], Error> { digest.try_into().map_err(|_| Error::Failed) };
    Ok(match which {
        op::FINGERPRINT => keys.fingerprint()?.to_vec(),
        op::PUBLIC => {
            let p = keys.public(path)?;
            let mut out = Vec::with_capacity(69);
            out.extend_from_slice(&p.key);
            out.extend_from_slice(&p.chain_code);
            out.extend_from_slice(&p.parent_fingerprint);
            out
        }
        op::UNCOMPRESSED => keys.uncompressed(path)?.to_vec(),
        op::TAPROOT => keys.taproot_output(path)?.to_vec(),
        op::SIGN_ECDSA => {
            let (sig, recid) = keys.sign_ecdsa(path, &digest()?)?;
            let mut out = sig.to_vec();
            out.push(recid);
            out
        }
        op::SIGN_SCHNORR => keys.sign_schnorr_with(path, &digest()?, Tweak::None, aux)?.to_vec(),
        op::SIGN_TAPROOT => keys.sign_schnorr_with(path, &digest()?, Tweak::Taproot, aux)?.to_vec(),
        op::MONERO_PUBLIC => {
            let (spend, view) = keys.monero(path)?.public();
            [spend, view].concat()
        }
        op::MONERO_SUBADDRESS => {
            let (major, minor) = indices()?;
            let (spend, view) = keys.monero(path)?.subaddress(major, minor);
            [spend, view].concat()
        }
        op::MONERO_WORDS => keys.monero(path)?.words().join(" ").into_bytes(),
        op::MONERO_VIEW_KEY => keys.monero(path)?.view_bytes().to_vec(),
        op::MONERO_KEY_IMAGE => {
            let d: &[u8; 80] = asked.try_into().map_err(|_| Error::Failed)?;
            let tx_key = maki_xmr::sign::point(d[..32].try_into().unwrap()).ok_or(Error::Key)?;
            let index = u64::from_le_bytes(d[32..40].try_into().unwrap());
            let (major, minor) = (
                u32::from_le_bytes(d[40..44].try_into().unwrap()),
                u32::from_le_bytes(d[44..48].try_into().unwrap()),
            );
            let key: &[u8; 32] = d[48..].try_into().unwrap();
            let (image, proof) = keys
                .monero(path)?
                .key_image_proof(&tx_key, index, major, minor, key, aux)
                .ok_or(Error::Key)?;
            [&image[..], &proof[..]].concat()
        }
        op::ED25519_PUBLIC => keys.ed25519_public(path)?.to_vec(),
        op::ED25519_SIGN => keys.sign_ed25519(path, asked)?.to_vec(),
        op::MONERO_SIGN => {
            let account = keys.monero(path)?;
            let signed = maki_xmr::request::Request::parse(asked)
                .map_err(|e| alloc::format!("{e}"))
                .and_then(|request| {
                    keys.generators
                        .with(|g| maki_xmr::spend::sign_with(&account, &request, aux, g))
                        .map_err(|e| alloc::format!("{e}"))
                });
            match signed {
                Ok(signed) => [&[0u8][..], &signed.to_bytes()].concat(),
                Err(why) => [&[1u8][..], why.as_bytes()].concat(),
            }
        }
        _ => return Err(Error::Failed),
    })
}
