//! The keys themselves, from a BIP39 seed (BIP32 on secp256k1, and SLIP-10 on Ed25519), and
//! Cardano's from the phrase's entropy (BIP32-Ed25519, Icarus): maki-keys', the fake maki's, the
//! simulator's and tests'. Every signature is checked before it's returned: one a fault spoiled
//! can give the key away.

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

/// A Cardano key: BIP32-Ed25519 (Khovratovich and Law's, the "V2" scheme Cardano's wallets use),
/// an extended Ed25519 key (`kl`, the scalar, clamped as RFC 8032's are, and `kr`, which makes
/// each signature's nonce) with a chain code. Its master key is Icarus's (CIP-3): PBKDF2 over the
/// phrase's entropy, not BIP39's seed. Unlike SLIP-10's, its children needn't be hardened: an
/// account's public key and chain code give every address under it.
struct Icarus {
    kl: [u8; 32],
    kr: [u8; 32],
    chain_code: [u8; 32],
}

impl Drop for Icarus {
    fn drop(&mut self) {
        self.kl.zeroize();
        self.kr.zeroize();
        self.chain_code.zeroize();
    }
}

impl Icarus {
    /// Icarus's master key (CIP-3): 96 bytes of PBKDF2-HMAC-SHA512, 4096 rounds, the phrase's
    /// entropy the salt and its passphrase (none, on maki) the password; the scalar clamped.
    fn master(entropy: &[u8]) -> Icarus {
        let mut out = [0u8; 96];
        pbkdf2::pbkdf2_hmac::<Sha512>(b"", entropy, 4096, &mut out);
        out[0] &= 0b1111_1000;
        out[31] &= 0b0001_1111;
        out[31] |= 0b0100_0000;
        let key = Icarus::from_parts(&out);
        out.zeroize();
        key
    }

    fn from_parts(b: &[u8; 96]) -> Icarus {
        let mut k = Icarus { kl: [0; 32], kr: [0; 32], chain_code: [0; 32] };
        k.kl.copy_from_slice(&b[..32]);
        k.kr.copy_from_slice(&b[32..64]);
        k.chain_code.copy_from_slice(&b[64..]);
        k
    }

    fn scalar(&self) -> curve25519_dalek::Scalar { curve25519_dalek::Scalar::from_bytes_mod_order(self.kl) }

    /// Its public key: the scalar times the base point (the scalar's full value; the point has
    /// the group's order, so it's the same reduced).
    fn public(&self) -> [u8; 32] {
        curve25519_dalek::EdwardsPoint::mul_base(&self.scalar()).compress().to_bytes()
    }

    /// The child at `index` (hardened at or above `HARDENED`), V2's way: the scalar gains eight
    /// times the first 28 bytes of an HMAC, the nonce key the last 32, as little-endian numbers.
    fn child(&self, index: u32) -> Icarus {
        let le = index.to_le_bytes();
        let (mut z, mut i) = if index >= HARDENED {
            (
                hmac512(&self.chain_code, &[&[0x00], &self.kl, &self.kr, &le]),
                hmac512(&self.chain_code, &[&[0x01], &self.kl, &self.kr, &le]),
            )
        } else {
            let a = self.public();
            (hmac512(&self.chain_code, &[&[0x02], &a, &le]), hmac512(&self.chain_code, &[&[0x03], &a, &le]))
        };
        let mut child = Icarus { kl: [0; 32], kr: [0; 32], chain_code: [0; 32] };
        // kl + 8 * zl, zl the first 28 bytes
        let mut carry = 0u16;
        for n in 0..32 {
            let add = if n < 28 { (z[n] as u16) << 3 } else { 0 };
            let sum = self.kl[n] as u16 + add + carry;
            child.kl[n] = sum as u8;
            carry = sum >> 8;
        }
        // kr + zr, mod 2^256
        let mut carry = 0u16;
        for n in 0..32 {
            let sum = self.kr[n] as u16 + z[32 + n] as u16 + carry;
            child.kr[n] = sum as u8;
            carry = sum >> 8;
        }
        child.chain_code.copy_from_slice(&i[32..]);
        z.zeroize();
        i.zeroize();
        child
    }

    /// An Ed25519 signature with the extended key (RFC 8032's, but for where the key comes from):
    /// the nonce from `kr` and the message, then S = r + H(R, A, M) times the scalar.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        use curve25519_dalek::{EdwardsPoint, Scalar};
        let a = self.public();
        let mut nonce: [u8; 64] = Sha512::new().chain_update(self.kr).chain_update(message).finalize().into();
        let r = Scalar::from_bytes_mod_order_wide(&nonce);
        nonce.zeroize();
        let big_r = EdwardsPoint::mul_base(&r).compress().to_bytes();
        let h: [u8; 64] =
            Sha512::new().chain_update(big_r).chain_update(a).chain_update(message).finalize().into();
        let s = r + Scalar::from_bytes_mod_order_wide(&h) * self.scalar();
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&big_r);
        sig[32..].copy_from_slice(s.as_bytes());
        // checked as any Ed25519 signature is, against the public key
        let key = ed25519_dalek::VerifyingKey::from_bytes(&a).map_err(|_| Error::Key)?;
        key.verify(message, &ed25519_dalek::Signature::from_bytes(&sig)).map_err(|_| Error::Key)?;
        Ok(sig)
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
    /// Cardano's master key, from the phrase's entropy rather than its seed: made the first time
    /// Cardano is asked for (`with_cardano`), since its PBKDF2 is twice the seed's
    cardano: Option<Icarus>,
    kept: Kept,
    generators: Generators,
}

impl SeedKeys {
    pub fn from_seed(seed: &[u8]) -> Result<SeedKeys, Error> {
        Ok(SeedKeys {
            master: Xpriv::master(seed)?,
            ed25519: Slip10::master(seed),
            cardano: None,
            kept: Kept { busy: AtomicBool::new(false), keys: UnsafeCell::new(Vec::new()) },
            generators: Generators {
                busy: AtomicBool::new(false),
                generators: UnsafeCell::new(maki_xmr::bulletproof::Generators::new()),
            },
        })
    }

    /// Cardano's keys too, from the phrase's entropy (the same phrase as the seed's: the caller's
    /// to see to). Until then `op::CARDANO_*` are `Error::Locked`.
    pub fn with_cardano(&mut self, entropy: &[u8]) { self.cardano = Some(Icarus::master(entropy)); }

    /// Whether Cardano's keys are made yet.
    pub fn has_cardano(&self) -> bool { self.cardano.is_some() }

    /// The Cardano key at `path`, under `m/1852'/1815'/account'` alone.
    fn cardano_key(&self, path: &[u32]) -> Result<Icarus, Error> {
        if path.len() > MAX_DEPTH || !crate::cardano_path(path) {
            return Err(Error::Path);
        }
        let master = self.cardano.as_ref().ok_or(Error::Locked)?;
        let mut key = master.child(path[0]);
        for &i in &path[1..] {
            key = key.child(i);
        }
        Ok(key)
    }

    /// A Cardano key's public key and chain code (`op::CARDANO_PUBLIC`).
    pub fn cardano_public(&self, path: &[u32]) -> Result<[u8; 64], Error> {
        let key = self.cardano_key(path)?;
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&key.public());
        out[32..].copy_from_slice(&key.chain_code);
        Ok(out)
    }

    /// An Ed25519 signature over the whole of `message` with the Cardano key at `path`.
    pub fn sign_cardano(&self, path: &[u32], message: &[u8]) -> Result<[u8; 64], Error> {
        self.cardano_key(path)?.sign(message)
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

    /// A BIP-85 child seed's words (`crate::child_seed`'s path): the key there made entropy
    /// (`bip85_entropy`), its first 16, 24 or 32 bytes a BIP39 phrase of 12, 18 or 24 words.
    fn child_seed_words(&self, path: &[u32]) -> Result<alloc::string::String, Error> {
        let (words, _) = crate::child_seed(path).ok_or(Error::Path)?;
        let mut k: [u8; 32] = self.derive(path)?.key.to_bytes().into();
        let mut entropy = bip85_entropy(&k);
        k.zeroize();
        let phrase = maki_seed::to_words(&entropy[..words as usize * 4 / 3]);
        entropy.zeroize();
        let out = phrase.join(" ");
        maki_seed::forget_words(phrase);
        Ok(out)
    }

    /// A BIP-85 password (`crate::bip85_password`'s path): the key there made entropy
    /// (`bip85_entropy`), written in base64 or base85 and cut to its length.
    fn bip85_password(&self, path: &[u32]) -> Result<alloc::string::String, Error> {
        let (kind, len, _) = crate::bip85_password(path).ok_or(Error::Path)?;
        let mut k: [u8; 32] = self.derive(path)?.key.to_bytes().into();
        let mut entropy = bip85_entropy(&k);
        k.zeroize();
        let password = bip85_password_text(kind, &entropy, len as usize);
        entropy.zeroize();
        Ok(password)
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

/// BIP-85's entropy from a private key `k` it derived: HMAC-SHA512, keyed "bip-entropy-from-k",
/// of `k`. Hashed, so what's made of it gives nothing of `k` (or the keys above it) away.
pub fn bip85_entropy(k: &[u8; 32]) -> [u8; 64] { hmac512(b"bip-entropy-from-k", &[k]) }

/// A BIP-85 password from its entropy: all 64 bytes in base64 (RFC 4648, 88 characters with
/// its padding) or base85 (RFC 1924's alphabet, 80), the first `len` characters of it. The
/// lengths `crate::bip85_password` allows never reach the padding.
pub fn bip85_password_text(
    kind: crate::Bip85Password,
    entropy: &[u8; 64],
    len: usize,
) -> alloc::string::String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const B85: &[u8; 85] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
    let mut out = alloc::string::String::with_capacity(88);
    match kind {
        crate::Bip85Password::Base64 => {
            for c in entropy.chunks(3) {
                let n = c.iter().enumerate().fold(0u32, |n, (i, &b)| n | (b as u32) << (16 - 8 * i));
                for i in 0..4 {
                    // a chunk of fewer than 3 bytes (the last: 64 = 21 × 3 + 1) ends with padding
                    out.push(if i <= c.len() { B64[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
                }
            }
        }
        crate::Bip85Password::Base85 => {
            // 64 bytes are 16 groups of 4: each, big-endian, five base-85 digits, the most
            // significant first
            for c in entropy.chunks(4) {
                let mut n = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
                let mut digits = [0u8; 5];
                for d in digits.iter_mut().rev() {
                    *d = B85[(n % 85) as usize];
                    n /= 85;
                }
                out.extend(digits.iter().map(|&d| d as char));
            }
        }
    }
    out.truncate(len);
    out
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
        op::BIP85_WORDS => keys.child_seed_words(path)?.into_bytes(),
        op::BIP85_PASSWORD => keys.bip85_password(path)?.into_bytes(),
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
        op::CARDANO_PUBLIC => keys.cardano_public(path)?.to_vec(),
        op::CARDANO_SIGN => keys.sign_cardano(path, asked)?.to_vec(),
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
