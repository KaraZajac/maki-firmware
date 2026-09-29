//! What spending takes of maki: the curve work of a Monero transaction that needs the account's
//! keys, or that decides where its money goes. The computer finds the account's outputs (with
//! the view key), picks the decoys and builds the rest; maki works out what the outputs pay, from
//! the payments the owner says yes to, and signs the inputs, each a CLSAG over its ring.
//!
//! As Monero's own `crypto` and `ringct` code does it, held to Monero's test vectors
//! (`tests/crypto/tests.txt` in the monero repository), to monero-rs, and to monero-oxide's
//! CLSAG verifier. The hash onto the curve is monero-oxide's (`monero-ed25519`, MIT): Elligator 2,
//! once, with crypto-bigint's field arithmetic, since dalek keeps its own to itself.

use alloc::vec::Vec;

use crypto_bigint::modular::constant_mod::{Residue, ResidueParams};
use crypto_bigint::{const_residue, impl_modulus, Encoding, U256};
/// The curve's points and scalars, as this module takes and gives them, and its generator G.
pub use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
use curve25519_dalek::edwards::CompressedEdwardsY;
pub use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
pub use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use sha3::{Digest, Keccak256, Keccak512};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use crate::keccak;

/// Monero's hash to a scalar (`hash_to_scalar`): Keccak-256, reduced.
pub fn hash_to_scalar(data: &[u8]) -> Scalar { Scalar::from_bytes_mod_order(keccak(data)) }

impl_modulus!(Field25519, U256, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
type FieldElement = Residue<Field25519, { U256::LIMBS }>;

/// Monero's hash onto the curve (`hash_to_ec`, `biased_hash_to_ec` in its tests): Keccak-256 of
/// `bytes`, taken to Curve25519 with Elligator 2 (once, so not every point can come of it), to
/// Ed25519, and multiplied by 8. A key image is an output key's secret times this of its key.
pub fn hash_to_point(bytes: &[u8]) -> EdwardsPoint {
    const A_INT: U256 = U256::from_u64(486_662);
    const A: FieldElement = const_residue!(A_INT, Field25519);
    let r = FieldElement::new(&U256::from_le_bytes(Keccak256::digest(bytes).into()));
    // with u = 2, the smallest number that isn't a square
    let ur2 = r.square() + r.square();
    let (inverse, _) = (FieldElement::ONE + ur2).invert();
    let upsilon = -A * inverse;
    let other = -upsilon - A;
    // whether upsilon is a u coordinate: whether u^3 + A u^2 + u has a square root, which is
    // v^((p+3)/8) or that times the square root of -1, 2^((p-1)/4)
    const EXPONENT: U256 = Field25519::MODULUS.shr_vartime(3).wrapping_add(&U256::ONE);
    const ROOT_OF_MINUS_ONE: FieldElement =
        FieldElement::ONE.add(&FieldElement::ONE).pow(&Field25519::MODULUS.shr_vartime(2));
    let square = |v: &FieldElement| -> Choice {
        let y = v.pow(&EXPONENT);
        y.square().ct_eq(v) | (y * ROOT_OF_MINUS_ONE).square().ct_eq(v)
    };
    let epsilon = square(&(((upsilon + A) * upsilon.square()) + upsilon));
    let u = FieldElement::conditional_select(&other, &upsilon, epsilon);
    MontgomeryPoint(u.retrieve().to_le_bytes())
        .to_edwards(epsilon.unwrap_u8())
        .expect("one of Elligator's two is always a point")
        .mul_by_cofactor()
}

/// H, the second generator, which amounts are committed to: Keccak-256 of G, read as a point,
/// times 8.
pub const H: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea, 0x6c, 0x72, 0x51,
    0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];

fn h() -> EdwardsPoint { CompressedEdwardsY(H).decompress().expect("H is a point") }

/// A commitment to `amount`, hidden by `mask`: mask·G + amount·H.
pub fn commit(mask: &Scalar, amount: u64) -> EdwardsPoint {
    EdwardsPoint::multiscalar_mul([*mask, Scalar::from(amount)], [G, h()])
}

/// A point from its 32 bytes, if they're one.
pub fn point(bytes: &[u8; 32]) -> Option<EdwardsPoint> { CompressedEdwardsY(*bytes).decompress() }

/// `n` as Monero writes numbers: 7 bits a byte, low first, the top bit saying more follow.
pub fn varint(mut n: u64, out: &mut Vec<u8>) {
    while n >= 0x80 {
        out.push((n as u8) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

/// What sender and receiver share of a transaction (`generate_key_derivation`): 8·a·R, the
/// receiver's view key a and the transaction's public key R, or the other way round, 8·r·A.
pub fn derivation(secret: &Scalar, public: &EdwardsPoint) -> [u8; 32] {
    (secret * public).mul_by_cofactor().compress().to_bytes()
}

/// The scalar an output's keys are made with (`derivation_to_scalar`): Hs(derivation ‖ index).
pub fn output_scalar(derivation: &[u8; 32], index: u64) -> Scalar {
    let mut data = Vec::with_capacity(32 + 10);
    data.extend_from_slice(derivation);
    varint(index, &mut data);
    let s = hash_to_scalar(&data);
    data.zeroize();
    s
}

/// An output's view tag (`derive_view_tag`): a byte a receiver checks first, so most outputs
/// that aren't theirs cost one hash rather than a scalar multiplication.
pub fn view_tag(derivation: &[u8; 32], index: u64) -> u8 {
    let mut data = Vec::with_capacity(8 + 32 + 10);
    data.extend_from_slice(b"view_tag");
    data.extend_from_slice(derivation);
    varint(index, &mut data);
    let tag = keccak(&data)[0];
    data.zeroize();
    tag
}

/// An output's amount as the transaction carries it (RingCT's `ecdhEncode`, version 2), from its
/// `output_scalar`; the same both ways.
pub fn encrypt_amount(amount: u64, scalar: &Scalar) -> [u8; 8] {
    let mut data = [0u8; 6 + 32];
    data[..6].copy_from_slice(b"amount");
    data[6..].copy_from_slice(scalar.as_bytes());
    let pad = keccak(&data);
    data.zeroize();
    let mut out = amount.to_le_bytes();
    for (o, p) in out.iter_mut().zip(pad) {
        *o ^= p;
    }
    out
}

/// The mask an output's amount commitment is made with (`genCommitmentMask`), from its
/// `output_scalar`: the receiver makes it again to spend the output.
pub fn commitment_mask(scalar: &Scalar) -> Scalar {
    let mut data = [0u8; 15 + 32];
    data[..15].copy_from_slice(b"commitment_mask");
    data[15..].copy_from_slice(scalar.as_bytes());
    let mask = hash_to_scalar(&data);
    data.zeroize();
    mask
}

/// What an output of a transaction maki signs pays: the one-time key, view tag, amount and its
/// commitment, as the transaction carries them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub key: [u8; 32],
    pub view_tag: u8,
    pub encrypted_amount: [u8; 8],
    pub commitment: [u8; 32],
    /// The commitment's mask, for the range proof and to balance the inputs' pseudo-outputs.
    pub mask: Scalar,
}

/// Output `index` of a transaction with secret key `r`, paying `amount` to an address with public
/// view key `view` and spend key `spend` (a subaddress's own, for one; the transaction's public
/// key must then be r times its spend key).
pub fn pay(r: &Scalar, view: &EdwardsPoint, spend: &EdwardsPoint, index: u64, amount: u64) -> Output {
    let mut shared = derivation(r, view);
    let scalar = output_scalar(&shared, index);
    let tag = view_tag(&shared, index);
    shared.zeroize();
    let mask = commitment_mask(&scalar);
    Output {
        key: (G * scalar + spend).compress().to_bytes(),
        view_tag: tag,
        encrypted_amount: encrypt_amount(amount, &scalar),
        commitment: commit(&mask, amount).compress().to_bytes(),
        mask,
    }
}

/// A key image (`generate_key_image`): what marks an output as spent, the same whichever ring
/// spends it. `secret` is the output's one-time secret, `key` its key.
pub fn key_image(secret: &Scalar, key: &EdwardsPoint) -> EdwardsPoint { secret * hash_to_point(key.compress().as_bytes()) }

/// A ring member: an output's key and amount commitment, as the chain has them.
#[derive(Clone, Copy, Debug)]
pub struct Member {
    pub key: EdwardsPoint,
    pub commitment: EdwardsPoint,
}

/// A CLSAG, as a transaction carries it: `s`, one for each ring member, `c1` and `d` (D/8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clsag {
    pub s: Vec<Scalar>,
    pub c1: Scalar,
    pub d: [u8; 32],
}

impl Clsag {
    /// Its bytes in a transaction: each s, then c1, then D/8.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out: Vec<u8> = self.s.iter().flat_map(|s| s.to_bytes()).collect();
        out.extend_from_slice(self.c1.as_bytes());
        out.extend_from_slice(&self.d);
        out
    }
}

/// Uniform scalars for a signature, from the key, what's signed and randomness of maki's own:
/// never the same for two messages, and no worse than deterministic if the randomness is weak.
struct Nonces {
    seed: [u8; 32],
    count: u64,
}

impl Nonces {
    fn new(secret: &Scalar, aux: &[u8; 32], message: &[u8; 32], ring: &[Member]) -> Nonces {
        let mut h = Keccak256::new();
        h.update(b"maki CLSAG nonces");
        h.update(secret.as_bytes());
        h.update(aux);
        h.update(message);
        for m in ring {
            h.update(m.key.compress().as_bytes());
            h.update(m.commitment.compress().as_bytes());
        }
        Nonces { seed: h.finalize().into(), count: 0 }
    }

    fn next(&mut self) -> Scalar {
        let mut h = Keccak512::new();
        h.update(self.seed);
        h.update(self.count.to_le_bytes());
        self.count += 1;
        let mut wide: [u8; 64] = h.finalize().into();
        let s = Scalar::from_bytes_mod_order_wide(&wide);
        wide.zeroize();
        s
    }
}

impl Drop for Nonces {
    fn drop(&mut self) { self.seed.zeroize(); }
}

/// Why a CLSAG wasn't made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignError {
    /// No ring, or more than Monero allows, or no member `real`.
    Ring,
    /// The secret isn't member `real`'s key's.
    Key,
    /// The commitment's mask difference doesn't open member `real`'s commitment less the
    /// pseudo-output: the amounts differ, or the mask is wrong.
    Commitment,
}

/// The most ring members a signature has room for; Monero's rings are 16.
pub const MAX_RING: usize = 128;

/// A CLSAG for input `real` of `ring`, whose one-time secret is `secret`, and the input's key
/// image. `mask_difference` is its commitment's mask less its pseudo-output's (the same amount
/// in both), `pseudo_out` the pseudo-output, and `message` what's signed (the transaction's
/// pre-MLSAG hash). `aux` is randomness for the nonces.
pub fn clsag(
    ring: &[Member],
    real: usize,
    secret: &Scalar,
    mask_difference: &Scalar,
    pseudo_out: &EdwardsPoint,
    message: &[u8; 32],
    aux: &[u8; 32],
) -> Result<(Clsag, EdwardsPoint), SignError> {
    let n = ring.len();
    if n == 0 || n > MAX_RING || real >= n {
        return Err(SignError::Ring);
    }
    if !bool::from((G * secret).ct_eq(&ring[real].key)) {
        return Err(SignError::Key);
    }
    if !bool::from((G * mask_difference).ct_eq(&(ring[real].commitment - pseudo_out))) {
        return Err(SignError::Commitment);
    }
    let hp: Vec<EdwardsPoint> = ring.iter().map(|m| hash_to_point(m.key.compress().as_bytes())).collect();
    let image = secret * hp[real];
    let d = mask_difference * hp[real];
    let d8 = (d * Scalar::from(8u8).invert()).compress().to_bytes();
    let keys: Vec<[u8; 32]> = ring.iter().map(|m| m.key.compress().to_bytes()).collect();
    let commitments: Vec<[u8; 32]> = ring.iter().map(|m| m.commitment.compress().to_bytes()).collect();
    let domain = |tag: &[u8; 5]| {
        let mut key = [0u8; 32];
        key[..6].copy_from_slice(b"CLSAG_");
        key[6..11].copy_from_slice(tag);
        key
    };

    // the aggregation coefficients, for keys and for commitments
    let mut agg = Vec::with_capacity((2 * n + 4) * 32);
    agg.extend_from_slice(&domain(b"agg_0"));
    keys.iter().chain(&commitments).for_each(|b| agg.extend_from_slice(b));
    agg.extend_from_slice(image.compress().as_bytes());
    agg.extend_from_slice(&d8);
    agg.extend_from_slice(pseudo_out.compress().as_bytes());
    let mu_p = hash_to_scalar(&agg);
    agg[6..11].copy_from_slice(b"agg_1");
    let mu_c = hash_to_scalar(&agg);

    // each round's challenge: this, then the round's L and R
    let mut round = Vec::with_capacity((2 * n + 5) * 32);
    round.extend_from_slice(&domain(b"round"));
    keys.iter().chain(&commitments).for_each(|b| round.extend_from_slice(b));
    round.extend_from_slice(pseudo_out.compress().as_bytes());
    round.extend_from_slice(message);
    let fixed = round.len();
    let mut challenge = |l: &EdwardsPoint, r: &EdwardsPoint| {
        round.truncate(fixed);
        round.extend_from_slice(l.compress().as_bytes());
        round.extend_from_slice(r.compress().as_bytes());
        hash_to_scalar(&round)
    };

    let mut nonces = Nonces::new(secret, aux, message, ring);
    let mut alpha = nonces.next();
    let mut s: Vec<Scalar> = (0..n).map(|_| nonces.next()).collect();
    let mut c = challenge(&(G * alpha), &(hp[real] * alpha));
    let mut c1 = c;
    for k in 1..n {
        let i = (real + k) % n;
        if i == 0 {
            c1 = c;
        }
        let (cp, cc) = (c * mu_p, c * mu_c);
        let l = EdwardsPoint::multiscalar_mul([s[i], cp, cc], [G, ring[i].key, ring[i].commitment - pseudo_out]);
        let r = EdwardsPoint::multiscalar_mul([s[i], cp, cc], [hp[i], image, d]);
        c = challenge(&l, &r);
    }
    // back round to the start: c is the real member's challenge
    if real == 0 {
        c1 = c;
    }
    s[real] = alpha - c * (mu_p * secret + mu_c * mask_difference);
    alpha.zeroize();
    Ok((Clsag { s, c1, d: d8 }, image))
}
