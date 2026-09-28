//! Taproot for one key (BIP86): the key tweaked as BIP341 has it with no scripts, and the key
//! that signs for it (BIP340 Schnorr).

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, PublicKey, Scalar, SecretKey};
use zeroize::Zeroize;

use crate::hash::tagged;

/// A public key's x coordinate, the form taproot writes keys in.
pub fn x_only(public_key: &[u8; 33]) -> [u8; 32] { public_key[1..].try_into().unwrap() }

/// BIP86's tweak for an internal key with no script tree: `H_TapTweak(P)`.
fn tweak(internal: &[u8; 32]) -> Option<Scalar> { Option::from(Scalar::from_repr(tagged("TapTweak", &[internal]).into())) }

/// The output key an internal key makes (BIP86): the internal key with its y even, plus the
/// tweak times G, x only. None for the (never met) keys that don't make one.
pub fn output_key(internal: &[u8; 32]) -> Option<[u8; 32]> {
    let mut sec1 = [0x02u8; 33];
    sec1[1..].copy_from_slice(internal);
    let p = PublicKey::from_sec1_bytes(&sec1).ok()?;
    let q = (ProjectivePoint::from(*p.as_affine()) + ProjectivePoint::GENERATOR * tweak(internal)?).to_affine();
    let q = PublicKey::from_affine(q).ok()?.to_encoded_point(true);
    Some(q.as_bytes()[1..].try_into().unwrap())
}

/// The key that signs for the output key `secret`'s public key makes: the secret, negated if
/// its point's y is odd, plus the tweak. (The Schnorr key takes its own point's y even in turn,
/// as BIP340 has it.)
pub fn signing_key(secret: &SecretKey) -> Option<k256::schnorr::SigningKey> {
    let point = secret.public_key().to_encoded_point(true);
    let internal: [u8; 32] = point.as_bytes()[1..].try_into().unwrap();
    let mut d = *secret.to_nonzero_scalar();
    if point.as_bytes()[0] == 0x03 {
        d = -d;
    }
    let mut bytes = (d + tweak(&internal)?).to_bytes();
    let key = k256::schnorr::SigningKey::from_bytes(&bytes).ok();
    bytes.zeroize();
    key
}
