//! Shamir's secret sharing as Blockchain Commons' bc-shamir does it (the Rust crate 0.13.0's
//! `split_secret` and `recover_secret`, the C library 0.4.0's `shamir.c`; BCR-2020-011 builds on
//! it). Each byte of the secret is the value at x = 255 of a polynomial over GF(2^8) of degree
//! threshold − 1, the same position in every polynomial making one share: share i is the values at
//! x = i. One more point fixes the polynomials, at x = 254: a digest, the first four bytes of
//! HMAC-SHA256 over the secret keyed by the rest of that point's bytes, which are random. The
//! first threshold − 2 shares are random too, and the rest follow, by Lagrange interpolation
//! through those points. Putting shares back together finds the values at 254 and 255 and checks
//! one against the other, so shares that don't belong together are caught, but for 1 in 2^32.
//! (The digest is also why bc-shamir is computationally secure rather than perfectly: someone with
//! threshold − 1 shares can test guesses at the secret against it. Their review of 2021 accepts
//! that for secrets of 128 bits and more; SLIP-39 makes the same choice.)
//!
//! A threshold of 1 has no polynomial: every share is the secret itself.

use alloc::vec;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::gf256::{inv, mul};

/// Where the secret is, x = 255, and the digest, x = 254 (bc-shamir's `SECRET_INDEX` and
/// `DIGEST_INDEX`). Shares are at 0 to 15, so never there.
const SECRET_X: u8 = 255;
const DIGEST_X: u8 = 254;

/// `count` shares of `secret`, any `threshold` of which put it back. The caller has checked that
/// 1 ≤ threshold ≤ count ≤ 16 and that the secret is 16 to 32 bytes; `random` is asked for bytes
/// as bc-shamir asks its random number generator: each of the first threshold − 2 shares in turn,
/// then the digest's random part (all but four bytes of a share), so the same random bytes make
/// the same shares.
pub(crate) fn split(
    threshold: usize,
    count: usize,
    secret: &[u8],
    random: &mut dyn FnMut(&mut [u8]),
) -> Vec<Zeroizing<Vec<u8>>> {
    let mut shares: Vec<Zeroizing<Vec<u8>>> =
        (0..count).map(|_| Zeroizing::new(vec![0u8; secret.len()])).collect();
    if threshold == 1 {
        for share in shares.iter_mut() {
            share.copy_from_slice(secret);
        }
        return shares;
    }
    let chosen = threshold - 2;
    for share in shares.iter_mut().take(chosen) {
        random(share);
    }
    let mut digest = Zeroizing::new(vec![0u8; secret.len()]);
    random(&mut digest[4..]);
    let check = hmac_sha256(&digest[4..], secret);
    digest[..4].copy_from_slice(&check[..4]);

    let (picked, rest) = shares.split_at_mut(chosen);
    let mut xs: Vec<u8> = (0..chosen as u8).collect();
    xs.extend([DIGEST_X, SECRET_X]);
    let mut ys: Vec<&[u8]> = picked.iter().map(|share| &share[..]).collect();
    ys.extend([&digest[..], secret]);
    for (i, share) in rest.iter_mut().enumerate() {
        interpolate(&xs, &ys, (chosen + i) as u8, share);
    }
    shares
}

/// The secret from shares (`xs[i]`, `ys[i]`), if they fit together: the digest they give checks
/// against the secret they give, or, for a threshold of 1, they're all the same. The caller has
/// checked that there are at least `threshold` of them, at different x, all the same length.
///
/// Unlike bc-shamir, which uses the first `threshold` shares it's given, this puts every one
/// through the interpolation, so a share given beyond the threshold must fit too: shares on one
/// polynomial of degree threshold − 1 give it back whatever their number, and one that's off the
/// polynomial throws the digest off. The same shares give the same secret either way.
pub(crate) fn recover(threshold: usize, xs: &[u8], ys: &[&[u8]]) -> Option<Zeroizing<Vec<u8>>> {
    let first = ys.first()?;
    if threshold == 1 {
        let same = ys.iter().fold(true, |same, y| same & equal(y, first));
        return same.then(|| Zeroizing::new(first.to_vec()));
    }
    let mut digest = Zeroizing::new(vec![0u8; first.len()]);
    let mut secret = Zeroizing::new(vec![0u8; first.len()]);
    interpolate(xs, ys, DIGEST_X, &mut digest);
    interpolate(xs, ys, SECRET_X, &mut secret);
    let check = hmac_sha256(digest.get(4..)?, &secret);
    equal(&digest[..4], &check[..4]).then_some(secret)
}

/// The value at `x` of the polynomials through the points (`xs[i]`, `ys[i]`), byte by byte, into
/// `out`: Σ yᵢ · Πⱼ≠ᵢ (x − xⱼ) / (xᵢ − xⱼ), subtracting being adding in GF(2^8). The x are
/// share numbers, not secret, so only the y are kept out of branches.
fn interpolate(xs: &[u8], ys: &[&[u8]], x: u8, out: &mut [u8]) {
    out.fill(0);
    for (i, (&xi, yi)) in xs.iter().zip(ys).enumerate() {
        let (mut numerator, mut denominator) = (1u8, 1u8);
        for (j, &xj) in xs.iter().enumerate() {
            if j != i {
                numerator = mul(numerator, x ^ xj);
                denominator = mul(denominator, xi ^ xj);
            }
        }
        let basis = mul(numerator, inv(denominator));
        for (o, &y) in out.iter_mut().zip(yi.iter()) {
            *o ^= mul(basis, y);
        }
    }
}

/// Byte for byte, without stopping at the first difference.
fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

/// HMAC-SHA256 (RFC 2104), what bc-shamir's `create_digest` takes four bytes of: keyed by the
/// digest's random bytes, over the secret.
fn hmac_sha256(key: &[u8], message: &[u8]) -> Zeroizing<[u8; 32]> {
    // the key here is 12 to 28 bytes, so it fits SHA-256's 64-byte block as it is
    let mut block = Zeroizing::new([0u8; 64]);
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut pad = Zeroizing::new([0u8; 64]);
    for (p, k) in pad.iter_mut().zip(block.iter()) {
        *p = k ^ 0x36;
    }
    let mut inner = Zeroizing::new([0u8; 32]);
    inner.copy_from_slice(&Sha256::new().chain_update(&pad[..]).chain_update(message).finalize());
    for (p, k) in pad.iter_mut().zip(block.iter()) {
        *p = k ^ 0x5c;
    }
    let mut outer = Zeroizing::new([0u8; 32]);
    outer.copy_from_slice(&Sha256::new().chain_update(&pad[..]).chain_update(&inner[..]).finalize());
    outer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn hmac_is_rfc_4231s() {
        // RFC 4231's test cases 1 and 2
        assert_eq!(
            &hmac_sha256(&[0x0b; 20], b"Hi There")[..],
            &unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")[..]
        );
        assert_eq!(
            &hmac_sha256(b"Jefe", b"what do ya want for nothing?")[..],
            &unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")[..]
        );
        // and case 6, a key longer than SHA-256's block
        assert_eq!(
            &hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")[..],
            &unhex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")[..]
        );
    }

    /// bc-shamir's own tests (the Rust crate's `test_split_secret_3_5` and `_2_7`, the C
    /// library's `test_shamir`), whose random number generator gives 0, 17, 34… each time it's
    /// asked.
    fn fake(bytes: &mut [u8]) {
        let mut b = 0u8;
        for x in bytes {
            *x = b;
            b = b.wrapping_add(17);
        }
    }

    #[test]
    fn bc_shamirs_vectors() {
        let secret = unhex("0ff784df000c4380a5ed683f7e6e3dcf");
        let shares = split(3, 5, &secret, &mut fake);
        let expected = [
            "00112233445566778899aabbccddeeff",
            "d43099fe444807c46921a4f33a2a798b",
            "d9ad4e3bec2e1a7485698823abf05d36",
            "0d8cf5f6ec337bc764d1866b5d07ca42",
            "1aa7fe3199bc5092ef3816b074cabdf2",
        ];
        for (share, hex) in shares.iter().zip(expected) {
            assert_eq!(&share[..], &unhex(hex)[..]);
        }
        let ys: Vec<&[u8]> = [1, 2, 4].iter().map(|&i| &shares[i][..]).collect();
        assert_eq!(&recover(3, &[1, 2, 4], &ys).unwrap()[..], &secret[..]);

        let secret = unhex("204188bfa6b440a1bdfd6753ff55a8241e07af5c5be943db917e3efabc184b1a");
        let shares = split(2, 7, &secret, &mut fake);
        let expected = [
            "2dcd14c2252dc8489af3985030e74d5a48e8eff1478ab86e65b43869bf39d556",
            "a1dfdd798388aada635b9974472b4fc59a32ae520c42c9f6a0af70149b882487",
            "2ee99daf727c0c7773b89a18de64497ff7476dacd1015a45f482a893f7402cef",
            "a2fb5414d4d96ee58a109b3ca9a84be0259d2c0f9ac92bdd3199e0eed3f1dd3e",
            "2b851d188b8f5b3653659cc0f7fa45102dadf04b708767385cd803862fcb3c3f",
            "a797d4a32d2a39a4aacd9de48036478fff77b1e83b4f16a099c34bfb0b7acdee",
            "28a19475dcde9f09ba2e9e881979413592027216e60c8513cdee937c67b2c586",
        ];
        for (share, hex) in shares.iter().zip(expected) {
            assert_eq!(&share[..], &unhex(hex)[..]);
        }
        let ys: Vec<&[u8]> = [3, 4].iter().map(|&i| &shares[i][..]).collect();
        assert_eq!(&recover(2, &[3, 4], &ys).unwrap()[..], &secret[..]);
        // every share at once fits too, and one changed doesn't
        let all: Vec<&[u8]> = shares.iter().map(|s| &s[..]).collect();
        assert_eq!(&recover(2, &[0, 1, 2, 3, 4, 5, 6], &all).unwrap()[..], &secret[..]);
        let mut bent = shares[6].to_vec();
        bent[0] ^= 1;
        let mut some = all.clone();
        some[6] = &bent;
        assert!(recover(2, &[0, 1, 2, 3, 4, 5, 6], &some).is_none());
    }

    #[test]
    fn bc_shamirs_example() {
        // bc-shamir's `recover_secret` example: 2 of 3, its shares 0 and 2 of a 24-byte secret
        let shares: [&[u8]; 2] = [
            &[
                47, 165, 102, 232, 218, 99, 6, 94, 39, 6, 253, 215, 12, 88, 64, 32, 105, 40, 222, 146, 93,
                197, 48, 129,
            ],
            &[
                221, 174, 116, 201, 90, 99, 136, 33, 64, 215, 60, 84, 207, 28, 74, 10, 111, 243, 43, 224, 48,
                64, 199, 172,
            ],
        ];
        assert_eq!(&recover(2, &[0, 2], &shares).unwrap()[..], b"my secret belongs to me.");
        // a share given as another one's isn't
        assert!(recover(2, &[0, 1], &shares).is_none());
    }
}
