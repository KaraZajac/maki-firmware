//! Spending: held to Monero's own test vectors (tests/monero-crypto.txt), outputs' one-time keys
//! to monero-rs, and CLSAGs to monero-oxide's verifier.
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use maki_xmr::Keys;
use maki_xmr::sign::{self, Member, SignError};
use monero::cryptonote::onetime_key::{KeyGenerator, KeyRecoverer};
use monero::cryptonote::subaddress::Index;
use monero::util::key::{KeyPair, PrivateKey, PublicKey};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn b32(s: &str) -> [u8; 32] { hex(s).try_into().unwrap() }
fn scalar(s: &str) -> Scalar { Scalar::from_bytes_mod_order(b32(s)) }

/// Numbers from a seed, the same every run.
struct Random(u64);

impl Random {
    fn u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for chunk in b.chunks_mut(8) {
            chunk.copy_from_slice(&self.u64().to_le_bytes());
        }
        b
    }

    fn scalar(&mut self) -> Scalar {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&self.bytes());
        wide[32..].copy_from_slice(&self.bytes());
        Scalar::from_bytes_mod_order_wide(&wide)
    }
}

#[test]
fn monero_crypto_vectors() {
    let mut seen = std::collections::BTreeMap::<&str, usize>::new();
    for line in include_str!("monero-crypto.txt").lines() {
        let w: Vec<&str> = line.split_whitespace().collect();
        *seen.entry(w[0]).or_default() += 1;
        match w[0] {
            "biased_hash_to_ec" => {
                assert_eq!(sign::hash_to_point(&hex(w[1])).compress().to_bytes(), b32(w[2]), "{line}")
            }
            "hash_to_scalar" => assert_eq!(sign::hash_to_scalar(&hex(w[1])).to_bytes(), b32(w[2]), "{line}"),
            "generate_key_derivation" => match (sign::point(&b32(w[1])), w[3]) {
                (Some(p), "true") => assert_eq!(sign::derivation(&scalar(w[2]), &p), b32(w[4]), "{line}"),
                (None, "false") => {}
                _ => panic!("{line}"),
            },
            "derive_public_key" => match (sign::point(&b32(w[3])), w[4]) {
                (Some(base), "true") => {
                    let derived = G * sign::output_scalar(&b32(w[1]), w[2].parse().unwrap()) + base;
                    assert_eq!(derived.compress().to_bytes(), b32(w[5]), "{line}");
                }
                (None, "false") => {}
                _ => panic!("{line}"),
            },
            "derive_secret_key" => {
                let derived = sign::output_scalar(&b32(w[1]), w[2].parse().unwrap()) + scalar(w[3]);
                assert_eq!(derived.to_bytes(), b32(w[4]), "{line}");
            }
            "generate_key_image" => {
                let key = sign::point(&b32(w[1])).unwrap();
                assert_eq!(sign::key_image(&scalar(w[2]), &key).compress().to_bytes(), b32(w[3]), "{line}");
            }
            "derive_view_tag" => {
                assert_eq!(sign::view_tag(&b32(w[1]), w[2].parse().unwrap()), hex(w[3])[0], "{line}")
            }
            _ => panic!("{line}"),
        }
    }
    assert_eq!(seen.values().sum::<usize>(), 462, "{seen:?}");
}

#[test]
fn h_is_monero_s() {
    let hashed = sign::point(&maki_xmr::keccak(G.compress().as_bytes())).unwrap();
    assert_eq!(hashed.mul_by_cofactor().compress().to_bytes(), sign::H);
    assert_eq!(monero_ed25519::CompressedPoint::H.to_bytes(), sign::H);
}

#[test]
fn commitments_are_monero_oxides() {
    let mut random = Random(0xc0_1117);
    for amount in [0, 1, 1_000_000_000_000, u64::MAX, random.u64(), random.u64()] {
        let mask = random.scalar();
        let theirs = monero_ed25519::Commitment::new(
            monero_ed25519::Scalar::read(&mut &mask.to_bytes()[..]).unwrap(),
            amount,
        );
        assert_eq!(
            sign::commit(&mask, amount).compress().to_bytes(),
            theirs.commit().compress().to_bytes(),
            "{amount}"
        );
    }
}

#[test]
fn varints_are_monero_s() {
    for (n, bytes) in [
        (0u64, &[0u8][..]),
        (127, &[0x7f]),
        (128, &[0x80, 1]),
        (300, &[0xac, 2]),
        (u64::MAX, &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1]),
    ] {
        let mut out = Vec::new();
        sign::varint(n, &mut out);
        assert_eq!(out, bytes, "{n}");
    }
}

/// Outputs maki pays have the keys monero-rs gives them, and outputs to an account of maki's
/// have the secrets monero-rs recovers; maki finds them, and opens their amounts.
#[test]
fn outputs_are_monero_rss() {
    let mut random = Random(0x0071_5ea1_1ed0);
    for round in 0..12 {
        let keys = Keys::from_bip32(&random.bytes());
        let pair = KeyPair {
            spend: PrivateKey::from_slice(&keys.spend_bytes()).unwrap(),
            view: PrivateKey::from_slice(&keys.view_bytes()).unwrap(),
        };
        for (major, minor) in [(0, 0), (0, 1), (2, 7)] {
            let (spend, view) = keys.subaddress(major, minor);
            let (spend, view) = (sign::point(&spend).unwrap(), sign::point(&view).unwrap());
            let r = random.scalar();
            // to a subaddress, the transaction's key is r times its spend key
            let tx_key = if (major, minor) == (0, 0) { G * r } else { spend * r };
            let index = (round * 3 + major as u64) % 5;
            let amount = random.u64() >> 4;
            let out = sign::pay(&r, &view, &spend, index, amount);

            let generator = KeyGenerator::from_random(
                PublicKey::from_slice(view.compress().as_bytes()).unwrap(),
                PublicKey::from_slice(spend.compress().as_bytes()).unwrap(),
                PrivateKey::from_slice(r.as_bytes()).unwrap(),
            );
            assert_eq!(out.key, generator.one_time_key(index as usize).to_bytes());

            let secret = keys.output_secret(&tx_key, index, major, minor);
            let recovered =
                KeyRecoverer::new(&pair, PublicKey::from_slice(tx_key.compress().as_bytes()).unwrap())
                    .recover(index as usize, Index { major, minor });
            assert_eq!(secret.to_bytes(), recovered.to_bytes());
            assert_eq!((G * secret).compress().to_bytes(), out.key);

            let key = sign::point(&out.key).unwrap();
            assert!(keys.owns(&tx_key, index, out.view_tag, &key, major, minor));
            assert!(!keys.owns(&tx_key, index + 1, out.view_tag, &key, major, minor));
            let commitment = sign::point(&out.commitment).unwrap();
            assert_eq!(
                keys.open_output(&tx_key, index, &out.encrypted_amount, &commitment),
                Some((amount, out.mask))
            );
            assert_eq!(keys.open_output(&tx_key, index, &[0; 8], &commitment), None);
        }
    }
}

fn ring(
    random: &mut Random,
    n: usize,
    real: usize,
    key: EdwardsPoint,
    commitment: EdwardsPoint,
) -> Vec<Member> {
    (0..n)
        .map(|i| {
            if i == real {
                Member { key, commitment }
            } else {
                Member { key: G * random.scalar(), commitment: sign::commit(&random.scalar(), random.u64()) }
            }
        })
        .collect()
}

fn theirs(p: &EdwardsPoint) -> monero_ed25519::CompressedPoint {
    monero_ed25519::CompressedPoint::from(p.compress().to_bytes())
}

/// Every ring size to 16 and every place in it: monero-oxide's verifier takes the signature,
/// with its key image, and the signature's the same again for the same randomness.
#[test]
fn monero_oxide_verifies_every_clsag() {
    let mut random = Random(0xc15a_9000);
    for n in 1..=16 {
        for real in 0..n {
            let secret = random.scalar();
            let (mask, amount) = (random.scalar(), random.u64());
            let pseudo_mask = random.scalar();
            let pseudo_out = sign::commit(&pseudo_mask, amount);
            let members = ring(&mut random, n, real, G * secret, sign::commit(&mask, amount));
            let (message, aux) = (random.bytes(), random.bytes());
            let (clsag, image) =
                sign::clsag(&members, real, &secret, &(mask - pseudo_mask), &pseudo_out, &message, &aux)
                    .unwrap();
            assert_eq!(image, sign::key_image(&secret, &(G * secret)));

            let signature = monero_clsag::Clsag::read(n, &mut &clsag.to_bytes()[..]).unwrap();
            let ring = members.iter().map(|m| [theirs(&m.key), theirs(&m.commitment)]).collect();
            signature
                .verify(ring, &theirs(&image), &theirs(&pseudo_out), &message)
                .unwrap_or_else(|e| panic!("ring of {n}, signer {real}: {e:?}"));

            let again =
                sign::clsag(&members, real, &secret, &(mask - pseudo_mask), &pseudo_out, &message, &aux)
                    .unwrap();
            assert_eq!(again, (clsag.clone(), image));
            let fresh = sign::clsag(
                &members,
                real,
                &secret,
                &(mask - pseudo_mask),
                &pseudo_out,
                &message,
                &random.bytes(),
            )
            .unwrap();
            assert_ne!(fresh.0, clsag);
        }
    }
}

#[test]
fn a_clsag_isnt_made_for_the_wrong_key_amount_or_member() {
    let mut random = Random(0xbad_5eed);
    let secret = random.scalar();
    let (mask, amount) = (random.scalar(), 1_000_000);
    let pseudo_mask = random.scalar();
    let members = ring(&mut random, 16, 5, G * secret, sign::commit(&mask, amount));
    let difference = mask - pseudo_mask;
    let sign = |real, secret: &Scalar, pseudo_out: &EdwardsPoint| {
        sign::clsag(&members, real, secret, &difference, pseudo_out, &[7; 32], &[0; 32]).map(|_| ())
    };
    let pseudo_out = sign::commit(&pseudo_mask, amount);
    assert_eq!(sign(5, &secret, &pseudo_out), Ok(()));
    assert_eq!(sign(4, &secret, &pseudo_out), Err(SignError::Key));
    assert_eq!(sign(5, &random.scalar(), &pseudo_out), Err(SignError::Key));
    assert_eq!(sign(16, &secret, &pseudo_out), Err(SignError::Ring));
    // a pseudo-output of another amount
    assert_eq!(sign(5, &secret, &sign::commit(&pseudo_mask, amount + 1)), Err(SignError::Commitment));
    assert_eq!(
        sign::clsag(&[], 0, &secret, &difference, &pseudo_out, &[7; 32], &[0; 32]).map(|_| ()),
        Err(SignError::Ring)
    );
}
