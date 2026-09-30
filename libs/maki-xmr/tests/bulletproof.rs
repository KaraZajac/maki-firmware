//! Range proofs maki makes, checked by monero-oxide's verifier.
use curve25519_dalek::scalar::Scalar;
use maki_xmr::bulletproof::{self, Generators, MAX_OUTPUTS};
use maki_xmr::sign;
use monero_bulletproofs::Bulletproof;
use monero_ed25519::CompressedPoint;
use rand_core::OsRng;

/// Numbers from a seed, the same every run.
struct Random(u64);

impl Random {
    fn u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn scalar(&mut self) -> Scalar {
        let mut wide = [0u8; 64];
        for chunk in wide.chunks_mut(8) {
            chunk.copy_from_slice(&self.u64().to_le_bytes());
        }
        Scalar::from_bytes_mod_order_wide(&wide)
    }
}

fn commitments(outputs: &[(u64, Scalar)]) -> Vec<CompressedPoint> {
    outputs
        .iter()
        .map(|(amount, mask)| CompressedPoint::from(sign::commit(mask, *amount).compress().to_bytes()))
        .collect()
}

fn verifies(proof: &[u8], outputs: &[(u64, Scalar)]) -> bool {
    match Bulletproof::read_plus(&mut &proof[..]) {
        Ok(proof) => proof.verify(&mut OsRng, &commitments(outputs)),
        Err(_) => false,
    }
}

#[test]
fn monero_oxide_verifies_the_range_proofs() {
    let mut random = Random(0xb9_91u64 << 20);
    let mut generators = Generators::new();
    for m in [1, 2, 3, 4, 5, 8, MAX_OUTPUTS] {
        let outputs: Vec<(u64, Scalar)> = (0..m)
            .map(|i| {
                let amount = match i {
                    0 => 0,
                    1 => u64::MAX,
                    _ => random.u64() >> (i % 7 * 9),
                };
                (amount, random.scalar())
            })
            .collect();
        let mut nonces = Random(m as u64 + 7);
        let proof = bulletproof::prove(&mut generators, &outputs, &mut || nonces.scalar()).unwrap();
        let bytes = proof.to_bytes();
        assert_eq!(
            bytes.len(),
            6 * 32 + 2 * (1 + 32 * (6 + m.next_power_of_two().trailing_zeros() as usize)),
            "{m}"
        );
        assert!(verifies(&bytes, &outputs), "{m} outputs");

        // another amount, or a changed proof, doesn't
        let mut other = outputs.clone();
        other[m - 1].0 ^= 1;
        assert!(!verifies(&bytes, &other), "{m}: another amount");
        let mut changed = bytes.clone();
        changed[3 * 32 + 5] ^= 1;
        assert!(!verifies(&changed, &outputs), "{m}: a changed proof");
    }
}

#[test]
fn no_outputs_or_too_many_get_no_proof() {
    let mut generators = Generators::new();
    let mut random = Random(3);
    assert!(bulletproof::prove(&mut generators, &[], &mut || random.scalar()).is_none());
    let outputs = vec![(1, Scalar::ONE); MAX_OUTPUTS + 1];
    assert!(bulletproof::prove(&mut generators, &outputs, &mut || random.scalar()).is_none());
}
