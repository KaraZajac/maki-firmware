//! A Monero transaction as maki makes one: version 2, RingCT type 6 (CLSAG and Bulletproofs+),
//! its outputs with view tags, as hard fork 16 has them. Its bytes and hashes, and reading one
//! back. No curve work here, just the encoding: points and scalars are their 32 bytes.

use alloc::vec::Vec;

use crate::keccak;

/// RingCT's type for CLSAG and Bulletproofs+.
pub const RCT_TYPE: u8 = 6;

/// An input: the ring (each member's global output index, as offsets from the one before, the
/// first from 0) and the spent output's key image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub key_offsets: Vec<u64>,
    pub key_image: [u8; 32],
}

/// An output: its one-time key and view tag (its amount is RingCT's, 0 here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub key: [u8; 32],
    pub view_tag: u8,
}

/// What the transaction's hash starts with, and the outputs' keys: everything but RingCT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub unlock_time: u64,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub extra: Vec<u8>,
}

/// RingCT's part the signatures cover: the fee, the outputs' amounts (encrypted) and commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Base {
    pub fee: u64,
    pub encrypted_amounts: Vec<[u8; 8]>,
    pub commitments: Vec<[u8; 32]>,
}

/// A Bulletproof+, as a transaction carries it.
#[allow(non_snake_case)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeProof {
    pub A: [u8; 32],
    pub A1: [u8; 32],
    pub B: [u8; 32],
    pub r1: [u8; 32],
    pub s1: [u8; 32],
    pub d1: [u8; 32],
    pub L: Vec<[u8; 32]>,
    pub R: Vec<[u8; 32]>,
}

/// A whole transaction: `clsags` are each input's signature's bytes (s, c1, D), and
/// `pseudo_outs` each input's pseudo-output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub prefix: Prefix,
    pub base: Base,
    pub proof: RangeProof,
    pub clsags: Vec<Vec<u8>>,
    pub pseudo_outs: Vec<[u8; 32]>,
}

/// `n` as Monero writes numbers: 7 bits a byte, low first, the top bit saying more follow.
pub fn varint(mut n: u64, out: &mut Vec<u8>) {
    while n >= 0x80 {
        out.push((n as u8) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

impl Prefix {
    /// Its bytes, the transaction's version (2) first.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.inputs.len() * 64 + self.outputs.len() * 40 + self.extra.len());
        varint(2, &mut out);
        varint(self.unlock_time, &mut out);
        varint(self.inputs.len() as u64, &mut out);
        for input in &self.inputs {
            // txin_to_key, of amount 0
            out.extend_from_slice(&[2, 0]);
            varint(input.key_offsets.len() as u64, &mut out);
            input.key_offsets.iter().for_each(|o| varint(*o, &mut out));
            out.extend_from_slice(&input.key_image);
        }
        varint(self.outputs.len() as u64, &mut out);
        for output in &self.outputs {
            // amount 0, then txout_to_tagged_key
            out.extend_from_slice(&[0, 3]);
            out.extend_from_slice(&output.key);
            out.push(output.view_tag);
        }
        varint(self.extra.len() as u64, &mut out);
        out.extend_from_slice(&self.extra);
        out
    }

    pub fn hash(&self) -> [u8; 32] { keccak(&self.to_bytes()) }
}

impl Base {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 40 * self.commitments.len());
        out.push(RCT_TYPE);
        varint(self.fee, &mut out);
        self.encrypted_amounts.iter().for_each(|a| out.extend_from_slice(a));
        self.commitments.iter().for_each(|c| out.extend_from_slice(c));
        out
    }

    pub fn hash(&self) -> [u8; 32] { keccak(&self.to_bytes()) }
}

impl RangeProof {
    /// Its bytes in a transaction: A, A1, B, r1, s1, d1, then L and R, each counted.
    pub fn to_bytes(&self) -> Vec<u8> { self.bytes(true) }

    /// Its bytes in the message the signatures sign: the same, L and R uncounted.
    pub fn message_bytes(&self) -> Vec<u8> { self.bytes(false) }

    fn bytes(&self, counted: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 * 32 + 2 * 32 * self.L.len() + 4);
        for part in [&self.A, &self.A1, &self.B, &self.r1, &self.s1, &self.d1] {
            out.extend_from_slice(part);
        }
        for points in [&self.L, &self.R] {
            if counted {
                varint(points.len() as u64, &mut out);
            }
            points.iter().for_each(|p| out.extend_from_slice(p));
        }
        out
    }
}

/// What each input's CLSAG signs (`get_pre_mlsag_hash`): the prefix's hash, the base's, and the
/// range proof's (its message bytes).
pub fn signature_hash(prefix: &Prefix, base: &Base, proof: &RangeProof) -> [u8; 32] {
    let mut hashes = Vec::with_capacity(96);
    hashes.extend_from_slice(&prefix.hash());
    hashes.extend_from_slice(&base.hash());
    hashes.extend_from_slice(&keccak(&proof.message_bytes()));
    keccak(&hashes)
}

impl Transaction {
    /// RingCT's prunable part: the range proof, the signatures and the pseudo-outputs.
    fn prunable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1024);
        // one range proof, for all the outputs
        varint(1, &mut out);
        out.extend_from_slice(&self.proof.to_bytes());
        self.clsags.iter().for_each(|c| out.extend_from_slice(c));
        self.pseudo_outs.iter().for_each(|p| out.extend_from_slice(p));
        out
    }

    /// Its bytes, as the network takes them.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.prefix.to_bytes();
        out.extend_from_slice(&self.base.to_bytes());
        out.extend_from_slice(&self.prunable_bytes());
        out
    }

    /// Its hash, its ID: of the prefix's hash, the base's and the prunable part's.
    pub fn hash(&self) -> [u8; 32] {
        let mut hashes = Vec::with_capacity(96);
        hashes.extend_from_slice(&self.prefix.hash());
        hashes.extend_from_slice(&self.base.hash());
        hashes.extend_from_slice(&keccak(&self.prunable_bytes()));
        keccak(&hashes)
    }

    /// What its signatures sign.
    pub fn signature_hash(&self) -> [u8; 32] { signature_hash(&self.prefix, &self.base, &self.proof) }

    /// One as `to_bytes` writes it (a ring of `ring` for each input), or None: a transaction of
    /// another kind, or bytes that aren't one.
    pub fn from_bytes(bytes: &[u8]) -> Option<Transaction> {
        let mut r = Reader(bytes);
        if r.varint()? != 2 {
            return None;
        }
        let unlock_time = r.varint()?;
        let mut inputs = Vec::new();
        for _ in 0..r.count(64)? {
            if r.byte()? != 2 || r.varint()? != 0 {
                return None;
            }
            let n = r.count(128)?;
            let key_offsets = (0..n).map(|_| r.varint()).collect::<Option<Vec<_>>>()?;
            inputs.push(Input { key_offsets, key_image: r.bytes32()? });
        }
        let mut outputs = Vec::new();
        for _ in 0..r.count(16)? {
            if r.varint()? != 0 || r.byte()? != 3 {
                return None;
            }
            outputs.push(Output { key: r.bytes32()?, view_tag: r.byte()? });
        }
        let n = r.count(1 << 16)?;
        let extra = r.take(n)?.to_vec();
        if r.byte()? != RCT_TYPE {
            return None;
        }
        let fee = r.varint()?;
        let encrypted_amounts = (0..outputs.len()).map(|_| r.take(8).map(|a| a.try_into().unwrap())).collect::<Option<_>>()?;
        let commitments = (0..outputs.len()).map(|_| r.bytes32()).collect::<Option<_>>()?;
        if r.varint()? != 1 {
            return None;
        }
        let mut proof = RangeProof {
            A: r.bytes32()?,
            A1: r.bytes32()?,
            B: r.bytes32()?,
            r1: r.bytes32()?,
            s1: r.bytes32()?,
            d1: r.bytes32()?,
            L: Vec::new(),
            R: Vec::new(),
        };
        let n = r.count(16)?;
        proof.L = (0..n).map(|_| r.bytes32()).collect::<Option<_>>()?;
        let n = r.count(16)?;
        proof.R = (0..n).map(|_| r.bytes32()).collect::<Option<_>>()?;
        let clsags = inputs.iter().map(|i| r.take(32 * (i.key_offsets.len() + 2)).map(|c| c.to_vec())).collect::<Option<_>>()?;
        let pseudo_outs = (0..inputs.len()).map(|_| r.bytes32()).collect::<Option<_>>()?;
        if !r.0.is_empty() {
            return None;
        }
        Some(Transaction {
            prefix: Prefix { unlock_time, inputs, outputs, extra },
            base: Base { fee, encrypted_amounts, commitments },
            proof,
            clsags,
            pseudo_outs,
        })
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        if self.0.len() < n {
            return None;
        }
        let (taken, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(taken)
    }

    fn byte(&mut self) -> Option<u8> { self.take(1).map(|b| b[0]) }

    fn bytes32(&mut self) -> Option<[u8; 32]> { self.take(32).map(|b| b.try_into().unwrap()) }

    fn varint(&mut self) -> Option<u64> {
        let mut n: u64 = 0;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            if shift == 63 && b > 1 {
                return None;
            }
            n |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                // the shortest way to write it only
                return (b != 0 || shift == 0).then_some(n);
            }
        }
        None
    }

    /// A count of at most `most`.
    fn count(&mut self, most: u64) -> Option<usize> { self.varint().filter(|n| *n <= most).map(|n| n as usize) }
}
