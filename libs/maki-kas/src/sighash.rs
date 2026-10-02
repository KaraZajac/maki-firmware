// Ported from rusty-kaspa v2.1.0 (consensus/core/src/hashing/sighash.rs and sighash_type.rs),
// under the ISC License:
//   Copyright (c) 2022-2024 Kaspa developers
// The license's text is LICENSE-rusty-kaspa, beside this crate's Cargo.toml.

//! Kaspa's signature hash: what an input's Schnorr signature signs, as rusty-kaspa computes it
//! (`calc_schnorr_signature_hash`), for each of the signature hash types consensus allows. maki
//! signs SIGHASH_ALL alone; the others are here to be held to rusty-kaspa's own test vectors.
//!
//! The hash covers the transaction's version, every input's coin (unless ANYONECANPAY), sequence
//! and (before version 1) signature check count, this input's coin, the script and amount it holds,
//! its sequence and count, the outputs, the lock time, the subnetwork, the gas, the payload, and the
//! hash type. It covers no other input's amount: each signature vouches for its own coin's alone.

use crate::hash::Hasher;
use crate::request::{Output, Request, Script};

/// Which parts of a transaction a signature covers, the last byte of every Kaspa signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigHashType(u8);

/// Every output, every input.
pub const SIG_HASH_ALL: SigHashType = SigHashType(0b0000_0001);
/// No output.
pub const SIG_HASH_NONE: SigHashType = SigHashType(0b0000_0010);
/// The output at the input's own index.
pub const SIG_HASH_SINGLE: SigHashType = SigHashType(0b0000_0100);
/// This input alone, with any of the above.
pub const SIG_HASH_ANY_ONE_CAN_PAY: SigHashType = SigHashType(0b1000_0000);

const MASK: u8 = 0b0000_0111;

impl SigHashType {
    /// One of the six types consensus allows, or None.
    pub fn from_u8(byte: u8) -> Option<SigHashType> {
        let allowed = [0x01, 0x02, 0x04, 0x81, 0x82, 0x84];
        allowed.contains(&byte).then_some(SigHashType(byte))
    }

    pub fn to_u8(self) -> u8 { self.0 }

    fn is_none(self) -> bool { self.0 & MASK == SIG_HASH_NONE.0 }

    fn is_single(self) -> bool { self.0 & MASK == SIG_HASH_SINGLE.0 }

    fn is_anyone_can_pay(self) -> bool { self.0 & SIG_HASH_ANY_ONE_CAN_PAY.0 != 0 }
}

/// The hashes every input's signature hash shares, made once a transaction (rusty-kaspa's
/// `SigHashReusedValues`): hashing them again for each input would take time to the square of
/// the inputs.
#[derive(Default)]
pub struct Reused {
    previous_outputs: Option<[u8; 32]>,
    sequences: Option<[u8; 32]>,
    sig_op_counts: Option<[u8; 32]>,
    outputs: Option<[u8; 32]>,
    payload: Option<[u8; 32]>,
}

fn reuse(slot: &mut Option<[u8; 32]>, make: impl FnOnce() -> [u8; 32]) -> [u8; 32] {
    *slot.get_or_insert_with(make)
}

fn previous_outputs_hash(tx: &Request, hash_type: SigHashType, reused: &mut Reused) -> [u8; 32] {
    if hash_type.is_anyone_can_pay() {
        return [0; 32];
    }
    reuse(&mut reused.previous_outputs, || {
        let mut h = Hasher::signing();
        for input in &tx.inputs {
            h.bytes(&input.txid).u32(input.index);
        }
        h.finish()
    })
}

fn sequences_hash(tx: &Request, hash_type: SigHashType, reused: &mut Reused) -> [u8; 32] {
    if hash_type.is_single() || hash_type.is_anyone_can_pay() || hash_type.is_none() {
        return [0; 32];
    }
    reuse(&mut reused.sequences, || {
        let mut h = Hasher::signing();
        for input in &tx.inputs {
            h.u64(input.sequence);
        }
        h.finish()
    })
}

fn sig_op_counts_hash(tx: &Request, hash_type: SigHashType, reused: &mut Reused) -> [u8; 32] {
    if hash_type.is_anyone_can_pay() {
        return [0; 32];
    }
    reuse(&mut reused.sig_op_counts, || {
        let mut h = Hasher::signing();
        for input in &tx.inputs {
            h.u8(input.sig_op_count);
        }
        h.finish()
    })
}

fn payload_hash(tx: &Request, reused: &mut Reused) -> [u8; 32] {
    if tx.subnetwork == crate::request::NATIVE && tx.payload.is_empty() {
        return [0; 32];
    }
    reuse(&mut reused.payload, || {
        let mut h = Hasher::signing();
        h.var_bytes(&tx.payload);
        h.finish()
    })
}

fn outputs_hash(tx: &Request, hash_type: SigHashType, reused: &mut Reused, input: usize) -> [u8; 32] {
    if hash_type.is_none() {
        return [0; 32];
    }
    if hash_type.is_single() {
        // the output at the input's index, or nothing if there's none
        let Some(output) = tx.outputs.get(input) else { return [0; 32] };
        let mut h = Hasher::signing();
        hash_output(&mut h, output, tx.version);
        return h.finish();
    }
    reuse(&mut reused.outputs, || {
        let mut h = Hasher::signing();
        for output in &tx.outputs {
            hash_output(&mut h, output, tx.version);
        }
        h.finish()
    })
}

fn hash_output(h: &mut Hasher, output: &Output, version: u16) {
    h.u64(output.value);
    hash_script(h, &output.script);
    // from version 1, whether it's bound to a covenant: none that maki signs is
    if version >= 1 {
        h.u8(0);
    }
}

fn hash_script(h: &mut Hasher, script: &Script) { h.u16(script.version).var_bytes(&script.script); }

/// The hash input `input`'s signature signs, as `hash_type` has it; None for an input the
/// transaction hasn't. `reused` keeps what every input's shares: one for each transaction.
pub fn signature_hash(
    tx: &Request,
    input: usize,
    hash_type: SigHashType,
    reused: &mut Reused,
) -> Option<[u8; 32]> {
    let this = tx.inputs.get(input)?;
    let mut h = Hasher::signing();
    h.u16(tx.version)
        .bytes(&previous_outputs_hash(tx, hash_type, reused))
        .bytes(&sequences_hash(tx, hash_type, reused));
    if tx.version < 1 {
        h.bytes(&sig_op_counts_hash(tx, hash_type, reused));
    }
    h.bytes(&this.txid).u32(this.index);
    hash_script(&mut h, &this.script);
    h.u64(this.amount).u64(this.sequence);
    if tx.version < 1 {
        h.u8(this.sig_op_count);
    }
    h.bytes(&outputs_hash(tx, hash_type, reused, input))
        .u64(tx.lock_time)
        .bytes(&tx.subnetwork)
        .u64(tx.gas)
        .bytes(&payload_hash(tx, reused))
        .u8(hash_type.to_u8());
    Some(h.finish())
}
