//! What each input's signature signs: ZIP-244's signature digest, a tree of personalized BLAKE2b-256
//! hashes over the transaction's parts, as zcashd, zebrad and librustzcash work it out. For a
//! transparent input it commits to the header (the consensus branch among it), every input's coin
//! and sequence, every coin's amount and script, every output, and the input being signed; the
//! shielded parts, which maki's transactions have none of, are the hashes of nothing under their
//! names. And the transaction's ID, the same tree with the transparent parts as the ID has them.

use alloc::vec::Vec;

use crate::hash::{Hasher, blake2b};
use crate::tx::{Transaction, TxIn, TxOut, VERSION_5, VERSION_GROUP, write_compact};

/// The one hash type maki signs: every input, every output.
pub const SIGHASH_ALL: u8 = 1;

/// The tree's nodes' personalizations (ZIP-244).
pub const HEADERS: &[u8; 16] = b"ZTxIdHeadersHash";
pub const TRANSPARENT: &[u8; 16] = b"ZTxIdTranspaHash";
pub const PREVOUTS: &[u8; 16] = b"ZTxIdPrevoutHash";
pub const SEQUENCES: &[u8; 16] = b"ZTxIdSequencHash";
pub const OUTPUTS: &[u8; 16] = b"ZTxIdOutputsHash";
pub const AMOUNTS: &[u8; 16] = b"ZTxTrAmountsHash";
pub const SCRIPTS: &[u8; 16] = b"ZTxTrScriptsHash";
pub const TXIN: &[u8; 16] = b"Zcash___TxInHash";
pub const SAPLING: &[u8; 16] = b"ZTxIdSaplingHash";
pub const ORCHARD: &[u8; 16] = b"ZTxIdOrchardHash";

/// What an input spends, as its signature commits to it: the coin's amount and script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spent<'a> {
    pub amount: u64,
    pub script: &'a [u8],
}

/// The header's digest (T.1): version 5 and its group, the consensus branch, the lock time, the
/// expiry height.
pub fn header_digest(branch_id: u32, lock_time: u32, expiry_height: u32) -> [u8; 32] {
    let mut h = Hasher::new(HEADERS);
    for n in [VERSION_5, VERSION_GROUP, branch_id, lock_time, expiry_height] {
        h.update(&n.to_le_bytes());
    }
    h.finish()
}

fn prevouts_digest(inputs: &[TxIn]) -> [u8; 32] {
    let mut h = Hasher::new(PREVOUTS);
    for i in inputs {
        h.update(&i.txid).update(&i.index.to_le_bytes());
    }
    h.finish()
}

fn sequences_digest(inputs: &[TxIn]) -> [u8; 32] {
    let mut h = Hasher::new(SEQUENCES);
    for i in inputs {
        h.update(&i.sequence.to_le_bytes());
    }
    h.finish()
}

fn outputs_digest(outputs: &[TxOut]) -> [u8; 32] {
    let mut h = Hasher::new(OUTPUTS);
    let mut buf = Vec::new();
    for o in outputs {
        buf.clear();
        o.write(&mut buf);
        h.update(&buf);
    }
    h.finish()
}

/// A script as a transaction writes it: after its length.
fn script_field(script: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(script.len() + 3);
    write_compact(&mut out, script.len());
    out.extend_from_slice(script);
    out
}

/// The transparent parts' digest as the transaction's ID has it (T.2): the coins spent, the
/// sequences, the outputs; with none of either, the hash of nothing.
pub fn transparent_digest(inputs: &[TxIn], outputs: &[TxOut]) -> [u8; 32] {
    if inputs.is_empty() && outputs.is_empty() {
        return blake2b(TRANSPARENT, &[]);
    }
    let mut h = Hasher::new(TRANSPARENT);
    h.update(&prevouts_digest(inputs)).update(&sequences_digest(inputs)).update(&outputs_digest(outputs));
    h.finish()
}

/// The digests every input's signature shares, worked out once: the coins, their amounts and
/// scripts, the sequences, the outputs.
pub struct Shared {
    prevouts: [u8; 32],
    amounts: [u8; 32],
    scripts: [u8; 32],
    sequences: [u8; 32],
    outputs: [u8; 32],
}

impl Shared {
    /// For a transaction's transparent parts, `spent` being what each input spends, in order.
    pub fn new(inputs: &[TxIn], outputs: &[TxOut], spent: &[Spent]) -> Shared {
        let mut amounts = Hasher::new(AMOUNTS);
        let mut scripts = Hasher::new(SCRIPTS);
        for s in spent {
            amounts.update(&s.amount.to_le_bytes());
            scripts.update(&script_field(s.script));
        }
        Shared {
            prevouts: prevouts_digest(inputs),
            amounts: amounts.finish(),
            scripts: scripts.finish(),
            sequences: sequences_digest(inputs),
            outputs: outputs_digest(outputs),
        }
    }

    /// The transparent parts' digest for input `i`'s signature, SIGHASH_ALL (S.2): the hash type,
    /// the shared digests, then the input's own: its coin, the amount and script it spends, its
    /// sequence. None if there's no input `i`, or nothing said of what it spends.
    pub fn transparent_sig_digest(&self, inputs: &[TxIn], spent: &[Spent], i: usize) -> Option<[u8; 32]> {
        let (input, s) = (inputs.get(i)?, spent.get(i)?);
        let mut txin = Hasher::new(TXIN);
        txin.update(&input.txid)
            .update(&input.index.to_le_bytes())
            .update(&s.amount.to_le_bytes())
            .update(&script_field(s.script))
            .update(&input.sequence.to_le_bytes());
        let mut h = Hasher::new(TRANSPARENT);
        h.update(&[SIGHASH_ALL])
            .update(&self.prevouts)
            .update(&self.amounts)
            .update(&self.scripts)
            .update(&self.sequences)
            .update(&self.outputs)
            .update(&txin.finish());
        Some(h.finish())
    }
}

/// The tree's root, for the transaction's ID or a signature: its four parts' digests, under a name
/// that ends with the consensus branch (T and S).
pub fn root(
    branch_id: u32,
    header: &[u8; 32],
    transparent: &[u8; 32],
    sapling: &[u8; 32],
    orchard: &[u8; 32],
) -> [u8; 32] {
    let mut personal = *b"ZcashTxHash_\0\0\0\0";
    personal[12..].copy_from_slice(&branch_id.to_le_bytes());
    let mut h = Hasher::new(&personal);
    h.update(header).update(transparent).update(sapling).update(orchard);
    h.finish()
}

/// The transaction's ID, its bytes as Zcash hashes them (explorers show them reversed). It doesn't
/// change when the transaction is signed.
pub fn txid(tx: &Transaction) -> [u8; 32] {
    root(
        tx.branch_id,
        &header_digest(tx.branch_id, tx.lock_time, tx.expiry_height),
        &transparent_digest(&tx.inputs, &tx.outputs),
        &blake2b(SAPLING, &[]),
        &blake2b(ORCHARD, &[]),
    )
}

/// What each input's signature signs, worked out with what they share made once.
pub struct Signing<'t> {
    tx: &'t Transaction,
    spent: Vec<Spent<'t>>,
    header: [u8; 32],
    shared: Shared,
    sapling: [u8; 32],
    orchard: [u8; 32],
}

impl<'t> Signing<'t> {
    /// For a transaction, `spent` being what each of its inputs spends.
    pub fn new(tx: &'t Transaction, spent: Vec<Spent<'t>>) -> Signing<'t> {
        Signing {
            tx,
            header: header_digest(tx.branch_id, tx.lock_time, tx.expiry_height),
            shared: Shared::new(&tx.inputs, &tx.outputs, &spent),
            spent,
            sapling: blake2b(SAPLING, &[]),
            orchard: blake2b(ORCHARD, &[]),
        }
    }

    /// The digest input `i`'s signature signs, SIGHASH_ALL; None if there's no input `i`.
    pub fn signature_hash(&self, i: usize) -> Option<[u8; 32]> {
        let transparent = self.shared.transparent_sig_digest(&self.tx.inputs, &self.spent, i)?;
        Some(root(self.tx.branch_id, &self.header, &transparent, &self.sapling, &self.orchard))
    }
}
