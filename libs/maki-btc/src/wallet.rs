//! The account, and the two things done with a PSBT: review it, then sign it.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};

use crate::address::{describe, p2wpkh_address, p2wpkh_script, Network};
use crate::bip32::{Xpriv, HARDENED};
use crate::hash::{hash160, sha256d};
use crate::psbt::{self, parse_derivation, Psbt};
use crate::tx::{write_varint, Tx, TxOut};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Key,
    Psbt(&'static str),
    /// This input isn't this wallet's: no derivation of ours, or one that doesn't match.
    NotOurs(usize),
    /// This input doesn't come with the transaction it spends.
    NoPreviousTx(usize),
    /// The transaction it came with isn't the one the input spends, or disagrees with the amount
    /// or script the PSBT claims.
    PreviousTxMismatch(usize),
    /// Asks for a signature other than SIGHASH_ALL.
    Sighash(usize),
    /// Spends a taproot output: not yet.
    Taproot(usize),
    /// The outputs pay more than the inputs hold.
    NegativeFee,
    /// An amount beyond the 21 million bitcoin there will ever be.
    Amount,
}

impl core::fmt::Display for Error {
    /// Why maki won't sign, for the computer to show.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Key => write!(f, "couldn't derive this wallet's keys"),
            Error::Psbt(why) => write!(f, "not a PSBT maki can read: {}", why),
            Error::NotOurs(i) => write!(f, "input {} isn't this wallet's (maki signs for its BIP84 account 0, native SegWit)", i),
            Error::NoPreviousTx(i) => {
                write!(f, "input {} doesn't come with the transaction it spends (the PSBT needs non_witness_utxo)", i)
            }
            Error::PreviousTxMismatch(i) => write!(f, "input {}'s previous transaction isn't the one it spends", i),
            Error::Sighash(i) => write!(f, "input {} asks for a signature other than SIGHASH_ALL", i),
            Error::Taproot(i) => write!(f, "input {} is taproot, which maki doesn't sign yet", i),
            Error::NegativeFee => write!(f, "the outputs pay more than the inputs hold"),
            Error::Amount => write!(f, "an amount is beyond 21 million bitcoin"),
        }
    }
}

/// Satoshis in 21 million bitcoin: no amount can be larger.
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

fn total(mut amounts: impl Iterator<Item = u64>) -> Result<u64, Error> {
    amounts.try_fold(0u64, |sum, a| sum.checked_add(a).filter(|&s| a <= MAX_MONEY && s <= MAX_MONEY)).ok_or(Error::Amount)
}

/// BIP84, account 0: `m/84'/coin'/0'`.
#[derive(Clone)]
pub struct Account {
    pub network: Network,
    pub master_fingerprint: [u8; 4],
    key: Xpriv,
    /// the receiving chain (`/0`) and the change chain (`/1`), derived once
    chains: [Xpriv; 2],
}

impl Account {
    pub fn from_seed(seed: &[u8], network: Network) -> Result<Account, Error> {
        let master = Xpriv::master(seed).map_err(|_| Error::Key)?;
        let key = master.derive(&[84 | HARDENED, network.coin_type() | HARDENED, HARDENED]).map_err(|_| Error::Key)?;
        let chains = [key.child(0).map_err(|_| Error::Key)?, key.child(1).map_err(|_| Error::Key)?];
        Ok(Account { network, master_fingerprint: master.fingerprint(), key, chains })
    }

    fn path(&self) -> [u32; 3] { [84 | HARDENED, self.network.coin_type() | HARDENED, HARDENED] }

    fn key_at(&self, change: bool, index: u32) -> Result<Xpriv, Error> {
        if index >= HARDENED {
            return Err(Error::Key);
        }
        self.chains[change as usize].child(index).map_err(|_| Error::Key)
    }

    /// A receiving (or change) address, to show on maki's screen and check against the computer.
    pub fn address(&self, change: bool, index: u32) -> Result<String, Error> {
        Ok(p2wpkh_address(&self.key_at(change, index)?.public_key(), self.network))
    }

    /// The account key in the form BIP84 wallets take: zpub (vpub on test networks).
    pub fn zpub(&self) -> String { self.key.xpub(self.network.zpub_version()) }

    /// An output descriptor for wallet software (Sparrow, Bitcoin Core): both chains, with the
    /// master key's fingerprint and path so it knows maki can sign for them.
    pub fn descriptor(&self) -> String {
        let fp: String = self.master_fingerprint.iter().map(|b| format!("{:02x}", b)).collect();
        let coin = self.network.coin_type();
        let body = format!("wpkh([{}/84h/{}h/0h]{}/<0;1>/*)", fp, coin, self.key.xpub(self.network.xpub_version()));
        format!("{}#{}", body, descriptor_checksum(&body))
    }

    /// Whose key a derivation names: ours, and one we can make, or not.
    fn ours(&self, derivation: &[u8], public_key: &[u8]) -> Option<Xpriv> {
        let (fp, path) = parse_derivation(derivation)?;
        if fp != self.master_fingerprint || path.len() != 5 || path[..3] != self.path() || path[3] > 1 {
            return None;
        }
        let key = self.key_at(path[3] == 1, path[4]).ok()?;
        (key.public_key()[..] == *public_key).then_some(key)
    }
}

/// What a transaction does, as maki shows it before signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    pub network: Network,
    /// every output, in order; change is marked, everything else is a payment
    pub outputs: Vec<Output>,
    pub fee: u64,
    /// the transaction's size once signed, in virtual bytes (for the fee rate)
    pub vbytes: u64,
    pub inputs: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub address: String,
    pub amount: u64,
    /// back to this wallet
    pub change: bool,
}

impl Review {
    /// Satoshis per virtual byte, rounded up.
    pub fn fee_rate(&self) -> u64 { self.fee.div_ceil(self.vbytes.max(1)) }
}

/// An input of ours: its key, and the output it spends.
struct Spend {
    key: Xpriv,
    spent: TxOut,
}

/// Check every input, and work out what each one spends.
fn spends(psbt: &Psbt, account: &Account) -> Result<Vec<Spend>, Error> {
    let mut out = Vec::with_capacity(psbt.tx.inputs.len());
    for (i, input) in psbt.tx.inputs.iter().enumerate() {
        if psbt.inputs[i].iter().any(|p| matches!(p.key.first(), Some(&psbt::IN_TAP_KEY_SIG | &psbt::IN_TAP_BIP32_DERIVATION))) {
            return Err(Error::Taproot(i));
        }
        // the whole previous transaction: amounts are never taken on the PSBT's word
        let prev = psbt.input(i, psbt::IN_NON_WITNESS_UTXO).ok_or(Error::NoPreviousTx(i))?;
        let prev = Tx::parse(prev).map_err(|_| Error::PreviousTxMismatch(i))?;
        if prev.txid() != input.prev_txid {
            return Err(Error::PreviousTxMismatch(i));
        }
        let spent = prev.outputs.get(input.prev_vout as usize).ok_or(Error::PreviousTxMismatch(i))?.clone();
        if let Some(w) = psbt.input(i, psbt::IN_WITNESS_UTXO) {
            let mut claimed = Vec::new();
            spent.write(&mut claimed);
            if w != claimed {
                return Err(Error::PreviousTxMismatch(i));
            }
        }
        if let Some(t) = psbt.input(i, psbt::IN_SIGHASH_TYPE) {
            if t != [1, 0, 0, 0] {
                return Err(Error::Sighash(i));
            }
        }
        let key = psbt.inputs[i]
            .iter()
            .filter(|p| p.key.first() == Some(&psbt::IN_BIP32_DERIVATION) && p.key.len() == 34)
            .find_map(|p| account.ours(&p.value, &p.key[1..]))
            .ok_or(Error::NotOurs(i))?;
        if p2wpkh_script(&key.public_key()) != spent.script_pubkey {
            return Err(Error::NotOurs(i));
        }
        out.push(Spend { key, spent });
    }
    Ok(out)
}

/// What the transaction does, checked: every input this wallet's, amounts from the transactions
/// they spend, change only where it derives from this wallet's change chain.
pub fn review(psbt: &Psbt, account: &Account) -> Result<Review, Error> { check(psbt, account).map(|(review, _)| review) }

fn check(psbt: &Psbt, account: &Account) -> Result<(Review, Vec<Spend>), Error> {
    if psbt.tx.inputs.is_empty() || psbt.tx.outputs.is_empty() {
        return Err(Error::Psbt("a transaction needs inputs and outputs"));
    }
    let spends = spends(psbt, account)?;
    let total_in = total(spends.iter().map(|s| s.spent.value))?;
    let total_out = total(psbt.tx.outputs.iter().map(|o| o.value))?;
    let fee = total_in.checked_sub(total_out).ok_or(Error::NegativeFee)?;
    let outputs = psbt
        .tx
        .outputs
        .iter()
        .enumerate()
        .map(|(j, o)| {
            let change = psbt.outputs[j].iter().any(|p| {
                p.key.first() == Some(&psbt::OUT_BIP32_DERIVATION)
                    && p.key.len() == 34
                    && parse_derivation(&p.value).map(|(_, path)| path.get(3) == Some(&1)).unwrap_or(false)
                    && account.ours(&p.value, &p.key[1..]).map(|k| p2wpkh_script(&k.public_key()) == o.script_pubkey).unwrap_or(false)
            });
            Output { address: describe(&o.script_pubkey, account.network), amount: o.value, change }
        })
        .collect();
    // signed size: the transaction, plus marker, flag and a P2WPKH witness per input (the
    // largest a low-S signature makes it)
    let weight = psbt.tx.serialize().len() as u64 * 4 + 2 + spends.len() as u64 * (1 + 1 + 72 + 1 + 33);
    let review = Review { network: account.network, outputs, fee, vbytes: weight.div_ceil(4), inputs: spends.len() };
    Ok((review, spends))
}

/// BIP143: the digest a P2WPKH input signs, SIGHASH_ALL.
fn sighash(tx: &Tx, i: usize, public_key: &[u8; 33], amount: u64) -> [u8; 32] {
    let mut prevouts = Vec::new();
    let mut sequences = Vec::new();
    for input in &tx.inputs {
        prevouts.extend_from_slice(&input.prev_txid);
        prevouts.extend_from_slice(&input.prev_vout.to_le_bytes());
        sequences.extend_from_slice(&input.sequence.to_le_bytes());
    }
    let mut outputs = Vec::new();
    for o in &tx.outputs {
        o.write(&mut outputs);
    }
    let input = &tx.inputs[i];
    let mut script_code = Vec::with_capacity(26);
    script_code.extend_from_slice(&[0x76, 0xa9, 0x14]);
    script_code.extend_from_slice(&hash160(public_key));
    script_code.extend_from_slice(&[0x88, 0xac]);

    let mut pre = Vec::with_capacity(160);
    pre.extend_from_slice(&(tx.version as u32).to_le_bytes());
    pre.extend_from_slice(&sha256d(&prevouts));
    pre.extend_from_slice(&sha256d(&sequences));
    pre.extend_from_slice(&input.prev_txid);
    pre.extend_from_slice(&input.prev_vout.to_le_bytes());
    write_varint(&mut pre, script_code.len() as u64);
    pre.extend_from_slice(&script_code);
    pre.extend_from_slice(&amount.to_le_bytes());
    pre.extend_from_slice(&input.sequence.to_le_bytes());
    pre.extend_from_slice(&sha256d(&outputs));
    pre.extend_from_slice(&tx.lock_time.to_le_bytes());
    pre.extend_from_slice(&1u32.to_le_bytes());
    sha256d(&pre)
}

/// DER, as Bitcoin wants an ECDSA signature: two positive integers, no padding beyond one zero.
fn der(sig: &Signature) -> Vec<u8> {
    let (r, s) = sig.split_bytes();
    let int = |b: &[u8]| -> Vec<u8> {
        let b = &b[b.iter().position(|&x| x != 0).unwrap_or(b.len() - 1)..];
        let mut v = Vec::with_capacity(34);
        v.push(0x02);
        let pad = b[0] & 0x80 != 0;
        v.push((b.len() + pad as usize) as u8);
        if pad {
            v.push(0);
        }
        v.extend_from_slice(b);
        v
    };
    let (r, s) = (int(&r), int(&s));
    let mut out = Vec::with_capacity(72);
    out.push(0x30);
    out.push((r.len() + s.len()) as u8);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

/// Sign every input (all are this wallet's; `review` has checked). Adds a partial signature to
/// each, and returns how many it signed. Deterministic (RFC 6979), low-S.
pub fn sign(psbt: &mut Psbt, account: &Account) -> Result<usize, Error> {
    let (_, spends) = check(psbt, account)?;
    for (i, s) in spends.iter().enumerate() {
        let public_key = s.key.public_key();
        let digest = sighash(&psbt.tx, i, &public_key, s.spent.value);
        let signer = SigningKey::from(s.key.secret());
        let sig: Signature = signer.sign_prehash(&digest).map_err(|_| Error::Key)?;
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut value = der(&sig);
        value.push(0x01); // SIGHASH_ALL
        let mut key = Vec::with_capacity(34);
        key.push(psbt::IN_PARTIAL_SIG);
        key.extend_from_slice(&public_key);
        psbt.set_input(i, key, value);
    }
    Ok(spends.len())
}

/// BIP380: a descriptor's checksum.
pub fn descriptor_checksum(desc: &str) -> String {
    const INPUT: &str = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    const CHECKSUM: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const GENERATOR: [u64; 5] = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd];
    fn polymod(chk: u64, value: u64) -> u64 {
        let top = chk >> 35;
        let mut chk = ((chk & 0x7_ffff_ffff) << 5) ^ value;
        for (i, g) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
        chk
    }
    let mut chk = 1u64;
    let (mut groups, mut count) = (0u64, 0);
    for c in desc.chars() {
        let v = INPUT.find(c).unwrap_or(0) as u64;
        chk = polymod(chk, v & 31);
        groups = groups * 3 + (v >> 5);
        count += 1;
        if count == 3 {
            chk = polymod(chk, groups);
            groups = 0;
            count = 0;
        }
    }
    if count > 0 {
        chk = polymod(chk, groups);
    }
    for _ in 0..8 {
        chk = polymod(chk, 0);
    }
    chk ^= 1;
    (0..8).map(|i| CHECKSUM[((chk >> (5 * (7 - i))) & 31) as usize] as char).collect()
}
