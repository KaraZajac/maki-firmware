//! The account, and the two things done with a PSBT: review it, then sign it.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use maki_hd::{Keys, Public, Tweak, HARDENED};

use crate::address::{address, describe, p2tr_script, p2wpkh_script, Network};
use crate::bip32::xpub;
use crate::hash::{hash160, sha256, sha256d, tagged};
use crate::psbt::{self, parse_derivation, parse_tap_derivation, Psbt};
use crate::taproot;
use crate::tx::{write_varint, Cursor, Tx, TxOut};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Key,
    /// maki couldn't make a key or a signature: it's locked, or said no.
    Keys(maki_hd::Error),
    Psbt(&'static str),
    /// This input isn't this wallet's: no derivation of ours, or one that doesn't match.
    NotOurs(usize),
    /// This input doesn't come with the transaction it spends.
    NoPreviousTx(usize),
    /// The transaction it came with isn't the one the input spends, or disagrees with the amount
    /// or script the PSBT claims.
    PreviousTxMismatch(usize),
    /// Asks for a signature other than SIGHASH_ALL (or taproot's default, which is the same).
    Sighash(usize),
    /// Spends a taproot output by a script: maki signs with the key alone (BIP86).
    ScriptPath(usize),
    /// The outputs pay more than the inputs hold.
    NegativeFee,
    /// An amount beyond the 21 million bitcoin there will ever be.
    Amount,
    /// A multisig wallet maki won't take, and why.
    Multisig(&'static str),
}

impl core::fmt::Display for Error {
    /// Why maki won't sign, for the computer to show.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Key => write!(f, "couldn't derive this wallet's keys"),
            Error::Keys(e) => write!(f, "{}", e),
            Error::Psbt(why) => write!(f, "not a PSBT maki can read: {}", why),
            Error::NotOurs(i) => write!(
                f,
                "input {} isn't this wallet's (maki signs for account 0 of BIP84, native SegWit, and BIP86, taproot)",
                i
            ),
            Error::NoPreviousTx(i) => write!(
                f,
                "input {} doesn't come with what it spends (the PSBT needs non_witness_utxo, or for taproot witness_utxo)",
                i
            ),
            Error::PreviousTxMismatch(i) => write!(f, "input {}'s previous transaction isn't the one it spends", i),
            Error::Sighash(i) => write!(f, "input {} asks for a signature other than SIGHASH_ALL", i),
            Error::ScriptPath(i) => write!(f, "input {} spends a taproot script, and maki signs with its key alone", i),
            Error::NegativeFee => write!(f, "the outputs pay more than the inputs hold"),
            Error::Amount => write!(f, "an amount is beyond 21 million bitcoin"),
            Error::Multisig(why) => write!(f, "{}", why),
        }
    }
}

/// Satoshis in 21 million bitcoin: no amount can be larger.
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

pub(crate) fn total(mut amounts: impl Iterator<Item = u64>) -> Result<u64, Error> {
    amounts.try_fold(0u64, |sum, a| sum.checked_add(a).filter(|&s| a <= MAX_MONEY && s <= MAX_MONEY)).ok_or(Error::Amount)
}

/// Which of maki's accounts: native SegWit (BIP84, P2WPKH), or taproot (BIP86, P2TR, spent with
/// the key alone).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Segwit,
    Taproot,
}

impl Kind {
    /// BIP43's purpose: 84 or 86.
    pub fn purpose(self) -> u32 {
        match self {
            Kind::Segwit => 84,
            Kind::Taproot => 86,
        }
    }
}

/// A key of an account's: where it is, and its public key.
#[derive(Clone)]
struct Key {
    path: [u32; 5],
    public: [u8; 33],
}

/// Account 0 of BIP84 or BIP86: `m/84'/coin'/0'` or `m/86'/coin'/0'`. Its keys are maki's
/// (`maki_hd::Keys`): the account asks for public keys and signatures by path.
#[derive(Clone)]
pub struct Account<'k> {
    pub network: Network,
    pub kind: Kind,
    pub master_fingerprint: [u8; 4],
    keys: &'k dyn Keys,
    /// the account key, for its xpub
    public: Public,
}

impl<'k> Account<'k> {
    /// The native SegWit account (BIP84).
    pub fn segwit(keys: &'k dyn Keys, network: Network) -> Result<Account<'k>, Error> { Account::new(keys, network, Kind::Segwit) }

    pub fn new(keys: &'k dyn Keys, network: Network, kind: Kind) -> Result<Account<'k>, Error> {
        let path = [kind.purpose() | HARDENED, network.coin_type() | HARDENED, HARDENED];
        let master_fingerprint = keys.fingerprint().map_err(Error::Keys)?;
        let public = keys.public(&path).map_err(Error::Keys)?;
        Ok(Account { network, kind, master_fingerprint, keys, public })
    }

    fn path(&self) -> [u32; 3] { [self.kind.purpose() | HARDENED, self.network.coin_type() | HARDENED, HARDENED] }

    fn key_at(&self, change: bool, index: u32) -> Result<Key, Error> {
        if index >= HARDENED {
            return Err(Error::Key);
        }
        let [purpose, coin, account] = self.path();
        let path = [purpose, coin, account, change as u32, index];
        Ok(Key { path, public: self.keys.public(&path).map_err(Error::Keys)?.key })
    }

    /// The output script a key of this account's pays to: P2WPKH, or P2TR with the key tweaked.
    fn script_of(&self, key: &Key) -> Result<Vec<u8>, Error> {
        match self.kind {
            Kind::Segwit => Ok(p2wpkh_script(&key.public)),
            Kind::Taproot => Ok(p2tr_script(&self.keys.taproot_output(&key.path).map_err(Error::Keys)?)),
        }
    }

    /// A receiving (or change) address, to show on maki's screen and check against the computer.
    pub fn address(&self, change: bool, index: u32) -> Result<String, Error> {
        let script = self.script_of(&self.key_at(change, index)?)?;
        address(&script, self.network).ok_or(Error::Key)
    }

    /// The account key as wallets take it: for native SegWit, a zpub (vpub on test networks), as
    /// BIP84 wallets want it; taproot has no such form, so an xpub (tpub).
    pub fn zpub(&self) -> String {
        match self.kind {
            Kind::Segwit => self.xpub(self.network.zpub_version()),
            Kind::Taproot => self.xpub(self.network.xpub_version()),
        }
    }

    /// An output descriptor for wallet software (Sparrow, Bitcoin Core): both chains, with the
    /// master key's fingerprint and path so it knows maki can sign for them.
    pub fn descriptor(&self) -> String {
        let fp: String = self.master_fingerprint.iter().map(|b| format!("{:02x}", b)).collect();
        let function = match self.kind {
            Kind::Segwit => "wpkh",
            Kind::Taproot => "tr",
        };
        let body = format!(
            "{}([{}/{}h/{}h/0h]{}/<0;1>/*)",
            function,
            fp,
            self.kind.purpose(),
            self.network.coin_type(),
            self.xpub(self.network.xpub_version())
        );
        format!("{}#{}", body, descriptor_checksum(&body))
    }

    /// The account key, base58check with the given version bytes.
    fn xpub(&self, version: [u8; 4]) -> String { xpub(version, 3, HARDENED, &self.public) }

    /// Whose key a path names: ours, from this account's chains, or not.
    fn derived(&self, fp: [u8; 4], path: &[u32]) -> Option<Key> {
        if fp != self.master_fingerprint || path.len() != 5 || path[..3] != self.path() || path[3] > 1 {
            return None;
        }
        self.key_at(path[3] == 1, path[4]).ok()
    }

    /// A native SegWit derivation (BIP174): ours if its key is the one we'd make.
    fn ours(&self, derivation: &[u8], public_key: &[u8]) -> Option<Key> {
        if self.kind != Kind::Segwit {
            return None;
        }
        let (fp, path) = parse_derivation(derivation)?;
        let key = self.derived(fp, &path)?;
        (key.public[..] == *public_key).then_some(key)
    }

    /// A taproot derivation (BIP371), for the key alone (no script leaves): ours if its x-only
    /// key is the one we'd make.
    fn ours_tap(&self, derivation: &[u8], x_only: &[u8]) -> Option<(Key, u32)> {
        if self.kind != Kind::Taproot {
            return None;
        }
        let (leaves, fp, path) = parse_tap_derivation(derivation)?;
        if leaves != 0 {
            return None;
        }
        let key = self.derived(fp, &path)?;
        (taproot::x_only(&key.public)[..] == *x_only).then_some((key, path[3]))
    }
}

/// What a transaction does, as maki shows it before signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    pub network: Network,
    /// the multisig wallet it spends from, by name; None for maki's own accounts
    pub wallet: Option<String>,
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

/// An input of ours: its key (and which account's), the output it spends, and how it's signed.
struct Spend {
    key: Key,
    account: usize,
    spent: TxOut,
    kind: Kind,
    /// taproot: 0 (the default) or 1 (SIGHASH_ALL, written out); native SegWit: always 1
    hash_type: u8,
}

/// The output a previous transaction's `vout` is, if its txid is the one spent.
pub(crate) fn previous_output(bytes: &[u8], txid: &[u8; 32], vout: u32) -> Option<TxOut> {
    let prev = Tx::parse(bytes).ok()?;
    if prev.txid() != *txid {
        return None;
    }
    prev.outputs.get(vout as usize).cloned()
}

/// A witness UTXO (an amount, then a script).
pub(crate) fn witness_utxo(bytes: &[u8]) -> Option<TxOut> {
    let mut c = Cursor::new(bytes);
    let value = u64::from_le_bytes(c.take(8).ok()?.try_into().unwrap());
    let script = c.bytes(10_000).ok()?.to_vec();
    c.done().then_some(TxOut { value, script_pubkey: script })
}

fn is_taproot(pairs: &[psbt::Pair]) -> bool {
    use psbt::*;
    pairs.iter().any(|p| {
        matches!(
            p.key.first(),
            Some(&IN_TAP_KEY_SIG | &IN_TAP_SCRIPT_SIG | &IN_TAP_LEAF_SCRIPT | &IN_TAP_BIP32_DERIVATION | &IN_TAP_INTERNAL_KEY | &IN_TAP_MERKLE_ROOT)
        )
    })
}

/// Check every input, and work out what each one spends.
fn spends(psbt: &Psbt, accounts: &[Account]) -> Result<Vec<Spend>, Error> {
    let mut out = Vec::with_capacity(psbt.tx.inputs.len());
    for (i, input) in psbt.tx.inputs.iter().enumerate() {
        let pairs = &psbt.inputs[i];
        let prev = psbt.input(i, psbt::IN_NON_WITNESS_UTXO);
        let from_prev = match prev {
            Some(bytes) => {
                Some(previous_output(bytes, &input.prev_txid, input.prev_vout).ok_or(Error::PreviousTxMismatch(i))?)
            }
            None => None,
        };
        let claimed = match psbt.input(i, psbt::IN_WITNESS_UTXO) {
            Some(bytes) => Some(witness_utxo(bytes).ok_or(Error::PreviousTxMismatch(i))?),
            None => None,
        };
        if let (Some(a), Some(b)) = (&from_prev, &claimed) {
            if a != b {
                return Err(Error::PreviousTxMismatch(i));
            }
        }
        let sighash = psbt.input(i, psbt::IN_SIGHASH_TYPE);
        let spend = if is_taproot(pairs) {
            // the key alone: no scripts to sign for
            if pairs.iter().any(|p| {
                matches!(p.key.first(), Some(&psbt::IN_TAP_SCRIPT_SIG | &psbt::IN_TAP_LEAF_SCRIPT | &psbt::IN_TAP_MERKLE_ROOT))
            }) {
                return Err(Error::ScriptPath(i));
            }
            // taproot's digest covers every input's amount and script, so a witness UTXO that
            // lies makes a signature that fails, not a fee the owner didn't see: it's enough
            let spent = from_prev.or(claimed).ok_or(Error::NoPreviousTx(i))?;
            let hash_type = match sighash {
                None | Some([0, 0, 0, 0]) => 0,
                Some([1, 0, 0, 0]) => 1,
                Some(_) => return Err(Error::Sighash(i)),
            };
            let (account, key) = pairs
                .iter()
                .filter(|p| p.key.first() == Some(&psbt::IN_TAP_BIP32_DERIVATION) && p.key.len() == 33)
                .find_map(|p| accounts.iter().enumerate().find_map(|(n, a)| a.ours_tap(&p.value, &p.key[1..]).map(|(k, _)| (n, k))))
                .ok_or(Error::NotOurs(i))?;
            if let Some(internal) = psbt.input(i, psbt::IN_TAP_INTERNAL_KEY) {
                if internal != taproot::x_only(&key.public) {
                    return Err(Error::NotOurs(i));
                }
            }
            if accounts[account].script_of(&key)? != spent.script_pubkey {
                return Err(Error::NotOurs(i));
            }
            Spend { key, account, spent, kind: Kind::Taproot, hash_type }
        } else {
            // the whole previous transaction: amounts are never taken on the PSBT's word
            let spent = from_prev.ok_or(Error::NoPreviousTx(i))?;
            if sighash.is_some_and(|t| t != [1, 0, 0, 0]) {
                return Err(Error::Sighash(i));
            }
            let (account, key) = pairs
                .iter()
                .filter(|p| p.key.first() == Some(&psbt::IN_BIP32_DERIVATION) && p.key.len() == 34)
                .find_map(|p| accounts.iter().enumerate().find_map(|(n, a)| a.ours(&p.value, &p.key[1..]).map(|k| (n, k))))
                .ok_or(Error::NotOurs(i))?;
            if p2wpkh_script(&key.public) != spent.script_pubkey {
                return Err(Error::NotOurs(i));
            }
            Spend { key, account, spent, kind: Kind::Segwit, hash_type: 1 }
        };
        out.push(spend);
    }
    Ok(out)
}

/// Whether an output is change: it names a key on one of this wallet's change chains, and pays
/// the script that key makes.
fn is_change(pairs: &[psbt::Pair], script: &[u8], accounts: &[Account]) -> bool {
    pairs.iter().any(|p| match p.key.first() {
        Some(&psbt::OUT_BIP32_DERIVATION) if p.key.len() == 34 => {
            parse_derivation(&p.value).is_some_and(|(_, path)| path.get(3) == Some(&1))
                && accounts.iter().any(|a| {
                    a.ours(&p.value, &p.key[1..]).is_some_and(|k| a.script_of(&k).is_ok_and(|s| s == script))
                })
        }
        Some(&psbt::OUT_TAP_BIP32_DERIVATION) if p.key.len() == 33 => accounts.iter().any(|a| {
            a.ours_tap(&p.value, &p.key[1..]).is_some_and(|(k, chain)| chain == 1 && a.script_of(&k).is_ok_and(|s| s == script))
        }),
        _ => false,
    })
}

/// What the transaction does, checked: every input this wallet's (of any of `accounts`, which
/// share a network), amounts from the transactions they spend, change only where it derives from
/// one of this wallet's change chains.
pub fn review(psbt: &Psbt, accounts: &[Account]) -> Result<Review, Error> { check(psbt, accounts).map(|(review, _)| review) }

fn check(psbt: &Psbt, accounts: &[Account]) -> Result<(Review, Vec<Spend>), Error> {
    if psbt.tx.inputs.is_empty() || psbt.tx.outputs.is_empty() {
        return Err(Error::Psbt("a transaction needs inputs and outputs"));
    }
    let network = accounts.first().ok_or(Error::Key)?.network;
    let spends = spends(psbt, accounts)?;
    let total_in = total(spends.iter().map(|s| s.spent.value))?;
    let total_out = total(psbt.tx.outputs.iter().map(|o| o.value))?;
    let fee = total_in.checked_sub(total_out).ok_or(Error::NegativeFee)?;
    let outputs = psbt
        .tx
        .outputs
        .iter()
        .enumerate()
        .map(|(j, o)| {
            let change = is_change(&psbt.outputs[j], &o.script_pubkey, accounts);
            Output { address: describe(&o.script_pubkey, network), amount: o.value, change }
        })
        .collect();
    // signed size: the transaction, plus marker, flag and a witness per input: P2WPKH's (the
    // largest a low-S signature makes it), or a taproot key's signature (a byte more for an
    // explicit SIGHASH_ALL)
    let witnesses: u64 = spends
        .iter()
        .map(|s| match s.kind {
            Kind::Segwit => 1 + 1 + 72 + 1 + 33,
            Kind::Taproot => 1 + 1 + 64 + s.hash_type as u64,
        })
        .sum();
    let weight = psbt.tx.serialize().len() as u64 * 4 + 2 + witnesses;
    let review = Review { network, wallet: None, outputs, fee, vbytes: weight.div_ceil(4), inputs: spends.len() };
    Ok((review, spends))
}

/// BIP341: the digest a taproot key spends sign, for `hash_type` 0 (the default) or 1 (ALL).
/// It covers every input's amount and script, and every output.
fn taproot_sighash(tx: &Tx, i: usize, spent: &[TxOut], hash_type: u8) -> [u8; 32] {
    let (mut prevouts, mut amounts, mut scripts, mut sequences, mut outputs) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for input in &tx.inputs {
        prevouts.extend_from_slice(&input.prev_txid);
        prevouts.extend_from_slice(&input.prev_vout.to_le_bytes());
        sequences.extend_from_slice(&input.sequence.to_le_bytes());
    }
    for o in spent {
        amounts.extend_from_slice(&o.value.to_le_bytes());
        write_varint(&mut scripts, o.script_pubkey.len() as u64);
        scripts.extend_from_slice(&o.script_pubkey);
    }
    for o in &tx.outputs {
        o.write(&mut outputs);
    }
    let mut m = Vec::with_capacity(1 + 1 + 4 + 4 + 32 * 5 + 1 + 4);
    // the epoch, then SigMsg
    m.push(0x00);
    m.push(hash_type);
    m.extend_from_slice(&(tx.version as u32).to_le_bytes());
    m.extend_from_slice(&tx.lock_time.to_le_bytes());
    m.extend_from_slice(&sha256(&prevouts));
    m.extend_from_slice(&sha256(&amounts));
    m.extend_from_slice(&sha256(&scripts));
    m.extend_from_slice(&sha256(&sequences));
    m.extend_from_slice(&sha256(&outputs));
    // spent with the key, no annex
    m.push(0x00);
    m.extend_from_slice(&(i as u32).to_le_bytes());
    tagged("TapSighash", &[&m])
}

/// BIP143: the digest a P2WPKH input signs, SIGHASH_ALL.
fn sighash(tx: &Tx, i: usize, public_key: &[u8; 33], amount: u64) -> [u8; 32] {
    let mut script_code = Vec::with_capacity(25);
    script_code.extend_from_slice(&[0x76, 0xa9, 0x14]);
    script_code.extend_from_slice(&hash160(public_key));
    script_code.extend_from_slice(&[0x88, 0xac]);
    segwit_sighash(tx, i, &script_code, amount)
}

/// BIP143's digest, SIGHASH_ALL, for an input whose script code is `script_code`: P2WPKH's
/// pay-to-key-hash, or a P2WSH input's witness script.
pub(crate) fn segwit_sighash(tx: &Tx, i: usize, script_code: &[u8], amount: u64) -> [u8; 32] {
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
    let mut pre = Vec::with_capacity(160 + script_code.len());
    pre.extend_from_slice(&(tx.version as u32).to_le_bytes());
    pre.extend_from_slice(&sha256d(&prevouts));
    pre.extend_from_slice(&sha256d(&sequences));
    pre.extend_from_slice(&input.prev_txid);
    pre.extend_from_slice(&input.prev_vout.to_le_bytes());
    write_varint(&mut pre, script_code.len() as u64);
    pre.extend_from_slice(script_code);
    pre.extend_from_slice(&amount.to_le_bytes());
    pre.extend_from_slice(&input.sequence.to_le_bytes());
    pre.extend_from_slice(&sha256d(&outputs));
    pre.extend_from_slice(&tx.lock_time.to_le_bytes());
    pre.extend_from_slice(&1u32.to_le_bytes());
    sha256d(&pre)
}

/// DER, as Bitcoin wants an ECDSA signature (r and s, 32 bytes each): two positive integers, no
/// padding beyond one zero.
pub(crate) fn der(sig: &[u8; 64]) -> Vec<u8> {
    let (r, s) = (&sig[..32], &sig[32..]);
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
    let (r, s) = (int(r), int(s));
    let mut out = Vec::with_capacity(72);
    out.push(0x30);
    out.push((r.len() + s.len()) as u8);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

/// How many signatures `sign` will make: one per input, which the owner is told before saying
/// yes (maki lets a wallet app make only as many as it said).
pub fn signatures(psbt: &Psbt, accounts: &[Account]) -> Result<usize, Error> { check(psbt, accounts).map(|(_, s)| s.len()) }

/// Sign every input (all are this wallet's; `review` has checked), and return how many it
/// signed. A native SegWit input gets a partial signature, deterministic (RFC 6979) and low-S; a
/// taproot one its key's Schnorr signature (BIP340), tweaked for the output key. The keys make
/// the signatures, and maki checks each one before it goes out: a signature a fault spoiled can
/// give the key away.
pub fn sign(psbt: &mut Psbt, accounts: &[Account]) -> Result<usize, Error> {
    let (_, spends) = check(psbt, accounts)?;
    let spent: Vec<TxOut> = spends.iter().map(|s| s.spent.clone()).collect();
    for (i, s) in spends.iter().enumerate() {
        let keys = accounts[s.account].keys;
        match s.kind {
            Kind::Segwit => {
                let digest = sighash(&psbt.tx, i, &s.key.public, s.spent.value);
                let (sig, _) = keys.sign_ecdsa(&s.key.path, &digest).map_err(Error::Keys)?;
                let mut value = der(&sig);
                value.push(0x01); // SIGHASH_ALL
                let mut key = Vec::with_capacity(34);
                key.push(psbt::IN_PARTIAL_SIG);
                key.extend_from_slice(&s.key.public);
                psbt.set_input(i, key, value);
            }
            Kind::Taproot => {
                let digest = taproot_sighash(&psbt.tx, i, &spent, s.hash_type);
                let sig = keys.sign_schnorr(&s.key.path, &digest, Tweak::Taproot).map_err(Error::Keys)?;
                let mut value = sig.to_vec();
                if s.hash_type == 1 {
                    value.push(0x01);
                }
                psbt.set_input(i, alloc::vec![psbt::IN_TAP_KEY_SIG], value);
            }
        }
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
