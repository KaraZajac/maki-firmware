//! The account, and the two things done with a PSBT: review it, then sign it.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use maki_hd::{HARDENED, Keys, Public, Tweak};

use crate::address::{Network, address, describe, p2pkh_script, p2tr_script, p2wpkh_script};
use crate::bip32::xpub;
use crate::hash::{sha256, sha256d, tagged};
use crate::psbt::{self, Psbt, parse_derivation, parse_tap_derivation};
use crate::taproot;
use crate::tx::{self, Cursor, Tx, TxOut, write_varint};

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
    /// An amount beyond all the coins there will ever be (21 million bitcoin, 84 million
    /// litecoin).
    Amount,
    /// A multisig wallet maki won't take, and why.
    Multisig(&'static str),
    /// Something this network's wallet doesn't do (an account kind it hasn't, CashTokens), and
    /// what.
    Unsupported(&'static str),
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
            Error::PreviousTxMismatch(i) => {
                write!(f, "input {}'s previous transaction isn't the one it spends", i)
            }
            Error::Sighash(i) => write!(f, "input {} asks for a signature other than SIGHASH_ALL", i),
            Error::ScriptPath(i) => {
                write!(f, "input {} spends a taproot script, and maki signs with its key alone", i)
            }
            Error::NegativeFee => write!(f, "the outputs pay more than the inputs hold"),
            Error::Amount => write!(f, "an amount is beyond all the coins there will ever be"),
            Error::Multisig(why) => write!(f, "{}", why),
            Error::Unsupported(what) => write!(f, "{}", what),
        }
    }
}

/// Satoshis in 21 million bitcoin: no amount can be larger (on bitcoin: `Network::max_money`).
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// The amounts added up, each and the sum no more than the network's coin will ever have.
pub(crate) fn total(network: Network, mut amounts: impl Iterator<Item = u64>) -> Result<u64, Error> {
    let max = network.max_money();
    amounts.try_fold(0u64, |sum, a| sum.checked_add(a).filter(|&s| a <= max && s <= max)).ok_or(Error::Amount)
}

/// Which of maki's accounts: native SegWit (BIP84, P2WPKH), taproot (BIP86, P2TR, spent with the
/// key alone), or, on the networks without SegWit (Dogecoin, Bitcoin Cash), pay-to-key-hash
/// (BIP44, P2PKH).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Segwit,
    Taproot,
    Legacy,
}

impl Kind {
    /// BIP43's purpose: 84, 86 or 44.
    pub fn purpose(self) -> u32 {
        match self {
            Kind::Segwit => 84,
            Kind::Taproot => 86,
            Kind::Legacy => 44,
        }
    }

    /// Whether a network's wallet has this kind of account: SegWit and taproot where there's
    /// SegWit, pay-to-key-hash where there isn't; on DigiByte all three, its wallets having made
    /// legacy accounts (`D…`) as long as SegWit ones.
    pub fn on(self, network: Network) -> bool {
        network.is_digibyte() || (self == Kind::Legacy) != network.has_segwit()
    }
}

/// Bitcoin Cash's fork ID, in the signature hash type of every signature it takes (BIP143's digest
/// with SIGHASH_FORKID, its fork ID zero): SIGHASH_ALL | SIGHASH_FORKID.
pub const SIGHASH_ALL_FORKID: u8 = 0x41;

/// CashTokens' prefix (Bitcoin Cash, 2023): an output's locking bytecode that starts with it
/// carries tokens, which maki can't show, so won't spend or make.
const PREFIX_TOKEN: u8 = 0xef;

/// DigiDollar's marker (DigiByte, 2026): a transaction whose version's low 16 bits are this
/// mints, sends or redeems DigiDollars, which maki can't show. Their tokens sit in outputs of no
/// DGB, their amounts in the transaction's data; a transaction without the marker that spends
/// one passes DigiByte's checks and destroys the tokens.
const DIGIDOLLAR: u32 = 0x0770;

/// Why maki won't sign a Dash special transaction (DIP-2), by its type: anything but a payment
/// does what maki's pages can't show.
fn dash_special(kind: u16) -> &'static str {
    match kind {
        1 => "a Dash masternode's registration (ProRegTx): maki signs payments only",
        2 => "a Dash masternode's service update (ProUpServTx): maki signs payments only",
        3 => "a Dash masternode's registrar update (ProUpRegTx): maki signs payments only",
        4 => "a Dash masternode's revocation (ProUpRevTx): maki signs payments only",
        5 => "a Dash coinbase (CbTx): maki signs payments only",
        6 => "a Dash quorum commitment (QcTx): maki signs payments only",
        7 => "a Dash masternode's hard fork signal (MnHfTx): maki signs payments only",
        8 => "a Dash asset lock (credit for Dash Platform): maki signs payments only",
        9 => "a Dash asset unlock (a withdrawal from Dash Platform): maki signs payments only",
        _ => "a Dash special transaction of a type Dash doesn't have",
    }
}

/// Whether Dash takes a transaction of this version to sign: a plain one (type 0, DIP-2), of a
/// version Dash relays (1 to 3).
fn dash_signable(version: i32) -> Result<(), Error> {
    let (v, kind) = (tx::dash_version(version), tx::dash_type(version));
    match kind {
        0 if (1..=3).contains(&v) => Ok(()),
        0 => Err(Error::Unsupported("a transaction version Dash doesn't relay (it relays 1 to 3)")),
        _ if v >= 3 => Err(Error::Unsupported(dash_special(kind))),
        _ => Err(Error::Unsupported("a special transaction type below version 3, which Dash refuses")),
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
    pub fn segwit(keys: &'k dyn Keys, network: Network) -> Result<Account<'k>, Error> {
        Account::new(keys, network, Kind::Segwit)
    }

    pub fn new(keys: &'k dyn Keys, network: Network, kind: Kind) -> Result<Account<'k>, Error> {
        if !kind.on(network) {
            return Err(Error::Unsupported(if network.has_segwit() {
                "this network's accounts are native SegWit and taproot"
            } else {
                "this network's accounts pay to a key's hash (BIP44): it has no SegWit"
            }));
        }
        let path = [kind.purpose() | HARDENED, network.coin_type() | HARDENED, HARDENED];
        let master_fingerprint = keys.fingerprint().map_err(Error::Keys)?;
        let public = keys.public(&path).map_err(Error::Keys)?;
        Ok(Account { network, kind, master_fingerprint, keys, public })
    }

    fn path(&self) -> [u32; 3] {
        [self.kind.purpose() | HARDENED, self.network.coin_type() | HARDENED, HARDENED]
    }

    fn key_at(&self, change: bool, index: u32) -> Result<Key, Error> {
        if index >= HARDENED {
            return Err(Error::Key);
        }
        let [purpose, coin, account] = self.path();
        let path = [purpose, coin, account, change as u32, index];
        Ok(Key { path, public: self.keys.public(&path).map_err(Error::Keys)?.key })
    }

    /// The output script a key of this account's pays to: P2WPKH, P2TR with the key tweaked, or
    /// P2PKH.
    fn script_of(&self, key: &Key) -> Result<Vec<u8>, Error> {
        match self.kind {
            Kind::Segwit => Ok(p2wpkh_script(&key.public)),
            Kind::Taproot => Ok(p2tr_script(&self.keys.taproot_output(&key.path).map_err(Error::Keys)?)),
            Kind::Legacy => Ok(p2pkh_script(&key.public)),
        }
    }

    /// A receiving (or change) address, to show on maki's screen and check against the computer.
    pub fn address(&self, change: bool, index: u32) -> Result<String, Error> {
        let script = self.script_of(&self.key_at(change, index)?)?;
        address(&script, self.network).ok_or(Error::Key)
    }

    /// The account key as wallets take it: for native SegWit, a zpub (vpub on test networks), as
    /// BIP84 wallets want it; taproot and pay-to-key-hash have no such form, so an xpub (tpub).
    pub fn zpub(&self) -> String {
        match self.kind {
            Kind::Segwit => self.xpub(self.network.zpub_version()),
            Kind::Taproot | Kind::Legacy => self.xpub(self.network.xpub_version()),
        }
    }

    /// An output descriptor for wallet software (Sparrow, Bitcoin Core): both chains, with the
    /// master key's fingerprint and path so it knows maki can sign for them.
    pub fn descriptor(&self) -> String {
        let fp: String = self.master_fingerprint.iter().map(|b| format!("{:02x}", b)).collect();
        let function = match self.kind {
            Kind::Segwit => "wpkh",
            Kind::Taproot => "tr",
            Kind::Legacy => "pkh",
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

    /// A native SegWit or pay-to-key-hash derivation (BIP174): ours if its key is the one we'd
    /// make.
    fn ours(&self, derivation: &[u8], public_key: &[u8]) -> Option<Key> {
        if self.kind == Kind::Taproot {
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
    /// taproot: 0 (the default) or 1 (SIGHASH_ALL, written out); native SegWit and Dogecoin's
    /// pay-to-key-hash: always 1; Bitcoin Cash's: always SIGHASH_ALL | SIGHASH_FORKID
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

/// The same, the transaction read as `network` writes one: on Dash's, as Dash does, a special
/// transaction with its payload (a withdrawal from Dash Platform, a coinbase), whose txid hashes
/// its bytes as they are.
fn previous_output_on(bytes: &[u8], txid: &[u8; 32], vout: u32, network: Network) -> Option<TxOut> {
    if !network.is_dash() {
        return previous_output(bytes, txid, vout);
    }
    let (prev, _) = Tx::parse_dash(bytes).ok()?;
    if sha256d(bytes) != *txid {
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
            Some(
                &IN_TAP_KEY_SIG
                    | &IN_TAP_SCRIPT_SIG
                    | &IN_TAP_LEAF_SCRIPT
                    | &IN_TAP_BIP32_DERIVATION
                    | &IN_TAP_INTERNAL_KEY
                    | &IN_TAP_MERKLE_ROOT
            )
        )
    })
}

/// Check every input, and work out what each one spends.
fn spends(psbt: &Psbt, accounts: &[Account]) -> Result<Vec<Spend>, Error> {
    let network = accounts.first().ok_or(Error::Key)?.network;
    let mut out = Vec::with_capacity(psbt.tx.inputs.len());
    for (i, input) in psbt.tx.inputs.iter().enumerate() {
        let pairs = &psbt.inputs[i];
        let prev = psbt.input(i, psbt::IN_NON_WITNESS_UTXO);
        let from_prev = match prev {
            Some(bytes) => Some(
                previous_output_on(bytes, &input.prev_txid, input.prev_vout, network)
                    .ok_or(Error::PreviousTxMismatch(i))?,
            ),
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
                matches!(
                    p.key.first(),
                    Some(&psbt::IN_TAP_SCRIPT_SIG | &psbt::IN_TAP_LEAF_SCRIPT | &psbt::IN_TAP_MERKLE_ROOT)
                )
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
                .find_map(|p| {
                    accounts
                        .iter()
                        .enumerate()
                        .find_map(|(n, a)| a.ours_tap(&p.value, &p.key[1..]).map(|(k, _)| (n, k)))
                })
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
            // the whole previous transaction: amounts are never taken on the PSBT's word (a
            // signature that commits to its own input's amount alone, as BIP143's and Bitcoin
            // Cash's do, still lets two transactions that each lie about another input's add up
            // to a fee nobody saw)
            let spent = from_prev.ok_or(Error::NoPreviousTx(i))?;
            let hash_type = if network.is_bitcoin_cash() { SIGHASH_ALL_FORKID } else { 1 };
            if sighash.is_some_and(|t| t != [hash_type, 0, 0, 0]) {
                return Err(Error::Sighash(i));
            }
            if spent.script_pubkey.first() == Some(&PREFIX_TOKEN) {
                return Err(Error::Unsupported("a coin carrying CashTokens, which maki can't show"));
            }
            let (account, key) = pairs
                .iter()
                .filter(|p| p.key.first() == Some(&psbt::IN_BIP32_DERIVATION) && p.key.len() == 34)
                .find_map(|p| {
                    accounts
                        .iter()
                        .enumerate()
                        .find_map(|(n, a)| a.ours(&p.value, &p.key[1..]).map(|k| (n, k)))
                })
                .ok_or(Error::NotOurs(i))?;
            if accounts[account].script_of(&key)? != spent.script_pubkey {
                return Err(Error::NotOurs(i));
            }
            Spend { key, account, spent, kind: accounts[account].kind, hash_type }
        };
        // a DigiDollar token's coin holds no DGB: spent by anything but DigiDollar's own
        // transactions, the tokens are gone
        if network.is_digibyte() && spend.spent.value == 0 {
            return Err(Error::Unsupported("a coin of no DGB: a DigiDollar token's, which maki can't show"));
        }
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
            a.ours_tap(&p.value, &p.key[1..])
                .is_some_and(|(k, chain)| chain == 1 && a.script_of(&k).is_ok_and(|s| s == script))
        }),
        _ => false,
    })
}

/// What the transaction does, checked: every input this wallet's (of any of `accounts`, which
/// share a network), amounts from the transactions they spend, change only where it derives from
/// one of this wallet's change chains.
pub fn review(psbt: &Psbt, accounts: &[Account]) -> Result<Review, Error> {
    check(psbt, accounts).map(|(review, _)| review)
}

fn check(psbt: &Psbt, accounts: &[Account]) -> Result<(Review, Vec<Spend>), Error> {
    if psbt.tx.inputs.is_empty() || psbt.tx.outputs.is_empty() {
        return Err(Error::Psbt("a transaction needs inputs and outputs"));
    }
    let network = accounts.first().ok_or(Error::Key)?.network;
    if accounts.iter().any(|a| a.network != network) {
        return Err(Error::Key);
    }
    if psbt.tx.outputs.iter().any(|o| o.script_pubkey.first() == Some(&PREFIX_TOKEN)) {
        return Err(Error::Unsupported("an output carrying CashTokens, which maki can't show"));
    }
    if network.is_dash() {
        dash_signable(psbt.tx.version)?;
    }
    if network.is_digibyte() && psbt.tx.version as u32 & 0xffff == DIGIDOLLAR {
        return Err(Error::Unsupported("a DigiDollar transaction, which maki can't show"));
    }
    let spends = spends(psbt, accounts)?;
    let total_in = total(network, spends.iter().map(|s| s.spent.value))?;
    let total_out = total(network, psbt.tx.outputs.iter().map(|o| o.value))?;
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
    // explicit SIGHASH_ALL); a pay-to-key-hash input's signature and key are in its script, which
    // counts in full
    let witnesses: u64 = spends
        .iter()
        .map(|s| match s.kind {
            Kind::Segwit => 1 + 1 + 72 + 1 + 33,
            Kind::Taproot => 1 + 1 + 64 + (s.hash_type != 0) as u64,
            Kind::Legacy => 0,
        })
        .sum();
    let scripts: u64 = spends.iter().filter(|s| s.kind == Kind::Legacy).map(|_| 1 + 72 + 1 + 33).sum();
    let marker = if witnesses > 0 { 2 } else { 0 };
    let weight = (psbt.tx.serialize().len() as u64 + scripts) * 4 + marker + witnesses;
    let review =
        Review { network, wallet: None, outputs, fee, vbytes: weight.div_ceil(4), inputs: spends.len() };
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
    segwit_sighash(tx, i, &p2pkh_script(public_key), amount)
}

/// BIP143's digest, SIGHASH_ALL, for an input whose script code is `script_code`: P2WPKH's
/// pay-to-key-hash, or a P2WSH input's witness script.
pub(crate) fn segwit_sighash(tx: &Tx, i: usize, script_code: &[u8], amount: u64) -> [u8; 32] {
    bip143_sighash(tx, i, script_code, amount, 1)
}

/// The digest a pay-to-key-hash input signs before SegWit (Dogecoin's), SIGHASH_ALL: the
/// transaction with that input's script the output it spends and every other input's empty, then
/// the hash type. It commits to no amount, which is why maki reads amounts from the transactions
/// spent.
fn legacy_sighash(tx: &Tx, i: usize, script_code: &[u8]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(tx.serialize().len() + script_code.len() + 4);
    pre.extend_from_slice(&(tx.version as u32).to_le_bytes());
    write_varint(&mut pre, tx.inputs.len() as u64);
    for (j, input) in tx.inputs.iter().enumerate() {
        pre.extend_from_slice(&input.prev_txid);
        pre.extend_from_slice(&input.prev_vout.to_le_bytes());
        let script: &[u8] = if j == i { script_code } else { &[] };
        write_varint(&mut pre, script.len() as u64);
        pre.extend_from_slice(script);
        pre.extend_from_slice(&input.sequence.to_le_bytes());
    }
    write_varint(&mut pre, tx.outputs.len() as u64);
    for o in &tx.outputs {
        o.write(&mut pre);
    }
    pre.extend_from_slice(&tx.lock_time.to_le_bytes());
    pre.extend_from_slice(&1u32.to_le_bytes());
    sha256d(&pre)
}

/// BIP143's digest with the hash type `hash_type`: SegWit's (SIGHASH_ALL), or Bitcoin Cash's,
/// which every input signs with SIGHASH_ALL | SIGHASH_FORKID (its fork ID zero).
fn bip143_sighash(tx: &Tx, i: usize, script_code: &[u8], amount: u64, hash_type: u32) -> [u8; 32] {
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
    pre.extend_from_slice(&hash_type.to_le_bytes());
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
pub fn signatures(psbt: &Psbt, accounts: &[Account]) -> Result<usize, Error> {
    check(psbt, accounts).map(|(_, s)| s.len())
}

/// Sign every input (all are this wallet's; `review` has checked), and return how many it
/// signed. A native SegWit or pay-to-key-hash input gets a partial signature, deterministic (RFC
/// 6979) and low-S (Dogecoin's over the old digest, Bitcoin Cash's over BIP143's with its fork
/// ID); a taproot one its key's Schnorr signature (BIP340), tweaked for the output key. The keys
/// make the signatures, and maki checks each one before it goes out: a signature a fault spoiled
/// can give the key away.
pub fn sign(psbt: &mut Psbt, accounts: &[Account]) -> Result<usize, Error> {
    let (_, spends) = check(psbt, accounts)?;
    let spent: Vec<TxOut> = spends.iter().map(|s| s.spent.clone()).collect();
    for (i, s) in spends.iter().enumerate() {
        let keys = accounts[s.account].keys;
        match s.kind {
            Kind::Segwit | Kind::Legacy => {
                let script_code = p2pkh_script(&s.key.public);
                let digest = match s.kind {
                    Kind::Segwit => sighash(&psbt.tx, i, &s.key.public, s.spent.value),
                    _ if s.hash_type == SIGHASH_ALL_FORKID => {
                        bip143_sighash(&psbt.tx, i, &script_code, s.spent.value, SIGHASH_ALL_FORKID as u32)
                    }
                    _ => legacy_sighash(&psbt.tx, i, &script_code),
                };
                let (sig, _) = keys.sign_ecdsa(&s.key.path, &digest).map_err(Error::Keys)?;
                let mut value = der(&sig);
                value.push(s.hash_type); // SIGHASH_ALL, with Bitcoin Cash's fork ID there
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
    const INPUT: &str =
        "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
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
