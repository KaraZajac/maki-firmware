//! Multisig: a wallet whose coins take k of n keys' signatures, maki's among them, as Sparrow,
//! Nunchuk, Specter, Coldcard and Bitcoin Core make them: native SegWit (P2WSH),
//! `wsh(sortedmulti(k, …))`, each key an account at BIP48's `m/48'/coin'/account'/2'`.
//!
//! maki signs for one only once it's registered: its owner has gone through it on maki's screen
//! (the threshold, and every key, maki's among them) and said yes. After that, what a computer
//! says about it doesn't count: an input is spent only if its script is the wallet's, rebuilt from
//! the registered keys at the input's place in it, and change is called change only if it pays
//! the wallet's own change chain. A computer can't swap a key, or pass off change to a wallet it
//! controls.
//!
//! A wallet comes as an output descriptor (BIP380, with BIP389's `<0;1>` for both chains, or a
//! chain's alone, `/0/*`) or as the multisig file Coldcard's firmware takes, which Sparrow and
//! others export:
//!
//! ```text
//! Name: Family vault
//! Policy: 2 of 3
//! Derivation: m/48'/0'/0'/2'
//! Format: P2WSH
//!
//! 73C5DA0A: xpub6…
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use maki_hd::{HARDENED, Keys};

use crate::address::{Network, address, describe};
use crate::bip32::{Xpub, multisig_version};
use crate::hash::sha256;
use crate::psbt::{self, Psbt, parse_derivation};
use crate::tx::TxOut;
use crate::wallet::{
    Error, Output, Review, der, descriptor_checksum, previous_output, segwit_sighash, total, witness_utxo,
};

/// BIP48's script type for native SegWit multisig: P2WSH.
pub const P2WSH: u32 = 2;
/// The most keys a wallet may have (as Coldcard allows), and a name's most bytes.
pub const MAX_KEYS: usize = 15;
pub const MAX_NAME: usize = 32;

/// One of a wallet's keys: whose (their master key's fingerprint), where (the path from it to the
/// account), and the account's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub fingerprint: [u8; 4],
    pub path: Vec<u32>,
    pub xpub: Xpub,
}

/// A multisig wallet, as registered: nothing about it is taken from a PSBT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Multisig {
    pub name: String,
    pub network: Network,
    /// how many of the keys' signatures a spend takes
    pub threshold: usize,
    pub keys: Vec<Key>,
    /// `sortedmulti`: each script's keys sorted (BIP67), as coordinators make them; else in order
    pub sorted: bool,
}

/// Why a wallet isn't one maki takes.
fn bad(why: &'static str) -> Error { Error::Multisig(why) }

/// A path as a descriptor writes it, after the fingerprint: `/48h/0h/0h/2h`.
fn path_text(path: &[u32]) -> String {
    path.iter()
        .map(|&n| if n >= HARDENED { format!("/{}h", n - HARDENED) } else { format!("/{}", n) })
        .collect()
}

/// `48'/0'/0'/2'`, `m/48h/…`, or `/48h/…`: a path's steps.
fn parse_steps(text: &str) -> Option<Vec<u32>> {
    let text = text.trim().trim_start_matches('m').trim_start_matches('/');
    if text.is_empty() {
        return Some(Vec::new());
    }
    text.split('/')
        .map(|step| {
            let (n, hard) = match step.strip_suffix(['\'', 'h', 'H']) {
                Some(n) => (n, true),
                None => (step, false),
            };
            let n: u32 = n.parse().ok().filter(|&n| n < HARDENED)?;
            Some(if hard { n | HARDENED } else { n })
        })
        .collect()
}

fn hex4(text: &str) -> Option<[u8; 4]> {
    if text.len() != 8 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }

impl Multisig {
    /// A wallet from a descriptor or a Coldcard multisig file; `name` names it if the text doesn't.
    pub fn parse(text: &str, name: &str) -> Result<Multisig, Error> {
        let text = text.trim();
        let wallet = if text.starts_with("wsh(") || text.starts_with("sh(") {
            Multisig::from_descriptor(text, name)?
        } else {
            Multisig::from_coldcard(text, name)?
        };
        wallet.checked()
    }

    /// `wsh(sortedmulti(k,[fp/path]xpub/<0;1>/*,…))`, its checksum checked if it has one.
    fn from_descriptor(text: &str, name: &str) -> Result<Multisig, Error> {
        let body = match text.split_once('#') {
            Some((body, sum)) => {
                if descriptor_checksum(body) != sum {
                    return Err(bad("the descriptor's checksum is wrong"));
                }
                body
            }
            None => text,
        };
        if body.starts_with("sh(") {
            return Err(bad("maki takes native SegWit multisig (wsh), not wrapped in P2SH"));
        }
        let inner = body
            .strip_prefix("wsh(")
            .and_then(|b| b.strip_suffix(')'))
            .ok_or(bad("not a wsh() descriptor"))?;
        let (sorted, args) = if let Some(a) = inner.strip_prefix("sortedmulti(") {
            (true, a)
        } else if let Some(a) = inner.strip_prefix("multi(") {
            (false, a)
        } else {
            return Err(bad("maki takes wsh(sortedmulti(…)) and wsh(multi(…)) wallets"));
        };
        let args = args.strip_suffix(')').ok_or(bad("the descriptor doesn't close"))?;
        let mut parts = args.split(',');
        let threshold: usize = parts.next().and_then(|k| k.trim().parse().ok()).ok_or(bad("no threshold"))?;
        let mut keys = Vec::new();
        for part in parts {
            // [fp/path]xpub/<0;1>/* (or /0/*, or /1/*: a chain's own descriptor)
            let part = part.trim();
            let rest = part.strip_prefix('[').ok_or(bad("each key needs its origin, [fingerprint/path]"))?;
            let (origin, key) = rest.split_once(']').ok_or(bad("a key's origin doesn't close"))?;
            let (fp, path) = origin.split_once('/').unwrap_or((origin, ""));
            let fingerprint = hex4(fp).ok_or(bad("a key's fingerprint isn't 8 hex digits"))?;
            let path = parse_steps(path).ok_or(bad("a key's path isn't one"))?;
            let (xpub, suffix) = key.split_once('/').ok_or(bad("each key needs its chains, /<0;1>/*"))?;
            if !matches!(suffix, "<0;1>/*" | "0/*" | "1/*") {
                return Err(bad("maki takes keys' chains as /<0;1>/*, /0/* or /1/*"));
            }
            let xpub = Xpub::parse(xpub).ok_or(bad("a key isn't an xpub"))?;
            keys.push(Key { fingerprint, path, xpub });
        }
        let network = keys.first().map(|k| k.xpub.network).ok_or(bad("no keys"))?;
        Ok(Multisig { name: name.to_string(), network, threshold, keys, sorted })
    }

    /// Coldcard's multisig file: `Name:`, `Policy: k of n`, `Derivation:` (for the keys after it),
    /// `Format: P2WSH`, then `FINGERPRINT: xpub` for each key.
    fn from_coldcard(text: &str, name: &str) -> Result<Multisig, Error> {
        let (mut named, mut policy, mut derivation, mut format) = (None, None, None, None);
        let mut keys = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (field, value) =
                line.split_once(':').ok_or(bad("not a multisig file: a line isn't `field: value`"))?;
            let (field, value) = (field.trim(), value.trim());
            match field.to_ascii_lowercase().as_str() {
                "name" => named = Some(value.to_string()),
                "policy" => {
                    let (k, n) = value
                        .split_once(" of ")
                        .or_else(|| value.split_once('/'))
                        .ok_or(bad("the policy isn't `k of n`"))?;
                    let k: usize = k.trim().parse().map_err(|_| bad("the policy isn't `k of n`"))?;
                    let n: usize = n.trim().parse().map_err(|_| bad("the policy isn't `k of n`"))?;
                    policy = Some((k, n));
                }
                "derivation" => {
                    derivation = Some(parse_steps(value).ok_or(bad("the derivation isn't a path"))?)
                }
                "format" => format = Some(value.to_ascii_uppercase()),
                other => {
                    let fingerprint = hex4(other).ok_or(bad("not a multisig file: a line isn't a key's"))?;
                    let path = derivation.clone().ok_or(bad("a key comes before its derivation"))?;
                    let xpub = Xpub::parse(value).ok_or(bad("a key isn't an xpub"))?;
                    keys.push(Key { fingerprint, path, xpub });
                }
            }
        }
        if format.as_deref() != Some("P2WSH") {
            return Err(bad("maki takes native SegWit multisig (Format: P2WSH)"));
        }
        let (threshold, n) = policy.ok_or(bad("the file has no policy"))?;
        if n != keys.len() {
            return Err(bad("the policy's count of keys isn't the file's"));
        }
        let network = keys.first().map(|k| k.xpub.network).ok_or(bad("no keys"))?;
        Ok(Multisig {
            name: named.unwrap_or_else(|| name.to_string()),
            network,
            threshold,
            keys,
            sorted: true,
        })
    }

    /// What every wallet must be: k of n, each key an account at BIP48's P2WSH path on the
    /// wallet's network, told apart; a name, printable and short.
    fn checked(mut self) -> Result<Multisig, Error> {
        let n = self.keys.len();
        if !(2..=MAX_KEYS).contains(&n) || !(1..=n).contains(&self.threshold) {
            return Err(bad("maki takes 1 to 15 of 2 to 15 keys"));
        }
        let coin = self.network.coin_type() | HARDENED;
        for (i, k) in self.keys.iter().enumerate() {
            if k.xpub.network != self.network {
                return Err(bad("its keys are for different networks"));
            }
            if k.path.len() != 4
                || k.path[0] != 48 | HARDENED
                || k.path[1] != coin
                || k.path[2] < HARDENED
                || k.path[3] != P2WSH | HARDENED
            {
                return Err(bad("each key must be an account at m/48'/coin'/account'/2' (BIP48, P2WSH)"));
            }
            if k.xpub.depth as usize != k.path.len() || k.xpub.child_number != k.path[3] {
                return Err(bad("a key's path isn't where its xpub says it is"));
            }
            if self.keys[..i].iter().any(|o| o.xpub.key == k.xpub.key) {
                return Err(bad("a key is in it twice"));
            }
        }
        let name: String =
            self.name.trim().chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(MAX_NAME).collect();
        self.name = if name.is_empty() { format!("{} of {} multisig", self.threshold, n) } else { name };
        Ok(self)
    }

    /// The wallet as a descriptor, both chains, with its checksum: how maki keeps it, and the same
    /// text for the same wallet however it came.
    pub fn descriptor(&self) -> String {
        let keys: Vec<String> = self
            .keys
            .iter()
            .map(|k| {
                format!(
                    "[{}{}]{}/<0;1>/*",
                    hex(&k.fingerprint),
                    path_text(&k.path),
                    k.xpub.encode(self.network.xpub_version())
                )
            })
            .collect();
        let body = format!(
            "wsh({}({},{}))",
            if self.sorted { "sortedmulti" } else { "multi" },
            self.threshold,
            keys.join(",")
        );
        format!("{}#{}", body, descriptor_checksum(&body))
    }

    /// A short name for it that the same wallet always has: its descriptor's hash, 4 bytes.
    pub fn id(&self) -> [u8; 4] { sha256(self.descriptor().as_bytes())[..4].try_into().unwrap() }

    /// The keys' xpubs for each chain, receive and change: derived once, for the scripts after.
    pub fn chains(&self) -> Result<Vec<[Xpub; 2]>, Error> {
        self.keys
            .iter()
            .map(|k| Ok([k.xpub.child(0).ok_or(Error::Key)?, k.xpub.child(1).ok_or(Error::Key)?]))
            .collect()
    }

    /// The witness script at `index` on a chain (0 receive, 1 change): `k <keys> n CHECKMULTISIG`.
    pub fn script(&self, chains: &[[Xpub; 2]], change: bool, index: u32) -> Result<Vec<u8>, Error> {
        let mut keys = Vec::with_capacity(chains.len());
        for c in chains {
            keys.push(c[change as usize].child(index).ok_or(Error::Key)?.key);
        }
        if self.sorted {
            keys.sort();
        }
        let mut s = Vec::with_capacity(3 + 34 * keys.len());
        s.push(0x50 + self.threshold as u8);
        for k in &keys {
            s.push(33);
            s.extend_from_slice(k);
        }
        s.push(0x50 + keys.len() as u8);
        s.push(0xae);
        Ok(s)
    }

    /// The output script paying a witness script: P2WSH.
    pub fn script_pubkey(witness_script: &[u8]) -> Vec<u8> {
        let mut s = Vec::with_capacity(34);
        s.extend_from_slice(&[0x00, 0x20]);
        s.extend_from_slice(&sha256(witness_script));
        s
    }

    /// An address of the wallet's.
    pub fn address(&self, chains: &[[Xpub; 2]], change: bool, index: u32) -> Result<String, Error> {
        if index >= HARDENED {
            return Err(Error::Key);
        }
        address(&Multisig::script_pubkey(&self.script(chains, change, index)?), self.network)
            .ok_or(Error::Key)
    }
}

/// maki's key as a cosigner: its account at `m/48'/coin'/0'/2'`, with its origin, as Sparrow and
/// Coldcard take a key to make a multisig wallet with (`[73c5da0a/48h/0h/0h/2h]Zpub…`).
pub fn cosigner(keys: &dyn Keys, network: Network) -> Result<String, Error> {
    let path = [48 | HARDENED, network.coin_type() | HARDENED, HARDENED, P2WSH | HARDENED];
    let fp = keys.fingerprint().map_err(Error::Keys)?;
    let public = keys.public(&path).map_err(Error::Keys)?;
    let key = crate::bip32::xpub(multisig_version(network), 4, path[3], &public);
    Ok(format!("[{}{}]{}", hex(&fp), path_text(&path), key))
}

/// A registered wallet with maki's key in it, ready to review and sign what spends from it.
pub struct Signer<'k> {
    pub wallet: Multisig,
    /// which of its keys is maki's
    pub ours: usize,
    keys: &'k dyn Keys,
    fingerprint: [u8; 4],
    chains: Vec<[Xpub; 2]>,
    /// the scripts made so far, by chain and index: each is n public derivations
    scripts: core::cell::RefCell<alloc::collections::BTreeMap<(bool, u32), Vec<u8>>>,
}

/// An input of the wallet's: which script, maki's key there, and what it spends.
struct Spend {
    script: Vec<u8>,
    path: Vec<u32>,
    public: [u8; 33],
    spent: TxOut,
}

impl<'k> Signer<'k> {
    /// The wallet, if exactly one of its keys is maki's: its fingerprint, at its path, the key
    /// maki makes there.
    pub fn new(wallet: Multisig, keys: &'k dyn Keys) -> Result<Signer<'k>, Error> {
        let fingerprint = keys.fingerprint().map_err(Error::Keys)?;
        let mut ours = None;
        for (i, k) in wallet.keys.iter().enumerate() {
            if k.fingerprint != fingerprint {
                continue;
            }
            let mine = keys.public(&k.path).map_err(Error::Keys)?;
            if mine.key != k.xpub.key || mine.chain_code != k.xpub.chain_code {
                return Err(bad("it names maki's fingerprint with a key that isn't maki's"));
            }
            if ours.replace(i).is_some() {
                return Err(bad("maki's key is in it twice"));
            }
        }
        let ours = ours.ok_or(bad("maki's key isn't one of its keys"))?;
        let chains = wallet.chains()?;
        Ok(Signer { wallet, ours, keys, fingerprint, chains, scripts: Default::default() })
    }

    pub fn address(&self, change: bool, index: u32) -> Result<String, Error> {
        if index >= HARDENED {
            return Err(Error::Key);
        }
        address(&Multisig::script_pubkey(&self.script(change, index)?), self.wallet.network).ok_or(Error::Key)
    }

    /// The wallet's witness script there, made once.
    fn script(&self, change: bool, index: u32) -> Result<Vec<u8>, Error> {
        if let Some(s) = self.scripts.borrow().get(&(change, index)) {
            return Ok(s.clone());
        }
        let s = self.wallet.script(&self.chains, change, index)?;
        self.scripts.borrow_mut().insert((change, index), s.clone());
        Ok(s)
    }

    /// Where a derivation names maki's key in the wallet: its chain and index there, if it's
    /// maki's key's, on a chain of the wallet's, and the key's what maki makes.
    fn ours(&self, derivation: &[u8], public_key: &[u8]) -> Option<(bool, u32, Vec<u32>, [u8; 33])> {
        let (fp, path) = parse_derivation(derivation)?;
        let account = &self.wallet.keys[self.ours].path;
        if fp != self.fingerprint || path.len() != account.len() + 2 || path[..account.len()] != account[..] {
            return None;
        }
        let (chain, index) = (path[account.len()], path[account.len() + 1]);
        if chain > 1 || index >= HARDENED {
            return None;
        }
        let public = self.keys.public(&path).ok()?.key;
        (public[..] == *public_key).then_some((chain == 1, index, path, public))
    }

    /// Check every input, and work out what each one spends.
    fn spends(&self, psbt: &Psbt) -> Result<Vec<Spend>, Error> {
        let mut out = Vec::with_capacity(psbt.tx.inputs.len());
        for (i, input) in psbt.tx.inputs.iter().enumerate() {
            // the whole previous transaction: amounts are never taken on the PSBT's word
            let bytes = psbt.input(i, psbt::IN_NON_WITNESS_UTXO).ok_or(Error::NoPreviousTx(i))?;
            let spent = previous_output(bytes, &input.prev_txid, input.prev_vout)
                .ok_or(Error::PreviousTxMismatch(i))?;
            if let Some(claimed) = psbt.input(i, psbt::IN_WITNESS_UTXO) {
                if witness_utxo(claimed).as_ref() != Some(&spent) {
                    return Err(Error::PreviousTxMismatch(i));
                }
            }
            if psbt.input(i, psbt::IN_SIGHASH_TYPE).is_some_and(|t| t != [1, 0, 0, 0]) {
                return Err(Error::Sighash(i));
            }
            if psbt.input(i, psbt::IN_REDEEM_SCRIPT).is_some() {
                return Err(Error::Psbt("an input is wrapped in P2SH: maki signs native SegWit multisig"));
            }
            let (change, index, path, public) = psbt.inputs[i]
                .iter()
                .filter(|p| p.key.first() == Some(&psbt::IN_BIP32_DERIVATION) && p.key.len() == 34)
                .find_map(|p| self.ours(&p.value, &p.key[1..]))
                .ok_or(Error::NotOurs(i))?;
            // the wallet's script there, rebuilt from its keys: not the PSBT's
            let script = self.script(change, index)?;
            if Multisig::script_pubkey(&script) != spent.script_pubkey {
                return Err(Error::NotOurs(i));
            }
            if psbt.input(i, psbt::IN_WITNESS_SCRIPT).is_some_and(|s| s != script) {
                return Err(Error::NotOurs(i));
            }
            out.push(Spend { script, path, public, spent });
        }
        Ok(out)
    }

    /// Whether an output is change: it names maki's key on the wallet's change chain, and pays
    /// the wallet's script there.
    fn is_change(&self, pairs: &[psbt::Pair], script_pubkey: &[u8]) -> bool {
        pairs.iter().any(|p| {
            p.key.first() == Some(&psbt::OUT_BIP32_DERIVATION)
                && p.key.len() == 34
                && self.ours(&p.value, &p.key[1..]).is_some_and(|(change, index, _, _)| {
                    change
                        && self
                            .script(true, index)
                            .is_ok_and(|s| Multisig::script_pubkey(&s) == script_pubkey)
                })
        })
    }

    fn check(&self, psbt: &Psbt) -> Result<(Review, Vec<Spend>), Error> {
        if psbt.tx.inputs.is_empty() || psbt.tx.outputs.is_empty() {
            return Err(Error::Psbt("a transaction needs inputs and outputs"));
        }
        let spends = self.spends(psbt)?;
        let total_in = total(spends.iter().map(|s| s.spent.value))?;
        let total_out = total(psbt.tx.outputs.iter().map(|o| o.value))?;
        let fee = total_in.checked_sub(total_out).ok_or(Error::NegativeFee)?;
        let outputs = psbt
            .tx
            .outputs
            .iter()
            .enumerate()
            .map(|(j, o)| Output {
                address: describe(&o.script_pubkey, self.wallet.network),
                amount: o.value,
                change: self.is_change(&psbt.outputs[j], &o.script_pubkey),
            })
            .collect();
        // signed size: the transaction, marker and flag, and each input's witness once complete:
        // the empty item CHECKMULTISIG takes, k signatures (72 bytes at most, low-S) and the script
        let k = self.wallet.threshold as u64;
        let witnesses: u64 = spends.iter().map(|s| 1 + 1 + k * (1 + 72) + 3 + s.script.len() as u64).sum();
        let weight = psbt.tx.serialize().len() as u64 * 4 + 2 + witnesses;
        let name = format!("{} ({} of {})", self.wallet.name, self.wallet.threshold, self.wallet.keys.len());
        let review = Review {
            network: self.wallet.network,
            wallet: Some(name),
            outputs,
            fee,
            vbytes: weight.div_ceil(4),
            inputs: spends.len(),
        };
        Ok((review, spends))
    }

    /// What a transaction spending from the wallet does, checked.
    pub fn review(&self, psbt: &Psbt) -> Result<Review, Error> { self.check(psbt).map(|(r, _)| r) }

    /// Signs every input with maki's key (all are the wallet's; `review` has checked): a partial
    /// signature each, deterministic and low-S, beside any the other keys made. How many it made.
    pub fn sign(&self, psbt: &mut Psbt) -> Result<usize, Error> {
        let (_, spends) = self.check(psbt)?;
        for (i, s) in spends.iter().enumerate() {
            let digest = segwit_sighash(&psbt.tx, i, &s.script, s.spent.value);
            let (sig, _) = self.keys.sign_ecdsa(&s.path, &digest).map_err(Error::Keys)?;
            let mut value = der(&sig);
            value.push(0x01); // SIGHASH_ALL
            let mut key = Vec::with_capacity(34);
            key.push(psbt::IN_PARTIAL_SIG);
            key.extend_from_slice(&s.public);
            psbt.set_input(i, key, value);
        }
        Ok(spends.len())
    }
}

/// Whether a PSBT spends from a multisig wallet: an input with a witness script, or maki's key at
/// BIP48's path.
pub fn is_multisig(psbt: &Psbt) -> bool {
    (0..psbt.tx.inputs.len()).any(|i| {
        psbt.input(i, psbt::IN_WITNESS_SCRIPT).is_some()
            || psbt.inputs[i].iter().any(|p| {
                p.key.first() == Some(&psbt::IN_BIP32_DERIVATION)
                    && parse_derivation(&p.value)
                        .is_some_and(|(_, path)| path.first() == Some(&(48 | HARDENED)))
            })
    })
}
