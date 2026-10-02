//! The account, and what's done with a request: check it against the account, then sign it.

use alloc::string::String;
use alloc::vec::Vec;

use maki_hd::{HARDENED, Keys, Public};

use crate::address::{self, key_script, p2pkh_hash};
use crate::request::{Derivation, Request, Shown};
use crate::sighash::{SIGHASH_ALL, Signing, Spent};
use crate::{Error, Network};

/// The account's path on a network, `m/44'/133'/0'` (`m/44'/1'/0'` on the test network): the
/// first transparent account Zcash's wallets make from a phrase.
pub fn account_path(network: Network) -> [u32; 3] {
    [44 | HARDENED, network.coin_type() | HARDENED, HARDENED]
}

/// ZIP-317's marginal fee, zatoshis for each logical action.
pub const MARGINAL_FEE: u64 = 5_000;
/// ZIP-317's grace actions: the fewest a transaction is charged for.
pub const GRACE_ACTIONS: u64 = 2;
/// ZIP-317's standard sizes: an input that pays a key's hash, signed, and an output that does.
pub const P2PKH_INPUT_SIZE: u64 = 150;
pub const P2PKH_OUTPUT_SIZE: u64 = 34;
/// The longest data output Zcash's nodes relay (zcashd's `MAX_OP_RETURN_RELAY`): OP_RETURN and its
/// pushes.
pub const MAX_DATA: usize = 83;

/// Account 0 of the phrase's, on a network. Its keys are maki's (`maki_hd::Keys`): the account asks
/// for public keys and signatures by path.
pub struct Account<'k> {
    pub network: Network,
    keys: &'k dyn Keys,
    /// The account's key and chain code: what a wallet on the computer makes every address of the
    /// account's from (view only).
    pub public: Public,
}

/// What an output does, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Paid {
    /// Pays someone: this t-address.
    Payment(String),
    /// Pays someone: this TEX address (ZIP-320), the owner's spelling of a key's hash.
    Tex(String),
    /// Writes this data on the chain (OP_RETURN), the bytes its pushes carry: the output can't be
    /// spent.
    Data(Vec<u8>),
    /// Comes back to this wallet, at this key.
    Change(Derivation),
}

/// A request checked against the account: every input its, what each output does, the fee, and
/// ZIP-317's conventional fee for it. Only `Account::check` makes one, and `Account::sign` signs
/// nothing else.
#[non_exhaustive]
pub struct Checked<'r> {
    pub network: Network,
    pub request: &'r Request,
    /// Each output's, in order.
    pub outputs: Vec<Paid>,
    pub fee: u64,
    pub conventional_fee: u64,
}

/// The data a data output (OP_RETURN, then pushes alone, as Zcash's nodes relay it) carries, or None
/// if the script isn't one.
pub fn data(script: &[u8]) -> Option<Vec<u8>> {
    let (&op, mut rest) = script.split_first()?;
    if op != 0x6a || script.len() > MAX_DATA {
        return None;
    }
    let mut out = Vec::new();
    while let Some((&op, after)) = rest.split_first() {
        let (n, after) = match op {
            0x00 => (0, after),
            0x01..=0x4b => (op as usize, after),
            // OP_PUSHDATA1 and OP_PUSHDATA2 (OP_PUSHDATA4 can't fit)
            0x4c => (*after.first()? as usize, &after[1..]),
            0x4d => (u16::from_le_bytes(after.get(..2)?.try_into().ok()?) as usize, &after[2..]),
            _ => return None,
        };
        out.extend_from_slice(after.get(..n)?);
        rest = &after[n..];
    }
    Some(out)
}

/// ZIP-317's conventional fee for a transaction of this wallet's coins: each input pays a key's
/// hash, and counts as the standard one (as librustzcash counts it); the outputs count by their
/// size. The marginal fee for each logical action, two at least.
pub fn conventional_fee(request: &Request) -> u64 {
    let inputs = request.tx.inputs.len() as u64 * P2PKH_INPUT_SIZE;
    let outputs: u64 = request
        .tx
        .outputs
        .iter()
        .map(|o| {
            let mut buf = Vec::new();
            o.write(&mut buf);
            buf.len() as u64
        })
        .sum();
    let actions = inputs.div_ceil(P2PKH_INPUT_SIZE).max(outputs.div_ceil(P2PKH_OUTPUT_SIZE));
    MARGINAL_FEE * actions.max(GRACE_ACTIONS)
}

/// DER, as a transparent input's script carries an ECDSA signature (r and s, 32 bytes each): two
/// positive integers, no padding beyond one zero.
pub fn der(sig: &[u8; 64]) -> Vec<u8> {
    let int = |b: &[u8]| -> Vec<u8> {
        let b = &b[b.iter().position(|&x| x != 0).unwrap_or(b.len() - 1)..];
        let pad = b[0] & 0x80 != 0;
        let mut v = Vec::with_capacity(35);
        v.push(0x02);
        v.push((b.len() + pad as usize) as u8);
        if pad {
            v.push(0);
        }
        v.extend_from_slice(b);
        v
    };
    let (r, s) = (int(&sig[..32]), int(&sig[32..]));
    let mut out = Vec::with_capacity(72);
    out.push(0x30);
    out.push((r.len() + s.len()) as u8);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

impl<'k> Account<'k> {
    pub fn new(keys: &'k dyn Keys, network: Network) -> Result<Account<'k>, Error> {
        let public = keys.public(&account_path(network)).map_err(Error::Keys)?;
        Ok(Account { network, keys, public })
    }

    /// The full path of a key of the account's.
    pub fn path(&self, key: Derivation) -> [u32; 5] {
        let [purpose, coin, account] = account_path(self.network);
        [purpose, coin, account, key.chain as u32, key.index]
    }

    /// A key of the account's, compressed: on its receive or change chain, unhardened.
    pub fn key(&self, key: Derivation) -> Result<[u8; 33], Error> {
        let key = Derivation::new(key.chain, key.index).ok_or(Error::Path)?;
        Ok(self.keys.public(&self.path(key)).map_err(Error::Keys)?.key)
    }

    /// An address of the account's: to show, and to check against the computer's.
    pub fn address(&self, key: Derivation) -> Result<String, Error> {
        Ok(address::of_key(self.network, &self.key(key)?))
    }

    /// Whether every input is this wallet's (its coin pays the key it names), and what each output
    /// does: change, if it names a key of this wallet's and pays it; a payment shown as a TEX
    /// address, if it pays a key's hash; else a payment to an address, or data.
    pub fn check<'r>(&self, request: &'r Request) -> Result<Checked<'r>, Error> {
        request.check()?;
        // the scripts this wallet's keys pay, each key derived once
        let mut scripts: Vec<(Derivation, Vec<u8>)> = Vec::new();
        let mut script = |key: Derivation| -> Result<Vec<u8>, Error> {
            if let Some((_, s)) = scripts.iter().find(|(k, _)| *k == key) {
                return Ok(s.clone());
            }
            let s = key_script(&self.key(key)?);
            scripts.push((key, s.clone()));
            Ok(s)
        };
        for (i, coin) in request.coins.iter().enumerate() {
            if coin.script != script(coin.key)? {
                return Err(Error::NotOurs(i));
            }
        }
        let mut outputs = Vec::with_capacity(request.outputs.len());
        for (j, (shown, output)) in request.outputs.iter().zip(&request.tx.outputs).enumerate() {
            outputs.push(match shown {
                Shown::Change(key) if output.script == script(*key)? => Paid::Change(*key),
                Shown::Change(_) => return Err(Error::NotChange(j)),
                Shown::Tex => match p2pkh_hash(&output.script) {
                    Some(hash) => Paid::Tex(address::tex(self.network, &hash)),
                    None => return Err(Error::NotTex(j)),
                },
                Shown::Payment => match address::of_script(self.network, &output.script) {
                    Some(a) => Paid::Payment(a),
                    None => Paid::Data(data(&output.script).ok_or(Error::NonStandard(j))?),
                },
            });
        }
        Ok(Checked {
            network: self.network,
            request,
            outputs,
            fee: request.fee()?,
            conventional_fee: conventional_fee(request),
        })
    }

    /// A signature for every input, in order, as its script pushes it: ECDSA over its signature
    /// hash (ZIP-244, SIGHASH_ALL), DER, then the hash type's byte. maki makes each (RFC 6979, low
    /// S) and checks it before it's given. An input's script is its signature pushed, then its key
    /// (33 bytes) pushed.
    pub fn sign(&self, checked: &Checked) -> Result<Vec<Vec<u8>>, Error> {
        let request = checked.request;
        let spent = request.coins.iter().map(|c| Spent { amount: c.amount, script: &c.script }).collect();
        let signing = Signing::new(&request.tx, spent);
        let mut out = Vec::with_capacity(request.coins.len());
        for (i, coin) in request.coins.iter().enumerate() {
            let digest = signing.signature_hash(i).ok_or(Error::Empty)?;
            let (sig, _) = self.keys.sign_ecdsa(&self.path(coin.key), &digest).map_err(Error::Keys)?;
            let mut signature = der(&sig);
            signature.push(SIGHASH_ALL);
            out.push(signature);
        }
        Ok(out)
    }
}
