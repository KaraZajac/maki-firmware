//! The account, and what's done with a request: check it against the account, then sign it.

use alloc::string::String;
use alloc::vec::Vec;

use maki_hd::{HARDENED, Keys, Public, Tweak};

use crate::address::{self, schnorr_script, x_only};
use crate::request::{Derivation, Request, Script};
use crate::sighash::{Reused, SIG_HASH_ALL, signature_hash};
use crate::{COIN_TYPE, Error, Network};

/// The account's path, `m/44'/111111'/0'`: the first account Kaspa's wallets make from a phrase.
pub const ACCOUNT: [u32; 3] = [44 | HARDENED, COIN_TYPE | HARDENED, HARDENED];

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
    /// Pays someone: this address.
    Payment(String),
    /// Comes back to this wallet, at this key.
    Change(Derivation),
}

/// A request checked against the account: every input its, what each output does, and the fee.
/// Only `Account::check` makes one, and `Account::sign` signs nothing else.
#[non_exhaustive]
pub struct Checked<'r> {
    pub network: Network,
    pub request: &'r Request,
    /// Each output's, in order.
    pub outputs: Vec<Paid>,
    pub fee: u64,
}

impl<'k> Account<'k> {
    pub fn new(keys: &'k dyn Keys, network: Network) -> Result<Account<'k>, Error> {
        let public = keys.public(&ACCOUNT).map_err(Error::Keys)?;
        Ok(Account { network, keys, public })
    }

    /// The full path of a key of the account's.
    pub fn path(key: Derivation) -> [u32; 5] {
        [ACCOUNT[0], ACCOUNT[1], ACCOUNT[2], key.chain as u32, key.index]
    }

    /// A key of the account's, compressed: on its receive or change chain, unhardened.
    pub fn key(&self, key: Derivation) -> Result<[u8; 33], Error> {
        let key = Derivation::new(key.chain, key.index).ok_or(Error::Path)?;
        Ok(self.keys.public(&Self::path(key)).map_err(Error::Keys)?.key)
    }

    /// An address of the account's: to show, and to check against the computer's.
    pub fn address(&self, key: Derivation) -> Result<String, Error> {
        Ok(address::of_key(self.network, &self.key(key)?))
    }

    /// Whether every input is this wallet's (its coin pays the key it names, and commits to the one
    /// signature check that takes), and what each output does: change, if it names a key of this
    /// wallet's and pays it; else a payment, to an address.
    pub fn check<'r>(&self, request: &'r Request) -> Result<Checked<'r>, Error> {
        request.check()?;
        // the scripts this wallet's keys pay, each key derived once
        let mut scripts: Vec<(Derivation, Script)> = Vec::new();
        let mut script = |key: Derivation| -> Result<Script, Error> {
            if let Some((_, s)) = scripts.iter().find(|(k, _)| *k == key) {
                return Ok(s.clone());
            }
            let s = Script { version: 0, script: schnorr_script(&x_only(&self.key(key)?)) };
            scripts.push((key, s.clone()));
            Ok(s)
        };
        for (i, input) in request.inputs.iter().enumerate() {
            if input.script != script(input.key)? {
                return Err(Error::NotOurs(i));
            }
            if request.version == 0 && input.sig_op_count != 1 {
                return Err(Error::SigOps(i));
            }
        }
        let mut outputs = Vec::with_capacity(request.outputs.len());
        for (j, output) in request.outputs.iter().enumerate() {
            outputs.push(match output.ours {
                Some(key) if output.script == script(key)? => Paid::Change(key),
                Some(_) => return Err(Error::NotChange(j)),
                None => Paid::Payment(
                    address::of_script(self.network, &output.script).ok_or(Error::NonStandard(j))?,
                ),
            });
        }
        Ok(Checked { network: self.network, request, outputs, fee: request.fee()? })
    }

    /// A signature for every input (BIP340 over its SIGHASH_ALL signature hash, then the hash
    /// type's byte, as the input's signature script will carry it), in order. maki makes each,
    /// with fresh randomness, and checks it before it's given.
    pub fn sign(&self, checked: &Checked) -> Result<Vec<[u8; 65]>, Error> {
        let request = checked.request;
        let mut reused = Reused::default();
        let mut out = Vec::with_capacity(request.inputs.len());
        for (i, input) in request.inputs.iter().enumerate() {
            let digest = signature_hash(request, i, SIG_HASH_ALL, &mut reused).ok_or(Error::Empty)?;
            let sig =
                self.keys.sign_schnorr(&Self::path(input.key), &digest, Tweak::None).map_err(Error::Keys)?;
            let mut signature = [0u8; 65];
            signature[..64].copy_from_slice(&sig);
            signature[64] = SIG_HASH_ALL.to_u8();
            out.push(signature);
        }
        Ok(out)
    }
}
