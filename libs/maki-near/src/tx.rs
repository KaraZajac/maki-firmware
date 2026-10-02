//! A NEAR transaction, nearcore's `Transaction` of the first kind (`TransactionV0`), as borsh
//! writes it: who signs it and with which key, a nonce, who it's for, a recent block's hash, and
//! its actions, every one of which acts on that receiver. Read as nearcore reads it (`borsh`) and
//! held to what nearcore checks before it takes a transaction (`validate_transaction`), so anything
//! NEAR would refuse maki refuses before it's shown. The actions maki reads are the eleven NEAR's
//! own JavaScript library makes (near-api-js 7.3): accounts made and deleted, contracts deployed,
//! published and used, calls, NEAR sent, staking, and keys added and deleted; and meta transactions
//! as far as their name, to refuse them. NEAR's newer actions and newer kind of transaction (gas
//! keys', state inits'), which that library doesn't make, it refuses by name.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha3::{Digest, Sha3_256};

use crate::borsh::Reader;
use crate::{Key, account, base58};

/// The longest transaction maki reads: a message from the computer is 4096 bytes at most. (NEAR
/// takes 1.5 MiB, for a contract's code.)
pub const MAX_TRANSACTION: usize = 4096;
/// The most actions one transaction can have (nearcore's `max_actions_per_receipt`).
pub const MAX_ACTIONS: usize = 100;
/// The most contracts one transaction can deploy or publish (`max_deploy_actions_per_receipt`).
pub const MAX_DEPLOYS: usize = 10;
/// The longest method name a call can have, or a key can name, in bytes (`max_length_method_name`).
pub const MAX_METHOD_NAME: usize = 256;
/// The most bytes the method names a key may call can take in all, each counted with one more
/// for its end (`max_number_bytes_method_names`).
pub const MAX_METHOD_NAMES: usize = 2_000;
/// The most gas a transaction's calls can have between them, 1 PGas (`max_total_prepaid_gas`).
pub const MAX_PREPAID_GAS: u64 = 1_000_000_000_000_000;
/// An ML-DSA-65 public key's length (FIPS 204), NEAR's post-quantum keys.
pub const ML_DSA_65_KEY: usize = 1952;

/// Why maki won't read a transaction: each says why, for the computer that sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Longer than maki reads.
    TooBig,
    /// Cut short, or with bytes after it.
    Length,
    /// Not borsh as nearcore reads it: a string that isn't UTF-8, a tag there isn't.
    Encoding,
    /// An account's name NEAR doesn't take.
    Account,
    /// NEAR's newer kind of transaction (`TransactionV1`, for gas keys), which maki doesn't sign.
    Version,
    /// A kind of action maki doesn't sign: its name.
    Unsupported(&'static str),
    /// Something NEAR would refuse, or that maki can't show for what it is: why.
    Invalid(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooBig => f.write_str("bigger than maki takes a NEAR transaction"),
            Error::Length => f.write_str("not a NEAR transaction: cut short, or with more after it"),
            Error::Encoding => f.write_str("not a NEAR transaction as borsh writes one"),
            Error::Account => f.write_str("an account name NEAR doesn't take"),
            Error::Version => {
                f.write_str("a transaction of NEAR's newer kind, for gas keys: maki doesn't sign those")
            }
            Error::Unsupported(name) => {
                // "a UniversalStateInit": the names that take "an" are those with a vowel's sound
                let a = if name.starts_with(['a', 'e', 'i', 'o', 'A', 'E', 'I', 'O']) { "an" } else { "a" };
                write!(f, "{a} {name}: maki doesn't sign those")
            }
            Error::Invalid(why) => f.write_str(why),
        }
    }
}

/// A public key, as NEAR's transactions carry one: a byte for its kind, then the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// Ed25519 (kind 0): maki's keys, and most of NEAR's.
    Ed25519(Key),
    /// secp256k1 (kind 1), its point's x and y without SEC1's first byte.
    Secp256k1([u8; 64]),
    /// ML-DSA-65 (kind 2), a post-quantum key: `ML_DSA_65_KEY` bytes.
    MlDsa65(Vec<u8>),
}

impl PublicKey {
    fn read(r: &mut Reader) -> Result<PublicKey, Error> {
        match r.u8()? {
            0 => Ok(PublicKey::Ed25519(r.array()?)),
            1 => Ok(PublicKey::Secp256k1(r.array()?)),
            2 => Ok(PublicKey::MlDsa65(r.vec(ML_DSA_65_KEY)?)),
            _ => Err(Error::Encoding),
        }
    }

    /// Its kind, as NEAR names it.
    pub fn kind(&self) -> &'static str {
        match self {
            PublicKey::Ed25519(_) => "ed25519",
            PublicKey::Secp256k1(_) => "secp256k1",
            PublicKey::MlDsa65(_) => "ml-dsa-65",
        }
    }

    /// The key itself.
    pub fn data(&self) -> &[u8] {
        match self {
            PublicKey::Ed25519(k) => k,
            PublicKey::Secp256k1(k) => k,
            PublicKey::MlDsa65(k) => k,
        }
    }

    /// Whether NEAR stakes with it (nearcore's `is_valid_staking_key`): an Ed25519 key that's a
    /// point of the curve's prime-order group, as every key made the usual way is.
    pub fn can_stake(&self) -> bool {
        match self {
            PublicKey::Ed25519(k) => CompressedEdwardsY(*k).decompress().is_some_and(|p| p.is_torsion_free()),
            _ => false,
        }
    }

    /// The key as NEAR lists an account's keys: as it's written (`Display`), but a post-quantum
    /// key, which NEAR keeps only the hash of, by that hash (`ml-dsa-65-hash:` and the SHA3-256 of
    /// a tag and the key, in base58): some 60 characters to compare, where the key takes 2,600.
    pub fn listed(&self) -> String {
        match self {
            PublicKey::MlDsa65(k) => {
                let hash = Sha3_256::new().chain_update(ML_DSA_65_HASH_TAG).chain_update(k).finalize();
                format!("ml-dsa-65-hash:{}", base58::encode(&hash))
            }
            _ => self.to_string(),
        }
    }
}

/// What nearcore puts before a post-quantum key it hashes (its `HashDomainTag::MlDsa65PubkeyV1`).
const ML_DSA_65_HASH_TAG: &[u8] = b"near:ml-dsa-65-pubkey-hash:v1";

/// As NEAR writes it: its kind, a colon, and the key in base58 (`ed25519:6j4b…`).
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind(), base58::encode(self.data()))
    }
}

/// What a key added to an account may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Permission {
    /// Anything the account can.
    FullAccess,
    /// Only sign calls to one contract (`receiver`), to any of its methods or only those named,
    /// with nothing attached, its gas paid from the account's NEAR, up to `allowance` (yoctoNEAR)
    /// in all, or with no limit.
    FunctionCall { allowance: Option<u128>, receiver: String, methods: Vec<String> },
}

/// Published code, as an account that uses it names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Code {
    /// The code with this hash (SHA-256), which no one can change.
    Hash([u8; 32]),
    /// Whatever code this account has published under its name, now and after.
    Account(String),
}

/// An action: what a transaction does to its receiver. Amounts are in yoctoNEAR, gas in gas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// The receiver made, as a new account.
    CreateAccount,
    /// The receiver's code, replaced with this WebAssembly.
    DeployContract { code: Vec<u8> },
    /// One of the receiver's methods called, with `args`, `gas` for it to run on, and `deposit`
    /// sent to the receiver with it.
    FunctionCall { method: String, args: Vec<u8>, gas: u64, deposit: u128 },
    /// NEAR sent to the receiver.
    Transfer { deposit: u128 },
    /// The receiver staking `stake` as a validator, with `key`: the whole amount staked, not more.
    Stake { stake: u128, key: PublicKey },
    /// A key added to the receiver, which may do what `permission` says.
    AddKey { key: PublicKey, permission: Permission },
    /// A key taken from the receiver.
    DeleteKey { key: PublicKey },
    /// The receiver deleted, and its NEAR sent to `beneficiary`.
    DeleteAccount { beneficiary: String },
    /// Code published for any account to use, under its hash, or under the receiver's name
    /// (`by_account`), which can then change it for every account that uses it.
    DeployGlobalContract { code: Vec<u8>, by_account: bool },
    /// The receiver's code made the published code `Code` names.
    UseGlobalContract(Code),
}

impl Action {
    /// The gas it's given to run on: a call's.
    pub fn gas(&self) -> u64 {
        match self {
            Action::FunctionCall { gas, .. } => *gas,
            _ => 0,
        }
    }

    fn read(r: &mut Reader) -> Result<Action, Error> {
        Ok(match r.u8()? {
            0 => Action::CreateAccount,
            1 => Action::DeployContract { code: r.bytes()? },
            2 => {
                let method = r.string()?;
                let args = r.bytes()?;
                let (gas, deposit) = (r.u64()?, r.u128()?);
                if gas == 0 {
                    return Err(Error::Invalid("a call with no gas: NEAR would refuse it"));
                }
                if method.is_empty() {
                    return Err(Error::Invalid("a call to no method: NEAR would refuse it"));
                }
                if method.len() > MAX_METHOD_NAME {
                    return Err(Error::Invalid("a method name longer than NEAR takes"));
                }
                Action::FunctionCall { method, args, gas, deposit }
            }
            3 => Action::Transfer { deposit: r.u128()? },
            4 => {
                let stake = r.u128()?;
                let key = PublicKey::read(r)?;
                if !key.can_stake() {
                    return Err(Error::Invalid(
                        "a validator key NEAR can't stake with: NEAR would refuse it",
                    ));
                }
                Action::Stake { stake, key }
            }
            5 => {
                let key = PublicKey::read(r)?;
                let nonce = r.u64()?;
                let permission = read_permission(r)?;
                // NEAR gives a new key a nonce of its own, whatever this says
                if nonce != 0 {
                    return Err(Error::Invalid(
                        "a new key with a nonce, which NEAR sets itself: its libraries write 0",
                    ));
                }
                Action::AddKey { key, permission }
            }
            6 => Action::DeleteKey { key: PublicKey::read(r)? },
            7 => Action::DeleteAccount { beneficiary: read_account(r)? },
            8 => return Err(Error::Unsupported("Delegate action (a meta transaction, for another account)")),
            9 => {
                let code = r.bytes()?;
                let by_account = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(Error::Encoding),
                };
                Action::DeployGlobalContract { code, by_account }
            }
            10 => Action::UseGlobalContract(match r.u8()? {
                0 => Code::Hash(r.array()?),
                1 => Code::Account(read_account(r)?),
                _ => return Err(Error::Encoding),
            }),
            11 => return Err(Error::Unsupported("DeterministicStateInit action")),
            12 => return Err(Error::Unsupported("TransferToGasKey action")),
            13 => return Err(Error::Unsupported("WithdrawFromGasKey action")),
            14 => return Err(Error::Unsupported("DelegateV2 action")),
            15 => return Err(Error::Unsupported("UniversalStateInit action")),
            _ => return Err(Error::Unsupported("action of a kind NEAR doesn't have")),
        })
    }
}

/// An account's name, as nearcore reads one: a string, then held to NEAR's rules.
fn read_account(r: &mut Reader) -> Result<String, Error> {
    let id = r.string()?;
    if !account::valid(&id) {
        return Err(Error::Account);
    }
    Ok(id)
}

/// An access key's permission. Gas keys' (a key with NEAR of its own to pay gas from), which
/// near-api-js doesn't make, maki refuses.
fn read_permission(r: &mut Reader) -> Result<Permission, Error> {
    match r.u8()? {
        0 => {
            let allowance = if r.some()? { Some(r.u128()?) } else { None };
            // a string in nearcore, for keys from before names were checked; a new key's must be a name
            let receiver = read_account(r)?;
            let mut methods = Vec::new();
            let mut bytes = 0;
            for _ in 0..r.count(4)? {
                let method = r.string()?;
                if method.len() > MAX_METHOD_NAME {
                    return Err(Error::Invalid("a method name longer than NEAR takes"));
                }
                // NEAR lets it be, but no call has an empty method
                if method.is_empty() {
                    return Err(Error::Invalid("a key for a method with no name"));
                }
                bytes += method.len() + 1;
                methods.push(method);
            }
            if bytes > MAX_METHOD_NAMES {
                return Err(Error::Invalid("more method names than NEAR takes for a key"));
            }
            Ok(Permission::FunctionCall { allowance, receiver, methods })
        }
        1 => Ok(Permission::FullAccess),
        2 | 3 => Err(Error::Unsupported("gas key")),
        _ => Err(Error::Encoding),
    }
}

/// A transaction, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The account that signs it, and pays for it.
    pub signer: String,
    /// The key it's signed with, which must be one of the signer's.
    pub key: PublicKey,
    /// More than the key's last: NEAR takes each nonce once.
    pub nonce: u64,
    /// The account its actions act on.
    pub receiver: String,
    /// A recent block of the network it's for: NEAR takes it only while that block is one of its
    /// last 86,400.
    pub block_hash: [u8; 32],
    /// What it does, in order.
    pub actions: Vec<Action>,
}

impl Transaction {
    /// A transaction's borsh bytes, read whole: everything in it, nothing after it.
    pub fn parse(bytes: &[u8]) -> Result<Transaction, Error> {
        if bytes.len() > MAX_TRANSACTION {
            return Err(Error::TooBig);
        }
        // The first kind starts with the signer's length, whose second byte is 0 (no name is 256
        // long); the newer kind starts with a 1, then the signer's length, whose first byte isn't.
        match bytes {
            [1, b, ..] if *b != 0 => return Err(Error::Version),
            [_, b, ..] if *b != 0 => return Err(Error::Encoding),
            _ => {}
        }
        let mut r = Reader::new(bytes);
        let signer = read_account(&mut r)?;
        let key = PublicKey::read(&mut r)?;
        let nonce = r.u64()?;
        let receiver = read_account(&mut r)?;
        let block_hash = r.array()?;
        let n = r.count(1)?;
        if n > MAX_ACTIONS {
            return Err(Error::Invalid("more than 100 actions: NEAR would refuse it"));
        }
        let mut actions = Vec::with_capacity(n);
        for _ in 0..n {
            actions.push(Action::read(&mut r)?);
        }
        if !r.done() {
            return Err(Error::Length);
        }
        let tx = Transaction { signer, key, nonce, receiver, block_hash, actions };
        tx.validate()?;
        Ok(tx)
    }

    /// What nearcore checks of the actions together (`validate_actions`).
    fn validate(&self) -> Result<(), Error> {
        let last = self.actions.len().saturating_sub(1);
        if self
            .actions
            .iter()
            .enumerate()
            .any(|(i, a)| matches!(a, Action::DeleteAccount { .. }) && i != last)
        {
            return Err(Error::Invalid("an action after the account's deleted: NEAR would refuse it"));
        }
        let deploys = self
            .actions
            .iter()
            .filter(|a| matches!(a, Action::DeployContract { .. } | Action::DeployGlobalContract { .. }))
            .count();
        if deploys > MAX_DEPLOYS {
            return Err(Error::Invalid("more than 10 contracts deployed at once: NEAR would refuse it"));
        }
        let gas = self.actions.iter().try_fold(0u64, |sum, a| sum.checked_add(a.gas()));
        if gas.is_none_or(|g| g > MAX_PREPAID_GAS) {
            return Err(Error::Invalid("more gas for its calls than NEAR gives a transaction (1 PGas)"));
        }
        Ok(())
    }

    /// The gas its calls are given, between them.
    pub fn prepaid_gas(&self) -> u64 { self.actions.iter().map(Action::gas).sum() }
}
