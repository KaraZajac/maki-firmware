//! A transaction (`RawTransaction` in aptos-core), what an Aptos signature signs: read as Aptos's own
//! software reads its BCS (`bcs`), and held to what Aptos takes, so anything Aptos would refuse maki
//! refuses before it's shown. Its payload is an entry function, a call of a function published on
//! chain, in either of the forms Aptos has: the first, and the newer one, which can carry a nonce in
//! place of a sequence number (an orderless transaction). Scripts, multisig accounts' transactions
//! and encrypted ones maki refuses, by name. What the calls maki knows do is in `call`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::Address;
use crate::bcs::{self, Reader};
use crate::call::{self, Call};

/// The longest transaction maki reads: a message from the computer is 4096 bytes at most.
pub const MAX_RAW: usize = 4096;
/// How deep types may nest in others (vectors and structs), as Aptos reads them
/// (`MAX_TYPE_TAG_NESTING`).
pub const MAX_TYPE_NESTING: usize = 8;
/// Sequence numbers Aptos takes are below this (the prologue's `PROLOGUE_ESEQUENCE_NUMBER_TOO_BIG`).
pub const MAX_SEQUENCE: u64 = 1 << 63;
/// The sequence number an orderless transaction carries, as aptos-core and the SDKs write it: its
/// nonce stands in for it.
pub const ORDERLESS: u64 = u64::MAX;

/// Why maki won't read a transaction: each says why, for the computer that sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Longer than maki reads.
    TooBig,
    /// Cut short, or with bytes after it.
    Length,
    /// Not written in BCS's one way of writing it.
    Encoding,
    /// A variant of something (a payload, a type) Aptos doesn't have.
    Unknown,
    /// A name of a module, function or type that isn't one Move can have.
    Identifier,
    /// Types nested deeper than Aptos reads them.
    Nesting,
    /// A kind of transaction maki doesn't sign: why.
    Unsupported(&'static str),
    /// Something Aptos would refuse: why.
    Invalid(&'static str),
}

impl From<bcs::Error> for Error {
    fn from(e: bcs::Error) -> Error {
        match e {
            bcs::Error::Length => Error::Length,
            bcs::Error::Encoding => Error::Encoding,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooBig => f.write_str("bigger than maki takes an Aptos transaction"),
            Error::Length => f.write_str("not an Aptos transaction: cut short, or with more after it"),
            Error::Encoding => f.write_str("not an Aptos transaction as BCS writes one"),
            Error::Unknown => {
                f.write_str("not an Aptos transaction: a kind of payload or type Aptos doesn't have")
            }
            Error::Identifier => f.write_str("a name Move can't have: Aptos would refuse it"),
            Error::Nesting => f.write_str("types nested deeper than Aptos reads them"),
            Error::Unsupported(why) | Error::Invalid(why) => f.write_str(why),
        }
    }
}

/// A Move type, as a call's type arguments name it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeTag {
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    I8,
    I16,
    I32,
    I64,
    I128,
    I256,
    Address,
    Signer,
    Vector(Box<TypeTag>),
    Struct(Box<StructTag>),
}

/// A struct's type: where its module is, the module's name and its own, and its type arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructTag {
    pub address: Address,
    pub module: String,
    pub name: String,
    pub args: Vec<TypeTag>,
}

impl StructTag {
    /// Whether it's `address::module::name`, with no type arguments.
    pub fn is(&self, address: &Address, module: &str, name: &str) -> bool {
        self.address == *address && self.module == module && self.name == name && self.args.is_empty()
    }
}

/// As Move writes a type: `u64`, `vector<u8>`, `0x1::aptos_coin::AptosCoin`, its addresses as
/// `crate::address` writes them.
impl fmt::Display for TypeTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            TypeTag::Bool => "bool",
            TypeTag::U8 => "u8",
            TypeTag::U16 => "u16",
            TypeTag::U32 => "u32",
            TypeTag::U64 => "u64",
            TypeTag::U128 => "u128",
            TypeTag::U256 => "u256",
            TypeTag::I8 => "i8",
            TypeTag::I16 => "i16",
            TypeTag::I32 => "i32",
            TypeTag::I64 => "i64",
            TypeTag::I128 => "i128",
            TypeTag::I256 => "i256",
            TypeTag::Address => "address",
            TypeTag::Signer => "signer",
            TypeTag::Vector(t) => return write!(f, "vector<{t}>"),
            TypeTag::Struct(s) => return write!(f, "{s}"),
        };
        f.write_str(name)
    }
}

impl fmt::Display for StructTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}::{}", crate::address(&self.address), self.module, self.name)?;
        if let Some((first, rest)) = self.args.split_first() {
            write!(f, "<{first}")?;
            for t in rest {
                write!(f, ", {t}")?;
            }
            f.write_str(">")?;
        }
        Ok(())
    }
}

/// A call of a function published on chain (`EntryFunction`): the module it's in (where, and its
/// name), the function, its type arguments, and its arguments, each in the BCS of the type the
/// function takes there (which only the function says).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryFunction {
    pub address: Address,
    pub module: String,
    pub function: String,
    pub type_args: Vec<TypeTag>,
    pub args: Vec<Vec<u8>>,
}

/// As Move writes a call's function: `0x1::aptos_account::transfer`.
impl fmt::Display for EntryFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}::{}", crate::address(&self.address), self.module, self.function)
    }
}

/// What keeps a transaction from going through twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// The account's next sequence number: it goes through only as that, in turn.
    Sequence(u64),
    /// A nonce, in an orderless transaction: it goes through once, in any order, before it expires.
    Nonce(u64),
}

/// A transaction, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The account it's from, which signs it and pays its fee.
    pub sender: Address,
    pub replay: Replay,
    /// The function it calls.
    pub function: EntryFunction,
    /// What that call does, as far as maki knows the function.
    pub call: Call,
    /// The most gas it may use, and what it pays for each unit, in octas.
    pub max_gas_amount: u64,
    pub gas_unit_price: u64,
    /// When it expires, in seconds since 1970: Aptos takes it only before then.
    pub expiration: u64,
    /// The network it's for.
    pub chain_id: u8,
}

/// A name of a module, function or struct, as Aptos holds it to be one (`Identifier::is_valid`):
/// ASCII letters, digits, `_` and `$`, starting with a letter, or with `_` or `$` and more after it;
/// or the `<SELF>` names scripts' modules have.
fn identifier(r: &mut Reader) -> Result<String, Error> {
    let b = r.bytes()?;
    let tail = |from: usize| b[from..].iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'$');
    let valid = match b {
        b"<SELF>" => true,
        [b'<', b'S', b'E', b'L', b'F', b'>', b'_', rest @ ..] => {
            !rest.is_empty() && rest.iter().all(u8::is_ascii_digit)
        }
        [c, ..] if c.is_ascii_alphabetic() => tail(1),
        [b'_' | b'$', _, ..] => tail(1),
        _ => false,
    };
    if !valid {
        return Err(Error::Identifier);
    }
    // ASCII, so UTF-8
    core::str::from_utf8(b).map(String::from).map_err(|_| Error::Identifier)
}

/// A type, nested `depth` deep in others.
fn type_tag(r: &mut Reader, depth: usize) -> Result<TypeTag, Error> {
    // a vector's or a struct's type arguments are a level deeper
    let deeper = || if depth < MAX_TYPE_NESTING { Ok(depth + 1) } else { Err(Error::Nesting) };
    Ok(match r.uleb()? {
        0 => TypeTag::Bool,
        1 => TypeTag::U8,
        2 => TypeTag::U64,
        3 => TypeTag::U128,
        4 => TypeTag::Address,
        5 => TypeTag::Signer,
        6 => TypeTag::Vector(Box::new(type_tag(r, deeper()?)?)),
        7 => TypeTag::Struct(Box::new(struct_tag(r, deeper()?)?)),
        8 => TypeTag::U16,
        9 => TypeTag::U32,
        10 => TypeTag::U256,
        // a function's type (Move 2's function values), which maki can't show
        11 => return Err(Error::Unsupported("a function's type as a type argument: maki can't show those")),
        12 => TypeTag::I8,
        13 => TypeTag::I16,
        14 => TypeTag::I32,
        15 => TypeTag::I64,
        16 => TypeTag::I128,
        17 => TypeTag::I256,
        _ => return Err(Error::Unknown),
    })
}

fn struct_tag(r: &mut Reader, depth: usize) -> Result<StructTag, Error> {
    let address = r.array()?;
    let module = identifier(r)?;
    let name = identifier(r)?;
    let mut args = Vec::new();
    for _ in 0..r.len()? {
        args.push(type_tag(r, depth)?);
    }
    Ok(StructTag { address, module, name, args })
}

fn entry_function(r: &mut Reader) -> Result<EntryFunction, Error> {
    let address = r.array()?;
    let module = identifier(r)?;
    let function = identifier(r)?;
    let mut type_args = Vec::new();
    for _ in 0..r.len()? {
        type_args.push(type_tag(r, 0)?);
    }
    let mut args = Vec::new();
    for _ in 0..r.len()? {
        args.push(r.bytes()?.to_vec());
    }
    Ok(EntryFunction { address, module, function, type_args, args })
}

const SCRIPT: &str =
    "a script, code maki can't read that could do anything this account can: maki doesn't sign those";
const MULTISIG: &str = "a multisig account's transaction: maki doesn't sign those";

/// The payload (`TransactionPayload`): the function it calls, and its nonce if it's orderless.
fn payload(r: &mut Reader) -> Result<(EntryFunction, Option<u64>), Error> {
    match r.uleb()? {
        0 => Err(Error::Unsupported(SCRIPT)),
        1 => Err(Error::Invalid("a module bundle, which Aptos no longer takes")),
        2 => Ok((entry_function(r)?, None)),
        3 => Err(Error::Unsupported(MULTISIG)),
        // the newer form (`TransactionPayloadInner::V1`): an executable, then what else it says
        4 => {
            if r.uleb()? != 0 {
                return Err(Error::Unknown);
            }
            let function = match r.uleb()? {
                0 => return Err(Error::Unsupported(SCRIPT)),
                1 => entry_function(r)?,
                2 => {
                    return Err(Error::Unsupported(
                        "a transaction that runs nothing: maki doesn't sign those",
                    ));
                }
                3 => {
                    return Err(Error::Unsupported(
                        "an encrypted transaction, which maki can't read: maki doesn't sign those",
                    ));
                }
                _ => return Err(Error::Unknown),
            };
            match r.uleb()? {
                // `TransactionExtraConfig::V1`: a multisig account it's for, and a nonce
                0 => {}
                1 => {
                    return Err(Error::Unsupported(
                        "a transaction asking Aptos for higher limits: maki doesn't sign those",
                    ));
                }
                _ => return Err(Error::Unknown),
            }
            if r.some()? {
                return Err(Error::Unsupported(MULTISIG));
            }
            let nonce = if r.some()? { Some(r.u64()?) } else { None };
            Ok((function, nonce))
        }
        5 => Err(Error::Unsupported(
            "an encrypted transaction, which maki can't read: maki doesn't sign those",
        )),
        _ => Err(Error::Unknown),
    }
}

impl Transaction {
    /// A transaction's BCS, read whole: everything in it, nothing after it.
    pub fn parse(raw: &[u8]) -> Result<Transaction, Error> {
        if raw.len() > MAX_RAW {
            return Err(Error::TooBig);
        }
        let mut r = Reader::new(raw);
        let sender = r.array()?;
        let sequence = r.u64()?;
        let (function, nonce) = payload(&mut r)?;
        let max_gas_amount = r.u64()?;
        let gas_unit_price = r.u64()?;
        let expiration = r.u64()?;
        let chain_id = r.u8()?;
        r.end()?;
        let replay = match nonce {
            None if sequence >= MAX_SEQUENCE => {
                return Err(Error::Invalid(
                    "a sequence number too big for any account: Aptos would refuse it",
                ));
            }
            None => Replay::Sequence(sequence),
            Some(n) if sequence == ORDERLESS => Replay::Nonce(n),
            Some(_) => {
                return Err(Error::Invalid(
                    "an orderless transaction with a sequence number: not as Aptos writes one",
                ));
            }
        };
        // Aptos checks the account holds the most it could charge, so that must be a number
        if max_gas_amount.checked_mul(gas_unit_price).is_none() {
            return Err(Error::Invalid("a fee too big to pay: Aptos would refuse it"));
        }
        let call = call::read(&function)?;
        Ok(Transaction {
            sender,
            replay,
            function,
            call,
            max_gas_amount,
            gas_unit_price,
            expiration,
            chain_id,
        })
    }

    /// The most the fee can be, in octas: its most gas, at its price for each unit.
    pub fn max_fee(&self) -> u64 { self.max_gas_amount.saturating_mul(self.gas_unit_price) }
}
