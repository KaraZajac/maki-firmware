//! A transaction's data (`TransactionData` in Sui's sui-types), what a Sui signature signs: read as
//! Sui's validators read it (`bcs`), and held to what they accept of it (sui-types'
//! `validity_check`, as mainnet-v1.80.1 has it under protocol version 137, on both networks), so
//! that anything Sui would refuse, maki refuses before it's shown. It reads the kind of transaction
//! anyone sends, a programmable one: inputs (bytes for calls, objects, withdrawals from an address
//! balance) and commands (coins split, merged and sent, Move functions called, values gathered
//! into a vector, code published and upgraded), then who sends it, how its fee is paid, and when it
//! expires. The kinds only Sui's validators make, it refuses by name.

use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::{format, string::String};
use core::fmt;

use crate::bcs::Reader;
use crate::{Address, bytes32};

/// An object's ID: an address, of an object rather than an account.
pub type ObjectId = Address;

/// Why maki won't read a transaction: each says why, for the computer that sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Longer than maki reads.
    TooBig,
    /// Cut short, longer than it says, or not BCS as Sui writes it.
    Encoding,
    /// Something of a kind maki doesn't know (one Sui has added since, perhaps): what it is.
    Unknown(&'static str),
    /// A kind of transaction only Sui's validators make: its name.
    System(&'static str),
    /// Something Sui would refuse: why.
    Invalid(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooBig => f.write_str("bigger than maki takes a Sui transaction"),
            Error::Encoding => f.write_str(
                "not a Sui transaction as BCS writes one: cut short, with more after it, or written another way",
            ),
            Error::Unknown(what) => write!(f, "a {what} maki doesn't know"),
            Error::System(name) => write!(f, "a system transaction ({name}): only Sui's validators make those"),
            Error::Invalid(why) => f.write_str(why),
        }
    }
}

// What Sui takes, as protocol version 137 has it on both networks (each read with Sui's GraphQL
// service, `epoch { protocolConfigs }`, on 2026-10-01). Upgrades can change these; most are far
// past what fits in a message to maki.

/// The longest transaction maki reads: a message from the computer is 4096 bytes at most.
pub const MAX_TX: usize = 4096;
/// Commands in a transaction: fewer than this (`max_programmable_tx_commands`).
pub const MAX_COMMANDS: usize = 1024;
/// Arguments to a command, or coins, amounts or objects in one: fewer than this (`max_arguments`).
pub const MAX_ARGUMENTS: usize = 512;
/// Type arguments to a call (or a vector's type), counting every type inside them: fewer than this
/// (`max_type_arguments`).
pub const MAX_TYPE_ARGUMENTS: usize = 16;
/// How deep a type argument nests, counting itself: less than this (`max_type_argument_depth`).
pub const MAX_TYPE_DEPTH: usize = 16;
/// The types a withdrawal's `Balance<T>` may count, itself among them, at most
/// (`max_accumulator_type_nodes`).
pub const MAX_BALANCE_TYPES: usize = 16;
/// Coins and reservations paying the fee, at most (`max_gas_payment_objects`).
pub const MAX_GAS_OBJECTS: usize = 256;
/// Withdrawals from address balances in a transaction, at most, its fee's among them (sui-types'
/// `max_withdraws`, which isn't yet in the protocol's config).
pub const MAX_WITHDRAWALS: usize = 10;
/// Packages a transaction publishes or upgrades, at most (`max_publish_or_upgrade_per_ptb`).
pub const MAX_PUBLISHES: usize = 5;
/// Modules in a package: fewer than this (`max_modules_in_publish`).
pub const MAX_MODULES: usize = 64;
/// A package's dependencies: fewer than this (`max_package_dependencies`).
pub const MAX_DEPENDENCIES: usize = 32;
/// A gas price, in MIST a unit of gas: less than this (`max_gas_price`).
pub const MAX_GAS_PRICE: u64 = 50_000_000_000;
/// A gas budget, in MIST, at most: 50,000 SUI (`max_tx_gas`).
pub const MAX_BUDGET: u64 = 50_000_000_000_000;
/// A gas budget, in units of gas at its price, at least (`base_tx_cost_fixed`).
pub const MIN_BUDGET_UNITS: u64 = 1_000;
/// The longest name Move gives a module, a function or a type (`max_move_identifier_len`): no
/// published package has a longer one for a call or a type to name.
pub const MAX_IDENTIFIER: usize = 128;
/// No object's version reaches this (`SequenceNumber::MAX`).
pub const MAX_VERSION: u64 = 0x7fff_ffff_ffff_ffff;
/// A gasless transaction's inputs of bytes: this long at most (`gasless_max_pure_input_bytes`).
pub const GASLESS_MAX_PURE: usize = 32;
/// A gasless transaction's inputs of bytes that no command uses, at most
/// (`gasless_max_unused_inputs`).
pub const GASLESS_MAX_UNUSED: usize = 1;

/// The Sui framework's package, `0x2`: coins, balances, transfers, its addresses' aliases.
pub const FRAMEWORK: Address = bytes32("0000000000000000000000000000000000000000000000000000000000000002");
/// Sui's system package, `0x3`: staking.
pub const SYSTEM: Address = bytes32("0000000000000000000000000000000000000000000000000000000000000003");
/// The shared object that holds Sui's validators and their stake, `0x5`.
pub const SYSTEM_STATE: ObjectId =
    bytes32("0000000000000000000000000000000000000000000000000000000000000005");
/// The shared object that gives Move its randomness, `0x8`.
pub const RANDOM: ObjectId = bytes32("0000000000000000000000000000000000000000000000000000000000000008");

/// The last 20 bytes of a coin reservation's digest (sui-types' `COIN_RESERVATION_MAGIC`).
const RESERVATION_MAGIC: [u8; 20] = [0xac; 20];

/// The kinds of transaction only Sui's validators make, by their number.
const SYSTEM_KINDS: [&str; 10] = [
    "ChangeEpoch",
    "Genesis",
    "ConsensusCommitPrologue",
    "AuthenticatorStateUpdate",
    "EndOfEpochTransaction",
    "RandomnessStateUpdate",
    "ConsensusCommitPrologueV2",
    "ConsensusCommitPrologueV3",
    "ConsensusCommitPrologueV4",
    "ProgrammableSystemTransaction",
];

/// An object as a transaction names it: its ID, the version it's at, and the digest of it there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectRef {
    /// Which object.
    pub id: ObjectId,
    /// The version it's at: one the transaction moves on, if it's owned.
    pub version: u64,
    /// The digest of the object at that version.
    pub digest: [u8; 32],
}

/// A coin reservation: an address balance passed off as a coin, for software that knows only
/// coins. Its object's ID is the field holding the balance, masked with its network's chain
/// identifier, and its digest says how much and in which epoch; Sui withdraws exactly that much
/// from the sender's balance, as a coin, and puts whatever's left of the coin back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    /// How much, in the balance's smallest units.
    pub amount: u64,
    /// The epoch it's for: Sui takes it in that epoch and the next.
    pub epoch: u32,
}

impl ObjectRef {
    /// The coin reservation this is, if it's one (its digest ends in the reservation's mark).
    pub fn reservation(&self) -> Option<Reservation> {
        if self.digest[12..] != RESERVATION_MAGIC {
            return None;
        }
        let amount = u64::from_le_bytes(self.digest[..8].try_into().ok()?);
        let epoch = u32::from_le_bytes(self.digest[8..12].try_into().ok()?);
        Some(Reservation { amount, epoch })
    }
}

/// How a transaction uses a shared object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutability {
    /// It only reads it.
    Immutable,
    /// It may change it.
    Mutable,
    /// It may add to it alongside others (Sui's own settlements use it; no one else may).
    NonExclusiveWrite,
}

/// Whose address balance a withdrawal draws on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawFrom {
    /// The sender's.
    Sender,
    /// The sponsor's, who pays the fee.
    Sponsor,
    /// Another's (`funder`), under an allowance (`allowance`, an object) they gave the sender.
    Allowance { funder: Address, allowance: ObjectId },
}

/// A withdrawal from an address balance (a `FundsWithdrawalArg`): Move gets it as a
/// `Withdrawal<Balance<T>>`, which `redeem_funds` turns into that much, exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawal {
    /// How much, in the coin's smallest units.
    pub amount: u64,
    /// The coin's type, `T` of `Balance<T>`.
    pub coin: TypeTag,
    /// Whose balance.
    pub from: WithdrawFrom,
}

/// One of a transaction's inputs (a `CallArg`), for its commands to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// Bytes, for a command to read as the type it takes (BCS): an amount, an address.
    Pure(Vec<u8>),
    /// An object the sender owns, or one no one does and anyone may read (an `ImmOrOwnedObject`):
    /// the transaction can't say which, or what it is. Or a coin reservation.
    Owned(ObjectRef),
    /// An object anyone may use, as its own code lets them.
    Shared { id: ObjectId, initial_version: u64, mutability: Mutability },
    /// An object sent to one of the sender's objects, to receive.
    Receiving(ObjectRef),
    /// A withdrawal from an address balance.
    Withdrawal(Withdrawal),
}

/// What a command takes: the coin paying the fee, an input, or what an earlier command gave back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argument {
    /// The gas coin: SUI, everything the fee is paid from, together.
    Gas,
    /// An input.
    Input(u16),
    /// What a command gave back (when it gave one thing back, all of it).
    Result(u16),
    /// One of the things a command gave back.
    Nested(u16, u16),
}

/// A Move type, as a transaction names one (a `TypeTag`, or a `TypeInput`, written the same).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeTag {
    /// `bool`.
    Bool,
    /// `u8`.
    U8,
    /// `u64`.
    U64,
    /// `u128`.
    U128,
    /// `address`.
    Address,
    /// `signer`.
    Signer,
    /// `vector<T>`.
    Vector(Box<TypeTag>),
    /// A struct's type, as `0x2::sui::SUI`.
    Struct(Box<StructTag>),
    /// `u16`.
    U16,
    /// `u32`.
    U32,
    /// `u256`.
    U256,
}

/// A struct's type: the package that defines it, its module, its name, and its type arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructTag {
    /// The package that defines it.
    pub address: Address,
    /// Its module.
    pub module: String,
    /// Its name.
    pub name: String,
    /// Its type arguments.
    pub params: Vec<TypeTag>,
}

impl TypeTag {
    /// A type of the Sui framework's (`0x2`).
    pub fn framework(module: &str, name: &str, params: Vec<TypeTag>) -> TypeTag {
        TypeTag::Struct(Box::new(StructTag {
            address: FRAMEWORK,
            module: module.into(),
            name: name.into(),
            params,
        }))
    }

    /// SUI: `0x2::sui::SUI`.
    pub fn sui() -> TypeTag { TypeTag::framework("sui", "SUI", Vec::new()) }

    /// `0x2::balance::Balance<coin>`.
    pub fn balance(coin: TypeTag) -> TypeTag { TypeTag::framework("balance", "Balance", alloc::vec![coin]) }

    /// Whether it's SUI.
    pub fn is_sui(&self) -> bool { *self == TypeTag::sui() }

    /// `T`, if it's `0x2::balance::Balance<T>`.
    pub fn balance_of(&self) -> Option<&TypeTag> {
        match self {
            TypeTag::Struct(s) if s.address == FRAMEWORK && s.module == "balance" && s.name == "Balance" => {
                match s.params.as_slice() {
                    [t] => Some(t),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// How many types it counts, itself and every one inside it (Sui's `node_count`).
    pub fn nodes(&self) -> usize {
        match self {
            TypeTag::Vector(t) => 1 + t.nodes(),
            TypeTag::Struct(s) => 1 + s.params.iter().map(TypeTag::nodes).sum::<usize>(),
            _ => 1,
        }
    }

    /// How deep it nests, counting itself.
    pub fn depth(&self) -> usize {
        match self {
            TypeTag::Vector(t) => 1 + t.depth(),
            TypeTag::Struct(s) => 1 + s.params.iter().map(TypeTag::depth).max().unwrap_or(0),
            _ => 1,
        }
    }

    /// Its BCS, appended to `out`.
    pub fn write(&self, out: &mut Vec<u8>) {
        let tag = match self {
            TypeTag::Bool => 0,
            TypeTag::U8 => 1,
            TypeTag::U64 => 2,
            TypeTag::U128 => 3,
            TypeTag::Address => 4,
            TypeTag::Signer => 5,
            TypeTag::Vector(_) => 6,
            TypeTag::Struct(_) => 7,
            TypeTag::U16 => 8,
            TypeTag::U32 => 9,
            TypeTag::U256 => 10,
        };
        out.push(tag);
        match self {
            TypeTag::Vector(t) => t.write(out),
            TypeTag::Struct(s) => {
                out.extend_from_slice(&s.address);
                for name in [&s.module, &s.name] {
                    // a name is at most 128 bytes: its length is one byte of ULEB128
                    out.push(name.len() as u8);
                    out.extend_from_slice(name.as_bytes());
                }
                out.push(s.params.len() as u8);
                for p in &s.params {
                    p.write(out);
                }
            }
            _ => {}
        }
    }
}

/// An address as Move writes one in a type: its hex without leading zeros, so `0x2` is the
/// framework.
pub fn short_address(a: &Address) -> String {
    let hex = crate::hex(a);
    let digits = hex.trim_start_matches('0');
    format!("0x{}", if digits.is_empty() { "0" } else { digits })
}

impl fmt::Display for TypeTag {
    /// As Sui writes a type: `0x2::sui::SUI`, `vector<u8>`, `0x2::coin::Coin<0x2::sui::SUI>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeTag::Bool => f.write_str("bool"),
            TypeTag::U8 => f.write_str("u8"),
            TypeTag::U16 => f.write_str("u16"),
            TypeTag::U32 => f.write_str("u32"),
            TypeTag::U64 => f.write_str("u64"),
            TypeTag::U128 => f.write_str("u128"),
            TypeTag::U256 => f.write_str("u256"),
            TypeTag::Address => f.write_str("address"),
            TypeTag::Signer => f.write_str("signer"),
            TypeTag::Vector(t) => write!(f, "vector<{t}>"),
            TypeTag::Struct(s) => {
                write!(f, "{}::{}::{}", short_address(&s.address), s.module, s.name)?;
                if let Some((first, rest)) = s.params.split_first() {
                    write!(f, "<{first}")?;
                    for p in rest {
                        write!(f, ", {p}")?;
                    }
                    f.write_str(">")?;
                }
                Ok(())
            }
        }
    }
}

/// A call of a Move function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveCall {
    /// The package that has it.
    pub package: ObjectId,
    /// Its module.
    pub module: String,
    /// Its name.
    pub function: String,
    /// Its type arguments.
    pub types: Vec<TypeTag>,
    /// What it's given.
    pub arguments: Vec<Argument>,
}

impl MoveCall {
    /// Whether it calls `function` of `module` in `package`.
    pub fn is(&self, package: &Address, module: &str, function: &str) -> bool {
        self.package == *package && self.module == module && self.function == function
    }
}

/// One of a transaction's commands, run in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// A Move function called.
    MoveCall(MoveCall),
    /// Objects sent to an address.
    TransferObjects { objects: Vec<Argument>, to: Argument },
    /// Coins of these amounts split off a coin, each a coin of its own.
    SplitCoins { coin: Argument, amounts: Vec<Argument> },
    /// Coins merged into a coin.
    MergeCoins { into: Argument, coins: Vec<Argument> },
    /// A package of Move code published: its modules, and the packages it uses.
    Publish { modules: usize, dependencies: Vec<ObjectId> },
    /// Values gathered into a Move vector, of a type it may say.
    MakeMoveVec { of: Option<TypeTag>, elements: Vec<Argument> },
    /// A package upgraded, by the ticket an earlier command gave back.
    Upgrade { modules: usize, dependencies: Vec<ObjectId>, package: ObjectId, ticket: Argument },
}

impl Command {
    /// Everything it takes, in order.
    pub fn arguments(&self) -> Vec<Argument> {
        match self {
            Command::MoveCall(c) => c.arguments.clone(),
            Command::TransferObjects { objects, to } => objects.iter().chain([to]).copied().collect(),
            Command::SplitCoins { coin, amounts } => [coin].into_iter().chain(amounts).copied().collect(),
            Command::MergeCoins { into, coins } => [into].into_iter().chain(coins).copied().collect(),
            Command::MakeMoveVec { elements, .. } => elements.clone(),
            Command::Upgrade { ticket, .. } => alloc::vec![*ticket],
            Command::Publish { .. } => Vec::new(),
        }
    }
}

/// How a transaction's fee is paid (its `GasData`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gas {
    /// The coins (and coin reservations) the fee comes from, merged into one, the gas coin; none,
    /// for a fee from the owner's address balance.
    pub payment: Vec<ObjectRef>,
    /// Whose they are: who pays.
    pub owner: Address,
    /// What it pays a unit of gas, in MIST.
    pub price: u64,
    /// The most it pays, in MIST.
    pub budget: u64,
}

/// When a transaction can be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expiration {
    /// Whenever: until what it uses changes.
    None,
    /// Until this epoch ends.
    Epoch(u64),
    /// In these epochs, on the chain it names (`ValidDuring`; `Validity` when it names the
    /// validators that may propose it, as `proposers`: an epoch, and their places in its
    /// committee).
    During {
        min: Option<u64>,
        max: Option<u64>,
        chain: [u8; 32],
        nonce: u32,
        proposers: Option<(u64, Vec<u32>)>,
    },
}

impl Expiration {
    /// Whether it keeps the transaction from being sent twice: valid in one epoch, or two in a
    /// row, which validators remember what they've run in.
    pub fn is_replay_protected(&self) -> bool {
        matches!(self, Expiration::During { min: Some(min), max: Some(max), .. }
            if max == min || Some(*max) == min.checked_add(1))
    }

    /// The chain it names, if it names one.
    pub fn chain(&self) -> Option<&[u8; 32]> {
        match self {
            Expiration::During { chain, .. } => Some(chain),
            _ => None,
        }
    }
}

/// A transaction's data, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// What its commands are given to work with.
    pub inputs: Vec<Input>,
    /// What it does, in order.
    pub commands: Vec<Command>,
    /// Who sends it: whose objects and balances it may use, and who signs it.
    pub sender: Address,
    /// How its fee is paid.
    pub gas: Gas,
    /// When it can be sent.
    pub expiration: Expiration,
    /// How many bytes it is.
    pub size: usize,
}

/// The framework's functions a gasless transaction may call (sui-types' `GASLESS_FUNCTIONS`): ways
/// of moving a balance, and nothing else.
const GASLESS_FUNCTIONS: [(&str, &str); 9] = [
    ("balance", "send_funds"),
    ("balance", "redeem_funds"),
    ("balance", "split"),
    ("balance", "zero"),
    ("funds_accumulator", "withdrawal_split"),
    ("coin", "into_balance"),
    ("coin", "redeem_funds"),
    ("coin", "send_funds"),
    ("coin", "put"),
];

/// A name Move takes for a module, a function or a type: a letter, then letters, digits and
/// underscores; or an underscore and at least one more of those. And no longer than Move gives one.
fn identifier(r: &mut Reader) -> Result<String, Error> {
    let s = r.string()?;
    let b = s.as_bytes();
    let rest_ok = |rest: &[u8]| rest.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_');
    let ok = match b {
        [first, rest @ ..] if first.is_ascii_alphabetic() => rest_ok(rest),
        [b'_', rest @ ..] if !rest.is_empty() => rest_ok(rest),
        _ => false,
    };
    if !ok {
        return Err(Error::Invalid("a Move name that isn't one: Sui would refuse it"));
    }
    if s.len() > MAX_IDENTIFIER {
        return Err(Error::Invalid("a Move name longer than any Move has: Sui would refuse it"));
    }
    Ok(s.into())
}

/// A type, nested `depth` deep.
fn type_tag(r: &mut Reader, depth: usize) -> Result<TypeTag, Error> {
    if depth >= MAX_TYPE_DEPTH {
        return Err(Error::Invalid("a type nested deeper than Sui takes"));
    }
    Ok(match r.variant()? {
        0 => TypeTag::Bool,
        1 => TypeTag::U8,
        2 => TypeTag::U64,
        3 => TypeTag::U128,
        4 => TypeTag::Address,
        5 => TypeTag::Signer,
        6 => TypeTag::Vector(Box::new(type_tag(r, depth + 1)?)),
        7 => {
            let address = r.bytes32()?;
            let module = identifier(r)?;
            let name = identifier(r)?;
            let n = r.len()?;
            let mut params = Vec::new();
            for _ in 0..n {
                params.push(type_tag(r, depth + 1)?);
            }
            TypeTag::Struct(Box::new(StructTag { address, module, name, params }))
        }
        8 => TypeTag::U16,
        9 => TypeTag::U32,
        10 => TypeTag::U256,
        _ => return Err(Error::Unknown("kind of Move type")),
    })
}

fn object_ref(r: &mut Reader) -> Result<ObjectRef, Error> {
    Ok(ObjectRef { id: r.bytes32()?, version: r.u64()?, digest: r.digest()? })
}

fn argument(r: &mut Reader) -> Result<Argument, Error> {
    Ok(match r.variant()? {
        0 => Argument::Gas,
        1 => Argument::Input(r.u16()?),
        2 => Argument::Result(r.u16()?),
        3 => Argument::Nested(r.u16()?, r.u16()?),
        _ => return Err(Error::Unknown("kind of argument")),
    })
}

/// A sequence of what `item` reads.
fn many<'a, T>(
    r: &mut Reader<'a>,
    mut item: impl FnMut(&mut Reader<'a>) -> Result<T, Error>,
) -> Result<Vec<T>, Error> {
    let n = r.len()?;
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(item(r)?);
    }
    Ok(out)
}

fn input(r: &mut Reader) -> Result<Input, Error> {
    Ok(match r.variant()? {
        0 => Input::Pure(r.bytes()?.into()),
        1 => match r.variant()? {
            0 => Input::Owned(object_ref(r)?),
            1 => {
                let id = r.bytes32()?;
                let initial_version = r.u64()?;
                let mutability = match r.variant()? {
                    0 => Mutability::Immutable,
                    1 => Mutability::Mutable,
                    2 => Mutability::NonExclusiveWrite,
                    _ => return Err(Error::Unknown("way of using a shared object")),
                };
                Input::Shared { id, initial_version, mutability }
            }
            2 => Input::Receiving(object_ref(r)?),
            _ => return Err(Error::Unknown("kind of object input")),
        },
        2 => {
            let amount = match r.variant()? {
                0 => r.u64()?,
                _ => return Err(Error::Unknown("kind of withdrawal")),
            };
            let coin = match r.variant()? {
                0 => type_tag(r, 1)?,
                _ => return Err(Error::Unknown("kind of withdrawal")),
            };
            let from = match r.variant()? {
                0 => WithdrawFrom::Sender,
                1 => WithdrawFrom::Sponsor,
                2 => WithdrawFrom::Allowance { funder: r.bytes32()?, allowance: r.bytes32()? },
                _ => return Err(Error::Unknown("kind of withdrawal")),
            };
            Input::Withdrawal(Withdrawal { amount, coin, from })
        }
        _ => return Err(Error::Unknown("kind of input")),
    })
}

fn command(r: &mut Reader) -> Result<Command, Error> {
    Ok(match r.variant()? {
        0 => Command::MoveCall(MoveCall {
            package: r.bytes32()?,
            module: identifier(r)?,
            function: identifier(r)?,
            types: many(r, |r| type_tag(r, 0))?,
            arguments: many(r, argument)?,
        }),
        1 => Command::TransferObjects { objects: many(r, argument)?, to: argument(r)? },
        2 => Command::SplitCoins { coin: argument(r)?, amounts: many(r, argument)? },
        3 => Command::MergeCoins { into: argument(r)?, coins: many(r, argument)? },
        4 => {
            let modules = many(r, |r| r.bytes().map(|_| ()))?.len();
            Command::Publish { modules, dependencies: many(r, Reader::bytes32)? }
        }
        5 => {
            let of = if r.some()? { Some(type_tag(r, 0)?) } else { None };
            Command::MakeMoveVec { of, elements: many(r, argument)? }
        }
        6 => {
            let modules = many(r, |r| r.bytes().map(|_| ()))?.len();
            let dependencies = many(r, Reader::bytes32)?;
            Command::Upgrade { modules, dependencies, package: r.bytes32()?, ticket: argument(r)? }
        }
        _ => return Err(Error::Unknown("kind of command")),
    })
}

fn expiration(r: &mut Reader) -> Result<Expiration, Error> {
    let kind = r.variant()?;
    Ok(match kind {
        0 => Expiration::None,
        1 => Expiration::Epoch(r.u64()?),
        2 | 3 => {
            let min = r.option_u64()?;
            let max = r.option_u64()?;
            let (min_time, max_time) = (r.option_u64()?, r.option_u64()?);
            let chain = r.digest()?;
            let nonce = r.u32()?;
            let proposers = if kind == 3 && r.some()? {
                let epoch = r.u64()?;
                let indices = many(r, Reader::u32)?;
                // Sui reads an empty set as no set at all: it isn't one
                if indices.is_empty() {
                    return Err(Error::Encoding);
                }
                Some((epoch, indices))
            } else {
                None
            };
            if min_time.is_some() || max_time.is_some() {
                return Err(Error::Invalid("a time limit by the clock: Sui doesn't take those yet"));
            }
            Expiration::During { min, max, chain, nonce, proposers }
        }
        _ => return Err(Error::Unknown("kind of expiration")),
    })
}

impl Transaction {
    /// A transaction's data, read whole: everything in it, nothing after it.
    pub fn parse(bytes: &[u8]) -> Result<Transaction, Error> {
        if bytes.len() > MAX_TX {
            return Err(Error::TooBig);
        }
        let mut r = Reader::new(bytes);
        if r.variant()? != 0 {
            return Err(Error::Unknown("version of transaction data"));
        }
        let (inputs, commands) = match r.variant()? {
            0 => (many(&mut r, input)?, many(&mut r, command)?),
            k @ 1..=10 => return Err(Error::System(SYSTEM_KINDS[k as usize - 1])),
            _ => return Err(Error::Unknown("kind of transaction")),
        };
        let sender = r.bytes32()?;
        let gas = Gas {
            payment: many(&mut r, object_ref)?,
            owner: r.bytes32()?,
            price: r.u64()?,
            budget: r.u64()?,
        };
        let expiration = expiration(&mut r)?;
        r.end()?;
        let tx = Transaction { inputs, commands, sender, gas, expiration, size: bytes.len() };
        tx.check()?;
        Ok(tx)
    }

    /// Whether its fee comes from the gas owner's address balance: it names no coins for it.
    pub fn pays_from_balance(&self) -> bool { self.gas.payment.is_empty() }

    /// Whether it's gasless: no coins for its fee, and no price for gas. Sui takes it (a few
    /// stablecoins sent, and little else) for nothing.
    pub fn is_gasless(&self) -> bool { self.pays_from_balance() && self.gas.price == 0 }

    /// What Sui checks of a transaction before it signs for it, as far as the transaction alone
    /// can say.
    fn check(&self) -> Result<(), Error> {
        let invalid = |why| Err(Error::Invalid(why));
        if self.commands.len() >= MAX_COMMANDS {
            return invalid("more commands than Sui takes in a transaction");
        }
        self.check_objects()?;
        let mut withdrawals = usize::from(self.pays_from_balance());
        for i in &self.inputs {
            match i {
                Input::Shared { mutability: Mutability::NonExclusiveWrite, .. } => {
                    return invalid(
                        "a shared object written alongside others: only Sui's own transactions may",
                    );
                }
                Input::Withdrawal(w) => {
                    withdrawals += 1;
                    if w.amount == 0 {
                        return invalid("a withdrawal of nothing: Sui would refuse it");
                    }
                    if w.from == WithdrawFrom::Sponsor {
                        return invalid(
                            "a withdrawal from the sponsor's balance: Sui doesn't take those yet",
                        );
                    }
                    if TypeTag::balance(w.coin.clone()).nodes() > MAX_BALANCE_TYPES {
                        return invalid("a withdrawal of a type bigger than Sui takes");
                    }
                }
                Input::Owned(r) => {
                    if let Some(reserved) = r.reservation() {
                        withdrawals += 1;
                        if reserved.amount == 0 {
                            return invalid("a coin reservation of nothing: Sui would refuse it");
                        }
                    }
                }
                _ => {}
            }
        }
        if withdrawals > MAX_WITHDRAWALS {
            return invalid("more withdrawals from address balances than Sui takes in a transaction");
        }
        let publishes = self
            .commands
            .iter()
            .filter(|c| matches!(c, Command::Publish { .. } | Command::Upgrade { .. }))
            .count();
        if publishes > MAX_PUBLISHES {
            return invalid("more packages published than Sui takes in a transaction");
        }
        for (at, c) in self.commands.iter().enumerate() {
            self.check_command(at, c)?;
        }
        self.check_random()?;
        self.check_gas()?;
        if let Expiration::During { proposers: Some((_, p)), .. } = &self.expiration {
            if p.windows(2).any(|w| w[0] >= w[1]) {
                return invalid("validators named to propose it out of order: Sui would refuse it");
            }
        }
        // Something has to keep it from being sent twice: coins for its fee or objects it uses (a
        // version that changes once it's run), or a window of an epoch or two that validators
        // remember. Whether an object is owned rather than shared to all, the transaction can't
        // say: Sui checks that.
        let owned = self.inputs.iter().any(|i| matches!(i, Input::Owned(r) if r.reservation().is_none()));
        if self.pays_from_balance() && !owned && !self.expiration.is_replay_protected() {
            return invalid("nothing keeps it from being sent twice: Sui would refuse it");
        }
        if self.is_gasless() {
            self.check_gasless()?;
        }
        Ok(())
    }

    /// Every object named once: Sui refuses an input named twice, a coin paying the fee that's an
    /// input too, and an object to receive that's either.
    fn check_objects(&self) -> Result<(), Error> {
        let mut ids: Vec<(&ObjectId, u64)> = Vec::new();
        for i in &self.inputs {
            match i {
                Input::Owned(r) | Input::Receiving(r) => ids.push((&r.id, r.version)),
                Input::Shared { id, initial_version, .. } => ids.push((id, *initial_version)),
                _ => {}
            }
        }
        if self.gas.payment.len() > MAX_GAS_OBJECTS {
            return Err(Error::Invalid("more coins paying the fee than Sui takes"));
        }
        ids.extend(self.gas.payment.iter().map(|r| (&r.id, r.version)));
        for (n, (id, version)) in ids.iter().enumerate() {
            if *version >= MAX_VERSION {
                return Err(Error::Invalid("an object at a version none can be: Sui would refuse it"));
            }
            if ids[..n].iter().any(|(other, _)| other == id) {
                return Err(Error::Invalid("an object named twice: Sui would refuse it"));
            }
        }
        Ok(())
    }

    fn check_command(&self, at: usize, c: &Command) -> Result<(), Error> {
        let invalid = |why| Err(Error::Invalid(why));
        let types = |t: &[TypeTag]| {
            if t.iter().map(TypeTag::nodes).sum::<usize>() >= MAX_TYPE_ARGUMENTS {
                return invalid("more type arguments than Sui takes in a call");
            }
            if t.iter().any(|t| t.depth() >= MAX_TYPE_DEPTH) {
                return invalid("a type nested deeper than Sui takes");
            }
            Ok(())
        };
        let some = |n: usize| {
            if n == 0 {
                return invalid("a command given nothing to work on: Sui would refuse it");
            }
            if n >= MAX_ARGUMENTS {
                return invalid("more arguments than Sui takes in a command");
            }
            Ok(())
        };
        match c {
            Command::MoveCall(call) => {
                types(&call.types)?;
                if call.arguments.len() >= MAX_ARGUMENTS {
                    return invalid("more arguments than Sui takes in a command");
                }
            }
            Command::TransferObjects { objects: v, .. }
            | Command::SplitCoins { amounts: v, .. }
            | Command::MergeCoins { coins: v, .. } => some(v.len())?,
            Command::MakeMoveVec { of, elements } => {
                if of.is_none() && elements.is_empty() {
                    return invalid("an empty vector of no type: Sui would refuse it");
                }
                if let Some(t) = of {
                    types(core::slice::from_ref(t))?;
                }
                if elements.len() >= MAX_ARGUMENTS {
                    return invalid("more arguments than Sui takes in a command");
                }
            }
            Command::Publish { modules, dependencies } | Command::Upgrade { modules, dependencies, .. } => {
                if *modules == 0 {
                    return invalid("a package of no modules: Sui would refuse it");
                }
                if *modules >= MAX_MODULES || dependencies.len() >= MAX_DEPENDENCIES {
                    return invalid("a package bigger than Sui takes");
                }
            }
        }
        // an input that's there, or what a command before this one gave back
        for a in c.arguments() {
            let there = match a {
                Argument::Gas => true,
                Argument::Input(i) => (i as usize) < self.inputs.len(),
                Argument::Result(j) | Argument::Nested(j, _) => (j as usize) < at,
            };
            if !there {
                return invalid("an argument that isn't there: Sui would refuse it");
            }
        }
        Ok(())
    }

    /// Once a command has used Move's randomness, Sui takes only sends and merges after it, so
    /// nothing can act on what it drew and try again.
    fn check_random(&self) -> Result<(), Error> {
        let Some(random) =
            self.inputs.iter().position(|i| matches!(i, Input::Shared { id, .. } if *id == RANDOM))
        else {
            return Ok(());
        };
        let mut used = false;
        for c in &self.commands {
            if used && !matches!(c, Command::TransferObjects { .. } | Command::MergeCoins { .. }) {
                return Err(Error::Invalid(
                    "a command after randomness is used, other than a send or a merge: Sui would refuse it",
                ));
            }
            used = used || c.arguments().contains(&Argument::Input(random as u16));
        }
        Ok(())
    }

    fn check_gas(&self) -> Result<(), Error> {
        let invalid = |why| Err(Error::Invalid(why));
        let Gas { price, budget, .. } = self.gas;
        if price >= MAX_GAS_PRICE {
            return invalid("a gas price higher than Sui takes");
        }
        if budget > MAX_BUDGET {
            return invalid("a gas budget bigger than Sui takes");
        }
        if self.is_gasless() {
            if budget != 0 {
                return invalid("a gasless transaction with a budget for gas: Sui would refuse it");
            }
        } else {
            if price == 0 {
                return invalid("no price for gas, when the fee is paid: Sui would refuse it");
            }
            // price is below MAX_GAS_PRICE: this can't overflow
            if budget < MIN_BUDGET_UNITS * price {
                return invalid("a gas budget too small for any transaction: Sui would refuse it");
            }
        }
        // a reservation draws on the sender's own balance: there's no sponsor's to draw on
        if self.gas.owner != self.sender && self.gas.payment.iter().any(|r| r.reservation().is_some()) {
            return invalid("a sponsor's fee paid by a coin reservation: Sui would refuse it");
        }
        Ok(())
    }

    /// What Sui takes for nothing: a balance moved with the framework's own functions, and no more.
    fn check_gasless(&self) -> Result<(), Error> {
        let invalid = |why| Err(Error::Invalid(why));
        if self.commands.is_empty() {
            return invalid("a gasless transaction that does nothing: Sui would refuse it");
        }
        let mut used = alloc::vec![false; self.inputs.len()];
        for c in &self.commands {
            match c {
                Command::MoveCall(call) => {
                    let known = call.package == FRAMEWORK
                        && GASLESS_FUNCTIONS.iter().any(|(m, f)| call.module == *m && call.function == *f);
                    let [t] = call.types.as_slice() else {
                        return invalid("a gasless transaction calling a function Sui doesn't let go free");
                    };
                    if !known || (call.module == "funds_accumulator" && t.balance_of().is_none()) {
                        return invalid("a gasless transaction calling a function Sui doesn't let go free");
                    }
                }
                Command::SplitCoins { .. } | Command::MergeCoins { .. } => {}
                _ => return invalid("a gasless transaction doing what Sui doesn't let go free"),
            }
            for a in c.arguments() {
                if let Argument::Input(i) = a {
                    used[i as usize] = true;
                }
            }
        }
        let mut unused_pure = 0;
        for (i, input) in self.inputs.iter().enumerate() {
            match input {
                Input::Receiving(_) => {
                    return invalid("a gasless transaction receiving an object: Sui would refuse it");
                }
                Input::Pure(b) if b.len() > GASLESS_MAX_PURE => {
                    return invalid("a gasless transaction with an input longer than Sui lets go free");
                }
                Input::Pure(_) if !used[i] => unused_pure += 1,
                Input::Pure(_) => {}
                _ if !used[i] => {
                    return invalid(
                        "a gasless transaction with an object it doesn't use: Sui would refuse it",
                    );
                }
                _ => {}
            }
        }
        if unused_pure > GASLESS_MAX_UNUSED {
            return invalid("a gasless transaction with inputs it doesn't use: Sui would refuse it");
        }
        Ok(())
    }
}
