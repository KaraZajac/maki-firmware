//! A transaction, read whole, and held to what rippled holds every transaction to before its
//! type's own rules (its `STTx`, and the first checks every transactor makes): the binary format
//! (`codec`); a type the ledger knows, which an account may send; the fields that type has and
//! no others, and those it must have; a fee in XRP; a sequence or a ticket, not both. And to what
//! maki signs: a transaction with no signatures in it yet, for one key, its SigningPubKey.

use core::fmt;

use crate::address::AccountId;
use crate::codec::fields::*;
use crate::codec::{self, Amount, Field, Object};
use crate::definitions::{COMMON, FORMATS, REQUIRED, TRANSACTION_TYPES};

/// The least a transaction can be, as rippled has it.
pub const MIN: usize = 32;
/// The most maki takes: what fits in a message to the app.
pub const MAX: usize = 4096;

/// The pseudo-transactions (EnableAmendment, SetFee, UNLModify): the ledger's validators make
/// them, and no account sends one.
const PSEUDO: [u16; 3] = [100, 101, 102];

/// A flag any transaction may have: its signature is fully canonical (every one is, now).
pub const FULLY_CANONICAL_SIG: u32 = 0x8000_0000;
/// A flag that makes a transaction part of a batch: signed with the batch, never alone.
pub const INNER_BATCH: u32 = 0x4000_0000;

/// A transaction, read and held to the ledger's rules for every transaction; what its type does
/// is `display`'s to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Its type's code (`TransactionType`), and the type's name.
    pub kind: u16,
    pub name: &'static str,
    pub fields: Object,
    /// The account it's from.
    pub account: AccountId,
    /// The key that signs it (SigningPubKey): secp256k1, compressed.
    pub key: [u8; 33],
    /// The fee, in drops: burnt, not paid to anyone.
    pub fee: u64,
    pub flags: u32,
    /// The account's sequence number it takes, or 0 for a ticket's.
    pub sequence: u32,
    pub ticket: Option<u32>,
    /// The last ledger it can be in, if it says.
    pub last_ledger: Option<u32>,
}

/// Why bytes aren't a transaction maki will read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Bigger than maki takes.
    TooBig,
    /// Shorter than any transaction.
    TooShort,
    /// Not in the ledger's binary format.
    Codec(codec::Error),
    /// A transaction type the ledger doesn't have.
    Type(u16),
    /// A pseudo-transaction, which only validators make.
    Pseudo(&'static str),
    /// Without a field its type must have.
    Missing { kind: &'static str, field: &'static str },
    /// With a field its type doesn't have.
    Unexpected { kind: &'static str, field: Field },
    /// With a signature in it already: maki signs a transaction without its signatures.
    Signed(Field),
    /// For several keys to sign (multisigning): its SigningPubKey is empty.
    Multisigned,
    /// A signing key that isn't secp256k1's.
    Key,
    /// From no account.
    Account,
    /// A fee in something other than XRP.
    Fee,
    /// Part of a batch.
    Batch,
    /// Both a sequence number and a ticket.
    SequenceAndTicket,
    /// A ticket, and the ID of the account's last transaction, which can't go together.
    TicketAndPrevious,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooBig => write!(f, "bigger than maki takes: {MAX} bytes"),
            Error::TooShort => f.write_str("not an XRP Ledger transaction: too short to be one"),
            Error::Codec(e) => e.fmt(f),
            Error::Type(n) => {
                write!(f, "not an XRP Ledger transaction: a type the ledger doesn't have ({n})")
            }
            Error::Pseudo(name) => {
                write!(f, "a pseudo-transaction ({name}): only the ledger's validators make those")
            }
            Error::Missing { kind, field } => {
                write!(f, "a {kind} without its {field}: the XRP Ledger would refuse it")
            }
            Error::Unexpected { kind, field } => {
                write!(f, "a {kind} with {field}, which it doesn't have: the XRP Ledger would refuse it")
            }
            Error::Signed(field) => {
                write!(f, "signed already ({field}): maki takes a transaction without its signatures")
            }
            Error::Multisigned => f.write_str("for several keys to sign together, which maki doesn't do"),
            Error::Key => {
                f.write_str("for a key that isn't a compressed secp256k1 key to sign: this account's is")
            }
            Error::Account => f.write_str("from no account: the XRP Ledger would refuse it"),
            Error::Fee => f.write_str("a fee that isn't XRP: the XRP Ledger would refuse it"),
            Error::Batch => f.write_str("part of a batch: it's signed with its batch, never alone"),
            Error::SequenceAndTicket => {
                f.write_str("both a sequence number and a ticket: the XRP Ledger would refuse it")
            }
            Error::TicketAndPrevious => {
                f.write_str("a ticket and AccountTxnID together: the XRP Ledger would refuse it")
            }
        }
    }
}

impl From<codec::Error> for Error {
    fn from(e: codec::Error) -> Error { Error::Codec(e) }
}

/// The name of the transaction type with code `kind`, if the ledger has one.
pub fn type_name(kind: u16) -> Option<&'static str> {
    TRANSACTION_TYPES.iter().find(|t| t.0 == kind).map(|t| t.1)
}

/// Whether a transaction of type `kind` may have field `f`, and whether it must: the fields
/// every transaction has (`COMMON`) and its type's own (`FORMATS`).
fn format(kind: u16) -> impl Iterator<Item = (Field, u8)> {
    COMMON
        .iter()
        .map(|&(f, need)| (Field(f), need))
        .chain(FORMATS.iter().filter(move |e| e.0 == kind).map(|&(_, f, need)| (Field(f), need)))
}

impl Transaction {
    /// A transaction, from the bytes the XRP Ledger's tooling makes of it to be signed
    /// (xrpl.js's `encode`, of a transaction with its SigningPubKey and no signature): read
    /// whole, and refused if rippled would refuse it, or if it isn't one for maki to sign.
    pub fn parse(bytes: &[u8]) -> Result<Transaction, Error> {
        if bytes.len() > MAX {
            return Err(Error::TooBig);
        }
        if bytes.len() < MIN {
            return Err(Error::TooShort);
        }
        let fields = codec::read(bytes)?;
        let kind = fields
            .u16(TRANSACTION_TYPE)
            .ok_or(Error::Missing { kind: "transaction", field: "TransactionType" })?;
        let name = type_name(kind).ok_or(Error::Type(kind))?;
        if PSEUDO.contains(&kind) {
            return Err(Error::Pseudo(name));
        }
        // the fields its type has, and none it hasn't (rippled's `applyTemplate`)
        if let Some(&(field, _)) = fields.fields.iter().find(|(f, _)| !format(kind).any(|(g, _)| g == *f)) {
            return Err(Error::Unexpected { kind: name, field });
        }
        if let Some((field, _)) = format(kind).find(|&(f, need)| need == REQUIRED && !fields.has(f)) {
            return Err(Error::Missing { kind: name, field: field.name().unwrap_or("?") });
        }
        // what's to be signed: no signature in it yet, nor anyone else's
        if let Some(&(field, _)) = fields.fields.iter().find(|(f, _)| !f.signed()) {
            return Err(Error::Signed(field));
        }
        let key = fields.bytes(SIGNING_PUB_KEY).unwrap_or_default();
        if key.is_empty() {
            return Err(Error::Multisigned);
        }
        let key: [u8; 33] =
            key.try_into().ok().filter(|k: &[u8; 33]| matches!(k[0], 2 | 3)).ok_or(Error::Key)?;
        let account = *fields.account(ACCOUNT).ok_or(Error::Account)?;
        if account == [0; 20] {
            return Err(Error::Account);
        }
        let fee = match fields.amount(FEE) {
            Some(Amount::Xrp(drops)) => *drops,
            _ => return Err(Error::Fee),
        };
        let flags = fields.u32(FLAGS).unwrap_or(0);
        if flags & INNER_BATCH != 0 {
            return Err(Error::Batch);
        }
        let sequence = fields.u32(SEQUENCE).unwrap_or(0);
        let ticket = fields.u32(TICKET_SEQUENCE);
        if sequence != 0 && ticket.is_some() {
            return Err(Error::SequenceAndTicket);
        }
        if ticket.is_some() && fields.has(ACCOUNT_TXN_ID) {
            return Err(Error::TicketAndPrevious);
        }
        let last_ledger = fields.u32(LAST_LEDGER_SEQUENCE);
        Ok(Transaction { kind, name, fields, account, key, fee, flags, sequence, ticket, last_ledger })
    }
}
