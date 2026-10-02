//! The XRP Ledger's binary format, read as rippled reads a transaction (its `STObject`, from a
//! `SerialIter`) and held to the one way it writes one: each field a header (its type's code
//! and its own, in the fewest bytes), then its value; the fields in order (by type, then by
//! field) and none twice; lengths in their shortest form; an inner object closed by its end
//! marker, an array by its own. Bytes that read any other way are refused: rippled would refuse
//! them, or write them back otherwise, and a signature over them wouldn't be the transaction's.

use alloc::vec::Vec;

use crate::address::AccountId;
use crate::definitions::FIELDS;

/// How deep objects and arrays may go inside one another: as deep as rippled reads them.
pub const MAX_DEPTH: usize = 10;

/// The types of value a field holds, by their codes in a field's header, named as the codec's
/// definitions name them (`UInt32`, `AccountID`, `STObject`...).
pub mod kind {
    pub const UINT16: u8 = 1;
    pub const UINT32: u8 = 2;
    pub const UINT64: u8 = 3;
    pub const HASH128: u8 = 4;
    pub const HASH256: u8 = 5;
    pub const AMOUNT: u8 = 6;
    pub const BLOB: u8 = 7;
    pub const ACCOUNT: u8 = 8;
    pub const NUMBER: u8 = 9;
    pub const INT32: u8 = 10;
    pub const INT64: u8 = 11;
    pub const OBJECT: u8 = 14;
    pub const ARRAY: u8 = 15;
    pub const UINT8: u8 = 16;
    pub const HASH160: u8 = 17;
    pub const PATH_SET: u8 = 18;
    pub const VECTOR256: u8 = 19;
    pub const UINT96: u8 = 20;
    pub const HASH192: u8 = 21;
    pub const HASH384: u8 = 22;
    pub const HASH512: u8 = 23;
    pub const ISSUE: u8 = 24;
    pub const BRIDGE: u8 = 25;
    pub const CURRENCY: u8 = 26;
}

/// A field: its type's code and its own, a byte each (`0x0801` is type 8, an account, field 1:
/// `Account`). The ledger writes a transaction's fields in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Field(pub u16);

impl Field {
    /// The field of a type's code and its own.
    pub const fn new(kind: u8, nth: u8) -> Field { Field(((kind as u16) << 8) | nth as u16) }

    /// Its type's code.
    pub const fn kind(self) -> u8 { (self.0 >> 8) as u8 }

    /// Its own code, among its type's.
    pub const fn nth(self) -> u8 { self.0 as u8 }

    fn known(self) -> Option<&'static (u16, &'static str, bool)> {
        FIELDS.binary_search_by_key(&self.0, |f| f.0).ok().map(|i| &FIELDS[i])
    }

    /// Its name, if the ledger knows it.
    pub fn name(self) -> Option<&'static str> { self.known().map(|f| f.1) }

    /// Whether a transaction's signature covers it: every field but the signatures themselves.
    pub fn signed(self) -> bool { self.known().is_some_and(|f| f.2) }
}

impl core::fmt::Display for Field {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "field {} of type {}", self.nth(), self.kind()),
        }
    }
}

/// The fields maki reads by name, each as the codec's definitions number it.
pub mod fields {
    use super::Field;

    pub const SIGNER_WEIGHT: Field = Field(0x0103);
    pub const TRANSACTION_TYPE: Field = Field(0x0102);
    pub const NETWORK_ID: Field = Field(0x0201);
    pub const FLAGS: Field = Field(0x0202);
    pub const SOURCE_TAG: Field = Field(0x0203);
    pub const SEQUENCE: Field = Field(0x0204);
    pub const EXPIRATION: Field = Field(0x020a);
    pub const TRANSFER_RATE: Field = Field(0x020b);
    pub const WALLET_SIZE: Field = Field(0x020c);
    pub const DESTINATION_TAG: Field = Field(0x020e);
    pub const QUALITY_IN: Field = Field(0x0214);
    pub const QUALITY_OUT: Field = Field(0x0215);
    pub const OFFER_SEQUENCE: Field = Field(0x0219);
    pub const LAST_LEDGER_SEQUENCE: Field = Field(0x021b);
    pub const SET_FLAG: Field = Field(0x0221);
    pub const CLEAR_FLAG: Field = Field(0x0222);
    pub const SIGNER_QUORUM: Field = Field(0x0223);
    pub const CANCEL_AFTER: Field = Field(0x0224);
    pub const FINISH_AFTER: Field = Field(0x0225);
    pub const TICKET_SEQUENCE: Field = Field(0x0229);
    pub const EMAIL_HASH: Field = Field(0x0401);
    pub const WALLET_LOCATOR: Field = Field(0x0507);
    pub const ACCOUNT_TXN_ID: Field = Field(0x0509);
    pub const INVOICE_ID: Field = Field(0x0511);
    pub const CHECK_ID: Field = Field(0x0518);
    pub const DOMAIN_ID: Field = Field(0x0522);
    pub const AMOUNT: Field = Field(0x0601);
    pub const LIMIT_AMOUNT: Field = Field(0x0603);
    pub const TAKER_PAYS: Field = Field(0x0604);
    pub const TAKER_GETS: Field = Field(0x0605);
    pub const FEE: Field = Field(0x0608);
    pub const SEND_MAX: Field = Field(0x0609);
    pub const DELIVER_MIN: Field = Field(0x060a);
    pub const MESSAGE_KEY: Field = Field(0x0702);
    pub const SIGNING_PUB_KEY: Field = Field(0x0703);
    pub const TXN_SIGNATURE: Field = Field(0x0704);
    pub const DOMAIN: Field = Field(0x0707);
    pub const MEMO_TYPE: Field = Field(0x070c);
    pub const MEMO_DATA: Field = Field(0x070d);
    pub const MEMO_FORMAT: Field = Field(0x070e);
    pub const FULFILLMENT: Field = Field(0x0710);
    pub const CONDITION: Field = Field(0x0711);
    pub const ACCOUNT: Field = Field(0x0801);
    pub const OWNER: Field = Field(0x0802);
    pub const DESTINATION: Field = Field(0x0803);
    pub const REGULAR_KEY: Field = Field(0x0808);
    pub const NFTOKEN_MINTER: Field = Field(0x0809);
    pub const DELEGATE: Field = Field(0x080c);
    pub const OBJECT_END: Field = Field(0x0e01);
    pub const MEMO: Field = Field(0x0e0a);
    pub const SIGNER_ENTRY: Field = Field(0x0e0b);
    pub const ARRAY_END: Field = Field(0x0f01);
    pub const SIGNERS: Field = Field(0x0f03);
    pub const SIGNER_ENTRIES: Field = Field(0x0f04);
    pub const MEMOS: Field = Field(0x0f09);
    pub const TICK_SIZE: Field = Field(0x1010);
    pub const PATHS: Field = Field(0x1201);
    pub const CREDENTIAL_IDS: Field = Field(0x1305);
}

use fields::{ARRAY_END, OBJECT_END};

/// A currency's code: 20 bytes. Three letters in the middle of zeros are a standard code
/// (`USD`); all zeros is XRP itself; anything else a code of its token's own.
pub type Currency = [u8; 20];

/// A token's amount, exactly: `mantissa` × 10^`exponent`. Zero is a mantissa of 0; any other is
/// 16 digits (10^15 to 10^16 - 1), the exponent -96 to 80.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimal {
    pub mantissa: u64,
    pub exponent: i32,
}

/// An amount, as the ledger writes one. Never negative: no transaction maki reads carries a
/// negative amount, and rippled refuses them where it reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Amount {
    /// XRP, in drops: a millionth of an XRP each.
    Xrp(u64),
    /// A token an account issues, by its currency's code (on a trust line to the issuer).
    Issued { value: Decimal, currency: Currency, issuer: AccountId },
    /// A multi-purpose token: whole units of an issuance (its sequence, then its issuer).
    Mpt { units: u64, issuance: [u8; 24] },
}

/// The most XRP there is, in drops: 100 billion XRP.
pub const MAX_DROPS: u64 = 100_000_000_000_000_000;
/// The most units of a multi-purpose token there can be.
pub const MAX_MPT: u64 = 0x7fff_ffff_ffff_ffff;

/// A step of a payment's path: an account to ripple through, or an order book to trade in (a
/// currency, and its issuer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step {
    pub account: Option<AccountId>,
    pub currency: Option<Currency>,
    pub issuer: Option<AccountId>,
}

/// A field's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// An unsigned number, written big-endian: a flag, a tag, a sequence number.
    UInt8(u8),
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
    /// A hash, or anything else of a fixed size maki shows as bytes.
    Bytes(Vec<u8>),
    /// An amount: of XRP, a token or an MPT.
    Amount(Amount),
    /// Bytes of a length the field gives.
    Blob(Vec<u8>),
    /// An account (20 bytes, after a length that must say so).
    Account(AccountId),
    /// A list of 256-bit hashes.
    Hashes(Vec<[u8; 32]>),
    /// A payment's paths, each a list of steps.
    Paths(Vec<Vec<Step>>),
    Object(Object),
    /// An array: objects, each under a field of its own.
    Array(Vec<(Field, Object)>),
}

/// An object: its fields, in the order the ledger writes them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Object {
    pub fields: Vec<(Field, Value)>,
}

impl Object {
    /// The value of field `f`, if it's there.
    pub fn get(&self, f: Field) -> Option<&Value> {
        self.fields.binary_search_by_key(&f, |(k, _)| *k).ok().map(|i| &self.fields[i].1)
    }

    /// Whether field `f` is there.
    pub fn has(&self, f: Field) -> bool { self.get(f).is_some() }

    /// The number in field `f`, if it's there and of that size (so with the next three).
    pub fn u8(&self, f: Field) -> Option<u8> {
        match self.get(f)? {
            Value::UInt8(v) => Some(*v),
            _ => None,
        }
    }

    pub fn u16(&self, f: Field) -> Option<u16> {
        match self.get(f)? {
            Value::UInt16(v) => Some(*v),
            _ => None,
        }
    }

    pub fn u32(&self, f: Field) -> Option<u32> {
        match self.get(f)? {
            Value::UInt32(v) => Some(*v),
            _ => None,
        }
    }

    /// The amount in field `f`, if it's there.
    pub fn amount(&self, f: Field) -> Option<&Amount> {
        match self.get(f)? {
            Value::Amount(a) => Some(a),
            _ => None,
        }
    }

    /// The account in field `f`, if it's there.
    pub fn account(&self, f: Field) -> Option<&AccountId> {
        match self.get(f)? {
            Value::Account(a) => Some(a),
            _ => None,
        }
    }

    /// A blob's bytes, or a hash's.
    pub fn bytes(&self, f: Field) -> Option<&[u8]> {
        match self.get(f)? {
            Value::Blob(b) | Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The hashes in field `f` (a list of them), if it's there.
    pub fn hashes(&self, f: Field) -> Option<&[[u8; 32]]> {
        match self.get(f)? {
            Value::Hashes(h) => Some(h),
            _ => None,
        }
    }

    /// The paths in field `f`, if it's there.
    pub fn paths(&self, f: Field) -> Option<&[Vec<Step>]> {
        match self.get(f)? {
            Value::Paths(p) => Some(p),
            _ => None,
        }
    }

    /// The objects in array `f`, each under its field, if it's there.
    pub fn array(&self, f: Field) -> Option<&[(Field, Object)]> {
        match self.get(f)? {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
}

/// Why bytes aren't a transaction in the ledger's format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A field, a length or a value runs past the end.
    Short,
    /// A field's header in a longer form than it needs.
    Header,
    /// A field the ledger doesn't know.
    Unknown(Field),
    /// Fields out of the order the ledger writes them in.
    Order(Field),
    /// A field given twice.
    Twice(Field),
    /// An end marker where none can be, or none where one must.
    Marker,
    /// Objects and arrays inside one another deeper than rippled reads.
    Depth,
    /// A length in a form the format doesn't have.
    Length,
    /// An account that isn't 20 bytes.
    Account,
    /// An amount the ledger can't hold, or writes another way: why.
    Amount(&'static str),
    /// Paths the ledger can't read: why.
    Paths(&'static str),
    /// A list of hashes that doesn't come out in whole hashes.
    Hashes,
    /// An array of something other than objects.
    Array,
    /// An asset (an issue) or a bridge the ledger can't read.
    Issue,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("not an XRP Ledger transaction: ")?;
        match self {
            Error::Short => f.write_str("cut short"),
            Error::Header => f.write_str("a field's header written longer than it is"),
            Error::Unknown(field) => write!(f, "a field the ledger doesn't know ({field})"),
            Error::Order(field) => write!(f, "{field} out of order"),
            Error::Twice(field) => write!(f, "{field} twice"),
            Error::Marker => f.write_str("an object or array that doesn't end where it should"),
            Error::Depth => f.write_str("objects inside objects deeper than the ledger reads"),
            Error::Length => f.write_str("a length the format doesn't have"),
            Error::Account => f.write_str("an account that isn't 20 bytes"),
            Error::Amount(why) => f.write_str(why),
            Error::Paths(why) => f.write_str(why),
            Error::Hashes => f.write_str("a list of hashes that isn't whole hashes"),
            Error::Array => f.write_str("an array of something other than objects"),
            Error::Issue => f.write_str("an asset the ledger can't read"),
        }
    }
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn done(&self) -> bool { self.at == self.b.len() }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len()).ok_or(Error::Short)?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Error> { Ok(self.take(1)?[0]) }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// A field's header: the type's code in the high four bits and the field's in the low,
    /// either 0 to mean it follows in a byte of its own, which it may only when it's 16 or more.
    fn field(&mut self) -> Result<Field, Error> {
        let first = self.u8()?;
        let (mut kind, mut nth) = (first >> 4, first & 15);
        if kind == 0 {
            kind = self.u8()?;
            if kind < 16 {
                return Err(Error::Header);
            }
        }
        if nth == 0 {
            nth = self.u8()?;
            if nth < 16 {
                return Err(Error::Header);
            }
        }
        Ok(Field::new(kind, nth))
    }

    /// A length before a field's bytes: one byte up to 192, two up to 12,480, three up to
    /// 918,744; each length has only the one form.
    fn length(&mut self) -> Result<usize, Error> {
        let b1 = self.u8()? as usize;
        Ok(match b1 {
            0..=192 => b1,
            193..=240 => 193 + (b1 - 193) * 256 + self.u8()? as usize,
            241..=254 => {
                let (b2, b3) = (self.u8()? as usize, self.u8()? as usize);
                12_481 + (b1 - 241) * 65_536 + b2 * 256 + b3
            }
            _ => return Err(Error::Length),
        })
    }

    fn account(&mut self) -> Result<AccountId, Error> {
        if self.length()? != 20 {
            return Err(Error::Account);
        }
        self.array()
    }

    /// An amount, as rippled reads one (`STAmount`), and only as it writes one back.
    fn amount(&mut self) -> Result<Amount, Error> {
        let first: [u8; 8] = self.array()?;
        let v = u64::from_be_bytes(first);
        const ISSUED: u64 = 1 << 63;
        const POSITIVE: u64 = 1 << 62;
        const MPT: u64 = 1 << 61;
        if v & ISSUED != 0 {
            let currency: Currency = self.array()?;
            let issuer: AccountId = self.array()?;
            if currency == [0; 20] {
                return Err(Error::Amount("a token amount in XRP's own code"));
            }
            if issuer == [0; 20] {
                return Err(Error::Amount("a token amount with no issuer"));
            }
            // ten bits: issued, positive, and the exponent plus 97
            let top = (v >> 54) as u32;
            let mantissa = v & ((1 << 54) - 1);
            if mantissa == 0 {
                // zero has the one form: issued, and nothing else
                if top != 0b10_0000_0000 {
                    return Err(Error::Amount("a token amount of zero, written oddly"));
                }
                return Ok(Amount::Issued { value: Decimal { mantissa: 0, exponent: 0 }, currency, issuer });
            }
            if top & 0b01_0000_0000 == 0 {
                return Err(Error::Amount("a negative amount"));
            }
            let exponent = (top & 0xff) as i32 - 97;
            if !(1_000_000_000_000_000..=9_999_999_999_999_999).contains(&mantissa)
                || !(-96..=80).contains(&exponent)
            {
                return Err(Error::Amount("a token amount the ledger can't hold"));
            }
            return Ok(Amount::Issued { value: Decimal { mantissa, exponent }, currency, issuer });
        }
        if v & MPT != 0 {
            // a byte of flags, then the units (eight bytes), then the issuance
            if first[0] != 0x60 {
                return Err(Error::Amount(if first[0] == 0x20 {
                    "a negative amount"
                } else {
                    "a token amount written oddly"
                }));
            }
            let mut units = [0u8; 8];
            units[..7].copy_from_slice(&first[1..]);
            units[7] = self.u8()?;
            let units = u64::from_be_bytes(units);
            if units > MAX_MPT {
                return Err(Error::Amount("more of a token than there can be"));
            }
            return Ok(Amount::Mpt { units, issuance: self.array()? });
        }
        if v & POSITIVE == 0 {
            return Err(Error::Amount("a negative amount"));
        }
        let drops = v & !POSITIVE;
        if drops > MAX_DROPS {
            return Err(Error::Amount("more XRP than there is"));
        }
        Ok(Amount::Xrp(drops))
    }

    /// A payment's paths, as rippled reads them (`STPathSet`): each path's steps, a byte saying
    /// which of an account, a currency and an issuer follow; 0xff between paths, 0 after the
    /// last. No path may be empty.
    fn paths(&mut self) -> Result<Vec<Vec<Step>>, Error> {
        let mut set = Vec::new();
        let mut path = Vec::new();
        loop {
            let kind = self.u8()?;
            if kind == 0x00 || kind == 0xff {
                if path.is_empty() {
                    return Err(Error::Paths("an empty path"));
                }
                set.push(core::mem::take(&mut path));
                if kind == 0x00 {
                    return Ok(set);
                }
                continue;
            }
            if kind & !0x31 != 0 {
                return Err(Error::Paths("a path's step of a kind the ledger doesn't know"));
            }
            let account = if kind & 0x01 != 0 { Some(self.array()?) } else { None };
            let currency = if kind & 0x10 != 0 { Some(self.array()?) } else { None };
            let issuer = if kind & 0x20 != 0 { Some(self.array()?) } else { None };
            path.push(Step { account, currency, issuer });
        }
    }

    /// An asset (`STIssue`): XRP (its code, all zeros), a token (its code and issuer), or a
    /// multi-purpose token (its issuer, the account numbered 1, and its sequence).
    fn issue(&mut self) -> Result<Vec<u8>, Error> {
        let start = self.at;
        let first: [u8; 20] = self.array()?;
        if first != [0; 20] {
            let second: [u8; 20] = self.array()?;
            let mut one = [0u8; 20];
            one[19] = 1;
            if second == one {
                self.take(4)?;
            } else if second == [0; 20] {
                return Err(Error::Issue);
            }
        }
        Ok(self.b[start..self.at].to_vec())
    }

    /// A cross-chain bridge (`STXChainBridge`): two doors (accounts) and the assets they carry.
    fn bridge(&mut self) -> Result<Vec<u8>, Error> {
        let start = self.at;
        for _ in 0..2 {
            self.account()?;
            self.issue()?;
        }
        Ok(self.b[start..self.at].to_vec())
    }

    /// A value of a fixed size, as bytes.
    fn fixed(&mut self, n: usize) -> Result<Value, Error> { Ok(Value::Bytes(self.take(n)?.to_vec())) }

    fn value(&mut self, f: Field, depth: usize) -> Result<Value, Error> {
        use kind::*;
        match f.kind() {
            UINT8 => Ok(Value::UInt8(self.u8()?)),
            UINT16 => Ok(Value::UInt16(u16::from_be_bytes(self.array()?))),
            UINT32 => Ok(Value::UInt32(u32::from_be_bytes(self.array()?))),
            UINT64 => Ok(Value::UInt64(u64::from_be_bytes(self.array()?))),
            INT32 => self.fixed(4),
            INT64 => self.fixed(8),
            HASH128 => self.fixed(16),
            HASH160 | CURRENCY => self.fixed(20),
            HASH192 => self.fixed(24),
            HASH256 => self.fixed(32),
            HASH384 => self.fixed(48),
            HASH512 => self.fixed(64),
            UINT96 | NUMBER => self.fixed(12),
            AMOUNT => Ok(Value::Amount(self.amount()?)),
            BLOB => {
                let n = self.length()?;
                Ok(Value::Blob(self.take(n)?.to_vec()))
            }
            ACCOUNT => Ok(Value::Account(self.account()?)),
            VECTOR256 => {
                let n = self.length()?;
                if n % 32 != 0 {
                    return Err(Error::Hashes);
                }
                let mut hashes = Vec::with_capacity(n / 32);
                for _ in 0..n / 32 {
                    hashes.push(self.array()?);
                }
                Ok(Value::Hashes(hashes))
            }
            PATH_SET => Ok(Value::Paths(self.paths()?)),
            ISSUE => Ok(Value::Bytes(self.issue()?)),
            BRIDGE => Ok(Value::Bytes(self.bridge()?)),
            OBJECT => Ok(Value::Object(self.object(depth + 1, None)?)),
            ARRAY => Ok(Value::Array(self.array_of_objects(depth + 1)?)),
            _ => Err(Error::Unknown(f)),
        }
    }

    /// An object's fields, up to its end marker; the transaction's own (`top`) up to the end of
    /// the bytes, with no marker, and where each field is (for `spans`).
    fn object(&mut self, depth: usize, mut top: Option<&mut Vec<Span>>) -> Result<Object, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Depth);
        }
        let mut fields: Vec<(Field, Value)> = Vec::new();
        loop {
            if top.is_some() && self.done() {
                return Ok(Object { fields });
            }
            let start = self.at;
            let f = self.field()?;
            if f == OBJECT_END {
                if top.is_some() {
                    return Err(Error::Marker);
                }
                return Ok(Object { fields });
            }
            if f == ARRAY_END || f.name().is_none() {
                return Err(if f == ARRAY_END { Error::Marker } else { Error::Unknown(f) });
            }
            if let Some(&(last, _)) = fields.last() {
                if f == last {
                    return Err(Error::Twice(f));
                }
                if f < last {
                    return Err(if fields.iter().any(|(k, _)| *k == f) {
                        Error::Twice(f)
                    } else {
                        Error::Order(f)
                    });
                }
            }
            let value = self.value(f, depth)?;
            fields.push((f, value));
            if let Some(spans) = top.as_deref_mut() {
                spans.push((f, start, self.at));
            }
        }
    }

    /// An array's objects, each under a field of its own, up to the array's end marker.
    fn array_of_objects(&mut self, depth: usize) -> Result<Vec<(Field, Object)>, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Depth);
        }
        let mut items = Vec::new();
        loop {
            let f = self.field()?;
            if f == ARRAY_END {
                return Ok(items);
            }
            if f == OBJECT_END {
                return Err(Error::Marker);
            }
            if f.name().is_none() {
                return Err(Error::Unknown(f));
            }
            if f.kind() != kind::OBJECT {
                return Err(Error::Array);
            }
            items.push((f, self.object(depth + 1, None)?));
        }
    }
}

/// Where a field is in a transaction: the field, where its header starts, and where its value
/// ends.
pub type Span = (Field, usize, usize);

/// A transaction's fields, read whole: every byte of `bytes`, and nothing past them.
pub fn read(bytes: &[u8]) -> Result<Object, Error> { read_spans(bytes).map(|(o, _)| o) }

/// A transaction's fields, and where each is in `bytes` (from its header to the end of its
/// value).
pub fn read_spans(bytes: &[u8]) -> Result<(Object, Vec<Span>), Error> {
    let mut r = Reader { b: bytes, at: 0 };
    let mut spans = Vec::new();
    let object = r.object(0, Some(&mut spans))?;
    Ok((object, spans))
}

/// A length before a field's bytes, as the ledger writes it.
pub fn length(n: usize) -> Vec<u8> {
    match n {
        0..=192 => alloc::vec![n as u8],
        193..=12_480 => {
            let m = n - 193;
            alloc::vec![193 + (m >> 8) as u8, m as u8]
        }
        _ => {
            let m = n - 12_481;
            alloc::vec![241 + (m >> 16) as u8, (m >> 8) as u8, m as u8]
        }
    }
}
