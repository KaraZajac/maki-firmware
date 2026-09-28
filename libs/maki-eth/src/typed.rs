//! Typed data (EIP-712, as `eth_signTypedData_v4` sends it): read from the site's JSON strictly,
//! hashed from exactly what maki shows, and signed.
//!
//! What maki takes, beyond what EIP-712 asks:
//!
//! - `types` names `EIP712Domain`, with only the fields EIP-712 defines for it, of their types.
//!   Wallets differ on typed data without it (some hash the domain as having no fields at all).
//! - No type refers to itself, however indirectly: EIP-712 leaves it open, and wallets differ.
//! - Every value is declared by its type, and every declared value is there (a struct may be
//!   null or left out, and hashes to zero, as v4 has it). An undeclared value isn't signed, so
//!   maki won't take one to show.
//! - Integers are JSON numbers or strings, decimal or `0x` hex; `bytes` and `bytesN` are hex (N
//!   bytes exactly); addresses are 20 bytes of hex; booleans are `true` or `false`.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::account::{keccak256, Account};
use crate::json::{self, Value};

/// The most JSON maki takes.
pub const MAX_TYPED: usize = 64 * 1024;
/// The most types, and fields in all.
const MAX_TYPES: usize = 64;
const MAX_FIELDS: usize = 512;

/// The fields EIP-712 defines for the domain, and their types, in its order.
pub const DOMAIN_FIELDS: [(&str, &str); 5] = [
    ("name", "string"),
    ("version", "string"),
    ("chainId", "uint256"),
    ("verifyingContract", "address"),
    ("salt", "bytes32"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Json(json::Error),
    /// What's wrong with it, for the computer to show.
    Shape(String),
    Key,
}

impl From<json::Error> for Error {
    fn from(e: json::Error) -> Self { Error::Json(e) }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Json(e) => write!(f, "not typed data maki can read: {}", e),
            Error::Shape(what) => write!(f, "not typed data maki can read: {}", what),
            Error::Key => write!(f, "couldn't make the signature"),
        }
    }
}

fn shape<T>(what: String) -> Result<T, Error> { Err(Error::Shape(what)) }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub ty: String,
}

/// Typed data, checked: its types sound, and its domain and message what they declare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedData {
    /// In the order written.
    pub types: Vec<(String, Vec<Field>)>,
    pub primary_type: String,
    pub domain: Value,
    pub message: Value,
}

/// A type as a field names it: a base (`uint256`, `Person`) and any array dimensions, the
/// innermost first (`Person[2][]`: `[Some(2), None]`).
fn split_type(ty: &str) -> Option<(&str, Vec<Option<usize>>)> {
    let base_end = ty.find('[').unwrap_or(ty.len());
    let (base, mut rest) = ty.split_at(base_end);
    let mut dims = Vec::new();
    while !rest.is_empty() {
        let close = rest.find(']')?;
        let inner = rest.get(1..close)?;
        if !rest.starts_with('[') {
            return None;
        }
        dims.push(if inner.is_empty() {
            None
        } else {
            // no leading zeros, and at least one element
            if inner.starts_with('0') || !inner.bytes().all(|b| b.is_ascii_digit()) || inner.len() > 4 {
                return None;
            }
            Some(inner.parse().ok()?)
        });
        rest = &rest[close + 1..];
    }
    Some((base, dims))
}

fn identifier(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        && s.len() <= 64
}

/// `uintN` or `intN` (N a multiple of 8, up to 256): whether it's signed, and N.
fn integer_type(base: &str) -> Option<(bool, u32)> {
    let (signed, bits) = match base.strip_prefix("uint") {
        Some(bits) => (false, bits),
        None => (true, base.strip_prefix("int")?),
    };
    if bits.starts_with('0') || !bits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u32 = bits.parse().ok()?;
    (n % 8 == 0 && (8..=256).contains(&n)).then_some((signed, n))
}

/// `bytesN`, N from 1 to 32: N.
fn fixed_bytes_type(base: &str) -> Option<usize> {
    let n = base.strip_prefix("bytes")?;
    if n.starts_with('0') || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: usize = n.parse().ok()?;
    (1..=32).contains(&n).then_some(n)
}

fn atomic(base: &str) -> bool {
    matches!(base, "address" | "bool" | "string" | "bytes") || integer_type(base).is_some() || fixed_bytes_type(base).is_some()
}

/// A hex string's bytes: `0x` and an even number of digits.
pub fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let digits = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    if digits.len() % 2 != 0 {
        return None;
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(digits.get(i..i + 2)?, 16).ok())
        .collect()
}

/// A 256-bit number, big-endian, from decimal digits.
fn decimal_word(digits: &str) -> Option<[u8; 32]> {
    let mut n = [0u8; 32];
    for d in digits.bytes() {
        let d = (d as char).to_digit(10)?;
        // n = n * 10 + d
        let mut carry = d;
        for byte in n.iter_mut().rev() {
            let v = (*byte as u32) * 10 + carry;
            *byte = v as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return None;
        }
    }
    Some(n)
}

/// A 256-bit number, big-endian, from hex digits (after `0x`).
fn hex_word(digits: &str) -> Option<[u8; 32]> {
    let digits = digits.trim_start_matches('0');
    if digits.len() > 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut padded = [b'0'; 64];
    padded[64 - digits.len()..].copy_from_slice(digits.as_bytes());
    let mut n = [0u8; 32];
    for (i, byte) in n.iter_mut().enumerate() {
        *byte = u8::from_str_radix(core::str::from_utf8(&padded[i * 2..i * 2 + 2]).ok()?, 16).ok()?;
    }
    Some(n)
}

/// An integer value: its sign, and its magnitude as a 256-bit number.
fn integer_value(v: &Value) -> Option<(bool, [u8; 32])> {
    let text = match v {
        Value::Number(n) => n.as_str(),
        Value::String(s) => s.as_str(),
        _ => return None,
    };
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    if digits.is_empty() {
        return None;
    }
    let magnitude = match digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        Some(hex) if !hex.is_empty() => hex_word(hex)?,
        Some(_) => return None,
        None => decimal_word(digits)?,
    };
    // -0 is 0
    Some((negative && magnitude != [0; 32], magnitude))
}

/// Whether `n` is less than 2^bits.
fn fits(n: &[u8; 32], bits: u32) -> bool {
    let bytes = (bits / 8) as usize;
    n[..32 - bytes].iter().all(|&b| b == 0)
}

/// -n, in two's complement.
fn negate(n: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 1u16;
    for i in (0..32).rev() {
        let v = (!n[i]) as u16 + carry;
        out[i] = v as u8;
        carry = v >> 8;
    }
    out
}

impl TypedData {
    /// Typed data from a site's JSON, checked all the way through.
    pub fn parse(text: &str) -> Result<TypedData, Error> {
        if text.len() > MAX_TYPED {
            return shape(format!("more than {} bytes", MAX_TYPED));
        }
        let root = json::parse(text)?;
        let Some(top) = root.as_object() else { return shape("not a JSON object".into()) };
        if let Some((k, _)) = top.iter().find(|(k, _)| !matches!(k.as_str(), "types" | "primaryType" | "domain" | "message")) {
            return shape(format!("\"{}\" isn't part of typed data", k));
        }
        let Some(types_value) = root.get("types").and_then(Value::as_object) else {
            return shape("no types".into());
        };
        if types_value.len() > MAX_TYPES {
            return shape("too many types".into());
        }
        let mut types: Vec<(String, Vec<Field>)> = Vec::new();
        let mut field_count = 0;
        for (name, fields) in types_value {
            if !identifier(name) || atomic(name) {
                return shape(format!("\"{}\" isn't a type name", name));
            }
            let Some(fields) = fields.as_array() else { return shape(format!("{}: not a list of fields", name)) };
            let mut list: Vec<Field> = Vec::new();
            for f in fields {
                let (Some(obj), Some(fname), Some(fty)) =
                    (f.as_object(), f.get("name").and_then(Value::as_str), f.get("type").and_then(Value::as_str))
                else {
                    return shape(format!("{}: a field without a name and a type", name));
                };
                if obj.len() != 2 {
                    return shape(format!("{}.{}: more than a name and a type", name, fname));
                }
                if !identifier(fname) {
                    return shape(format!("{}: \"{}\" isn't a field name", name, fname));
                }
                if list.iter().any(|x| x.name == fname) {
                    return shape(format!("{}.{}: declared twice", name, fname));
                }
                list.push(Field { name: fname.into(), ty: fty.into() });
            }
            field_count += list.len();
            if field_count > MAX_FIELDS {
                return shape("too many fields".into());
            }
            types.push((name.clone(), list));
        }
        let td = TypedData {
            types,
            primary_type: match root.get("primaryType").and_then(Value::as_str) {
                Some(p) => p.into(),
                None => return shape("no primaryType".into()),
            },
            domain: match root.get("domain") {
                Some(d @ Value::Object(_)) => d.clone(),
                _ => return shape("no domain".into()),
            },
            message: match root.get("message") {
                Some(m @ Value::Object(_)) => m.clone(),
                _ => return shape("no message".into()),
            },
        };
        // every field's type exists
        for (name, fields) in &td.types {
            for f in fields {
                let Some((base, _)) = split_type(&f.ty) else { return shape(format!("{}.{}: \"{}\" isn't a type", name, f.name, f.ty)) };
                if !atomic(base) && td.fields(base).is_none() {
                    return shape(format!("{}.{}: no type \"{}\"", name, f.name, base));
                }
            }
        }
        // no type refers to itself, however indirectly: EIP-712 leaves it open, and wallets
        // differ (alloy and ethers refuse, MetaMask takes it)
        for (name, _) in &td.types {
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            let mut todo: Vec<&str> = alloc::vec![name.as_str()];
            while let Some(t) = todo.pop() {
                for f in td.fields(t).unwrap_or(&[]) {
                    let base = split_type(&f.ty).map(|(b, _)| b).unwrap_or("");
                    if td.fields(base).is_none() {
                        continue;
                    }
                    if base == name {
                        return shape(format!("{} refers to itself", name));
                    }
                    if seen.insert(base) {
                        todo.push(base);
                    }
                }
            }
        }
        // the domain as EIP-712 defines it
        let Some(domain_fields) = td.fields("EIP712Domain") else { return shape("types has no EIP712Domain".into()) };
        let mut last = None;
        for f in domain_fields {
            let Some(at) = DOMAIN_FIELDS.iter().position(|(n, _)| *n == f.name) else {
                return shape(format!("EIP712Domain.{} isn't a domain field", f.name));
            };
            if DOMAIN_FIELDS[at].1 != f.ty {
                return shape(format!("EIP712Domain.{} should be {}", f.name, DOMAIN_FIELDS[at].1));
            }
            if last.is_some_and(|l| at <= l) {
                return shape("EIP712Domain's fields out of order".into());
            }
            last = Some(at);
        }
        if td.primary_type == "EIP712Domain" || td.fields(&td.primary_type).is_none() {
            return shape(format!("no type \"{}\" to sign", td.primary_type));
        }
        // and the values are what the types say: hashing checks every one
        td.signing_hash()?;
        Ok(td)
    }

    /// A struct type's fields.
    pub fn fields(&self, ty: &str) -> Option<&[Field]> { self.types.iter().find(|(n, _)| n == ty).map(|(_, f)| f.as_slice()) }

    /// EIP-712's `encodeType`: the type, then the struct types it refers to (however deep),
    /// sorted by name.
    pub fn encode_type(&self, ty: &str) -> Result<String, Error> {
        let mut found: BTreeSet<String> = BTreeSet::new();
        let mut todo: Vec<String> = alloc::vec![ty.into()];
        while let Some(t) = todo.pop() {
            let Some(fields) = self.fields(&t) else { return shape(format!("no type \"{}\"", t)) };
            for f in fields {
                let (base, _) = split_type(&f.ty).ok_or_else(|| Error::Shape(format!("\"{}\" isn't a type", f.ty)))?;
                if self.fields(base).is_some() && base != ty && found.insert(base.into()) {
                    todo.push(base.into());
                }
            }
        }
        let mut out = String::new();
        for t in core::iter::once(ty).chain(found.iter().map(String::as_str)) {
            out.push_str(t);
            out.push('(');
            let fields = self.fields(t).unwrap();
            for (i, f) in fields.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&f.ty);
                out.push(' ');
                out.push_str(&f.name);
            }
            out.push(')');
        }
        Ok(out)
    }

    pub fn type_hash(&self, ty: &str) -> Result<[u8; 32], Error> { Ok(keccak256(self.encode_type(ty)?.as_bytes())) }

    /// EIP-712's `hashStruct`: the type's hash, then each field's value encoded.
    pub fn hash_struct(&self, ty: &str, value: &Value) -> Result<[u8; 32], Error> {
        let fields = self.fields(ty).ok_or_else(|| Error::Shape(format!("no type \"{}\"", ty)))?;
        let Some(given) = value.as_object() else { return shape(format!("{}: not an object", ty)) };
        if let Some((k, _)) = given.iter().find(|(k, _)| !fields.iter().any(|f| f.name == *k)) {
            return shape(format!("{}.{}: not declared, so it wouldn't be signed", ty, k));
        }
        let mut data = Vec::with_capacity(32 * (fields.len() + 1));
        data.extend_from_slice(&self.type_hash(ty)?);
        for f in fields {
            let word = match value.get(&f.name) {
                Some(v) => self.encode_value(&f.ty, v).map_err(|e| match e {
                    Error::Shape(what) => Error::Shape(format!("{}.{}: {}", ty, f.name, what)),
                    e => e,
                })?,
                // a struct left out hashes to zero, as v4 has it; anything else must be there
                None if self.fields(&f.ty).is_some() => [0u8; 32],
                None => return shape(format!("{}.{}: missing", ty, f.name)),
            };
            data.extend_from_slice(&word);
        }
        Ok(keccak256(&data))
    }

    /// One value, as EIP-712 encodes it: 32 bytes.
    fn encode_value(&self, ty: &str, v: &Value) -> Result<[u8; 32], Error> {
        let (base, dims) = split_type(ty).ok_or_else(|| Error::Shape(format!("\"{}\" isn't a type", ty)))?;
        if let Some(&len) = dims.last() {
            let Some(items) = v.as_array() else { return shape("not a list".into()) };
            if len.is_some_and(|n| n != items.len()) {
                return shape(format!("{} items, not {}", items.len(), len.unwrap()));
            }
            let inner = &ty[..ty.rfind('[').unwrap()];
            let mut data = Vec::with_capacity(32 * items.len());
            for item in items {
                data.extend_from_slice(&self.encode_value(inner, item)?);
            }
            return Ok(keccak256(&data));
        }
        if self.fields(base).is_some() {
            return match v {
                Value::Null => Ok([0u8; 32]),
                _ => self.hash_struct(base, v),
            };
        }
        let mut word = [0u8; 32];
        match base {
            "string" => {
                let Some(s) = v.as_str() else { return shape("not a string".into()) };
                word = keccak256(s.as_bytes());
            }
            "bytes" => {
                let Some(b) = v.as_str().and_then(hex_bytes) else { return shape("not hex".into()) };
                word = keccak256(&b);
            }
            "bool" => match v {
                Value::Bool(b) => word[31] = *b as u8,
                _ => return shape("not true or false".into()),
            },
            "address" => match v.as_str().and_then(hex_bytes) {
                Some(b) if b.len() == 20 => word[12..].copy_from_slice(&b),
                _ => return shape("not an address".into()),
            },
            _ => {
                if let Some(n) = fixed_bytes_type(base) {
                    match v.as_str().and_then(hex_bytes) {
                        Some(b) if b.len() == n => word[..n].copy_from_slice(&b),
                        _ => return shape(format!("not {} bytes of hex", n)),
                    }
                } else if let Some((signed, bits)) = integer_type(base) {
                    let Some((negative, magnitude)) = integer_value(v) else { return shape("not a whole number".into()) };
                    word = if !signed {
                        if negative || !fits(&magnitude, bits) {
                            return shape(format!("out of range for {}", base));
                        }
                        magnitude
                    } else {
                        // up to 2^(bits-1) - 1, or down to -2^(bits-1)
                        let limit = {
                            let mut l = [0u8; 32];
                            let bit = bits - 1;
                            l[31 - (bit / 8) as usize] = 1 << (bit % 8);
                            l
                        };
                        let ok = if negative { magnitude <= limit } else { magnitude < limit };
                        if !ok {
                            return shape(format!("out of range for {}", base));
                        }
                        if negative {
                            negate(&magnitude)
                        } else {
                            magnitude
                        }
                    };
                } else {
                    return shape(format!("\"{}\" isn't a type", base));
                }
            }
        }
        Ok(word)
    }

    pub fn domain_separator(&self) -> Result<[u8; 32], Error> { self.hash_struct("EIP712Domain", &self.domain) }

    /// What's signed: `keccak256(0x19 0x01 || domain separator || hashStruct(message))`.
    pub fn signing_hash(&self) -> Result<[u8; 32], Error> {
        let mut data = Vec::with_capacity(66);
        data.extend_from_slice(&[0x19, 0x01]);
        data.extend_from_slice(&self.domain_separator()?);
        data.extend_from_slice(&self.hash_struct(&self.primary_type, &self.message)?);
        Ok(keccak256(&data))
    }

    /// The domain's chain ID, if it names one that fits in 64 bits.
    pub fn chain_id(&self) -> Option<u64> {
        let (negative, n) = integer_value(self.domain.get("chainId")?)?;
        (!negative && fits(&n, 64)).then(|| u64::from_be_bytes(n[24..].try_into().unwrap()))
    }
}

impl Account {
    /// Typed data (EIP-712), signed: r, s and v (27 or 28), 65 bytes.
    pub fn sign_typed(&self, typed: &TypedData) -> Result<[u8; 65], Error> {
        let digest = typed.signing_hash()?;
        let (r, s, v) = self.sign(&digest).map_err(|_| Error::Key)?;
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&r);
        out[32..64].copy_from_slice(&s);
        out[64] = 27 + v;
        Ok(out)
    }
}

/// An integer field's value for the screen, in decimal (negative with a minus).
pub fn integer_text(v: &Value) -> Option<String> {
    let (negative, n) = integer_value(v)?;
    let digits = crate::display::decimal(&n);
    Some(if negative { format!("-{}", digits) } else { digits })
}

/// An integer field's value, if it fits in 64 bits and isn't negative.
pub fn integer_u64(v: &Value) -> Option<u64> {
    let (negative, n) = integer_value(v)?;
    (!negative && fits(&n, 64)).then(|| u64::from_be_bytes(n[24..].try_into().unwrap()))
}

/// Whether an integer field's value is 2^bits - 1: "any amount", as permits use it.
pub fn is_max(v: &Value, bits: u32) -> bool {
    let Some((false, n)) = integer_value(v) else { return false };
    let bytes = (bits / 8) as usize;
    n[..32 - bytes].iter().all(|&b| b == 0) && n[32 - bytes..].iter().all(|&b| b == 0xff)
}
