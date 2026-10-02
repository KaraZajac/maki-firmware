//! Protocol Buffers as Tron's own software writes them (java-tron, and TronWeb with Google's
//! library): each field once, in the order of its number (a repeated field's entries together),
//! nothing at its default (zero, false, empty), every number in its shortest form. java-tron makes
//! a transaction's ID from `raw_data` as it writes it again, so a transaction written any other way
//! can't have the ID maki would sign. The contract inside it, which java-tron hashes as it comes and
//! reads more loosely, maki holds to the same form: then what maki reads is what java-tron reads,
//! with no second way of writing anything for the two to read differently.

use alloc::vec::Vec;

/// The highest field number Protocol Buffers allows.
const MAX_FIELD: u64 = (1 << 29) - 1;

/// What a field holds: a number (wire type 0), or bytes (wire type 2: bytes, a string, a message).
#[derive(Debug, Clone, Copy)]
enum Value<'a> {
    Number(u64),
    Bytes(&'a [u8]),
}

/// Why a message isn't one maki reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    /// Cut short, or not written as Tron writes it.
    Encoding,
    /// A field maki doesn't know, or one of another kind than it should be.
    Unknown,
    /// A field given twice.
    Duplicate,
}

/// A varint: seven bits a byte, the least significant first, ten bytes at most for 64 bits, and in
/// its shortest form (no last byte of zero, but for zero itself).
fn varint(b: &[u8], at: &mut usize) -> Result<u64, Error> {
    let mut n = 0u64;
    for i in 0..10 {
        let byte = *b.get(*at).ok_or(Error::Encoding)?;
        *at += 1;
        // the tenth byte has room for 64's last bit alone
        if i == 9 && byte > 1 {
            return Err(Error::Encoding);
        }
        n |= ((byte & 0x7f) as u64) << (7 * i);
        if byte & 0x80 == 0 {
            // a zero after the first byte is a longer way of writing a smaller number
            return if byte == 0 && i > 0 { Err(Error::Encoding) } else { Ok(n) };
        }
    }
    Err(Error::Encoding)
}

/// A message's fields, each taken in the order of its number, as its schema has them.
pub(crate) struct Fields<'a> {
    fields: Vec<(u32, Value<'a>)>,
    next: usize,
}

impl<'a> Fields<'a> {
    /// The fields of `b`, all of it, in order.
    pub(crate) fn read(b: &'a [u8]) -> Result<Fields<'a>, Error> {
        let mut fields = Vec::new();
        let (mut at, mut last) = (0, 0);
        while at < b.len() {
            let key = varint(b, &mut at)?;
            let (number, wire) = (key >> 3, key & 7);
            if number == 0 || number > MAX_FIELD {
                return Err(Error::Encoding);
            }
            // in order, a repeated field's entries together
            if number < last {
                return Err(Error::Encoding);
            }
            let value = match wire {
                0 => Value::Number(varint(b, &mut at)?),
                2 => {
                    let n = varint(b, &mut at)?;
                    let end =
                        (at as u64).checked_add(n).filter(|&e| e <= b.len() as u64).ok_or(Error::Encoding)?
                            as usize;
                    let v = &b[at..end];
                    at = end;
                    Value::Bytes(v)
                }
                // fixed-size numbers and groups: no field of a transaction's is one
                _ => return Err(Error::Unknown),
            };
            fields.push((number as u32, value));
            last = number;
        }
        Ok(Fields { fields, next: 0 })
    }

    /// The next field, if it's `number`. One before it is a field this message doesn't have.
    fn take(&mut self, number: u32) -> Result<Option<Value<'a>>, Error> {
        match self.fields.get(self.next) {
            Some(&(n, _)) if n < number => Err(Error::Unknown),
            Some(&(n, v)) if n == number => {
                self.next += 1;
                Ok(Some(v))
            }
            _ => Ok(None),
        }
    }

    /// A field that's there once at most.
    fn once(&mut self, number: u32) -> Result<Option<Value<'a>>, Error> {
        let v = self.take(number)?;
        if v.is_some() && matches!(self.fields.get(self.next), Some(&(n, _)) if n == number) {
            return Err(Error::Duplicate);
        }
        Ok(v)
    }

    /// A number (an int64's or an enum's bits): 0 when it isn't there, as proto3 has it. Written
    /// out as 0, it isn't as Tron writes it.
    pub(crate) fn number(&mut self, number: u32) -> Result<u64, Error> {
        match self.once(number)? {
            None => Ok(0),
            Some(Value::Number(0)) => Err(Error::Encoding),
            Some(Value::Number(n)) => Ok(n),
            Some(Value::Bytes(_)) => Err(Error::Unknown),
        }
    }

    /// An int64: a negative one is its two's complement, ten bytes.
    pub(crate) fn int64(&mut self, number: u32) -> Result<i64, Error> { Ok(self.number(number)? as i64) }

    /// An int32 (an enum, a permission's ID), written as the int64 it's the same as. Any other
    /// number java-tron would cut to its low 32 bits, and write again as another.
    pub(crate) fn int32(&mut self, number: u32) -> Result<i32, Error> {
        i32::try_from(self.number(number)? as i64).map_err(|_| Error::Encoding)
    }

    /// A bool: there only when it's true, as 1.
    pub(crate) fn bool(&mut self, number: u32) -> Result<bool, Error> {
        match self.number(number)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Encoding),
        }
    }

    /// Bytes, or a string's: empty when they aren't there. Written out empty, they aren't as Tron
    /// writes them.
    pub(crate) fn bytes(&mut self, number: u32) -> Result<&'a [u8], Error> {
        match self.once(number)? {
            None => Ok(&[]),
            Some(Value::Bytes([])) => Err(Error::Encoding),
            Some(Value::Bytes(b)) => Ok(b),
            Some(Value::Number(_)) => Err(Error::Unknown),
        }
    }

    /// A message: None when it isn't there. One that's there may be empty.
    pub(crate) fn message(&mut self, number: u32) -> Result<Option<&'a [u8]>, Error> {
        match self.once(number)? {
            None => Ok(None),
            Some(Value::Bytes(b)) => Ok(Some(b)),
            Some(Value::Number(_)) => Err(Error::Unknown),
        }
    }

    /// A repeated message's entries, all of them.
    pub(crate) fn messages(&mut self, number: u32) -> Result<Vec<&'a [u8]>, Error> {
        let mut out = Vec::new();
        while let Some(v) = self.take(number)? {
            match v {
                Value::Bytes(b) => out.push(b),
                Value::Number(_) => return Err(Error::Unknown),
            }
        }
        Ok(out)
    }

    /// The end of the message: every field taken, none left that it doesn't have.
    pub(crate) fn end(self) -> Result<(), Error> {
        if self.next < self.fields.len() { Err(Error::Unknown) } else { Ok(()) }
    }
}
