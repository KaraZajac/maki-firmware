//! RLP, strictly: every length in its shortest form and single bytes below 0x80 as themselves,
//! so there's one encoding per value and what maki shows is exactly what it signs.

use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item<'a> {
    Bytes(&'a [u8]),
    List(Vec<Item<'a>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub &'static str);

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { f.write_str(self.0) }
}

const MAX_DEPTH: u32 = 8;

/// A length in big-endian bytes, which must not start with zero and must be more than 55.
fn long_length(b: &[u8]) -> Result<usize, Error> {
    if b.is_empty() || b.len() > 4 || b[0] == 0 {
        return Err(Error("length not minimal"));
    }
    let n = b.iter().fold(0usize, |n, &x| (n << 8) | x as usize);
    if n <= 55 {
        return Err(Error("length not minimal"));
    }
    Ok(n)
}

/// One item from the start of `b`, and how many bytes it took.
fn item(b: &[u8], depth: u32) -> Result<(Item<'_>, usize), Error> {
    let first = *b.first().ok_or(Error("ends early"))?;
    let (header, len, list) = match first {
        0x00..=0x7f => return Ok((Item::Bytes(&b[..1]), 1)),
        0x80..=0xb7 => (1, (first - 0x80) as usize, false),
        0xb8..=0xbf => {
            let n = (first - 0xb7) as usize;
            (1 + n, long_length(b.get(1..1 + n).ok_or(Error("ends early"))?)?, false)
        }
        0xc0..=0xf7 => (1, (first - 0xc0) as usize, true),
        _ => {
            let n = (first - 0xf7) as usize;
            (1 + n, long_length(b.get(1..1 + n).ok_or(Error("ends early"))?)?, true)
        }
    };
    let payload = b.get(header..header.checked_add(len).ok_or(Error("too long"))?).ok_or(Error("ends early"))?;
    if !list {
        if len == 1 && payload[0] < 0x80 {
            return Err(Error("single byte not encoded as itself"));
        }
        return Ok((Item::Bytes(payload), header + len));
    }
    if depth >= MAX_DEPTH {
        return Err(Error("nested too deep"));
    }
    let mut items = Vec::new();
    let mut at = 0;
    while at < payload.len() {
        let (i, n) = item(&payload[at..], depth + 1)?;
        items.push(i);
        at += n;
    }
    Ok((Item::List(items), header + len))
}

/// The one item `b` holds, all of it.
pub fn decode(b: &[u8]) -> Result<Item<'_>, Error> {
    let (i, n) = item(b, 0)?;
    if n != b.len() {
        return Err(Error("bytes after the end"));
    }
    Ok(i)
}

fn header(out: &mut Vec<u8>, len: usize, short: u8) {
    if len <= 55 {
        out.push(short + len as u8);
    } else {
        let bytes = (len as u64).to_be_bytes();
        let skip = bytes.iter().take_while(|&&x| x == 0).count();
        out.push(short + 55 + (8 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

pub fn encode_bytes(out: &mut Vec<u8>, b: &[u8]) {
    if b.len() == 1 && b[0] < 0x80 {
        out.push(b[0]);
    } else {
        header(out, b.len(), 0x80);
        out.extend_from_slice(b);
    }
}

/// An unsigned integer: big-endian, no leading zeros (zero is empty).
pub fn encode_uint(out: &mut Vec<u8>, n: &[u8]) {
    let skip = n.iter().take_while(|&&x| x == 0).count();
    encode_bytes(out, &n[skip..]);
}

/// A list around `payload`, the items already encoded.
pub fn encode_list(out: &mut Vec<u8>, payload: &[u8]) {
    header(out, payload.len(), 0xc0);
    out.extend_from_slice(payload);
}

impl<'a> Item<'a> {
    pub fn bytes(&self) -> Result<&'a [u8], Error> {
        match self {
            Item::Bytes(b) => Ok(b),
            Item::List(_) => Err(Error("a list where bytes belong")),
        }
    }

    pub fn list(&self) -> Result<&[Item<'a>], Error> {
        match self {
            Item::List(l) => Ok(l),
            Item::Bytes(_) => Err(Error("bytes where a list belongs")),
        }
    }

    /// An unsigned integer of at most `max` bytes, without leading zeros.
    fn uint(&self, max: usize) -> Result<u128, Error> {
        let b = self.bytes()?;
        if b.len() > max {
            return Err(Error("number too big"));
        }
        if b.first() == Some(&0) {
            return Err(Error("number with a leading zero"));
        }
        Ok(b.iter().fold(0u128, |n, &x| (n << 8) | x as u128))
    }

    pub fn u64(&self) -> Result<u64, Error> { self.uint(8).map(|n| n as u64) }

    /// Amounts in wei: up to 16 bytes, more than all the ether there is.
    pub fn u128(&self) -> Result<u128, Error> { self.uint(16) }
}
