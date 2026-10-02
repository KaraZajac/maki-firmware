//! BCS as Sui's validators read a transaction (the `bcs` crate's `from_bytes`): numbers
//! little-endian and of their full width; a sequence's length and an enum's variant as ULEB128 in
//! its shortest form, of 32 bits at most (a length less than 2^31); a bool 0 or 1, and an option's
//! tag the same; a string's bytes UTF-8; and nothing left over. Anything else isn't BCS, and
//! there's no second way of writing anything for maki and Sui to read differently.

use crate::tx::Error;

/// A transaction's bytes, read from the start.
pub(crate) struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Reader<'a> { Reader { b, at: 0 } }

    /// The next `n` bytes.
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len()).ok_or(Error::Encoding)?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> { Ok(self.take(1)?[0]) }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> { Ok(u16::from_le_bytes(self.array()?)) }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> { Ok(u32::from_le_bytes(self.array()?)) }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> { Ok(u64::from_le_bytes(self.array()?)) }

    /// 32 bytes: an address, or an object's ID.
    pub(crate) fn bytes32(&mut self) -> Result<[u8; 32], Error> { self.array() }

    /// ULEB128: seven bits a byte, the least significant first; five bytes at most, the value 32
    /// bits, and no last byte of zero but for zero itself.
    pub(crate) fn uleb128(&mut self) -> Result<u32, Error> {
        let mut n = 0u64;
        for shift in (0..32).step_by(7) {
            let byte = self.u8()?;
            n |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                // a zero after the first byte is a longer way of writing a smaller number
                if shift > 0 && byte == 0 {
                    return Err(Error::Encoding);
                }
                return u32::try_from(n).map_err(|_| Error::Encoding);
            }
        }
        Err(Error::Encoding)
    }

    /// An enum's variant.
    pub(crate) fn variant(&mut self) -> Result<u32, Error> { self.uleb128() }

    /// A sequence's length. Each of the elements a transaction has takes a byte at least, so a
    /// length past the bytes left is one that can't be.
    pub(crate) fn len(&mut self) -> Result<usize, Error> {
        let n = self.uleb128()?;
        if n >= 1 << 31 || n as usize > self.b.len() - self.at {
            return Err(Error::Encoding);
        }
        Ok(n as usize)
    }

    pub(crate) fn bool(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Encoding),
        }
    }

    /// Whether an option is there: its tag.
    pub(crate) fn some(&mut self) -> Result<bool, Error> { self.bool() }

    /// An option of a u64.
    pub(crate) fn option_u64(&mut self) -> Result<Option<u64>, Error> {
        if self.some()? { Ok(Some(self.u64()?)) } else { Ok(None) }
    }

    /// Bytes (a `vector<u8>`): their length, then them.
    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = self.len()?;
        self.take(n)
    }

    /// A string: bytes that are UTF-8.
    pub(crate) fn string(&mut self) -> Result<&'a str, Error> {
        core::str::from_utf8(self.bytes()?).map_err(|_| Error::Encoding)
    }

    /// A digest: 32 bytes, written as bytes are (with their length, which must be 32).
    pub(crate) fn digest(&mut self) -> Result<[u8; 32], Error> {
        self.bytes()?.try_into().map_err(|_| Error::Encoding)
    }

    /// The end: nothing may be left over.
    pub(crate) fn end(&self) -> Result<(), Error> {
        if self.at == self.b.len() { Ok(()) } else { Err(Error::Encoding) }
    }
}
