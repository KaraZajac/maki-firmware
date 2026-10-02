//! BCS, the Binary Canonical Serialization Aptos writes its transactions in, read as Aptos's own
//! software reads it (the `bcs` crate): numbers little-endian and of their own width; lengths and
//! enums' variants in ULEB128, in its shortest form and no bigger than a u32; a bool or an option's
//! tag one byte of 0 or 1. Canonical means one way to write each thing, so what maki reads is
//! what Aptos reads.

/// Why bytes aren't BCS maki reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    /// Cut short.
    Length,
    /// Not in BCS's one way of writing it.
    Encoding,
}

/// BCS bytes, read from the start.
pub(crate) struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Reader<'a> { Reader { b, at: 0 } }

    /// The next `n` bytes.
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len()).ok_or(Error::Length)?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    /// The next `N` bytes, as an array.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> { Ok(self.take(1)?[0]) }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> { Ok(u64::from_le_bytes(self.array()?)) }

    /// A ULEB128: seven bits a byte, the least significant first, at most five bytes, its last not
    /// zero (but for zero itself), and no bigger than a u32, as `bcs` reads it.
    pub(crate) fn uleb(&mut self) -> Result<u32, Error> {
        let mut n = 0u64;
        for shift in (0..35).step_by(7) {
            let byte = self.u8()?;
            n |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                // a zero after the first byte is a longer way of writing a smaller number
                if byte == 0 && shift > 0 {
                    return Err(Error::Encoding);
                }
                return u32::try_from(n).map_err(|_| Error::Encoding);
            }
        }
        Err(Error::Encoding)
    }

    /// A sequence's length: a ULEB128, no more than what's left to read (each of its entries is a
    /// byte at least).
    pub(crate) fn len(&mut self) -> Result<usize, Error> {
        let n = self.uleb()? as usize;
        if n > self.left() {
            return Err(Error::Length);
        }
        Ok(n)
    }

    /// Bytes (a `vector<u8>`, or a string's): their length, then them.
    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = self.len()?;
        self.take(n)
    }

    /// A bool: 0 or 1.
    pub(crate) fn bool(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Encoding),
        }
    }

    /// Whether an option holds something: its tag, 0 or 1.
    pub(crate) fn some(&mut self) -> Result<bool, Error> { self.bool() }

    /// How many bytes are left.
    pub(crate) fn left(&self) -> usize { self.b.len() - self.at }

    /// The end: everything read, nothing after it.
    pub(crate) fn end(&self) -> Result<(), Error> {
        if self.left() == 0 { Ok(()) } else { Err(Error::Length) }
    }
}
