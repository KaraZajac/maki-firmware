//! Borsh, as nearcore reads it: numbers little-endian at their full width, a string or a list as a
//! u32 count and then its items, an option or an enum as a byte that says which and then what it
//! holds. Borsh has one way of writing each value, so bytes that read are bytes nearcore reads the
//! same; anything cut short, a string that isn't UTF-8, or a tag there isn't, doesn't read.

use alloc::string::String;
use alloc::vec::Vec;

use crate::tx::Error;

pub(crate) struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Reader<'a> { Reader { b, at: 0 } }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len()).ok_or(Error::Length)?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// `n` bytes, where their length is fixed rather than written.
    pub(crate) fn vec(&mut self, n: usize) -> Result<Vec<u8>, Error> { Ok(self.take(n)?.to_vec()) }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> { Ok(self.take(1)?[0]) }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> { Ok(u32::from_le_bytes(self.array()?)) }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> { Ok(u64::from_le_bytes(self.array()?)) }

    pub(crate) fn u128(&mut self) -> Result<u128, Error> { Ok(u128::from_le_bytes(self.array()?)) }

    /// A list's count: what's left must hold at least `each` bytes for every item, so a count
    /// written to make maki loop or allocate past the transaction is refused before it does.
    pub(crate) fn count(&mut self, each: usize) -> Result<usize, Error> {
        let n = self.u32()? as usize;
        if n.saturating_mul(each) > self.b.len() - self.at {
            return Err(Error::Length);
        }
        Ok(n)
    }

    /// Bytes (`Vec<u8>`): their count, then them.
    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>, Error> {
        let n = self.count(1)?;
        Ok(self.take(n)?.to_vec())
    }

    /// A string: its length in bytes, then them, which must be UTF-8.
    pub(crate) fn string(&mut self) -> Result<String, Error> {
        let n = self.count(1)?;
        let s = core::str::from_utf8(self.take(n)?).map_err(|_| Error::Encoding)?;
        Ok(String::from(s))
    }

    /// An option's tag: whether what it holds follows.
    pub(crate) fn some(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Encoding),
        }
    }

    /// Whether every byte has been read.
    pub(crate) fn done(&self) -> bool { self.at == self.b.len() }
}
