//! XDR (RFC 4506), as Stellar writes its transactions, read strictly: big-endian, everything in
//! four-byte units with its padding zero, every variable length within the bound Stellar's
//! definitions give it, a boolean or an option 0 or 1, and every enum and union only the values
//! Stellar has. stellar-core's XDR reader refuses the rest, so maki does.

use crate::transaction::Error;
use crate::{Hash, Key};

pub(crate) struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Reader<'a> { Reader { b, at: 0 } }

    /// Where the next byte is: for a part's bytes, as it was written.
    pub(crate) fn at(&self) -> usize { self.at }

    /// The bytes from `start` to here.
    pub(crate) fn since(&self, start: usize) -> &'a [u8] { &self.b[start..self.at] }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len()).ok_or(Error::Length)?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| Error::Length)?))
    }

    pub(crate) fn i32(&mut self) -> Result<i32, Error> { Ok(self.u32()? as i32) }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| Error::Length)?))
    }

    pub(crate) fn i64(&mut self) -> Result<i64, Error> { Ok(self.u64()? as i64) }

    /// A boolean, or whether an optional part is there: 0 or 1, nothing else.
    pub(crate) fn bool(&mut self) -> Result<bool, Error> {
        match self.u32()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Unknown),
        }
    }

    /// An enum, or a union's discriminant, whose values run from 0 to `last`.
    pub(crate) fn kind(&mut self, last: u32) -> Result<u32, Error> {
        let k = self.u32()?;
        if k > last {
            return Err(Error::Unknown);
        }
        Ok(k)
    }

    /// Fixed-length opaque data of `N` bytes, padded to four.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let a: [u8; N] = self.take(N)?.try_into().map_err(|_| Error::Length)?;
        self.padding(N)?;
        Ok(a)
    }

    /// 32 bytes: a key, or a hash.
    pub(crate) fn key(&mut self) -> Result<Key, Error> { self.array::<32>() }

    pub(crate) fn hash(&mut self) -> Result<Hash, Error> { self.array::<32>() }

    /// The zero bytes after `n` bytes of data, to a multiple of four.
    fn padding(&mut self, n: usize) -> Result<(), Error> {
        let pad = n.next_multiple_of(4) - n;
        if self.take(pad)?.iter().any(|&b| b != 0) {
            return Err(Error::Padding);
        }
        Ok(())
    }

    /// Variable-length opaque data, or a string: a length of at most `max`, the bytes, and the
    /// padding.
    pub(crate) fn opaque(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let n = self.length(max)?;
        let data = self.take(n)?;
        self.padding(n)?;
        Ok(data)
    }

    /// A length: at most `max`.
    pub(crate) fn length(&mut self, max: usize) -> Result<usize, Error> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(Error::TooLong);
        }
        Ok(n)
    }

    /// How many items a list has: at most `max`. Each item takes four bytes at least, so a count
    /// more than what's left could hold is cut short here, not item by item.
    pub(crate) fn count(&mut self, max: usize) -> Result<usize, Error> {
        let n = self.length(max)?;
        if n > (self.b.len() - self.at) / 4 {
            return Err(Error::Length);
        }
        Ok(n)
    }

    /// Nothing after it.
    pub(crate) fn done(&self) -> Result<(), Error> {
        if self.at != self.b.len() {
            return Err(Error::Length);
        }
        Ok(())
    }
}

/// No bound: what XDR writes as `<>`, a length that can be anything a u32 holds. The envelope
/// itself bounds it.
pub(crate) const UNBOUNDED: usize = u32::MAX as usize;
