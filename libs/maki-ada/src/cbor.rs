//! CBOR as Cardano's hardware wallets take a transaction (CIP-21, after RFC 7049's canonical form):
//! every number and length in its shortest form, every length stated (nothing indefinite), each
//! map's keys in order. And nothing but numbers, bytes, arrays, maps and tags: no text, no floats,
//! no simple values, which nothing in a body maki signs has. Then each thing is written one way
//! alone: the body maki shows is the body the node reads, and the one Ledger's and Trezor's
//! Cardano apps would sign. (The node itself takes more ways of writing things, which is why a
//! hardware wallet can't.)

use crate::Error;

/// CBOR's major types: what an item is.
pub(crate) const UINT: u8 = 0;
pub(crate) const NINT: u8 = 1;
pub(crate) const BYTES: u8 = 2;
pub(crate) const ARRAY: u8 = 4;
pub(crate) const MAP: u8 = 5;
pub(crate) const TAG: u8 = 6;

/// The tag a set may carry since Conway: an array that holds each member once.
pub(crate) const SET: u64 = 258;
/// The tag of CBOR inside bytes: a datum, a script.
pub(crate) const EMBEDDED: u64 = 24;

/// Items read one after another from bytes, each held to its canonical form.
pub(crate) struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Reader<'a> { Reader { b, at: 0 } }

    /// Where the next item starts.
    pub(crate) fn at(&self) -> usize { self.at }

    /// The bytes from `start` to here: an item just read, as it's written.
    pub(crate) fn since(&self, start: usize) -> &'a [u8] { &self.b[start..self.at] }

    /// How many bytes are left: no count can be more, each item taking one at least.
    fn left(&self) -> usize { self.b.len() - self.at }

    /// The end: nothing after what's been read.
    pub(crate) fn end(&self) -> Result<(), Error> {
        if self.at == self.b.len() { Ok(()) } else { Err(Error::Encoding) }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len()).ok_or(Error::Encoding)?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8, Error> { Ok(self.take(1)?[0]) }

    /// What the next item is, without reading it: its major type.
    pub(crate) fn peek(&self) -> Option<u8> { self.b.get(self.at).map(|b| b >> 5) }

    /// The next item's head: its major type, and its number (a value, a length, a tag) in its
    /// shortest form. An indefinite length and the reserved forms aren't taken.
    fn head(&mut self) -> Result<(u8, u64), Error> {
        let b = self.byte()?;
        let (major, info) = (b >> 5, b & 0x1f);
        let n = match info {
            0..=23 => info as u64,
            24 => self.byte()? as u64,
            25 => u16::from_be_bytes([self.byte()?, self.byte()?]) as u64,
            26 => {
                let mut n = [0u8; 4];
                n.copy_from_slice(self.take(4)?);
                u32::from_be_bytes(n) as u64
            }
            27 => {
                let mut n = [0u8; 8];
                n.copy_from_slice(self.take(8)?);
                u64::from_be_bytes(n)
            }
            _ => return Err(Error::Encoding),
        };
        // a longer form than the number needs is another way of writing it
        let shortest = match info {
            24 => n >= 24,
            25 => n > 0xff,
            26 => n > 0xffff,
            27 => n > 0xffff_ffff,
            _ => true,
        };
        if !shortest {
            return Err(Error::Encoding);
        }
        Ok((major, n))
    }

    /// An item of type `major`, its number.
    fn expect(&mut self, major: u8) -> Result<u64, Error> {
        match self.head()? {
            (m, n) if m == major => Ok(n),
            _ => Err(Error::Shape),
        }
    }

    /// An unsigned number.
    pub(crate) fn uint(&mut self) -> Result<u64, Error> { self.expect(UINT) }

    /// A number that fits 64 bits, signed (CDDL's `int64`): unsigned, or negative.
    pub(crate) fn int64(&mut self) -> Result<i64, Error> {
        match self.head()? {
            (UINT, n) => i64::try_from(n).map_err(|_| Error::Shape),
            // -1 - n
            (NINT, n) => i64::try_from(n).map(|n| -1 - n).map_err(|_| Error::Shape),
            _ => Err(Error::Shape),
        }
    }

    /// Bytes.
    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = self.expect(BYTES)?;
        let n = usize::try_from(n).map_err(|_| Error::Encoding)?;
        self.take(n)
    }

    /// Exactly `N` bytes: a hash.
    pub(crate) fn hash<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.bytes()?.try_into().map_err(|_| Error::Shape)
    }

    /// An array's length.
    pub(crate) fn array(&mut self) -> Result<usize, Error> {
        let n = self.expect(ARRAY)?;
        self.count(n, 1)
    }

    /// A map's length: how many keys it has.
    pub(crate) fn map(&mut self) -> Result<usize, Error> {
        let n = self.expect(MAP)?;
        self.count(n, 2)
    }

    /// A count of things each at least `each` bytes long: no more than are left.
    fn count(&self, n: u64, each: usize) -> Result<usize, Error> {
        usize::try_from(n).ok().filter(|&n| n <= self.left() / each).ok_or(Error::Encoding)
    }

    /// A tag.
    pub(crate) fn tag(&mut self) -> Result<u64, Error> { self.expect(TAG) }

    /// A set's length (Conway's `set`, `nonempty_set` and `nonempty_oset`): an array, tagged 258
    /// or not. CIP-21 has a transaction tag all its sets or none: the first decides (`tagged`),
    /// and a set the other way is refused.
    pub(crate) fn set(&mut self, tagged: &mut Option<bool>) -> Result<usize, Error> {
        let this = self.peek() == Some(TAG);
        if this && self.tag()? != SET {
            return Err(Error::Shape);
        }
        match *tagged {
            Some(t) if t != this => {
                return Err(Error::Invalid(
                    "sets written two ways, with Cardano's set tag and without: CIP-21 has a transaction write them one way",
                ));
            }
            _ => *tagged = Some(this),
        }
        self.array()
    }
}

/// Map keys, each after the last in CIP-21's order (RFC 7049's canonical one: a shorter key first,
/// then byte by byte, as they're written); one the same as the last is given twice.
pub(crate) struct Keys<'a> {
    last: Option<&'a [u8]>,
}

impl<'a> Keys<'a> {
    pub(crate) fn new() -> Keys<'a> { Keys { last: None } }

    /// The next key, as it's written.
    pub(crate) fn next(&mut self, key: &'a [u8]) -> Result<(), Error> {
        if let Some(last) = self.last {
            match (key.len(), key).cmp(&(last.len(), last)) {
                core::cmp::Ordering::Equal => return Err(Error::Duplicate),
                core::cmp::Ordering::Less => return Err(Error::Encoding),
                core::cmp::Ordering::Greater => {}
            }
        }
        self.last = Some(key);
        Ok(())
    }
}
