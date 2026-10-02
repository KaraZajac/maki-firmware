//! Cells, and the bags of cells (BOCs) they travel in, read as TON reads them (its node's
//! `BagOfCells::deserialize` and `DataCell`, and the TL-B of `serialized_boc`) and held to it.
//!
//! Everything on TON is cells: up to 1023 bits and up to four references to other cells, and each
//! named by its hash, SHA-256 of its bits and its references' depths and hashes. A BOC writes a
//! tree of them: a header, then each cell (two descriptor bytes, its bits a byte at a time with an
//! end mark after the last, and its references as indices of later cells), and a CRC32C. maki
//! reads the BOCs TON's libraries write: one root, first; no index; every cell reachable from
//! the root; library cells (which stand for code by its hash) and ordinary ones, and nothing that
//! stands for cells maki can't see (pruned branches, Merkle proofs).

use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::{Address, Error, Hash};

/// The biggest BOC maki reads: what one message over maki's link holds.
pub const MAX_BOC: usize = 4096;
/// TON's limits on a cell, and on how deeply cells nest.
pub const MAX_BITS: usize = 1023;
pub const MAX_REFS: usize = 4;
pub const MAX_DEPTH: u16 = 1024;

/// `serialized_boc#b5ee9c72`: the BOC TON's libraries write. (The older forms, with an index
/// always, maki doesn't take.)
const MAGIC: [u8; 4] = [0xb5, 0xee, 0x9c, 0x72];

/// A library cell's type, its first byte: it holds the hash of the code it stands for.
const LIBRARY: u8 = 2;

/// A cell, as a BOC holds it: its bits (the first in its first byte's top bit), its references
/// (indices of later cells), and its hash and depth. Kept small: a BOC maki reads can hold 2048.
#[derive(Debug, Clone)]
pub struct Cell<'a> {
    /// Its bits, a byte at a time; the last byte may hold the end mark after them.
    data: &'a [u8],
    bits: u16,
    refs: [u16; MAX_REFS],
    count: u8,
    /// A library cell (exotic, type 2): it stands for code by the code's hash.
    library: bool,
    depth: u16,
    hash: Hash,
}

impl Cell<'_> {
    /// Its hash: what names it.
    pub fn hash(&self) -> Hash { self.hash }

    /// How deep the cells under it go: 0 with no references.
    pub fn depth(&self) -> u16 { self.depth }

    /// How many bits it holds.
    pub fn bits(&self) -> usize { self.bits as usize }

    /// How many cells it refers to.
    pub fn refs(&self) -> usize { self.count as usize }

    /// The indices of the cells it refers to.
    fn to(&self) -> impl Iterator<Item = usize> + '_ {
        self.refs[..self.count as usize].iter().map(|&t| t as usize)
    }

    /// Whether it's a library cell, which stands for code by its hash.
    pub fn is_library(&self) -> bool { self.library }
}

/// A bag of cells, read whole: its cells, the root first.
#[derive(Debug, Clone)]
pub struct Boc<'a> {
    cells: Vec<Cell<'a>>,
}

/// Bytes read in order, big-endian, as a BOC's header is written.
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len()).ok_or(Error::Header)?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Error> { Ok(self.take(1)?[0]) }

    /// A number of `n` bytes (1 to 8).
    fn uint(&mut self, n: usize) -> Result<usize, Error> {
        let v = self.take(n)?.iter().fold(0u64, |v, &b| v << 8 | b as u64);
        usize::try_from(v).map_err(|_| Error::Header)
    }
}

/// CRC-32C (Castagnoli), as a BOC's checksum is: reflected, its polynomial 0x82f63b78.
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x82f6_3b78 } else { crc >> 1 };
        }
    }
    !crc
}

/// A cell's hash from its parts, as TON's `DataCell` computes it at level 0: its two descriptor
/// bytes, its bits with their end mark, and each reference's depth (two bytes) and then each one's
/// hash.
fn hash_parts(exotic: bool, data: &[u8], bits: usize, refs: &[(Hash, u16)]) -> Hash {
    let mut h = Sha256::new();
    let d1 = refs.len() as u8 + if exotic { 8 } else { 0 };
    let d2 = (bits / 8 * 2 + usize::from(!bits.is_multiple_of(8))) as u8;
    h.update([d1, d2]);
    h.update(&data[..bits / 8]);
    if !bits.is_multiple_of(8) {
        // the bits of the last byte, then the end mark, then zeros
        let used = bits % 8;
        let last = data[bits / 8] & (0xff << (8 - used)) | (0x80 >> used);
        h.update([last]);
    }
    for (_, depth) in refs {
        h.update(depth.to_be_bytes());
    }
    for (hash, _) in refs {
        h.update(hash);
    }
    h.finalize().into()
}

/// A cell's depth from its references': one more than the deepest, or 0.
fn depth_of(refs: &[(Hash, u16)]) -> Result<u16, Error> {
    match refs.iter().map(|r| r.1).max() {
        None => Ok(0),
        Some(d) if d < MAX_DEPTH => Ok(d + 1),
        Some(_) => Err(Error::Deep),
    }
}

impl<'a> Boc<'a> {
    /// A bag of cells, read whole and held to what TON's node accepts: and to what TON's
    /// libraries write (one root, first; no index; nothing nothing refers to), which maki asks for.
    pub fn parse(b: &'a [u8]) -> Result<Boc<'a>, Error> {
        if b.len() > MAX_BOC {
            return Err(Error::TooBig);
        }
        if b.get(..4) != Some(&MAGIC[..]) {
            return Err(Error::NotBoc);
        }
        let mut r = Reader { b, at: 4 };
        // has_idx:1 has_crc32c:1 has_cache_bits:1 flags:2 (zero) size:3 (1 to 4)
        let flags = r.u8()?;
        if flags & 0xa0 != 0 {
            return Err(Error::Index);
        }
        let size = (flags & 7) as usize;
        if flags & 0x18 != 0 || !(1..=4).contains(&size) {
            return Err(Error::Header);
        }
        let off = r.u8()? as usize;
        if !(1..=8).contains(&off) {
            return Err(Error::Header);
        }
        let (count, roots, absent, total) = (r.uint(size)?, r.uint(size)?, r.uint(size)?, r.uint(off)?);
        if roots != 1 {
            return Err(Error::Roots);
        }
        // absent cells are ones the BOC leaves out: TON's node doesn't read them either
        if absent != 0 || count == 0 {
            return Err(Error::Header);
        }
        let root = r.uint(size)?;
        if root >= count {
            return Err(Error::Header);
        }
        // the root first: a cell before it, nothing could refer to
        if root != 0 {
            return Err(Error::Unreached);
        }
        let end = if flags & 0x40 != 0 {
            let end = b.len().checked_sub(4).filter(|&e| e >= r.at).ok_or(Error::Header)?;
            let stored = u32::from_le_bytes([b[end], b[end + 1], b[end + 2], b[end + 3]]);
            if crc32c(&b[..end]) != stored {
                return Err(Error::Checksum);
            }
            end
        } else {
            b.len()
        };
        // the cells take exactly what the header says, and each takes two bytes at least
        if r.at.checked_add(total) != Some(end) || count > total / 2 {
            return Err(Error::Header);
        }
        let mut r = Reader { b: &b[..end], at: r.at };
        let mut cells = Vec::with_capacity(count);
        for i in 0..count {
            let (d1, d2) = (r.u8()?, r.u8()?);
            let refs = (d1 & 7) as usize;
            let exotic = d1 & 8 != 0;
            // more than four references (seven: an absent cell), its hashes stored with it
            if refs > MAX_REFS || d1 & 16 != 0 {
                return Err(Error::Encoding);
            }
            let len = (d2 >> 1) as usize + (d2 & 1) as usize;
            let data = r.take(len)?;
            let bits = if d2 & 1 != 0 {
                // the end mark: the last byte's lowest 1, with a bit of data before it
                let last = data[len - 1];
                if last & 0x7f == 0 {
                    return Err(Error::Encoding);
                }
                (len - 1) * 8 + 7 - last.trailing_zeros() as usize
            } else {
                len * 8
            };
            if bits > MAX_BITS {
                return Err(Error::Encoding);
            }
            // an exotic cell's first byte is its type
            let library = match (exotic, data.first()) {
                (false, _) => false,
                (true, _) if bits < 8 => return Err(Error::Encoding),
                (true, Some(&LIBRARY)) if bits == 8 + 256 && refs == 0 => true,
                (true, Some(1 | 3 | 4)) => return Err(Error::Special),
                (true, _) => return Err(Error::Encoding),
            };
            // a level above 0 only comes from pruned branches and Merkle proofs
            if d1 >> 5 != 0 {
                return Err(Error::Encoding);
            }
            let mut to = [0u16; MAX_REFS];
            for t in to.iter_mut().take(refs) {
                let n = r.uint(size)?;
                if n <= i || n >= count {
                    return Err(Error::Order);
                }
                // fewer than 2048 cells: an index fits
                *t = n as u16;
            }
            cells.push(Cell {
                data,
                bits: bits as u16,
                refs: to,
                count: refs as u8,
                library,
                depth: 0,
                hash: [0; 32],
            });
        }
        if r.at != end {
            return Err(Error::Header);
        }
        // every cell reachable from the root: references only point onwards, so one pass finds them
        let mut reached = alloc::vec![false; count];
        reached[0] = true;
        for i in 0..count {
            if !reached[i] {
                return Err(Error::Unreached);
            }
            for t in cells[i].to() {
                reached[t] = true;
            }
        }
        // hashes from the last cell to the first: each refers only to later ones
        for i in (0..count).rev() {
            let c = &cells[i];
            let refs: Vec<(Hash, u16)> = c.to().map(|t| (cells[t].hash, cells[t].depth)).collect();
            let depth = depth_of(&refs)?;
            let hash = hash_parts(c.library, c.data, c.bits as usize, &refs);
            cells[i].hash = hash;
            cells[i].depth = depth;
        }
        Ok(Boc { cells })
    }

    /// The root cell's hash.
    pub fn hash(&self) -> Hash { self.cells[0].hash }

    /// How many cells it has.
    pub fn len(&self) -> usize { self.cells.len() }

    /// Never: a BOC has its root at least.
    pub fn is_empty(&self) -> bool { self.cells.is_empty() }

    /// The root, to read; a library cell has nothing to read.
    pub fn root(&self) -> Result<Slice<'_>, Error> { Slice::of(&self.cells, 0) }

    /// The root cell itself.
    pub fn root_cell(&self) -> &Cell<'a> { &self.cells[0] }
}

/// Where reading a cell has got to: the bits and references left of it.
#[derive(Debug, Clone, Copy)]
pub struct Slice<'s> {
    cells: &'s [Cell<'s>],
    cell: usize,
    at: usize,
    next: usize,
}

impl<'s> Slice<'s> {
    fn of(cells: &'s [Cell<'s>], cell: usize) -> Result<Slice<'s>, Error> {
        if cells[cell].library {
            return Err(Error::Invalid(
                "a library cell where data should be: maki can't see what it stands for",
            ));
        }
        Ok(Slice { cells, cell, at: 0, next: 0 })
    }

    fn here(&self) -> &'s Cell<'s> { &self.cells[self.cell] }

    /// Its bits not yet read.
    pub fn bits_left(&self) -> usize { self.here().bits() - self.at }

    /// Its references not yet followed.
    pub fn refs_left(&self) -> usize { self.here().refs() - self.next }

    /// Nothing left of it.
    pub fn is_empty(&self) -> bool { self.bits_left() == 0 && self.refs_left() == 0 }

    /// Nothing more: refused if there is.
    pub fn end(&self) -> Result<(), Error> { if self.is_empty() { Ok(()) } else { Err(Error::Extra) } }

    fn bit_at(&self, i: usize) -> bool { self.here().data[i / 8] & (0x80 >> (i % 8)) != 0 }

    /// The next bit.
    pub fn bit(&mut self) -> Result<bool, Error> {
        if self.bits_left() == 0 {
            return Err(Error::Short);
        }
        self.at += 1;
        Ok(self.bit_at(self.at - 1))
    }

    /// The next `n` bits (up to 64) as a number, without moving on.
    pub fn peek(&self, n: usize) -> Result<u64, Error> {
        if n > 64 || n > self.bits_left() {
            return Err(Error::Short);
        }
        Ok((self.at..self.at + n).fold(0u64, |v, i| v << 1 | self.bit_at(i) as u64))
    }

    /// The next `n` bits (up to 64) as an unsigned number.
    pub fn uint(&mut self, n: usize) -> Result<u64, Error> {
        let v = self.peek(n)?;
        self.at += n;
        Ok(v)
    }

    /// The next eight bits as a signed number: a workchain.
    pub fn int8(&mut self) -> Result<i8, Error> { Ok(self.uint(8)? as u8 as i8) }

    /// The next `N` bytes' worth of bits.
    pub fn bytes<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        for b in out.iter_mut() {
            *b = self.uint(8)? as u8;
        }
        Ok(out)
    }

    /// The rest of its bits as bytes: refused if they aren't whole bytes.
    pub fn rest_bytes(&mut self) -> Result<Vec<u8>, Error> {
        if !self.bits_left().is_multiple_of(8) {
            return Err(Error::Invalid("text that isn't whole bytes: not as TON writes it"));
        }
        let mut out = Vec::with_capacity(self.bits_left() / 8);
        while self.bits_left() > 0 {
            out.push(self.uint(8)? as u8);
        }
        Ok(out)
    }

    /// An amount (`Coins`, VarUInteger 16): four bits of how many bytes it takes, then them.
    pub fn coins(&mut self) -> Result<u128, Error> {
        let n = self.uint(4)? as usize;
        let mut v = 0u128;
        for _ in 0..n {
            v = v << 8 | self.uint(8)? as u128;
        }
        Ok(v)
    }

    /// An address (`MsgAddress`): none (`addr_none`), or a standard one (`addr_std`) without
    /// anycast, which TON stopped taking in 2025. Addresses outside TON and the variable-length
    /// form, wallets don't write: refused.
    pub fn address(&mut self) -> Result<Option<Address>, Error> {
        match self.uint(2)? {
            0b00 => Ok(None),
            0b10 => {
                if self.bit()? {
                    return Err(Error::Invalid("an anycast address, which TON refuses"));
                }
                let workchain = self.int8()?;
                Ok(Some(Address { workchain, hash: self.bytes()? }))
            }
            0b01 => Err(Error::Invalid("an address outside TON, where an account's should be")),
            _ => Err(Error::Invalid("an address in a form wallets don't write (addr_var)")),
        }
    }

    /// The next reference, to read: refused if it's a library cell, which stands for code.
    pub fn reference(&mut self) -> Result<Slice<'s>, Error> {
        let i = self.reference_cell()?;
        Slice::of(self.cells, i)
    }

    /// The next reference, whatever it is: the cell, to hash.
    pub fn reference_cell(&mut self) -> Result<usize, Error> {
        if self.refs_left() == 0 {
            return Err(Error::Short);
        }
        self.next += 1;
        Ok(self.here().refs[self.next - 1] as usize)
    }

    /// A cell's hash and depth.
    pub fn cell_hash(&self, cell: usize) -> (Hash, u16) { (self.cells[cell].hash, self.cells[cell].depth) }

    /// A `Maybe ^X`: a bit, and the reference if it's 1.
    pub fn maybe_reference(&mut self) -> Result<Option<Slice<'s>>, Error> {
        if self.bit()? { Ok(Some(self.reference()?)) } else { Ok(None) }
    }

    /// An `Either X ^X`: a bit, then what's left of this cell (0), or one reference and nothing
    /// else (1).
    pub fn either(&mut self) -> Result<Slice<'s>, Error> {
        if self.bit()? {
            let r = self.reference()?;
            self.end()?;
            Ok(r)
        } else {
            let rest = *self;
            self.at = self.here().bits();
            self.next = self.here().refs();
            Ok(rest)
        }
    }

    /// How big what's left of it is: its bytes (rounded up) and cells, each cell under it counted
    /// once however many times it's referred to.
    pub fn size(&self) -> (usize, usize) {
        let mut seen = alloc::vec![false; self.cells.len()];
        let mut stack: Vec<usize> = self.here().to().skip(self.next).collect();
        let (mut bits, mut cells) = (self.bits_left(), 1);
        while let Some(i) = stack.pop() {
            if core::mem::replace(&mut seen[i], true) {
                continue;
            }
            bits += self.cells[i].bits();
            cells += 1;
            stack.extend(self.cells[i].to());
        }
        (bits.div_ceil(8), cells)
    }

    /// The hash and depth of a cell made of what's left of this one: its bits and references.
    pub fn rest_hash(&self) -> (Hash, u16) {
        let mut b = Builder::new();
        for i in self.at..self.here().bits() {
            b.bit(self.bit_at(i));
        }
        for c in self.here().to().skip(self.next) {
            b.reference(self.cell_hash(c));
        }
        b.finish()
    }
}

/// A cell put together here, to hash: a wallet's or a jetton wallet's first state, a library
/// cell, what's left of another cell.
#[derive(Debug, Clone)]
pub struct Builder {
    data: Vec<u8>,
    bits: usize,
    refs: Vec<(Hash, u16)>,
    exotic: bool,
}

impl Default for Builder {
    fn default() -> Builder { Builder::new() }
}

impl Builder {
    /// An empty cell.
    pub fn new() -> Builder { Builder { data: Vec::new(), bits: 0, refs: Vec::new(), exotic: false } }

    /// A library cell standing for the code whose hash is `code`.
    pub fn library(code: &Hash) -> Builder {
        let mut b = Builder::new();
        b.exotic = true;
        b.uint(LIBRARY as u64, 8);
        b.bytes(code);
        b
    }

    /// One bit more.
    pub fn bit(&mut self, bit: bool) -> &mut Builder {
        if self.bits.is_multiple_of(8) {
            self.data.push(0);
        }
        if let (true, Some(last)) = (bit, self.data.last_mut()) {
            *last |= 0x80 >> (self.bits % 8);
        }
        self.bits += 1;
        self
    }

    /// `n` bits (up to 64) of `v`, the most significant first.
    pub fn uint(&mut self, v: u64, n: usize) -> &mut Builder {
        for i in (0..n).rev() {
            self.bit(v >> i & 1 != 0);
        }
        self
    }

    /// Whole bytes more.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Builder {
        for &x in b {
            self.uint(x as u64, 8);
        }
        self
    }

    /// A standard address (`addr_std`, without anycast).
    pub fn address(&mut self, a: &Address) -> &mut Builder {
        self.uint(0b100, 3).uint(a.workchain as u8 as u64, 8).bytes(&a.hash)
    }

    /// A reference to a cell, by its hash and depth.
    pub fn reference(&mut self, cell: (Hash, u16)) -> &mut Builder {
        self.refs.push(cell);
        self
    }

    /// Its hash and depth. What's put together here is never more than a cell holds: the parts of
    /// a cell that was read, or a state of a known size.
    pub fn finish(&self) -> (Hash, u16) {
        debug_assert!(self.bits <= MAX_BITS && self.refs.len() <= MAX_REFS);
        let depth = self.refs.iter().map(|r| r.1.saturating_add(1)).max().unwrap_or(0);
        (hash_parts(self.exotic, &self.data, self.bits, &self.refs), depth)
    }
}
