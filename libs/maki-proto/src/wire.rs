//! Message bodies: little-endian integers, `str8` (u8 length + UTF-8) and `bytes16` (u16 length
//! + bytes). Nothing else, so the TypeScript side stays small.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncated;

#[derive(Default)]
pub struct Writer(Vec<u8>);

impl Writer {
    pub fn new() -> Self { Writer(Vec::new()) }

    pub fn u8(mut self, v: u8) -> Self {
        self.0.push(v);
        self
    }

    pub fn u16(mut self, v: u16) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn i32(mut self, v: i32) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u64(mut self, v: u64) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn str8(mut self, s: &str) -> Self {
        let s = &s.as_bytes()[..s.len().min(255)];
        self.0.push(s.len() as u8);
        self.0.extend_from_slice(s);
        self
    }

    pub fn bytes16(mut self, b: &[u8]) -> Self {
        let b = &b[..b.len().min(u16::MAX as usize)];
        self.0.extend_from_slice(&(b.len() as u16).to_le_bytes());
        self.0.extend_from_slice(b);
        self
    }

    pub fn finish(self) -> Vec<u8> { self.0 }
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self { Reader { data, pos: 0 } }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Truncated> {
        let end = self.pos.checked_add(n).ok_or(Truncated)?;
        let slice = self.data.get(self.pos..end).ok_or(Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8, Truncated> { Ok(self.take(1)?[0]) }

    pub fn u16(&mut self) -> Result<u16, Truncated> { Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap())) }

    pub fn u32(&mut self) -> Result<u32, Truncated> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }

    pub fn i32(&mut self) -> Result<i32, Truncated> { Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap())) }

    pub fn u64(&mut self) -> Result<u64, Truncated> { Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap())) }

    pub fn str8(&mut self) -> Result<&'a str, Truncated> {
        let n = self.u8()? as usize;
        core::str::from_utf8(self.take(n)?).map_err(|_| Truncated)
    }

    pub fn bytes16(&mut self) -> Result<&'a [u8], Truncated> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    /// Everything must have been consumed: trailing bytes mean a malformed message.
    pub fn end(&self) -> Result<(), Truncated> { if self.pos == self.data.len() { Ok(()) } else { Err(Truncated) } }
}
