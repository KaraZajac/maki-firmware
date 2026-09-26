//! Frames on the wire: `COBS(version, kind, id, body.., crc32) 0x00`.
//!
//! COBS removes every zero byte from the frame, so a zero always means "end of frame" and a
//! reader that joins mid-stream resynchronises at the next one. The CRC catches the rest.

pub const PROTOCOL_VERSION: u8 = 2;
/// Largest decoded frame either side will accept.
pub const MAX_FRAME: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub kind: u8,
    /// Chosen by the host; the reply carries it back, so replies can arrive in any order.
    pub id: u16,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Cobs,
    TooShort,
    TooLong,
    Crc,
    Version(u8),
}

/// CRC-32/ISO-HDLC, the common one (zlib, PNG, Ethernet).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

pub fn cobs_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 254 + 2);
    let mut code_at = 0;
    out.push(0);
    let mut code = 1u8;
    for &b in data {
        if b == 0 {
            out[code_at] = code;
            code_at = out.len();
            out.push(0);
            code = 1;
        } else {
            out.push(b);
            code += 1;
            if code == 0xff {
                out[code_at] = code;
                code_at = out.len();
                out.push(0);
                code = 1;
            }
        }
    }
    out[code_at] = code;
    out
}

pub fn cobs_decode(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        let code = data[i] as usize;
        if code == 0 {
            return None;
        }
        let end = i + code;
        if end > data.len() {
            return None;
        }
        for &b in &data[i + 1..end] {
            if b == 0 {
                return None;
            }
            out.push(b);
        }
        i = end;
        if code < 0xff && i < data.len() {
            out.push(0);
        }
    }
    Some(out)
}

/// Encode one packet, delimiter included.
pub fn encode(kind: u8, id: u16, body: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity(body.len() + 8);
    raw.push(PROTOCOL_VERSION);
    raw.push(kind);
    raw.extend_from_slice(&id.to_le_bytes());
    raw.extend_from_slice(body);
    raw.extend_from_slice(&crc32(&raw).to_le_bytes());
    let mut out = cobs_encode(&raw);
    out.push(0);
    out
}

/// Decode one frame, without its delimiter.
pub fn decode(frame: &[u8]) -> Result<Packet, FrameError> {
    let raw = cobs_decode(frame).ok_or(FrameError::Cobs)?;
    if raw.len() < 8 {
        return Err(FrameError::TooShort);
    }
    if raw.len() > MAX_FRAME {
        return Err(FrameError::TooLong);
    }
    let (data, crc) = raw.split_at(raw.len() - 4);
    if crc32(data).to_le_bytes() != crc {
        return Err(FrameError::Crc);
    }
    if data[0] != PROTOCOL_VERSION {
        return Err(FrameError::Version(data[0]));
    }
    Ok(Packet { kind: data[1], id: u16::from_le_bytes([data[2], data[3]]), body: data[4..].to_vec() })
}

/// Splits a byte stream into packets at zero delimiters, however the bytes arrive.
#[derive(Default)]
pub struct Deframer {
    buf: Vec<u8>,
    overflow: bool,
}

impl Deframer {
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Result<Packet, FrameError>> {
        let mut out = Vec::new();
        for &b in bytes {
            if b == 0 {
                if self.overflow {
                    out.push(Err(FrameError::TooLong));
                } else if !self.buf.is_empty() {
                    out.push(decode(&self.buf));
                }
                self.buf.clear();
                self.overflow = false;
            } else if self.buf.len() < MAX_FRAME + MAX_FRAME / 254 + 8 {
                self.buf.push(b);
            } else {
                self.overflow = true;
            }
        }
        out
    }
}
