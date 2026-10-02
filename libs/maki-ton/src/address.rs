//! TON's addresses (TEP-2): a workchain (0, the basechain, where wallets live; -1, the
//! masterchain) and 256 bits, the hash of the contract's first state. People see them
//! "user-friendly": a tag byte (0x11 bounceable, 0x51 not, plus 0x80 for the test network's), the
//! workchain, the 32 bytes and their CRC16 (XModem's, most significant byte first), in base64url:
//! `EQ…` and `UQ…` on TON, `kQ…` and `0Q…` on its test network. Wallets show their own address
//! non-bounceable and other contracts' bounceable, and the flag says how to send to it: bounceable
//! comes back if nothing there takes it. And "raw": `0:` and the 64 hex digits.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::{Error, Hash};

/// A standard address on TON: a workchain and a hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address {
    /// 0, the basechain, where wallets live; -1, the masterchain.
    pub workchain: i8,
    /// The hash of the contract's first state.
    pub hash: Hash,
}

/// An address as it was written, and what its user-friendly form said of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parsed {
    /// The address itself.
    pub address: Address,
    /// None for a raw address, which says neither.
    pub bounceable: Option<bool>,
    /// Whether it's only for TON's test network.
    pub testnet: Option<bool>,
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// CRC-16/XModem: polynomial 0x1021, starting at 0, as TEP-2 checks an address with.
pub fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &b in bytes {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { crc << 1 ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

impl Address {
    /// The raw form: `0:` and the hash in hex.
    pub fn raw(&self) -> String { format!("{}:{}", self.workchain, hex(&self.hash)) }

    /// The user-friendly form, bounceable or not, for TON or its test network.
    pub fn friendly(&self, bounceable: bool, testnet: bool) -> String {
        let mut b = [0u8; 36];
        b[0] = if bounceable { 0x11 } else { 0x51 } | if testnet { 0x80 } else { 0 };
        b[1] = self.workchain as u8;
        b[2..34].copy_from_slice(&self.hash);
        let crc = crc16(&b[..34]);
        b[34..].copy_from_slice(&crc.to_be_bytes());
        b.chunks(3)
            .flat_map(|c| {
                let n = (c[0] as u32) << 16 | (c[1] as u32) << 8 | c[2] as u32;
                [18, 12, 6, 0].map(|s| ALPHABET[(n >> s & 63) as usize] as char)
            })
            .collect()
    }

    /// An address as people write it: user-friendly (base64url, or base64's other two letters,
    /// not mixed), its checksum and tag checked; or raw. On the basechain or the masterchain
    /// only: TON has no others.
    pub fn parse(text: &str) -> Result<Parsed, Error> {
        let parsed = match text.split_once(':') {
            Some((wc, h)) => {
                let workchain = match wc {
                    "0" => 0,
                    "-1" => -1,
                    _ if wc.parse::<i32>().is_ok() && !wc.starts_with('+') => {
                        return Err(Error::Invalid("an address on a workchain TON doesn't have"));
                    }
                    _ => return Err(Error::Invalid("not a TON address")),
                };
                if h.len() != 64 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
                    return Err(Error::Invalid("not a TON address"));
                }
                let mut hash = [0u8; 32];
                for (i, b) in hash.iter_mut().enumerate() {
                    *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16)
                        .map_err(|_| Error::Invalid("not a TON address"))?;
                }
                Parsed { address: Address { workchain, hash }, bounceable: None, testnet: None }
            }
            None => {
                let b = decode(text).ok_or(Error::Invalid("not a TON address"))?;
                if crc16(&b[..34]).to_be_bytes() != b[34..] {
                    return Err(Error::Invalid("a TON address whose checksum is wrong: mistyped?"));
                }
                let (bounceable, testnet) = match b[0] {
                    0x11 => (true, false),
                    0x51 => (false, false),
                    0x91 => (true, true),
                    0xd1 => (false, true),
                    _ => return Err(Error::Invalid("not a TON address")),
                };
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&b[2..34]);
                Parsed {
                    address: Address { workchain: b[1] as i8, hash },
                    bounceable: Some(bounceable),
                    testnet: Some(testnet),
                }
            }
        };
        if !matches!(parsed.address.workchain, 0 | -1) {
            return Err(Error::Invalid("an address on a workchain TON doesn't have"));
        }
        Ok(parsed)
    }
}

/// 48 characters of base64url (or of base64, its `+` and `/`, but not both kinds) as 36 bytes.
fn decode(text: &str) -> Option<[u8; 36]> {
    let t = text.as_bytes();
    if t.len() != 48 {
        return None;
    }
    let url = t.iter().any(|c| matches!(c, b'-' | b'_'));
    let std = t.iter().any(|c| matches!(c, b'+' | b'/'));
    if url && std {
        return None;
    }
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        } as u32)
    };
    let mut out = Vec::with_capacity(36);
    for chunk in t.chunks(4) {
        let mut n = 0u32;
        for &c in chunk {
            n = n << 6 | value(c)?;
        }
        out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    out.try_into().ok()
}
