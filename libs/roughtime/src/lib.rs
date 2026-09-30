//! Roughtime for maki: build a request, verify a response.
//!
//! Implements draft-ietf-ntp-roughtime-19 (wire version `0x8000000c`). Checked on 2026-09-26
//! against time.txryan.com, roughtime.se and roughtime.int08h.com, whose answers are the test
//! vectors in `tests/vectors`.
//!
//! The device builds the whole request packet itself and keeps it. A server's Merkle leaf is
//! `H(0x00 || request packet)`, so whoever relays the exchange (the desktop app) can neither pick
//! the nonce nor substitute an answer meant for another request. Trust comes only from the
//! server key the caller passes in, which should be pinned on the device.
#![no_std]

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha512};

/// Wire version this crate speaks.
pub const VERSION: u32 = 0x8000_000c;
/// Request size; UDP requests must be at least 1024 bytes so a server can't be used as an amplifier.
pub const REQUEST_LEN: usize = 1024;
/// Upper bound on a response we're willing to parse.
pub const MAX_RESPONSE_LEN: usize = 2048;

const MAGIC: &[u8; 8] = b"ROUGHTIM";
const DELEGATION_CONTEXT: &[u8] = b"RoughTime v1 delegation signature\0";
const RESPONSE_CONTEXT: &[u8] = b"RoughTime v1 response signature\0";

const VER: [u8; 4] = *b"VER\0";
const NONC: [u8; 4] = *b"NONC";
const TYPE: [u8; 4] = *b"TYPE";
const ZZZZ: [u8; 4] = *b"ZZZZ";
const SIG: [u8; 4] = *b"SIG\0";
const SREP: [u8; 4] = *b"SREP";
const CERT: [u8; 4] = *b"CERT";
const DELE: [u8; 4] = *b"DELE";
const PUBK: [u8; 4] = *b"PUBK";
const MINT: [u8; 4] = *b"MINT";
const MAXT: [u8; 4] = *b"MAXT";
const ROOT: [u8; 4] = *b"ROOT";
const MIDP: [u8; 4] = *b"MIDP";
const RADI: [u8; 4] = *b"RADI";
const PATH: [u8; 4] = *b"PATH";
const INDX: [u8; 4] = *b"INDX";

/// A server's time, proven fresh by our nonce and signed by its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    /// Seconds since the Unix epoch at the moment the server processed the request.
    pub midpoint: u64,
    /// The server's own bound on its error, in seconds.
    pub radius: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not a `ROUGHTIM` packet, or its length field disagrees with the data.
    Framing,
    /// A message whose header, offsets or tag order break the encoding rules.
    Malformed,
    /// A tag the protocol requires is absent.
    Missing([u8; 4]),
    /// A field has the wrong size or value.
    BadField([u8; 4]),
    /// The server's long-term key did not sign this delegation.
    Delegation,
    /// The delegated key did not sign this response.
    Signature,
    /// The response is for a different request.
    Nonce,
    /// The midpoint lies outside the delegation's validity window.
    Window,
    /// The Merkle proof doesn't lead from our request to the signed root.
    Proof,
    /// The server answered in a version we didn't ask for.
    Version,
}

fn tag_value(tag: [u8; 4]) -> u32 { u32::from_le_bytes(tag) }

/// A borrowed Roughtime message: `N`, `N-1` offsets, `N` tags, then the values, all little-endian.
struct Message<'a> {
    count: usize,
    header: &'a [u8],
    values: &'a [u8],
}

impl<'a> Message<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(Error::Malformed);
        }
        let count = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let header_len = count.checked_mul(8).ok_or(Error::Malformed)?;
        if count == 0 || header_len > bytes.len() {
            return Err(Error::Malformed);
        }
        let msg = Message { count, header: &bytes[..header_len], values: &bytes[header_len..] };
        // offsets: multiples of four, non-decreasing, inside the values; tags strictly ascending
        let mut last_offset = 0;
        for i in 1..count {
            let offset = msg.offset(i);
            if !offset.is_multiple_of(4) || offset < last_offset || offset > msg.values.len() {
                return Err(Error::Malformed);
            }
            last_offset = offset;
        }
        for i in 1..count {
            if tag_value(msg.tag(i)) <= tag_value(msg.tag(i - 1)) {
                return Err(Error::Malformed);
            }
        }
        Ok(msg)
    }

    /// Start of value `i` within `values`; value 0 always starts at 0.
    fn offset(&self, i: usize) -> usize {
        if i == 0 {
            return 0;
        }
        let at = 4 * i;
        u32::from_le_bytes(self.header[at..at + 4].try_into().unwrap()) as usize
    }

    fn tag(&self, i: usize) -> [u8; 4] {
        let at = 4 + 4 * (self.count - 1) + 4 * i;
        self.header[at..at + 4].try_into().unwrap()
    }

    fn get(&self, tag: [u8; 4]) -> Option<&'a [u8]> {
        let i = (0..self.count).find(|&i| self.tag(i) == tag)?;
        let end = if i + 1 < self.count { self.offset(i + 1) } else { self.values.len() };
        Some(&self.values[self.offset(i)..end])
    }

    fn require(&self, tag: [u8; 4]) -> Result<&'a [u8], Error> { self.get(tag).ok_or(Error::Missing(tag)) }

    fn fixed<const N: usize>(&self, tag: [u8; 4]) -> Result<[u8; N], Error> {
        self.require(tag)?.try_into().map_err(|_| Error::BadField(tag))
    }

    fn u32(&self, tag: [u8; 4]) -> Result<u32, Error> { Ok(u32::from_le_bytes(self.fixed(tag)?)) }

    fn u64(&self, tag: [u8; 4]) -> Result<u64, Error> { Ok(u64::from_le_bytes(self.fixed(tag)?)) }
}

fn unframe(packet: &[u8]) -> Result<&[u8], Error> {
    if packet.len() < 12 || &packet[..8] != MAGIC {
        return Err(Error::Framing);
    }
    let len = u32::from_le_bytes(packet[8..12].try_into().unwrap()) as usize;
    if packet.len() != 12 + len {
        return Err(Error::Framing);
    }
    Ok(&packet[12..])
}

/// First 32 bytes of SHA-512, the protocol's `H`.
fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha512::new();
    for part in parts {
        h.update(part);
    }
    h.finalize()[..32].try_into().unwrap()
}

fn verify_signed(key: &VerifyingKey, context: &[u8], data: &[u8], sig: &[u8]) -> bool {
    let Ok(sig) = <[u8; 64]>::try_from(sig) else { return false };
    let mut buf = [0u8; 512];
    let len = context.len() + data.len();
    if len > buf.len() {
        return false;
    }
    buf[..context.len()].copy_from_slice(context);
    buf[context.len()..len].copy_from_slice(data);
    key.verify_strict(&buf[..len], &Signature::from_bytes(&sig)).is_ok()
}

/// Build a 1024-byte request carrying `nonce`. Keep the returned bytes: `verify` needs them.
pub fn request(nonce: &[u8; 32]) -> [u8; REQUEST_LEN] {
    // tags in ascending order of their little-endian value: VER, NONC, TYPE, ZZZZ
    const HEADER: usize = 4 * 8; // N + 3 offsets + 4 tags
    const PAD: usize = REQUEST_LEN - 12 - HEADER - 4 - 32 - 4;
    let mut p = [0u8; REQUEST_LEN];
    p[..8].copy_from_slice(MAGIC);
    p[8..12].copy_from_slice(&((REQUEST_LEN - 12) as u32).to_le_bytes());
    let m = &mut p[12..];
    let words: [u32; 8] = [
        4,          // N
        4,          // NONC starts after VER
        4 + 32,     // TYPE
        4 + 32 + 4, // ZZZZ
        tag_value(VER),
        tag_value(NONC),
        tag_value(TYPE),
        tag_value(ZZZZ),
    ];
    for (i, w) in words.iter().enumerate() {
        m[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    let v = &mut m[HEADER..];
    v[0..4].copy_from_slice(&VERSION.to_le_bytes());
    v[4..36].copy_from_slice(nonce);
    v[36..40].copy_from_slice(&0u32.to_le_bytes()); // TYPE 0 = request
    debug_assert_eq!(v.len(), 40 + PAD); // the rest is ZZZZ padding, already zero
    p
}

/// Verify `response` against the exact `request` bytes that were sent, under `server_key`.
pub fn verify(request: &[u8], response: &[u8], server_key: &[u8; 32]) -> Result<Verified, Error> {
    if response.len() > MAX_RESPONSE_LEN {
        return Err(Error::Framing);
    }
    let sent = Message::parse(unframe(request)?)?;
    let top = Message::parse(unframe(response)?)?;

    if top.u32(TYPE)? != 1 {
        return Err(Error::BadField(TYPE));
    }
    if top.fixed::<32>(NONC)? != sent.fixed::<32>(NONC)? {
        return Err(Error::Nonce);
    }

    // long-term key -> delegation of a short-term key
    let long_term = VerifyingKey::from_bytes(server_key).map_err(|_| Error::Delegation)?;
    let cert = Message::parse(top.require(CERT)?)?;
    let dele_bytes = cert.require(DELE)?;
    if !verify_signed(&long_term, DELEGATION_CONTEXT, dele_bytes, cert.require(SIG)?) {
        return Err(Error::Delegation);
    }
    let dele = Message::parse(dele_bytes)?;
    let short_term = VerifyingKey::from_bytes(&dele.fixed(PUBK)?).map_err(|_| Error::BadField(PUBK))?;

    // short-term key -> signed response
    let srep_bytes = top.require(SREP)?;
    if !verify_signed(&short_term, RESPONSE_CONTEXT, srep_bytes, top.require(SIG)?) {
        return Err(Error::Signature);
    }
    let srep = Message::parse(srep_bytes)?;
    if srep.u32(VER)? != VERSION {
        return Err(Error::Version);
    }
    let midpoint = srep.u64(MIDP)?;
    let radius = srep.u32(RADI)?;
    if midpoint < dele.u64(MINT)? || midpoint > dele.u64(MAXT)? {
        return Err(Error::Window);
    }

    // our request is a leaf under the signed root
    let path = top.require(PATH)?;
    if path.len() % 32 != 0 || path.len() / 32 > 32 {
        return Err(Error::BadField(PATH));
    }
    let depth = path.len() / 32;
    let mut index = top.u32(INDX)? as u64;
    if index >> depth != 0 {
        return Err(Error::BadField(INDX));
    }
    let mut node = hash(&[&[0x00], request]);
    for sibling in path.chunks_exact(32) {
        node =
            if index & 1 == 0 { hash(&[&[0x01], &node, sibling]) } else { hash(&[&[0x01], sibling, &node]) };
        index >>= 1;
    }
    if node != srep.fixed::<32>(ROOT)? {
        return Err(Error::Proof);
    }

    Ok(Verified { midpoint, radius })
}
