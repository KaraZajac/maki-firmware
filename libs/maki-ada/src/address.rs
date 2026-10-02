//! Addresses (CIP-19): what one is made of, read as the ledger reads an output's or a withdrawal's
//! since Babbage (whole, nothing after it, nothing it doesn't use), and written as wallets show it:
//! bech32 for Shelley's kinds (CIP-5's prefixes, without BIP173's length limit), base58 for
//! Byron's. And the IDs certificates name: a stake pool's (`pool1…`) and a DRep's (CIP-129's
//! `drep1…`).

use alloc::string::String;
use alloc::vec::Vec;

use crate::cbor::{EMBEDDED, Keys, Reader};
use crate::{Error, Hash28, Network};

/// Who a payment or a stake belongs to: a key, by its hash, or a script, by its.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credential {
    Key(Hash28),
    Script(Hash28),
}

impl Credential {
    /// Its hash, a key's or a script's.
    pub fn hash(&self) -> &Hash28 {
        match self {
            Credential::Key(h) | Credential::Script(h) => h,
        }
    }
}

/// Whose stake what an address holds counts toward: its delegation part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stake {
    /// A stake key's or a script's: a base address.
    Credential(Credential),
    /// A stake key named by where it was registered on chain (a slot, a transaction in it, a
    /// certificate in that): a pointer address.
    Pointer { slot: u32, tx: u16, cert: u16 },
    /// No one's: an enterprise address.
    None,
}

/// What an address is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An address since Shelley: who can spend what it holds, and whose stake that counts toward.
    Shelley { payment: Credential, stake: Stake },
    /// An address from Byron, Cardano's first era: its network is a test network's if it names
    /// its magic, Cardano's own if it doesn't.
    Byron { magic: Option<u32> },
}

/// An address an output can pay: a payment address since Shelley, or Byron's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// As a transaction carries it: what's shown, in bech32 or base58.
    pub bytes: Vec<u8>,
    /// The network ID it's for: 1 for Cardano's own, 0 for a test network.
    pub network: u8,
    pub kind: Kind,
}

/// A reward account (a stake address): whose rewards a withdrawal takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewardAccount {
    /// The network ID it's for: 1 for Cardano's own, 0 for a test network.
    pub network: u8,
    pub stake: Credential,
}

/// A credential's hash at `at`, a script's or a key's.
fn credential(b: &[u8], at: usize, script: bool) -> Result<Credential, Error> {
    let hash: Hash28 = b.get(at..at + 28).ok_or(Error::Address)?.try_into().map_err(|_| Error::Address)?;
    Ok(if script { Credential::Script(hash) } else { Credential::Key(hash) })
}

/// A pointer's number, as the ledger reads it (`decodeVariableLengthWord32` and `Word16`): seven
/// bits a byte, the most significant first, the high bit on every byte but the last; `bits` at
/// most, so at most `(bits + 6) / 7` bytes, and with that many, a first byte carrying no more than
/// the bits left over.
fn varint(b: &[u8], at: &mut usize, bits: u32) -> Result<u32, Error> {
    let most = bits.div_ceil(7) as usize;
    let first = *at;
    let mut n = 0u32;
    for i in 0..most {
        let byte = *b.get(*at).ok_or(Error::Address)?;
        *at += 1;
        n = (n << 7) | (byte & 0x7f) as u32;
        if byte & 0x80 == 0 {
            // with every byte used, the first's spare bits must be clear
            let spare = (most * 7) as u32 - bits;
            if i == most - 1 && (b[first] & 0x7f) >> (7 - spare) != 0 {
                return Err(Error::Address);
            }
            return Ok(n);
        }
    }
    Err(Error::Address)
}

impl Address {
    /// An output's address, read whole as the ledger reads it (Babbage's rules, Conway's pointers):
    /// a payment address since Shelley, its header naming what it is and its network (and nothing
    /// else), then its hashes, or its pointer; or, its header's high bit set, Byron's, which is
    /// CBOR, with a checksum.
    pub fn parse(b: &[u8]) -> Result<Address, Error> {
        let header = *b.first().ok_or(Error::Address)?;
        if header & 0x80 != 0 {
            // whatever isn't one is no address an output can pay (a reward account's among them)
            return byron(b).map_err(|e| if matches!(e, Error::Invalid(_)) { e } else { Error::Address });
        }
        let (kind, network) = (header >> 4, header & 0x0f);
        // the network is the low bit alone; the others are for networks that aren't yet
        if network > 1 {
            return Err(Error::Address);
        }
        let payment = credential(b, 1, kind & 1 == 1)?;
        let stake = match kind {
            0..=3 => {
                if b.len() != 57 {
                    return Err(Error::Address);
                }
                Stake::Credential(credential(b, 29, kind & 2 == 2)?)
            }
            4 | 5 => {
                let mut at = 29;
                let slot = varint(b, &mut at, 32)?;
                let tx = varint(b, &mut at, 16)? as u16;
                let cert = varint(b, &mut at, 16)? as u16;
                if at != b.len() {
                    return Err(Error::Address);
                }
                Stake::Pointer { slot, tx, cert }
            }
            _ => {
                if b.len() != 29 {
                    return Err(Error::Address);
                }
                Stake::None
            }
        };
        Ok(Address { bytes: b.to_vec(), network, kind: Kind::Shelley { payment, stake } })
    }

    /// A base address: a payment key's and a stake key's, as an account's own addresses are.
    pub fn base(network: Network, payment: &Hash28, stake: &Hash28) -> Address {
        let mut bytes = Vec::with_capacity(57);
        bytes.push(network.id());
        bytes.extend_from_slice(payment);
        bytes.extend_from_slice(stake);
        Address {
            bytes,
            network: network.id(),
            kind: Kind::Shelley {
                payment: Credential::Key(*payment),
                stake: Stake::Credential(Credential::Key(*stake)),
            },
        }
    }

    /// The address as wallets show it: bech32 (`addr1…`, `addr_test1…`), or Byron's base58.
    pub fn text(&self) -> String {
        match self.kind {
            Kind::Shelley { .. } => bech32(if self.network == 1 { "addr" } else { "addr_test" }, &self.bytes),
            Kind::Byron { .. } => base58(&self.bytes),
        }
    }

    /// The address `text` writes, as a wallet shows one: bech32 with its network's prefix, or
    /// base58 for Byron's; None if it isn't one.
    pub fn from_text(text: &str) -> Option<Address> {
        if let Some((hrp, bytes)) = from_bech32(text) {
            let a = Address::parse(&bytes).ok()?;
            let hrp_network = match hrp.as_str() {
                "addr" => 1,
                "addr_test" => 0,
                _ => return None,
            };
            return (matches!(a.kind, Kind::Shelley { .. }) && a.network == hrp_network).then_some(a);
        }
        let a = Address::parse(&from_base58(text)?).ok()?;
        matches!(a.kind, Kind::Byron { .. }).then_some(a)
    }
}

impl RewardAccount {
    /// A withdrawal's account, read whole: a header naming a key's or a script's and the network,
    /// and its hash.
    pub fn parse(b: &[u8]) -> Result<RewardAccount, Error> {
        let header = *b.first().ok_or(Error::Address)?;
        if header & 0b1110_1110 != 0b1110_0000 || b.len() != 29 {
            return Err(Error::Address);
        }
        Ok(RewardAccount { network: header & 1, stake: credential(b, 1, header & 0x10 != 0)? })
    }

    /// An account's own: its stake key's.
    pub fn new(network: Network, stake: &Hash28) -> RewardAccount {
        RewardAccount { network: network.id(), stake: Credential::Key(*stake) }
    }

    /// As a transaction carries it: 29 bytes.
    pub fn bytes(&self) -> [u8; 29] {
        let mut out = [0u8; 29];
        out[0] = 0xe0 | (matches!(self.stake, Credential::Script(_)) as u8) << 4 | self.network;
        out[1..].copy_from_slice(self.stake.hash());
        out
    }

    /// As wallets show it: `stake1…`, `stake_test1…`.
    pub fn text(&self) -> String {
        bech32(if self.network == 1 { "stake" } else { "stake_test" }, &self.bytes())
    }

    /// The reward account `text` writes; None if it isn't one.
    pub fn from_text(text: &str) -> Option<RewardAccount> {
        let (hrp, bytes) = from_bech32(text)?;
        let a = RewardAccount::parse(&bytes).ok()?;
        let network = match hrp.as_str() {
            "stake" => 1,
            "stake_test" => 0,
            _ => return None,
        };
        (a.network == network).then_some(a)
    }
}

/// A stake pool's ID, as pools are found by: its key's hash in bech32, `pool1…`.
pub fn pool_id(pool: &Hash28) -> String { bech32("pool", pool) }

/// A DRep's ID as CIP-129 has it (Cardanoscan, Koios and gov.tools show and take it): a header byte
/// saying it's a DRep's key (0x22) or script (0x23), then its hash, in bech32: `drep1…`.
pub fn drep_id(drep: &Credential) -> String {
    let mut b = [0u8; 29];
    b[0] = match drep {
        Credential::Key(_) => 0x22,
        Credential::Script(_) => 0x23,
    };
    b[1..].copy_from_slice(drep.hash());
    bech32("drep", &b)
}

/// The most a Byron address's attributes may hold beyond its network's magic, in bytes (the
/// ledger's `OutputBootAddrAttrsTooBig`): an old wallet's derivation path, and what it doesn't know.
const MAX_BYRON_ATTRIBUTES: usize = 64;

/// A Byron address: CBOR, `[#6.24(bytes .cbor [root, attributes, type]), crc32]`, the CRC-32 that
/// of the bytes inside. Its attributes may name a test network's magic (2) and an old wallet's
/// derivation path (1).
fn byron(b: &[u8]) -> Result<Address, Error> {
    let mut r = Reader::new(b);
    if r.array()? != 2 || r.tag()? != EMBEDDED {
        return Err(Error::Address);
    }
    let payload = r.bytes()?;
    let crc = r.uint()?;
    r.end()?;
    if crc != crc32(payload) as u64 {
        return Err(Error::Address);
    }
    let mut p = Reader::new(payload);
    if p.array()? != 3 {
        return Err(Error::Address);
    }
    let _root: Hash28 = p.hash()?;
    let (mut magic, mut extra) = (None, 0usize);
    let mut keys = Keys::new();
    for _ in 0..p.map()? {
        let start = p.at();
        let key = p.uint()?;
        keys.next(p.since(start))?;
        let value = p.bytes()?;
        match key {
            // the network's magic: CBOR, a 32-bit number
            2 => {
                let mut m = Reader::new(value);
                let n = u32::try_from(m.uint()?).map_err(|_| Error::Address)?;
                m.end()?;
                magic = Some(n);
            }
            // an old wallet's derivation path, encrypted: CBOR bytes
            1 => {
                let mut d = Reader::new(value);
                extra += d.bytes()?.len();
                d.end()?;
            }
            k if k > 0xff => return Err(Error::Address),
            _ => extra += value.len(),
        }
    }
    // a key's (0) or redemption's (2): no other kind was ever made
    if !matches!(p.uint()?, 0 | 2) {
        return Err(Error::Address);
    }
    p.end()?;
    if extra > MAX_BYRON_ATTRIBUTES {
        return Err(Error::Invalid("a Byron address with more attributes than Cardano takes"));
    }
    Ok(Address { bytes: b.to_vec(), network: magic.is_none() as u8, kind: Kind::Byron { magic } })
}

/// CRC-32 (IEEE 802.3's, as zlib's), which a Byron address checks itself with.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// BIP173's checksum over five-bit values.
fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    const GENERATOR: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk = 1u32;
    for v in values {
        let top = chk >> 25;
        chk = (chk & 0x1ff_ffff) << 5 ^ v as u32;
        for (i, g) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// The prefix's part of the checksum: each character's high bits, a zero, then its low bits.
fn hrp_values(hrp: &str) -> impl Iterator<Item = u8> + '_ {
    hrp.bytes().map(|c| c >> 5).chain(core::iter::once(0)).chain(hrp.bytes().map(|c| c & 31))
}

/// Eight-bit bytes as five-bit values, the last padded with zeros.
fn to_fives(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push((acc >> bits) as u8 & 31);
        }
    }
    if bits > 0 {
        out.push((acc << (5 - bits)) as u8 & 31);
    }
    out
}

/// `bytes` in bech32 (BIP173's checksum, not bech32m's) under `hrp`, lowercase, of any length: as
/// Cardano writes addresses and IDs.
pub fn bech32(hrp: &str, bytes: &[u8]) -> String {
    let data = to_fives(bytes);
    let chk = polymod(hrp_values(hrp).chain(data.iter().copied()).chain([0u8; 6])) ^ 1;
    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    out.push_str(hrp);
    out.push('1');
    out.extend(data.iter().map(|&v| BECH32[v as usize] as char));
    out.extend((0..6).map(|i| BECH32[(chk >> (5 * (5 - i))) as usize & 31] as char));
    out
}

/// What bech32 `text` writes: its prefix and bytes, if its checksum is BIP173's and it's written
/// the one way bech32 writes those bytes (lowercase, the last value's padding zero). Its time grows
/// with its length: no more than 130 characters are read (no address is longer).
pub fn from_bech32(text: &str) -> Option<(String, Vec<u8>)> {
    if text.len() > 130 {
        return None;
    }
    let sep = text.rfind('1')?;
    let (hrp, data) = (&text[..sep], &text[sep + 1..]);
    if hrp.is_empty() || data.len() < 6 || !hrp.bytes().all(|c| (33..=126).contains(&c)) {
        return None;
    }
    let values: Vec<u8> =
        data.bytes().map(|c| BECH32.iter().position(|&b| b == c).map(|p| p as u8)).collect::<Option<_>>()?;
    if polymod(hrp_values(hrp).chain(values.iter().copied())) != 1 {
        return None;
    }
    let values = &values[..values.len() - 6];
    let mut bytes = Vec::with_capacity(values.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &v in values {
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((acc >> bits) as u8);
        }
    }
    // padding: fewer than five bits, all zeros
    if bits >= 5 || acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    // lowercase, as it's written (an uppercase hrp would have failed the checksum differently)
    (bech32(hrp, &bytes) == text).then(|| (String::from(hrp), bytes))
}

const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// `bytes` in base58, Bitcoin's alphabet, a `1` for each zero byte they start with: as Byron's
/// addresses are written (their checksum is inside them).
pub(crate) fn base58(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    // base-58 digits, least significant first
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &b in &bytes[zeros..] {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(core::iter::repeat_n('1', zeros));
    out.extend(digits.iter().rev().map(|&d| BASE58[d as usize] as char));
    out
}

/// The bytes base58 `text` writes; None if it has a character base58 doesn't, or is longer than
/// any Byron address (its time grows with the square of its length).
pub(crate) fn from_base58(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() > 200 {
        return None;
    }
    let zeros = text.bytes().take_while(|&c| c == b'1').count();
    // bytes, least significant first
    let mut bytes: Vec<u8> = Vec::with_capacity(text.len());
    for c in text.bytes().skip(zeros) {
        let mut carry = BASE58.iter().position(|&a| a == c)? as u32;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push(carry as u8);
            carry >>= 8;
        }
    }
    let mut out = alloc::vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}
