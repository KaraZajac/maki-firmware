//! Spending: the transaction maki signs for a request its owner said yes to (`request`), made
//! whole on maki, as Monero's own wallet (wallet2) makes one, so it looks like any other: the
//! outputs' one-time keys and view tags, the change, or wallet2's output of nothing when there's
//! none, the transaction's keys (additional ones for subaddresses), the payment ID, encrypted, or a
//! dummy one, the range proof over every amount (Bulletproofs+), and a CLSAG for each input,
//! whose key images mark them spent. The computer finds the wallet's outputs, picks the decoys and
//! says what to pay; everything that decides where the money goes is made here.
//!
//! Byte for byte as `construct_tx_with_tx_key` and `genRctSimple` (Monero v0.18.5.1) make a
//! version 2, RingCT type 6 transaction; the randomness is maki's own (hedged: the spend key and
//! the request go into it with fresh randomness, so a weak source repeats nothing).

use alloc::vec::Vec;

use sha3::{Digest, Keccak512};
use zeroize::Zeroize;

use crate::bulletproof::{self, Generators};
use crate::keys::Keys;
use crate::request::{Request, MAX_OUTPUTS};
use crate::sign::{self, commit, derivation, output_scalar, point, EdwardsPoint, Member, Scalar, G};
use crate::tx::{self, Base, Prefix, Transaction};
use crate::{keccak, Kind};

/// Why maki didn't sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendError {
    /// Input `i` isn't this wallet's to spend (its key isn't the one this wallet would have).
    NotOurs(usize),
    /// Input `i`'s amount isn't what its commitment on the chain hides.
    Amount(usize),
    /// A key, in a ring or an address, that isn't a point.
    Point,
    /// The same output spent twice.
    Twice,
    /// Bigger than Monero takes.
    TooBig,
}

impl core::fmt::Display for SpendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SpendError::NotOurs(i) => write!(f, "input {} isn't this wallet's", i + 1),
            SpendError::Amount(i) => write!(f, "input {}'s amount isn't what the chain has", i + 1),
            SpendError::Point => write!(f, "a key that isn't a point"),
            SpendError::Twice => write!(f, "the same output spent twice"),
            SpendError::TooBig => write!(f, "bigger than a Monero transaction may be"),
        }
    }
}

/// What an output of the transaction is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Paid {
    /// The request's payment of this index.
    Payment(u8),
    Change,
    /// wallet2's output of nothing, when there's no change and one payment.
    Dummy,
}

impl Paid {
    fn byte(self) -> u8 {
        match self {
            Paid::Payment(i) => i,
            Paid::Change => CHANGE,
            Paid::Dummy => DUMMY,
        }
    }
}

const CHANGE: u8 = 0xfe;
const DUMMY: u8 = 0xff;

/// A signed transaction, and what goes with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    /// Its bytes, as the network takes them.
    pub transaction: Vec<u8>,
    /// Its secret key r, and the additional ones: what proves a payment was made.
    pub tx_key: [u8; 32],
    pub additional_keys: Vec<[u8; 32]>,
    /// What each output is, in the transaction's order.
    pub outputs: Vec<Paid>,
    /// Outputs coming back to this wallet (the change): each one's index, and its key image.
    pub own: Vec<(u8, [u8; 32])>,
}

impl Signed {
    /// Its bytes, as maki-keys answers: the transaction (a u32 length, little-endian, then it),
    /// the secret key, the additional keys (a count, then each), each output's kind (a count,
    /// then a payment's index, 0xfe for change or 0xff for nothing), and the change's key images
    /// (a count, then each output's index and key image).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.transaction.len() + 64 + 32 * self.additional_keys.len() + 40);
        out.extend_from_slice(&(self.transaction.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.transaction);
        out.extend_from_slice(&self.tx_key);
        out.push(self.additional_keys.len() as u8);
        self.additional_keys.iter().for_each(|k| out.extend_from_slice(k));
        out.push(self.outputs.len() as u8);
        out.extend(self.outputs.iter().map(|p| p.byte()));
        out.push(self.own.len() as u8);
        for (i, image) in &self.own {
            out.push(*i);
            out.extend_from_slice(image);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Signed> {
        let mut at = 0usize;
        let mut take = |n: usize| -> Option<&[u8]> {
            let s = bytes.get(at..at + n)?;
            at += n;
            Some(s)
        };
        let n = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        let transaction = take(n)?.to_vec();
        let tx_key = take(32)?.try_into().ok()?;
        let n = take(1)?[0] as usize;
        let additional_keys = (0..n).map(|_| take(32).map(|k| k.try_into().unwrap())).collect::<Option<_>>()?;
        let n = take(1)?[0] as usize;
        let outputs = take(n)?
            .iter()
            .map(|b| match *b {
                CHANGE => Paid::Change,
                DUMMY => Paid::Dummy,
                i => Paid::Payment(i),
            })
            .collect();
        let n = take(1)?[0] as usize;
        let own = (0..n).map(|_| Some((take(1)?[0], take(32)?.try_into().unwrap()))).collect::<Option<_>>()?;
        (at == bytes.len()).then_some(Signed { transaction, tx_key, additional_keys, outputs, own })
    }
}

/// maki's randomness for a transaction: uniform scalars and numbers from its spend key, the
/// request and fresh randomness, hashed with a counter.
struct Randomness {
    seed: [u8; 64],
    count: u64,
}

impl Randomness {
    fn new(keys: &Keys, aux: &[u8; 32], request: &[u8]) -> Randomness {
        let mut h = Keccak512::new();
        h.update(b"maki monero transaction");
        h.update(keys.spend().as_bytes());
        h.update(aux);
        h.update(request);
        Randomness { seed: h.finalize().into(), count: 0 }
    }

    fn wide(&mut self) -> [u8; 64] {
        let mut h = Keccak512::new();
        h.update(self.seed);
        h.update(self.count.to_le_bytes());
        self.count += 1;
        h.finalize().into()
    }

    /// Uniform, and never zero.
    fn scalar(&mut self) -> Scalar {
        loop {
            let mut wide = self.wide();
            let s = Scalar::from_bytes_mod_order_wide(&wide);
            wide.zeroize();
            if s != Scalar::ZERO {
                return s;
            }
        }
    }

    /// Uniform below `n`.
    fn below(&mut self, n: u64) -> u64 {
        let limit = u64::MAX - u64::MAX % n;
        loop {
            let x = u64::from_le_bytes(self.wide()[..8].try_into().unwrap());
            if x < limit {
                return x % n;
            }
        }
    }
}

impl Drop for Randomness {
    fn drop(&mut self) { self.seed.zeroize(); }
}

/// An input, as it's spent.
struct Spend {
    /// which of the request's inputs it is
    which: usize,
    amount: u64,
    secret: Scalar,
    /// its commitment's mask
    mask: Scalar,
    image: [u8; 32],
    real: usize,
    ring: Vec<Member>,
    globals: Vec<u64>,
}

impl Drop for Spend {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.mask.zeroize();
    }
}

/// An output, before it's made: where it goes.
struct Out {
    paid: Paid,
    spend: EdwardsPoint,
    view: EdwardsPoint,
    subaddress: bool,
    amount: u64,
    /// the address's keys, to tell addresses apart as wallet2 does
    address: [u8; 64],
}

fn address_bytes(spend: &[u8; 32], view: &[u8; 32]) -> [u8; 64] {
    let mut a = [0u8; 64];
    a[..32].copy_from_slice(spend);
    a[32..].copy_from_slice(view);
    a
}

/// Monero's biggest transaction weight, and the most its extra holds.
const MAX_WEIGHT: usize = 149_400;
const MAX_EXTRA: usize = 1060;

/// The transaction for `request`, signed with `keys`, the account's. `aux` is fresh randomness.
pub fn sign(keys: &Keys, request: &Request, aux: &[u8; 32]) -> Result<Signed, SpendError> {
    let mut generators = Generators::new();
    sign_with(keys, request, aux, &mut generators)
}

/// The same, keeping the range proof's generators for the next.
pub fn sign_with(keys: &Keys, request: &Request, aux: &[u8; 32], generators: &mut Generators) -> Result<Signed, SpendError> {
    let mut random = Randomness::new(keys, aux, &request.to_bytes());
    let account = request.account;

    // what's spent: each input this wallet's, and its amount what its commitment hides
    let mut spends = Vec::with_capacity(request.inputs.len());
    for (i, input) in request.inputs.iter().enumerate() {
        let tx_key = point(&input.tx_key).ok_or(SpendError::NotOurs(i))?;
        let ring = input
            .ring
            .iter()
            .map(|m| Some(Member { key: point(&m.key)?, commitment: point(&m.commitment)? }))
            .collect::<Option<Vec<_>>>()
            .ok_or(SpendError::Point)?;
        let real = &ring[input.real];
        let mut secret = keys.output_secret(&tx_key, input.index, account, input.subaddress);
        if G * secret != real.key {
            secret.zeroize();
            return Err(SpendError::NotOurs(i));
        }
        // a coinbase output's mask is 1
        let mut mask = keys.output_mask(&tx_key, input.index);
        if commit(&mask, input.amount) != real.commitment {
            mask = Scalar::ONE;
            if commit(&mask, input.amount) != real.commitment {
                secret.zeroize();
                return Err(SpendError::Amount(i));
            }
        }
        let image = sign::key_image(&secret, &real.key).compress().to_bytes();
        spends.push(Spend {
            which: i,
            amount: input.amount,
            secret,
            mask,
            image,
            real: input.real,
            globals: input.ring.iter().map(|m| m.global).collect(),
            ring,
        });
    }
    // Monero's order: key images from the greatest, byte by byte
    spends.sort_by_key(|s| core::cmp::Reverse(s.image));
    if spends.windows(2).any(|w| w[0].image == w[1].image) {
        return Err(SpendError::Twice);
    }

    // where it goes: the payments, the change to the account's own address, or, with none and
    // one payment, nothing to an address nobody has, which wallet2 takes as the change address
    let mut outs = Vec::with_capacity(request.outputs());
    for (i, p) in request.payments.iter().enumerate() {
        let (spend, view) = (point(&p.destination.spend), point(&p.destination.view));
        let (Some(spend), Some(view)) = (spend, view) else { return Err(SpendError::Point) };
        outs.push(Out {
            paid: Paid::Payment(i as u8),
            spend,
            view,
            subaddress: p.destination.kind == Kind::Subaddress,
            amount: p.amount,
            address: address_bytes(&p.destination.spend, &p.destination.view),
        });
    }
    let change_address = if request.change > 0 {
        let (spend, view) = keys.subaddress_points(account, 0);
        let address = address_bytes(&spend.compress().to_bytes(), &view.compress().to_bytes());
        outs.push(Out { paid: Paid::Change, spend, view, subaddress: account != 0, amount: request.change, address });
        address
    } else if request.payments.len() == 1 {
        let (spend, view) = (G * random.scalar(), G * random.scalar());
        let address = address_bytes(&spend.compress().to_bytes(), &view.compress().to_bytes());
        outs.push(Out { paid: Paid::Dummy, spend, view, subaddress: false, amount: 0, address });
        address
    } else {
        // no change: an address nothing matches
        [0u8; 64]
    };
    if outs.len() > MAX_OUTPUTS || outs.len() < 2 {
        return Err(SpendError::TooBig);
    }

    // the addresses paid, the change's aside: to one subaddress alone, the transaction's key is
    // r times its spend key; to a subaddress and anything else, each output has a key of its own
    let mut distinct: Vec<&Out> = Vec::new();
    for o in outs.iter().filter(|o| o.address != change_address) {
        if !distinct.iter().any(|d| d.address == o.address) {
            distinct.push(o);
        }
    }
    let subaddresses = distinct.iter().filter(|o| o.subaddress).count();
    let standard = distinct.len() - subaddresses;
    let additional = subaddresses > 0 && (standard > 0 || subaddresses > 1);
    let mut r = random.scalar();
    let tx_public = match distinct.iter().find(|o| o.subaddress) {
        Some(single) if standard == 0 && subaddresses == 1 => single.spend * r,
        _ => G * r,
    };
    // whose view key the payment ID is encrypted to: the one place paid, or the change's
    let view_key_pub = {
        let paid: Vec<&Out> = outs.iter().filter(|o| o.amount > 0 && o.address != change_address).collect();
        match paid.first() {
            Some(first) if paid.iter().all(|o| o.address == first.address) => Some(first.view),
            Some(_) => None,
            None => outs.iter().find(|o| o.address == change_address).map(|o| o.view),
        }
    };
    drop(distinct);

    // the outputs in an order of maki's choosing, as wallet2 shuffles them
    for i in (1..outs.len()).rev() {
        let j = random.below(i as u64 + 1) as usize;
        outs.swap(i, j);
    }
    let mut extra_keys: Vec<Scalar> = if additional { (0..outs.len()).map(|_| random.scalar()).collect() } else { Vec::new() };

    let (view, spend_key) = (keys.view(), keys.spend());
    let mut made = Vec::with_capacity(outs.len());
    let mut additional_public = Vec::with_capacity(extra_keys.len());
    let mut own = Vec::new();
    for (i, o) in outs.iter().enumerate() {
        if additional {
            let s = &extra_keys[i];
            additional_public.push(if o.subaddress { o.spend * s } else { G * s }.compress().to_bytes());
        }
        // change comes back with the account's view key; to a subaddress, with an output's own key
        let mut shared = if o.address == change_address {
            derivation(view, &tx_public)
        } else if additional && o.subaddress {
            derivation(&extra_keys[i], &o.view)
        } else {
            derivation(&r, &o.view)
        };
        let out = sign::output(&shared, i as u64, &o.spend, o.amount);
        if o.paid == Paid::Change {
            let mut secret = output_scalar(&shared, i as u64) + spend_key;
            if account != 0 {
                let mut m = keys.subaddress_scalar(account, 0);
                secret += m;
                m.zeroize();
            }
            let key = point(&out.key).expect("an output's key is a point");
            own.push((i as u8, sign::key_image(&secret, &key).compress().to_bytes()));
            secret.zeroize();
        }
        shared.zeroize();
        made.push(out);
    }

    // extra: the transaction's key, the outputs' own keys, and a payment ID, encrypted
    let mut extra = Vec::with_capacity(44 + 33 * additional_public.len());
    extra.push(1);
    extra.extend_from_slice(tx_public.compress().as_bytes());
    if additional {
        extra.push(4);
        sign::varint(additional_public.len() as u64, &mut extra);
        additional_public.iter().for_each(|k| extra.extend_from_slice(k));
    }
    let payment_id = request.payments.iter().find_map(|p| p.destination.payment_id);
    // a dummy one, of zeros, when there's no other and no more than two outputs
    let payment_id = payment_id.or((outs.len() <= 2).then_some([0u8; 8]));
    if let (Some(mut id), Some(key)) = (payment_id, view_key_pub) {
        let mut data = [0u8; 33];
        data[..32].copy_from_slice(&derivation(&r, &key));
        data[32] = 0x8d;
        let pad = keccak(&data);
        data.zeroize();
        id.iter_mut().zip(pad).for_each(|(b, p)| *b ^= p);
        extra.extend_from_slice(&[2, 9, 1]);
        extra.extend_from_slice(&id);
    }
    if extra.len() > MAX_EXTRA {
        return Err(SpendError::TooBig);
    }

    let prefix = Prefix {
        unlock_time: 0,
        inputs: spends
            .iter()
            .map(|s| tx::Input {
                key_offsets: s.globals.iter().scan(0u64, |last, g| Some(g - core::mem::replace(last, *g))).collect(),
                key_image: s.image,
            })
            .collect(),
        outputs: made.iter().map(|o| tx::Output { key: o.key, view_tag: o.view_tag }).collect(),
        extra,
    };
    let base = Base {
        fee: request.fee,
        encrypted_amounts: made.iter().map(|o| o.encrypted_amount).collect(),
        commitments: made.iter().map(|o| o.commitment).collect(),
    };
    let amounts: Vec<(u64, Scalar)> = outs.iter().zip(&made).map(|(o, m)| (o.amount, m.mask)).collect();
    let proof = bulletproof::prove(generators, &amounts, &mut || random.scalar()).ok_or(SpendError::TooBig)?;
    let message = tx::signature_hash(&prefix, &base, &proof);

    // the inputs' pseudo-outputs hide their amounts again, with masks adding up to the outputs'
    let sum: Scalar = made.iter().map(|o| o.mask).sum();
    let mut masks: Vec<Scalar>;
    loop {
        masks = (1..spends.len()).map(|_| random.scalar()).collect();
        masks.push(sum - masks.iter().sum::<Scalar>());
        // one equal to its input's own would make the signature's D nothing, which Monero refuses
        if masks.iter().zip(&spends).all(|(a, s)| *a != s.mask) {
            break;
        }
        masks.zeroize();
    }
    let mut clsags = Vec::with_capacity(spends.len());
    let mut pseudo_outs = Vec::with_capacity(spends.len());
    for (s, a) in spends.iter().zip(&masks) {
        let pseudo_out = commit(a, s.amount);
        let mut difference = s.mask - a;
        let mut nonce = random.wide();
        let signed = sign::clsag(&s.ring, s.real, &s.secret, &difference, &pseudo_out, &message, nonce[..32].try_into().unwrap());
        difference.zeroize();
        nonce.zeroize();
        let (clsag, _) = signed.map_err(|_| SpendError::Amount(s.which))?;
        clsags.push(clsag.to_bytes());
        pseudo_outs.push(pseudo_out.compress().to_bytes());
    }
    masks.zeroize();

    let transaction = Transaction { prefix, base, proof, clsags, pseudo_outs };
    let bytes = transaction.to_bytes();
    if weight(bytes.len(), outs.len()) > MAX_WEIGHT {
        return Err(SpendError::TooBig);
    }
    let signed = Signed {
        transaction: bytes,
        tx_key: r.to_bytes(),
        additional_keys: extra_keys.iter().map(|s| s.to_bytes()).collect(),
        outputs: outs.iter().map(|o| o.paid).collect(),
        own,
    };
    r.zeroize();
    extra_keys.zeroize();
    Ok(signed)
}

/// A transaction's weight, as fees and Monero's limit count it: its size, and for more than two
/// outputs, most of what a range proof for each alone would have taken more (the "clawback").
pub fn weight(size: usize, outputs: usize) -> usize {
    let padded = outputs.next_power_of_two();
    if padded <= 2 {
        return size;
    }
    let lr = padded.trailing_zeros() as usize + 6;
    let proof = 32 * (6 + 2 * lr);
    size + (320 * padded - proof) * 4 / 5
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn weights_are_monero_s() {
        // the clawback wallet2 and monerod add: none for two outputs, then 460, 1433, 3430
        assert_eq!(weight(1500, 2), 1500);
        assert_eq!(weight(1500, 3) - 1500, 460);
        assert_eq!(weight(1500, 4) - 1500, 460);
        assert_eq!(weight(1500, 5) - 1500, 1433);
        assert_eq!(weight(1500, 16) - 1500, 3430);
    }

    #[test]
    fn signed_reads_back() {
        let s = Signed {
            transaction: vec![1, 2, 3],
            tx_key: [7; 32],
            additional_keys: vec![[8; 32], [9; 32]],
            outputs: vec![Paid::Payment(0), Paid::Change, Paid::Dummy],
            own: vec![(1, [5; 32])],
        };
        assert_eq!(Signed::from_bytes(&s.to_bytes()), Some(s.clone()));
        let mut longer = s.to_bytes();
        longer.push(0);
        assert_eq!(Signed::from_bytes(&longer), None);
    }
}
