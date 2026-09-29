//! Bulletproofs+, the range proof a Monero transaction carries for its outputs: that each amount
//! its commitments hide is less than 2^64, without saying what it is. Proving only: the node
//! checks it. Monero's (`src/ringct/bulletproofs_plus.cc`), ported from monero-oxide's
//! monero-bulletproofs (MIT) onto maki's dalek, with the generators made as a proof needs them
//! and kept for the next.
#![allow(non_snake_case)]

use alloc::vec::Vec;

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{MultiscalarMul, VartimeMultiscalarMul};
use zeroize::Zeroize;

use crate::keccak;
use crate::sign::{commit, hash_to_point, hash_to_scalar, point, varint, G, H};
use crate::tx::RangeProof;

/// The most outputs one proof covers (and so a transaction has).
pub const MAX_OUTPUTS: usize = 16;
/// Bits an amount may have.
const BITS: usize = 64;

/// The generators proofs are made with, as many as the biggest proof so far has needed: making
/// them takes longer than a proof, so they're kept.
#[derive(Default)]
pub struct Generators {
    g: Vec<EdwardsPoint>,
    h: Vec<EdwardsPoint>,
}

impl Generators {
    pub const fn new() -> Generators { Generators { g: Vec::new(), h: Vec::new() } }

    /// At least `n` of each: generator i of H is Monero's hash onto the curve of Keccak-256 of H ‖
    /// "bulletproof_plus" ‖ 2i, and of G the same of 2i + 1.
    fn make(&mut self, n: usize) {
        let mut preimage = Vec::with_capacity(32 + 16 + 10);
        while self.g.len() < n {
            let i = 2 * self.g.len() as u64;
            for (index, list) in [(i, 0), (i + 1, 1)] {
                preimage.clear();
                preimage.extend_from_slice(&H);
                preimage.extend_from_slice(b"bulletproof_plus");
                varint(index, &mut preimage);
                let generator = hash_to_point(&keccak(&preimage));
                if list == 0 { &mut self.h } else { &mut self.g }.push(generator);
            }
        }
    }
}

fn inv_eight() -> Scalar { Scalar::from(8u8).invert() }

fn amount_generator() -> EdwardsPoint { point(&H).expect("H is a point") }

/// What the transcript starts with: Monero's hash onto the curve of Keccak-256 of
/// "bulletproof_plus_transcript".
fn transcript_start() -> [u8; 32] { hash_to_point(&keccak(b"bulletproof_plus_transcript")).compress().to_bytes() }

fn transcript(parts: &[&[u8; 32]]) -> Scalar {
    let mut data = Vec::with_capacity(32 * parts.len());
    parts.iter().for_each(|p| data.extend_from_slice(*p));
    hash_to_scalar(&data)
}

/// Σ a_i b_i y^(i+1)
fn weighted_inner_product(a: &[Scalar], b: &[Scalar], y: &[Scalar]) -> Scalar {
    a.iter().zip(b).zip(y).map(|((a, b), y)| a * b * y).sum()
}

fn msm(scalars: Vec<Scalar>, points: &[EdwardsPoint]) -> EdwardsPoint {
    let mut scalars = scalars;
    let p = EdwardsPoint::multiscalar_mul(scalars.iter(), points.iter());
    scalars.zeroize();
    p
}

/// A proof that each of `outputs`' amounts, committed to with its mask (amount·H + mask·G), is
/// less than 2^64. `nonce` gives uniform scalars, secret ones; `generators` are kept for the next.
/// None for no outputs or more than MAX_OUTPUTS.
pub fn prove(generators: &mut Generators, outputs: &[(u64, Scalar)], nonce: &mut dyn FnMut() -> Scalar) -> Option<RangeProof> {
    let m = outputs.len();
    if m == 0 || m > MAX_OUTPUTS {
        return None;
    }
    let m_padded = m.next_power_of_two();
    let mn = m_padded * BITS;
    generators.make(mn);
    let (g_bold, h_bold) = (&generators.g[..mn], &generators.h[..mn]);
    let (g, h) = (amount_generator(), G);
    let inv8 = inv_eight();

    // the commitments, which the transcript takes eighths of
    let V: Vec<[u8; 32]> =
        outputs.iter().map(|(amount, mask)| (commit(mask, *amount) * inv8).compress().to_bytes()).collect();
    let mut V_all = Vec::with_capacity(32 * m);
    V.iter().for_each(|v| V_all.extend_from_slice(v));
    let mut transcript_now = transcript(&[&transcript_start(), &hash_to_scalar(&V_all).to_bytes()]);

    // the amounts' bits, and those less one
    let mut a_l: Vec<Scalar> = Vec::with_capacity(mn);
    for j in 0..m_padded {
        let amount = outputs.get(j).map_or(0, |o| o.0);
        a_l.extend((0..BITS).map(|bit| Scalar::from((amount >> bit) & 1)));
    }
    let mut a_r: Vec<Scalar> = a_l.iter().map(|a| a - Scalar::ONE).collect();

    let mut alpha = nonce();
    let mut A_scalars: Vec<Scalar> = a_l.iter().chain(&a_r).copied().collect();
    A_scalars.push(alpha);
    let A_points: Vec<EdwardsPoint> = g_bold.iter().chain(h_bold).copied().chain([h]).collect();
    let A = (msm(A_scalars, &A_points) * inv8).compress().to_bytes();

    let y = transcript(&[&transcript_now.to_bytes(), &A]);
    let z = hash_to_scalar(y.as_bytes());
    transcript_now = z;

    // z^2, z^4, ... one for each (padded) output
    let mut z_pow = Vec::with_capacity(m_padded);
    z_pow.push(z * z);
    for j in 1..m_padded {
        z_pow.push(z_pow[j - 1] * z_pow[0]);
    }
    // d: each output's 2^i, times its power of z
    let mut d = Vec::with_capacity(mn);
    for zp in &z_pow {
        let mut two = Scalar::ONE;
        for _ in 0..BITS {
            d.push(two * zp);
            two += two;
        }
    }
    // y^1 ... y^mn, and y^(mn+1)
    let mut y_pow = Vec::with_capacity(mn);
    y_pow.push(y);
    for i in 1..mn {
        y_pow.push(y_pow[i - 1] * y);
    }
    let y_mn_plus_one = y_pow[mn - 1] * y;

    for a in &mut a_l {
        *a -= z;
    }
    for (i, a) in a_r.iter_mut().enumerate() {
        // d times descending powers of y, plus z
        *a += d[i] * y_pow[mn - 1 - i] + z;
    }
    for (j, (_, mask)) in outputs.iter().enumerate() {
        alpha += z_pow[j] * mask * y_mn_plus_one;
    }

    let wip = weighted_inner_product_proof(g_bold, h_bold, g, h, y_pow, transcript_now, a_l, a_r, alpha, nonce);
    alpha.zeroize();
    Some(RangeProof { A, A1: wip.0, B: wip.1, r1: wip.2.to_bytes(), s1: wip.3.to_bytes(), d1: wip.4.to_bytes(), L: wip.5, R: wip.6 })
}

type Wip = ([u8; 32], [u8; 32], Scalar, Scalar, Scalar, Vec<[u8; 32]>, Vec<[u8; 32]>);

/// Figure 1 of the Bulletproofs+ paper: the weighted inner product argument.
#[allow(clippy::too_many_arguments)]
fn weighted_inner_product_proof(
    g_bold: &[EdwardsPoint],
    h_bold: &[EdwardsPoint],
    g: EdwardsPoint,
    h: EdwardsPoint,
    mut y: Vec<Scalar>,
    mut transcript_now: Scalar,
    mut a: Vec<Scalar>,
    mut b: Vec<Scalar>,
    mut alpha: Scalar,
    nonce: &mut dyn FnMut() -> Scalar,
) -> Wip {
    let inv8 = inv_eight();
    let mut g_bold = g_bold.to_vec();
    let mut h_bold = h_bold.to_vec();
    // y^-1, y^-2, y^-4, ... for each round, the last round's first
    let mut y_inv: Vec<Scalar> = {
        let mut i = 1;
        let mut out = Vec::new();
        while i < g_bold.len() {
            out.push(y[i - 1].invert());
            i *= 2;
        }
        out
    };
    let (mut L, mut R) = (Vec::new(), Vec::new());
    while g_bold.len() > 1 {
        let n_hat = g_bold.len() / 2;
        let (a1, a2) = a.split_at(n_hat);
        let (b1, b2) = b.split_at(n_hat);
        let (g1, g2) = g_bold.split_at(n_hat);
        let (h1, h2) = h_bold.split_at(n_hat);
        let y_n_hat = y[n_hat - 1];
        y.truncate(n_hat);

        let d_l = nonce();
        let d_r = nonce();
        let a2_y: Vec<Scalar> = a2.iter().map(|a| a * y_n_hat).collect();
        let c_l = weighted_inner_product(a1, b2, &y);
        let c_r = weighted_inner_product(&a2_y, b1, &y);
        let y_inv_n_hat = y_inv.pop().expect("one for each round");

        let mut scalars: Vec<Scalar> = a1.iter().map(|a| a * y_inv_n_hat).chain(b2.iter().copied()).collect();
        scalars.extend([c_l, d_l]);
        let points: Vec<EdwardsPoint> = g2.iter().chain(h1).copied().chain([g, h]).collect();
        let l = (msm(scalars, &points) * inv8).compress().to_bytes();

        let mut scalars: Vec<Scalar> = a2_y.iter().copied().chain(b1.iter().copied()).collect();
        scalars.extend([c_r, d_r]);
        let points: Vec<EdwardsPoint> = g1.iter().chain(h2).copied().chain([g, h]).collect();
        let r = (msm(scalars, &points) * inv8).compress().to_bytes();

        let e = transcript(&[&transcript_now.to_bytes(), &l, &r]);
        transcript_now = e;
        let inv_e = e.invert();
        L.push(l);
        R.push(r);

        // the next round's generators (public: variable time is fine)
        let e_y_inv = e * y_inv_n_hat;
        let new_g: Vec<EdwardsPoint> =
            g1.iter().zip(g2).map(|(p1, p2)| EdwardsPoint::vartime_multiscalar_mul([inv_e, e_y_inv], [p1, p2])).collect();
        let new_h: Vec<EdwardsPoint> =
            h1.iter().zip(h2).map(|(p1, p2)| EdwardsPoint::vartime_multiscalar_mul([e, inv_e], [p1, p2])).collect();

        let y_n_hat_inv_e = y_n_hat * inv_e;
        let new_a: Vec<Scalar> = a1.iter().zip(a2).map(|(x1, x2)| x1 * e + x2 * y_n_hat_inv_e).collect();
        let new_b: Vec<Scalar> = b1.iter().zip(b2).map(|(x1, x2)| x1 * inv_e + x2 * e).collect();
        alpha += d_l * (e * e) + d_r * (inv_e * inv_e);
        a.zeroize();
        b.zeroize();
        (a, b, g_bold, h_bold) = (new_a, new_b, new_g, new_h);
    }

    let mut r = nonce();
    let mut s = nonce();
    let mut delta = nonce();
    let mut eta = nonce();
    let ry = r * y[0];
    let A1 = (msm([r, s, ry * b[0] + s * y[0] * a[0], delta].to_vec(), &[g_bold[0], h_bold[0], g, h]) * inv8)
        .compress()
        .to_bytes();
    let B = (msm([ry * s, eta].to_vec(), &[g, h]) * inv8).compress().to_bytes();
    let e = transcript(&[&transcript_now.to_bytes(), &A1, &B]);
    let r1 = r + a[0] * e;
    let s1 = s + b[0] * e;
    let d1 = eta + delta * e + alpha * (e * e);
    for secret in [&mut a, &mut b] {
        secret.zeroize();
    }
    for secret in [&mut alpha, &mut r, &mut s, &mut delta, &mut eta] {
        secret.zeroize();
    }
    (A1, B, r1, s1, d1, L, R)
}
