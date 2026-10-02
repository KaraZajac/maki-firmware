//! GF(2^8), the field shares are computed in: a byte is a polynomial over GF(2), adding is XOR, and
//! multiplying is reduced by x^8 + x^4 + x^3 + x + 1 (0x11b, AES's), as bc-shamir's `hazmat` does
//! it. Neither function looks a byte up in a table or branches on one, so how long they take says
//! nothing about the secret.

/// a × b.
pub fn mul(a: u8, b: u8) -> u8 {
    let (mut a, mut b, mut product) = (a, b, 0u8);
    for _ in 0..8 {
        // add a if b's lowest bit is set, then a × x, reduced if it reached x^8
        product ^= a & (b & 1).wrapping_neg();
        a = (a << 1) ^ (0x1b & (a >> 7).wrapping_neg());
        b >>= 1;
    }
    product
}

/// 1 / a, as a^254 (every a but 0 has a^255 = 1); 0 for 0, as bc-shamir's `gf256_inv` gives.
pub fn inv(a: u8) -> u8 {
    // a^254 = a^2 · a^4 · a^8 · … · a^128
    let (mut power, mut result) = (a, 1u8);
    for _ in 1..8 {
        power = mul(power, power);
        result = mul(result, power);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The slow way: shift and add, reducing at the end.
    fn mul_by_hand(a: u8, b: u8) -> u8 {
        let mut wide = 0u16;
        for i in 0..8 {
            if b >> i & 1 == 1 {
                wide ^= (a as u16) << i;
            }
        }
        for i in (8..16).rev() {
            if wide >> i & 1 == 1 {
                wide ^= 0x11b << (i - 8);
            }
        }
        wide as u8
    }

    #[test]
    fn multiplies_and_inverts() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(mul(a, b), mul_by_hand(a, b), "{a} × {b}");
            }
            if a != 0 {
                assert_eq!(mul(a, inv(a)), 1, "1 / {a}");
            }
        }
        assert_eq!(inv(0), 0);
        // FIPS 197's examples: {57} × {83} = {c1}, {57} × {13} = {fe}
        assert_eq!(mul(0x57, 0x83), 0xc1);
        assert_eq!(mul(0x57, 0x13), 0xfe);
    }
}
