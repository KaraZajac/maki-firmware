//! Tokens maki knows, by their issuer and their currency's code: what they're called, and whose
//! they are. Any other shows its code and its issuer's address for the owner to check, since
//! anyone can issue a token by any name. Names come from this list alone, never from what a
//! token calls itself. Each issuer here is on its issuer's own page (Ripple's token addresses,
//! Circle's USDC contract addresses), and on the ledger it issues just this code.

use crate::address::{ALPHABET, AccountId};
use crate::codec::Currency;

/// A token maki knows.
pub struct Token {
    pub currency: Currency,
    pub issuer: AccountId,
    /// What maki calls it: `RLUSD`.
    pub symbol: &'static str,
    /// Whose it is, as a page says it: "Ripple".
    pub by: &'static str,
}

/// A currency's code of its own (not a standard three letters): the text, then zeros.
const fn code(text: &str) -> Currency {
    let t = text.as_bytes();
    assert!(!t.is_empty() && t.len() <= 20, "a code is 1 to 20 bytes");
    let mut out = [0u8; 20];
    let mut i = 0;
    while i < t.len() {
        out[i] = t[i];
        i += 1;
    }
    out
}

/// An account from its classic address, read when the program is built: the 20 bytes after
/// its version byte. Panics (so doesn't build) for anything that isn't 25 bytes of base58 with a
/// version of 0; its checksum is held to in the tests.
const fn account(address: &str) -> AccountId {
    let t = address.as_bytes();
    let mut bytes = [0u8; 25];
    let mut i = 0;
    while i < t.len() {
        let mut v = 0;
        while v < 58 && ALPHABET[v] != t[i] {
            v += 1;
        }
        assert!(v < 58, "not base58");
        let mut carry = v as u32;
        let mut j = 25;
        while j > 0 {
            j -= 1;
            carry += bytes[j] as u32 * 58;
            bytes[j] = carry as u8;
            carry >>= 8;
        }
        assert!(carry == 0, "more than 25 bytes");
        i += 1;
    }
    assert!(bytes[0] == 0, "not an account's address");
    let mut out = [0u8; 20];
    let mut k = 0;
    while k < 20 {
        out[k] = bytes[1 + k];
        k += 1;
    }
    out
}

/// The tokens maki knows: two stablecoins, each at the address its issuer's own page gives, on
/// the main network and the test network.
pub const TOKENS: &[Token] = &[
    Token {
        currency: code("RLUSD"),
        issuer: account("rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De"),
        symbol: "RLUSD",
        by: "Ripple",
    },
    Token {
        currency: code("USDC"),
        issuer: account("rGm7WCVp9gb4jZHWTEtGUr4dd74z2XuWhE"),
        symbol: "USDC",
        by: "Circle",
    },
    // the test network's, for trying things out
    Token {
        currency: code("RLUSD"),
        issuer: account("rQhWct2fv4Vc4KRjRgMrxa8xPN9Zx9iLKV"),
        symbol: "RLUSD",
        by: "Ripple, on the test network",
    },
    Token {
        currency: code("USDC"),
        issuer: account("rHuGNhqTG32mfmAvWA8hUyWRLV3tCSwKQt"),
        symbol: "USDC",
        by: "Circle, on the test network",
    },
];

/// The token `issuer` issues under `currency`, if maki knows it.
pub fn known(currency: &Currency, issuer: &AccountId) -> Option<&'static Token> {
    TOKENS.iter().find(|t| t.currency == *currency && t.issuer == *issuer)
}
