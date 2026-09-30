//! Tokens maki knows by their mint: what they're called, and their decimals. Any other shows its
//! mint's address, and amounts in the decimals the transfer says (which Solana checks against the
//! mint's). Names come from this list alone, never from what a token says of itself.

use crate::Key;
use crate::base58::key;

pub struct Token {
    pub mint: Key,
    pub symbol: &'static str,
    pub decimals: u8,
}

pub const TOKENS: &[Token] = &[
    Token { mint: key("So11111111111111111111111111111111111111112"), symbol: "wSOL", decimals: 9 },
    Token { mint: key("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"), symbol: "USDC", decimals: 6 },
    Token { mint: key("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"), symbol: "USDT", decimals: 6 },
    Token { mint: key("2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"), symbol: "PYUSD", decimals: 6 },
    // devnet's USDC (Circle's faucet), for trying things out
    Token { mint: key("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"), symbol: "USDC (devnet)", decimals: 6 },
];

pub fn known(mint: &Key) -> Option<&'static Token> { TOKENS.iter().find(|t| t.mint == *mint) }
