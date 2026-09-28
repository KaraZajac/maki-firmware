//! Tokens maki knows by their contracts: enough to say "1.5 USDC" where it would say "1500000
//! in its smallest units" of a contract. Only the contract, on its own network, says which token
//! it is: a contract anywhere else with the same symbol is just a contract, and shows as one.
//! Each was checked against the contract itself (its `symbol()` and `decimals()`) on
//! 2026-09-28; maki desktop carries the same table (desktop/src/shared/tokens.ts), and a test
//! there keeps the two alike.

use alloc::format;
use alloc::string::String;

pub struct Token {
    pub chain_id: u64,
    pub contract: [u8; 20],
    pub symbol: &'static str,
    pub decimals: u8,
}

const fn hex20(s: &str) -> [u8; 20] {
    let b = s.as_bytes();
    let mut out = [0u8; 20];
    let mut i = 0;
    while i < 20 {
        out[i] = (nibble(b[2 + i * 2]) << 4) | nibble(b[3 + i * 2]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("not hex"),
    }
}

const fn token(chain_id: u64, contract: &str, symbol: &'static str, decimals: u8) -> Token {
    Token { chain_id, contract: hex20(contract), symbol, decimals }
}

pub const TOKENS: [Token; 19] = [
    token(1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "USDC", 6),
    token(1, "0xdAC17F958D2ee523a2206206994597C13D831ec7", "USDT", 6),
    token(1, "0x6B175474E89094C44Da98b954EedeAC495271d0F", "DAI", 18),
    token(1, "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "WETH", 18),
    token(1, "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", "WBTC", 8),
    token(8453, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "USDC", 6),
    token(8453, "0x4200000000000000000000000000000000000006", "WETH", 18),
    token(10, "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", "USDC", 6),
    token(10, "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58", "USDT", 6),
    token(10, "0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1", "DAI", 18),
    token(10, "0x4200000000000000000000000000000000000006", "WETH", 18),
    token(42161, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "USDC", 6),
    token(42161, "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", "USDT0", 6),
    token(42161, "0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1", "DAI", 18),
    token(42161, "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", "WETH", 18),
    token(137, "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", "USDC", 6),
    token(137, "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", "USDT0", 6),
    token(137, "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063", "DAI", 18),
    token(137, "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619", "WETH", 18),
];

/// The token this contract is on this network, if maki knows it.
pub fn known(chain_id: u64, contract: &[u8; 20]) -> Option<&'static Token> {
    TOKENS.iter().find(|t| t.chain_id == chain_id && t.contract == *contract)
}

/// An amount of it, exactly, and its symbol: "1.5 USDC".
pub fn amount(token: &Token, smallest: &[u8; 32]) -> String {
    let digits = crate::display::decimal(smallest);
    let places = token.decimals as usize;
    let (whole, frac) = if digits.len() > places {
        (String::from(&digits[..digits.len() - places]), String::from(&digits[digits.len() - places..]))
    } else {
        (String::from("0"), format!("{:0>width$}", digits, width = places))
    };
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() { format!("{} {}", whole, token.symbol) } else { format!("{}.{} {}", whole, frac, token.symbol) }
}
