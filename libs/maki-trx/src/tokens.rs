//! TRC-20 tokens maki knows by their contract: what they're called, and their decimals. Only the
//! contract, on its own network, says which token it is: a contract anywhere else with the same
//! symbol is just a contract, and shows as one. Names come from this list alone, never from what a
//! token says of itself. Each was checked against the contract itself (its `symbol()` and
//! `decimals()`, through TronGrid) on 2026-10-01.

use crate::base58::address;
use crate::{Address, Network};

/// A token maki knows.
pub struct Token {
    /// The network its contract is on.
    pub network: Network,
    /// Its contract: what says which token it is.
    pub contract: Address,
    /// What maki calls it.
    pub symbol: &'static str,
    /// How many of its smallest units are one of it, as a power of ten.
    pub decimals: u8,
}

/// Every token maki knows.
pub const TOKENS: &[Token] = &[
    Token {
        network: Network::Tron,
        contract: address("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"),
        symbol: "USDT",
        decimals: 6,
    },
    // Circle's USDC on Tron: Circle stopped making it in February 2024 and stopped standing behind
    // it on Tron after February 2025; what's left still moves, and explorers call it USDCOLD
    Token {
        network: Network::Tron,
        contract: address("TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8"),
        symbol: "USDC (old)",
        decimals: 6,
    },
    // USDD as it's been since January 2025 (its first contract, TPYmHEhy..., is USDDOLD)
    Token {
        network: Network::Tron,
        contract: address("TXDk8mbtRbXeYuMNS83CfKPaYYT8XWv9Hz"),
        symbol: "USDD",
        decimals: 18,
    },
    Token {
        network: Network::Tron,
        contract: address("TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR"),
        symbol: "WTRX",
        decimals: 6,
    },
    // Nile's USDT, the one its faucet gives, for trying things out
    Token {
        network: Network::Nile,
        contract: address("TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"),
        symbol: "USDT (Nile)",
        decimals: 6,
    },
];

/// The token this contract is on this network, if maki knows it.
pub fn known(network: Network, contract: &Address) -> Option<&'static Token> {
    TOKENS.iter().find(|t| t.network == network && t.contract == *contract)
}
