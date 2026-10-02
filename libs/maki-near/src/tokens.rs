//! NEP-141 tokens maki knows by their contract: what they're called, and their decimals. Only the
//! contract, on its own network, says which token it is: a contract anywhere else is just a
//! contract, and shows as one. Names come from this list alone, never from what a token says of
//! itself. Each was checked against the contract itself (its `ft_metadata`, through FastNEAR's
//! RPC) on 2026-10-02; the first three, and the test network's wNEAR, are in near-api-js 7.3's own
//! lists too.

use crate::Network;

/// A token maki knows.
pub struct Token {
    /// The network its contract is on.
    pub network: Network,
    /// Its contract's account: what says which token it is.
    pub contract: &'static str,
    /// What maki calls it.
    pub symbol: &'static str,
    /// How many of its smallest units are one of it, as a power of ten.
    pub decimals: u8,
}

/// Every token maki knows.
pub const TOKENS: &[Token] = &[
    // Circle's own USDC on NEAR: its contract is an implicit account
    Token {
        network: Network::Mainnet,
        contract: "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1",
        symbol: "USDC",
        decimals: 6,
    },
    // Tether's own (its contract calls it USDt)
    Token { network: Network::Mainnet, contract: "usdt.tether-token.near", symbol: "USDT", decimals: 6 },
    // NEAR wrapped as a token, one for one
    Token { network: Network::Mainnet, contract: "wrap.near", symbol: "wNEAR", decimals: 24 },
    // USDC and USDT brought over from Ethereum by the Rainbow Bridge, as NEAR's wallets call them
    Token {
        network: Network::Mainnet,
        contract: "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.factory.bridge.near",
        symbol: "USDC.e",
        decimals: 6,
    },
    Token {
        network: Network::Mainnet,
        contract: "dac17f958d2ee523a2206206994597c13d831ec7.factory.bridge.near",
        symbol: "USDT.e",
        decimals: 6,
    },
    // Circle's USDC on the test network, the one its faucet gives, for trying things out
    Token {
        network: Network::Testnet,
        contract: "3e2210e1184b45b64c8a434c0a7e7b23cc04ea7eb7a6c3c32520d03d4afcb8af",
        symbol: "USDC (testnet)",
        decimals: 6,
    },
    Token { network: Network::Testnet, contract: "wrap.testnet", symbol: "wNEAR (testnet)", decimals: 24 },
];

/// The token this contract is on this network, if maki knows it.
pub fn known(network: Network, contract: &str) -> Option<&'static Token> {
    TOKENS.iter().find(|t| t.network == network && t.contract == contract)
}

/// The network a token's contract is on, if maki knows it on either: a call to it is for that
/// network, whatever the computer says.
pub fn network_of(contract: &str) -> Option<Network> {
    TOKENS.iter().find(|t| t.contract == contract).map(|t| t.network)
}
