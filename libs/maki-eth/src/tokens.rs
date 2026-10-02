//! Tokens maki knows by their contracts: enough to say "1.5 USDC" where it would say "1500000
//! in its smallest units" of a contract. Only the contract, on its own network, says which token
//! it is: a contract anywhere else with the same symbol is just a contract, and shows as one.
//! Each was checked against the contract itself (its `symbol()` and `decimals()`) on
//! 2026-09-28, the networks added since on 2026-10-02; maki desktop carries the same table
//! (desktop/src/shared/tokens.ts), and a test there keeps the two alike.
//!
//! On each network: the stablecoins their issuers make there, from the issuer's own list
//! (Circle's for USDC, developers.circle.com/stablecoins/usdc-contract-addresses; Tether's for
//! USDT, tether.to/en/supported-protocols; USDT0's, docs.usdt0.to/technical-documentation/
//! deployments; Paxos's for USDG, docs.paxos.com/guides/stablecoin/usdg/mainnet; Binance's own
//! deposit networks for BNB Chain's, which Binance makes), and WETH where the network's
//! documentation or canonical bridge names one. A token bridged from elsewhere by a third party
//! (Gnosis's USDC.e) goes by its own symbol, never by the original's. Symbols are as their
//! contracts give them, in ASCII: USDT0's contracts call themselves USD₮0 on some networks, and
//! Tether's USD₮ (Celo) or USDt (Avalanche); maki's screen shows them as USDT0 and USDT.

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

pub const TOKENS: [Token; 52] = [
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
    // BNB Chain: Binance's own (Binance-Peg), with 18 decimals, not the 6 USDT and USDC have
    // elsewhere; Tether and Circle make none there
    token(56, "0x55d398326f99059fF775485246999027B3197955", "USDT", 18),
    token(56, "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", "USDC", 18),
    // Avalanche: Circle's and Tether's
    token(43114, "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", "USDC", 6),
    token(43114, "0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7", "USDT", 6),
    // Robinhood Chain: Paxos's USDG, and WETH (docs.robinhood.com/chain/contracts)
    token(4663, "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168", "USDG", 6),
    token(4663, "0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73", "WETH", 18),
    // HyperEVM
    token(999, "0xb88339CB7199b77E23DB6E890353E22632Ba630f", "USDC", 6),
    token(999, "0xB8CE59FC3717ada4C02eaDF9682A9e934F625ebb", "USDT0", 6),
    // Monad
    token(143, "0x754704Bc059F8C67012fEd69BC8A327a5aafb603", "USDC", 6),
    token(143, "0xe7cd86e13AC4309349F30B3435a9d337750fC82D", "USDT0", 6),
    // Mantle: USDT0, and ether from Ethereum through Mantle's bridge, which calls itself WETH
    // (github.com/mantlenetworkio/mantle-token-lists)
    token(5000, "0x779Ded0c9e1022225f8E0630b35a9b54bE713736", "USDT0", 6),
    token(5000, "0xdEAddEaDdeadDEadDEADDEAddEADDEAddead1111", "WETH", 18),
    // Plasma
    token(9745, "0xB8CE59FC3717ada4C02eaDF9682A9e934F625ebb", "USDT0", 6),
    token(9745, "0x2d661C89D812261039AF9764eceaAee884f5F67F", "USDC", 6),
    // X Layer
    token(196, "0x779Ded0c9e1022225f8E0630b35a9b54bE713736", "USDT0", 6),
    token(196, "0xB6CEceAB302E2E4948951eE7843FC24E92933061", "USDC", 6),
    token(196, "0x4ae46a509F6b1D9056937BA4500cb143933D2dc8", "USDG", 6),
    // Arc: its coin, USDC, as an ERC-20 too (docs.arc.io): the same balance, in 6 decimals
    token(5042, "0x3600000000000000000000000000000000000000", "USDC", 6),
    // World Chain (docs.world.org, Useful contracts)
    token(480, "0x79A02482A880bCE3F13e09Da970dC34db4CD24d1", "USDC", 6),
    token(480, "0x4200000000000000000000000000000000000006", "WETH", 18),
    // Ink; its WETH is the OP Stack's (specs.optimism.io, Predeploys)
    token(57073, "0x2D270e6886d130D724215A266106e6832161EAEd", "USDC", 6),
    token(57073, "0x0200C29006150606B650577BBE7B6248F58470c1", "USDT0", 6),
    token(57073, "0xe343167631d89B6Ffc58B88d6b7fB0228795491D", "USDG", 6),
    token(57073, "0x4200000000000000000000000000000000000006", "WETH", 18),
    // Linea (Consensys's linea-token-list)
    token(59144, "0x176211869cA2b568f2A7D4EE941E073a821EE1ff", "USDC", 6),
    token(59144, "0xe5D7C2a44FfDDf6b295A15c148167daaAf5Cf34f", "WETH", 18),
    // Gnosis: no USDC of Circle's, but USDC.e, Circle's standard for USDC bridged by others,
    // here by Gnosis's own bridge (docs.gnosischain.com)
    token(100, "0x2a22f9c3b484c3629090FeED35F17Ff8F88f76F0", "USDC.e", 6),
    // ZKsync Era
    token(324, "0x1d17CBcF0D6D143135aE902365D2E5e2A16538D4", "USDC", 6),
    // Celo (docs.celo.org, Stablecoin contracts)
    token(42220, "0xcebA9300f2b948710d2653dD7B07f33A8B32118C", "USDC", 6),
    token(42220, "0x48065fbBE25f71C9282ddf5e1cD6D6A887483D5e", "USDT", 6),
    // Unichain (developers.uniswap.org, Unichain's contract addresses)
    token(130, "0x078D782b760474a361dDA0AF3839290b0EF57AD6", "USDC", 6),
    token(130, "0x9151434b16b9763660705744891fA906F660EcC5", "USDT0", 6),
    token(130, "0x4200000000000000000000000000000000000006", "WETH", 18),
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
    if frac.is_empty() {
        format!("{} {}", whole, token.symbol)
    } else {
        format!("{}.{} {}", whole, frac, token.symbol)
    }
}
