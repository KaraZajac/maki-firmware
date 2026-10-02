//! Coins maki knows by their type: what they're called, and their decimals. Only the type, on its
//! own network, says which coin it is: a type anywhere else with the same name is just a type, and
//! shows as one. Names come from this list alone, never from what a coin says of itself. The
//! stablecoins are those Sui's protocol lets go without a fee (sui-protocol-config's
//! `gasless_allowed_token_types`, mainnet-v1.80.1); each entry's decimals and symbol were checked
//! against the coin's own metadata (Sui's GraphQL service, `coinMetadata`) on 2026-10-01.

use crate::tx::{FRAMEWORK, TypeTag};
use crate::{Address, Network, bytes32};

/// A coin maki knows.
pub struct Token {
    /// The network it's on.
    pub network: Network,
    /// The package that defines its type.
    pub package: Address,
    /// Its type's module, as `usdc` in `0x…::usdc::USDC`.
    pub module: &'static str,
    /// Its type's name, as `USDC` in `0x…::usdc::USDC`.
    pub name: &'static str,
    /// What maki calls it.
    pub symbol: &'static str,
    /// How many of its smallest units are one of it, as a power of ten.
    pub decimals: u8,
}

impl Token {
    /// Its type.
    pub fn type_tag(&self) -> TypeTag {
        TypeTag::Struct(alloc::boxed::Box::new(crate::tx::StructTag {
            address: self.package,
            module: self.module.into(),
            name: self.name.into(),
            params: alloc::vec::Vec::new(),
        }))
    }

    /// Whether `t` is its type.
    pub fn is(&self, t: &TypeTag) -> bool {
        matches!(t, TypeTag::Struct(s) if s.address == self.package && s.module == self.module
            && s.name == self.name && s.params.is_empty())
    }
}

const fn token(
    network: Network,
    package: &str,
    module: &'static str,
    name: &'static str,
    symbol: &'static str,
    decimals: u8,
) -> Token {
    Token { network, package: bytes32(package), module, name, symbol, decimals }
}

/// SUI itself, on both networks: `0x2::sui::SUI`, nine decimals (a MIST is a billionth).
pub const SUI: [Token; 2] = [
    Token {
        network: Network::Mainnet,
        package: FRAMEWORK,
        module: "sui",
        name: "SUI",
        symbol: "SUI",
        decimals: 9,
    },
    Token {
        network: Network::Testnet,
        package: FRAMEWORK,
        module: "sui",
        name: "SUI",
        symbol: "SUI",
        decimals: 9,
    },
];

/// Every other coin maki knows.
pub const TOKENS: &[Token] = &[
    // Circle's USDC, issued on Sui itself
    token(
        Network::Mainnet,
        "dba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7",
        "usdc",
        "USDC",
        "USDC",
        6,
    ),
    token(
        Network::Mainnet,
        "44f838219cf67b058f3b37907b655f226153c18e33dfcd0da559a844fea9b1c1",
        "usdsui",
        "USDSUI",
        "USDSUI",
        6,
    ),
    token(
        Network::Mainnet,
        "41d587e5336f1c86cad50d38a7136db99333bb9bda91cea4ba69115defeb1402",
        "sui_usde",
        "SUI_USDE",
        "suiUSDe",
        6,
    ),
    token(
        Network::Mainnet,
        "960b531667636f39e85867775f52f6b1f220a058c4de786905bdf761e06a56bb",
        "usdy",
        "USDY",
        "USDY",
        6,
    ),
    token(
        Network::Mainnet,
        "f16e6b723f242ec745dfd7634ad072c42d5c1d9ac9d62a39c381303eaa57693a",
        "fdusd",
        "FDUSD",
        "FDUSD",
        6,
    ),
    token(
        Network::Mainnet,
        "2053d08c1e2bd02791056171aab0fd12bd7cd7efad2ab8f6b9c8902f14df2ff2",
        "ausd",
        "AUSD",
        "AUSD",
        6,
    ),
    token(
        Network::Mainnet,
        "e14726c336e81b32328e92afc37345d159f5b550b09fa92bd43640cfdd0a0cfd",
        "usdb",
        "USDB",
        "USDB",
        6,
    ),
    // Walrus's WAL and DeepBook's DEEP, Sui's own projects' coins
    token(
        Network::Mainnet,
        "356a26eb9e012a68958082340d4c4116e7f55615cf27affcff209cf0ae544f59",
        "wal",
        "WAL",
        "WAL",
        9,
    ),
    token(
        Network::Mainnet,
        "deeb7a4662eec9f2f3def03fb937a663dddaa2e215b8078a284d026b7946c270",
        "deep",
        "DEEP",
        "DEEP",
        6,
    ),
    // Circle's USDC on the test network, the one its faucet gives
    token(
        Network::Testnet,
        "a1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29",
        "usdc",
        "USDC",
        "USDC (testnet)",
        6,
    ),
];

/// The coin `t` is on `network`, if maki knows it: SUI, or one of `TOKENS`.
pub fn known(network: Network, t: &TypeTag) -> Option<&'static Token> {
    SUI.iter().chain(TOKENS).find(|k| k.network == network && k.is(t))
}

/// The network a coin of type `t` is on, if maki knows it on one alone: a token's type names its
/// network, whatever the computer says.
pub fn network_of(t: &TypeTag) -> Option<Network> {
    let mut on = TOKENS.iter().filter(|k| k.is(t)).map(|k| k.network);
    let first = on.next()?;
    on.all(|n| n == first).then_some(first)
}
