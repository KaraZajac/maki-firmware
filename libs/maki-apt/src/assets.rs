//! Assets maki knows: APT, and the dollars people hold on Aptos, by what alone says which asset each
//! is, on its own network: a coin by its type (where its module is, the module's name and its own),
//! a fungible asset by its metadata object's address. Another coin can be called `AptosCoin` in a
//! module called `aptos_coin`, and another asset can call itself USDC: they're just what they are,
//! and show as that. Names and decimals come from this list alone, never from what an asset says of
//! itself. Each was checked against the chain (its `CoinInfo` or `Metadata`, and a coin's paired
//! fungible asset, through Aptos Labs' fullnodes) on 2026-10-02.

use crate::call::Asset;
use crate::tx::StructTag;
use crate::{Address, Network};

/// What says which asset it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Id {
    /// A coin, by its type: `address::module::name`.
    Coin { address: Address, module: &'static str, name: &'static str },
    /// A fungible asset, by its metadata's address.
    Fungible(Address),
}

/// An asset maki knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Known {
    /// The network it's on.
    pub network: Network,
    pub id: Id,
    /// What maki calls it.
    pub symbol: &'static str,
    /// How many of its smallest units are one of it, as a power of ten.
    pub decimals: u8,
}

/// A hex digit's value, for the list below.
const fn digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("not hex"),
    }
}

/// An address written in hex (64 digits), for the list below.
const fn hex(text: &str) -> Address {
    let b = text.as_bytes();
    assert!(b.len() == 64);
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 64 {
        out[i / 2] = digit(b[i]) << 4 | digit(b[i + 1]);
        i += 2;
    }
    out
}

/// One of Aptos's own addresses, 0x0 to 0xf.
const fn special(n: u8) -> Address {
    let mut a = [0u8; 32];
    a[31] = n;
    a
}

/// LayerZero's bridge, whose USDC and USDT (coins) came before Circle's and Tether's own.
const LAYERZERO: Address = hex("f22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa");

const fn apt(network: Network) -> [Known; 2] {
    [
        Known {
            network,
            id: Id::Coin { address: special(1), module: "aptos_coin", name: "AptosCoin" },
            symbol: "APT",
            decimals: 8,
        },
        // APT as a fungible asset, which it is now: its coin's paired asset
        Known { network, id: Id::Fungible(special(0xa)), symbol: "APT", decimals: 8 },
    ]
}

/// Every asset maki knows.
pub const KNOWN: &[Known] = &[
    apt(Network::Mainnet)[0],
    apt(Network::Mainnet)[1],
    // Circle's USDC, and Tether's USDT (which it calls USDt), each made on Aptos itself
    Known {
        network: Network::Mainnet,
        id: Id::Fungible(hex("bae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b")),
        symbol: "USDC",
        decimals: 6,
    },
    Known {
        network: Network::Mainnet,
        id: Id::Fungible(hex("357b0b74bc833e95a115ad22604854d6b0fca151cecd94111770e5d6ffc9dc2b")),
        symbol: "USDT",
        decimals: 6,
    },
    // LayerZero's bridged USDC and USDT, as coins and as the fungible assets paired with them, by
    // the names Aptos's wallets and exchanges give them
    Known {
        network: Network::Mainnet,
        id: Id::Coin { address: LAYERZERO, module: "asset", name: "USDC" },
        symbol: "lzUSDC",
        decimals: 6,
    },
    Known {
        network: Network::Mainnet,
        id: Id::Fungible(hex("2b3be0a97a73c87ff62cbdd36837a9fb5bbd1d7f06a73b7ed62ec15c5326c1b8")),
        symbol: "lzUSDC",
        decimals: 6,
    },
    Known {
        network: Network::Mainnet,
        id: Id::Coin { address: LAYERZERO, module: "asset", name: "USDT" },
        symbol: "lzUSDT",
        decimals: 6,
    },
    Known {
        network: Network::Mainnet,
        id: Id::Fungible(hex("e568e9322107a5c9ba4cbd05a630a5586aa73e744ada246c3efb0f4ce3e295f3")),
        symbol: "lzUSDT",
        decimals: 6,
    },
    apt(Network::Testnet)[0],
    apt(Network::Testnet)[1],
    // Circle's USDC on the test network, the one its faucet gives, for trying things out
    Known {
        network: Network::Testnet,
        id: Id::Fungible(hex("69091fbab5f7d635ee7ac5098cf0c1efbe31d68fec0f2cd565e8d168daf52832")),
        symbol: "USDC (testnet)",
        decimals: 6,
    },
];

/// The asset maki knows that a coin it doesn't know borrows the name of, on this network: one called
/// `AptosCoin` in a module called `aptos_coin` that isn't APT, or one whose type is named as an asset
/// maki knows is (`USDC`).
pub fn lookalike(network: Network, coin: &StructTag) -> Option<&'static Known> {
    if known(network, &Asset::Coin(coin.clone())).is_some() {
        return None;
    }
    let mine = KNOWN.iter().filter(|k| k.network == network);
    mine.clone()
        .find(|k| matches!(k.id, Id::Coin { module, name, .. } if coin.module == module && coin.name == name))
        .or_else(|| mine.clone().find(|k| coin.name.eq_ignore_ascii_case(k.symbol)))
}

/// The asset maki knows this is, on this network.
pub fn known(network: Network, asset: &Asset) -> Option<&'static Known> {
    KNOWN.iter().filter(|k| k.network == network).find(|k| match (asset, k.id) {
        (Asset::Apt, Id::Fungible(a)) => a == special(0xa),
        (Asset::Coin(t), Id::Coin { address, module, name }) => t.is(&address, module, name),
        (Asset::Fungible(a), Id::Fungible(b)) => *a == b,
        _ => false,
    })
}
