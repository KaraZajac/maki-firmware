//! The chains maki knows: the Cosmos Hub, the chains of Cosmos that take its keys (SLIP-44's coin
//! type 118: the same key, the same address but for its prefix), and a test network of three of
//! them. Each by its chain ID, which a sign doc names and a signature covers: a chain maki doesn't
//! know, maki won't sign for, since it can't say what its coin is. Each was checked against the
//! chain registry (cosmos/chain-registry: its `chain.json` and `assetlist.json`) and against the
//! chain itself (its REST API's staking parameters) on 2026-10-02.
//!
//! And the IBC channels between them: a token from another chain is named for what it is only when
//! it came straight from its own chain, by the channel the registry has between the two (`token`).

use alloc::format;
use alloc::string::String;

use sha2::{Digest, Sha256};

/// Which kind of network a chain is, as a message's network byte says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// A chain whose coins are the real thing: byte 0.
    Main,
    /// A test network, whose coins are worth nothing: byte 1.
    Test,
}

impl Network {
    /// The network a message's byte names.
    pub fn from_byte(b: u8) -> Option<Network> {
        match b {
            0 => Some(Network::Main),
            1 => Some(Network::Test),
            _ => None,
        }
    }
}

/// A coin maki knows by its denom: what it calls it, and how many of its smallest units are one of
/// it, as a power of ten (the registry's `denom_units`).
#[derive(Debug, PartialEq, Eq)]
pub struct Token {
    pub denom: &'static str,
    pub symbol: &'static str,
    pub decimals: u8,
}

/// A chain maki knows.
#[derive(Debug, PartialEq, Eq)]
pub struct Chain {
    /// Its chain ID, as its sign docs name it.
    pub id: &'static str,
    /// What maki calls it.
    pub name: &'static str,
    pub network: Network,
    /// Its accounts' addresses' prefix (bech32's human-readable part); its validators' is this and
    /// `valoper`.
    pub prefix: &'static str,
    /// Its own coin: what it charges its fees in.
    pub coin: Token,
    /// The denom staked on it: its own coin's, but on Noble, whose coin is USDC.
    pub bond: &'static str,
    /// How long unstaking takes, in seconds (the staking module's `unbonding_time`, which its
    /// governance can change).
    pub unbonding: u32,
}

const DAY: u32 = 86_400;

/// Every chain maki knows: the main networks, then the test networks.
pub const CHAINS: &[Chain] = &[
    Chain {
        id: "cosmoshub-4",
        name: "Cosmos Hub",
        network: Network::Main,
        prefix: "cosmos",
        coin: Token { denom: "uatom", symbol: "ATOM", decimals: 6 },
        bond: "uatom",
        unbonding: 21 * DAY,
    },
    Chain {
        id: "osmosis-1",
        name: "Osmosis",
        network: Network::Main,
        prefix: "osmo",
        coin: Token { denom: "uosmo", symbol: "OSMO", decimals: 6 },
        bond: "uosmo",
        unbonding: 14 * DAY,
    },
    Chain {
        id: "celestia",
        name: "Celestia",
        network: Network::Main,
        prefix: "celestia",
        coin: Token { denom: "utia", symbol: "TIA", decimals: 6 },
        bond: "utia",
        unbonding: 14 * DAY + 3_600,
    },
    Chain {
        id: "dydx-mainnet-1",
        name: "dYdX",
        network: Network::Main,
        prefix: "dydx",
        coin: Token { denom: "adydx", symbol: "DYDX", decimals: 18 },
        bond: "adydx",
        unbonding: 21 * DAY,
    },
    Chain {
        id: "neutron-1",
        name: "Neutron",
        network: Network::Main,
        prefix: "neutron",
        coin: Token { denom: "untrn", symbol: "NTRN", decimals: 6 },
        bond: "untrn",
        unbonding: 20 * DAY,
    },
    // Circle's USDC, issued on Noble itself
    Chain {
        id: "noble-1",
        name: "Noble",
        network: Network::Main,
        prefix: "noble",
        coin: Token { denom: "uusdc", symbol: "USDC", decimals: 6 },
        bond: "ustake",
        unbonding: 21 * DAY,
    },
    Chain {
        id: "akashnet-2",
        name: "Akash",
        network: Network::Main,
        prefix: "akash",
        coin: Token { denom: "uakt", symbol: "AKT", decimals: 6 },
        bond: "uakt",
        unbonding: 21 * DAY,
    },
    Chain {
        id: "axelar-dojo-1",
        name: "Axelar",
        network: Network::Main,
        prefix: "axelar",
        coin: Token { denom: "uaxl", symbol: "AXL", decimals: 6 },
        bond: "uaxl",
        unbonding: 7 * DAY,
    },
    Chain {
        id: "bbn-1",
        name: "Babylon",
        network: Network::Main,
        prefix: "bbn",
        coin: Token { denom: "ubbn", symbol: "BABY", decimals: 6 },
        bond: "ubbn",
        unbonding: 21 * DAY,
    },
    Chain {
        id: "juno-1",
        name: "Juno",
        network: Network::Main,
        prefix: "juno",
        coin: Token { denom: "ujuno", symbol: "JUNO", decimals: 6 },
        bond: "ujuno",
        unbonding: 28 * DAY,
    },
    // the Cosmos Hub's public test network (the old theta-testnet-001 ended in 2024)
    Chain {
        id: "provider",
        name: "Cosmos Hub testnet",
        network: Network::Test,
        prefix: "cosmos",
        coin: Token { denom: "uatom", symbol: "ATOM", decimals: 6 },
        bond: "uatom",
        unbonding: 21 * DAY,
    },
    Chain {
        id: "osmo-test-5",
        name: "Osmosis testnet",
        network: Network::Test,
        prefix: "osmo",
        coin: Token { denom: "uosmo", symbol: "OSMO", decimals: 6 },
        bond: "uosmo",
        unbonding: 5 * DAY,
    },
    // Mocha, which went on as mocha-5 in 2026
    Chain {
        id: "mocha-5",
        name: "Celestia testnet",
        network: Network::Test,
        prefix: "celestia",
        coin: Token { denom: "utia", symbol: "TIA", decimals: 6 },
        bond: "utia",
        unbonding: 14 * DAY + 3_600,
    },
];

/// The chain whose ID this is, if maki knows it.
pub fn by_id(id: &str) -> Option<&'static Chain> { CHAINS.iter().find(|c| c.id == id) }

/// The Cosmos Hub on a network: its own, or its test network.
pub fn hub(network: Network) -> &'static Chain {
    let id = match network {
        Network::Main => "cosmoshub-4",
        Network::Test => "provider",
    };
    CHAINS.iter().find(|c| c.id == id).unwrap_or(&CHAINS[0])
}

impl Chain {
    /// Its validators' addresses' prefix: `cosmosvaloper`.
    pub fn valoper(&self) -> String { format!("{}valoper", self.prefix) }
}

/// The transfer channels between the main networks maki knows: each pair's channel, on each side,
/// as the chain registry's `_IBC` files have them, and as each chain itself has them: open, to the
/// other side's channel, through a client of the other chain (each checked on 2026-10-02).
pub const CHANNELS: &[(&str, &str, &str, &str)] = &[
    // a chain, its channel, the chain at the other end, and its channel
    ("akashnet-2", "channel-17", "cosmoshub-4", "channel-184"),
    ("akashnet-2", "channel-35", "juno-1", "channel-29"),
    ("akashnet-2", "channel-9", "osmosis-1", "channel-1"),
    ("axelar-dojo-1", "channel-175", "bbn-1", "channel-2"),
    ("axelar-dojo-1", "channel-125", "celestia", "channel-1"),
    ("axelar-dojo-1", "channel-2", "cosmoshub-4", "channel-293"),
    ("axelar-dojo-1", "channel-4", "juno-1", "channel-71"),
    ("axelar-dojo-1", "channel-78", "neutron-1", "channel-2"),
    ("axelar-dojo-1", "channel-3", "osmosis-1", "channel-208"),
    ("bbn-1", "channel-0", "cosmoshub-4", "channel-1341"),
    ("bbn-1", "channel-5", "neutron-1", "channel-6980"),
    ("bbn-1", "channel-1", "noble-1", "channel-132"),
    ("bbn-1", "channel-3", "osmosis-1", "channel-101635"),
    ("celestia", "channel-278", "cosmoshub-4", "channel-1879"),
    ("celestia", "channel-8", "neutron-1", "channel-35"),
    ("celestia", "channel-2", "osmosis-1", "channel-6994"),
    ("cosmoshub-4", "channel-207", "juno-1", "channel-1"),
    ("cosmoshub-4", "channel-569", "neutron-1", "channel-1"),
    ("cosmoshub-4", "channel-536", "noble-1", "channel-4"),
    ("cosmoshub-4", "channel-141", "osmosis-1", "channel-0"),
    ("dydx-mainnet-1", "channel-11", "neutron-1", "channel-48"),
    ("dydx-mainnet-1", "channel-0", "noble-1", "channel-33"),
    ("dydx-mainnet-1", "channel-3", "osmosis-1", "channel-6787"),
    ("juno-1", "channel-548", "neutron-1", "channel-4328"),
    ("juno-1", "channel-224", "noble-1", "channel-3"),
    ("juno-1", "channel-0", "osmosis-1", "channel-42"),
    ("neutron-1", "channel-30", "noble-1", "channel-18"),
    ("neutron-1", "channel-10", "osmosis-1", "channel-874"),
    ("noble-1", "channel-1", "osmosis-1", "channel-750"),
];

/// `chain`'s channels to the other chains maki knows: each channel, and the chain it leads to.
fn channels(chain: &Chain) -> impl Iterator<Item = (&'static str, &'static Chain)> + '_ {
    CHANNELS.iter().filter_map(move |&(a, a_channel, b, b_channel)| {
        if a == chain.id {
            Some((a_channel, by_id(b)?))
        } else if b == chain.id {
            Some((b_channel, by_id(a)?))
        } else {
            None
        }
    })
}

/// The chain at the other end of `chain`'s transfer channel `channel`, if maki knows it.
pub fn route(chain: &Chain, channel: &str) -> Option<&'static Chain> {
    channels(chain).find(|(c, _)| *c == channel).map(|(_, to)| to)
}

/// A coin on a chain, as maki knows it: the chain's own, or another chain's that came by the
/// channel between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Known {
    pub token: &'static Token,
    /// For another chain's coin: that chain, and the channel it came by.
    pub from: Option<(&'static Chain, &'static str)>,
}

/// The denom another chain's coin has on a chain it came to by `channel`: `ibc/` and the SHA-256,
/// in upper-case hex, of its path (ICS-20's denom trace: `transfer/channel-0/uatom`).
pub fn ibc_denom(channel: &str, denom: &str) -> String {
    let hash = Sha256::new()
        .chain_update(b"transfer/")
        .chain_update(channel.as_bytes())
        .chain_update(b"/")
        .chain_update(denom.as_bytes())
        .finalize();
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(4 + 64);
    out.push_str("ibc/");
    for b in hash {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}

/// The coin `denom` is on `chain`, if maki knows it: the chain's own coin, or one of the other
/// chains' that came straight from it by the channel between them. The same coin by another path
/// (through a third chain, or another channel) has another denom, and isn't known: it isn't what a
/// wallet would call it.
pub fn token(chain: &'static Chain, denom: &str) -> Option<Known> {
    if denom == chain.coin.denom {
        return Some(Known { token: &chain.coin, from: None });
    }
    if !denom.starts_with("ibc/") {
        return None;
    }
    channels(chain)
        .find(|(channel, from)| ibc_denom(channel, from.coin.denom) == denom)
        .map(|(channel, from)| Known { token: &from.coin, from: Some((from, channel)) })
}
