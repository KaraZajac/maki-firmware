//! Tokens maki knows by their policy and name: what they're called, and their decimals. Only the
//! policy says which token it is (nothing but its script can mint under it), and only on Cardano's
//! own network: a token with the same name under any other policy is another token, and shows as
//! one, by its policy. Names come from this list alone, never from what a token says of itself.
//! Decimals aren't on chain: each one here is the Cardano Token Registry's (CIP-26), checked
//! through Koios's `asset_info` on 2026-10-02.

use crate::{Hash28, Network};

/// A token maki knows.
pub struct Known {
    /// Its policy's ID: its minting script's hash.
    pub policy: Hash28,
    /// Its name under the policy.
    pub name: &'static [u8],
    /// What maki calls it.
    pub symbol: &'static str,
    /// How many of its smallest units are one of it, as a power of ten.
    pub decimals: u8,
}

/// A policy's ID from its hex, at compile time.
const fn policy(hex: &str) -> Hash28 {
    const fn digit(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not hex"),
        }
    }
    let b = hex.as_bytes();
    assert!(b.len() == 56);
    let mut out = [0u8; 28];
    let mut i = 0;
    while i < 28 {
        out[i] = digit(b[2 * i]) << 4 | digit(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// Every token maki knows: Cardano's stablecoins, and a few of its most held tokens.
pub const TOKENS: &[Known] = &[
    // Moneta's USDM, a CIP-68 token: its name is label 333's prefix, then "USDM"
    Known {
        policy: policy("c48cbb3d5e57ed56e276bc45f99ab39abe94e6cd7ac39fb402da47ad"),
        name: b"\x00\x14\xdf\x10USDM",
        symbol: "USDM",
        decimals: 6,
    },
    Known {
        policy: policy("8db269c3ec630e06ae29f74bc39edd1f87c819f1056206e879a1cd61"),
        name: b"DjedMicroUSD",
        symbol: "DJED",
        decimals: 6,
    },
    Known {
        policy: policy("f66d78b4a3cb3d37afa0ec36461e51ecbde00f26c8f0a68f94b69880"),
        name: b"iUSD",
        symbol: "iUSD",
        decimals: 6,
    },
    Known {
        policy: policy("fe7c786ab321f41c654ef6c1af7b3250a613c24e4213e0425a7ae456"),
        name: b"USDA",
        symbol: "USDA",
        decimals: 6,
    },
    Known {
        policy: policy("29d222ce763455e3d7a09a665ce554f00ac89d2e99a1a83d267170c6"),
        name: b"MIN",
        symbol: "MIN",
        decimals: 6,
    },
    Known {
        policy: policy("533bb94a8850ee3ccbe483106489399112b74c905342cb1792a797a0"),
        name: b"INDY",
        symbol: "INDY",
        decimals: 6,
    },
    Known {
        policy: policy("1d7f33bd23d85e1a25d87d86fac4f199c3197a2f7afeb662a0f34e1e"),
        name: b"worldmobiletoken",
        symbol: "WMT",
        decimals: 6,
    },
    Known {
        policy: policy("279c909f348e533da5808898f87f9a14bb2c3dfbbacccd631d927a3f"),
        name: b"SNEK",
        symbol: "SNEK",
        decimals: 0,
    },
    Known {
        policy: policy("a0028f350aaabe0545fdcb56b039bfb08e4bb4d8c4d7c3c7d481c235"),
        name: b"HOSKY",
        symbol: "HOSKY",
        decimals: 0,
    },
];

/// The token this is on this network, if maki knows it.
pub fn known(network: Network, policy: &Hash28, name: &[u8]) -> Option<&'static Known> {
    if network != Network::Mainnet {
        return None;
    }
    TOKENS.iter().find(|t| t.policy == *policy && t.name == name)
}
