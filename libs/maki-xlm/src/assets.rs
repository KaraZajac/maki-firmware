//! Assets maki knows by their issuer: on Stellar anyone can issue an asset of any code, so an
//! asset is who issued it, and a code alone says nothing. These are Circle's (its developer
//! documentation lists them, and their accounts' home domain is circle.com); any other shows its
//! code and its issuer, and one that borrows a known asset's code says it isn't that asset.

use crate::strkey::account_key;
use crate::transaction::Asset;
use crate::{Key, Network};

/// An asset maki knows: its code, its issuer, and the network it's on.
pub struct Known {
    pub code: &'static str,
    pub issuer: Key,
    pub network: Network,
    /// Whose it is, as a page says it.
    pub by: &'static str,
}

/// The assets maki knows, on each network.
pub const KNOWN: &[Known] = &[
    Known {
        code: "USDC",
        issuer: account_key("GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"),
        network: Network::Public,
        by: "Circle",
    },
    Known {
        code: "EURC",
        issuer: account_key("GDHU6WRG4IEQXM5NZ4BMPKOXHW76MZM4Y2IEMFDVXBSDP6SJY4ITNPP2"),
        network: Network::Public,
        by: "Circle",
    },
    // the test network's, from Circle's faucet, for trying things out
    Known {
        code: "USDC",
        issuer: account_key("GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"),
        network: Network::Test,
        by: "Circle",
    },
    Known {
        code: "EURC",
        issuer: account_key("GB3Q6QDZYTHWT7E5PVS3W7FUT5GVAFC5KSZFFLPU25GO7VTC3NM2ZTVO"),
        network: Network::Test,
        by: "Circle",
    },
];

/// The asset, if maki knows it on `network`.
pub fn known(asset: &Asset, network: Network) -> Option<&'static Known> {
    let Asset::Credit { code, issuer } = asset else { return None };
    KNOWN.iter().find(|k| k.network == network && k.code == code.as_str() && k.issuer == *issuer)
}

/// The asset maki knows that `asset` borrows the code of, if it isn't that asset: `USDC` that
/// isn't Circle's.
pub fn lookalike(asset: &Asset, network: Network) -> Option<&'static Known> {
    let Asset::Credit { code, .. } = asset else { return None };
    if known(asset, network).is_some() {
        return None;
    }
    KNOWN.iter().find(|k| k.network == network && k.code == code.as_str())
}
