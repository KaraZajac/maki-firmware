//! What maki's screen says about a transaction or an address: shared by the firmware and the fake
//! maki, so both say the same thing.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::address::Network;
use crate::wallet::Review;

/// A screen's worth of review: a heading at the top, the thing to check in bold (an amount), and
/// fixed-width text under it, across as many lines as it takes (an address), or small words,
/// wrapped (what it means).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub heading: String,
    pub value: String,
    pub mono: String,
    pub prose: String,
}

/// The unit amounts are shown in: test coins are marked as such.
pub fn unit(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "BTC",
        Network::Testnet => "tBTC",
    }
}

/// The network's name, as the owner sees it.
pub fn network_name(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "bitcoin",
        Network::Testnet => "testnet",
    }
}

/// An amount, exactly, in bitcoin without trailing zeros: `0.0007 BTC`, `1 BTC`.
pub fn amount(sats: u64, network: Network) -> String {
    let whole = sats / 100_000_000;
    let frac = sats % 100_000_000;
    if frac == 0 {
        return format!("{} {}", whole, unit(network));
    }
    let digits = format!("{:08}", frac);
    format!("{}.{} {}", whole, digits.trim_end_matches('0'), unit(network))
}

impl Review {
    /// What leaves the wallet: every payment, and the fee.
    pub fn spent(&self) -> u64 {
        self.outputs.iter().filter(|o| !o.change).map(|o| o.amount).sum::<u64>() + self.fee
    }

    /// A fee over a tenth of what's sent (or, sending nothing but change, of what moves) is
    /// called out: it's how a mistyped fee rate looks.
    pub fn fee_is_high(&self) -> bool {
        let sent: u64 = self.outputs.iter().filter(|o| !o.change).map(|o| o.amount).sum();
        let base = if sent > 0 { sent } else { self.outputs.iter().map(|o| o.amount).sum() };
        self.fee.saturating_mul(10) > base
    }

    /// The pages the owner goes through before signing: each payment with its full address, the
    /// change coming back, then the fee.
    pub fn pages(&self) -> Vec<Page> {
        let payments: Vec<_> = self.outputs.iter().filter(|o| !o.change).collect();
        let mut pages = Vec::new();
        for (i, o) in payments.iter().enumerate() {
            let heading = if payments.len() > 1 {
                format!("Send {}/{}", i + 1, payments.len())
            } else {
                String::from("Send")
            };
            pages.push(Page {
                heading,
                value: amount(o.amount, self.network),
                mono: o.address.clone(),
                prose: String::new(),
            });
        }
        for o in self.outputs.iter().filter(|o| o.change) {
            // a multisig wallet's name is words, which the fixed-width type would break mid-word
            let (mono, prose) = match &self.wallet {
                Some(wallet) => (String::new(), format!("back to {wallet}")),
                None => (String::from("back to you"), String::new()),
            };
            pages.push(Page {
                heading: String::from("Change"),
                value: amount(o.amount, self.network),
                mono,
                prose,
            });
        }
        pages.push(Page {
            heading: String::from(if self.fee_is_high() { "High fee!" } else { "Fee" }),
            value: amount(self.fee, self.network),
            mono: format!("{} sat/vB", self.fee_rate()),
            prose: String::new(),
        });
        pages
    }

    /// The line that goes with sign and reject.
    pub fn summary(&self) -> String { format!("Total {}", amount(self.spent(), self.network)) }
}

/// An address to compare with the computer's.
pub fn address_page(address: &str, change: bool, index: u32, network: Network) -> Page {
    Page {
        heading: format!("{} #{}", if change { "Change" } else { "Receive" }, index),
        value: String::from(network_name(network)),
        mono: String::from(address),
        prose: String::new(),
    }
}
