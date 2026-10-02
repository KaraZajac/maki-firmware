//! What the owner reads on maki's review screen before a Kaspa transaction is signed: each payment
//! with its address in full, the change coming back, any data it carries for all to read, when it
//! can be confirmed if not at once, and the fee, exactly, called out when it's high; on the test
//! network, first, that its signatures would spend real KAS as well. And the page an address is
//! compared on.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::request::Derivation;
use crate::wallet::{Checked, Paid};
use crate::{Network, SOMPI_PER_KAS};

/// A page of a review, as maki's review screen lays it out (`maki_app::wallet::Page`): a heading,
/// the thing to check in bold, fixed-width text across as many lines as it takes (an address), and
/// small words, wrapped (what it means).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    pub heading: String,
    pub value: String,
    pub mono: String,
    pub prose: String,
}

fn page(heading: &str, value: impl Into<String>, mono: impl Into<String>, prose: impl Into<String>) -> Page {
    Page { heading: heading.into(), value: value.into(), mono: mono.into(), prose: prose.into() }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    pub pages: Vec<Page>,
    /// The line under the question: what it sends, and the fee.
    pub summary: String,
}

/// The longest summary: what maki's review screen takes under its question.
pub const MAX_SUMMARY: usize = 128;

/// Lock times this low are DAA scores; from here up, Unix times in milliseconds (rusty-kaspa's
/// `LOCK_TIME_THRESHOLD`).
pub const LOCK_TIME_THRESHOLD: u64 = 500_000_000_000;

/// A sequence with this bit set has no relative lock (`SEQUENCE_LOCK_TIME_DISABLED`); without it,
/// its low 32 bits are how many DAA scores its coin must wait (`SEQUENCE_LOCK_TIME_MASK`).
pub const SEQUENCE_LOCK_DISABLED: u64 = 1 << 63;
pub const SEQUENCE_LOCK_MASK: u64 = 0xffff_ffff;

/// `n` with `places` decimals, exactly, without trailing zeros: `decimals(150_000_000, 8)` is `1.5`.
pub fn decimals(n: u64, places: u8) -> String {
    let digits = n.to_string();
    let places = places as usize;
    if places == 0 {
        return digits;
    }
    let padded =
        if digits.len() <= places { "0".repeat(places + 1 - digits.len()) + &digits } else { digits };
    let (whole, frac) = padded.split_at(padded.len() - places);
    match frac.trim_end_matches('0') {
        "" => whole.into(),
        frac => format!("{whole}.{frac}"),
    }
}

/// Sompi, exactly, in KAS (or a test network's TKAS): `0.002036 KAS`.
pub fn kas(sompi: u64, network: Network) -> String {
    const PLACES: u8 = SOMPI_PER_KAS.ilog10() as u8;
    format!("{} {}", decimals(sompi, PLACES), network.unit())
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

/// Text a page can show as it is: UTF-8, without control characters but newlines.
fn text(bytes: &[u8]) -> Option<&str> {
    core::str::from_utf8(bytes).ok().filter(|t| !t.chars().any(|c| c.is_control() && c != '\n'))
}

/// A Unix time in milliseconds, as a date and time in UTC: `2027-01-01 00:00:00 UTC`.
pub fn date(ms: u64) -> String {
    let (secs, ms) = (ms / 1000, ms % 1000);
    let (days, day) = ((secs / 86_400) as i64, secs % 86_400);
    // days since 1970 to a civil date (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    let (h, min, s) = (day / 3600, day / 60 % 60, day % 60);
    let ms = if ms == 0 { String::new() } else { format!(".{ms:03}") };
    format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{s:02}{ms} UTC")
}

/// About how long `scores` of Kaspa's DAA score take: ten a second.
fn wait(scores: u64) -> String {
    let secs = scores.div_ceil(10);
    let (n, unit) = match secs {
        0..=119 => (secs, "second"),
        120..=3_599 => (secs.div_ceil(60), "minute"),
        3_600..=172_799 => (secs.div_ceil(3600), "hour"),
        _ => (secs.div_ceil(86_400), "day"),
    };
    format!("about {n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// The pages the owner goes through before the inputs are signed, and the line that goes with
/// them.
pub fn review(c: &Checked) -> Review {
    let (tx, network) = (c.request, c.network);
    let payments: Vec<(&String, u64)> = c
        .outputs
        .iter()
        .zip(&tx.outputs)
        .filter_map(|(paid, o)| match paid {
            Paid::Payment(address) => Some((address, o.value)),
            Paid::Change(_) => None,
        })
        .collect();
    let mut pages = Vec::new();
    // the test network's keys are Kaspa's own (its wallets derive both alike), and a signature doesn't
    // say which network it's for: test coins are only test coins if the computer is honest
    if network == Network::Testnet {
        pages.push(page(
            "Test network!",
            network.name(),
            "",
            "Kaspa's signatures don't say which network they're for, and its test network has the same keys: if these coins are real KAS, this spends them as shown.",
        ));
    }
    for (i, (address, value)) in payments.iter().enumerate() {
        let heading = if payments.len() > 1 {
            format!("Send {}/{}", i + 1, payments.len())
        } else {
            String::from("Send")
        };
        pages.push(page(&heading, kas(*value, network), address.as_str(), ""));
    }
    let mut kept = 0u64;
    for (paid, o) in c.outputs.iter().zip(&tx.outputs) {
        if let Paid::Change(_) = paid {
            kept += o.value;
            pages.push(page("Change", kas(o.value, network), "back to you", ""));
        }
    }
    if !tx.payload.is_empty() {
        let prose = "Everyone can read it, on chain, and software that reads the chain may act on it: maki can't tell how.";
        pages.push(match text(&tx.payload) {
            Some(t) => page("Data", "", t, prose),
            None => page("Data", "in hex", hex(&tx.payload), prose),
        });
    }
    // a lock time holds unless every input's sequence is final (rusty-kaspa's `check_tx_is_finalized`)
    if tx.lock_time != 0 && tx.inputs.iter().any(|i| i.sequence != u64::MAX) {
        pages.push(if tx.lock_time < LOCK_TIME_THRESHOLD {
            page(
                "Not before",
                format!("DAA score {}", tx.lock_time),
                "",
                "It can't be confirmed until Kaspa's DAA score, which goes up about ten a second, passes this.",
            )
        } else {
            page("Not before", date(tx.lock_time), "", "It can't be confirmed before then.")
        });
    }
    // and each input's relative lock, its coin's age in DAA scores (`check_sequence_lock`)
    let waits = tx
        .inputs
        .iter()
        .filter(|i| i.sequence & SEQUENCE_LOCK_DISABLED == 0)
        .map(|i| i.sequence & SEQUENCE_LOCK_MASK)
        .max()
        .unwrap_or(0);
    if waits > 0 {
        pages.push(page(
            "Waits",
            format!("{waits} DAA score{}", if waits == 1 { "" } else { "s" }),
            "",
            format!(
                "It can't be confirmed until the coins it spends are that old: {} after they arrived.",
                wait(waits)
            ),
        ));
    }
    let sent: u64 = payments.iter().map(|(_, v)| v).sum();
    // a fee over a tenth of what's sent (or, sending nothing but change, of what moves) is how a
    // mistyped fee looks
    let base = if payments.is_empty() { kept } else { sent };
    let high = c.fee.saturating_mul(10) > base;
    pages.push(if high {
        let of = if payments.is_empty() { "moves" } else { "sends" };
        page("High fee!", kas(c.fee, network), "", format!("More than a tenth of what it {of}."))
    } else {
        page("Fee", kas(c.fee, network), "", "")
    });
    let what = match payments.len() {
        0 => format!("moves {} within this wallet", kas(kept, network)),
        1 => format!("sends {}", kas(sent, network)),
        n => format!("sends {} in {n} payments", kas(sent, network)),
    };
    let data = if tx.payload.is_empty() { "" } else { " with data" };
    let fee = if high {
        format!("high fee {}!", kas(c.fee, network))
    } else {
        format!("fee {}", kas(c.fee, network))
    };
    let mut summary = format!("{what}{data}; {fee}");
    // the line under the question is short (the pages say it all): cut, if it must be, at a character
    if summary.len() > MAX_SUMMARY {
        let mut end = MAX_SUMMARY - '…'.len_utf8();
        while !summary.is_char_boundary(end) {
            end -= 1;
        }
        summary.truncate(end);
        summary.push('…');
    }
    Review { pages, summary }
}

/// An address of the account's, to compare with the computer's.
pub fn address_page(address: &str, key: Derivation, network: Network) -> Page {
    let which = if key.chain == 1 { "Change" } else { "Receive" };
    page(&format!("{which} #{}", key.index), network.name(), address, "")
}
