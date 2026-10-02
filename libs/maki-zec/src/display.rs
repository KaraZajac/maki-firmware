//! What the owner reads on maki's review screen before a Zcash transaction is signed: each payment
//! with its address in full (a TEX address as the owner gave it), the change coming back, any data
//! it writes on the chain for all to read, when it can be confirmed if not at once, and the fee,
//! exactly, beside ZIP-317's conventional fee for it, called out when it's high. And the page an
//! address is compared on.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::request::Derivation;
use crate::wallet::{Checked, Paid};
use crate::{Network, ZATOSHIS_PER_ZEC};

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

/// Lock times this low are block heights; from here up, Unix times in seconds.
pub const LOCK_TIME_THRESHOLD: u32 = 500_000_000;

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

/// Zatoshis, exactly, in ZEC (or the test network's TAZ): `0.0001 ZEC`.
pub fn zec(zatoshis: u64, network: Network) -> String {
    const PLACES: u8 = ZATOSHIS_PER_ZEC.ilog10() as u8;
    format!("{} {}", decimals(zatoshis, PLACES), network.unit())
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

/// Text a page can show as it is: UTF-8, without control characters but newlines.
fn text(bytes: &[u8]) -> Option<&str> {
    core::str::from_utf8(bytes).ok().filter(|t| !t.chars().any(|c| c.is_control() && c != '\n'))
}

/// A Unix time in seconds, as a date and time in UTC: `2027-01-01 00:00:00 UTC`.
pub fn date(secs: u64) -> String {
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
    format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{s:02} UTC")
}

const DATA: &str =
    "Everyone can read it, on chain, and software that reads the chain may act on it: maki can't tell how.";

/// The pages the owner goes through before the inputs are signed, and the line that goes with
/// them.
pub fn review(c: &Checked) -> Review {
    let (tx, network) = (&c.request.tx, c.network);
    let mut pages = Vec::new();
    let payments: Vec<(&String, u64)> = c
        .outputs
        .iter()
        .zip(&tx.outputs)
        .filter_map(|(paid, o)| match paid {
            Paid::Payment(a) | Paid::Tex(a) => Some((a, o.value)),
            _ => None,
        })
        .collect();
    let mut n = 0;
    for (paid, o) in c.outputs.iter().zip(&tx.outputs) {
        let (address, prose) = match paid {
            Paid::Payment(a) => (a, ""),
            Paid::Tex(a) => {
                (a, "A TEX address: it takes coins from transparent transactions alone, as this is.")
            }
            _ => continue,
        };
        n += 1;
        let heading =
            if payments.len() > 1 { format!("Send {n}/{}", payments.len()) } else { String::from("Send") };
        pages.push(page(&heading, zec(o.value, network), address.as_str(), prose));
    }
    let mut kept = 0u64;
    for (paid, o) in c.outputs.iter().zip(&tx.outputs) {
        if let Paid::Change(_) = paid {
            kept += o.value;
            pages.push(page("Change", zec(o.value, network), "back to you", ""));
        }
    }
    let mut burnt = 0u64;
    for (paid, o) in c.outputs.iter().zip(&tx.outputs) {
        if let Paid::Data(bytes) = paid {
            let (value, mono) = match text(bytes) {
                Some(t) => (String::new(), String::from(t)),
                None => (String::from("in hex"), hex(bytes)),
            };
            pages.push(page("Data", value, mono, DATA));
            // what a data output holds can't be spent again: it's gone
            if o.value > 0 {
                burnt += o.value;
                pages.push(page(
                    "Burns!",
                    zec(o.value, network),
                    "",
                    "Paid to the data above, which no one can spend: it's gone.",
                ));
            }
        }
    }
    // a lock time holds unless every input's sequence is final
    if tx.lock_time != 0 && tx.inputs.iter().any(|i| i.sequence != u32::MAX) {
        pages.push(if tx.lock_time < LOCK_TIME_THRESHOLD {
            page(
                "Not before",
                format!("block {}", tx.lock_time),
                "",
                "It can't be confirmed until Zcash's chain is this long.",
            )
        } else {
            page("Not before", date(tx.lock_time as u64), "", "It can't be confirmed before then.")
        });
    }
    let sent: u64 = payments.iter().map(|(_, v)| v).sum::<u64>() + burnt;
    // a fee over the conventional one and a tenth of what's sent (or, sending nothing but change,
    // of what moves) is how a mistyped fee looks; under the conventional one, it may never be mined
    let base = if sent == 0 { kept } else { sent };
    let (fee, conventional) = (c.fee, c.conventional_fee);
    let high = fee > conventional && fee.saturating_mul(10) > base;
    let of = if sent == 0 { "moves" } else { "sends" };
    let zip317 = zec(conventional, network);
    pages.push(if high {
        let prose = format!("More than a tenth of what it {of}: ZIP-317's conventional fee is {zip317}.");
        page("High fee!", zec(fee, network), "", prose)
    } else if fee < conventional {
        let prose = format!("Less than ZIP-317's conventional fee of {zip317}: it may never be mined.");
        page("Fee", zec(fee, network), "", prose)
    } else if fee == conventional {
        page("Fee", zec(fee, network), "", "ZIP-317's conventional fee.")
    } else {
        page("Fee", zec(fee, network), "", format!("ZIP-317's conventional fee is {zip317}."))
    });
    let what = match payments.len() {
        0 if burnt > 0 => format!("burns {}", zec(burnt, network)),
        0 => format!("moves {} within this wallet", zec(kept, network)),
        1 => format!("sends {}", zec(sent, network)),
        n => format!("sends {} in {n} payments", zec(sent, network)),
    };
    let data = if c.outputs.iter().any(|p| matches!(p, Paid::Data(_))) { " with data" } else { "" };
    let fee = if high {
        format!("high fee {}!", zec(fee, network))
    } else if fee < conventional {
        format!("low fee {}", zec(fee, network))
    } else {
        format!("fee {}", zec(fee, network))
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
