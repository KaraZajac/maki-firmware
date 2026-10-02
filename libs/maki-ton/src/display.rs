//! What the owner reads on maki's review screen before a TON wallet's request is signed: what it
//! does in turn, as pages. TON and jettons sent, how much and to whom (as the message is sent:
//! bounceable or not), and the comment with them; a contract set up; anything that sends all the
//! wallet holds, closes it, or lets another take from it or act for it, loudly; what maki can't
//! read, flagged; then how long the request is good for, and whose wallet it is, on which
//! network. The network's fee isn't in what's signed: TON takes it from the wallet's balance when
//! the request runs, at its prices then, so the pages say so rather than a number maki can't
//! vouch for.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::jettons;
use crate::message::{Message, Payload};
use crate::wallet::{Action, Request, Wallet, mode};
use crate::{Address, Key, Network};

/// A page of a review, as maki's review screen lays it out (`maki_app::wallet::Page`).
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

/// What the owner goes through before a request is signed: the pages, and a line about them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    /// What it does, a page at a time; then how long it's good for, and whose it is.
    pub pages: Vec<Page>,
    /// The line under the question: what it does that matters most.
    pub summary: String,
}

/// Why maki won't show a request it read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// For another of the key's wallets: another wallet ID.
    NotMine,
    /// A W5 request for the other network: its wallet ID is that network's.
    Network(Network),
    /// More pages than maki's review screen goes through.
    TooMuch,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::NotMine => "not this account's wallet: another wallet ID",
            Error::Network(Network::Test) => {
                "a request for TON's test network, not TON: its wallet ID says so"
            }
            Error::Network(Network::Main) => "a request for TON, not its test network: its wallet ID says so",
            Error::TooMuch => "too much to go through on maki's screen",
        })
    }
}

/// The longest summary: what maki's review screen takes under its question.
pub const MAX_SUMMARY: usize = 128;
/// The most pages maki's review screen goes through.
pub const MAX_PAGES: usize = 128;
/// A request with no time limit: its `valid_until` is as late as there is.
pub const NO_TIME_LIMIT: u32 = u32::MAX;

/// `n` with `places` decimals, exactly, without trailing zeros: `decimals(1500, 3)` is `1.5`.
pub fn decimals(n: u128, places: u8) -> String {
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

/// Nanotons, exactly, in TON: `0.05 TON`.
pub fn ton(nanotons: u128) -> String { format!("{} TON", decimals(nanotons, 9)) }

/// A Unix time as a date, in UTC: `2027-01-01 00:00:00 UTC`.
pub fn date(unix: u64) -> String {
    // days to a civil date (Howard Hinnant's algorithm), on the proleptic Gregorian calendar
    let (days, secs) = ((unix / 86_400) as i64, unix % 86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", secs / 3_600, secs % 3_600 / 60, secs % 60)
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

/// Text a page can show as it is: UTF-8, without control characters but newlines.
fn text(bytes: &[u8]) -> Option<&str> {
    core::str::from_utf8(bytes).ok().filter(|t| !t.chars().any(|c| c.is_control() && c != '\n'))
}

struct Reading<'a> {
    me: &'a Key,
    network: Network,
    wallet: Wallet,
    /// This wallet's address.
    mine: Address,
    /// The account's wallets on this network, and their addresses.
    wallets: [(Wallet, Address); 2],
    pages: Vec<Page>,
    /// Something maki can't read.
    unreadable: bool,
    /// What it does that the owner must not miss.
    warnings: Vec<&'static str>,
    /// TON it sends, in nanotons (all of it, as far as the messages say), and in how many messages.
    sent: u128,
    messages: usize,
    /// Jettons it sends, each as said: `5.25 USDT`.
    jettons: Vec<String>,
    /// What else it does, a few words each, for the summary.
    said: Vec<String>,
}

impl Reading<'_> {
    fn testnet(&self) -> bool { self.network == Network::Test }

    fn warn(&mut self, w: &'static str) {
        if !self.warnings.contains(&w) {
            self.warnings.push(w);
        }
    }

    /// This account's wallet at `a`, if it's one of its wallets on this network: its name.
    fn own(&self, a: &Address) -> Option<Wallet> { self.wallets.iter().find(|w| w.1 == *a).map(|w| w.0) }

    /// An address a message goes to, as a page shows it: this account's wallet, or the address
    /// as the message is sent to it (bounceable or not).
    fn whom(&self, a: &Address, bounceable: bool) -> String {
        match self.own(a) {
            Some(w) => format!("this account's {} wallet", w.name()),
            None => a.friendly(bounceable, self.testnet()),
        }
    }

    /// An account's address (an owner of jettons, what's left of a transfer's TON): a wallet's,
    /// shown as wallets show their own, non-bounceable.
    fn account(&self, a: &Address) -> String { self.whom(a, false) }

    /// A contract's address (a plugin, an extension, a jetton wallet), bounceable.
    fn contract(&self, a: &Address) -> String { self.whom(a, true) }

    fn action(&mut self, action: &Action) {
        match action {
            Action::Send { mode, message } => self.send(*mode, message),
            Action::DeployPlugin { plugin, amount, .. } => {
                self.sent += amount;
                self.unreadable = true;
                self.warn("lets a plugin take its TON");
                let prose = format!(
                    "A new contract, set up with {}, may take TON from this wallet whenever it asks, until it's removed. Its code comes from the computer: maki can't read it.",
                    ton(*amount)
                );
                self.pages.push(page("Plugin!", "may take its TON", self.contract(plugin), prose));
            }
            Action::InstallPlugin { plugin, amount } => {
                self.sent += amount;
                self.warn("lets a plugin take its TON");
                let prose = format!(
                    "That contract may take TON from this wallet whenever it asks, until it's removed. It's sent {} to say so.",
                    ton(*amount)
                );
                self.pages.push(page("Plugin!", "may take its TON", self.contract(plugin), prose));
            }
            Action::RemovePlugin { plugin, amount } => {
                self.sent += amount;
                self.said.push(String::from("removes a plugin"));
                let prose = format!(
                    "That contract may no longer take TON from this wallet. It's sent {} to say so.",
                    ton(*amount)
                );
                self.pages.push(page("Remove plugin", "no more", self.contract(plugin), prose));
            }
            Action::AddExtension(a) => {
                self.warn("lets another control the wallet");
                let prose = "That contract may send anything from this wallet, and change who controls it, without its key.";
                self.pages.push(page("Extension!", "may do anything", self.contract(a), prose));
            }
            Action::RemoveExtension(a) => {
                self.said.push(String::from("removes an extension"));
                let prose = "That contract may no longer act for this wallet.";
                self.pages.push(page("Remove extension", "no more", self.contract(a), prose));
            }
        }
    }

    fn send(&mut self, m: u8, msg: &Message) {
        let all = m & mode::ALL_BALANCE != 0;
        if all {
            self.warn("sends all its TON");
        }
        self.messages += 1;
        if !all {
            self.sent += msg.value;
        }
        let what = if all { String::from("all its TON") } else { ton(msg.value) };
        match &msg.payload {
            Payload::Jetton(j) => self.jetton(msg, j, &what),
            _ => {
                let bounce = if msg.bounce {
                    "Bounceable: if nothing at the address takes it, it comes back."
                } else {
                    "Not bounceable: it stays, even if nothing's at the address yet."
                };
                let fee = if all || m & mode::PAY_FEES_SEPARATELY == 0 {
                    "The network's fee for sending it comes out of it."
                } else {
                    "The network's fee for sending it comes from this wallet."
                };
                let to_self = self.own(&msg.dest).is_some();
                let to = self.whom(&msg.dest, msg.bounce);
                if all {
                    let says = match msg.value {
                        0 => String::new(),
                        v => format!(" The amount it says, {}, doesn't count.", ton(v)),
                    };
                    let bounce = if to_self { "" } else { bounce };
                    let prose =
                        format!("Everything this wallet holds, less the network's fee.{says} {bounce}");
                    self.pages.push(page("Sends everything!", what, to, prose.trim_end()));
                } else {
                    let notes = if to_self { String::from(fee) } else { format!("{bounce} {fee}") };
                    self.pages.push(page("Send", what, to, notes));
                }
            }
        }
        if let Some(init) = &msg.init {
            match self.own(&msg.dest).filter(|w| w.init(self.me, self.network) == *init) {
                Some(w) => {
                    self.said.push(format!("sets up its {} wallet", w.name()));
                    self.pages.push(page(
                        "Sets up",
                        format!("this account's {} wallet", w.name()),
                        "",
                        format!(
                            "With {}'s code and this account's key: the wallet starts working.",
                            w.name()
                        ),
                    ));
                }
                None => {
                    self.unreadable = true;
                    let prose = "At the address it's sent to. Its code and data come from the computer: what it does, maki can't tell.";
                    self.pages.push(page("Sets up!", "a contract maki can't read", "", prose));
                }
            }
        }
        self.payload(
            &msg.payload,
            "Message",
            "Its body is for the contract it goes to: what it asks, maki can't tell.",
        );
        if m & mode::DESTROY_IF_ZERO != 0 {
            self.warn("closes the wallet");
            let prose = "If this leaves it with no TON, TON deletes this wallet. Set up again, its seqno starts over, and requests signed before could go through again.";
            self.pages.push(page("Closes it!", "deletes this wallet", "", prose));
        }
    }

    /// A body's pages after its message's (or a jetton transfer's forward payload's): a comment,
    /// or what maki can't read. A jetton transfer has its own.
    fn payload(&mut self, p: &Payload, heading: &str, why: &str) {
        match p {
            Payload::Empty | Payload::Jetton(_) => {}
            Payload::Text(t) if t.is_empty() => {
                self.pages.push(page("Comment", "an empty one", "", "Everyone can see it, on chain."))
            }
            Payload::Text(t) => self.pages.push(match text(t) {
                Some(t) => page("Comment", "", t, "Everyone can read it, on chain."),
                None => page("Comment", "in hex", hex(t), "Everyone can read it, on chain."),
            }),
            Payload::Binary(b) => self.pages.push(page(
                "Comment",
                "binary, in hex",
                hex(b),
                "For software, not people: everyone can read it, on chain.",
            )),
            Payload::Encrypted => {
                self.unreadable = true;
                self.pages.push(page(
                    "Comment",
                    "encrypted",
                    "",
                    "Only the recipient's key opens it: maki can't read it.",
                ));
            }
            Payload::Unknown { op, bytes, cells } => {
                self.unreadable = true;
                let op = op.map(|op| format!("op 0x{op:08x}\n")).unwrap_or_default();
                let s = |n: usize| if n == 1 { "" } else { "s" };
                let mono = format!("{op}{bytes} byte{}, {cells} cell{}", s(*bytes), s(*cells));
                self.pages.push(page(heading, "maki can't read it", mono, why));
            }
        }
    }

    /// A jetton transfer, sent to `msg.dest` with `with` (TON, or all of it).
    fn jetton(&mut self, msg: &Message, j: &crate::message::Jetton, with: &str) {
        let known = match self.network {
            Network::Main => jettons::known(&msg.dest, &self.mine),
            Network::Test => None,
        };
        let amount = match known {
            Some(k) => format!("{} {}", decimals(j.amount, k.decimals), k.symbol),
            None => format!("{} units", j.amount),
        };
        self.jettons.push(amount.clone());
        let back = match &j.response {
            Some(r) if *r == self.mine => "what's left comes back to this wallet",
            Some(_) => "what's left goes to another address",
            None => "what's left isn't sent back",
        };
        let on = match j.forward_ton {
            0 => String::new(),
            t => format!(" {} goes on to them with it.", ton(t)),
        };
        let of = match known {
            Some(k) => format!("From this account's {}", k.symbol),
            None => String::from("Of a jetton maki doesn't know"),
        };
        let prose = format!("{of}, with {with} to its jetton wallet for the fees; {back}.{on}");
        self.pages.push(page("Send", amount, self.account(&j.destination), prose));
        if known.is_none() {
            self.unreadable = true;
            let prose = "Its jetton wallet: maki can't tell which jetton it holds, or whose it is.";
            self.pages.push(page("Jetton", "one maki doesn't know", self.contract(&msg.dest), prose));
        }
        if let Some(r) = j.response.filter(|r| *r != self.mine) {
            let prose = "What's left of the TON sent with it goes there, not to this wallet.";
            self.pages.push(page("What's left to", "another address", self.account(&r), prose));
        }
        if j.custom {
            self.unreadable = true;
            let prose = "A payload for the jetton wallet itself: what it asks, maki can't tell.";
            self.pages.push(page("Jetton payload", "maki can't read it", "", prose));
        }
        self.payload(
            &j.forward,
            "For them",
            "It goes to them with the jettons: what it asks of them, maki can't tell.",
        );
    }

    /// The line under the question: what it does that matters most.
    fn summary(&self) -> String {
        let what = if !self.warnings.is_empty() {
            format!(
                "{}!{}",
                self.warnings.join(", "),
                if self.unreadable { " And maki can't read all of it" } else { "" }
            )
        } else if self.unreadable {
            String::from("maki can't read all of it")
        } else {
            let mut said = self.said.clone();
            let mut sends = self.jettons.clone();
            if self.sent != 0 {
                sends.push(ton(self.sent));
            }
            if self.jettons.is_empty() && self.sent != 0 && self.messages > 1 {
                said.push(format!("sends {} in {} messages", ton(self.sent), self.messages));
            } else if !sends.is_empty() {
                said.push(format!("sends {}", sends.join(", ")));
            }
            if said.is_empty() { String::from("sends nothing") } else { said.join(", ") }
        };
        let mut summary = if self.testnet() { format!("testnet: {what}") } else { what };
        summary.push_str("; plus the network's fee");
        // the line under the question is short (the pages say it all): cut, if it must be, at a character
        if summary.len() > MAX_SUMMARY {
            let mut end = MAX_SUMMARY - '…'.len_utf8();
            while !summary.is_char_boundary(end) {
                end -= 1;
            }
            summary.truncate(end);
            summary.push('…');
        }
        summary
    }
}

/// The pages the owner goes through before `me` signs `request` on `network`, and the line that
/// goes with them; refused if it's for another of the key's wallets, or the other network.
pub fn review(request: &Request, me: &Key, network: Network) -> Result<Review, Error> {
    let wallet = request.wallet;
    if request.wallet_id != wallet.wallet_id(network) {
        let other = match network {
            Network::Main => Network::Test,
            Network::Test => Network::Main,
        };
        return Err(if request.wallet_id == wallet.wallet_id(other) {
            Error::Network(other)
        } else {
            Error::NotMine
        });
    }
    let wallets = Wallet::ALL.map(|w| (w, w.address(me, network)));
    let mine = wallet.address(me, network);
    let mut r = Reading {
        me,
        network,
        wallet,
        mine,
        wallets,
        pages: Vec::new(),
        unreadable: false,
        warnings: Vec::new(),
        sent: 0,
        messages: 0,
        jettons: Vec::new(),
        said: Vec::new(),
    };
    for action in &request.actions {
        r.action(action);
    }
    if request.actions.is_empty() {
        r.pages.push(page(
            "Nothing",
            "no messages",
            "",
            "It sends nothing: the wallet only counts it, and its seqno moves on.",
        ));
    }
    if request.valid_until == NO_TIME_LIMIT {
        r.pages.push(page(
            "No time limit",
            "",
            "",
            "It stays good until it's sent, or the wallet's seqno moves past it.",
        ));
    } else {
        r.pages.push(page(
            "Valid until",
            date(request.valid_until as u64),
            "",
            "After that, the wallet refuses it.",
        ));
    }
    let on = match network {
        Network::Main => String::from("On TON"),
        Network::Test => String::from("On TON's test network, where TON is worth nothing"),
    };
    let first = if request.seqno == 0 { ": its first, which sets the wallet up" } else { "" };
    let prose = format!(
        "{on}; its seqno is {}{first}. The network's fee comes from its balance as well, at TON's prices when it runs.",
        request.seqno
    );
    let from = format!("this account's {} wallet", r.wallet.name());
    r.pages.push(page("From", from, r.mine.friendly(false, r.testnet()), prose));
    if r.pages.len() > MAX_PAGES {
        return Err(Error::TooMuch);
    }
    Ok(Review { summary: r.summary(), pages: r.pages })
}
