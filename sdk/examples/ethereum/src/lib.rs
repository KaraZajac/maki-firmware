//! Ethereum: maki's Ethereum account, as an app from the maki store (ARCHITECTURE.md, "Wallets
//! are apps"). The account is BIP44's, `m/44'/60'/0'/0/i`, as MetaMask and Ledger make it, so the
//! phrase works there too. maki keeps the key (the wallet permission, on `m/44'/60'` and nothing
//! else); this app reads what it's asked to sign with maki's code (`maki-eth`: strictly, one
//! encoding per value, token transfers and approvals spelled out, any other call flagged as
//! unreadable, typed data hashed from the very values shown), shows it on maki's own review
//! screen after the site that asked, and signs once the owner says yes.
//!
//! Opened, it shows the account's address as a QR code: the centre shows it as text, left and
//! right step through accounts.
//!
//! maki desktop (for sites, through the maki extension, and for its own wallet as `desktop.maki`)
//! talks to it over the link. Each message starts with what it is; each answer with a status,
//! then its fields (strings as a u16 length and the bytes, numbers little-endian). `site` is the
//! site asking, as a length byte and the name:
//!
//! - `A` index (u32), site: the account's address, once the owner lets the site connect;
//! - `M` index, site, then the message: its signature (EIP-191, 65 bytes), once the owner has
//!   read it;
//! - `T` index, total (u32), offset (u32), site, then a piece of a transaction: the last piece is
//!   read, shown and signed, and answered with the signed transaction's size (or why not);
//! - `Y` the same for typed data (EIP-712, JSON): the last piece is answered with its signature;
//! - `G` offset (u32): a piece of the transaction last signed: total, offset, the bytes.
//!
//! And MetaMask, with no cable, as a QR-code wallet (Keystone's protocol, ERC-4527, which
//! MetaMask's "QR-based" hardware wallets speak): the menu's Account for MetaMask shows the
//! account as a UR `crypto-hdkey` (the key at `m/44'/60'/0'` with maki's fingerprint, the
//! accounts under it `0/*`), which MetaMask scans to add it; Sign from a QR code reads an
//! `eth-sign-request` off MetaMask's screen (a transaction, a message or typed data, for an
//! account of this wallet's, checked before anything's shown), goes through it on maki's review
//! screen as any other, and shows the `eth-signature` back for MetaMask to scan.

use maki_app::wallet::{HostKeys, Page, Review};
use maki_app::*;
use maki_eth::{display, Account, Tx, TypedData};

const ACCOUNT: u8 = b'A';
const MESSAGE: u8 = b'M';
const SIGN: u8 = b'T';
const TYPED: u8 = b'Y';
const SIGNED: u8 = b'G';

/// What an answer's first byte says.
const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;
/// Refused, with why: not something maki can read, or can't show.
const REFUSED: u8 = 5;
/// A piece taken: send the next.
const MORE: u8 = 6;

/// The biggest transaction this app takes in (room for the largest contract a deployment may
/// carry), and the pieces things come and go in.
const MAX_TX: usize = 128 * 1024;
const PIECE: usize = 4000;

/// An answer: the status, then its fields.
struct Answer(Vec<u8>);

impl Answer {
    fn new(status: u8) -> Answer { Answer(vec![status]) }
    fn text(mut self, s: &str) -> Answer {
        self.0.extend_from_slice(&(s.len() as u16).to_le_bytes());
        self.0.extend_from_slice(s.as_bytes());
        self
    }
    fn u32(mut self, n: u32) -> Answer {
        self.0.extend_from_slice(&n.to_le_bytes());
        self
    }
    fn bytes(mut self, b: &[u8]) -> Answer {
        self.0.extend_from_slice(b);
        self
    }
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> { b.get(at..at + 4).map(|x| u32::from_le_bytes(x.try_into().unwrap())) }

/// The site at `at` (a length byte, then the name), and where what follows starts.
fn site_at(b: &[u8], at: usize) -> Option<(&str, usize)> {
    let n = *b.get(at)? as usize;
    let site = core::str::from_utf8(b.get(at + 1..at + 1 + n)?).ok()?;
    valid_site(site).then_some((site, at + 1 + n))
}

/// A site maki is willing to show, as for logins (maki-proto's `site::valid`): a plain hostname,
/// lowercase ASCII letters, digits, dots and hyphens. An international domain comes as punycode
/// (`xn--...`) and is shown that way, never as characters that could pass for another site's.
fn valid_site(site: &str) -> bool {
    !site.is_empty()
        && site.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !site.starts_with('.')
        && !site.ends_with('.')
        && !site.contains("..")
}

/// The page every review starts with: who's asking. The browser names the site; maki shows it.
fn site_page(site: &str) -> Page { Page::new("Asked by").mono(site) }

fn page(p: display::Page) -> Page { Page::new(&p.heading).value(&p.value).mono(&p.mono) }

fn keys_status(e: maki_hd::Error) -> u8 {
    match e {
        maki_hd::Error::Locked => LOCKED,
        _ => REFUSED,
    }
}

fn account(index: u32) -> Result<Account<'static>, Answer> {
    Account::new(&HostKeys, index).map_err(|e| match e {
        maki_eth::account::Error::Keys(e) => Answer::new(keys_status(e)),
        _ => Answer::new(BAD),
    })
}

/// The owner's answer to a review: go on, or the answer to send back.
fn said_yes(asked: Result<maki_app::Answer, Error>) -> Result<(), Answer> {
    match asked {
        Ok(maki_app::Answer::Yes) => Ok(()),
        Ok(maki_app::Answer::No) => Err(Answer::new(DENIED)),
        Ok(maki_app::Answer::NoAnswer) => Err(Answer::new(NO_ANSWER)),
        Err(Error::Locked) => Err(Answer::new(LOCKED)),
        Err(_) => Err(Answer::new(REFUSED).text("too much to show on maki's screen")),
    }
}

fn which(index: u32) -> String { if index == 0 { "ethereum account".into() } else { format!("account #{index}") } }

/// A transaction or typed data coming in, and the transaction last signed.
#[derive(Default)]
struct Wallet {
    incoming: Vec<u8>,
    incoming_total: usize,
    incoming_kind: u8,
    signed: Vec<u8>,
}

impl Wallet {
    fn answer(&mut self, m: &[u8]) -> Answer {
        let result = match m.first() {
            Some(&ACCOUNT) => connect(m),
            Some(&MESSAGE) => message(m),
            Some(&SIGN) | Some(&TYPED) => self.piece(m),
            Some(&SIGNED) => self.signed_piece(m),
            _ => Err(Answer::new(BAD)),
        };
        result.unwrap_or_else(|a| a)
    }

    fn piece(&mut self, m: &[u8]) -> Result<Answer, Answer> {
        let kind = m[0];
        let (Some(index), Some(total), Some(offset), Some((site, at))) = (u32_at(m, 1), u32_at(m, 5), u32_at(m, 9), site_at(m, 13)) else {
            return Err(Answer::new(BAD));
        };
        let (total, offset, piece) = (total as usize, offset as usize, &m[at..]);
        let max = if kind == SIGN { MAX_TX } else { maki_eth::typed::MAX_TYPED };
        if total > max {
            return Err(Answer::new(REFUSED).text(&format!("bigger than maki takes ({} KiB)", max / 1024)));
        }
        if offset == 0 {
            self.incoming.clear();
            self.incoming_total = total;
            self.incoming_kind = kind;
        }
        if offset != self.incoming.len() || total != self.incoming_total || kind != self.incoming_kind || offset + piece.len() > total {
            self.incoming.clear();
            return Err(Answer::new(BAD));
        }
        self.incoming.extend_from_slice(piece);
        if self.incoming.len() < total {
            return Ok(Answer::new(MORE));
        }
        let bytes = std::mem::take(&mut self.incoming);
        let account = account(index)?;
        if kind == SIGN {
            let signed = transaction(&account, site, &bytes)?;
            self.signed = signed;
            Ok(Answer::new(OK).u32(self.signed.len() as u32))
        } else {
            Ok(Answer::new(OK).bytes(&typed(&account, site, &bytes)?))
        }
    }

    fn signed_piece(&self, m: &[u8]) -> Result<Answer, Answer> {
        let offset = u32_at(m, 1).ok_or(Answer::new(BAD))? as usize;
        if self.signed.is_empty() {
            return Err(Answer::new(BAD));
        }
        let start = offset.min(self.signed.len());
        let end = (start + PIECE).min(self.signed.len());
        Ok(Answer::new(OK).u32(self.signed.len() as u32).u32(start as u32).bytes(&self.signed[start..end]))
    }
}

/// `A`: the address, once the owner lets the site connect.
fn connect(m: &[u8]) -> Result<Answer, Answer> {
    let (Some(index), Some((site, _))) = (u32_at(m, 1), site_at(m, 5)) else { return Err(Answer::new(BAD)) };
    let account = account(index)?;
    let asked = Review::new("Connect wallet?").detail(&which(index)).answers("connect", "don't").page(site_page(site)).signatures(0).timeout(60);
    said_yes(asked.show())?;
    Ok(Answer::new(OK).text(&account.address_string()))
}

/// `M`: a message (EIP-191), signed once the owner has read it: a warning first when it's a
/// sign-in for another site.
fn message(m: &[u8]) -> Result<Answer, Answer> {
    let (Some(index), Some((site, at))) = (u32_at(m, 1), site_at(m, 5)) else { return Err(Answer::new(BAD)) };
    let message = &m[at..];
    let account = account(index)?;
    let mut asked = Review::new("Sign message?").detail("not a transaction").page(site_page(site)).timeout(120);
    for p in display::message_pages(site, message) {
        asked = asked.page(page(p));
    }
    said_yes(asked.show())?;
    let signature = account.sign_message(message).map_err(|_| Answer::new(REFUSED).text("maki couldn't sign it"))?;
    Ok(Answer::new(OK).bytes(&signature))
}

/// A whole transaction: read strictly, shown (the network, the recipient and amount, a token's
/// transfer or approval spelled out, the most the fee can be), and signed on a yes.
fn transaction(account: &Account, site: &str, bytes: &[u8]) -> Result<Vec<u8>, Answer> {
    let tx = Tx::parse(bytes).map_err(|e| Answer::new(REFUSED).text(&e.to_string()))?;
    let (pages, summary) = display::review(&tx).map_err(|e| Answer::new(REFUSED).text(&e.to_string()))?;
    let mut asked = Review::new("Sign and send").detail(&summary).page(site_page(site)).timeout(300);
    for p in pages {
        asked = asked.page(page(p));
    }
    said_yes(asked.show())?;
    tx.sign(account).map_err(|e| Answer::new(REFUSED).text(&e.to_string()))
}

/// Typed data (EIP-712): read from the site's JSON, shown (a permit as who may spend how much of
/// which token, until when; anything else field by field), hashed from what was shown, and
/// signed on a yes.
fn typed(account: &Account, site: &str, bytes: &[u8]) -> Result<[u8; 65], Answer> {
    let text = core::str::from_utf8(bytes).map_err(|_| Answer::new(REFUSED).text("not typed data maki can read: not UTF-8"))?;
    let typed = TypedData::parse(text).map_err(|e| Answer::new(REFUSED).text(&e.to_string()))?;
    let (pages, title, line) = display::typed_review(&typed).map_err(|e| Answer::new(REFUSED).text(&e.to_string()))?;
    let mut asked = Review::new(title).detail(line).page(site_page(site)).timeout(300);
    for p in pages {
        asked = asked.page(page(p));
    }
    said_yes(asked.show())?;
    account.sign_typed(&typed).map_err(|e| Answer::new(REFUSED).text(&e.to_string()))
}

const H: u32 = maki_app::wallet::HARDENED;
const MENU: [&str; 2] = ["Account for MetaMask", "Sign from a QR code"];

/// What MetaMask's QR-code wallets scan to add the account: a UR `crypto-hdkey` (BCR-2020-007),
/// the key at `m/44'/60'/0'` and its chain code, where it's from (maki's fingerprint), and the
/// accounts under it (`0/*`), BIP44's standard ones.
fn hdkey() -> Result<String, Error> {
    let public = maki_app::wallet::public(&[44 | H, 60 | H, H])?;
    let master = u32::from_be_bytes(maki_app::wallet::fingerprint()?);
    let mut e = minicbor::Encoder::new(Vec::new());
    (|| -> Result<(), minicbor::encode::Error<core::convert::Infallible>> {
        let keypath = minicbor::data::Tag::Unassigned(304);
        e.map(8)?;
        e.u8(3)?.bytes(&public.key)?;
        e.u8(4)?.bytes(&public.chain_code)?;
        e.u8(5)?.tag(minicbor::data::Tag::Unassigned(305))?.map(1)?.u8(1)?.u8(60)?;
        e.u8(6)?.tag(keypath)?.map(3)?;
        e.u8(1)?.array(6)?.u32(44)?.bool(true)?.u32(60)?.bool(true)?.u32(0)?.bool(true)?;
        e.u8(2)?.u32(master)?.u8(3)?.u8(3)?;
        e.u8(7)?.tag(keypath)?.map(1)?.u8(1)?.array(4)?.u32(0)?.bool(false)?.array(0)?.bool(false)?;
        e.u8(8)?.u32(u32::from_be_bytes(public.parent_fingerprint))?;
        e.u8(9)?.str("maki")?;
        e.u8(10)?.str("account.standard")?;
        Ok(())
    })()
    .map_err(|_| Error::Failed)?;
    Ok(ur::ur::encode(&e.into_writer(), &ur::ur::Type::Custom("crypto-hdkey")))
}

/// What MetaMask asks a QR-code wallet to sign (ERC-4527's eth-sign-request).
struct Request {
    id: Vec<u8>,
    data: Vec<u8>,
    /// 1 a legacy transaction, 2 typed data, 3 a message, 4 an EIP-1559 transaction
    kind: u32,
    chain: Option<u64>,
    path: Vec<u32>,
    fingerprint: Option<u32>,
    address: Option<Vec<u8>>,
    origin: String,
}

/// A request from its CBOR: None if it isn't one.
fn read_request(cbor: &[u8]) -> Option<Request> {
    let mut d = minicbor::Decoder::new(cbor);
    let n = d.map().ok()??;
    let mut r = Request { id: Vec::new(), data: Vec::new(), kind: 0, chain: None, path: Vec::new(), fingerprint: None, address: None, origin: String::new() };
    for _ in 0..n {
        match d.u32().ok()? {
            1 => {
                d.tag().ok()?;
                r.id = d.bytes().ok()?.to_vec();
            }
            2 => r.data = d.bytes().ok()?.to_vec(),
            3 => r.kind = d.u32().ok()?,
            4 => r.chain = Some(d.u64().ok()?),
            5 => {
                d.tag().ok()?;
                for _ in 0..d.map().ok()?? {
                    match d.u32().ok()? {
                        1 => {
                            let items = d.array().ok()??;
                            for _ in 0..items / 2 {
                                let index = d.u32().ok()?;
                                let hardened = d.bool().ok()?;
                                r.path.push(if hardened { index | H } else { index });
                            }
                        }
                        2 => r.fingerprint = Some(d.u32().ok()?),
                        _ => d.skip().ok()?,
                    }
                }
            }
            6 => r.address = Some(d.bytes().ok()?.to_vec()),
            7 => r.origin = d.str().ok()?.chars().filter(|c| !c.is_control()).take(40).collect(),
            _ => d.skip().ok()?,
        }
    }
    (!r.id.is_empty() && !r.data.is_empty() && (1..=4).contains(&r.kind)).then_some(r)
}

/// The signature for MetaMask to scan: a UR `eth-signature`, the request's ID with it.
fn signature_ur(id: &[u8], signature: &[u8]) -> String {
    let mut e = minicbor::Encoder::new(Vec::new());
    let _ = (|| -> Result<(), minicbor::encode::Error<core::convert::Infallible>> {
        e.map(3)?;
        e.u8(1)?.tag(minicbor::data::Tag::Unassigned(37))?.bytes(id)?;
        e.u8(2)?.bytes(signature)?;
        e.u8(3)?.str("maki")?;
        Ok(())
    })();
    ur::ur::encode(&e.into_writer(), &ur::ur::Type::Custom("eth-signature"))
}

/// What's asked, read off MetaMask's screen: a UR `eth-sign-request`, whole or in parts. Why not,
/// if it isn't one, or the owner stopped.
fn scan_request() -> Result<Request, String> {
    let mut decoder = ur::Decoder::default();
    let (mut seen, mut of) = (std::collections::BTreeSet::new(), 0);
    loop {
        screen::clear(Color::Dark);
        screen::text_centred(24, "Reading the request", Style::Bold, Color::Light);
        let line = if of > 0 { format!("{} of {of} parts", seen.len()) } else { "from MetaMask's screen".into() };
        screen::text_centred(50, &line, Style::Regular, Color::Light);
        screen::text_centred(80, "any button stops", Style::Small, Color::Light);
        screen::present();
        let mut buf = vec![0u8; 4400];
        let Some(text) = camera::scan_qr(&mut buf) else { return Err("stopped".into()) };
        let lower = text.trim().to_ascii_lowercase();
        let Some(rest) = lower.strip_prefix("ur:eth-sign-request/") else { return Err("that isn't a request to sign".into()) };
        let cbor = match ur::ur::decode(&lower) {
            Ok((ur::ur::Kind::SinglePart, cbor)) => cbor,
            Ok((ur::ur::Kind::MultiPart, _)) => {
                if decoder.receive(&lower).is_err() {
                    decoder = ur::Decoder::default();
                    seen.clear();
                    decoder.receive(&lower).map_err(|_| "a part maki can't read")?;
                }
                if let Some((n, total)) = rest.split_once('/').and_then(|(i, _)| i.split_once('-')) {
                    if let (Ok(n), Ok(total)) = (n.parse::<usize>(), total.parse::<usize>()) {
                        of = total;
                        seen.insert(n.min(total + 1));
                    }
                }
                if !decoder.complete() {
                    continue;
                }
                decoder.message().ok().flatten().ok_or("parts that don't add up")?
            }
            Err(_) => return Err("a code maki can't read".into()),
        };
        return read_request(&cbor).ok_or_else(|| "not a request maki can read".into());
    }
}

/// A request signed, once it's checked and gone through on maki's review screen: the signature.
fn sign_request(r: &Request) -> Result<Vec<u8>, String> {
    // an account of this wallet's: m/44'/60'/0'/0/i, maki's fingerprint, its address
    let [a, b, c, 0, index] = r.path[..] else { return Err("for an account maki doesn't make".into()) };
    if [a, b, c] != [44 | H, 60 | H, H] || index >= H {
        return Err("for an account maki doesn't make".into());
    }
    let ours = maki_app::wallet::fingerprint().map(u32::from_be_bytes).map_err(|_| "maki is locked")?;
    if r.fingerprint.is_some_and(|f| f != ours) {
        return Err("for another wallet".into());
    }
    let account = account(index).map_err(|_| "maki is locked")?;
    if r.address.as_deref().is_some_and(|a| a != account.address()) {
        return Err("for another address".into());
    }
    let asked_by = Page::new("Asked by").value("a QR code").mono(if r.origin.is_empty() { "the site isn't known" } else { &r.origin });
    let said = |asked: Result<maki_app::Answer, Error>| said_yes(asked).map_err(|a| refusal(&a));
    match r.kind {
        1 | 4 => {
            let tx = Tx::parse(&r.data).map_err(|e| e.to_string())?;
            if r.chain.is_some_and(|c| c != tx.chain_id) {
                return Err("a transaction for another network than it says".into());
            }
            let (pages, summary) = display::review(&tx).map_err(|e| e.to_string())?;
            let mut asked = Review::new("Sign and send").detail(&summary).page(asked_by).timeout(300);
            for p in pages {
                asked = asked.page(page(p));
            }
            said(asked.show())?;
            tx.signature(&account).map_err(|e| e.to_string())
        }
        2 => {
            let text = core::str::from_utf8(&r.data).map_err(|_| "typed data that isn't UTF-8")?;
            let typed = TypedData::parse(text).map_err(|e| e.to_string())?;
            let (pages, title, line) = display::typed_review(&typed).map_err(|e| e.to_string())?;
            let mut asked = Review::new(title).detail(line).page(asked_by).timeout(300);
            for p in pages {
                asked = asked.page(page(p));
            }
            said(asked.show())?;
            account.sign_typed(&typed).map(|s| s.to_vec()).map_err(|e| e.to_string())
        }
        _ => {
            // the site isn't known, so a sign-in is for the site it names, which the owner reads
            let site = display::sign_in_site(&r.data).unwrap_or_default();
            let mut asked = Review::new("Sign message?").detail("not a transaction").page(asked_by).timeout(120);
            for p in display::message_pages(&site, &r.data) {
                asked = asked.page(page(p));
            }
            said(asked.show())?;
            account.sign_message(&r.data).map(|s| s.to_vec()).map_err(|_| "maki couldn't sign it".into())
        }
    }
}

/// Why it didn't sign, in words, from the answer it would have sent.
fn refusal(a: &Answer) -> String {
    match a.0.first() {
        Some(&DENIED) => "you said no".into(),
        Some(&NO_ANSWER) => "no answer".into(),
        Some(&LOCKED) => "maki is locked".into(),
        _ => "too much to show on maki's screen".into(),
    }
}

/// A QR code on the whole screen until a button; whether the owner left the app meanwhile.
fn show_code(text: &str) -> bool {
    let code = text.to_uppercase();
    let mut hidden = false;
    loop {
        if !hidden {
            screen::clear(Color::Dark);
            let side = screen::qr(0, 0, code.as_bytes(), HEIGHT).unwrap_or(0);
            screen::clear(Color::Dark);
            screen::qr((WIDTH - side) / 2, (HEIGHT - side) / 2, code.as_bytes(), HEIGHT);
            screen::present();
        }
        match wait(None) {
            Event::Centre | Event::Left | Event::Right => return false,
            Event::Hidden => hidden = true,
            Event::Shown => hidden = false,
            Event::Exit => return true,
            _ => {}
        }
    }
}

fn draw_note(note: &str) {
    screen::clear(Color::Dark);
    screen::text_centred(30, "Not signed:", Style::Bold, Color::Light);
    screen::text_centred(52, note, Style::Small, Color::Light);
    screen::text_centred(80, "centre: back", Style::Small, Color::Light);
    screen::present();
}

fn draw(index: u32, as_text: bool) {
    screen::clear(Color::Dark);
    let Ok(account) = Account::new(&HostKeys, index) else {
        screen::text_centred(40, "maki is locked", Style::Regular, Color::Light);
        screen::text_centred(58, "enter its PIN first", Style::Small, Color::Light);
        screen::present();
        return;
    };
    let address = account.address_string();
    if as_text {
        screen::text_centred(2, &which(index), Style::Small, Color::Light);
        for (i, start) in (0..address.len()).step_by(14).enumerate() {
            screen::text_centred(20 + i as i32 * 15, &address[start..(start + 14).min(address.len())], Style::Mono, Color::Light);
        }
    } else {
        let side = screen::qr(0, 0, address.as_bytes(), 94).unwrap_or(0);
        screen::clear(Color::Dark);
        screen::qr((WIDTH - side) / 2, 0, address.as_bytes(), 94);
        let short = format!("{}…{}", &address[..6], &address[address.len() - 4..]);
        screen::text_centred(97, &short, Style::Small, Color::Light);
    }
    screen::present();
}

fn main() {
    let _ = menu(&MENU);
    let (mut index, mut as_text, mut shown) = (0u32, false, true);
    let mut wallet = Wallet::default();
    let mut note = String::new();
    loop {
        if shown && !note.is_empty() {
            draw_note(&note);
        } else if shown {
            draw(index, as_text);
        }
        match wait(None) {
            Event::Message => {
                let mut m = vec![0u8; 4096];
                let n = link::read(&mut m).unwrap_or(0).min(m.len());
                let answer = wallet.answer(&m[..n]);
                let _ = link::reply(&answer.0);
            }
            Event::Centre | Event::Left | Event::Right if !note.is_empty() => note.clear(),
            Event::Menu(0) => match hdkey() {
                Ok(code) => {
                    if show_code(&code) {
                        return;
                    }
                }
                Err(_) => note = "maki is locked".into(),
            },
            // no cable: MetaMask's request off its screen, signed, and the signature shown back
            Event::Menu(1) => match scan_request().and_then(|r| sign_request(&r).map(|s| signature_ur(&r.id, &s))) {
                Ok(code) => {
                    if show_code(&code) {
                        return;
                    }
                }
                Err(why) if why == "stopped" => {}
                Err(why) => note = why,
            },
            Event::Left => index = index.saturating_sub(1),
            Event::Right => index = (index + 1).min(maki_app::wallet::HARDENED - 1),
            Event::Centre => as_text = !as_text,
            Event::Hidden => shown = false,
            Event::Shown => shown = true,
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
