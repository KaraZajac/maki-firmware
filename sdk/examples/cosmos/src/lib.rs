//! Cosmos: maki's Cosmos account, as an app from the maki store (ARCHITECTURE.md, "Wallets are
//! apps"), on the Cosmos Hub and the chains that take its keys. The account is BIP32's on secp256k1
//! at `m/44'/118'/0'/0/i`: the first is every Cosmos wallet's (Keplr's, Cosmostation's, Ledger's
//! Cosmos app's), the next ones CosmJS's and Cosmostation's, so the phrase works there too. maki
//! keeps the key (the wallet permission, on `m/44'/118'` and nothing else); this app reads what it's
//! asked to sign with maki's code (`maki-atom`: a sign doc in Amino JSON, strictly, as the chain
//! writes it to check the signature; coins sent, here or over IBC, staking, rewards and votes
//! spelled out; the fee; a message it can't read flagged; a grant to another account refused), shows
//! it on maki's own review screen, and signs once the owner says yes.
//!
//! Opened, it shows the account's address as a QR code: the centre shows it as text, left and right
//! step through accounts, and the menu's "Next chain" through the chains maki knows.
//!
//! maki desktop talks to it over the link, in the messages every account coin's app speaks. Each
//! starts with what it is, the network (0 for a main network, 1 for a test network) and the account
//! (a u32, little-endian: `i` of `m/44'/118'/0'/0/i`); each answer with a status, then its fields (a
//! string as a u16 length, little-endian, and its UTF-8; REFUSED is followed by why):
//!
//! - `A` network, account, chain: the account's public key, as a length byte (33) and the key compressed
//!   (what a transaction's `/cosmos.crypto.secp256k1.PubKey` carries), and its address on the chain, once the
//!   owner agrees to share them;
//! - `D` network, account, chain: the address, put on maki's screen for the owner to compare with the
//!   computer's; the owner's answer (OK, it matches; DENIED, it doesn't), then maki's address either way;
//! - `T` network, account, then a sign doc: its bytes as CosmJS's `serializeSignDoc` writes them (Amino JSON,
//!   as the chain writes it to check the signature): read, shown, and signed on a yes; the signature, 64
//!   bytes, r and s (s low), as the transaction's `signatures` carries it.
//!
//! The chain, for `A` and `D`, is its chain ID, a string after the account (`osmosis-1`); with
//! nothing after the account, the Cosmos Hub of that network (`cosmoshub-4`, or `provider`, its test
//! network). A sign doc names its own. A chain maki doesn't know, or one on the other kind of network
//! than the message says, is refused.

use maki_app::wallet::{self, Page, Review};
use maki_app::*;
use maki_atom::chains::{self, Chain, Network};
use maki_atom::{SignDoc, account, address, digest, display, path};

const ACCOUNT: u8 = b'A';
const ADDRESS: u8 = b'D';
const TRANSACTION: u8 = b'T';

/// What an answer's first byte says.
const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;
/// Refused, with why: not something maki can read, another network's, or not this account's.
const REFUSED: u8 = 5;

/// The most a message can be: maki's link carries 4096 bytes each way.
const MAX_MESSAGE: usize = 4096;
/// A message's head: what it is, the network, the account.
const HEAD: usize = 6;

const MENU: [&str; 1] = ["Next chain"];

/// An answer: the status, then its fields.
struct Answer(Vec<u8>);

impl Answer {
    fn new(status: u8) -> Answer { Answer(vec![status]) }

    fn text(mut self, s: &str) -> Answer {
        self.0.extend_from_slice(&(s.len() as u16).to_le_bytes());
        self.0.extend_from_slice(s.as_bytes());
        self
    }

    fn bytes(mut self, b: &[u8]) -> Answer {
        self.0.extend_from_slice(b);
        self
    }
}

fn refused(why: &str) -> Answer { Answer::new(REFUSED).text(why) }

/// The network and account a message's head names.
fn head(m: &[u8]) -> Option<(Network, u32)> {
    let network = Network::from_byte(*m.get(1)?)?;
    let index = u32::from_le_bytes(m.get(2..HEAD)?.try_into().ok()?);
    (index < wallet::HARDENED).then_some((network, index))
}

/// The chain an `A` or `D` names after its head: its chain ID, as a string and nothing after it; or
/// nothing, for the network's Cosmos Hub.
fn named_chain(m: &[u8], network: Network) -> Result<&'static Chain, Answer> {
    let rest = &m[HEAD..];
    if rest.is_empty() {
        return Ok(chains::hub(network));
    }
    let id = rest
        .get(..2)
        .map(|n| u16::from_le_bytes([n[0], n[1]]) as usize)
        .filter(|&n| rest.len() == 2 + n)
        .and_then(|_| core::str::from_utf8(&rest[2..]).ok())
        .ok_or_else(|| Answer::new(BAD))?;
    let Some(chain) = chains::by_id(id) else {
        // its ID, as far as it's an ID
        let shown: String = id.chars().take(64).filter(|c| c.is_ascii_graphic()).collect();
        return Err(refused(&format!("a chain maki doesn't know ({shown})")));
    };
    if chain.network != network {
        return Err(refused(&match chain.network {
            Network::Main => {
                format!("{} is a main network, not a test network: its coins are real", chain.id)
            }
            Network::Test => format!("{} is a test network, not a main network", chain.id),
        }));
    }
    Ok(chain)
}

/// The account, as the owner reads it: `cosmos hub`, `osmosis account #2`.
fn which(chain: &Chain, index: u32) -> String {
    let name = chain.name.to_lowercase();
    if index == 0 { name } else { format!("{name} account #{index}") }
}

/// Account `index`'s public key (compressed), and the account it is, from maki; an answer to send
/// back if maki can't give them.
fn keys(index: u32) -> Result<([u8; 33], [u8; 20]), Answer> {
    let public = wallet::public(&path(index)).map_err(|e| match e {
        Error::Locked => Answer::new(LOCKED),
        _ => refused("maki wouldn't give this app that account"),
    })?;
    Ok((public.key, account(&public.key)))
}

/// What the owner answered, as an answer's status.
fn status(a: maki_app::Answer) -> u8 {
    match a {
        maki_app::Answer::Yes => OK,
        maki_app::Answer::No => DENIED,
        maki_app::Answer::NoAnswer => NO_ANSWER,
    }
}

/// The owner's answer to a review: go on, or the answer to send back.
fn said_yes(asked: Result<maki_app::Answer, Error>) -> Result<(), Answer> {
    match asked {
        Ok(maki_app::Answer::Yes) => Ok(()),
        Ok(a) => Err(Answer::new(status(a))),
        Err(Error::Locked) => Err(Answer::new(LOCKED)),
        Err(_) => Err(refused("too much to show on maki's screen")),
    }
}

fn answer(m: &[u8]) -> Answer {
    let result = match m.first() {
        Some(&ACCOUNT) => share(m),
        Some(&ADDRESS) => compare(m),
        Some(&TRANSACTION) => sign(m),
        _ => Err(Answer::new(BAD)),
    };
    result.unwrap_or_else(|a| a)
}

/// `A`: the account's key and address on a chain, once the owner agrees: view only, but everything
/// the account does is theirs to see.
fn share(m: &[u8]) -> Result<Answer, Answer> {
    let Some((network, index)) = head(m) else { return Err(Answer::new(BAD)) };
    let chain = named_chain(m, network)?;
    let (key, me) = keys(index)?;
    let asked = Review::new("Share account?")
        .detail(&format!("{}, view only", which(chain, index)))
        .answers("share", "don't")
        .signatures(0)
        .timeout(60);
    said_yes(asked.show())?;
    Ok(Answer::new(OK).bytes(&[key.len() as u8]).bytes(&key).text(&address(chain, &me)))
}

/// `D`: the address on a chain, on maki's screen for the owner to compare with the computer's.
fn compare(m: &[u8]) -> Result<Answer, Answer> {
    let Some((network, index)) = head(m) else { return Err(Answer::new(BAD)) };
    let chain = named_chain(m, network)?;
    let (_, me) = keys(index)?;
    let a = address(chain, &me);
    let asked = Review::new("Same on computer?")
        .answers("matches", "doesn't match")
        .page(Page::new("Address").value(&which(chain, index)).mono(&a))
        .signatures(0)
        .show();
    match asked {
        Ok(answer) => Ok(Answer::new(status(answer)).text(&a)),
        Err(Error::Locked) => Err(Answer::new(LOCKED)),
        Err(_) => Err(refused("maki couldn't show it")),
    }
}

fn page(p: display::Page) -> Page { Page::new(&p.heading).value(&p.value).mono(&p.mono).prose(&p.prose) }

/// `T`: a sign doc, read strictly (one for a chain maki doesn't know, on the other kind of network,
/// another account's, or anything the chain would refuse, refused before anything is shown), shown
/// (the chain, what each message does, the memo, the fee, whatever maki can't read), and signed on
/// a yes.
fn sign(m: &[u8]) -> Result<Answer, Answer> {
    let Some((network, index)) = head(m) else { return Err(Answer::new(BAD)) };
    let bytes = &m[HEAD..];
    let (_, me) = keys(index)?;
    let doc = SignDoc::parse(bytes).map_err(|e| refused(&e.to_string()))?;
    let review = display::review(&doc, &me, network).map_err(|e| refused(&e.to_string()))?;
    let mut asked = Review::new("Sign and send").detail(&review.summary).timeout(300).signatures(1);
    for p in review.pages {
        asked = asked.page(page(p));
    }
    said_yes(asked.show())?;
    match wallet::sign_ecdsa(&path(index), &digest(bytes)) {
        Ok((rs, _)) => Ok(Answer::new(OK).bytes(&rs)),
        Err(Error::Locked) => Err(Answer::new(LOCKED)),
        Err(_) => Err(refused("maki couldn't sign it")),
    }
}

fn draw(chain: &Chain, index: u32, as_text: bool) {
    screen::clear(Color::Dark);
    let Ok((_, me)) = keys(index) else {
        screen::text_centred(40, "maki is locked", Style::Regular, Color::Light);
        screen::text_centred(58, "enter its PIN first", Style::Small, Color::Light);
        screen::present();
        return;
    };
    let address = address(chain, &me);
    if as_text {
        screen::text_centred(2, &which(chain, index), Style::Small, Color::Light);
        // 47 characters at most (celestia1…): four lines of twelve
        for (i, start) in (0..address.len()).step_by(12).enumerate() {
            screen::text_centred(
                20 + i as i32 * 15,
                &address[start..(start + 12).min(address.len())],
                Style::Mono,
                Color::Light,
            );
        }
    } else {
        let side = screen::qr(0, 0, address.as_bytes(), 94).unwrap_or(0);
        screen::clear(Color::Dark);
        screen::qr((WIDTH - side) / 2, 0, address.as_bytes(), 94);
        // the prefix and the first characters after it, and the last
        let head = chain.prefix.len() + 5;
        let short = format!("{}…{}", &address[..head], &address[address.len() - 4..]);
        screen::text_centred(97, &short, Style::Small, Color::Light);
    }
    screen::present();
}

fn main() {
    let _ = menu(&MENU);
    let (mut chain, mut index, mut as_text, mut shown) = (0usize, 0u32, false, true);
    loop {
        if shown {
            draw(&chains::CHAINS[chain], index, as_text);
        }
        match wait(None) {
            Event::Message => {
                let mut m = vec![0u8; MAX_MESSAGE];
                // the whole message's length: one longer than the link carries isn't read at all
                let n = link::read(&mut m).unwrap_or(0);
                let reply = if n > MAX_MESSAGE { Answer::new(BAD) } else { answer(&m[..n]) };
                let _ = link::reply(&reply.0);
            }
            Event::Left => index = index.saturating_sub(1),
            Event::Right => index = (index + 1).min(wallet::HARDENED - 1),
            Event::Centre => as_text = !as_text,
            Event::Menu(0) => chain = (chain + 1) % chains::CHAINS.len(),
            Event::Hidden => shown = false,
            Event::Shown => shown = true,
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
