//! Cardano: maki's Cardano account, as an app from the maki store (ARCHITECTURE.md, "Wallets are
//! apps"). Its keys are BIP32-Ed25519's from the phrase's entropy (Icarus, CIP-3) at CIP-1852's
//! `m/1852'/1815'/account'/role/index`, as Eternl, Lace, Yoroi, Daedalus, Ledger and Trezor make
//! them, so the phrase works there too; its addresses pay one of its payment keys and stake with its
//! stake key (`2/0`). maki keeps the keys (the wallet permission, BIP32-Ed25519 on `m/1852'/1815'`
//! and nothing else: host API 11); this app reads what it's asked to sign with maki's code
//! (`maki-ada`: a transaction's body as the ledger reads it, written as Cardano's hardware wallets
//! take it; ADA and tokens sent and to whom, change only where maki has made the address itself,
//! staking, rewards and vote delegation spelled out, the fee; what's for scripts, pools and
//! governance refused), shows it on maki's own review screen, and signs once the owner says yes.
//!
//! Opened, it shows the account's first address as a QR code: the centre shows it as text, left
//! and right step through accounts.
//!
//! maki desktop talks to it over the link. Each message starts with what it is, the network (0 for
//! Cardano's own, 1 for Preprod, its test network) and the account (a u32, little-endian: `account`
//! of `m/1852'/1815'/account'`), and is 4096 bytes at most; each answer with a status, then its
//! fields (a string as a u16 length, little-endian, and its UTF-8; REFUSED is followed by why):
//!
//! - `A` network, account: the account's public key and chain code (a length byte, 64, then the key's 32
//!   bytes and the chain code's 32: every address under the account is worked out from them, as Cardano's
//!   wallets do), and its first address (`0/0`'s, with its stake key), once the owner agrees to share them;
//! - `D` network, account, role (u8), index (u32): an address, put on maki's screen for the owner to compare
//!   with the computer's: role 0 (receiving) or 1 (change) with an index below 2^31, a base address paying
//!   that key and staking with the account's stake key; or role 2, index 0, the account's reward address
//!   (`stake1…`). The owner's answer (OK, it matches; DENIED, it doesn't), then maki's address either way;
//! - `T` network, account, total (u32), offset (u32), then a piece: a request (`maki_ada::request`: the keys
//!   that sign, the outputs that are change, then the transaction's body as it will go on chain) of `total`
//!   bytes, in pieces in order from offset 0, each answered MORE (6) until the last. Then it's read, shown,
//!   and signed on a yes: OK, then for each key asked for, in order, its 32-byte public key and its 64-byte
//!   Ed25519 signature of the body's hash (the transaction's ID), a witness as the transaction's witness set
//!   holds one.
//!
//! Statuses: 0 OK, 1 DENIED, 2 NO_ANSWER, 3 LOCKED, 4 BAD (not a message this app takes), 5 REFUSED,
//! then why, 6 MORE.

use maki_ada::address::RewardAccount;
use maki_ada::display::{self, Account, Own};
use maki_ada::request::{self, Key, Request};
use maki_ada::{Address, Body, Network, key_hash, key_path, stake_path, tx_id};
use maki_app::wallet::{self, Page, Review};
use maki_app::*;

const ACCOUNT: u8 = b'A';
const ADDRESS: u8 = b'D';
const TRANSACTION: u8 = b'T';

/// What an answer's first byte says.
const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;
/// Refused, with why: not something maki can read, or not this account's.
const REFUSED: u8 = 5;
/// A piece taken: send the next.
const MORE: u8 = 6;

/// The most a message can be: maki's link carries 4096 bytes each way.
const MAX_MESSAGE: usize = 4096;
/// A message's head: what it is, the network, the account.
const HEAD: usize = 6;
/// `T`'s head: that, then the request's total and the piece's offset.
const PIECE_HEAD: usize = HEAD + 8;

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

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
}

/// The network and account a message's head names.
fn head(m: &[u8]) -> Option<(Network, u32)> {
    let network = Network::from_byte(*m.get(1)?)?;
    let account = u32_at(m, 2)?;
    (account < wallet::HARDENED).then_some((network, account))
}

/// The account, as the owner reads it: `cardano`, `cardano preprod account #2`.
fn which(network: Network, account: u32) -> String {
    let name = match network {
        Network::Mainnet => "cardano",
        Network::Preprod => "cardano preprod",
    };
    if account == 0 { name.into() } else { format!("{name} account #{account}") }
}

/// What maki's keys said, as an answer.
fn keys_error(e: Error) -> Answer {
    match e {
        Error::Locked => Answer::new(LOCKED),
        _ => refused("maki wouldn't give this app that key"),
    }
}

/// A key's public key and chain code, from maki.
fn public(path: &[u32]) -> Result<[u8; 64], Answer> { wallet::cardano_public(path).map_err(keys_error) }

/// A key's hash, as addresses and certificates name it.
fn hash_at(path: &[u32]) -> Result<maki_ada::Hash28, Answer> {
    let key = public(path)?;
    let mut k = [0u8; 32];
    k.copy_from_slice(&key[..32]);
    Ok(key_hash(&k))
}

/// The address at `role`/`index` of `account`: a base address paying that key and staking with the
/// account's stake key, or, for the stake key itself (2/0), its reward address.
fn address(network: Network, account: u32, role: u8, index: u32) -> Result<String, Answer> {
    let stake = hash_at(&stake_path(account))?;
    if Key::witness(role, index) == Some(Key::STAKE) {
        return Ok(RewardAccount::new(network, &stake).text());
    }
    let payment = hash_at(&key_path(account, role, index))?;
    Ok(Address::base(network, &payment, &stake).text())
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

/// `A`: the account's key and chain code, and its first address, once the owner agrees: view only,
/// but every address the account will ever have, and everything it does.
fn share(m: &[u8]) -> Result<Answer, Answer> {
    let Some((network, account)) = head(m).filter(|_| m.len() == HEAD) else { return Err(Answer::new(BAD)) };
    let key = public(&maki_ada::account_path(account))?;
    let first = address(network, account, 0, 0)?;
    let asked = Review::new("Share account?")
        .detail(&format!("{}, view only", which(network, account)))
        .answers("share", "don't")
        .signatures(0)
        .timeout(60);
    said_yes(asked.show())?;
    Ok(Answer::new(OK).bytes(&[key.len() as u8]).bytes(&key).text(&first))
}

/// `D`: an address, on maki's screen for the owner to compare with the computer's.
fn compare(m: &[u8]) -> Result<Answer, Answer> {
    let Some((network, account)) = head(m).filter(|_| m.len() == HEAD + 5) else {
        return Err(Answer::new(BAD));
    };
    let (role, index) = (m[HEAD], u32_at(m, HEAD + 1).unwrap_or(u32::MAX));
    let heading = match Key::witness(role, index) {
        Some(Key::STAKE) => String::from("Stake address"),
        Some(Key { role: maki_ada::CHANGE, index }) => format!("Change #{index}"),
        Some(Key { index, .. }) => format!("Receive #{index}"),
        None => return Err(Answer::new(BAD)),
    };
    let a = address(network, account, role, index)?;
    let asked = Review::new("Same on computer?")
        .answers("matches", "doesn't match")
        .page(Page::new(&heading).value(&which(network, account)).mono(&a))
        .signatures(0)
        .show();
    match asked {
        Ok(answer) => Ok(Answer::new(status(answer)).text(&a)),
        Err(Error::Locked) => Err(Answer::new(LOCKED)),
        Err(_) => Err(refused("maki couldn't show it")),
    }
}

fn page(p: display::Page) -> Page { Page::new(&p.heading).value(&p.value).mono(&p.mono).prose(&p.prose) }

/// A request coming in, in pieces: its network, account and total, and what's come so far.
#[derive(Default)]
struct Incoming {
    head: Option<(Network, u32, usize)>,
    bytes: Vec<u8>,
}

impl Incoming {
    /// `T`: a piece of a request; the last read, shown, and signed on a yes.
    fn piece(&mut self, m: &[u8]) -> Answer {
        let (Some((network, account)), Some(total), Some(offset)) =
            (head(m), u32_at(m, HEAD), u32_at(m, HEAD + 4))
        else {
            self.forget();
            return Answer::new(BAD);
        };
        let (total, offset, piece) = (total as usize, offset as usize, &m[PIECE_HEAD.min(m.len())..]);
        if total > request::MAX_REQUEST {
            self.forget();
            return refused("bigger than a Cardano transaction can be");
        }
        if offset == 0 {
            self.forget();
            // locked, nothing more's worth sending
            if let Err(a) = public(&stake_path(account)) {
                return a;
            }
            self.head = Some((network, account, total));
        }
        let fits = offset == self.bytes.len() && offset + piece.len() <= total && !piece.is_empty();
        if self.head != Some((network, account, total)) || !fits {
            self.forget();
            return Answer::new(BAD);
        }
        self.bytes.extend_from_slice(piece);
        if self.bytes.len() < total {
            return Answer::new(MORE);
        }
        let bytes = core::mem::take(&mut self.bytes);
        self.forget();
        sign(network, account, &bytes).unwrap_or_else(|a| a)
    }

    fn forget(&mut self) {
        self.head = None;
        self.bytes.clear();
    }
}

/// A whole request: read strictly (anything Cardano would refuse, another account's, or for another
/// network, refused before anything is shown), shown (the network, what it pays and does, the fee,
/// what's out of the ordinary), and signed on a yes by each key asked for.
fn sign(network: Network, account: u32, bytes: &[u8]) -> Result<Answer, Answer> {
    let request = Request::parse(bytes).map_err(|e| refused(&e.to_string()))?;
    let body = Body::parse(request.body).map_err(|e| refused(&e.to_string()))?;
    let me = Account { network, stake: hash_at(&stake_path(account))? };
    let mut change = Vec::with_capacity(request.change.len());
    for c in &request.change {
        change.push(Own {
            output: c.output,
            key: c.key,
            payment: hash_at(&key_path(account, c.key.role, c.key.index))?,
        });
    }
    // each key that signs, as its witness names it
    let mut keys = Vec::with_capacity(request.witnesses.len());
    for k in &request.witnesses {
        let path = key_path(account, k.role, k.index);
        keys.push((path, public(&path)?));
    }
    let now = unix_time();
    let review =
        display::review(&body, &me, &change, keys.len(), now).map_err(|e| refused(&e.to_string()))?;
    let mut asked =
        Review::new("Sign and send").detail(&review.summary).timeout(300).signatures(keys.len() as u32);
    for p in review.pages {
        asked = asked.page(page(p));
    }
    said_yes(asked.show())?;
    let id = tx_id(request.body);
    let mut answer = Answer::new(OK);
    for (path, key) in &keys {
        let signature = wallet::sign_cardano(path, &id).map_err(|e| match e {
            Error::Locked => Answer::new(LOCKED),
            _ => refused("maki couldn't sign it"),
        })?;
        answer = answer.bytes(&key[..32]).bytes(&signature);
    }
    Ok(answer)
}

fn draw(account: u32, as_text: bool) {
    screen::clear(Color::Dark);
    let Ok(address) = address(Network::Mainnet, account, 0, 0) else {
        screen::text_centred(40, "maki is locked", Style::Regular, Color::Light);
        screen::text_centred(58, "enter its PIN first", Style::Small, Color::Light);
        screen::present();
        return;
    };
    if as_text {
        // 103 characters: eight lines of thirteen at most, a little closer than the font's own
        for (i, start) in (0..address.len()).step_by(13).enumerate() {
            screen::text_centred(
                2 + i as i32 * 13,
                &address[start..(start + 13).min(address.len())],
                Style::Mono,
                Color::Light,
            );
        }
    } else {
        let side = screen::qr(0, 0, address.as_bytes(), 94).unwrap_or(0);
        screen::clear(Color::Dark);
        screen::qr((WIDTH - side) / 2, 0, address.as_bytes(), 94);
        let caption =
            if account == 0 { String::from("cardano account") } else { format!("account #{account}") };
        screen::text_centred(97, &caption, Style::Small, Color::Light);
    }
    screen::present();
}

fn main() {
    let (mut account, mut as_text, mut shown) = (0u32, false, true);
    let mut incoming = Incoming::default();
    loop {
        if shown {
            draw(account, as_text);
        }
        match wait(None) {
            Event::Message => {
                let mut m = vec![0u8; MAX_MESSAGE];
                // the whole message's length: one longer than the link carries isn't read at all
                let n = link::read(&mut m).unwrap_or(0);
                let reply = if n > MAX_MESSAGE {
                    incoming.forget();
                    Answer::new(BAD)
                } else {
                    let m = &m[..n];
                    match m.first() {
                        Some(&ACCOUNT) => share(m).unwrap_or_else(|a| a),
                        Some(&ADDRESS) => compare(m).unwrap_or_else(|a| a),
                        Some(&TRANSACTION) => incoming.piece(m),
                        _ => Answer::new(BAD),
                    }
                };
                let _ = link::reply(&reply.0);
            }
            Event::Left => account = account.saturating_sub(1),
            Event::Right => account = (account + 1).min(wallet::HARDENED - 1),
            Event::Centre => as_text = !as_text,
            Event::Hidden => shown = false,
            Event::Shown => shown = true,
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
