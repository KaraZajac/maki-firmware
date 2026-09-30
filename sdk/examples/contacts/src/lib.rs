//! Contacts: your card as a QR code, to swap at the con. A card is a name and up to three lines
//! (a handle, an email, a site), signed with a key from the recovery phrase (the keys
//! permission's Ed25519 key, which maki holds): another maki scans it (camera), checks the
//! signature itself, and keeps who you are and when you met. A phone's contact QR code (a vCard or
//! a MECARD) is kept too, marked as unsigned.
//!
//! On maki: your card (the centre goes to the people you met); the people, left and right going
//! through them, the centre opening one; the menu scans a card, or forgets someone.
//!
//! A maki card's QR code is `MAKI1:` and, in base45 (RFC 9285, the QR code's own alphabet), its
//! version (1), its name and lines (each a byte's length, then UTF-8; the lines after a byte's
//! count), its public key (32 bytes) and the Ed25519 signature of all that (64).
//!
//! The link's messages, a byte saying what first:
//! - `C`, then a card as above from its version to its lines: your card from now on, once the owner says yes.
//!   Answered `0`, or `1` the owner said no, `2` no answer, `3` maki is locked, `4` not a card it takes.
//! - `P`: the people met, once the owner says yes: `0`, then for each, whether its card was signed (a byte),
//!   when you met (u64, seconds since 1970, 0 if maki didn't know), its card as above (a u16's length,
//!   little-endian, first), and its key (32 bytes) if signed.

use maki_app::*;

const LABEL: &str = "card";
const PREFIX: &str = "MAKI1:";
const VERSION: u8 = 1;
/// A name's and a line's most bytes, and the most lines.
const NAME: usize = 32;
const LINE: usize = 48;
const LINES: usize = 3;

const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;

const B45: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

fn base45(data: &[u8]) -> String {
    let mut out = String::new();
    for pair in data.chunks(2) {
        let (mut n, digits) = match pair {
            [a, b] => ((*a as u32) << 8 | *b as u32, 3),
            [a] => (*a as u32, 2),
            _ => unreachable!(),
        };
        for _ in 0..digits {
            out.push(B45[(n % 45) as usize] as char);
            n /= 45;
        }
    }
    out
}

fn unbase45(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u32> =
        text.bytes().map(|c| B45.iter().position(|&b| b == c).map(|i| i as u32)).collect::<Option<_>>()?;
    let mut out = Vec::new();
    for group in digits.chunks(3) {
        match group {
            [c, d, e] => {
                let n = c + d * 45 + e * 45 * 45;
                if n > 0xffff {
                    return None;
                }
                out.extend_from_slice(&[(n >> 8) as u8, n as u8]);
            }
            [c, d] => {
                let n = c + d * 45;
                if n > 0xff {
                    return None;
                }
                out.push(n as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// A name and up to three lines.
#[derive(Clone, PartialEq, Debug)]
struct Card {
    name: String,
    lines: Vec<String>,
}

fn text_ok(s: &str, most: usize) -> bool { s.len() <= most && !s.chars().any(|c| c.is_control()) }

impl Card {
    fn ok(&self) -> bool {
        !self.name.trim().is_empty()
            && text_ok(&self.name, NAME)
            && self.lines.len() <= LINES
            && self.lines.iter().all(|l| text_ok(l, LINE))
    }

    /// Its version, name and lines, as the card's bytes have them.
    fn body(&self) -> Vec<u8> {
        let mut b = vec![VERSION, self.name.len() as u8];
        b.extend_from_slice(self.name.as_bytes());
        b.push(self.lines.len() as u8);
        for l in &self.lines {
            b.push(l.len() as u8);
            b.extend_from_slice(l.as_bytes());
        }
        b
    }

    /// A card from its bytes, and what's left after it.
    fn read(bytes: &[u8]) -> Option<(Card, &[u8])> {
        let mut r = bytes;
        let mut take = |n: usize| -> Option<&[u8]> {
            let (a, b) = (r.get(..n)?, r.get(n..)?);
            r = b;
            Some(a)
        };
        if take(1)? != [VERSION] {
            return None;
        }
        let n = take(1)?[0] as usize;
        let name = String::from_utf8(take(n)?.to_vec()).ok()?;
        let count = take(1)?[0] as usize;
        let mut lines = Vec::new();
        for _ in 0..count {
            let n = take(1)?[0] as usize;
            lines.push(String::from_utf8(take(n)?.to_vec()).ok()?);
        }
        let card = Card { name, lines };
        card.ok().then_some((card, r))
    }
}

/// Your card, signed, as its QR code says it.
fn your_code(card: &Card) -> Option<String> {
    let mut bytes = card.body();
    bytes.extend_from_slice(&keys::public_key(LABEL).ok()?);
    let signature = keys::sign(LABEL, &bytes).ok()?;
    bytes.extend_from_slice(&signature);
    Some(format!("{PREFIX}{}", base45(&bytes)))
}

/// A maki card from its QR code: the card and its key, if its signature checks out.
fn read_maki(text: &str) -> Option<(Card, [u8; 32])> {
    let bytes = unbase45(text.strip_prefix(PREFIX)?)?;
    let (card, rest) = Card::read(&bytes)?;
    if rest.len() != 32 + 64 {
        return None;
    }
    let signed = &bytes[..bytes.len() - 64];
    let key = ed25519_compact::PublicKey::from_slice(&rest[..32]).ok()?;
    let signature = ed25519_compact::Signature::from_slice(&rest[32..]).ok()?;
    key.verify(signed, &signature).ok()?;
    Some((card, rest[..32].try_into().ok()?))
}

fn fit(s: &str, most: usize) -> String {
    let mut out = String::new();
    for c in s.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > most {
            break;
        }
        out.push(c);
    }
    out.trim().to_string()
}

/// A phone's contact QR code, a vCard or a MECARD: its name, and a phone number, an email and a
/// site as its lines. Unsigned.
fn read_phone(text: &str) -> Option<Card> {
    let (mut name, mut lines) = (String::new(), Vec::new());
    if text.starts_with("BEGIN:VCARD") {
        let mut family = String::new();
        for line in text.lines() {
            let (key, value) = line.split_once(':')?;
            let key = key.split(';').next().unwrap_or("").to_ascii_uppercase();
            match key.as_str() {
                "FN" => name = value.to_string(),
                "N" => {
                    let mut parts = value.split(';');
                    let (last, first) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                    family = format!("{first} {last}").trim().to_string();
                }
                "TEL" | "EMAIL" | "URL" if lines.len() < LINES => lines.push(fit(value, LINE)),
                _ => {}
            }
        }
        if name.is_empty() {
            name = family;
        }
    } else if let Some(body) = text.strip_prefix("MECARD:") {
        for field in body.split(';') {
            let Some((key, value)) = field.split_once(':') else { continue };
            match key {
                "N" => name = value.split(',').rev().collect::<Vec<_>>().join(" ").trim().to_string(),
                "TEL" | "EMAIL" | "URL" if lines.len() < LINES => lines.push(fit(value, LINE)),
                _ => {}
            }
        }
    } else {
        return None;
    }
    let card = Card { name: fit(&name, NAME), lines: lines.into_iter().filter(|l| !l.is_empty()).collect() };
    card.ok().then_some(card)
}

/// Someone you met.
struct Person {
    key: String,
    card: Card,
    /// their card's key, if it was signed
    signer: Option<[u8; 32]>,
    met: u64,
}

impl Person {
    fn bytes(&self) -> Vec<u8> {
        let mut b = vec![self.signer.is_some() as u8];
        b.extend_from_slice(&self.met.to_le_bytes());
        let body = self.card.body();
        b.extend_from_slice(&(body.len() as u16).to_le_bytes());
        b.extend_from_slice(&body);
        if let Some(k) = self.signer {
            b.extend_from_slice(&k);
        }
        b
    }

    fn read(key: String, b: &[u8]) -> Option<Person> {
        let signed = *b.first()? == 1;
        let met = u64::from_le_bytes(b.get(1..9)?.try_into().ok()?);
        let n = u16::from_le_bytes(b.get(9..11)?.try_into().ok()?) as usize;
        let (card, _) = Card::read(b.get(11..11 + n)?)?;
        let signer = if signed { Some(b.get(11 + n..11 + n + 32)?.try_into().ok()?) } else { None };
        Some(Person { key, card, signer, met })
    }
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

/// A key for someone in storage: their card's key, or (unsigned) what their card says.
fn storage_key(card: &Card, signer: Option<&[u8; 32]>) -> String {
    match signer {
        Some(k) => format!("p:{}", hex(&k[..8])),
        None => {
            // FNV-1a over the card: the same card, the same person
            let h = card
                .body()
                .iter()
                .fold(0xcbf2_9ce4_8422_2325u64, |h, &b| (h ^ b as u64).wrapping_mul(0x100_0000_01b3));
            format!("p:u{h:016x}")
        }
    }
}

fn load() -> Vec<Person> {
    let mut people = Vec::new();
    let mut name = [0u8; 48];
    let mut buf = vec![0u8; 512];
    let mut i = 0;
    while let Some(key) = storage::key(i, &mut name) {
        i += 1;
        if !key.starts_with("p:") {
            continue;
        }
        let key = key.to_string();
        if let Some(n) = storage::get(&key, &mut buf) {
            if let Some(p) = Person::read(key, &buf[..n.min(buf.len())]) {
                people.push(p);
            }
        }
    }
    people.sort_by_key(|p| p.met);
    people
}

/// A day from seconds since 1970 (the civil calendar from days since then).
fn date(secs: u64) -> String {
    const MONTHS: [&str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!("{day} {} {year}", MONTHS[month as usize - 1])
}

/// `text` cut to fit `room` pixels in `style`, with "..." where it's cut.
fn fit_width(text: &str, style: Style, room: i32) -> String {
    if screen::text_width(text, style) <= room {
        return text.to_string();
    }
    let mut cut = text.to_string();
    while !cut.is_empty() && screen::text_width(&format!("{cut}..."), style) > room {
        cut.pop();
    }
    format!("{}...", cut.trim_end())
}

#[derive(Clone, Copy, PartialEq)]
enum View {
    Card,
    People,
    Person(usize),
}

struct App {
    card: Option<Card>,
    code: Option<String>,
    people: Vec<Person>,
    selected: usize,
    view: View,
    note: String,
}

impl App {
    fn draw(&mut self) {
        screen::clear(Color::Dark);
        match self.view {
            View::Card => match (&self.card, &self.code) {
                (Some(_), Some(code)) => {
                    let side = screen::qr(0, 0, code.as_bytes(), HEIGHT).unwrap_or(0);
                    screen::clear(Color::Dark);
                    screen::qr((WIDTH - side) / 2, (HEIGHT - side) / 2, code.as_bytes(), HEIGHT);
                }
                (Some(_), None) => {
                    screen::text_centred(30, "Unlock maki to", Style::Regular, Color::Light);
                    screen::text_centred(45, "show your card", Style::Regular, Color::Light);
                }
                (None, _) => {
                    screen::text_centred(24, "No card yet", Style::Bold, Color::Light);
                    screen::text_centred(48, "make yours in", Style::Small, Color::Light);
                    screen::text_centred(60, "maki desktop", Style::Small, Color::Light);
                    screen::text_centred(84, "centre: people you met", Style::Small, Color::Light);
                }
            },
            View::People => {
                if self.people.is_empty() {
                    screen::text_centred(24, "Nobody yet", Style::Bold, Color::Light);
                    screen::text_centred(48, "menu: Scan a card", Style::Small, Color::Light);
                } else {
                    let first = self.selected.saturating_sub(5);
                    for (row, (i, p)) in self.people.iter().enumerate().skip(first).take(6).enumerate() {
                        let y = row as i32 * 16;
                        if i == self.selected {
                            screen::fill_rect(0, y, WIDTH, 16, Color::Light);
                        }
                        let color = if i == self.selected { Color::Dark } else { Color::Light };
                        screen::text(
                            3,
                            y,
                            &fit_width(&p.card.name, Style::Regular, WIDTH - 6),
                            Style::Regular,
                            color,
                        );
                    }
                }
                self.foot(&format!("{} people", self.people.len()));
            }
            View::Person(i) => {
                let Some(p) = self.people.get(i) else { return };
                screen::text(
                    2,
                    0,
                    &fit_width(&p.card.name, Style::Bold, WIDTH - 4),
                    Style::Bold,
                    Color::Light,
                );
                for (row, l) in p.card.lines.iter().enumerate() {
                    screen::text(
                        2,
                        18 + row as i32 * 13,
                        &fit_width(l, Style::Small, WIDTH - 4),
                        Style::Small,
                        Color::Light,
                    );
                }
                let met = if p.met > 0 { format!("met {}", date(p.met)) } else { "met".to_string() };
                screen::text(2, 60, &met, Style::Small, Color::Light);
                let signed = match p.signer {
                    Some(k) => format!("signed, key {}", &hex(&k[..4])),
                    None => "unsigned: a phone's card".to_string(),
                };
                screen::text(2, 73, &signed, Style::Small, Color::Light);
                self.foot(&format!("{} of {}", i + 1, self.people.len()));
            }
        }
        screen::present();
    }

    fn foot(&self, otherwise: &str) {
        screen::line(0, 97, WIDTH - 1, 97, Color::Light);
        let text = if self.note.is_empty() { otherwise } else { &self.note };
        screen::text_centred(99, text, Style::Small, Color::Light);
    }

    fn scan(&mut self) {
        let mut buf = vec![0u8; 4400];
        let Some(text) = camera::scan_qr(&mut buf) else {
            self.note = "nothing read".into();
            return;
        };
        let (card, signer) = if text.starts_with(PREFIX) {
            match read_maki(text) {
                Some((card, key)) => (card, Some(key)),
                None => {
                    self.note = "a maki card that doesn't check out".into();
                    return;
                }
            }
        } else {
            match read_phone(text) {
                Some(card) => (card, None),
                None => {
                    self.note = "that isn't a card".into();
                    return;
                }
            }
        };
        let key = storage_key(&card, signer.as_ref());
        let person = Person { key: key.clone(), card, signer, met: unix_time().unwrap_or(0) };
        if storage::set(&key, &person.bytes()).is_err() {
            self.note = "no room for more".into();
            return;
        }
        self.people.retain(|p| p.key != key);
        self.people.push(person);
        self.selected = self.people.len() - 1;
        self.view = View::Person(self.selected);
        self.note = if signer.is_some() { "kept: signed by their maki" } else { "kept: unsigned" }.into();
    }

    /// A message from maki desktop, and the answer.
    fn handle(&mut self, message: &[u8]) -> Vec<u8> {
        match message.first() {
            Some(b'C') => {
                let Some((card, rest)) = Card::read(&message[1..]) else { return vec![BAD] };
                if !rest.is_empty() {
                    return vec![BAD];
                }
                let detail = if card.lines.is_empty() {
                    card.name.clone()
                } else {
                    format!("{}: {}", card.name, card.lines.join(", "))
                };
                match Ask::new("Make this your card?").detail(&fit(&detail, 120)).answers("yes", "no").show()
                {
                    Ok(Answer::Yes) => {}
                    Ok(Answer::No) => return vec![DENIED],
                    _ => return vec![NO_ANSWER],
                }
                let Some(code) = your_code(&card) else { return vec![LOCKED] };
                let _ = storage::set("card", &card.body());
                self.card = Some(card);
                self.code = Some(code);
                self.view = View::Card;
                vec![OK]
            }
            Some(b'P') if message.len() == 1 => {
                let detail = format!("{} people", self.people.len());
                match Ask::new("Share who you met with the computer?")
                    .detail(&detail)
                    .answers("share", "no")
                    .show()
                {
                    Ok(Answer::Yes) => {}
                    Ok(Answer::No) => return vec![DENIED],
                    _ => return vec![NO_ANSWER],
                }
                let mut a = vec![OK];
                for p in &self.people {
                    a.extend_from_slice(&p.bytes());
                }
                a
            }
            _ => vec![BAD],
        }
    }
}

fn main() {
    let _ = menu(&["Scan a card", "People you met", "Your card", "Forget this one"]);
    let mut buf = [0u8; 256];
    let card =
        storage::get("card", &mut buf).and_then(|n| Card::read(&buf[..n.min(buf.len())]).map(|(c, _)| c));
    let code = card.as_ref().and_then(your_code);
    let mut app = App { card, code, people: load(), selected: 0, view: View::Card, note: String::new() };
    loop {
        app.draw();
        let event = wait(None);
        if !matches!(event, Event::Message | Event::Hidden | Event::Shown) {
            app.note.clear();
        }
        let n = app.people.len();
        match (app.view, event) {
            (_, Event::Message) => {
                let mut message = vec![0u8; 4096];
                let answer = match link::read(&mut message) {
                    Some(len) if len <= message.len() => app.handle(&message[..len]),
                    _ => vec![BAD],
                };
                let _ = link::reply(&answer);
            }
            (_, Event::Exit) => return,
            (_, Event::Menu(0)) => app.scan(),
            (_, Event::Menu(1)) | (View::Card, Event::Centre) | (View::Person(_), Event::Centre) => {
                app.view = View::People
            }
            (_, Event::Menu(2)) => app.view = View::Card,
            (View::Person(i), Event::Menu(3)) => {
                let p = app.people.remove(i);
                storage::delete(&p.key);
                app.selected = app.selected.min(app.people.len().saturating_sub(1));
                app.view = View::People;
                app.note = "forgotten".into();
            }
            (_, Event::Menu(3)) => app.note = "open someone first".into(),
            (View::People, Event::Left) => app.selected = app.selected.saturating_sub(1),
            (View::People, Event::Right) => app.selected = (app.selected + 1).min(n.saturating_sub(1)),
            (View::People, Event::Centre) if n > 0 => app.view = View::Person(app.selected),
            (View::Person(i), Event::Left) => {
                app.selected = i.saturating_sub(1);
                app.view = View::Person(app.selected);
            }
            (View::Person(i), Event::Right) => {
                app.selected = (i + 1).min(n.saturating_sub(1));
                app.view = View::Person(app.selected);
            }
            _ => {}
        }
    }
}

maki_app::main!(main);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base45_is_rfc_9285s() {
        // the RFC's examples
        assert_eq!(base45(b"AB"), "BB8");
        assert_eq!(base45(b"Hello!!"), "%69 VD92EX0");
        assert_eq!(base45(b"base-45"), "UJCLQE7W581");
        assert_eq!(unbase45("QED8WEX0").unwrap(), b"ietf!");
        assert!(unbase45("GGW").is_none());
    }
}
