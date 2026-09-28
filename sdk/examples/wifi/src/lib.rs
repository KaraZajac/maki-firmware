//! Wi-Fi networks as QR codes, for guests: phones join a network by scanning maki's screen. A
//! network comes from a QR code (the camera permission: a router's sticker, a phone's share
//! screen) or from the computer (the link permission), as the `WIFI:` text those QR codes hold
//! (`WIFI:T:WPA;S:name;P:password;;`). Left and right go through them; the menu scans another,
//! shows the password as text, or forgets one. Kept in the app's storage, on maki.
//!
//! Messages: a `WIFI:` text adds the network (or replaces one of the same name) and is answered
//! `ok`, or why not; an empty one is answered with the networks' names, a line each.

#![no_std]

use core::fmt::Write;

use maki_app::*;

const MOST: usize = 8;
const LONGEST: usize = 200;
const KEY: &str = "networks";

/// A network, as its QR code has it, and what's in it.
#[derive(Clone, Copy)]
struct Network {
    text: [u8; LONGEST],
    len: usize,
}

impl Network {
    fn as_str(&self) -> &str { core::str::from_utf8(&self.text[..self.len]).unwrap_or("") }
}

/// A field of a `WIFI:` text (`S`, `T`, `P`, `H`), its escapes (\\ \; \, \: \") undone, into `out`.
fn field<'a>(text: &str, name: char, out: &'a mut Buf<LONGEST>) -> Option<&'a str> {
    out.clear();
    let body = text.strip_prefix("WIFI:")?;
    let mut chars = body.chars();
    loop {
        // a field's name, then a colon
        let first = chars.next()?;
        if first == ';' {
            return None; // the end: ";;"
        }
        let second = chars.next()?;
        let this = second == ':' && first.eq_ignore_ascii_case(&name);
        // its value, to an unescaped semicolon
        loop {
            match chars.next()? {
                ';' => break,
                '\\' => {
                    let c = chars.next()?;
                    if this {
                        let _ = out.write_char(c);
                    }
                }
                c => {
                    if this {
                        let _ = out.write_char(c);
                    }
                }
            }
        }
        if this {
            return Some(out.as_str());
        }
    }
}

/// Whether `text` is a network maki can show: `WIFI:` with a name, nothing that isn't text.
fn readable(text: &str) -> bool {
    let mut name = Buf::<LONGEST>::new();
    text.len() <= LONGEST
        && !text.chars().any(|c| c.is_control())
        && field(text, 'S', &mut name).is_some_and(|n| !n.is_empty())
}

struct Networks {
    list: [Network; MOST],
    n: usize,
}

impl Networks {
    fn load() -> Networks {
        let mut all = Networks { list: [Network { text: [0; LONGEST], len: 0 }; MOST], n: 0 };
        let mut buf = [0u8; MOST * (LONGEST + 1)];
        let got = storage::get(KEY, &mut buf).unwrap_or(0).min(buf.len());
        for line in core::str::from_utf8(&buf[..got]).unwrap_or("").lines() {
            if readable(line) && all.n < MOST {
                let net = &mut all.list[all.n];
                net.text[..line.len()].copy_from_slice(line.as_bytes());
                net.len = line.len();
                all.n += 1;
            }
        }
        all
    }

    fn save(&self) {
        let mut buf = [0u8; MOST * (LONGEST + 1)];
        let mut at = 0;
        for net in &self.list[..self.n] {
            buf[at..at + net.len].copy_from_slice(&net.text[..net.len]);
            buf[at + net.len] = b'\n';
            at += net.len + 1;
        }
        let _ = storage::set(KEY, &buf[..at]);
    }

    fn name_of<'a>(net: &Network, out: &'a mut Buf<LONGEST>) -> &'a str {
        field(net.as_str(), 'S', out).unwrap_or("")
    }

    /// Add `text`, or put it in place of the network of the same name: where it went, or why not.
    fn add(&mut self, text: &str) -> Result<usize, &'static str> {
        if !readable(text) {
            return Err("that isn't a network: a WIFI: text with a name");
        }
        let (mut a, mut b) = (Buf::<LONGEST>::new(), Buf::<LONGEST>::new());
        let name = field(text, 'S', &mut a).unwrap_or("");
        let at = (0..self.n).find(|&i| Networks::name_of(&self.list[i], &mut b) == name).unwrap_or(self.n);
        if at == MOST {
            return Err("maki has eight networks: forget one first");
        }
        let net = &mut self.list[at];
        net.text[..text.len()].copy_from_slice(text.as_bytes());
        net.len = text.len();
        self.n = self.n.max(at + 1);
        self.save();
        Ok(at)
    }

    fn forget(&mut self, at: usize) {
        if at < self.n {
            self.list.copy_within(at + 1..self.n, at);
            self.n -= 1;
            self.save();
        }
    }
}

fn draw(nets: &Networks, at: usize, showing: bool, note: &str) {
    screen::clear(Color::Dark);
    if nets.n == 0 {
        screen::text_centred(16, "No networks yet", Style::Bold, Color::Light);
        screen::text_centred(40, "Scan one's QR code", Style::Small, Color::Light);
        screen::text_centred(52, "from the menu: a router's", Style::Small, Color::Light);
        screen::text_centred(64, "sticker, a phone's share", Style::Small, Color::Light);
        screen::text_centred(76, "screen. Or send one", Style::Small, Color::Light);
        screen::text_centred(88, "from your computer.", Style::Small, Color::Light);
        if !note.is_empty() {
            screen::fill_rect(0, 44, WIDTH, 20, Color::Dark);
            screen::rect(0, 44, WIDTH, 20, Color::Light);
            screen::text_centred(48, note, Style::Small, Color::Light);
        }
        screen::present();
        return;
    }
    let net = &nets.list[at];
    let mut whole = Buf::<LONGEST>::new();
    let name = first(field(net.as_str(), 'S', &mut whole).unwrap_or(""), 24);
    if showing {
        // the network written out, for typing it in by hand
        let mut kind = Buf::<LONGEST>::new();
        let kind = match field(net.as_str(), 'T', &mut kind) {
            Some(k) if k.eq_ignore_ascii_case("nopass") || k.is_empty() => "open",
            Some(k) => k,
            None => "open",
        };
        let mut line = Buf::<64>::new();
        screen::text(2, 2, "Network", Style::Small, Color::Light);
        screen::text(2, 15, name.as_str(), Style::Bold, Color::Light);
        let _ = write!(line, "Security: {kind}");
        screen::text(2, 34, line.as_str(), Style::Small, Color::Light);
        screen::text(2, 50, "Password", Style::Small, Color::Light);
        let mut pass = Buf::<LONGEST>::new();
        let pass = field(net.as_str(), 'P', &mut pass).unwrap_or("");
        let pass = if pass.is_empty() { "(none)" } else { pass };
        for (i, start) in (0..pass.len()).step_by(15).take(3).enumerate() {
            let end = (start + 15).min(pass.len());
            if let Some(chunk) = pass.get(start..end) {
                screen::text(2, 63 + i as i32 * 15, chunk, Style::Mono, Color::Light);
            }
        }
    } else {
        let side = screen::qr(0, 0, net.as_str().as_bytes(), 94).unwrap_or(0);
        if side > 0 && side < WIDTH {
            screen::clear(Color::Dark);
            screen::qr((WIDTH - side) / 2, 0, net.as_str().as_bytes(), 94);
        }
        let mut under = Buf::<48>::new();
        if nets.n > 1 {
            let _ = write!(under, "{}  {}/{}", name.as_str(), at + 1, nets.n);
        } else {
            let _ = under.write_str(name.as_str());
        }
        screen::text_centred(97, under.as_str(), Style::Small, Color::Light);
    }
    if !note.is_empty() {
        screen::fill_rect(0, 44, WIDTH, 20, Color::Dark);
        screen::rect(0, 44, WIDTH, 20, Color::Light);
        screen::text_centred(48, note, Style::Small, Color::Light);
    }
    screen::present();
}

/// The first `most` characters of `s`.
fn first(s: &str, most: usize) -> Buf<LONGEST> {
    let mut b = Buf::<LONGEST>::new();
    for c in s.chars().take(most) {
        let _ = b.write_char(c);
    }
    b
}

fn main() {
    let _ = menu(&["Scan a network", "Show the password", "Forget this one"]);
    let mut nets = Networks::load();
    let mut at = 0;
    let mut showing = false;
    let mut note: &str = "";
    loop {
        at = at.min(nets.n.saturating_sub(1));
        draw(&nets, at, showing, note);
        let event = wait(None);
        note = "";
        match event {
            Event::Left if nets.n > 1 => at = (at + nets.n - 1) % nets.n,
            Event::Right if nets.n > 1 => at = (at + 1) % nets.n,
            Event::Centre => showing = false,
            Event::Menu(0) => {
                let mut buf = [0u8; 512];
                if let Some(text) = camera::scan_qr(&mut buf) {
                    match nets.add(text) {
                        Ok(i) => at = i,
                        Err(why) => {
                            note = if why.starts_with("maki") {
                                "full: forget one first"
                            } else {
                                "not a Wi-Fi network"
                            }
                        }
                    }
                }
                showing = false;
            }
            Event::Menu(1) => showing = !showing && nets.n > 0,
            Event::Menu(2) => {
                nets.forget(at);
                showing = false;
            }
            Event::Message => {
                let mut msg = [0u8; LONGEST + 1];
                let n = link::read(&mut msg).unwrap_or(0).min(msg.len());
                let text = core::str::from_utf8(&msg[..n]).unwrap_or("").trim();
                if text.is_empty() {
                    let mut names = [0u8; MOST * (LONGEST + 1)];
                    let mut used = 0;
                    for net in &nets.list[..nets.n] {
                        let mut b = Buf::<LONGEST>::new();
                        let name = Networks::name_of(net, &mut b);
                        names[used..used + name.len()].copy_from_slice(name.as_bytes());
                        names[used + name.len()] = b'\n';
                        used += name.len() + 1;
                    }
                    let _ = link::reply(&names[..used]);
                } else {
                    match nets.add(text) {
                        Ok(i) => {
                            at = i;
                            let _ = link::reply(b"ok");
                        }
                        Err(why) => {
                            let _ = link::reply(why.as_bytes());
                        }
                    }
                }
            }
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
