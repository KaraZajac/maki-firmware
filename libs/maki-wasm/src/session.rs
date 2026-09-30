//! maki's functions for an app, whatever runs it: the WebAssembly host's imports call these,
//! and so does the app service a native app talks to. Each takes and returns plain values and
//! keeps the same rules: the limits, what it checks of what it's given, and the permissions.

use std::collections::BTreeMap;
use std::time::Duration;

use ed25519_dalek::Signer;
use maki_bundle::{Curve, Permission};

use crate::*;

/// What a function returns to an app without the permission it needs. A WebAssembly app can't
/// import it at all (maki refuses the app); a native app, which can call anything, gets this.
pub const REFUSED: i32 = -6;

/// One app's run: what it runs on, what it draws, what it may use.
pub struct Session {
    pub platform: Box<dyn Platform>,
    pub canvas: Canvas,
    pub limits: Limits,
    /// Stored keys and the length of each value, read on first use, for the quota.
    sizes: Option<BTreeMap<String, usize>>,
    started: u64,
    /// A wait returned Exit: waiting again means the app didn't.
    pub exit_sent: bool,
    /// With the wallet permission: the paths its manifest names, which maki holds it to.
    pub wallet: Option<maki_bundle::Wallet>,
    /// The signatures the owner's last yes to a review allows, and until when (millis).
    allowance: (u32, u64),
}

impl Session {
    pub fn new(platform: Box<dyn Platform>, limits: Limits) -> Session {
        let started = platform.millis();
        Session {
            platform,
            canvas: Canvas::default(),
            limits,
            sizes: None,
            started,
            exit_sent: false,
            wallet: None,
            allowance: (0, 0),
        }
    }

    fn sizes(&mut self) -> &mut BTreeMap<String, usize> {
        if self.sizes.is_none() {
            let mut sizes = BTreeMap::new();
            for key in self.platform.storage_keys() {
                let len = self.platform.storage_get(&key).map(|v| v.len()).unwrap_or(0);
                sizes.insert(key, len);
            }
            self.sizes = Some(sizes);
        }
        self.sizes.as_mut().unwrap()
    }

    pub fn permitted(&self, p: Permission) -> bool { self.limits.granted.has(p) }

    fn needs(&self, p: Permission) -> Result<(), i32> {
        if self.permitted(p) { Ok(()) } else { Err(REFUSED) }
    }

    pub fn present(&mut self) { self.platform.present(&self.canvas) }

    /// The next event's code (`Event::code`), or `None` if the app was told to exit already:
    /// it should have returned.
    pub fn wait(&mut self, timeout_ms: i32) -> Option<i32> {
        if self.exit_sent {
            return None;
        }
        let timeout = (timeout_ms >= 0).then(|| Duration::from_millis(timeout_ms as u64));
        let event = self.platform.wait(timeout);
        self.exit_sent = event == Event::Exit;
        Some(event.code())
    }

    /// The app's own menu items, a line each (none: empty).
    pub fn menu(&mut self, text: &str) -> i32 {
        // before it's split: a native app's text is as long as it likes
        if text.len() > MENU_TEXT {
            return INVALID;
        }
        let items: Vec<String> =
            if text.is_empty() { vec![] } else { text.split('\n').map(String::from).collect() };
        if items.len() > MAX_MENU_ITEMS
            || items
                .iter()
                .any(|i| i.trim().is_empty() || i.len() > MAX_MENU_ITEM || i.chars().any(|c| c.is_control()))
        {
            return INVALID;
        }
        self.platform.set_menu(&items);
        0
    }

    pub fn storage_get(&mut self, key: &str) -> Result<Vec<u8>, i32> {
        if !key_ok(key) {
            return Err(INVALID);
        }
        self.platform.storage_get(key).ok_or(NOT_FOUND)
    }

    pub fn storage_set(&mut self, key: &str, value: &[u8]) -> i32 {
        if !key_ok(key) {
            return INVALID;
        }
        if value.len() > MAX_VALUE {
            return TOO_BIG;
        }
        let quota = self.limits.storage;
        let sizes = self.sizes();
        let used: usize = sizes.iter().map(|(k, v)| k.len() + v).sum();
        let old = sizes.get(key).map(|v| key.len() + v).unwrap_or(0);
        if used - old + key.len() + value.len() > quota {
            return FULL;
        }
        if self.platform.storage_set(key, value).is_err() {
            return FAILED;
        }
        self.sizes().insert(key.to_string(), value.len());
        0
    }

    pub fn storage_delete(&mut self, key: &str) -> i32 {
        if !key_ok(key) {
            return INVALID;
        }
        self.sizes();
        if !self.platform.storage_delete(key) {
            return NOT_FOUND;
        }
        self.sizes().remove(key);
        0
    }

    /// The stored key at `index`, in order.
    pub fn storage_key(&mut self, index: i32) -> Result<String, i32> {
        if index < 0 {
            return Err(NOT_FOUND);
        }
        self.sizes().keys().nth(index as usize).cloned().ok_or(NOT_FOUND)
    }

    /// Milliseconds since the app started.
    pub fn millis(&self) -> i64 { self.platform.millis().saturating_sub(self.started) as i64 }

    /// Unix seconds, or -1 if maki's clock isn't set.
    pub fn unix_time(&self) -> i64 { self.platform.unix_time().map(|(t, _)| t as i64).unwrap_or(-1) }

    pub fn time_verified(&self) -> i32 { matches!(self.platform.unix_time(), Some((_, true))) as i32 }

    pub fn random(&mut self, len: usize) -> Result<Vec<u8>, i32> {
        if len > MAX_RANDOM {
            return Err(TOO_BIG);
        }
        let mut buf = vec![0u8; len];
        self.platform.random(&mut buf);
        Ok(buf)
    }

    pub fn log(&mut self, line: &str) {
        let mut end = line.len().min(MAX_LOG);
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        self.platform.log(&line[..end]);
    }

    /// The ask permission: "question\ndetail\nyes\nno" (the last three optional), and how long
    /// to wait (0 or less: 30 s; at most 120). 0 yes, 1 no, 2 no answer.
    pub fn ask(&mut self, text: &str, timeout_s: i32) -> i32 {
        if let Err(e) = self.needs(Permission::Ask) {
            return e;
        }
        if text.len() > ASK_TEXT {
            return TOO_BIG;
        }
        let Some(ask) = parse_ask(text, timeout_s) else { return INVALID };
        self.platform.ask(&ask).code()
    }

    /// The ask permission (host API 7): a question on maki's review screen after pages of what
    /// it's about (the text as `wallet_review` takes it, see `parse_review`), for what an ask's
    /// line can't hold: a whole command line, say. Its answers are "allow" and "deny" unless the
    /// app names them, and a yes allows no signatures. 0 yes, 1 no, 2 no answer.
    pub fn ask_review(&mut self, text: &str, timeout_s: i32) -> i32 {
        if let Err(e) = self.needs(Permission::Ask) {
            return e;
        }
        if text.len() > MAX_REVIEW {
            return TOO_BIG;
        }
        let Some(mut review) = parse_review(text, timeout_s) else { return INVALID };
        if review.yes.is_empty() {
            review.yes = "allow".into();
        }
        if review.no.is_empty() {
            review.no = "deny".into();
        }
        self.platform.review(&review).code()
    }

    fn label_ok(label: &str) -> bool { label.len() <= MAX_LABEL && !label.chars().any(|ch| ch.is_control()) }

    /// The keys permission: the app's 32-byte secret for a label.
    pub fn key_secret(&mut self, label: &str) -> Result<[u8; 32], i32> {
        self.needs(Permission::Keys)?;
        if !Self::label_ok(label) {
            return Err(INVALID);
        }
        self.platform.app_secret(label).ok_or(FAILED)
    }

    /// The Ed25519 key made from the app's secret for a label: its public half.
    pub fn key_public(&mut self, label: &str) -> Result<[u8; 32], i32> {
        self.needs(Permission::Keys)?;
        if !Self::label_ok(label) {
            return Err(INVALID);
        }
        let key = signing_key(self.platform.as_mut(), label).ok_or(FAILED)?;
        Ok(key.verifying_key().to_bytes())
    }

    /// A signature by that key, which maki holds, so the app needn't carry it.
    pub fn key_sign(&mut self, label: &str, message: &[u8]) -> Result<[u8; 64], i32> {
        self.needs(Permission::Keys)?;
        if !Self::label_ok(label) {
            return Err(INVALID);
        }
        if message.len() > MAX_SIGN {
            return Err(TOO_BIG);
        }
        let key = signing_key(self.platform.as_mut(), label).ok_or(FAILED)?;
        Ok(key.sign(message).to_bytes())
    }

    /// The BIP340 (Schnorr, secp256k1) key made from the app's secret for a label: its x-only
    /// public half, as Nostr and Taproot write keys.
    pub fn key_schnorr_public(&mut self, label: &str) -> Result<[u8; 32], i32> {
        self.needs(Permission::Keys)?;
        if !Self::label_ok(label) {
            return Err(INVALID);
        }
        let key = schnorr_key(self.platform.as_mut(), label).ok_or(FAILED)?;
        Ok(key.verifying_key().to_bytes().into())
    }

    /// A BIP340 signature by that key, which maki holds, of a 32-byte message (a hash: a Nostr
    /// event's id, a Taproot sighash), with fresh randomness from maki's TRNG.
    pub fn key_schnorr_sign(&mut self, label: &str, message: &[u8]) -> Result<[u8; 64], i32> {
        self.needs(Permission::Keys)?;
        if !Self::label_ok(label) {
            return Err(INVALID);
        }
        let message: &[u8; 32] = message.try_into().map_err(|_| INVALID)?;
        let key = schnorr_key(self.platform.as_mut(), label).ok_or(FAILED)?;
        let mut aux = [0u8; 32];
        self.platform.random(&mut aux);
        key.sign_prehash_with_aux_rand(message, &aux).map(|s| s.to_bytes()).map_err(|_| FAILED)
    }

    /// The X25519 key (RFC 7748) made from the app's secret for a label: its public half, as
    /// age writes recipients.
    pub fn key_x25519_public(&mut self, label: &str) -> Result<[u8; 32], i32> {
        self.needs(Permission::Keys)?;
        if !Self::label_ok(label) {
            return Err(INVALID);
        }
        let mut key = x25519_key(self.platform.as_mut(), label).ok_or(FAILED)?;
        let public = curve25519_dalek::MontgomeryPoint::mul_base_clamped(key).to_bytes();
        zeroize::Zeroize::zeroize(&mut key);
        Ok(public)
    }

    /// What that key and `peer`'s public key agree on (X25519), for what was encrypted to the
    /// app's key: an age file key, say. maki holds the key; the app gets the shared secret. A
    /// peer whose agreement is all zeros (a point of small order) is refused, as age requires.
    pub fn key_x25519_agree(&mut self, label: &str, peer: &[u8]) -> Result<[u8; 32], i32> {
        self.needs(Permission::Keys)?;
        if !Self::label_ok(label) {
            return Err(INVALID);
        }
        let peer: [u8; 32] = peer.try_into().map_err(|_| INVALID)?;
        let mut key = x25519_key(self.platform.as_mut(), label).ok_or(FAILED)?;
        // RFC 7748's X25519: the scalar clamped, times the peer's point
        let shared = curve25519_dalek::MontgomeryPoint(peer).mul_clamped(key).to_bytes();
        zeroize::Zeroize::zeroize(&mut key);
        if shared == [0u8; 32] {
            return Err(INVALID);
        }
        Ok(shared)
    }

    /// Whether the wallet permission's paths let the app use `path`, on its curve: a
    /// secp256k1 wallet's keys (and Monero's, made from them), or an Ed25519 wallet's.
    fn wallet_path(&self, path: &[u32], curve: Curve) -> Result<(), i32> {
        match &self.wallet {
            Some(w) if w.curve == curve && path.len() <= maki_hd::MAX_DEPTH && w.allows(path) => Ok(()),
            _ => Err(REFUSED),
        }
    }

    /// The wallet permission: the master key's fingerprint, as descriptors and PSBTs name the
    /// seed their keys come from.
    pub fn wallet_fingerprint(&mut self) -> Result<[u8; 4], i32> {
        self.needs(Permission::Wallet)?;
        self.platform.wallet(maki_hd::op::FINGERPRINT, &[], &[])?.as_slice().try_into().map_err(|_| FAILED)
    }

    /// The wallet permission: the public key at `path` (one of its own), in the `WALLET_*`
    /// form asked for.
    pub fn wallet_public(&mut self, path: &[u32], form: u8) -> Result<Vec<u8>, i32> {
        self.needs(Permission::Wallet)?;
        if !matches!(
            form,
            WALLET_PUBLIC | WALLET_UNCOMPRESSED | WALLET_TAPROOT | WALLET_MONERO | WALLET_ED25519
        ) {
            return Err(INVALID);
        }
        self.wallet_path(path, if form == WALLET_ED25519 { Curve::Ed25519 } else { Curve::Secp256k1 })?;
        self.platform.wallet(form, path, &[])
    }

    /// The wallet permission (host API 4): a Monero subaddress's public spend and view keys, for
    /// account `major`'s address `minor` (0 and 0: the account's own address), of the account at
    /// `path` (one of its own).
    pub fn wallet_subaddress(&mut self, path: &[u32], major: u32, minor: u32) -> Result<[u8; 64], i32> {
        self.needs(Permission::Wallet)?;
        self.wallet_path(path, Curve::Secp256k1)?;
        let mut indices = [0u8; 8];
        indices[..4].copy_from_slice(&major.to_le_bytes());
        indices[4..].copy_from_slice(&minor.to_le_bytes());
        self.platform.wallet(maki_hd::op::MONERO_SUBADDRESS, path, &indices)?.try_into().map_err(|_| FAILED)
    }

    /// The wallet permission (host API 4): has maki show its owner the backup words of the account
    /// at `path` (one of its own), itself, once they've said they want them. 0 shown, 1 not
    /// wanted, 2 no answer; the words never come to the app.
    pub fn wallet_show_backup(&mut self, path: &[u32]) -> i32 {
        if let Err(e) = self.needs(Permission::Wallet).and_then(|_| self.wallet_path(path, Curve::Secp256k1))
        {
            return e;
        }
        match self.platform.show_backup(path) {
            Ok(answer) => answer.code(),
            Err(e) => e,
        }
    }

    /// The wallet permission: shows the owner a review on maki's own screen (see `parse_review`
    /// for its text), then asks. A yes lets the app make `signatures` signatures, within
    /// `ALLOWANCE_MS`; whatever the last review allowed goes, either way. 0 yes, 1 no, 2 no answer.
    pub fn wallet_review(&mut self, text: &str, signatures: u32, timeout_s: i32) -> i32 {
        if let Err(e) = self.needs(Permission::Wallet) {
            return e;
        }
        if text.len() > MAX_REVIEW {
            return TOO_BIG;
        }
        if signatures > MAX_SIGNATURES {
            return INVALID;
        }
        let Some(review) = parse_review(text, timeout_s) else { return INVALID };
        self.allowance = (0, 0);
        let answer = self.platform.review(&review);
        if answer == Answer::Yes {
            self.allowance = (signatures, self.platform.millis() + ALLOWANCE_MS);
        }
        answer.code()
    }

    /// The wallet permission: a signature with the key at `path` (one of its own) over a 32-byte
    /// digest, `WALLET_SIGN_*`, if the owner's last yes to a review allows one more.
    pub fn wallet_sign(&mut self, path: &[u32], digest: &[u8], scheme: u8) -> Result<Vec<u8>, i32> {
        self.needs(Permission::Wallet)?;
        if !matches!(scheme, WALLET_SIGN_ECDSA | WALLET_SIGN_SCHNORR | WALLET_SIGN_TAPROOT)
            || digest.len() != 32
        {
            return Err(INVALID);
        }
        self.wallet_path(path, Curve::Secp256k1)?;
        self.allowed(1)?;
        self.platform.wallet(scheme, path, digest)
    }

    /// Takes `n` of what the owner's last yes to a review allows, or refuses and ends it.
    fn allowed(&mut self, n: u32) -> Result<(), i32> {
        let (left, until) = self.allowance;
        if left < n || n == 0 || self.platform.millis() > until {
            self.allowance = (0, 0);
            return Err(REFUSED);
        }
        self.allowance.0 -= n;
        Ok(())
    }

    /// The wallet permission (host API 5): the secret view key of the Monero account at `path`
    /// (one of its own), what a computer finds the account's outputs with, and can't spend them,
    /// if the owner's last yes to a review allows one more.
    pub fn wallet_monero_view_key(&mut self, path: &[u32]) -> Result<[u8; 32], i32> {
        self.needs(Permission::Wallet)?;
        self.wallet_path(path, Curve::Secp256k1)?;
        self.allowed(1)?;
        self.platform.wallet(maki_hd::op::MONERO_VIEW_KEY, path, &[])?.try_into().map_err(|_| FAILED)
    }

    /// The wallet permission (host API 5): the key image of an output of the Monero account at
    /// `path` (one of its own), and what proves it, for a view-only wallet to learn what's spent:
    /// `output` is its transaction key, index, subaddress and key (`maki_hd::op::MONERO_KEY_IMAGE`).
    /// `FAILED` for an output that isn't the account's.
    pub fn wallet_monero_key_image(&mut self, path: &[u32], output: &[u8]) -> Result<[u8; 96], i32> {
        self.needs(Permission::Wallet)?;
        if output.len() != MONERO_OUTPUT {
            return Err(INVALID);
        }
        self.wallet_path(path, Curve::Secp256k1)?;
        self.platform.wallet(maki_hd::op::MONERO_KEY_IMAGE, path, output)?.try_into().map_err(|_| FAILED)
    }

    /// The wallet permission (host API 5): a Monero transaction, made and signed by maki, from the
    /// account at `path` (one of its own): `request` says what it pays (`maki_xmr::request`). A
    /// signature for each input, of what the owner's last yes allows. 0 and the signed transaction
    /// (`maki_xmr::spend::Signed`), or 1 and why maki didn't sign.
    pub fn wallet_monero_sign(&mut self, path: &[u32], request: &[u8]) -> Result<Vec<u8>, i32> {
        self.needs(Permission::Wallet)?;
        if request.len() > MAX_MONERO_REQUEST {
            return Err(TOO_BIG);
        }
        let inputs = maki_xmr::request::Request::parse(request).map_err(|_| INVALID)?.inputs.len();
        self.wallet_path(path, Curve::Secp256k1)?;
        self.allowed(inputs as u32)?;
        self.platform.wallet(maki_hd::op::MONERO_SIGN, path, request)
    }

    /// The wallet permission (host API 6): an Ed25519 signature (RFC 8032) over the whole of
    /// `message`, with the key at `path` (one of its own, by SLIP-10: a Solana account's), if the
    /// owner's last yes to a review allows one more.
    pub fn wallet_sign_ed25519(&mut self, path: &[u32], message: &[u8]) -> Result<[u8; 64], i32> {
        self.needs(Permission::Wallet)?;
        if message.len() > MAX_SIGN {
            return Err(TOO_BIG);
        }
        self.wallet_path(path, Curve::Ed25519)?;
        self.allowed(1)?;
        self.platform.wallet(maki_hd::op::ED25519_SIGN, path, message)?.try_into().map_err(|_| FAILED)
    }

    /// The keyboard permission: printable ASCII, newlines and tabs.
    pub fn type_text(&mut self, text: &str) -> i32 {
        if let Err(e) = self.needs(Permission::Keyboard) {
            return e;
        }
        if text.len() > MAX_TYPE {
            return TOO_BIG;
        }
        if !text.chars().all(|ch| ch == '\n' || ch == '\t' || (' '..='~').contains(&ch)) {
            return INVALID;
        }
        if self.platform.type_text(text) { 0 } else { FAILED }
    }

    /// The keyboard permission, host API 8: a key beyond text (`pressable`), Shift held or not.
    pub fn press_key(&mut self, code: i32, shift: bool) -> i32 {
        if let Err(e) = self.needs(Permission::Keyboard) {
            return e;
        }
        match u8::try_from(code) {
            Ok(code) if crate::pressable(code) => {
                if self.platform.press_key(code, shift) {
                    0
                } else {
                    FAILED
                }
            }
            _ => INVALID,
        }
    }

    /// Host API 8: the whole screen dark, or not.
    pub fn screen_dark(&mut self, dark: bool) { self.platform.set_dark(dark) }

    /// The link permission: the message the last Message event brought.
    pub fn link_read(&mut self) -> Result<Vec<u8>, i32> {
        self.needs(Permission::Link)?;
        self.platform.message().ok_or(NOT_FOUND)
    }

    /// And the app's answer to it.
    pub fn link_reply(&mut self, reply: &[u8]) -> i32 {
        if let Err(e) = self.needs(Permission::Link) {
            return e;
        }
        if reply.len() > MAX_MESSAGE {
            return TOO_BIG;
        }
        if self.platform.reply(reply) { 0 } else { NOT_FOUND }
    }

    /// The camera permission: a QR code's text from maki's scanner.
    pub fn scan_qr(&mut self) -> Result<String, i32> {
        self.needs(Permission::Camera)?;
        self.platform.scan_qr().ok_or(NOT_FOUND)
    }

    /// The motion permission: x, y and z, in milli-g.
    pub fn motion(&mut self) -> Result<[i16; 3], i32> {
        self.needs(Permission::Motion)?;
        self.platform.motion().ok_or(FAILED)
    }

    /// The motion permission, host API 8: the accelerometer's range, ±`g` rounded up to one it
    /// has (2, 4, 8 or 16); the range it has now.
    pub fn motion_range(&mut self, g: i32) -> Result<u8, i32> {
        self.needs(Permission::Motion)?;
        let g = match g {
            ..=2 => 2,
            3..=4 => 4,
            5..=8 => 8,
            _ => 16,
        };
        self.platform.motion_range(g).ok_or(FAILED)
    }
}

pub(crate) fn key_ok(key: &str) -> bool {
    !key.is_empty() && key.len() <= MAX_KEY && !key.chars().any(|c| c.is_control())
}

/// "question\ndetail\nyes\nno", the last three optional, as `ask` takes it.
fn parse_ask(text: &str, timeout_s: i32) -> Option<Ask> {
    let parts: Vec<&str> = text.split('\n').collect();
    if parts.len() > 4 || parts.iter().any(|p| p.chars().any(|ch| ch.is_control())) {
        return None;
    }
    let part = |i: usize| parts.get(i).copied().unwrap_or("").to_string();
    let ask = Ask {
        question: part(0),
        detail: part(1),
        yes: part(2),
        no: part(3),
        timeout_s: if timeout_s <= 0 {
            ASK_TIMEOUT_S
        } else {
            (timeout_s as u32).clamp(5, MAX_ASK_TIMEOUT_S)
        },
    };
    let fits = !ask.question.trim().is_empty()
        && ask.question.len() <= MAX_QUESTION
        && ask.detail.len() <= MAX_DETAIL
        && ask.yes.len() <= MAX_ANSWER_LABEL
        && ask.no.len() <= MAX_ANSWER_LABEL;
    fits.then_some(ask)
}

/// A review's text: "question\ndetail\nyes\nno" (the last three optional, as an ask's), then
/// each page after a record separator (0x1e): its heading, value, fixed-width text and prose,
/// separated by unit separators (0x1f), the last two optional. None if it doesn't fit maki's
/// screen or limits.
fn parse_review(text: &str, timeout_s: i32) -> Option<Review> {
    let mut records = text.split('\x1e');
    let head: Vec<&str> = records.next()?.split('\n').collect();
    if head.len() > 4 || head.iter().any(|p| p.chars().any(|ch| ch.is_control())) {
        return None;
    }
    let part = |i: usize| head.get(i).copied().unwrap_or("").to_string();
    let mut pages = Vec::new();
    for record in records {
        let fields: Vec<&str> = record.split('\x1f').collect();
        if !(2..=4).contains(&fields.len()) {
            return None;
        }
        let field = |i: usize| fields.get(i).copied().unwrap_or("");
        let page = Page {
            heading: field(0).into(),
            value: field(1).into(),
            mono: field(2).into(),
            prose: field(3).into(),
        };
        // fixed-width text and prose may run over lines; nothing else is a control character
        let plain = |t: &str| !t.chars().any(|ch| ch.is_control());
        let lines = |t: &str| !t.chars().any(|ch| ch.is_control() && ch != '\n');
        if !plain(&page.heading) || !plain(&page.value) || !lines(&page.mono) || !lines(&page.prose) {
            return None;
        }
        if page.heading.trim().is_empty()
            || page.heading.len() > MAX_HEADING
            || page.value.len() > MAX_PAGE_VALUE
            || page.mono.len() > MAX_PAGE_TEXT
            || page.prose.len() > MAX_PAGE_TEXT
        {
            return None;
        }
        pages.push(page);
    }
    let review = Review {
        question: part(0),
        detail: part(1),
        yes: part(2),
        no: part(3),
        pages,
        timeout_s: if timeout_s <= 0 {
            REVIEW_TIMEOUT_S
        } else {
            (timeout_s as u32).clamp(5, MAX_REVIEW_TIMEOUT_S)
        },
    };
    let fits = !review.question.trim().is_empty()
        && review.question.len() <= MAX_QUESTION
        && review.detail.len() <= MAX_DETAIL
        && review.yes.len() <= MAX_ANSWER_LABEL
        && review.no.len() <= MAX_ANSWER_LABEL
        && review.pages.len() <= MAX_PAGES;
    fits.then_some(review)
}

/// The app's Ed25519 key for `label`: its secret for that label is the key's seed.
/**
 * The BIP340 key for a label: from the app's secret for it, tagged (as BIP340 tags its hashes) so
 * the same bytes aren't both an Ed25519 seed and a secp256k1 key. None in the 2^-128 case that
 * it's no key at all.
 */
fn schnorr_key(platform: &mut dyn Platform, label: &str) -> Option<k256::schnorr::SigningKey> {
    use sha2::{Digest, Sha256};
    let mut secret = platform.app_secret(label)?;
    let tag = Sha256::digest(b"maki/bip340");
    let mut scalar: [u8; 32] =
        Sha256::new().chain_update(tag).chain_update(tag).chain_update(secret).finalize().into();
    let key = k256::schnorr::SigningKey::from_bytes(&scalar).ok();
    zeroize::Zeroize::zeroize(&mut secret);
    zeroize::Zeroize::zeroize(&mut scalar);
    key
}

/** The X25519 key for a label: the app's secret for it, tagged apart as the BIP340 key is. */
fn x25519_key(platform: &mut dyn Platform, label: &str) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut secret = platform.app_secret(label)?;
    let tag = Sha256::digest(b"maki/x25519");
    let key: [u8; 32] =
        Sha256::new().chain_update(tag).chain_update(tag).chain_update(secret).finalize().into();
    zeroize::Zeroize::zeroize(&mut secret);
    Some(key)
}

fn signing_key(platform: &mut dyn Platform, label: &str) -> Option<ed25519_dalek::SigningKey> {
    let mut secret = platform.app_secret(label)?;
    let key = ed25519_dalek::SigningKey::from_bytes(&secret);
    zeroize::Zeroize::zeroize(&mut secret);
    Some(key)
}
