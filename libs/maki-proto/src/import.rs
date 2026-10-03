//! Importing logins, codes and passkeys from other password managers (IMPORT_PUT; PROTOCOL.md,
//! "Importing"): the import as maki desktop hands it over, maki's checks of every record, what of
//! it maki has already, whether maki has room for the rest, and the records maki keeps of what it
//! adds, in the formats its vault (vault2) and its FIDO authenticator (OpenSK) keep their own in.
//!
//! maki desktop reads another manager's export and turns it into the records below. maki checks
//! every one before it asks its owner anything, and refuses the whole import, saying why, if one
//! won't do. maki-keys does the importing on the badge; the fake maki keeps the same records in
//! memory, by the same rules.

use std::collections::HashSet;
use std::fmt;
use std::ops::RangeInclusive;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::site;
use crate::wire::Reader;

/// What an import starts with.
pub const MAGIC: &[u8; 8] = b"MAKIIMP1";
/// The kinds of record.
pub const LOGIN: u8 = 1;
pub const CODE: u8 = 2;
pub const PASSKEY: u8 = 3;
/// The name of the manager it's from, as maki shows it ("Bitwarden"), in bytes.
pub const SOURCE_LEN: RangeInclusive<usize> = 1..=32;
/// A code's secret (the key itself), in bytes.
pub const SECRET_LEN: RangeInclusive<usize> = 10..=64;
pub const DIGITS: RangeInclusive<u8> = 6..=8;
/// How often a code changes, in seconds.
pub const PERIOD_S: RangeInclusive<u16> = 15..=300;
pub const CREDENTIAL_ID_LEN: RangeInclusive<usize> = 16..=255;
pub const USER_HANDLE_LEN: RangeInclusive<usize> = 1..=64;
/// A passkey's private key: a P-256 private scalar, big-endian.
pub const PRIVATE_KEY_LEN: usize = 32;
/// The most records one import holds: maki reads them all into its memory before it asks
/// anything (as many as maki can keep, with room to spare for ones it has already).
pub const MAX_RECORDS: usize = 2000;

/// The most logins maki's vault keeps after an import. vault2 reads every login for its list,
/// and again for each browser request, in a heap of 512 KiB: much past this, it would run out
/// (its own estimate is that it stops working somewhere past 500 to 1000 records).
pub const MAX_LOGINS: usize = 500;
/// The most codes maki's Authenticator keeps after an import, for the same reason.
pub const MAX_CODES: usize = 250;
/// The most passkeys maki holds: its FIDO authenticator's resident credentials (OpenSK's
/// `max_supported_resident_keys`; maki-fido's `CREDENTIALS`).
pub const MAX_PASSKEYS: usize = 150;
/// What maki's logins, codes and passkeys may take of its encrypted database (4 MiB on the
/// badge) after an import: apps have 2 MiB of it (`maki_app_host_api::APP_SPACE`), and the rest
/// is the database's own and maki's. The database won't say how much of it is free (that would
/// say how much is hidden in it), so maki keeps to this, and the database never fills.
pub const VAULT_ROOM: u64 = 1024 * 1024;
/// What a record takes of the database beyond its own bytes: its entry in its dictionary's table
/// of keys (127 bytes in the PDDB), rounded up.
pub const RECORD_COST: u64 = 128;
/// How many codes may share a name: the second is kept as "name (2)", and so on.
const MAX_SAME_NAME: usize = 99;

/// The bytes of the database a record of `len` bytes takes, about.
pub fn cost(len: usize) -> u64 { len as u64 + RECORD_COST }

/// An import: the manager it's from, and its records, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub source: String,
    pub records: Vec<Record>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Login(Login),
    Code(Code),
    Passkey(Passkey),
}

/// A login: a site's username and password.
#[derive(Clone, PartialEq, Eq)]
pub struct Login {
    /// a hostname, as GET_LOGIN takes it (`site::valid`)
    pub site: String,
    /// may be empty: some sites take a password alone
    pub username: String,
    pub password: String,
    /// the entry's name in the manager it came from ("GitHub (work)"), or empty
    pub title: String,
}

/// A code: a TOTP generator (RFC 6238).
#[derive(Clone, PartialEq, Eq)]
pub struct Code {
    /// either may be empty, not both
    pub issuer: String,
    pub account: String,
    /// the key itself
    pub secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub period_s: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Algorithm {
    Sha1 = 1,
    Sha256 = 2,
    Sha512 = 3,
}

impl Algorithm {
    /// As vault2 writes it in a code's record.
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }
}

/// A passkey: a WebAuthn resident credential, ES256.
#[derive(Clone, PartialEq, Eq)]
pub struct Passkey {
    /// the relying party ID, a hostname as for a login's site
    pub rp_id: String,
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    /// either may be empty
    pub user_name: String,
    pub display_name: String,
    /// the P-256 private scalar, big-endian
    pub private_key: [u8; PRIVATE_KEY_LEN],
}

// The secrets are wiped when a record goes, and never printed.

impl Drop for Login {
    fn drop(&mut self) { self.password.zeroize() }
}

impl Drop for Code {
    fn drop(&mut self) { self.secret.zeroize() }
}

impl Drop for Passkey {
    fn drop(&mut self) { self.private_key.zeroize() }
}

impl fmt::Debug for Login {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Login")
            .field("site", &self.site)
            .field("username", &self.username)
            .field("password", &format_args!("({} bytes)", self.password.len()))
            .field("title", &self.title)
            .finish()
    }
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Code")
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("secret", &format_args!("({} bytes)", self.secret.len()))
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period_s", &self.period_s)
            .finish()
    }
}

impl fmt::Debug for Passkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Passkey")
            .field("rp_id", &self.rp_id)
            .field("credential_id", &self.credential_id)
            .field("user_handle", &self.user_handle)
            .field("user_name", &self.user_name)
            .field("display_name", &self.display_name)
            .field("private_key", &format_args!("(32 bytes)"))
            .finish()
    }
}

/// An import, read and checked: every record, or why maki won't take it, in words for maki
/// desktop to show (IMPORT_PUT's `reason`; records are counted from 1).
pub fn parse(blob: &[u8]) -> Result<Import, String> {
    let body = blob
        .strip_prefix(MAGIC.as_slice())
        .ok_or_else(|| "it isn’t an import maki reads: it doesn’t start with MAKIIMP1".to_string())?;
    let mut r = Reader::new(body);
    let cut_short = || "it’s cut short before its records".to_string();
    let source = match r.bytes8().map(core::str::from_utf8) {
        Ok(Ok(source)) => source,
        Ok(Err(_)) => return Err("its source’s name isn’t UTF-8 text".into()),
        Err(_) => return Err(cut_short()),
    };
    if !SOURCE_LEN.contains(&source.len()) {
        return Err(format!("its source’s name is {} bytes: maki takes 1 to 32", source.len()));
    }
    if !plain(source) {
        return Err("its source’s name has a control character".into());
    }
    let count = r.u32().map_err(|_| cut_short())? as usize;
    if count == 0 {
        return Err("it has no records".into());
    }
    if count > MAX_RECORDS {
        return Err(format!("it has {count} records: maki takes at most {MAX_RECORDS} at a time"));
    }
    let mut records = Vec::with_capacity(count);
    for n in 1..=count {
        records.push(match r.u8() {
            Ok(LOGIN) => login(&mut r, n)?,
            Ok(CODE) => code(&mut r, n)?,
            Ok(PASSKEY) => passkey(&mut r, n)?,
            Ok(kind) => return Err(format!("record {n} is of a kind maki doesn’t know ({kind})")),
            Err(_) => return Err(cut(n)),
        });
    }
    if !r.at_end() {
        return Err("it has something after its last record".into());
    }
    Ok(Import { source: source.into(), records })
}

fn cut(n: usize) -> String { format!("record {n} is cut short") }

/// Nothing that could move the cursor on maki's screen, or break a line of the vault's records.
fn plain(s: &str) -> bool { !s.chars().any(char::is_control) }

/// A `str8`, which must be UTF-8 text: `what` names it for the reason.
fn text<'a>(r: &mut Reader<'a>, n: usize, what: &str) -> Result<&'a str, String> {
    let bytes = r.bytes8().map_err(|_| cut(n))?;
    core::str::from_utf8(bytes).map_err(|_| format!("record {n}: {what} that isn’t UTF-8 text"))
}

/// A `str8` of text with no control characters.
fn plain_text<'a>(r: &mut Reader<'a>, n: usize, what: &str) -> Result<&'a str, String> {
    let s = text(r, n, what)?;
    if !plain(s) {
        return Err(format!("record {n}: {what} with a control character"));
    }
    Ok(s)
}

fn login(r: &mut Reader, n: usize) -> Result<Record, String> {
    let site = text(r, n, "a login’s site")?;
    if !site::valid(site) {
        return Err(format!(
            "record {n}: a login’s site that isn’t a plain hostname (lowercase letters, digits, dots and \
             hyphens)"
        ));
    }
    let username = plain_text(r, n, "a username")?;
    let password = plain_text(r, n, "a password")?;
    if password.is_empty() {
        return Err(format!("record {n}: an empty password"));
    }
    let title = plain_text(r, n, "a title")?;
    Ok(Record::Login(Login {
        site: site.into(),
        username: username.into(),
        password: password.into(),
        title: title.into(),
    }))
}

fn code(r: &mut Reader, n: usize) -> Result<Record, String> {
    let issuer = plain_text(r, n, "a code’s issuer")?;
    let account = plain_text(r, n, "a code’s account")?;
    if issuer.is_empty() && account.is_empty() {
        return Err(format!("record {n}: a code with neither an issuer nor an account"));
    }
    let secret = r.bytes16().map_err(|_| cut(n))?;
    if !SECRET_LEN.contains(&secret.len()) {
        return Err(format!("record {n}: a code’s secret of {} bytes: maki takes 10 to 64", secret.len()));
    }
    let algorithm = match r.u8().map_err(|_| cut(n))? {
        1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        other => return Err(format!("record {n}: a code’s algorithm maki doesn’t know ({other})")),
    };
    let digits = r.u8().map_err(|_| cut(n))?;
    if !DIGITS.contains(&digits) {
        return Err(format!("record {n}: a code of {digits} digits: maki takes 6 to 8"));
    }
    let period_s = r.u16().map_err(|_| cut(n))?;
    if !PERIOD_S.contains(&period_s) {
        return Err(format!("record {n}: a code that changes every {period_s} s: maki takes 15 to 300"));
    }
    Ok(Record::Code(Code {
        issuer: issuer.into(),
        account: account.into(),
        secret: secret.to_vec(),
        algorithm,
        digits,
        period_s,
    }))
}

fn passkey(r: &mut Reader, n: usize) -> Result<Record, String> {
    let rp_id = text(r, n, "a passkey’s site")?;
    if !site::valid(rp_id) {
        return Err(format!("record {n}: a passkey’s site (its relying party) that isn’t a plain hostname"));
    }
    let credential_id = r.bytes16().map_err(|_| cut(n))?;
    if !CREDENTIAL_ID_LEN.contains(&credential_id.len()) {
        return Err(format!(
            "record {n}: a passkey’s credential ID of {} bytes: maki takes 16 to 255",
            credential_id.len()
        ));
    }
    let user_handle = r.bytes16().map_err(|_| cut(n))?;
    if !USER_HANDLE_LEN.contains(&user_handle.len()) {
        return Err(format!(
            "record {n}: a passkey’s user handle of {} bytes: maki takes 1 to 64",
            user_handle.len()
        ));
    }
    let user_name = plain_text(r, n, "a passkey’s user name")?;
    let display_name = plain_text(r, n, "a passkey’s display name")?;
    let key = r.bytes16().map_err(|_| cut(n))?;
    if key.len() != PRIVATE_KEY_LEN {
        return Err(format!(
            "record {n}: a passkey’s private key of {} bytes: a P-256 key has 32",
            key.len()
        ));
    }
    let mut passkey = Passkey {
        rp_id: rp_id.into(),
        credential_id: credential_id.to_vec(),
        user_handle: user_handle.to_vec(),
        user_name: user_name.into(),
        display_name: display_name.into(),
        private_key: [0; PRIVATE_KEY_LEN],
    };
    passkey.private_key.copy_from_slice(key);
    if !p256_private_key(&passkey.private_key) {
        return Err(format!("record {n}: a passkey’s private key that isn’t a P-256 key"));
    }
    Ok(Record::Passkey(passkey))
}

/// The order of P-256's group (SEC 2): a private key is a number from 1 to one less than this.
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc,
    0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Whether `key` (big-endian) is a P-256 private key, as OpenSK's signing takes one: neither 0
/// nor the group's order or more. The same work whatever the key.
pub fn p256_private_key(key: &[u8; PRIVATE_KEY_LEN]) -> bool {
    // key - n, byte by byte from the end: a borrow out of the top means key < n
    let mut borrow = 0u16;
    for i in (0..PRIVATE_KEY_LEN).rev() {
        let d = (key[i] as u16).wrapping_sub(P256_N[i] as u16).wrapping_sub(borrow);
        borrow = (d >> 15) & 1;
    }
    let nonzero = key.iter().fold(0u8, |a, &b| a | b) != 0;
    borrow == 1 && nonzero
}

/// What the vault has already, for telling what of an import is new, and how much room is left.
#[derive(Default)]
pub struct Have {
    /// Its logins: each one's site, as `site::normalize` has it, and its username.
    pub logins: HashSet<(String, String)>,
    /// The names its logins' and its codes' records are kept under (`vault::login_key`,
    /// `vault::code_key`): one per record, so their counts are how many it has.
    pub login_keys: HashSet<String>,
    pub code_keys: HashSet<String>,
    /// Its codes' secrets.
    pub code_secrets: Vec<Vec<u8>>,
    /// Its passkeys' credential IDs, and the accounts they're for: each one's site (RP ID) and
    /// user handle.
    pub credential_ids: HashSet<Vec<u8>>,
    pub accounts: HashSet<(String, Vec<u8>)>,
    /// How many more passkeys it has room for.
    pub passkey_room: usize,
    /// About how much of maki's database its logins, codes and passkeys take (`cost`).
    pub used: u64,
}

impl Drop for Have {
    fn drop(&mut self) {
        for secret in self.code_secrets.iter_mut() {
            secret.zeroize();
        }
    }
}

/// What of an import maki would add, and what it has already.
#[derive(Debug)]
pub struct Plan<'a> {
    pub logins: Vec<&'a Login>,
    /// each with the name maki keeps it under: `vault::code_name`'s, numbered ("GitHub:kara (2)")
    /// when another code has that name already
    pub codes: Vec<(String, &'a Code)>,
    pub passkeys: Vec<&'a Passkey>,
    /// Records maki has already, or that came earlier in the same import: maki keeps what it has.
    pub skipped: u32,
    /// Records the vault can't keep beside one of its own, which neither is added nor counts as
    /// skipped: a login whose record would have another login's name (the SHA-256 of the site and
    /// username run together: "a.co" + "mkara" is "a.com" + "kara"). Next to never.
    pub clashes: u32,
}

impl Plan<'_> {
    /// Whether there's anything new to add.
    pub fn is_empty(&self) -> bool {
        self.logins.is_empty() && self.codes.is_empty() && self.passkeys.is_empty()
    }

    /// About how much of maki's database the new records take (`cost`), as maki writes them,
    /// with the passkeys' marks.
    pub fn bytes(&self) -> u64 {
        // the longest a time or an order is written
        const CTIME: u64 = 9_999_999_999;
        let mut total = 0;
        for login in &self.logins {
            let mut record = vault::login_record(login, CTIME);
            total += cost(record.len());
            record.zeroize();
        }
        for (name, code) in &self.codes {
            let mut record = vault::code_record(name, code, CTIME);
            total += cost(record.len());
            record.zeroize();
        }
        for passkey in &self.passkeys {
            let mut record = opensk::credential(passkey, u64::MAX);
            total += cost(record.len()) + cost(passkey.credential_id.len());
            record.zeroize();
        }
        total
    }
}

/// What of `import` maki would add: what it doesn't have, and the first of what comes twice. It
/// keeps what it has: a login for the same site (`site::normalize`'s) and username, a code with
/// the same secret, a passkey with the same credential ID, or for an account (a site and a user
/// handle) maki has a passkey for already, since its authenticator holds one passkey an account.
/// An import never overwrites anything.
pub fn plan<'a>(import: &'a Import, have: &Have) -> Plan<'a> {
    let mut plan =
        Plan { logins: Vec::new(), codes: Vec::new(), passkeys: Vec::new(), skipped: 0, clashes: 0 };
    let mut logins: HashSet<(String, String)> = HashSet::new();
    let mut login_keys: HashSet<String> = HashSet::new();
    let mut secrets: Vec<&[u8]> = Vec::new();
    let mut code_keys: HashSet<String> = HashSet::new();
    let mut ids: HashSet<&[u8]> = HashSet::new();
    let mut accounts: HashSet<(String, Vec<u8>)> = HashSet::new();
    for record in &import.records {
        match record {
            Record::Login(login) => {
                let who = (site::normalize(&login.site), login.username.clone());
                if have.logins.contains(&who) || logins.contains(&who) {
                    plan.skipped += 1;
                    continue;
                }
                let key = vault::login_key(&login.site, &login.username);
                if have.login_keys.contains(&key) || login_keys.contains(&key) {
                    plan.clashes += 1;
                    continue;
                }
                logins.insert(who);
                login_keys.insert(key);
                plan.logins.push(login);
            }
            Record::Code(code) => {
                let secret = code.secret.as_slice();
                if have.code_secrets.iter().any(|s| s.as_slice() == secret) || secrets.contains(&secret) {
                    plan.skipped += 1;
                    continue;
                }
                let base = vault::code_name(&code.issuer, &code.account);
                let mut name = None;
                for n in 1..=MAX_SAME_NAME {
                    let candidate = if n == 1 { base.clone() } else { format!("{base} ({n})") };
                    let key = vault::code_key(&candidate);
                    if !have.code_keys.contains(&key) && !code_keys.contains(&key) {
                        code_keys.insert(key);
                        name = Some(candidate);
                        break;
                    }
                }
                match name {
                    Some(name) => {
                        secrets.push(secret);
                        plan.codes.push((name, code));
                    }
                    None => plan.clashes += 1,
                }
            }
            Record::Passkey(passkey) => {
                let id = passkey.credential_id.as_slice();
                let account = (passkey.rp_id.clone(), passkey.user_handle.clone());
                if have.credential_ids.contains(id)
                    || ids.contains(id)
                    || have.accounts.contains(&account)
                    || accounts.contains(&account)
                {
                    plan.skipped += 1;
                    continue;
                }
                ids.insert(id);
                accounts.insert(account);
                plan.passkeys.push(passkey);
            }
        }
    }
    plan
}

/// Whether maki has room for what `plan` adds, beside what it `have`s: or why not, in words.
/// What's checked here is all that can fill: the vault's lists, the authenticator's slots and
/// maki's share of the database.
pub fn check_room(plan: &Plan, have: &Have) -> Result<(), String> {
    let (logins, codes) = (have.login_keys.len(), have.code_keys.len());
    if !plan.logins.is_empty() && logins + plan.logins.len() > MAX_LOGINS {
        return Err(format!(
            "maki’s vault holds up to {MAX_LOGINS} logins: it has {logins}, and this import has {} more",
            plan.logins.len()
        ));
    }
    if !plan.codes.is_empty() && codes + plan.codes.len() > MAX_CODES {
        return Err(format!(
            "maki’s Authenticator holds up to {MAX_CODES} codes: it has {codes}, and this import has {} more",
            plan.codes.len()
        ));
    }
    if plan.passkeys.len() > have.passkey_room {
        return Err(format!(
            "maki holds up to {MAX_PASSKEYS} passkeys: it has room for {} more, and this import has {}",
            have.passkey_room,
            plan.passkeys.len()
        ));
    }
    let adding = plan.bytes();
    if adding > 0 && have.used + adding > VAULT_ROOM {
        return Err(format!(
            "maki keeps up to {} KiB of logins, codes and passkeys: it has about {} KiB, and this import would \
             add about {} KiB",
            VAULT_ROOM / 1024,
            have.used.div_ceil(1024),
            adding.div_ceil(1024)
        ));
    }
    Ok(())
}

/// The vault's records as vault2 keeps them (its `storage.rs`): lines of `tag:value`, in the
/// order it writes them, in a dictionary of the secret basis, under the SHA-256 of what names the
/// record, in upper-case hex. Written so, an imported login is found by GET_LOGIN, listed and
/// typed as one saved from a browser is, and an imported code shows and works in the
/// Authenticator as one scanned from a QR code does.
pub mod vault {
    use super::*;

    /// vault2's dictionaries of logins and of codes.
    pub const LOGINS: &str = "vault.passwords";
    pub const CODES: &str = "vault.totp";
    /// maki-keys' record of the passkeys it was given in an import, not made on it: one key
    /// each, named by `mark_key`, holding its credential ID, in the secret basis beside the
    /// vault's. A passkey deleted since leaves its mark behind, which counts for nothing.
    pub const IMPORTED: &str = "maki.imported";
    /// The notes a login saved from a browser gets (vault2's `vault.notes`, in English): an
    /// imported login's, when its entry had no title.
    pub const NOTES: &str = "Notes";
    /// The versions vault2 writes its records at (3 for codes has the sites each is for).
    pub const LOGIN_VERSION: u32 = 1;
    pub const CODE_VERSION: u32 = 3;

    fn upper_hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02X}")).collect() }

    /// The name vault2 keeps a login's record under: the SHA-256 of its site (as written in the
    /// record) and username, run together.
    pub fn login_key(site: &str, username: &str) -> String {
        let mut h = Sha256::new();
        h.update(site.as_bytes());
        h.update(username.as_bytes());
        upper_hex(&h.finalize())
    }

    /// The name vault2 keeps a code's record under: the SHA-256 of the code's name.
    pub fn code_key(name: &str) -> String { upper_hex(&Sha256::digest(name.as_bytes())) }

    /// The name of maki-keys' mark on an imported passkey: the SHA-256 of its credential ID, in
    /// hex (a key's name holds at most 95 bytes; an ID, 255).
    pub fn mark_key(credential_id: &[u8]) -> String {
        Sha256::digest(credential_id).iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The name a code shows under in the Authenticator: "issuer:account", as an `otpauth://`
    /// QR code's label has it (and Google Authenticator's export, as maki reads that).
    pub fn code_name(issuer: &str, account: &str) -> String {
        match (issuer.is_empty(), account.is_empty()) {
            (false, true) => issuer.into(),
            (false, false) if !account.starts_with(&format!("{issuer}:")) => format!("{issuer}:{account}"),
            _ => account.into(),
        }
    }

    /// `tag:value` lines, each ended with a line feed, in a buffer of their size (one that grew
    /// would leave copies of the secrets in them behind).
    fn lines(fields: &[(&str, &str)]) -> Vec<u8> {
        let len = fields.iter().map(|(tag, value)| tag.len() + value.len() + 2).sum();
        let mut out = Vec::with_capacity(len);
        for (tag, value) in fields {
            out.extend_from_slice(tag.as_bytes());
            out.push(b':');
            out.extend_from_slice(value.as_bytes());
            out.push(b'\n');
        }
        out
    }

    /// A login's record, as vault2 writes one saved from a browser (SAVE_LOGIN): its site as the
    /// description, the title as its notes, never used yet. It holds the password: wipe it once
    /// it's written.
    pub fn login_record(login: &Login, ctime: u64) -> Vec<u8> {
        let notes = if login.title.is_empty() { NOTES } else { login.title.as_str() };
        lines(&[
            ("version", &LOGIN_VERSION.to_string()),
            ("description", &login.site),
            ("username", &login.username),
            ("password", &login.password),
            ("notes", notes),
            ("ctime", &ctime.to_string()),
            ("atime", "0"),
            ("count", "0"),
        ])
    }

    /// A code's record, as vault2 writes one scanned from a QR code: its secret in base32, its
    /// issuer as its notes, time-based, for no site yet (the first site to ask for a code has the
    /// owner pick one). It holds the secret: wipe it once it's written.
    pub fn code_record(name: &str, code: &Code, ctime: u64) -> Vec<u8> {
        let mut secret = base32(&code.secret);
        let record = lines(&[
            ("version", &CODE_VERSION.to_string()),
            ("secret", &secret),
            ("name", name),
            ("algorithm", code.algorithm.name()),
            ("notes", &code.issuer),
            ("digits", &code.digits.to_string()),
            ("timestep", &code.period_s.to_string()),
            ("hotp", "0"),
            ("site", ""),
            ("ctime", &ctime.to_string()),
        ]);
        secret.zeroize();
        record
    }

    const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// Base32 (RFC 4648), upper case, without padding: how vault2 keeps a code's secret.
    pub fn base32(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
        let (mut buffer, mut bits) = (0u32, 0u32);
        for &b in bytes {
            buffer = (buffer << 8) | b as u32;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(BASE32[((buffer >> bits) & 31) as usize] as char);
            }
            buffer &= (1 << bits) - 1;
        }
        if bits > 0 {
            out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
        }
        buffer.zeroize();
        out
    }

    /// A secret as vault2 reads one back for a code (link.rs): in either case, spaces and
    /// padding ignored. None if it isn't base32.
    pub fn base32_decode(text: &str) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(text.len() * 5 / 8);
        let (mut buffer, mut bits) = (0u32, 0u32);
        for c in text.trim_end_matches('=').bytes().filter(|&c| c != b' ') {
            let value = BASE32.iter().position(|&a| a == c.to_ascii_uppercase())? as u32;
            buffer = (buffer << 5) | value;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((buffer >> bits) as u8);
            }
            buffer &= (1 << bits) - 1;
        }
        buffer.zeroize();
        Some(out)
    }

    /// A tag's value in one of vault2's records, as it reads them: every line with the tag, run
    /// together.
    fn field(record: &str, tag: &str) -> String {
        let mut value = String::new();
        for line in record.split('\n') {
            if let Some((t, v)) = line.split_once(':') {
                if t == tag {
                    value.push_str(v);
                }
            }
        }
        value
    }

    /// The site (as written in the record) and the username of a login's record.
    pub fn login_fields(record: &[u8]) -> Option<(String, String)> {
        let text = core::str::from_utf8(record).ok()?;
        Some((field(text, "description"), field(text, "username")))
    }

    /// The secret of a code's record.
    pub fn code_secret(record: &[u8]) -> Option<Vec<u8>> {
        let text = core::str::from_utf8(record).ok()?;
        let mut secret = field(text, "secret");
        let bytes = base32_decode(&secret);
        secret.zeroize();
        bytes.filter(|b| !b.is_empty())
    }
}

/// Resident credentials as maki's FIDO authenticator (OpenSK, in vault2) keeps them: a CBOR map
/// each, in its dictionary `opensk` of the secret basis, under the number of a slot (maki-fido's
/// `CREDENTIALS`). OpenSK reads every one of them for each request a site makes, and one it can't
/// read would fail them all: an imported passkey is written as OpenSK writes one it made itself
/// (canonical CBOR, minimal lengths, its keys in order), which its own strict reader takes
/// (maki-proto's tests read it with that reader). Its private key is kept as OpenSK keeps one
/// (`[-7, key]`, the scalar itself, which OpenSK's key store hands back as it is), so OpenSK
/// signs with it as with its own; its credential ID is kept as it came, which OpenSK looks up by
/// its bytes alone, whatever their length (only credentials that aren't resident have an ID it
/// made, and decrypts).
pub mod opensk {
    use super::Passkey;

    // OpenSK's credential fields (ctap/data_formats.rs, PublicKeyCredentialSourceField)
    const CREDENTIAL_ID: u64 = 0;
    const RP_ID: u64 = 2;
    const USER_HANDLE: u64 = 3;
    const USER_DISPLAY_NAME: u64 = 4;
    const CREATION_ORDER: u64 = 7;
    const USER_NAME: u64 = 8;
    const PRIVATE_KEY: u64 = 12;
    /// COSE's ES256, which OpenSK keeps with an ECDSA key
    const ES256: i64 = -7;
    /// OpenSK keeps the names a site gives it cut to this many bytes, at a character.
    pub const NAME_LEN: usize = 64;

    fn head(out: &mut Vec<u8>, major: u8, n: u64) {
        let m = major << 5;
        match n {
            0..=23 => out.push(m | n as u8),
            24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
            0x100..=0xffff => {
                out.push(m | 25);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                out.push(m | 26);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            }
            _ => {
                out.push(m | 27);
                out.extend_from_slice(&n.to_be_bytes());
            }
        }
    }

    fn bytes(out: &mut Vec<u8>, major: u8, b: &[u8]) {
        head(out, major, b.len() as u64);
        out.extend_from_slice(b);
    }

    /// At most `max` bytes of `s`, cut at a character, as OpenSK cuts a site's names.
    fn cut(s: &str, max: usize) -> &str {
        let mut end = s.len().min(max);
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }

    /// The record of an imported passkey: its credential ID, site and user handle, its names
    /// (empty ones left out, as a site that gives none), `creation_order`, and its key. It holds
    /// the private key: wipe it once it's written.
    pub fn credential(passkey: &Passkey, creation_order: u64) -> Vec<u8> {
        let display_name = cut(&passkey.display_name, NAME_LEN);
        let user_name = cut(&passkey.user_name, NAME_LEN);
        let pairs = 5 + !display_name.is_empty() as u64 + !user_name.is_empty() as u64;
        let room = 64 + passkey.credential_id.len() + passkey.rp_id.len() + passkey.user_handle.len();
        let mut out = Vec::with_capacity(room + display_name.len() + user_name.len() + 40);
        head(&mut out, 5, pairs);
        head(&mut out, 0, CREDENTIAL_ID);
        bytes(&mut out, 2, &passkey.credential_id);
        head(&mut out, 0, RP_ID);
        bytes(&mut out, 3, passkey.rp_id.as_bytes());
        head(&mut out, 0, USER_HANDLE);
        bytes(&mut out, 2, &passkey.user_handle);
        if !display_name.is_empty() {
            head(&mut out, 0, USER_DISPLAY_NAME);
            bytes(&mut out, 3, display_name.as_bytes());
        }
        head(&mut out, 0, CREATION_ORDER);
        head(&mut out, 0, creation_order);
        if !user_name.is_empty() {
            head(&mut out, 0, USER_NAME);
            bytes(&mut out, 3, user_name.as_bytes());
        }
        head(&mut out, 0, PRIVATE_KEY);
        head(&mut out, 4, 2);
        head(&mut out, 1, (-1 - ES256) as u64);
        bytes(&mut out, 2, &passkey.private_key);
        out
    }

    /// What maki needs to know of a passkey it holds: which it is, the account it's for, and
    /// where it comes in OpenSK's order.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Held {
        pub credential_id: Vec<u8>,
        pub rp_id: String,
        pub user_handle: Vec<u8>,
        /// 0 when the record has none, as OpenSK reads it
        pub creation_order: u64,
    }

    /// The header at `at`: its major type, its argument, and where what follows it starts.
    /// Definite lengths only, which is what OpenSK writes.
    fn read_head(b: &[u8], at: usize) -> Option<(u8, u64, usize)> {
        let first = *b.get(at)?;
        let (major, info) = (first >> 5, first & 31);
        let (value, next) = match info {
            0..=23 => (info as u64, at + 1),
            24 => (*b.get(at + 1)? as u64, at + 2),
            25 => (u16::from_be_bytes(b.get(at + 1..at + 3)?.try_into().ok()?) as u64, at + 3),
            26 => (u32::from_be_bytes(b.get(at + 1..at + 5)?.try_into().ok()?) as u64, at + 5),
            27 => (u64::from_be_bytes(b.get(at + 1..at + 9)?.try_into().ok()?), at + 9),
            _ => return None,
        };
        Some((major, value, next))
    }

    /// Where the item at `at` ends.
    fn skip(b: &[u8], at: usize, depth: u32) -> Option<usize> {
        if depth > 8 {
            return None;
        }
        let (major, value, next) = read_head(b, at)?;
        match major {
            0 | 1 | 7 => Some(next),
            2 | 3 => {
                let end = next.checked_add(usize::try_from(value).ok()?)?;
                (end <= b.len()).then_some(end)
            }
            4 => (0..value).try_fold(next, |at, _| skip(b, at, depth + 1)),
            5 => (0..value.checked_mul(2)?).try_fold(next, |at, _| skip(b, at, depth + 1)),
            6 => skip(b, next, depth + 1),
            _ => None,
        }
    }

    /// A passkey's record, read for what maki needs of it; None if it isn't one.
    pub fn read(record: &[u8]) -> Option<Held> {
        let (major, pairs, mut at) = read_head(record, 0)?;
        if major != 5 {
            return None;
        }
        let (mut id, mut rp_id, mut user_handle, mut order) = (None, None, None, 0);
        for _ in 0..pairs {
            let (key_major, key, _) = read_head(record, at)?;
            let value = skip(record, at, 1)?;
            let end = skip(record, value, 1)?;
            let (major, n, data) = read_head(record, value)?;
            let contents = || record.get(data..data.checked_add(usize::try_from(n).ok()?)?);
            match (key_major, key, major) {
                (0, CREDENTIAL_ID, 2) => id = Some(contents()?.to_vec()),
                (0, RP_ID, 3) => rp_id = Some(core::str::from_utf8(contents()?).ok()?.to_string()),
                (0, USER_HANDLE, 2) => user_handle = Some(contents()?.to_vec()),
                (0, CREATION_ORDER, 0) => order = n,
                _ => {}
            }
            at = end;
        }
        Some(Held { credential_id: id?, rp_id: rp_id?, user_handle: user_handle?, creation_order: order })
    }
}
