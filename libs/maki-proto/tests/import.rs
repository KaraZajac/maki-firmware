//! Imports from other password managers: the format, every check maki makes of it, what of it
//! maki has already, its room, and the records maki writes, held to vault2's own formats and to
//! OpenSK's own CBOR reader and writer.

use cbor::Value;
use maki_proto::import::*;

/// An import, as maki desktop writes one.
struct Blob {
    records: Vec<u8>,
    count: u32,
}

fn str8(out: &mut Vec<u8>, s: &[u8]) {
    out.push(s.len() as u8);
    out.extend_from_slice(s);
}

fn bytes16(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u16).to_le_bytes());
    out.extend_from_slice(b);
}

impl Blob {
    fn new() -> Self { Blob { records: Vec::new(), count: 0 } }

    fn login(mut self, site: &str, username: &str, password: &str, title: &str) -> Self {
        self.records.push(LOGIN);
        for s in [site, username, password, title] {
            str8(&mut self.records, s.as_bytes());
        }
        self.count += 1;
        self
    }

    #[allow(clippy::too_many_arguments)]
    fn code(
        mut self,
        issuer: &str,
        account: &str,
        secret: &[u8],
        algorithm: u8,
        digits: u8,
        period: u16,
    ) -> Self {
        self.records.push(CODE);
        str8(&mut self.records, issuer.as_bytes());
        str8(&mut self.records, account.as_bytes());
        bytes16(&mut self.records, secret);
        self.records.extend_from_slice(&[algorithm, digits]);
        self.records.extend_from_slice(&period.to_le_bytes());
        self.count += 1;
        self
    }

    fn passkey(mut self, rp: &str, id: &[u8], handle: &[u8], name: &str, display: &str, key: &[u8]) -> Self {
        self.records.push(PASSKEY);
        str8(&mut self.records, rp.as_bytes());
        bytes16(&mut self.records, id);
        bytes16(&mut self.records, handle);
        str8(&mut self.records, name.as_bytes());
        str8(&mut self.records, display.as_bytes());
        bytes16(&mut self.records, key);
        self.count += 1;
        self
    }

    /// Anything at all, as a record.
    fn raw(mut self, bytes: &[u8]) -> Self {
        self.records.extend_from_slice(bytes);
        self.count += 1;
        self
    }

    fn finish(self, source: &str) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        str8(&mut out, source.as_bytes());
        out.extend_from_slice(&self.count.to_le_bytes());
        out.extend_from_slice(&self.records);
        out
    }
}

/// A P-256 private key: RFC 6979's test key (A.2.5).
const KEY: [u8; 32] = [
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e,
    0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
];
const SECRET: &[u8] = b"Hello!\xde\xad\xbe\xef";

fn sample() -> Vec<u8> {
    Blob::new()
        .login("github.com", "kara", "correct horse", "GitHub (work)")
        .login("192.168.1.1", "", "router-pw", "")
        .code("GitHub", "kara", SECRET, 1, 6, 30)
        .passkey("example.com", &[0x11; 16], &[0x22; 8], "kara", "Kara Z", &KEY)
        .finish("Bitwarden")
}

fn refused(blob: &[u8]) -> String {
    match parse(blob) {
        Ok(import) => panic!("taken: {import:?}"),
        Err(why) => why,
    }
}

#[test]
fn an_import_reads_as_its_records() {
    let import = parse(&sample()).unwrap();
    assert_eq!(import.source, "Bitwarden");
    assert_eq!(import.records.len(), 4);
    match &import.records[0] {
        Record::Login(l) => {
            assert_eq!(
                (&*l.site, &*l.username, &*l.password, &*l.title),
                ("github.com", "kara", "correct horse", "GitHub (work)")
            )
        }
        other => panic!("{other:?}"),
    }
    match &import.records[1] {
        Record::Login(l) => assert_eq!((&*l.site, &*l.username, &*l.title), ("192.168.1.1", "", "")),
        other => panic!("{other:?}"),
    }
    match &import.records[2] {
        Record::Code(c) => {
            assert_eq!((&*c.issuer, &*c.account, &c.secret[..]), ("GitHub", "kara", SECRET));
            assert_eq!((c.algorithm, c.digits, c.period_s), (Algorithm::Sha1, 6, 30));
        }
        other => panic!("{other:?}"),
    }
    match &import.records[3] {
        Record::Passkey(p) => {
            assert_eq!(
                (&*p.rp_id, &p.credential_id[..], &p.user_handle[..]),
                ("example.com", &[0x11; 16][..], &[0x22; 8][..])
            );
            assert_eq!((&*p.user_name, &*p.display_name, p.private_key), ("kara", "Kara Z", KEY));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn every_limit_is_taken_at_its_edge() {
    let id = vec![7u8; 255];
    let blob = Blob::new()
        .login(&format!("{}.com", "a".repeat(249)), &"u".repeat(255), &"p".repeat(255), &"t".repeat(255))
        .code("", "kara", &[1; 10], 2, 8, 15)
        .code("Bank", "", &[2; 64], 3, 7, 300)
        .passkey("example.com", &id, &[1; 64], "", "", &KEY)
        .passkey("example.com", &[3; 16], &[1], &"é".repeat(127), "", &KEY)
        .finish(&"s".repeat(32));
    let import = parse(&blob).unwrap();
    assert_eq!(import.records.len(), 5);
    // the most records an import holds
    let mut many = Blob::new();
    for i in 0..MAX_RECORDS {
        many = many.login("example.com", &i.to_string(), "pw", "");
    }
    assert_eq!(parse(&many.finish("Many")).unwrap().records.len(), MAX_RECORDS);
}

#[test]
fn what_isnt_an_import_is_refused() {
    assert!(refused(b"MAKIBAK1\x09Bitwarden").contains("doesn’t start with MAKIIMP1"));
    assert_eq!(refused(&MAGIC[..]), "it’s cut short before its records");
    assert_eq!(refused(&Blob::new().finish("")), "its source’s name is 0 bytes: maki takes 1 to 32");
    assert_eq!(
        refused(&Blob::new().finish(&"x".repeat(33))),
        "its source’s name is 33 bytes: maki takes 1 to 32"
    );
    assert_eq!(refused(&Blob::new().finish("Bit\nwarden")), "its source’s name has a control character");
    let mut not_text = MAGIC.to_vec();
    not_text.extend_from_slice(&[2, 0xff, 0xfe, 1, 0, 0, 0]);
    assert_eq!(refused(&not_text), "its source’s name isn’t UTF-8 text");
    // no count, or none
    let mut no_count = MAGIC.to_vec();
    str8(&mut no_count, b"Bitwarden");
    assert_eq!(refused(&no_count), "it’s cut short before its records");
    assert_eq!(refused(&Blob::new().finish("Bitwarden")), "it has no records");
    // more than maki reads at once: refused before any is read
    let mut too_many = Blob::new().login("example.com", "kara", "pw", "");
    too_many.count = MAX_RECORDS as u32 + 1;
    assert_eq!(
        refused(&too_many.finish("Bitwarden")),
        "it has 2001 records: maki takes at most 2000 at a time"
    );
    // fewer records than it says, more, or a kind maki doesn't know
    let mut short = Blob::new().login("example.com", "kara", "pw", "");
    short.count = 2;
    assert_eq!(refused(&short.finish("Bitwarden")), "record 2 is cut short");
    let mut long = Blob::new().login("example.com", "kara", "pw", "").login("example.com", "x", "pw", "");
    long.count = 1;
    assert_eq!(refused(&long.finish("Bitwarden")), "it has something after its last record");
    let unknown = Blob::new().login("example.com", "kara", "pw", "").raw(&[4, 0]).finish("Bitwarden");
    assert_eq!(refused(&unknown), "record 2 is of a kind maki doesn’t know (4)");
}

#[test]
fn a_login_maki_wont_take_refuses_the_whole_import() {
    let one = |site: &str, user: &str, pass: &str, title: &str| {
        refused(
            &Blob::new()
                .login("example.com", "ok", "ok", "")
                .login(site, user, pass, title)
                .finish("Proton Pass"),
        )
    };
    for site in ["GitHub.com", "аpple.com", "github.com/login", ".github.com", "git hub.com", "", "a..b"] {
        assert!(
            one(site, "kara", "pw", "").starts_with("record 2: a login’s site that isn’t a plain hostname"),
            "{site:?}"
        );
    }
    assert_eq!(one("example.com", "ka\nra", "pw", ""), "record 2: a username with a control character");
    assert_eq!(
        one("example.com", "kara", "pw\npassword:x", ""),
        "record 2: a password with a control character"
    );
    assert_eq!(one("example.com", "kara", "p\u{7f}w", ""), "record 2: a password with a control character");
    assert_eq!(one("example.com", "kara", "", ""), "record 2: an empty password");
    assert_eq!(
        one("example.com", "kara", "pw", "work\u{1b}[2J"),
        "record 2: a title with a control character"
    );
    // not UTF-8, and cut short in each of its fields
    let mut bad = Blob::new().raw(&[LOGIN]);
    str8(&mut bad.records, b"example.com");
    str8(&mut bad.records, b"kara");
    str8(&mut bad.records, &[0xc3, 0x28]);
    str8(&mut bad.records, b"");
    assert_eq!(refused(&bad.finish("x")), "record 1: a password that isn’t UTF-8 text");
    let whole = Blob::new().login("example.com", "kara", "pw", "t").finish("x");
    for cut in 1..whole.len() - 18 {
        assert_eq!(refused(&whole[..whole.len() - cut]), "record 1 is cut short", "{cut}");
    }
}

#[test]
fn a_code_maki_wont_take_refuses_the_whole_import() {
    let one = |issuer: &str, account: &str, secret: &[u8], alg: u8, digits: u8, period: u16| {
        refused(&Blob::new().code(issuer, account, secret, alg, digits, period).finish("1Password"))
    };
    assert_eq!(one("", "", &[1; 20], 1, 6, 30), "record 1: a code with neither an issuer nor an account");
    assert_eq!(
        one("Git\tHub", "kara", &[1; 20], 1, 6, 30),
        "record 1: a code’s issuer with a control character"
    );
    assert_eq!(
        one("GitHub", "ka\rra", &[1; 20], 1, 6, 30),
        "record 1: a code’s account with a control character"
    );
    assert_eq!(
        one("GitHub", "kara", &[1; 9], 1, 6, 30),
        "record 1: a code’s secret of 9 bytes: maki takes 10 to 64"
    );
    assert_eq!(
        one("GitHub", "kara", &[1; 65], 1, 6, 30),
        "record 1: a code’s secret of 65 bytes: maki takes 10 to 64"
    );
    assert_eq!(
        one("GitHub", "kara", &[1; 20], 0, 6, 30),
        "record 1: a code’s algorithm maki doesn’t know (0)"
    );
    assert_eq!(
        one("GitHub", "kara", &[1; 20], 4, 6, 30),
        "record 1: a code’s algorithm maki doesn’t know (4)"
    );
    assert_eq!(one("GitHub", "kara", &[1; 20], 1, 5, 30), "record 1: a code of 5 digits: maki takes 6 to 8");
    assert_eq!(one("GitHub", "kara", &[1; 20], 1, 9, 30), "record 1: a code of 9 digits: maki takes 6 to 8");
    assert_eq!(
        one("GitHub", "kara", &[1; 20], 1, 6, 14),
        "record 1: a code that changes every 14 s: maki takes 15 to 300"
    );
    assert_eq!(
        one("GitHub", "kara", &[1; 20], 1, 6, 301),
        "record 1: a code that changes every 301 s: maki takes 15 to 300"
    );
    let whole = Blob::new().code("GitHub", "kara", &[1; 20], 1, 6, 30).finish("x");
    for cut in 1..whole.len() - 18 {
        assert_eq!(refused(&whole[..whole.len() - cut]), "record 1 is cut short", "{cut}");
    }
}

#[test]
fn a_passkey_maki_wont_take_refuses_the_whole_import() {
    let one = |rp: &str, id: &[u8], handle: &[u8], name: &str, display: &str, key: &[u8]| {
        refused(&Blob::new().passkey(rp, id, handle, name, display, key).finish("KeePassXC"))
    };
    let good = |rp| one(rp, &[1; 16], &[2; 8], "", "", &KEY);
    assert!(
        good("Example.com")
            .starts_with("record 1: a passkey’s site (its relying party) that isn’t a plain hostname")
    );
    assert!(good("").starts_with("record 1: a passkey’s site"));
    assert_eq!(
        one("example.com", &[1; 15], &[2; 8], "", "", &KEY),
        "record 1: a passkey’s credential ID of 15 bytes: maki takes 16 to 255"
    );
    assert_eq!(
        one("example.com", &[1; 256], &[2; 8], "", "", &KEY),
        "record 1: a passkey’s credential ID of 256 bytes: maki takes 16 to 255"
    );
    assert_eq!(
        one("example.com", &[1; 16], &[], "", "", &KEY),
        "record 1: a passkey’s user handle of 0 bytes: maki takes 1 to 64"
    );
    assert_eq!(
        one("example.com", &[1; 16], &[2; 65], "", "", &KEY),
        "record 1: a passkey’s user handle of 65 bytes: maki takes 1 to 64"
    );
    assert_eq!(
        one("example.com", &[1; 16], &[2; 8], "ka\u{85}ra", "", &KEY),
        "record 1: a passkey’s user name with a control character"
    );
    assert_eq!(
        one("example.com", &[1; 16], &[2; 8], "", "K\0", &KEY),
        "record 1: a passkey’s display name with a control character"
    );
    assert_eq!(
        one("example.com", &[1; 16], &[2; 8], "", "", &KEY[..31]),
        "record 1: a passkey’s private key of 31 bytes: a P-256 key has 32"
    );
    assert_eq!(
        one("example.com", &[1; 16], &[2; 8], "", "", &[KEY.as_slice(), &[0]].concat()),
        "record 1: a passkey’s private key of 33 bytes: a P-256 key has 32"
    );
    let n: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc,
        0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ];
    for key in [[0u8; 32], n, [0xff; 32]] {
        assert_eq!(
            one("example.com", &[1; 16], &[2; 8], "", "", &key),
            "record 1: a passkey’s private key that isn’t a P-256 key"
        );
    }
    let whole = Blob::new().passkey("example.com", &[1; 16], &[2; 8], "k", "K", &KEY).finish("x");
    for cut in 1..whole.len() - 18 {
        assert_eq!(refused(&whole[..whole.len() - cut]), "record 1 is cut short", "{cut}");
    }
}

#[test]
fn a_private_key_is_one_p256_takes() {
    use p256::NonZeroScalar;
    let n_minus = |k: u8| {
        let mut n: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
        ];
        n[31] = n[31].wrapping_sub(k);
        n
    };
    let mut one = [0u8; 32];
    one[31] = 1;
    let mut keys = vec![[0u8; 32], one, KEY, n_minus(0), n_minus(1), n_minus(2), [0xff; 32], [0x7f; 32]];
    // and some from a simple generator, near the top and anywhere
    let mut x = 0x2545_f491_4f6c_dd1du64;
    for i in 0..2000 {
        let mut k = [0u8; 32];
        for b in k.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        if i % 2 == 0 {
            k[..4].fill(0xff);
            k[4..8].fill(0);
            k[8..16].fill(0xff);
        }
        keys.push(k);
    }
    for k in keys {
        let theirs = bool::from(NonZeroScalar::from_repr(k.into()).is_some());
        assert_eq!(p256_private_key(&k), theirs, "{k:02x?}");
    }
}

/// What a vault with these in it has.
fn have_of(logins: &[(&str, &str)], codes: &[(&str, &[u8])], passkeys: &[(&[u8], &str, &[u8])]) -> Have {
    let mut have = Have::default();
    for (site, user) in logins {
        have.logins.insert((maki_proto::site::normalize(site), user.to_string()));
        have.login_keys.insert(vault::login_key(site, user));
    }
    for (name, secret) in codes {
        have.code_keys.insert(vault::code_key(name));
        have.code_secrets.push(secret.to_vec());
    }
    for (id, rp, handle) in passkeys {
        have.credential_ids.insert(id.to_vec());
        have.accounts.insert((rp.to_string(), handle.to_vec()));
    }
    have.passkey_room = MAX_PASSKEYS - passkeys.len();
    have
}

#[test]
fn what_maki_has_it_keeps() {
    let blob = Blob::new()
        // the same site and username as maki's (www. or not), twice in the import, a new username
        .login("www.github.com", "kara", "new password", "")
        .login("example.com", "kara", "pw", "")
        .login("example.com", "kara", "another", "")
        .login("example.com", "kara2", "pw", "")
        // a code maki has (its secret), one twice, and one with a name maki has for another secret
        .code("Bank", "", b"maki-bank!", 2, 8, 30)
        .code("GitHub", "kara", SECRET, 1, 6, 30)
        .code("Other", "x", SECRET, 1, 6, 30)
        .code("Mail", "kara", b"0123456789", 1, 6, 30)
        .code("Mail", "kara", b"9876543210", 1, 6, 30)
        // a passkey maki has, one for an account maki has a passkey for, one twice, a new one
        .passkey("example.com", &[1; 16], &[2; 8], "", "", &KEY)
        .passkey("example.com", &[9; 16], &[2; 8], "", "", &KEY)
        .passkey("example.com", &[3; 16], &[3; 8], "", "", &KEY)
        .passkey("example.org", &[3; 16], &[4; 8], "", "", &KEY)
        .passkey("example.com", &[5; 16], &[5; 8], "", "", &KEY)
        .finish("LastPass");
    let import = parse(&blob).unwrap();
    let have = have_of(
        &[("https://github.com/login", "kara")],
        &[("Bank", b"maki-bank!"), ("Mail:kara", b"another secret")],
        &[(&[1; 16], "example.com", &[2; 8])],
    );
    let p = plan(&import, &have);
    let logins: Vec<(&str, &str, &str)> =
        p.logins.iter().map(|l| (&*l.site, &*l.username, &*l.password)).collect();
    assert_eq!(logins, [("example.com", "kara", "pw"), ("example.com", "kara2", "pw")]);
    let codes: Vec<(&str, &[u8])> = p.codes.iter().map(|(n, c)| (n.as_str(), &c.secret[..])).collect();
    assert_eq!(
        codes,
        [
            ("GitHub:kara", SECRET),
            ("Mail:kara (2)", &b"0123456789"[..]),
            ("Mail:kara (3)", &b"9876543210"[..])
        ]
    );
    let passkeys: Vec<&[u8]> = p.passkeys.iter().map(|k| &k.credential_id[..]).collect();
    assert_eq!(passkeys, [&[3; 16][..], &[5; 16][..]]);
    // 2 logins, 2 codes and 3 passkeys maki has, or that came before in the import
    assert_eq!((p.skipped, p.clashes), (7, 0));
    assert!(!p.is_empty());

    // the same import again, once maki has all of it: nothing new, every record skipped
    let mut all = Have::default();
    for record in &import.records {
        match record {
            Record::Login(l) => {
                all.logins.insert((maki_proto::site::normalize(&l.site), l.username.clone()));
                all.login_keys.insert(vault::login_key(&l.site, &l.username));
            }
            Record::Code(c) => all.code_secrets.push(c.secret.clone()),
            Record::Passkey(k) => {
                all.credential_ids.insert(k.credential_id.clone());
                all.accounts.insert((k.rp_id.clone(), k.user_handle.clone()));
            }
        }
    }
    let again = plan(&import, &all);
    assert!(again.is_empty());
    assert_eq!((again.skipped, again.clashes), (import.records.len() as u32, 0));
}

#[test]
fn a_login_whose_record_would_take_anothers_name_is_neither_added_nor_skipped() {
    // the vault names a login's record by its site and username run together
    assert_eq!(vault::login_key("a.co", "mkara"), vault::login_key("a.com", "kara"));
    let import = parse(&Blob::new().login("a.co", "mkara", "pw", "").finish("x")).unwrap();
    let p = plan(&import, &have_of(&[("a.com", "kara")], &[], &[]));
    assert!(p.is_empty());
    assert_eq!((p.skipped, p.clashes), (0, 1));
    // within one import too
    let import =
        parse(&Blob::new().login("a.com", "kara", "pw", "").login("a.co", "mkara", "pw", "").finish("x"))
            .unwrap();
    let p = plan(&import, &Have::default());
    assert_eq!((p.logins.len(), p.skipped, p.clashes), (1, 0, 1));
}

#[test]
fn maki_refuses_what_it_hasnt_room_for() {
    let logins = |n: usize| {
        let mut b = Blob::new();
        for i in 0..n {
            b = b.login("example.com", &format!("user{i}"), "pw", "");
        }
        parse(&b.finish("Bitwarden")).unwrap()
    };
    let mut have = Have::default();
    have.passkey_room = MAX_PASSKEYS;
    for i in 0..100 {
        have.login_keys.insert(format!("{i}"));
    }
    // up to the vault's limit, and one past it
    let fits = logins(MAX_LOGINS - 100);
    assert_eq!(check_room(&plan(&fits, &have), &have), Ok(()));
    let over = logins(MAX_LOGINS - 99);
    assert_eq!(
        check_room(&plan(&over, &have), &have),
        Err("maki’s vault holds up to 500 logins: it has 100, and this import has 401 more".into())
    );
    // codes
    let mut b = Blob::new();
    for i in 0..=MAX_CODES {
        b = b.code("Issuer", &format!("{i}"), format!("secret {i:05}").as_bytes(), 1, 6, 30);
    }
    let codes = parse(&b.finish("Aegis")).unwrap();
    assert_eq!(
        check_room(&plan(&codes, &Have::default()), &have_of(&[], &[], &[])),
        Err("maki’s Authenticator holds up to 250 codes: it has 0, and this import has 251 more".into())
    );
    // passkeys: by the authenticator's free slots
    let mut b = Blob::new();
    for i in 0..3u8 {
        b = b.passkey("example.com", &[i; 16], &[i; 4], "", "", &KEY);
    }
    let passkeys = parse(&b.finish("1Password")).unwrap();
    let mut have = Have::default();
    have.passkey_room = 2;
    assert_eq!(
        check_room(&plan(&passkeys, &have), &have),
        Err("maki holds up to 150 passkeys: it has room for 2 more, and this import has 3".into())
    );
    have.passkey_room = 3;
    assert_eq!(check_room(&plan(&passkeys, &have), &have), Ok(()));
    // and maki's share of its database
    let mut have = Have::default();
    have.passkey_room = MAX_PASSKEYS;
    have.used = VAULT_ROOM - 100;
    let one = parse(&Blob::new().login("example.com", "kara", "pw", "").finish("x")).unwrap();
    let plan_one = plan(&one, &have);
    let needs = plan_one.bytes();
    assert!(needs > 100 && needs < 300, "{needs}");
    assert_eq!(
        check_room(&plan_one, &have),
        Err("maki keeps up to 1024 KiB of logins, codes and passkeys: it has about 1024 KiB, and this import would add \
             about 1 KiB"
            .into())
    );
    have.used = VAULT_ROOM - needs;
    assert_eq!(check_room(&plan(&one, &have), &have), Ok(()));
    // a vault over its limits still takes an import with nothing new of that kind
    let mut have = have_of(&[("example.com", "kara")], &[], &[]);
    for i in 0..MAX_LOGINS {
        have.login_keys.insert(format!("{i}"));
    }
    have.used = 0;
    assert_eq!(check_room(&plan(&one, &have), &have), Ok(()));
}

#[test]
fn a_login_is_kept_as_vault2_keeps_one_saved_from_a_browser() {
    let import = parse(&sample()).unwrap();
    let Record::Login(login) = &import.records[0] else { panic!() };
    assert_eq!(
        String::from_utf8(vault::login_record(login, 1_790_000_000)).unwrap(),
        "version:1\ndescription:github.com\nusername:kara\npassword:correct horse\nnotes:GitHub (work)\n\
         ctime:1790000000\natime:0\ncount:0\n"
    );
    let Record::Login(login) = &import.records[1] else { panic!() };
    // no title: the notes a login saved from a browser gets
    assert_eq!(
        String::from_utf8(vault::login_record(login, 7)).unwrap(),
        "version:1\ndescription:192.168.1.1\nusername:\npassword:router-pw\nnotes:Notes\nctime:7\natime:0\n\
         count:0\n"
    );
    // vault2's name for it: the SHA-256 of the site and username, upper-case hex
    assert_eq!(
        vault::login_key("github.com", "kara"),
        "D99330E72517368CE62C57E6C35BFB9EE17999EB4CFC66101C4F814B8165B196"
    );
    // and what the vault reads back of one it wrote, used since (as link.rs updates it)
    let record = b"version:1\ndescription:https://www.github.com/login\nusername:kara\npassword:x:y\n\
                   notes:previous password: z\nctime:1\natime:2\ncount:3\n";
    assert_eq!(
        vault::login_fields(record),
        Some(("https://www.github.com/login".to_string(), "kara".to_string()))
    );
    assert_eq!(vault::login_fields(&[0xff, 0xfe]), None);
}

#[test]
fn a_code_is_kept_as_vault2_keeps_one_scanned_from_a_qr_code() {
    let import = parse(&sample()).unwrap();
    let Record::Code(code) = &import.records[2] else { panic!() };
    let name = vault::code_name(&code.issuer, &code.account);
    assert_eq!(name, "GitHub:kara");
    assert_eq!(
        String::from_utf8(vault::code_record(&name, code, 1_790_000_000)).unwrap(),
        "version:3\nsecret:JBSWY3DPEHPK3PXP\nname:GitHub:kara\nalgorithm:SHA1\nnotes:GitHub\ndigits:6\n\
         timestep:30\nhotp:0\nsite:\nctime:1790000000\n"
    );
    assert_eq!(
        vault::code_key("GitHub:kara"),
        "0C04C5CD0DF62D4179A2D73789DEADCB9F0DCCEAD7F3CCEA9E725E97D92412A0"
    );
    // names as an otpauth:// label and Google Authenticator's export have them
    assert_eq!(vault::code_name("GitHub", ""), "GitHub");
    assert_eq!(vault::code_name("", "kara"), "kara");
    assert_eq!(vault::code_name("GitHub", "GitHub:kara"), "GitHub:kara");
    // the secret, read back as vault2 reads it, written in either case, padded or spaced
    assert_eq!(vault::code_secret(b"version:3\nsecret:JBSWY3DPEHPK3PXP\nname:x\n").as_deref(), Some(SECRET));
    assert_eq!(vault::code_secret(b"secret:jbsw y3dp ehpk 3pxp====\n").as_deref(), Some(SECRET));
    assert_eq!(vault::code_secret(b"secret:not base32!\n"), None);
    assert_eq!(vault::code_secret(b"name:no secret\n"), None);
}

#[test]
fn base32_is_rfc_4648s() {
    for (bytes, text) in [
        (&b""[..], ""),
        (b"f", "MY"),
        (b"fo", "MZXQ"),
        (b"foo", "MZXW6"),
        (b"foob", "MZXW6YQ"),
        (b"fooba", "MZXW6YTB"),
        (b"foobar", "MZXW6YTBOI"),
        (SECRET, "JBSWY3DPEHPK3PXP"),
    ] {
        assert_eq!(vault::base32(bytes), text);
        assert_eq!(vault::base32_decode(text).as_deref(), Some(bytes));
    }
    let all: Vec<u8> = (0..=255).collect();
    assert_eq!(vault::base32_decode(&vault::base32(&all)), Some(all));
}

/// A passkey as OpenSK's `From<PublicKeyCredentialSource> for cbor::Value` builds one, written
/// by OpenSK's own writer.
fn as_opensk_writes_it(p: &Passkey, order: u64, display: Option<&str>, name: Option<&str>) -> Vec<u8> {
    let mut map = vec![
        (Value::Unsigned(0), Value::ByteString(p.credential_id.clone())),
        (Value::Unsigned(2), Value::TextString(p.rp_id.clone())),
        (Value::Unsigned(3), Value::ByteString(p.user_handle.clone())),
        (Value::Unsigned(7), Value::Unsigned(order)),
        (
            Value::Unsigned(12),
            Value::Array(vec![Value::Negative(-7), Value::ByteString(p.private_key.to_vec())]),
        ),
    ];
    if let Some(d) = display {
        map.push((Value::Unsigned(4), Value::TextString(d.into())));
    }
    if let Some(n) = name {
        map.push((Value::Unsigned(8), Value::TextString(n.into())));
    }
    let mut out = Vec::new();
    cbor::writer::write(Value::Map(map), &mut out).unwrap();
    out
}

fn passkey_of(rp: &str, id: &[u8], handle: &[u8], name: &str, display: &str) -> Passkey {
    let blob = Blob::new().passkey(rp, id, handle, name, display, &KEY).finish("x");
    match parse(&blob).unwrap().records.remove(0) {
        Record::Passkey(p) => p,
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_passkey_is_written_byte_for_byte_as_opensk_writes_its_own() {
    let p = passkey_of("example.com", &[0x11; 16], &[0x22; 8], "kara", "Kara Z");
    for order in [0, 1, 23, 24, 255, 256, 65_535, 65_536, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
        let ours = opensk::credential(&p, order);
        assert_eq!(ours, as_opensk_writes_it(&p, order, Some("Kara Z"), Some("kara")), "{order}");
        // and OpenSK's reader, which refuses what isn't canonical, takes it: at OpenSK's own depth
        let read = cbor::reader::read_nested(&ours, Some(4)).unwrap();
        let Value::Map(fields) = read else { panic!() };
        let keys: Vec<u64> = fields
            .iter()
            .map(|(k, _)| match k {
                Value::Unsigned(k) => *k,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(keys, [0, 2, 3, 4, 7, 8, 12]);
        assert_eq!(
            opensk::read(&ours),
            Some(opensk::Held {
                credential_id: vec![0x11; 16],
                rp_id: "example.com".into(),
                user_handle: vec![0x22; 8],
                creation_order: order,
            })
        );
    }
    // no names: none written, as from a site that gives none
    let bare = passkey_of("example.com", &[0x33; 255], &[0x44; 64], "", "");
    let ours = opensk::credential(&bare, 9);
    assert_eq!(ours, as_opensk_writes_it(&bare, 9, None, None));
    assert_eq!(&ours[..4], &[0xa5, 0x00, 0x58, 0xff], "a map of five; an ID of 255 bytes");
    assert!(cbor::reader::read_nested(&ours, Some(4)).is_ok());
    // names longer than OpenSK keeps: cut at 64 bytes, never inside a character
    let long = passkey_of("example.com", &[1; 16], &[2; 4], &"é".repeat(40), &"x".repeat(100));
    assert_eq!(
        opensk::credential(&long, 0),
        as_opensk_writes_it(&long, 0, Some(&"x".repeat(64)), Some(&"é".repeat(32)))
    );
}

#[test]
fn passkeys_maki_holds_are_read_for_their_account_and_order() {
    // what maki-keys' demo plants: {0: id, 2: rp, 3: user handle, 12: [-7, key]}, no order
    let mut c = vec![0xa4, 0x00, 0x58, 0x20];
    c.extend((0..32u8).map(|i| 0xd0 ^ i));
    c.extend([0x02, 0x69]);
    c.extend(b"demo.maki");
    c.extend([0x03, 0x44, 0x6d, 0x61, 0x6b, 0x69]);
    c.extend([0x0c, 0x82, 0x26, 0x58, 0x20]);
    c.extend(1..=32u8);
    let held = opensk::read(&c).unwrap();
    assert_eq!(held.credential_id, (0..32u8).map(|i| 0xd0 ^ i).collect::<Vec<_>>());
    assert_eq!(
        (held.rp_id.as_str(), &held.user_handle[..], held.creation_order),
        ("demo.maki", &b"maki"[..], 0)
    );
    // one OpenSK made with everything it keeps (credProtect, an icon, a blob, a large blob key)
    let mut map = vec![
        (Value::Unsigned(0), Value::ByteString(vec![5; 32])),
        (Value::Unsigned(2), Value::TextString("github.com".into())),
        (Value::Unsigned(3), Value::ByteString(vec![6; 20])),
        (Value::Unsigned(4), Value::TextString("Kara".into())),
        (Value::Unsigned(6), Value::Unsigned(2)),
        (Value::Unsigned(7), Value::Unsigned(41)),
        (Value::Unsigned(8), Value::TextString("kara".into())),
        (Value::Unsigned(9), Value::TextString("icon".into())),
        (Value::Unsigned(10), Value::ByteString(vec![7; 32])),
        (Value::Unsigned(11), Value::ByteString(vec![8; 32])),
        (Value::Unsigned(12), Value::Array(vec![Value::Negative(-7), Value::ByteString(vec![9; 32])])),
    ];
    map.reverse();
    let mut theirs = Vec::new();
    cbor::writer::write(Value::Map(map), &mut theirs).unwrap();
    assert_eq!(
        opensk::read(&theirs),
        Some(opensk::Held {
            credential_id: vec![5; 32],
            rp_id: "github.com".into(),
            user_handle: vec![6; 20],
            creation_order: 41
        })
    );
    // what isn't one
    assert_eq!(opensk::read(&[0xa1, 0x02, 0x61, 0x61]), None);
    assert_eq!(opensk::read(&[0x82, 0x00, 0x01]), None);
    assert_eq!(opensk::read(&theirs[..theirs.len() - 1]), None);
    assert_eq!(opensk::read(&[]), None);
}

#[test]
fn an_imported_passkeys_mark_is_named_by_its_id() {
    assert_eq!(
        vault::mark_key(&[0x11; 16]),
        "b8f12ea8c9a95d4b4641b03d9fa5a71ad30b44ed6cd4bf793bbe1a5801b986d4"
    );
    // under the PDDB's longest key name, whatever the ID
    assert!(vault::mark_key(&[0; 255]).len() <= 95);
}

#[test]
fn nothing_secret_is_printed() {
    let import = parse(&sample()).unwrap();
    let shown = format!("{import:?}");
    assert!(!shown.contains("correct horse") && !shown.contains("router-pw"), "{shown}");
    // the passkey's key, and the code's secret, by their lengths alone
    assert!(!shown.contains("201") && !shown.contains("222, 173"), "{shown}");
    assert!(
        shown.contains("(13 bytes)") && shown.contains("(10 bytes)") && shown.contains("(32 bytes)"),
        "{shown}"
    );
}
