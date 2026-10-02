//! maki-xrp against the XRP Ledger's own JavaScript library: transactions xrpl.js made
//! (`fixtures/make.mjs`), read as they are and shown as they should be, and signed by maki's keys
//! as xrpl.js signs them with the same account (the test phrase's first, at `m/44'/144'/0'/0/0`,
//! as Ledger, Xaman and xrpl.js have it), down to the signed transaction and its hash; and what
//! the ledger would refuse, encoded by xrpl.js all the same, refused, saying why.

use maki_hd::Keys;
use maki_hd::seed::SeedKeys;
use maki_xrp::codec::{self, Decimal, Field, fields};
use maki_xrp::display::{self, Code, Error, Page, Review, code, decimals, review, utc, value, xrp};
use maki_xrp::tx::{self, Transaction};
use maki_xrp::{Network, address, sign, tokens};

/// The test phrase's first account, as xrpl.js derives it and Ripple's Xpring SDK published it.
const ME: &str = "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3";
const KEY: &str = "031D68BC1A142E6766B2BDFB006CCFE135EF2E0E2E94ABB5CF5C9AB6104776FBAE";
const RECIPIENT: &str = "rMPrYipfRHJryWfwYARAwhsVGvHwpUDjgA";
const ISSUER: &str = "raa1x16A7hZRavaSTL8F8LQhFw7i3cUa4A";
const REGULAR: &str = "rGuN53T7cUp6Ec5L2tX9H7oJ7vQzVy6Cvq";
const RLUSD: &str = "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De";
const CHECK: &str = "49647F0D748DC3FE26BDACBC57F251AADEFFF391403EC9BF87C97F67E9977FB0";
const INVOICE: &str = "6F1DFD1D0FE8A32E40E1F2C05CF1C15545BAB56B617F9C6C2D63A6B704BEF59B";
const CONDITION: &str = "A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100";
const FEE: &str = "Sequence 7; good until ledger 107373103.";
const UNKNOWN: &str = "Anyone can issue a token by any name: check it's from the issuer you mean.";
const TAG: &str = "The recipient's tag for it: an exchange's tells them whose deposit it is. Check it's the one you were given.";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02X}")).collect() }

fn fixtures() -> serde_json::Value {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transactions.json"))
            .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// A transaction xrpl.js made, unsigned (or one it encoded that maki refuses).
fn fixture(name: &str) -> Vec<u8> {
    let json = fixtures();
    let all = json["transactions"].as_array().unwrap().iter().chain(json["refused"].as_array().unwrap());
    let found = all.clone().find(|t| t["name"] == name).unwrap_or_else(|| panic!("no fixture {name}"));
    unhex(found["transaction"].as_str().unwrap())
}

fn key() -> [u8; 33] { unhex(KEY).try_into().unwrap() }

fn shown_on(name: &str, network: Network) -> Review {
    let tx = Transaction::parse(&fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    review(&tx, &key(), network).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn shown(name: &str) -> Review { shown_on(name, Network::Main) }

fn p(heading: &str, value: &str, mono: &str, prose: &str) -> Page {
    Page { heading: heading.into(), value: value.into(), mono: mono.into(), prose: prose.into() }
}

fn fee_page(prose: &str) -> Page { p("Fee", "0.000012 XRP", "", prose) }

fn usd_page() -> Page { p("Token", "one maki doesn't know", &format!("USD\n{ISSUER}"), UNKNOWN) }

fn keys() -> SeedKeys {
    let words =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    SeedKeys::from_seed(&maki_seed::seed(&words.split(' ').collect::<Vec<_>>(), "")).unwrap()
}

/// Account `index`'s path: `m/44'/144'/index'/0/0`.
fn path(index: u32) -> Vec<u32> { maki_hd::parse_path(&format!("m/44'/144'/{index}'/0/0")).unwrap() }

#[test]
fn the_account_is_the_one_xrpl_js_and_ledger_make() {
    let keys = keys();
    let public = keys.public(&path(0)).unwrap().key;
    assert_eq!(public, key());
    assert_eq!(address::address(&public), ME);
    // the second account, a level up, as Ledger Live and Xaman number them
    let second = keys.public(&path(1)).unwrap().key;
    assert_eq!(address::address(&second), fixtures()["accounts"]["second"].as_str().unwrap());
    // a classic address read back, and only as the ledger writes one
    let me = address::account_id(&key());
    assert_eq!(address::decode(ME), Some(me));
    assert_eq!(address::encode(&me), ME);
    assert_eq!(address::decode("rrrrrrrrrrrrrrrrrrrrrhoLvTp"), Some([0; 20]));
    for not in [
        "",
        "r",
        // a character changed: the checksum's wrong
        "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v4",
        // Bitcoin's alphabet, not the ledger's
        "1HsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3",
        // an X-address: the account with a tag in it
        "X7AcgcsBL6XDcUb289X4mJ8djcdyKaB5hJDWMArnXr61cqZ",
        // a zero byte more in front
        "rrHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3",
        // an address's family seed (the secret), not an address
        "snoPBrXtMeMyMHUVTgbuqAfg1SUTb",
    ] {
        assert_eq!(address::decode(not), None, "{not}");
    }
    // the tokens maki knows are at their issuers' addresses, checksums and all
    let issuers: Vec<String> = tokens::TOKENS.iter().map(|t| address::encode(&t.issuer)).collect();
    assert_eq!(
        issuers,
        [
            RLUSD,
            "rGm7WCVp9gb4jZHWTEtGUr4dd74z2XuWhE",
            "rQhWct2fv4Vc4KRjRgMrxa8xPN9Zx9iLKV",
            "rHuGNhqTG32mfmAvWA8hUyWRLV3tCSwKQt"
        ]
    );
    assert_eq!(hex(&tokens::TOKENS[0].currency), "524C555344000000000000000000000000000000");
    assert_eq!(hex(&tokens::TOKENS[1].currency), "5553444300000000000000000000000000000000");
}

#[test]
fn amounts_codes_and_times() {
    assert_eq!(decimals(0, 6), "0");
    assert_eq!(decimals(1, 6), "0.000001");
    assert_eq!(decimals(1_500_000, 6), "1.5");
    assert_eq!(xrp(12), "0.000012 XRP");
    assert_eq!(xrp(codec::MAX_DROPS), "100000000000 XRP");
    let d = |mantissa, exponent| value(&Decimal { mantissa, exponent });
    assert_eq!(d(2_575_000_000_000_000, -14), "25.75");
    assert_eq!(d(1_000_000_000_000_000, -15), "1");
    assert_eq!(d(0, 0), "0");
    // the least and the most a token's amount can be, exactly
    assert_eq!(d(1_000_000_000_000_000, -96), format!("0.{}1", "0".repeat(80)));
    assert_eq!(d(9_999_999_999_999_999, 80), format!("{}{}", "9".repeat(16), "0".repeat(80)));
    assert_eq!(d(1_234_567_890_123_456, -96).len(), 98);
    let c = |text: &str| {
        let mut c = [0u8; 20];
        c.copy_from_slice(&unhex(text));
        code(&c)
    };
    assert_eq!(c("0000000000000000000000005553440000000000"), Code::Standard("USD".into()));
    assert_eq!(c("524C555344000000000000000000000000000000"), Code::Text("RLUSD".into()));
    // XRP's own code, as a token's, is no code: the ledger refuses it
    assert_eq!(
        c("0000000000000000000000005852500000000000"),
        Code::Hex("0000000000000000000000005852500000000000".into())
    );
    // a code of interest-bearing days, and text with a space in it
    assert_eq!(
        c("0158415500000000C1F76FF6ECB0BAC600000000"),
        Code::Hex("0158415500000000C1F76FF6ECB0BAC600000000".into())
    );
    assert_eq!(
        c("5553442055534400000000000000000000000000"),
        Code::Hex("5553442055534400000000000000000000000000".into())
    );
    // the ledger's times, as xrpl.js's rippleTimeToISOTime has them
    assert_eq!(utc(0), "2000-01-01 00:00:00 UTC");
    assert_eq!(utc(812_345_678), "2025-09-28 03:34:38 UTC");
    assert_eq!(utc(u32::MAX), "2136-02-07 06:28:15 UTC");
}

#[test]
fn maki_signs_what_xrpl_js_signs() {
    let keys = keys();
    let json = fixtures();
    let mut signed = 0;
    for t in json["transactions"].as_array().unwrap() {
        let name = t["name"].as_str().unwrap();
        let bytes = unhex(t["transaction"].as_str().unwrap());
        let Some(signature) = t["signature"].as_str().map(unhex) else { continue };
        let tx = Transaction::parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(tx.key, key(), "{name}");
        // what's signed: "STX\0" and the transaction, SHA-512's first half, signed as maki signs
        let (rs, _) = keys.sign_ecdsa(&path(0), &sign::digest(&bytes)).unwrap();
        let der = sign::der(&rs);
        assert_eq!(hex(&der), hex(&signature), "{name}");
        // put in where xrpl.js puts it, and the transaction's hash
        let blob = sign::with_signature(&bytes, &der).unwrap();
        assert_eq!(hex(&blob), t["signed"].as_str().unwrap(), "{name}");
        assert_eq!(hex(&sign::id(&blob)), t["hash"].as_str().unwrap(), "{name}");
        // and one maki shows (another network's, it refuses: below)
        if name != "other-network" {
            assert!(review(&tx, &key(), Network::Main).is_ok(), "{name}");
        }
        signed += 1;
    }
    assert_eq!(signed, 35);
    // a signed transaction has its signature: another doesn't go in
    let blob = sign::with_signature(&fixture("xrp"), &[0x30, 0]).unwrap();
    assert_eq!(sign::with_signature(&blob, &[0x30, 0]), Err(sign::Error::Unsigned));
}

#[test]
fn xrp_sent_with_its_tag_and_memos() {
    let r = shown("xrp");
    assert_eq!(r.pages, [p("Send", "1.5 XRP", RECIPIENT, ""), fee_page(FEE)]);
    assert_eq!(r.summary, "sends 1.5 XRP; fee 0.000012 XRP");
    let r = shown("xrp-tag-memo");
    assert_eq!(
        r.pages,
        [
            p("Send", "12.5 XRP", RECIPIENT, ""),
            p("Destination tag", "4242", "", TAG),
            p("Invoice", "", INVOICE, "The recipient's ID for what it pays for."),
            p(
                "Memo 1",
                "",
                "thanks for the coffee",
                "Everyone can read it, on the ledger. Its type: text/plain."
            ),
            p("Memo 2", "in hex", "FF00", "Everyone can read it, on the ledger."),
            p("Source tag", "7", "", "This account's own tag for it."),
            fee_page(FEE)
        ]
    );
    assert_eq!(r.summary, "sends 12.5 XRP; fee 0.000012 XRP");
    // by ticket, and with no last ledger
    assert_eq!(shown("ticket").pages[1], fee_page("Ticket 12; good until ledger 107373103."));
    assert_eq!(
        shown("no-last-ledger").pages[1],
        fee_page("Sequence 7. No last ledger: it stays good until it's sent, or that number's used.")
    );
    // a fee no wallet would set, said loudly
    let r = shown("high-fee");
    assert_eq!(
        r.pages[1],
        p(
            "Fee!",
            "5 XRP",
            "",
            "Far more than the ledger asks: xrpl.js never sets more than 2 XRP. Burnt, not paid to anyone. Sequence 7; good until ledger 107373103."
        )
    );
    assert_eq!(r.summary, "sends 1 XRP, a fee over 2 XRP!; fee 5 XRP");
}

#[test]
fn tokens_sent_and_whose_they_are() {
    let r = shown("usd");
    assert_eq!(r.pages, [p("Send", "25.75 USD", RECIPIENT, ""), usd_page(), fee_page(FEE)]);
    assert_eq!(r.summary, "sends 25.75 USD; fee 0.000012 XRP");
    let r = shown("rlusd");
    assert_eq!(
        r.pages[..2],
        [p("Send", "100 RLUSD", RECIPIENT, ""), p("Token", "RLUSD", RLUSD, "Issued by Ripple.")]
    );
    // RLUSD bought with XRP on the way
    let r = shown("cross");
    assert_eq!(
        r.pages[..4],
        [
            p("Send", "10 RLUSD", RECIPIENT, ""),
            p("Token", "RLUSD", RLUSD, "Issued by Ripple."),
            p(
                "Costs at most",
                "25 XRP",
                "",
                "What this account may pay for it, at most, through the order books and trust lines on its way."
            ),
            p("Paths", "1 path", "", "Through others' offers and trust lines, on its way.")
        ]
    );
    assert_eq!(r.summary, "sends 10 RLUSD; fee 0.000012 XRP");
    // XRP into USD in this account
    let r = shown("convert");
    assert_eq!(
        r.pages[0],
        p(
            "Convert",
            "5 USD",
            "this account",
            "Into this account: a trade on the ledger's exchange, paid for as below."
        )
    );
    assert_eq!(r.summary, "converts to 5 USD; fee 0.000012 XRP");
    // only at the rate asked, along the one path there is without paths
    let r = shown("limit-quality");
    assert_eq!(
        r.pages[3],
        p(
            "Paths",
            "the direct one",
            "",
            "Only at a rate as good as the most it costs for what it sends, or better."
        )
    );
    // a token whose own code spells XRP, which isn't XRP
    let r = shown("fake-xrp");
    assert_eq!(
        r.pages[..3],
        [
            p("Send", "1000 tokens called XRP", RECIPIENT, ""),
            p(
                "Not XRP!",
                "a token called XRP",
                &format!("5852500000000000000000000000000000000000\n{ISSUER}"),
                "XRP has no issuer: this is a token someone issued, and worth what they stand behind."
            ),
            p(
                "Token",
                "one maki doesn't know",
                &format!("XRP\n5852500000000000000000000000000000000000\n{ISSUER}"),
                UNKNOWN
            )
        ]
    );
    assert_eq!(r.summary, "sends 1000 tokens called XRP, which aren't XRP!; fee 0.000012 XRP");
    // a multi-purpose token: its units, and whose it is
    let r = shown("mpt");
    assert_eq!(
        r.pages[..2],
        [
            p("Send", "1000 units of an MPT", RECIPIENT, ""),
            p(
                "Token",
                "an MPT maki doesn't know",
                &format!("issuance 42\nby {ISSUER}"),
                "Its amount is in its smallest units: maki can't see its decimals, or its name."
            )
        ]
    );
}

#[test]
fn a_partial_payment_says_it_may_deliver_far_less() {
    let r = shown("partial");
    assert_eq!(
        r.pages,
        [
            p("Send", "100 USD", RECIPIENT, ""),
            usd_page(),
            p(
                "Partial payment!",
                "may deliver less",
                "",
                "100 USD is the most it delivers: the recipient may get as little as 1 USD."
            ),
            p(
                "Costs at most",
                "50 XRP",
                "",
                "What this account may pay for it, at most, through the order books and trust lines on its way."
            ),
            fee_page(FEE)
        ]
    );
    assert_eq!(r.summary, "sends 100 USD, may deliver far less!; fee 0.000012 XRP");
}

#[test]
fn trust_lines_and_offers() {
    let r = shown("trust-rlusd");
    assert_eq!(
        r.pages,
        [
            p(
                "Trust line",
                "up to 1000000 RLUSD",
                RLUSD,
                "This account takes RLUSD from this issuer, up to that much. While the line's open, some of its XRP is held in reserve."
            ),
            p("Token", "RLUSD", RLUSD, "Issued by Ripple."),
            p(
                "No rippling",
                "through this line",
                "",
                "Payments can't move between this line and this account's others."
            ),
            fee_page(FEE)
        ]
    );
    assert_eq!(r.summary, "trusts RLUSD; fee 0.000012 XRP");
    // a code of its own, the largest limit there is, a quality, and rippling let through
    let r = shown("trust-solo");
    assert_eq!(r.pages[0].value, format!("up to {}{} SOLO", "9".repeat(16), "0".repeat(80)));
    assert_eq!(r.pages[0].value.len(), 107);
    assert_eq!(
        r.pages[1..4],
        [
            p(
                "Token",
                "one maki doesn't know",
                &format!("SOLO\n534F4C4F00000000000000000000000000000000\n{ISSUER}"),
                UNKNOWN
            ),
            p(
                "Quality",
                "1.01 coming in",
                "",
                "What this account counts a unit of SOLO coming in through this line as."
            ),
            p(
                "Rippling!",
                "through this line",
                "",
                "Payments may move through it: what this account holds of SOLO can shift to other lines of the same code, other issuers'."
            )
        ]
    );
    assert_eq!(r.summary, "trusts SOLO, lets payments ripple through it!; fee 0.000012 XRP");
    let r = shown("trust-remove");
    assert_eq!(
        r.pages[0],
        p(
            "Trust line",
            "limit 0",
            ISSUER,
            "This account takes no more USD from this issuer: once it holds none, the line closes and its reserve comes back."
        )
    );
    assert_eq!(r.summary, "closes its USD line; fee 0.000012 XRP");
    let r = shown("offer");
    assert_eq!(
        r.pages,
        [
            p(
                "Offers",
                "100 XRP",
                "",
                "On the ledger's exchange, until it's taken, cancelled or expires: whoever takes it gets this from this account. It sells all of it, even for more than it asks."
            ),
            p("For", "250 USD", "", "What this account gets for it, at that rate or better."),
            usd_page(),
            p("Expires", "2025-09-28 18:40:00 UTC", "", "It's gone then, whatever's left of it."),
            p("Replaces", "offer #5", "", "It cancels this account's offer with that sequence number first."),
            fee_page(FEE)
        ]
    );
    assert_eq!(r.summary, "offers 100 XRP for 250 USD; fee 0.000012 XRP");
    let r = shown("offer-cancel");
    assert_eq!(
        r.pages[0],
        p("Cancel offer", "#5", "", "This account's offer with that sequence number, if it's still there.")
    );
    assert_eq!(r.summary, "cancels offer #5; fee 0.000012 XRP");
}

#[test]
fn what_hands_the_account_over_or_empties_it_says_so() {
    let r = shown("regular-key");
    assert_eq!(
        r.pages[0],
        p(
            "Hands over!",
            "a key to this account",
            REGULAR,
            "That address's key can sign for this account, as its own key can, until it's taken away."
        )
    );
    assert_eq!(r.summary, "lets another key sign for it!; fee 0.000012 XRP");
    let r = shown("regular-key-off");
    assert_eq!(
        r.pages[0],
        p(
            "Regular key",
            "taken away",
            "",
            "Only this account's own key, or its signer list, can sign for it then."
        )
    );
    assert_eq!(r.summary, "takes its regular key away; fee 0.000012 XRP");
    let signers: Vec<String> = fixtures()["accounts"]["signers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().into())
        .collect();
    let r = shown("signers");
    assert_eq!(
        r.pages[0],
        p(
            "Hands over!",
            "to 3 signers",
            &format!("{}, weight 2\n{}, weight 1\n{}, weight 1", signers[0], signers[1], signers[2]),
            "Signers whose weights add up to 3 can sign for this account together, as its own key can, until the list is taken away."
        )
    );
    assert_eq!(r.summary, "lets 3 other keys sign for it!; fee 0.000012 XRP");
    let r = shown("signers-off");
    assert_eq!(
        r.pages[0],
        p("Signer list", "taken away", "", "No other accounts can sign for this one together then.")
    );
    assert_eq!(r.summary, "takes its signer list away; fee 0.000012 XRP");
    let r = shown("disable-master");
    assert_eq!(
        r.pages[0],
        p(
            "Turns off its key!",
            "this account's own key",
            "",
            "From then on only its regular key or its signer list can sign for it: lose those, and the account is lost."
        )
    );
    assert_eq!(r.summary, "turns off this account's own key!; fee 0.000012 XRP");
    let r = shown("minter");
    assert_eq!(
        r.pages[0],
        p(
            "NFT minter!",
            "may mint as this account",
            REGULAR,
            "That account may mint NFTs this account issues, until it's taken away."
        )
    );
    assert_eq!(r.summary, "lets another mint its NFTs!; fee 0.000012 XRP");
    let r = shown("delete");
    assert_eq!(
        r.pages,
        [
            p(
                "Deletes it!",
                "this account",
                RECIPIENT,
                "All its XRP goes to this address, less the fee, and the account is gone from the ledger."
            ),
            p("Destination tag", "99", "", TAG),
            p("Fee", "0.2 XRP", "", FEE)
        ]
    );
    assert_eq!(r.summary, format!("deletes this account, all its XRP to {RECIPIENT}!; fee 0.2 XRP"));
    // the account's settings: a tag on payments to it, a transfer fee, a tick size, its domain
    let r = shown("account-set");
    assert_eq!(
        r.pages,
        [
            p("Sets", "destination tags", "", "Payments to this account will need a destination tag."),
            p(
                "Transfer fee",
                "0.2%",
                "",
                "What this account keeps, of the tokens it issues, when others pay each other in them."
            ),
            p("Tick size", "5 digits", "", "How finely offers in the tokens it issues are priced."),
            p("Domain", "", "example.com", "Where this account says it's from: anyone can read it."),
            fee_page(FEE)
        ]
    );
    assert_eq!(r.summary, "changes the account's settings; fee 0.000012 XRP");
}

#[test]
fn checks_and_escrows() {
    let r = shown("check");
    assert_eq!(
        r.pages,
        [
            p(
                "Check",
                "up to 50 USD",
                RECIPIENT,
                "They may cash it for up to that, from this account, until it expires or is cancelled."
            ),
            usd_page(),
            p("Expires", "2025-09-28 18:40:00 UTC", "", "It can't be cashed after then."),
            p("Invoice", "", INVOICE, "The recipient's ID for what it pays for."),
            fee_page(FEE)
        ]
    );
    assert_eq!(r.summary, "writes a check for up to 50 USD; fee 0.000012 XRP");
    let r = shown("check-cash");
    assert_eq!(
        r.pages[0],
        p("Cash check", "at least 95 XRP", CHECK, "From the account that wrote it, into this one.")
    );
    assert_eq!(r.summary, "cashes a check for at least 95 XRP; fee 0.000012 XRP");
    let r = shown("check-cancel");
    assert_eq!(r.pages[0], p("Cancel check", "", CHECK, "The check is gone: it can't be cashed."));
    let r = shown("escrow");
    assert_eq!(
        r.pages,
        [
            p(
                "Escrow",
                "50 XRP",
                RECIPIENT,
                "Held by the ledger, out of this account, until it's released to them or cancelled back."
            ),
            p("Destination tag", "23", "", TAG),
            p("Release after", "2025-09-28 03:34:38 UTC", "", "It can't be released to them before then."),
            p(
                "Condition",
                "",
                CONDITION,
                "It's released only with the fulfilment that matches: whoever has it can release it."
            ),
            p(
                "Cancel after",
                "2025-09-28 18:40:00 UTC",
                "",
                "If it isn't released by then, it can be cancelled, back to this account."
            ),
            fee_page(FEE)
        ]
    );
    assert_eq!(r.summary, "escrows 50 XRP; fee 0.000012 XRP");
    let r = shown("escrow-finish");
    assert_eq!(
        r.pages[..2],
        [
            p(
                "Release escrow",
                "#5",
                ISSUER,
                "Pays out that account's escrow, made with that sequence number, to its destination."
            ),
            p(
                "Fulfilment",
                "",
                &format!("A0028000\nfor condition\n{CONDITION}"),
                "The escrow's secret, which releases it: anyone can read it, once it's sent."
            )
        ]
    );
    let r = shown("escrow-cancel");
    assert_eq!(
        r.pages[0],
        p(
            "Cancel escrow",
            "#5",
            "this account",
            "Returns that account's escrow, made with that sequence number, to it, once its time to cancel has come."
        )
    );
}

#[test]
fn what_maki_cant_read_is_flagged() {
    let r = shown("nft-mint");
    assert_eq!(
        r.pages,
        [
            p(
                "Transaction",
                "maki can't read it",
                "NFTokenMint\nTransferFee\nFlags\nNFTokenTaxon\nURI",
                "maki can't say what it does. Signed, it can do anything this account can."
            ),
            fee_page(FEE)
        ]
    );
    assert_eq!(r.summary, "NFTokenMint, which maki can't read; fee 0.000012 XRP");
    // a field every transaction may carry, which maki can't say the use of
    let r = shown("unread-field");
    assert_eq!(
        r.pages[1],
        p("Not read", "maki can't read these", "OperationLimit", "maki can't say what they do.")
    );
    assert_eq!(r.summary, "sends 1 XRP; maki can't read all of it; fee 0.000012 XRP");
}

#[test]
fn the_test_network_says_the_transaction_is_good_on_the_main_one_too() {
    let r = shown_on("xrp", Network::Test);
    assert_eq!(
        r.pages[0],
        p(
            "Network",
            "xrp testnet",
            "",
            "So the computer says. An XRP Ledger transaction doesn't name its network: signed, it's good on the main network too, while this account there is at sequence 7, until ledger 107373103."
        )
    );
    assert_eq!(r.pages[1..], shown("xrp").pages);
    assert_eq!(r.summary, "testnet: sends 1.5 XRP; fee 0.000012 XRP");
    let r = shown_on("ticket", Network::Test);
    assert!(r.pages[0].prose.ends_with("while this account there holds ticket 12, until ledger 107373103."));
}

#[test]
fn what_isnt_this_accounts_to_sign_is_refused() {
    let refused =
        |name: &str| review(&Transaction::parse(&fixture(name)).unwrap(), &key(), Network::Main).unwrap_err();
    assert_eq!(
        refused("not-mine"),
        Error::NotMine(fixtures()["accounts"]["stranger"].as_str().unwrap().into())
    );
    assert_eq!(
        refused("not-mine").to_string(),
        "not this account's: it's rLpgximdBvEHy8TxUwyj6mjCRNcJju5qGG's"
    );
    assert_eq!(refused("other-network"), Error::Network(21337));
    assert_eq!(
        refused("other-network").to_string(),
        "for another network (network 21337): maki signs for the XRP Ledger and its test network"
    );
    assert_eq!(refused("another-key"), Error::Key);
    assert_eq!(refused("delegate"), Error::Delegate);
    assert_eq!(Transaction::parse(&fixture("multisig")), Err(tx::Error::Multisigned));
    // another account's key, signing for this one: not this account's key
    let tx = Transaction::parse(&fixture("xrp")).unwrap();
    let other: [u8; 33] = keys().public(&path(1)).unwrap().key;
    assert_eq!(review(&tx, &other, Network::Main), Err(Error::NotMine(ME.into())));
}

#[test]
fn what_the_ledger_would_refuse_maki_refuses_saying_why() {
    let why = |name: &str| match Transaction::parse(&fixture(name)) {
        Err(e) => e.to_string(),
        Ok(tx) => match review(&tx, &key(), Network::Main) {
            Err(e) => e.to_string(),
            Ok(r) => panic!("{name} shown: {}", r.summary),
        },
    };
    let ledger = |what: &str| format!("{what}: the XRP Ledger would refuse it");
    for (name, said) in [
        ("xrp-to-self", ledger("a payment to itself, in what it pays with")),
        ("xrp-partial", ledger("XRP sent as XRP, as a partial payment")),
        ("xrp-send-max", ledger("XRP sent as XRP, with a most it costs")),
        ("xrp-paths", ledger("XRP sent as XRP, through paths")),
        ("nothing", ledger("a payment of nothing")),
        ("xrp-code", ledger("a token with XRP's own code")),
        ("sponsor-flag", ledger("a flag this transaction can't have")),
        ("deliver-min-whole", ledger("a least to deliver, in a payment that isn't partial")),
        ("deliver-min-more", ledger("a least to deliver over what it sends")),
        ("deliver-min-other", ledger("a least to deliver of nothing, or of another token")),
        ("no-direct-no-paths", ledger("no paths, and not straight there either")),
        ("seven-paths", String::from("more paths than the XRP Ledger takes: 6, of 8 steps")),
        ("mpt-paths", ledger("an MPT sent through paths")),
        ("mpt-for-xrp", ledger("an MPT paid for with something else")),
        ("trust-xrp", ledger("a trust line for something other than a token")),
        ("trust-self", ledger("a trust line to itself")),
        ("trust-freeze-thaw", ledger("a setting turned both on and off")),
        ("offer-xrp-for-xrp", ledger("an offer of a thing for itself")),
        ("offer-ioc-fok", ledger("an offer both immediate-or-cancel and fill-or-kill")),
        ("offer-expiration-0", ledger("an expiration of 0")),
        ("offer-mpt", String::from("an offer of an MPT: the XRP Ledger takes none yet")),
        ("cancel-offer-0", ledger("an offer to cancel numbered 0")),
        ("set-and-clear", ledger("a setting both set and cleared")),
        ("auth-both-ways", ledger("a setting both set and cleared")),
        ("transfer-rate", ledger("a transfer fee over 100%, or a rate under 1")),
        ("tick-size", ledger("a tick size that isn't 3 to 15")),
        ("message-key", ledger("a message key that isn't a key")),
        ("long-domain", ledger("a domain longer than 256 bytes")),
        ("minter-missing", ledger("an NFT minter without its setting, or cleared with one")),
        ("regular-key-self", ledger("its own key as its regular key")),
        ("signers-short", ledger("a quorum its signers can't reach")),
        ("signers-self", ledger("a signer list with this account in it")),
        ("signers-twice", ledger("a signer twice")),
        ("signers-weightless", ledger("a signer of no weight")),
        ("signers-33", ledger("a signer list without 1 to 32 signers")),
        ("signers-quorum-0", ledger("a signer list without its quorum, or a quorum without its list")),
        ("signers-none", ledger("a signer list without its quorum, or a quorum without its list")),
        ("delete-into-itself", ledger("an account deleted into itself")),
        ("check-to-itself", ledger("a check to itself")),
        ("check-for-nothing", ledger("a check for nothing")),
        ("cash-both", ledger("a check cashed for an amount and a least, or neither")),
        ("escrow-timeless", ledger("an escrow without a time")),
        ("escrow-backwards", ledger("an escrow cancelled before it can be released")),
        ("escrow-open", ledger("an escrow released at once, with no time or condition")),
        (
            "escrow-condition",
            String::from("an escrow's condition the XRP Ledger can't read: it would refuse it"),
        ),
        ("finish-half", ledger("a condition without its fulfilment, or one without the other")),
        ("memo-big", String::from("memos over a kilobyte: the XRP Ledger would refuse them")),
        ("memo-type", ledger("a memo's type or format not in a URL's characters")),
        ("delegate", String::from("for a delegate to sign, not this account")),
        ("another-key", String::from("for another key than this account's to sign")),
        (
            "ed25519-key",
            String::from("for a key that isn't a compressed secp256k1 key to sign: this account's is"),
        ),
        (
            "signed",
            String::from("signed already (TxnSignature): maki takes a transaction without its signatures"),
        ),
        (
            "signers-in-it",
            String::from("signed already (Signers): maki takes a transaction without its signatures"),
        ),
        ("batch-inner", String::from("part of a batch: it's signed with its batch, never alone")),
        ("sequence-and-ticket", ledger("both a sequence number and a ticket")),
        ("ticket-and-previous", ledger("a ticket and AccountTxnID together")),
        ("fee-in-tokens", ledger("a fee that isn't XRP")),
        ("not-a-payment-field", ledger("a Payment with LimitAmount, which it doesn't have")),
        ("no-destination", ledger("a Payment without its Destination")),
        ("no-account", ledger("from no account")),
        (
            "pseudo",
            String::from("a pseudo-transaction (EnableAmendment): only the ledger's validators make those"),
        ),
    ] {
        assert_eq!(why(name), said, "{name}");
    }
    // and every one xrpl.js encoded is among them
    assert_eq!(fixtures()["refused"].as_array().unwrap().len(), 61);
}

/// `bytes` with the field `f` (its header and value) put in place of the one there, or added
/// where the ledger's order puts it.
fn with_field(bytes: &[u8], f: Field, field: &[u8]) -> Vec<u8> {
    let (_, spans) = codec::read_spans(bytes).unwrap();
    let (start, end) = match spans.iter().find(|s| s.0 == f) {
        Some(&(_, start, end)) => (start, end),
        None => {
            let at = spans.iter().filter(|s| s.0 < f).map(|s| s.2).max().unwrap_or(0);
            (at, at)
        }
    };
    [&bytes[..start], field, &bytes[end..]].concat()
}

#[test]
fn bytes_the_ledger_would_read_otherwise_are_refused() {
    use codec::Error::*;
    let good = fixture("xrp");
    assert!(Transaction::parse(&good).is_ok());
    let codec_error = |bytes: &[u8]| match Transaction::parse(bytes) {
        Err(tx::Error::Codec(e)) => e,
        other => panic!("{other:?}"),
    };
    // cut short, or more after it: a stray byte, an end marker
    assert_eq!(codec_error(&good[..good.len() - 1]), Short);
    assert_eq!(codec_error(&[&good[..], &[0x00]].concat()), Short);
    assert_eq!(codec_error(&[&good[..], &[0xe1]].concat()), Marker);
    assert_eq!(codec_error(&[&good[..], &[0xf1]].concat()), Marker);
    // a field written longer than it is (Flags, type 2 field 2, in three bytes)
    let flags = with_field(&good, fields::FLAGS, &[0x00, 0x02, 0x02, 0, 0, 0, 0]);
    assert_eq!(codec_error(&flags), Header);
    // a field out of order, a field twice, one the ledger doesn't have
    let (_, spans) = codec::read_spans(&good).unwrap();
    let fee = spans.iter().find(|s| s.0 == fields::FEE).unwrap();
    let moved = [&good[fee.1..fee.2], &good[..fee.1], &good[fee.2..]].concat();
    assert_eq!(codec_error(&moved), Order(fields::TRANSACTION_TYPE));
    let dest = spans.iter().find(|s| s.0 == fields::DESTINATION).unwrap();
    assert_eq!(codec_error(&[&good[..], &good[dest.1..dest.2]].concat()), Twice(fields::DESTINATION));
    assert_eq!(codec_error(&[&good[..], &[0x20, 0xfe, 0, 0, 0, 0]].concat()), Unknown(Field(0x02fe)));
    // a length the format doesn't have; an account of 19 bytes
    let key = with_field(&good, fields::SIGNING_PUB_KEY, &[0x73, 0xff]);
    assert_eq!(codec_error(&key), Length);
    let short = [&[0x83, 0x13][..], &[7; 19]].concat();
    assert_eq!(codec_error(&with_field(&good, fields::DESTINATION, &short)), Account);
    // amounts: negative, too much XRP, a token's written another way
    let amount = |bytes: &[u8]| with_field(&good, fields::AMOUNT, &[&[0x61][..], bytes].concat());
    assert_eq!(codec_error(&amount(&[0, 0, 0, 0, 0, 0x16, 0xe3, 0x60])), Amount("a negative amount"));
    assert_eq!(codec_error(&amount(&[0, 0, 0, 0, 0, 0, 0, 0])), Amount("a negative amount"));
    let over = (codec::MAX_DROPS + 1) | 1 << 62;
    assert_eq!(codec_error(&amount(&over.to_be_bytes())), Amount("more XRP than there is"));
    let usd = fixture("usd");
    let (_, spans) = codec::read_spans(&usd).unwrap();
    let a = spans.iter().find(|s| s.0 == fields::AMOUNT).unwrap();
    let token = |first: [u8; 8], currency: &[u8], issuer: &[u8]| {
        with_field(&usd, fields::AMOUNT, &[&[0x61][..], &first, currency, issuer].concat())
    };
    let (currency, issuer) = (&usd[a.1 + 9..a.1 + 29], &usd[a.1 + 29..a.2]);
    let first: [u8; 8] = usd[a.1 + 1..a.1 + 9].try_into().unwrap();
    assert!(Transaction::parse(&token(first, currency, issuer)).is_ok());
    // 15 digits, not 16
    let v = u64::from_be_bytes(first);
    let shrunk = (v & !((1u64 << 54) - 1)) | 100_000_000_000_000;
    assert_eq!(
        codec_error(&token(shrunk.to_be_bytes(), currency, issuer)),
        Amount("a token amount the ledger can't hold")
    );
    assert_eq!(
        codec_error(&token((v & !(1 << 62)).to_be_bytes(), currency, issuer)),
        Amount("a negative amount")
    );
    assert_eq!(codec_error(&token(first, &[0; 20], issuer)), Amount("a token amount in XRP's own code"));
    assert_eq!(codec_error(&token(first, currency, &[0; 20])), Amount("a token amount with no issuer"));
    assert_eq!(
        codec_error(&token([0xc0, 0, 0, 0, 0, 0, 0, 0], currency, issuer)),
        Amount("a token amount of zero, written oddly")
    );
    // an MPT's, with a flag the ledger wouldn't write back
    let mpt = fixture("mpt");
    let (_, spans) = codec::read_spans(&mpt).unwrap();
    let a = spans.iter().find(|s| s.0 == fields::AMOUNT).unwrap();
    let mut odd = mpt[a.1..a.2].to_vec();
    odd[1] = 0x61;
    assert_eq!(codec_error(&with_field(&mpt, fields::AMOUNT, &odd)), Amount("a token amount written oddly"));
    // paths: an empty one; a step of a kind there isn't
    let cross = fixture("cross");
    assert_eq!(codec_error(&with_field(&cross, fields::PATHS, &[0x01, 0x12, 0x00])), Paths("an empty path"));
    assert_eq!(
        codec_error(&with_field(&cross, fields::PATHS, &[0x01, 0x12, 0x02, 0x00])),
        Paths("a path's step of a kind the ledger doesn't know")
    );
    // a list of hashes that isn't whole hashes (credentials, 33 bytes)
    let ids = [&[0x05, 0x13, 33][..], &[1; 33]].concat();
    assert_eq!(codec_error(&with_field(&good, fields::CREDENTIAL_IDS, &ids)), Hashes);
    // an array of something other than objects; an object without its end; too deep
    let memos =
        [0xf9, 0x81, 0x14].iter().chain([7; 20].iter()).chain([0xf1].iter()).copied().collect::<Vec<u8>>();
    assert_eq!(codec_error(&with_field(&good, fields::MEMOS, &memos)), Array);
    assert_eq!(codec_error(&with_field(&good, fields::MEMOS, &[0xf9, 0xea, 0x7d, 0x01, 0x61])), Short);
    let deep: Vec<u8> = [0xf9].into_iter().chain([0xea; 11]).chain([0xe1; 11]).chain([0xf1]).collect();
    assert_eq!(codec_error(&with_field(&good, fields::MEMOS, &deep)), Depth);
    // a type the ledger doesn't have, too short, too long
    let mut kind = good.clone();
    kind[2] = 99;
    assert_eq!(Transaction::parse(&kind), Err(tx::Error::Type(99)));
    assert_eq!(Transaction::parse(&good[..20]), Err(tx::Error::TooShort));
    let big = [&good[..], &[0x7d], &codec::length(4096), &[0x61; 4096]].concat();
    assert_eq!(Transaction::parse(&big), Err(tx::Error::TooBig));
}

/// Whether a review fits maki's review screen, as its host takes one (maki-wasm's
/// `parse_review`): a summary of 128 bytes, up to 128 pages, a heading of 32 bytes and a value
/// of 128 (one line each), fixed-width text and prose of 4 KiB (lines, but no other control
/// characters), 16 KiB in all.
fn fits(r: &Review) -> Result<(), String> {
    let plain = |t: &str| !t.chars().any(|c| c.is_control());
    let lines = |t: &str| !t.chars().any(|c| c.is_control() && c != '\n');
    if r.summary.len() > display::MAX_SUMMARY || !plain(&r.summary) || r.pages.len() > 128 {
        return Err(format!("summary or pages: {}", r.summary));
    }
    let mut total = r.summary.len() + 32;
    for page in &r.pages {
        let ok = !page.heading.trim().is_empty()
            && page.heading.len() <= 32
            && page.value.len() <= 128
            && page.mono.len() <= 4096
            && page.prose.len() <= 4096
            && plain(&page.heading)
            && plain(&page.value)
            && lines(&page.mono)
            && lines(&page.prose);
        if !ok {
            return Err(format!("{page:?}"));
        }
        total += 4 + page.heading.len() + page.value.len() + page.mono.len() + page.prose.len();
    }
    if total > 16 * 1024 { Err(format!("{total} bytes")) } else { Ok(()) }
}

#[test]
fn every_review_fits_makis_screen() {
    // the largest token amount there is, of a code of its own, fits its line
    assert_eq!(shown("trust-solo").pages[0].value.len(), 107);
    for t in fixtures()["transactions"].as_array().unwrap() {
        let name = t["name"].as_str().unwrap();
        let Ok(tx) = Transaction::parse(&unhex(t["transaction"].as_str().unwrap())) else { continue };
        for network in [Network::Main, Network::Test] {
            let Ok(r) = review(&tx, &key(), network) else { continue };
            fits(&r).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(r.summary.starts_with("testnet: "), network == Network::Test, "{name}");
        }
    }
}

#[test]
fn the_table_is_the_codecs() {
    use maki_xrp::definitions::{FIELDS, TRANSACTION_TYPES};
    // in order, once each, as the ledger numbers them
    assert!(FIELDS.windows(2).all(|w| w[0].0 < w[1].0));
    // every field the codec serializes, its two end markers among them
    assert_eq!(FIELDS.len(), 351);
    assert_eq!(
        (fields::OBJECT_END.name(), fields::ARRAY_END.name()),
        (Some("ObjectEndMarker"), Some("ArrayEndMarker"))
    );
    for (f, name) in [
        (fields::ACCOUNT, "Account"),
        (fields::DESTINATION, "Destination"),
        (fields::AMOUNT, "Amount"),
        (fields::FEE, "Fee"),
        (fields::SIGNING_PUB_KEY, "SigningPubKey"),
        (fields::TXN_SIGNATURE, "TxnSignature"),
        (fields::MEMOS, "Memos"),
        (fields::MEMO, "Memo"),
        (fields::PATHS, "Paths"),
        (fields::CREDENTIAL_IDS, "CredentialIDs"),
        (fields::DOMAIN_ID, "DomainID"),
        (fields::TICK_SIZE, "TickSize"),
    ] {
        assert_eq!(f.name(), Some(name));
    }
    // what a signature covers: all but signatures
    assert!(fields::SIGNING_PUB_KEY.signed() && !fields::TXN_SIGNATURE.signed() && !fields::SIGNERS.signed());
    assert_eq!(tx::type_name(0), Some("Payment"));
    assert_eq!(tx::type_name(21), Some("AccountDelete"));
    assert!(TRANSACTION_TYPES.iter().all(|t| t.1.len() <= 33));
}
