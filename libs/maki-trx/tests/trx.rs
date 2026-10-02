//! maki-trx against Tron's own library: transactions TronWeb made (`fixtures/make.mjs`), read as
//! they are and shown as they should be, and signed by maki's keys as TronWeb signs them with the
//! same account (the test phrase's first, as TronLink and Ledger's Tron app have it). And what
//! Tron would refuse, written by hand, refused.

use maki_hd::Keys;
use maki_hd::seed::SeedKeys;
use maki_trx::display::{self, Error, Page, Review, review};
use maki_trx::tx::{self, Contract, Resource, Transaction};
use maki_trx::{Address, Network, address, address_of, base58, parse_address, path, signature, tokens, txid};

const ME: &str = "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH";
const RECIPIENT: &str = "TCNkawTmcQgYSU8nP8cHswT1QPjharxJr7";
const SPENDER: &str = "THHsfg2eNiv6MSXC4y5d4t5wkvRVADRKiF";
const RECEIVER: &str = "TEdea7WvtoCNceWPwaz7JbkBjbb6omTQcL";
const CONTRACT: &str = "TUzD1rsJtHzx5zQzzLgzmmaKUDzcDAU6KD";
const WITNESSES: [&str; 2] = ["TB8JBJdVX7FSU9WsGPyvQ1i6gGWAhut65r", "TGkWdpawVNfeset3P6uTBbLaPY7nZVZvXY"];
const USDT: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
const NILE_USDT: &str = "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf";
/// When block 86746173, which the fixtures name, was made: 2026-10-02 03:18:51 UTC.
const MADE: u64 = 1_790_911_131_000;

fn me() -> Address { parse_address(ME).unwrap() }

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

struct Fixture {
    name: String,
    raw: Vec<u8>,
    txid: Vec<u8>,
    /// TronWeb's signature for this account, if it's this account's
    signature: Option<Vec<u8>>,
}

/// The transactions TronWeb made.
fn fixtures() -> Vec<Fixture> {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transactions.json"))
            .unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    json.as_array()
        .unwrap()
        .iter()
        .map(|f| Fixture {
            name: f["name"].as_str().unwrap().into(),
            raw: unhex(f["raw"].as_str().unwrap()),
            txid: unhex(f["txid"].as_str().unwrap()),
            signature: f["signature"].as_str().map(unhex),
        })
        .collect()
}

fn fixture(name: &str) -> Vec<u8> { fixtures().into_iter().find(|f| f.name == name).unwrap().raw }

fn parsed(name: &str) -> Transaction { Transaction::parse(&fixture(name)).unwrap() }

fn shown_on(name: &str, network: Network) -> Review { review(&parsed(name), &me(), network, None).unwrap() }

fn shown(name: &str) -> Review { shown_on(name, Network::Tron) }

fn p(heading: &str, value: &str, mono: &str, prose: &str) -> Page {
    Page { heading: heading.into(), value: value.into(), mono: mono.into(), prose: prose.into() }
}

fn network() -> Page { p("Network", "Tron", "", "") }

fn keys() -> SeedKeys {
    let seed = maki_seed::seed(
        &"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' ')
            .collect::<Vec<_>>(),
        "",
    );
    SeedKeys::from_seed(&seed).unwrap()
}

/// What maki's review screen takes (maki-wasm's limits): a heading of 32 bytes, a value of 128, no
/// control characters but newlines in the fixed-width text and the prose, 4096 bytes of each.
fn fits_the_screen(r: &Review) {
    assert!(r.summary.len() <= display::MAX_SUMMARY, "{}", r.summary);
    for page in &r.pages {
        let plain = |t: &str| !t.chars().any(|c| c.is_control());
        let lines = |t: &str| !t.chars().any(|c| c.is_control() && c != '\n');
        assert!(!page.heading.trim().is_empty() && page.heading.len() <= 32, "{page:?}");
        assert!(page.value.len() <= 128 && page.mono.len() <= 4096 && page.prose.len() <= 4096, "{page:?}");
        assert!(
            plain(&page.heading) && plain(&page.value) && lines(&page.mono) && lines(&page.prose),
            "{page:?}"
        );
    }
}

const TRANSFER_FEE: &str = "1.1 TRX if the recipient is new to Tron. If not, 0.267 TRX for 267 bytes of bandwidth, or nothing while this account has bandwidth left: 600 bytes free a day.";
const CALL_FEE: &str = "Up to 30 TRX burnt for energy, if this account's staked energy runs short. 0.345 TRX for 345 bytes of bandwidth, if its bandwidth does: 600 bytes free a day.";

#[test]
fn addresses_as_tron_wallets_make_them() {
    let keys = keys();
    // the test phrase's account, as Ledger's Tron app publishes it (its README) and Keystone's
    // firmware tests it, with the accounts after it in the last place, as Keystone's tests have them
    for (index, expected) in
        [(0, ME), (1, "TSeJkUh4Qv67VNFwY8LaAxERygNdy6NQZK"), (2, "TYJPRrdB5APNeRs4R7fYZSwW3TcrTKw2gx")]
    {
        let key = keys.uncompressed(&path(index)).unwrap();
        assert_eq!(address(&address_of(&key).unwrap()), expected, "account {index}");
    }
    assert_eq!(maki_hd::format_path(&path(0)), "m/44'/195'/0'/0/0");
    assert_eq!(address_of(&[0x02; 65]), None, "not an uncompressed key");
    // as transactions carry it: 0x41 and the hash's last 20 bytes
    assert_eq!(hex(&me()), "41c8599111f29c1e1e061265b4af93ea1f274ad78a");
    assert_eq!(parse_address(&address(&me())), Some(me()));
    // a character changed, one too many or too few, letters base58 doesn't have
    assert_eq!(parse_address("TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdh"), None);
    assert_eq!(parse_address("TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYd"), None);
    assert_eq!(parse_address("TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdHH"), None);
    assert_eq!(parse_address("TUEZSdKsoDHQMeZwihtdoBiN46zxhGWY0O"), None);
    // base58check of 21 bytes that aren't an address of Tron's: 0x42 first, which looks like one,
    // and Tron's old test networks' 0xa0
    let mut other = [0x11; 21];
    other[0] = 0x42;
    let other = base58::check_encode(&other);
    assert_eq!(other, "Tas3vExdmvHHZhkC1z5ByHT3Szd491AdKz");
    assert_eq!(parse_address(&other), None);
    assert_eq!(parse_address(&base58::check_encode(&[0xa0; 21])), None);
    assert_eq!(base58::encode(&[0, 0, 1]), "112");
    assert_eq!(base58::decode("112"), Some(vec![0, 0, 1]));
    assert_eq!(base58::decode("0OIl"), None);
    assert_eq!(base58::check_decode("1"), None);
    // every token maki knows, by an address whose checksum is its own
    let written = [
        USDT,
        "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8",
        "TXDk8mbtRbXeYuMNS83CfKPaYYT8XWv9Hz",
        "TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR",
        NILE_USDT,
    ];
    assert_eq!(tokens::TOKENS.len(), written.len());
    for (t, w) in tokens::TOKENS.iter().zip(written) {
        assert_eq!(address(&t.contract), w);
        assert_eq!(parse_address(w), Some(t.contract));
    }
    let usdt = parse_address(USDT).unwrap();
    assert_eq!(tokens::known(Network::Tron, &usdt).map(|t| (t.symbol, t.decimals)), Some(("USDT", 6)));
    assert!(tokens::known(Network::Nile, &usdt).is_none(), "mainnet's USDT isn't Nile's");
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

#[test]
fn amounts_times_and_sizes() {
    assert_eq!(display::decimals(0, 6), "0");
    assert_eq!(display::decimals(1, 6), "0.000001");
    assert_eq!(display::decimals(1_500_000, 6), "1.5");
    assert_eq!(display::decimals(42, 0), "42");
    assert_eq!(display::trx(267_000), "0.267 TRX");
    assert_eq!(display::trx(i64::MAX as u128), "9223372036854.775807 TRX");
    assert_eq!(display::uint256(&[0; 32]), "0");
    assert_eq!(
        display::uint256(&[0xff; 32]),
        "115792089237316195423570985008687907853269984665640564039457584007913129639935"
    );
    let mut five = [0u8; 32];
    five[29..].copy_from_slice(&[0x50, 0x1b, 0xd0]);
    assert_eq!(display::uint256(&five), "5250000");
    let usdt = tokens::known(Network::Tron, &parse_address(USDT).unwrap()).unwrap();
    assert_eq!(display::token_amount(usdt, &five), "5.25 USDT");
    assert_eq!(display::utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(display::utc(MADE), "2026-10-02 03:18:51 UTC");
    assert_eq!(display::utc(951_782_400_000), "2000-02-29 00:00:00 UTC");
    assert_eq!(display::utc(4_102_444_800_000), "2100-01-01 00:00:00 UTC");
    assert_eq!(display::utc(253_402_300_799_000), "9999-12-31 23:59:59 UTC");
    assert_eq!(display::utc(i64::MAX as u64), "292278994-08-17 07:12:55 UTC");
    assert_eq!(display::span(3 * 86_400_000), "3 days");
    assert_eq!(display::span(86_400_000 + 3_600_000), "1 day 1 hour");
    assert_eq!(display::span(5_400_000), "1 hour 30 minutes");
    assert_eq!(display::span(90_000), "1 minute 30 seconds");
    assert_eq!(display::span(30_000), "30 seconds");
    // bandwidth as Tron counted it for transactions of these sizes (TronGrid's net_usage)
    assert_eq!(display::bandwidth(134), 268);
    assert_eq!(display::bandwidth(211), 345);
    assert_eq!(display::unstake_days(Network::Tron), 14);
}

#[test]
fn maki_signs_what_tronweb_signs() {
    let keys = keys();
    let mut signed = 0;
    for f in fixtures() {
        // the transaction's ID is what's signed: the SHA-256 of raw_data
        assert_eq!(txid(&f.raw).to_vec(), f.txid, "{}", f.name);
        let Some(expected) = f.signature else { continue };
        let (rs, recovery) = keys.sign_ecdsa(&path(0), &txid(&f.raw)).unwrap();
        assert_eq!(signature(&rs, recovery).to_vec(), expected, "{}", f.name);
        signed += 1;
    }
    assert_eq!(signed, 32);
}

#[test]
fn every_transaction_tronweb_made_reads_as_it_should() {
    for f in fixtures() {
        let result = Transaction::parse(&f.raw).map_err(|e| e.to_string()).and_then(|tx| {
            let network = if f.name.starts_with("nile") { Network::Nile } else { Network::Tron };
            review(&tx, &me(), network, None).map_err(|e| e.to_string())
        });
        match f.name.as_str() {
            "not-mine" => {
                assert_eq!(result, Err(String::from("another account's transaction, not this one's to sign")))
            }
            "permission-update" => {
                assert_eq!(
                    result,
                    Err(String::from("it changes who controls this account: maki won't sign that"))
                )
            }
            "freeze-v1" => {
                assert_eq!(result, Err(String::from("a FreezeBalanceContract: maki doesn't sign those")))
            }
            "create-account" => {
                assert_eq!(result, Err(String::from("an AccountCreateContract: maki doesn't sign those")))
            }
            name => fits_the_screen(&result.unwrap_or_else(|e| panic!("{name}: {e}"))),
        }
    }
}

#[test]
fn trx_and_trc10_tokens_sent() {
    let r = shown("trx");
    assert_eq!(
        r.pages,
        [network(), p("Send", "1.5 TRX", RECIPIENT, ""), p("Max fee", "1.1 TRX", "", TRANSFER_FEE)]
    );
    assert_eq!(r.summary, "sends 1.5 TRX; fee up to 1.1 TRX");
    let tx = parsed("trx");
    assert_eq!(
        tx.contract,
        Contract::Transfer { owner: me(), to: parse_address(RECIPIENT).unwrap(), amount: 1_500_000 }
    );
    assert_eq!(
        (tx.ref_block_bytes, tx.ref_block_hash),
        ([0xa4, 0x3d], [0x93, 0xb3, 0xe5, 0xe6, 0xef, 0x2d, 0xe8, 0x32])
    );
    assert_eq!((tx.timestamp, tx.expiration, tx.fee_limit, tx.permission), (MADE, MADE + 60_000, 0, 0));
    let r = shown("memo");
    assert_eq!(r.pages[2], p("Memo", "", "thanks for the coffee", "Everyone can read it, on chain."));
    assert_eq!(r.pages[3].value, "2.1 TRX");
    assert!(r.pages[3].prose.ends_with(" And 1 TRX for the memo."));
    assert_eq!(r.summary, "sends 20 TRX; fee up to 2.1 TRX");
    // a memo that isn't text, in hex
    assert_eq!(
        shown("memo-bytes").pages[2],
        p("Memo", "in hex", "ff00fe41", "Everyone can read it, on chain.")
    );
    let r = shown("trc10");
    assert_eq!(
        r.pages[1],
        p(
            "Send",
            "42 units",
            RECIPIENT,
            "Of TRC-10 token 1002000, in its smallest units: maki doesn't know it."
        )
    );
    assert_eq!(r.summary, "sends 42 units of token 1002000; fee up to 1.1 TRX");
    // signed under one of the account's active permissions
    let r = shown("active-permission");
    assert_eq!(
        r.pages[2],
        p(
            "Permission",
            "active #2",
            "",
            "It's signed under one of this account's active permissions, which may need others' signatures too: with more than one, Tron charges 1 TRX more."
        )
    );
    assert_eq!(r.summary, "sends 1 TRX; fee up to 1.1 TRX");
}

#[test]
fn tokens_sent_approved_and_revoked() {
    let r = shown("usdt");
    assert_eq!(
        r.pages,
        [network(), p("Send", "5.25 USDT", RECIPIENT, ""), p("Max fee", "30.345 TRX", "", CALL_FEE)]
    );
    assert_eq!(r.summary, "sends 5.25 USDT; fee up to 30.345 TRX");
    // 18 decimals
    assert_eq!(shown("usdd").pages[1], p("Send", "1.5 USDD", RECIPIENT, ""));
    let approve = "That address may spend this account's USDT without asking, until it's revoked.";
    let r = shown("usdt-approve");
    assert_eq!(r.pages[1], p("Approve!", "up to 100 USDT", SPENDER, approve));
    assert_eq!(r.summary, "lets another spend its USDT!; fee up to 30.345 TRX");
    let r = shown("usdt-approve-all");
    assert_eq!(r.pages[1], p("Approve!", "all its USDT", SPENDER, approve));
    assert_eq!(r.summary, "lets another spend its USDT!; fee up to 30.345 TRX");
    let r = shown("usdt-revoke");
    assert_eq!(
        r.pages[1],
        p("Revoke", "USDT", SPENDER, "That address may no longer spend this account's USDT.")
    );
    assert_eq!(r.summary, "revokes an approval of USDT; fee up to 30.345 TRX");
    // Nile's USDT, on Nile
    let r = shown_on("nile-usdt", Network::Nile);
    assert_eq!(
        r.pages[..2],
        [
            p(
                "Network",
                "Nile (test)",
                "",
                "Tron's test network, whose TRX is worth nothing. A transaction doesn't name its network: made for Tron's own, it would work there."
            ),
            p("Send", "1 USDT (Nile)", RECIPIENT, "")
        ]
    );
    assert_eq!(r.summary, "sends 1 USDT (Nile); fee up to 30.345 TRX");
    // a token's contract says which network a transaction is for, whatever the computer says: Tron's
    // USDT said to be on Nile (real money passed off as play money), and Nile's said to be on Tron's
    assert_eq!(
        review(&parsed("usdt"), &me(), Network::Nile, None),
        Err(Error::Invalid("a call to a token of Tron's own network: it's for that network, not Nile"))
    );
    assert_eq!(
        review(&parsed("nile-usdt"), &me(), Network::Tron, None),
        Err(Error::Invalid("a call to a token of Nile's: it's for Nile, not Tron's own network"))
    );
}

#[test]
fn calls_maki_cant_read_are_flagged() {
    let r = shown("unknown-token");
    assert_eq!(
        r.pages[1..3],
        [
            p(
                "Send",
                "42 units",
                RECIPIENT,
                "Of a token maki doesn't know, if that's what the contract is: maki can't tell what it does."
            ),
            p(
                "Token",
                "one maki doesn't know",
                CONTRACT,
                "Check its contract's address: maki can't tell what the contract does."
            )
        ]
    );
    assert_eq!(r.summary, "maki can't read all of it; fee up to 30.345 TRX");
    // a call to a token maki knows, that isn't a transfer or an approval
    let r = shown("usdt-other");
    assert_eq!(
        r.pages[1],
        p(
            "Contract call",
            "maki can't read it",
            &format!("{USDT}\nfunction 23b872dd, 100 bytes"),
            "A call to USDT's contract that maki can't spell out. It acts as this account: it may move its USDT."
        )
    );
    // TRX sent with a call, and a fee limit of 100 TRX
    let r = shown("contract-call");
    assert_eq!(
        r.pages[1..],
        [
            p(
                "Contract call",
                "maki can't read it",
                &format!("{CONTRACT}\nfunction d0e30db0, 4 bytes"),
                "maki can't tell what it does. It acts as this account: it may move its tokens of that contract, and any it's let it spend."
            ),
            p("Send", "2 TRX", CONTRACT, "To the contract, with the call."),
            p(
                "Max fee",
                "100.283 TRX",
                "",
                "Up to 100 TRX burnt for energy, if this account's staked energy runs short. 0.283 TRX for 283 bytes of bandwidth, if its bandwidth does: 600 bytes free a day."
            )
        ]
    );
    assert_eq!(r.summary, "maki can't read all of it; fee up to 100.283 TRX");
    // a TRC-10 token sent with one
    let r = shown("contract-trc10");
    assert_eq!(
        r.pages[2],
        p("Send", "5 units", CONTRACT, "Of TRC-10 token 1002000, to the contract, with the call.")
    );
}

#[test]
fn staking_delegating_and_votes() {
    let r = shown("stake");
    assert_eq!(
        r.pages[1..],
        [
            p(
                "Stake",
                "100 TRX",
                "",
                "For energy. Staked, it stays this account's but can't be spent: unstaking it takes 14 days."
            ),
            p(
                "Max fee",
                "0.253 TRX",
                "",
                "For 253 bytes of bandwidth, only if this account has none left: 600 bytes free a day."
            )
        ]
    );
    assert_eq!(r.summary, "stakes 100 TRX for energy; fee up to 0.253 TRX");
    assert_eq!(shown("stake-bandwidth").summary, "stakes 50 TRX for bandwidth; fee up to 0.251 TRX");
    let unstake = "Staked for energy. It can be withdrawn in 14 days. If this account's votes need more than stays staked, they're cut to fit.";
    let r = shown("unstake");
    assert_eq!(r.pages[1], p("Unstake", "100 TRX", "", unstake));
    assert_eq!(r.summary, "unstakes 100 TRX; fee up to 0.255 TRX");
    // Nile waits a day
    assert_eq!(shown_on("unstake", Network::Nile).pages[1].prose, unstake.replace("14 days", "1 day"));
    assert_eq!(
        shown("withdraw-unstaked").pages[1],
        p("Withdraw", "unstaked TRX", "", "Whatever is done unstaking comes back to this account, to spend.")
    );
    assert_eq!(
        shown("cancel-unstaking").pages[1],
        p(
            "Cancel unstaking",
            "all of it",
            "",
            "TRX this account is unstaking is staked again, as it was; any that's done unstaking comes back to it."
        )
    );
    let r = shown("delegate");
    assert_eq!(
        r.pages[1],
        p(
            "Delegate energy",
            "100 TRX",
            RECEIVER,
            "That address uses the energy this account's staked 100 TRX makes; the TRX stays this account's."
        )
    );
    assert_eq!(r.summary, "delegates 100 TRX of energy; fee up to 0.278 TRX");
    let r = shown("delegate-locked");
    assert_eq!(
        r.pages[1],
        p(
            "Delegate bandwidth",
            "200 TRX",
            RECEIVER,
            "That address uses the bandwidth this account's staked 200 TRX makes; the TRX stays this account's. Locked for 1 day: it can't be reclaimed sooner."
        )
    );
    // a lock without a period is Tron's three days
    let tx = parsed("delegate-locked-3-days");
    assert!(matches!(tx.contract, Contract::Delegate { lock: Some(86_400), resource: Resource::Energy, .. }));
    assert!(
        shown("delegate-locked-3-days").pages[1]
            .prose
            .ends_with("Locked for 3 days: it can't be reclaimed sooner.")
    );
    let r = shown("undelegate");
    assert_eq!(
        r.pages[1],
        p(
            "Reclaim energy",
            "100 TRX",
            RECEIVER,
            "That address stops using the energy this account's staked 100 TRX makes."
        )
    );
    assert_eq!(r.summary, "reclaims 100 TRX of energy; fee up to 0.28 TRX");
    let r = shown("vote");
    assert_eq!(
        r.pages[1..3],
        [
            p(
                "Vote",
                "100 votes",
                WITNESSES[0],
                "These votes replace every vote this account has made; each takes 1 TRX it has staked."
            ),
            p("Vote", "50 votes", WITNESSES[1], "")
        ]
    );
    assert_eq!(r.summary, "votes for 2 witnesses; fee up to 0.299 TRX");
    let r = shown("claim-rewards");
    assert_eq!(
        r.pages[1],
        p("Claim rewards", "for voting", "", "The rewards this account has earned by voting come to it.")
    );
    assert_eq!(r.summary, "claims voting rewards; fee up to 0.246 TRX");
}

#[test]
fn when_it_expires_out_of_the_ordinary_says_so() {
    // a minute after it was made, as TronWeb makes them: nothing to say
    assert!(
        shown("trx")
            .pages
            .iter()
            .all(|p| !["Valid for", "Expired!", "Expires late!"].contains(&p.heading.as_str()))
    );
    let r = shown("six-hours");
    assert_eq!(
        r.pages[2],
        p("Valid for", "6 hours", "", "Whoever has it can send it until 2026-10-02 09:18:51 UTC.")
    );
    assert_eq!(r.summary, "sends 1 TRX; fee up to 1.1 TRX");
    let r = shown("three-days");
    assert_eq!(
        r.pages[2],
        p(
            "Expires late!",
            "2026-10-05 03:18:51 UTC",
            "",
            "Tron takes a transaction only in the day before it expires: whoever has this one can send it then, and not before."
        )
    );
    assert_eq!(r.summary, "can only be sent later!; fee up to 1.1 TRX");
    let r = shown("expired");
    assert_eq!(
        r.pages[2],
        p(
            "Expired!",
            "2026-10-02 03:17:51 UTC",
            "",
            "That's before it says it was made: Tron won't take it."
        )
    );
    assert_eq!(r.summary, "already expired!; fee up to 1.1 TRX");
    // maki's clock, when it has one, rather than what the transaction says
    let tx = parsed("trx");
    let late = review(&tx, &me(), Network::Tron, Some(MADE + 120_000)).unwrap();
    assert_eq!(
        late.pages[2],
        p("Expired!", "2026-10-02 03:19:51 UTC", "", "That's past, by maki's clock: Tron won't take it.")
    );
    let early = review(&tx, &me(), Network::Tron, Some(MADE - 2 * 86_400_000)).unwrap();
    assert_eq!(early.pages[2].heading, "Expires late!");
    // nothing to judge it by
    let undated = Transaction::parse(&raw_at(&send(&me(), 1), MADE + 60_000, None).0).unwrap();
    assert_eq!(
        review(&undated, &me(), Network::Tron, None).unwrap().pages[2],
        p(
            "Expires",
            "2026-10-02 03:19:51 UTC",
            "",
            "maki can't tell how far off that is: the transaction doesn't say when it was made."
        )
    );
}

/// Protocol Buffers written by hand, for what TronWeb wouldn't make.
#[derive(Clone, Default)]
struct Pb(Vec<u8>);

impl Pb {
    fn varint(&mut self, mut n: u64) {
        while n >= 0x80 {
            self.0.push(n as u8 | 0x80);
            n >>= 7;
        }
        self.0.push(n as u8);
    }

    fn num(mut self, field: u64, n: u64) -> Pb {
        self.varint(field << 3);
        self.varint(n);
        self
    }

    fn bytes(mut self, field: u64, b: &[u8]) -> Pb {
        self.varint(field << 3 | 2);
        self.varint(b.len() as u64);
        self.0.extend_from_slice(b);
        self
    }

    fn then(mut self, b: &[u8]) -> Pb {
        self.0.extend_from_slice(b);
        self
    }
}

fn a(text: &str) -> Vec<u8> { parse_address(text).unwrap().to_vec() }

/// A `Transaction.Contract` of `kind`, named `name`, holding `value`.
fn contract(kind: u64, name: &str, value: &Pb) -> Pb {
    let any =
        Pb::default().bytes(1, format!("type.googleapis.com/protocol.{name}").as_bytes()).bytes(2, &value.0);
    Pb::default().num(1, kind).bytes(2, &any.0)
}

/// raw_data with this contract, naming the fixtures' block, expiring then, made when it says.
fn raw_at(contract: &Pb, expiration: u64, made: Option<u64>) -> Pb {
    let raw = Pb::default()
        .bytes(1, &[0xa4, 0x3d])
        .bytes(4, &[0x93, 0xb3, 0xe5, 0xe6, 0xef, 0x2d, 0xe8, 0x32])
        .num(8, expiration)
        .bytes(11, &contract.0);
    match made {
        Some(t) => raw.num(14, t),
        None => raw,
    }
}

fn raw(contract: &Pb) -> Pb { raw_at(contract, MADE + 60_000, Some(MADE)) }

/// A TransferContract from `owner`, to the recipient.
fn send(owner: &Address, amount: u64) -> Pb {
    contract(1, "TransferContract", &Pb::default().bytes(1, owner).bytes(2, &a(RECIPIENT)).num(3, amount))
}

fn refused(bytes: &[u8]) -> tx::Error { Transaction::parse(bytes).unwrap_err() }

#[test]
fn transactions_tron_would_refuse_maki_refuses() {
    use tx::Error::*;
    let good = raw(&send(&me(), 1_500_000));
    // written as TronWeb writes it
    assert_eq!(good.0, fixture("trx"));
    // cut short, or with more after it
    assert_eq!(refused(&good.0[..good.0.len() - 1]), Encoding);
    assert_eq!(refused(&good.clone().then(&[0x00]).0), Encoding);
    assert_eq!(refused(&good.clone().then(&[0x90]).0), Encoding);
    assert_eq!(refused(&[0xff; tx::MAX_RAW + 1]), TooBig);
    // not as Tron writes it: out of order, a default written out, a number longer than it need be
    let c = send(&me(), 1_500_000);
    let out_of_order =
        Pb::default().bytes(1, &[0xa4, 0x3d]).num(8, MADE + 60_000).bytes(4, &[7; 8]).bytes(11, &c.0);
    assert_eq!(refused(&out_of_order.0), Encoding);
    assert_eq!(refused(&good.clone().num(18, 0).0), Encoding);
    assert_eq!(refused(&memo_raw(&[])), Encoding);
    let long =
        Pb::default().bytes(1, &[0xa4, 0x3d]).bytes(4, &[7; 8]).then(&[0x40, 0x81, 0x00]).bytes(11, &c.0);
    assert_eq!(refused(&long.0), Encoding);
    assert!(Transaction::parse(&memo_raw(b"hi")).is_ok());
    // a field twice, a field Tron doesn't use or that isn't there at all, a field of the wrong kind
    let twice = Pb::default()
        .bytes(1, &[0xa4, 0x3d])
        .bytes(4, &[7; 8])
        .bytes(4, &[7; 8])
        .num(8, MADE)
        .bytes(11, &c.0);
    assert_eq!(refused(&twice.0), Duplicate);
    let numbered = Pb::default()
        .bytes(1, &[0xa4, 0x3d])
        .num(3, 86_746_173)
        .bytes(4, &[7; 8])
        .num(8, MADE)
        .bytes(11, &c.0);
    assert_eq!(refused(&numbered.0), Unknown);
    assert_eq!(refused(&good.clone().num(99, 1).0), Unknown);
    assert_eq!(
        refused(&Pb::default().bytes(1, &[0xa4, 0x3d]).bytes(4, &[7; 8]).bytes(8, &[1]).bytes(11, &c.0).0),
        Unknown
    );
    // a field TransferContract doesn't have
    let extra = Pb::default().bytes(1, &me()).bytes(2, &a(RECIPIENT)).num(3, 1).num(4, 1);
    assert_eq!(refused(&raw(&contract(1, "TransferContract", &extra)).0), Unknown);
    // a contract's provider, which Tron doesn't use
    let any = Pb::default()
        .bytes(1, b"type.googleapis.com/protocol.TransferContract")
        .bytes(2, &Pb::default().bytes(1, &me()).bytes(2, &a(RECIPIENT)).num(3, 1).0);
    assert_eq!(refused(&raw(&Pb::default().num(1, 1).bytes(2, &any.0).bytes(3, b"me")).0), Unknown);
    // exactly one contract
    let two =
        Pb::default().bytes(1, &[0xa4, 0x3d]).bytes(4, &[7; 8]).num(8, MADE).bytes(11, &c.0).bytes(11, &c.0);
    assert_eq!(refused(&two.0), Contracts);
    assert_eq!(refused(&Pb::default().bytes(1, &[0xa4, 0x3d]).bytes(4, &[7; 8]).num(8, MADE).0), Contracts);
    // a type its contents aren't, or a type URL Tron's software doesn't write
    let value = Pb::default().bytes(1, &me()).bytes(2, &a(RECIPIENT)).num(3, 1);
    assert_eq!(refused(&raw(&contract(1, "TriggerSmartContract", &value)).0), Mismatch);
    let any = Pb::default().bytes(1, b"example.com/protocol.TransferContract").bytes(2, &value.0);
    assert_eq!(refused(&raw(&Pb::default().num(1, 1).bytes(2, &any.0)).0), Mismatch);
    assert_eq!(refused(&raw(&Pb::default().num(1, 1)).0), Mismatch);
    assert_eq!(
        refused(&raw(&contract(7, "Nothing", &value)).0).to_string(),
        "a contract of a kind Tron doesn't have: maki doesn't sign those"
    );
    // addresses that aren't Tron's
    let mut a0 = me();
    a0[0] = 0xa0;
    assert_eq!(refused(&raw(&send(&a0, 1)).0), Address);
    let short = contract(
        1,
        "TransferContract",
        &Pb::default().bytes(1, &me()[..20]).bytes(2, &a(RECIPIENT)).num(3, 1),
    );
    assert_eq!(refused(&raw(&short).0), Address);
    // what java-tron refuses: nothing sent, to itself, no expiration, a block that isn't one
    let invalid = |bytes: &[u8]| matches!(refused(bytes), Invalid(_));
    assert!(invalid(&raw(&send(&me(), (-5i64) as u64)).0));
    let to_me = contract(1, "TransferContract", &Pb::default().bytes(1, &me()).bytes(2, &me()).num(3, 1));
    assert!(invalid(&raw(&to_me).0));
    assert!(invalid(&Pb::default().bytes(1, &[0xa4, 0x3d]).bytes(4, &[7; 8]).bytes(11, &c.0).0));
    assert!(invalid(
        &Pb::default().bytes(1, &[0xa4, 0x3d, 0]).bytes(4, &[7; 8]).num(8, MADE).bytes(11, &c.0).0
    ));
    assert!(invalid(&Pb::default().bytes(4, &[7; 8]).num(8, MADE).bytes(11, &c.0).0));
    assert!(invalid(&Pb::default().bytes(1, &[0xa4, 0x3d]).bytes(4, &[7; 7]).num(8, MADE).bytes(11, &c.0).0));
    // a fee limit on what calls no contract, which means nothing
    assert_eq!(
        refused(&good.clone().num(18, 1_000_000).0).to_string(),
        "a fee limit on a transaction that calls no contract"
    );
    // the witness permission, which signs blocks; a permission that can't be; one written in 5 bytes
    let any = Pb::default().bytes(1, b"type.googleapis.com/protocol.TransferContract").bytes(2, &value.0);
    let with = |permission: u64| raw(&Pb::default().num(1, 1).bytes(2, &any.0).num(5, permission)).0;
    assert!(invalid(&with(1)));
    assert!(invalid(&with(-2i64 as u64)));
    assert_eq!(refused(&with(0xffff_fffe)), Encoding);
    assert!(Transaction::parse(&with(3)).is_ok());
}

#[test]
fn contracts_tron_would_refuse_maki_refuses() {
    let invalid = |name: &str, kind: u64, value: Pb| {
        let e = refused(&raw(&contract(kind, name, &value)).0);
        assert!(matches!(e, tx::Error::Invalid(_)), "{name}: {e:?}");
        e.to_string()
    };
    let me = me();
    let trc10 = |name: &[u8]| Pb::default().bytes(1, name).bytes(2, &me).bytes(3, &a(RECIPIENT)).num(4, 1);
    for name in [&b"01002000"[..], b"1000000", b"BitTorrent", b"10020001002000100200"] {
        invalid("TransferAssetContract", 2, trc10(name));
    }
    assert!(Transaction::parse(&raw(&contract(2, "TransferAssetContract", &trc10(b"1000001"))).0).is_ok());
    // staking: under 1 TRX, Tron Power, a resource there isn't
    let stake = |amount: u64, resource: u64| Pb::default().bytes(1, &me).num(2, amount).num(3, resource);
    invalid("FreezeBalanceV2Contract", 54, stake(999_999, 1));
    invalid("FreezeBalanceV2Contract", 54, stake(1_000_000, 2));
    invalid("UnfreezeBalanceV2Contract", 55, stake(1, 7));
    // delegating to itself, under 1 TRX, a lock's period without the lock
    let delegate = |to: &[u8], amount: u64| Pb::default().bytes(1, &me).num(2, 1).num(3, amount).bytes(4, to);
    invalid("DelegateResourceContract", 57, delegate(&me, 1_000_000));
    invalid("DelegateResourceContract", 57, delegate(&a(RECEIVER), 999_999));
    assert_eq!(
        invalid("DelegateResourceContract", 57, delegate(&a(RECEIVER), 1_000_000).num(6, 100)),
        "a lock's period, without the lock"
    );
    // a bool written as 2
    let e = refused(
        &raw(&contract(57, "DelegateResourceContract", &delegate(&a(RECEIVER), 1_000_000).num(5, 2))).0,
    );
    assert_eq!(e, tx::Error::Encoding);
    invalid("UnDelegateResourceContract", 58, Pb::default().bytes(1, &me).num(3, 1).bytes(4, &me));
    invalid("UnDelegateResourceContract", 58, Pb::default().bytes(1, &me).bytes(4, &a(RECEIVER)));
    // votes: none, more than 30, one witness twice; and Tron's unused "support"
    let vote = |w: &str, n: u64| Pb::default().bytes(1, &a(w)).num(2, n).0;
    invalid("VoteWitnessContract", 4, Pb::default().bytes(1, &me));
    let mut many = Pb::default().bytes(1, &me);
    for _ in 0..31 {
        many = many.bytes(2, &vote(WITNESSES[0], 1));
    }
    invalid("VoteWitnessContract", 4, many);
    assert_eq!(
        invalid(
            "VoteWitnessContract",
            4,
            Pb::default().bytes(1, &me).bytes(2, &vote(WITNESSES[0], 1)).bytes(2, &vote(WITNESSES[0], 2))
        ),
        "the same witness voted for twice"
    );
    let support = Pb::default().bytes(1, &me).bytes(2, &vote(WITNESSES[0], 1)).num(3, 1);
    assert_eq!(refused(&raw(&contract(4, "VoteWitnessContract", &support)).0), tx::Error::Unknown);
    // calls: to itself, a TRC-10 token sent without saying which, one named and none sent, one
    // that can't be
    let call = |to: &[u8]| Pb::default().bytes(1, &me).bytes(2, to).bytes(4, &[0xd0, 0xe3, 0x0d, 0xb0]);
    invalid("TriggerSmartContract", 31, call(&me));
    invalid("TriggerSmartContract", 31, call(&a(CONTRACT)).num(5, 5));
    invalid("TriggerSmartContract", 31, call(&a(CONTRACT)).num(6, 1_002_000));
    invalid("TriggerSmartContract", 31, call(&a(CONTRACT)).num(5, 5).num(6, 1000));
    let negative = Pb::default().bytes(1, &me).bytes(2, &a(CONTRACT)).num(3, (-1i64) as u64);
    invalid("TriggerSmartContract", 31, negative.bytes(4, &[0xd0, 0xe3, 0x0d, 0xb0]));
}

#[test]
fn what_maki_wont_sign() {
    // another account's
    assert_eq!(review(&parsed("not-mine"), &me(), Network::Tron, None), Err(Error::NotMine));
    // a change of who controls this account: the trap the test phrase's own account on Tron fell
    // into, its owner permission now another's
    let tx = parsed("permission-update");
    assert_eq!(tx.contract, Contract::UpdatePermissions { owner: me() });
    assert_eq!(
        review(&tx, &me(), Network::Tron, None),
        Err(Error::Invalid("it changes who controls this account: maki won't sign that"))
    );
    // and Tron's old staking, and making an account
    assert_eq!(refused(&fixture("freeze-v1")), tx::Error::Unsupported("FreezeBalanceContract"));
    assert_eq!(refused(&fixture("create-account")), tx::Error::Unsupported("AccountCreateContract"));
    // a memo too long to show as hex; as text, it's shown
    let binary = Transaction::parse(&memo_raw(&[0xff; 2100])).unwrap();
    assert_eq!(
        review(&binary, &me(), Network::Tron, None),
        Err(Error::Invalid("a memo too long to show on maki's screen"))
    );
    let text = Transaction::parse(&memo_raw(&[b'a'; 2100])).unwrap();
    assert_eq!(review(&text, &me(), Network::Tron, None).unwrap().pages[2].mono.len(), 2100);
}

/// A transfer with a memo, in order: the memo (10) before the contract (11).
fn memo_raw(memo: &[u8]) -> Vec<u8> {
    Pb::default()
        .bytes(1, &[0xa4, 0x3d])
        .bytes(4, &[0x93, 0xb3, 0xe5, 0xe6, 0xef, 0x2d, 0xe8, 0x32])
        .num(8, MADE + 60_000)
        .bytes(10, memo)
        .bytes(11, &send(&me(), 1).0)
        .num(14, MADE)
        .0
}
