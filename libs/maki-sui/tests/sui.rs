//! maki-sui against Sui's own library: transactions @mysten/sui made (`fixtures/make.mjs`), read as
//! they are and shown as they should be, and signed by maki's keys as the library signs them with
//! the same account (the test phrase's first, as Slush and Ledger's Sui app have it). And what Sui
//! would refuse, written by hand, refused.

use maki_hd::seed::SeedKeys;
use maki_sui::display::{self, Page, Review, review};
use maki_sui::tx::{self, Argument, Command, Expiration, Input, Transaction, TypeTag};
use maki_sui::{
    Address, INTENT, Network, address, address_of, balance_field, mask, parse_address, path, signature,
    signing_digest, tokens,
};

const ME: &str = "0x5e93a736d04fbb25737aa40bee40171ef79f65fae833749e3c089fe7cc2161f1";
const RECIPIENT: &str = "0x29dfbf688abce7ab43bb8e70cae158ae961196e721440f515482f8ba1684390f";
const SECOND: &str = "0x7799ea80594c35644321148485238c7a7a1c6549809e1795e6747c6d4da2504c";
const THIRD: &str = "0xd64fe64522169a8a26fed5ae2f9a3c76363a18650a580379f23ddf64c2587066";
const VALIDATOR: &str = "0xa6ab0f1337bdb36bfd9733866e28f4aa0eec865a2bd8a4632f25456e5f02f0c7";
const USDC: &str = "0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC";

fn me() -> Address { parse_address(ME).unwrap() }

/// The made-up object IDs the fixtures use: the byte `n`, 32 times.
fn id(n: u8) -> String { address(&[n; 32]) }

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

fn json() -> serde_json::Value {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transactions.json"))
            .unwrap();
    serde_json::from_str(&text).unwrap()
}

struct Fixture {
    name: String,
    tx: Vec<u8>,
    /// What the library signs: the BLAKE2b-256 of the intent message
    digest: Vec<u8>,
    /// The library's signature for this account, if it's this account's
    signature: Option<Vec<u8>>,
}

/// The transactions @mysten/sui made.
fn fixtures() -> Vec<Fixture> {
    json()["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| Fixture {
            name: f["name"].as_str().unwrap().into(),
            tx: unhex(f["tx"].as_str().unwrap()),
            digest: unhex(f["digest"].as_str().unwrap()),
            signature: f["signature"].as_str().map(unhex),
        })
        .collect()
}

fn fixture(name: &str) -> Vec<u8> { fixtures().into_iter().find(|f| f.name == name).unwrap().tx }

fn parsed(name: &str) -> Transaction { Transaction::parse(&fixture(name)).unwrap() }

fn shown_on(name: &str, network: Network) -> Review { review(&parsed(name), &me(), network).unwrap() }

fn shown(name: &str) -> Review { shown_on(name, Network::Mainnet) }

fn refused_on(name: &str, network: Network) -> String {
    review(&parsed(name), &me(), network).unwrap_err().to_string()
}

fn p(heading: &str, value: &str, mono: &str, prose: &str) -> Page {
    Page { heading: heading.into(), value: value.into(), mono: mono.into(), prose: prose.into() }
}

fn network() -> Page { p("Network", "Sui", "", "") }

fn fee(paid_from: &str) -> Page {
    p(
        "Max fee",
        "0.003 SUI",
        "",
        &format!(
            "The most gas and storage can cost, at 1000 MIST a unit of gas; what isn't used stays this account's. Paid from {paid_from}."
        ),
    )
}

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

#[test]
fn addresses_as_sui_wallets_make_them() {
    let keys = keys();
    // the test phrase's accounts, as @mysten/sui's Ed25519Keypair.deriveKeypair makes them at
    // m/44'/784'/i'/0'/0', accounts counted at the third step as Slush and Ledger count them
    let accounts = json()["accounts"].as_array().unwrap().clone();
    assert_eq!(accounts.len(), 3);
    for a in accounts {
        let index = a["index"].as_u64().unwrap() as u32;
        let key = keys.ed25519_public(&path(index)).unwrap();
        assert_eq!(hex(&key), a["key"].as_str().unwrap(), "account {index}");
        assert_eq!(address(&address_of(&key)), a["address"].as_str().unwrap(), "account {index}");
    }
    assert_eq!(address(&address_of(&keys.ed25519_public(&path(0)).unwrap())), ME);
    assert_eq!(maki_hd::format_path(&path(0)), "m/44'/784'/0'/0'/0'");
    assert_eq!(maki_hd::format_path(&path(7)), "m/44'/784'/7'/0'/0'");
    assert_eq!(maki_hd::coin(&path(0)), Some("Sui"));
    // written in full, `0x` and 64 hex digits, either case; nothing shorter, longer, or else
    assert_eq!(parse_address(ME), Some(me()));
    assert_eq!(parse_address(&ME.to_uppercase().replace("0X", "0x")), Some(me()));
    assert_eq!(parse_address(&ME[2..]), None);
    assert_eq!(parse_address(&ME[..65]), None);
    assert_eq!(parse_address(&format!("{ME}0")), None);
    assert_eq!(parse_address(&ME.replace('e', "g")), None);
    assert_eq!(parse_address("0x2"), None);
    assert_eq!(parse_address(&format!("0X{}", &ME[2..])), None);
    // what's signed: BLAKE2b-256 of [0, 0, 0] and the transaction's data (of nothing, here, as
    // @noble/hashes, the library's, makes it)
    assert_eq!(INTENT, [0, 0, 0]);
    assert_eq!(hex(&signing_digest(&[])), "ab29e6dc16755d0071eba349ebda225d15e4f910cb474549c47e95cb85ecc4d6");
    // the signature as Sui takes it: Ed25519's flag, the signature, the key
    let s = signature(&[7; 64], &[9; 32]);
    assert_eq!((s[0], s[1], s[64], s[65], s[96]), (0, 7, 7, 9, 9));
}

#[test]
fn networks_and_address_balances() {
    // the chain identifiers, as Sui writes them in base58: mainnet's 4btiuiMP…, testnet's 69WiPg3D…
    assert_eq!(hex(&Network::Mainnet.chain())[..8], *"35834a8a");
    assert_eq!(hex(&Network::Testnet.chain())[..8], *"4c78adac");
    assert_eq!(Network::of_chain(&Network::Testnet.chain()), Some(Network::Testnet));
    assert_eq!(Network::of_chain(&[0; 32]), None);
    assert_eq!(Network::from_byte(0), Some(Network::Mainnet));
    assert_eq!(Network::from_byte(1), Some(Network::Testnet));
    assert_eq!(Network::from_byte(2), None);
    // the fields that hold this account's SUI and USDC, as @mysten/sui derives them
    // (deriveDynamicFieldID on 0xacc)
    let fields = &json()["accumulators"];
    assert_eq!(address(&balance_field(&me(), &TypeTag::sui())), fields["sui"].as_str().unwrap());
    let usdc = tokens::TOKENS[0].type_tag();
    assert_eq!(usdc.to_string(), USDC);
    assert_eq!(address(&balance_field(&me(), &usdc)), fields["usdc"].as_str().unwrap());
    let field = balance_field(&me(), &TypeTag::sui());
    assert_eq!(mask(&mask(&field, &Network::Mainnet.chain()), &Network::Mainnet.chain()), field);
    // every coin maki knows, by its type, on its network
    assert_eq!(tokens::known(Network::Mainnet, &usdc).map(|t| (t.symbol, t.decimals)), Some(("USDC", 6)));
    assert!(tokens::known(Network::Testnet, &usdc).is_none(), "mainnet's USDC isn't the test network's");
    assert_eq!(tokens::network_of(&usdc), Some(Network::Mainnet));
    assert_eq!(tokens::network_of(&TypeTag::sui()), None, "SUI is both networks'");
    assert_eq!(tokens::known(Network::Testnet, &TypeTag::sui()).map(|t| t.symbol), Some("SUI"));
    let types: Vec<String> = tokens::TOKENS.iter().map(|t| t.type_tag().to_string()).collect();
    assert_eq!(
        types,
        [
            USDC,
            "0x44f838219cf67b058f3b37907b655f226153c18e33dfcd0da559a844fea9b1c1::usdsui::USDSUI",
            "0x41d587e5336f1c86cad50d38a7136db99333bb9bda91cea4ba69115defeb1402::sui_usde::SUI_USDE",
            "0x960b531667636f39e85867775f52f6b1f220a058c4de786905bdf761e06a56bb::usdy::USDY",
            "0xf16e6b723f242ec745dfd7634ad072c42d5c1d9ac9d62a39c381303eaa57693a::fdusd::FDUSD",
            "0x2053d08c1e2bd02791056171aab0fd12bd7cd7efad2ab8f6b9c8902f14df2ff2::ausd::AUSD",
            "0xe14726c336e81b32328e92afc37345d159f5b550b09fa92bd43640cfdd0a0cfd::usdb::USDB",
            "0x356a26eb9e012a68958082340d4c4116e7f55615cf27affcff209cf0ae544f59::wal::WAL",
            "0xdeeb7a4662eec9f2f3def03fb937a663dddaa2e215b8078a284d026b7946c270::deep::DEEP",
            "0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC",
        ]
    );
}

#[test]
fn amounts_and_types() {
    assert_eq!(display::decimals(0, 9), "0");
    assert_eq!(display::decimals(1, 9), "0.000000001");
    assert_eq!(display::decimals(1_500_000_000, 9), "1.5");
    assert_eq!(display::decimals(42, 0), "42");
    assert_eq!(display::sui(3_000_000), "0.003 SUI");
    assert_eq!(display::sui(u64::MAX as u128), "18446744073.709551615 SUI");
    assert_eq!(TypeTag::sui().to_string(), "0x2::sui::SUI");
    let coin = TypeTag::framework("coin", "Coin", vec![TypeTag::sui()]);
    assert_eq!(coin.to_string(), "0x2::coin::Coin<0x2::sui::SUI>");
    assert_eq!(TypeTag::Vector(Box::new(TypeTag::U8)).to_string(), "vector<u8>");
    assert_eq!(TypeTag::balance(TypeTag::sui()).balance_of(), Some(&TypeTag::sui()));
    assert_eq!((coin.nodes(), coin.depth()), (2, 2));
}

#[test]
fn maki_signs_what_the_sdk_signs() {
    let keys = keys();
    let mut signed = 0;
    for f in fixtures() {
        // what's signed: the intent message's digest, as the library makes it
        assert_eq!(signing_digest(&f.tx).to_vec(), f.digest, "{}", f.name);
        let Some(expected) = f.signature else { continue };
        let ours = keys.sign_ed25519(&path(0), &signing_digest(&f.tx)).unwrap();
        assert_eq!(ours.to_vec(), expected, "{}", f.name);
        signed += 1;
    }
    assert_eq!(signed, 39);
}

#[test]
fn every_transaction_the_sdk_made_reads_as_it_should() {
    let refusals = [
        ("not-mine", "another account's transaction, not this one's to sign"),
        (
            "sponsored",
            "its fee is paid by another account: maki signs only transactions this account pays for",
        ),
        (
            "sponsor-only",
            "another account's transaction, with this one to pay its fee: maki doesn't sponsor others'",
        ),
        ("publish", "it publishes Move code: maki can't show what code does, so it doesn't sign that"),
        ("upgrade", "it upgrades Move code: maki can't show what code does, so it doesn't sign that"),
        ("alias-add", "it changes which keys can sign for this account: maki won't sign that"),
        ("allowance-new", "it lets another account spend from this one: maki won't sign that"),
        ("allowance-spend", "it spends another account's funds, by an allowance: maki doesn't sign those"),
    ];
    for f in fixtures() {
        let network = if f.name.starts_with("testnet") { Network::Testnet } else { Network::Mainnet };
        let tx = Transaction::parse(&f.tx).unwrap_or_else(|e| panic!("{}: {e}", f.name));
        let result = review(&tx, &me(), network).map_err(|e| e.to_string());
        match refusals.iter().find(|(name, _)| *name == f.name) {
            Some((_, why)) => assert_eq!(result, Err(why.to_string()), "{}", f.name),
            None => fits_the_screen(&result.unwrap_or_else(|e| panic!("{}: {e}", f.name))),
        }
    }
}

#[test]
fn sui_sent_from_its_coins() {
    for name in ["sui", "sui-nested"] {
        let tx = parsed(name);
        assert_eq!(tx.sender, me());
        assert_eq!((tx.gas.owner, tx.gas.price, tx.gas.budget), (me(), 1000, 3_000_000));
        assert_eq!(tx.expiration, Expiration::None);
    }
    let r = shown("sui");
    assert_eq!(r.pages, [network(), p("Send", "1.5 SUI", RECIPIENT, ""), fee("this account's coin")]);
    assert_eq!(r.summary, "sends 1.5 SUI; fee up to 0.003 SUI");
    // the split's whole result, as Slush sends it, or its first coin
    assert!(
        matches!(parsed("sui").commands[1], Command::TransferObjects { ref objects, .. } if objects[..] == [Argument::Result(0)])
    );
    assert!(
        matches!(parsed("sui-nested").commands[1], Command::TransferObjects { ref objects, .. } if objects[..] == [Argument::Nested(0, 0)])
    );
    assert_eq!(shown("sui-nested").summary, "sends 2 SUI; fee up to 0.003 SUI");
    let r = shown("sui-many");
    assert_eq!(
        r.pages,
        [
            network(),
            p("Send", "1 SUI", RECIPIENT, ""),
            p("Send", "2 SUI", SECOND, ""),
            p("Send", "0.5 SUI", THIRD, ""),
            fee("2 of this account's coins"),
        ]
    );
    assert_eq!(r.summary, "sends 3.5 SUI in 3 payments; fee up to 0.003 SUI");
    let r = shown("sui-together");
    assert_eq!(r.pages[1..3], [p("Send", "1 SUI", RECIPIENT, ""), p("Send", "2 SUI", RECIPIENT, "")]);
    assert_eq!(r.summary, "sends 3 SUI in 2 payments; fee up to 0.003 SUI");
}

#[test]
fn everything_in_the_gas_coin_and_coins_merged() {
    let r = shown("sui-all");
    assert_eq!(
        r.pages,
        [
            network(),
            p(
                "Send",
                "the whole gas coin",
                RECIPIENT,
                "All the SUI in 3 of this account's coins, less the fee."
            ),
            fee("3 of this account's coins"),
        ]
    );
    assert_eq!(r.summary, "sends the whole gas coin; fee up to 0.003 SUI");
    let merged = p(
        "Merge",
        "2 coins",
        &format!("coin {}\ncoin {}", id(0x21), id(0x22)),
        "Into the gas coin: they stay this account's.",
    );
    let r = shown("sui-all-merged");
    assert_eq!(
        r.pages[1..3],
        [
            merged.clone(),
            p(
                "Send",
                "the whole gas coin",
                RECIPIENT,
                "All the SUI in this account's coin and the 2 coins merged into it, less the fee."
            ),
        ]
    );
    let r = shown("merge");
    assert_eq!(r.pages, [network(), merged, fee("this account's coin")]);
    assert_eq!(r.summary, "merges coins; fee up to 0.003 SUI");
}

#[test]
fn objects_sent_by_their_ids() {
    let object = |n: u8| format!("{}: the transaction doesn't say what it is.", id(n));
    let r = shown("object");
    assert_eq!(r.pages[1], p("Send", "an object", RECIPIENT, &object(0x31)));
    assert_eq!(r.summary, "sends an object; fee up to 0.003 SUI");
    let r = shown("objects");
    assert_eq!(
        r.pages[1..3],
        [p("Send", "an object", SECOND, &object(0x31)), p("Send", "an object", SECOND, &object(0x32))]
    );
    assert_eq!(r.summary, "sends 2 objects; fee up to 0.003 SUI");
}

#[test]
fn tokens_from_coins_named_or_not() {
    let merge = p(
        "Merge",
        "1 coin",
        &format!("coin {}", id(0x22)),
        &format!("Into coin {}: they stay this account's.", id(0x21)),
    );
    // a token's coins, which the transaction doesn't name: units of a coin maki can't tell
    let r = shown("token-coins");
    assert_eq!(
        r.pages[1..3],
        [
            merge.clone(),
            p(
                "Send",
                "5250000 units",
                RECIPIENT,
                &format!(
                    "The transaction doesn't say which coin this is, so maki can't tell what these units are. From coin {}.",
                    id(0x21)
                )
            ),
        ]
    );
    assert_eq!(r.summary, "maki can't read all of it; fee up to 0.003 SUI");
    let r = shown("token-surplus");
    assert_eq!(r.pages[1].value, "5250000 units");
    assert_eq!(r.summary, "maki can't read all of it; fee up to 0.003 SUI");
    // named by a call of the coin's own functions: into the recipient's address balance; the empty
    // coin left destroyed; what's left going back to this account's address balance
    let r = shown("token-send-funds");
    assert_eq!(
        r.pages[1..3],
        [
            merge.clone(),
            p(
                "Send",
                "5.25 USDC",
                RECIPIENT,
                &format!("From coin {}, into their address balance.", id(0x21))
            )
        ]
    );
    assert_eq!(r.summary, "sends 5.25 USDC; fee up to 0.003 SUI");
    let r = shown("token-exact");
    assert_eq!(
        r.pages[1..3],
        [merge, p("Send", "5.25 USDC", RECIPIENT, &format!("From coin {}.", id(0x21)))]
    );
    assert_eq!(r.summary, "sends 5.25 USDC; fee up to 0.003 SUI");
    let r = shown("token-mixed");
    assert_eq!(
        r.pages[1..4],
        [
            p(
                "Merge",
                "1 coin",
                "0.25 USDC from its address balance",
                &format!("Into coin {}: they stay this account's.", id(0x21))
            ),
            p(
                "Send",
                "a whole coin",
                "this account",
                &format!(
                    "From coin {}. All it holds: the transaction doesn't say how much. Into its own address balance.",
                    id(0x21)
                )
            ),
            p("Send", "5.25 USDC", RECIPIENT, &format!("From coin {}.", id(0x21))),
        ]
    );
    // what goes back to this account itself it keeps: maki reads all that leaves
    assert_eq!(r.summary, "sends 5.25 USDC; fee up to 0.003 SUI");
}

#[test]
fn from_the_address_balance() {
    let from = "From this account's address balance.";
    let r = shown("ab-sui");
    assert_eq!(
        r.pages,
        [network(), p("Send", "1.5 SUI", RECIPIENT, from), fee("this account's address balance")]
    );
    assert_eq!(r.summary, "sends 1.5 SUI; fee up to 0.003 SUI");
    let tx = parsed("ab-sui");
    assert!(tx.pays_from_balance() && !tx.is_gasless());
    assert!(matches!(tx.inputs[1], Input::Withdrawal(tx::Withdrawal { amount: 1_500_000_000, .. })));
    assert!(matches!(
        tx.expiration,
        Expiration::During { min: Some(1268), max: Some(1269), proposers: None, .. }
    ));
    let r = shown("ab-many");
    assert_eq!(r.pages[1..3], [p("Send", "1 SUI", RECIPIENT, from), p("Send", "2 SUI", SECOND, from)]);
    assert_eq!(r.summary, "sends 3 SUI in 2 payments; fee up to 0.003 SUI");
    let into = "From this account's address balance, into theirs.";
    let r = shown("ab-send-funds");
    assert_eq!(r.pages[1], p("Send", "1 SUI", RECIPIENT, into));
    let r = shown("ab-usdc");
    assert_eq!(r.pages[1], p("Send", "5.25 USDC", RECIPIENT, from));
    assert_eq!(r.summary, "sends 5.25 USDC; fee up to 0.003 SUI");
    // with no fee, as Sui lets stablecoins go
    let r = shown("gasless-usdc");
    assert!(parsed("gasless-usdc").is_gasless());
    assert_eq!(
        r.pages,
        [
            network(),
            p("Send", "5.25 USDC", RECIPIENT, into),
            p("Fee", "none", "", "Sui lets this go without a fee: a gasless transfer."),
        ]
    );
    assert_eq!(r.summary, "sends 5.25 USDC; no fee");
    // a coin maki doesn't know, by its type, in its smallest units
    let r = shown("ab-strange");
    assert_eq!(
        r.pages[1],
        p(
            "Send",
            "42 units",
            RECIPIENT,
            &format!(
                "Of {}::meme::MEME, which maki doesn't know: in its smallest units. From this account's address balance, into theirs.",
                id(0x44)
            )
        )
    );
    assert_eq!(r.summary, "sends 42 units of a coin maki doesn't know; fee up to 0.003 SUI");
}

#[test]
fn coin_reservations_this_accounts_sui() {
    // in the gas payment, as the library pays when a transaction uses the gas coin
    let r = shown("reservation-gas");
    let tx = parsed("reservation-gas");
    assert_eq!(tx.gas.payment[0].reservation().map(|r| (r.amount, r.epoch)), Some((2_000_000_000, 1268)));
    assert_eq!(r.pages[1], p("Send", "1.5 SUI", RECIPIENT, ""));
    assert_eq!(r.pages[2], fee("this account's coin and 2 SUI of its address balance"));
    // as a coin of its own, for older software
    let r = shown("reservation-input");
    assert_eq!(r.pages[1], p("Send", "1 SUI", RECIPIENT, "From this account's address balance."));
    assert_eq!(r.summary, "sends 1 SUI; fee up to 0.003 SUI");
    // each names this account's SUI on Sui's own network: not on its test network
    let own = "a transaction for Sui's own network, not its test network";
    assert_eq!(refused_on("reservation-gas", Network::Testnet), own);
    assert_eq!(refused_on("reservation-input", Network::Testnet), own);
}

#[test]
fn staking() {
    let r = shown("stake");
    assert_eq!(
        r.pages[1],
        p(
            "Stake",
            "1 SUI",
            VALIDATOR,
            "With this validator. It stays this account's, as staked SUI, earning rewards from the next epoch; unstaking brings it back with them."
        )
    );
    assert_eq!(r.summary, "stakes 1 SUI; fee up to 0.003 SUI");
    let r = shown("unstake");
    assert_eq!(
        r.pages[1],
        p(
            "Unstake",
            "staked SUI",
            &id(0x33),
            "It comes back to this account, with its rewards. The transaction doesn't say how much it is."
        )
    );
    assert_eq!(r.summary, "unstakes; fee up to 0.003 SUI");
}

#[test]
fn calls_maki_cant_read_are_flagged_with_what_theyre_given() {
    let pkg = id(0x41);
    let acts = |given: &str| {
        format!(
            "maki can't tell what it does. It acts as this account, and is given {given}: it may do anything with those, and whatever a shared object's code lets this account do."
        )
    };
    let r = shown("move-call");
    assert_eq!(
        r.pages[1..3],
        [
            p(
                "Move call",
                "maki can't read it",
                &format!("{pkg}::market::buy\n<{USDC}>"),
                &acts(&format!("shared object {}, 3 SUI split off the gas coin, and 1 value", id(0x42)))
            ),
            p(
                "Send",
                "maki can't tell",
                "this account",
                &format!(
                    "Something the 2nd command (0x{}::market::buy) gave back: maki can't see what.",
                    &pkg[2..]
                )
            ),
        ]
    );
    assert_eq!(r.summary, "maki can't read all of it; fee up to 0.003 SUI");
    let r = shown("move-call-objects");
    assert_eq!(
        r.pages[1],
        p(
            "Move call",
            "maki can't read it",
            &format!("{pkg}::vault::deposit"),
            &acts(&format!(
                "its object {}, its object {}, and the gas coin (this account's coin)",
                id(0x31),
                id(0x21)
            ))
        )
    );
    // an object received, by the framework's own function, which maki doesn't follow
    let r = shown("receiving");
    assert_eq!(
        r.pages[1],
        p(
            "Move call",
            "maki can't read it",
            &format!(
                "{}::transfer::public_receive\n<0x{}::ticket::Ticket>",
                id(0)[..65].to_string() + "2",
                &pkg[2..]
            ),
            &acts(&format!("its object {} and object {}, sent to one of its objects", id(0x31), id(0x35)))
        )
    );
    // coins gathered into a vector are the vector's: the call is given them
    let r = shown("move-vec");
    assert_eq!(r.pages[1].prose, acts("1 SUI split off the gas coin and 1 SUI split off the gas coin"));
}

#[test]
fn when_it_expires_and_which_network() {
    let r = shown("epoch");
    assert_eq!(
        r.pages[2],
        p(
            "Valid until",
            "epoch 1300",
            "",
            "Sui takes it until that epoch ends (an epoch is about a day): maki can't tell how far off that is."
        )
    );
    // the epoch or two a transaction paid from the address balance is valid in: nothing to say
    for name in ["ab-sui", "validity"] {
        assert!(shown(name).pages.iter().all(|p| !p.heading.starts_with("Valid")), "{name}");
    }
    assert!(matches!(
        parsed("validity").expiration,
        Expiration::During { proposers: Some((1268, ref p)), .. } if p[..] == [3, 17, 40]
    ));
    // the test network, which the transaction names
    let r = shown_on("testnet", Network::Testnet);
    assert_eq!(
        r.pages[0],
        p("Network", "Sui testnet", "", "Sui's test network, whose SUI is worth nothing.")
    );
    assert_eq!(r.summary, "sends 1 SUI; fee up to 0.003 SUI");
    assert_eq!(shown_on("testnet-usdc", Network::Testnet).pages[1].value, "1 USDC (testnet)");
    // one that doesn't name it: made with Sui's own coins, it would spend them there
    assert_eq!(
        shown_on("sui", Network::Testnet).pages[0].prose,
        "Sui's test network, whose SUI is worth nothing. The transaction doesn't name its network: made with coins of Sui's own, it would spend them there."
    );
    // the network a transaction names, whatever the computer says; and a token's type names its own
    assert_eq!(refused_on("testnet", Network::Mainnet), "a transaction for Sui's test network, not its own");
    assert_eq!(
        refused_on("ab-sui", Network::Testnet),
        "a transaction for Sui's own network, not its test network"
    );
    assert_eq!(
        refused_on("token-send-funds", Network::Testnet),
        "a transaction for Sui's own network, not its test network"
    );
    // nothing but the fee
    let r = shown("empty");
    assert_eq!(r.pages[1], p("Nothing", "no commands", "", "It does nothing but pay the fee."));
    assert_eq!(r.summary, "sends nothing; fee up to 0.003 SUI");
}

/// BCS written by hand, for what @mysten/sui wouldn't make.
#[derive(Clone, Default)]
struct Bcs(Vec<u8>);

impl Bcs {
    fn uleb(mut self, mut n: u64) -> Bcs {
        while n >= 0x80 {
            self.0.push(n as u8 | 0x80);
            n >>= 7;
        }
        self.0.push(n as u8);
        self
    }

    fn raw(mut self, b: &[u8]) -> Bcs {
        self.0.extend_from_slice(b);
        self
    }

    fn bytes(self, b: &[u8]) -> Bcs { self.uleb(b.len() as u64).raw(b) }

    fn u16(self, n: u16) -> Bcs { self.raw(&n.to_le_bytes()) }

    fn u32(self, n: u32) -> Bcs { self.raw(&n.to_le_bytes()) }

    fn u64(self, n: u64) -> Bcs { self.raw(&n.to_le_bytes()) }

    fn many(self, items: &[Bcs]) -> Bcs {
        let mut out = self.uleb(items.len() as u64);
        for i in items {
            out = out.raw(&i.0);
        }
        out
    }
}

fn b() -> Bcs { Bcs::default() }

fn obj(n: u8) -> Bcs { b().raw(&[n; 32]).u64(1000 + n as u64).bytes(&[n; 32]) }

fn pure(bytes: &[u8]) -> Bcs { b().uleb(0).bytes(bytes) }

fn owned(n: u8) -> Bcs { b().uleb(1).uleb(0).raw(&obj(n).0) }

fn shared(n: u8, mutability: u64) -> Bcs { b().uleb(1).uleb(1).raw(&[n; 32]).u64(77).uleb(mutability) }

fn receiving(n: u8) -> Bcs { b().uleb(1).uleb(2).raw(&obj(n).0) }

/// A type: a struct of package `n`'s, with these parameters.
fn ty(n: u8, module: &str, name: &str, params: &[Bcs]) -> Bcs {
    b().uleb(7).raw(&[n; 32]).bytes(module.as_bytes()).bytes(name.as_bytes()).many(params)
}

fn sui_type() -> Bcs {
    let mut two = [0u8; 32];
    two[31] = 2;
    b().uleb(7).raw(&two).bytes(b"sui").bytes(b"SUI").uleb(0)
}

/// A withdrawal of `amount` of SUI from the sender (0), the sponsor (1).
fn withdrawal(amount: u64, from: u64) -> Bcs {
    b().uleb(2).uleb(0).u64(amount).uleb(0).raw(&sui_type().0).uleb(from)
}

fn gas() -> Bcs { b().uleb(0) }
fn input(i: u16) -> Bcs { b().uleb(1).u16(i) }
fn result(c: u16) -> Bcs { b().uleb(2).u16(c) }
fn nested(c: u16, n: u16) -> Bcs { b().uleb(3).u16(c).u16(n) }

fn transfer(objects: &[Bcs], to: Bcs) -> Bcs { b().uleb(1).many(objects).raw(&to.0) }
fn split(coin: Bcs, amounts: &[Bcs]) -> Bcs { b().uleb(2).raw(&coin.0).many(amounts) }
fn merge(into: Bcs, coins: &[Bcs]) -> Bcs { b().uleb(3).raw(&into.0).many(coins) }

/// A call of `module::function` in package `package` (32 bytes).
fn call(package: &[u8; 32], module: &str, function: &str, types: &[Bcs], args: &[Bcs]) -> Bcs {
    b().uleb(0).raw(package).bytes(module.as_bytes()).bytes(function.as_bytes()).many(types).many(args)
}

fn framework() -> [u8; 32] {
    let mut a = [0u8; 32];
    a[31] = 2;
    a
}

/// A transaction of this account's: these inputs and commands, its fee from coin 0x11 at 1000 MIST
/// a unit, up to 0.003 SUI, and no expiration.
#[derive(Clone)]
struct Tx {
    inputs: Vec<Bcs>,
    commands: Vec<Bcs>,
    sender: Address,
    payment: Vec<Bcs>,
    owner: Address,
    price: u64,
    budget: u64,
    expiration: Bcs,
}

fn tx(inputs: &[Bcs], commands: &[Bcs]) -> Tx {
    Tx {
        inputs: inputs.to_vec(),
        commands: commands.to_vec(),
        sender: me(),
        payment: vec![obj(0x11)],
        owner: me(),
        price: 1000,
        budget: 3_000_000,
        expiration: b().uleb(0),
    }
}

impl Tx {
    fn bytes(&self) -> Vec<u8> {
        b().uleb(0)
            .uleb(0)
            .many(&self.inputs)
            .many(&self.commands)
            .raw(&self.sender)
            .many(&self.payment)
            .raw(&self.owner)
            .u64(self.price)
            .u64(self.budget)
            .raw(&self.expiration.0)
            .0
    }
}

/// 1.5 SUI to the recipient, from the gas coin: as the library writes it.
fn send() -> Tx {
    let to = parse_address(RECIPIENT).unwrap();
    tx(
        &[pure(&1_500_000_000u64.to_le_bytes()), pure(&to)],
        &[split(gas(), &[input(0)]), transfer(&[result(0)], input(1))],
    )
}

fn refused(bytes: &[u8]) -> tx::Error { Transaction::parse(bytes).unwrap_err() }

fn invalid(bytes: &[u8]) -> String {
    match refused(bytes) {
        tx::Error::Invalid(why) => why.into(),
        e => panic!("{e:?}"),
    }
}

/// A ValidDuring expiration, on mainnet, for epochs `min` to `max`.
fn during(min: Option<u64>, max: Option<u64>) -> Bcs {
    let opt = |o: Option<u64>| match o {
        Some(n) => b().uleb(1).u64(n),
        None => b().uleb(0),
    };
    b().uleb(2).raw(&opt(min).0).raw(&opt(max).0).uleb(0).uleb(0).bytes(&Network::Mainnet.chain()).u32(7)
}

#[test]
fn bcs_as_sui_reads_it() {
    use tx::Error::*;
    let good = send().bytes();
    // written as the library writes it
    assert_eq!(good, fixture("sui"));
    // cut short, or with more after it
    assert_eq!(refused(&good[..good.len() - 1]), Encoding);
    assert_eq!(refused(&[good.clone(), vec![0]].concat()), Encoding);
    assert_eq!(refused(&[]), Encoding);
    assert_eq!(refused(&vec![0; tx::MAX_TX + 1]), TooBig);
    // a length not in its shortest form: two inputs written as 0x82 0x00
    let mut long = good.clone();
    long.splice(2..3, [0x82, 0x00]);
    assert_eq!(refused(&long), Encoding);
    // a length past what's there: 255 inputs, in what's left of 217 bytes
    let mut past = good.clone();
    past.splice(2..3, [0xff, 0x01]);
    assert_eq!(refused(&past), Encoding);
    // versions, kinds and variants maki doesn't know
    let mut v2 = good.clone();
    v2[0] = 1;
    assert_eq!(refused(&v2), Unknown("version of transaction data"));
    assert_eq!(refused(&v2).to_string(), "a version of transaction data maki doesn't know");
    let mut kind = good.clone();
    kind[1] = 11;
    assert_eq!(refused(&kind), Unknown("kind of transaction"));
    for (n, name) in [(1, "ChangeEpoch"), (5, "EndOfEpochTransaction"), (10, "ProgrammableSystemTransaction")]
    {
        let mut system = good.clone();
        system[1] = n;
        assert_eq!(refused(&system), System(name));
    }
    assert_eq!(
        System("Genesis").to_string(),
        "a system transaction (Genesis): only Sui's validators make those"
    );
    let with = |inputs: &[Bcs], commands: &[Bcs]| tx(inputs, commands).bytes();
    assert_eq!(refused(&with(&[b().uleb(3).uleb(0)], &[])), Unknown("kind of input"));
    assert_eq!(refused(&with(&[b().uleb(1).uleb(3)], &[])), Unknown("kind of object input"));
    assert_eq!(refused(&with(&[shared(0x42, 3)], &[])), Unknown("way of using a shared object"));
    assert_eq!(refused(&with(&[], &[b().uleb(7)])), Unknown("kind of command"));
    assert_eq!(refused(&with(&[], &[transfer(&[b().uleb(4)], gas())])), Unknown("kind of argument"));
    let mut expiring = send();
    expiring.expiration = b().uleb(4);
    assert_eq!(refused(&expiring.bytes()), Unknown("kind of expiration"));
    let strange = ty(0x44, "m", "T", &[b().uleb(11)]);
    assert_eq!(
        refused(&with(&[pure(&[1])], &[call(&[0x44; 32], "m", "f", &[strange], &[input(0)])])),
        Unknown("kind of Move type")
    );
    // a digest of 31 or 33 bytes
    let short = b().uleb(1).uleb(0).raw(&[0x21; 32]).u64(5).bytes(&[1; 31]);
    assert_eq!(refused(&with(&[short], &[])), Encoding);
    let mut long_digest = send();
    long_digest.payment = vec![b().raw(&[0x11; 32]).u64(5).bytes(&[1; 33])];
    assert_eq!(refused(&long_digest.bytes()), Encoding);
    // a bool or an option's tag that isn't 0 or 1
    let mut option = send();
    option.expiration = b().uleb(2).uleb(2);
    assert_eq!(refused(&option.bytes()), Encoding);
    // names that aren't UTF-8, or aren't Move's
    let call_named = |module: &[u8]| {
        let c = b().uleb(0).raw(&[0x44; 32]).bytes(module).bytes(b"f").uleb(0).uleb(0);
        with(&[], &[c])
    };
    assert_eq!(refused(&call_named(&[0xff, 0xfe])), Encoding);
    for bad in [&b"1st"[..], b"_", b"", b"caf\xc3\xa9", b"a-b"] {
        assert_eq!(
            refused(&call_named(bad)),
            Invalid("a Move name that isn't one: Sui would refuse it"),
            "{bad:?}"
        );
    }
    assert!(Transaction::parse(&call_named(b"_ok")).is_ok());
    assert!(Transaction::parse(&call_named(&[b'a'; 128])).is_ok());
    assert_eq!(
        refused(&call_named(&[b'a'; 129])),
        Invalid("a Move name longer than any Move has: Sui would refuse it")
    );
}

#[test]
fn transactions_sui_would_refuse_maki_refuses() {
    let with = |inputs: &[Bcs], commands: &[Bcs]| tx(inputs, commands).bytes();
    let to = || pure(&parse_address(RECIPIENT).unwrap());
    // arguments that aren't there: an input past the inputs, a result of this command or a later one
    assert_eq!(
        invalid(&with(&[to()], &[transfer(&[gas()], input(1))])),
        "an argument that isn't there: Sui would refuse it"
    );
    assert_eq!(
        invalid(&with(&[to()], &[transfer(&[result(0)], input(0))])),
        "an argument that isn't there: Sui would refuse it"
    );
    assert_eq!(
        invalid(&with(&[to()], &[transfer(&[nested(1, 0)], input(0))])),
        "an argument that isn't there: Sui would refuse it"
    );
    // commands given nothing
    let nothing = "a command given nothing to work on: Sui would refuse it";
    assert_eq!(invalid(&with(&[to()], &[transfer(&[], input(0))])), nothing);
    assert_eq!(invalid(&with(&[], &[split(gas(), &[])])), nothing);
    assert_eq!(invalid(&with(&[], &[merge(gas(), &[])])), nothing);
    assert_eq!(
        invalid(&with(&[], &[b().uleb(5).uleb(0).uleb(0)])),
        "an empty vector of no type: Sui would refuse it"
    );
    // too many type arguments, nested too deep
    let nest = |depth: usize| (1..depth).fold(b().uleb(1), |inner, _| b().uleb(6).raw(&inner.0));
    let typed = |types: &[Bcs]| with(&[], &[call(&[0x44; 32], "m", "f", types, &[])]);
    // a type 16 deep counts 16 types, which Sui refuses before it counts how deep; deeper, maki
    // stops reading
    assert!(Transaction::parse(&typed(&[nest(15)])).is_ok());
    assert_eq!(invalid(&typed(&[nest(16)])), "more type arguments than Sui takes in a call");
    assert_eq!(invalid(&typed(&[nest(17)])), "a type nested deeper than Sui takes");
    let fifteen: Vec<Bcs> = (0..15).map(|_| b().uleb(1)).collect();
    assert!(Transaction::parse(&typed(&fifteen)).is_ok());
    let sixteen: Vec<Bcs> = (0..16).map(|_| b().uleb(1)).collect();
    assert_eq!(invalid(&typed(&sixteen)), "more type arguments than Sui takes in a call");
    // an object named twice: two inputs, an input that pays the fee, one to receive that's an input
    let twice = "an object named twice: Sui would refuse it";
    assert_eq!(invalid(&with(&[owned(0x21), owned(0x21)], &[])), twice);
    assert_eq!(invalid(&with(&[owned(0x11)], &[])), twice);
    assert_eq!(invalid(&with(&[owned(0x21), receiving(0x21)], &[])), twice);
    assert_eq!(invalid(&with(&[shared(0x21, 1), owned(0x21)], &[])), twice);
    let mut paid_twice = send();
    paid_twice.payment = vec![obj(0x11), obj(0x11)];
    assert_eq!(invalid(&paid_twice.bytes()), twice);
    // a version none can be; a shared object written alongside others
    let at_max = b().uleb(1).uleb(0).raw(&[0x21; 32]).u64(tx::MAX_VERSION).bytes(&[1; 32]);
    assert_eq!(invalid(&with(&[at_max], &[])), "an object at a version none can be: Sui would refuse it");
    assert_eq!(
        invalid(&with(&[shared(0x42, 2)], &[])),
        "a shared object written alongside others: only Sui's own transactions may"
    );
    // withdrawals: of nothing, from the sponsor, too many
    assert_eq!(invalid(&with(&[withdrawal(0, 0)], &[])), "a withdrawal of nothing: Sui would refuse it");
    assert_eq!(
        invalid(&with(&[withdrawal(1, 1)], &[])),
        "a withdrawal from the sponsor's balance: Sui doesn't take those yet"
    );
    let ten: Vec<Bcs> = (0..10).map(|_| withdrawal(1, 0)).collect();
    assert!(Transaction::parse(&with(&ten, &[])).is_ok());
    let eleven: Vec<Bcs> = (0..11).map(|_| withdrawal(1, 0)).collect();
    assert_eq!(
        invalid(&with(&eleven, &[])),
        "more withdrawals from address balances than Sui takes in a transaction"
    );
    // a withdrawal of a type of more than 15 types (its Balance<T> counts one more)
    let wide = |params: usize| {
        let t = ty(0x44, "m", "T", &vec![b().uleb(1); params]);
        b().uleb(2).uleb(0).u64(1).uleb(0).raw(&t.0).uleb(0)
    };
    assert!(Transaction::parse(&with(&[wide(14)], &[])).is_ok());
    assert_eq!(invalid(&with(&[wide(15)], &[])), "a withdrawal of a type bigger than Sui takes");
    // a coin reservation of nothing
    let mut digest = [0xac; 32];
    digest[..12].copy_from_slice(&[0; 12]);
    let empty_reservation = b().uleb(1).uleb(0).raw(&[0x29; 32]).u64(0).bytes(&digest);
    assert_eq!(
        invalid(&with(&[empty_reservation], &[])),
        "a coin reservation of nothing: Sui would refuse it"
    );
    // randomness used, then a split
    let mut random = [0u8; 32];
    random[31] = 8;
    let random = b().uleb(1).uleb(1).raw(&random).u64(1).uleb(0);
    let draw = call(&[0x44; 32], "game", "draw", &[], &[input(0)]);
    assert!(
        Transaction::parse(&with(&[random.clone(), to()], &[draw.clone(), transfer(&[gas()], input(1))]))
            .is_ok()
    );
    assert_eq!(
        invalid(&with(&[random, pure(&[1; 8])], &[draw, split(gas(), &[input(1)])])),
        "a command after randomness is used, other than a send or a merge: Sui would refuse it"
    );
    // packages: none of their modules, more than five
    let publish = |modules: usize| b().uleb(4).many(&vec![b().bytes(&[1, 2, 3]); modules]).uleb(0);
    assert_eq!(invalid(&with(&[], &[publish(0)])), "a package of no modules: Sui would refuse it");
    assert!(Transaction::parse(&with(&[], &vec![publish(1); 5])).is_ok());
    assert_eq!(
        invalid(&with(&[], &vec![publish(1); 6])),
        "more packages published than Sui takes in a transaction"
    );
}

#[test]
fn gas_sui_would_refuse_maki_refuses() {
    let priced = |price: u64, budget: u64| {
        let mut t = send();
        (t.price, t.budget) = (price, budget);
        t.bytes()
    };
    assert!(Transaction::parse(&priced(1000, 1_000_000)).is_ok());
    assert_eq!(
        invalid(&priced(1000, 999_999)),
        "a gas budget too small for any transaction: Sui would refuse it"
    );
    assert_eq!(invalid(&priced(tx::MAX_GAS_PRICE, u64::MAX)), "a gas price higher than Sui takes");
    assert!(Transaction::parse(&priced(tx::MAX_GAS_PRICE - 1, tx::MAX_BUDGET)).is_ok());
    assert_eq!(invalid(&priced(1000, tx::MAX_BUDGET + 1)), "a gas budget bigger than Sui takes");
    assert_eq!(invalid(&priced(0, 0)), "no price for gas, when the fee is paid: Sui would refuse it");
    // from the address balance, with no price: gasless, and so no budget
    let mut gasless = send();
    (gasless.payment, gasless.price, gasless.budget, gasless.expiration) =
        (vec![], 0, 1, during(Some(1), Some(2)));
    assert_eq!(invalid(&gasless.bytes()), "a gasless transaction with a budget for gas: Sui would refuse it");
    // a sponsor's fee paid by a coin reservation, which draws on the sender's own balance
    let mut reserved = [0xac; 32];
    reserved[..8].copy_from_slice(&5u64.to_le_bytes());
    let mut sponsored = send();
    sponsored.payment = vec![b().raw(&[0x29; 32]).u64(0).bytes(&reserved)];
    sponsored.owner = [9; 32];
    assert_eq!(
        invalid(&sponsored.bytes()),
        "a sponsor's fee paid by a coin reservation: Sui would refuse it"
    );
}

#[test]
fn expirations_sui_would_refuse_maki_refuses() {
    let expiring = |e: Bcs, payment: Vec<Bcs>| {
        let mut t = send();
        (t.expiration, t.payment) = (e, payment);
        t.bytes()
    };
    // paid from the address balance, with nothing else to keep it from being sent twice
    let again = "nothing keeps it from being sent twice: Sui would refuse it";
    assert_eq!(invalid(&expiring(b().uleb(0), vec![])), again);
    assert_eq!(invalid(&expiring(b().uleb(1).u64(9), vec![])), again);
    assert_eq!(invalid(&expiring(during(Some(5), Some(7)), vec![])), again);
    assert_eq!(invalid(&expiring(during(None, Some(7)), vec![])), again);
    assert!(Transaction::parse(&expiring(during(Some(5), Some(6)), vec![])).is_ok());
    assert!(Transaction::parse(&expiring(during(Some(5), Some(5)), vec![])).is_ok());
    // with coins for the fee, any window will do
    assert!(Transaction::parse(&expiring(during(None, None), vec![obj(0x11)])).is_ok());
    // a time limit by the clock
    let clocked = b().uleb(2).uleb(0).uleb(0).uleb(1).u64(5).uleb(0).bytes(&Network::Mainnet.chain()).u32(7);
    assert_eq!(
        invalid(&expiring(clocked, vec![obj(0x11)])),
        "a time limit by the clock: Sui doesn't take those yet"
    );
    // validators named to propose it: none (which isn't a set), out of order
    let proposers = |p: &[u32]| {
        let mut list = b().uleb(p.len() as u64);
        for n in p {
            list = list.u32(*n);
        }
        let during = during(Some(5), Some(6));
        b().uleb(3).raw(&during.0[1..]).uleb(1).u64(5).raw(&list.0)
    };
    assert!(Transaction::parse(&expiring(proposers(&[1, 4]), vec![])).is_ok());
    assert_eq!(refused(&expiring(proposers(&[]), vec![])), tx::Error::Encoding);
    assert_eq!(
        invalid(&expiring(proposers(&[4, 1]), vec![])),
        "validators named to propose it out of order: Sui would refuse it"
    );
    assert_eq!(
        invalid(&expiring(proposers(&[4, 4]), vec![])),
        "validators named to propose it out of order: Sui would refuse it"
    );
}

#[test]
fn gasless_only_as_sui_lets_it_go() {
    let to = || pure(&parse_address(RECIPIENT).unwrap());
    let free = |inputs: &[Bcs], commands: &[Bcs]| {
        let mut t = tx(inputs, commands);
        (t.payment, t.price, t.budget, t.expiration) = (vec![], 0, 0, during(Some(1268), Some(1269)));
        t.bytes()
    };
    let redeem = call(&framework(), "balance", "redeem_funds", &[sui_type()], &[input(0)]);
    let send_funds = call(&framework(), "balance", "send_funds", &[sui_type()], &[nested(0, 0), input(1)]);
    let good = free(&[withdrawal(5, 0), to()], &[redeem.clone(), send_funds.clone()]);
    let r = review(&Transaction::parse(&good).unwrap(), &me(), Network::Mainnet).unwrap();
    assert_eq!(r.summary, "sends 0.000000005 SUI; no fee");
    let not_free = "a gasless transaction calling a function Sui doesn't let go free";
    let other = call(&[0x44; 32], "m", "f", &[sui_type()], &[nested(0, 0), input(1)]);
    assert_eq!(invalid(&free(&[withdrawal(5, 0), to()], &[redeem.clone(), other])), not_free);
    let transfer_too = transfer(&[nested(0, 0)], input(1));
    assert_eq!(
        invalid(&free(&[withdrawal(5, 0), to()], &[redeem.clone(), transfer_too])),
        "a gasless transaction doing what Sui doesn't let go free"
    );
    assert_eq!(invalid(&free(&[], &[])), "a gasless transaction that does nothing: Sui would refuse it");
    assert_eq!(
        invalid(&free(&[withdrawal(5, 0), to(), owned(0x21)], &[redeem.clone(), send_funds.clone()])),
        "a gasless transaction with an object it doesn't use: Sui would refuse it"
    );
    assert_eq!(
        invalid(&free(&[withdrawal(5, 0), to(), pure(&[0; 33])], &[redeem.clone(), send_funds.clone()])),
        "a gasless transaction with an input longer than Sui lets go free"
    );
    assert_eq!(
        invalid(&free(
            &[withdrawal(5, 0), to(), pure(&[1]), pure(&[2])],
            &[redeem.clone(), send_funds.clone()]
        )),
        "a gasless transaction with inputs it doesn't use: Sui would refuse it"
    );
    assert_eq!(
        invalid(&free(&[withdrawal(5, 0), to(), receiving(0x35)], &[redeem, send_funds])),
        "a gasless transaction receiving an object: Sui would refuse it"
    );
}

/// The review of a transaction written by hand, or why it's refused.
fn reviewed(t: &Tx) -> Result<Review, String> {
    let tx = Transaction::parse(&t.bytes()).map_err(|e| e.to_string())?;
    review(&tx, &me(), Network::Mainnet).map_err(|e| e.to_string())
}

#[test]
fn what_would_fail_maki_refuses_before_showing() {
    let to = || pure(&parse_address(RECIPIENT).unwrap());
    let amount = |n: u64| pure(&n.to_le_bytes());
    let cant = Err(String::from("a command given what it can't take: Sui would refuse it"));
    // more split off a withdrawal's coin than it holds
    let redeem = call(&framework(), "coin", "redeem_funds", &[sui_type()], &[input(0)]);
    let t = tx(
        &[withdrawal(5, 0), amount(6), to()],
        &[redeem.clone(), split(result(0), &[input(1)]), transfer(&[nested(1, 0)], input(2))],
    );
    assert_eq!(reviewed(&t), Err("more split off a coin than it holds: Sui would refuse it".into()));
    // the gas coin merged into another, or sent twice
    let t = tx(&[owned(0x21)], &[merge(input(0), &[gas()])]);
    assert_eq!(reviewed(&t), Err("the gas coin used up, other than to be sent: Sui would refuse it".into()));
    let t = tx(&[to()], &[transfer(&[gas(), gas()], input(0))]);
    assert_eq!(reviewed(&t), Err("a coin used after it's used up: Sui would refuse it".into()));
    // a balance sent as an object: it isn't one
    let balance = call(&framework(), "balance", "redeem_funds", &[sui_type()], &[input(0)]);
    let t = tx(&[withdrawal(5, 0), to()], &[balance, transfer(&[nested(0, 0)], input(1))]);
    assert_eq!(reviewed(&t), cant);
    // a coin named as two kinds of coin
    let usdc = ty(0xdb, "usdc", "USDC", &[]);
    let t = tx(
        &[owned(0x21), to()],
        &[
            call(&framework(), "coin", "value", &[sui_type()], &[input(0)]),
            call(&framework(), "coin", "send_funds", &[usdc], &[input(0), input(1)]),
        ],
    );
    assert_eq!(reviewed(&t), Err("one coin used as two kinds of coin: Sui would refuse it".into()));
    // a recipient that isn't 32 bytes; an amount that isn't 8
    let t = tx(&[amount(1), pure(&[7; 31])], &[split(gas(), &[input(0)]), transfer(&[result(0)], input(1))]);
    assert_eq!(reviewed(&t), cant);
    let t = tx(&[pure(&[1; 7]), to()], &[split(gas(), &[input(0)]), transfer(&[result(0)], input(1))]);
    assert_eq!(reviewed(&t), cant);
    // all of what a command gave back, when it gave back two coins
    let t = tx(
        &[amount(1), amount(2), to()],
        &[split(gas(), &[input(0), input(1)]), transfer(&[result(0)], input(2))],
    );
    assert_eq!(reviewed(&t), cant);
    // a coin that isn't empty, destroyed
    let t = tx(
        &[withdrawal(5, 0)],
        &[redeem, call(&framework(), "coin", "destroy_zero", &[sui_type()], &[result(0)])],
    );
    assert_eq!(reviewed(&t), Err("a coin that isn't empty destroyed: Sui would refuse it".into()));
    // a shared object, sent; bytes split as a coin
    let t = tx(&[shared(0x42, 1), to()], &[transfer(&[input(0)], input(1))]);
    assert_eq!(reviewed(&t), cant);
    let t = tx(&[pure(&[1; 8])], &[split(input(0), &[input(0)])]);
    assert_eq!(reviewed(&t), cant);
}

#[test]
fn what_the_framework_does_maki_follows() {
    let to = || pure(&parse_address(RECIPIENT).unwrap());
    let amount = |n: u64| pure(&n.to_le_bytes());
    let fw = framework();
    // a coin split, joined and sent by the framework's own functions
    let t = tx(
        &[owned(0x21), amount(250), owned(0x22), to()],
        &[
            call(&fw, "coin", "join", &[sui_type()], &[input(0), input(2)]),
            call(&fw, "coin", "split", &[sui_type()], &[input(0), input(1)]),
            call(
                &fw,
                "transfer",
                "public_transfer",
                &[ty(2, "coin", "Coin", &[sui_type()])],
                &[result(1), input(3)],
            ),
        ],
    );
    let r = reviewed(&t).unwrap();
    assert_eq!(r.pages[2], p("Send", "0.00000025 SUI", RECIPIENT, &format!("From coin {}.", id(0x21))));
    assert_eq!(r.summary, "sends 0.00000025 SUI; fee up to 0.003 SUI");
    // a withdrawal split, and its part redeemed and sent into an address balance
    let mut part = [0u8; 32];
    part[0] = 40;
    let balance_type = b().uleb(7).raw(&fw).bytes(b"balance").bytes(b"Balance").many(&[sui_type()]);
    let t = tx(
        &[withdrawal(100, 0), pure(&part), to()],
        &[
            call(&fw, "funds_accumulator", "withdrawal_split", &[balance_type], &[input(0), input(1)]),
            call(&fw, "balance", "redeem_funds", &[sui_type()], &[result(0)]),
            call(&fw, "balance", "send_funds", &[sui_type()], &[result(1), input(2)]),
        ],
    );
    let r = reviewed(&t).unwrap();
    assert_eq!(
        r.pages[1],
        p("Send", "0.00000004 SUI", RECIPIENT, "From this account's address balance, into theirs.")
    );
    // a zero coin, kept
    let t = tx(&[to()], &[call(&fw, "coin", "zero", &[sui_type()], &[]), transfer(&[result(0)], input(0))]);
    assert_eq!(reviewed(&t).unwrap().pages[1], p("Send", "0 SUI", RECIPIENT, ""));
    // a balance put into a coin by `put`, and taken out again by `take`
    let t = tx(
        &[withdrawal(9, 0), owned(0x21), amount(4), to()],
        &[
            call(&fw, "balance", "redeem_funds", &[sui_type()], &[input(0)]),
            call(&fw, "coin", "put", &[sui_type()], &[result(0), input(1)]),
            call(&fw, "coin", "take", &[sui_type()], &[result(0), input(2)]),
            transfer(&[result(2)], input(3)),
        ],
    );
    let r = reviewed(&t).unwrap();
    assert_eq!(r.pages[1].heading, "Merge");
    assert_eq!(r.pages[2], p("Send", "0.000000004 SUI", RECIPIENT, "From this account's address balance."));
}

#[test]
fn too_much_to_show_is_refused() {
    // 127 payments of a coin each, and the network and the fee: more pages than maki's screen takes
    let to = pure(&parse_address(RECIPIENT).unwrap());
    let amounts: Vec<Bcs> = (0..127).map(|_| input(1)).collect();
    let coins: Vec<Bcs> = (0..127).map(|n| nested(0, n)).collect();
    let t = tx(&[to, pure(&1u64.to_le_bytes())], &[split(gas(), &amounts), transfer(&coins, input(0))]);
    assert_eq!(reviewed(&t), Err("too much to show on maki's screen".into()));
}

#[test]
fn rarer_shapes_said_as_they_are() {
    let to = || pure(&parse_address(RECIPIENT).unwrap());
    let unknown = call(&[0x44; 32], "m", "f", &[], &[]);
    // a call given nothing of this account's
    let r = reviewed(&tx(&[], std::slice::from_ref(&unknown))).unwrap();
    assert_eq!(
        r.pages[1].prose,
        "maki can't tell what it does. It acts as this account, and is given nothing: it may do whatever a shared object's code lets this account do."
    );
    // an amount a call works out, to an address another works out
    let t = tx(
        &[],
        &[unknown.clone(), unknown.clone(), split(gas(), &[result(0)]), transfer(&[result(2)], result(1))],
    );
    let r = reviewed(&t).unwrap();
    assert_eq!(
        r.pages[3],
        p(
            "Send",
            "maki can't tell",
            &format!("an address the 2nd command (0x{}::m::f) works out: maki can't see it", &id(0x44)[2..]),
            "maki can't tell how much: a call works it out, or may have taken some of it."
        )
    );
    assert_eq!(r.summary, "maki can't read all of it; fee up to 0.003 SUI");
    // the whole gas coin, when the fee comes from the address balance: what's set aside for it
    let mut t = tx(&[to()], &[transfer(&[gas()], input(0))]);
    (t.payment, t.expiration) = (vec![], during(Some(1268), Some(1269)));
    let r = reviewed(&t).unwrap();
    assert_eq!(
        r.pages[1],
        p(
            "Send",
            "the whole gas coin",
            RECIPIENT,
            "What it sets aside for the fee from this account's address balance (0.003 SUI), less the fee."
        )
    );
    // the gas coin sent whole after a coin's split off it: what's left of it
    let t = tx(
        &[pure(&1_000_000_000u64.to_le_bytes()), to(), pure(&parse_address(SECOND).unwrap())],
        &[split(gas(), &[input(0)]), transfer(&[result(0)], input(1)), transfer(&[gas()], input(2))],
    );
    let r = reviewed(&t).unwrap();
    assert_eq!(
        r.pages[1..3],
        [
            p("Send", "1 SUI", RECIPIENT, ""),
            p("Send", "the whole gas coin", SECOND, "All the SUI left in this account's coin, less the fee."),
        ]
    );
    assert_eq!(r.summary, "2 payments; fee up to 0.003 SUI");
    // a coin split off and kept: nothing leaves
    let mine = pure(&me());
    let r = reviewed(&tx(
        &[pure(&1u64.to_le_bytes()), mine],
        &[split(gas(), &[input(0)]), transfer(&[result(0)], input(1))],
    ))
    .unwrap();
    assert_eq!(r.pages[1], p("Send", "0.000000001 SUI", "this account", ""));
    assert_eq!(r.summary, "moves coins within this account; fee up to 0.003 SUI");
}
