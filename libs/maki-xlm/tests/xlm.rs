//! maki-xlm against Stellar's own library and specifications: transactions @stellar/stellar-sdk
//! made (`fixtures/make.mjs`), read as they are, hashed as stellar-sdk hashes them, shown as they
//! should be, and signed by maki's keys as stellar-sdk signs them with the same account (the test
//! phrase's first, as SEP-5 derives it); SEP-5's own accounts for its phrases, and SEP-23's
//! StrKeys, valid and not.

use maki_hd::seed::SeedKeys;
use maki_xlm::display::{self, Error, Page, Review, review};
use maki_xlm::transaction::{self, Asset, Code, Envelope, Kind, MAX_ENVELOPE, pool_id};
use maki_xlm::{Key, Network, address, soroban, strkey};

const ME: &str = "GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX";
const RECIPIENT: &str = "GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR";
const SIGNER: &str = "GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U";
const SERVICE: &str = "GDWUSKGGFDI4FRXK5EBTRECZSVQSSWJHHJOGH6JWG3AUMFFMQ435DIAG";
const CREATED: &str = "GDFJHLAXAUMHA4OWPOB4P7YO72AQR2HMIUYFOXLXE2DZGM633K7HZDQP";
const ISSUER: &str = "GBXHUHG5FGYLPD6RHL2MKWMP572O6KUXCZXDZJXS4T57ZTMAKBN7DWXN";
const USDC: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
const EURC: &str = "GDHU6WRG4IEQXM5NZ4BMPKOXHW76MZM4Y2IEMFDVXBSDP6SJY4ITNPP2";
const TEST_USDC: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
const BALANCE: &str = "BAANUDKX3J6UQUHH7QINFKOQ5PDTD55PWQCXJQBTSWYX2SIUTOI7LPQEI4";
const POOL: &str = "LCSGRVA5R2NY6PDSBFSRMCFXJN63PLEZKLOK4DG7ESDR2HM4PMAIQQUG";
const USDC_CONTRACT: &str = "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75";

fn key(text: &str) -> Key { strkey::decode_account(text).unwrap() }

fn me() -> Key { key(ME) }

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

/// A transaction stellar-sdk made: its name, network, envelope, the hash stellar-sdk signs, and
/// its signature with this account.
struct Fixture {
    name: String,
    network: Network,
    envelope: Vec<u8>,
    hash: Vec<u8>,
    signature: Vec<u8>,
}

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
            network: Network::from_byte(f["network"].as_u64().unwrap() as u8).unwrap(),
            envelope: unhex(f["envelope"].as_str().unwrap()),
            hash: unhex(f["hash"].as_str().unwrap()),
            signature: unhex(f["signature"].as_str().unwrap()),
        })
        .collect()
}

fn fixture(name: &str, network: Network) -> Vec<u8> {
    fixtures().into_iter().find(|f| f.name == name && f.network == network).unwrap().envelope
}

fn p(heading: &str, value: &str, mono: &str, prose: &str) -> Page {
    Page { heading: heading.into(), value: value.into(), mono: mono.into(), prose: prose.into() }
}

fn shown_on(name: &str, network: Network) -> Review {
    review(&Envelope::parse(&fixture(name, network)).unwrap(), &me(), network).unwrap()
}

fn shown(name: &str) -> Review { shown_on(name, Network::Public) }

/// The pages every one of this account's transactions ends with, but the fee's: until 2027, and
/// from this account.
fn until() -> Page { p("Valid until", "2027-01-01 00:00:00 UTC", "", "After that, it can't go through.") }

fn from_me(network: Network) -> Page {
    let on = match network {
        Network::Public => "On Stellar's public network; its sequence number is 123456789013.",
        Network::Test => "On Stellar's test network; its sequence number is 123456789013.",
    };
    p("From", "this account", ME, on)
}

fn fee(value: &str, prose: &str) -> Page { p("Max fee", value, "", prose) }

/// What Stellar refuses that stellar-sdk builds anyway, and what isn't this account's to sign.
const REFUSED: &[&str] = &["inflation", "revoke-pool"];
const NOT_MINE: &[&str] = &["not-mine", "fee-bump-theirs"];

#[test]
fn sep5_accounts_and_sep23_strkeys() {
    // SEP-5's test vectors: each phrase's first ten accounts, at m/44'/148'/i'
    let vectors: [(&str, &str, [&str; 10]); 5] = [
        (
            "illness spike retreat truth genius clock brain pass fit cave bargain toe",
            "",
            [
                "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6",
                "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX",
                "GAY5PRAHJ2HIYBYCLZXTHID6SPVELOOYH2LBPH3LD4RUMXUW3DOYTLXW",
                "GAOD5NRAEORFE34G5D4EOSKIJB6V4Z2FGPBCJNQI6MNICVITE6CSYIAE",
                "GBCUXLFLSL2JE3NWLHAWXQZN6SQC6577YMAU3M3BEMWKYPFWXBSRCWV4",
                "GBRQY5JFN5UBG5PGOSUOL4M6D7VRMAYU6WW2ZWXBMCKB7GPT3YCBU2XZ",
                "GBY27SJVFEWR3DUACNBSMJB6T4ZPR4C7ZXSTHT6GMZUDL23LAM5S2PQX",
                "GAY7T23Z34DWLSTEAUKVBPHHBUE4E3EMZBAQSLV6ZHS764U3TKUSNJOF",
                "GDJTCF62UUYSAFAVIXHPRBR4AUZV6NYJR75INVDXLLRZLZQ62S44443R",
                "GBTVYYDIYWGUQUTKX6ZMLGSZGMTESJYJKJWAATGZGITA25ZB6T5REF44",
            ],
        ),
        (
            "resource asthma orphan phone ice canvas fire useful arch jewel impose vague theory cushion top",
            "",
            [
                "GAVXVW5MCK7Q66RIBWZZKZEDQTRXWCZUP4DIIFXCCENGW2P6W4OA34RH",
                "GDFCYVCICATX5YPJUDS22KM2GW5QU2KKSPPPT2IC5AQIU6TP3BZSLR5K",
                "GAUA3XK3SGEQFNCBM423WIM5WCZ4CR4ZDPDFCYSFLCTODGGGJMPOHAAE",
                "GAH3S77QXTAPZ77REY6LGFIJ2XWVXFOKXHCFLA6HQTL3POLVZJDHHUDM",
                "GCSCZVGV2Y3EQ2RATJ7TE6PVWTW5OH5SMG754AF6W6YM3KJF7RMNPB4Y",
                "GDKWYAJE3W6PWCXDZNMFNFQSPTF6BUDANE6OVRYMJKBYNGL62VKKCNCC",
                "GCDTVB4XDLNX22HI5GUWHBXJFBCPB6JNU6ZON7E57FA3LFURS74CWDJH",
                "GBTDPL5S4IOUQHDLCZ7I2UXJ2TEHO6DYIQ3F2P5OOP3IS7JSJI4UMHQJ",
                "GD3KWA24OIM7V3MZKDAVSLN3NBHGKVURNJ72ZCTAJSDTF7RIGFXPW5FQ",
                "GB3C6RRQB3V7EPDXEDJCMTS45LVDLSZQ46PTIGKZUY37DXXEOAKJIWSV",
            ],
        ),
        (
            "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better",
            "",
            [
                "GC3MMSXBWHL6CPOAVERSJITX7BH76YU252WGLUOM5CJX3E7UCYZBTPJQ",
                "GB3MTYFXPBZBUINVG72XR7AQ6P2I32CYSXWNRKJ2PV5H5C7EAM5YYISO",
                "GDYF7GIHS2TRGJ5WW4MZ4ELIUIBINRNYPPAWVQBPLAZXC2JRDI4DGAKU",
                "GAFLH7DGM3VXFVUID7JUKSGOYG52ZRAQPZHQASVCEQERYC5I4PPJUWBD",
                "GAXG3LWEXWCAWUABRO6SMAEUKJXLB5BBX6J2KMHFRIWKAMDJKCFGS3NN",
                "GA6RUD4DZ2NEMAQY4VZJ4C6K6VSEYEJITNSLUQKLCFHJ2JOGC5UCGCFQ",
                "GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS",
                "GBJ646Q524WGBN5X5NOAPIF5VQCR2WZCN6QZIDOSY6VA2PMHJ2X636G4",
                "GDHX4LU6YBSXGYTR7SX2P4ZYZSN24VXNJBVAFOB2GEBKNN3I54IYSRM4",
                "GDXOY6HXPIDT2QD352CH7VWX257PHVFR72COWQ74QE3TEV4PK2KCKZX7",
            ],
        ),
        (
            "cable spray genius state float twenty onion head street palace net private method loan turn phrase state blanket interest dry amazing dress blast tube",
            "p4ssphr4se",
            [
                "GDAHPZ2NSYIIHZXM56Y36SBVTV5QKFIZGYMMBHOU53ETUSWTP62B63EQ",
                "GDY47CJARRHHL66JH3RJURDYXAMIQ5DMXZLP3TDAUJ6IN2GUOFX4OJOC",
                "GCLAQF5H5LGJ2A6ACOMNEHSWYDJ3VKVBUBHDWFGRBEPAVZ56L4D7JJID",
                "GBC36J4KG7ZSIQ5UOSJFQNUP4IBRN6LVUFAHQWT2ODEQ7Y3ASWC5ZN3B",
                "GA6NHA4KPH5LFYD6LZH35SIX3DU5CWU3GX6GCKPJPPTQCCQPP627E3CB",
                "GBOWMXTLABFNEWO34UJNSJJNVEF6ESLCNNS36S5SX46UZT2MNYJOLA5L",
                "GBL3F5JUZN3SQKZ7SL4XSXEJI2SNSVGO6WZWNJLG666WOJHNDDLEXTSZ",
                "GA5XPPWXL22HFFL5K5CE37CEPUHXYGSP3NNWGM6IK6K4C3EFHZFKSAND",
                "GDS5I7L7LWFUVSYVAOHXJET2565MGGHJ4VHGVJXIKVKNO5D4JWXIZ3XU",
                "GBOSMFQYKWFDHJWCMCZSMGUMWCZOM4KFMXXS64INDHVCJ2A2JAABCYRR",
            ],
        ),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
            [
                ME,
                "GDVSYYTUAJ3ACHTPQNSTQBDQ4LDHQCMNY4FCEQH5TJUMSSLWQSTG42MV",
                "GBFPWBTN4AXHPWPTQVQBP4KRZ2YVYYOGRMV2PEYL2OBPPJDP7LECEVHR",
                "GCCCOWAKYVFY5M6SYHOW33TSNC7Z5IBRUEU2XQVVT34CIZU7CXZ4OQ4O",
                "GCQ3J35MKPKJX7JDXRHC5YTXTULFMCBMZ5IC63EDR66QA3LO7264ZL7Q",
                "GDTA7622ZA5PW7F7JL7NOEFGW62M7GW2GY764EQC2TUJ42YJQE2A3QUL",
                "GD7A7EACTPTBCYCURD43IEZXGIBCEXNBHN3OFWV2FOX67XKUIGRCTBNU",
                "GAF4AGPVLQXFKEWQV3DZU5YEFU6YP7XJHAEEQH4G3R664MSF77FLLRK3",
                "GABTYCZJMCP55SS6I46SR76IHETZDLG4L37MLZRZKQDGBLS5RMP65TSX",
                "GAKFARYSPI33KUJE7HYLT47DCX2PFWJ77W3LZMRBPSGPGYPMSDBE7W7X",
            ],
        ),
    ];
    for (phrase, passphrase, accounts) in vectors {
        let seed = maki_seed::seed(&phrase.split(' ').collect::<Vec<_>>(), passphrase);
        let keys = SeedKeys::from_seed(&seed).unwrap();
        for (i, expected) in accounts.iter().enumerate() {
            let path = maki_hd::parse_path(&format!("m/44'/148'/{i}'")).unwrap();
            assert_eq!(address(&keys.ed25519_public(&path).unwrap()), *expected, "{phrase}: account {i}");
        }
    }
    // SEP-23's valid StrKeys, each read and written back
    let k = key("GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ");
    assert_eq!(k[..4], [0x3f, 0x0c, 0x34, 0xbf]);
    assert_eq!(
        strkey::decode_muxed("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ"),
        Some((k, 0))
    );
    assert_eq!(
        strkey::decode_muxed("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK"),
        Some((k, 9223372036854775808))
    );
    assert_eq!(
        strkey::muxed(&k, 9223372036854775808),
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK"
    );
    let payload: Vec<u8> = (1..=32).collect();
    assert_eq!(
        strkey::signed_payload(&k, &payload),
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IBZGM"
    );
    assert_eq!(
        strkey::signed_payload(&k, &payload[..29]),
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUAAAAFGBU"
    );
    assert_eq!(strkey::contract(&k), "CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA");
    assert_eq!(strkey::liquidity_pool(&k), "LA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUPJN");
    assert_eq!(strkey::claimable_balance(&k), "BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGR4TU");
    for valid in [
        "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ",
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ",
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK",
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IBZGM",
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUAAAAFGBU",
        "CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA",
        "LA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUPJN",
        "BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGR4TU",
    ] {
        let (kind, payload) = strkey::decode(valid).unwrap_or_else(|| panic!("{valid}"));
        assert_eq!(strkey::encode(kind, &payload), valid);
    }
    // and SEP-23's invalid ones refused, every one
    for invalid in [
        "GAAAAAAAACGC6",
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUR",
        "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZA",
        "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUACUSI",
        "G47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVP2I",
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLKA",
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAAV75I",
        "M47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ",
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUK===",
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUO",
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IAAAAAAAAPM",
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4Z2PQ",
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DXFH6",
        "BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGR4TV",
        "BAAT6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGXACA",
    ] {
        assert_eq!(strkey::decode(invalid), None, "{invalid}");
    }
    // nor in lower case, nor a secret key, which maki never reads
    assert_eq!(strkey::decode(&ME.to_lowercase()), None);
    assert_eq!(strkey::decode("SBUV3MRWKNS6AYKZ6E6MOUVF2OYMON3MIUASWL3JLY5E3ISDJFELYBRZ"), None);
    assert_eq!(
        strkey::decode_account("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ"),
        None
    );
    assert_eq!(strkey::account_key(ME), me());
}

#[test]
fn networks_amounts_dates_and_prices() {
    let hex = |h: [u8; 32]| h.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(hex(Network::Public.id()), "7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979");
    assert_eq!(hex(Network::Test.id()), "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472");
    assert_eq!(
        (Network::from_byte(0), Network::from_byte(1), Network::from_byte(2)),
        (Some(Network::Public), Some(Network::Test), None)
    );
    assert_eq!(display::amount(125_000_000), "12.5");
    assert_eq!(display::amount(1), "0.0000001");
    assert_eq!(display::amount(i64::MAX), "922337203685.4775807");
    assert_eq!(display::amount(-5), "-0.0000005");
    assert_eq!(display::xlm(100), "0.00001 XLM");
    assert_eq!(display::decimals(0, 7), "0");
    assert_eq!(display::date(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(display::date(1_798_761_600), "2027-01-01 00:00:00 UTC");
    assert_eq!(display::date(951_825_600), "2000-02-29 12:00:00 UTC");
    assert_eq!(display::date(u64::MAX), "584554051223-11-09 07:00:15 UTC");
    assert_eq!(display::duration(86_400), "1 day");
    assert_eq!(display::duration(90_061), "1 day, 1 hour, 1 minute, 1 second");
    assert_eq!(display::duration(0), "0 seconds");
    let price = |n, d| display::price(&transaction::Price { n, d });
    assert_eq!(price(11, 100), "0.11");
    assert_eq!(price(19, 2), "9.5");
    assert_eq!(price(1, 3), "1/3");
    assert_eq!(price(6, 4), "1.5");
    assert_eq!(price(1, 1024), "0.0009765625");
    assert_eq!(price(i32::MAX, 1 << 30), "2147483647/1073741824");
    assert_eq!(price(1, i32::MAX), "1/2147483647");
    // a liquidity pool's ID and a Stellar asset's contract, as stellar-sdk makes them
    let usdc = Asset::Credit { code: Code::from_text("USDC").unwrap(), issuer: key(USDC) };
    assert_eq!(strkey::liquidity_pool(&pool_id(&Asset::Native, &usdc, 30)), POOL);
    assert_eq!(strkey::contract(&soroban::asset_contract(&usdc, Network::Public)), USDC_CONTRACT);
    assert_eq!(
        strkey::contract(&soroban::asset_contract(&usdc, Network::Test)),
        "CA2E53VHFZ6YSWQIEIPBXJQGT6VW3VKWWZO555XKRQXYJ63GEBJJGHY7"
    );
    assert_eq!(
        strkey::contract(&soroban::asset_contract(&Asset::Native, Network::Public)),
        "CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA"
    );
    // asset codes as Stellar allows them
    assert_eq!(Code::from_text("USDC").unwrap().as_str(), "USDC");
    assert_eq!(Code::from_text("LONGNAME123").unwrap().as_str(), "LONGNAME123");
    for bad in ["", "US D", "USDC\0", "ÜSDC", "THIRTEENCHARS"] {
        assert_eq!(Code::from_text(bad), None, "{bad:?}");
    }
}

#[test]
fn maki_signs_what_stellar_sdk_signs() {
    let seed = maki_seed::seed(
        &"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' ')
            .collect::<Vec<_>>(),
        "",
    );
    let keys = SeedKeys::from_seed(&seed).unwrap();
    let account = maki_hd::parse_path("m/44'/148'/0'").unwrap();
    assert_eq!(keys.ed25519_public(&account).unwrap(), me());
    let mut signed = 0;
    for f in fixtures() {
        let parsed = Envelope::parse(&f.envelope);
        if REFUSED.contains(&f.name.as_str()) {
            assert!(matches!(parsed, Err(transaction::Error::Invalid(_))), "{}: {parsed:?}", f.name);
            continue;
        }
        let envelope = parsed.unwrap_or_else(|e| panic!("{}: {e}", f.name));
        // the hash stellar-sdk signs (what's hashed: the network's ID, then the rest), and the
        // signature it makes of it
        let hash = envelope.hash(f.network);
        assert_eq!(hash.to_vec(), f.hash, "{}", f.name);
        let base = envelope.signature_base(f.network);
        assert_eq!(base[..32], Network::id(f.network), "{}", f.name);
        assert_eq!(keys.sign_ed25519(&account, &hash).unwrap().to_vec(), f.signature, "{}", f.name);
        let shown = review(&envelope, &me(), f.network);
        if NOT_MINE.contains(&f.name.as_str()) {
            assert_eq!(shown, Err(Error::NotMine), "{}", f.name);
        } else {
            let r = shown.unwrap_or_else(|e| panic!("{}: {e}", f.name));
            assert!(r.summary.len() <= display::MAX_SUMMARY, "{}", f.name);
            for page in &r.pages {
                assert!(page.heading.len() <= 32 && page.value.len() <= 128, "{}: {page:?}", f.name);
                assert!(!page.value.contains('\n') && !page.heading.contains('\n'), "{}: {page:?}", f.name);
            }
            signed += 1;
        }
    }
    let mut kinds: Vec<String> = fixtures().into_iter().map(|f| f.name).collect();
    kinds.sort();
    kinds.dedup();
    assert_eq!(signed, 2 * (kinds.len() - REFUSED.len() - NOT_MINE.len()));
    // the same transaction signed for the other network signs another hash
    let payment = Envelope::parse(&fixture("payment", Network::Public)).unwrap();
    assert_ne!(payment.hash(Network::Public), payment.hash(Network::Test));
    // version 0 signs as version 1 does: the same transaction, a source's key type before it
    let v0 = Envelope::parse(&fixture("v0", Network::Public)).unwrap();
    assert_eq!(v0.kind, Kind::V0);
}

#[test]
fn payments_and_their_recipients() {
    let r = shown("payment");
    assert_eq!(
        r.pages,
        [
            p("Send", "12.5 XLM", RECIPIENT, ""),
            p(
                "Memo",
                "",
                "thanks for the coffee",
                "Everyone can read it, on chain. An exchange may need it to know the payment is yours."
            ),
            until(),
            fee("0.00001 XLM", "The most it can cost, for its operation."),
            from_me(Network::Public)
        ]
    );
    assert_eq!(r.summary, "sends 12.5 XLM; fee up to 0.00001 XLM");
    let r = shown_on("payment", Network::Test);
    assert_eq!(r.pages.last().unwrap(), &from_me(Network::Test));
    assert_eq!(r.summary, "testnet: sends 12.5 XLM; fee up to 0.00001 XLM");
    // an account with an ID: as such, and the account it is
    let r = shown("muxed");
    assert_eq!(
        r.pages[0],
        p(
            "Send",
            "100 XLM",
            &format!(
                "MCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYAAAAAAAAAAAFKQTI\nwhich is account\n{RECIPIENT}\nwith ID 42"
            ),
            ""
        )
    );
    let r = shown("create-account");
    assert_eq!(r.pages[0], p("New account", "2 XLM", CREATED, "Its first XLM."));
    assert_eq!(r.summary, "opens an account with 2 XLM; fee up to 0.00001 XLM");
    // the most sent, the least received
    let r = shown("strict-send");
    assert_eq!(
        r.pages[0],
        p(
            "Send",
            "10 XLM",
            RECIPIENT,
            "They get at least 1.2 USDC, traded on Stellar's exchange. Through EURC."
        )
    );
    let r = shown("strict-receive");
    assert_eq!(r.pages[0], p("Swap", "up to 20 XLM", "", "For 5 USDC, traded on Stellar's exchange."));
    assert_eq!(r.summary, "swaps up to 20 XLM for 5 USDC; fee up to 0.00001 XLM");
    let r = shown("many");
    assert_eq!(r.summary, "sends 3.75 XLM in 3 payments; fee up to 0.00003 XLM");
    assert_eq!(r.pages[1], p("Send", "2.5 XLM", SIGNER, ""));
    assert_eq!(shown("mixed").summary, "sends 1 XLM, sends 2 USDC; fee up to 0.00002 XLM");
    // version 0, as old tools write it
    let r = shown("v0");
    assert_eq!(r.pages[0], p("Send", "0.5 XLM", RECIPIENT, ""));
    assert_eq!(r.summary, "sends 0.5 XLM; fee up to 0.00001 XLM");
}

#[test]
fn assets_by_their_issuer() {
    // Circle's USDC on the public network, by its issuer
    let r = shown("usdc");
    assert_eq!(r.pages[0], p("Send", "5.25 USDC", RECIPIENT, ""));
    assert_eq!(r.summary, "sends 5.25 USDC; fee up to 0.00001 XLM");
    // a USDC another issued: never just "USDC"
    let lookalike = |issuer: &str| {
        p(
            "Another USDC!",
            "not the one maki knows",
            &format!("USDC\nissued by\n{issuer}"),
            "Anyone can issue an asset called USDC: this one's issuer isn't the one Circle issues USDC from.",
        )
    };
    let r = shown("fake-usdc");
    assert_eq!(r.pages[..2], [p("Send", "1000 USDC (another issuer's)", RECIPIENT, ""), lookalike(ISSUER)]);
    assert_eq!(r.summary, "sends 1000 USDC (another issuer's); fee up to 0.00001 XLM");
    // the test network's USDC is Circle's there, and not on the public network; and the public
    // network's isn't on the test network
    assert_eq!(shown_on("test-usdc", Network::Test).pages[0], p("Send", "7 USDC", RECIPIENT, ""));
    assert_eq!(shown("test-usdc").pages[1], lookalike(TEST_USDC));
    assert_eq!(shown_on("usdc", Network::Test).pages[1], lookalike(USDC));
    // one maki doesn't know at all
    let r = shown("long-asset");
    assert_eq!(
        r.pages[..2],
        [
            p("Send", "0.0000001 LONGNAME123", RECIPIENT, ""),
            p(
                "Asset",
                "one maki doesn't know",
                &format!("LONGNAME123\nissued by\n{ISSUER}"),
                "Anyone can issue an asset of any name: what it's worth depends on who issued it."
            )
        ]
    );
}

#[test]
fn trades_and_trustlines() {
    let r = shown("offers");
    let stays = "It stays on Stellar's exchange until it's taken or cancelled.";
    assert_eq!(
        r.pages[..6],
        [
            p("Sell offer", "100 XLM", "", &format!("For USDC, at least 0.11 USDC each. {stays}")),
            p("Buy offer", "50 USDC", "", &format!("Paying XLM, at most 9.5 XLM each. {stays}")),
            p(
                "Cancel offer",
                "#12345",
                "",
                "Its offer to sell XLM for USDC goes, and what it held back is free again."
            ),
            p("Sell offer", "3 USDC", "", "For FOO, at least 1/3 FOO each. It replaces offer #678."),
            p(
                "Asset",
                "one maki doesn't know",
                &format!("FOO\nissued by\n{ISSUER}"),
                "Anyone can issue an asset of any name: what it's worth depends on who issued it."
            ),
            p(
                "Passive offer",
                "10 USDC",
                "",
                "For EURC, at least 0.92 EURC each. It doesn't take offers at its own price; it stays until it's taken or cancelled."
            )
        ]
    );
    assert_eq!(r.pages[7], fee("0.00005 XLM", "The most it can cost, for its 5 operations."));
    let r = shown("trust");
    assert_eq!(
        r.pages[..3],
        [
            p(
                "Trust",
                "USDC",
                &format!("USDC\nissued by\n{USDC}"),
                "Circle's USDC. Lets this account hold any amount of it. Its reserve holds back some XLM."
            ),
            p(
                "Trust",
                "FOO",
                &format!("FOO\nissued by\n{ISSUER}"),
                "An asset maki doesn't know: anyone can issue one of any name. Lets this account hold up to 1000 of it. Its reserve holds back some XLM."
            ),
            p(
                "Drop trustline",
                "EURC",
                &format!("EURC\nissued by\n{EURC}"),
                "Circle's EURC. This account stops holding it: its balance of it must be 0."
            )
        ]
    );
    assert_eq!(r.summary, "trusts USDC, trusts FOO, drops its EURC trustline; fee up to 0.00003 XLM");
    // a pool, its assets named by the trustline to it
    let r = shown("pool");
    assert_eq!(
        r.pages[..3],
        [
            p(
                "Trust",
                "pool shares",
                &format!("XLM / USDC\n{POOL}"),
                "Lets this account hold any amount of that liquidity pool's shares. Its fee: 0.3%."
            ),
            p("Pool deposit", "up to 100 XLM", POOL, "And up to 11 USDC, at 0.09 to 0.12 XLM for each USDC."),
            p("Pool withdrawal", "5 shares", POOL, "For at least 1 XLM and 0.1 USDC.")
        ]
    );
    assert_eq!(
        r.summary,
        "trusts a pool, deposits into a pool, withdraws from a pool; fee up to 0.00003 XLM"
    );
}

#[test]
fn who_controls_the_account_says_so_loudly() {
    let thresholds = "What its signers' weights must add up to: low for a few operations, medium for most, high to change its signers or close it.";
    let any_key =
        "That key could sign for the account: with enough weight, alone, and spend everything it holds.";
    let r = shown("signer");
    assert_eq!(
        r.pages[..2],
        [
            p("Thresholds!", "low 1, medium 2, high 2", "this account", thresholds),
            p("New signer!", "weight 1", SIGNER, any_key)
        ]
    );
    assert_eq!(r.summary, "changes who can sign for this account, adds a signer!; fee up to 0.00001 XLM");
    let r = shown("lockout");
    assert_eq!(
        r.pages[0],
        p(
            "Locks out its key!",
            "weight 0",
            "this account",
            "Its own key won't sign for it any more: only its other signers will. With none, it's locked for good."
        )
    );
    assert_eq!(r.summary, "locks out this account's key, adds a signer!; fee up to 0.00001 XLM");
    let r = shown("options");
    assert_eq!(
        r.pages[..7],
        [
            p(
                "Inflation vote",
                "",
                RECIPIENT,
                "Stellar no longer runs inflation: this does nothing that matters."
            ),
            p(
                "Issuer flags",
                "sets revocable, clawback; clears auth required",
                "",
                "For the assets it issues. Clawback lets it take back what it issues from whoever holds it."
            ),
            p("Home domain", "example.com", "", "Where wallets look the account up."),
            p("Removes a signer!", "", SIGNER, "It can't sign for the account any more."),
            p(
                "New signer!",
                "weight 1",
                "TBNFUWS2LJNFUWS2LJNFUWS2LJNFUWS2LJNFUWS2LJNFUWS2LJNFUGBA",
                "The transaction with this hash is signed for the account, once, when it's sent."
            ),
            p(
                "New signer!",
                "weight 2",
                "XBVWW23LNNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVWWJ7H",
                "Whoever reveals the secret this is the hash of can sign for the account."
            ),
            p(
                "New signer!",
                "weight 1",
                "PCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZIAAAAACQCAQDAQCQAAAADVUA",
                "That key signs for the account by signing 0102030405."
            )
        ]
    );
    assert_eq!(r.summary, "removes a signer, adds a signer!; fee up to 0.00005 XLM");
    let r = shown("merge");
    assert_eq!(
        r.pages[0],
        p(
            "Close account!",
            "all of its XLM",
            RECIPIENT,
            "This account closes, and all its XLM goes to that address: it can't be taken back."
        )
    );
    assert_eq!(r.summary, "closes this account!; fee up to 0.00001 XLM");
    let r = shown("data");
    assert_eq!(
        r.pages[..3],
        [
            p("Set data", "config", "hello", "Kept on the account, for anyone to read."),
            p("Set data", "key", "000102ff", "Kept on the account, for anyone to read."),
            p("Delete data", "old", "", "")
        ]
    );
    let r = shown("bump");
    assert_eq!(
        r.pages[0],
        p(
            "Sequence",
            "jumps to 123456789999",
            "",
            "Transactions signed for it with lower numbers can't go through any more."
        )
    );
}

#[test]
fn an_issuers_operations() {
    let r = shown("issuer");
    assert_eq!(
        r.pages[..4],
        [
            p(
                "Trustline flags",
                "MAKI",
                RECIPIENT,
                "As MAKI's issuer, on that account's trustline: sets authorized; clears authorized to keep what it has, clawback."
            ),
            p(
                "Authorize",
                "MAKI",
                RECIPIENT,
                "As MAKI's issuer: that account may keep what it has, and take no more."
            ),
            p("Claw back", "3 MAKI", RECIPIENT, "As MAKI's issuer: it takes them back from that account."),
            p(
                "Claw back",
                "a claimable balance",
                BALANCE,
                "As its asset's issuer: it takes back what it holds."
            )
        ]
    );
}

#[test]
fn claimable_balances_and_sponsorships() {
    let r = shown("claimable");
    assert_eq!(
        r.pages[0],
        p(
            "Claimable",
            "50 XLM",
            &format!(
                "{RECIPIENT}\n before 2027-01-01 00:00:00 UTC\nthis account\n after 1 day\n{SIGNER}\n any time or (within 1 hour and before 2027-01-01 00:00:00 UTC)"
            ),
            "Set aside: those named may claim it, each when their condition holds, its times from when it's set aside."
        )
    );
    assert_eq!(r.summary, "sets aside 50 XLM; fee up to 0.00001 XLM");
    let r = shown("claim");
    assert_eq!(
        r.pages[0],
        p(
            "Claim",
            "a claimable balance",
            BALANCE,
            "What it holds goes to this account, if it may claim it now."
        )
    );
    // this account sponsors a new account, whose own operation (and signature) ends it
    let r = shown("sponsor");
    assert_eq!(
        r.pages[..3],
        [
            p(
                "Sponsor",
                "reserves",
                CREATED,
                "This account pays the reserves of what that account adds next in this transaction, for as long as it's there."
            ),
            p("New account", "0 XLM", CREATED, "Its first XLM."),
            p(
                "End sponsoring",
                "",
                "",
                &format!("The sponsorship begun for it ends. As {CREATED}, not this account.")
            )
        ]
    );
    let revoked = "Its sponsor stops paying its reserve: its owner does, or this account's own sponsor.";
    let r = shown("revoke");
    assert_eq!(
        r.pages[..6],
        [
            p("Revoke sponsorship", "an account", RECIPIENT, revoked),
            p("Revoke sponsorship", "a trustline", &format!("USDC trustline of\n{RECIPIENT}"), revoked),
            p("Revoke sponsorship", "an offer", &format!("offer #7 of\n{RECIPIENT}"), revoked),
            p("Revoke sponsorship", "data", &format!("\"config\" of\n{RECIPIENT}"), revoked),
            p("Revoke sponsorship", "a claimable balance", BALANCE, revoked),
            p("Revoke sponsorship", "a signer", &format!("{SIGNER}\nof {RECIPIENT}"), revoked)
        ]
    );
}

#[test]
fn conditions_memos_and_the_fee() {
    let r = shown("no-limit");
    assert_eq!(
        r.pages[1],
        p(
            "No time limit",
            "",
            "",
            "It stays valid until it's sent, or its account's sequence moves past it."
        )
    );
    let r = shown("conditions");
    assert_eq!(
        r.pages[1..6],
        [
            p("Valid until", "2027-01-01 00:00:00 UTC", "", "Not before 2026-09-21 14:13:20 UTC."),
            p("Ledgers", "ledgers 60000000 to 69999999", "", "It can only go through in those."),
            p(
                "Sequence",
                "from 123456789000",
                "",
                "It can go through while its account's sequence is anywhere from that up to its own, not just one below it."
            ),
            p(
                "Waits",
                "1 hour, 10 ledgers",
                "",
                "Only once that's passed since its account's sequence last changed."
            ),
            p(
                "Signed by others",
                "2 more",
                &format!("{SIGNER}\nPCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZIAAAAACASCIJBFGYY"),
                "It goes through only with their signatures too."
            )
        ]
    );
    let everyone = "Everyone can read it, on chain. An exchange may need it to know the payment is yours.";
    assert_eq!(shown("usdc").pages[1], p("Memo", "ID 1234567890", "", everyone));
    assert_eq!(shown("memo-hash").pages[1], p("Memo", "a hash", &"ab".repeat(32), everyone));
    assert_eq!(
        shown("memo-return").pages[1],
        p("Memo", "returns a payment", &"cd".repeat(32), "The hash of the transaction it sends back.")
    );
    // its source this account with an ID
    let r = shown("muxed-source");
    assert_eq!(r.pages[0], p("Send", "3 XLM", RECIPIENT, "As this account, ID 7."));
    assert_eq!(
        r.pages[3],
        p(
            "From",
            "this account",
            &format!(
                "MB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQAAAAAAAAAAAA7EFC\nwhich is account\n{ME}\nwith ID 7"
            ),
            "On Stellar's public network; its sequence number is 123456789013."
        )
    );
}

#[test]
fn others_transactions_this_account_signs_for() {
    // a service's transaction: it pays the fee, and the two swap
    let r = shown("swap");
    assert_eq!(
        r.pages,
        [
            p("Send", "10 XLM", SERVICE, "As this account."),
            p("Send", "1.1 USDC", "this account", &format!("As {SERVICE}, not this account.")),
            until(),
            p("Fee paid by", "another account", SERVICE, "Up to 0.00002 XLM, not this account's."),
            p(
                "Another's!",
                "another account",
                SERVICE,
                "On Stellar's public network; its sequence number is 556. It's that account's transaction; this account signs for what it does as this account."
            )
        ]
    );
    assert_eq!(r.summary, "sends 10 XLM, gets 1.1 USDC; another pays the fee");
    // a sign-in: numbered 0, so it never goes on chain
    let r = shown("sign-in");
    assert_eq!(
        r.pages[..2],
        [
            p(
                "Never on chain",
                "sequence 0",
                "",
                "A transaction numbered 0 never goes through: signing it moves nothing. Sites ask for one to sign you in (SEP-10)."
            ),
            p(
                "Set data",
                "example.com auth",
                &"A".repeat(48),
                "Kept on the account, for anyone to read. As this account."
            )
        ]
    );
    assert_eq!(r.summary, "signs in to example.com; it can't go on chain");
}

#[test]
fn fee_bumps() {
    let r = shown("fee-bump");
    assert_eq!(
        r.pages,
        [
            p(
                "Fee bump",
                "pays the fee",
                SERVICE,
                "This account pays the fee of that account's transaction. What the transaction does follows."
            ),
            p("Send", "4 XLM", RECIPIENT, &format!("As {SERVICE}, not this account.")),
            until(),
            fee("0.00004 XLM", "The most it can cost, for its operation and the fee bump."),
            p(
                "Transaction of",
                "another account",
                SERVICE,
                "On Stellar's public network; its sequence number is 556. It's that account's transaction, signed by it; this account signs the fee bump."
            )
        ]
    );
    assert_eq!(r.summary, "pays the fee of another's transaction; fee bump up to 0.00004 XLM");
    let bytes = fixture("fee-bump", Network::Public);
    let envelope = Envelope::parse(&bytes).unwrap();
    assert!(matches!(envelope.kind, Kind::FeeBump { fee: 400, inner_signatures: 1, .. }));
    // a fee bump that bumps: twice the transaction's 100 stroops, for its operation and its own,
    // at least
    let bumped = |fee: i64| [&bytes[..40], &fee.to_be_bytes(), &bytes[48..]].concat();
    assert!(Envelope::parse(&bumped(200)).is_ok());
    assert!(matches!(Envelope::parse(&bumped(199)), Err(transaction::Error::Invalid(_))));
    assert!(matches!(Envelope::parse(&bumped(-1)), Err(transaction::Error::Invalid(_))));
    let r = shown("fee-bump-mine");
    assert_eq!(
        r.pages[0],
        p(
            "Fee bump",
            "pays the fee",
            "this account",
            "This account pays its own transaction's fee anew. What the transaction does follows."
        )
    );
    assert_eq!(r.summary, "sends 9 USDC; fee bump up to 0.0002 XLM");
}

#[test]
fn contracts_flagged_with_what_maki_can_read() {
    let authority = "It's given this account's authority: it can do as this account whatever its authorizations allow, which maki can't read.";
    let none = "It isn't given this account's authority: it can't act as this account.";
    // stellar-sdk's transfer of USDC through its Stellar asset contract
    let r = shown("contract");
    assert_eq!(
        r.pages[0],
        p(
            "Contract call",
            "maki can't read it",
            &format!(
                "{USDC_CONTRACT}\nUSDC's asset contract\ntransfer()\n3 arguments\n\nthis account authorizes\n{USDC_CONTRACT} transfer()"
            ),
            authority
        )
    );
    assert_eq!(
        r.pages[2],
        fee(
            "0.50001 XLM",
            "The most it can cost, for its operation. 0.5 XLM of it for the contract's resources, some back if unused."
        )
    );
    assert_eq!(r.summary, "maki can't read all of it; fee up to 0.50001 XLM");
    // authorized by others apart from the transaction, one with others signing for it, and by
    // this account
    let deposit = strkey::contract(&[0x66; 32]);
    let r = shown("contract-authorized");
    assert_eq!(
        r.pages[0],
        p(
            "Contract call",
            "maki can't read it",
            &format!(
                "{deposit}\ndeposit()\n1 argument\n\n{} authorizes\n{deposit} deposit()\n\n{SIGNER}, and 2 signing for it, authorizes\n{deposit} deposit()\n\nthis account authorizes\n{deposit} deposit()",
                "GAJZR5RMNUNEK7CRXJVEWXZ5XUXWT7FJGILCDDOITF7EC26RPWJ4UVOE"
            ),
            authority
        )
    );
    let contract = "CAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDB3V";
    let r = shown("contract-call");
    assert_eq!(
        r.pages[0],
        p(
            "Contract call",
            "maki can't read it",
            &format!("{contract}\nswap()\n3 arguments\n\nthis account authorizes\n{contract} swap()"),
            authority
        )
    );
    let r = shown("contract-no-auth");
    assert_eq!(
        r.pages[0],
        p(
            "Contract call",
            "maki can't read it",
            "CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH\nhello()\n1 argument",
            none
        )
    );
    let r = shown("upload");
    assert_eq!(
        r.pages[0],
        p(
            "Contract code",
            "28 bytes",
            "",
            "Code for contracts to run, uploaded: on its own, it can't act as this account."
        )
    );
    assert_eq!(r.summary, "uploads contract code; fee up to 0.00901 XLM");
    let r = shown("new-contract");
    assert_eq!(
        r.pages[0],
        p(
            "New contract",
            "maki can't read it",
            &format!("made by\nthis account\nits code {}", "44".repeat(32)),
            none
        )
    );
    let r = shown("asset-contract");
    assert_eq!(
        r.pages[0],
        p("New contract", "a Stellar asset's", "for MAKI\na Stellar asset's contract", none)
    );
    assert_eq!(r.summary, "makes a contract; fee up to 0.00601 XLM");
    let r = shown("extend");
    assert_eq!(
        r.pages[0],
        p(
            "Keep alive",
            "500000 ledgers",
            &format!("data of {contract}\ncode {}", "22".repeat(32)),
            "It pays to keep these contracts' data and code for that many more ledgers."
        )
    );
    let r = shown("restore");
    assert_eq!(
        r.pages[0],
        p(
            "Restore",
            "archived contract data",
            &format!("data of {contract}"),
            "It pays to bring these contracts' data and code back from the archive."
        )
    );
}

/// XDR written out by hand, for what stellar-sdk won't build.
mod xdr {
    use maki_xlm::Key;

    pub fn u32(n: u32) -> Vec<u8> { n.to_be_bytes().to_vec() }

    pub fn i64(n: i64) -> Vec<u8> { n.to_be_bytes().to_vec() }

    /// An account (or a muxed account without an ID: the same bytes).
    pub fn account(k: &Key) -> Vec<u8> { [u32(0), k.to_vec()].concat() }

    pub fn opaque(data: &[u8]) -> Vec<u8> {
        let mut out = u32(data.len() as u32);
        out.extend_from_slice(data);
        out.resize(out.len().next_multiple_of(4), 0);
        out
    }

    pub fn native() -> Vec<u8> { u32(0) }

    pub fn credit(code: &[u8; 4], issuer: &Key) -> Vec<u8> {
        [u32(1), code.to_vec(), account(issuer)].concat()
    }

    /// An operation: its source, if it has its own, its type and its body.
    pub fn op(source: Option<&Key>, kind: u32, body: Vec<u8>) -> Vec<u8> {
        let source = match source {
            Some(k) => [u32(1), account(k)].concat(),
            None => u32(0),
        };
        [source, u32(kind), body].concat()
    }

    pub fn payment(to: &Key, asset: Vec<u8>, amount: i64) -> Vec<u8> {
        op(None, 1, [account(to), asset, i64(amount)].concat())
    }

    /// A version 1 envelope from `source`: these conditions, memo, operations and extension, and
    /// no signatures.
    pub fn envelope_with(
        source: &Key,
        cond: Vec<u8>,
        memo: Vec<u8>,
        ops: &[Vec<u8>],
        ext: Vec<u8>,
    ) -> Vec<u8> {
        let mut out = [u32(2), account(source), u32(100), i64(1), cond, memo, u32(ops.len() as u32)].concat();
        for o in ops {
            out.extend_from_slice(o);
        }
        [out, ext, u32(0)].concat()
    }

    pub fn envelope(source: &Key, ops: &[Vec<u8>]) -> Vec<u8> {
        envelope_with(source, u32(0), u32(0), ops, u32(0))
    }

    /// A contract's resources: no archived entries, these footprints, and a resource fee.
    pub fn soroban(read_only: &[Vec<u8>], read_write: &[Vec<u8>], fee: i64) -> Vec<u8> {
        let mut out = [u32(1), u32(0), u32(read_only.len() as u32)].concat();
        for k in read_only {
            out.extend_from_slice(k);
        }
        out.extend(u32(read_write.len() as u32));
        for k in read_write {
            out.extend_from_slice(k);
        }
        [out, u32(0), u32(0), u32(0), i64(fee)].concat()
    }

    /// A contract's code's ledger key, and a contract's data's (kept for good or not).
    pub fn code_key(hash: u8) -> Vec<u8> { [u32(7), vec![hash; 32]].concat() }

    pub fn data_key(contract: u8, persistent: bool) -> Vec<u8> {
        [u32(6), u32(1), vec![contract; 32], u32(20), u32(persistent as u32)].concat()
    }

    /// A call of a contract's function with one argument, `arg` (an `SCVal`), and no
    /// authorizations.
    pub fn call(arg: Vec<u8>) -> Vec<u8> {
        op(None, 24, [u32(0), u32(1), vec![0x11; 32], opaque(b"f"), u32(1), arg, u32(0)].concat())
    }
}

#[test]
fn envelopes_stellar_would_refuse_maki_refuses() {
    use transaction::Error::*;
    use xdr::*;
    let (me, them, issuer) = (me(), key(RECIPIENT), key(ISSUER));
    let good = envelope(&me, &[payment(&them, native(), 1)]);
    assert!(Envelope::parse(&good).is_ok());
    let bad =
        |bytes: Vec<u8>, e: transaction::Error| assert_eq!(Envelope::parse(&bytes), Err(e), "{bytes:02x?}");
    let invalid = |ops: &[Vec<u8>]| match Envelope::parse(&envelope(&me, ops)) {
        Err(Invalid(why)) => why,
        other => panic!("{other:?}"),
    };
    // XDR: cut short, more after it, padding, types Stellar doesn't have, lengths over their bounds
    bad(good[..good.len() - 1].to_vec(), Length);
    bad([&good[..], &[0]].concat(), Length);
    bad([&good[..], &[0, 0, 0, 0]].concat(), Length);
    bad([u32(1), good[4..].to_vec()].concat(), Unknown);
    bad([u32(11), good[4..].to_vec()].concat(), Unknown);
    bad(envelope(&me, &[op(None, 27, vec![])]), Unknown);
    bad(envelope(&me, &[[u32(2), payment(&them, native(), 1)[4..].to_vec()].concat()]), Unknown);
    let text = |t: &[u8]| {
        envelope_with(&me, u32(0), [u32(1), opaque(t)].concat(), &[payment(&them, native(), 1)], u32(0))
    };
    assert!(Envelope::parse(&text(b"28 bytes of memo, at most!!!")).is_ok());
    bad(text(b"29 bytes of memo: one too many"), TooLong);
    let mut padded = text(b"hi");
    let at = padded.len() - 4 - 4 - 4 - payment(&them, native(), 1).len() - 2;
    padded[at] = 1;
    bad(padded, Padding);
    bad(envelope(&me, &vec![payment(&them, native(), 1); 101]), TooLong);
    assert!(Envelope::parse(&envelope(&me, &vec![payment(&them, native(), 1); 100])).is_ok());
    bad(vec![0; MAX_ENVELOPE + 1], TooBig);
    // an asset code Stellar doesn't allow
    assert!(invalid(&[payment(&them, credit(b"US D", &issuer), 1)]).starts_with("an asset code"));
    assert!(invalid(&[payment(&them, credit(b"U\0SD", &issuer), 1)]).starts_with("an asset code"));
    assert!(invalid(&[payment(&them, credit(b"\0\0\0\0", &issuer), 1)]).starts_with("an asset code"));
    // operations stellar-core calls malformed
    let malformed = [
        (payment(&them, native(), 0), "a payment of nothing"),
        (op(None, 0, [account(&me), i64(1)].concat()), "an account making itself"),
        (op(None, 0, [account(&them), i64(-1)].concat()), "an account made with less than nothing"),
        (op(None, 8, account(&me)), "an account merged into itself"),
        (
            op(None, 3, [native(), native(), i64(1), u32(1), u32(1), i64(0)].concat()),
            "an offer of an asset for itself",
        ),
        (
            op(None, 3, [native(), credit(b"USDC", &issuer), i64(1), u32(0), u32(1), i64(0)].concat()),
            "an offer of less than nothing",
        ),
        (
            op(None, 3, [native(), credit(b"USDC", &issuer), i64(0), u32(1), u32(1), i64(0)].concat()),
            "an offer that can't be",
        ),
        (
            op(None, 12, [native(), credit(b"USDC", &issuer), i64(1), u32(1), u32(1), i64(-1)].concat()),
            "an offer that can't be",
        ),
        (
            op(None, 4, [native(), credit(b"USDC", &issuer), i64(0), u32(1), u32(1)].concat()),
            "an offer that can't be",
        ),
        (op(None, 6, [u32(0), i64(1)].concat()), "a trustline to XLM"),
        (op(None, 6, [credit(b"USDC", &issuer), i64(-1)].concat()), "a trustline's limit below nothing"),
        (op(None, 6, [credit(b"MAKI", &me), i64(1)].concat()), "a trustline to an account's own asset"),
        (
            op(None, 6, [u32(3), u32(0), native(), native(), u32(30), i64(1)].concat()),
            "a liquidity pool Stellar",
        ),
        (
            op(None, 6, [u32(3), u32(0), credit(b"USDC", &issuer), native(), u32(30), i64(1)].concat()),
            "a liquidity pool",
        ),
        (
            op(None, 6, [u32(3), u32(0), native(), credit(b"USDC", &issuer), u32(31), i64(1)].concat()),
            "a liquidity pool",
        ),
        (
            op(None, 7, [account(&them), u32(1), b"MAKI".to_vec(), u32(3)].concat()),
            "an authorization Stellar",
        ),
        (
            op(None, 7, [account(&me), u32(1), b"MAKI".to_vec(), u32(1)].concat()),
            "an issuer authorizing itself",
        ),
        (op(None, 10, [opaque(b""), u32(0)].concat()), "data without a name"),
        (op(None, 10, [opaque(b"new\nline"), u32(0)].concat()), "a data name Stellar would refuse"),
        (op(None, 11, i64(-1)), "a sequence below nothing"),
        (op(None, 14, [native(), i64(1), u32(0)].concat()), "a claimable balance of nothing"),
        (
            op(None, 14, [native(), i64(0), u32(1), u32(0), account(&them), u32(0)].concat()),
            "a claimable balance of nothing",
        ),
        (
            op(
                None,
                14,
                [native(), i64(1), u32(2), u32(0), account(&them), u32(0), u32(0), account(&them), u32(0)]
                    .concat(),
            ),
            "a claimant named twice",
        ),
        (op(None, 16, account(&me)), "an account sponsoring itself"),
        (op(None, 18, [u32(0), u32(2), account(&them), i64(0)].concat()), "an offer that can't be"),
        (op(None, 18, [u32(0), u32(1), account(&them), native()].concat()), "a trustline to XLM"),
        (op(None, 18, [u32(0), u32(5), vec![1; 32]].concat()), "a sponsorship of what isn't sponsored"),
        (op(None, 19, [credit(b"USDC", &issuer), account(&them), i64(1)].concat()), "a clawback by another"),
        (op(None, 19, [credit(b"MAKI", &me), account(&them), i64(0)].concat()), "a clawback of nothing"),
        (
            op(None, 19, [credit(b"MAKI", &me), account(&me), i64(1)].concat()),
            "an issuer clawing back from itself",
        ),
        (op(None, 21, [account(&them), credit(b"MAKI", &me), u32(0), u32(3)].concat()), "trustline flags"),
        (op(None, 21, [account(&them), credit(b"MAKI", &me), u32(0), u32(4)].concat()), "trustline flags"),
        (op(None, 21, [account(&them), credit(b"MAKI", &me), u32(1), u32(1)].concat()), "trustline flags"),
        (op(None, 21, [account(&them), credit(b"MAKI", &me), u32(8), u32(0)].concat()), "trustline flags"),
        (
            op(None, 21, [account(&me), credit(b"MAKI", &me), u32(0), u32(1)].concat()),
            "an issuer setting its own",
        ),
        (
            op(None, 21, [account(&them), credit(b"USDC", &issuer), u32(0), u32(1)].concat()),
            "a trustline's flags set by another",
        ),
        (
            op(None, 22, [vec![1; 32], i64(0), i64(1), u32(1), u32(1), u32(1), u32(1)].concat()),
            "a deposit of nothing",
        ),
        (
            op(None, 22, [vec![1; 32], i64(1), i64(1), u32(2), u32(1), u32(1), u32(1)].concat()),
            "a deposit's least price",
        ),
        (op(None, 23, [vec![1; 32], i64(0), i64(0), i64(0)].concat()), "a withdrawal of nothing"),
        (op(None, 9, vec![]), "inflation"),
    ];
    for (op, why) in malformed {
        let said = invalid(&[op]);
        assert!(said.starts_with(why), "{why}: {said}");
        assert!(said.ends_with("refuse it") || said.ends_with("would refuse"), "{said}");
    }
    // SetOptions: flags Stellar doesn't have, or set and cleared at once, weights over 255, the
    // account as its own signer
    let options = |fields: [Option<u32>; 6], signer: Option<(Key, u32)>| {
        let mut body = u32(0);
        for f in fields {
            body.extend(match f {
                Some(v) => [u32(1), u32(v)].concat(),
                None => u32(0),
            });
        }
        body.extend(u32(0));
        body.extend(match signer {
            Some((k, w)) => [u32(1), account(&k), u32(w)].concat(),
            None => u32(0),
        });
        op(None, 5, body)
    };
    assert!(
        Envelope::parse(&envelope(&me, &[options([None, Some(8), Some(255), None, None, None], None)]))
            .is_ok()
    );
    for (o, why) in [
        (options([Some(16), None, None, None, None, None], None), "a flag Stellar doesn't have"),
        (options([Some(1), Some(1), None, None, None, None], None), "a flag both set and cleared"),
        (options([None, None, Some(256), None, None, None], None), "a weight or threshold over 255"),
        (options([None, None, None, None, None, Some(1000)], None), "a weight or threshold over 255"),
        (options([None; 6], Some((me, 1))), "a signer Stellar would refuse"),
        (options([None; 6], Some((them, 256))), "a signer Stellar would refuse"),
    ] {
        assert!(invalid(&[o]).starts_with(why), "{why}");
    }
    // claim conditions: an "and" of one, a "not" of nothing, a time before 1970, too deep
    let claim = |predicate: Vec<u8>| {
        op(None, 14, [native(), i64(1), u32(1), u32(0), account(&them), predicate].concat())
    };
    let not = |p: Vec<u8>| [u32(3), u32(1), p].concat();
    assert!(Envelope::parse(&envelope(&me, &[claim(not(not(not(u32(0)))))])).is_ok());
    for predicate in [
        [u32(1), u32(1), u32(0)].concat(),
        [u32(3), u32(0)].concat(),
        [u32(4), i64(-1)].concat(),
        not(not(not(not(u32(0))))),
    ] {
        assert!(invalid(&[claim(predicate)]).starts_with("a claim condition"));
    }
    // the transaction: no operations, the same extra signer twice
    assert!(invalid(&[]).starts_with("no operations"));
    let twice =
        [u32(2), u32(0), u32(0), u32(0), i64(0), u32(0), u32(2), account(&them), account(&them)].concat();
    match Envelope::parse(&envelope_with(&me, twice, u32(0), &[payment(&them, native(), 1)], u32(0))) {
        Err(Invalid(why)) => assert!(why.starts_with("the same extra signer twice")),
        other => panic!("{other:?}"),
    }
    // contracts: alone in a transaction, with their resources, and only theirs; a resource fee
    // within the fee; no memo or account ID for a call; an entry named once; extending and
    // restoring only what contracts keep
    let symbol = [u32(15), opaque(b"x")].concat();
    let call = xdr::call(symbol.clone());
    let alone = [call.clone()];
    let with = |ops: &[Vec<u8>], memo: Vec<u8>, ext: Vec<u8>| {
        Envelope::parse(&envelope_with(&me, u32(0), memo, ops, ext))
    };
    let ok = soroban(&[], &[], 50);
    assert!(with(&alone, u32(0), ok.clone()).is_ok());
    for (envelope, why) in [
        (
            with(&[call.clone(), payment(&them, native(), 1)], u32(0), ok.clone()),
            "a contract's operation with others",
        ),
        (with(&[call.clone(), call.clone()], u32(0), ok.clone()), "a contract's operation with others"),
        (with(&alone, u32(0), u32(0)), "a contract's operation without its resources"),
        (
            with(&[payment(&them, native(), 1)], u32(0), ok.clone()),
            "resources for a contract with no contract",
        ),
        (with(&alone, u32(0), soroban(&[], &[], 101)), "a resource fee more than the whole fee"),
        (with(&alone, u32(0), soroban(&[], &[], -1)), "a resource fee Stellar would refuse"),
        (with(&alone, [u32(2), i64(7)].concat(), ok.clone()), "a contract call with a memo"),
        (with(&alone, u32(0), soroban(&[code_key(1)], &[code_key(1)], 50)), "a contract's entry named twice"),
        (
            with(&[op(None, 25, [u32(0), u32(10)].concat())], u32(0), soroban(&[], &[code_key(1)], 50)),
            "extending what",
        ),
        (
            with(
                &[op(None, 25, [u32(0), u32(10)].concat())],
                u32(0),
                soroban(&[[u32(0), account(&me)].concat()], &[], 50),
            ),
            "extending what",
        ),
        (with(&[op(None, 26, u32(0))], u32(0), soroban(&[code_key(1)], &[], 50)), "restoring what"),
        (with(&[op(None, 26, u32(0))], u32(0), soroban(&[], &[data_key(1, false)], 50)), "restoring what"),
    ] {
        match envelope {
            Err(Invalid(said)) => assert!(said.starts_with(why), "{why}: {said}"),
            other => panic!("{why}: {other:?}"),
        }
    }
    assert!(
        with(&[op(None, 26, u32(0))], u32(0), soroban(&[], &[data_key(1, true), code_key(2)], 50)).is_ok()
    );
    // a contract's argument nested deeper than maki reads, and one just within it
    let nested = |depth: usize| {
        let mut v = u32(1);
        for _ in 1..depth {
            v = [u32(16), u32(1), u32(1), v].concat();
        }
        v
    };
    assert!(with(&[xdr::call(nested(soroban::MAX_DEPTH))], u32(0), ok.clone()).is_ok());
    assert_eq!(with(&[xdr::call(nested(soroban::MAX_DEPTH + 1))], u32(0), ok.clone()), Err(Deep));
    // and a review that wouldn't fit maki's screen: a hundred operations of pages each
    let many = envelope(&me, &vec![payment(&them, credit(b"FOO\0", &issuer), 1); 100]);
    let shown = review(&Envelope::parse(&many).unwrap(), &me, Network::Public);
    assert_eq!(shown.unwrap().pages.len(), 104, "one page each, one for the asset, and three");
    // its key's weight and a threshold, two pages each
    let weights = op(None, 5, [vec![0; 12], u32(1), u32(1), u32(1), u32(1), vec![0; 12], u32(0)].concat());
    let many = envelope(&me, &vec![weights; 100]);
    assert_eq!(review(&Envelope::parse(&many).unwrap(), &me, Network::Public), Err(Error::TooMuch));
}

#[test]
fn whose_it_is_to_sign() {
    use xdr::*;
    let (me, them) = (me(), key(RECIPIENT));
    // the transaction's source, an operation's, or neither
    let mine = envelope(&me, &[payment(&them, native(), 1)]);
    assert!(review(&Envelope::parse(&mine).unwrap(), &me, Network::Public).is_ok());
    let theirs = envelope(&them, &[payment(&me, native(), 1)]);
    assert_eq!(review(&Envelope::parse(&theirs).unwrap(), &me, Network::Public), Err(Error::NotMine));
    let for_me = envelope(&them, &[op(Some(&me), 11, i64(5))]);
    let r = review(&Envelope::parse(&for_me).unwrap(), &me, Network::Public).unwrap();
    assert_eq!(r.summary, "bumps its sequence; another pays the fee");
    // and the line under the question, however much there is to say, fits maki's screen
    // its key locked out, a threshold, and a signer added
    let control = op(
        None,
        5,
        [vec![0; 12], u32(1), u32(0), u32(1), u32(1), vec![0; 12], u32(1), account(&them), u32(1)].concat(),
    );
    let all = envelope(&me, &[op(None, 8, account(&them)), control.clone(), xdr::call(u32(1))]);
    assert!(Envelope::parse(&all).is_err(), "a contract alone");
    let pool = op(None, 22, [vec![9; 32], i64(1), i64(1), u32(1), u32(2), u32(1), u32(1)].concat());
    let all = envelope(&me, &[op(None, 8, account(&them)), control, pool]);
    let r = review(&Envelope::parse(&all).unwrap(), &me, Network::Test).unwrap();
    assert_eq!(r.summary.len(), display::MAX_SUMMARY, "{}", r.summary);
    assert!(
        r.summary.starts_with(
            "testnet: closes this account, locks out this account's key, changes who can sign for this account, adds a signer!"
        ),
        "{}",
        r.summary
    );
    assert!(r.summary.ends_with('…'));
}
