//! maki-zec against Zcash's own: ZIP-244's published test vectors for the transaction ID and
//! signature digests (zcash-test-vectors, whose transactions have shielded parts, read here far
//! enough for their digests); ZIP-320's for TEX addresses; and transactions librustzcash made and
//! signed (`fixtures/make.rs`: zcash_primitives, zcash_transparent, the test phrase's keys as they
//! derive them, version 5 at NU6.3's consensus branch), read as they are, their signature hashes and
//! IDs worked out the same, shown as they should be, and signed by maki's keys with the same account
//! byte for byte as librustzcash signs them; the fee beside ZIP-317's as librustzcash's fee rule
//! works it out; and everything maki must refuse, refused, with why.

use maki_hd::seed::SeedKeys;
use maki_zec::address::{self, Kind};
use maki_zec::display::{Page, date, decimals, zec};
use maki_zec::hash::{Hasher, blake2b};
use maki_zec::request::{Coin, Derivation, MAX_REQUEST, Shown};
use maki_zec::sighash::{self, Shared, Signing, Spent, header_digest, root, transparent_digest};
use maki_zec::tx::{self, BRANCH_ID, Transaction, TxIn, TxOut};
use maki_zec::wallet::{self, Paid, conventional_fee, data};
use maki_zec::{Account, Error, MAX_MONEY, Network, Request};

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// The phrase's first transparent address, as Zcash's wallets make it.
const ME: &str = "t1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F";
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

fn keys() -> &'static SeedKeys {
    Box::leak(Box::new(
        SeedKeys::from_seed(&maki_seed::seed(&PHRASE.split(' ').collect::<Vec<_>>(), "")).unwrap(),
    ))
}

fn json(name: &str) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{FIXTURES}/{name}")).unwrap()).unwrap()
}

fn p(heading: &str, value: &str, mono: &str, prose: &str) -> Page {
    Page { heading: heading.into(), value: value.into(), mono: mono.into(), prose: prose.into() }
}

/// A version 5 transaction with its shielded parts, read only as far as ZIP-244's digests need
/// (what the published vectors have, and maki doesn't read): the header's fields, the transparent
/// parts, and the Sapling and Orchard digests (T.3, T.4), worked out here with maki's hasher.
struct Full {
    branch: u32,
    lock_time: u32,
    expiry: u32,
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    sapling: [u8; 32],
    orchard: [u8; 32],
}

struct Cursor<'a>(&'a [u8], usize);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.0[self.1..self.1 + n];
        self.1 += n;
        s
    }

    fn u32(&mut self) -> u32 { u32::from_le_bytes(self.take(4).try_into().unwrap()) }

    fn compact(&mut self) -> usize {
        match self.take(1)[0] {
            0xfd => u16::from_le_bytes(self.take(2).try_into().unwrap()) as usize,
            0xfe => self.u32() as usize,
            n => n as usize,
        }
    }
}

fn hash(personal: &[u8; 16], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Hasher::new(personal);
    for part in parts {
        h.update(part);
    }
    h.finish()
}

fn full(bytes: &[u8]) -> Full {
    let mut c = Cursor(bytes, 0);
    assert_eq!((c.u32(), c.u32()), (tx::VERSION_5, tx::VERSION_GROUP));
    let (branch, lock_time, expiry) = (c.u32(), c.u32(), c.u32());
    let inputs = (0..c.compact())
        .map(|_| {
            let (txid, index) = (c.take(32).try_into().unwrap(), c.u32());
            let n = c.compact();
            c.take(n);
            TxIn { txid, index, sequence: c.u32() }
        })
        .collect();
    let outputs = (0..c.compact())
        .map(|_| {
            let value = u64::from_le_bytes(c.take(8).try_into().unwrap());
            let n = c.compact();
            TxOut { value, script: c.take(n).to_vec() }
        })
        .collect();
    // Sapling: spends (cv, nullifier, rk), outputs (cv, cmu, ephemeral key, ciphertexts), the
    // value balance and anchor, then proofs and signatures (authorizing data, not hashed here)
    let spends: Vec<&[u8]> = (0..c.compact()).map(|_| c.take(96)).collect();
    let outs: Vec<&[u8]> = (0..c.compact()).map(|_| c.take(756)).collect();
    let balance = if spends.len() + outs.len() > 0 { c.take(8) } else { &[] };
    let anchor = if !spends.is_empty() { c.take(32) } else { &[] };
    c.take(spends.len() * (192 + 64) + outs.len() * 192 + if balance.is_empty() { 0 } else { 64 });
    let sapling = if spends.is_empty() && outs.is_empty() {
        blake2b(b"ZTxIdSaplingHash", &[])
    } else {
        let spends_digest = if spends.is_empty() {
            blake2b(b"ZTxIdSSpendsHash", &[])
        } else {
            let compact: Vec<&[u8]> = spends.iter().map(|s| &s[32..64]).collect();
            let noncompact: Vec<&[u8]> = spends.iter().flat_map(|s| [&s[..32], anchor, &s[64..]]).collect();
            hash(
                b"ZTxIdSSpendsHash",
                &[&hash(b"ZTxIdSSpendCHash", &compact), &hash(b"ZTxIdSSpendNHash", &noncompact)],
            )
        };
        let outputs_digest = if outs.is_empty() {
            blake2b(b"ZTxIdSOutputHash", &[])
        } else {
            let compact: Vec<&[u8]> = outs.iter().map(|o| &o[32..96 + 52]).collect();
            let memos: Vec<&[u8]> = outs.iter().map(|o| &o[96 + 52..96 + 564]).collect();
            let noncompact: Vec<&[u8]> = outs.iter().flat_map(|o| [&o[..32], &o[96 + 564..]]).collect();
            hash(
                b"ZTxIdSOutputHash",
                &[
                    &hash(b"ZTxIdSOutC__Hash", &compact),
                    &hash(b"ZTxIdSOutM__Hash", &memos),
                    &hash(b"ZTxIdSOutN__Hash", &noncompact),
                ],
            )
        };
        hash(b"ZTxIdSaplingHash", &[&spends_digest, &outputs_digest, balance])
    };
    // Orchard: actions (cv, nullifier, rk, cmx, ephemeral key, ciphertexts), then the flags, value
    // balance and anchor; the proofs and signatures after
    let actions: Vec<&[u8]> = (0..c.compact()).map(|_| c.take(820)).collect();
    let orchard = if actions.is_empty() {
        blake2b(b"ZTxIdOrchardHash", &[])
    } else {
        let (flags, balance, anchor) = (c.take(1), c.take(8), c.take(32));
        // each action's nullifier, then its cmx, ephemeral key and ciphertext's first 52 bytes
        let compact: Vec<&[u8]> = actions.iter().flat_map(|a| [&a[32..64], &a[96..160 + 52]]).collect();
        let memos: Vec<&[u8]> = actions.iter().map(|a| &a[160 + 52..160 + 564]).collect();
        let noncompact: Vec<&[u8]> =
            actions.iter().flat_map(|a| [&a[..32], &a[64..96], &a[160 + 564..]]).collect();
        hash(
            b"ZTxIdOrchardHash",
            &[
                &hash(b"ZTxIdOrcActCHash", &compact),
                &hash(b"ZTxIdOrcActMHash", &memos),
                &hash(b"ZTxIdOrcActNHash", &noncompact),
                flags,
                balance,
                anchor,
            ],
        )
    };
    Full { branch, lock_time, expiry, inputs, outputs, sapling, orchard }
}

#[test]
fn digests_are_zip_244s() {
    // zcash-test-vectors' ZIP-244 vectors (test-vectors/json/zip_0244.json at 78321beacb0e04): each
    // transaction's ID, and the signature digest of its transparent input, SIGHASH_ALL
    let vectors = json("zip_0244.json");
    let (mut ids, mut sigs) = (0, 0);
    for v in &vectors.as_array().unwrap()[2..] {
        let tx = full(&unhex(v[0].as_str().unwrap()));
        let header = header_digest(tx.branch, tx.lock_time, tx.expiry);
        let id =
            root(tx.branch, &header, &transparent_digest(&tx.inputs, &tx.outputs), &tx.sapling, &tx.orchard);
        assert_eq!(hex(&id), v[1].as_str().unwrap());
        ids += 1;
        let Some(i) = v[5].as_u64() else { continue };
        let amounts: Vec<u64> = v[3].as_array().unwrap().iter().map(|a| a.as_u64().unwrap()).collect();
        let scripts: Vec<Vec<u8>> =
            v[4].as_array().unwrap().iter().map(|s| unhex(s.as_str().unwrap())).collect();
        let spent: Vec<Spent> =
            amounts.iter().zip(&scripts).map(|(&amount, script)| Spent { amount, script }).collect();
        let shared = Shared::new(&tx.inputs, &tx.outputs, &spent);
        let transparent = shared.transparent_sig_digest(&tx.inputs, &spent, i as usize).unwrap();
        let digest = root(tx.branch, &header, &transparent, &tx.sapling, &tx.orchard);
        assert_eq!(hex(&digest), v[7].as_str().unwrap());
        sigs += 1;
    }
    assert_eq!((ids, sigs), (10, 6));
    // no input there, or nothing said of what it spends: no digest
    assert!(Shared::new(&[], &[], &[]).transparent_sig_digest(&[], &[], 0).is_none());
}

#[test]
fn addresses_are_zcashs() {
    let fixtures = json("transactions.json");
    let main = Account::new(keys(), Network::Mainnet).unwrap();
    let test = Account::new(keys(), Network::Testnet).unwrap();
    assert_eq!(main.address(Derivation { chain: 0, index: 0 }).unwrap(), ME);
    for a in fixtures["addresses"].as_array().unwrap() {
        let account = if a["network"] == 0 { &main } else { &test };
        let key =
            Derivation::new(a["chain"].as_u64().unwrap() as u8, a["index"].as_u64().unwrap() as u32).unwrap();
        assert_eq!(account.address(key).unwrap(), a["address"].as_str().unwrap());
        // and read back: the network and the key's hash
        let (network, kind) = address::decode(a["address"].as_str().unwrap()).unwrap();
        assert_eq!(network, account.network);
        assert_eq!(kind.script(), address::key_script(&account.key(key).unwrap()));
    }
    // the account's key and chain code, as zcash_transparent has them (`AccountPubKey`)
    assert_eq!(hex(&main.public.key), fixtures["account"]["key"].as_str().unwrap());
    assert_eq!(hex(&main.public.chain_code), fixtures["account"]["chainCode"].as_str().unwrap());
    assert_eq!(wallet::account_path(Network::Mainnet), [44 | 1 << 31, 133 | 1 << 31, 1 << 31]);
    assert_eq!(wallet::account_path(Network::Testnet), [44 | 1 << 31, 1 | 1 << 31, 1 << 31]);
    // other people's, as librustzcash writes them
    let payees = &fixtures["payees"];
    let hash_of = |text: &str| match address::decode(text).unwrap() {
        (_, Kind::PublicKeyHash(h) | Kind::ScriptHash(h) | Kind::Tex(h)) => h,
    };
    let sevens = hash_of(payees["p2pkh"].as_str().unwrap());
    assert_eq!(address::p2pkh(Network::Testnet, &sevens), payees["p2pkhTest"].as_str().unwrap());
    assert_eq!(address::p2sh(Network::Mainnet, &[0x11; 20]), payees["p2sh"].as_str().unwrap());
    assert_eq!(address::p2sh(Network::Testnet, &[0x11; 20]), payees["p2shTest"].as_str().unwrap());
    let nines = hash_of(payees["tex"].as_str().unwrap());
    assert_eq!(address::tex(Network::Mainnet, &nines), payees["tex"].as_str().unwrap());
    assert_eq!(address::tex(Network::Testnet, &nines), payees["texTest"].as_str().unwrap());
    assert_eq!(
        address::decode(payees["p2sh"].as_str().unwrap()),
        Some((Network::Mainnet, Kind::ScriptHash([0x11; 20])))
    );
}

#[test]
fn tex_addresses_are_zip_320s() {
    // zcash-test-vectors' ZIP-320 vectors: a t-address, its key's hash, its TEX address
    let vectors = json("zip_0320.json");
    let mut n = 0;
    for v in &vectors.as_array().unwrap()[2..] {
        let (t, hash, tex) = (v[0].as_str().unwrap(), unhex(v[1].as_str().unwrap()), v[2].as_str().unwrap());
        let hash: [u8; 20] = hash.try_into().unwrap();
        assert_eq!(address::decode(t), Some((Network::Mainnet, Kind::PublicKeyHash(hash))));
        assert_eq!(address::p2pkh(Network::Mainnet, &hash), t);
        assert_eq!(address::tex(Network::Mainnet, &hash), tex);
        assert_eq!(address::decode(tex), Some((Network::Mainnet, Kind::Tex(hash))));
        // all in capitals is the same address; some in capitals isn't one
        assert_eq!(address::decode(&tex.to_uppercase()), Some((Network::Mainnet, Kind::Tex(hash))));
        // (its first letter after the separator)
        let at = 4 + tex[4..].find(|c: char| c.is_ascii_lowercase()).unwrap();
        let mixed: String =
            tex.chars().enumerate().map(|(i, c)| if i == at { c.to_ascii_uppercase() } else { c }).collect();
        assert_eq!(address::decode(&mixed), None);
        n += 1;
    }
    assert_eq!(n, 15);
    let hash = [0x42; 20];
    // bech32 (BIP-173) rather than bech32m, another prefix, or other than 20 bytes: no TEX address
    let as_bech32 = bech32_encode::<bech32::Bech32>("tex", &hash);
    assert_eq!(address::decode(&as_bech32), None);
    assert_eq!(address::decode(&bech32_encode::<bech32::Bech32m>("zex", &hash)), None);
    assert_eq!(address::decode(&bech32_encode::<bech32::Bech32m>("tex", &[0x42; 21])), None);
    assert_eq!(address::decode(&bech32_encode::<bech32::Bech32m>("tex", &[0x42; 19])), None);
    // a t-address with a wrong checksum, another prefix, or other than 20 bytes
    let t = address::p2pkh(Network::Mainnet, &hash);
    let mut wrong = t.clone().into_bytes();
    wrong[10] = if wrong[10] == b'a' { b'b' } else { b'a' };
    assert_eq!(address::decode(std::str::from_utf8(&wrong).unwrap()), None);
    assert_eq!(address::decode(&address::base58check(&[&[0x1c, 0xb9][..], &hash].concat())), None);
    assert_eq!(address::decode(&address::base58check(&[&[0x1c, 0xb8][..], &[0x42; 21]].concat())), None);
    assert_eq!(address::decode(""), None);
    assert_eq!(address::decode("0OIl"), None);
}

fn bech32_encode<C: bech32::Checksum>(hrp: &str, data: &[u8]) -> String {
    bech32::encode::<C>(bech32::Hrp::parse(hrp).unwrap(), data).unwrap()
}

/// A transaction librustzcash made: its network, the request, the transaction unsigned and signed,
/// its ID, each input's signature hash, librustzcash's signatures (None for one maki mustn't sign),
/// the fee and ZIP-317's conventional fee as its fee rule works it out.
struct Fixture {
    name: String,
    network: Network,
    request: Vec<u8>,
    unsigned: Vec<u8>,
    signed: Vec<u8>,
    txid: Vec<u8>,
    sighashes: Vec<Vec<u8>>,
    signatures: Option<Vec<Vec<u8>>>,
    fee: u64,
    conventional_fee: u64,
}

fn fixtures() -> Vec<Fixture> {
    let list =
        |v: &serde_json::Value| v.as_array().unwrap().iter().map(|s| unhex(s.as_str().unwrap())).collect();
    json("transactions.json")["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| Fixture {
            name: f["name"].as_str().unwrap().into(),
            network: Network::from_byte(f["network"].as_u64().unwrap() as u8).unwrap(),
            request: unhex(f["request"].as_str().unwrap()),
            unsigned: unhex(f["unsigned"].as_str().unwrap()),
            signed: unhex(f["signed"].as_str().unwrap()),
            txid: unhex(f["txid"].as_str().unwrap()),
            sighashes: list(&f["sighashes"]),
            signatures: (!f["signatures"].is_null()).then(|| list(&f["signatures"])),
            fee: f["fee"].as_u64().unwrap(),
            conventional_fee: f["conventionalFee"].as_u64().unwrap(),
        })
        .collect()
}

fn fixture(name: &str) -> Fixture { fixtures().into_iter().find(|f| f.name == name).unwrap() }

/// Each input's script: its signature pushed, then its key pushed.
fn script_sigs(account: &Account, request: &Request, signatures: &[Vec<u8>]) -> Vec<Vec<u8>> {
    request
        .coins
        .iter()
        .zip(signatures)
        .map(|(coin, sig)| {
            let key = account.key(coin.key).unwrap();
            [&[sig.len() as u8][..], sig, &[33], &key].concat()
        })
        .collect()
}

#[test]
fn transactions_read_as_librustzcash_writes_them() {
    let fixtures = fixtures();
    assert_eq!(fixtures.len(), 12);
    for f in &fixtures {
        let request = Request::parse(&f.request).unwrap_or_else(|e| panic!("{}: {e}", f.name));
        // the transaction and the request, written back as they came
        assert_eq!(request.tx.bytes(), f.unsigned, "{}", f.name);
        assert_eq!(request.bytes(), f.request, "{}", f.name);
        assert_eq!(Transaction::parse(&f.unsigned).unwrap(), request.tx);
        // its ID, the same signed or not
        assert_eq!(sighash::txid(&request.tx).to_vec(), f.txid, "{}", f.name);
        // each input's signature hash, ZIP-244's as zcash_primitives works it out
        let spent = request.coins.iter().map(|c| Spent { amount: c.amount, script: &c.script }).collect();
        let signing = Signing::new(&request.tx, spent);
        for (i, want) in f.sighashes.iter().enumerate() {
            assert_eq!(signing.signature_hash(i).unwrap().to_vec(), *want, "{} input {i}", f.name);
        }
        assert!(signing.signature_hash(f.sighashes.len()).is_none());
        assert_eq!(request.fee().unwrap(), f.fee, "{}", f.name);
        assert_eq!(conventional_fee(&request), f.conventional_fee, "{}", f.name);
    }
}

#[test]
fn maki_signs_as_librustzcash_signs() {
    let mut signed = 0;
    for f in fixtures() {
        let Some(theirs) = &f.signatures else { continue };
        let account = Account::new(keys(), f.network).unwrap();
        let request = Request::parse(&f.request).unwrap();
        let checked = account.check(&request).unwrap();
        let ours = account.sign(&checked).unwrap();
        // RFC 6979 and low S, DER, SIGHASH_ALL: the very bytes
        assert_eq!(ours, *theirs, "{}", f.name);
        // and the transaction they make, signed, the one librustzcash wrote
        assert_eq!(request.tx.write(&script_sigs(&account, &request, &ours)), f.signed, "{}", f.name);
        signed += 1;
    }
    assert_eq!(signed, 11);
}

#[test]
fn reviews_say_what_they_should() {
    let review = |name: &str| {
        let f = fixture(name);
        let request = Box::leak(Box::new(Request::parse(&f.request).unwrap()));
        let account = Account::new(keys(), f.network).unwrap();
        maki_zec::display::review(&account.check(request).unwrap())
    };
    let json = json("transactions.json");
    let payee = json["payees"]["p2pkh"].as_str().unwrap();
    let r = review("payment");
    assert_eq!(
        r.pages,
        [
            p("Send", "1 ZEC", payee, ""),
            p("Change", "0.4999 ZEC", "back to you", ""),
            p("Fee", "0.0001 ZEC", "", "ZIP-317's conventional fee.")
        ]
    );
    assert_eq!(r.summary, "sends 1 ZEC; fee 0.0001 ZEC");
    let r = review("three-payments");
    let headings: Vec<(&str, &str)> = r.pages.iter().map(|p| (p.heading.as_str(), p.mono.as_str())).collect();
    assert_eq!(
        headings,
        [
            ("Send 1/3", payee),
            ("Send 2/3", json["payees"]["p2sh"].as_str().unwrap()),
            ("Send 3/3", json["transactions"][2]["outputs"][2]["address"].as_str().unwrap()),
            ("Change", "back to you"),
            ("Fee", "")
        ]
    );
    assert_eq!(r.summary, "sends 3.5 ZEC in 3 payments; fee 0.0002 ZEC");
    // a TEX address, as the owner gave it
    let r = review("tex");
    assert_eq!(
        r.pages[0],
        p(
            "Send",
            "0.075 ZEC",
            json["payees"]["tex"].as_str().unwrap(),
            "A TEX address: it takes coins from transparent transactions alone, as this is."
        )
    );
    // data for all to read, and its outputs' fee
    let r = review("data");
    let headings: Vec<&str> = r.pages.iter().map(|p| p.heading.as_str()).collect();
    assert_eq!(headings, ["Send", "Change", "Data", "Fee"]);
    assert_eq!((r.pages[2].value.as_str(), r.pages[2].mono.as_str()), ("", "maki"));
    assert_eq!(r.pages[3], p("Fee", "0.00015 ZEC", "", "ZIP-317's conventional fee."));
    assert_eq!(r.summary, "sends 0.01 ZEC with data; fee 0.00015 ZEC");
    // a lock time that holds: the block it waits for
    let r = review("lock-time");
    assert_eq!(
        r.pages[1],
        p("Not before", "block 3600000", "", "It can't be confirmed until Zcash's chain is this long.")
    );
    // a fee that's a mistake, and one that may never be mined
    let r = review("high-fee");
    assert_eq!(
        r.pages[1],
        p(
            "High fee!",
            "1 ZEC",
            "",
            "More than a tenth of what it sends: ZIP-317's conventional fee is 0.0001 ZEC."
        )
    );
    assert_eq!(r.summary, "sends 0.5 ZEC; high fee 1 ZEC!");
    let r = review("low-fee");
    assert_eq!(
        r.pages[1],
        p(
            "Fee",
            "0.00001 ZEC",
            "",
            "Less than ZIP-317's conventional fee of 0.0001 ZEC: it may never be mined."
        )
    );
    assert_eq!(r.summary, "sends 1.49999 ZEC; low fee 0.00001 ZEC");
    // the test network's coins are TAZ, its addresses `tm…`
    let r = review("testnet");
    assert_eq!(r.pages[0], p("Send", "1 TAZ", json["payees"]["p2pkhTest"].as_str().unwrap(), ""));
    assert_eq!(r.summary, "sends 1 TAZ; fee 0.0001 TAZ");
    // the most a message holds: 49 coins, their fee ZIP-317's for 49 actions
    let r = review("many-inputs");
    let headings: Vec<&str> = r.pages.iter().map(|p| p.heading.as_str()).collect();
    assert_eq!(headings, ["Send", "Change", "Fee"]);
    assert_eq!(r.pages[2].value, "0.00245 ZEC");
}

/// A fixture's request with its transaction changed by `f`, the rest as it was.
fn with_tx(name: &str, f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let request = fixture(name).request;
    let n = u16::from_le_bytes([request[0], request[1]]) as usize;
    let mut tx = request[2..2 + n].to_vec();
    f(&mut tx);
    [&(tx.len() as u16).to_le_bytes()[..], &tx, &request[2 + n..]].concat()
}

/// What maki says of a request: why it won't, or that it would.
fn why(request: &[u8]) -> Result<(), Error> {
    let request = Request::parse(request)?;
    Account::new(keys(), Network::Mainnet).unwrap().check(&request).map(|_| ())
}

#[test]
fn what_zcash_refuses_maki_refuses_first() {
    // not this wallet's coin: another phrase's key
    let theirs = fixture("not-mine");
    assert_eq!(why(&theirs.request), Err(Error::NotOurs(0)));
    assert_eq!(
        Error::NotOurs(0).to_string(),
        "input 0 isn't this wallet's (maki signs for Zcash's transparent account, m/44'/133'/0')"
    );
    // the test network's coins aren't the main network's account's: other keys
    assert_eq!(why(&fixture("testnet").request), Err(Error::NotOurs(0)));
    // version 6, as wallets make by default since NU6.3 (librustzcash's builder, signed)
    let v6 = unhex(json("transactions.json")["version6"].as_str().unwrap());
    assert_eq!(Transaction::parse(&v6), Err(Error::Version(tx::VERSION_6)));
    assert_eq!(
        Error::Version(tx::VERSION_6).to_string(),
        "a version 6 transaction (ZIP 229, NU6.3's): maki reads version 5, which Zcash still takes"
    );
    // version 4, and a header without the overwintered flag
    for (header, version) in [(0x8000_0004u32, tx::VERSION_4), (0x0000_0005, 5)] {
        let r = with_tx("payment", |t| t[..4].copy_from_slice(&header.to_le_bytes()));
        assert_eq!(why(&r), Err(Error::Version(version)));
    }
    assert_eq!(why(&with_tx("payment", |t| t[4] ^= 1)), Err(Error::Group));
    // a transaction for an upgrade gone by, or one maki doesn't know: named
    let nu6_2 = with_tx("payment", |t| t[8..12].copy_from_slice(&0x5437_f330u32.to_le_bytes()));
    assert_eq!(why(&nu6_2), Err(Error::Branch(0x5437_f330)));
    assert_eq!(
        Error::Branch(0x5437_f330).to_string(),
        "a transaction for NU6.2's rules (consensus branch 5437f330), which Zcash has left behind: it follows NU6.3's"
    );
    let nu7 = with_tx("payment", |t| t[8..12].copy_from_slice(&0x7719_0ad9u32.to_le_bytes()));
    assert_eq!(
        why(&nu7).unwrap_err().to_string(),
        "a transaction for a network upgrade maki doesn't know (consensus branch 77190ad9): it signs for NU6.3's, the one in force"
    );
    assert_eq!(BRANCH_ID, json("transactions.json")["branchId"].as_u64().unwrap() as u32);
    // an expiry Zcash takes no more
    let expiry = with_tx("payment", |t| t[16..20].copy_from_slice(&500_000_000u32.to_le_bytes()));
    assert_eq!(why(&expiry), Err(Error::Expiry));
    // shielded parts, each by name, after the transparent ones
    for (from_end, what) in [(3, "Sapling spends"), (2, "Sapling outputs"), (1, "Orchard actions")] {
        let r = with_tx("payment", |t| {
            let at = t.len() - from_end;
            t[at] = 1;
        });
        assert_eq!(why(&r), Err(Error::Shielded(what)));
    }
    assert_eq!(
        Error::Shielded("Orchard actions").to_string(),
        "a transaction with Orchard actions, which are shielded: maki can't see into them, and signs transparent transactions only"
    );
    // a transaction already signed, read as one to sign
    let f = fixture("payment");
    let signed =
        [&(f.signed.len() as u16).to_le_bytes()[..], &f.signed, &f.request[2 + f.unsigned.len()..]].concat();
    assert_eq!(why(&signed), Err(Error::Signed));
}

#[test]
fn what_doesnt_add_up_is_refused() {
    let base = fixture("two-coins").request;
    let tx_len = u16::from_le_bytes([base[0], base[1]]) as usize;
    // where the coins are said in the request: after the transaction; each 8 + 1 + 25 + 1 + 4 bytes
    let coin = 2 + tx_len;
    let changed = |at: usize, bytes: &[u8]| {
        let mut r = base.clone();
        r[at..at + bytes.len()].copy_from_slice(bytes);
        r
    };
    // outputs that pay more than the coins hold
    assert_eq!(why(&changed(coin, &1u64.to_le_bytes())), Err(Error::NegativeFee));
    // a coin holding more than there can be
    assert_eq!(why(&changed(coin, &(MAX_MONEY + 1).to_le_bytes())), Err(Error::Amount));
    // coins that add up to more than there can be (each one less)
    let both = {
        let r = changed(coin, &MAX_MONEY.to_le_bytes());
        let mut r = r;
        r[coin + 39..coin + 47].copy_from_slice(&MAX_MONEY.to_le_bytes());
        r
    };
    assert_eq!(why(&both), Err(Error::Amount));
    // a coin said to pay another script than its key's: not this wallet's
    assert_eq!(why(&changed(coin + 13, &[0x55])), Err(Error::NotOurs(0)));
    // a key off the account's chains, or hardened
    assert_eq!(why(&changed(coin + 34, &[2])), Err(Error::Path));
    assert_eq!(why(&changed(coin + 35, &(1u32 << 31).to_le_bytes())), Err(Error::Path));
    // the same coin twice: the second input's coin the first's
    let twice = with_tx("two-coins", |t| {
        let first = t[21..57].to_vec();
        t[62..98].copy_from_slice(&first);
    });
    assert_eq!(why(&twice), Err(Error::Duplicate(1)));
    // a coinbase's null coin
    let null = with_tx("payment", |t| {
        t[21..53].copy_from_slice(&[0; 32]);
        t[53..57].copy_from_slice(&u32::MAX.to_le_bytes());
    });
    assert_eq!(why(&null), Err(Error::Coinbase(0)));
    // change that doesn't pay the key it names; a TEX showing of what isn't a key's hash; a showing
    // the format hasn't
    let payment = fixture("payment").request;
    let last = payment.len() - 6;
    let mut wrong_change = payment.clone();
    wrong_change[last + 2] = 1;
    assert_eq!(why(&wrong_change), Err(Error::NotChange(1)));
    let three = fixture("three-payments").request;
    let shown = three.len() - (1 + 1 + 1 + 6);
    let mut tex_p2sh = three.clone();
    tex_p2sh[shown + 1] = 2;
    assert_eq!(why(&tex_p2sh), Err(Error::NotTex(1)));
    let mut flag = payment.clone();
    flag[last - 1] = 3;
    assert_eq!(why(&flag), Err(Error::Flag));
    // cut short, more after it, bigger than a message
    assert_eq!(why(&payment[..payment.len() - 1]), Err(Error::Length));
    assert_eq!(why(&[&payment[..], &[0]].concat()), Err(Error::Length));
    assert_eq!(why(&vec![0; MAX_REQUEST + 1]), Err(Error::TooBig));
    assert_eq!(why(&[]), Err(Error::Length));
}

#[test]
fn outputs_maki_cant_show_are_refused() {
    let account = Account::new(keys(), Network::Mainnet).unwrap();
    let f = fixture("payment");
    let mut request = Request::parse(&f.request).unwrap();
    // a script that's no address and no data: nobody can say who it pays
    for script in [vec![0x51], vec![0x6a, 0x51], vec![0x6a, 0x04, 1, 2, 3], vec![0x6a; 84]] {
        request.tx.outputs[0].script = script.clone();
        assert_eq!(account.check(&request).err(), Some(Error::NonStandard(0)), "{script:02x?}");
    }
    // data, pushed: shown
    for (script, carried) in [
        (vec![0x6a], vec![]),
        (vec![0x6a, 0x00], vec![]),
        (vec![0x6a, 0x02, 0xab, 0xcd, 0x01, 0xef], vec![0xab, 0xcd, 0xef]),
        (vec![0x6a, 0x4c, 0x01, 0x07], vec![0x07]),
        (vec![0x6a, 0x4d, 0x01, 0x00, 0x09], vec![0x09]),
    ] {
        assert_eq!(data(&script), Some(carried.clone()));
        request.tx.outputs[0].script = script;
        assert!(matches!(&account.check(&request).unwrap().outputs[0], Paid::Data(d) if *d == carried));
    }
    // no inputs or no outputs: no transaction Zcash takes
    let mut empty = request.clone();
    empty.tx.outputs.clear();
    empty.outputs.clear();
    assert_eq!(account.check(&empty).err(), Some(Error::Empty));
    let mut empty = request.clone();
    empty.tx.inputs.clear();
    empty.coins.clear();
    assert_eq!(account.check(&empty).err(), Some(Error::Empty));
    // more inputs than a message's answer holds
    let mut many = request.clone();
    for i in 0..tx::MAX_INPUTS {
        many.tx.inputs.push(TxIn { txid: [i as u8 + 9; 32], index: 0, sequence: u32::MAX });
        many.coins.push(Coin { amount: 1, script: many.coins[0].script.clone(), key: many.coins[0].key });
    }
    assert_eq!(account.check(&many).err(), Some(Error::TooMany));
    assert_eq!(Transaction::parse(&many.tx.bytes()), Err(Error::TooMany));
    // the showing and the outputs must match up
    let mut short = request.clone();
    short.outputs.pop();
    assert_eq!(short.check(), Err(Error::Length));
    let _ = Shown::Payment;
}

#[test]
fn amounts_and_dates_read_exactly() {
    assert_eq!(zec(0, Network::Mainnet), "0 ZEC");
    assert_eq!(zec(1, Network::Mainnet), "0.00000001 ZEC");
    assert_eq!(zec(150_000_000, Network::Testnet), "1.5 TAZ");
    assert_eq!(zec(MAX_MONEY, Network::Mainnet), "21000000 ZEC");
    assert_eq!(decimals(10_000, 8), "0.0001");
    assert_eq!(date(1_790_985_600), "2026-10-03 00:00:00 UTC");
    assert_eq!(date(0), "1970-01-01 00:00:00 UTC");
    // a lock time in seconds, past 500,000,000: a date
    let f = fixture("lock-time");
    let mut request = Request::parse(&f.request).unwrap();
    request.tx.lock_time = 1_800_000_000;
    let account = Account::new(keys(), Network::Mainnet).unwrap();
    let r = maki_zec::display::review(&account.check(&request).unwrap());
    assert_eq!(
        r.pages[1],
        p("Not before", "2027-01-15 08:00:00 UTC", "", "It can't be confirmed before then.")
    );
    // a lock time with every sequence final holds nothing: no page
    request.tx.inputs[0].sequence = u32::MAX;
    let r = maki_zec::display::review(&account.check(&request).unwrap());
    assert_eq!(r.pages.len(), 2);
    // the address page
    let key = Derivation { chain: 1, index: 4 };
    assert_eq!(
        maki_zec::display::address_page("t1x", key, Network::Testnet),
        p("Change #4", "zcash testnet", "t1x", "")
    );
}

#[test]
fn locked_maki_has_no_account() {
    struct Locked;
    impl maki_hd::Keys for Locked {
        fn fingerprint(&self) -> Result<[u8; 4], maki_hd::Error> { Err(maki_hd::Error::Locked) }

        fn public(&self, _: &[u32]) -> Result<maki_hd::Public, maki_hd::Error> { Err(maki_hd::Error::Locked) }

        fn uncompressed(&self, _: &[u32]) -> Result<[u8; 65], maki_hd::Error> { Err(maki_hd::Error::Locked) }

        fn taproot_output(&self, _: &[u32]) -> Result<[u8; 32], maki_hd::Error> {
            Err(maki_hd::Error::Locked)
        }

        fn sign_ecdsa(&self, _: &[u32], _: &[u8; 32]) -> Result<([u8; 64], u8), maki_hd::Error> {
            Err(maki_hd::Error::Locked)
        }

        fn sign_schnorr(
            &self,
            _: &[u32],
            _: &[u8; 32],
            _: maki_hd::Tweak,
        ) -> Result<[u8; 64], maki_hd::Error> {
            Err(maki_hd::Error::Locked)
        }
    }
    assert_eq!(Account::new(&Locked, Network::Mainnet).err(), Some(Error::Keys(maki_hd::Error::Locked)));
    assert_eq!(Error::Keys(maki_hd::Error::Locked).to_string(), "maki is locked");
}
