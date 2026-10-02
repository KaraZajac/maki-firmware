//! Zcash's transparent transactions for maki-zec's tests, made by librustzcash, Zcash's own Rust
//! library, which Zashi and zcashd's successor Zallet build on: the test phrase's keys and
//! addresses as zcash_transparent derives them (BIP44 at `m/44'/133'/0'`, the test network's at
//! coin type 1), and transactions of each kind the Zcash app reads, version 5 (ZIP-225) at NU6.3's
//! consensus branch, the one in force on 2026-10-02: each one's signature hashes (ZIP-244) by
//! zcash_primitives, signed as zcash_transparent signs them (secp256k1's RFC 6979, low S, DER,
//! SIGHASH_ALL), and written by zcash_primitives, unsigned and signed; with the request maki
//! desktop sends the app for it (`maki_zec::request`). The ones a wallet's builder can make are
//! made by zcash_primitives' builder too (its ZIP-317 fee, its expiry), and must come out the same.
//! To make them again, in a scratch folder:
//!   cargo new --bin make && cd make && cp <this file> src/main.rs
//!   cargo add zcash_primitives@=0.30.1 --features transparent-inputs,non-standard-fees
//!   cargo add zcash_transparent@=0.10.0 --rename transparent --features transparent-inputs
//!   cargo add sapling-crypto@=0.7.0 --rename sapling --features test-dependencies
//!   cargo add zcash_protocol@=0.10.6 zcash_address@=0.13.0 zcash_script@=0.4.5 orchard@=0.15.5
//!   cargo add zip32@=0.2.1 secp256k1@=0.29.1 bip0039@=0.12.0 serde_json@1
//!   cargo add rand_core@0.6 --features getrandom
//!   cargo run --release > transactions.json

use std::fmt::Write as _;

use rand_core::OsRng;
use sapling::prover::mock::{MockOutputProver, MockSpendProver};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{Value, json};
use transparent::address::{Script, TransparentAddress};
use transparent::builder::TransparentSigningSet;
use transparent::bundle::{Authorized as TAuthorized, Bundle, OutPoint, TxIn, TxOut};
use transparent::keys::{AccountPrivKey, NonHardenedChildIndex};
use transparent::sighash::{SighashType, TransparentAuthorizingContext};
use zcash_address::{ToAddress, ZcashAddress};
use zcash_primitives::transaction::builder::{BuildConfig, Builder};
use zcash_primitives::transaction::fees::{fixed, zip317};
use zcash_primitives::transaction::sighash::{SignableInput, signature_hash};
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{Authorization, Authorized, TransactionData, TxVersion};
use zcash_protocol::consensus::{BlockHeight, BranchId, MainNetwork, NetworkType, Parameters, TestNetwork};
use zcash_protocol::value::Zatoshis;
use zip32::AccountId;

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// Mainnet's height on 2026-10-02 (NU6.3's since 3,428,143), and the test network's (since 4,134,000).
const MAIN_HEIGHT: u32 = 3_503_905;
const TEST_HEIGHT: u32 = 4_434_184;

fn hex(b: &[u8]) -> String { b.iter().fold(String::new(), |mut s, x| { let _ = write!(s, "{x:02x}"); s }) }

/// A coin's spending conditions, the way a transaction's signature hash needs them: what each input
/// spends (ZIP-244 commits to every one's amount and script).
#[derive(Debug)]
struct Coins(Vec<TxOut>);

impl transparent::bundle::Authorization for Coins {
    type ScriptSig = ();
}

impl TransparentAuthorizingContext for Coins {
    fn input_amounts(&self) -> Vec<Zatoshis> { self.0.iter().map(|c| c.value()).collect() }

    fn input_scriptpubkeys(&self) -> Vec<Script> { self.0.iter().map(|c| c.script_pubkey().clone()).collect() }
}

/// A transaction about to be signed: transparent, its coins known.
#[derive(Debug)]
struct Unsigned;

impl Authorization for Unsigned {
    type OrchardAuth = orchard::bundle::Authorized;
    type SaplingAuth = sapling::bundle::Authorized;
    type TransparentAuth = Coins;
}

/// The test phrase's keys, on a network.
struct Keys {
    secp: Secp256k1<secp256k1::All>,
    account: AccountPrivKey,
    net: NetworkType,
}

impl Keys {
    fn new(seed: &[u8], main: bool) -> Keys {
        let account = if main {
            AccountPrivKey::from_seed(&MainNetwork, seed, AccountId::ZERO).unwrap()
        } else {
            AccountPrivKey::from_seed(&TestNetwork, seed, AccountId::ZERO).unwrap()
        };
        let net = if main { NetworkType::Main } else { NetworkType::Test };
        Keys { secp: Secp256k1::new(), account, net }
    }

    /// The key at `chain`/`index` under the account: 0 receiving, 1 change.
    fn secret(&self, chain: u8, index: u32) -> SecretKey {
        let i = NonHardenedChildIndex::from_index(index).unwrap();
        if chain == 0 {
            self.account.derive_external_secret_key(i).unwrap()
        } else {
            self.account.derive_internal_secret_key(i).unwrap()
        }
    }

    fn public(&self, chain: u8, index: u32) -> PublicKey {
        PublicKey::from_secret_key(&self.secp, &self.secret(chain, index))
    }

    fn address(&self, chain: u8, index: u32) -> String {
        p2pkh_address(self.net, &self.public(chain, index))
    }
}

fn hash160(pk: &PublicKey) -> [u8; 20] {
    match TransparentAddress::from_pubkey(pk) {
        TransparentAddress::PublicKeyHash(h) => h,
        TransparentAddress::ScriptHash(_) => unreachable!(),
    }
}

fn p2pkh_address(net: NetworkType, pk: &PublicKey) -> String {
    ZcashAddress::from_transparent_p2pkh(net, hash160(pk)).encode()
}

fn script(addr: &TransparentAddress) -> Script { addr.script().into() }

/// Someone else's key: a secret of `fill`s.
fn others(fill: u8) -> PublicKey {
    PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[fill; 32]).unwrap())
}

/// Where an output goes, and how the request says to show it.
#[derive(Clone)]
enum Pay {
    /// Someone's address: its script, shown by its t-address.
    To(TransparentAddress),
    /// The same, shown as a TEX address (ZIP-320): pay-to-key-hash only.
    Tex([u8; 20]),
    /// Data, OP_RETURN.
    Data(Vec<u8>),
    /// This wallet's change, at a key of its change chain.
    Change(u32),
}

/// A coin of this wallet's (or `foreign`, someone else's) to spend: its key, and what it holds.
#[derive(Clone)]
struct Coin {
    chain: u8,
    index: u32,
    value: u64,
    foreign: bool,
}

struct Spec {
    name: &'static str,
    main: bool,
    coins: Vec<Coin>,
    outputs: Vec<(Pay, u64)>,
    lock_time: u32,
    sequence: u32,
    expiry: u32,
}

fn outpoint(n: usize, coin: &Coin) -> OutPoint {
    let mut txid = [0u8; 32];
    txid[0] = n as u8 + 1;
    txid[1] = coin.index as u8;
    txid[31] = 0x5a;
    OutPoint::new(txid, coin.index % 3)
}

fn output(keys: &Keys, pay: &Pay, value: u64) -> TxOut {
    let script = match pay {
        Pay::To(a) => script(a),
        Pay::Tex(h) => script(&TransparentAddress::PublicKeyHash(*h)),
        Pay::Data(d) => {
            let mut s = vec![0x6a, d.len() as u8];
            s.extend_from_slice(d);
            Script(zcash_script::script::Code(s))
        }
        Pay::Change(i) => script(&TransparentAddress::from_pubkey(&keys.public(1, *i))),
    };
    TxOut::new(Zatoshis::from_u64(value).unwrap(), script)
}

fn write_tx(tx: TransactionData<Authorized>) -> (Vec<u8>, [u8; 32]) {
    let tx = tx.freeze().unwrap();
    let mut bytes = Vec::new();
    tx.write(&mut bytes).unwrap();
    (bytes, *tx.txid().as_ref())
}

/// The ZIP-317 conventional fee for a transparent transaction of these coins and outputs, as
/// zcash_primitives' fee rule works it out: the builder, given them, says.
fn conventional(keys: &Keys, coins: &[(SecretKey, OutPoint, TxOut)], outputs: &[TxOut], main: bool) -> u64 {
    fn fee<P: Parameters>(params: P, height: u32, coins: &[(SecretKey, OutPoint, TxOut)], outputs: &[TxOut]) -> u64 {
        let mut b = Builder::new(params, BlockHeight::from_u32(height), standard());
        b.propose_version::<std::convert::Infallible>(TxVersion::V5).unwrap();
        let secp = Secp256k1::new();
        for (sk, op, coin) in coins {
            b.add_transparent_p2pkh_input(PublicKey::from_secret_key(&secp, sk), op.clone(), coin.clone()).unwrap();
        }
        for o in outputs {
            match o.recipient_address() {
                Some(a) => b.add_transparent_output(&a, o.value()).unwrap(),
                None => {
                    let data = &o.script_pubkey().0.0[2..];
                    b.add_transparent_null_data_output::<std::convert::Infallible>(data).unwrap()
                }
            }
        }
        u64::from(b.get_fee(&zip317::FeeRule::standard()).unwrap())
    }
    let _ = keys;
    if main { fee(MainNetwork, MAIN_HEIGHT, coins, outputs) } else { fee(TestNetwork, TEST_HEIGHT, coins, outputs) }
}

fn standard() -> BuildConfig {
    BuildConfig::Standard {
        sapling_anchor: None,
        orchard_anchor: None,
        ironwood_anchor: None,
        orchard_padding: zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
        ironwood_padding: zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
    }
}

/// The same payment by zcash_primitives' builder, as a wallet makes it: its fee (given), its
/// expiry (forty blocks on), every input's sequence final and no lock time; the signed bytes.
fn built<P: Parameters + Clone>(
    params: P,
    height: u32,
    coins: &[(SecretKey, OutPoint, TxOut)],
    outputs: &[TxOut],
    fee: u64,
    version: TxVersion,
) -> Vec<u8> {
    let mut b = Builder::new(params, BlockHeight::from_u32(height), standard());
    b.propose_version::<std::convert::Infallible>(version).unwrap();
    let mut set = TransparentSigningSet::new();
    for (sk, op, coin) in coins {
        let pk = set.add_key(*sk);
        b.add_transparent_p2pkh_input(pk, op.clone(), coin.clone()).unwrap();
    }
    for o in outputs {
        match o.recipient_address() {
            Some(a) => b.add_transparent_output(&a, o.value()).unwrap(),
            None => {
                let data = &o.script_pubkey().0.0[2..];
                b.add_transparent_null_data_output::<std::convert::Infallible>(data).unwrap()
            }
        }
    }
    let rule = fixed::FeeRule::non_standard(Zatoshis::from_u64(fee).unwrap());
    let res = b.build(&set, &[], &[], OsRng, &MockSpendProver, &MockOutputProver, &rule).unwrap();
    let mut bytes = Vec::new();
    res.transaction().write(&mut bytes).unwrap();
    bytes
}

fn make(spec: &Spec, seed: &[u8], other_seed: &[u8]) -> Value {
    let keys = Keys::new(seed, spec.main);
    let theirs = Keys::new(other_seed, spec.main);
    let branch = BranchId::Nu6_3;
    let (height, net_byte) = if spec.main { (MAIN_HEIGHT, 0) } else { (TEST_HEIGHT, 1) };
    let coins: Vec<(SecretKey, OutPoint, TxOut)> = spec
        .coins
        .iter()
        .enumerate()
        .map(|(n, c)| {
            let k = if c.foreign { &theirs } else { &keys };
            let sk = k.secret(c.chain, c.index);
            let pk = PublicKey::from_secret_key(&k.secp, &sk);
            let coin = TxOut::new(Zatoshis::from_u64(c.value).unwrap(), script(&TransparentAddress::from_pubkey(&pk)));
            (sk, outpoint(n, c), coin)
        })
        .collect();
    let outputs: Vec<TxOut> = spec.outputs.iter().map(|(p, v)| output(&keys, p, *v)).collect();
    let expiry = BlockHeight::from_u32(spec.expiry);
    // unsigned, its coins known: the signature hashes
    let unsigned = TransactionData::<Unsigned>::from_parts(
        TxVersion::V5,
        branch,
        spec.lock_time,
        expiry,
        Some(Bundle {
            vin: coins.iter().map(|(_, op, _)| TxIn::from_parts(op.clone(), (), spec.sequence)).collect(),
            vout: outputs.clone(),
            authorization: Coins(coins.iter().map(|(_, _, c)| c.clone()).collect()),
        }),
        None,
        None,
        None,
    );
    let txid_parts = unsigned.digest(TxIdDigester);
    let bundle = unsigned.transparent_bundle().unwrap();
    let mut sighashes = Vec::new();
    let mut signatures = Vec::new();
    let mut script_sigs = Vec::new();
    for (i, (sk, _, coin)) in coins.iter().enumerate() {
        let input = transparent::sighash::SignableInput::from_parts(
            bundle,
            SighashType::ALL,
            i,
            coin.script_pubkey(),
            coin.script_pubkey(),
            coin.value(),
        )
        .unwrap();
        let sighash = signature_hash(&unsigned, &SignableInput::Transparent(input), &txid_parts);
        let digest: [u8; 32] = *sighash.as_ref();
        sighashes.push(hex(&digest));
        let sig = keys.secp.sign_ecdsa(&Message::from_digest(digest), sk);
        let mut der = sig.serialize_der().to_vec();
        der.push(1);
        let pk = PublicKey::from_secret_key(&keys.secp, sk).serialize();
        let mut script_sig = vec![der.len() as u8];
        script_sig.extend_from_slice(&der);
        script_sig.push(pk.len() as u8);
        script_sig.extend_from_slice(&pk);
        signatures.push(hex(&der));
        script_sigs.push(script_sig);
    }
    let with = |sigs: Option<&[Vec<u8>]>| {
        TransactionData::<Authorized>::from_parts(
            TxVersion::V5,
            branch,
            spec.lock_time,
            expiry,
            Some(Bundle {
                vin: coins
                    .iter()
                    .enumerate()
                    .map(|(i, (_, op, _))| {
                        let s = sigs.map_or(vec![], |s| s[i].clone());
                        TxIn::<TAuthorized>::from_parts(op.clone(), Script(zcash_script::script::Code(s)), spec.sequence)
                    })
                    .collect(),
                vout: outputs.clone(),
                authorization: TAuthorized,
            }),
            None,
            None,
            None,
        )
    };
    let (unsigned_bytes, txid) = write_tx(with(None));
    let (signed_bytes, signed_txid) = write_tx(with(Some(&script_sigs)));
    assert_eq!(txid, signed_txid, "a signature changes no txid");
    // the request maki desktop sends: the transaction, then each coin and each output's showing
    let mut request = (unsigned_bytes.len() as u16).to_le_bytes().to_vec();
    request.extend_from_slice(&unsigned_bytes);
    for (c, (_, _, coin)) in spec.coins.iter().zip(&coins) {
        request.extend_from_slice(&c.value.to_le_bytes());
        let s = &coin.script_pubkey().0.0;
        request.push(s.len() as u8);
        request.extend_from_slice(s);
        request.push(c.chain);
        request.extend_from_slice(&c.index.to_le_bytes());
    }
    for (pay, _) in &spec.outputs {
        match pay {
            Pay::Change(i) => {
                request.push(1);
                request.push(1);
                request.extend_from_slice(&i.to_le_bytes());
            }
            Pay::Tex(_) => request.push(2),
            _ => request.push(0),
        }
    }
    let fee: u64 = spec.coins.iter().map(|c| c.value).sum::<u64>() - spec.outputs.iter().map(|(_, v)| v).sum::<u64>();
    let conventional = conventional(&keys, &coins, &outputs, spec.main);
    // what a wallet's builder makes of it, where it can: the same bytes
    let wallet_made = spec.lock_time == 0 && spec.sequence == u32::MAX && spec.expiry == height + 40;
    if wallet_made {
        let theirs = if spec.main {
            built(MainNetwork, height, &coins, &outputs, fee, TxVersion::V5)
        } else {
            built(TestNetwork, height, &coins, &outputs, fee, TxVersion::V5)
        };
        assert_eq!(hex(&theirs), hex(&signed_bytes), "{}: the builder makes it otherwise", spec.name);
    }
    let foreign = spec.coins.iter().any(|c| c.foreign);
    let mut mine = 0;
    let shown: Vec<Value> = spec
        .outputs
        .iter()
        .map(|(pay, value)| {
            let addr = match pay {
                Pay::To(TransparentAddress::PublicKeyHash(h)) => {
                    ZcashAddress::from_transparent_p2pkh(keys.net, *h).encode()
                }
                Pay::To(TransparentAddress::ScriptHash(h)) => ZcashAddress::from_transparent_p2sh(keys.net, *h).encode(),
                Pay::Tex(h) => ZcashAddress::from_tex(keys.net, *h).encode(),
                Pay::Data(d) => format!("data {}", hex(d)),
                Pay::Change(i) => {
                    mine += 1;
                    keys.address(1, *i)
                }
            };
            json!({ "address": addr, "value": value })
        })
        .collect();
    json!({
        "name": spec.name,
        "network": net_byte,
        "unsigned": hex(&unsigned_bytes),
        "signed": hex(&signed_bytes),
        "txid": hex(&txid),
        "request": hex(&request),
        "sighashes": sighashes,
        "signatures": if foreign { Value::Null } else { json!(signatures) },
        "fee": fee,
        "conventionalFee": conventional,
        "builder": wallet_made,
        "outputs": shown,
        "change": mine,
    })
}

fn main() {
    let mnemonic = bip0039::Mnemonic::<bip0039::English>::from_phrase(PHRASE).unwrap();
    let seed = mnemonic.to_seed("");
    let other = bip0039::Mnemonic::<bip0039::English>::from_phrase(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    )
    .unwrap()
    .to_seed("");
    let main = Keys::new(&seed, true);
    let test = Keys::new(&seed, false);
    let account = main.account.to_account_pubkey().serialize();
    let mut addresses = Vec::new();
    for (keys, net) in [(&main, 0), (&test, 1)] {
        for (chain, index) in [(0u8, 0u32), (0, 1), (0, 2), (1, 0), (1, 1)] {
            addresses.push(json!({ "network": net, "chain": chain, "index": index, "address": keys.address(chain, index) }));
        }
    }
    let payee = TransparentAddress::from_pubkey(&others(7));
    let payee2 = TransparentAddress::from_pubkey(&others(8));
    let script_payee = TransparentAddress::ScriptHash([0x11; 20]);
    let tex = hash160(&others(9));
    let mine = |chain: u8, index: u32, value: u64| Coin { chain, index, value, foreign: false };
    let wallet = |main: bool, coins, outputs| Spec {
        name: "",
        main,
        coins,
        outputs,
        lock_time: 0,
        sequence: u32::MAX,
        expiry: if main { MAIN_HEIGHT + 40 } else { TEST_HEIGHT + 40 },
    };
    let mut specs = vec![
        Spec { name: "payment", ..wallet(true, vec![mine(0, 0, 150_000_000)], vec![(Pay::To(payee.clone()), 100_000_000), (Pay::Change(0), 49_990_000)]) },
        Spec {
            name: "two-coins",
            ..wallet(
                true,
                vec![mine(0, 0, 30_000_000), mine(0, 1, 20_000_000)],
                vec![(Pay::To(payee.clone()), 45_000_000), (Pay::Change(1), 4_990_000)],
            )
        },
        Spec {
            name: "three-payments",
            ..wallet(
                true,
                vec![mine(1, 0, 500_000_000)],
                vec![
                    (Pay::To(payee.clone()), 100_000_000),
                    (Pay::To(script_payee.clone()), 200_000_000),
                    (Pay::To(payee2.clone()), 50_000_000),
                    (Pay::Change(1), 149_980_000),
                ],
            )
        },
        Spec { name: "tex", ..wallet(true, vec![mine(0, 2, 10_000_000)], vec![(Pay::Tex(tex), 7_500_000), (Pay::Change(0), 2_490_000)]) },
        Spec {
            name: "data",
            ..wallet(
                true,
                vec![mine(0, 0, 10_000_000)],
                vec![(Pay::Data(b"maki".to_vec()), 0), (Pay::To(payee.clone()), 1_000_000), (Pay::Change(0), 8_985_000)],
            )
        },
        Spec {
            name: "lock-time",
            lock_time: 3_600_000,
            sequence: 0xffff_fffe,
            ..wallet(true, vec![mine(0, 1, 20_000_000)], vec![(Pay::To(payee.clone()), 19_990_000)])
        },
        Spec { name: "high-fee", ..wallet(true, vec![mine(0, 0, 150_000_000)], vec![(Pay::To(payee.clone()), 50_000_000)]) },
        Spec { name: "low-fee", ..wallet(true, vec![mine(0, 0, 150_000_000)], vec![(Pay::To(payee.clone()), 149_999_000)]) },
        Spec { name: "testnet", ..wallet(false, vec![mine(0, 0, 150_000_000)], vec![(Pay::To(payee.clone()), 100_000_000), (Pay::Change(0), 49_990_000)]) },
        Spec {
            name: "not-mine",
            ..wallet(true, vec![Coin { chain: 0, index: 0, value: 150_000_000, foreign: true }], vec![(Pay::To(payee.clone()), 149_990_000)])
        },
        Spec {
            name: "expiry-zero",
            expiry: 0,
            ..wallet(true, vec![mine(0, 0, 150_000_000)], vec![(Pay::To(payee.clone()), 149_990_000)])
        },
    ];
    // the most coins a message holds: 49 of them, a payment and change
    let many: Vec<Coin> = (0..49).map(|i| mine((i % 2) as u8, i / 2, 1_000_000)).collect();
    specs.push(Spec { name: "many-inputs", ..wallet(true, many, vec![(Pay::To(payee.clone()), 40_000_000), (Pay::Change(3), 8_755_000)]) });
    let transactions: Vec<Value> = specs.iter().map(|s| make(s, &seed, &other)).collect();
    // and what wallets make by default since NU6.3, which maki doesn't read: version 6 (ZIP-229)
    let v6 = {
        let sk = main.secret(0, 0);
        let pk = PublicKey::from_secret_key(&main.secp, &sk);
        let coin = TxOut::new(Zatoshis::from_u64(150_000_000).unwrap(), script(&TransparentAddress::from_pubkey(&pk)));
        let coins = [(sk, outpoint(0, &mine(0, 0, 0)), coin)];
        let outs = [output(&main, &Pay::To(payee.clone()), 100_000_000), output(&main, &Pay::Change(0), 49_990_000)];
        hex(&built(MainNetwork, MAIN_HEIGHT, &coins, &outs, 10_000, TxVersion::V6))
    };
    let out = json!({
        "account": { "key": hex(&account[32..]), "chainCode": hex(&account[..32]) },
        "addresses": addresses,
        "payees": {
            "p2pkh": ZcashAddress::from_transparent_p2pkh(NetworkType::Main, hash160(&others(7))).encode(),
            "p2pkhTest": ZcashAddress::from_transparent_p2pkh(NetworkType::Test, hash160(&others(7))).encode(),
            "p2sh": ZcashAddress::from_transparent_p2sh(NetworkType::Main, [0x11; 20]).encode(),
            "p2shTest": ZcashAddress::from_transparent_p2sh(NetworkType::Test, [0x11; 20]).encode(),
            "tex": ZcashAddress::from_tex(NetworkType::Main, tex).encode(),
            "texTest": ZcashAddress::from_tex(NetworkType::Test, tex).encode(),
        },
        "branchId": u32::from(BranchId::Nu6_3),
        "transactions": transactions,
        "version6": v6,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
