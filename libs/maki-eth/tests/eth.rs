//! maki-eth against the EIPs' own examples and against alloy, which signs the same transactions
//! and messages independently: the signed bytes must come out the same (both use RFC 6979).

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy::eips::eip2718::Encodable2718;
use alloy::eips::eip2930::{AccessList, AccessListItem};
use alloy::primitives::{Address, B256, Bytes, TxKind, U256};
use alloy::signers::SignerSync;
use alloy::signers::local::PrivateKeySigner;
use maki_eth::display::{self, Call};
use maki_eth::tx::{Error, Kind};
use maki_eth::{Account, Tx, checksum};
use maki_hd::HARDENED;
use maki_hd::seed::{OneKey, SeedKeys};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn hex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// maki's keys for a seed, for as long as the tests run.
fn keys(seed: &[u8]) -> &'static SeedKeys { Box::leak(Box::new(SeedKeys::from_seed(seed).unwrap())) }

/// One bare private key, as other software makes them, at every path.
fn one(secret: &[u8; 32]) -> &'static OneKey { Box::leak(Box::new(OneKey::new(secret).unwrap())) }

fn seed() -> [u8; 64] {
    let words: Vec<&str> = ABANDON.split(' ').collect();
    maki_seed::seed(&words, "")
}

/// alloy's signer for the same key maki derives.
fn alloy_signer(index: u32) -> PrivateKeySigner {
    // the key rust-bitcoin derives: maki's keys never hand theirs out
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let master = bitcoin::bip32::Xpriv::new_master(bitcoin::NetworkKind::Main, &seed()).unwrap();
    let path: bitcoin::bip32::DerivationPath = format!("m/44'/60'/0'/0/{index}").parse().unwrap();
    PrivateKeySigner::from_slice(&master.derive_priv(&secp, &path).unwrap().private_key.secret_bytes())
        .unwrap()
}

#[test]
fn the_test_phrases_first_account_is_the_one_everyone_gets() {
    let account = Account::new(keys(&seed()), 0).unwrap();
    assert_eq!(account.address_string(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    for i in [0, 1, 7] {
        let a = Account::new(keys(&seed()), i).unwrap();
        assert_eq!(a.address(), alloy_signer(i).address().0.0, "{i}");
    }
    assert!(Account::new(keys(&seed()), HARDENED).is_err());
}

#[test]
fn addresses_are_checksummed_as_eip55_says() {
    for a in [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ] {
        assert_eq!(checksum(&hex(a).try_into().unwrap()), a);
    }
}

#[test]
fn eip155s_example_signs_as_published() {
    let unsigned =
        hex("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080");
    let tx = Tx::parse(&unsigned).unwrap();
    assert_eq!((tx.kind, tx.chain_id, tx.nonce, tx.value), (Kind::Legacy, 1, 9, 1_000_000_000_000_000_000));
    assert_eq!(
        tx.sighash().to_vec(),
        hex("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53")
    );
    let account = Account::new(one(&[0x46; 32]), 0).unwrap();
    assert_eq!(
        tx.sign(&account).unwrap(),
        hex(
            "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        )
    );
}

fn eip1559(to: Option<Address>, value: u128, input: Vec<u8>, access_list: AccessList) -> TxEip1559 {
    TxEip1559 {
        chain_id: 1,
        nonce: 42,
        gas_limit: 65_000,
        max_fee_per_gas: 30_000_000_000,
        max_priority_fee_per_gas: 1_500_000_000,
        to: to.map(TxKind::Call).unwrap_or(TxKind::Create),
        value: U256::from(value),
        access_list,
        input: Bytes::from(input),
    }
}

fn usdc() -> Address { "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".parse().unwrap() }
fn bob() -> Address { "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".parse().unwrap() }

fn erc20(selector: [u8; 4], who: Address, amount: U256) -> Vec<u8> {
    let mut d = selector.to_vec();
    d.extend([0u8; 12]);
    d.extend(who.0.0);
    d.extend(amount.to_be_bytes::<32>());
    d
}

#[test]
fn eip1559_transactions_sign_as_alloy_signs_them() {
    let signer = alloy_signer(0);
    let account = Account::new(keys(&seed()), 0).unwrap();
    let list = AccessList(vec![AccessListItem {
        address: usdc(),
        storage_keys: vec![B256::repeat_byte(7), B256::ZERO],
    }]);
    let cases = [
        eip1559(Some(bob()), 50_000_000_000_000_000, vec![], AccessList::default()),
        eip1559(
            Some(usdc()),
            0,
            erc20([0xa9, 0x05, 0x9c, 0xbb], bob(), U256::from(1_500_000u64)),
            AccessList::default(),
        ),
        eip1559(Some(usdc()), 0, vec![0xde, 0xad, 0xbe, 0xef, 1, 2, 3], list),
        eip1559(None, 0, vec![0x60; 300], AccessList::default()),
    ];
    for tx in cases {
        let unsigned = tx.encoded_for_signing();
        let ours = Tx::parse(&unsigned).unwrap();
        assert_eq!(ours.sighash(), tx.signature_hash().0);
        let sig = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
        let theirs = TxEnvelope::from(tx.into_signed(sig)).encoded_2718();
        assert_eq!(ours.sign(&account).unwrap(), theirs);
    }
}

#[test]
fn legacy_transactions_sign_as_alloy_signs_them() {
    let signer = alloy_signer(3);
    let account = Account::new(keys(&seed()), 3).unwrap();
    for chain_id in [1u64, 137, 11155111] {
        let tx = TxLegacy {
            chain_id: Some(chain_id),
            nonce: 0,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: TxKind::Call(bob()),
            value: U256::from(1u64),
            input: Bytes::new(),
        };
        let ours = Tx::parse(&tx.encoded_for_signing()).unwrap();
        let sig = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
        let theirs = TxEnvelope::from(tx.into_signed(sig)).encoded_2718();
        assert_eq!(ours.sign(&account).unwrap(), theirs, "chain {chain_id}");
    }
}

#[test]
fn messages_sign_as_alloy_signs_them() {
    let signer = alloy_signer(0);
    let account = Account::new(keys(&seed()), 0).unwrap();
    for m in [
        &b"hello"[..],
        b"",
        &[0u8, 1, 2, 0xff][..],
        "example.com wants you to sign in with your Ethereum account".as_bytes(),
    ] {
        let theirs = signer.sign_message_sync(m).unwrap().as_bytes();
        assert_eq!(account.sign_message(m).unwrap(), theirs);
    }
}

#[test]
fn what_maki_wont_sign() {
    // no chain ID: replayable on every network
    let pre155 = hex("e9098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080");
    assert!(matches!(Tx::parse(&pre155), Err(Error::Unsupported(_))));
    assert!(matches!(Tx::parse(&[0x01, 0xc0]), Err(Error::Unsupported(_))));
    assert!(matches!(Tx::parse(&[0x03, 0xc0]), Err(Error::Unsupported(_))));
    // networks' own kinds: refused, saying which, rather than read as something they aren't
    let zksync = Tx::parse(&[0x71, 0xc0]).unwrap_err().to_string();
    assert_eq!(zksync, "maki doesn't sign ZKsync's own transactions (EIP-712): send an EIP-1559 one");
    let celo = Tx::parse(&[0x7b, 0xc0]).unwrap_err().to_string();
    assert_eq!(celo, "maki doesn't sign Celo's fee-currency transactions: pay the fee in CELO");
    let good = eip1559(Some(bob()), 1, vec![], AccessList::default()).encoded_for_signing();
    assert!(Tx::parse(&good).is_ok());
    // bytes after the end
    let mut long = good.clone();
    long.push(0);
    assert!(matches!(Tx::parse(&long), Err(Error::Rlp(_))));
    // a number with a leading zero (nonce 42 written as 0x00 0x2a)
    let unsigned = eip1559(Some(bob()), 1, vec![], AccessList::default());
    let mut body = Vec::new();
    for field in [&[0x01][..], &[0x82, 0x00, 0x2a]] {
        body.extend(field);
    }
    let odd = [&[0x02, 0xc0 + body.len() as u8][..], &body].concat();
    assert!(Tx::parse(&odd).is_err());
    // a single byte below 0x80 written as a string
    assert!(maki_eth::rlp::decode(&[0x81, 0x05]).is_err());
    // a length written longer than it needs
    assert!(maki_eth::rlp::decode(&[0xb8, 0x02, 0xaa, 0xbb]).is_err());
    let _ = unsigned;
}

#[test]
fn the_review_says_what_the_transaction_does() {
    let tx = |t: TxEip1559| Tx::parse(&t.encoded_for_signing()).unwrap();
    let send = tx(eip1559(Some(bob()), 50_000_000_000_000_000, vec![], AccessList::default()));
    let (pages, summary) = display::review(&send).unwrap();
    let headings: Vec<&str> = pages.iter().map(|p| p.heading.as_str()).collect();
    assert_eq!(headings, ["Network", "Send", "Max fee"]);
    assert_eq!((pages[0].value.as_str(), pages[0].mono.as_str()), ("ethereum", "chain ID 1"));
    assert_eq!(pages[1].value, "0.05 ETH");
    assert_eq!(pages[1].mono, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
    assert_eq!(pages[2].value, "0.00195 ETH");
    assert_eq!(pages[2].mono, "65000 gas\n30 gwei");
    assert_eq!(summary, "up to 0.05195 ETH");

    let transfer = tx(eip1559(
        Some(usdc()),
        0,
        erc20([0xa9, 0x05, 0x9c, 0xbb], bob(), U256::from(1_500_000u64)),
        AccessList::default(),
    ));
    assert_eq!(
        display::call(&transfer),
        Call::Transfer { to: bob().0.0, amount: U256::from(1_500_000u64).to_be_bytes() }
    );
    // USDC on Ethereum: maki knows it by its contract, and says how much in USDC
    let (pages, _) = display::review(&transfer).unwrap();
    let headings: Vec<&str> = pages.iter().map(|p| p.heading.as_str()).collect();
    assert_eq!(headings, ["Network", "Send tokens", "Token", "Max fee"]);
    assert_eq!(
        (pages[1].value.as_str(), pages[1].mono.as_str()),
        ("1.5 USDC", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
    );
    assert_eq!(
        (pages[2].value.as_str(), pages[2].mono.as_str()),
        ("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
    );

    // the same contract on another network is just a contract: its smallest units (and Base adds
    // its L1 fee, which nothing caps, to the gas)
    let elsewhere = Tx::parse(
        &TxEip1559 {
            chain_id: 8453,
            ..eip1559(
                Some(usdc()),
                0,
                erc20([0xa9, 0x05, 0x9c, 0xbb], bob(), U256::from(1_500_000u64)),
                AccessList::default(),
            )
        }
        .encoded_for_signing(),
    )
    .unwrap();
    let (pages, _) = display::review(&elsewhere).unwrap();
    let headings: Vec<&str> = pages.iter().map(|p| p.heading.as_str()).collect();
    assert_eq!(headings, ["Network", "Send tokens", "Token amount", "Token", "Max gas fee", "L1 fee"]);
    assert_eq!(pages[2].mono, "1500000");

    let approve = tx(eip1559(
        Some(usdc()),
        0,
        erc20([0x09, 0x5e, 0xa7, 0xb3], bob(), U256::MAX),
        AccessList::default(),
    ));
    let (pages, _) = display::review(&approve).unwrap();
    assert_eq!((pages[1].heading.as_str(), pages[2].mono.as_str()), ("Approve!", "any amount"));
    assert_eq!(pages[3].value, "USDC");
    let some = tx(eip1559(
        Some(usdc()),
        0,
        erc20([0x09, 0x5e, 0xa7, 0xb3], bob(), U256::from(25_000_000u64)),
        AccessList::default(),
    ));
    let (pages, _) = display::review(&some).unwrap();
    assert_eq!(pages[2].mono, "25 USDC");

    let unknown = tx(eip1559(Some(usdc()), 0, vec![0xde, 0xad, 0xbe, 0xef, 9], AccessList::default()));
    let (pages, _) = display::review(&unknown).unwrap();
    assert_eq!(pages[1].heading, "Contract call");
    assert!(pages[1].mono.ends_with("function deadbeef\n5 bytes"));

    let polygon = Tx::parse(
        &TxEip1559 { chain_id: 137, ..eip1559(Some(bob()), 10u128.pow(18), vec![], AccessList::default()) }
            .encoded_for_signing(),
    )
    .unwrap();
    let (pages, _) = display::review(&polygon).unwrap();
    assert_eq!((pages[0].value.as_str(), pages[1].value.as_str()), ("polygon", "1 POL"));
    assert_eq!(display::network(424242), ("chain 424242".to_string(), "coins"));
}

#[test]
fn known_tokens_say_their_amounts_exactly() {
    use maki_eth::tokens::{TOKENS, amount, known};
    let usdc = known(1, &TOKENS[0].contract).unwrap();
    let wei = |n: u128| U256::from(n).to_be_bytes::<32>();
    assert_eq!(amount(usdc, &wei(0)), "0 USDC");
    assert_eq!(amount(usdc, &wei(1)), "0.000001 USDC");
    assert_eq!(amount(usdc, &wei(1_000_000)), "1 USDC");
    assert_eq!(amount(usdc, &wei(123_456_789)), "123.456789 USDC");
    let weth = known(1, &TOKENS[3].contract).unwrap();
    assert_eq!(amount(weth, &wei(50_000_000_000_000_000)), "0.05 WETH");
    assert_eq!(amount(weth, &U256::MAX.to_be_bytes::<32>()).split('.').next().unwrap().len(), 60);
    // one entry per contract and network
    for (i, a) in TOKENS.iter().enumerate() {
        assert!(TOKENS[i + 1..].iter().all(|b| (a.chain_id, a.contract) != (b.chain_id, b.contract)));
    }
    assert!(known(1, &[0; 20]).is_none());
}

/// Each network maki names, as its own documentation and chainlist name it, with its coin: written
/// out again here, so a slip in the table shows.
const NAMED: [(u64, &str, &str); 25] = [
    (1, "ethereum", "ETH"),
    (10, "optimism", "ETH"),
    (56, "bnb chain", "BNB"),
    (137, "polygon", "POL"),
    (8453, "base", "ETH"),
    (42161, "arbitrum", "ETH"),
    (43114, "avalanche", "AVAX"),
    (4663, "robinhood chain", "ETH"),
    (999, "hyperevm", "HYPE"),
    (143, "monad", "MON"),
    (5000, "mantle", "MNT"),
    (9745, "plasma", "XPL"),
    (196, "x layer", "OKB"),
    (5042, "arc", "USDC"),
    (480, "world chain", "ETH"),
    (57073, "ink", "ETH"),
    (59144, "linea", "ETH"),
    (100, "gnosis", "xDAI"),
    (324, "zksync era", "ETH"),
    (42220, "celo", "CELO"),
    (130, "unichain", "ETH"),
    (11155111, "sepolia", "ETH"),
    (17000, "holesky", "ETH"),
    (560048, "hoodi", "ETH"),
    (84532, "base sepolia", "ETH"),
];

#[test]
fn every_network_maki_names_says_its_coin() {
    for (id, name, coin) in NAMED {
        assert_eq!(display::network(id), (name.to_string(), coin), "chain {id}");
    }
    assert_eq!(display::NETWORKS.len(), NAMED.len());
    for (i, a) in display::NETWORKS.iter().enumerate() {
        assert!(display::NETWORKS[i + 1..].iter().all(|b| b.chain_id != a.chain_id), "chain {}", a.chain_id);
    }
    // the rest: their chain ID, in coins, which maki can't name; never a neighbour's name
    for id in [0, 2, 25, 146, 204, 998, 4217, 42170, 534352, 7777777, u64::MAX] {
        assert_eq!(display::network(id), (format!("chain {id}"), "coins"));
    }
    // the OP Stack's, which add fees no transaction caps; Celo sets them to zero
    let outside: Vec<u64> =
        display::NETWORKS.iter().filter(|n| n.fees_outside_gas).map(|n| n.chain_id).collect();
    assert_eq!(outside, [10, 8453, 5000, 196, 480, 57073, 130, 84532]);
}

#[test]
fn tokens_are_known_by_their_network_and_contract() {
    use maki_eth::tokens::known;
    let addr = |s: &str| -> [u8; 20] { hex(s).try_into().unwrap() };
    for (chain, contract, symbol, decimals) in [
        (56, "0x55d398326f99059fF775485246999027B3197955", "USDT", 18),
        (56, "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", "USDC", 18),
        (43114, "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", "USDC", 6),
        (43114, "0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7", "USDT", 6),
        (4663, "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168", "USDG", 6),
        (999, "0xB8CE59FC3717ada4C02eaDF9682A9e934F625ebb", "USDT0", 6),
        (9745, "0xB8CE59FC3717ada4C02eaDF9682A9e934F625ebb", "USDT0", 6),
        (143, "0x754704Bc059F8C67012fEd69BC8A327a5aafb603", "USDC", 6),
        (5000, "0xdEAddEaDdeadDEadDEADDEAddEADDEAddead1111", "WETH", 18),
        (5042, "0x3600000000000000000000000000000000000000", "USDC", 6),
        (480, "0x4200000000000000000000000000000000000006", "WETH", 18),
        (59144, "0xe5D7C2a44FfDDf6b295A15c148167daaAf5Cf34f", "WETH", 18),
        (100, "0x2a22f9c3b484c3629090FeED35F17Ff8F88f76F0", "USDC.e", 6),
        (324, "0x1d17CBcF0D6D143135aE902365D2E5e2A16538D4", "USDC", 6),
        (42220, "0x48065fbBE25f71C9282ddf5e1cD6D6A887483D5e", "USDT", 6),
        (130, "0x9151434b16b9763660705744891fA906F660EcC5", "USDT0", 6),
    ] {
        let t = known(chain, &addr(contract)).unwrap_or_else(|| panic!("{symbol} on chain {chain}"));
        assert_eq!((t.symbol, t.decimals), (symbol, decimals), "{contract} on chain {chain}");
    }
    // a contract is a token only on the networks it's listed for: USDT0's address on HyperEVM
    // and Plasma is nothing on Monad, and the OP Stack's WETH is nothing on Ethereum or Arbitrum
    assert!(known(143, &addr("0xB8CE59FC3717ada4C02eaDF9682A9e934F625ebb")).is_none());
    assert!(known(1, &addr("0x4200000000000000000000000000000000000006")).is_none());
    assert!(known(42161, &addr("0x4200000000000000000000000000000000000006")).is_none());
    // every token is on a network maki names, and none goes by its network's coin's symbol, but
    // Arc's USDC: that is Arc's coin, through its ERC-20 interface

    for t in &maki_eth::tokens::TOKENS {
        let n =
            display::known_network(t.chain_id).unwrap_or_else(|| panic!("{} on {}", t.symbol, t.chain_id));
        assert!(t.symbol != n.unit || t.chain_id == 5042, "{} on {}", t.symbol, n.name);
    }
}

/// An EIP-1559 transaction as `eip1559` makes them, on another network.
fn on(chain_id: u64, t: TxEip1559) -> TxEip1559 { TxEip1559 { chain_id, ..t } }

#[test]
fn a_transaction_on_another_network_is_shown_with_its_name_and_coin() {
    let signer = alloy_signer(0);
    let account = Account::new(keys(&seed()), 0).unwrap();
    // one AVAX to Bob on Avalanche: signed as alloy signs it, the chain ID in what's signed
    let avax = on(43114, eip1559(Some(bob()), 10u128.pow(18), vec![], AccessList::default()));
    let ours = Tx::parse(&avax.encoded_for_signing()).unwrap();
    let sig = signer.sign_hash_sync(&avax.signature_hash()).unwrap();
    assert_eq!(ours.sign(&account).unwrap(), TxEnvelope::from(avax.into_signed(sig)).encoded_2718());
    let (pages, summary) = display::review(&ours).unwrap();
    let headings: Vec<&str> = pages.iter().map(|p| p.heading.as_str()).collect();
    assert_eq!(headings, ["Network", "Send", "Max fee"]);
    assert_eq!((pages[0].value.as_str(), pages[0].mono.as_str()), ("avalanche", "chain ID 43114"));
    assert_eq!((pages[1].value.as_str(), pages[2].value.as_str()), ("1 AVAX", "0.00195 AVAX"));
    assert_eq!(summary, "up to 1.00195 AVAX");

    // a legacy one on Monad (as wallets there often send them): EIP-155's v for chain 143
    let legacy = TxLegacy {
        chain_id: Some(143),
        nonce: 3,
        gas_price: 102_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(bob()),
        value: U256::from(25u128 * 10u128.pow(17)),
        input: Bytes::new(),
    };
    let ours = Tx::parse(&legacy.encoded_for_signing()).unwrap();
    let sig = signer.sign_hash_sync(&legacy.signature_hash()).unwrap();
    let signed = ours.sign(&account).unwrap();
    assert_eq!(signed, TxEnvelope::from(legacy.into_signed(sig)).encoded_2718());
    assert!(
        [321, 322].contains(
            &(ours.signature(&account).unwrap()[64..].iter().fold(0u64, |v, b| v << 8 | *b as u64))
        )
    );
    let (pages, summary) = display::review(&ours).unwrap();
    assert_eq!((pages[0].value.as_str(), pages[1].value.as_str()), ("monad", "2.5 MON"));
    assert_eq!((pages[2].value.as_str(), pages[2].mono.as_str()), ("0.002142 MON", "21000 gas\n102 gwei"));
    assert_eq!(summary, "up to 2.502142 MON");

    // Arc counts in USDC, its coin, with 18 decimals as a coin
    let arc = Tx::parse(
        &on(5042, eip1559(Some(bob()), 5 * 10u128.pow(17), vec![], AccessList::default()))
            .encoded_for_signing(),
    )
    .unwrap();
    let (pages, _) = display::review(&arc).unwrap();
    assert_eq!((pages[0].value.as_str(), pages[1].value.as_str()), ("arc", "0.5 USDC"));
}

#[test]
fn a_token_on_another_network_is_shown_by_its_symbol() {
    let send = |chain: u64, token: &str, amount: U256| {
        let to = Some(token.parse::<Address>().unwrap());
        let data = erc20([0xa9, 0x05, 0x9c, 0xbb], bob(), amount);
        display::review(
            &Tx::parse(&on(chain, eip1559(to, 0, data, AccessList::default())).encoded_for_signing())
                .unwrap(),
        )
        .unwrap()
        .0
    };
    // USDC on Monad: Circle's, in its 6 decimals
    let pages = send(143, "0x754704Bc059F8C67012fEd69BC8A327a5aafb603", U256::from(1_500_000u64));
    let headings: Vec<&str> = pages.iter().map(|p| p.heading.as_str()).collect();
    assert_eq!(headings, ["Network", "Send tokens", "Token", "Max fee"]);
    assert_eq!(
        (pages[1].value.as_str(), pages[1].mono.as_str()),
        ("1.5 USDC", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
    );
    assert_eq!(
        (pages[2].value.as_str(), pages[2].mono.as_str()),
        ("USDC", "0x754704Bc059F8C67012fEd69BC8A327a5aafb603")
    );
    assert_eq!(pages[3].value, "0.00195 MON");
    // BNB Chain's USDT has 18 decimals: 1.5 of it is 1.5 × 10^18 of its smallest units
    let pages = send(56, "0x55d398326f99059fF775485246999027B3197955", U256::from(15u128 * 10u128.pow(17)));
    assert_eq!((pages[0].value.as_str(), pages[1].value.as_str()), ("bnb chain", "1.5 USDT"));
    // a bridged look-alike, by its own symbol
    let pages = send(100, "0x2a22f9c3b484c3629090FeED35F17Ff8F88f76F0", U256::from(2_250_000u64));
    assert_eq!((pages[1].value.as_str(), pages[2].value.as_str()), ("2.25 USDC.e", "USDC.e"));
    assert_eq!(pages[3].value, "0.00195 xDAI");
    // Monad's USDC contract on HyperEVM is just a contract: its smallest units
    let pages = send(999, "0x754704Bc059F8C67012fEd69BC8A327a5aafb603", U256::from(1_500_000u64));
    let headings: Vec<&str> = pages.iter().map(|p| p.heading.as_str()).collect();
    assert_eq!(headings, ["Network", "Send tokens", "Token amount", "Token", "Max fee"]);
    assert_eq!((pages[0].value.as_str(), pages[2].mono.as_str()), ("hyperevm", "1500000"));
}

#[test]
fn fees_outside_the_gas_are_called_out_where_a_network_adds_them() {
    let send = |chain: u64| {
        display::review(
            &Tx::parse(
                &on(chain, eip1559(Some(bob()), 10u128.pow(17), vec![], AccessList::default()))
                    .encoded_for_signing(),
            )
            .unwrap(),
        )
        .unwrap()
    };
    for (chain, coin) in
        [(8453, "ETH"), (10, "ETH"), (5000, "MNT"), (480, "ETH"), (57073, "ETH"), (130, "ETH"), (196, "OKB")]
    {
        let (pages, summary) = send(chain);
        let headings: Vec<&str> = pages.iter().map(|p| p.heading.as_str()).collect();
        // the most the gas can cost, then what the network adds on top, which nothing caps
        assert_eq!(headings, ["Network", "Send", "Max gas fee", "L1 fee"], "chain {chain}");
        assert_eq!(pages[2].value, format!("0.00195 {coin}"));
        assert_eq!((pages[3].value.as_str(), pages[3].mono.as_str()), ("not capped", ""));
        assert!(pages[3].prose.contains("nothing in a transaction caps them"), "chain {chain}");
        assert_eq!(summary, format!("up to 0.10195 {coin} and L1 fees"));
    }
    // Arbitrum's and Celo's are in the gas (Celo's L1 fees are always zero): the max fee is the most
    for chain in [42161, 42220, 4663, 324, 59144, 1] {
        let (pages, summary) = send(chain);
        assert_eq!(pages.last().unwrap().heading, "Max fee", "chain {chain}");
        assert!(pages.iter().all(|p| p.prose.is_empty()));
        assert!(!summary.contains("L1"), "chain {chain}");
    }
}

#[test]
fn messages_show_as_text_or_hex() {
    assert_eq!(
        display::message(b"Sign in to example.com\nNonce: 12").mono,
        "Sign in to example.com\nNonce: 12"
    );
    let binary = display::message(&[0x19, 0x01, 0xff]);
    assert_eq!((binary.value.as_str(), binary.mono.as_str()), ("in hex", "1901ff"));
}

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// The emulator demo's transaction (0.05 ETH to Bob on Ethereum), unsigned and as maki signs it
/// for the test phrase's first account, and its message's and typed data's signatures. Regenerate (only if
/// the fixture changes) with     cargo test -p maki-eth -- --ignored write_fixtures
fn fixture_tx() -> TxEip1559 { eip1559(Some(bob()), 50_000_000_000_000_000, vec![], AccessList::default()) }
const FIXTURE_MESSAGE: &[u8] = b"Sign in to demo.maki";
/// Typed data: a permit to spend 1 USDC on Ethereum, from the test phrase's first account.
const FIXTURE_TYPED: &str = r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Permit":[{"name":"owner","type":"address"},{"name":"spender","type":"address"},{"name":"value","type":"uint256"},{"name":"nonce","type":"uint256"},{"name":"deadline","type":"uint256"}]},"primaryType":"Permit","domain":{"name":"USD Coin","version":"2","chainId":1,"verifyingContract":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},"message":{"owner":"0x9858EfFD232B4033E47d90003D41EC34EcaEda94","spender":"0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD","value":"1000000","nonce":0,"deadline":1790000000}}"#;

#[test]
#[ignore]
fn write_fixtures() {
    let account = Account::new(keys(&seed()), 0).unwrap();
    let unsigned = fixture_tx().encoded_for_signing();
    std::fs::create_dir_all(FIXTURES).unwrap();
    std::fs::write(format!("{FIXTURES}/abandon-tx-unsigned.bin"), &unsigned).unwrap();
    std::fs::write(
        format!("{FIXTURES}/abandon-tx-signed.bin"),
        Tx::parse(&unsigned).unwrap().sign(&account).unwrap(),
    )
    .unwrap();
    std::fs::write(format!("{FIXTURES}/abandon-message.sig"), account.sign_message(FIXTURE_MESSAGE).unwrap())
        .unwrap();
    std::fs::write(format!("{FIXTURES}/abandon-typed.json"), FIXTURE_TYPED).unwrap();
    let typed = maki_eth::TypedData::parse(FIXTURE_TYPED).unwrap();
    std::fs::write(format!("{FIXTURES}/abandon-typed.sig"), account.sign_typed(&typed).unwrap()).unwrap();
}

#[test]
fn the_fixtures_are_current() {
    let account = Account::new(keys(&seed()), 0).unwrap();
    let unsigned = std::fs::read(format!("{FIXTURES}/abandon-tx-unsigned.bin")).unwrap();
    assert_eq!(unsigned, fixture_tx().encoded_for_signing());
    let signed = std::fs::read(format!("{FIXTURES}/abandon-tx-signed.bin")).unwrap();
    assert_eq!(Tx::parse(&unsigned).unwrap().sign(&account).unwrap(), signed);
    let sig = std::fs::read(format!("{FIXTURES}/abandon-message.sig")).unwrap();
    assert_eq!(account.sign_message(FIXTURE_MESSAGE).unwrap().to_vec(), sig);
    assert_eq!(std::fs::read_to_string(format!("{FIXTURES}/abandon-typed.json")).unwrap(), FIXTURE_TYPED);
    let typed = maki_eth::TypedData::parse(FIXTURE_TYPED).unwrap();
    let sig = std::fs::read(format!("{FIXTURES}/abandon-typed.sig")).unwrap();
    assert_eq!(account.sign_typed(&typed).unwrap().to_vec(), sig);
}

#[test]
fn a_sign_in_for_another_site_is_called_out() {
    let siwe = |first: &str| {
        format!(
            "{first} wants you to sign in with your Ethereum account:\n0x9858EfFD232B4033E47d90003D41EC34EcaEda94\n\nURI: https://app.example.com\nVersion: 1\nChain ID: 1\nNonce: 32891756\nIssued At: 2026-09-26T12:00:00Z"
        )
    };
    assert_eq!(display::sign_in_site(siwe("app.example.com").as_bytes()).as_deref(), Some("app.example.com"));
    assert_eq!(
        display::sign_in_site(siwe("https://App.Example.com:8443").as_bytes()).as_deref(),
        Some("app.example.com")
    );
    assert_eq!(display::sign_in_site(b"just a message"), None);
    // from the site it names: just the message
    let pages = display::message_pages("app.example.com", siwe("app.example.com").as_bytes());
    assert_eq!(pages.len(), 1);
    // from anywhere else: the warning first
    let pages = display::message_pages("app-example.evil.io", siwe("app.example.com").as_bytes());
    assert_eq!((pages[0].heading.as_str(), pages[0].mono.as_str()), ("Wrong site!", "app.example.com"));
    assert_eq!(pages[1].heading, "Message");
}
