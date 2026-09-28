//! maki-eth against the EIPs' own examples and against alloy, which signs the same transactions
//! and messages independently: the signed bytes must come out the same (both use RFC 6979).

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy::eips::eip2718::Encodable2718;
use alloy::eips::eip2930::{AccessList, AccessListItem};
use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use maki_btc::bip32::{Xpriv, HARDENED};
use maki_eth::display::{self, Call};
use maki_eth::tx::{Error, Kind};
use maki_eth::{checksum, Account, Tx};

const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn hex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn seed() -> [u8; 64] {
    let words: Vec<&str> = ABANDON.split(' ').collect();
    maki_seed::seed(&words, "")
}

/// alloy's signer for the same key maki derives.
fn alloy_signer(index: u32) -> PrivateKeySigner {
    let key = Xpriv::master(&seed()).unwrap().derive(&[44 | HARDENED, 60 | HARDENED, HARDENED, 0, index]).unwrap();
    PrivateKeySigner::from_slice(&key.secret().to_bytes()).unwrap()
}

#[test]
fn the_test_phrases_first_account_is_the_one_everyone_gets() {
    let account = Account::from_seed(&seed(), 0).unwrap();
    assert_eq!(account.address_string(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    for i in [0, 1, 7] {
        let a = Account::from_seed(&seed(), i).unwrap();
        assert_eq!(a.address(), alloy_signer(i).address().0 .0, "{i}");
    }
    assert!(Account::from_seed(&seed(), HARDENED).is_err());
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
    let unsigned = hex("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080");
    let tx = Tx::parse(&unsigned).unwrap();
    assert_eq!((tx.kind, tx.chain_id, tx.nonce, tx.value), (Kind::Legacy, 1, 9, 1_000_000_000_000_000_000));
    assert_eq!(tx.sighash().to_vec(), hex("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"));
    let account = Account::from_private_key(&[0x46; 32]).unwrap();
    assert_eq!(
        tx.sign(&account).unwrap(),
        hex("f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83")
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
    d.extend(who.0 .0);
    d.extend(amount.to_be_bytes::<32>());
    d
}

#[test]
fn eip1559_transactions_sign_as_alloy_signs_them() {
    let signer = alloy_signer(0);
    let account = Account::from_seed(&seed(), 0).unwrap();
    let list = AccessList(vec![AccessListItem { address: usdc(), storage_keys: vec![B256::repeat_byte(7), B256::ZERO] }]);
    let cases = [
        eip1559(Some(bob()), 50_000_000_000_000_000, vec![], AccessList::default()),
        eip1559(Some(usdc()), 0, erc20([0xa9, 0x05, 0x9c, 0xbb], bob(), U256::from(1_500_000u64)), AccessList::default()),
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
    let account = Account::from_seed(&seed(), 3).unwrap();
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
    let account = Account::from_seed(&seed(), 0).unwrap();
    for m in [&b"hello"[..], b"", &[0u8, 1, 2, 0xff][..], "example.com wants you to sign in with your Ethereum account".as_bytes()] {
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

    let transfer = tx(eip1559(Some(usdc()), 0, erc20([0xa9, 0x05, 0x9c, 0xbb], bob(), U256::from(1_500_000u64)), AccessList::default()));
    assert_eq!(display::call(&transfer), Call::Transfer { to: bob().0 .0, amount: U256::from(1_500_000u64).to_be_bytes() });
    // USDC on Ethereum: maki knows it by its contract, and says how much in USDC
    let (pages, _) = display::review(&transfer).unwrap();
    let headings: Vec<&str> = pages.iter().map(|p| p.heading.as_str()).collect();
    assert_eq!(headings, ["Network", "Send tokens", "Token", "Max fee"]);
    assert_eq!((pages[1].value.as_str(), pages[1].mono.as_str()), ("1.5 USDC", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"));
    assert_eq!((pages[2].value.as_str(), pages[2].mono.as_str()), ("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"));

    // the same contract on another network is just a contract: its smallest units
    let elsewhere = Tx::parse(
        &TxEip1559 {
            chain_id: 8453,
            ..eip1559(Some(usdc()), 0, erc20([0xa9, 0x05, 0x9c, 0xbb], bob(), U256::from(1_500_000u64)), AccessList::default())
        }
        .encoded_for_signing(),
    )
    .unwrap();
    let (pages, _) = display::review(&elsewhere).unwrap();
    let headings: Vec<&str> = pages.iter().map(|p| p.heading.as_str()).collect();
    assert_eq!(headings, ["Network", "Send tokens", "Token amount", "Token", "Max fee"]);
    assert_eq!(pages[2].mono, "1500000");

    let approve = tx(eip1559(Some(usdc()), 0, erc20([0x09, 0x5e, 0xa7, 0xb3], bob(), U256::MAX), AccessList::default()));
    let (pages, _) = display::review(&approve).unwrap();
    assert_eq!((pages[1].heading.as_str(), pages[2].mono.as_str()), ("Approve!", "any amount"));
    assert_eq!(pages[3].value, "USDC");
    let some = tx(eip1559(Some(usdc()), 0, erc20([0x09, 0x5e, 0xa7, 0xb3], bob(), U256::from(25_000_000u64)), AccessList::default()));
    let (pages, _) = display::review(&some).unwrap();
    assert_eq!(pages[2].mono, "25 USDC");

    let unknown = tx(eip1559(Some(usdc()), 0, vec![0xde, 0xad, 0xbe, 0xef, 9], AccessList::default()));
    let (pages, _) = display::review(&unknown).unwrap();
    assert_eq!(pages[1].heading, "Contract call");
    assert!(pages[1].mono.ends_with("function deadbeef\n5 bytes"));

    let polygon = Tx::parse(
        &TxEip1559 { chain_id: 137, ..eip1559(Some(bob()), 10u128.pow(18), vec![], AccessList::default()) }.encoded_for_signing(),
    )
    .unwrap();
    let (pages, _) = display::review(&polygon).unwrap();
    assert_eq!((pages[0].value.as_str(), pages[1].value.as_str()), ("polygon", "1 POL"));
    assert_eq!(display::network(424242), ("chain 424242".to_string(), "coins"));
}

#[test]
fn known_tokens_say_their_amounts_exactly() {
    use maki_eth::tokens::{amount, known, TOKENS};
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

#[test]
fn messages_show_as_text_or_hex() {
    assert_eq!(display::message(b"Sign in to example.com\nNonce: 12").mono, "Sign in to example.com\nNonce: 12");
    let binary = display::message(&[0x19, 0x01, 0xff]);
    assert_eq!((binary.value.as_str(), binary.mono.as_str()), ("in hex", "1901ff"));
}

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// The emulator demo's transaction (0.05 ETH to Bob on Ethereum), unsigned and as maki signs it
/// for the test phrase's first account, and its message's and typed data's signatures. Regenerate (only if the fixture changes) with
///     cargo test -p maki-eth -- --ignored write_fixtures
fn fixture_tx() -> TxEip1559 { eip1559(Some(bob()), 50_000_000_000_000_000, vec![], AccessList::default()) }
const FIXTURE_MESSAGE: &[u8] = b"Sign in to demo.maki";
/// Typed data: a permit to spend 1 USDC on Ethereum, from the test phrase's first account.
const FIXTURE_TYPED: &str = r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Permit":[{"name":"owner","type":"address"},{"name":"spender","type":"address"},{"name":"value","type":"uint256"},{"name":"nonce","type":"uint256"},{"name":"deadline","type":"uint256"}]},"primaryType":"Permit","domain":{"name":"USD Coin","version":"2","chainId":1,"verifyingContract":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},"message":{"owner":"0x9858EfFD232B4033E47d90003D41EC34EcaEda94","spender":"0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD","value":"1000000","nonce":0,"deadline":1790000000}}"#;

#[test]
#[ignore]
fn write_fixtures() {
    let account = Account::from_seed(&seed(), 0).unwrap();
    let unsigned = fixture_tx().encoded_for_signing();
    std::fs::create_dir_all(FIXTURES).unwrap();
    std::fs::write(format!("{FIXTURES}/abandon-tx-unsigned.bin"), &unsigned).unwrap();
    std::fs::write(format!("{FIXTURES}/abandon-tx-signed.bin"), Tx::parse(&unsigned).unwrap().sign(&account).unwrap()).unwrap();
    std::fs::write(format!("{FIXTURES}/abandon-message.sig"), account.sign_message(FIXTURE_MESSAGE).unwrap()).unwrap();
    std::fs::write(format!("{FIXTURES}/abandon-typed.json"), FIXTURE_TYPED).unwrap();
    let typed = maki_eth::TypedData::parse(FIXTURE_TYPED).unwrap();
    std::fs::write(format!("{FIXTURES}/abandon-typed.sig"), account.sign_typed(&typed).unwrap()).unwrap();
}

#[test]
fn the_fixtures_are_current() {
    let account = Account::from_seed(&seed(), 0).unwrap();
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
    let siwe = |first: &str| format!("{first} wants you to sign in with your Ethereum account:\n0x9858EfFD232B4033E47d90003D41EC34EcaEda94\n\nURI: https://app.example.com\nVersion: 1\nChain ID: 1\nNonce: 32891756\nIssued At: 2026-09-26T12:00:00Z");
    assert_eq!(display::sign_in_site(siwe("app.example.com").as_bytes()).as_deref(), Some("app.example.com"));
    assert_eq!(display::sign_in_site(siwe("https://App.Example.com:8443").as_bytes()).as_deref(), Some("app.example.com"));
    assert_eq!(display::sign_in_site(b"just a message"), None);
    // from the site it names: just the message
    let pages = display::message_pages("app.example.com", siwe("app.example.com").as_bytes());
    assert_eq!(pages.len(), 1);
    // from anywhere else: the warning first
    let pages = display::message_pages("app-example.evil.io", siwe("app.example.com").as_bytes());
    assert_eq!((pages[0].heading.as_str(), pages[0].mono.as_str()), ("Wrong site!", "app.example.com"));
    assert_eq!(pages[1].heading, "Message");
}
