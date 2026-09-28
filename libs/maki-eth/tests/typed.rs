//! Typed data (EIP-712): the spec's own example, hashes that match alloy's implementation on
//! typed data of every shape, what maki refuses, and what the owner reads.

use maki_eth::display::{self, Page};
use maki_eth::{keccak256, Account, TypedData};

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }

/// EIP-712's example: Cow mails Bob.
const MAIL: &str = r#"{
  "types": {
    "EIP712Domain": [
      {"name": "name", "type": "string"},
      {"name": "version", "type": "string"},
      {"name": "chainId", "type": "uint256"},
      {"name": "verifyingContract", "type": "address"}
    ],
    "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
    "Mail": [
      {"name": "from", "type": "Person"},
      {"name": "to", "type": "Person"},
      {"name": "contents", "type": "string"}
    ]
  },
  "primaryType": "Mail",
  "domain": {
    "name": "Ether Mail",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
  },
  "message": {
    "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
    "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
    "contents": "Hello, Bob!"
  }
}"#;

#[test]
fn the_spec_example_hashes_and_signs_as_the_spec_says() {
    let td = TypedData::parse(MAIL).unwrap();
    assert_eq!(td.encode_type("Mail").unwrap(), "Mail(Person from,Person to,string contents)Person(string name,address wallet)");
    assert_eq!(hex(&td.type_hash("Mail").unwrap()), "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2");
    assert_eq!(hex(&td.hash_struct("Mail", &td.message).unwrap()), "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e");
    assert_eq!(hex(&td.domain_separator().unwrap()), "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f");
    assert_eq!(hex(&td.signing_hash().unwrap()), "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
    // the spec's key: keccak256("cow"), whose address is Cow's
    let cow = Account::from_private_key(&keccak256(b"cow")).unwrap();
    assert_eq!(cow.address_string(), "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826");
    let sig = cow.sign_typed(&td).unwrap();
    assert_eq!(hex(&sig[..32]), "4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d");
    assert_eq!(hex(&sig[32..64]), "07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b91562");
    assert_eq!(sig[64], 28);
}

/// alloy's EIP-712 signing hash for the same JSON.
fn alloy_hash(json: &str) -> String {
    let td: alloy_dyn_abi::TypedData = serde_json::from_str(json).expect("alloy reads it");
    hex(td.eip712_signing_hash().expect("alloy hashes it").as_slice())
}

fn domain_types(extra: &str) -> String {
    format!(
        r#""EIP712Domain": [{{"name": "name", "type": "string"}}, {{"name": "chainId", "type": "uint256"}},
            {{"name": "verifyingContract", "type": "address"}}, {{"name": "salt", "type": "bytes32"}}]{}"#,
        extra
    )
}

const DOMAIN: &str = r#"{"name": "Test", "chainId": "0x2105", "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
    "salt": "0x00000000000000000000000000000000000000000000000000000000000000ff"}"#;

/// Typed data of many shapes: every kind of value, arrays of both sizes and of structs, types
/// that refer to themselves, and values at the edges of their ranges.
fn shapes() -> Vec<String> {
    let mut out = Vec::new();
    out.push(MAIL.to_string());
    // integers at their edges, as numbers and as strings, decimal and hex
    out.push(format!(
        r#"{{"types": {{{}, "Edges": [{{"name": "a", "type": "uint8"}}, {{"name": "b", "type": "int8"}}, {{"name": "c", "type": "int8"}},
            {{"name": "d", "type": "uint256"}}, {{"name": "e", "type": "int256"}}, {{"name": "f", "type": "int256"}},
            {{"name": "g", "type": "uint48"}}, {{"name": "h", "type": "int128"}}, {{"name": "i", "type": "uint160"}}]}},
          "primaryType": "Edges", "domain": {},
          "message": {{"a": 255, "b": -128, "c": "127", "d": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "e": "-57896044618658097711785492504343953926634992332820282019728792003956564819968",
            "f": "57896044618658097711785492504343953926634992332820282019728792003956564819967",
            "g": "0xffffffffffff", "h": "-1", "i": 0}}}}"#,
        domain_types(""),
        DOMAIN
    ));
    // bytes of both kinds, booleans, text beyond ASCII
    out.push(format!(
        r#"{{"types": {{{}, "Blob": [{{"name": "data", "type": "bytes"}}, {{"name": "empty", "type": "bytes"}}, {{"name": "one", "type": "bytes1"}},
            {{"name": "id", "type": "bytes32"}}, {{"name": "yes", "type": "bool"}}, {{"name": "no", "type": "bool"}},
            {{"name": "note", "type": "string"}}]}},
          "primaryType": "Blob", "domain": {},
          "message": {{"data": "0xdeadbeef00", "empty": "0x", "one": "0x7f", "id": "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "yes": true, "no": false, "note": "café 🍰 \"quoted\"\n"}}}}"#,
        domain_types(""),
        DOMAIN
    ));
    // arrays: dynamic and fixed, of values, of structs, of arrays
    out.push(format!(
        r#"{{"types": {{{}, "Item": [{{"name": "id", "type": "uint256"}}, {{"name": "tags", "type": "string[]"}}],
            "Order": [{{"name": "items", "type": "Item[]"}}, {{"name": "pair", "type": "address[2]"}},
            {{"name": "grid", "type": "uint16[3][]"}}, {{"name": "none", "type": "bytes32[]"}}]}},
          "primaryType": "Order", "domain": {},
          "message": {{"items": [{{"id": 1, "tags": ["a", "b"]}}, {{"id": "2", "tags": []}}],
            "pair": ["0x0000000000000000000000000000000000000001", "0x00000000000000000000000000000000000000fF"],
            "grid": [[1, 2, 3], [4, 5, 6]], "none": []}}}}"#,
        domain_types(""),
        DOMAIN
    ));
    // types referred to in several places and at several depths (each encoded once, sorted)
    out.push(format!(
        r#"{{"types": {{{}, "Node": [{{"name": "label", "type": "string"}}, {{"name": "kids", "type": "Leaf[]"}}, {{"name": "owner", "type": "Zed"}}],
            "Leaf": [{{"name": "label", "type": "string"}}, {{"name": "owner", "type": "Zed"}}],
            "Zed": [{{"name": "who", "type": "address"}}], "Alpha": [{{"name": "a", "type": "Node"}}, {{"name": "z", "type": "Zed"}}]}},
          "primaryType": "Alpha", "domain": {},
          "message": {{"a": {{"label": "root", "kids": [{{"label": "leaf", "owner": {{"who": "0x0000000000000000000000000000000000000002"}}}}],
            "owner": {{"who": "0x0000000000000000000000000000000000000003"}}}}, "z": {{"who": "0x0000000000000000000000000000000000000004"}}}}}}"#,
        domain_types(""),
        DOMAIN
    ));
    // Uniswap's Permit2, a batch
    out.push(permit2_batch());
    out
}

fn permit2_batch() -> String {
    r#"{"types": {
        "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
        "PermitDetails": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint160"},
            {"name": "expiration", "type": "uint48"}, {"name": "nonce", "type": "uint48"}],
        "PermitBatch": [{"name": "details", "type": "PermitDetails[]"}, {"name": "spender", "type": "address"}, {"name": "sigDeadline", "type": "uint256"}]},
      "primaryType": "PermitBatch",
      "domain": {"name": "Permit2", "chainId": 1, "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"},
      "message": {"details": [
          {"token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "amount": "1461501637330902918203684832716283019655932542975", "expiration": "1790000000", "nonce": 0},
          {"token": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "amount": "25000000", "expiration": 0, "nonce": 3}],
        "spender": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", "sigDeadline": "1790001800"}}"#
        .to_string()
}

#[test]
fn typed_data_of_every_shape_hashes_as_alloy_hashes_it() {
    for json in shapes() {
        let td = TypedData::parse(&json).unwrap_or_else(|e| panic!("{}\n{}", e, json));
        assert_eq!(hex(&td.signing_hash().unwrap()), alloy_hash(&json), "{}", json);
    }
}

#[test]
fn signatures_recover_to_the_account() {
    let account = Account::from_private_key(&[7u8; 32]).unwrap();
    for json in shapes() {
        let td = TypedData::parse(&json).unwrap();
        let sig = account.sign_typed(&td).unwrap();
        let signature = alloy::primitives::Signature::from_raw(&sig).unwrap();
        let hash = alloy::primitives::B256::from(td.signing_hash().unwrap());
        let signer = signature.recover_address_from_prehash(&hash).unwrap();
        assert_eq!(signer.as_slice(), account.address());
        // low s, v 27 or 28
        assert!(sig[32] < 0x80 && (sig[64] == 27 || sig[64] == 28));
    }
}

fn refused(json: &str) -> String {
    match TypedData::parse(json) {
        Ok(_) => panic!("took {}", json),
        Err(e) => e.to_string(),
    }
}

/// MAIL with one piece of text replaced.
fn mail_with(from: &str, to: &str) -> String {
    assert!(MAIL.contains(from), "{}", from);
    MAIL.replacen(from, to, 1)
}

#[test]
fn what_maki_wont_take() {
    // a value its type doesn't declare, which wouldn't be signed
    assert!(refused(&mail_with(r#""contents": "Hello, Bob!""#, r#""contents": "Hello, Bob!", "amount": "1000000""#)).contains("not declared"));
    // a declared value left out
    assert!(refused(&mail_with(",\n    \"contents\": \"Hello, Bob!\"", "")).contains("missing"));
    // a type that refers to itself, however indirectly
    assert!(refused(&mail_with(r#"{"name": "wallet", "type": "address"}"#, r#"{"name": "wallet", "type": "address"}, {"name": "last", "type": "Mail"}"#)).contains("refers to itself"));
    // wrong kinds of value
    assert!(refused(&mail_with(r#""chainId": 1"#, r#""chainId": 1.5"#)).contains("whole numbers"));
    assert!(refused(&mail_with(r#""chainId": 1"#, r#""chainId": true"#)).contains("whole number"));
    assert!(refused(&mail_with("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB", "0xbBbB")).contains("address"));
    assert!(refused(&mail_with(r#""contents": "Hello, Bob!""#, r#""contents": 7"#)).contains("string"));
    // a type nobody declared, and types that aren't
    assert!(refused(&mail_with(r#""type": "Person"}"#, r#""type": "Persona"}"#)).contains("no type"));
    assert!(refused(&mail_with(r#""contents", "type": "string""#, r#""contents", "type": "string[0]""#)).contains("isn't a type"));
    assert!(refused(&mail_with(r#""contents", "type": "string""#, r#""contents", "type": "uint7""#)).contains("no type \"uint7\""));
    // the domain: EIP-712's fields only, of their types, in its order
    assert!(refused(&mail_with(r#"{"name": "version", "type": "string"},"#, r#"{"name": "version", "type": "uint256"},"#)).contains("should be string"));
    assert!(refused(&mail_with(r#""EIP712Domain": ["#, r#""EIP712Domain": [{"name": "owner", "type": "address"},"#)).contains("isn't a domain field"));
    assert!(refused(&MAIL.replace("EIP712Domain", "Domain")).contains("EIP712Domain"));
    // JSON that's too loose: a name twice, a trailing comma, more after the end, deep nesting
    assert!(refused(&mail_with(r#""contents": "Hello, Bob!""#, r#""contents": "Hello, Bob!", "contents": "Hi""#)).contains("twice"));
    assert!(refused(&mail_with(r#""contents": "Hello, Bob!""#, r#""contents": "Hello, Bob!","#)).contains("expected"));
    assert!(refused(&format!("{} {{}}", MAIL)).contains("after the end"));
    assert!(refused(&format!("{}{}", "[".repeat(40), "]".repeat(40))).contains("deep"));
    // out of range
    let edges = shapes()[1].clone();
    assert!(refused(&edges.replacen(r#""a": 255"#, r#""a": 256"#, 1)).contains("out of range"));
    assert!(refused(&edges.replacen(r#""b": -128"#, r#""b": -129"#, 1)).contains("out of range"));
    assert!(refused(&edges.replacen(r#""c": "127""#, r#""c": "128""#, 1)).contains("out of range"));
    assert!(refused(&edges.replacen(r#""i": 0"#, r#""i": -1"#, 1)).contains("out of range"));
    // a fixed-size array or bytesN of the wrong length
    let arrays = shapes()[3].clone();
    assert!(refused(&arrays.replacen(r#""0x00000000000000000000000000000000000000fF"]"#, r#""0x00000000000000000000000000000000000000fF", "0x0000000000000000000000000000000000000001"]"#, 1)).contains("items"));
    let blob = shapes()[2].clone();
    assert!(refused(&blob.replacen(r#""one": "0x7f""#, r#""one": "0x7f00""#, 1)).contains("1 bytes"));
    // something other than typed data, and signing the domain itself
    assert!(refused(r#"{"types": {}, "primaryType": "Mail", "domain": {}, "message": {}, "extra": 1}"#).contains("isn't part of typed data"));
    assert!(refused(&mail_with(r#""primaryType": "Mail""#, r#""primaryType": "EIP712Domain""#)).contains("to sign"));
}

fn show(pages: &[Page]) -> Vec<String> { pages.iter().map(|p| format!("{} | {} | {}", p.heading, p.value, p.mono)).collect() }

#[test]
fn a_permit_is_spelled_out() {
    let permit = r#"{"types": {
        "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
        "Permit": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"}, {"name": "value", "type": "uint256"},
            {"name": "nonce", "type": "uint256"}, {"name": "deadline", "type": "uint256"}]},
      "primaryType": "Permit",
      "domain": {"name": "USD Coin", "version": "2", "chainId": 8453, "verifyingContract": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"},
      "message": {"owner": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "spender": "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad",
        "value": "115792089237316195423570985008687907853269984665640564039457584007913129639935", "nonce": 0, "deadline": 1790000000}}"#;
    let td = TypedData::parse(permit).unwrap();
    assert_eq!(hex(&td.signing_hash().unwrap()), alloy_hash(permit));
    let (pages, title, line) = display::typed_review(&td).unwrap();
    assert_eq!((title, line), ("Sign permit?", "it can spend tokens"));
    assert_eq!(
        show(&pages),
        [
            "Network | base | chain ID 8453",
            "App | USD Coin | version 2\n0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "Permit! | lets it spend tokens | 0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
            "Up to | in its smallest units | any amount",
            "Until | 2026-09-21 | 14:13 UTC",
            "Token | its contract | 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        ]
    );
    // the same types renamed aren't taken for a permit: they go field by field
    let lookalike = permit.replace("\"Permit\"", "\"Permlt\"");
    let (pages, title, _) = display::typed_review(&TypedData::parse(&lookalike).unwrap()).unwrap();
    assert_eq!(title, "Sign data?");
    assert!(show(&pages).contains(&"value | number | 115792089237316195423570985008687907853269984665640564039457584007913129639935".to_string()));
}

#[test]
fn a_permit2_batch_is_spelled_out_token_by_token() {
    let td = TypedData::parse(&permit2_batch()).unwrap();
    let (pages, title, _) = display::typed_review(&td).unwrap();
    assert_eq!(title, "Sign permit?");
    assert_eq!(
        show(&pages),
        [
            "Network | ethereum | chain ID 1",
            "App | Permit2 | 0x000000000022D473030F116dDEE9F6B43aC78BA3",
            "Permit! | lets it spend tokens | 0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
            "Token 1 | its contract | 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "Up to 1 | in its smallest units | any amount",
            "Until 1 | 2026-09-21 | 14:13 UTC",
            "Token 2 | its contract | 0xdAC17F958D2ee523a2206206994597C13D831ec7",
            "Up to 2 | in its smallest units | 25000000",
            "Until 2 | its first use | ",
        ]
    );
}

#[test]
fn anything_else_goes_field_by_field() {
    let td = TypedData::parse(MAIL).unwrap();
    let (pages, title, line) = display::typed_review(&td).unwrap();
    assert_eq!((title, line), ("Sign data?", "apps may act on it"));
    assert_eq!(
        show(&pages),
        [
            "Network | ethereum | chain ID 1",
            "App | Ether Mail | version 1\n0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
            "Data | Mail | ",
            "from.name | text | Cow",
            "from.wallet | address | 0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
            "to.name | text | Bob",
            "to.wallet | address | 0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
            "contents | text | Hello, Bob!",
        ]
    );
    // arrays, nested and empty, and every kind of value
    let (pages, _, _) = display::typed_review(&TypedData::parse(&shapes()[3]).unwrap()).unwrap();
    let shown = show(&pages);
    assert!(shown.contains(&"items[0].tags[1] | text | b".to_string()));
    assert!(shown.contains(&"items[1].tags | an empty list | ".to_string()));
    assert!(shown.contains(&"grid[1][2] | number | 6".to_string()));
    let (pages, _, _) = display::typed_review(&TypedData::parse(&shapes()[2]).unwrap()).unwrap();
    let shown = show(&pages);
    assert!(shown.contains(&"data | 5 bytes | deadbeef00".to_string()));
    assert!(shown.contains(&"yes | yes | ".to_string()));
    assert!(shown.contains(&"note | text | café 🍰 \"quoted\"\n".to_string()));
    let (pages, _, _) = display::typed_review(&TypedData::parse(&shapes()[1]).unwrap()).unwrap();
    assert!(show(&pages).contains(&"b | number | -128".to_string()));
}

#[test]
fn too_much_to_show_is_refused() {
    let many: Vec<String> = (0..60).map(|i| format!("\"{}\"", i)).collect();
    let json = format!(
        r#"{{"types": {{{}, "List": [{{"name": "all", "type": "string[]"}}]}}, "primaryType": "List", "domain": {}, "message": {{"all": [{}]}}}}"#,
        domain_types(""),
        DOMAIN,
        many.join(",")
    );
    let td = TypedData::parse(&json).unwrap();
    assert!(display::typed_review(&td).unwrap_err().to_string().contains("too much to show"));
}

#[test]
fn dates_are_utc() {
    assert_eq!(display::utc(0), "1970-01-01 00:00 UTC");
    assert_eq!(display::utc(951_782_400), "2000-02-29 00:00 UTC");
    assert_eq!(display::utc(1_790_000_000), "2026-09-21 14:13 UTC");
    assert_eq!(display::utc(253_402_300_799), "9999-12-31 23:59 UTC");
}
