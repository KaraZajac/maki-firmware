//! Transactions as maki writes them, held to one from Monero's own chain: its bytes, hash and
//! the message its signature signs (monero-oxide's vectors, `tests/vectors/transactions.json`).
use maki_xmr::tx::Transaction;

fn hex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }

#[test]
fn a_mainnet_transaction_reads_writes_and_hashes_as_monero_does() {
    let mut lines = include_str!("mainnet-tx.txt").lines();
    let (id, signature_hash, bytes) = (hex(lines.next().unwrap()), hex(lines.next().unwrap()), hex(lines.next().unwrap()));
    let tx = Transaction::from_bytes(&bytes).expect("a type-6 transaction");
    assert_eq!(tx.to_bytes(), bytes);
    assert_eq!(tx.hash().to_vec(), id);
    assert_eq!(tx.signature_hash().to_vec(), signature_hash);
    assert_eq!((tx.prefix.inputs.len(), tx.prefix.outputs.len(), tx.prefix.inputs[0].key_offsets.len()), (1, 4, 16));
    // anything more, or less, isn't one
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(Transaction::from_bytes(&longer).is_none());
    assert!(Transaction::from_bytes(&bytes[..bytes.len() - 1]).is_none());
}
