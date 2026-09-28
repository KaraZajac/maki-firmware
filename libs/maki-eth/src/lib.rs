//! maki's Ethereum account: keys from the recovery phrase (BIP44, `m/44'/60'/0'/0/i`, as MetaMask
//! and Ledger make them, so the phrase works there too), EIP-55 addresses, and what maki signs,
//! shown on its screen first: transactions (EIP-1559, and EIP-155 legacy ones), messages
//! (EIP-191 `personal_sign`) and typed data (EIP-712 `eth_signTypedData_v4`).
//!
//! What keeps a lying computer from getting a signature the owner didn't mean to give:
//!
//! - maki parses the exact bytes it signs, strictly (one encoding per value), and shows what
//!   they say: the network, the recipient and amount, a token transfer or approval spelled out,
//!   and any other contract call flagged as one maki can't read;
//! - legacy transactions must carry a chain ID (EIP-155), so a signature can't be replayed on
//!   another network;
//! - messages are signed with the EIP-191 prefix, so a message can never pass for a
//!   transaction;
//! - typed data is read from the site's JSON on maki and hashed from the very values shown,
//!   every signed field among them, and a permit is spelled out as the spending it allows.

#![no_std]
extern crate alloc;

pub mod account;
pub mod display;
pub mod json;
pub mod rlp;
pub mod tokens;
pub mod tx;
pub mod typed;

pub use account::{checksum, keccak256, Account};
pub use tx::Tx;
pub use typed::TypedData;
