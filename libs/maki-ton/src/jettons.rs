//! Jettons maki knows (TEP-74), by their masters: their symbols and decimals (as each master's
//! own content says them), and how to tell an account's jetton wallet for each from the account.
//!
//! An account's jettons are held by a contract of their own, its jetton wallet, which its master
//! sets up at an address made from the account's: the hash of the jetton wallet's first state
//! (the wallet code the master holds, and status 0, balance 0, the owner and the master). An
//! account sends jettons by asking that jetton wallet to; so a transfer goes to an address that,
//! if it's this account's jetton wallet for a jetton maki knows, maki can work out, and so know
//! which jetton it is. Any other, maki can't tell.

use crate::cell::Builder;
use crate::{Address, Hash};

/// A jetton maki knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Jetton {
    /// Its symbol, as maki shows it.
    pub symbol: &'static str,
    /// How many decimal places its amounts have, as its master's content says.
    pub decimals: u8,
    /// Its master, on the basechain.
    pub master: Hash,
    /// The code its jetton wallets run, by its hash: the master holds it as a library cell that
    /// stands for it.
    pub code: Hash,
}

/// Tether's USD₮ (6 decimals): its master `EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs`.
pub const USDT: Jetton = Jetton {
    symbol: "USDT",
    decimals: 6,
    master: [
        0xb1, 0x13, 0xa9, 0x94, 0xb5, 0x02, 0x4a, 0x16, 0x71, 0x9f, 0x69, 0x13, 0x93, 0x28, 0xeb, 0x75, 0x95,
        0x96, 0xc3, 0x8a, 0x25, 0xf5, 0x90, 0x28, 0xb1, 0x46, 0xfe, 0xcd, 0xc3, 0x62, 0x1d, 0xfe,
    ],
    code: [
        0x8f, 0x45, 0x2d, 0x7a, 0x4d, 0xfd, 0x74, 0x06, 0x6b, 0x68, 0x23, 0x65, 0x17, 0x72, 0x59, 0xed, 0x05,
        0x73, 0x44, 0x35, 0xbe, 0x76, 0xb5, 0xfd, 0x4b, 0xd5, 0xd8, 0xaf, 0x2b, 0x7c, 0x3d, 0x68,
    ],
};

/// The wallet code Notcoin's and DOGS's masters share.
const NOTCOIN_WALLET: Hash = [
    0xba, 0x29, 0x18, 0xc8, 0x94, 0x7e, 0x9b, 0x25, 0xaf, 0x9a, 0xc1, 0xb8, 0x83, 0x35, 0x77, 0x54, 0x17,
    0x3e, 0x58, 0x12, 0xf8, 0x07, 0xa3, 0xd6, 0xe6, 0x42, 0xa1, 0x47, 0x09, 0x59, 0x53, 0x95,
];

/// Notcoin (9 decimals): its master `EQAvlWFDxGF2lXm67y4yzC17wYKD9A0guwPkMs1gOsM__NOT`.
pub const NOT: Jetton = Jetton {
    symbol: "NOT",
    decimals: 9,
    master: [
        0x2f, 0x95, 0x61, 0x43, 0xc4, 0x61, 0x76, 0x95, 0x79, 0xba, 0xef, 0x2e, 0x32, 0xcc, 0x2d, 0x7b, 0xc1,
        0x82, 0x83, 0xf4, 0x0d, 0x20, 0xbb, 0x03, 0xe4, 0x32, 0xcd, 0x60, 0x3a, 0xc3, 0x3f, 0xfc,
    ],
    code: NOTCOIN_WALLET,
};

/// DOGS (9 decimals): its master `EQCvxJy4eG8hyHBFsZ7eePxrRsUQSFE_jpptRAYBmcG_DOGS`.
pub const DOGS: Jetton = Jetton {
    symbol: "DOGS",
    decimals: 9,
    master: [
        0xaf, 0xc4, 0x9c, 0xb8, 0x78, 0x6f, 0x21, 0xc8, 0x70, 0x45, 0xb1, 0x9e, 0xde, 0x78, 0xfc, 0x6b, 0x46,
        0xc5, 0x10, 0x48, 0x51, 0x3f, 0x8e, 0x9a, 0x6d, 0x44, 0x06, 0x01, 0x99, 0xc1, 0xbf, 0x0c,
    ],
    code: NOTCOIN_WALLET,
};

/// Every jetton maki knows, on TON (its test network has none of them).
pub const KNOWN: [Jetton; 3] = [USDT, NOT, DOGS];

impl Jetton {
    /// Its master's address.
    pub fn master(&self) -> Address { Address { workchain: 0, hash: self.master } }

    /// The hash of the library cell its master holds for its wallets' code: what their first
    /// state refers to.
    pub fn code_cell(&self) -> Hash { Builder::library(&self.code).finish().0 }

    /// `owner`'s jetton wallet for it: the hash of its first state, as the master works it out.
    pub fn wallet(&self, owner: &Address) -> Address {
        let code = Builder::library(&self.code).finish();
        // status:uint4 balance:Coins owner_address:MsgAddressInt jetton_master_address:MsgAddressInt
        let data = Builder::new().uint(0, 4).uint(0, 4).address(owner).address(&self.master()).finish();
        let init = Builder::new().uint(0b00110, 5).reference(code).reference(data).finish();
        Address { workchain: 0, hash: init.0 }
    }
}

/// The jetton `wallet` is `owner`'s jetton wallet for, if it's one maki knows.
pub fn known(wallet: &Address, owner: &Address) -> Option<&'static Jetton> {
    KNOWN.iter().find(|j| j.wallet(owner) == *wallet)
}
