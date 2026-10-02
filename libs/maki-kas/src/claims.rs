//! What the computer said each coin held, kept for the coins maki signed for. A Kaspa signature
//! covers its own input's amount and no other's: a computer that lies about one coin while maki
//! signs, and about another the next time it asks for the same transaction, gets every input
//! signed once, each time over a fee that isn't the fee (the SegWit fee attack of 2020). Kept, the
//! claims catch it: the second time, a coin maki signed for is said to hold something else, and
//! maki refuses. A coin's amount never changes, so an honest computer says the same each time.
//!
//! The app keeps them in its storage, the newest `MAX_CLAIMS`, each `CLAIM` bytes: the first eight
//! of the coin's transaction ID, its output's index (u32) and the amount said (u64), little-endian,
//! the oldest first. Only a yes adds to them, so a computer can't push the claims of coins it lies
//! about out of them without the owner saying yes to `MAX_CLAIMS` other coins first.

use alloc::vec::Vec;

use crate::Error;
use crate::request::{Input, Request};

/// How many claims are kept: the coins of the last few hundred inputs signed.
pub const MAX_CLAIMS: usize = 768;
/// The bytes of a claim.
pub const CLAIM: usize = 20;

/// The claims kept, the oldest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Claims(Vec<[u8; CLAIM]>);

/// Which coin an input spends, as a claim names it: eight bytes of a hash are plenty to tell coins
/// apart, and two that matched would only have maki refuse.
fn coin(input: &Input) -> [u8; 12] {
    let mut c = [0u8; 12];
    c[..8].copy_from_slice(&input.txid[..8]);
    c[8..].copy_from_slice(&input.index.to_le_bytes());
    c
}

fn claim(input: &Input) -> [u8; CLAIM] {
    let mut c = [0u8; CLAIM];
    c[..12].copy_from_slice(&coin(input));
    c[12..].copy_from_slice(&input.amount.to_le_bytes());
    c
}

impl Claims {
    /// The claims as the app keeps them: whole ones, the newest `MAX_CLAIMS`.
    pub fn read(bytes: &[u8]) -> Claims {
        let mut claims: Vec<[u8; CLAIM]> = bytes
            .chunks_exact(CLAIM)
            .map(|c| {
                let mut claim = [0u8; CLAIM];
                claim.copy_from_slice(c);
                claim
            })
            .collect();
        let over = claims.len().saturating_sub(MAX_CLAIMS);
        claims.drain(..over);
        Claims(claims)
    }

    /// The claims, to keep.
    pub fn bytes(&self) -> Vec<u8> { self.0.concat() }

    pub fn len(&self) -> usize { self.0.len() }

    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Whether every coin the request spends that maki signed for before is said to hold what it was
    /// then. `Error::Claim` names the first that isn't.
    pub fn check(&self, request: &Request) -> Result<(), Error> {
        for (i, input) in request.inputs.iter().enumerate() {
            let said = claim(input);
            if self.0.iter().any(|c| c[..12] == said[..12] && c[12..] != said[12..]) {
                return Err(Error::Claim(i));
            }
        }
        Ok(())
    }

    /// What the request says its coins hold, kept as the newest claims (once the owner has said
    /// yes); the oldest go when there are more than `MAX_CLAIMS`.
    pub fn add(&mut self, request: &Request) {
        for input in &request.inputs {
            let said = claim(input);
            self.0.retain(|c| c[..12] != said[..12]);
            self.0.push(said);
        }
        let over = self.0.len().saturating_sub(MAX_CLAIMS);
        self.0.drain(..over);
    }
}
