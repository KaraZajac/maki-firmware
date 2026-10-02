//! What a transaction costs, as nearcore charges it (`tx_cost`): gas to send each action and gas to
//! run it, more for each byte of a call's method and arguments, a contract's code or a key's method
//! names, and more again for NEAR sent to an account that sending makes (what making it costs); and
//! the gas its calls are given to run on. NEAR's protocol sets these: they're protocol 86's and 87's (NEAR's
//! own network and its test network on 2026-10-02, read with `EXPERIMENTAL_protocol_config` and from
//! nearcore's `parameters.yaml`), and a later protocol can change them.
//!
//! What gas costs isn't in the transaction. NEAR's blocks set its price, from the least it can be
//! (100 million yoctoNEAR a gas, 0.0001 NEAR a Tgas, where it usually is) up to 20 times that
//! (nearcore's `MAX_GAS_MULTIPLIER`), each checked by the network; so the most a transaction can
//! cost is its gas at the highest price. Gas a call doesn't use comes back, and making an account
//! costs `ACCOUNT_CREATION_CHARGE` in all, gas included (protocol 85's `AccountCostIncrease`).

use crate::account::{self, Kind};
use crate::tx::{Action, Code, Permission, Transaction};

/// What an action costs to send, when it's to the signer itself (`sir`, so it stays on its shard)
/// and when it isn't, and what it costs to run, in gas.
#[derive(Clone, Copy)]
struct Fee {
    sir: u64,
    not_sir: u64,
    exec: u64,
}

impl Fee {
    const fn same(gas: u64) -> Fee { Fee { sir: gas, not_sir: gas, exec: gas } }

    fn send(self, sir: bool) -> u64 { if sir { self.sir } else { self.not_sir } }

    /// Sending and running it, with `n` of what `per` is the fee for each of.
    fn with(self, per: Fee, n: usize, sir: bool) -> (u64, u64) {
        let n = n as u64;
        (self.send(sir) + per.send(sir) * n, self.exec + per.exec * n)
    }

    fn both(self, sir: bool) -> (u64, u64) { (self.send(sir), self.exec) }
}

const RECEIPT: Fee = Fee::same(108_059_500_000);
const CREATE_ACCOUNT: Fee = Fee { sir: 500_000_000_000, not_sir: 500_000_000_000, exec: 7_200_000_000_000 };
const DELETE_ACCOUNT: Fee = Fee::same(147_489_000_000);
const DEPLOY: Fee = Fee::same(184_765_750_000);
const DEPLOY_BYTE: Fee = Fee { sir: 6_812_999, not_sir: 47_683_715, exec: 64_572_944 };
const CALL: Fee = Fee { sir: 200_000_000_000, not_sir: 200_000_000_000, exec: 780_000_000_000 };
const CALL_BYTE: Fee = Fee { sir: 2_235_934, not_sir: 47_683_715, exec: 2_235_934 };
const TRANSFER: Fee = Fee::same(115_123_062_500);
const STAKE: Fee = Fee { sir: 141_715_687_500, not_sir: 141_715_687_500, exec: 102_217_625_000 };
const ADD_FULL_KEY: Fee = Fee::same(101_765_125_000);
const ADD_CALL_KEY: Fee = Fee::same(102_217_625_000);
const ADD_CALL_KEY_BYTE: Fee = Fee { sir: 1_925_331, not_sir: 47_683_715, exec: 1_925_331 };
const DELETE_KEY: Fee = Fee::same(94_946_625_000);
const PUBLISH: Fee = Fee::same(184_765_750_000);
const PUBLISH_BYTE: Fee = Fee { sir: 6_812_999, not_sir: 47_683_715, exec: 70_000_000 };
const USE_PUBLISHED: Fee = Fee::same(184_765_750_000);
const USE_PUBLISHED_BYTE: Fee = Fee { sir: 6_812_999, not_sir: 47_683_715, exec: 64_572_944 };

/// The least gas can cost, in yoctoNEAR a gas (nearcore's `MIN_GAS_PRICE_NEP_92_FIX`, for both
/// networks): 0.0001 NEAR a Tgas.
pub const MIN_GAS_PRICE: u128 = 100_000_000;
/// The most gas can cost: 20 times the least, 0.002 NEAR a Tgas.
pub const MAX_GAS_PRICE: u128 = 20 * MIN_GAS_PRICE;
/// What making an account costs in all, gas included: 0.007 NEAR.
pub const ACCOUNT_CREATION_CHARGE: u128 = 7_000_000_000_000_000_000_000;
/// What publishing code burns for each of its bytes, for keeping it: 0.0001 NEAR
/// (`global_contract_storage_amount_per_byte`).
pub const PUBLISH_PER_BYTE: u128 = 100_000_000_000_000_000_000;

/// What sending NEAR to `receiver` costs: more if sending can make it, what making it does (and
/// adding its key, for an implicit account). A universal account (`0u`) costs that only from
/// protocol 87, which NEAR's own network hasn't reached: maki counts it anyway, so the most the
/// fee can be is never less than NEAR charges.
fn transfer(receiver: &str, sir: bool) -> (u64, u64) {
    let (mut send, mut exec) = TRANSFER.both(sir);
    if account::kind(receiver) != Kind::Named {
        send += CREATE_ACCOUNT.send(sir);
        exec += CREATE_ACCOUNT.exec;
    }
    if account::kind(receiver) == Kind::Implicit {
        send += ADD_FULL_KEY.send(sir);
        exec += ADD_FULL_KEY.exec;
    }
    (send, exec)
}

/// The gas sending `tx` and its actions takes, and the gas running them takes (not counting what
/// its calls are given to run on).
fn parts(tx: &Transaction) -> (u64, u64) {
    let sir = tx.receiver == tx.signer;
    let (mut send, mut exec) = RECEIPT.both(sir);
    for a in &tx.actions {
        let (s, e) = match a {
            Action::CreateAccount => CREATE_ACCOUNT.both(sir),
            Action::DeployContract { code } => DEPLOY.with(DEPLOY_BYTE, code.len(), sir),
            Action::FunctionCall { method, args, .. } => CALL.with(CALL_BYTE, method.len() + args.len(), sir),
            Action::Transfer { .. } => transfer(&tx.receiver, sir),
            Action::Stake { .. } => STAKE.both(sir),
            Action::AddKey { permission: Permission::FullAccess, .. } => ADD_FULL_KEY.both(sir),
            // each name counted with one more byte, for its end
            Action::AddKey { permission: Permission::FunctionCall { methods, .. }, .. } => {
                ADD_CALL_KEY.with(ADD_CALL_KEY_BYTE, methods.iter().map(|m| m.len() + 1).sum(), sir)
            }
            Action::DeleteKey { .. } => DELETE_KEY.both(sir),
            Action::DeleteAccount { .. } => DELETE_ACCOUNT.both(sir),
            Action::DeployGlobalContract { code, .. } => PUBLISH.with(PUBLISH_BYTE, code.len(), sir),
            Action::UseGlobalContract(code) => {
                let n = match code {
                    Code::Hash(_) => 32,
                    Code::Account(id) => id.len(),
                };
                USE_PUBLISHED.with(USE_PUBLISHED_BYTE, n, sir)
            }
        };
        send += s;
        exec += e;
    }
    (send, exec)
}

/// The gas burnt as NEAR takes `tx`, turning it into a receipt (an outcome's `gas_burnt` for the
/// transaction): sending it and its actions.
pub fn conversion(tx: &Transaction) -> u64 { parts(tx).0 }

/// The most gas `tx` can take: sending it and its actions, burnt as NEAR takes it, and running
/// them with the gas its calls are given, bought then and burnt as they run.
pub fn gas(tx: &Transaction) -> u64 {
    let (send, exec) = parts(tx);
    send + exec + tx.prepaid_gas()
}

/// What making an account costs beyond the gas its making takes, at the least gas can cost: what
/// a transaction that makes one costs more, as NEAR usually charges.
pub fn creation_surcharge() -> u128 { ACCOUNT_CREATION_CHARGE - CREATE_ACCOUNT.exec as u128 * MIN_GAS_PRICE }
