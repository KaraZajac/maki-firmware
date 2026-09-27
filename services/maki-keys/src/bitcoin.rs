//! The Bitcoin wallet's keys, from the recovery phrase: the account handed to wallet software,
//! addresses shown for the owner to compare, and PSBTs signed once the owner has gone through
//! them on screen (ARCHITECTURE.md, "Order of work"; the checks are maki-btc's).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use maki_btc::psbt::Psbt;
use maki_btc::{display, wallet, Account, Network};
use maki_keys_api::*;
use maki_launcher::{Answer, Launcher, Page};
use xous_ipc::Buffer;
use zeroize::Zeroize;

const ACCOUNT_TIMEOUT_S: u32 = if option_env!("MAKI_DEMO").is_some() { 600 } else { 60 };
const ADDRESS_TIMEOUT_S: u32 = if option_env!("MAKI_DEMO").is_some() { 600 } else { 120 };
/// Time to read every payment's address, carefully.
const SIGN_TIMEOUT_S: u32 = if option_env!("MAKI_DEMO").is_some() { 600 } else { 300 };
/// More outputs than this and a transaction isn't reviewed page by page on a small screen with
/// any care: maki refuses it.
const MAX_OUTPUTS: usize = 64;

fn network(n: u8) -> Network { if n == NETWORK_TESTNET { Network::Testnet } else { Network::Bitcoin } }

/// Ask on the launcher's screen, from a thread of our own: the owner takes their time.
fn owner_says(ask: impl FnOnce(&Launcher) -> Result<Answer, xous::Error>) -> u32 {
    let xns = xous_names::XousNames::new().unwrap();
    match Launcher::new(&xns).map(|l| ask(&l)) {
        Ok(Ok(Answer::Allowed(_))) => RESULT_OK,
        Ok(Ok(Answer::Denied)) => RESULT_DENIED,
        Ok(Ok(Answer::TimedOut)) => RESULT_TIMED_OUT,
        _ => RESULT_FAILED,
    }
}

/// Answer a held `Wallet` message.
fn answer_wallet(mut msg: xous::MessageEnvelope, fill: impl FnOnce(&mut Wallet)) {
    if let Some(mem) = msg.body.memory_message_mut() {
        let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
        if let Ok(mut req) = buffer.to_original::<Wallet, _>() {
            fill(&mut req);
            buffer.replace(req).ok();
        }
    }
}

pub(crate) struct Btc {
    /// bitcoin's and the test networks', derived at first use while unlocked
    accounts: [Option<Account>; 2],
    incoming: Vec<u8>,
    incoming_total: u32,
    /// the PSBT last signed, for the computer to fetch
    signed: Arc<Mutex<Vec<u8>>>,
    /// a PSBT is being reviewed: another has to wait
    busy: Arc<AtomicBool>,
}

impl Btc {
    pub(crate) fn new() -> Self {
        Btc {
            accounts: [None, None],
            incoming: Vec::new(),
            incoming_total: 0,
            signed: Arc::new(Mutex::new(Vec::new())),
            busy: Arc::new(AtomicBool::new(false)),
        }
    }

    /// maki locked: the keys go until the PIN comes back.
    pub(crate) fn forget(&mut self) {
        self.accounts = [None, None];
        self.incoming.clear();
    }

    /// The account on `n`, from the seed (None: locked, or no phrase yet).
    fn account(&mut self, seed: Option<[u8; 64]>, n: u8) -> Result<Account, u32> {
        let slot = n.min(1) as usize;
        if let Some(a) = &self.accounts[slot] {
            return Ok(a.clone());
        }
        let Some(mut seed) = seed else { return Err(RESULT_NO_PHRASE) };
        let account = Account::from_seed(&seed, network(n));
        seed.zeroize();
        let account = account.map_err(|_| RESULT_FAILED)?;
        self.accounts[slot] = Some(account.clone());
        Ok(account)
    }

    /// `KeysOp::BtcAccount`: the zpub and descriptor, once the owner agrees if asked to ask.
    pub(crate) fn share_account(&mut self, mut msg: xous::MessageEnvelope, seed: Option<[u8; 64]>) {
        let Some(mem) = msg.body.memory_message_mut() else { return };
        let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
        let Ok(mut req) = buffer.to_original::<Wallet, _>() else { return };
        let account = match self.account(seed, req.network) {
            Ok(a) => a,
            Err(result) => {
                req.result = result;
                buffer.replace(req).ok();
                return;
            }
        };
        if !req.ask {
            req.result = RESULT_OK;
            req.text = account.zpub();
            req.descriptor = account.descriptor();
            buffer.replace(req).ok();
            return;
        }
        drop(buffer);
        std::thread::spawn(move || {
            let name = display::network_name(account.network);
            let result = owner_says(|l| l.ask(name, "Share account?", "view only", &[], ACCOUNT_TIMEOUT_S));
            log::info!("bitcoin account shared: {}", result == RESULT_OK);
            answer_wallet(msg, |req| {
                req.result = result;
                if result == RESULT_OK {
                    req.text = account.zpub();
                    req.descriptor = account.descriptor();
                }
            });
        });
    }

    /// `KeysOp::BtcAddress`: an address, compared on screen first if asked to ask.
    pub(crate) fn address(&mut self, mut msg: xous::MessageEnvelope, seed: Option<[u8; 64]>) {
        let Some(mem) = msg.body.memory_message_mut() else { return };
        let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
        let Ok(mut req) = buffer.to_original::<Wallet, _>() else { return };
        let address = match self.account(seed, req.network) {
            Ok(a) => a.address(req.change, req.index).map_err(|_| RESULT_FAILED),
            Err(result) => Err(result),
        };
        let address = match address {
            Ok(a) if req.ask => a,
            Ok(a) => {
                req.result = RESULT_OK;
                req.text = a;
                buffer.replace(req).ok();
                return;
            }
            Err(result) => {
                req.result = result;
                buffer.replace(req).ok();
                return;
            }
        };
        let which = format!("{} #{}", if req.change { "Change" } else { "Receive" }, req.index);
        drop(buffer);
        std::thread::spawn(move || {
            // the address where a site's name goes: 42 characters, three lines of the screen
            let result = owner_says(|l| {
                l.review(&address, "Same on computer?", &which, Vec::new(), "matches", "doesn't match", ADDRESS_TIMEOUT_S)
            });
            answer_wallet(msg, |req| {
                req.result = result;
                req.text = address;
            });
        });
    }

    /// `KeysOp::BtcSign`: a piece of a PSBT. The last one is checked, shown, and signed if the
    /// owner says so.
    pub(crate) fn sign_piece(&mut self, mut msg: xous::MessageEnvelope, seed: impl FnOnce() -> Option<[u8; 64]>) {
        let Some(mem) = msg.body.memory_message_mut() else { return };
        let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
        let Ok(mut req) = buffer.to_original::<Chunk, _>() else { return };
        let mut reply = |mut req: Chunk, result: u32, reason: String| {
            req.data.clear();
            req.result = result;
            req.done = true;
            req.reason = reason;
            buffer.replace(req).ok();
        };
        if self.busy.load(Ordering::SeqCst) {
            // one PSBT on screen at a time
            return reply(req, RESULT_FAILED, String::new());
        }
        if req.offset == 0 {
            self.incoming.clear();
            self.incoming_total = req.total;
        }
        let in_order = req.offset as usize == self.incoming.len()
            && req.total == self.incoming_total
            && req.total as usize <= MAX_PSBT
            && self.incoming.len() + req.data.len() <= req.total as usize;
        if !in_order {
            self.incoming.clear();
            return reply(req, RESULT_FAILED, String::new());
        }
        self.incoming.extend_from_slice(&req.data);
        if self.incoming.len() < self.incoming_total as usize {
            req.data.clear();
            req.result = RESULT_OK;
            req.done = false;
            buffer.replace(req).ok();
            return;
        }
        let bytes = std::mem::take(&mut self.incoming);
        let account = match self.account(seed(), req.network) {
            Ok(a) => a,
            Err(result) => return reply(req, result, String::new()),
        };
        let mut psbt = match Psbt::parse(&bytes) {
            Ok(p) => p,
            Err(e) => return reply(req, RESULT_REFUSED, format!("not a PSBT maki can read: {}", e)),
        };
        let review = match wallet::review(&psbt, &account) {
            Ok(r) => r,
            Err(e) => return reply(req, RESULT_REFUSED, e.to_string()),
        };
        if review.outputs.len() > MAX_OUTPUTS {
            return reply(req, RESULT_REFUSED, format!("more than {} outputs to go through on maki's screen", MAX_OUTPUTS));
        }
        log::info!("PSBT: {} inputs, {} outputs, fee {}", review.inputs, review.outputs.len(), review.fee);
        drop(buffer);
        let (signed, busy) = (self.signed.clone(), self.busy.clone());
        busy.store(true, Ordering::SeqCst);
        std::thread::spawn(move || {
            let net = account.network;
            let pages = review
                .pages()
                .into_iter()
                .map(|p| Page { heading: p.heading, value: p.value, mono: p.mono })
                .collect();
            let spent = display::amount(review.spent(), net);
            let mut result = owner_says(|l| {
                l.review(display::network_name(net), "Sign and spend", &spent, pages, "sign", "reject", SIGN_TIMEOUT_S)
            });
            let mut total = 0;
            if result == RESULT_OK {
                match wallet::sign(&mut psbt, &account) {
                    Ok(n) => {
                        let out = psbt.serialize();
                        total = out.len() as u32;
                        *signed.lock().unwrap() = out;
                        log::info!("signed {} inputs", n);
                    }
                    Err(e) => {
                        log::error!("couldn't sign after review: {}", e);
                        result = RESULT_FAILED;
                    }
                }
            }
            busy.store(false, Ordering::SeqCst);
            if let Some(mem) = msg.body.memory_message_mut() {
                let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                if let Ok(mut req) = buffer.to_original::<Chunk, _>() {
                    req.data.clear();
                    req.result = result;
                    req.done = true;
                    req.total = total;
                    buffer.replace(req).ok();
                }
            }
        });
    }

    /// `KeysOp::BtcSigned`: a piece of the PSBT last signed.
    pub(crate) fn signed_piece(&self, msg: &mut xous::MessageEnvelope) {
        let Some(mem) = msg.body.memory_message_mut() else { return };
        let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
        let Ok(mut req) = buffer.to_original::<Chunk, _>() else { return };
        let signed = self.signed.lock().unwrap();
        req.data.clear();
        if signed.is_empty() {
            req.result = RESULT_FAILED;
        } else {
            let start = (req.offset as usize).min(signed.len());
            let end = (start + CHUNK).min(signed.len());
            req.data.extend_from_slice(&signed[start..end]);
            req.total = signed.len() as u32;
            req.result = RESULT_OK;
        }
        buffer.replace(req).ok();
    }
}
