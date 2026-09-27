//! The Ethereum account's keys, from the recovery phrase: the address shared with sites the
//! owner connects, messages (EIP-191) and transactions signed once the owner has read them on
//! screen. What's shown and checked is maki-eth's.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use maki_eth::{display, Account, Tx};
use maki_keys_api::*;
use maki_launcher::{Answer, Launcher, Page};
use xous_ipc::Buffer;
use zeroize::Zeroize;

const TIMEOUT_S: u32 = if option_env!("MAKI_DEMO").is_some() { 600 } else { 60 };
/// Time to read a transaction's pages, carefully.
const SIGN_TIMEOUT_S: u32 = if option_env!("MAKI_DEMO").is_some() { 600 } else { 300 };

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

fn page(p: display::Page) -> Page { Page { heading: p.heading, value: p.value, mono: p.mono } }

pub(crate) struct Eth {
    /// derived at first use while unlocked, by index
    accounts: Vec<Account>,
    incoming: Vec<u8>,
    incoming_total: u32,
    signed: Arc<Mutex<Vec<u8>>>,
    busy: Arc<AtomicBool>,
}

impl Eth {
    pub(crate) fn new() -> Self {
        Eth {
            accounts: Vec::new(),
            incoming: Vec::new(),
            incoming_total: 0,
            signed: Arc::new(Mutex::new(Vec::new())),
            busy: Arc::new(AtomicBool::new(false)),
        }
    }

    /// maki locked: the keys go until the PIN comes back.
    pub(crate) fn forget(&mut self) {
        self.accounts.clear();
        self.incoming.clear();
    }

    fn account(&mut self, seed: Option<[u8; 64]>, index: u32) -> Result<Account, u32> {
        if let Some(a) = self.accounts.iter().find(|a| a.index == index) {
            return Ok(a.clone());
        }
        let Some(mut seed) = seed else { return Err(RESULT_NO_PHRASE) };
        let account = Account::from_seed(&seed, index);
        seed.zeroize();
        let account = account.map_err(|_| RESULT_FAILED)?;
        self.accounts.push(account.clone());
        Ok(account)
    }

    /// `KeysOp::EthAccount`: the address, once the owner lets the site connect if asked to ask.
    pub(crate) fn share_account(&mut self, mut msg: xous::MessageEnvelope, seed: Option<[u8; 64]>) {
        let Some(mem) = msg.body.memory_message_mut() else { return };
        let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
        let Ok(mut req) = buffer.to_original::<EthRequest, _>() else { return };
        let account = match self.account(seed, req.index) {
            Ok(a) => a,
            Err(result) => {
                req.result = result;
                buffer.replace(req).ok();
                return;
            }
        };
        if !req.ask {
            req.result = RESULT_OK;
            req.address = account.address_string();
            buffer.replace(req).ok();
            return;
        }
        drop(buffer);
        std::thread::spawn(move || {
            let site = {
                let buffer = unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                buffer.to_original::<EthRequest, _>().map(|r| r.site).unwrap_or_default()
            };
            let which = if account.index == 0 { String::from("ethereum account") } else { format!("account #{}", account.index) };
            let result = owner_says(|l| l.ask(&site, "Connect wallet?", &which, &[], TIMEOUT_S));
            log::info!("ethereum account for {}: {}", site, result);
            if let Some(mem) = msg.body.memory_message_mut() {
                let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                if let Ok(mut req) = buffer.to_original::<EthRequest, _>() {
                    req.result = result;
                    if result == RESULT_OK {
                        req.address = account.address_string();
                    }
                    buffer.replace(req).ok();
                }
            }
        });
    }

    /// `KeysOp::EthMessage`: a message, signed once the owner has read it.
    pub(crate) fn sign_message(&mut self, mut msg: xous::MessageEnvelope, seed: Option<[u8; 64]>) {
        let Some(mem) = msg.body.memory_message_mut() else { return };
        let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
        let Ok(mut req) = buffer.to_original::<EthMessage, _>() else { return };
        let account = match self.account(seed, req.index) {
            Ok(a) => a,
            Err(result) => {
                req.result = result;
                req.message.clear();
                buffer.replace(req).ok();
                return;
            }
        };
        let (site, message) = (req.site.clone(), req.message.clone());
        drop(buffer);
        std::thread::spawn(move || {
            let pages = display::message_pages(&site, &message).into_iter().map(page).collect();
            let result = owner_says(|l| l.review(&site, "Sign message?", "not a transaction", pages, "sign", "reject", TIMEOUT_S));
            let signature = if result == RESULT_OK { account.sign_message(&message).ok() } else { None };
            log::info!("ethereum message for {}: {}", site, result);
            if let Some(mem) = msg.body.memory_message_mut() {
                let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                if let Ok(mut req) = buffer.to_original::<EthMessage, _>() {
                    req.message.clear();
                    req.result = if result == RESULT_OK && signature.is_none() { RESULT_FAILED } else { result };
                    req.signature = signature.map(|s| s.to_vec()).unwrap_or_default();
                    buffer.replace(req).ok();
                }
            }
        });
    }

    /// `KeysOp::EthSign`: a piece of a transaction. The last one is checked, shown, and signed
    /// if the owner says so.
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
            return reply(req, RESULT_FAILED, String::new());
        }
        if req.offset == 0 {
            self.incoming.clear();
            self.incoming_total = req.total;
        }
        let in_order = req.offset as usize == self.incoming.len()
            && req.total == self.incoming_total
            && req.total as usize <= MAX_TX
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
        let account = match self.account(seed(), req.index) {
            Ok(a) => a,
            Err(result) => return reply(req, result, String::new()),
        };
        let tx = match Tx::parse(&bytes) {
            Ok(t) => t,
            Err(e) => return reply(req, RESULT_REFUSED, e.to_string()),
        };
        let (pages, summary) = match display::review(&tx) {
            Ok(r) => r,
            Err(e) => return reply(req, RESULT_REFUSED, e.to_string()),
        };
        let site = req.site.clone();
        log::info!("ethereum transaction from {}: chain {}, {} bytes of data", site, tx.chain_id, tx.data.len());
        drop(buffer);
        let (signed, busy) = (self.signed.clone(), self.busy.clone());
        busy.store(true, Ordering::SeqCst);
        std::thread::spawn(move || {
            let pages = pages.into_iter().map(page).collect();
            let mut result = owner_says(|l| l.review(&site, "Sign and send", &summary, pages, "sign", "reject", SIGN_TIMEOUT_S));
            let mut total = 0;
            if result == RESULT_OK {
                match tx.sign(&account) {
                    Ok(out) => {
                        total = out.len() as u32;
                        *signed.lock().unwrap() = out;
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

    /// `KeysOp::EthSigned`: a piece of the transaction last signed.
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
