// Added for maki (a fork of Xous: github.com/KaraZajac/maki-firmware) in 2026, under its crate's license.
//! FIDO while maki is locked. OpenSK keeps its store in the secret basis, which the PIN opens:
//! until then nothing that reads it can run (the store would read, and even write, the system
//! basis instead). But a computer looking for an authenticator sends CTAPHID_INIT first, and
//! libfido2 (what systemd-cryptsetup unlocks disks with at boot, while maki waits for its PIN)
//! takes a device that doesn't answer it for one that isn't there, and waits for another to be
//! plugged in. So while maki is locked it answers what reads no store: INIT, numbering channels as
//! OpenSK numbers them (from 1, one more each time) so they stay good once it runs; PING and WINK.
//! A request that needs the store (CBOR: GetInfo, GetAssertion) is held, the computer told every
//! tenth of a second that maki waits for its owner (CTAPHID_KEEPALIVE, UP needed), until the PIN
//! opens maki: then OpenSK answers it as if it had just come. If the computer cancels, or nobody
//! unlocks maki within `HOLD`, it's answered with the error CTAP gives for each.

use std::time::{Duration, Instant};

use vault2::ctap::hid::{ChannelID, CtapHid, HidPacket, KeepaliveStatus};

/// How long a request waits for maki's PIN: time to see maki, take it in hand and enter it.
pub const HOLD: Duration = Duration::from_secs(120);
/// How long the computer has between a message's packets (OpenSK's `TIMEOUT_DURATION`, as maki
/// has it).
const PACKET_GAP: Duration = Duration::from_millis(500);
/// The computer hears from maki this often while a request waits.
const KEEPALIVE_EVERY: Duration = Duration::from_millis(100);

const BROADCAST: ChannelID = [0xff; 4];
const INIT_BIT: u8 = 0x80;
// CTAPHID commands (CTAP 2.1, 11.2.9), without the packet's init bit
const PING: u8 = 0x01;
const MSG: u8 = 0x03;
const INIT: u8 = 0x06;
const WINK: u8 = 0x08;
const CBOR: u8 = 0x10;
const CANCEL: u8 = 0x11;
const ERROR: u8 = 0x3f;
// CTAPHID error codes
const ERR_INVALID_CMD: u8 = 0x01;
const ERR_INVALID_LEN: u8 = 0x03;
const ERR_INVALID_SEQ: u8 = 0x04;
const ERR_MSG_TIMEOUT: u8 = 0x05;
const ERR_CHANNEL_BUSY: u8 = 0x06;
const ERR_INVALID_CHANNEL: u8 = 0x0b;
// CTAP2 status codes, a CBOR response's only byte
const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2d;
const CTAP2_ERR_USER_ACTION_TIMEOUT: u8 = 0x2f;

/// What a packet starts, from its header: an init packet's channel, command and length, or a
/// continuation packet's channel.
pub enum Packet {
    Init { cid: ChannelID, cmd: u8, len: usize },
    Continuation { cid: ChannelID },
}

pub fn read(p: &HidPacket) -> Packet {
    let cid = [p[0], p[1], p[2], p[3]];
    if p[4] & INIT_BIT != 0 {
        Packet::Init { cid, cmd: p[4] & !INIT_BIT, len: (p[5] as usize) << 8 | p[6] as usize }
    } else {
        Packet::Continuation { cid }
    }
}

/// Whether a packet starts a request OpenSK would need its store for: CBOR (and MSG, which
/// maki refuses anyway, but only once it can say so as OpenSK does).
pub fn needs_store(p: &HidPacket) -> bool { matches!(read(p), Packet::Init { cmd: CBOR | MSG, .. }) }

/// One packet of a message to the computer: the message's first, or (with `seq`) a later one.
fn packet(cid: ChannelID, cmd: u8, payload: &[u8]) -> HidPacket {
    let mut p = [0u8; 64];
    p[..4].copy_from_slice(&cid);
    p[4] = cmd | INIT_BIT;
    p[5] = (payload.len() >> 8) as u8;
    p[6] = payload.len() as u8;
    p[7..7 + payload.len()].copy_from_slice(payload);
    p
}

pub fn error(cid: ChannelID, code: u8) -> HidPacket { packet(cid, ERROR, &[code]) }

/// A CBOR response of a CTAP2 status alone.
pub fn cbor_status(cid: ChannelID, status: u8) -> HidPacket { packet(cid, CBOR, &[status]) }

/// The packets of a keepalive saying maki waits for its owner.
fn keepalive(cid: ChannelID) -> Vec<HidPacket> {
    CtapHid::keepalive(cid, KeepaliveStatus::UpNeeded).collect()
}

/// Answers what reads no store, for the time before OpenSK runs (it answers these itself after):
/// INIT, as OpenSK would, PING (one packet's worth: libfido2 pings with less), WINK and CANCEL
/// (nothing to cancel: no answer). Anything else on a channel that isn't open is refused as OpenSK
/// refuses it. `opened` counts the channels handed out.
pub fn answer_before_opensk(p: &HidPacket, opened: &mut u32) -> Vec<HidPacket> {
    let is_open = |cid: ChannelID| {
        let n = u32::from_be_bytes(cid);
        n != 0 && n <= *opened
    };
    match read(p) {
        Packet::Init { cid, cmd: INIT, len } => {
            if len != 8 {
                return vec![error(cid, ERR_INVALID_LEN)];
            }
            let channel = if cid == BROADCAST {
                *opened += 1;
                opened.to_be_bytes()
            } else if is_open(cid) {
                cid
            } else {
                return vec![error(cid, ERR_INVALID_CHANNEL)];
            };
            // the nonce back, the channel, the CTAPHID protocol (2), the device's version as
            // OpenSK gives it (1.0.0), and its capabilities: WINK, CBOR, and NMSG (maki answers no
            // U2F message)
            let mut payload = [0u8; 17];
            payload[..8].copy_from_slice(&p[7..15]);
            payload[8..12].copy_from_slice(&channel);
            payload[12] = 2;
            payload[13] = 1;
            payload[16] = CtapHid::CAPABILITY_WINK | CtapHid::CAPABILITY_CBOR | CtapHid::CAPABILITY_NMSG;
            vec![packet(cid, INIT, &payload)]
        }
        Packet::Init { cid, .. } | Packet::Continuation { cid } if !is_open(cid) => {
            vec![error(cid, ERR_INVALID_CHANNEL)]
        }
        Packet::Init { cid, cmd: PING, len } if len <= 57 => vec![packet(cid, PING, &p[7..7 + len])],
        Packet::Init { cid, cmd: WINK, len: 0 } => vec![packet(cid, WINK, &[])],
        Packet::Init { cmd: CANCEL, .. } | Packet::Continuation { .. } => Vec::new(),
        Packet::Init { cid, .. } => vec![error(cid, ERR_INVALID_CMD)],
    }
}

/// The source of packets and where answers go: maki's FIDO endpoint, or a test's.
pub trait Hid {
    /// The next packet, or None if none came in `wait`.
    fn recv(&mut self, wait: Duration) -> Option<HidPacket>;
    fn send(&mut self, p: &HidPacket);
}

/// The rest of a message whose first packet is `first`: every packet of it, or None if the
/// computer didn't send them in time or in order (it has been told so), or started something
/// else on the channel (answered by `other`, as `hold` answers it). Packets for other channels
/// meanwhile are told the channel is busy, as OpenSK tells them.
pub fn collect(
    hid: &mut impl Hid,
    first: HidPacket,
    mut other: impl FnMut(&HidPacket) -> Vec<HidPacket>,
) -> Option<Vec<HidPacket>> {
    let mut first = first;
    'message: loop {
        let Packet::Init { cid, len, .. } = read(&first) else { return None };
        let more = len.saturating_sub(57).div_ceil(59);
        let mut packets = vec![first];
        let mut seq = 0u8;
        let mut deadline = Instant::now() + PACKET_GAP;
        while packets.len() <= more {
            let Some(p) = hid.recv(deadline.saturating_duration_since(Instant::now())) else {
                hid.send(&error(cid, ERR_MSG_TIMEOUT));
                return None;
            };
            match read(&p) {
                Packet::Init { cid: c, .. } | Packet::Continuation { cid: c } if c != cid => {
                    hid.send(&error(c, ERR_CHANNEL_BUSY))
                }
                Packet::Continuation { .. } if p[4] != seq => {
                    hid.send(&error(cid, ERR_INVALID_SEQ));
                    return None;
                }
                Packet::Continuation { .. } => {
                    seq += 1;
                    packets.push(p);
                    deadline = Instant::now() + PACKET_GAP;
                }
                // the computer started over on the channel: another request, collected instead
                Packet::Init { .. } if needs_store(&p) => {
                    first = p;
                    continue 'message;
                }
                // or something else (a resync, a ping): answered, and the request forgotten
                Packet::Init { .. } => {
                    for r in other(&p) {
                        hid.send(&r);
                    }
                    return None;
                }
            }
        }
        return Some(packets);
    }
}

/// How a held request ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Held {
    /// maki is open: answer it
    Unlocked,
    /// the computer cancelled it (it's been told)
    Cancelled,
    /// nobody unlocked maki in time (the computer's been told)
    TimedOut,
}

/// Holds the request on `cid` until `unlocked` says maki is open, keeping the computer waiting
/// with keepalives, for `HOLD` at most. Packets for other channels meanwhile go to `other`
/// (INIT, before OpenSK runs; OpenSK itself, after), save a request, which is told the channel
/// is busy: one request waits at a time.
pub fn hold(
    hid: &mut impl Hid,
    cid: ChannelID,
    mut unlocked: impl FnMut() -> bool,
    mut other: impl FnMut(&HidPacket) -> Vec<HidPacket>,
    limit: Duration,
) -> Held {
    let end = Instant::now() + limit;
    loop {
        if unlocked() {
            return Held::Unlocked;
        }
        if Instant::now() >= end {
            hid.send(&cbor_status(cid, CTAP2_ERR_USER_ACTION_TIMEOUT));
            return Held::TimedOut;
        }
        for k in keepalive(cid) {
            hid.send(&k);
        }
        let wait_until = Instant::now() + KEEPALIVE_EVERY;
        while let Some(p) = hid.recv(wait_until.saturating_duration_since(Instant::now())) {
            match read(&p) {
                Packet::Init { cid: c, cmd: CANCEL, .. } if c == cid => {
                    hid.send(&cbor_status(cid, CTAP2_ERR_KEEPALIVE_CANCEL));
                    return Held::Cancelled;
                }
                // the computer gave up on it and started again on the same channel: nothing
                // waits now, and what it sent is answered as the next request when maki opens
                Packet::Init { cid: c, cmd: INIT, .. } if c == cid => {
                    for r in other(&p) {
                        hid.send(&r);
                    }
                    return Held::Cancelled;
                }
                Packet::Init { cid: c, .. } | Packet::Continuation { cid: c } if c == cid => {}
                _ if needs_store(&p) => {
                    if let Packet::Init { cid: c, .. } = read(&p) {
                        hid.send(&error(c, ERR_CHANNEL_BUSY));
                    }
                }
                _ => {
                    for r in other(&p) {
                        hid.send(&r);
                    }
                }
            }
        }
    }
}

/// The packets of an INIT on the broadcast channel, which opens the next channel: fed to OpenSK
/// once it runs, as many times as channels were opened before it, so it opens the next one after.
pub fn broadcast_init() -> HidPacket { packet(BROADCAST, INIT, &[0; 8]) }

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    struct Fake {
        incoming: VecDeque<HidPacket>,
        sent: Vec<HidPacket>,
    }

    impl Hid for Fake {
        fn recv(&mut self, _: Duration) -> Option<HidPacket> { self.incoming.pop_front() }

        fn send(&mut self, p: &HidPacket) { self.sent.push(*p) }
    }

    fn fake(incoming: Vec<HidPacket>) -> Fake { Fake { incoming: incoming.into(), sent: Vec::new() } }

    fn init_on(cid: ChannelID, nonce: [u8; 8]) -> HidPacket { packet(cid, INIT, &nonce) }

    /// A request's packets as the computer sends them: `len` bytes of payload.
    fn request(cid: ChannelID, len: usize) -> Vec<HidPacket> {
        let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let mut out = vec![{
            let mut p = packet(cid, CBOR, &[]);
            p[5] = (len >> 8) as u8;
            p[6] = len as u8;
            let n = len.min(57);
            p[7..7 + n].copy_from_slice(&payload[..n]);
            p
        }];
        for (seq, chunk) in payload[len.min(57)..].chunks(59).enumerate() {
            let mut p = [0u8; 64];
            p[..4].copy_from_slice(&cid);
            p[4] = seq as u8;
            p[5..5 + chunk.len()].copy_from_slice(chunk);
            out.push(p);
        }
        out
    }

    #[test]
    fn init_opens_channels_as_opensk_numbers_them() {
        let mut opened = 0;
        for want in 1..=3u32 {
            let r = answer_before_opensk(&init_on(BROADCAST, [want as u8; 8]), &mut opened);
            assert_eq!(r.len(), 1);
            let p = r[0];
            assert_eq!((&p[..4], p[4], p[6]), (&BROADCAST[..], INIT | INIT_BIT, 17));
            assert_eq!(&p[7..15], &[want as u8; 8], "the nonce back");
            assert_eq!(&p[15..19], &want.to_be_bytes());
            assert_eq!(&p[19..24], &[2, 1, 0, 0, 0x0d]);
        }
        // and OpenSK's own, fed as many broadcast INITs, opens the same: see OpenSK's
        // `allocated_cids`, which these mirror
        assert_eq!(opened, 3);
        // an INIT on an open channel keeps it; on one never opened, refused
        assert_eq!(
            &answer_before_opensk(&init_on([0, 0, 0, 2], [9; 8]), &mut opened)[0][15..19],
            &[0, 0, 0, 2]
        );
        assert_eq!(
            answer_before_opensk(&init_on([0, 0, 0, 9], [9; 8]), &mut opened)[0][4..8],
            [ERROR | INIT_BIT, 0, 1, ERR_INVALID_CHANNEL]
        );
        assert_eq!(opened, 3);
    }

    #[test]
    fn ping_wink_and_cancel_before_opensk() {
        let mut opened = 1;
        let cid = [0, 0, 0, 1];
        let ping = packet(cid, PING, b"hello");
        assert_eq!(answer_before_opensk(&ping, &mut opened), [ping]);
        assert_eq!(answer_before_opensk(&packet(cid, WINK, &[]), &mut opened), [packet(cid, WINK, &[])]);
        assert!(answer_before_opensk(&packet(cid, CANCEL, &[]), &mut opened).is_empty());
        // a channel never opened
        assert_eq!(answer_before_opensk(&ping, &mut 0)[0][7], ERR_INVALID_CHANNEL);
        assert!(needs_store(&request(cid, 10)[0]) && !needs_store(&ping));
    }

    #[test]
    fn a_request_is_collected_whole_and_others_told_to_wait() {
        let cid = [0, 0, 0, 1];
        let packets = request(cid, 200);
        assert_eq!(packets.len(), 4);
        // another channel's packet in the middle: told it's busy
        let mut incoming = packets[1..].to_vec();
        incoming.insert(1, init_on([0, 0, 0, 2], [0; 8]));
        let mut h = fake(incoming);
        assert_eq!(collect(&mut h, packets[0], |_| Vec::new()), Some(packets.clone()));
        assert_eq!(h.sent.len(), 1);
        assert_eq!((&h.sent[0][..4], h.sent[0][7]), (&[0, 0, 0, 2][..], ERR_CHANNEL_BUSY));
        // cut short: a timeout; out of order: a bad sequence
        let mut h = fake(packets[1..2].to_vec());
        assert_eq!(collect(&mut h, packets[0], |_| Vec::new()), None);
        assert_eq!(h.sent[0][7], ERR_MSG_TIMEOUT);
        let mut h = fake(vec![packets[2]]);
        assert_eq!(collect(&mut h, packets[0], |_| Vec::new()), None);
        assert_eq!(h.sent[0][7], ERR_INVALID_SEQ);
        // one packet's worth needs no more
        let short = request(cid, 30);
        assert_eq!(collect(&mut fake(vec![]), short[0], |_| Vec::new()), Some(short));
        // a resync on the channel: answered by `other`, and the request forgotten
        let mut answered = 0;
        let mut h = fake(vec![init_on(cid, [1; 8])]);
        assert_eq!(
            collect(&mut h, packets[0], |_| {
                answered += 1;
                Vec::new()
            }),
            None
        );
        assert_eq!(answered, 1);
        // another request on the channel instead: that one's collected
        let next = request(cid, 20);
        assert_eq!(collect(&mut fake(vec![next[0]]), packets[0], |_| Vec::new()), Some(next));
    }

    #[test]
    fn a_held_request_keeps_the_computer_waiting_until_maki_opens() {
        let cid = [0, 0, 0, 1];
        let mut checks = 0;
        let mut h = fake(vec![]);
        let held = hold(
            &mut h,
            cid,
            || {
                checks += 1;
                checks > 3
            },
            |_| Vec::new(),
            HOLD,
        );
        assert_eq!(held, Held::Unlocked);
        // a keepalive each time it looked and maki wasn't open: UP needed
        assert_eq!(h.sent.len(), 3);
        assert!(h.sent.iter().all(|p| p[..4] == cid && p[4] == 0xbb && p[6] == 1 && p[7] == 2));
    }

    #[test]
    fn a_held_request_is_cancelled_or_times_out_as_ctap_says() {
        let cid = [0, 0, 0, 1];
        let mut h =
            fake(vec![init_on([0, 0, 0, 2], [0; 8]), request([0, 0, 0, 2], 10)[0], packet(cid, CANCEL, &[])]);
        let mut others = Vec::new();
        let held = hold(
            &mut h,
            cid,
            || false,
            |p| {
                others.push(*p);
                Vec::new()
            },
            HOLD,
        );
        assert_eq!(held, Held::Cancelled);
        // the other channel's INIT went to `other`; its request was told the channel is busy
        assert_eq!(others.len(), 1);
        let last = h.sent.last().unwrap();
        assert_eq!(
            (&last[..4], last[4], last[6], last[7]),
            (&cid[..], CBOR | INIT_BIT, 1, CTAP2_ERR_KEEPALIVE_CANCEL)
        );
        assert!(h.sent.iter().any(|p| p[..4] == [0, 0, 0, 2] && p[7] == ERR_CHANNEL_BUSY));
        // nobody unlocks maki
        let mut h = fake(vec![]);
        assert_eq!(hold(&mut h, cid, || false, |_| Vec::new(), Duration::ZERO), Held::TimedOut);
        assert_eq!(h.sent.last().unwrap()[7], CTAP2_ERR_USER_ACTION_TIMEOUT);
    }
}
