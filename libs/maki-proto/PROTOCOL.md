# maki serial protocol, version 2

How the desktop app talks to maki. The badge side is `libs/maki-proto` (framing, messages,
logic) and `services/maki-link` (USB glue); `examples/fake_maki.rs` runs the same logic on a
TCP socket for development. Change this document and the code together.

## Transport

The badge's USB CDC-ACM serial interface: VID `1d50`, PID `6198`, product name **`maki`**.
A stock DC34 badge shares the VID/PID but calls itself `Baosec-lite`, so a host must not treat
the IDs alone as proof: a device is maki once it answers HELLO. (HELLO contains no line ending,
so probing a stock badge can't run anything on its serial console.) The baud rate is
irrelevant. For development, the same byte stream over TCP to `fake_maki` (default
`127.0.0.1:7878`).

## Link

While connected, the host sends at least one request every 10 s; STATUS makes a good
heartbeat. maki counts itself linked from the first valid frame and unlinked after 25 s of
silence, and shows the link on its home screen, so each end knows about the other without
extra messages.

## Frames

```
COBS( version:u8  kind:u8  id:u16le  body:bytes  crc32:u32le )  0x00
```

- COBS removes every zero byte, so `0x00` only ever ends a frame, and a reader that starts
  mid-stream resynchronises at the next one.
- `crc32` is CRC-32/ISO-HDLC (zlib's) over `version`, `kind`, `id` and `body`.
- `version` is `2`. A frame with any other version is rejected.
- `id` is chosen by the host and echoed in the reply.
- A decoded frame is at most 8192 bytes.

Every request gets exactly one reply, carrying the request's `id`. A reply's `kind` is the
request's with the top bit set (`0x01` → `0x81`), or `0x7f` for an error. Replies can arrive in
any order: requests that wait for the owner (below) are answered when they answer, while
heartbeats and time sync carry on. A reply whose `id` the host no longer waits for (it gave up)
is dropped.

## Body encoding

Little-endian integers; `str8` is a `u8` length then UTF-8; `bytes16` is a `u16` length then
bytes. Bodies must be consumed exactly: trailing bytes are an error.

## Messages

| Kind | Request body | Reply body |
|---|---|---|
| `0x01` HELLO | — | `protocol:u8` `name:str8` `version:str8` |
| `0x02` STATUS | — | `time_state:u8` `utc_ms:u64` (0 if unset) `tz_offset_s:i32` |
| `0x03` TIME_CHALLENGE | — | `count:u8`, then `count` × (`id:u8` `host:str8` `port:u16` `request:bytes16`) |
| `0x04` TIME_PROOF | `tz_offset_s:i32` `count:u8`, then `count` × (`id:u8` `response:bytes16`) | `status:u8` `verified:u8` `utc_ms:u64`, then `count:u8` × (`id:u8` `answer:u8`) |
| `0x05` TIME_UNVERIFIED | `utc_ms:u64` `tz_offset_s:i32` | `refused:u8` (0 set, 1 refused) |
| `0x10` GET_LOGIN | `site:str8` | `approval:u8` `username:str8` `password:str8` |
| `0x11` GET_TOTP | `site:str8` | `approval:u8` `code:str8` `valid_for_s:u8` |
| `0x12` SAVE_LOGIN | `site:str8` `username:str8` `password:str8` | `approval:u8` |
| `0x7f` ERROR (reply only) | | `code:u8` `detail:str8` |

`time_state`: 0 unset, 1 unverified, 2 verified.
TIME_PROOF `status`: 0 clock set, 1 too few verified answers, 2 answers disagree.
TIME_PROOF `answer`: 0 verified, 1 unknown server, 2 duplicate, 3 invalid, 4 too imprecise.
ERROR `code`: 1 malformed, 2 unknown kind, 3 no challenge, 4 challenge expired, 5 bad argument.
`approval`: 0 approved, 1 denied, 2 nothing saved for the site (the owner wasn't asked), 3 timed
out, 4 vault unavailable (or busy: at most three requests wait for the owner at once), 5 clock
not verified (GET_TOTP only). Only an approved reply carries a username, password or code.

## Setting the time

1. The host sends **TIME_CHALLENGE**. maki draws a fresh 32-byte nonce per pinned server from
   its TRNG, builds a complete 1024-byte Roughtime request (draft-ietf-ntp-roughtime-19, wire
   version `0x8000000c`), remembers it, and returns each with the server's address.
2. The host sends each `request` **unmodified** as a UDP datagram to `host:port` and collects
   the answers.
3. The host sends **TIME_PROOF** with the answers and the local timezone offset. maki verifies
   each answer against the request it built and the server key *it* pins: the delegation and
   response signatures, the nonce, the protocol version, the delegation window, and the Merkle
   proof over the exact request bytes.
4. With at least **two** verified answers that agree (their spread within the largest radius
   plus the round trip plus 2 s), maki sets its clock to their median midpoint plus half the
   round trip, and reports `Verified`.

Rules that make this safe against a host that lies:

- Server keys live in the firmware. The host carries packets and can't choose whom to trust.
- The request, nonce included, is built by maki, and a server's answer commits to the whole
  packet. An answer to anyone else's request fails the Merkle proof.
- A challenge is good for one proof, within 30 s. A new challenge replaces the old one.
- One server alone can't set the clock, answers claiming more than 10 s of error are ignored,
  and the same server counted twice counts once.
- **TIME_UNVERIFIED** (the host's own clock, for when Roughtime is unreachable) is accepted only
  while the clock isn't already verified, and is shown on the badge with a `?` after the time.

The timezone offset is always the host's word: it only affects what the clock displays.

## Logins and codes

GET_LOGIN, GET_TOTP and SAVE_LOGIN go to the vault, which asks the owner on maki's screen: the
launcher shows the site and the question over whatever is in front, and gives the screen back
after. **Press** (select, or the centre of the pad) allows; nothing else does, so a bumped
key can't. **Left** (or down, on a plain question) refuses, and the question gives up after
30 s. When there's more than one answer (two logins for a site), **up** and **down** go
through them and pressing picks one.

- **`site` is what maki displays**, so it must be a lowercase ASCII hostname: letters, digits,
  dots, hyphens. Anything else is refused with `bad argument`. International domains travel as
  punycode (`xn--…`) and are shown that way, so look-alike Unicode can't pass for another site.
  The browser extension takes it from the tab's URL, which the page can't forge.
- **An entry covers its own host and its subdomains**: one saved for `github.com` serves
  `gist.github.com`, never `evilgithub.com`. Saved entries may hold a URL; maki compares the
  hostname without `www.`.
- **Nothing saved means no prompt**: maki answers `2` at once rather than asking the owner about a
  site it has nothing for. An entry that doesn't name a host with a dot ("GitHub", "bank")
  covers nothing, rather than whole top-level domains.
- **Codes need a verified clock.** GET_TOTP is answered `5` at once unless Roughtime set the
  clock: a host that could set the time with TIME_UNVERIFIED could otherwise collect codes for
  times still to come.
- **Which code is for which site is the owner's call.** TOTP entries (from a QR code) don't name
  a website. The first time a site asks, maki lists the entries, the likeliest first, and the
  one picked remembers that site; after that the site gets a plain yes-or-no.
- **SAVE_LOGIN** needs a username and a password, with no control characters: the vault keeps
  records as lines of text, and the owner reads them on screen. The same login already kept is
  approved without asking. A new password for a username maki has asks "Update password?", and
  keeps the old one in the entry's notes unless those hold something of the owner's.
- **What this protects.** Nothing leaves maki without a press on a screen naming the site, so
  software on the computer can't quietly empty the vault. Once approved, a password or code is on
  the computer, and maki can't prove the site is the one the request claims. Passkeys, which never
  leave maki and are bound to the site by the browser, are the stronger choice where offered.
