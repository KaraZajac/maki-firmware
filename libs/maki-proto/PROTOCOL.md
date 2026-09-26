# maki serial protocol, version 1

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
COBS( version:u8  kind:u8  body:bytes  crc32:u32le )  0x00
```

- COBS removes every zero byte, so `0x00` only ever ends a frame, and a reader that starts
  mid-stream resynchronises at the next one.
- `crc32` is CRC-32/ISO-HDLC (zlib's) over `version`, `kind` and `body`.
- `version` is `1`. A frame with any other version is rejected.
- A decoded frame is at most 8192 bytes.

Every request gets exactly one reply. A reply's `kind` is the request's with the top bit set
(`0x01` → `0x81`), or `0x7f` for an error. The host sends one request at a time.

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
| `0x7f` ERROR (reply only) | | `code:u8` `detail:str8` |

`time_state`: 0 unset, 1 unverified, 2 verified.
TIME_PROOF `status`: 0 clock set, 1 too few verified answers, 2 answers disagree.
TIME_PROOF `answer`: 0 verified, 1 unknown server, 2 duplicate, 3 invalid, 4 too imprecise.
ERROR `code`: 1 malformed, 2 unknown kind, 3 no challenge, 4 challenge expired, 5 bad argument.

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
