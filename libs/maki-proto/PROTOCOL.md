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
| `0x20` BACKUP_GET | `offset:u32` | `status:u8` `total:u32` `offset:u32` `piece:bytes16` |
| `0x21` BACKUP_PUT | `total:u32` `offset:u32` `piece:bytes16` | `done:u8` `approval:u8` `logins:u16` `codes:u16` `passkeys:u16` |
| `0x30` BTC_ACCOUNT | `network:u8` | `approval:u8` `zpub:str8` `descriptor:str8` |
| `0x31` BTC_ADDRESS | `network:u8` `change:u8` `index:u32` | `approval:u8` `address:str8` |
| `0x32` BTC_SIGN | `network:u8` `total:u32` `offset:u32` `piece:bytes16` | `done:u8` `approval:u8` `signed:u32` `reason:str8` |
| `0x33` BTC_SIGNED | `offset:u32` | `status:u8` `total:u32` `offset:u32` `piece:bytes16` |
| `0x40` ETH_ACCOUNT | `site:str8` `index:u32` | `approval:u8` `address:str8` |
| `0x41` ETH_SIGN_TX | `site:str8` `index:u32` `total:u32` `offset:u32` `piece:bytes16` | `done:u8` `approval:u8` `signed:u32` `reason:str8` |
| `0x42` ETH_SIGNED | `offset:u32` | `status:u8` `total:u32` `offset:u32` `piece:bytes16` |
| `0x43` ETH_SIGN_MESSAGE | `site:str8` `index:u32` `message:bytes16` | `approval:u8` `signature:bytes16` |
| `0x7f` ERROR (reply only) | | `code:u8` `detail:str8` |

`time_state`: 0 unset, 1 unverified, 2 verified.
TIME_PROOF `status`: 0 clock set, 1 too few verified answers, 2 answers disagree.
TIME_PROOF `answer`: 0 verified, 1 unknown server, 2 duplicate, 3 invalid, 4 too imprecise.
ERROR `code`: 1 malformed, 2 unknown kind, 3 no challenge, 4 challenge expired, 5 bad argument.
`approval`: 0 approved, 1 denied, 2 nothing saved for the site (the owner wasn't asked), 3 timed
out, 4 vault unavailable (or busy: at most three requests wait for the owner at once), 5 clock
not verified (GET_TOTP only), 6 locked (maki is waiting for its PIN), 7 not yours (a backup
this maki's recovery phrase can't open), 8 no phrase (no recovery phrase yet), 9 refused (a PSBT
maki won't sign; the reply says why). Only an approved reply carries a username, password, code,
backup piece, account or signed PSBT.
`network`: 0 bitcoin, 1 the test networks (testnet and signet share keys and addresses).

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
after. The screen offers one answer at a time and the **centre** button gives it: "allow" comes
first, and **left** or **right** moves to "deny". Nothing but the centre answers, so a bumped
side button can't. The question gives up after 30 s. When there's more than one answer (two
logins for a site), left and right go through them, then "cancel", and the centre picks.

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

## Backups

maki's logins, codes and passkeys (its resident FIDO credentials, and the signature counter),
sealed by maki with AES-256-GCM-SIV under a key derived from its recovery phrase (HKDF over the
BIP39 seed), so the host keeps them without being able to read them, and a maki restored from
the phrase can open them. The passkeys' keys and the credential IDs maki gave sites come from
the phrase too, so the phrase and a backup are all a new maki needs.

- **BACKUP_GET** hands the backup out in pieces of up to 4096 bytes. Offset 0 seals a fresh one
  (reading the vault and deriving the key takes maki a moment); the host asks for further
  offsets until it has `total` bytes. `status` is `0` with a piece, or `6` locked or `8` no
  phrase with none.
- **BACKUP_PUT** sends one back in pieces of up to 4096 bytes, in order, with the same `total`
  each time (at most 512 KiB). A piece before the last is answered `done` = 0 at once. The last
  is answered once maki has opened the backup and asked the owner (what it would add: logins,
  codes, passkeys): `done` = 1, then the approval and what was added. maki only adds records it
  doesn't have (passkeys are matched by credential ID); what it has, it keeps. A signature
  counter higher than maki's is taken, so sites never see it go back. A backup maki can't open
  is `7` not yours, and nothing is asked. If there's nothing new, nothing is asked either:
  approved, with nothing added.

## Bitcoin

maki keeps one Bitcoin account, the standard native SegWit one (BIP84, `m/84'/0'/0'`, or
`m/84'/1'/0'` on the test networks), derived from its recovery phrase, so the same phrase works in
Sparrow, Electrum and the rest. Wallet software keeps track of coins and builds transactions;
maki only ever shows and signs.

- **BTC_ACCOUNT** hands out the account's public key, once the owner agrees on maki ("Share
  account? view only"): `zpub` (`vpub` on the test networks) and an output descriptor with the
  master key's fingerprint and both chains, e.g.
  `wpkh([73c5da0a/84h/0h/0h]xpub…/<0;1>/*)#qf45pmyh`, which Sparrow and Bitcoin Core import
  as a watch-only wallet that knows maki signs for it. It reveals every address, so it is asked
  for, but it can't spend.
- **BTC_ADDRESS** puts an address on maki's screen, the whole of it, for the owner to compare
  with what the computer shows: `approval` is 0 if they said it matches and 1 if it doesn't
  (then the computer's copy isn't to be trusted). `address` is maki's, either way.
- **BTC_SIGN** sends a PSBT (BIP174, version 0) in pieces of up to 4096 bytes, in order, with
  the same `total` each time (at most 512 KiB). A piece before the last is answered `done` = 0
  at once. The last is answered once the owner decides: `done` = 1, `approval` 0 with the
  signed PSBT's size in `signed`, 1 rejected, 3 timed out, or 9 refused with `reason`.
- **BTC_SIGNED** hands the signed PSBT out in pieces: everything that came in, plus a partial
  signature for each input. Finalizing and broadcasting are the wallet software's.

What maki checks before it asks, refusing (`9`, with the reason) rather than asking about a
transaction it can't vouch for:

- **Every input is this wallet's**: its BIP32 derivation names this maki's fingerprint and a
  path on the account's receiving or change chain, the key derived there is the one named, and
  the coin it spends pays to that key.
- **Every input comes with the whole transaction it spends** (`non_witness_utxo`), which must
  hash to the input's outpoint. Amounts are taken from there, never from the computer's word
  alone: with SegWit, the computer could otherwise lie about one input's amount per signing
  and have the difference paid out as fee (the 2020 fee attack).
- **Only SIGHASH_ALL** is signed, and no taproot inputs yet.
- **The fee is what the inputs hold minus what the outputs pay**, never negative, and no
  amount is beyond 21 million bitcoin.
- At most 64 outputs, each of which the owner sees.

The owner then goes through the transaction with left and right, the centre moving on: every
payment with its amount and full address, the change coming back (an output counts as change
only if it derives from this wallet's change chain; anything else is shown as a payment), and
the fee with its rate (called out when over a tenth of what's sent). Last come "sign" and
"reject". Signatures are deterministic (RFC 6979) and low-S.

## Ethereum

maki keeps an Ethereum account from the same recovery phrase, the standard way
(`m/44'/60'/0'/0/index`, BIP44, as MetaMask and Ledger make it; `index` 0 is the first account).
Requests come from sites, through the browser extension's EIP-1193 provider, and carry the site
(a hostname, checked like GET_LOGIN's) that maki shows the owner.

- **ETH_ACCOUNT** hands the site the account's address (EIP-55), once the owner lets it connect
  ("Connect wallet?"). maki desktop remembers which sites are connected; a site that isn't sees
  no account.
- **ETH_SIGN_MESSAGE** signs a message (EIP-191 `personal_sign`, at most 4096 bytes) once the
  owner has read it on maki: as text, or in hex if it isn't text. A Sign-In with Ethereum message
  (EIP-4361) that names another site than the one asking gets a "Wrong site!" page first: that's
  how a phishing site uses a real site's sign-in. The signature is r, s, v (65
  bytes, v 27 or 28). The prefix EIP-191 adds means a message can never pass for a transaction.
- **ETH_SIGN_TX** sends an unsigned transaction in pieces of up to 4096 bytes, in order, with the
  same `total` each time (at most 128 KiB): EIP-1559 (`0x02 || rlp([...])`) or legacy EIP-155
  (`rlp([nonce, gas price, gas, to, value, data, chain ID, 0, 0])`). The last piece is answered
  once the owner decides: approved with the signed transaction's size, to fetch with
  **ETH_SIGNED** (ready for `eth_sendRawTransaction`), 1 rejected, 3 timed out, or 9 refused
  with `reason`.

What maki checks and shows:

- **The bytes it signs are the bytes it shows.** The transaction is parsed strictly (one
  encoding per value: shortest lengths, no leading zeros, no bytes after the end), and the hash
  signed is of exactly what came.
- **A chain ID is required**: legacy transactions without one (before EIP-155) could be replayed
  on every network, and are refused, as are EIP-2930 and blob transactions for now.
- The owner goes through the network (named when maki knows it, else its chain ID), what's sent
  and to whom (full EIP-55 address), and the most the fee can be (gas limit times the fee cap),
  then "sign" or "reject". Contract calls maki can read are spelled out: ERC-20 `transfer` (the
  recipient, and the amount in the token's smallest units, since maki can't know its decimals),
  ERC-20 `approve` (the spender, and "any amount" for an unlimited approval) and ERC-721/1155
  `setApprovalForAll` (the operator gets every item). Any other call is shown as a contract
  call maki can't read, with its function selector and length.
- Typed data (EIP-712) isn't signed yet: maki couldn't show what it means. `eth_sign` never will
  be: it signs anything, a transaction included.
