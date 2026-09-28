# maki serial protocol, version 3

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
- `version` is `3`. A frame with any other version is rejected. (Version 2 had messages for
  Bitcoin and Ethereum, kinds `0x30`–`0x44`; the wallets are apps now, below.)
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
| `0x50` APP_LIST | `index:u32` | `status:u8` `count:u32` `present:u8`, then if present: `id:str8` `name:str8` `version:u32` `label:str8` `developer:bytes16` `from_store:u8` `backup:u8` `used:u32` `icon:bytes16` `bundle:u32` `storage:u32` |
| `0x51` APP_INSTALL | `total:u32` `offset:u32` `piece:bytes16` | `done:u8` `approval:u8` `reason:str8` |
| `0x52` APP_REMOVE | `id:str8` | `approval:u8` |
| `0x53` APP_MESSAGE | `id:str8` `message:bytes16` | `status:u8` `answer:bytes16` |
| `0x54` STORE_UPDATE | `total:u32` `offset:u32` `piece:bytes16` | `done:u8` `status:u8` `root:u32` `revocations:u32` `revocations_expires:u64` `reason:str8` |
| `0x55` APP_SPACE | | `status:u8` `apps:u32` `max_apps:u32` `space:u32` `taken:u32` |
| `0x7f` ERROR (reply only) | | `code:u8` `detail:str8` |

`time_state`: 0 unset, 1 unverified, 2 verified.
TIME_PROOF `status`: 0 clock set, 1 too few verified answers, 2 answers disagree.
TIME_PROOF `answer`: 0 verified, 1 unknown server, 2 duplicate, 3 invalid, 4 too imprecise.
ERROR `code`: 1 malformed, 2 unknown kind, 3 no challenge, 4 challenge expired, 5 bad argument.
`approval`: 0 approved, 1 denied, 2 nothing saved for the site (the owner wasn't asked), 3 timed
out, 4 vault unavailable (or busy: at most three requests wait for the owner at once), 5 clock
not verified (GET_TOTP only), 6 locked (maki is waiting for its PIN), 7 not yours (a backup
this maki's recovery phrase can't open), 8 no phrase (no recovery phrase yet), 9 refused (a bundle
or record maki won't take; the reply says why). Only an approved reply carries a username,
password, code or backup piece.

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

## Apps

maki installs apps from `.maki` bundles (ARCHITECTURE.md in the maki repo, "Apps you can
install"; the format is `libs/maki-bundle`). maki's app host checks each bundle itself and asks
the owner before installing or removing anything: whoever sends these can't do either alone.

- **APP_LIST** describes the installed app at `index` (in order of ID), with how many there are;
  past the end, `present` is 0. `status` is 6 (locked) until maki has its PIN, and 4 if the
  firmware has no app host. `developer` is the developer's Ed25519 key (32 bytes); `from_store`
  is 0 for a sideloaded app; `backup` is whether its data goes in maki's backup (the owner's
  choice); `used` is the bytes of storage it uses; `icon` is 64x64 in `maki_icons` form as 128
  little-endian words, or empty; `bundle` is the bytes its bundle takes on maki, and `storage`
  the bytes of storage its manifest asks for, which maki keeps for it whether it's used or not.
- **APP_SPACE** says how much room maki has for apps: at most `max_apps` of them, their bundles
  and the storage each asks for within `space` bytes of maki's encrypted database, which they
  share with its logins, codes and passkeys (the database itself won't say how much of it is
  free: that would say how much is hidden in it). `taken` is what the `apps` installed take.
  `status` is 6 (locked) until maki has its PIN, and 4 if the firmware has no app host; only
  an approved reply carries the numbers. An install that doesn't fit is refused, with how much
  it needs and how much is free.
- **APP_INSTALL** sends a bundle in pieces of up to 4096 bytes, in order, with the same `total`
  each time (at most 512 KiB); a piece at offset 0 starts a new bundle. Pieces before the last
  are answered at once (`done` 0). The last is answered once maki has checked the bundle (its
  signature, its manifest, and that its code is WebAssembly or a native program maki can run
  within what it asks for) and the owner has gone through what it is, where it's from, its
  developer's key and what it may do: 0 installed, 1 cancelled, 3 timed out, 6 locked, or 9
  refused with `reason` (maki's own words: a bad signature, native code for other firmware, a
  permission this maki doesn't offer, an older version than the one installed, another
  developer's app with the same ID, no room for it). An update (the same ID) must be signed
  with the same developer key and have a higher version.
- **APP_REMOVE** removes an app and its data once the owner says so on maki: 0 removed,
  1 denied, 2 no such app, 3 timed out, 6 locked.
- **APP_MESSAGE** hands `message` (at most 4096 bytes) to the app with ID `id`, which must have
  the link permission, and returns its answer (at most 4096 bytes). If the app isn't running,
  maki starts it without the screen, unless the owner has another app open; one started without
  the screen for another app's message first finishes its exchange (it keeps maki for 5 s after
  each of its own messages). The app may ask the owner before it answers, so the answer can take
  as long as that. `status`: 0 answered, 1 the app didn't answer (it went on to its next event),
  2 no such app, 3 timed out (60 s, or an ask's time), 4 busy (the owner has another app open,
  another message already waits for the one running, or at most three requests wait at once) or
  no app host, 6 locked, 9 refused (the app hasn't the link permission). Only an answered reply carries
  the app's answer. What the messages mean is up to the app and the software talking to it.
- **STORE_UPDATE** hands maki a record from the maki store (`libs/maki-store`): a newer root,
  or a newer revocation list. It goes in pieces of up to 4096 bytes, in order, with the same
  `total` each time (at most 64 KiB); a piece at offset 0 starts a new record, and pieces before
  the last are answered at once (`done` 0). maki checks the record itself against the root it
  trusts, and doesn't ask the owner: a root must be signed by the threshold of the current
  root's keys and of its own, and a revocation list by the catalogue key while that's current,
  which takes a verified clock. `total` 0 (with offset 0 and no piece) just asks what maki has.
  `status`: 0 taken (or nothing sent), 4 no app host, 6 locked, or 9 refused with `reason`
  (maki's own words: not signed by the store, older than what maki has, the clock isn't
  verified). Unless locked or unavailable, the reply says what maki has now: the version of the
  root it trusts, and the version of its revocation list and when that goes stale (unix
  seconds; both 0 for none). Stamps, which make a bundle a store app, travel inside bundles
  (APP_INSTALL), not here.

## The wallets

maki's wallets are apps from the maki store (ARCHITECTURE.md, "Wallets are apps"), which a maki
has only if its owner adds them: **Bitcoin** (`com.leviathan.maki.bitcoin`), **Ethereum**
(`com.leviathan.maki.ethereum`) and **Monero** (`com.leviathan.maki.monero`), the SDK's examples
`bitcoin`, `ethereum` and `monero`. maki keeps the
keys, from its recovery phrase, and gives an app only the accounts its manifest names (the wallet
permission, which the owner sees when installing it); the app reads what it's asked to sign with
maki's wallet code (`maki-btc`, `maki-eth`), shows it on maki's review screen, and maki signs
only after the owner says yes there. The computer talks to them with APP_MESSAGE; an APP_MESSAGE
`status` of 2 means the app isn't installed.

Each message starts with a letter saying what it is; each answer with a status, then its fields.
`str16` is a `u16` length then UTF-8; `site` is the site asking, a `str8` holding a plain
hostname (lowercase ASCII letters, digits, dots and hyphens, as for GET_LOGIN: an international
domain comes as punycode and is shown that way). Something big (a PSBT, a transaction, typed
data) goes in pieces of as much as fits in a message, in order, with the same `total` each time;
each piece before the last is answered 6 at once, and the last once the owner decides. What was
signed comes back with `G`, a piece at a time.

Status: 0 done, 1 the owner said no, 2 no answer in time, 3 locked (or no recovery phrase yet), 4
a message the app couldn't read (a site maki won't show among them), 5 refused, with `reason`:
what the app won't sign, and why, 6 piece taken: send the next.

**Bitcoin** keeps two accounts, the standard ones, so the same phrase works in Sparrow, Electrum
and the rest: native SegWit (`account` 0: BIP84, `m/84'/0'/0'`, or `m/84'/1'/0'` on the test
networks) and taproot (`account` 1: BIP86, `m/86'/0'/0'` or `m/86'/1'/0'`, spent with the key
alone). `network` is 0 for bitcoin, 1 for the test networks (testnet and signet share keys and
addresses). Wallet software keeps track of coins and builds transactions; maki only shows and
signs.

| Message | Answer |
|---|---|
| `A` `network:u8` `account:u8` | `status` `key:str16` `descriptor:str16` |
| `D` `network:u8` `account:u8` `change:u8` `index:u32` | `status` `address:str16` |
| `P` `network:u8` `total:u32` `offset:u32` `piece` (at most 256 KiB in all) | 6, or `status` `signed:u32`, or 5 `reason:str16` |
| `G` `offset:u32` | `status` `total:u32` `offset:u32` `piece` |

- **`A`** hands out an account's public key once the owner agrees on maki ("Share account? view
  only"): for native SegWit, a `zpub` (`vpub` on the test networks) and an output descriptor with
  the master key's fingerprint and both chains, e.g.
  `wpkh([73c5da0a/84h/0h/0h]xpub…/<0;1>/*)#qf45pmyh`, which Sparrow and Bitcoin Core import as a
  watch-only wallet that knows maki signs for it; for taproot, the xpub (tpub), which has no form
  of its own, and `tr([73c5da0a/86h/0h/0h]xpub…/<0;1>/*)#…`. It reveals every address, so it's
  asked for, but it can't spend.
- **`D`** puts an address on maki's screen, the whole of it, for the owner to compare with what
  the computer shows: 0 if they said it matches, 1 if it doesn't (then the computer's copy isn't
  to be trusted). `address` is maki's, either way.
- **`P`** sends a PSBT (BIP174, version 0; BIP371's fields for taproot) spending coins of either
  account or both. The last piece is answered with the signed PSBT's size: everything that came
  in, plus a partial signature for each native SegWit input and a key signature (BIP340 Schnorr,
  `tap_key_sig`) for each taproot one. Finalizing and broadcasting are the wallet software's.

What the app checks before it asks, refusing (5, with the reason) rather than asking about a
transaction it can't vouch for:

- **Every input is this wallet's**: its BIP32 derivation (BIP371's for taproot) names this
  maki's fingerprint and a path on an account's receiving or change chain, the key derived there
  is the one named, and the coin it spends pays to that key (for taproot, the key tweaked as
  BIP86 has it, with no scripts: maki signs taproot key spends only, and refuses script paths).
- **Every native SegWit input comes with the whole transaction it spends**
  (`non_witness_utxo`), which must hash to the input's outpoint. Amounts are taken from there,
  never from the computer's word alone: with SegWit, the computer could otherwise lie about one
  input's amount per signing and have the difference paid out as fee (the 2020 fee attack). A
  taproot signature covers every input's amount and script, so a taproot input's
  `witness_utxo` is enough: a false amount makes a signature that fails.
- **Only SIGHASH_ALL** is signed (for taproot, its default, which is the same, or ALL written
  out).
- **The fee is what the inputs hold minus what the outputs pay**, never negative, and no
  amount is beyond 21 million bitcoin.
- At most 64 outputs, each of which the owner sees.

The owner then goes through the transaction with left and right: every payment with its amount
and full address, the change coming back (an output counts as change only if it derives from
this wallet's change chain; anything else is shown as a payment), and the fee with its rate
(called out when over a tenth of what's sent); then "sign" or "reject". A yes lets the app have
one signature for each input, within two minutes. ECDSA signatures are deterministic (RFC 6979)
and low-S; taproot's take fresh randomness from maki's TRNG, as BIP340 recommends.

**Ethereum** keeps an account from the same phrase, the standard way (`m/44'/60'/0'/0/index`,
BIP44, as MetaMask and Ledger make it; `index` 0 is the first account). Requests come from sites,
through the browser extension's EIP-1193 provider, and from maki desktop's own wallet (as the
site `desktop.maki`); maki shows the owner the site asking on every review.

| Message | Answer |
|---|---|
| `A` `index:u32` `site` | `status` `address:str16` |
| `M` `index:u32` `site` `message` (the rest of the message) | `status` `signature` (65 bytes) |
| `T` `index:u32` `total:u32` `offset:u32` `site` `piece` (at most 128 KiB in all) | 6, or `status` `signed:u32`, or 5 `reason:str16` |
| `Y` `index:u32` `total:u32` `offset:u32` `site` `piece` (at most 64 KiB in all) | 6, or `status` `signature` (65 bytes), or 5 `reason:str16` |
| `G` `offset:u32` | `status` `total:u32` `offset:u32` `piece` |

- **`A`** hands the site the account's address (EIP-55), once the owner lets it connect
  ("Connect wallet?"). maki desktop remembers which sites are connected; a site that isn't sees
  no account.
- **`M`** signs a message (EIP-191 `personal_sign`) once the owner has read it on maki: as text,
  or in hex if it isn't text. A Sign-In with Ethereum message (EIP-4361) that names another site
  than the one asking gets a "Wrong site!" page first: that's how a phishing site uses a real
  site's sign-in. The signature is r, s, v (v 27 or 28). The prefix EIP-191 adds means a message
  can never pass for a transaction.
- **`Y`** signs typed data (EIP-712, as `eth_signTypedData_v4` takes it: the JSON with `types`,
  `primaryType`, `domain` and `message`, in UTF-8). The app reads the JSON itself, strictly, and
  hashes it from the values it shows: the network and the app the domain names, then a permit
  (EIP-2612, or Uniswap's Permit2, known by its types' exact shape) as who may spend how much of
  which token until when, or anything else field by field, every signed field among them. It
  refuses typed data whose `types` has no `EIP712Domain` of EIP-712's own fields, with a type
  that refers to itself, with a value its type doesn't declare or missing one it does, or that
  takes more than 48 pages to show.
- **`T`** sends an unsigned transaction: EIP-1559 (`0x02 || rlp([...])`) or legacy EIP-155
  (`rlp([nonce, gas price, gas, to, value, data, chain ID, 0, 0])`). The last piece is answered
  with the signed transaction's size, to fetch with `G`, ready for `eth_sendRawTransaction`.

What the app checks and shows:

- **The bytes it signs are the bytes it shows.** The transaction is parsed strictly (one
  encoding per value: shortest lengths, no leading zeros, no bytes after the end), and the hash
  signed is of exactly what came.
- **A chain ID is required**: legacy transactions without one (before EIP-155) could be replayed
  on every network, and are refused, as are EIP-2930 and blob transactions for now.
- The owner goes through the site asking, the network (named when maki knows it, else its chain
  ID), what's sent and to whom (full EIP-55 address), and the most the fee can be (gas limit
  times the fee cap), then "sign" or "reject". Contract calls the app can read are spelled out:
  ERC-20 `transfer` (the recipient, and the amount in the token's own units when the app knows
  the token, else its smallest units), ERC-20 `approve` (the spender, and "any amount" for an
  unlimited approval) and ERC-721/1155 `setApprovalForAll` (the operator gets every item). Any
  other call is shown as a contract call the app can't read, with its function selector and
  length.
- Typed data is shown as `Y` says, from the app's own reading of it: the hash signed is of
  exactly the values shown. `eth_sign` never will be signed: it signs anything, a transaction
  included.

**Monero** keeps the account Ledger's Monero app makes from the same phrase (the key at
`m/44'/128'/0'/0/0`, hashed to the spend key, and that to the view key), so the phrase gives the
same wallet there, and the spend key's 25 words restore it in any Monero wallet. maki shows its
owner those words itself, from the app's menu, once they've said they want them: they never
leave maki, not even for the app. `network` is 0 (Monero), 1 (testnet) or 2 (stagenet).

| Message | Answer |
|---|---|
| `D` `network:u8` `account:u32` `index:u32` | `status` `address:str16` |

- **`D`** puts an address on maki's screen, the whole of it, for the owner to compare with what
  the computer shows: account 0's index 0 is the primary address, any other a subaddress (made
  with the view key, which maki keeps). 0 if they said it matches, 1 if it doesn't (then the
  computer's copy isn't to be trusted); `address` is maki's, either way.
