# Nostr

Your Nostr key, from maki's recovery phrase: the app's BIP340 (Schnorr) key for the label
`nostr`, which maki holds and signs with (host API 2's `keys::schnorr_*`). The same key on any
maki restored from the phrase; there's no importing another.

Sites use it through the maki extension, which gives pages `window.nostr` (NIP-07) when no
other signer has: `getPublicKey()`, `signEvent(event)` and `getRelays()`. maki desktop hands each
call to this app (the link permission), and the app asks on maki's screen (the ask permission):
before a site first sees the key ("Let it see your Nostr key?", with the site), and before each
event it signs ("Sign a Nostr note?", with the site and how the event begins). The app works out
the event's id itself from the fields it shows (NIP-01's serialization, hashed), so what it
signs is what its owner saw.

Opened, it shows the key's npub as a QR code, to share with a phone. The menu's "Forget sites"
makes every site ask again.

Not yet: NIP-04 and NIP-44 encryption (direct messages), and events over 4 KB (a message to an
app is 4 KB at most).
