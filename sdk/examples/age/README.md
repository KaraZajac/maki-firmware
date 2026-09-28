# Age

Your [age](https://age-encryption.org) key, from maki's recovery phrase: the app's X25519 key for
the label `age`, which maki holds (host API 2's `keys::x25519_*`). The same key on any maki
restored from the phrase.

Its public half is an ordinary age recipient (`age1…`), so anyone encrypts files to it with age as
it is, no plugin needed:

```sh
age -r age1… -o notes.age notes.txt
```

Decrypting asks maki. maki desktop installs `age-plugin-maki` (Connections, age) and saves an
identity file naming maki's key (`AGE-PLUGIN-MAKI-1…`, nothing secret in it):

```sh
age -d -i maki-age.txt notes.age
```

age hands the plugin the file's stanzas; the plugin asks this app, through maki desktop, which of
the file's X25519 stanzas is its own (without bothering its owner: a stanza doesn't say who it's
for), then for that one's file key, which the app asks about on maki's screen first ("Decrypt a
file with your age key?", naming the program). maki works out the key agreement; the app unwraps
the file key as age does (HKDF-SHA-256, ChaCha20-Poly1305) and hands over that alone.

Opened, it shows the recipient as a QR code; the centre shows it as text.
