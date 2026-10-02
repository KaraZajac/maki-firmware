// DigiByte for maki-btc's tests, made by DigiByte's own JavaScript library (`digibyte`, from
// DigiByte-Core's digibyte-lib), which signs native SegWit and legacy inputs, and, for taproot (2025
// on DigiByte, after that library), bitcoinjs-lib with DigiByte's parameters, which are DigiByte
// Core's chainparams (P2PKH 30, P2SH 63, bech32 `dgb`; testnet 126, 140, `dgbt`) and the same as
// DigiByte's library has: checked here. Each derives the test phrase's keys itself. The test
// phrase's addresses, and a payment spending a native SegWit, a taproot and a legacy coin: its PSBT
// as bitcoinjs-lib makes it, the SegWit and legacy inputs' signatures as DigiByte's library makes
// them over the same transaction, and the taproot input's as bitcoinjs-lib does. To make them
// again, in a scratch folder:
//   npm install digibyte@0.15.8 bitcoinjs-lib@7.0.2 bip32@5.0.1 bip39@3.1.0 tiny-secp256k1@2.2.4
//   node make-digibyte.mjs > digibyte.json
import digibyte from 'digibyte'
import * as bitcoin from 'bitcoinjs-lib'
import { BIP32Factory } from 'bip32'
import * as ecc from 'tiny-secp256k1'
import * as bip39 from 'bip39'

bitcoin.initEccLib(ecc)
const PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const seed = bip39.mnemonicToSeedSync(PHRASE)

// DigiByte Core's chainparams, as bitcoinjs-lib takes them
const DGB = {
  messagePrefix: '\x19DigiByte Signed Message:\n',
  bech32: 'dgb',
  bip32: { public: 0x0488b21e, private: 0x0488ade4 },
  pubKeyHash: 30,
  scriptHash: 63,
  wif: 128
}
const DGB_TEST = { ...DGB, bech32: 'dgbt', bip32: { public: 0x043587cf, private: 0x04358394 }, pubKeyHash: 126, scriptHash: 140, wif: 254 }
// the same as DigiByte's own library has
for (const [ours, theirs] of [
  [DGB, digibyte.Networks.livenet],
  [DGB_TEST, digibyte.Networks.testnet]
]) {
  if (
    ours.bech32 !== theirs.prefix ||
    ours.pubKeyHash !== theirs.pubkeyhash ||
    ours.scriptHash !== theirs.scripthash ||
    ours.bip32.public !== theirs.xpubkey
  )
    throw new Error(`DigiByte's parameters disagree: ${theirs.name}`)
}

const bip32 = BIP32Factory(ecc)
const root = bip32.fromSeed(seed)
const node = (path) => root.derivePath(path)
// BIP32's master key, as DigiByte Core, Ledger and Trust Wallet make it ("Bitcoin seed"): DigiByte's
// library makes its own by default ("DigiByte seed"), so it's told
const theirRoot = digibyte.HDPrivateKey.fromSeed(seed.toString('hex'), 'livenet', 'Bitcoin seed')
const theirTestRoot = digibyte.HDPrivateKey.fromSeed(seed.toString('hex'), 'testnet', 'Bitcoin seed')
/** An address by DigiByte's own library (BIP32's derivation, `deriveChild`): native SegWit, or legacy. */
function theirs(path, kind, test = false) {
  const k = (test ? theirTestRoot : theirRoot).deriveChild(path).publicKey
  const network = test ? 'testnet' : 'livenet'
  return (kind === 'legacy' ? k.toLegacyAddress(network) : k.toAddress(network)).toString()
}
const toXOnly = (pubkey) => Buffer.from(pubkey).subarray(1, 33)
const p2tr = (path, network = DGB) =>
  bitcoin.payments.p2tr({ internalPubkey: toXOnly(node(path).publicKey), network }).address
const p2wpkh = (path, network = DGB) =>
  bitcoin.payments.p2wpkh({ pubkey: Buffer.from(node(path).publicKey), network }).address
const p2pkh = (path, network = DGB) =>
  bitcoin.payments.p2pkh({ pubkey: Buffer.from(node(path).publicKey), network }).address

const out = {
  addresses: {
    "m/84'/20'/0'/0/0": theirs("m/84'/20'/0'/0/0", 'segwit'),
    "m/84'/20'/0'/0/1": theirs("m/84'/20'/0'/0/1", 'segwit'),
    "m/84'/20'/0'/1/0": theirs("m/84'/20'/0'/1/0", 'segwit'),
    "m/44'/20'/0'/0/0": theirs("m/44'/20'/0'/0/0", 'legacy'),
    "m/44'/20'/0'/1/0": theirs("m/44'/20'/0'/1/0", 'legacy'),
    "m/86'/20'/0'/0/0": p2tr("m/86'/20'/0'/0/0"),
    "m/86'/20'/0'/1/1": p2tr("m/86'/20'/0'/1/1"),
    "m/84'/1'/0'/0/0": theirs("m/84'/1'/0'/0/0", 'segwit', true),
    "m/44'/1'/0'/0/0": theirs("m/44'/1'/0'/0/0", 'legacy', true),
    "m/86'/1'/0'/0/0": p2tr("m/86'/1'/0'/0/0", DGB_TEST)
  },
  // a script's hash as P2SH, DigiByte's `S…` (and its test network's)
  p2sh: {
    livenet: digibyte.Address.fromScriptHash(Buffer.alloc(20, 0x11), 'livenet').toString(),
    testnet: digibyte.Address.fromScriptHash(Buffer.alloc(20, 0x11), 'testnet').toString()
  },
  xpubs: {
    "m/84'/20'/0'": node("m/84'/20'/0'").neutered().toBase58(),
    "m/44'/20'/0'": node("m/44'/20'/0'").neutered().toBase58()
  }
}
// a check that both libraries derived the same keys: each address, both ways
for (const path of ["m/84'/20'/0'/0/0", "m/84'/20'/0'/1/0"]) {
  if (out.addresses[path] !== p2wpkh(path)) throw new Error('the libraries disagree about ' + path)
}
for (const path of ["m/44'/20'/0'/0/0", "m/44'/20'/0'/1/0"]) {
  if (out.addresses[path] !== p2pkh(path)) throw new Error('the libraries disagree about ' + path)
}
if (out.addresses["m/84'/1'/0'/0/0"] !== p2wpkh("m/84'/1'/0'/0/0", DGB_TEST)) throw new Error('testnet')

/** A transaction paying `value` to `script`, from a coin no one has: what a payment spends. */
function funding(salt, value, script) {
  const tx = new bitcoin.Transaction()
  tx.version = 2
  tx.addInput(Buffer.alloc(32, salt), 1, 0xffffffff, Buffer.from([0x51]))
  tx.addOutput(Buffer.from([0x6a]), 0n) // an OP_RETURN first: the coin is vout 1
  tx.addOutput(script, value)
  return tx
}

const fp = Buffer.from(root.fingerprint)
const segwit = node("m/84'/20'/0'/0/0")
const tap = node("m/86'/20'/0'/0/0")
const legacy = node("m/44'/20'/0'/0/0")
const change = node("m/84'/20'/0'/1/0")
const script = (address) => bitcoin.address.toOutputScript(address, DGB)
const prevSegwit = funding(1, 60_000_000_000n, script(out.addresses["m/84'/20'/0'/0/0"])) // 600 DGB
const prevTap = funding(2, 40_000_000_000n, script(out.addresses["m/86'/20'/0'/0/0"])) // 400 DGB
const prevLegacy = funding(3, 25_000_000_000n, script(out.addresses["m/44'/20'/0'/0/0"])) // 250 DGB
// someone else's: a key of sevens, as DigiByte's library writes its native SegWit address
const sevens = new digibyte.PrivateKey(Buffer.alloc(32, 7).toString('hex'), 'livenet')
const payee = sevens.publicKey.toAddress('livenet').toString()
const psbt = new bitcoin.Psbt({ network: DGB })
psbt.setVersion(2)
psbt.setLocktime(24_314_525)
psbt.addInput({
  hash: prevSegwit.getId(),
  index: 1,
  sequence: 0xfffffffd,
  nonWitnessUtxo: prevSegwit.toBuffer(),
  bip32Derivation: [{ masterFingerprint: fp, path: "m/84'/20'/0'/0/0", pubkey: Buffer.from(segwit.publicKey) }]
})
psbt.addInput({
  hash: prevTap.getId(),
  index: 1,
  sequence: 0xfffffffd,
  witnessUtxo: { script: prevTap.outs[1].script, value: 40_000_000_000n },
  tapInternalKey: toXOnly(tap.publicKey),
  tapBip32Derivation: [
    { masterFingerprint: fp, path: "m/86'/20'/0'/0/0", pubkey: toXOnly(tap.publicKey), leafHashes: [] }
  ]
})
psbt.addInput({
  hash: prevLegacy.getId(),
  index: 1,
  sequence: 0xfffffffd,
  nonWitnessUtxo: prevLegacy.toBuffer(),
  bip32Derivation: [{ masterFingerprint: fp, path: "m/44'/20'/0'/0/0", pubkey: Buffer.from(legacy.publicKey) }]
})
psbt.addOutput({ address: payee, value: 100_000_000_000n }) // 1000 DGB
psbt.addOutput({
  address: out.addresses["m/84'/20'/0'/1/0"],
  value: 24_990_000_000n, // 249.9 DGB back; 0.1 DGB fee
  bip32Derivation: [{ masterFingerprint: fp, path: "m/84'/20'/0'/1/0", pubkey: Buffer.from(change.publicKey) }]
})
const unsigned = psbt.toHex()
// the taproot input by bitcoinjs-lib: BIP340 with no auxiliary randomness, the key tweaked BIP86's way
psbt.signInput(1, tap.tweak(bitcoin.crypto.taggedHash('TapTweak', toXOnly(tap.publicKey))))
psbt.signInput(0, segwit)
psbt.signInput(2, legacy)
const bjs = psbt.data.inputs.map((i) =>
  i.tapKeySig ? Buffer.from(i.tapKeySig).toString('hex') : Buffer.from(i.partialSig[0].signature).toString('hex')
)
// the SegWit and legacy inputs again by DigiByte's library, over the same transaction (BIP143's
// digest, and the old one)
const tx = new digibyte.Transaction(Buffer.from(psbt.data.globalMap.unsignedTx.toBuffer()).toString('hex'))
const theirKey = (path) => theirRoot.deriveChild(path).privateKey
const all = digibyte.crypto.Signature.SIGHASH_ALL
const p2pkhCode = (pub) => digibyte.Script.buildPublicKeyHashOut(pub.toLegacyAddress('livenet'))
const segwitCode = p2pkhCode(theirKey("m/84'/20'/0'/0/0").publicKey).toBuffer()
const satoshis = Buffer.alloc(8)
satoshis.writeBigUInt64LE(60_000_000_000n)
const segwitSig = digibyte.Transaction.SighashWitness.sign(
  tx,
  theirKey("m/84'/20'/0'/0/0"),
  all,
  0,
  Buffer.concat([Buffer.from([segwitCode.length]), segwitCode]),
  satoshis
)
const legacySig = digibyte.Transaction.Sighash.sign(
  tx,
  theirKey("m/44'/20'/0'/0/0"),
  all,
  2,
  p2pkhCode(theirKey("m/44'/20'/0'/0/0").publicKey)
)
const der = (sig) => Buffer.concat([sig.toDER(), Buffer.from([all])]).toString('hex')
if (der(segwitSig) !== bjs[0] || der(legacySig) !== bjs[2]) throw new Error('the libraries sign differently')
out.payment = {
  payee,
  unsigned,
  signatures: [der(segwitSig), bjs[1], der(legacySig)],
  signed: psbt.toHex()
}
console.log(JSON.stringify(out, null, 2))
