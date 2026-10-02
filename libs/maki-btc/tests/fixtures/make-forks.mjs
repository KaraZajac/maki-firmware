// Dogecoin and Bitcoin Cash for maki-btc's tests, made by those coins' own kind of libraries, each
// deriving the test phrase's keys itself: Dogecoin's addresses and a payment as a PSBT, signed,
// by bitcoinjs-lib with Dogecoin's parameters (Dogecoin Core's chainparams); Bitcoin Cash's
// addresses (CashAddr), a payment, each input's signing serialization (BIP143's, with
// SIGHASH_FORKID) and its signature, by libauth. To make them again, in a scratch folder:
//   npm install bitcoinjs-lib@7.0.2 bip32@5.0.1 bip39@3.1.0 tiny-secp256k1@2.2.4 @bitauth/libauth@3.0.0
//   node make-forks.mjs > forks.json
import * as bitcoin from 'bitcoinjs-lib'
import { BIP32Factory } from 'bip32'
import * as ecc from 'tiny-secp256k1'
import * as bip39 from 'bip39'
import {
  binToHex,
  deriveHdPath,
  deriveHdPrivateNodeFromSeed,
  deriveSeedFromBip39Mnemonic,
  encodeLockingBytecodeP2pkh,
  encodeTransactionBCH,
  generateSigningSerializationBCH,
  hash160,
  hash256,
  hexToBin,
  publicKeyToP2pkhCashAddress,
  secp256k1
} from '@bitauth/libauth'

const PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const out = {}

// Dogecoin: P2PKH 0x1e (D…), P2SH 0x16, its own extended key versions (dgub)
const DOGE = {
  messagePrefix: '\x19Dogecoin Signed Message:\n',
  bip32: { public: 0x02facafd, private: 0x02fac398 },
  pubKeyHash: 0x1e,
  scriptHash: 0x16,
  wif: 0x9e
}
const DOGE_TEST = { ...DOGE, pubKeyHash: 0x71, scriptHash: 0xc4, wif: 0xf1 }
const bip32 = BIP32Factory(ecc)
const root = bip32.fromSeed(bip39.mnemonicToSeedSync(PHRASE))
const dogeKey = (path) => root.derivePath(path)
const p2pkh = (key, network) =>
  bitcoin.payments.p2pkh({ pubkey: Buffer.from(key.publicKey), network }).address
out.dogecoin = {
  addresses: {
    "m/44'/3'/0'/0/0": p2pkh(dogeKey("m/44'/3'/0'/0/0"), DOGE),
    "m/44'/3'/0'/0/1": p2pkh(dogeKey("m/44'/3'/0'/0/1"), DOGE),
    "m/44'/3'/0'/1/0": p2pkh(dogeKey("m/44'/3'/0'/1/0"), DOGE),
    "m/44'/1'/0'/0/0": p2pkh(dogeKey("m/44'/1'/0'/0/0"), DOGE_TEST)
  }
}

/** A transaction paying `value` to `script`, from a coin no one has: what a payment spends. */
function funding(salt, value, script) {
  const tx = new bitcoin.Transaction()
  tx.version = 1
  tx.addInput(Buffer.alloc(32, salt), 1, 0xffffffff, Buffer.from([0x51]))
  tx.addOutput(Buffer.alloc(25, 0x6a).subarray(0, 1), 0n) // an OP_RETURN first: the coin is vout 1
  tx.addOutput(script, value)
  return tx
}
{
  const a = dogeKey("m/44'/3'/0'/0/0")
  const b = dogeKey("m/44'/3'/0'/0/1")
  const change = dogeKey("m/44'/3'/0'/1/0")
  const script = (k) => bitcoin.payments.p2pkh({ pubkey: Buffer.from(k.publicKey), network: DOGE }).output
  const prevA = funding(1, 150_000_000n, script(a)) // 1.5 DOGE
  const prevB = funding(2, 2_000_000_000n, script(b)) // 20 DOGE
  // someone else's: a key of sevens
  const payee = bitcoin.payments.p2pkh({
    pubkey: Buffer.from(ecc.pointFromScalar(Buffer.alloc(32, 7), true)),
    network: DOGE
  }).address
  const psbt = new bitcoin.Psbt({ network: DOGE })
  psbt.setVersion(1)
  const fp = Buffer.from(root.fingerprint)
  for (const [prev, key, path] of [
    [prevA, a, "m/44'/3'/0'/0/0"],
    [prevB, b, "m/44'/3'/0'/0/1"]
  ]) {
    psbt.addInput({
      hash: prev.getId(),
      index: 1,
      sequence: 0xfffffffd,
      nonWitnessUtxo: prev.toBuffer(),
      bip32Derivation: [{ masterFingerprint: fp, path, pubkey: Buffer.from(key.publicKey) }]
    })
  }
  psbt.addOutput({ address: payee, value: 1_000_000_000n }) // 10 DOGE
  psbt.addOutput({
    address: p2pkh(change, DOGE),
    value: 1_149_000_000n, // 11.49 DOGE back; 0.01 DOGE fee
    bip32Derivation: [
      { masterFingerprint: fp, path: "m/44'/3'/0'/1/0", pubkey: Buffer.from(change.publicKey) }
    ]
  })
  const unsigned = psbt.toHex()
  psbt.signInput(0, a)
  psbt.signInput(1, b)
  out.dogecoin.payment = {
    payee,
    unsigned,
    signatures: psbt.data.inputs.map((i) => Buffer.from(i.partialSig[0].signature).toString('hex'))
  }
}

// Bitcoin Cash: CashAddr, BIP143's digest with SIGHASH_FORKID (0x41), keys derived by libauth
const seed = deriveSeedFromBip39Mnemonic(PHRASE)
const master = deriveHdPrivateNodeFromSeed(seed)
const bchKey = (path) => deriveHdPath(master, path)
const pub = (node) => secp256k1.derivePublicKeyCompressed(node.privateKey)
const cash = (node, prefix = 'bitcoincash') => publicKeyToP2pkhCashAddress({ publicKey: pub(node), prefix }).address
out.bitcoinCash = {
  addresses: {
    "m/44'/145'/0'/0/0": cash(bchKey("m/44'/145'/0'/0/0")),
    "m/44'/145'/0'/0/1": cash(bchKey("m/44'/145'/0'/0/1")),
    "m/44'/145'/0'/1/0": cash(bchKey("m/44'/145'/0'/1/0")),
    "m/44'/1'/0'/0/0": cash(bchKey("m/44'/1'/0'/0/0"), 'bchtest')
  }
}
{
  const lock = (node) => encodeLockingBytecodeP2pkh(hash160(pub(node)))
  const a = bchKey("m/44'/145'/0'/0/0")
  const b = bchKey("m/44'/145'/0'/0/1")
  const change = bchKey("m/44'/145'/0'/1/0")
  const fundingBch = (salt, value, lockingBytecode) => ({
    version: 1,
    inputs: [
      {
        outpointTransactionHash: new Uint8Array(32).fill(salt),
        outpointIndex: 1,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: Uint8Array.of(0x51)
      }
    ],
    outputs: [
      { lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n },
      { lockingBytecode, valueSatoshis: value }
    ],
    locktime: 0
  })
  const prevA = fundingBch(3, 60_000n, lock(a))
  const prevB = fundingBch(4, 40_000n, lock(b))
  // a transaction's ID is its hash256, reversed; an outpoint carries it unreversed
  const idOf = (tx) => hash256(encodeTransactionBCH(tx))
  const sevens = secp256k1.derivePublicKeyCompressed(new Uint8Array(32).fill(7))
  const payee = encodeLockingBytecodeP2pkh(hash160(sevens))
  const tx = {
    version: 2,
    inputs: [prevA, prevB].map((p) => ({
      outpointTransactionHash: idOf(p).slice().reverse(),
      outpointIndex: 1,
      sequenceNumber: 0xfffffffe,
      unlockingBytecode: new Uint8Array()
    })),
    outputs: [
      { lockingBytecode: payee, valueSatoshis: 70_000n },
      { lockingBytecode: lock(change), valueSatoshis: 29_500n } // 500 fee
    ],
    locktime: 900_000
  }
  const sourceOutputs = [prevA.outputs[1], prevB.outputs[1]]
  const digests = []
  const signatures = []
  for (const [i, key] of [a, b].entries()) {
    const serialization = generateSigningSerializationBCH(
      { inputIndex: i, sourceOutputs, transaction: tx },
      { coveredBytecode: lock(key), signingSerializationType: Uint8Array.of(0x41) }
    )
    const digest = hash256(serialization)
    digests.push(binToHex(digest))
    signatures.push(binToHex(secp256k1.signMessageHashDER(key.privateKey, digest)) + '41')
  }
  out.bitcoinCash.payment = {
    payee: publicKeyToP2pkhCashAddress({ publicKey: sevens }).address,
    previous: [prevA, prevB].map((p) => binToHex(encodeTransactionBCH(p))),
    paths: ["m/44'/145'/0'/0/0", "m/44'/145'/0'/0/1"],
    change: "m/44'/145'/0'/1/0",
    unsigned: binToHex(encodeTransactionBCH(tx)),
    digests,
    signatures
  }
}

// a check that both libraries derived the same keys: one path, both ways
if (Buffer.from(dogeKey("m/44'/145'/0'/0/0").publicKey).toString('hex') !== binToHex(pub(bchKey("m/44'/145'/0'/0/0"))))
  throw new Error('the libraries disagree about the test phrase’s keys')
void hexToBin
console.log(JSON.stringify(out, null, 2))
