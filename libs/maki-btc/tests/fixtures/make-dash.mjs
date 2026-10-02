// Dash for maki-btc's tests, made by Dash's own library, @dashevo/dashcore-lib, deriving the test
// phrase's keys itself from bip39's seed: its addresses (BIP44's first is the one wallets publish
// for the test phrase), and transactions as Dash writes them (DIP-2): a payment spending a plain
// coin and one a withdrawal from Dash Platform paid (an asset unlock, a special transaction with no
// inputs and a payload), and its signatures; and an asset lock, a special transaction maki must
// refuse. To make them again, in a scratch folder:
//   npm install @dashevo/dashcore-lib@0.25.0 bip39@3.1.0
//   node make-dash.mjs > dash.json
import dashcore from '@dashevo/dashcore-lib'
import * as bip39 from 'bip39'

const { HDPrivateKey, Transaction, Script, Address, PrivateKey } = dashcore
const PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const seed = bip39.mnemonicToSeedSync(PHRASE)
const root = HDPrivateKey.fromSeed(seed, 'livenet')
const testRoot = HDPrivateKey.fromSeed(seed, 'testnet')
const key = (path) => root.deriveChild(path).privateKey
const out = {}

out.addresses = {
  "m/44'/5'/0'/0/0": key("m/44'/5'/0'/0/0").toAddress('livenet').toString(),
  "m/44'/5'/0'/0/1": key("m/44'/5'/0'/0/1").toAddress('livenet').toString(),
  "m/44'/5'/0'/1/0": key("m/44'/5'/0'/1/0").toAddress('livenet').toString(),
  "m/44'/1'/0'/0/0": testRoot.deriveChild("m/44'/1'/0'/0/0").privateKey.toAddress('testnet').toString()
}
out.xpub = root.deriveChild("m/44'/5'/0'").hdPublicKey.toString()
// a script's hash as P2SH, Dash's `7…` (and its test network's)
const hash = Buffer.alloc(20, 0x11)
out.p2sh = {
  livenet: new Address(hash, 'livenet', 'scripthash').toString(),
  testnet: new Address(hash, 'testnet', 'scripthash').toString()
}

const p2pkh = (privateKey) => Script.buildPublicKeyHashOut(privateKey.toAddress('livenet'))
/** A plain transaction paying `value` to `script`, from a coin no one has: what a payment spends. */
function funding(salt, value, script) {
  const tx = new Transaction()
  tx.uncheckedAddInput(
    new Transaction.Input({
      prevTxId: Buffer.alloc(32, salt),
      outputIndex: 1,
      script: Script.fromHex('51'),
      sequenceNumber: 0xffffffff
    })
  )
  tx.addOutput(new Transaction.Output({ script: Script.fromHex('6a'), satoshis: 0 })) // the coin is vout 1
  tx.addOutput(new Transaction.Output({ script, satoshis: value }))
  return tx
}
/** A withdrawal from Dash Platform paying `value` to `script`: an asset unlock (type 9), no inputs. */
function withdrawal(value, script) {
  const tx = new Transaction()
  tx.setType(Transaction.TYPES.TRANSACTION_ASSET_UNLOCK)
  tx.addOutput(new Transaction.Output({ script, satoshis: value }))
  Object.assign(tx.extraPayload, {
    version: 1,
    index: 4242,
    fee: 1000,
    requestHeight: 2_500_000,
    quorumHash: '22'.repeat(32),
    quorumSig: '33'.repeat(96)
  })
  return tx
}

const a = key("m/44'/5'/0'/0/0")
const b = key("m/44'/5'/0'/0/1")
const change = key("m/44'/5'/0'/1/0")
const prevA = funding(1, 150_000_000, p2pkh(a)) // 1.5 DASH
const prevB = withdrawal(25_000_000, p2pkh(b)) // 0.25 DASH from Dash Platform
const prevBIndex = 0
// someone else's: a key of sevens
const payee = new PrivateKey(Buffer.alloc(32, 7).toString('hex'), 'livenet').toAddress('livenet')
const payment = new Transaction()
payment.from([
  { txId: prevA.hash, outputIndex: 1, script: p2pkh(a).toHex(), satoshis: 150_000_000 },
  { txId: prevB.hash, outputIndex: prevBIndex, script: p2pkh(b).toHex(), satoshis: 25_000_000 }
])
payment.addOutput(new Transaction.Output({ script: Script.buildPublicKeyHashOut(payee), satoshis: 100_000_000 }))
payment.addOutput(new Transaction.Output({ script: p2pkh(change), satoshis: 74_990_000 })) // 0.0001 DASH fee
const unsigned = payment.uncheckedSerialize()
payment.sign([a, b])
out.payment = {
  payee: payee.toString(),
  previous: [prevA.uncheckedSerialize(), prevB.uncheckedSerialize()],
  previousIds: [prevA.hash, prevB.hash],
  vouts: [1, prevBIndex],
  paths: ["m/44'/5'/0'/0/0", "m/44'/5'/0'/0/1"],
  change: "m/44'/5'/0'/1/0",
  version: payment.version,
  unsigned,
  signatures: payment.inputs.map((i) => i.script.chunks[0].buf.toString('hex')),
  signed: payment.serialize(true)
}

// an asset lock (type 8): credit for Dash Platform, an OP_RETURN holding what's locked, the
// credit's key in the payload; a special transaction maki refuses by name
const lock = new Transaction()
lock.setType(Transaction.TYPES.TRANSACTION_ASSET_LOCK)
lock.from([{ txId: prevA.hash, outputIndex: 1, script: p2pkh(a).toHex(), satoshis: 150_000_000 }])
lock.addOutput(new Transaction.Output({ script: Script.fromHex('6a00'), satoshis: 100_000_000 }))
lock.addOutput(new Transaction.Output({ script: p2pkh(change), satoshis: 49_990_000 }))
lock.extraPayload.creditOutputs = [
  new Transaction.Output({ script: Script.buildPublicKeyHashOut(payee), satoshis: 100_000_000 })
]
out.assetLock = { unsigned: lock.uncheckedSerialize(), type: lock.type, version: lock.version }

console.log(JSON.stringify(out, null, 2))
