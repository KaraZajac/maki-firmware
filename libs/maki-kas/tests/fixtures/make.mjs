// Transactions for maki-kas's tests, made with Kaspa's own SDK and signed by the test phrase's
// account as Kaspium, Kaspa NG, Kastle and Ledger's Kaspa app derive it (m/44'/111111'/0'/chain/
// index): what maki must show, and the signatures it must make. The SDK is rusty-kaspa's WASM SDK,
// v2.1.0: the Node.js build in its release's kaspa-wasm32-sdk-v2.1.0.zip (sha256 ba674e109ff5dd8b
// edc4dc2ee8a5ecdf4b600b1178a541d77888ec58310b6124). npm's `kaspa` and `kaspa-wasm` packages stop at
// 0.13.0, from 2023, before Kaspa's Crescendo and Toccata forks. BIP340 signatures with no aux
// randomness, as maki's tests make them, come from @noble/curves 2.4.0; the SDK then checks every one
// of them as the chain would, so each signature here is one Kaspa takes. To make them again:
//   curl -LO https://github.com/kaspanet/rusty-kaspa/releases/download/v2.1.0/kaspa-wasm32-sdk-v2.1.0.zip
//   unzip kaspa-wasm32-sdk-v2.1.0.zip && npm install ./kaspa-wasm32-sdk/nodejs/kaspa @noble/curves@2.4.0
//   node make.mjs transactions.json
//
// `request` is what maki desktop sends the Kaspa app after `T` and the network (maki-kas's
// request.rs says it byte by byte); `encode` below is how a wallet on the computer writes one from
// the SDK's transaction.
import { createRequire } from 'node:module'
import { writeFileSync } from 'node:fs'
import { schnorr } from '@noble/curves/secp256k1.js'

const require = createRequire(import.meta.url)
const kaspa = require('kaspa-wasm')
if (kaspa.version() !== '2.1.0') throw new Error(`the SDK is ${kaspa.version()}, not 2.1.0`)

const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const root = new kaspa.XPrv(new kaspa.Mnemonic(phrase).toSeed(''))
const secret = (chain, index) => root.derivePath(`m/44'/111111'/0'/${chain}/${index}`).toPrivateKey()
const NETWORKS = { 0: 'mainnet', 1: 'testnet-10' }

// the phrase's first address, as Kastle's tests publish it (forbole/kastle, tests/signtx-unit.spec.ts)
if (secret(0, 0).toAddress('mainnet').toString() !== 'kaspa:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9s3qt0lqeh') {
  throw new Error('not the address other wallets make from the phrase')
}
// and rusty-kaspa's own wallet tests (wallet/keys/src/derivation/gen1/hd.rs): a phrase's kpub, and
// a test network address
{
  const fringe = 'fringe ceiling crater inject pilot travel gas nurse bulb bullet horn segment snack harbor dice laugh vital cigar push couple plastic into slender worry'
  const kpub = new kaspa.XPrv(new kaspa.Mnemonic(fringe).toSeed('')).derivePath("m/44'/111111'/0'").toXPub().intoString('kpub')
  if (kpub !== 'kpub2HtoTgsG6e1c7ixJ6JY49otNSzhEKkwnH6bsPHLAXUdYnfEuYw9LnhT7uRzaS4LSeit2rzutV6z8Fs9usdEGKnNe6p1JxfP71mK8rbUfYWo') throw new Error('kpub')
  const hunt = 'hunt bitter praise lift buyer topic crane leopard uniform network inquiry over grain pass match crush marine strike doll relax fortune trumpet sunny silk'
  const address = new kaspa.XPrv(new kaspa.Mnemonic(hunt).toSeed('')).derivePath("m/44'/111111'/0'/0/1").toPrivateKey().toAddress('testnet').toString()
  if (address !== 'kaspatest:qrc2959g0pqda53glnfd238cdnmk24zxzkj8n5x83rkktx4h73dkc4ave6wyg') throw new Error('hunt')
}

const hex = (b) => Buffer.from(b).toString('hex')
const unhex = (s) => Buffer.from(s, 'hex')
const u8 = (n) => Buffer.from([n])
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b }
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b }
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b }

// Keys that aren't this wallet's: someone to pay, an ECDSA account's key, and a key for nothing
const other = (byte) => new kaspa.PrivateKey(byte.repeat(32))
const RECIPIENT = other('11')
const ECDSA = other('22')
const NOBODY = other('99')
// a script hash address: of a script anyone can spend (OP_TRUE), as the SDK makes one
const P2SH = kaspa.payToScriptHashScript('51')

// A script public key as the SDK's JSON writes it: the version (two bytes, 0), then the script.
const spk = (script) => '0000' + script
const p2pk = (key) => '20' + key.toPublicKey().toXOnlyPublicKey().toString() + 'ac'
const p2pkEcdsa = (key) => '21' + key.toPublicKey().toString() + 'ab'

/** A transaction, from the SDK's own JSON, its ID made. */
function transaction(json) {
  const tx = kaspa.Transaction.deserializeFromSafeJSON(JSON.stringify(json))
  tx.finalize()
  return tx
}

/** What maki desktop sends the Kaspa app after `T` and the network: the unsigned transaction, each
 * input's coin (its amount and script) and key (chain and index), and the keys of outputs that are
 * this wallet's. `keys` gives an input's (chain, index); `ours` an output's, or null for a payment. */
function encode(tx, keys, ours) {
  const parts = [u16(tx.version), u8(tx.inputs.length)]
  tx.inputs.forEach((input, i) => {
    const script = unhex(input.utxo.scriptPublicKey)
    if (script.readUInt16BE(0) !== 0) throw new Error('script version')
    const [chain, index] = keys[i]
    parts.push(unhex(input.transactionId), u32(input.index), u64(input.sequence))
    parts.push(tx.version === 0 ? u8(input.sigOpCount) : u16(input.computeBudget))
    parts.push(u64(input.utxo.amount), u16(0), u8(script.length - 2), script.subarray(2), u8(chain), u32(index))
  })
  parts.push(u8(tx.outputs.length))
  tx.outputs.forEach((output, j) => {
    const script = unhex(output.scriptPublicKey)
    parts.push(u64(output.value), u16(script.readUInt16BE(0)), u8(script.length - 2), script.subarray(2))
    if (tx.version >= 1) {
      if (output.covenant) throw new Error('covenant')
      parts.push(u8(0))
    }
    parts.push(ours[j] ? Buffer.concat([u8(1), u8(ours[j][0]), u32(ours[j][1])]) : u8(0))
  })
  const payload = unhex(tx.payload)
  parts.push(u64(tx.lockTime), unhex(tx.subnetworkId), u64(tx.gas), u16(payload.length), payload)
  return Buffer.concat(parts)
}

/** Kaspa's signature hash for each input, SIGHASH_ALL, as rusty-kaspa computes it, with the SDK's own
 * keyed BLAKE2b: ported from its consensus/core/src/hashing/sighash.rs (ISC License, Copyright (c)
 * 2022-2024 Kaspa developers: LICENSE-rusty-kaspa, beside maki-kas's Cargo.toml). The SDK's own
 * signatures checking out against it shows it's the SDK's. */
function sighashes(tx) {
  const H = (...parts) => {
    const h = new kaspa.TransactionSigningHash()
    for (const p of parts) h.update(p)
    return unhex(h.finalize())
  }
  const v0 = tx.version < 1
  const coin = (input) => unhex(input.utxo.scriptPublicKey)
  const varScript = (s) => Buffer.concat([s.subarray(0, 2).reverse(), u64(s.length - 2), s.subarray(2)])
  const previous = H(...tx.inputs.map((i) => Buffer.concat([unhex(i.transactionId), u32(i.index)])))
  const sequences = H(...tx.inputs.map((i) => u64(i.sequence)))
  const sigOps = H(...tx.inputs.map((i) => u8(i.sigOpCount)))
  const outputs = H(...tx.outputs.map((o) => Buffer.concat([u64(o.value), varScript(unhex(o.scriptPublicKey)), v0 ? Buffer.alloc(0) : u8(0)])))
  const payload = unhex(tx.payload)
  const native = /^0+$/.test(tx.subnetworkId)
  const payloadHash = native && payload.length === 0 ? Buffer.alloc(32) : H(u64(payload.length), payload)
  return tx.inputs.map((input) =>
    H(
      u16(tx.version), previous, sequences, v0 ? sigOps : Buffer.alloc(0),
      unhex(input.transactionId), u32(input.index), varScript(coin(input)), u64(input.utxo.amount), u64(input.sequence),
      v0 ? u8(input.sigOpCount) : Buffer.alloc(0),
      outputs, u64(tx.lockTime), unhex(tx.subnetworkId), u64(tx.gas), payloadHash, u8(1)
    )
  )
}

const out = { account: {}, addresses: [], others: {}, transactions: [] }
{
  const xpub = root.derivePath("m/44'/111111'/0'").toXPub()
  out.account = { key: xpub.toPublicKey().toString(), chainCode: xpub.chainCode, kpub: xpub.intoString('kpub') }
  // rusty-kaspa's test phrase's account (its kpub, above), as the SDK reads it
  const fringe = new kaspa.XPub('kpub2HtoTgsG6e1c7ixJ6JY49otNSzhEKkwnH6bsPHLAXUdYnfEuYw9LnhT7uRzaS4LSeit2rzutV6z8Fs9usdEGKnNe6p1JxfP71mK8rbUfYWo')
  out.fringe = { key: fringe.toPublicKey().toString(), chainCode: fringe.chainCode }
  out.others = {
    recipient: RECIPIENT.toAddress('mainnet').toString(),
    recipientTestnet: RECIPIENT.toAddress('testnet').toString(),
    ecdsa: ECDSA.toAddressECDSA('mainnet').toString(),
    p2sh: kaspa.addressFromScriptPublicKey(P2SH, 'mainnet').toString(),
  }
  for (const [network, name] of Object.entries(NETWORKS)) {
    for (const [chain, index] of [[0, 0], [0, 1], [0, 2], [1, 0], [1, 1]]) {
      const key = secret(chain, index)
      out.addresses.push({ network: Number(network), chain, index, key: key.toPublicKey().toString(), address: key.toAddress(name).toString() })
    }
  }
}

/**
 * A transaction for the fixtures: its request, each input's signature hash, the signatures the SDK
 * made (random aux), and the ones maki makes (no aux), which the SDK checks as the chain would.
 * `signers` are the keys the SDK signs with: this wallet's, or (for a coin that isn't) its owner's.
 */
function add(name, network, tx, keys, ours, { signers, mine = true } = {}) {
  const json = JSON.parse(tx.serializeToSafeJSON())
  const request = encode(json, keys, ours)
  const signed = JSON.parse(kaspa.signTransaction(tx, signers ?? keys.map(([c, i]) => secret(c, i)), true).serializeToSafeJSON())
  const digests = sighashes(json)
  const sdk = signed.inputs.map((input, i) => {
    const script = unhex(input.signatureScript)
    if (script.length !== 66 || script[0] !== 0x41 || script[65] !== 1) throw new Error(`${name}: signature script ${i}`)
    const xonly = unhex(input.utxo.scriptPublicKey).subarray(3, 35)
    // the SDK signed Kaspa's own digest: this one, then
    if (!schnorr.verify(script.subarray(1, 65), digests[i], xonly)) throw new Error(`${name}: sighash ${i}`)
    return hex(script.subarray(1))
  })
  const entry = { name, network, request: hex(request), txid: tx.id, sighashes: digests.map(hex), sdk, signatures: null }
  if (mine) {
    const ours = digests.map((d, i) => Buffer.concat([schnorr.sign(d, unhex(secret(...keys[i]).toString()), new Uint8Array(32)), u8(1)]))
    // the SDK checks every input's signature against the transaction (signing nothing itself: no
    // input is NOBODY's)
    const check = JSON.parse(tx.serializeToSafeJSON())
    check.inputs.forEach((input, i) => { input.signatureScript = '41' + hex(ours[i]) })
    kaspa.signTransaction(transaction(check), [NOBODY], true)
    entry.signatures = ours.map(hex)
    // the transaction as sent, maki's signatures in it: once, to show what that looks like
    if (name === 'payment') entry.signed = JSON.parse(transaction(check).serializeToSafeJSON())
  }
  out.transactions.push(entry)
  console.log(`${name}: ${request.length} bytes, ${json.inputs.length} in, ${json.outputs.length} out`)
}

/** A coin of this wallet's (or `owner`'s), as the SDK's JSON has an input. */
function coin(chain, index, amount, { txid, vout = 0, sequence = 0n, version = 0, budget = 10, owner } = {}) {
  return {
    transactionId: txid ?? hex(Buffer.alloc(32, (chain * 64 + index + 1) & 0xff).map((b, i) => (b * 7 + i * 13) & 0xff)),
    index: vout,
    sequence: String(sequence),
    sigOpCount: version === 0 ? 1 : 0,
    computeBudget: version === 0 ? 0 : budget,
    signatureScript: '',
    utxo: { address: null, amount: String(amount), scriptPublicKey: spk(p2pk(owner ?? secret(chain, index))), blockDaaScore: '474000000', isCoinbase: false, covenantId: null },
  }
}
const pay = (amount, script) => ({ value: String(amount), scriptPublicKey: spk(script), covenant: null })
const tx = ({ version = 0, inputs, outputs, lockTime = 0n, payload = '' }) =>
  transaction({ id: hex(Buffer.alloc(32)), version, inputs, outputs, subnetworkId: '00'.repeat(20), lockTime: String(lockTime), gas: '0', storageMass: '0', payload })

/** A payment as the SDK's transaction generator makes it (Kaspa NG's): coins picked, the fee from
 * the mass, change to this wallet's change address. */
async function generated(network, entries, outputs, change, extra = {}) {
  const name = NETWORKS[network]
  const utxos = entries.map(([chain, index, amount], n) => {
    const key = secret(chain, index)
    return {
      address: key.toAddress(name),
      outpoint: { transactionId: hex(Buffer.alloc(32, 0xc3 + n)), index: n },
      amount,
      scriptPublicKey: kaspa.payToAddressScript(key.toAddress(name)),
      blockDaaScore: 474000000n,
      isCoinbase: false,
    }
  })
  const { transactions } = await kaspa.createTransactions({
    entries: utxos,
    outputs: outputs.map(([address, amount]) => ({ address, amount })),
    changeAddress: secret(...change).toAddress(name),
    networkId: name,
    ...extra,
  })
  if (transactions.length !== 1) throw new Error('one transaction')
  const pending = transactions[0]
  const json = JSON.parse(pending.serializeToSafeJSON())
  const keys = json.inputs.map((input) => {
    const n = utxos.findIndex((u) => u.outpoint.transactionId === input.transactionId && u.outpoint.index === input.index)
    return entries[n].slice(0, 2)
  })
  const changeScript = spk(p2pk(secret(...change)))
  const ours = json.outputs.map((o) => (o.scriptPublicKey === changeScript ? change : null))
  return [transaction(json), keys, ours]
}

const recipient = (network) => RECIPIENT.toAddress(NETWORKS[network])

// a payment, change and all, as Kaspa NG makes one
add('payment', 0, ...(await generated(0, [[0, 0, 1000000000n]], [[recipient(0), 150000000n]], [1, 0], { priorityFee: 0n })))
add('payment-testnet', 1, ...(await generated(1, [[0, 0, 1000000000n]], [[recipient(1), 150000000n]], [1, 0], { priorityFee: 0n })))
// with a note, and with bytes that aren't text, everyone can read on chain
add('payload', 0, ...(await generated(0, [[0, 0, 1000000000n]], [[recipient(0), 150000000n]], [1, 0], { priorityFee: 0n, payload: hex(Buffer.from('thanks for the coffee')) })))
add('payload-bytes', 0, ...(await generated(0, [[0, 0, 1000000000n]], [[recipient(0), 150000000n]], [1, 0], { priorityFee: 0n, payload: '00017f80feff' })))
// coins gathered from three addresses to one of this wallet's own: nothing leaves but the fee
add('consolidate', 0, tx({
  inputs: [coin(0, 0, 200000000n), coin(0, 1, 300000000n), coin(1, 0, 50000000n)],
  outputs: [pay(549000000n, p2pk(secret(0, 2)))],
}), [[0, 0], [0, 1], [1, 0]], [[0, 2]])
// three payments, to each kind of address there is, and change
add('three-payments', 0, tx({
  inputs: [coin(0, 0, 200000000n), coin(1, 1, 300000000n)],
  outputs: [pay(100000000n, p2pk(RECIPIENT)), pay(50000000n, p2pkEcdsa(ECDSA)), pay(25000000n, P2SH.script), pay(324700000n, p2pk(secret(1, 2)))],
}), [[0, 0], [1, 1]], [null, null, null, [1, 2]])
// not before a DAA score, not before a time, and coins that must wait
add('lock-time', 0, tx({ inputs: [coin(0, 0, 1000000000n)], outputs: [pay(150000000n, p2pk(RECIPIENT)), pay(849700000n, p2pk(secret(1, 0)))], lockTime: 480000000n }), [[0, 0]], [null, [1, 0]])
add('lock-time-date', 0, tx({ inputs: [coin(0, 0, 1000000000n)], outputs: [pay(150000000n, p2pk(RECIPIENT)), pay(849700000n, p2pk(secret(1, 0)))], lockTime: 1798761600000n }), [[0, 0]], [null, [1, 0]])
add('sequence-lock', 0, tx({ inputs: [coin(0, 0, 1000000000n, { sequence: 36000n })], outputs: [pay(150000000n, p2pk(RECIPIENT)), pay(849700000n, p2pk(secret(1, 0)))] }), [[0, 0]], [null, [1, 0]])
// Toccata's transaction version 1: compute budgets for sig op counts, no covenants
add('version-1', 0, tx({
  version: 1,
  inputs: [coin(0, 0, 1000000000n, { version: 1, budget: 10 }), coin(1, 3, 20000000n, { version: 1, budget: 12 })],
  outputs: [pay(150000000n, p2pk(RECIPIENT)), pay(869700000n, p2pk(secret(1, 4)))],
}), [[0, 0], [1, 3]], [null, [1, 4]])
// half of what it spends goes to the fee
add('high-fee', 0, tx({ inputs: [coin(0, 0, 100000000n)], outputs: [pay(50000000n, p2pk(RECIPIENT))] }), [[0, 0]], [null])
// a coin that isn't this wallet's, said to be receive #0's: the SDK signs it with its owner's key
add('not-mine', 0, tx({ inputs: [coin(0, 0, 1000000000n, { owner: RECIPIENT })], outputs: [pay(150000000n, p2pk(secret(0, 1)))] }), [[0, 0]], [null], { signers: [RECIPIENT], mine: false })
// as many coins as one message holds
{
  const n = 41
  const inputs = Array.from({ length: n }, (_, i) => coin(0, i, 100000000n, { txid: hex(Buffer.alloc(32, i + 1)), vout: i }))
  add('many-inputs', 0, tx({ inputs, outputs: [pay(3000000000n, p2pk(RECIPIENT)), pay(1099000000n, p2pk(secret(1, 3)))] }), inputs.map((_, i) => [0, i]), [null, [1, 3]])
}

writeFileSync(process.argv[2], JSON.stringify(out, null, 1) + '\n')
