// What maki-ton's tests hold it to, made with TON's own JavaScript libraries: @ton/core 0.63.1
// (cells, BOCs, addresses, messages), @ton/ton 16.3.0 (the wallet contracts, and what each one
// signs), @ton/crypto 3.3.0 (SLIP-10 and Ed25519), with @scure/bip39 2.4.0 for the test phrase's
// seed. The account is the test phrase's as Ledger's TON app makes it (ton-ledger-ts's
// `pathForAccount`, Ledger Live's `44'/607'/0'/0'/<account>'/0'`): SLIP-10 at
// m/44'/607'/network'/0'/account'/0', network 0 for TON and 1 for its test network. To make them
// again:
//   npm install @ton/core@0.63.1 @ton/ton@16.3.0 @ton/crypto@3.3.0 @scure/bip39@2.4.0
//   node make.mjs transactions.json
// It asks toncenter (TON's own API, no key needed) once a second what each jetton maki knows says
// this account's jetton wallets are, and stops if they aren't the ones it worked out.
//
// Each transaction: the cell a wallet's signer is handed (@ton/ton's `createTransfer` with a
// `signer`), as @ton/core writes it in a BOC (with its CRC32C), which is what maki is asked to sign;
// its hash, which is what's signed; @ton/crypto's signature with this account's key; and the
// external message that carries it to the network, its body the signature and that cell (v4R2: the
// signature first; W5: last), as @ton/ton and @ton/core make them. A few are ones TON or maki
// refuses, which the libraries make anyway.
import { createHmac } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { mnemonicToSeedSync, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { deriveEd25519Path, keyPairFromSeed, sign, signVerify } from '@ton/crypto'
import {
  Address,
  beginCell,
  Cell,
  comment,
  contractAddress,
  Dictionary,
  external,
  internal,
  SendMode,
  storeMessage,
  storeMessageRelaxed,
  storeOutList,
  storeStateInit
} from '@ton/core'
import { WalletContractV4, WalletContractV5R1 } from '@ton/ton'

const out = process.argv[2] ?? 'transactions.json'
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
if (!validateMnemonic(phrase, wordlist)) throw new Error('not a BIP-39 phrase')
const seed = Buffer.from(mnemonicToSeedSync(phrase))

/** SLIP-10, written out (as SEP-5's test does it): a second implementation for @ton/crypto's. */
function slip10(path) {
  const hmac = (k, d) => createHmac('sha512', k).update(d).digest()
  let i = hmac(Buffer.from('ed25519 seed'), seed)
  for (const n of path) {
    const b = Buffer.alloc(4)
    b.writeUInt32BE((n | 0x80000000) >>> 0)
    i = hmac(i.subarray(32), Buffer.concat([Buffer.from([0]), i.subarray(0, 32), b]))
  }
  return i.subarray(0, 32)
}

/** ton-ledger-ts's `pathForAccount(testnet, workchain, account)`, every step hardened. */
const ledgerPath = (network, account) => [44, 607, network, 0, account, 0]

async function keys(network, account) {
  const path = ledgerPath(network, account)
  const secret = await deriveEd25519Path(seed, path)
  if (!secret.equals(slip10(path))) throw new Error('two SLIP-10s disagree')
  return keyPairFromSeed(secret)
}

const GLOBAL_ID = [-239, -3]
/** W5's wallet ID for a network, as @ton/ton's `storeWalletIdV5R1` writes it for workchain 0,
 * version v5r1, subwallet 0: the network's global ID XOR the context (a 1, then zeros). */
const w5Id = (network) => Number(BigInt.asUintN(32, BigInt(GLOBAL_ID[network]) ^ -0x80000000n))
function wallets(publicKey, network) {
  return {
    v4R2: WalletContractV4.create({ workchain: 0, publicKey }),
    v5R1: WalletContractV5R1.create({ walletId: { networkGlobalId: GLOBAL_ID[network] }, publicKey })
  }
}

const hex = (b) => Buffer.from(b).toString('hex')

/** An address every way TON writes it. */
function forms(address, network) {
  const testOnly = network === 1
  return {
    raw: address.toRawString(),
    bounceable: address.toString({ bounceable: true, testOnly }),
    non_bounceable: address.toString({ bounceable: false, testOnly })
  }
}

// --- jettons maki knows: their masters, and their wallets' code, which each master holds as a
// library cell (exotic, type 2) naming the code by its hash: the library cell's own hash is the one
// Ledger's TON app has for it, and toncenter's `jetton_wallet_code_hash` ---
const library = (h) => beginCell().storeUint(2, 8).storeBuffer(Buffer.from(h, 'hex')).endCell({ exotic: true })
const JETTONS = {
  USDT: { master: Address.parse('EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs'), code: library('8f452d7a4dfd74066b682365177259ed05734435be76b5fd4bd5d8af2b7c3d68'), hash: '89468f02c78e570802e39979c8516fc38df07ea76a48357e0536f2ba7b3ee37b' },
  NOT: { master: Address.parse('EQAvlWFDxGF2lXm67y4yzC17wYKD9A0guwPkMs1gOsM__NOT'), code: library('ba2918c8947e9b25af9ac1b883357754173e5812f807a3d6e642a14709595395'), hash: '8d28ea421b77e805fea52acf335296499f03aec8e9fd21ddb5f2564aa65c48de' },
  DOGS: { master: Address.parse('EQCvxJy4eG8hyHBFsZ7eePxrRsUQSFE_jpptRAYBmcG_DOGS'), code: library('ba2918c8947e9b25af9ac1b883357754173e5812f807a3d6e642a14709595395'), hash: '8d28ea421b77e805fea52acf335296499f03aec8e9fd21ddb5f2564aa65c48de' }
}
for (const [name, j] of Object.entries(JETTONS)) {
  if (j.code.hash().toString('hex') !== j.hash || j.code.depth() !== 0) throw new Error(`${name}: not the library cell Ledger's app has`)
}
/** A jetton wallet's address, as its master works it out: its first state (status 0, balance 0,
 * its owner and master) with the master's wallet code. */
function jettonWallet(name, owner) {
  const { master, code } = JETTONS[name]
  const data = beginCell().storeUint(0, 4).storeCoins(0).storeAddress(owner).storeAddress(master).endCell()
  return contractAddress(0, { code, data })
}
/** What the master itself says, asked over toncenter: its `get_wallet_address`. */
async function chainSays(name, owner) {
  await new Promise((r) => setTimeout(r, 1200))
  const body = { address: JETTONS[name].master.toString(), method: 'get_wallet_address', stack: [['tvm.Slice', beginCell().storeAddress(owner).endCell().toBoc().toString('base64')]] }
  const r = await fetch('https://toncenter.com/api/v2/runGetMethod', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  const j = await r.json()
  if (!j.ok || j.result.exit_code !== 0) throw new Error(`toncenter: ${JSON.stringify(j)}`)
  return Cell.fromBase64(j.result.stack[0][1].bytes).beginParse().loadAddress()
}

// --- the accounts ---
const accounts = []
const me = {}
for (const [network, account] of [[0, 0], [0, 1], [1, 0], [0, 7]]) {
  const kp = await keys(network, account)
  const w = wallets(kp.publicKey, network)
  const entry = {
    network,
    account,
    path: `m/${ledgerPath(network, account).map((n) => n + "'").join('/')}`,
    public_key: hex(kp.publicKey),
    v4R2: forms(w.v4R2.address, network),
    v5R1: forms(w.v5R1.address, network)
  }
  if (network === 0 && account === 0) {
    entry.jettons = {}
    for (const name of Object.keys(JETTONS)) {
      entry.jettons[name] = {}
      for (const version of ['v4R2', 'v5R1']) {
        const ours = jettonWallet(name, w[version].address)
        const theirs = await chainSays(name, w[version].address)
        if (!ours.equals(theirs)) throw new Error(`${name}: the chain says ${theirs}, not ${ours}`)
        entry.jettons[name][version] = ours.toRawString()
      }
    }
  }
  accounts.push(entry)
  me[`${network}/${account}`] = { kp, w }
}

// --- others: a wallet (v4R2 of the key whose seed is 32 ones), a contract, a masterchain one ---
const RECIPIENT = WalletContractV4.create({ workchain: 0, publicKey: keyPairFromSeed(Buffer.alloc(32, 1)).publicKey }).address
const CONTRACT = new Address(0, Buffer.alloc(32, 0x22))
const MASTERCHAIN = new Address(-1, Buffer.alloc(32, 0x33))
const STRANGER = new Address(0, Buffer.alloc(32, 0x44))
const PLUGIN = new Address(0, Buffer.alloc(32, 0x55))
const UNTIL = 1798761600 // 2027-01-01 00:00:00 UTC
const SEQNO = 7

/** TEP-74's transfer, written with @ton/core's builders as its TL-B has it. */
function jettonTransfer({ amount, to, response, custom = null, forwardTon = 0n, forward = null, forwardInline = false, queryId = 0n }) {
  const b = beginCell().storeUint(0x0f8a7ea5, 32).storeUint(queryId, 64).storeCoins(amount).storeAddress(to).storeAddress(response).storeMaybeRef(custom).storeCoins(forwardTon)
  if (forwardInline) {
    b.storeBit(0)
    if (forward) b.storeSlice(forward.beginParse())
  } else if (forward) {
    b.storeBit(1).storeRef(forward)
  } else {
    b.storeBit(0)
  }
  return b.endCell()
}

/** TEP-62's NFT transfer: a payload maki doesn't read. */
const nftTransfer = beginCell().storeUint(0x5fcc3d14, 32).storeUint(0, 64).storeAddress(RECIPIENT).storeAddress(null).storeBit(0).storeCoins(1n).storeBit(0).endCell()
/** An encrypted comment's shape (its op and some bytes): maki can't read one. */
const encrypted = beginCell().storeUint(0x2167da4b, 32).storeBuffer(Buffer.alloc(48, 0xab)).endCell()
/** A contract's code and data maki can't read. */
const someCode = beginCell().storeUint(0xdeadbeef, 32).endCell()
const someData = beginCell().storeUint(42, 64).endCell()
const someInit = { code: someCode, data: someData }

const transactions = []
/** Signs what `build` makes with this account's `version` wallet on `network`, as @ton/ton signs
 * it with a signer, and keeps everything. */
async function add(name, network, version, build, { account = 0, seqno = SEQNO } = {}) {
  const { kp, w } = me[`${network}/${account}`]
  const wallet = w[version]
  let signing = null
  const signer = async (cell) => {
    signing = cell
    return sign(cell.hash(), kp.secretKey)
  }
  const body = await build(wallet, { seqno, signer, kp })
  if (!signing) throw new Error(`${name}: nothing was signed`)
  const signature = version === 'v4R2' ? body.bits.substring(0, 512) : body.bits.substring(body.bits.length - 512, 512)
  const sig = Buffer.alloc(64)
  for (let i = 0; i < 512; i++) if (signature.at(i)) sig[i >> 3] |= 0x80 >> (i & 7)
  if (!signVerify(signing.hash(), sig, kp.publicKey)) throw new Error(`${name}: a signature that doesn't check`)
  const ext = beginCell().store(storeMessage(external({ to: wallet.address, init: seqno === 0 ? wallet.init : undefined, body }))).endCell()
  transactions.push({
    name,
    network,
    version,
    account,
    boc: hex(signing.toBoc()),
    hash: hex(signing.hash()),
    signature: hex(sig),
    external: hex(ext.toBoc())
  })
}

/** A transfer of `messages`, each sent with `mode`, as @ton/ton makes it (W5 adds +2 itself). */
const transfer = (messages, mode = SendMode.PAY_GAS_SEPARATELY | SendMode.IGNORE_ERRORS, extra = {}) =>
  (wallet, { seqno, signer }) => wallet.createTransfer({ seqno, signer, messages, sendMode: mode, timeout: UNTIL, ...extra })

const coffee = () => internal({ to: RECIPIENT, value: 1_500_000_000n, bounce: false, body: comment('thanks for the coffee') })
const usdt = (owner, more = {}) => internal({
  to: jettonWallet('USDT', owner),
  value: 50_000_000n,
  bounce: true,
  body: jettonTransfer({ amount: 5_250_000n, to: RECIPIENT, response: owner, forwardTon: 1n, forward: comment('invoice 42'), ...more })
})

for (const version of ['v4R2', 'v5R1']) {
  for (const network of [0, 1]) {
    const mine = me[`${network}/0`].w[version].address
    await add('ton', network, version, transfer([coffee()]))
    await add('bounceable', network, version, transfer([internal({ to: CONTRACT, value: 250_000_000n, bounce: true })]))
    await add('usdt', network, version, transfer([usdt(mine)]))
  }
  const mine = me['0/0'].w[version].address
  const other = me['0/0'].w[version === 'v4R2' ? 'v5R1' : 'v4R2']
  await add('not-inline', 0, version, transfer([internal({ to: jettonWallet('NOT', mine), value: 50_000_000n, body: jettonTransfer({ amount: 1_000_000_000_000n, to: RECIPIENT, response: mine, forwardInline: true }) })]))
  await add('usdt-elsewhere', 0, version, transfer([internal({ to: jettonWallet('USDT', mine), value: 50_000_000n, body: jettonTransfer({ amount: 1n, to: STRANGER, response: STRANGER, custom: beginCell().storeUint(1, 8).endCell(), forwardTon: 10_000_000n, forward: beginCell().storeUint(0x25938561, 32).storeUint(7, 64).endCell() }) })]))
  await add('usdt-binary', 0, version, transfer([usdt(mine, { forward: beginCell().storeUint(0, 32).storeUint(0xff, 8).storeBuffer(Buffer.from('order 1234')).endCell() })]))
  await add('jetton-unknown', 0, version, transfer([internal({ to: STRANGER, value: 50_000_000n, body: jettonTransfer({ amount: 77n, to: RECIPIENT, response: mine }) })]))
  await add('send-all', 0, version, transfer([internal({ to: RECIPIENT, value: 0n, bounce: false })], SendMode.CARRY_ALL_REMAINING_BALANCE | SendMode.DESTROY_ACCOUNT_IF_ZERO))
  await add('send-all-keep', 0, version, transfer([internal({ to: RECIPIENT, value: 0n, bounce: false })], SendMode.CARRY_ALL_REMAINING_BALANCE))
  await add('masterchain', 0, version, transfer([internal({ to: MASTERCHAIN, value: 1_000_000_000n, bounce: true })]))
  await add('long-comment', 0, version, transfer([internal({ to: RECIPIENT, value: 1n, bounce: false, body: comment('A comment longer than a cell holds, so it goes on into the next cell, and the one after that, as TON writes long text: '.repeat(3)) })]))
  await add('encrypted', 0, version, transfer([internal({ to: RECIPIENT, value: 10n, bounce: false, body: encrypted })]))
  await add('nft', 0, version, transfer([internal({ to: CONTRACT, value: 50_000_000n, bounce: true, body: nftTransfer })]))
  await add('deploy', 0, version, transfer([internal({ to: contractAddress(0, someInit), value: 100_000_000n, bounce: false, init: someInit })]))
  await add('deploy-other-wallet', 0, version, transfer([internal({ to: other.address, value: 100_000_000n, bounce: false, init: other.init })]))
  await add('to-self', 0, version, transfer([internal({ to: mine, value: 1n, bounce: false, body: comment('note to self') })]))
  await add('usdt-no-response', 0, version, transfer([usdt(mine, { response: null, forward: null, forwardTon: 0n })]))
  // a comment that isn't UTF-8, and one with a control character: shown in hex
  await add('comment-bytes', 0, version, transfer([internal({ to: RECIPIENT, value: 1n, bounce: false, body: beginCell().storeUint(0, 32).storeBuffer(Buffer.from([0xc3, 0x28, 0x41])).endCell() })]))
  await add('comment-control', 0, version, transfer([internal({ to: RECIPIENT, value: 1n, bounce: false, body: comment('ring\u0007') })]))
  await add('extra-currency', 0, version, transfer([internal({ to: RECIPIENT, value: 1n, bounce: false, extracurrency: { 100: 5n } })]))
  await add('workchain-1', 0, version, transfer([internal({ to: new Address(1, Buffer.alloc(32, 0x66)), value: 1n, bounce: false })]))
  await add('first', 0, version, transfer([coffee()]), { seqno: 0 })
  await add('no-time-limit', 0, version, transfer([coffee()], undefined, { timeout: 0xffffffff }))
  await add('account-7', 0, version, transfer([coffee()]), { account: 7 })
}

// v4R2: up to four messages, its plugins, nothing at all, and what it doesn't take
const v4 = 'v4R2'
const mine4 = me['0/0'].w.v4R2.address
await add('multi', 0, v4, transfer([coffee(), usdt(mine4), internal({ to: CONTRACT, value: 1n, bounce: true, body: nftTransfer }), internal({ to: RECIPIENT, value: 2n, bounce: false })]))
await add('nothing', 0, v4, transfer([]))
await add('plugin-install', 0, v4, (w, { seqno, signer }) => w.createAddPlugin({ seqno, signer, address: PLUGIN, forwardAmount: 100_000_000n, queryId: 5n, timeout: UNTIL }))
await add('plugin-remove', 0, v4, (w, { seqno, signer }) => w.createRemovePlugin({ seqno, signer, address: PLUGIN, forwardAmount: 50_000_000n, timeout: UNTIL }))
await add('plugin-deploy', 0, v4, (w, { seqno, signer }) => w.createAddAndDeployPlugin({ seqno, signer, workchain: 0, stateInit: someInit, body: beginCell().storeUint(0x6e6f7465, 32).endCell(), forwardAmount: 200_000_000n, timeout: UNTIL }))
/** v4R2's own signing message written by hand with @ton/core, as @ton/ton writes it, but with each
 * message's mode its own (or the bits after it not what the wallet reads). */
function v4By(modes, messages, tail = null, op = 0) {
  return async (w, { seqno, signer }) => {
    const b = beginCell().storeUint(w.walletId, 32).storeUint(UNTIL, 32).storeUint(seqno, 32).storeUint(op, 8)
    messages.forEach((m, i) => b.storeUint(modes[i], 8).storeRef(beginCell().store(storeMessageRelaxed(m))))
    if (tail) tail(b)
    const sig = await signer(b.endCell())
    return beginCell().storeBuffer(sig).storeBuilder(b).endCell()
  }
}
await add('modes', 0, v4, v4By([0, 1, 2, 3], [coffee(), internal({ to: RECIPIENT, value: 2n, bounce: false }), internal({ to: RECIPIENT, value: 3n, bounce: false }), internal({ to: RECIPIENT, value: 4n, bounce: false })]))
await add('mode-64', 0, v4, v4By([64 | 2], [coffee()]))
await add('mode-16', 0, v4, v4By([16 | 3], [coffee()]))
await add('mode-4', 0, v4, v4By([4 | 3], [coffee()]))
await add('mode-192', 0, v4, v4By([192], [coffee()]))
await add('more-bits', 0, v4, v4By([3], [coffee()], (b) => b.storeUint(0, 8)))
await add('op-9', 0, v4, v4By([], [], null, 9))
// another subwallet's: not this account's (another wallet of the same key)
await add('subwallet', 0, v4, async (w, { seqno, signer, kp }) => WalletContractV4.create({ workchain: 0, publicKey: kp.publicKey, walletId: 698983192 }).createTransfer({ seqno, signer, messages: [coffee()], sendMode: 3, timeout: UNTIL }))
// what a v3R2 wallet signs, with the same subwallet: never read as v4R2's
await add('v3r2', 0, v4, async (w, { seqno, signer }) => {
  const b = beginCell().storeUint(698983191, 32).storeUint(UNTIL, 32).storeUint(seqno, 32).storeUint(3, 8).storeRef(beginCell().store(storeMessageRelaxed(coffee())))
  const sig = await signer(b.endCell())
  return beginCell().storeBuffer(sig).storeBuilder(b).endCell()
})

// W5: more messages, its extensions, a request for another to send, and what it refuses
const v5 = 'v5R1'
const mine5 = me['0/0'].w.v5R1.address
const many = (n) => Array.from({ length: n }, (_, i) => internal({ to: RECIPIENT, value: BigInt(i + 1), bounce: false }))
await add('multi', 0, v5, transfer([coffee(), usdt(mine5), internal({ to: CONTRACT, value: 1n, bounce: true, body: nftTransfer }), ...many(4)]))
await add('nothing', 0, v5, (w, { seqno, signer }) => w.createRequest({ seqno, signer, actions: [], timeout: UNTIL }))
await add('extension-add', 0, v5, (w, { seqno, signer }) => w.createAddExtension({ seqno, signer, extensionAddress: PLUGIN, timeout: UNTIL }))
await add('extension-remove', 0, v5, (w, { seqno, signer }) => w.createRemoveExtension({ seqno, signer, extensionAddress: PLUGIN, timeout: UNTIL }))
await add('extensions-and-send', 0, v5, (w, { seqno, signer }) => w.createRequest({ seqno, signer, timeout: UNTIL, actions: [
  { type: 'sendMsg', mode: SendMode.PAY_GAS_SEPARATELY | SendMode.IGNORE_ERRORS, outMsg: coffee() },
  { type: 'addExtension', address: PLUGIN },
  { type: 'removeExtension', address: STRANGER }
] }))
await add('signature-off', 0, v5, (w, { seqno, signer }) => w.createRequest({ seqno, signer, actions: [{ type: 'setIsPublicKeyEnabled', isEnabled: false }], timeout: UNTIL }))
await add('internal', 0, v5, transfer([coffee()], undefined, { authType: 'internal' }))
await add('many', 0, v5, transfer(many(40)))
// as many messages as maki goes through (126: a page each, and two more pages), the same one
await add('most', 0, v5, transfer(Array.from({ length: 126 }, () => internal({ to: RECIPIENT, value: 1n, bounce: false }))))
// more pages than maki's screen goes through: 150 messages, the same one, which a BOC holds once
await add('too-many', 0, v5, transfer(Array.from({ length: 150 }, () => internal({ to: RECIPIENT, value: 1n, bounce: false }))))
// as many pages as maki's screen goes through, but more text than it takes: 63 messages, each
// with a long comment, the same message and comment, which a BOC holds once
await add('too-long', 0, v5, transfer(Array.from({ length: 63 }, () => internal({ to: RECIPIENT, value: 1n, bounce: false, body: comment('x'.repeat(120)) }))))
// more messages than W5 sends: @ton/ton won't make it, so its list is written with @ton/core
await add('256', 0, v5, async (w, { seqno, signer }) => {
  const list = beginCell().store(storeOutList(Array.from({ length: 256 }, () => ({ type: 'sendMsg', mode: 3, outMsg: internal({ to: RECIPIENT, value: 1n, bounce: false }) })))).endCell()
  const b = beginCell().storeUint(0x7369676e, 32).storeUint(w5Id(0), 32).storeUint(UNTIL, 32).storeUint(seqno, 32).storeMaybeRef(list).storeBit(0)
  const sig = await signer(b.endCell())
  return beginCell().storeBuilder(b).storeBuffer(sig).endCell()
})
/** W5's signing message written by hand with @ton/core, as @ton/ton writes it, but with an action's
 * mode as given (@ton/ton adds +2 to every external one; the wallet refuses one without). */
await add('no-ignore-errors', 0, v5, async (w, { seqno, signer }) => {
  const list = beginCell().store(storeOutList([{ type: 'sendMsg', mode: SendMode.PAY_GAS_SEPARATELY, outMsg: coffee() }])).endCell()
  const b = beginCell().storeUint(0x7369676e, 32).storeUint(w5Id(0), 32).storeUint(UNTIL, 32).storeUint(seqno, 32).storeMaybeRef(list).storeBit(0)
  const sig = await signer(b.endCell())
  return beginCell().storeBuilder(b).storeBuffer(sig).endCell()
})
// the test network's W5, asked of the main network's: its wallet ID is the other network's
await add('testnet-id', 1, v5, transfer([coffee()]))

writeFileSync(out, JSON.stringify({
  phrase,
  addresses: [
    // TEP-2's own example: the root DNS contract
    { raw: '-1:e56754f83426f69b09267bd876ac97c44821345b7e266bd956a7bfbfb98df35c', bounceable: 'Ef_lZ1T4NCb2mwkme9h2rJfESCE0W34ma9lWp7-_uY3zXDvq', non_bounceable: 'Uf_lZ1T4NCb2mwkme9h2rJfESCE0W34ma9lWp7-_uY3zXGYv' },
    { name: 'recipient', ...forms(RECIPIENT, 0), test: forms(RECIPIENT, 1) },
    { name: 'contract', ...forms(CONTRACT, 0) },
    { name: 'masterchain', ...forms(MASTERCHAIN, 0) },
    { name: 'stranger', ...forms(STRANGER, 0) },
    { name: 'plugin', ...forms(PLUGIN, 0) },
    { name: 'deployed', ...forms(contractAddress(0, someInit), 0) }
  ],
  accounts,
  transactions
}, null, 1) + '\n')
console.log(`${accounts.length} accounts, ${transactions.length} transactions`)
