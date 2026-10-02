// Transactions for maki-near's tests, made with NEAR's own JavaScript library (near-api-js), each
// serialized as near-api-js serializes it and signed as it signs it (Ed25519 over the SHA-256 of
// the transaction's borsh bytes) by the test phrase's account at m/44'/397'/0', the key
// MyNearWallet, near-cli and Trust Wallet make from a phrase: what maki must read, show and sign
// the same. They're built offline, naming a final block of each network, so nothing is fetched.
// To make them again, in a directory of their own:
//   npm install near-api-js@7.3.1 @noble/hashes@2.2.0 @noble/post-quantum@0.6.1 && node make.mjs transactions.json
// (the two @noble packages at the versions near-api-js 7.3.1 itself takes, with @noble/curves 2.2.0,
// borsh 2.0.0, and near-seed-phrase 0.2.1, which it derives a phrase's key with.)
import { createHmac, pbkdf2Sync } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { sha256 } from '@noble/hashes/sha2.js'
import { sha3_256 } from '@noble/hashes/sha3.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import {
  KeyPairEd25519,
  KeyPairSecp256k1,
  KeyPairSigner,
  PublicKey,
  actions,
  baseDecode,
  baseEncode,
  buildDelegateAction,
  createTransaction,
  encodeTransaction,
  keyToImplicitAddress,
  nearToYocto,
  teraToGas
} from 'near-api-js'
import { parseSeedPhrase } from 'near-api-js/seed-phrase'

const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const hex = (b) => Buffer.from(b).toString('hex')

/** The Ed25519 seed at `path` (every step hardened), by SLIP-10, as near-hd-key derives it. */
function slip10(words, path) {
  const seed = pbkdf2Sync(Buffer.from(words), Buffer.from('mnemonic'), 2048, 64, 'sha512')
  const hmac = (k, d) => createHmac('sha512', k).update(d).digest()
  let i = hmac(Buffer.from('ed25519 seed'), seed)
  for (const n of path) {
    const b = Buffer.alloc(4)
    b.writeUInt32BE((n | 0x80000000) >>> 0)
    i = hmac(i.subarray(32), Buffer.concat([Buffer.from([0]), i.subarray(0, 32), b]))
  }
  return i.subarray(0, 32)
}
const ed25519 = (seed) => new KeyPairEd25519(baseEncode(seed))

// the account, as near-seed-phrase (MyNearWallet's, and near-api-js's parseSeedPhrase) makes it,
// and the next ones as maki counts them, at m/44'/397'/i'
const accounts = [0, 1, 2].map((i) => {
  const key = ed25519(slip10(phrase, [44, 397, i]))
  return { index: i, path: `m/44'/397'/${i}'`, public_key: key.getPublicKey().toString(), account_id: keyToImplicitAddress(key.getPublicKey()) }
})
const me = ed25519(slip10(phrase, [44, 397, 0]))
if (parseSeedPhrase(phrase).getPublicKey().toString() !== me.getPublicKey().toString()) throw new Error('not near-seed-phrase’s key')
// Trust Wallet's wallet-core publishes this phrase's key at the same path (HDWalletTests, NearKey)
const published = ed25519(slip10('owner erupt swamp room swift final allow unaware hint identify figure cotton', [44, 397, 0]))
if (keyToImplicitAddress(published.getPublicKey()) !== 'b8d5df25047841365008f30fb6b30dd820e9a84d869f05623d114e96831f2fbf') throw new Error('not wallet-core’s key')
const ME = keyToImplicitAddress(me.getPublicKey())

const other = (n) => ed25519(new Uint8Array(32).fill(n))
const implicit = keyToImplicitAddress(other(1).getPublicKey())
const stranger = other(6)
const STRANGER = keyToImplicitAddress(stranger.getPublicKey())
const secp256k1 = new KeyPairSecp256k1(baseEncode(new Uint8Array(32).fill(7))).getPublicKey()
const mldsa = new PublicKey({ keyType: 2, data: ml_dsa65.keygen(new Uint8Array(32).fill(8)).publicKey })
// NEAR keeps a post-quantum key only by its hash, and lists it so: nearcore's MlDsa65PublicKeyHandle,
// the SHA3-256 of its domain's tag and the key (near-api-js doesn't make it)
const listed = `ml-dsa-65-hash:${baseEncode(sha3_256(Buffer.concat([Buffer.from('near:ml-dsa-65-pubkey-hash:v1'), mldsa.data])))}`
const ETH = '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'

// a final block of each network on 2026-10-02, and a nonce as a new key's would be after it
const blocks = {
  mainnet: { hash: 'Cf8GRmjFKSM3jnE7BPENs5LNQdhhMbpmJWTaEzg6gfCw', height: 218152378n },
  testnet: { hash: '9FLbsgHebYjbYFDDJ5spbMdMs9CYG4qhkTAK8mtiPN5y', height: 271173758n }
}

const USDC = '17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1'
const USDT = 'usdt.tether-token.near'
const USDC_E = 'a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.factory.bridge.near'
const TESTNET_USDC = '3e2210e1184b45b64c8a434c0a7e7b23cc04ea7eb7a6c3c32520d03d4afcb8af'
const NEAR = (n) => nearToYocto(n)
const yocto = (n) => BigInt(n)
// a token's transfer as near-api-js's FungibleToken makes it: 30 Tgas and 1 yoctoNEAR
const ft = (method, args) => actions.functionCall(method, args, teraToGas(30), 1n)
// the smallest WebAssembly module there is, and one with a function in it
const wasm = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00])
const wasmFn = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0x07, 0x08, 0x01, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00, 0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b])

const out = []
/** A transaction from `signer` to `receiver`, on `network`, signed by `signer`: this account's
 *  signature, or none if it isn't its. */
async function add(name, receiver, list, { network = 'mainnet', signer = me, nonce = 1n } = {}) {
  const block = blocks[network]
  const from = keyToImplicitAddress(signer.getPublicKey())
  const tx = createTransaction(from, signer.getPublicKey(), receiver, block.height * 1_000_000n + nonce, list, baseDecode(block.hash))
  const bytes = encodeTransaction(tx)
  const { txHash, signedTransaction } = await new KeyPairSigner(signer).signTransaction(tx)
  if (hex(txHash) !== hex(sha256(bytes))) throw new Error(name)
  const mine = signer === me
  out.push({
    name,
    network,
    transaction: hex(bytes),
    hash: baseEncode(txHash),
    signature: mine ? hex(signedTransaction.signature.data) : null,
    signed: mine ? hex(signedTransaction.encode()) : null
  })
}

// NEAR sent: to a named account, an implicit one, an Ethereum address's, itself, the least there is
await add('transfer', 'bob.near', [actions.transfer(NEAR('1.5'))])
await add('transfer-implicit', implicit, [actions.transfer(NEAR('0.1'))])
await add('transfer-eth', ETH, [actions.transfer(NEAR('0.25'))])
await add('transfer-self', ME, [actions.transfer(NEAR('1'))])
await add('transfer-yocto', 'bob.near', [actions.transfer(yocto(1))])
// tokens maki knows, as NEP-141 sends them; a memo; to a contract, with a message; 24 decimals;
// a bridged one
await add('usdc', USDC, [ft('ft_transfer', { amount: '5250000', receiver_id: 'bob.near' })])
await add('usdt-memo', USDT, [ft('ft_transfer', { receiver_id: 'bob.near', amount: '10000000', memo: 'invoice 42' })])
await add('usdc-call', USDC, [
  actions.functionCall('ft_transfer_call', { receiver_id: 'v2.ref-finance.near', amount: '100000000', msg: '' }, teraToGas(50), 1n)
])
await add('wnear', 'wrap.near', [ft('ft_transfer', { receiver_id: 'bob.near', amount: '2000000000000000000000000' })])
await add('usdc-bridged', USDC_E, [ft('ft_transfer', { receiver_id: implicit, amount: '1000000' })])
// storage for a token, for another account (as near-api-js's registerAccount pays it) and for this one
await add('storage-deposit', USDC, [
  actions.functionCall('storage_deposit', { account_id: 'bob.near', registration_only: true }, teraToGas(30), NEAR('0.00125'))
])
await add('storage-deposit-self', USDT, [actions.functionCall('storage_deposit', {}, teraToGas(30), NEAR('0.00125'))])
// both in one, as wallets send to an account new to a token
await add('usdc-register-and-send', USDC, [
  actions.functionCall('storage_deposit', { account_id: 'bob.near', registration_only: true }, teraToGas(30), NEAR('0.00125')),
  ft('ft_transfer', { receiver_id: 'bob.near', amount: '5250000' })
])
// a token maki doesn't know
await add('unknown-token', 'token.example.near', [ft('ft_transfer', { receiver_id: 'bob.near', amount: '42' })])
// calls maki can't read: JSON, binary arguments, NEAR sent with one, and wNEAR's contract's own
await add('call', 'v2.ref-finance.near', [
  actions.functionCall('swap', { actions: [{ pool_id: 79, token_in: 'wrap.near', token_out: USDC, amount_in: '1000000000000000000000000', min_amount_out: '1' }] }, teraToGas(100), 1n)
])
await add('call-binary', 'aurora', [actions.functionCall('submit', Uint8Array.from([0xf8, 0x6c, 0x01, 0x84, 0x3b, 0x9a, 0xca, 0x00, 0xff]), teraToGas(300), 0n)])
await add('stake-pool', 'astro-stakers.poolv1.near', [actions.functionCall('deposit_and_stake', {}, teraToGas(50), NEAR('10'))])
await add('wrap', 'wrap.near', [actions.functionCall('near_deposit', {}, teraToGas(10), NEAR('1'))])
// keys: full access, for calls (with an allowance and methods named, and without either), of each kind
await add('add-full-key', ME, [actions.addFullAccessKey(other(2).getPublicKey())])
await add('add-call-key', ME, [actions.addFunctionCallAccessKey(other(3).getPublicKey(), 'v2.ref-finance.near', ['swap', 'withdraw'], NEAR('0.25'))])
await add('add-call-key-any', ME, [actions.addFunctionCallAccessKey(other(4).getPublicKey(), 'app.example.near', [])])
await add('add-secp256k1-key', ME, [actions.addFullAccessKey(secp256k1)])
await add('add-ml-dsa-key', ME, [actions.addFullAccessKey(mldsa)])
await add('delete-key', ME, [actions.deleteKey(other(2).getPublicKey())])
await add('delete-own-key', ME, [actions.deleteKey(me.getPublicKey())])
await add('delete-account', ME, [actions.deleteAccount('bob.near')])
// code: deployed, published (under its hash, and under this account), and used
await add('deploy', ME, [actions.deployContract(wasmFn)])
await add('deploy-global', ME, [actions.deployGlobalContract(wasm, 'codeHash')])
await add('deploy-global-account', ME, [actions.deployGlobalContract(wasm, 'accountId')])
await add('use-global-hash', ME, [actions.useGlobalContract({ codeHash: hex(sha256(wasmFn)) })])
await add('use-global-account', ME, [actions.useGlobalContract({ accountId: 'contracts.example.near' })])
// staking as a validator, and unstaking
await add('stake', ME, [actions.stake(NEAR('100'), other(5).getPublicKey())])
await add('unstake', ME, [actions.stake(0n, other(5).getPublicKey())])
// NEAR sent and a call made in one; and nothing at all
await add('batch', 'bob.near', [actions.transfer(NEAR('1')), actions.functionCall('hello', { name: 'maki' }, teraToGas(10), 0n)])
await add('nothing', 'bob.near', [])
// NEAR's test network
await add('testnet-transfer', 'bob.testnet', [actions.transfer(NEAR('2'))], { network: 'testnet' })
await add('testnet-usdc', TESTNET_USDC, [ft('ft_transfer', { receiver_id: 'bob.testnet', amount: '1000000' })], { network: 'testnet' })
// what maki refuses: another account's; an account made (only its parent can make one); a meta
// transaction relayed for another account
await add('not-mine', 'bob.near', [actions.transfer(NEAR('1'))], { signer: stranger })
await add('create-account', 'new-account.near', [
  actions.createAccount(),
  actions.transfer(NEAR('1')),
  actions.addFullAccessKey(other(2).getPublicKey())
])
const delegate = buildDelegateAction({
  actions: [actions.transfer(NEAR('1'))],
  maxBlockHeight: blocks.mainnet.height + 100n,
  nonce: blocks.mainnet.height * 1_000_000n + 1n,
  publicKey: stranger.getPublicKey(),
  receiverId: 'bob.near',
  senderId: STRANGER
})
const { signedDelegate } = await new KeyPairSigner(stranger).signDelegateAction(delegate)
await add('delegate', STRANGER, [actions.signedDelegate(signedDelegate)])

writeFileSync(
  process.argv[2],
  JSON.stringify(
    {
      accounts,
      keys: {
        implicit,
        stranger: STRANGER,
        secp256k1: secp256k1.toString(),
        ml_dsa: mldsa.toString(),
        ml_dsa_listed: listed,
        other: [2, 3, 4, 5].map((n) => other(n).getPublicKey().toString())
      },
      transactions: out
    },
    null,
    1
  ) + '\n'
)
console.log(out.map((o) => `${o.name}: ${o.transaction.length / 2} bytes`).join('\n'))
