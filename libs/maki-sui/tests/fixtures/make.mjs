// Transactions for maki-sui's tests, made with Sui's own TypeScript library (@mysten/sui), each
// signed as it signs them by the test phrase's first account, m/44'/784'/0'/0'/0' (Slush's and
// Ledger's): what maki must read, show and sign the same. Everything is built offline: object
// references, gas and expiration are given here, and where the library looks up what an account
// holds (its coin intents), a stand-in answers with the coins and balances below. To make them
// again, in a directory of their own (the library brings @mysten/bcs 2.1.2 and @noble/hashes
// 2.4.0, which this uses too):
//   npm install @mysten/sui@2.33.2 && node make.mjs transactions.json
import { writeFileSync } from 'node:fs'
import { fromBase58, toBase58, toHex } from '@mysten/bcs'
import { blake2b } from '@noble/hashes/blake2.js'
import { bcs } from '@mysten/sui/bcs'
import { messageWithIntent } from '@mysten/sui/cryptography'
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519'
import { Inputs, Transaction } from '@mysten/sui/transactions'
import { deriveDynamicFieldID } from '@mysten/sui/utils'

const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const account = (i) => Ed25519Keypair.deriveKeypair(phrase, `m/44'/784'/${i}'/0'/0'`)
const key = account(0)
const me = key.toSuiAddress()
const other = (n) => Ed25519Keypair.fromSecretKey(new Uint8Array(32).fill(n))
const recipient = other(1).toSuiAddress()
const second = other(2).toSuiAddress()
const third = other(3).toSuiAddress()
const validator = other(4).toSuiAddress()
const stranger = other(5)
const sponsor = other(6).toSuiAddress()
const spender = other(7).toSuiAddress()
const attacker = other(8).toSuiAddress()

// objects of this account's, by made-up IDs, versions and digests
const id = (n) => '0x' + n.toString(16).padStart(2, '0').repeat(32)
const ref = (n, version = 1000 + n) => ({ objectId: id(n), version: String(version), digest: toBase58(new Uint8Array(32).fill(n)) })
const gas = [ref(0x11), ref(0x12), ref(0x13)]
const coins = [ref(0x21), ref(0x22), ref(0x23)]
const nft = ref(0x31)
const cap = ref(0x32)
const staked = ref(0x33)
const aliases = ref(0x34)
const pkg = id(0x41)
const pool = id(0x42)
const allowance = id(0x43)

const SUI = 1_000_000_000
const MAINNET = '4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S'
const TESTNET = '69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD'
const USDC = '0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC'
const TESTNET_USDC = '0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC'
const STRANGE = `${id(0x44)}::meme::MEME`
const EPOCH = 1268
const validDuring = (chain = MAINNET) => ({
  ValidDuring: { minEpoch: String(EPOCH), maxEpoch: String(EPOCH + 1), minTimestamp: null, maxTimestamp: null, chain, nonce: 0x6d616b69 }
})
const system = () => Inputs.SharedObjectRef({ objectId: '0x5', initialSharedVersion: 1, mutable: true })

// A coin reservation: an address balance passed off as a coin (an ObjectRef) for clients that know
// only coins, as @mysten/sui makes one for gas (utils/coin-reservation.ts, which it doesn't export).
function reservation(owner, coinType, amount, epoch, chain = MAINNET) {
  const key = bcs.Address.serialize(owner).toBytes()
  const field = fromBase58(chain)
  const accumulator = deriveDynamicFieldID('0xacc', `0x2::accumulator::Key<0x2::balance::Balance<${coinType}>>`, key)
  const masked = Uint8Array.from(Buffer.from(accumulator.slice(2), 'hex'), (b, i) => b ^ field[i])
  const digest = new Uint8Array(32)
  const view = new DataView(digest.buffer)
  view.setBigUint64(0, BigInt(amount), true)
  view.setUint32(8, epoch, true)
  digest.fill(0xac, 12)
  return { objectId: '0x' + toHex(masked), version: '0', digest: toBase58(digest), accumulator }
}

// what the library's coin intents look up: this account's coins of a type, and its address balance
function holding({ coins: held = [], addressBalance = 0 }) {
  return {
    core: {
      async getBalance({ coinType }) {
        const coinBalance = held.reduce((sum, c) => sum + BigInt(c.balance), 0n)
        return {
          balance: {
            coinType,
            balance: String(coinBalance + BigInt(addressBalance)),
            coinBalance: String(coinBalance),
            addressBalance: String(addressBalance)
          }
        }
      },
      async listCoins({ coinType }) {
        return { objects: held.map((c) => ({ ...c, type: `0x2::coin::Coin<${coinType}>` })), hasNextPage: false, cursor: null }
      }
    }
  }
}

/** A transaction of this account's, paying for itself from its coins unless it says otherwise. */
function make({ sender = me, payment = [gas[0]], price = 1000, budget = 3_000_000, expiration } = {}) {
  const tx = new Transaction()
  tx.setSender(sender)
  tx.setGasPrice(price)
  tx.setGasBudget(budget)
  // null leaves it for the library to choose: from the address balance, offline
  if (payment !== null) tx.setGasPayment(payment)
  if (expiration) tx.setExpiration(expiration)
  return tx
}

const out = []
/** Builds `tx`, and signs it as this account (or `signer`, whose signature isn't this account's). */
async function add(name, tx, options = {}, signer = key) {
  const bytes = await tx.build(options)
  const digest = blake2b(messageWithIntent('TransactionData', bytes), { dkLen: 32 })
  const { signature } = await signer.signTransaction(bytes)
  const serialized = Buffer.from(signature, 'base64')
  // flag (0, Ed25519), the signature, the key
  if (serialized.length !== 97 || serialized[0] !== 0) throw new Error(name)
  if (Buffer.compare(serialized.subarray(65), Buffer.from(signer.getPublicKey().toRawBytes())) !== 0) throw new Error(name)
  out.push({
    name,
    tx: toHex(bytes),
    digest: toHex(digest),
    signature: signer === key ? toHex(serialized.subarray(1, 65)) : null
  })
}
const offline = { assumeSufficientAddressBalances: true }

// SUI sent from the coins paying the fee, as Slush sends it (the split's whole result), and as the
// library's examples do (its first coin)
{
  const tx = make()
  tx.transferObjects([tx.splitCoins(tx.gas, [1.5 * SUI])], recipient)
  await add('sui', tx)
}
{
  const tx = make()
  const [coin] = tx.splitCoins(tx.gas, [2 * SUI])
  tx.transferObjects([coin], recipient)
  await add('sui-nested', tx)
}
// to several, and two coins to one
{
  const tx = make({ payment: gas.slice(0, 2) })
  const [a, b, c] = tx.splitCoins(tx.gas, [1 * SUI, 2 * SUI, 0.5 * SUI])
  tx.transferObjects([a], recipient)
  tx.transferObjects([b], second)
  tx.transferObjects([c], third)
  await add('sui-many', tx)
}
{
  const tx = make()
  const [a, b] = tx.splitCoins(tx.gas, [1 * SUI, 2 * SUI])
  tx.transferObjects([a, b], recipient)
  await add('sui-together', tx)
}
// everything: the coins paying the fee, whole; and with two more of its coins merged in first
{
  const tx = make({ payment: gas })
  tx.transferObjects([tx.gas], recipient)
  await add('sui-all', tx)
}
{
  const tx = make()
  tx.mergeCoins(tx.gas, [tx.object(Inputs.ObjectRef(coins[0])), tx.object(Inputs.ObjectRef(coins[1]))])
  tx.transferObjects([tx.gas], recipient)
  await add('sui-all-merged', tx)
}
// coins merged, and nothing sent
{
  const tx = make()
  tx.mergeCoins(tx.gas, [tx.object(Inputs.ObjectRef(coins[0])), tx.object(Inputs.ObjectRef(coins[1]))])
  await add('merge', tx)
}
// objects, which the transaction doesn't say what they are
{
  const tx = make()
  tx.transferObjects([tx.object(Inputs.ObjectRef(nft))], recipient)
  await add('object', tx)
}
{
  const tx = make()
  tx.transferObjects([tx.object(Inputs.ObjectRef(nft)), tx.object(Inputs.ObjectRef(cap))], second)
  await add('objects', tx)
}
// a token from coins, which the transaction doesn't name...
{
  const tx = make()
  const primary = tx.object(Inputs.ObjectRef(coins[0]))
  tx.mergeCoins(primary, [tx.object(Inputs.ObjectRef(coins[1]))])
  const [part] = tx.splitCoins(primary, [5_250_000])
  tx.transferObjects([part], recipient)
  await add('token-coins', tx)
}
// ...unless a call does: into the recipient's address balance
{
  const tx = make()
  const primary = tx.object(Inputs.ObjectRef(coins[0]))
  tx.mergeCoins(primary, [tx.object(Inputs.ObjectRef(coins[1]))])
  const [part] = tx.splitCoins(primary, [5_250_000])
  tx.moveCall({ target: '0x2::coin::send_funds', typeArguments: [USDC], arguments: [part, tx.pure.address(recipient)] })
  await add('token-send-funds', tx)
}
// the library's own coin intent, for a token held as coins: they add up exactly (and the empty
// coin left is destroyed, by its type), they're more than enough (and what's left stays), or the
// address balance makes up the rest (and what's left goes back to it)
{
  const tx = make()
  tx.transferObjects([tx.coin({ type: USDC, balance: 5_250_000 })], recipient)
  const held = [{ ...coins[0], balance: '5000000' }, { ...coins[1], balance: '250000' }]
  await add('token-exact', tx, { client: holding({ coins: held }) })
}
{
  const tx = make()
  tx.transferObjects([tx.coin({ type: USDC, balance: 5_250_000 })], recipient)
  const held = [{ ...coins[0], balance: '9000000' }]
  await add('token-surplus', tx, { client: holding({ coins: held }) })
}
{
  const tx = make()
  tx.transferObjects([tx.coin({ type: USDC, balance: 5_250_000 })], recipient)
  const held = [{ ...coins[0], balance: '5000000' }]
  await add('token-mixed', tx, { client: holding({ coins: held, addressBalance: 1_000_000 }) })
}
// SUI from the address balance, as the library sends it when that's where the SUI is, its fee
// paid from there too: a coin, two coins to two, a balance into the recipient's address balance
{
  const tx = make({ payment: null, expiration: validDuring() })
  tx.transferObjects([tx.coin({ balance: 1.5 * SUI })], recipient)
  await add('ab-sui', tx, offline)
}
{
  const tx = make({ payment: null, expiration: validDuring() })
  tx.transferObjects([tx.coin({ balance: 1 * SUI })], recipient)
  tx.transferObjects([tx.coin({ balance: 2 * SUI })], second)
  await add('ab-many', tx, offline)
}
{
  const tx = make({ payment: null, expiration: validDuring() })
  tx.moveCall({ target: '0x2::balance::send_funds', typeArguments: ['0x2::sui::SUI'], arguments: [tx.balance({ balance: 1 * SUI }), tx.pure.address(recipient)] })
  await add('ab-send-funds', tx, offline)
}
// USDC from the address balance, the fee in SUI; and with no fee at all, as Sui lets stablecoins go
{
  const tx = make({ payment: null, expiration: validDuring() })
  tx.transferObjects([tx.coin({ type: USDC, balance: 5_250_000 })], recipient)
  await add('ab-usdc', tx, offline)
}
{
  const tx = make({ payment: [], price: 0, budget: 0, expiration: validDuring() })
  tx.moveCall({ target: '0x2::balance::send_funds', typeArguments: [USDC], arguments: [tx.balance({ type: USDC, balance: 5_250_000 }), tx.pure.address(recipient)] })
  await add('gasless-usdc', tx, offline)
}
// a token maki doesn't know, by its type
{
  const tx = make({ payment: null, expiration: validDuring() })
  tx.moveCall({ target: '0x2::balance::send_funds', typeArguments: [STRANGE], arguments: [tx.balance({ type: STRANGE, balance: 42 }), tx.pure.address(recipient)] })
  await add('ab-strange', tx, offline)
}
// the address balance as a coin: in the gas payment, as the library pays when a transaction uses the
// gas coin and there's SUI in the address balance; and as a coin of its own, for older clients
{
  const reserved = reservation(me, '0x2::sui::SUI', 2 * SUI, EPOCH)
  const tx = make({ payment: [{ objectId: reserved.objectId, version: reserved.version, digest: reserved.digest }, gas[0]] })
  tx.transferObjects([tx.splitCoins(tx.gas, [1.5 * SUI])], recipient)
  await add('reservation-gas', tx)
}
{
  const reserved = reservation(me, '0x2::sui::SUI', 3 * SUI, EPOCH)
  const tx = make()
  const coin = tx.object(Inputs.ObjectRef({ objectId: reserved.objectId, version: reserved.version, digest: reserved.digest }))
  tx.transferObjects([tx.splitCoins(coin, [1 * SUI])], recipient)
  await add('reservation-input', tx)
}
// staking and unstaking
{
  const tx = make()
  tx.moveCall({ target: '0x3::sui_system::request_add_stake', arguments: [tx.object(system()), tx.splitCoins(tx.gas, [1 * SUI]), tx.pure.address(validator)] })
  await add('stake', tx)
}
{
  const tx = make()
  tx.moveCall({ target: '0x3::sui_system::request_withdraw_stake', arguments: [tx.object(system()), tx.object(Inputs.ObjectRef(staked))] })
  await add('unstake', tx)
}
// calls maki can't read: given SUI and a shared object; given this account's objects and the gas
// coin; an object sent to one of this account's, received; coins in a vector
{
  const tx = make()
  const [coin] = tx.splitCoins(tx.gas, [3 * SUI])
  const [out] = tx.moveCall({
    target: `${pkg}::market::buy`,
    typeArguments: [USDC],
    arguments: [tx.object(Inputs.SharedObjectRef({ objectId: pool, initialSharedVersion: 77, mutable: true })), coin, tx.pure.u64(42)]
  })
  tx.transferObjects([out], me)
  await add('move-call', tx)
}
{
  const tx = make()
  tx.moveCall({ target: `${pkg}::vault::deposit`, arguments: [tx.object(Inputs.ObjectRef(nft)), tx.object(Inputs.ObjectRef(coins[0])), tx.gas] })
  await add('move-call-objects', tx)
}
{
  const tx = make()
  tx.moveCall({ target: '0x2::transfer::public_receive', typeArguments: [`${pkg}::ticket::Ticket`], arguments: [tx.object(Inputs.ObjectRef(nft)), tx.object(Inputs.ReceivingRef(ref(0x35)))] })
  await add('receiving', tx)
}
{
  const tx = make()
  const [a, b] = tx.splitCoins(tx.gas, [1 * SUI, 1 * SUI])
  const vec = tx.makeMoveVec({ elements: [a, b] })
  tx.moveCall({ target: `${pkg}::pot::fill`, arguments: [vec] })
  await add('move-vec', tx)
}
// when it expires: after an epoch; in the epochs a test network names; restricted to proposers
{
  const tx = make({ expiration: { Epoch: '1300' } })
  tx.transferObjects([tx.splitCoins(tx.gas, [1 * SUI])], recipient)
  await add('epoch', tx)
}
{
  const tx = make({ payment: null, expiration: validDuring(TESTNET) })
  tx.transferObjects([tx.coin({ balance: 1 * SUI })], recipient)
  await add('testnet', tx, offline)
}
{
  const tx = make({ payment: null, expiration: validDuring(TESTNET) })
  tx.transferObjects([tx.coin({ type: TESTNET_USDC, balance: 1_000_000 })], recipient)
  await add('testnet-usdc', tx, offline)
}
{
  const tx = make({
    payment: null,
    expiration: { Validity: { ...validDuring().ValidDuring, allowedProposers: { epoch: String(EPOCH), proposers: [3, 17, 40] } } }
  })
  tx.transferObjects([tx.coin({ balance: 1 * SUI })], recipient)
  await add('validity', tx, offline)
}
// nothing but the fee
await add('empty', make())
// what maki refuses: another account's; another's to pay for; this one paying for another's
{
  const tx = make({ sender: stranger.toSuiAddress(), payment: [ref(0x51)] })
  tx.transferObjects([tx.splitCoins(tx.gas, [1 * SUI])], recipient)
  await add('not-mine', tx, {}, stranger)
}
{
  const tx = make({ payment: [ref(0x52)] })
  tx.setGasOwner(sponsor)
  tx.transferObjects([tx.object(Inputs.ObjectRef(nft))], recipient)
  await add('sponsored', tx)
}
{
  const tx = make({ sender: stranger.toSuiAddress() })
  tx.setGasOwner(me)
  tx.transferObjects([tx.splitCoins(tx.gas, [1 * SUI])], attacker)
  await add('sponsor-only', tx, {}, stranger)
}
// code, published and upgraded
{
  const tx = make()
  const [upgradeCap] = tx.publish({ modules: [[0xa1, 0x1c, 0xeb, 0x0b, 6, 0, 0, 0]], dependencies: ['0x1', '0x2'] })
  tx.transferObjects([upgradeCap], me)
  await add('publish', tx)
}
{
  const tx = make()
  const upgradeCap = tx.object(Inputs.ObjectRef(cap))
  const ticket = tx.moveCall({ target: '0x2::package::authorize_upgrade', arguments: [upgradeCap, tx.pure.u8(0), tx.pure.vector('u8', new Uint8Array(32).fill(9))] })
  const receipt = tx.upgrade({ modules: [[0xa1, 0x1c, 0xeb, 0x0b, 6, 0, 0, 0]], dependencies: ['0x1', '0x2'], package: pkg, ticket })
  tx.moveCall({ target: '0x2::package::commit_upgrade', arguments: [upgradeCap, receipt] })
  await add('upgrade', tx)
}
// another key made able to sign for this account; another account let spend from it; spending
// another's under an allowance
{
  const tx = make()
  tx.moveCall({ target: '0x2::address_alias::add', arguments: [tx.object(Inputs.SharedObjectRef({ objectId: aliases.objectId, initialSharedVersion: 5, mutable: true })), tx.pure.address(attacker)] })
  await add('alias-add', tx)
}
{
  const tx = make()
  tx.moveCall({
    target: '0x2::allowance::new',
    typeArguments: ['0x2::balance::Balance<0x2::sui::SUI>'],
    arguments: [tx.pure.string('maki test'), tx.pure.address(spender), tx.pure.option('u256', 100n * BigInt(SUI)), tx.pure.option('u64', null), tx.pure.option('u64', 1_800_000_000_000), tx.pure.option('u64', null)]
  })
  await add('allowance-new', tx)
}
{
  const tx = make()
  const withdrawal = tx.withdrawal({ amount: 1 * SUI, from: 'allowance', funder: second, allowance })
  tx.transferObjects([tx.moveCall({ target: '0x2::coin::redeem_funds', typeArguments: ['0x2::sui::SUI'], arguments: [withdrawal] })], recipient)
  await add('allowance-spend', tx)
}

const accounts = [0, 1, 2].map((i) => {
  const k = account(i)
  return { index: i, address: k.toSuiAddress(), key: toHex(k.getPublicKey().toRawBytes()) }
})
if (accounts[0].address !== me) throw new Error('not the first account')
const sui = reservation(me, '0x2::sui::SUI', 1, EPOCH)
const usdc = reservation(me, USDC, 1, EPOCH)
const fixtures = {
  accounts,
  // the field of the address-balance accumulator (0xacc) that holds this account's SUI, and its USDC
  accumulators: { sui: sui.accumulator, usdc: usdc.accumulator },
  transactions: out
}
writeFileSync(process.argv[2], JSON.stringify(fixtures, null, 1) + '\n')
console.log(out.map((o) => `${o.name}: ${o.tx.length / 2} bytes`).join('\n'))
