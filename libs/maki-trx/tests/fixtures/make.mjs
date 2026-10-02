// Transactions for maki-trx's tests, made with TronWeb (Tron's own JavaScript library), each
// signed as TronWeb signs it by the test phrase's first account, m/44'/195'/0'/0/0 (TronLink's and
// Ledger's): what maki must read, show and sign the same. They're built offline, from the header
// of mainnet's block 86746173, so nothing is fetched. To make them again, in a directory of their
// own:
//   npm install tronweb@6.5.1 && node make.mjs transactions.json
import { writeFileSync } from 'node:fs'
import { TronWeb } from 'tronweb'

const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
// never asked anything: every transaction here is built from the header below, and signed here
const tronWeb = new TronWeb({ fullHost: 'http://127.0.0.1:9' })
const me = TronWeb.fromMnemonic(phrase, "m/44'/195'/0'/0/0")
const key = me.privateKey.replace(/^0x/, '')
if (me.address !== 'TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH') throw new Error('not the account Ledger’s Tron app publishes')
const other = (n) => {
  const k = n.toString(16).padStart(2, '0').repeat(32)
  return { key: k, address: TronWeb.address.fromPrivateKey(k) }
}
const recipient = other(1).address
const spender = other(2).address
const receiver = other(3).address
const stranger = other(4)
const contract = other(5).address
const witness = [other(6).address, other(7).address]
const attacker = other(8).address

const USDT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
const USDD = 'TXDk8mbtRbXeYuMNS83CfKPaYYT8XWv9Hz'
const NILE_USDT = 'TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf'
const TRX = 1_000_000
const MAX = (2n ** 256n - 1n).toString()

// block 86746173: its number's last two bytes, bytes 8 to 16 of its ID, its time; and the
// minute TronWeb gives a transaction when it fetches the header itself
const made = 1790911131000
const header = { ref_block_bytes: 'a43d', ref_block_hash: '93b3e5e6ef2de832', timestamp: made, expiration: made + 60_000 }
const at = (h = {}) => ({ blockHeader: { ...header, ...h } })
const builder = tronWeb.transactionBuilder

const out = []
/** A transaction, signed by `signer`: this account's signature, or none if it isn't its. */
async function add(name, tx, signer = key) {
  const signed = await tronWeb.trx.sign(tx, signer)
  if (signed.txID !== tx.txID) throw new Error(name)
  out.push({ name, raw: tx.raw_data_hex, txid: tx.txID, signature: signer === key ? signed.signature[0] : null })
}
const call = async (to, method, params, options = {}, from = me.address) =>
  (await builder.triggerSmartContract(to, method, { feeLimit: 30 * TRX, txLocal: true, ...at(), ...options }, params, from))
    .transaction
const transfer = (to, amount) => [{ type: 'address', value: to }, { type: 'uint256', value: amount }]

await add('trx', await builder.sendTrx(recipient, 1_500_000, me.address, at()))
await add('memo', await builder.addUpdateData(await builder.sendTrx(recipient, 20 * TRX, me.address, at()), 'thanks for the coffee', 'utf8', { txLocal: true }))
await add('memo-bytes', await builder.addUpdateData(await builder.sendTrx(recipient, 20 * TRX, me.address, at()), 'ff00fe41', 'hex', { txLocal: true }))
await add('usdt', await call(USDT, 'transfer(address,uint256)', transfer(recipient, 5_250_000)))
await add('usdd', await call(USDD, 'transfer(address,uint256)', transfer(recipient, '1500000000000000000')))
await add('usdt-approve', await call(USDT, 'approve(address,uint256)', transfer(spender, 100_000_000)))
await add('usdt-approve-all', await call(USDT, 'approve(address,uint256)', transfer(spender, MAX)))
await add('usdt-revoke', await call(USDT, 'approve(address,uint256)', transfer(spender, 0)))
// another call to a token maki knows, which it can't spell out
await add('usdt-other', await call(USDT, 'transferFrom(address,address,uint256)', [{ type: 'address', value: spender }, ...transfer(recipient, 1)]))
// a token maki doesn't know, and a call it can't read, with TRX and a TRC-10 token sent along
await add('unknown-token', await call(contract, 'transfer(address,uint256)', transfer(recipient, 42)))
await add('contract-call', await call(contract, 'deposit()', [], { feeLimit: 100 * TRX, callValue: 2 * TRX }))
await add('contract-trc10', await call(contract, 'buy()', [], { tokenValue: 5, tokenId: 1002000 }))
await add('nile-usdt', await call(NILE_USDT, 'transfer(address,uint256)', transfer(recipient, 1_000_000)))
await add('trc10', await builder.sendToken(recipient, 42, '1002000', me.address, at()))
await add('stake', await builder.freezeBalanceV2(100 * TRX, 'ENERGY', me.address, at()))
await add('stake-bandwidth', await builder.freezeBalanceV2(50 * TRX, 'BANDWIDTH', me.address, at()))
await add('unstake', await builder.unfreezeBalanceV2(100 * TRX, 'ENERGY', me.address, at()))
await add('withdraw-unstaked', await builder.withdrawExpireUnfreeze(me.address, at()))
await add('cancel-unstaking', await builder.cancelUnfreezeBalanceV2(me.address, at()))
await add('delegate', await builder.delegateResource(100 * TRX, receiver, 'ENERGY', me.address, false, undefined, at()))
await add('delegate-locked', await builder.delegateResource(200 * TRX, receiver, 'BANDWIDTH', me.address, true, 28_800, at()))
// locked without a period: Tron's three days
await add('delegate-locked-3-days', await builder.delegateResource(10 * TRX, receiver, 'ENERGY', me.address, true, undefined, at()))
await add('undelegate', await builder.undelegateResource(100 * TRX, receiver, 'ENERGY', me.address, at()))
await add('vote', await builder.vote({ [witness[0]]: 100, [witness[1]]: 50 }, me.address, at()))
await add('claim-rewards', await builder.withdrawBlockRewards(me.address, at()))
// signed with one of the account's active permissions
await add('active-permission', await builder.sendTrx(recipient, TRX, me.address, { permissionId: 2, ...at() }))
// valid for six hours; for three days, which Tron won't take until the last; expired as it's made
await add('six-hours', await builder.sendTrx(recipient, TRX, me.address, at({ expiration: made + 6 * 3600_000 })))
await add('three-days', await builder.sendTrx(recipient, TRX, me.address, at({ expiration: made + 72 * 3600_000 })))
await add('expired', await builder.sendTrx(recipient, TRX, me.address, at({ expiration: made - 60_000 })))
// what maki refuses: another account's, a hand-over of this one, and kinds it doesn't sign
await add('not-mine', await builder.sendTrx(recipient, TRX, stranger.address, at()), stranger.key)
const owner = { type: 0, permission_name: 'owner', threshold: 1, keys: [{ address: attacker, weight: 1 }] }
const active = {
  type: 2,
  permission_name: 'active',
  threshold: 1,
  operations: '7fff1fc0033e0000000000000000000000000000000000000000000000000000',
  keys: [{ address: attacker, weight: 1 }]
}
await add('permission-update', await builder.updateAccountPermissions(me.address, owner, null, [active], at()))
await add('freeze-v1', await builder.freezeBalance(100 * TRX, 3, 'ENERGY', me.address, undefined, at()))
await add('create-account', await builder.createAccount(recipient, me.address, at()))

writeFileSync(process.argv[2], JSON.stringify(out, null, 1) + '\n')
console.log(out.map((o) => `${o.name}: ${o.raw.length / 2} bytes`).join('\n'))
