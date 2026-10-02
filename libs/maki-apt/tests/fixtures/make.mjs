// Transactions for maki-apt's tests, made with Aptos's own TypeScript SDK, each signed as the SDK
// signs it by the test phrase's first account, m/44'/637'/0'/0'/0' (Petra's and Ledger's): what
// maki must read, show and sign the same. Everything is built offline, with the sequence number,
// gas, expiry and chain explicit and every function's ABI given, so nothing is fetched (the
// fullnode below is nowhere). To make them again, in a directory of their own:
//   npm install @aptos-labs/ts-sdk@7.3.0 && node make.mjs transactions.json
import { writeFileSync } from 'node:fs'
import {
  Account,
  AccountAddress,
  Aptos,
  AptosConfig,
  Ed25519PrivateKey,
  Network,
  TypeTagAddress,
  TypeTagU64,
  TypeTagU8,
  generateSignedTransaction,
  generateSigningMessageForTransaction,
  generateUserTransactionHash,
  parseTypeTag
} from '@aptos-labs/ts-sdk'

const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const path = (i) => `m/44'/637'/${i}'/0'/0'`
const me = Account.fromDerivationPath({ path: path(0), mnemonic })
if (me.accountAddress.toString() !== '0xeb663b681209e7087d681c5d3eed12aaa8e1915e7c87794542c3f96e94b3d3bf') {
  throw new Error('not the account Petra makes from the test phrase')
}
const accounts = [0, 1, 2].map((i) => {
  const a = Account.fromDerivationPath({ path: path(i), mnemonic })
  return { index: i, path: path(i), publicKey: a.publicKey.toString(), address: a.accountAddress.toString() }
})
// accounts of keys 0x0101..., 0x0202..., for the others in these transactions
const other = (n) => Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(n.toString(16).padStart(2, '0').repeat(32)) })
const recipient = other(1).accountAddress
const second = other(2).accountAddress
const pool = other(3).accountAddress
const stranger = other(4)
const object = other(5).accountAddress
const issuer = other(6).accountAddress
const dex = other(7).accountAddress
const attacker = other(8)

const USDC = '0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b'
const USDT = '0x357b0b74bc833e95a115ad22604854d6b0fca151cecd94111770e5d6ffc9dc2b'
const TESTNET_USDC = '0x69091fbab5f7d635ee7ac5098cf0c1efbe31d68fec0f2cd565e8d168daf52832'
const LZ_USDC = '0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa::asset::USDC'
const LZ_USDT = '0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa::asset::USDT'
const APT = 100_000_000

// 2026-10-02 04:00:00 UTC, and the 20 seconds the SDK gives a transaction to live
const made = 1790913600
const options = (o = {}) => ({ accountSequenceNumber: 7, maxGasAmount: 2000, gasUnitPrice: 100, expireTimestamp: made + 20, ...o })
// a fullnode nowhere: anything the SDK fetched would fail
const client = (network) => new Aptos(new AptosConfig({ network, fullnode: 'http://127.0.0.1:9/v1', indexer: 'http://127.0.0.1:9/v1/graphql' }))
const mainnet = client(Network.MAINNET)
const testnet = client(Network.TESTNET)

const T = (s) => parseTypeTag(s, { allowGenerics: true })
const abi = (types, parameters) => ({ typeParameters: Array.from({ length: types }, () => ({ constraints: [] })), parameters: parameters.map(T) })
const payments = abi(0, ['address', 'u64'])
const coinPayments = abi(1, ['address', 'u64'])
const batch = abi(0, ['vector<address>', 'vector<u64>'])
const coinBatch = abi(1, ['vector<address>', 'vector<u64>'])
const fa = abi(1, ['0x1::object::Object<T0>', 'address', 'u64'])
const faMetadata = abi(0, ['0x1::object::Object<0x1::fungible_asset::Metadata>', 'address', 'u64'])
const faBatch = abi(0, ['0x1::object::Object<0x1::fungible_asset::Metadata>', 'vector<address>', 'vector<u64>'])

const out = []
/** A transaction, with this account's signature if it's this account's (`signer` signs it otherwise). */
function add(name, network, tx, signer = me) {
  const message = generateSigningMessageForTransaction(tx)
  const senderAuthenticator = (network === 1 ? testnet : mainnet).transaction.sign({ signer, transaction: tx })
  const signature = senderAuthenticator.signature.toUint8Array()
  if (!signer.publicKey.verifySignature({ message, signature: senderAuthenticator.signature })) throw new Error(name)
  const mine = signer === me
  const hex = (b) => Buffer.from(b).toString('hex')
  out.push({
    name,
    network,
    raw: hex(tx.rawTransaction.bcsToBytes()),
    message: hex(message),
    signature: mine ? hex(signature) : null,
    signed: mine ? hex(generateSignedTransaction({ transaction: tx, senderAuthenticator })) : null,
    hash: mine ? generateUserTransactionHash({ transaction: tx, senderAuthenticator }).replace(/^0x/, '') : null
  })
}
const call = (aptos, data, o = {}, sender = me.accountAddress) =>
  aptos.transaction.build.simple({ sender, data, options: options(o) })

// APT: aptos_account::transfer, and the SDK's own coin transfer (transfer_coins<AptosCoin>)
add('apt', 0, await call(mainnet, { function: '0x1::aptos_account::transfer', functionArguments: [recipient, 150_000_000], abi: payments }))
add('apt-coins', 0, await mainnet.transferCoinTransaction({ sender: me.accountAddress, recipient, amount: 25_000_000, options: options() }))
add('apt-coin-transfer', 0, await call(mainnet, { function: '0x1::coin::transfer', typeArguments: ['0x1::aptos_coin::AptosCoin'], functionArguments: [recipient, APT], abi: coinPayments }))
// coins by their type: LayerZero's USDC, one maki doesn't know, and one named as APT is, at another address
add('lzusdc', 0, await call(mainnet, { function: '0x1::coin::transfer', typeArguments: [LZ_USDC], functionArguments: [recipient, 5_250_000], abi: coinPayments }))
add('coin-unknown', 0, await call(mainnet, { function: '0x1::aptos_account::transfer_coins', typeArguments: [`${issuer}::meme::MEME`], functionArguments: [recipient, 42], abi: coinPayments }))
add('coin-lookalike', 0, await call(mainnet, { function: '0x1::aptos_account::transfer_coins', typeArguments: [`${issuer}::aptos_coin::AptosCoin`], functionArguments: [recipient, APT], abi: coinPayments }))
// fungible assets by their metadata: the SDK's own transfer (primary_fungible_store::transfer), and
// aptos_account's; USDC, USDT, APT's own, and one maki doesn't know
add('usdc', 0, await mainnet.transferFungibleAsset({ sender: me, fungibleAssetMetadataAddress: USDC, recipient, amount: 5_250_000, options: options() }))
add('usdt', 0, await call(mainnet, { function: '0x1::aptos_account::transfer_fungible_assets', functionArguments: [USDT, recipient, 100_000_000], abi: faMetadata }))
add('apt-fa', 0, await call(mainnet, { function: '0x1::primary_fungible_store::transfer', typeArguments: ['0x1::fungible_asset::Metadata'], functionArguments: ['0xa', recipient, 2 * APT], abi: fa }))
add('fa-unknown', 0, await mainnet.transferFungibleAsset({ sender: me, fungibleAssetMetadataAddress: issuer, recipient, amount: 42, options: options() }))
// several payments at once
add('batch-apt', 0, await call(mainnet, { function: '0x1::aptos_account::batch_transfer', functionArguments: [[recipient, second], [APT, 2 * APT]], abi: batch }))
add('batch-usdc', 0, await call(mainnet, { function: '0x1::aptos_account::batch_transfer_fungible_assets', functionArguments: [USDC, [recipient, second], [1_000_000, 2_500_000]], abi: faBatch }))
add('batch-lzusdt', 0, await call(mainnet, { function: '0x1::aptos_account::batch_transfer_coins', typeArguments: [LZ_USDT], functionArguments: [[recipient, second], [1_000_000, 3_000_000]], abi: coinBatch }))
// to itself
add('self', 0, await call(mainnet, { function: '0x1::aptos_account::transfer', functionArguments: [me.accountAddress, APT], abi: payments }))
// staking with a delegation pool
for (const [name, fn, amount] of [['stake', 'add_stake', 100 * APT], ['unlock', 'unlock', 50 * APT], ['reactivate', 'reactivate_stake', 50 * APT], ['withdraw', 'withdraw', 50 * APT]]) {
  add(name, 0, await call(mainnet, { function: `0x1::delegation_pool::${fn}`, functionArguments: [pool, amount], abi: payments }))
}
// an object handed over: a digital asset (an NFT), and any object by its address
add('nft', 0, await call(mainnet, { function: '0x1::object::transfer', typeArguments: ['0x4::token::Token'], functionArguments: [object, recipient], abi: abi(1, ['0x1::object::Object<T0>', 'address']) }))
add('object', 0, await call(mainnet, { function: '0x1::object::transfer_call', functionArguments: [object, recipient], abi: abi(0, ['address', 'address']) }))
// a call maki can't read: a swap on an exchange it doesn't know
add('swap', 0, await call(mainnet, {
  function: `${dex}::router::swap_exact_input`,
  typeArguments: ['0x1::aptos_coin::AptosCoin', `${issuer}::meme::MEME`],
  functionArguments: [APT, 1_000_000, recipient],
  abi: abi(2, ['u64', 'u64', 'address'])
}))
// on the test network
add('testnet-apt', 1, await call(testnet, { function: '0x1::aptos_account::transfer', functionArguments: [recipient, 150_000_000], abi: payments }))
add('testnet-usdc', 1, await testnet.transferFungibleAsset({ sender: me, fungibleAssetMetadataAddress: TESTNET_USDC, recipient, amount: 1_000_000, options: options() }))
// orderless: a nonce rather than a sequence number (the newer payload)
add('orderless', 0, await call(mainnet, { function: '0x1::aptos_account::transfer', functionArguments: [recipient, APT], abi: payments }, { accountSequenceNumber: undefined, replayProtectionNonce: 7_777_777n }))
// the SDK's own most gas, when it isn't told: 2,000,000 units
add('default-gas', 0, await call(mainnet, { function: '0x1::aptos_account::transfer', functionArguments: [recipient, APT], abi: payments }, { maxGasAmount: undefined }))
// valid for three days, and forever
add('three-days', 0, await call(mainnet, { function: '0x1::aptos_account::transfer', functionArguments: [recipient, APT], abi: payments }, { expireTimestamp: made + 3 * 86400 }))
add('forever', 0, await call(mainnet, { function: '0x1::aptos_account::transfer', functionArguments: [recipient, APT], abi: payments }, { expireTimestamp: 2n ** 64n - 1n }))
// what maki refuses: another account's; whatever would hand this account to another; kinds of
// payload it doesn't sign
add('not-mine', 0, await call(mainnet, { function: '0x1::aptos_account::transfer', functionArguments: [recipient, APT], abi: payments }, {}, stranger.accountAddress), stranger)
add('rotate', 0, await call(mainnet, { function: '0x1::account::rotate_authentication_key_call', functionArguments: [attacker.accountAddress.toUint8Array()], abi: abi(0, ['vector<u8>']) }))
add('offer-signer', 0, await call(mainnet, {
  function: '0x1::account::offer_signer_capability',
  functionArguments: [new Uint8Array(64), 0, me.publicKey.toUint8Array(), attacker.accountAddress],
  abi: { typeParameters: [], parameters: [T('vector<u8>'), new TypeTagU8(), T('vector<u8>'), new TypeTagAddress()] }
}))
add('abstraction', 0, await call(mainnet, {
  function: '0x1::account_abstraction::add_authentication_function',
  functionArguments: [attacker.accountAddress, 'auth', 'authenticate'],
  abi: abi(0, ['address', '0x1::string::String', '0x1::string::String'])
}))
add('multisig-convert', 0, await call(mainnet, {
  function: '0x1::multisig_account::create_with_existing_account_and_revoke_auth_key_call',
  functionArguments: [[attacker.accountAddress], 1, [], []],
  abi: { typeParameters: [], parameters: [T('vector<address>'), new TypeTagU64(), T('vector<0x1::string::String>'), T('vector<vector<u8>>')] }
}))
add('script', 0, await mainnet.transaction.build.simple({ sender: me.accountAddress, data: { bytecode: 'a11ceb0b0700000a', functionArguments: [] }, options: options() }))
add('multisig', 0, await call(mainnet, { multisigAddress: AccountAddress.from(dex), function: '0x1::aptos_account::transfer', functionArguments: [recipient, APT], abi: payments }))

writeFileSync(process.argv[2], JSON.stringify({ accounts, transactions: out }, null, 1) + '\n')
console.log(out.map((o) => `${o.name}: ${o.raw.length / 2} bytes`).join('\n'))
