// Sign docs for maki-atom's tests, made with CosmJS (Cosmos's own JavaScript library) and signed as
// CosmJS signs them (Secp256k1HdWallet's signAmino) by the test phrase's first account,
// m/44'/118'/0'/0/0 (CosmJS's makeCosmoshubPath(0): Keplr's, Cosmostation's and Ledger's first), on
// each chain maki knows: what maki must read, show and sign the same. The messages are CosmJS's own,
// written as protobuf and turned into Amino JSON by its AminoTypes, as its SigningStargateClient
// does; the kinds CosmJS has no converter for (governance v1's votes, authz and feegrant, contracts)
// are written here as the SDK's x/tx writes them, and only signed by CosmJS. Where CosmJS can make
// the whole transaction, a few of them have their TxRaw too (`tx`): what a wallet broadcasts, with
// the signature in it. Nothing is fetched. To make them again, in a directory of their own:
//   npm install @cosmjs/amino@0.39.0 @cosmjs/stargate@0.39.0 @cosmjs/crypto@0.39.0 \
//     @cosmjs/encoding@0.39.0 cosmjs-types@0.11.0 @noble/curves@2.4.0 @scure/base@2.4.0 && \
//     node make.mjs signdocs.json
// (CosmJS signs with @noble/curves: RFC 6979, s low; @scure/base is its bech32)
import { writeFileSync } from 'node:fs'
import { Secp256k1HdWallet, Secp256k1Wallet, makeCosmoshubPath, makeSignDoc, serializeSignDoc } from '@cosmjs/amino'
import { Secp256k1, Secp256k1Signature, sha256 } from '@cosmjs/crypto'
import { fromBase64, fromBech32, toBech32, toHex } from '@cosmjs/encoding'
import { AminoTypes, GasPrice, SigningStargateClient, calculateFee, createDefaultAminoConverters } from '@cosmjs/stargate'
import { TxRaw } from 'cosmjs-types/cosmos/tx/v1beta1/tx'

const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
// the account's number and sequence on each chain, made up: maki shows neither
const ACCOUNT = 1234567
const SEQUENCE = 42
// a time IBC transfers time out at: 2026-10-02 05:00:00 UTC, in nanoseconds
const TIMEOUT = BigInt(Date.UTC(2026, 9, 2, 5, 0, 0)) * 1_000_000n
const PROPOSAL = 1000n

// each chain maki knows, its prefix and coin, and a fee: its chain registry's average gas price for
// 200,000 gas
const chains = {
  hub: { id: 'cosmoshub-4', prefix: 'cosmos', denom: 'uatom', one: '1500000', fee: '5000' },
  osmosis: { id: 'osmosis-1', prefix: 'osmo', denom: 'uosmo', one: '1500000', fee: '20000' },
  celestia: { id: 'celestia', prefix: 'celestia', denom: 'utia', one: '1500000', fee: '4000' },
  dydx: { id: 'dydx-mainnet-1', prefix: 'dydx', denom: 'adydx', one: '1500000000000000000', fee: '2500000000000000' },
  neutron: { id: 'neutron-1', prefix: 'neutron', denom: 'untrn', one: '1500000', fee: '1060' },
  noble: { id: 'noble-1', prefix: 'noble', denom: 'uusdc', one: '1500000', fee: '20000' },
  akash: { id: 'akashnet-2', prefix: 'akash', denom: 'uakt', one: '1500000', fee: '5000' },
  axelar: { id: 'axelar-dojo-1', prefix: 'axelar', denom: 'uaxl', one: '1500000', fee: '1400' },
  babylon: { id: 'bbn-1', prefix: 'bbn', denom: 'ubbn', one: '1500000', fee: '1400' },
  juno: { id: 'juno-1', prefix: 'juno', denom: 'ujuno', one: '1500000', fee: '20000' },
  hubtest: { id: 'provider', prefix: 'cosmos', denom: 'uatom', one: '1500000', fee: '4000' },
  osmotest: { id: 'osmo-test-5', prefix: 'osmo', denom: 'uosmo', one: '1500000', fee: '5000' },
  celestiatest: { id: 'mocha-5', prefix: 'celestia', denom: 'utia', one: '1500000', fee: '4000' },
}
// IBC denoms of coins that came straight from their own chains (the SHA-256 of their path)
const ATOM_ON_OSMOSIS = 'ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2'
const USDC_ON_OSMOSIS = 'ibc/498A0751C798A0D9A389AA3691123DADA57DAA4FE165D5C75894505B876BA6E4'
const OSMO_ON_HUB = 'ibc/14F9BC3E44B8A9C1BE1FB08980FAB87034C9905EF17CF2F5008FC085218811CC'
const USDC_ON_DYDX = 'ibc/8E27BA2D5493AF5636760E354E46004562C46AB7EC0CC4C1CA14E9E20E2545B5'
// ATOM that came to Osmosis by way of another chain: not the ATOM a wallet means
const STRAY = 'ibc/0000000000000000000000000000000000000000000000000000000000000001'

const coin = (amount, denom) => ({ amount, denom })
const fee = (chain, extra = {}) => ({ amount: [coin(chain.fee, chain.denom)], gas: '200000', ...extra })

/** The test phrase's account on a chain. */
async function mine(chain) {
  const wallet = await Secp256k1HdWallet.fromMnemonic(phrase, { prefix: chain.prefix, hdPaths: [makeCosmoshubPath(0)] })
  const [account] = await wallet.getAccounts()
  return { wallet, address: account.address, pubkey: account.pubkey }
}

/** Another account: the key of 32 bytes of `n`. */
async function other(n, chain) {
  const wallet = await Secp256k1Wallet.fromKey(new Uint8Array(32).fill(n), chain.prefix)
  const [account] = await wallet.getAccounts()
  return { wallet, address: account.address, pubkey: account.pubkey }
}
// (CosmJS's fromBech32 needs a length limit with @scure/base 2: bech32's own, 90)
const valoper = (account, chain) => toBech32(chain.prefix + 'valoper', fromBech32(account.address, 90).data)

const aminoTypes = new AminoTypes(createDefaultAminoConverters())
const out = []
// the sign docs whose whole transaction is kept: one of each shape a wallet sends
const withTx = new Set(['send', 'multi-send', 'compound', 'redelegate', 'vote-split', 'ibc', 'fee-granter', 'fee-payer', 'valid-until', 'osmosis-ibc-home', 'dydx-usdc-fee'])

/**
 * A sign doc for `chain` of these messages (protobuf, as CosmJS takes them, or `{ amino }` written
 * here), signed by `signer`; this account's signature, and CosmJS's transaction, if it's its.
 */
async function add(name, chain, msgs, { signer, fee: f = fee(chain), memo = '', timeoutHeight } = {}) {
  signer = signer ?? (await mine(chain))
  const amino = msgs.map((m) => m.amino ?? aminoTypes.toAmino(m))
  const doc = makeSignDoc(amino, f, chain.id, memo, ACCOUNT, SEQUENCE, timeoutHeight)
  const bytes = serializeSignDoc(doc)
  const { signature } = await signer.wallet.signAmino(signer.address, doc)
  const rs = fromBase64(signature.signature)
  if (!(await Secp256k1.verifySignature(Secp256k1Signature.fromFixedLength(rs), sha256(bytes), signer.pubkey))) {
    throw new Error(name)
  }
  const mineToo = signer.address === (await mine(chain)).address
  let tx = null
  if (mineToo && withTx.has(name)) {
    const client = await SigningStargateClient.offline(signer.wallet)
    const signerData = { accountNumber: ACCOUNT, sequence: SEQUENCE, chainId: chain.id }
    const raw = await client.sign(signer.address, msgs, f, memo, signerData, timeoutHeight)
    if (toHex(raw.signatures[0]) !== toHex(rs)) throw new Error(`${name}: TxRaw's signature`)
    tx = toHex(TxRaw.encode(raw).finish())
  }
  out.push({
    name,
    chain: chain.id,
    doc: new TextDecoder().decode(bytes),
    signature: mineToo ? toHex(rs) : null,
    tx,
  })
}

const hub = chains.hub
const me = await mine(hub)
const recipient = await other(1, hub)
const second = await other(2, hub)
const stranger = await other(3, hub)
const grantee = await other(4, hub)
const validator = valoper(await other(5, hub), hub)
const validator2 = valoper(await other(6, hub), hub)
const meOn = async (chain) => (await mine(chain)).address

const send = (from, to, amount) => ({
  typeUrl: '/cosmos.bank.v1beta1.MsgSend',
  value: { fromAddress: from, toAddress: to, amount },
})
const staking = (kind, extra) => ({
  typeUrl: `/cosmos.staking.v1beta1.${kind}`,
  value: { delegatorAddress: me.address, ...extra },
})
const transfer = (extra) => ({
  typeUrl: '/ibc.applications.transfer.v1.MsgTransfer',
  value: {
    sourcePort: 'transfer',
    sourceChannel: 'channel-141',
    token: coin('1500000', 'uatom'),
    sender: me.address,
    receiver: '',
    timeoutTimestamp: TIMEOUT,
    memo: '',
    ...extra,
  },
})
const vote = (option) => ({
  typeUrl: '/cosmos.gov.v1beta1.MsgVote',
  value: { proposalId: PROPOSAL, voter: me.address, option },
})

// coins sent
await add('send', hub, [send(me.address, recipient.address, [coin('1500000', 'uatom')])])
await add('send-memo', hub, [send(me.address, recipient.address, [coin('20000000', 'uatom')])], { memo: 'thanks for the coffee' })
// a memo with what Cosmos escapes, and what it doesn't
await add('send-escapes', hub, [send(me.address, recipient.address, [coin('1', 'uatom')])], {
  memo: 'Tom & Jerry <tj@example.com> said "hi" \\o/\nsecond line: café ✓',
})
await add('send-two-coins', hub, [send(me.address, recipient.address, [coin('2500000', OSMO_ON_HUB), coin('1500000', 'uatom')])])
await add('send-to-itself', hub, [send(me.address, me.address, [coin('1000000', 'uatom')])])
await add('send-unknown-coin', hub, [send(me.address, recipient.address, [coin('42', 'factory/cosmos1xyz/token')])])
await add('multi-send', hub, [
  {
    typeUrl: '/cosmos.bank.v1beta1.MsgMultiSend',
    value: {
      inputs: [{ address: me.address, coins: [coin('3000000', 'uatom')] }],
      outputs: [
        { address: recipient.address, coins: [coin('1000000', 'uatom')] },
        { address: second.address, coins: [coin('2000000', 'uatom')] },
      ],
    },
  },
])

// staking
await add('delegate', hub, [staking('MsgDelegate', { validatorAddress: validator, amount: coin('10000000', 'uatom') })])
await add('undelegate', hub, [staking('MsgUndelegate', { validatorAddress: validator, amount: coin('5000000', 'uatom') })])
await add('redelegate', hub, [
  staking('MsgBeginRedelegate', {
    validatorSrcAddress: validator,
    validatorDstAddress: validator2,
    amount: coin('5000000', 'uatom'),
  }),
])
await add('cancel-unstaking', hub, [
  staking('MsgCancelUnbondingDelegation', {
    validatorAddress: validator,
    amount: coin('1000000', 'uatom'),
    creationHeight: 33218000n,
  }),
])
const claim = (v) => ({
  typeUrl: '/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward',
  value: { delegatorAddress: me.address, validatorAddress: v },
})
await add('claim-rewards', hub, [claim(validator)])
// claimed from two validators and staked again: compounding
await add('compound', hub, [
  claim(validator),
  claim(validator2),
  staking('MsgDelegate', { validatorAddress: validator, amount: coin('2000000', 'uatom') }),
])
const rewardsTo = (to) => ({
  typeUrl: '/cosmos.distribution.v1beta1.MsgSetWithdrawAddress',
  value: { delegatorAddress: me.address, withdrawAddress: to },
})
await add('rewards-elsewhere', hub, [rewardsTo(stranger.address)])
await add('rewards-to-itself', hub, [rewardsTo(me.address)])
await add('donate', hub, [
  {
    typeUrl: '/cosmos.distribution.v1beta1.MsgFundCommunityPool',
    value: { amount: [coin('1000000', 'uatom')], depositor: me.address },
  },
])

// governance: votes, a split vote, a deposit; and governance v1's vote, with a note
await add('vote-yes', hub, [vote(1)])
await add('vote-abstain', hub, [vote(2)])
await add('vote-no', hub, [vote(3)])
await add('vote-veto', hub, [vote(4)])
await add('vote-split', hub, [
  {
    typeUrl: '/cosmos.gov.v1beta1.MsgVoteWeighted',
    value: {
      proposalId: PROPOSAL,
      voter: me.address,
      options: [
        { option: 1, weight: '700000000000000000' },
        { option: 3, weight: '300000000000000000' },
      ],
    },
  },
])
await add('deposit', hub, [
  {
    typeUrl: '/cosmos.gov.v1beta1.MsgDeposit',
    value: { proposalId: PROPOSAL, depositor: me.address, amount: [coin('10000000', 'uatom')] },
  },
])
await add('vote-v1', hub, [
  { amino: { type: 'cosmos-sdk/v1/MsgVote', value: { metadata: 'for the community', option: 1, proposal_id: '1000', voter: me.address } } },
])

// IBC: to Osmosis by the Hub's channel to it, timing out at a time, or a block there; with a memo
// of instructions for the other chain, or of words; by a channel maki doesn't know; to an address
// that isn't the other chain's
const osmoMe = await meOn(chains.osmosis)
await add('ibc', hub, [transfer({ receiver: osmoMe })])
await add('ibc-height', hub, [
  transfer({ receiver: osmoMe, timeoutTimestamp: 0n, timeoutHeight: { revisionNumber: 1n, revisionHeight: 72000000n } }),
])
await add('ibc-both', hub, [
  transfer({ receiver: osmoMe, timeoutHeight: { revisionNumber: 1n, revisionHeight: 72000000n } }),
])
const forward = JSON.stringify({
  forward: { receiver: (await other(3, chains.neutron)).address, port: 'transfer', channel: 'channel-874' },
})
await add('ibc-instructions', hub, [transfer({ receiver: osmoMe, memo: forward })])
await add('ibc-memo', hub, [transfer({ receiver: osmoMe, memo: 'deposit 1234' })])
await add('ibc-unknown-channel', hub, [transfer({ receiver: osmoMe, sourceChannel: 'channel-9999' })])
await add('ibc-wrong-receiver', hub, [transfer({ receiver: recipient.address })])

// what this account gave others, taken back (written here: CosmJS has no converter for them)
await add('revoke', hub, [
  { amino: { type: 'cosmos-sdk/MsgRevoke', value: { grantee: grantee.address, granter: me.address, msg_type_url: '/cosmos.staking.v1beta1.MsgDelegate' } } },
])
await add('revoke-allowance', hub, [
  { amino: { type: 'cosmos-sdk/MsgRevokeAllowance', value: { grantee: grantee.address, granter: me.address } } },
])

// fees: from another's allowance, paid by another, none at all; and good until a block
await add('fee-granter', hub, [send(me.address, recipient.address, [coin('1500000', 'uatom')])], { fee: fee(hub, { granter: grantee.address }) })
await add('fee-payer', hub, [send(me.address, recipient.address, [coin('1500000', 'uatom')])], { fee: fee(hub, { payer: grantee.address }) })
await add('no-fee', hub, [send(me.address, recipient.address, [coin('1500000', 'uatom')])], { fee: { amount: [], gas: '200000' } })
// a fee at a gas price of nothing, as CosmJS's calculateFee makes one: a test network takes it
const osmotest = chains.osmotest
await add('fee-of-nothing', osmotest, [send(await meOn(osmotest), (await other(1, osmotest)).address, [coin('1500000', 'uosmo')])], {
  fee: calculateFee(200000, GasPrice.fromString('0uosmo')),
})
await add('valid-until', hub, [send(me.address, recipient.address, [coin('1500000', 'uatom')])], { timeoutHeight: 33300000n })
// a memo as long as a message to maki lets it be
await add('long-memo', hub, [send(me.address, recipient.address, [coin('1500000', 'uatom')])], { memo: 'a'.repeat(3500) })

// what maki won't sign: another account's, grants that let another act for this one, a chain maki
// doesn't know
await add('not-mine', hub, [send(stranger.address, recipient.address, [coin('1500000', 'uatom')])], { signer: stranger })
await add('grant', hub, [
  {
    amino: {
      type: 'cosmos-sdk/MsgGrant',
      value: {
        grant: { authorization: { type: 'cosmos-sdk/GenericAuthorization', value: { msg: '/cosmos.bank.v1beta1.MsgSend' } }, expiration: '2027-10-02T00:00:00Z' },
        grantee: grantee.address,
        granter: me.address,
      },
    },
  },
])
await add('grant-allowance', hub, [
  {
    amino: {
      type: 'cosmos-sdk/MsgGrantAllowance',
      value: {
        allowance: { type: 'cosmos-sdk/BasicAllowance', value: { spend_limit: [coin('1000000', 'uatom')] } },
        grantee: grantee.address,
        granter: me.address,
      },
    },
  },
])
const secret = { id: 'secret-4', prefix: 'secret', denom: 'uscrt', one: '1500000', fee: '5000' }
await add('unknown-chain', secret, [send(await meOn(secret), (await other(1, secret)).address, [coin('1500000', 'uscrt')])])

// Osmosis: ATOM and USDC that came straight from their chains; ATOM that didn't; ATOM back to the
// Hub; a swap and a contract's call, which maki can't read
const osmosis = chains.osmosis
const osmoRecipient = (await other(1, osmosis)).address
await add('osmosis-atom', osmosis, [send(osmoMe, osmoRecipient, [coin('1500000', ATOM_ON_OSMOSIS)])])
await add('osmosis-usdc', osmosis, [send(osmoMe, osmoRecipient, [coin('25000000', USDC_ON_OSMOSIS)])])
await add('osmosis-stray-atom', osmosis, [send(osmoMe, osmoRecipient, [coin('1500000', STRAY)])])
await add('osmosis-ibc-home', osmosis, [
  transfer({ sender: osmoMe, receiver: me.address, sourceChannel: 'channel-0', token: coin('1500000', ATOM_ON_OSMOSIS) }),
])
await add('osmosis-swap', osmosis, [
  {
    amino: {
      type: 'osmosis/poolmanager/swap-exact-amount-in',
      value: { routes: [{ pool_id: '1', token_out_denom: ATOM_ON_OSMOSIS }], sender: osmoMe, token_in: coin('1000000', 'uosmo'), token_out_min_amount: '100000' },
    },
  },
])
await add('osmosis-contract', osmosis, [
  {
    amino: {
      type: 'wasm/MsgExecuteContract',
      value: {
        contract: toBech32('osmo', new Uint8Array(32).fill(7)),
        funds: [coin('1000000', 'uosmo')],
        msg: { swap: { min_out: '100', route: [1, 2] } },
        sender: osmoMe,
      },
    },
  },
])

// dYdX: 18 decimals, and the fee in USDC that came from Noble
const dydx = chains.dydx
await add('dydx-usdc-fee', dydx, [send(await meOn(dydx), (await other(1, dydx)).address, [coin(dydx.one, 'adydx')])], {
  fee: { amount: [coin('5000', USDC_ON_DYDX)], gas: '200000' },
})

// a payment on each chain maki knows, in its own coin
for (const [key, chain] of Object.entries(chains)) {
  await add(`send-${key}`, chain, [send(await meOn(chain), (await other(1, chain)).address, [coin(chain.one, chain.denom)])])
}

writeFileSync(process.argv[2], JSON.stringify(out, null, 1) + '\n')
console.log(out.map((o) => `${o.name}: ${o.doc.length} bytes${o.tx ? ', with its transaction' : ''}`).join('\n'))
