// Transactions the chains took, signed in Amino JSON (SIGN_MODE_LEGACY_AMINO_JSON, as a Ledger signs):
// their sign docs made again from the transactions themselves, and kept only where the
// transaction's own signature checks out over them. Each chain made the same bytes to check that
// signature, or it wouldn't have taken the transaction: these are sign docs as the chains write
// them, for maki to read as they are. CosmJS writes most kinds of message; the ones it has no
// converter for (governance v1's votes and deposits, an authz or fee allowance taken back) are
// written here as maki reads them, so their signatures checking out holds maki's reading to the
// chain's writing. Found by asking each chain's REST API (through cosmos.directory's proxies,
// keyless) for its latest transactions of each kind, and reading them whole from their blocks. To
// make them again, in a directory of their own (the transactions will be other ones):
//   npm install @cosmjs/amino@0.39.0 @cosmjs/proto-signing@0.39.0 @cosmjs/stargate@0.39.0 \
//     @cosmjs/crypto@0.39.0 @cosmjs/encoding@0.39.0 cosmjs-types@0.11.0 @noble/curves@2.4.0 \
//     @scure/base@2.4.0 && node onchain.mjs onchain.json
import { writeFileSync } from 'node:fs'
import { makeSignDoc, pubkeyToAddress, serializeSignDoc } from '@cosmjs/amino'
import { Secp256k1, Secp256k1Signature, sha256 } from '@cosmjs/crypto'
import { fromBase64, toBase64, toHex } from '@cosmjs/encoding'
import { Registry } from '@cosmjs/proto-signing'
import { AminoTypes, createDefaultAminoConverters, defaultRegistryTypes } from '@cosmjs/stargate'
import { MsgRevoke } from 'cosmjs-types/cosmos/authz/v1beta1/tx'
import { PubKey } from 'cosmjs-types/cosmos/crypto/secp256k1/keys'
import { MsgRevokeAllowance } from 'cosmjs-types/cosmos/feegrant/v1beta1/tx'
import { MsgDeposit, MsgVote } from 'cosmjs-types/cosmos/gov/v1/tx'
import { AuthInfo, TxBody, TxRaw } from 'cosmjs-types/cosmos/tx/v1beta1/tx'

const chains = [
  { name: 'cosmoshub', id: 'cosmoshub-4', prefix: 'cosmos' },
  { name: 'osmosis', id: 'osmosis-1', prefix: 'osmo' },
  { name: 'celestia', id: 'celestia', prefix: 'celestia' },
  { name: 'dydx', id: 'dydx-mainnet-1', prefix: 'dydx' },
  { name: 'neutron', id: 'neutron-1', prefix: 'neutron' },
  { name: 'noble', id: 'noble-1', prefix: 'noble' },
  { name: 'akash', id: 'akashnet-2', prefix: 'akash' },
  { name: 'axelar', id: 'axelar-dojo-1', prefix: 'axelar' },
  { name: 'babylon', id: 'bbn-1', prefix: 'bbn' },
  { name: 'juno', id: 'juno-1', prefix: 'juno' },
]
// the kinds of message maki reads
const kinds = [
  '/cosmos.bank.v1beta1.MsgSend',
  '/cosmos.bank.v1beta1.MsgMultiSend',
  '/cosmos.staking.v1beta1.MsgDelegate',
  '/cosmos.staking.v1beta1.MsgUndelegate',
  '/cosmos.staking.v1beta1.MsgBeginRedelegate',
  '/cosmos.staking.v1beta1.MsgCancelUnbondingDelegation',
  '/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward',
  '/cosmos.distribution.v1beta1.MsgSetWithdrawAddress',
  '/cosmos.distribution.v1beta1.MsgFundCommunityPool',
  '/cosmos.gov.v1beta1.MsgVote',
  '/cosmos.gov.v1beta1.MsgVoteWeighted',
  '/cosmos.gov.v1beta1.MsgDeposit',
  '/cosmos.gov.v1.MsgVote',
  '/cosmos.gov.v1.MsgDeposit',
  '/ibc.applications.transfer.v1.MsgTransfer',
  '/cosmos.authz.v1beta1.MsgRevoke',
  '/cosmos.feegrant.v1beta1.MsgRevokeAllowance',
]
// how many of each kind to keep on each chain, and how many of the latest of a kind to look at
const PER_KIND = 1
const LATEST = 100
const AMINO_JSON = 127

// the kinds CosmJS has no converter for, written as the SDK's x/tx writes them: fields in the
// order of their names, empty ones left out (but those the SDK says not to), uint64s as strings,
// enums as numbers
const written = {
  '/cosmos.gov.v1.MsgVote': {
    aminoType: 'cosmos-sdk/v1/MsgVote',
    toAmino: ({ proposalId, voter, option, metadata }) => ({
      ...(metadata ? { metadata } : {}),
      ...(option ? { option } : {}),
      proposal_id: proposalId.toString(),
      voter,
    }),
    fromAmino: () => null,
  },
  '/cosmos.gov.v1.MsgDeposit': {
    aminoType: 'cosmos-sdk/v1/MsgDeposit',
    toAmino: ({ proposalId, depositor, amount }) => ({ amount, depositor, proposal_id: proposalId.toString() }),
    fromAmino: () => null,
  },
  '/cosmos.authz.v1beta1.MsgRevoke': {
    aminoType: 'cosmos-sdk/MsgRevoke',
    toAmino: ({ granter, grantee, msgTypeUrl }) => ({ grantee, granter, msg_type_url: msgTypeUrl }),
    fromAmino: () => null,
  },
  '/cosmos.feegrant.v1beta1.MsgRevokeAllowance': {
    aminoType: 'cosmos-sdk/MsgRevokeAllowance',
    toAmino: ({ granter, grantee }) => ({ grantee, granter }),
    fromAmino: () => null,
  },
}
const registry = new Registry([
  ...defaultRegistryTypes,
  ['/cosmos.gov.v1.MsgVote', MsgVote],
  ['/cosmos.gov.v1.MsgDeposit', MsgDeposit],
  ['/cosmos.authz.v1beta1.MsgRevoke', MsgRevoke],
  ['/cosmos.feegrant.v1beta1.MsgRevokeAllowance', MsgRevokeAllowance],
])
const aminoTypes = new AminoTypes({ ...createDefaultAminoConverters(), ...written })
const pause = (ms) => new Promise((r) => setTimeout(r, ms))

async function get(chain, path) {
  for (let attempt = 0; attempt < 3; attempt++) {
    await pause(200)
    try {
      const r = await fetch(`https://rest.cosmos.directory/${chain.name}${path}`)
      if (r.ok) return r.json()
      if (r.status === 404 || r.status === 400) return null
    } catch {
      // try again
    }
  }
  return null
}

function accountNumber(account) {
  const a = account?.account
  const base = a?.base_account ?? a?.base_vesting_account?.base_account ?? a
  return base?.account_number
}

/** The sign doc a transaction's signer signed, if it signed one in Amino JSON that CosmJS (or this) can write. */
async function signDoc(chain, raw64) {
  let raw, body, auth
  try {
    raw = TxRaw.decode(fromBase64(raw64))
    body = TxBody.decode(raw.bodyBytes)
    auth = AuthInfo.decode(raw.authInfoBytes)
  } catch {
    return null
  }
  const [signer] = auth.signerInfos
  if (auth.signerInfos.length !== 1 || signer.modeInfo?.single?.mode !== AMINO_JSON) return null
  if (signer.publicKey?.typeUrl !== '/cosmos.crypto.secp256k1.PubKey') return null
  let msgs
  try {
    msgs = body.messages.map((m) => aminoTypes.toAmino({ typeUrl: m.typeUrl, value: registry.decode(m) }))
  } catch {
    return null // a kind neither has a converter for
  }
  const key = PubKey.decode(signer.publicKey.value).key
  const address = pubkeyToAddress({ type: 'tendermint/PubKeySecp256k1', value: toBase64(key) }, chain.prefix)
  const number = accountNumber(await get(chain, `/cosmos/auth/v1beta1/accounts/${address}`))
  if (number === undefined) return null
  const fee = {
    amount: auth.fee.amount.map(({ amount, denom }) => ({ amount, denom })),
    gas: auth.fee.gasLimit.toString(),
    ...(auth.fee.granter ? { granter: auth.fee.granter } : {}),
    ...(auth.fee.payer ? { payer: auth.fee.payer } : {}),
  }
  const timeout = body.timeoutHeight > 0n ? body.timeoutHeight : undefined
  const doc = makeSignDoc(msgs, fee, chain.id, body.memo, number, signer.sequence.toString(), timeout)
  const bytes = serializeSignDoc(doc)
  const signature = raw.signatures[0]
  const good = await Secp256k1.verifySignature(Secp256k1Signature.fromFixedLength(signature), sha256(bytes), key)
  return { good, bytes, key, signature, kinds: body.messages.map((m) => m.typeUrl) }
}

const out = []
for (const chain of chains) {
  for (const kind of kinds) {
    const query = encodeURIComponent(`message.action='${kind}'`)
    const found = await get(chain, `/cosmos/tx/v1beta1/txs?query=${query}&order_by=ORDER_BY_DESC&pagination.limit=${LATEST}`)
    let kept = 0
    for (const [i, tx] of (found?.txs ?? []).entries()) {
      if (kept >= PER_KIND) break
      if (tx.auth_info?.signer_infos?.[0]?.mode_info?.single?.mode !== 'SIGN_MODE_LEGACY_AMINO_JSON') continue
      const { height, txhash } = found.tx_responses[i]
      // one of several kinds, kept already for another
      if (out.some((o) => o.hash === txhash)) continue
      const block = await get(chain, `/cosmos/tx/v1beta1/txs/block/${height}`)
      const raw64 = (block?.block?.data?.txs ?? []).find((t) => toHex(sha256(fromBase64(t))).toUpperCase() === txhash)
      const made = raw64 && (await signDoc(chain, raw64))
      console.log(`${chain.id} ${height} ${txhash} ${kind}: ${made ? (made.good ? 'signature checks out' : 'NOT THIS SIGN DOC') : 'not read'}`)
      // longer than a message to maki can be (4096 bytes, its head of 6 with them), it can't be asked
      if (!made?.good || made.bytes.length > 4090) continue
      kept++
      out.push({
        chain: chain.id,
        height: Number(height),
        hash: txhash,
        kinds: made.kinds,
        doc: new TextDecoder().decode(made.bytes),
        key: toHex(made.key),
        signature: toHex(made.signature),
      })
    }
  }
}
writeFileSync(process.argv[2], JSON.stringify(out, null, 1) + '\n')
console.log(`${out.length} transactions`)
