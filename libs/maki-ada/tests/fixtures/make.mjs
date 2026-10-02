// Transactions for maki-ada's tests, built by EMURGO's cardano-serialization-lib (CSL: what Eternl,
// Yoroi, Typhon and most of Cardano's wallets build on), each signed as CSL signs it
// (make_vkey_witness) with the keys of the test phrase's first account, m/1852'/1815'/0' (Icarus's
// master key from the phrase's entropy, as maki-hd makes it): what maki must read, show and sign the
// same. Nothing is fetched: the coins spent are made up, with the amounts the builder balances them
// against, the fees are mainnet's (44 lovelace a byte and 0.155381 ADA), and the slots count from
// each network's tip at 2026-10-02 04:01 UTC, as Koios gave them. To make them again, in a directory
// of their own:
//   npm install @emurgo/cardano-serialization-lib-nodejs@17.0.0 bip39@3.1.0
//   node make.mjs transactions.json
import { writeFileSync } from 'node:fs'
import CSL from '@emurgo/cardano-serialization-lib-nodejs'
import bip39 from 'bip39'

const H = 0x80000000
const hex = (b) => Buffer.from(b).toString('hex')
const big = (n) => CSL.BigNum.from_str(String(n))
const ADA = 1_000_000

const rootOf = (phrase) =>
  CSL.Bip32PrivateKey.from_bip39_entropy(Buffer.from(bip39.mnemonicToEntropy(phrase), 'hex'), Buffer.alloc(0))
const account = (root) => root.derive(1852 + H).derive(1815 + H).derive(0 + H)

// the test phrase's account: its keys, and its base addresses (a payment key with its stake key, 2/0)
const me = account(rootOf('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'))
const key = (role, index) => me.derive(role).derive(index)
const hashOf = (k) => k.to_public().to_raw_key().hash()
const credOf = (k) => CSL.Credential.from_keyhash(hashOf(k))
const STAKE = credOf(key(2, 0))
const MAIN = 1
const TEST = 0
const base = (net, role, index) => CSL.BaseAddress.new(net, credOf(key(role, index)), STAKE).to_address()
const reward = (net) => CSL.RewardAddress.new(net, STAKE)
if (base(MAIN, 0, 0).to_bech32() !== 'addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv') {
  throw new Error('not the account maki-hd’s vectors have')
}

// someone else: the account of BIP39's "legal winner" test phrase, and addresses of every other kind
const other = rootOf('legal winner thank year wave sausage worth useful legal winner thank yellow')
const theirs = account(other)
const theirPay = credOf(theirs.derive(0).derive(0))
const theirStake = credOf(theirs.derive(2).derive(0))
const recipient = (net) => CSL.BaseAddress.new(net, theirPay, theirStake).to_address()
const enterprise = (net) => CSL.EnterpriseAddress.new(net, theirPay).to_address()
const pointer = (net) => CSL.PointerAddress.new(net, theirPay, CSL.Pointer.new_pointer(big(2498243), big(27), big(3))).to_address()
const byron = (magic) =>
  CSL.ByronAddress.icarus_from_key(other.derive(44 + H).derive(1815 + H).derive(0 + H).derive(0).derive(0).to_public(), magic).to_address()
// a script: their key's signature; and a policy only this account can mint under, its key 0/0's
const theirScript = CSL.NativeScript.new_script_pubkey(CSL.ScriptPubkey.new(hashOf(theirs.derive(0).derive(0))))
const scriptAddress = (net) =>
  CSL.BaseAddress.new(net, CSL.Credential.from_scripthash(theirScript.hash()), theirStake).to_address()
const myPolicy = CSL.NativeScript.new_script_pubkey(CSL.ScriptPubkey.new(hashOf(key(0, 0))))

// a stake pool and DReps, by made-up key and script hashes
const POOL = CSL.Ed25519KeyHash.from_bytes(Buffer.alloc(28, 0x70))
const DREP_KEY = CSL.DRep.new_key_hash(CSL.Ed25519KeyHash.from_bytes(Buffer.alloc(28, 0xd1)))
const DREP_SCRIPT = CSL.DRep.new_script_hash(CSL.ScriptHash.from_bytes(Buffer.alloc(28, 0xd5)))

// tokens: two stablecoins and a memecoin maki knows (mainnet's own), and others it doesn't, by policy
// and name: one named in text, one under CIP-68's label 333, one named in bytes, one with no name
const asset = (policy, name) => [CSL.ScriptHash.from_hex(policy), CSL.AssetName.new(Buffer.from(name, 'hex'))]
const USDM = asset('c48cbb3d5e57ed56e276bc45f99ab39abe94e6cd7ac39fb402da47ad', '0014df105553444d')
const DJED = asset('8db269c3ec630e06ae29f74bc39edd1f87c819f1056206e879a1cd61', '446a65644d6963726f555344')
const HOSKY = asset('a0028f350aaabe0545fdcb56b039bfb08e4bb4d8c4d7c3c7d481c235', '484f534b59')
const MAKI = asset(hex(theirScript.hash().to_bytes()), hex(Buffer.from('MAKI')))
const BADGE = asset(hex(theirScript.hash().to_bytes()), '0014df10' + hex(Buffer.from('BADGE')))
const NFT = asset(hex(theirScript.hash().to_bytes()), 'de0a00ff')
const NAMELESS = asset('7f'.repeat(28), '')
const MINE = asset(hex(myPolicy.hash().to_bytes()), hex(Buffer.from('MAKI')))
const tokens = (list) => {
  const m = CSL.MultiAsset.new()
  for (const [[policy, name], n] of list) m.set_asset(policy, name, big(n))
  return m
}
const value = (lovelace, list = []) => {
  const v = CSL.Value.new(big(lovelace))
  if (list.length) v.set_multiasset(tokens(list))
  return v
}

// mainnet's tip at 2026-10-02 04:01:50 UTC, and Preprod's at 04:01:19, by Koios's /tip
const TIP = { [MAIN]: 199347419, [TEST]: 135230479 }

const config = CSL.TransactionBuilderConfigBuilder.new()
  .fee_algo(CSL.LinearFee.new(big(44), big(155381)))
  .coins_per_utxo_byte(big(4310))
  .pool_deposit(big(500 * ADA))
  .key_deposit(big(2 * ADA))
  .max_value_size(5000)
  .max_tx_size(16384)
  .ref_script_coins_per_byte(CSL.UnitInterval.new(big(15), big(1)))
  .build()

/** A builder spending made-up coins at keys of this account: [role, index, value]. */
function builder(net, coins, ttl = TIP[net] + 7200) {
  const tb = CSL.TransactionBuilder.new(config)
  coins.forEach(([role, index, v], n) => {
    const input = CSL.TransactionInput.new(CSL.TransactionHash.from_bytes(Buffer.alloc(32, 0x10 + n)), n)
    tb.add_key_input(hashOf(key(role, index)), input, v)
  })
  if (ttl !== null) tb.set_ttl_bignum(big(ttl))
  return tb
}

const pay = (tb, address, v) => tb.add_output(CSL.TransactionOutput.new(address, v))

const out = []

/**
 * A transaction body, its hash, and the witnesses of these keys ([role, index]) as CSL makes them;
 * the change at [role, index], which must be its last output, if there's any.
 */
function add(name, net, body, witnesses, change = null) {
  const bytes = body.to_bytes()
  const fixed = CSL.FixedTransaction.new_from_body_bytes(bytes)
  const hash = fixed.transaction_hash()
  const outputs = body.outputs()
  const claims = []
  if (change) {
    const last = outputs.len() - 1
    if (outputs.get(last).address().to_bech32() !== base(net, ...change).to_bech32()) throw new Error(name)
    claims.push({ output: last, role: change[0], index: change[1] })
  }
  out.push({
    name,
    network: net === MAIN ? 'mainnet' : 'preprod',
    body: hex(bytes),
    hash: hex(hash.to_bytes()),
    witnesses: witnesses.map(([role, index]) => {
      const w = CSL.make_vkey_witness(hash, key(role, index).to_raw_key())
      return { role, index, key: hex(w.vkey().public_key().as_bytes()), signature: hex(w.signature().to_bytes()) }
    }),
    change: claims
  })
}

/** Built: change to this account's change address #`index`, then the body. */
function built(tb, net, index = 0) {
  tb.add_change_if_needed(base(net, 1, index))
  return tb.build()
}

const certs = (list) => {
  const b = CSL.CertificatesBuilder.new()
  for (const c of list) b.add(c)
  return b
}

// payments
{
  const tb = builder(MAIN, [[0, 0, value(10 * ADA)]])
  pay(tb, recipient(MAIN), value(1_500_000))
  add('payment', MAIN, built(tb, MAIN), [[0, 0]], [1, 0])
}
{
  // two of this account's keys, and addresses of the other kinds: enterprise, Byron, pointer
  const tb = builder(MAIN, [[0, 0, value(3 * ADA)], [0, 4, value(4_200_000)]])
  pay(tb, enterprise(MAIN), value(2 * ADA))
  pay(tb, byron(764824073), value(1_200_000))
  pay(tb, pointer(MAIN), value(1 * ADA))
  add('two-keys', MAIN, built(tb, MAIN, 1), [[0, 0], [0, 4]], [1, 1])
}
{
  const tb = builder(MAIN, [[0, 0, value(20 * ADA, [[USDM, 25_500_000], [HOSKY, 3_000_000], [MAKI, 100], [BADGE, 7], [NFT, 1], [NAMELESS, 5], [DJED, 1_000_000]])]])
  pay(tb, recipient(MAIN), value(2 * ADA, [[USDM, 5_250_000], [HOSKY, 1000], [MAKI, 42], [BADGE, 7], [NFT, 1], [NAMELESS, 5]]))
  add('tokens', MAIN, built(tb, MAIN), [[0, 0]], [1, 0])
}
{
  const tb = builder(TEST, [[0, 0, value(10 * ADA)]])
  pay(tb, recipient(TEST), value(1_500_000))
  add('preprod', TEST, built(tb, TEST), [[0, 0]], [1, 0])
}
{
  // bigger than one of maki's messages: seventy payments, from three keys
  const tb = builder(MAIN, [[0, 0, value(40 * ADA)], [0, 1, value(40 * ADA)], [1, 3, value(40 * ADA)]])
  for (let n = 1; n <= 70; n++) pay(tb, recipient(MAIN), value(1_000_000 + n))
  add('seventy', MAIN, built(tb, MAIN, 4), [[0, 0], [0, 1], [1, 3]], [1, 4])
}

// staking
{
  const tb = builder(MAIN, [[0, 0, value(10 * ADA)]])
  tb.set_certs_builder(certs([
    CSL.Certificate.new_stake_registration(CSL.StakeRegistration.new_with_explicit_deposit(STAKE, big(2 * ADA))),
    CSL.Certificate.new_stake_delegation(CSL.StakeDelegation.new(STAKE, POOL))
  ]))
  add('delegation', MAIN, built(tb, MAIN), [[0, 0], [2, 0]], [1, 0])
}
{
  // Shelley's registration, which pays the key deposit without saying
  const tb = builder(MAIN, [[0, 0, value(10 * ADA)]])
  tb.set_certs_builder(certs([
    CSL.Certificate.new_stake_registration(CSL.StakeRegistration.new(STAKE)),
    CSL.Certificate.new_stake_delegation(CSL.StakeDelegation.new(STAKE, POOL))
  ]))
  add('delegation-shelley', MAIN, built(tb, MAIN), [[0, 0], [2, 0]], [1, 0])
}
{
  const tb = builder(MAIN, [[0, 0, value(5 * ADA)]])
  const w = CSL.WithdrawalsBuilder.new()
  w.add(reward(MAIN), big(12_345_678))
  tb.set_withdrawals_builder(w)
  add('withdrawal', MAIN, built(tb, MAIN), [[0, 0], [2, 0]], [1, 0])
}
for (const [name, drep] of [
  ['vote', DREP_KEY],
  ['vote-script', DREP_SCRIPT],
  ['vote-abstain', CSL.DRep.new_always_abstain()],
  ['vote-no-confidence', CSL.DRep.new_always_no_confidence()]
]) {
  const tb = builder(MAIN, [[0, 0, value(5 * ADA)]])
  tb.set_certs_builder(certs([CSL.Certificate.new_vote_delegation(CSL.VoteDelegation.new(STAKE, drep))]))
  add(name, MAIN, built(tb, MAIN), [[0, 0], [2, 0]], [1, 0])
}
{
  // the deposit back, with the last of the rewards
  const tb = builder(MAIN, [[0, 0, value(5 * ADA)]])
  const w = CSL.WithdrawalsBuilder.new()
  w.add(reward(MAIN), big(1_234_567))
  tb.set_withdrawals_builder(w)
  tb.set_certs_builder(certs([
    CSL.Certificate.new_stake_deregistration(CSL.StakeDeregistration.new_with_explicit_refund(STAKE, big(2 * ADA)))
  ]))
  add('deregistration', MAIN, built(tb, MAIN), [[0, 0], [2, 0]], [1, 0])
}
{
  const tb = builder(MAIN, [[0, 0, value(5 * ADA)]])
  tb.set_certs_builder(certs([CSL.Certificate.new_stake_deregistration(CSL.StakeDeregistration.new(STAKE))]))
  add('deregistration-shelley', MAIN, built(tb, MAIN), [[0, 0], [2, 0]], [1, 0])
}
// Conway's certificates that do two or three things at once
for (const [name, cert] of [
  ['delegate-and-vote', CSL.Certificate.new_stake_and_vote_delegation(CSL.StakeAndVoteDelegation.new(STAKE, POOL, DREP_KEY))],
  ['register-and-delegate', CSL.Certificate.new_stake_registration_and_delegation(CSL.StakeRegistrationAndDelegation.new(STAKE, POOL, big(2 * ADA)))],
  ['register-and-vote', CSL.Certificate.new_vote_registration_and_delegation(CSL.VoteRegistrationAndDelegation.new(STAKE, CSL.DRep.new_always_abstain(), big(2 * ADA)))],
  ['register-delegate-and-vote', CSL.Certificate.new_stake_vote_registration_and_delegation(CSL.StakeVoteRegistrationAndDelegation.new(STAKE, POOL, DREP_SCRIPT, big(2 * ADA)))]
]) {
  const tb = builder(MAIN, [[0, 0, value(10 * ADA)]])
  tb.set_certs_builder(certs([cert]))
  add(name, MAIN, built(tb, MAIN), [[0, 0], [2, 0]], [1, 0])
}

// the rest of what a body can hold
{
  // a message (CIP-20): the body has its hash alone
  const tb = builder(MAIN, [[0, 0, value(10 * ADA)]])
  pay(tb, recipient(MAIN), value(1_500_000))
  tb.add_json_metadatum(big(674), JSON.stringify({ msg: ['thanks for the coffee'] }))
  add('metadata', MAIN, built(tb, MAIN), [[0, 0]], [1, 0])
}
{
  // tokens made under this account's policy, sent; and some burnt
  const tb = builder(MAIN, [[0, 0, value(10 * ADA)]])
  tb.add_mint_asset_and_output_min_required_coin(
    myPolicy,
    MINE[1],
    CSL.Int.new(big(1000)),
    CSL.TransactionOutputBuilder.new().with_address(recipient(MAIN)).next()
  )
  add('mint', MAIN, built(tb, MAIN), [[0, 0]], [1, 0])
}
{
  const tb = builder(MAIN, [[0, 0, value(10 * ADA, [[MINE, 10]])]])
  tb.add_mint_asset(myPolicy, MINE[1], CSL.Int.new_negative(big(10)))
  add('burn', MAIN, built(tb, MAIN), [[0, 0]], [1, 0])
}
{
  const tb = builder(MAIN, [[0, 0, value(10 * ADA)]])
  tb.set_donation(big(1 * ADA))
  add('donation', MAIN, built(tb, MAIN), [[0, 0]], [1, 0])
}
{
  const tb = builder(MAIN, [[0, 0, value(10 * ADA)]])
  tb.set_current_treasury_value(big('1700000000000000'))
  add('treasury', MAIN, built(tb, MAIN), [[0, 0]], [1, 0])
}
{
  const tb = builder(MAIN, [[0, 0, value(10 * ADA)]])
  pay(tb, recipient(MAIN), value(1_500_000))
  const body = built(tb, MAIN)
  body.set_network_id(CSL.NetworkId.mainnet())
  add('network-id', MAIN, body, [[0, 0]], [1, 0])
}
// when it's valid: no limit; from a minute ago; from tomorrow; for three days
for (const [name, start, ttl] of [
  ['no-ttl', null, null],
  ['valid-from', TIP[MAIN] - 60, TIP[MAIN] + 7200],
  ['valid-later', TIP[MAIN] + 86_400, TIP[MAIN] + 90_000],
  ['three-days', null, TIP[MAIN] + 3 * 86_400]
]) {
  const tb = builder(MAIN, [[0, 0, value(10 * ADA)]], ttl)
  if (start !== null) tb.set_validity_start_interval_bignum(big(start))
  pay(tb, recipient(MAIN), value(1_500_000))
  add(name, MAIN, built(tb, MAIN), [[0, 0]], [1, 0])
}
// outputs for scripts: an inline datum (Babbage's map), a datum's hash, neither, a script to refer to
{
  const datum = CSL.PlutusData.new_integer(CSL.BigInt.from_str('42'))
  const tb = builder(MAIN, [[0, 0, value(20 * ADA)]])
  tb.add_output(CSL.TransactionOutputBuilder.new().with_address(scriptAddress(MAIN)).with_plutus_data(datum).next().with_coin(big(3 * ADA)).build())
  tb.add_output(CSL.TransactionOutputBuilder.new().with_address(scriptAddress(MAIN)).with_data_hash(CSL.hash_plutus_data(datum)).next().with_coin(big(2 * ADA)).build())
  pay(tb, scriptAddress(MAIN), value(2 * ADA))
  tb.add_output(
    CSL.TransactionOutputBuilder.new()
      .with_address(recipient(MAIN))
      .with_script_ref(CSL.ScriptRef.new_native_script(theirScript))
      .next()
      .with_coin(big(2 * ADA))
      .build()
  )
  add('scripts', MAIN, built(tb, MAIN), [[0, 0]], [1, 0])
}

// what maki refuses: what's for scripts, a pool's or a DRep's, governance, and another's stake
{
  const tb = builder(MAIN, [[0, 0, value(10 * ADA)]])
  const collateral = CSL.TxInputsBuilder.new()
  collateral.add_key_input(hashOf(key(0, 0)), CSL.TransactionInput.new(CSL.TransactionHash.from_bytes(Buffer.alloc(32, 0xc0)), 0), value(5 * ADA))
  tb.set_collateral(collateral)
  add('collateral', MAIN, built(tb, MAIN), [[0, 0]])
}
{
  const tb = builder(MAIN, [[0, 0, value(10 * ADA)]])
  tb.add_required_signer(hashOf(key(0, 0)))
  add('required-signer', MAIN, built(tb, MAIN), [[0, 0]])
}
{
  const tb = builder(MAIN, [[0, 0, value(10 * ADA)]])
  tb.add_reference_input(CSL.TransactionInput.new(CSL.TransactionHash.from_bytes(Buffer.alloc(32, 0xee)), 1))
  add('reference-input', MAIN, built(tb, MAIN), [[0, 0]])
}
{
  const tb = builder(MAIN, [[0, 0, value(10 * ADA)]])
  tb.set_certs_builder(certs([CSL.Certificate.new_pool_retirement(CSL.PoolRetirement.new(POOL, 700))]))
  add('pool-retirement', MAIN, built(tb, MAIN), [[0, 0]])
}
{
  // CIP-105's DRep key, at 3/0
  const tb = builder(MAIN, [[0, 0, value(600 * ADA)]])
  tb.set_certs_builder(certs([CSL.Certificate.new_drep_registration(CSL.DRepRegistration.new(credOf(key(3, 0)), big(500 * ADA)))]))
  add('drep-registration', MAIN, built(tb, MAIN), [[0, 0]])
}
{
  const tb = builder(MAIN, [[0, 0, value(10 * ADA)]])
  const v = CSL.VotingBuilder.new()
  v.add(
    CSL.Voter.new_drep_credential(credOf(key(3, 0))),
    CSL.GovernanceActionId.new(CSL.TransactionHash.from_bytes(Buffer.alloc(32, 0x9a)), 0),
    CSL.VotingProcedure.new(CSL.VoteKind.Yes)
  )
  tb.set_voting_builder(v)
  add('voting', MAIN, built(tb, MAIN), [[0, 0]])
}
{
  const tb = builder(MAIN, [[0, 0, value(100_010 * ADA)]])
  const p = CSL.VotingProposalBuilder.new()
  p.add(
    CSL.VotingProposal.new(
      CSL.GovernanceAction.new_info_action(CSL.InfoAction.new()),
      CSL.Anchor.new(CSL.URL.new('https://example.com/maki'), CSL.AnchorDataHash.from_bytes(Buffer.alloc(32, 0xab))),
      reward(MAIN),
      big(100_000 * ADA)
    )
  )
  tb.set_voting_proposal_builder(p)
  add('proposal', MAIN, built(tb, MAIN), [[0, 0]])
}
{
  const tb = builder(MAIN, [[0, 0, value(10 * ADA)]])
  tb.set_certs_builder(certs([CSL.Certificate.new_stake_delegation(CSL.StakeDelegation.new(theirStake, POOL))]))
  add('their-delegation', MAIN, built(tb, MAIN), [[0, 0]])
}
{
  const tb = builder(MAIN, [[0, 0, value(5 * ADA)]])
  const w = CSL.WithdrawalsBuilder.new()
  w.add(CSL.RewardAddress.new(MAIN, theirStake), big(12_345_678))
  tb.set_withdrawals_builder(w)
  add('their-withdrawal', MAIN, built(tb, MAIN), [[0, 0]])
}

// the addresses, as CSL writes them, for the address tests
const addresses = {
  base: base(MAIN, 0, 0).to_bech32(),
  change: base(MAIN, 1, 0).to_bech32(),
  baseTest: base(TEST, 0, 0).to_bech32(),
  reward: reward(MAIN).to_address().to_bech32(),
  rewardTest: reward(TEST).to_address().to_bech32(),
  recipient: recipient(MAIN).to_bech32(),
  recipientTest: recipient(TEST).to_bech32(),
  enterprise: enterprise(MAIN).to_bech32(),
  pointer: pointer(MAIN).to_bech32(),
  byron: CSL.ByronAddress.from_address(byron(764824073)).to_base58(),
  byronTest: CSL.ByronAddress.from_address(byron(1)).to_base58(),
  script: scriptAddress(MAIN).to_bech32(),
  pool: POOL.to_bech32('pool'),
  drep: DREP_KEY.to_bech32(true),
  drepScript: DREP_SCRIPT.to_bech32(true)
}

writeFileSync(process.argv[2], JSON.stringify({ addresses, transactions: out }, null, 1) + '\n')
console.log(out.map((o) => `${o.name}: ${o.body.length / 2} bytes`).join('\n'))
