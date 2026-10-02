// Transactions for maki-xlm's tests, made with Stellar's own JavaScript library
// (@stellar/stellar-sdk 17.2.1, which since 16.0 holds what was @stellar/stellar-base: its
// `/base` entry is that library), each built for the test phrase's first account as SEP-5
// derives it (SLIP-10 at m/44'/148'/0'), on Stellar's public network and its test network, and
// signed by stellar-sdk: what maki must show, and sign the same. To make them again:
//   npm install @stellar/stellar-sdk@17.2.1 && node make.mjs transactions.json
// Each entry: the envelope as stellar-sdk writes it unsigned (hex), the network (0 public, 1
// test), the hash stellar-sdk signs (SHA-256 of the network ID, the envelope type and the
// transaction), and stellar-sdk's signature with this account. A few are ones Stellar refuses
// (inflation, a liquidity pool's sponsorship revoked), which stellar-sdk builds anyway: maki
// must refuse them too.
import { createHmac, pbkdf2Sync } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import {
  Account,
  Address,
  Asset,
  AuthClawbackEnabledFlag,
  AuthRequiredFlag,
  AuthRevocableFlag,
  Claimant,
  Keypair,
  LiquidityPoolAsset,
  LiquidityPoolFeeV18,
  Memo,
  MuxedAccount,
  Networks,
  Operation,
  SorobanDataBuilder,
  StrKey,
  TimeoutInfinite,
  Transaction,
  TransactionBuilder,
  authorizeEntry,
  buildWithDelegatesEntry,
  getLiquidityPoolId,
  hash,
  nativeToScVal,
  xdr
} from '@stellar/stellar-sdk/base'

const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const seed = pbkdf2Sync(Buffer.from(phrase), Buffer.from('mnemonic'), 2048, 64, 'sha512')
/** SLIP-10's Ed25519 key at a path of hardened steps, as SEP-5 derives Stellar's accounts. */
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
const me = Keypair.fromRawEd25519Seed(slip10([44, 148, 0]))
// SEP-5's own vector for this phrase (Test 5), account 0 and account 1
if (me.publicKey() !== 'GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX') throw new Error('not SEP-5’s account 0')
if (Keypair.fromRawEd25519Seed(slip10([44, 148, 1])).publicKey() !== 'GDVSYYTUAJ3ACHTPQNSTQBDQ4LDHQCMNY4FCEQH5TJUMSSLWQSTG42MV') throw new Error('not SEP-5’s account 1')

const other = (n) => Keypair.fromRawEd25519Seed(Buffer.alloc(32, n))
const recipient = other(1).publicKey()
const signer = other(2).publicKey()
const service = other(3)
const created = other(4)
const issuer = other(5).publicKey()
const stranger = other(8)
const USDC = new Asset('USDC', 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN')
const EURC = new Asset('EURC', 'GDHU6WRG4IEQXM5NZ4BMPKOXHW76MZM4Y2IEMFDVXBSDP6SJY4ITNPP2')
const TEST_USDC = new Asset('USDC', 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5')
// assets maki doesn't know: one with a name of its own, one that borrows USDC's
const FOO = new Asset('FOO', issuer)
const FAKE_USDC = new Asset('USDC', issuer)
const LONG = new Asset('LONGNAME123', issuer)
// this account as an issuer, of its own asset
const MAKI = new Asset('MAKI', me.publicKey())
const XLM = Asset.native()
const balanceId = '00000000' + 'da0d57da7d4850e7fc10d2a9d0ebc731f7afb40574c03395b17d49149b91f5be'
const until = { minTime: 0, maxTime: 1798761600 } // 2027-01-01 00:00:00 UTC

/** A contract's call, and the same call authorized apart from the transaction, as stellar-sdk
 * signs authorizations: by another account (credentials version 2), by an account with others
 * signing for it (delegates, CAP-71), and by this account (version 1). */
const deposit = StrKey.encodeContract(Buffer.alloc(32, 0x66))
const depositArgs = [nativeToScVal(5, { type: 'i128' })]
async function authorizations(passphrase) {
  const invocation = new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({ contractAddress: new Address(deposit).toScAddress(), functionName: 'deposit', args: depositArgs })),
    subInvocations: []
  })
  const entry = (who, kind) => new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials[kind](new xdr.SorobanAddressCredentials({ address: new Address(who).toScAddress(), nonce: xdr.Int64.fromString('7'), signatureExpirationLedger: 0, signature: xdr.ScVal.scvVoid() })),
    rootInvocation: invocation
  })
  const theirs = await authorizeEntry(entry(stranger.publicKey(), 'sorobanCredentialsAddressV2'), stranger, 70000000, passphrase)
  const delegated = buildWithDelegatesEntry({ entry: entry(signer, 'sorobanCredentialsAddressV2'), validUntilLedgerSeq: 70000000, delegates: [{ address: service.publicKey(), nestedDelegates: [{ address: created.publicKey() }] }] })
  const mine = await authorizeEntry(entry(me.publicKey(), 'sorobanCredentialsAddress'), me, 70000000, passphrase)
  return [theirs, delegated, mine]
}
const authorized = { [Networks.PUBLIC]: await authorizations(Networks.PUBLIC), [Networks.TESTNET]: await authorizations(Networks.TESTNET) }

/** A transaction from `source` (this account unless said), its operations and options. */
function build(passphrase, ops, { source = me.publicKey(), sequence = '123456789012', account = new Account(source, sequence), memo, timebounds = until, fee = '100', soroban, conditions } = {}) {
  const b = new TransactionBuilder(account, { fee, networkPassphrase: passphrase, ...(timebounds === 'none' ? {} : { timebounds }) })
  if (timebounds === 'none') b.setTimeout(TimeoutInfinite)
  for (const op of ops) b.addOperation(op)
  if (memo) b.addMemo(memo)
  if (soroban) b.setSorobanData(soroban)
  if (conditions) conditions(b)
  return b.build()
}

const kinds = [
  ['payment', (n) => build(n, [Operation.payment({ destination: recipient, asset: XLM, amount: '12.5' })], { memo: Memo.text('thanks for the coffee') })],
  ['usdc', (n) => build(n, [Operation.payment({ destination: recipient, asset: USDC, amount: '5.25' })], { memo: Memo.id('1234567890') })],
  ['test-usdc', (n) => build(n, [Operation.payment({ destination: recipient, asset: TEST_USDC, amount: '7' })])],
  ['fake-usdc', (n) => build(n, [Operation.payment({ destination: recipient, asset: FAKE_USDC, amount: '1000' })])],
  ['muxed', (n) => build(n, [Operation.payment({ destination: new MuxedAccount(new Account(recipient, '0'), '42').accountId(), asset: XLM, amount: '100' })])],
  ['create-account', (n) => build(n, [Operation.createAccount({ destination: created.publicKey(), startingBalance: '2' })])],
  ['strict-send', (n) => build(n, [Operation.pathPaymentStrictSend({ sendAsset: XLM, sendAmount: '10', destination: recipient, destAsset: USDC, destMin: '1.2', path: [EURC] })])],
  // a swap: to this account itself
  ['strict-receive', (n) => build(n, [Operation.pathPaymentStrictReceive({ sendAsset: XLM, sendMax: '20', destination: me.publicKey(), destAsset: USDC, destAmount: '5', path: [] })])],
  ['offers', (n) => build(n, [
    Operation.manageSellOffer({ selling: XLM, buying: USDC, amount: '100', price: '0.11' }),
    Operation.manageBuyOffer({ selling: XLM, buying: USDC, buyAmount: '50', price: '9.5' }),
    Operation.manageSellOffer({ selling: XLM, buying: USDC, amount: '0', price: '1', offerId: '12345' }),
    Operation.manageSellOffer({ selling: USDC, buying: FOO, amount: '3', price: { n: 1, d: 3 }, offerId: '678' }),
    Operation.createPassiveSellOffer({ selling: USDC, buying: EURC, amount: '10', price: '0.92' })
  ])],
  ['trust', (n) => build(n, [
    Operation.changeTrust({ asset: USDC }),
    Operation.changeTrust({ asset: FOO, limit: '1000' }),
    Operation.changeTrust({ asset: EURC, limit: '0' })
  ])],
  ['signer', (n) => build(n, [Operation.setOptions({ signer: { ed25519PublicKey: signer, weight: 1 }, lowThreshold: 1, medThreshold: 2, highThreshold: 2 })])],
  ['lockout', (n) => build(n, [Operation.setOptions({ masterWeight: 0, signer: { ed25519PublicKey: signer, weight: 10 } })])],
  ['options', (n) => build(n, [
    Operation.setOptions({ homeDomain: 'example.com', setFlags: AuthRevocableFlag | AuthClawbackEnabledFlag, clearFlags: AuthRequiredFlag, inflationDest: recipient }),
    Operation.setOptions({ signer: { ed25519PublicKey: signer, weight: 0 } }),
    Operation.setOptions({ signer: { preAuthTx: Buffer.alloc(32, 0x5a), weight: 1 } }),
    Operation.setOptions({ signer: { sha256Hash: Buffer.alloc(32, 0x6b), weight: 2 } }),
    Operation.setOptions({ signer: { ed25519SignedPayload: StrKey.encodeSignedPayload(Buffer.concat([Buffer.from(other(2).rawPublicKey()), Buffer.from([0, 0, 0, 5, 1, 2, 3, 4, 5, 0, 0, 0])])), weight: 1 } })
  ])],
  ['merge', (n) => build(n, [Operation.accountMerge({ destination: recipient })])],
  ['data', (n) => build(n, [Operation.manageData({ name: 'config', value: 'hello' }), Operation.manageData({ name: 'key', value: Buffer.from([0, 1, 2, 0xff]) }), Operation.manageData({ name: 'old', value: null })])],
  ['bump', (n) => build(n, [Operation.bumpSequence({ bumpTo: '123456789999' })])],
  ['claimable', (n) => build(n, [Operation.createClaimableBalance({
    asset: XLM,
    amount: '50',
    claimants: [
      new Claimant(recipient, Claimant.predicateBeforeAbsoluteTime('1798761600')),
      new Claimant(me.publicKey(), Claimant.predicateNot(Claimant.predicateBeforeRelativeTime('86400'))),
      new Claimant(signer, Claimant.predicateOr(Claimant.predicateUnconditional(), Claimant.predicateAnd(Claimant.predicateBeforeRelativeTime('3600'), Claimant.predicateBeforeAbsoluteTime('1798761600'))))
    ]
  })])],
  ['claim', (n) => build(n, [Operation.claimClaimableBalance({ balanceId })])],
  // this account sponsors a new account's reserve: the new account signs too, for its operation
  ['sponsor', (n) => build(n, [
    Operation.beginSponsoringFutureReserves({ sponsoredId: created.publicKey() }),
    Operation.createAccount({ destination: created.publicKey(), startingBalance: '0' }),
    Operation.endSponsoringFutureReserves({ source: created.publicKey() })
  ])],
  ['revoke', (n) => build(n, [
    Operation.revokeAccountSponsorship({ account: recipient }),
    Operation.revokeTrustlineSponsorship({ account: recipient, asset: USDC }),
    Operation.revokeOfferSponsorship({ seller: recipient, offerId: '7' }),
    Operation.revokeDataSponsorship({ account: recipient, name: 'config' }),
    Operation.revokeClaimableBalanceSponsorship({ balanceId }),
    Operation.revokeSignerSponsorship({ account: recipient, signer: { ed25519PublicKey: signer } })
  ])],
  // this account as an issuer: of MAKI
  ['issuer', (n) => build(n, [
    Operation.setTrustLineFlags({ trustor: recipient, asset: MAKI, flags: { authorized: true, authorizedToMaintainLiabilities: false, clawbackEnabled: false } }),
    Operation.allowTrust({ trustor: recipient, assetCode: 'MAKI', authorize: 2 }),
    Operation.clawback({ asset: MAKI, from: recipient, amount: '3' }),
    Operation.clawbackClaimableBalance({ balanceId })
  ])],
  ['pool', (n) => {
    const pool = new LiquidityPoolAsset(XLM, USDC, LiquidityPoolFeeV18)
    const id = Buffer.from(getLiquidityPoolId('constant_product', pool.getLiquidityPoolParameters())).toString('hex')
    return build(n, [
      Operation.changeTrust({ asset: pool }),
      Operation.liquidityPoolDeposit({ liquidityPoolId: id, maxAmountA: '100', maxAmountB: '11', minPrice: '0.09', maxPrice: '0.12' }),
      Operation.liquidityPoolWithdraw({ liquidityPoolId: id, amount: '5', minAmountA: '1', minAmountB: '0.1' })
    ])
  }],
  ['long-asset', (n) => build(n, [Operation.payment({ destination: recipient, asset: LONG, amount: '0.0000001' })])],
  ['many', (n) => build(n, [
    Operation.payment({ destination: recipient, asset: XLM, amount: '1' }),
    Operation.payment({ destination: signer, asset: XLM, amount: '2.5' }),
    Operation.payment({ destination: created.publicKey(), asset: XLM, amount: '0.25' })
  ])],
  ['mixed', (n) => build(n, [
    Operation.payment({ destination: recipient, asset: XLM, amount: '1' }),
    Operation.payment({ destination: recipient, asset: USDC, amount: '2' })
  ])],
  ['memo-hash', (n) => build(n, [Operation.payment({ destination: recipient, asset: XLM, amount: '1' })], { memo: Memo.hash(Buffer.alloc(32, 0xab)) })],
  ['memo-return', (n) => build(n, [Operation.payment({ destination: recipient, asset: XLM, amount: '1' })], { memo: Memo.return(Buffer.alloc(32, 0xcd)) })],
  ['no-limit', (n) => build(n, [Operation.payment({ destination: recipient, asset: XLM, amount: '1' })], { timebounds: 'none' })],
  ['conditions', (n) => build(n, [Operation.payment({ destination: recipient, asset: XLM, amount: '1' })], {
    timebounds: { minTime: 1790000000, maxTime: 1798761600 },
    conditions: (b) => b.setLedgerbounds(60000000, 70000000).setMinAccountSequence('123456789000').setMinAccountSequenceAge(3600n).setMinAccountSequenceLedgerGap(10).setExtraSigners([signer, StrKey.encodeSignedPayload(Buffer.concat([Buffer.from(other(2).rawPublicKey()), Buffer.from([0, 0, 0, 4, 9, 9, 9, 9])]))])
  })],
  // its source as a muxed account: this account, ID 7
  ['muxed-source', (n) => build(n, [Operation.payment({ destination: recipient, asset: XLM, amount: '3' })], { account: new MuxedAccount(new Account(me.publicKey(), '123456789012'), '7') })],
  // another's transaction this account signs for: a service pays the fee, and the two swap
  ['swap', (n) => build(n, [
    Operation.payment({ source: me.publicKey(), destination: service.publicKey(), asset: XLM, amount: '10' }),
    Operation.payment({ destination: me.publicKey(), asset: USDC, amount: '1.1' })
  ], { source: service.publicKey(), sequence: '555' })],
  // a sign-in (SEP-10): sequence 0, so it can never go on chain
  ['sign-in', (n) => build(n, [
    Operation.manageData({ source: me.publicKey(), name: 'example.com auth', value: Buffer.alloc(48, 0x41) }),
    Operation.manageData({ name: 'web_auth_domain', value: 'auth.example.com' })
  ], { source: service.publicKey(), sequence: '-1', timebounds: { minTime: 1790000000, maxTime: 1790000900 } })],
  ['not-mine', (n) => build(n, [Operation.payment({ destination: recipient, asset: XLM, amount: '5' })], { source: stranger.publicKey() })],
  // a contract call: the USDC contract's transfer, with this account's authority, as stellar-sdk makes it
  ['contract', (n) => {
    const b = new TransactionBuilder(new Account(me.publicKey(), '123456789012'), { fee: '100', networkPassphrase: n, timebounds: until })
    b.addSacTransferOperation(recipient, USDC, '52500000')
    return b.build()
  }],
  ['contract-call', (n) => {
    const contract = StrKey.encodeContract(Buffer.alloc(32, 0x11))
    const args = [nativeToScVal(me.publicKey(), { type: 'address' }), nativeToScVal([1, 'two', { three: 3 }]), nativeToScVal(Buffer.from([1, 2, 3]))]
    const auth = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
      rootInvocation: new xdr.SorobanAuthorizedInvocation({
        function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({ contractAddress: new Address(contract).toScAddress(), functionName: 'swap', args })),
        subInvocations: []
      })
    })
    const data = new SorobanDataBuilder().setResources(2000000, 5000, 1000).setResourceFee(123456).setReadOnly([
      xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: new Address(contract).toScAddress(), key: xdr.ScVal.scvLedgerKeyContractInstance(), durability: xdr.ContractDataDurability.persistent })),
      xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: Buffer.alloc(32, 0x22) }))
    ]).setReadWrite([
      xdr.LedgerKey.account(new xdr.LedgerKeyAccount({ accountId: me.xdrPublicKey() })),
      xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: new Address(contract).toScAddress(), key: nativeToScVal(['Balance', me.publicKey()], { type: ['symbol', 'address'] }), durability: xdr.ContractDataDurability.temporary }))
    ]).build()
    return build(n, [Operation.invokeContractFunction({ contract, function: 'swap', args, auth: [auth] })], { soroban: data, timebounds: until })
  }],
  // a call others authorize too, and this account apart from the transaction
  ['contract-authorized', (n) => {
    const data = new SorobanDataBuilder().setResources(500000, 1000, 1000).setResourceFee(20000).build()
    return build(n, [Operation.invokeContractFunction({ contract: deposit, function: 'deposit', args: depositArgs, auth: authorized[n] })], { soroban: data })
  }],
  // a call that isn't given this account's authority
  ['contract-no-auth', (n) => {
    const contract = StrKey.encodeContract(Buffer.alloc(32, 0x33))
    const data = new SorobanDataBuilder().setResources(100000, 1000, 0).setResourceFee(5000).setReadOnly([
      xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: new Address(contract).toScAddress(), key: xdr.ScVal.scvLedgerKeyContractInstance(), durability: xdr.ContractDataDurability.persistent }))
    ]).build()
    return build(n, [Operation.invokeContractFunction({ contract, function: 'hello', args: [nativeToScVal('world', { type: 'symbol' })] })], { soroban: data })
  }],
  ['upload', (n) => {
    const wasm = Buffer.from('0061736d0100000001040160000003020100070a01066d61696e0000', 'hex')
    const data = new SorobanDataBuilder().setResources(1000000, 0, 600).setResourceFee(90000).setReadWrite([
      xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: hash(wasm) }))
    ]).build()
    return build(n, [Operation.uploadContractWasm({ wasm })], { soroban: data })
  }],
  ['new-contract', (n) => {
    const data = new SorobanDataBuilder().setResources(1000000, 2000, 800).setResourceFee(70000).build()
    return build(n, [Operation.createCustomContract({ address: new Address(me.publicKey()), wasmHash: Buffer.alloc(32, 0x44), salt: Buffer.alloc(32, 0x55), constructorArgs: [nativeToScVal(7, { type: 'u32' })] })], { soroban: data })
  }],
  ['asset-contract', (n) => {
    const data = new SorobanDataBuilder().setResources(1000000, 2000, 800).setResourceFee(60000).build()
    return build(n, [Operation.createStellarAssetContract({ asset: MAKI })], { soroban: data })
  }],
  ['extend', (n) => {
    const contract = StrKey.encodeContract(Buffer.alloc(32, 0x11))
    const data = new SorobanDataBuilder().setResources(0, 500, 0).setResourceFee(25000).setReadOnly([
      xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: new Address(contract).toScAddress(), key: xdr.ScVal.scvLedgerKeyContractInstance(), durability: xdr.ContractDataDurability.persistent })),
      xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: Buffer.alloc(32, 0x22) }))
    ]).build()
    return build(n, [Operation.extendFootprintTtl({ extendTo: 500000 })], { soroban: data })
  }],
  ['restore', (n) => {
    const contract = StrKey.encodeContract(Buffer.alloc(32, 0x11))
    const data = new SorobanDataBuilder().setResources(0, 500, 500).setResourceFee(30000).setReadWrite([
      xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: new Address(contract).toScAddress(), key: nativeToScVal('Counter', { type: 'symbol' }), durability: xdr.ContractDataDurability.persistent }))
    ]).build()
    return build(n, [Operation.restoreFootprint({})], { soroban: data })
  }],
  // fee bumps: this account pays the fee of another's transaction, and of its own; and another
  // pays for this account's, which isn't this account's to sign
  ['fee-bump', (n) => {
    const inner = build(n, [Operation.payment({ destination: recipient, asset: XLM, amount: '4' })], { source: service.publicKey(), sequence: '555' })
    inner.sign(service)
    return TransactionBuilder.buildFeeBumpTransaction(me.publicKey(), '200', inner, n)
  }],
  ['fee-bump-mine', (n) => {
    const inner = build(n, [Operation.payment({ destination: recipient, asset: USDC, amount: '9' })])
    inner.sign(me)
    return TransactionBuilder.buildFeeBumpTransaction(me.publicKey(), '1000', inner, n)
  }],
  ['fee-bump-theirs', (n) => {
    const inner = build(n, [Operation.payment({ destination: recipient, asset: XLM, amount: '4' })])
    inner.sign(me)
    return TransactionBuilder.buildFeeBumpTransaction(service.publicKey(), '200', inner, n)
  }],
  // what Stellar refuses, which stellar-sdk builds anyway
  ['inflation', (n) => build(n, [Operation.inflation()])],
  ['revoke-pool', (n) => build(n, [Operation.revokeLiquidityPoolSponsorship({ liquidityPoolId: 'dd7b1ab831c273310ddbec6f97870aa83c2fbd78ce22aded37ecbf4f3380fac7' })])]
]

/** The same transaction as a version 0 envelope, as Stellar's tools wrote them before protocol 13:
 * the source a bare key, and time bounds where the conditions go. */
function v0(passphrase) {
  const tx = build(passphrase, [Operation.payment({ destination: recipient, asset: XLM, amount: '0.5' })], { memo: Memo.text('v0') })
  const v1 = tx.toEnvelope().value.tx
  const body = Buffer.from(v1.toXdr())
  // the source's key type (4 bytes) goes, and nothing else changes: TransactionV0's fields are
  // Transaction's, its time bounds an option where Transaction has conditions
  const v0tx = xdr.TransactionV0.fromXdr(body.subarray(4))
  const env = xdr.TransactionEnvelope.envelopeTypeTxV0(new xdr.TransactionV0Envelope({ tx: v0tx, signatures: [] }))
  return new Transaction(env, passphrase)
}

const out = []
for (const [network, passphrase] of [[0, Networks.PUBLIC], [1, Networks.TESTNET]]) {
  for (const [name, make] of [...kinds, ['v0', v0]]) {
    const tx = make(passphrase)
    const envelope = Buffer.from(tx.toEnvelope().toXdr())
    const before = tx.signatures.length
    tx.sign(me)
    const signature = Buffer.from(tx.signatures[before].signature.toXdrObject())
    // stellar-sdk reads the envelope back as the same transaction
    const again = TransactionBuilder.fromXdr(envelope.toString('base64'), passphrase)
    if (Buffer.from(again.hash()).toString('hex') !== Buffer.from(tx.hash()).toString('hex')) throw new Error(`${name}: read back differently`)
    out.push({ name, network, envelope: envelope.toString('hex'), hash: Buffer.from(tx.hash()).toString('hex'), signature: signature.toString('hex') })
  }
}
writeFileSync(process.argv[2], JSON.stringify(out, null, 1) + '\n')
console.log(out.filter((o) => o.network === 0).map((o) => `${o.name}: ${o.envelope.length / 2} bytes`).join('\n'))
