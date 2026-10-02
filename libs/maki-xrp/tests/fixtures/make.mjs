// Transactions for maki-xrp's tests, made with the XRP Ledger's own JavaScript library, and each
// signed by the test phrase's first account as xrpl.js signs it: what maki must show, and sign
// the same. And maki's table of the ledger's fields and transaction types (src/definitions.rs),
// from the binary codec's own definitions, so maki knows the fields rippled knows.
//
// Made with xrpl 5.3.0, which brings ripple-binary-codec 2.11.0, ripple-keypairs 3.1.0,
// ripple-address-codec 5.0.1, @noble/curves 2.4.0, @scure/bip32 2.4.0 and @scure/bip39 2.4.0.
// To make them again, beside the installed packages (node finds them from the script's own
// directory, so copy it there):
//   npm install --save-exact xrpl@5.3.0
//   node make.mjs <maki-xrp>/tests/fixtures/transactions.json <maki-xrp>/src/definitions.rs
import { writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { ECDSA, Wallet, decode, encode, encodeForSigning, hashes, verifySignature } from 'xrpl'

const require = createRequire(import.meta.url)
const definitions = require('ripple-binary-codec/dist/enums/definitions.json')
const versions = ['xrpl', 'ripple-binary-codec', 'ripple-keypairs'].map((p) => `${p} ${require(`${p}/package.json`).version}`)

const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
// xrpl.js's own path for a phrase, m/44'/144'/0'/0/0, as Ledger, Xaman and Trust Wallet have it
const me = Wallet.fromMnemonic(phrase)
// the account Ripple's Xpring SDK published for the phrase (its README), with its key
if (me.classicAddress !== 'rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3') throw new Error('not the published account')
if (me.publicKey !== '031D68BC1A142E6766B2BDFB006CCFE135EF2E0E2E94ABB5CF5C9AB6104776FBAE') throw new Error('not the published key')
const second = Wallet.fromMnemonic(phrase, { derivationPath: "m/44'/144'/1'/0/0" })
const other = (n) => Wallet.fromEntropy(new Uint8Array(16).fill(n), { algorithm: ECDSA.secp256k1 })
const recipient = other(1).classicAddress
const issuer = other(2).classicAddress
const regular = other(3).classicAddress
const signers = [4, 5, 6].map((n) => other(n).classicAddress)
const stranger = other(7)
const RLUSD = { currency: '524C555344000000000000000000000000000000', issuer: 'rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De' }
const hex = (text) => Buffer.from(text, 'utf8').toString('hex').toUpperCase()
// the most an account's last ledger is set ahead of the network's, as xrpl.js's autofill sets it
const common = { Account: me.classicAddress, Fee: '12', Sequence: 7, LastLedgerSequence: 107373103 }

const out = []
/** A transaction from this account (or `from`), as xrpl.js encodes it unsigned and signs it. */
function tx(name, fields, { from = me, signed = true } = {}) {
  const t = { ...common, Account: from.classicAddress, ...fields }
  if (t.SigningPubKey === undefined) t.SigningPubKey = from.publicKey
  for (const k of Object.keys(t)) if (t[k] === undefined) delete t[k]
  const unsigned = encode(t)
  // what's signed is the same bytes, after the prefix "STX\0"
  if (encodeForSigning(t) !== '53545800' + unsigned) throw new Error(`${name}: signing bytes differ`)
  const entry = { name, transaction: unsigned }
  if (signed) {
    const { tx_blob, hash } = from.sign(t)
    if (!verifySignature(tx_blob, from.publicKey)) throw new Error(`${name}: doesn't verify`)
    entry.signature = from === me ? decode(tx_blob).TxnSignature : null
    entry.signed = tx_blob
    entry.hash = hash
    if (hashes.hashSignedTx(tx_blob) !== hash) throw new Error(`${name}: hash`)
  } else {
    entry.signature = null
  }
  out.push(entry)
}

// XRP, plain; and with what an exchange needs (a tag), a memo, the sender's tag and an invoice
tx('xrp', { TransactionType: 'Payment', Destination: recipient, Amount: '1500000' })
tx('xrp-tag-memo', {
  TransactionType: 'Payment',
  Destination: recipient,
  Amount: '12500000',
  DestinationTag: 4242,
  SourceTag: 7,
  InvoiceID: '6F1DFD1D0FE8A32E40E1F2C05CF1C15545BAB56B617F9C6C2D63A6B704BEF59B',
  Memos: [{ Memo: { MemoType: hex('text/plain'), MemoData: hex('thanks for the coffee') } }, { Memo: { MemoData: 'FF00' } }]
})
// tokens: one maki doesn't know (USD of an issuer), and Ripple's RLUSD
tx('usd', { TransactionType: 'Payment', Destination: recipient, Amount: { currency: 'USD', issuer, value: '25.75' } })
tx('rlusd', { TransactionType: 'Payment', Destination: recipient, Amount: { ...RLUSD, value: '100' } })
// RLUSD bought with XRP on the way: the most it costs, and the path
tx('cross', {
  TransactionType: 'Payment',
  Destination: recipient,
  Amount: { ...RLUSD, value: '10' },
  SendMax: '25000000',
  Paths: [[{ currency: RLUSD.currency, issuer: RLUSD.issuer }]]
})
// a partial payment: the recipient may get as little as DeliverMin
tx('partial', {
  TransactionType: 'Payment',
  Destination: recipient,
  Amount: { currency: 'USD', issuer, value: '100' },
  DeliverMin: { currency: 'USD', issuer, value: '1' },
  SendMax: '50000000',
  Flags: 0x00020000
})
// an MPT: the issuer's issuance made at its sequence 42
tx('mpt', {
  TransactionType: 'Payment',
  Destination: recipient,
  Amount: { mpt_issuance_id: '0000002A' + accountHex(issuer), value: '1000' }
})
// a token whose own code spells XRP: it isn't XRP
tx('fake-xrp', { TransactionType: 'Payment', Destination: recipient, Amount: { currency: hex('XRP').padEnd(40, '0'), issuer, value: '1000' } })
// USD bought with XRP only at the rate asked, along the direct path
tx('limit-quality', {
  TransactionType: 'Payment',
  Destination: recipient,
  Amount: { currency: 'USD', issuer, value: '5' },
  SendMax: '10000000',
  Flags: 0x00040000
})
// XRP turned into USD in this account: to itself, through the order book
tx('convert', {
  TransactionType: 'Payment',
  Destination: me.classicAddress,
  Amount: { currency: 'USD', issuer, value: '5' },
  SendMax: '10000000',
  Paths: [[{ currency: 'USD', issuer }]]
})
// a payment by ticket, and one that stays good until it's sent
tx('ticket', { TransactionType: 'Payment', Destination: recipient, Amount: '1000000', Sequence: 0, TicketSequence: 12 })
tx('no-last-ledger', { TransactionType: 'Payment', Destination: recipient, Amount: '1000000', LastLedgerSequence: undefined })
// a fee no wallet would set: 5 XRP
tx('high-fee', { TransactionType: 'Payment', Destination: recipient, Amount: '1000000', Fee: '5000000' })
// trust lines: RLUSD's; a token by a code of its own with the largest limit and a quality, letting
// payments ripple; and one taken away
tx('trust-rlusd', { TransactionType: 'TrustSet', LimitAmount: { ...RLUSD, value: '1000000' }, Flags: 0x00020000 })
tx('trust-solo', {
  TransactionType: 'TrustSet',
  LimitAmount: { currency: hex('SOLO').padEnd(40, '0'), issuer, value: '9999999999999999e80' },
  QualityIn: 1010000000,
  Flags: 0x00040000
})
tx('trust-remove', { TransactionType: 'TrustSet', LimitAmount: { currency: 'USD', issuer, value: '0' } })
// the exchange
tx('offer', {
  TransactionType: 'OfferCreate',
  TakerGets: '100000000',
  TakerPays: { currency: 'USD', issuer, value: '250' },
  Expiration: 812400000,
  OfferSequence: 5,
  Flags: 0x00080000
})
tx('offer-cancel', { TransactionType: 'OfferCancel', OfferSequence: 5 })
// the account's settings, and what hands it over
tx('account-set', { TransactionType: 'AccountSet', SetFlag: 1, Domain: hex('example.com'), TransferRate: 1002000000, TickSize: 5 })
tx('disable-master', { TransactionType: 'AccountSet', SetFlag: 4 })
tx('minter', { TransactionType: 'AccountSet', SetFlag: 10, NFTokenMinter: regular })
tx('regular-key', { TransactionType: 'SetRegularKey', RegularKey: regular })
tx('regular-key-off', { TransactionType: 'SetRegularKey' })
tx('signers', {
  TransactionType: 'SignerListSet',
  SignerQuorum: 3,
  SignerEntries: signers.map((Account, i) => ({ SignerEntry: { Account, SignerWeight: i === 0 ? 2 : 1 } }))
})
tx('signers-off', { TransactionType: 'SignerListSet', SignerQuorum: 0 })
tx('delete', { TransactionType: 'AccountDelete', Destination: recipient, DestinationTag: 99, Fee: '200000' })
// checks
const checkID = '49647F0D748DC3FE26BDACBC57F251AADEFFF391403EC9BF87C97F67E9977FB0'
tx('check', {
  TransactionType: 'CheckCreate',
  Destination: recipient,
  SendMax: { currency: 'USD', issuer, value: '50' },
  Expiration: 812400000,
  InvoiceID: '6F1DFD1D0FE8A32E40E1F2C05CF1C15545BAB56B617F9C6C2D63A6B704BEF59B'
})
tx('check-cash', { TransactionType: 'CheckCash', CheckID: checkID, DeliverMin: '95000000' })
tx('check-cancel', { TransactionType: 'CheckCancel', CheckID: checkID })
// escrows: XRP held for a recipient until a time, unless a condition is met; finished; cancelled
const condition = 'A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100'
tx('escrow', {
  TransactionType: 'EscrowCreate',
  Destination: recipient,
  Amount: '50000000',
  FinishAfter: 812345678,
  CancelAfter: 812400000,
  Condition: condition,
  DestinationTag: 23
})
tx('escrow-finish', { TransactionType: 'EscrowFinish', Owner: issuer, OfferSequence: 5, Condition: condition, Fulfillment: 'A0028000' })
tx('escrow-cancel', { TransactionType: 'EscrowCancel', Owner: me.classicAddress, OfferSequence: 5 })
// what maki doesn't read: an NFT minted, and a field every transaction may have that does nothing
// maki can say
tx('nft-mint', { TransactionType: 'NFTokenMint', NFTokenTaxon: 0, URI: hex('ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi'), TransferFee: 500, Flags: 8 })
tx('unread-field', { TransactionType: 'Payment', Destination: recipient, Amount: '1000000', OperationLimit: 3 })
// what isn't this account's to sign: another's, multisigned, another network's
tx('not-mine', { TransactionType: 'Payment', Destination: recipient, Amount: '5' }, { from: stranger })
tx('multisig', { TransactionType: 'Payment', Destination: recipient, Amount: '5', SigningPubKey: '' }, { signed: false })
tx('other-network', { TransactionType: 'Payment', Destination: recipient, Amount: '5', NetworkID: 21337 })

/** An account's 20 bytes, in hex. */
function accountHex(address) {
  return encode({ Account: address }).slice(4)
}

// what the ledger would refuse, or maki won't sign, encoded as xrpl.js encodes anything it's given
const refused = []
function refuse(name, fields) {
  const t = { ...common, SigningPubKey: me.publicKey, ...fields }
  for (const k of Object.keys(t)) if (t[k] === undefined) delete t[k]
  refused.push({ name, transaction: encode(t) })
}
const pay = { TransactionType: 'Payment', Destination: recipient, Amount: '1000000' }
const usd = (value, by = issuer) => ({ currency: 'USD', issuer: by, value })
const mpt = { mpt_issuance_id: '0000002A' + accountHex(issuer), value: '5' }
refuse('xrp-to-self', { ...pay, Destination: me.classicAddress })
refuse('xrp-partial', { ...pay, Flags: 0x00020000 })
refuse('xrp-send-max', { ...pay, SendMax: '2000000' })
refuse('xrp-paths', { ...pay, Paths: [[{ currency: 'USD', issuer }]] })
refuse('nothing', { ...pay, Amount: '0' })
refuse('xrp-code', { ...pay, Amount: { currency: '0000000000000000000000005852500000000000', issuer, value: '1' } })
refuse('sponsor-flag', { ...pay, Flags: 0x00080000 })
refuse('deliver-min-whole', { ...pay, Amount: usd('100'), DeliverMin: usd('1'), SendMax: '5000000' })
refuse('deliver-min-more', { ...pay, Amount: usd('1'), DeliverMin: usd('2'), SendMax: '5000000', Flags: 0x00020000 })
refuse('deliver-min-other', { ...pay, Amount: usd('1'), DeliverMin: usd('1', regular), SendMax: '5000000', Flags: 0x00020000 })
refuse('no-direct-no-paths', { ...pay, Amount: usd('1'), SendMax: '5000000', Flags: 0x00010000 })
refuse('seven-paths', { ...pay, Amount: usd('1'), SendMax: '5000000', Paths: Array.from({ length: 7 }, () => [{ currency: 'USD', issuer }]) })
refuse('mpt-paths', { ...pay, Amount: mpt, Paths: [[{ currency: 'USD', issuer }]] })
refuse('mpt-for-xrp', { ...pay, Amount: mpt, SendMax: '5000000' })
refuse('trust-xrp', { TransactionType: 'TrustSet', LimitAmount: '1000' })
refuse('trust-self', { TransactionType: 'TrustSet', LimitAmount: usd('5', me.classicAddress) })
refuse('trust-freeze-thaw', { TransactionType: 'TrustSet', LimitAmount: usd('5'), Flags: 0x00100000 | 0x00200000 })
refuse('offer-xrp-for-xrp', { TransactionType: 'OfferCreate', TakerGets: '1000', TakerPays: '2000' })
refuse('offer-ioc-fok', { TransactionType: 'OfferCreate', TakerGets: '1000', TakerPays: usd('2'), Flags: 0x00020000 | 0x00040000 })
refuse('offer-expiration-0', { TransactionType: 'OfferCreate', TakerGets: '1000', TakerPays: usd('2'), Expiration: 0 })
refuse('offer-mpt', { TransactionType: 'OfferCreate', TakerGets: '1000', TakerPays: mpt })
refuse('cancel-offer-0', { TransactionType: 'OfferCancel', OfferSequence: 0 })
refuse('set-and-clear', { TransactionType: 'AccountSet', SetFlag: 1, ClearFlag: 1 })
refuse('auth-both-ways', { TransactionType: 'AccountSet', SetFlag: 2, Flags: 0x00080000 })
refuse('transfer-rate', { TransactionType: 'AccountSet', TransferRate: 2000000001 })
refuse('tick-size', { TransactionType: 'AccountSet', TickSize: 2 })
refuse('message-key', { TransactionType: 'AccountSet', MessageKey: '04' + '11'.repeat(32) })
refuse('long-domain', { TransactionType: 'AccountSet', Domain: '61'.repeat(257) })
refuse('minter-missing', { TransactionType: 'AccountSet', SetFlag: 10 })
refuse('regular-key-self', { TransactionType: 'SetRegularKey', RegularKey: me.classicAddress })
const signer = (Account, SignerWeight = 1) => ({ SignerEntry: { Account, SignerWeight } })
refuse('signers-short', { TransactionType: 'SignerListSet', SignerQuorum: 5, SignerEntries: signers.slice(0, 2).map((a) => signer(a)) })
refuse('signers-self', { TransactionType: 'SignerListSet', SignerQuorum: 1, SignerEntries: [signer(me.classicAddress)] })
refuse('signers-twice', { TransactionType: 'SignerListSet', SignerQuorum: 1, SignerEntries: [signer(signers[0]), signer(signers[0])] })
refuse('signers-weightless', { TransactionType: 'SignerListSet', SignerQuorum: 1, SignerEntries: [signer(signers[0], 0), signer(signers[1])] })
refuse('signers-33', {
  TransactionType: 'SignerListSet',
  SignerQuorum: 1,
  SignerEntries: Array.from({ length: 33 }, (_, i) => signer(other(40 + i).classicAddress))
})
refuse('signers-quorum-0', { TransactionType: 'SignerListSet', SignerQuorum: 0, SignerEntries: [signer(signers[0])] })
refuse('signers-none', { TransactionType: 'SignerListSet', SignerQuorum: 2 })
refuse('delete-into-itself', { TransactionType: 'AccountDelete', Destination: me.classicAddress })
refuse('check-to-itself', { TransactionType: 'CheckCreate', Destination: me.classicAddress, SendMax: '5000' })
refuse('check-for-nothing', { TransactionType: 'CheckCreate', Destination: recipient, SendMax: '0' })
refuse('cash-both', { TransactionType: 'CheckCash', CheckID: checkID, Amount: '5', DeliverMin: '5' })
refuse('escrow-timeless', { TransactionType: 'EscrowCreate', Destination: recipient, Amount: '5', Condition: condition })
refuse('escrow-backwards', { TransactionType: 'EscrowCreate', Destination: recipient, Amount: '5', FinishAfter: 812400000, CancelAfter: 812345678 })
refuse('escrow-open', { TransactionType: 'EscrowCreate', Destination: recipient, Amount: '5', CancelAfter: 812400000 })
refuse('escrow-condition', { TransactionType: 'EscrowCreate', Destination: recipient, Amount: '5', FinishAfter: 812345678, Condition: 'A0258120' + '00'.repeat(35) })
refuse('finish-half', { TransactionType: 'EscrowFinish', Owner: issuer, OfferSequence: 5, Condition: condition })
refuse('memo-big', { ...pay, Memos: [{ Memo: { MemoData: '61'.repeat(1100) } }] })
refuse('memo-type', { ...pay, Memos: [{ Memo: { MemoType: hex('text plain'), MemoData: '61' } }] })
refuse('delegate', { ...pay, Delegate: regular })
refuse('another-key', { ...pay, SigningPubKey: other(3).publicKey })
refuse('ed25519-key', { ...pay, SigningPubKey: 'ED' + '22'.repeat(32) })
refuse('signed', { ...pay, TxnSignature: '3006020101020101' })
refuse('signers-in-it', { ...pay, Signers: [{ Signer: { Account: regular, SigningPubKey: other(3).publicKey, TxnSignature: '3006020101020101' } }] })
refuse('batch-inner', { ...pay, Flags: 0x40000000 })
refuse('sequence-and-ticket', { ...pay, TicketSequence: 12 })
refuse('ticket-and-previous', { ...pay, Sequence: 0, TicketSequence: 12, AccountTxnID: checkID })
refuse('fee-in-tokens', { ...pay, Fee: usd('1') })
refuse('not-a-payment-field', { ...pay, LimitAmount: usd('1') })
refuse('no-destination', { ...pay, Destination: undefined })
refuse('no-account', { ...pay, Account: 'rrrrrrrrrrrrrrrrrrrrrhoLvTp' })
refuse('pseudo', { TransactionType: 'EnableAmendment', Account: 'rrrrrrrrrrrrrrrrrrrrrhoLvTp', Amendment: checkID, LedgerSequence: 5 })

const accounts = { me: me.classicAddress, second: second.classicAddress, recipient, issuer, regular, signers, stranger: stranger.classicAddress }
const made = versions.join(', ')
writeFileSync(process.argv[2], JSON.stringify({ made, accounts, transactions: out, refused }, null, 1) + '\n')

// maki's table of fields and transaction types, from the codec's definitions
const types = definitions.TYPES
const fields = definitions.FIELDS.filter(([, f]) => f.isSerialized && f.nth > 0 && types[f.type] > 0 && types[f.type] < 256)
  .map(([name, f]) => ({ name, id: (types[f.type] << 8) | f.nth, signing: f.isSigningField }))
  .sort((a, b) => a.id - b.id)
const byName = Object.fromEntries(fields.map((f) => [f.name, f]))
const id = (n) => `0x${n.toString(16).padStart(4, '0')}`
const transactionTypes = Object.entries(definitions.TRANSACTION_TYPES).filter(([, code]) => code >= 0).sort((a, b) => a[1] - b[1])
const need = (o) => ['REQUIRED', 'OPTIONAL', 'DEFAULT'][o]
// entries one to a line, each field's name after it, the names lined up as rustfmt lines them up
const entries = (list) => {
  const lines = list.map(([prefix, e]) => [`(${prefix}${id(byName[e.name].id)}, ${need(e.optionality)}),`, e.name])
  const width = Math.max(...lines.map(([code]) => code.length))
  return lines.map(([code, name]) => `    ${code.padEnd(width)} // ${name}`).join('\n')
}
let rs = `//! The XRP Ledger's fields and transaction types, as its binary format numbers them: made by
//! \`tests/fixtures/make.mjs\` from the binary codec's own definitions (${versions[1]}'s
//! definitions.json, ${versions[0]}'s). Don't edit it: make it again.

/// A field a transaction must have.
pub const REQUIRED: u8 = 0;
/// A field a transaction may have.
pub const OPTIONAL: u8 = 1;
/// A field a transaction may have, but not with its default value (an empty path set).
pub const DEFAULT: u8 = 2;

/// Every field the ledger knows, by its id (its type's code, then its own, a byte each), in
/// order: its name, and whether a signature covers it (none covers a signature).
pub const FIELDS: &[(u16, &str, bool)] = &[
${fields.map((f) => `    (${id(f.id)}, ${JSON.stringify(f.name)}, ${f.signing}),`).join('\n')}
];

/// The transaction types, by their code.
pub const TRANSACTION_TYPES: &[(u16, &str)] = &[
${transactionTypes.map(([name, code]) => `    (${code}, ${JSON.stringify(name)}),`).join('\n')}
];

/// The fields every transaction may have, and whether it must.
pub const COMMON: &[(u16, u8)] = &[
${entries(definitions.TRANSACTION_FORMATS.common.map((e) => ['', e]))}
];

/// The fields each transaction type has besides the common ones: its code, the field, and
/// whether it must.
pub const FORMATS: &[(u16, u16, u8)] = &[
${entries(
  transactionTypes
    .filter(([name]) => definitions.TRANSACTION_FORMATS[name])
    .flatMap(([name, code]) => definitions.TRANSACTION_FORMATS[name].map((e) => [`${code}, `, e]))
)}
];
`
writeFileSync(process.argv[3], rs)
console.log(out.map((o) => `${o.name}: ${o.transaction.length / 2} bytes`).join('\n'))
