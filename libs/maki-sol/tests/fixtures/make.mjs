// Transactions for maki-sol's tests, made with Solana's own JavaScript libraries (@solana/web3.js
// 1.x and @solana/spl-token), and each signed by the test phrase's first account, as Phantom
// derives it: what maki must show, and sign the same. To make them again:
//   npm install @solana/web3.js@1 @solana/spl-token@0.4 && node make.mjs transactions.json
import { createHmac, pbkdf2Sync } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import {
  AddressLookupTableAccount,
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  SystemProgram,
  StakeProgram,
  Transaction,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction
} from '@solana/web3.js'
import {
  AuthorityType,
  NATIVE_MINT,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  createApproveCheckedInstruction,
  createApproveInstruction,
  createAssociatedTokenAccountIdempotentInstruction,
  createBurnCheckedInstruction,
  createCloseAccountInstruction,
  createSetAuthorityInstruction,
  createSyncNativeInstruction,
  createTransferCheckedInstruction,
  createTransferInstruction,
  getAssociatedTokenAddressSync
} from '@solana/spl-token'

const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const seed = pbkdf2Sync(Buffer.from(phrase), Buffer.from('mnemonic'), 2048, 64, 'sha512')
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
const me = Keypair.fromSeed(slip10([44, 501, 0, 0]))
if (me.publicKey.toBase58() !== 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk') throw new Error('not Phantom’s account')
const other = (n) => Keypair.fromSeed(new Uint8Array(32).fill(n))
const recipient = other(1).publicKey
const delegate = other(2).publicKey
const payer = other(3)
const created = other(4)
const nonce = other(5).publicKey
const program = other(6).publicKey
const table = other(7).publicKey
const stranger = other(8)
const mint = other(9).publicKey
const blockhash = 'EETubP5AKHgjPAhzPAFcb8BAY1hMH639CWCFTqi3hq1k'
const USDC = new PublicKey('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v')
const PYUSD = new PublicKey('2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo')
const MEMO = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr')
const ata = (owner, m, p = TOKEN_PROGRAM_ID) => getAssociatedTokenAddressSync(m, owner, true, p)
const fee = [
  ComputeBudgetProgram.setComputeUnitLimit({ units: 600 }),
  ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 100_000 })
]

const out = []
/** A legacy transaction, signed by `signers` (maki's account among them). */
function legacy(name, instructions, { feePayer = me.publicKey, signers = [me] } = {}) {
  const tx = new Transaction({ feePayer, recentBlockhash: blockhash }).add(...instructions)
  const message = tx.serializeMessage()
  tx.sign(...signers)
  const sig = tx.signatures.find((s) => s.publicKey.equals(me.publicKey))?.signature
  out.push({ name, message: message.toString('hex'), signature: sig ? Buffer.from(sig).toString('hex') : null })
}
/** A version 0 transaction. */
function v0(name, instructions, tables = []) {
  const message = new TransactionMessage({ payerKey: me.publicKey, recentBlockhash: blockhash, instructions }).compileToV0Message(tables)
  const tx = new VersionedTransaction(message)
  tx.sign([me])
  out.push({ name, message: Buffer.from(message.serialize()).toString('hex'), signature: Buffer.from(tx.signatures[0]).toString('hex') })
}

const transfer = (lamports, to = recipient) => SystemProgram.transfer({ fromPubkey: me.publicKey, toPubkey: to, lamports })
legacy('sol', [...fee, transfer(1_500_000_000)])
v0('sol-v0', [...fee, transfer(1_500_000_000)])
legacy('usdc', [
  ...fee,
  createAssociatedTokenAccountIdempotentInstruction(me.publicKey, ata(recipient, USDC), recipient, USDC),
  createTransferCheckedInstruction(ata(me.publicKey, USDC), USDC, ata(recipient, USDC), me.publicKey, 5_250_000, 6)
])
legacy('pyusd-2022', [
  createAssociatedTokenAccountIdempotentInstruction(me.publicKey, ata(recipient, PYUSD, TOKEN_2022_PROGRAM_ID), recipient, PYUSD, TOKEN_2022_PROGRAM_ID),
  createTransferCheckedInstruction(ata(me.publicKey, PYUSD, TOKEN_2022_PROGRAM_ID), PYUSD, ata(recipient, PYUSD, TOKEN_2022_PROGRAM_ID), me.publicKey, 10_000_000, 6, [], TOKEN_2022_PROGRAM_ID)
])
// a token maki doesn't know, to a token account nothing proves is anyone's
legacy('unknown-token', [createTransferCheckedInstruction(ata(me.publicKey, mint), mint, ata(recipient, mint), me.publicKey, 42_000_000_000n, 9)])
// a plain transfer: no mint, no decimals
legacy('plain-token', [createTransferInstruction(ata(me.publicKey, USDC), ata(recipient, USDC), me.publicKey, 1_000_000)])
legacy('nonce', [SystemProgram.nonceAdvance({ noncePubkey: nonce, authorizedPubkey: me.publicKey }), transfer(100_000_000)])
legacy('memo', [
  transfer(20_000_000),
  new TransactionInstruction({ programId: MEMO, keys: [{ pubkey: me.publicKey, isSigner: true, isWritable: false }], data: Buffer.from('thanks for the coffee') })
])
legacy('approve', [
  createApproveCheckedInstruction(ata(me.publicKey, USDC), USDC, delegate, me.publicKey, 100_000_000, 6),
  createApproveInstruction(ata(me.publicKey, mint), delegate, me.publicKey, 7)
])
legacy('set-authority', [createSetAuthorityInstruction(ata(me.publicKey, USDC), me.publicKey, AuthorityType.AccountOwner, delegate)])
legacy('others-pay', [SystemProgram.transfer({ fromPubkey: me.publicKey, toPubkey: payer.publicKey, lamports: 1_000_000_000 })], {
  feePayer: payer.publicKey,
  signers: [payer, me]
})
legacy('create-account', [
  SystemProgram.createAccount({ fromPubkey: me.publicKey, newAccountPubkey: created.publicKey, lamports: 2_282_880, space: 200, programId: StakeProgram.programId })
], { signers: [me, created] })
legacy('not-mine', [SystemProgram.transfer({ fromPubkey: stranger.publicKey, toPubkey: recipient, lamports: 5 })], {
  feePayer: stranger.publicKey,
  signers: [stranger]
})
legacy('assign', [SystemProgram.assign({ accountPubkey: me.publicKey, programId: program })])
legacy('wrap-unwrap', [
  createSyncNativeInstruction(ata(me.publicKey, NATIVE_MINT)),
  createBurnCheckedInstruction(ata(me.publicKey, USDC), USDC, me.publicKey, 1_000_000, 6),
  createCloseAccountInstruction(ata(me.publicKey, NATIVE_MINT), me.publicKey, me.publicKey)
])
// a swap-like call: a program maki doesn't know, given this account, with addresses from a lookup
// table; and SOL sent to an address in the table
const entries = [1, 2, 3, 4].map((n) => other(20 + n).publicKey)
const lookup = new AddressLookupTableAccount({ key: table, state: { deactivationSlot: 2n ** 64n - 1n, lastExtendedSlot: 0, lastExtendedSlotStartIndex: 0, addresses: entries } })
v0('swap-v0', [
  ...fee,
  new TransactionInstruction({
    programId: program,
    keys: [
      { pubkey: me.publicKey, isSigner: true, isWritable: true },
      { pubkey: entries[0], isSigner: false, isWritable: true },
      { pubkey: entries[1], isSigner: false, isWritable: false }
    ],
    data: Buffer.from([1, 2, 3, 4, 5])
  }),
  transfer(3_000_000, entries[2])
], [lookup])
// a program that isn't given this account
legacy('not-given', [
  transfer(1),
  new TransactionInstruction({ programId: program, keys: [{ pubkey: recipient, isSigner: false, isWritable: true }], data: Buffer.from([9]) })
])
writeFileSync(process.argv[2], JSON.stringify(out, null, 1) + '\n')
// the USDC payment's message and signature as bytes too, for the emulator's MAKI_DEMO_WALLET
const usdc = out.find((o) => o.name === 'usdc')
writeFileSync(new URL('usdc.bin', import.meta.url), Buffer.from(usdc.message, 'hex'))
writeFileSync(new URL('usdc.sig', import.meta.url), Buffer.from(usdc.signature, 'hex'))
console.log(out.map((o) => `${o.name}: ${Buffer.from(o.message, 'hex').length} bytes`).join('\n'))
