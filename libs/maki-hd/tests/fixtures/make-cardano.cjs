// Cardano's keys for maki-hd's tests, by EMURGO's cardano-serialization-lib (what Yoroi, Eternl and
// most of Cardano's wallets build on): the Icarus master key from a phrase's entropy (CIP-3), the
// CIP-1852 account keys and the first addresses, and signatures with the extended keys. To make
// them again, in a scratch folder:
//   npm install @emurgo/cardano-serialization-lib-nodejs@17.0.0 bip39@3.1.0
//   node make-cardano.cjs > cardano.json
const CSL = require('@emurgo/cardano-serialization-lib-nodejs')
const bip39 = require('bip39')

const PHRASES = [
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  // twenty-four words, as maki makes them
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art'
]
const H = 0x80000000
const hex = (b) => Buffer.from(b).toString('hex')
const out = []
for (const phrase of PHRASES) {
  const entropy = Buffer.from(bip39.mnemonicToEntropy(phrase), 'hex')
  const root = CSL.Bip32PrivateKey.from_bip39_entropy(entropy, Buffer.alloc(0))
  const account = root.derive(1852 + H).derive(1815 + H).derive(0 + H)
  const pay = account.derive(0).derive(0)
  const stake = account.derive(2).derive(0)
  const change = account.derive(1).derive(0)
  const credential = (k) => CSL.Credential.from_keyhash(k.to_public().to_raw_key().hash())
  const base = (network, k) =>
    CSL.BaseAddress.new(network, credential(k), credential(stake)).to_address().to_bech32()
  const message = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex')
  out.push({
    phrase,
    entropy: hex(entropy),
    // 96 bytes: kL ‖ kR (the extended key) ‖ the chain code
    root: hex(root.as_bytes()),
    // the account's public key ‖ its chain code: what derives every address
    account: hex(account.to_public().as_bytes()),
    payment0: hex(pay.to_public().to_raw_key().as_bytes()),
    change0: hex(change.to_public().to_raw_key().as_bytes()),
    stake0: hex(stake.to_public().to_raw_key().as_bytes()),
    address: base(1, pay),
    changeAddress: base(1, change),
    testAddress: base(0, pay),
    reward: CSL.RewardAddress.new(1, credential(stake)).to_address().to_bech32(),
    message: hex(message),
    signature: hex(pay.to_raw_key().sign(message).to_bytes()),
    stakeSignature: hex(stake.to_raw_key().sign(message).to_bytes()),
    // a deeper, hardened path too: m/1852'/1815'/7'/0/3
    deep: hex(root.derive(1852 + H).derive(1815 + H).derive(7 + H).derive(0).derive(3).to_public().to_raw_key().as_bytes())
  })
}
console.log(JSON.stringify(out, null, 2))
