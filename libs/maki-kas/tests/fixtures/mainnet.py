# Transactions Kaspa's mainnet took, for maki-kas's tests: their inputs' signatures must check out
# against maki's signature hash, as consensus checked them against its own. Fetched from the Kaspa REST
# API (api.kaspa.org, kaspa-rest-server v2.2.3, its inputs resolved to the coins they spend), with Python
# 3.14's standard library alone. The API leaves out each input's sequence: for a version 0 transaction
# it's found as the one its ID was made with (Kaspa's TransactionID, keyed BLAKE2b); a version 1's ID is
# BLAKE3's, which Python hasn't, so its sequences are taken as 0, as wallets write them (the test then
# shows they were). Lock times and gas are taken as 0, the ID agreeing for version 0. To fetch again:
#   python3 mainnet.py mainnet.json
import hashlib
import json
import struct
import sys
import urllib.request

# a payment with change; eight coins swept, each input's sequence 1; data (a Kasplex payload), sequence
# at its most; a lane's transaction (Toccata's version 1, compute budget for its count, data); 35 coins
TXIDS = [
    '5baa50e0b44f457d5ec11964f9267999feb29730b6bf86b5adc00ad7666ae526',
    '93f04b5f3d1c62ba756003f670c62700dc30820f60d31c2e4e89cd4602633c02',
    '0c132f1820b814e9c3c66b271be8a571d9128228ceeeed616a47e78c11c46faf',
    '97b1e4857542f4d82ec7ea0df28b3c245b28464416e1b66583ea5f6e1b27a494',
    '3a8e0c6b4c70ac6ec270c143c0a86dee123039de50ff61cfda5418a868517f8f',
]


def u16(n): return struct.pack('<H', n)
def u32(n): return struct.pack('<I', n)
def u64(n): return struct.pack('<Q', n)
def var(b): return u64(len(b)) + b


def txid(t, sequence):
    """A version 0 transaction's ID (rusty-kaspa's `id_v0`): the transaction without its signature
    scripts or mass, hashed with BLAKE2b keyed "TransactionID"."""
    b = u16(t['version']) + u64(len(t['inputs']))
    for i in t['inputs']:
        b += bytes.fromhex(i['previous_outpoint_hash']) + u32(int(i['previous_outpoint_index'])) + var(b'') + u64(sequence)
    b += u64(len(t['outputs']))
    for o in t['outputs']:
        b += u64(o['amount']) + u16(0) + var(bytes.fromhex(o['script_public_key']))
    b += u64(0) + bytes.fromhex(t['subnetwork_id']) + u64(0) + var(bytes.fromhex(t.get('payload') or ''))
    return hashlib.blake2b(b, digest_size=32, key=b'TransactionID').hexdigest()


request = urllib.request.Request(
    'https://api.kaspa.org/transactions/search?resolve_previous_outpoints=full',
    data=json.dumps({'transactionIds': TXIDS}).encode(),
    headers={'Content-Type': 'application/json', 'User-Agent': 'maki-kas fixtures'},
)
found = {t['transaction_id']: t for t in json.load(urllib.request.urlopen(request, timeout=60))}
out = []
for id in TXIDS:
    t = found[id]
    t['inputs'].sort(key=lambda i: i['index'])
    t['outputs'].sort(key=lambda o: o['index'])
    sequence = 0
    if t['version'] == 0:
        sequence = next(s for s in [0, 1, 2**64 - 1] if txid(t, s) == id)
    out.append({
        'txid': id,
        'version': t['version'],
        'subnetwork': t['subnetwork_id'],
        'payload': t.get('payload') or '',
        'inputs': [{
            'txid': i['previous_outpoint_hash'],
            'index': int(i['previous_outpoint_index']),
            'sequence': str(sequence),
            'sigOpCount': int(i['sig_op_count'] or 0),
            'computeBudget': i.get('compute_budget') or 0,
            'amount': i['previous_outpoint_resolved']['amount'],
            'script': i['previous_outpoint_resolved']['script_public_key'],
            'signatureScript': i['signature_script'],
        } for i in t['inputs']],
        'outputs': [{'value': o['amount'], 'script': o['script_public_key']} for o in t['outputs']],
    })
    print(f"{id}: version {t['version']}, {len(t['inputs'])} in, {len(t['outputs'])} out, sequence {sequence}")
with open(sys.argv[1], 'w') as f:
    json.dump(out, f, indent=1)
    f.write('\n')
