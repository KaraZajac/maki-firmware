//! Transactions maki signs, held to what others make of them: monero-oxide reads each one (its
//! hash and the message its signatures sign the same as ours), verifies every CLSAG and the range
//! proof, and the amounts balance; monero-rs finds each payment for whoever it pays, and the change
//! for this wallet; the extra is laid out as wallet2 lays it out.
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use maki_xmr::request::{self, Input, Member, Payment, Request, RequestError};
use maki_xmr::spend::{self, Paid, SpendError};
use maki_xmr::tx::Transaction;
use maki_xmr::{sign, Keys, Kind, Network};
use rand_core::OsRng;

fn hex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }

/// Numbers from a seed, the same every run.
struct Random(u64);

impl Random {
    fn u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for chunk in b.chunks_mut(8) {
            chunk.copy_from_slice(&self.u64().to_le_bytes());
        }
        b
    }

    fn scalar(&mut self) -> Scalar {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&self.bytes());
        wide[32..].copy_from_slice(&self.bytes());
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    fn point(&mut self) -> EdwardsPoint { G * self.scalar() }
}

/// The wallet the BIP39 test phrase gives (maki's, and Ledger's).
fn wallet() -> Keys {
    let spend: [u8; 32] = hex("3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109").try_into().unwrap();
    Keys::from_spend(Scalar::from_bytes_mod_order(spend))
}

fn keys_of(k: &Keys, major: u32, minor: u32) -> (EdwardsPoint, EdwardsPoint) {
    let (spend, view) = k.subaddress(major, minor);
    (sign::point(&spend).unwrap(), sign::point(&view).unwrap())
}

fn address_of(k: &Keys, major: u32, minor: u32) -> String {
    let (spend, view) = k.subaddress(major, minor);
    let kind = if (major, minor) == (0, 0) { Kind::Standard } else { Kind::Subaddress };
    maki_xmr::address(Network::Mainnet, kind, &spend, &view)
}

/// An output paid to `k`'s address (major, minor), as a sender makes one (to a subaddress alone,
/// the transaction's key is r times its spend key), or a coinbase output (its mask 1): its
/// transaction's key, its index there, its key and its commitment.
fn received(random: &mut Random, k: &Keys, major: u32, minor: u32, amount: u64, coinbase: bool) -> ([u8; 32], u64, [u8; 32], [u8; 32]) {
    let r = random.scalar();
    let (spend, view) = keys_of(k, major, minor);
    let tx_key = if (major, minor) == (0, 0) { G * r } else { spend * r };
    let index = random.u64() % 5;
    let out = sign::pay(&r, &view, &spend, index, amount);
    let commitment = if coinbase { sign::commit(&Scalar::ONE, amount).compress().to_bytes() } else { out.commitment };
    (tx_key.compress().to_bytes(), index, out.key, commitment)
}

/// An input spending that output, in a ring of 16 of the chain's outputs.
fn input(random: &mut Random, k: &Keys, minor: u32, amount: u64, coinbase: bool) -> Input {
    let (tx_key, index, key, commitment) = received(random, k, 0, minor, amount, coinbase);
    let real = (random.u64() % 16) as usize;
    let mut global = random.u64() % 1_000_000;
    let ring = (0..16)
        .map(|i| {
            global += 1 + random.u64() % 5000;
            if i == real {
                Member { global, key, commitment }
            } else {
                Member {
                    global,
                    key: random.point().compress().to_bytes(),
                    commitment: sign::commit(&random.scalar(), random.u64()).compress().to_bytes(),
                }
            }
        })
        .collect();
    Input { amount, tx_key, index, subaddress: minor, real, ring }
}

fn payment(address: &str, amount: u64) -> Payment {
    let (network, destination) = request::read_destination(address).unwrap();
    assert_eq!(network, Network::Mainnet);
    Payment { address: address.into(), amount, destination }
}

fn theirs(bytes: &[u8; 32]) -> monero_ed25519::CompressedPoint { monero_ed25519::CompressedPoint::from(*bytes) }

/// Everything the network, and whoever's paid, checks of a signed transaction.
fn check(request: &Request, signed: &spend::Signed, expected: &[(&Keys, u32, u32, u64)]) -> Transaction {
    let bytes = &signed.transaction;
    let tx = Transaction::from_bytes(bytes).expect("ours reads it");
    assert_eq!(&tx.to_bytes(), bytes);
    let oxide = monero_oxide::transaction::Transaction::<monero_oxide::transaction::NotPruned>::read(&mut &bytes[..]).expect("monero-oxide reads it");
    assert_eq!(oxide.hash(), tx.hash(), "the transaction's ID");
    assert_eq!(oxide.signature_hash(), Some(tx.signature_hash()), "what's signed");
    let message = tx.signature_hash();

    // inputs: key images from the greatest, each ring the request's, each CLSAG good
    let inputs = &tx.prefix.inputs;
    assert_eq!(inputs.len(), request.inputs.len());
    assert!(inputs.windows(2).all(|w| w[0].key_image > w[1].key_image));
    for (i, input) in inputs.iter().enumerate() {
        let globals: Vec<u64> = input.key_offsets.iter().scan(0, |sum, o| Some(*sum + o).inspect(|s| *sum = *s)).collect();
        let spent = request.inputs.iter().find(|r| r.ring.iter().map(|m| m.global).eq(globals.iter().copied())).expect("a ring asked for");
        let ring = spent.ring.iter().map(|m| [theirs(&m.key), theirs(&m.commitment)]).collect();
        let clsag = monero_clsag::Clsag::read(16, &mut &tx.clsags[i][..]).unwrap();
        clsag.verify(ring, &theirs(&input.key_image), &theirs(&tx.pseudo_outs[i]), &message).unwrap_or_else(|e| panic!("input {i}: {e:?}"));
    }
    // outputs: the range proof, and the amounts balance
    let commitments: Vec<_> = tx.base.commitments.iter().map(theirs).collect();
    let proof = monero_bulletproofs::Bulletproof::read_plus(&mut &tx.proof.to_bytes()[..]).unwrap();
    assert!(proof.verify(&mut OsRng, &commitments), "the range proof");
    let points = |v: &[[u8; 32]]| v.iter().map(|p| sign::point(p).unwrap()).sum::<EdwardsPoint>();
    assert_eq!(points(&tx.pseudo_outs), points(&tx.base.commitments) + sign::commit(&Scalar::ZERO, tx.base.fee), "balanced");
    assert_eq!(tx.base.fee, request.fee);
    assert_eq!(tx.prefix.outputs.len(), request.outputs());
    assert_eq!(signed.outputs.len(), request.outputs());

    // whoever's paid finds it, with the amount (monero-rs)
    let theirs_tx: monero::Transaction = monero::consensus::deserialize(bytes).expect("monero-rs reads it");
    for (who, major, minor, amount) in expected {
        let pair = monero::ViewPair {
            view: monero::PrivateKey::from_slice(&who.view_bytes()).unwrap(),
            spend: monero::PublicKey::from_slice(&who.public().0).unwrap(),
        };
        let found = theirs_tx.check_outputs(&pair, 0..(major + 1), 0..(minor + 1)).unwrap();
        let index = monero::cryptonote::subaddress::Index { major: *major, minor: *minor };
        let got: u64 = found.iter().filter(|o| o.sub_index() == index).map(|o| o.amount().unwrap().as_pico()).sum();
        assert_eq!(got, *amount, "paid to {major}/{minor}");
    }
    tx
}

#[test]
fn a_payment_with_change_is_one_monero_takes() {
    let mut random = Random(0x5e7d_0001);
    let me = wallet();
    let them = Keys::from_spend(random.scalar());
    let inputs = vec![input(&mut random, &me, 0, 3 * request::ATOMIC, false), input(&mut random, &me, 2, 250_000_000_000, false)];
    let request = Request {
        network: Network::Mainnet,
        account: 0,
        fee: 61_440_000,
        change: 3_250_000_000_000 - 1_200_000_000_000 - 61_440_000,
        payments: vec![payment(&address_of(&them, 0, 0), 1_200_000_000_000)],
        inputs,
    };
    let bytes = request.to_bytes();
    assert_eq!(Request::parse(&bytes), Ok(request.clone()));

    let signed = spend::sign(&me, &request, &[7; 32]).unwrap();
    let tx = check(&request, &signed, &[(&me, 0, 0, request.change), (&them, 0, 0, 1_200_000_000_000)]);
    // one payment and change: the transaction's key and a dummy payment ID, as wallet2's are
    let extra = &tx.prefix.extra;
    assert_eq!((extra.len(), extra[0], &extra[33..36]), (44, 1, &[2u8, 9, 1][..]));
    assert_eq!(&extra[1..33], (G * Scalar::from_bytes_mod_order(signed.tx_key)).compress().as_bytes());
    // the dummy payment ID is zeros to whoever's paid
    let r = sign::point(&extra[1..33].try_into().unwrap()).unwrap();
    let mut data = sign::derivation(&Scalar::from_bytes_mod_order(them.view_bytes()), &r).to_vec();
    data.push(0x8d);
    let pad = maki_xmr::keccak(&data);
    assert!(extra[36..].iter().zip(pad).all(|(e, p)| e ^ p == 0));
    // the change's key image, as this wallet would make it spending it
    let change = signed.outputs.iter().position(|p| *p == Paid::Change).unwrap();
    assert_eq!(signed.own.len(), 1);
    assert_eq!(signed.own[0].0 as usize, change);
    let secret = me.output_secret(&r, change as u64, 0, 0);
    let key = sign::point(&tx.prefix.outputs[change].key).unwrap();
    assert_eq!(G * secret, key);
    assert_eq!(signed.own[0].1, sign::key_image(&secret, &key).compress().to_bytes());

    // the same randomness, the same transaction; other randomness, another
    assert_eq!(spend::sign(&me, &request, &[7; 32]).unwrap(), signed);
    assert_ne!(spend::sign(&me, &request, &[8; 32]).unwrap().transaction, signed.transaction);
}

#[test]
fn one_payment_and_no_change_gets_wallet2_s_output_of_nothing() {
    let mut random = Random(0x5e7d_0002);
    let me = wallet();
    let them = Keys::from_spend(random.scalar());
    // a coinbase output, whose mask is 1, spent whole
    let request = Request {
        network: Network::Mainnet,
        account: 0,
        fee: 30_000_000,
        change: 0,
        payments: vec![payment(&address_of(&them, 0, 0), 17_000_000_000_000 - 30_000_000)],
        inputs: vec![input(&mut random, &me, 0, 17_000_000_000_000, true)],
    };
    let signed = spend::sign(&me, &request, &[1; 32]).unwrap();
    check(&request, &signed, &[(&them, 0, 0, 17_000_000_000_000 - 30_000_000)]);
    assert_eq!(signed.outputs.iter().filter(|p| **p == Paid::Dummy).count(), 1);
    assert!(signed.own.is_empty());
}

#[test]
fn to_a_subaddress_alone_the_key_is_r_times_its_spend_key() {
    let mut random = Random(0x5e7d_0003);
    let me = wallet();
    let them = Keys::from_spend(random.scalar());
    let request = Request {
        network: Network::Mainnet,
        account: 0,
        fee: 50_000_000,
        change: 1_000_000_000,
        payments: vec![payment(&address_of(&them, 0, 3), 2_000_000_000)],
        inputs: vec![input(&mut random, &me, 1, 3_050_000_000, false)],
    };
    let signed = spend::sign(&me, &request, &[2; 32]).unwrap();
    let tx = check(&request, &signed, &[(&me, 0, 0, 1_000_000_000), (&them, 0, 3, 2_000_000_000)]);
    let (spend, _) = keys_of(&them, 0, 3);
    assert_eq!(&tx.prefix.extra[1..33], (spend * Scalar::from_bytes_mod_order(signed.tx_key)).compress().as_bytes());
    assert!(signed.additional_keys.is_empty());
    assert_eq!(tx.prefix.extra.len(), 44);
}

#[test]
fn a_subaddress_and_another_address_give_each_output_its_own_key() {
    let mut random = Random(0x5e7d_0004);
    let me = wallet();
    let (them, other) = (Keys::from_spend(random.scalar()), Keys::from_spend(random.scalar()));
    let request = Request {
        network: Network::Mainnet,
        account: 0,
        fee: 80_000_000,
        change: 500_000_000,
        payments: vec![payment(&address_of(&them, 0, 1), 1_000_000_000), payment(&address_of(&other, 0, 0), 2_000_000_000)],
        inputs: vec![input(&mut random, &me, 0, 1_000_000_000, false), input(&mut random, &me, 0, 2_580_000_000, false)],
    };
    let signed = spend::sign(&me, &request, &[3; 32]).unwrap();
    let tx = check(&request, &signed, &[(&me, 0, 0, 500_000_000), (&them, 0, 1, 1_000_000_000), (&other, 0, 0, 2_000_000_000)]);
    // three outputs: no dummy payment ID; a key for each output
    let extra = &tx.prefix.extra;
    assert_eq!(signed.additional_keys.len(), 3);
    assert_eq!((extra.len(), extra[33], extra[34]), (35 + 32 * 3, 4, 3));
}

#[test]
fn an_integrated_address_s_payment_id_goes_with_it_encrypted() {
    let mut random = Random(0x5e7d_0005);
    let me = wallet();
    let them = Keys::from_spend(random.scalar());
    let (spend, view) = them.public();
    let id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let integrated = maki_xmr::integrated_address(Network::Mainnet, &spend, &view, &id);
    let request = Request {
        network: Network::Mainnet,
        account: 0,
        fee: 40_000_000,
        change: 60_000_000,
        payments: vec![payment(&integrated, 900_000_000)],
        inputs: vec![input(&mut random, &me, 0, 1_000_000_000, false)],
    };
    assert_eq!(request.pages()[0].prose, "payment ID 1122334455667788");
    let signed = spend::sign(&me, &request, &[4; 32]).unwrap();
    let tx = check(&request, &signed, &[(&them, 0, 0, 900_000_000), (&me, 0, 0, 60_000_000)]);
    let r = sign::point(&tx.prefix.extra[1..33].try_into().unwrap()).unwrap();
    let mut data = sign::derivation(&Scalar::from_bytes_mod_order(them.view_bytes()), &r).to_vec();
    data.push(0x8d);
    let pad = maki_xmr::keccak(&data);
    let decrypted: Vec<u8> = tx.prefix.extra[36..].iter().zip(pad).map(|(e, p)| e ^ p).collect();
    assert_eq!(decrypted, id);
}

#[test]
fn many_payments_and_inputs() {
    let mut random = Random(0x5e7d_0006);
    let me = wallet();
    let people: Vec<Keys> = (0..6).map(|_| Keys::from_spend(random.scalar())).collect();
    let payments: Vec<Payment> =
        people.iter().enumerate().map(|(i, k)| payment(&address_of(k, 0, (i % 2) as u32), 100_000_000 * (i as u64 + 1))).collect();
    let paid: u64 = payments.iter().map(|p| p.amount).sum();
    let inputs: Vec<Input> = (0..5).map(|i| input(&mut random, &me, i, paid / 4, i == 3)).collect();
    let spent: u64 = inputs.iter().map(|i| i.amount).sum();
    let request = Request { network: Network::Mainnet, account: 0, fee: 123_450_000, change: spent - paid - 123_450_000, payments, inputs };
    let signed = spend::sign(&me, &request, &[5; 32]).unwrap();
    let mut expected: Vec<(&Keys, u32, u32, u64)> =
        people.iter().enumerate().map(|(i, k)| (k, 0, (i % 2) as u32, 100_000_000 * (i as u64 + 1))).collect();
    expected.push((&me, 0, 0, request.change));
    check(&request, &signed, &expected);
}

#[test]
fn what_isnt_this_wallet_s_or_doesn_t_add_up_isn_t_signed() {
    let mut random = Random(0x5e7d_0007);
    let me = wallet();
    let them = Keys::from_spend(random.scalar());
    let base = Request {
        network: Network::Mainnet,
        account: 0,
        fee: 10,
        change: 0,
        payments: vec![payment(&address_of(&them, 0, 0), 990)],
        inputs: vec![input(&mut random, &me, 0, 1000, false)],
    };
    assert!(spend::sign(&me, &base, &[0; 32]).is_ok());
    // someone else's output
    let mut theirs = base.clone();
    theirs.inputs = vec![input(&mut random, &them, 0, 1000, false)];
    assert_eq!(spend::sign(&me, &theirs, &[0; 32]), Err(SpendError::NotOurs(0)));
    // the wrong subaddress for it
    let mut wrong = base.clone();
    wrong.inputs[0].subaddress = 1;
    assert_eq!(spend::sign(&me, &wrong, &[0; 32]), Err(SpendError::NotOurs(0)));
    // an amount its commitment doesn't hide: the fee would be a lie
    let mut lie = base.clone();
    lie.inputs[0].amount = 2000;
    lie.fee = 1010;
    assert_eq!(spend::sign(&me, &lie, &[0; 32]), Err(SpendError::Amount(0)));
    // the same output twice
    let mut twice = base.clone();
    twice.inputs.push(twice.inputs[0].clone());
    twice.change = 1000;
    assert_eq!(spend::sign(&me, &twice, &[0; 32]), Err(SpendError::Twice));

    // the request itself: sums, rings, payment IDs, networks
    let reparse = |r: &Request| Request::parse(&r.to_bytes());
    let mut sum = base.clone();
    sum.fee = 11;
    assert_eq!(reparse(&sum), Err(RequestError::Sum));
    let mut unordered = base.clone();
    unordered.inputs[0].ring.swap(3, 4);
    assert_eq!(reparse(&unordered), Err(RequestError::Ring(0)));
    let (spend, view) = them.public();
    let integrated = maki_xmr::integrated_address(Network::Mainnet, &spend, &view, &[1; 8]);
    let mut two = base.clone();
    two.payments = vec![payment(&integrated, 490), payment(&address_of(&me, 0, 1), 500)];
    assert_eq!(reparse(&two), Err(RequestError::PaymentId));
    let mut stagenet = base.clone();
    stagenet.network = Network::Stagenet;
    assert_eq!(reparse(&stagenet), Err(RequestError::Address(0)));
    let mut cut = base.to_bytes();
    cut.pop();
    assert_eq!(Request::parse(&cut), Err(RequestError::Malformed));
}

#[test]
fn the_pages_say_what_s_paid() {
    let mut random = Random(0x5e7d_0008);
    let me = wallet();
    let them = Keys::from_spend(random.scalar());
    let request = Request {
        network: Network::Mainnet,
        account: 0,
        fee: 30_720_000,
        change: 1_250_000_000_000,
        payments: vec![payment(&address_of(&them, 0, 0), 500_000_000_000)],
        inputs: vec![input(&mut random, &me, 0, 1_750_030_720_000, false)],
    };
    let pages: Vec<(String, String, String)> = request.pages().into_iter().map(|p| (p.heading, p.value, p.mono)).collect();
    assert_eq!(
        pages,
        vec![
            ("Send".into(), "0.5 XMR".into(), address_of(&them, 0, 0)),
            ("Change".into(), "1.25 XMR".into(), "back to you".into()),
            ("Fee".into(), "0.00003072 XMR".into(), String::new()),
        ]
    );
    assert_eq!(request.summary(), "Total 0.50003072 XMR");
    let mut high = request.clone();
    high.fee = 60_000_000_000;
    high.change -= 60_000_000_000 - 30_720_000;
    assert_eq!(high.pages()[2].heading, "High fee!");
    assert_eq!(request::amount(1, Network::Stagenet), "0.000000000001 sXMR");
}

#[test]
fn key_images_come_with_what_proves_them() {
    let mut random = Random(0x5e7d_0009);
    let me = wallet();
    for (major, minor) in [(0, 0), (0, 7), (1, 2)] {
        let r = random.scalar();
        let (spend, view) = keys_of(&me, major, minor);
        let tx_key = if (major, minor) == (0, 0) { G * r } else { spend * r };
        let out = sign::pay(&r, &view, &spend, 1, 5);
        let (image, proof) = me.key_image_proof(&tx_key, 1, major, minor, &out.key, &random.bytes()).expect("ours");
        let secret = me.output_secret(&tx_key, 1, major, minor);
        assert_eq!(image, sign::key_image(&secret, &sign::point(&out.key).unwrap()).compress().to_bytes());
        // Monero's ring signature of one, over the image: what wallet2 checks importing it
        let signature = monero_oxide::ring_signatures::RingSignature::read(1, &mut &proof[..]).unwrap();
        assert!(signature.verify(&image, &[theirs(&out.key)], &theirs(&image)), "{major}/{minor}");
        assert!(!signature.verify(&[9; 32], &[theirs(&out.key)], &theirs(&image)));
        // not for another subaddress, index or key
        assert_eq!(me.key_image_proof(&tx_key, 1, major, minor + 1, &out.key, &[0; 32]), None);
        assert_eq!(me.key_image_proof(&tx_key, 2, major, minor, &out.key, &[0; 32]), None);
    }
}

/// The request the emulator's wallet demo has maki sign (MAKI_DEMO_WALLET, in maki-link), and one
/// of its outputs for a key image: the test phrase's, in made-up rings, the same every time.
/// `MAKI_WRITE_FIXTURES=1` writes them again.
#[test]
fn the_emulator_s_request_is_the_test_phrase_s_to_sign() {
    let mut random = Random(0xab4d_0071);
    let me = wallet();
    let them = Keys::from_spend(random.scalar());
    let inputs = vec![input(&mut random, &me, 0, 2_000_000_000_000, false), input(&mut random, &me, 1, 750_000_000_000, true)];
    let request = Request {
        network: Network::Mainnet,
        account: 0,
        fee: 30_720_000,
        change: 2_750_000_000_000 - 1_500_000_000_000 - 30_720_000,
        payments: vec![payment(&address_of(&them, 0, 0), 1_500_000_000_000)],
        inputs,
    };
    let first = &request.inputs[0];
    let output = [&first.tx_key[..], &first.index.to_le_bytes(), &0u32.to_le_bytes(), &first.subaddress.to_le_bytes(), &first.ring[first.real].key]
        .concat();
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    if std::env::var("MAKI_WRITE_FIXTURES").is_ok() {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(format!("{dir}/abandon-request.bin"), request.to_bytes()).unwrap();
        std::fs::write(format!("{dir}/abandon-output.bin"), &output).unwrap();
    }
    assert_eq!(std::fs::read(format!("{dir}/abandon-request.bin")).unwrap(), request.to_bytes());
    assert_eq!(std::fs::read(format!("{dir}/abandon-output.bin")).unwrap(), output);
    let signed = spend::sign(&me, &request, &[0; 32]).unwrap();
    check(&request, &signed, &[(&them, 0, 0, 1_500_000_000_000), (&me, 0, 0, request.change)]);
}
