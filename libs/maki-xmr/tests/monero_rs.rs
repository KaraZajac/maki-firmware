//! Addresses and subaddresses for many keys, held to monero-rs's.
use maki_xmr::{Keys, Kind, Network, address};
use monero::cryptonote::subaddress::{Index, get_subaddress};
use monero::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair};

#[test]
fn addresses_and_subaddresses_are_monero_rss() {
    let mut x: u64 = 0x5eed_0f5e_ed00;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..24 {
        let mut bip32 = [0u8; 32];
        for chunk in bip32.chunks_mut(8) {
            chunk.copy_from_slice(&next().to_le_bytes());
        }
        let ours = Keys::from_bip32(&bip32);
        let theirs = KeyPair {
            spend: PrivateKey::from_slice(&ours.spend_bytes()).unwrap(),
            view: PrivateKey::from_slice(&ours.view_bytes()).unwrap(),
        };
        let (spend, view) = ours.public();
        assert_eq!(spend, PublicKey::from_private_key(&theirs.spend).to_bytes());
        assert_eq!(view, PublicKey::from_private_key(&theirs.view).to_bytes());
        for (network, net) in [
            (Network::Mainnet, monero::Network::Mainnet),
            (Network::Testnet, monero::Network::Testnet),
            (Network::Stagenet, monero::Network::Stagenet),
        ] {
            assert_eq!(
                address(network, Kind::Standard, &spend, &view),
                monero::Address::from_keypair(net, &theirs).to_string()
            );
            let pair = ViewPair::from(theirs);
            for (major, minor) in [(0, 1), (0, 9), (3, 0), (7, 1234)] {
                let (d, c) = ours.subaddress(major, minor);
                let expected = get_subaddress(&pair, Index { major, minor }, Some(net)).to_string();
                assert_eq!(address(network, Kind::Subaddress, &d, &c), expected, "{major},{minor}");
            }
        }
    }
}
