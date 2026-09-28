//! Taproot for one key (BIP86). The tweak and its signatures are maki's (`maki_hd`): here, only
//! the form taproot writes keys in.

/// A public key's x coordinate, the form taproot writes keys in.
pub fn x_only(public_key: &[u8; 33]) -> [u8; 32] { public_key[1..].try_into().unwrap() }
