//! Account IDs, as NEAR takes them (near-account-id's rules, which nearcore holds every name in a
//! transaction to): 2 to 64 characters, lowercase letters and digits, parted by `-`, `_` or `.`,
//! never two of those together, nor one at either end. The dots make sub-accounts: `alice.near` is
//! `near`'s, and only `near` can make it. Some names aren't chosen but say what holds them: an
//! implicit account (64 hex digits, an Ed25519 key), an Ethereum address's (`0x` and 40 hex
//! digits), and accounts named by the code they were made with (`0s` and 40 hex digits, `0u` and
//! 52 of base32).

/// The shortest account ID NEAR takes.
pub const MIN_LEN: usize = 2;
/// The longest account ID NEAR takes.
pub const MAX_LEN: usize = 64;

/// Whether NEAR takes `id` as an account's name.
pub fn valid(id: &str) -> bool {
    let b = id.as_bytes();
    if b.len() < MIN_LEN || b.len() > MAX_LEN {
        return false;
    }
    // a separator can't start it, end it, or follow another
    let mut after_separator = true;
    for &c in b {
        let separator = match c {
            b'a'..=b'z' | b'0'..=b'9' => false,
            b'-' | b'_' | b'.' => true,
            _ => return false,
        };
        if separator && after_separator {
            return false;
        }
        after_separator = separator;
    }
    !after_separator
}

/// What kind of account a name is: chosen, or named by what holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A name someone chose (`alice.near`), made by its parent account.
    Named,
    /// An implicit account: 64 hex digits, an Ed25519 key, which holds it. Sending NEAR to it
    /// makes it.
    Implicit,
    /// An Ethereum address's account (`0x` and 40 hex digits, NEP-518), held by that address's
    /// key. Sending NEAR to it makes it.
    Ethereum,
    /// An account named by the code and state it was made with (`0s` and 40 hex digits, NEP-616;
    /// or a universal account, `0u` and 52 digits of Crockford's base32, whose state can name keys
    /// too): no one chooses it, and whoever makes it gets just what its name says.
    Code,
}

fn hex_digits(b: &[u8]) -> bool { b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) }

/// The kind of account `id` is, as nearcore tells them apart (an id that isn't valid is `Named`).
pub fn kind(id: &str) -> Kind {
    let b = id.as_bytes();
    match b {
        _ if b.len() == 64 && hex_digits(b) => Kind::Implicit,
        [b'0', b'x', rest @ ..] if rest.len() == 40 && hex_digits(rest) => Kind::Ethereum,
        [b'0', b's', rest @ ..] if rest.len() == 40 && hex_digits(rest) => Kind::Code,
        // 52 base32 digits carry 260 bits, the hash's 256 and four of nothing: only `0` and `g`
        // end one with those four bits clear
        [b'0', b'u', rest @ ..]
            if rest.len() == 52
                && rest.iter().all(|c| b"0123456789abcdefghjkmnpqrstvwxyz".contains(c))
                && matches!(rest[51], b'0' | b'g') =>
        {
            Kind::Code
        }
        _ => Kind::Named,
    }
}

/// Whether `id` is a sub-account of `parent`: `parent` with a part before it (`alice.near` of
/// `near`), which only `parent` can make.
pub fn is_sub_account_of(id: &str, parent: &str) -> bool {
    id.strip_suffix(parent).and_then(|s| s.strip_suffix('.')).is_some_and(|s| !s.is_empty())
}

/// Whether `id` names an account of NEAR's test network: `testnet` or one of its sub-accounts.
/// NEAR's own network has no `testnet` account, so none of those can be there.
pub fn is_testnet(id: &str) -> bool { id == "testnet" || id.ends_with(".testnet") }
