//! A spend key as the 25 words Monero wallets restore from (Monero's "Electrum" seeds): each four
//! bytes as three words from the 1626 of the English list, then a word repeated from those to
//! check them by, picked by the CRC-32 of the words' first three letters.

use crate::english::{ENGLISH, PREFIX};

const N: u32 = ENGLISH.len() as u32;

/// The 25 words for 32 bytes.
pub fn encode(seed: &[u8; 32]) -> [&'static str; 25] {
    let mut words = [""; 25];
    for (i, chunk) in seed.chunks(4).enumerate() {
        let x = u32::from_le_bytes(chunk.try_into().unwrap());
        let w1 = x % N;
        let w2 = (x / N + w1) % N;
        let w3 = (x / N / N + w2) % N;
        words[3 * i] = ENGLISH[w1 as usize];
        words[3 * i + 1] = ENGLISH[w2 as usize];
        words[3 * i + 2] = ENGLISH[w3 as usize];
    }
    words[24] = words[checksum(&words[..24])];
    words
}

/// The 32 bytes 25 words (or the 24 without their check) stand for, each word whole and lower
/// case. None if one isn't on the list, three don't make four bytes, or the check word is wrong.
pub fn decode(words: &[&str]) -> Option<[u8; 32]> {
    if words.len() != 24 && words.len() != 25 {
        return None;
    }
    let index = |w: &str| ENGLISH.iter().position(|e| *e == w).map(|i| i as u32);
    let mut seed = [0u8; 32];
    for (i, three) in words[..24].chunks(3).enumerate() {
        let (w1, w2, w3) = (index(three[0])?, index(three[1])?, index(three[2])?);
        let x = w1 as u64 + N as u64 * ((N + w2 - w1) % N) as u64 + (N as u64 * N as u64) * ((N + w3 - w2) % N) as u64;
        // three words can say more than four bytes hold
        if x > u32::MAX as u64 {
            return None;
        }
        seed[4 * i..4 * i + 4].copy_from_slice(&(x as u32).to_le_bytes());
    }
    if words.len() == 25 && words[24] != words[checksum(&words[..24])] {
        return None;
    }
    Some(seed)
}

/// Which of the 24 words is repeated to check them: CRC-32 of their first three letters, in turn.
fn checksum(words: &[&str]) -> usize {
    let mut crc = !0u32;
    for w in words {
        // the first three letters, whatever their size in UTF-8
        let end = w.char_indices().nth(PREFIX).map_or(w.len(), |(i, _)| i);
        for b in w[..end].bytes() {
            crc ^= b as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
            }
        }
    }
    (!crc % words.len() as u32) as usize
}
