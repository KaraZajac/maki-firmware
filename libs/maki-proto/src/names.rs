//! What a maki is called. The firmware and the app are maki; each badge picks a name of its own
//! the first time it starts, a maki roll, and keeps it: this one might be natto.

/// Maki rolls, and what goes in them: 32, so a random byte picks one as likely as any other.
pub const ROLLS: [&str; 32] = [
    "natto", "uni", "unagi", "kappa", "tekka", "negitoro", "kanpyo", "oshinko", "umekyu", "tamago", "ikura",
    "anago", "ebi", "hamachi", "negihama", "shake", "maguro", "toro", "kani", "hotate", "saba", "ika",
    "tako", "takuan", "gobo", "shiso", "kyuri", "futomaki", "hosomaki", "temaki", "gunkan", "uramaki",
];

/// The longest name, in bytes: it goes over IPC in four words.
pub const MAX_NAME: usize = 16;

/// The roll a random byte picks.
pub fn pick(random: u8) -> &'static str { ROLLS[random as usize % ROLLS.len()] }

/// A name maki would keep: one of the rolls, or anything short and plain someone chose.
pub fn valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == ' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_roll_is_a_name_maki_keeps_and_a_byte_picks_evenly() {
        assert!(ROLLS.iter().all(|r| valid(r)));
        assert_eq!(256 % ROLLS.len(), 0);
        let mut seen = std::collections::BTreeSet::new();
        for b in 0..=255u8 {
            seen.insert(pick(b));
        }
        assert_eq!(seen.len(), ROLLS.len());
        assert!(!valid("") && !valid("a/b") && !valid(&"x".repeat(MAX_NAME + 1)));
    }
}
