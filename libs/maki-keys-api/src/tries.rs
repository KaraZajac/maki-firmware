//! The PIN's tries, counted in the chip.
//!
//! maki-keys counts every PIN try on one of the chip's one-way counters, before it checks the
//! PIN, and keeps in the flash only the counter's value at the last right PIN (its base). The
//! tries since then are the counter less the base. A one-way counter only ever counts up, so
//! putting back an older copy of the flash brings back an older, lower base: more tries, never
//! fewer. Once they're used up, the next try wipes maki without its PIN being checked at all, so
//! a copy of the flash put back gets no guess from it either.
//!
//! A counter wears out after about ten thousand counts (the RRAM's limit), and every try counts,
//! right ones too: counting after a wrong PIN instead would leave a moment, between the check
//! and the count, when cutting the power gives a free guess. So maki keeps a few counters, and
//! after a right PIN, once the one in use is nearly worn, moves to the next. The flash names the
//! new one first, and only then is the old one counted up past the tries: a power cut in between
//! can't lock the owner out, and a copy of the flash that still names the old counter finds its
//! tries used up.
//!
//! Before this, the count lived in the flash. The first time, that count is carried onto the
//! chip. After that, a flash with no base while the counters have counted is one from before, put
//! back, and its tries are used up.

use crate::MAX_TRIES;

/// The first of the one-way counters maki's PIN tries use, and how many there are. The chip's
/// counters from 128 up are left to applications (`bao1x_api::APP_OWC_BEGIN`); nothing else in
/// maki counts on these (the stock DC34 firmware used 129).
pub const COUNTER_FIRST: usize = 192;
pub const COUNTERS: usize = 8;
/// A counter is good for 10,000 counts (`bao1x_hal::acram::ONEWAY_MAX_VALUE`); maki moves to
/// the next one well before.
pub const WORN_AT: u32 = 9_000;

/// What the flash keeps: which counter, and its value at the last right PIN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Base {
    pub counter: usize,
    pub at: u32,
}

impl Base {
    pub fn to_bytes(self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&(self.counter as u32).to_le_bytes());
        b[4..].copy_from_slice(&self.at.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Base> {
        let b: &[u8; 8] = b.try_into().ok()?;
        let counter = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
        let at = u32::from_le_bytes(b[4..].try_into().unwrap());
        pool().contains(&counter).then_some(Base { counter, at })
    }
}

fn pool() -> core::ops::Range<usize> { COUNTER_FIRST..COUNTER_FIRST + COUNTERS }

/// The chip's counters and the flash, as maki-keys reaches them.
pub trait Counters {
    /// A counter's value; None if the chip couldn't be asked.
    fn get(&self, counter: usize) -> Option<u32>;
    /// Counts one up; false if it didn't (worn out, or the chip couldn't be asked).
    fn bump(&self, counter: usize) -> bool;
    /// The base the flash keeps, if any.
    fn base(&self) -> Option<Base>;
    fn set_base(&self, base: Base) -> bool;
    /// The count firmware before this kept in the flash (0 if none), and forgetting it.
    fn old_tries(&self) -> u32;
    fn forget_old_tries(&self);
}

/// Where the count starts: a base, or used up (a flash from before, put back).
enum Start {
    Base(Base),
    UsedUp,
}

fn start<C: Counters>(c: &C) -> Option<Start> {
    if let Some(base) = c.base() {
        return Some(Start::Base(base));
    }
    // counted on the chip before, but the flash doesn't say so: it's from before, put back
    for counter in pool() {
        if c.get(counter)? != 0 {
            return Some(Start::UsedUp);
        }
    }
    // the first time: the flash's own count is carried onto the chip
    let old = c.old_tries().min(MAX_TRIES);
    for _ in 0..old {
        if !c.bump(COUNTER_FIRST) {
            return None;
        }
    }
    let base = Base { counter: COUNTER_FIRST, at: c.get(COUNTER_FIRST)?.checked_sub(old)? };
    if !c.set_base(base) {
        return None;
    }
    c.forget_old_tries();
    Some(Start::Base(base))
}

/// The tries a base has counted. A base above its counter can't be this chip's (the counter
/// only goes up), so it has none left.
fn since<C: Counters>(c: &C, base: Base) -> Option<u32> {
    Some(c.get(base.counter)?.checked_sub(base.at).unwrap_or(MAX_TRIES))
}

/// Tries since the last right PIN; MAX_TRIES or more when they're used up. None if they can't
/// be counted.
pub fn tries<C: Counters>(c: &C) -> Option<u32> {
    match start(c)? {
        Start::Base(base) => since(c, base),
        Start::UsedUp => Some(MAX_TRIES),
    }
}

/// What a PIN try may do.
#[derive(Debug, PartialEq, Eq)]
pub enum Try {
    /// Check the PIN: this is try `n` since the last right one (1 to MAX_TRIES), counted.
    Check(u32),
    /// The tries were used up before this one: wipe, and don't check the PIN.
    UsedUp,
}

/// Counts a try on the chip, before its PIN is checked. None if it couldn't be counted: then
/// the PIN mustn't be checked.
pub fn count_try<C: Counters>(c: &C) -> Option<Try> {
    let base = match start(c)? {
        Start::Base(base) => base,
        Start::UsedUp => return Some(Try::UsedUp),
    };
    let before = since(c, base)?;
    if before >= MAX_TRIES {
        return Some(Try::UsedUp);
    }
    if !c.bump(base.counter) {
        return None;
    }
    // and it did count: the counter moved
    let now = since(c, base)?;
    (now > before).then_some(Try::Check(now))
}

/// A right PIN, or a new one: the tries start again from here, on the next counter once this
/// one is nearly worn. False if the flash couldn't take it (the try stays counted).
pub fn forgive<C: Counters>(c: &C) -> bool {
    let current = c.base().map(|b| b.counter).unwrap_or(COUNTER_FIRST);
    let Some(value) = c.get(current) else { return false };
    if value >= WORN_AT {
        let next = pool().find(|&n| n > current && c.get(n).is_some_and(|v| v < WORN_AT));
        if let Some(next) = next {
            let Some(at) = c.get(next) else { return false };
            if !c.set_base(Base { counter: next, at }) {
                return false;
            }
            // the flash names the new counter; now the old one's tries are used up, for any copy
            // of the flash that still names it
            for _ in 0..MAX_TRIES {
                c.bump(current);
            }
            return true;
        }
    }
    c.set_base(Base { counter: current, at: value })
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;

    /// The chip's counters (up only, worn out at 10,000) and the flash.
    struct Fake {
        counters: RefCell<[u32; 256]>,
        base: Cell<Option<Base>>,
        old: Cell<u32>,
        flash_ok: Cell<bool>,
    }

    impl Fake {
        fn new() -> Fake {
            Fake {
                counters: RefCell::new([0; 256]),
                base: Cell::new(None),
                old: Cell::new(0),
                flash_ok: Cell::new(true),
            }
        }

        /// A copy of the flash, to put back later.
        fn copy(&self) -> (Option<Base>, u32) { (self.base.get(), self.old.get()) }

        fn put_back(&self, copy: (Option<Base>, u32)) {
            self.base.set(copy.0);
            self.old.set(copy.1);
        }
    }

    impl Counters for Fake {
        fn get(&self, n: usize) -> Option<u32> { Some(self.counters.borrow()[n]) }

        fn bump(&self, n: usize) -> bool {
            let mut c = self.counters.borrow_mut();
            if c[n] >= 10_000 {
                return false;
            }
            c[n] += 1;
            true
        }

        fn base(&self) -> Option<Base> { self.base.get() }

        fn set_base(&self, base: Base) -> bool {
            if self.flash_ok.get() {
                self.base.set(Some(base));
            }
            self.flash_ok.get()
        }

        fn old_tries(&self) -> u32 { self.old.get() }

        fn forget_old_tries(&self) { self.old.set(0) }
    }

    /// Wrong PINs until used up: the tries it was allowed to check.
    fn wrong_until_used_up(c: &Fake) -> Vec<u32> {
        let mut checked = vec![];
        while let Some(Try::Check(n)) = count_try(c) {
            checked.push(n);
            assert!(checked.len() <= 10, "never used up");
        }
        checked
    }

    #[test]
    fn five_tries_then_used_up() {
        let c = Fake::new();
        assert!(forgive(&c)); // the PIN is set
        assert_eq!(wrong_until_used_up(&c), [1, 2, 3, 4, 5]);
        assert_eq!(count_try(&c), Some(Try::UsedUp));
        assert_eq!(tries(&c), Some(5));
    }

    #[test]
    fn a_right_pin_starts_them_again() {
        let c = Fake::new();
        forgive(&c);
        for n in 1..=3 {
            assert_eq!(count_try(&c), Some(Try::Check(n)));
        }
        assert_eq!(count_try(&c), Some(Try::Check(4))); // this one's right
        forgive(&c);
        assert_eq!(tries(&c), Some(0));
        assert_eq!(wrong_until_used_up(&c), [1, 2, 3, 4, 5]);
    }

    #[test]
    fn the_flash_put_back_gives_no_try_back() {
        let c = Fake::new();
        forgive(&c);
        let copy = c.copy(); // taken with all five tries left
        assert_eq!(wrong_until_used_up(&c), [1, 2, 3, 4, 5]); // maki wipes on the fifth
        c.put_back(copy); // the lock and the base come back
        assert_eq!(count_try(&c), Some(Try::UsedUp)); // and no PIN is checked
        c.put_back(copy);
        assert_eq!(count_try(&c), Some(Try::UsedUp));
    }

    #[test]
    fn a_copy_mid_way_leaves_only_the_tries_it_had_left() {
        let c = Fake::new();
        forgive(&c);
        count_try(&c);
        count_try(&c);
        let copy = c.copy(); // three left
        count_try(&c);
        count_try(&c);
        c.put_back(copy);
        assert_eq!(wrong_until_used_up(&c), [5]); // not three more
    }

    #[test]
    fn the_first_time_the_flash_count_moves_onto_the_chip() {
        let c = Fake::new();
        c.old.set(2); // firmware before this counted two wrong PINs in the flash
        assert_eq!(tries(&c), Some(2));
        assert_eq!(c.old.get(), 0);
        assert_eq!(c.base.get(), Some(Base { counter: COUNTER_FIRST, at: 0 }));
        assert_eq!(wrong_until_used_up(&c), [3, 4, 5]);
    }

    #[test]
    fn a_flash_from_before_put_back_has_no_tries() {
        let c = Fake::new();
        let before = c.copy(); // from firmware before this: no base, no wrong PINs
        forgive(&c);
        count_try(&c); // a right PIN, counted
        forgive(&c);
        c.put_back(before);
        assert_eq!(count_try(&c), Some(Try::UsedUp));
    }

    #[test]
    fn a_worn_counter_hands_over_and_its_copies_are_used_up() {
        let c = Fake::new();
        forgive(&c);
        c.counters.borrow_mut()[COUNTER_FIRST] = WORN_AT - 1;
        forgive(&c); // (as if every try so far had been right)
        let old_era = c.copy();
        assert_eq!(count_try(&c), Some(Try::Check(1))); // a right PIN: 192 reaches WORN_AT
        assert!(forgive(&c));
        assert_eq!(c.base.get().unwrap().counter, COUNTER_FIRST + 1);
        assert_eq!(tries(&c), Some(0));
        assert_eq!(wrong_until_used_up(&c), [1, 2, 3, 4, 5]); // on the new counter
        c.put_back(old_era); // a copy that still names the old counter
        assert_eq!(count_try(&c), Some(Try::UsedUp));
    }

    #[test]
    fn a_power_cut_mid_handover_never_locks_the_owner_out() {
        let c = Fake::new();
        forgive(&c);
        c.counters.borrow_mut()[COUNTER_FIRST] = WORN_AT;
        // the flash takes the new counter, and the power goes before the old one is counted up
        let next = Base { counter: COUNTER_FIRST + 1, at: 0 };
        assert!(c.set_base(next));
        assert_eq!(tries(&c), Some(0));
        assert_eq!(count_try(&c), Some(Try::Check(1)));
    }

    #[test]
    fn nothing_is_checked_when_the_count_cant_be_kept() {
        let c = Fake::new();
        forgive(&c);
        c.counters.borrow_mut()[COUNTER_FIRST] = 10_000; // worn out
        c.base.set(Some(Base { counter: COUNTER_FIRST, at: 10_000 }));
        assert_eq!(count_try(&c), None);
    }

    #[test]
    fn a_base_above_its_counter_has_no_tries() {
        let c = Fake::new();
        c.base.set(Some(Base { counter: COUNTER_FIRST, at: 7 })); // not this chip's
        assert_eq!(count_try(&c), Some(Try::UsedUp));
    }

    #[test]
    fn a_right_pin_the_flash_cant_record_stays_counted() {
        let c = Fake::new();
        forgive(&c);
        count_try(&c);
        c.flash_ok.set(false);
        assert!(!forgive(&c));
        assert_eq!(tries(&c), Some(1));
    }

    #[test]
    fn base_bytes_round_trip_and_stay_in_the_pool() {
        let b = Base { counter: COUNTER_FIRST + 3, at: 1234 };
        assert_eq!(Base::from_bytes(&b.to_bytes()), Some(b));
        assert_eq!(Base::from_bytes(&Base { counter: 129, at: 0 }.to_bytes()), None);
        assert_eq!(Base::from_bytes(&[0; 4]), None);
    }
}
