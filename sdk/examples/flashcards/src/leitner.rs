//! When a card comes back: Leitner's boxes (Sebastian Leitner, "So lernt man lernen", 1972). A card
//! you know moves up a box, and one you don't goes back to the first, so what you know comes back
//! less and less often and what you don't keeps coming back. Leitner moved a box on as it filled;
//! on a calendar each box waits a time of its own, here doubling from box to box, as is usual: a
//! card in box n comes back 2^(n-1) days after it was last seen (1, 2, 4, 8, 16, 32 or 64), and box
//! 7, the last, stays box 7. A new card hasn't a box yet: known the first time it's seen, it goes in
//! box 2, as if it had passed box 1; not, in box 1.
//!
//! Days are whole days since 1970 (UTC), as a u16 (to the year 2149). A card last seen after
//! today (maki's clock was wrong then, or is now) is due today: when it was really seen isn't
//! known, and a card back early is better than one held back, maybe for years.

/// How many boxes there are.
pub const BOXES: usize = 7;

/// A card's progress: its box (0 while it's new), and the day it was last seen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    pub boxed: u8,
    pub seen: u16,
}

impl Progress {
    /// Not seen yet.
    pub fn is_new(self) -> bool { self.boxed == 0 }

    /// How many days its box waits.
    pub fn wait(self) -> u16 { 1 << (self.boxed.clamp(1, BOXES as u8) - 1) }

    /// The day it comes back: its box's wait after it was last seen; today, if it was last seen
    /// after today.
    pub fn due(self, today: u16) -> u16 {
        if self.seen > today { today } else { self.seen.saturating_add(self.wait()) }
    }

    /// Whether it's to be studied today (a new card waits to be brought in).
    pub fn is_due(self, today: u16) -> bool { !self.is_new() && self.due(today) <= today }

    /// Where it goes once answered on `today`: up a box if `knew`, back to box 1 if not.
    pub fn answered(self, knew: bool, today: u16) -> Progress {
        let boxed = match (knew, self.boxed) {
            (false, _) => 1,
            (true, 0) => 2,
            (true, b) => (b + 1).min(BOXES as u8),
        };
        Progress { boxed, seen: today }
    }
}

/// How many new cards a deck may still bring in today: `per_day`, less those it brought in on
/// `day` if that's today.
pub fn new_left(day: u16, brought: u16, today: u16, per_day: u16) -> u16 {
    if day == today { per_day.saturating_sub(brought) } else { per_day }
}

/// The cards to study today, in order: those due, the longest due first (then as the deck has
/// them), then up to `new` new ones, as the deck has them.
pub fn sitting(cards: &[Progress], today: u16, new: u16) -> Vec<u16> {
    let mut due: Vec<(u16, u16)> = cards
        .iter()
        .enumerate()
        .filter(|(_, p)| p.is_due(today))
        .map(|(i, p)| (p.due(today), i as u16))
        .collect();
    due.sort_unstable();
    let fresh = cards.iter().enumerate().filter(|(_, p)| p.is_new()).take(new as usize);
    due.into_iter().map(|(_, i)| i).chain(fresh.map(|(i, _)| i as u16)).collect()
}

/// A deck as it stands today.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// cards not seen yet
    pub new: u16,
    /// cards due today
    pub due: u16,
    /// what a sitting today would hold: those due, and the new ones it may bring in
    pub study: u16,
    /// how many cards are in each box
    pub boxes: [u16; BOXES],
    /// in how many days the next card not due today comes back, if any will
    pub next: Option<u16>,
}

/// How a deck's cards stand on `today`, `new` new ones left to bring in.
pub fn counts(cards: &[Progress], today: u16, new: u16) -> Counts {
    let mut c = Counts::default();
    for p in cards {
        if p.is_new() {
            c.new += 1;
            continue;
        }
        c.boxes[p.boxed.clamp(1, BOXES as u8) as usize - 1] += 1;
        let due = p.due(today);
        if due <= today {
            c.due += 1;
        } else {
            let days = due - today;
            c.next = Some(c.next.map_or(days, |n| n.min(days)));
        }
    }
    c.study = c.due + c.new.min(new);
    // a new card left for another day comes back tomorrow
    if c.new > new {
        c.next = Some(1);
    }
    c
}

/// Days in a row studied, once something's been studied on `today`, given the last day studied
/// and the run up to it.
pub fn streak_after(last: u16, run: u16, today: u16) -> u16 {
    if last == today {
        run.max(1)
    } else if last.checked_add(1) == Some(today) {
        run.saturating_add(1)
    } else {
        1
    }
}

/// Days in a row studied as of `today`: the run, if it ended today or yesterday.
pub fn streak_now(last: u16, run: u16, today: u16) -> u16 {
    if last == today || last.checked_add(1) == Some(today) { run } else { 0 }
}
