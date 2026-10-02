//! Sudoku's puzzles, made on maki: a solution filled in at random, then its clues taken away
//! one at a time, in a random order, for as long as that solution stays the only one; each
//! graded by the techniques a person needs to solve it, always the easiest that does anything
//! (`grade`). A puzzle is made a step at a time (`Maker::step`), each step bounded, so the app
//! waits between them and maki keeps answering. Everything is in fixed arrays: there's no
//! allocator.

/// 81 cells, row by row: 0 for an empty cell, else its digit, 1 to 9.
pub type Grid = [u8; 81];

/// A set of digits: bit d for digit d.
pub type Digits = u16;
pub const ALL: Digits = 0x3fe;

/// The 27 units, the rows, then the columns, then the boxes, each nine cells.
pub const UNITS: [[u8; 9]; 27] = {
    let mut u = [[0u8; 9]; 27];
    let mut i = 0;
    while i < 9 {
        let mut j = 0;
        while j < 9 {
            u[i][j] = (i * 9 + j) as u8;
            u[9 + i][j] = (j * 9 + i) as u8;
            u[18 + i][j] = ((i / 3 * 3 + j / 3) * 9 + i % 3 * 3 + j % 3) as u8;
            j += 1;
        }
        i += 1;
    }
    u
};

const fn box_of(c: usize) -> usize { c / 27 * 3 + c % 9 / 3 }

/// Each cell's row, column and box, as numbers of `UNITS`.
const HOME: [[u8; 3]; 81] = {
    let mut h = [[0u8; 3]; 81];
    let mut c = 0;
    while c < 81 {
        h[c] = [(c / 9) as u8, (9 + c % 9) as u8, (18 + box_of(c)) as u8];
        c += 1;
    }
    h
};

/// Each cell's 20 peers: the other cells of its row, its column and its box.
pub const PEERS: [[u8; 20]; 81] = {
    let mut p = [[0u8; 20]; 81];
    let mut c = 0;
    while c < 81 {
        let (mut n, mut o) = (0, 0);
        while o < 81 {
            if o != c && (o / 9 == c / 9 || o % 9 == c % 9 || box_of(o) == box_of(c)) {
                p[c][n] = o as u8;
                n += 1;
            }
            o += 1;
        }
        c += 1;
    }
    p
};

/// How hard a puzzle is: the hardest technique it needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Hidden singles alone: a digit with one place left in a row, column or box. And more
    /// clues than it needs (`EASY_CLUES`).
    Easy,
    /// Naked singles too: a cell with one digit left.
    Medium,
    /// Locked candidates (pointing and claiming), and naked and hidden pairs and triples.
    Hard,
    /// More than those: X-wings, swordfish, XY-wings, chains.
    Expert,
}

pub const LEVELS: [Level; 4] = [Level::Easy, Level::Medium, Level::Hard, Level::Expert];

/// How many clues an easy puzzle keeps, more than it needs: there's always a digit to find.
pub const EASY_CLUES: usize = 36;

/// Whether `grid` is a whole sudoku: every unit holds each digit once.
pub fn complete(grid: &Grid) -> bool {
    UNITS.iter().all(|unit| unit.iter().fold(0 as Digits, |m, &c| m | 1 << grid[c as usize].min(15)) == ALL)
}

/// A small, fast random number generator (xoshiro128**), seeded from maki's.
pub struct Rng([u32; 4]);

impl Rng {
    pub fn new(seed: [u8; 16]) -> Rng {
        let mut s = [0u32; 4];
        for (i, w) in s.iter_mut().enumerate() {
            *w = u32::from_le_bytes([seed[4 * i], seed[4 * i + 1], seed[4 * i + 2], seed[4 * i + 3]]);
        }
        // all zeros is the one state it never leaves
        if s == [0; 4] {
            s[0] = 1;
        }
        Rng(s)
    }

    fn next(&mut self) -> u32 {
        let s = &mut self.0;
        let out = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 9;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(11);
        out
    }

    /// A number in `0..n` (n > 0), without bias.
    fn below(&mut self, n: u32) -> u32 {
        let zone = u32::MAX - u32::MAX % n;
        loop {
            let v = self.next();
            if v < zone {
                return v % n;
            }
        }
    }

    /// One of the digits in `set` (not empty), at random.
    fn pick(&mut self, set: Digits) -> Digits {
        let mut rest = set;
        for _ in 0..self.below(set.count_ones()) {
            rest &= rest - 1;
        }
        rest & rest.wrapping_neg()
    }
}

/// Cells waiting to be placed: those left with one candidate.
struct Queue {
    cells: [u8; 81],
    n: usize,
}

impl Queue {
    fn new() -> Queue { Queue { cells: [0; 81], n: 0 } }

    fn push(&mut self, c: usize) {
        if let Some(slot) = self.cells.get_mut(self.n) {
            *slot = c as u8;
            self.n += 1;
        }
    }

    fn pop(&mut self) -> Option<usize> {
        self.n = self.n.checked_sub(1)?;
        Some(self.cells[self.n] as usize)
    }
}

/// A puzzle being solved: the digits placed, each empty cell's candidates (none once it has
/// its digit), the digits each unit has, and how many cells are empty.
#[derive(Clone, Copy)]
struct Board {
    grid: Grid,
    cand: [Digits; 81],
    done: [Digits; 27],
    left: u8,
}

impl Board {
    /// The puzzle, each empty cell's candidates what its row, column and box don't have: None if
    /// two clues clash, or a cell has no candidates.
    fn new(puzzle: &Grid) -> Option<Board> {
        let mut b = Board { grid: *puzzle, cand: [0; 81], done: [0; 27], left: 0 };
        for (c, &d) in puzzle.iter().enumerate() {
            if d != 0 {
                let [r, k, x] = HOME[c].map(usize::from);
                if d > 9 || (b.done[r] | b.done[k] | b.done[x]) & 1 << d != 0 {
                    return None;
                }
                b.done[r] |= 1 << d;
                b.done[k] |= 1 << d;
                b.done[x] |= 1 << d;
            }
        }
        for c in 0..81 {
            if puzzle[c] == 0 {
                let [r, k, x] = HOME[c].map(usize::from);
                b.cand[c] = ALL & !(b.done[r] | b.done[k] | b.done[x]);
                if b.cand[c] == 0 {
                    return None;
                }
                b.left += 1;
            }
        }
        Some(b)
    }

    fn solved(&self) -> bool { self.left == 0 }

    /// Puts `d` in empty cell `c` and takes it from the cell's peers, queueing those left with
    /// one candidate: false if `d` isn't one of the cell's, or a peer is left with none.
    fn place(&mut self, c: usize, d: u8, queue: &mut Queue) -> bool {
        let bit = 1 << d;
        if self.cand[c] & bit == 0 {
            return false;
        }
        self.grid[c] = d;
        self.cand[c] = 0;
        self.left -= 1;
        for &u in &HOME[c] {
            self.done[u as usize] |= bit;
        }
        for &p in &PEERS[c] {
            let p = p as usize;
            let m = self.cand[p];
            if m & bit != 0 {
                let m = m & !bit;
                self.cand[p] = m;
                if m & m.wrapping_sub(1) == 0 {
                    if m == 0 {
                        return false;
                    }
                    queue.push(p);
                }
            }
        }
        true
    }

    /// Places the hidden singles of each unit in turn, each digit with one place left in it:
    /// whether it placed any, or None if a digit has no place left in a unit, which a puzzle
    /// with a solution never comes to.
    fn hidden_singles(&mut self, queue: &mut Queue) -> Option<bool> {
        let mut placed = false;
        for (u, unit) in UNITS.iter().enumerate() {
            let (mut once, mut twice) = (0, 0);
            for &c in unit {
                let m = self.cand[c as usize];
                twice |= once & m;
                once |= m;
            }
            if once | self.done[u] != ALL {
                return None;
            }
            let mut single = once & !twice;
            while single != 0 {
                let d = single & single.wrapping_neg();
                single &= !d;
                let c = unit.iter().map(|&c| c as usize).find(|&c| self.cand[c] & d != 0)?;
                if !self.place(c, d.trailing_zeros() as u8, queue) {
                    return None;
                }
                placed = true;
            }
        }
        Some(placed)
    }

    /// Places every naked single there is, each cell with one candidate left: whether it placed
    /// any, or None on a contradiction.
    fn naked_singles(&mut self) -> Option<bool> {
        let mut placed = false;
        for c in 0..81 {
            let m = self.cand[c];
            if m != 0 && m & (m - 1) == 0 {
                if !self.place(c, m.trailing_zeros() as u8, &mut Queue::new()) {
                    return None;
                }
                placed = true;
            }
        }
        Some(placed)
    }

    /// Places singles until there are none: hidden ones, and naked ones too if `naked`. False
    /// if it comes to a contradiction.
    fn settle(&mut self, naked: bool) -> bool {
        let mut queue = Queue::new();
        if naked {
            for c in 0..81 {
                let m = self.cand[c];
                if m != 0 && m & (m - 1) == 0 {
                    queue.push(c);
                }
            }
        }
        loop {
            while let Some(c) = queue.pop() {
                let m = self.cand[c];
                if naked && m != 0 && !self.place(c, m.trailing_zeros() as u8, &mut queue) {
                    return false;
                }
            }
            match self.hidden_singles(&mut queue) {
                None => return false,
                Some(false) if queue.n == 0 || !naked => return true,
                _ => {}
            }
        }
    }

    /// The empty cell with fewest candidates.
    fn fewest(&self) -> usize {
        let (mut best, mut fewest) = (0, 10);
        for (c, m) in self.cand.iter().enumerate() {
            let k = m.count_ones();
            if k != 0 && k < fewest {
                (best, fewest) = (c, k);
                if k == 2 {
                    break;
                }
            }
        }
        best
    }

    /// Takes `digits` from cell `c`'s candidates: whether it had any of them.
    fn take(&mut self, c: usize, digits: Digits) -> bool {
        let had = self.cand[c] & digits != 0;
        self.cand[c] &= !digits;
        had
    }

    /// Locked candidates: where a box meets a row or column, a digit that the box has nowhere
    /// else leaves the rest of the line (pointing), and one the line has nowhere else leaves the
    /// rest of the box (claiming).
    fn locked(&mut self) -> bool {
        let mut progress = false;
        for b in 0..9 {
            let boxed = &UNITS[18 + b];
            for line in (0..3).map(|i| b / 3 * 3 + i).chain((0..3).map(|i| 9 + b % 3 * 3 + i)) {
                let on = |c: u8| HOME[c as usize][..2].contains(&(line as u8));
                let (mut meet, mut box_rest, mut line_rest) = (0, 0, 0);
                for &c in boxed {
                    if on(c) {
                        meet |= self.cand[c as usize];
                    } else {
                        box_rest |= self.cand[c as usize];
                    }
                }
                for &c in &UNITS[line] {
                    if HOME[c as usize][2] as usize != 18 + b {
                        line_rest |= self.cand[c as usize];
                    }
                }
                let pointing = meet & !box_rest & line_rest;
                for &c in UNITS[line].iter().filter(|&&c| HOME[c as usize][2] as usize != 18 + b) {
                    progress |= self.take(c as usize, pointing);
                }
                let claiming = meet & !line_rest & box_rest;
                for &c in boxed.iter().filter(|&&c| !on(c)) {
                    progress |= self.take(c as usize, claiming);
                }
            }
        }
        progress
    }

    /// Naked subsets: `size` cells of a unit whose candidates are `size` digits between them
    /// hold those digits, which leave the unit's other cells.
    fn naked(&mut self, size: u32) -> bool {
        let mut progress = false;
        for unit in &UNITS {
            let mut cells = [0usize; 9];
            let mut n = 0;
            for &c in unit {
                if (2..=size).contains(&self.cand[c as usize].count_ones()) {
                    cells[n] = c as usize;
                    n += 1;
                }
            }
            each_subset(n, size as usize, &mut |pick| {
                let digits = pick.iter().fold(0, |m, &i| m | self.cand[cells[i]]);
                if digits.count_ones() == size {
                    for &c in unit {
                        if !pick.iter().any(|&i| cells[i] == c as usize) {
                            progress |= self.take(c as usize, digits);
                        }
                    }
                }
            });
        }
        progress
    }

    /// Hidden subsets: `size` digits that have only `size` cells of a unit between them fill
    /// those cells, whose other candidates go.
    fn hidden(&mut self, size: u32) -> bool {
        let mut progress = false;
        for unit in &UNITS {
            // where in the unit each digit can go, a bit a cell
            let mut places = [0u16; 10];
            for (i, &c) in unit.iter().enumerate() {
                let m = self.cand[c as usize];
                for (d, p) in places.iter_mut().enumerate() {
                    if m & 1 << d != 0 {
                        *p |= 1 << i;
                    }
                }
            }
            let mut digits = [0usize; 9];
            let mut n = 0;
            for (d, p) in places.iter().enumerate() {
                if (2..=size).contains(&p.count_ones()) {
                    digits[n] = d;
                    n += 1;
                }
            }
            each_subset(n, size as usize, &mut |pick| {
                let cells = pick.iter().fold(0, |m, &i| m | places[digits[i]]);
                if cells.count_ones() == size {
                    let keep = pick.iter().fold(0 as Digits, |m, &i| m | 1 << digits[i]);
                    for (i, &c) in unit.iter().enumerate() {
                        if cells & 1 << i != 0 {
                            progress |= self.take(c as usize, !keep);
                        }
                    }
                }
            });
        }
        progress
    }
}

/// Calls `f` with each way of choosing `k` (2 or 3) of `0..n`.
fn each_subset(n: usize, k: usize, f: &mut impl FnMut(&[usize])) {
    for a in 0..n {
        for b in a + 1..n {
            if k == 2 {
                f(&[a, b]);
            } else {
                for c in b + 1..n {
                    f(&[a, b, c]);
                }
            }
        }
    }
}

/// The most guesses a search keeps track of, one inside another: a puzzle seldom needs more
/// than a handful. Past this a search gives up, as when it runs out of budget.
const DEPTH: usize = 24;

/// Every way to finish `board`, placing singles and guessing where they run out (at the cell
/// with fewest candidates, in the order `pick` takes them); `found` hears of each solution and
/// says whether to look for more. A step of `budget` for each guess: None if it ran out first.
fn search(
    board: &Board,
    budget: &mut u32,
    pick: &mut impl FnMut(Digits) -> Digits,
    found: &mut impl FnMut(&Grid) -> bool,
) -> Option<()> {
    let mut b = *board;
    if !b.settle(true) {
        return Some(());
    }
    // each guess: the board before it, the cell, and the digits still to try there
    let mut guesses = [(b, 0u8, 0 as Digits); DEPTH];
    let mut depth = 0;
    loop {
        if b.solved() {
            if !found(&b.grid) {
                return Some(());
            }
        } else {
            if *budget == 0 || depth == DEPTH {
                return None;
            }
            *budget -= 1;
            let c = b.fewest();
            guesses[depth] = (b, c as u8, b.cand[c]);
            depth += 1;
        }
        // the next digit to try at the latest guess, or back to the one before
        loop {
            if depth == 0 {
                return Some(());
            }
            let (before, c, left) = &mut guesses[depth - 1];
            if *left == 0 {
                depth -= 1;
                continue;
            }
            let d = pick(*left);
            *left &= !d;
            b = *before;
            if b.place(*c as usize, d.trailing_zeros() as u8, &mut Queue::new()) && b.settle(true) {
                break;
            }
        }
    }
}

/// How many solutions `grid` has, counted as far as `limit`: None if counting took more than
/// `budget` guesses. A grid whose clues clash has none.
pub fn solutions(grid: &Grid, limit: u32, budget: &mut u32) -> Option<u32> {
    let Some(board) = Board::new(grid) else { return Some(0) };
    let mut count = 0;
    search(&board, budget, &mut |d| d & d.wrapping_neg(), &mut |_| {
        count += 1;
        count < limit
    })?;
    Some(count)
}

/// Whether the clues in `puzzle` force digit `d` into empty cell `c` at a glance: one of its
/// units has nowhere else for `d` (a hidden single), or, if `naked` counts, its peers hold every
/// other digit (a naked single).
fn forced(puzzle: &Grid, c: usize, d: u8, naked: bool) -> bool {
    let seen = PEERS[c].iter().fold(1 << d | 1, |m: Digits, &p| m | 1 << puzzle[p as usize]);
    naked && seen == ALL | 1
        || HOME[c].iter().any(|&u| {
            UNITS[u as usize].iter().all(|&x| {
                let x = x as usize;
                x == c || puzzle[x] != 0 || PEERS[x].iter().any(|&p| puzzle[p as usize] == d)
            })
        })
}

/// Whether `puzzle`, whose one solution is `solution`, keeps it alone without its clue at `c`:
/// whether no solution has another digit there. None if finding out took more than `budget`
/// guesses.
fn unique_without(puzzle: &Grid, solution: &Grid, c: usize, budget: &mut u32) -> Option<bool> {
    let mut p = *puzzle;
    p[c] = 0;
    if forced(&p, c, solution[c], true) {
        return Some(true);
    }
    let mut board = Board::new(&p)?;
    board.cand[c] &= !(1 << solution[c]);
    if board.cand[c] == 0 {
        return Some(true);
    }
    let mut other = false;
    search(&board, budget, &mut |d| d & d.wrapping_neg(), &mut |_| {
        other = true;
        false
    })?;
    Some(!other)
}

/// Whether singles alone solve `puzzle` (hidden ones alone, unless `naked`), to `solution`.
fn singles_solve(puzzle: &Grid, solution: &Grid, naked: bool) -> bool {
    Board::new(puzzle).is_some_and(|mut b| b.settle(naked) && b.solved() && b.grid == *solution)
}

/// A whole grid at random, or None if `budget` guesses weren't enough: the boxes on the
/// diagonal, which share no row or column, shuffled, and the rest found by guessing at random.
fn fill(rng: &mut Rng, budget: &mut u32) -> Option<Grid> {
    let mut grid = [0; 81];
    for b in [18, 22, 26] {
        let mut digits = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        for i in (1..9).rev() {
            digits.swap(i, rng.below(i as u32 + 1) as usize);
        }
        for (&c, &d) in UNITS[b].iter().zip(&digits) {
            grid[c as usize] = d;
        }
    }
    let mut out = None;
    search(&Board::new(&grid)?, budget, &mut |d| rng.pick(d), &mut |g| {
        out = Some(*g);
        false
    })?;
    out
}

/// How hard `puzzle` is, solved as a person would, each time with the easiest technique that
/// does anything, and its solution; None if those techniques aren't enough, or it has no
/// solution. One they solve has one solution alone: each step takes away only what no solution
/// has.
pub fn grade(puzzle: &Grid) -> Option<(Level, Grid)> {
    let mut b = Board::new(puzzle)?;
    let mut hardest = Level::Easy;
    loop {
        if b.hidden_singles(&mut Queue::new())? {
            continue;
        }
        if b.solved() {
            return Some((hardest, b.grid));
        }
        let level = if b.naked_singles()? {
            Level::Medium
        } else if b.locked() || b.naked(2) || b.hidden(2) || b.naked(3) || b.hidden(3) {
            Level::Hard
        } else {
            return None;
        };
        hardest = hardest.max(level);
    }
}

/// What a puzzle being made has come to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// a solution to fill in
    Fill,
    /// clues to take away: the next of `order`
    Dig,
    /// dug: to grade
    Grade,
}

/// Puzzles being made, a step at a time.
pub struct Maker {
    rng: Rng,
    /// the level it's making for
    pub level: Level,
    stage: Stage,
    solution: Grid,
    puzzle: Grid,
    order: [u8; 81],
    tried: usize,
    clues: usize,
    /// puzzles begun for this level so far
    pub tries: u32,
}

impl Maker {
    pub fn new(seed: [u8; 16], level: Level) -> Maker {
        Maker {
            rng: Rng::new(seed),
            level,
            stage: Stage::Fill,
            solution: [0; 81],
            puzzle: [0; 81],
            order: [0; 81],
            tried: 0,
            clues: 81,
            tries: 0,
        }
    }

    /// Makes for `level` from now on: the puzzle being dug goes on if it's dug the same way
    /// (hard and expert ones both by any means), else it starts again.
    pub fn make(&mut self, level: Level) {
        let dig = |l: Level| l.min(Level::Hard);
        if dig(level) != dig(self.level) {
            (self.stage, self.tries) = (Stage::Fill, 0);
        }
        self.level = level;
    }

    /// How far into the clues of the puzzle being dug, out of 81.
    pub fn tried(&self) -> usize { if self.stage == Stage::Fill { 0 } else { self.tried } }

    /// A step: filling a solution in, trying a clue away, or grading what's left (most take a
    /// few hundred thousand of wasm's instructions, and none many millions). A puzzle once one's
    /// finished, whatever its level, its clues and its solution; then it starts another.
    pub fn step(&mut self) -> Option<(Level, Grid, Grid)> {
        match self.stage {
            Stage::Fill => {
                // a few dozen guesses at most fill one; past them, a new start next step
                if let Some(solution) = fill(&mut self.rng, &mut 64) {
                    self.solution = solution;
                    self.puzzle = solution;
                    for (i, o) in self.order.iter_mut().enumerate() {
                        *o = i as u8;
                    }
                    for i in (1..81).rev() {
                        self.order.swap(i, self.rng.below(i as u32 + 1) as usize);
                    }
                    (self.tried, self.clues, self.stage) = (0, 81, Stage::Dig);
                    self.tries += 1;
                }
                None
            }
            Stage::Dig => {
                if self.tried == 81 || self.level == Level::Easy && self.clues <= EASY_CLUES {
                    self.stage = Stage::Grade;
                    return None;
                }
                let c = self.order[self.tried] as usize;
                self.tried += 1;
                let clue = self.puzzle[c];
                // the easy levels dug by singles, so they can't need more; the others by any
                // means, with a dozen guesses at most (past them, the clue stays)
                let gone = match self.level {
                    Level::Easy | Level::Medium => {
                        self.puzzle[c] = 0;
                        let naked = self.level == Level::Medium;
                        let ok = forced(&self.puzzle, c, clue, naked)
                            || singles_solve(&self.puzzle, &self.solution, naked);
                        self.puzzle[c] = clue;
                        ok
                    }
                    _ => unique_without(&self.puzzle, &self.solution, c, &mut 12) == Some(true),
                };
                if gone {
                    self.puzzle[c] = 0;
                    self.clues -= 1;
                }
                None
            }
            Stage::Grade => {
                self.stage = Stage::Fill;
                let level = match grade(&self.puzzle) {
                    Some((level, solution)) if solution == self.solution => level,
                    Some(_) => return None,
                    None => Level::Expert,
                };
                // one solution alone, whatever the grade says, or it isn't kept
                if solutions(&self.puzzle, 2, &mut 32) != Some(1) {
                    return None;
                }
                // an easy one dug for another level gets an easy one's clues back
                while level == Level::Easy && self.clues < EASY_CLUES {
                    let c = self.rng.below(81) as usize;
                    if self.puzzle[c] == 0 {
                        self.puzzle[c] = self.solution[c];
                        self.clues += 1;
                    }
                }
                Some((level, self.puzzle, self.solution))
            }
        }
    }
}
