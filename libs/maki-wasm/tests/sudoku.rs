//! The Sudoku example (sdk/examples/sudoku), as `maki build` packed it and maki runs it: its
//! puzzles made on maki, each with one solution alone and as hard as its level says (checked here
//! with a solver and a grader of the tests' own), made ahead while it's left alone and never long
//! without waiting; the cursor, the picker that writes digits and pencils marks in, a puzzle
//! solved and a grid full but wrong, mistakes shown only when asked; the game and its clock kept
//! across a restart; and stored data that makes no sense refused. Rebuild the fixture after
//! changing the app: `maki build sdk/examples/sudoku`, then copy
//! `sdk/target/maki/com.leviathan.maki.sudoku.maki` to `tests/fixtures/sudoku.maki`.

mod harness;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use harness::*;
use maki_wasm::*;

type Grid = [u8; 81];

const SOLUTION: &str = "365781429941326875728549613279658134514237968683194752856412397437965281192873546";

fn grid(s: &str) -> Grid {
    let mut g = [0; 81];
    for (c, ch) in s.chars().enumerate() {
        g[c] = ch.to_digit(10).unwrap() as u8;
    }
    g
}

/// The 27 units: rows, columns, boxes.
fn units() -> Vec<Vec<usize>> {
    let mut u = vec![];
    for i in 0..9 {
        u.push((0..9).map(|j| i * 9 + j).collect());
        u.push((0..9).map(|j| j * 9 + i).collect());
        u.push((0..9).map(|j| (i / 3 * 3 + j / 3) * 9 + i % 3 * 3 + j % 3).collect());
    }
    u
}

fn sees(a: usize, b: usize) -> bool {
    a != b && (a / 9 == b / 9 || a % 9 == b % 9 || (a / 27 == b / 27 && a % 9 / 3 == b % 9 / 3))
}

fn complete(g: &Grid) -> bool {
    units().iter().all(|u| {
        let mut ds: Vec<u8> = u.iter().map(|&c| g[c]).collect();
        ds.sort();
        ds == (1..=9).collect::<Vec<u8>>()
    })
}

/// How many solutions `g` has, counted as far as `limit`: the cell with fewest digits that fit
/// first, each in turn.
fn count(g: &mut Grid, limit: usize) -> usize {
    let mut best: Option<(usize, Vec<u8>)> = None;
    for c in (0..81).filter(|&c| g[c] == 0) {
        let fit: Vec<u8> = (1..=9).filter(|&d| (0..81).all(|o| !sees(c, o) || g[o] != d)).collect();
        if best.as_ref().is_none_or(|b| fit.len() < b.1.len()) {
            best = Some((c, fit));
        }
    }
    let Some((c, fit)) = best else { return 1 };
    let mut n = 0;
    for d in fit {
        g[c] = d;
        n += count(g, limit - n);
        g[c] = 0;
        if n >= limit {
            break;
        }
    }
    n
}

/// The tests' own grader: how far each set of rules gets, applied until it can't. 0: hidden
/// singles solve it; 1: naked singles too; 2: with locked candidates and naked and hidden pairs
/// and triples; 3: not even those.
fn grade(p: &Grid) -> u8 {
    for (level, rules) in [1, 2, 3].iter().enumerate() {
        if closes(p, *rules) {
            return level as u8;
        }
    }
    3
}

/// Whether `rules` (1 hidden singles, 2 naked singles too, 3 locked candidates and subsets too)
/// solve `p`.
fn closes(p: &Grid, rules: u8) -> bool {
    let units = units();
    let mut g = *p;
    let mut cand = [0u16; 81];
    for c in 0..81 {
        if g[c] == 0 {
            cand[c] =
                (1..=9u8).filter(|&d| (0..81).all(|o| !sees(c, o) || g[o] != d)).fold(0, |m, d| m | 1 << d);
        }
    }
    let place = |g: &mut Grid, cand: &mut [u16; 81], c: usize, d: u8| {
        g[c] = d;
        cand[c] = 0;
        for o in (0..81).filter(|&o| sees(c, o)) {
            cand[o] &= !(1 << d);
        }
    };
    loop {
        let mut progress = false;
        // hidden singles
        for u in &units {
            for d in 1..=9u8 {
                let places: Vec<usize> = u.iter().copied().filter(|&c| cand[c] & 1 << d != 0).collect();
                if places.len() == 1 && !u.iter().any(|&c| g[c] == d) {
                    place(&mut g, &mut cand, places[0], d);
                    progress = true;
                }
            }
        }
        if progress {
            continue;
        }
        if rules >= 2 {
            for c in 0..81 {
                if g[c] == 0 && cand[c].count_ones() == 1 {
                    let d = cand[c].trailing_zeros() as u8;
                    place(&mut g, &mut cand, c, d);
                    progress = true;
                }
            }
        }
        if progress {
            continue;
        }
        if rules >= 3 {
            let before = cand;
            // locked candidates: a box's digit on one line alone leaves the line, and a line's
            // digit in one box alone leaves the box
            for b in 18..27 {
                for line in (0..18).filter(|&l| units[l].iter().any(|c| units[b].contains(c))) {
                    let meet: Vec<usize> =
                        units[b].iter().copied().filter(|c| units[line].contains(c)).collect();
                    for d in 1..=9u8 {
                        let has = |c: &usize| cand[*c] & 1 << d != 0;
                        let in_meet = meet.iter().any(has);
                        let box_rest = units[b].iter().filter(|c| !meet.contains(c)).any(has);
                        let line_rest = units[line].iter().filter(|c| !meet.contains(c)).any(has);
                        if in_meet && !box_rest {
                            for &c in units[line].iter().filter(|c| !meet.contains(c)) {
                                cand[c] &= !(1 << d);
                            }
                        }
                        if in_meet && !line_rest {
                            for &c in units[b].iter().filter(|c| !meet.contains(c)) {
                                cand[c] &= !(1 << d);
                            }
                        }
                    }
                }
            }
            // naked and hidden subsets of two and three
            for u in &units {
                let empty: Vec<usize> = u.iter().copied().filter(|&c| g[c] == 0).collect();
                for size in [2usize, 3] {
                    for pick in subsets(&empty, size) {
                        let digits = pick.iter().fold(0u16, |m, &c| m | cand[c]);
                        if digits.count_ones() as usize == size {
                            for &c in empty.iter().filter(|c| !pick.contains(c)) {
                                cand[c] &= !digits;
                            }
                        }
                    }
                    let digits: Vec<u8> =
                        (1..=9).filter(|&d| empty.iter().any(|&c| cand[c] & 1 << d != 0)).collect();
                    for pick in subsets(&digits, size) {
                        let cells: Vec<usize> = empty
                            .iter()
                            .copied()
                            .filter(|&c| pick.iter().any(|&d| cand[c] & 1 << d != 0))
                            .collect();
                        if cells.len() == size {
                            let keep = pick.iter().fold(0u16, |m, &d| m | 1 << d);
                            for &c in &cells {
                                cand[c] &= keep;
                            }
                        }
                    }
                }
            }
            progress = cand != before;
        }
        if !progress {
            return g.iter().all(|&d| d != 0);
        }
    }
}

fn subsets<T: Copy>(items: &[T], k: usize) -> Vec<Vec<T>> {
    if k == 0 {
        return vec![vec![]];
    }
    let mut out = vec![];
    for i in 0..items.len() {
        for mut rest in subsets(&items[i + 1..], k - 1) {
            rest.insert(0, items[i]);
            out.push(rest);
        }
    }
    out
}

/// A game as the app keeps it.
#[derive(Clone, Debug, PartialEq)]
struct Kept {
    level: u8,
    cursor: usize,
    solved: bool,
    seconds: u32,
    solution: Grid,
    clues: Grid,
    written: Grid,
    marks: [u16; 81],
}

fn kept(storage: &BTreeMap<String, Vec<u8>>) -> Kept {
    let b = &storage["game"];
    assert_eq!((b.len(), b[0]), (343, 1));
    let solution: Grid = b[8..89].try_into().unwrap();
    let mut clues = [0; 81];
    for c in 0..81 {
        if b[89 + c / 8] & 1 << (c % 8) != 0 {
            clues[c] = solution[c];
        }
    }
    Kept {
        level: b[1],
        cursor: b[2] as usize,
        solved: b[3] == 1,
        seconds: u32::from_le_bytes(b[4..8].try_into().unwrap()),
        solution,
        clues,
        written: b[100..181].try_into().unwrap(),
        marks: std::array::from_fn(|c| u16::from_le_bytes([b[181 + 2 * c], b[182 + 2 * c]])),
    }
}

fn record(k: &Kept) -> Vec<u8> {
    let mut b = vec![1, k.level, k.cursor as u8, k.solved as u8];
    b.extend(k.seconds.to_le_bytes());
    b.extend(k.solution);
    let mut bits = [0u8; 11];
    for c in 0..81 {
        if k.clues[c] != 0 {
            bits[c / 8] |= 1 << (c % 8);
        }
    }
    b.extend(bits);
    b.extend(k.written);
    for m in k.marks {
        b.extend(m.to_le_bytes());
    }
    b
}

/// A ready puzzle as the app keeps it: the solution and which cells are clues.
fn ready_record(clues: &Grid, solution: &Grid) -> Vec<u8> {
    let mut b = solution.to_vec();
    let mut bits = [0u8; 11];
    for c in 0..81 {
        if clues[c] != 0 {
            bits[c / 8] |= 1 << (c % 8);
        }
    }
    b.extend(bits);
    b
}

fn ready(storage: &BTreeMap<String, Vec<u8>>, level: usize) -> Option<(Grid, Grid)> {
    let b = storage.get(&format!("ready{level}"))?;
    assert_eq!(b.len(), 92);
    let solution: Grid = b[..81].try_into().unwrap();
    let clues = std::array::from_fn(|c| if b[81 + c / 8] & 1 << (c % 8) != 0 { solution[c] } else { 0 });
    Some((clues, solution))
}

/// A medium game on `SOLUTION`, a cell in three a clue, nothing written yet, at `cursor`.
fn a_game(cursor: usize) -> Kept {
    let solution = grid(SOLUTION);
    Kept {
        level: 1,
        cursor,
        solved: false,
        seconds: 0,
        solution,
        clues: std::array::from_fn(|c| if c % 3 == 0 { solution[c] } else { 0 }),
        written: [0; 81],
        marks: [0; 81],
    }
}

/// Storage holding `game`, and a puzzle ready at every level (so nothing's being made).
fn with(game: &Kept) -> BTreeMap<String, Vec<u8>> {
    let mut s = BTreeMap::from([("game".to_string(), record(game))]);
    for l in 0..4 {
        s.insert(format!("ready{l}"), ready_record(&game.clues, &game.solution));
    }
    s
}

fn run(events: &[Event], storage: BTreeMap<String, Vec<u8>>) -> Record {
    let (stop, r) = run_fixture("sudoku", events, storage);
    assert_eq!(stop, Stop::Finished);
    r
}

fn run_clocked(events: &[Event], storage: BTreeMap<String, Vec<u8>>, fuel: Option<u64>) -> (Stop, Record) {
    let bytes = std::fs::read(format!("{}/tests/fixtures/sudoku.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bytes).unwrap();
    let limits = admit(&bundle.manifest, bundle.code).unwrap();
    let record = Rc::new(RefCell::new(Record {
        events: events.iter().copied().collect(),
        storage,
        clock: true,
        ..Default::default()
    }));
    let mut loaded = load_installed(&bundle.manifest, bundle.code).unwrap();
    loaded.limits = limits;
    if let Some(fuel) = fuel {
        loaded.limits.fuel = fuel;
    }
    let stop = loaded.run(Box::new(Script(record.clone())));
    (stop, Rc::try_unwrap(record).ok().unwrap().into_inner())
}

/// Where cell `i` of a row or column starts on the screen: 11-pixel cells, a line before each.
fn at(i: usize) -> i32 { 1 + i as i32 * 12 }

/// The digit cell `c` shows, read off the screen as maki's fonts draw it (clues bold, the rest
/// plain), and whether it's bold; the cursor's cell inverted. None for a cell with no digit.
fn digit_at(frame: &Canvas, c: usize, cursor: bool) -> Option<(u8, bool)> {
    let (x, y) = (at(c % 9), at(c / 9));
    let cell = |canvas: &Canvas| -> Vec<bool> {
        (0..11)
            .flat_map(|dy| (0..11).map(move |dx| (dx, dy)))
            .map(|(dx, dy)| canvas.get(x + dx, y + dy))
            .collect()
    };
    let shown: Vec<bool> = cell(frame).into_iter().map(|p| p != cursor).collect();
    for d in 1..=9u8 {
        for (style, bold) in [(Style::Bold, true), (Style::Regular, false)] {
            let mut want = Canvas::default();
            let s = d.to_string();
            want.text(x + (11 - Canvas::text_width(&s, style) + 1) / 2, y - 2, &s, style, Color::Light);
            if cell(&want) == shown {
                return Some((d, bold));
            }
        }
    }
    None
}

/// Whether the grid's on the screen: its solid lines round the boxes.
fn grid_shown(frame: &Canvas) -> bool {
    (0..109).all(|i| frame.get(0, i) && frame.get(i, 36) && frame.get(72, i))
}

/// Whether the level chooser's on the screen with row `i` picked: its bar, lit across.
fn choosing(frame: &Canvas, i: i32) -> bool { (0..WIDTH as i32).all(|x| frame.get(x, 17 + 16 * i)) }

#[test]
fn sudoku_makes_the_puzzle_chosen_with_one_solution_and_the_level_it_says() {
    use Event::*;
    // nothing kept: the chooser, easy picked; nothing's made yet, so it's made now
    let mut events = vec![Centre];
    events.extend([Timeout; 30]);
    let r = run(&events, BTreeMap::new());
    assert_eq!(r.menu, ["New puzzle", "Show mistakes", "Start over", "Forget best times"]);
    assert!(choosing(&r.frames[0], 0));
    assert!(!grid_shown(&r.frames[1]), "making it first");
    assert!(grid_shown(r.frames.last().unwrap()));
    let g = kept(&r.storage);
    assert_eq!((g.level, g.solved, g.written, g.marks), (0, false, [0; 81], [0; 81]));
    assert!(complete(&g.solution));
    assert!((0..81).all(|c| g.clues[c] == 0 || g.clues[c] == g.solution[c]));
    assert_eq!(g.clues.iter().filter(|&&d| d != 0).count(), 36, "an easy one keeps 36 clues");
    assert_eq!(count(&mut g.clues.clone(), 2), 1);
    assert_eq!(grade(&g.clues), 0, "hidden singles alone");
    // and it's drawn: each clue bold where it is, the rest empty
    let last = r.frames.last().unwrap();
    for c in 0..81 {
        let want = (g.clues[c] != 0).then_some((g.clues[c], true));
        assert_eq!(digit_at(last, c, c == g.cursor), want, "cell {c}");
    }
}

#[test]
fn sudoku_makes_each_level_ahead_while_left_alone_never_long_without_waiting() {
    // left on the chooser, quiet: a puzzle for each level is made and kept, a step at a time.
    // Run with a twentieth of the work maki allows between waits, it's never stopped for it
    let (stop, r) = run_clocked(&[Event::Timeout; 400], BTreeMap::new(), Some(5_000_000));
    assert_eq!(stop, Stop::Finished);
    assert!(!r.storage.contains_key("game"));
    for level in 0..4 {
        let (clues, solution) = ready(&r.storage, level).unwrap_or_else(|| panic!("level {level} made"));
        assert!(complete(&solution));
        assert!((0..81).all(|c| clues[c] == 0 || clues[c] == solution[c]));
        assert_eq!(count(&mut clues.clone(), 2), 1, "level {level}: one solution");
        assert_eq!(grade(&clues), level as u8, "level {level}");
        let n = clues.iter().filter(|&&d| d != 0).count();
        if level == 0 {
            assert_eq!(n, 36);
        } else {
            assert!((17..=32).contains(&n), "level {level}: {n} clues");
        }
    }
    // picking a level that's ready begins it at once, and another's made to take its place
    let mut events = vec![Event::Down, Event::Down, Event::Centre];
    events.extend([Event::Timeout; 200]);
    let (_, again) = run_clocked(&events, r.storage.clone(), None);
    let g = kept(&again.storage);
    assert_eq!(
        (g.level, g.clues, g.solution),
        (2, ready(&r.storage, 2).unwrap().0, ready(&r.storage, 2).unwrap().1)
    );
    let (clues, _) = ready(&again.storage, 2).expect("another hard one");
    assert_ne!(clues, g.clues);
    assert_eq!((count(&mut clues.clone(), 2), grade(&clues)), (1, 2));
}

#[test]
fn sudoku_moves_round_the_grid_with_left_right_and_the_dial() {
    use Event::*;
    let at = |events: &[Event], from: usize| kept(&run(events, with(&a_game(from))).storage).cursor;
    // left and right go along the rows and on round, the dial up and down the columns
    assert_eq!(at(&[Left], 0), 80);
    assert_eq!(at(&[Right], 80), 0);
    assert_eq!(at(&[Right, Right], 8), 10);
    assert_eq!(at(&[Up], 4), 76);
    assert_eq!(at(&[Down], 76), 4);
    // the centre on a clue opens nothing: the dial still moves the cursor
    assert_eq!(at(&[Centre, Down], 0), 9);
}

#[test]
fn sudoku_picker_writes_a_digit_and_pencils_marks_in() {
    use Event::*;
    // cell 1 is empty (its solution 6): the picker opens at 1; five down and the centre write 6
    let r = run(&[Right, Centre, Down, Down, Down, Down, Down, Centre], with(&a_game(0)));
    let g = kept(&r.storage);
    assert_eq!((g.cursor, g.written[1]), (1, 6));
    assert_eq!(digit_at(r.frames.last().unwrap(), 1, true), Some((6, false)), "written plain");
    // it opens at the cell's digit: up writes 5 over it; left in the left column closes it
    let r = run(&[Centre, Up, Centre, Centre, Down, Left, Down], with(&g));
    let after = kept(&r.storage);
    assert_eq!((after.written[1], after.cursor), (5, 10), "left closed it unchanged; the dial moved on");
    // the right column pencils marks in, one at a time, and stays open; out of its right closes it
    let r = run(&[Right, Centre, Right, Centre, Down, Down, Centre, Right, Down], with(&a_game(1)));
    let g = kept(&r.storage);
    assert_eq!((g.marks[2], g.cursor), (1 << 1 | 1 << 3, 11));
    // shown as dots in the cell, where the digits are on a keypad: 1 top left, 3 top right
    let last = r.frames.last().unwrap();
    let (x, y) = (at(2), at(0));
    assert!(last.get(x + 2, y + 2) && last.get(x + 8, y + 2) && !last.get(x + 5, y + 2));
    // the x at the bottom of the right column clears them; of the left, the digit
    let mut marked = a_game(2);
    marked.marks[2] = 0b1110;
    marked.written[4] = 7;
    let r = run(
        &[Centre, Right, Up, Centre, Left, Left, Right, Right, Centre, Down, Down, Down, Centre],
        with(&marked),
    );
    let g = kept(&r.storage);
    assert_eq!((g.marks[2], g.written[4], g.cursor), (0, 0, 4));
    // a digit written takes itself from the marks of every cell that sees it, and the cell's own go
    let mut marked = a_game(1);
    for c in [2, 10, 37, 7, 50] {
        marked.marks[c] = 1 << 6 | 1 << 8;
    }
    marked.marks[1] = 1 << 4;
    let r = run(&[Centre, Down, Down, Down, Down, Down, Centre], with(&marked));
    let g = kept(&r.storage);
    assert_eq!(g.written[1], 6);
    assert_eq!(g.marks[1], 0);
    for c in [2, 10, 37, 7] {
        assert_eq!(g.marks[c], 1 << 8, "cell {c} sees cell 1");
    }
    assert_eq!(g.marks[50], 1 << 6 | 1 << 8, "cell 50 doesn't");
}

#[test]
fn sudoku_solved_with_the_last_digit_keeps_the_best_time() {
    use Event::*;
    // everything written but cell 80 (its solution 6)
    let mut g = a_game(80);
    for c in 0..80 {
        if g.clues[c] == 0 {
            g.written[c] = g.solution[c];
        }
    }
    g.seconds = 754;
    let finish = [Centre, Down, Down, Down, Down, Down, Centre];
    let r = run(&finish, with(&g));
    let after = kept(&r.storage);
    assert!(after.solved);
    assert_eq!(after.seconds, 754);
    let best = |r: &Record| r.storage.get("best").map(|b| u32::from_le_bytes(b[4..8].try_into().unwrap()));
    assert_eq!(best(&r), Some(754));
    let note = r.frames.last().unwrap();
    assert!(note.get(6, 30) && note.get(WIDTH as i32 - 7, 81), "the note over the grid");
    // a slower one keeps the best; a faster one takes its place
    for (was, now) in [(700, 700), (800, 754)] {
        let mut storage = with(&g);
        let mut b = vec![0u8; 16];
        b[4..8].copy_from_slice(&(was as u32).to_le_bytes());
        storage.insert("best".into(), b);
        assert_eq!(best(&run(&finish, storage)), Some(now));
    }
    // solved, the centre goes to the chooser, on its level; nothing more is written
    let mut events = finish.to_vec();
    events.extend([Down, Centre]);
    let r = run(&events, with(&g));
    assert!(choosing(r.frames.last().unwrap(), 1));
    assert!(kept(&r.storage).solved);
    // opened again, it's still solved: presses other than the centre do nothing
    let r = run(&[Left, Up, Centre], r.storage);
    assert_eq!(kept(&r.storage).cursor, 80);
    assert!(choosing(r.frames.last().unwrap(), 1));
}

#[test]
fn sudoku_full_but_wrong_says_so_and_shows_mistakes_only_when_asked() {
    use Event::*;
    // everything written, cell 1 wrong (a 7 for a 6), but cell 80
    let mut g = a_game(80);
    for c in 0..80 {
        if g.clues[c] == 0 {
            g.written[c] = g.solution[c];
        }
    }
    g.written[1] = 7;
    let r = run(&[Centre, Down, Down, Down, Down, Down, Centre, Left], with(&g));
    let after = kept(&r.storage);
    assert!(!after.solved);
    assert_eq!(after.written[80], 6);
    // a note over the grid that any key takes away (not moving the cursor)
    let n = r.frames.len();
    assert_ne!(r.frames[n - 2], r.frames[n - 1]);
    assert_eq!(after.cursor, 80);
    assert!(!r.storage.contains_key("best"));
    // the wrong digit is drawn as any other, until mistakes are asked for: then struck through
    let r = run(&[Menu(1), Menu(1)], with(&after));
    assert_eq!(r.menu, ["New puzzle", "Show mistakes", "Start over", "Forget best times"]);
    let (plain, struck) = (&r.frames[0], &r.frames[1]);
    assert_eq!(digit_at(plain, 1, false), Some((7, false)));
    assert_eq!(digit_at(struck, 1, false), None);
    let (x, y) = (at(1), at(0));
    assert_ne!(plain.get(x, y + 10), struck.get(x, y + 10), "the stroke's corner");
    for c in (0..81).filter(|&c| c != 1) {
        assert_eq!(digit_at(struck, c, c == 80), digit_at(plain, c, c == 80), "cell {c} untouched");
    }
    assert_eq!(r.frames[2], r.frames[0], "and hidden again");
    assert_eq!(r.storage.get("mistakes"), Some(&0u32.to_le_bytes().to_vec()));
    let r = run(&[Menu(1)], with(&after));
    assert_eq!(r.storage.get("mistakes"), Some(&1u32.to_le_bytes().to_vec()));
    // kept: shown from the start next time, and the menu says so
    let mut storage = with(&after);
    storage.insert("mistakes".into(), 1u32.to_le_bytes().to_vec());
    let r = run(&[], storage);
    assert_eq!(r.menu[1], "Hide mistakes");
    assert_eq!(digit_at(&r.frames[0], 1, false), None);
}

#[test]
fn sudoku_keeps_the_game_and_its_clock_which_stops_while_away() {
    use Event::*;
    // a minute's tick at a time: two, away a while, back for one more, then left
    let mut g = a_game(5);
    g.written[1] = 6;
    g.marks[2] = 1 << 4;
    let events = [Timeout, Timeout, Hidden, Timeout, Shown, Timeout];
    let (_, r) = run_clocked(&events, with(&g), None);
    let after = kept(&r.storage);
    assert_eq!(after.seconds, 180);
    assert_eq!(Kept { seconds: 0, ..after.clone() }, g);
    // the chooser stops it too
    let (_, r) = run_clocked(&[Timeout, Menu(0), Timeout, Timeout], with(&g), None);
    assert_eq!(kept(&r.storage).seconds, 60);
    // opened again, it's the same game, the panel saying how long
    let r = run(&[], r.storage);
    assert_eq!(kept(&r.storage).seconds, 60);
    assert_eq!(digit_at(&r.frames[0], 1, false), Some((6, false)));
}

#[test]
fn sudoku_new_puzzle_start_over_and_forgetting_the_best() {
    use Event::*;
    let mut g = a_game(1);
    g.written[1] = 6;
    g.marks[2] = 1 << 4;
    g.seconds = 99;
    // the chooser: back to the puzzle being played, below the levels, changes nothing
    let r = run(&[Menu(0), Up, Up, Centre], with(&g));
    assert!(grid_shown(r.frames.last().unwrap()));
    assert_eq!(kept(&r.storage), g);
    // a level picked begins its ready puzzle, which is used up
    let mut storage = with(&g);
    let mut fresh = a_game(0);
    fresh.clues = std::array::from_fn(|c| if c % 2 == 0 { fresh.solution[c] } else { 0 });
    storage.insert("ready3".into(), ready_record(&fresh.clues, &fresh.solution));
    let r = run(&[Menu(0), Down, Down, Centre], storage);
    let now = kept(&r.storage);
    assert_eq!(
        (now.level, now.clues, now.written, now.seconds, now.cursor),
        (3, fresh.clues, [0; 81], 0, 40)
    );
    assert!(!r.storage.contains_key("ready3"));
    // start over: what's written and marked goes, the clock doesn't
    let r = run(&[Menu(2)], with(&g));
    let now = kept(&r.storage);
    assert_eq!((now.written, now.marks, now.seconds), ([0; 81], [0; 81], 99));
    // forgetting the best times
    let mut storage = with(&g);
    storage.insert("best".into(), vec![1; 16]);
    let r = run(&[Menu(3)], storage);
    assert!(!r.storage.contains_key("best"));
}

#[test]
fn sudoku_refuses_kept_data_that_makes_no_sense() {
    use Event::*;
    let good = record(&a_game(3));
    let chooser = run(&[], BTreeMap::new()).frames[0].clone();
    let mut bad: Vec<(&str, Vec<u8>)> = vec![];
    bad.push(("short", good[..342].to_vec()));
    let mut b = good.clone();
    b[0] = 2;
    bad.push(("a format to come", b));
    let mut b = good.clone();
    b[1] = 4;
    bad.push(("no such level", b));
    let mut b = good.clone();
    b[2] = 81;
    bad.push(("cursor off the grid", b));
    let mut b = good.clone();
    b[3] = 2;
    bad.push(("solved neither way", b));
    let mut b = good.clone();
    b.swap(8, 9);
    bad.push(("a solution that isn't one", b));
    let mut b = good.clone();
    b[100 + 1] = 10;
    bad.push(("a digit past 9", b));
    let mut b = good.clone();
    b[181 + 2] = 1;
    bad.push(("a mark for 0", b));
    let mut b = good.clone();
    b[89..100].fill(0);
    b[89] = 0xff;
    bad.push(("8 clues", b));
    for (why, b) in bad {
        let r = run(&[Exit], BTreeMap::from([("game".to_string(), b.clone())]));
        assert_eq!(r.frames[0], chooser, "{why}: the chooser, as with nothing kept");
        assert_eq!(r.storage["game"], b, "{why}: left alone");
    }
    // a ready puzzle that isn't one isn't played: it's made again
    let mut solution = grid(SOLUTION);
    solution.swap(0, 1);
    let storage = BTreeMap::from([("ready0".to_string(), ready_record(&[0; 81], &solution))]);
    let r = run(&[Centre], storage);
    assert!(!r.storage.contains_key("game"));
    assert!(!grid_shown(r.frames.last().unwrap()), "making one");
    // best times of the wrong length are none
    let r = run(&[], BTreeMap::from([("best".to_string(), vec![9; 15])]));
    assert_eq!(r.frames[0], chooser);
}
