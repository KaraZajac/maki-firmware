//! The Sokoban example (sdk/examples/sokoban), as `maki build` packed it and maki runs it: every
//! level it ships played to the end through its buttons, with solutions found by a solver of the
//! tests' own (`fixtures/sokoban-solutions.txt`) and replayed here first on a model of the rules,
//! from the level file the app embeds; walking and pushing as that model says, moves taken back,
//! the fewest moves kept, the levels to choose from, a level too big for the screen scrolled, the
//! game kept across a restart, and stored data that makes no sense refused. Rebuild the fixture
//! after changing the app: `maki build sdk/examples/sokoban`, then copy
//! `sdk/target/maki/com.leviathan.maki.sokoban.maki` to `tests/fixtures/sokoban.maki`.

mod harness;

use std::collections::BTreeMap;

use harness::*;
use maki_wasm::*;

const LEVELS: &str = include_str!("../../../sdk/examples/sokoban/src/microban.txt");
const SOLUTIONS: &str = include_str!("fixtures/sokoban-solutions.txt");

/// A level as the file has it, and where things stand in it.
#[derive(Clone, Debug, PartialEq)]
struct Level {
    number: u8,
    w: usize,
    h: usize,
    walls: Vec<bool>,
    goals: Vec<bool>,
    boxes: Vec<bool>,
    player: usize,
}

/// The levels in the file, in its order: a "; 12" (or "; 44 'Duh!'") line, then the rows.
fn levels() -> Vec<Level> {
    let mut out: Vec<(u8, Vec<&str>)> = vec![];
    for line in LEVELS.lines() {
        if let Some(rest) = line.strip_prefix("; ") {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !digits.is_empty() && matches!(rest[digits.len()..].chars().next(), None | Some(' ')) {
                out.push((digits.parse().unwrap(), vec![]));
                continue;
            }
        }
        if !line.starts_with(';') && !line.trim().is_empty() {
            out.last_mut().unwrap().1.push(line.trim_end());
        }
    }
    out.into_iter()
        .map(|(number, rows)| {
            let (w, h) = (rows.iter().map(|r| r.len()).max().unwrap(), rows.len());
            let mut l = Level {
                number,
                w,
                h,
                walls: vec![false; w * h],
                goals: vec![false; w * h],
                boxes: vec![false; w * h],
                player: usize::MAX,
            };
            for (y, row) in rows.iter().enumerate() {
                for (x, ch) in row.chars().enumerate() {
                    let c = y * w + x;
                    l.walls[c] = ch == '#';
                    l.goals[c] = matches!(ch, '.' | '*' | '+');
                    l.boxes[c] = matches!(ch, '$' | '*');
                    if matches!(ch, '@' | '+') {
                        l.player = c;
                    }
                }
            }
            l
        })
        .collect()
}

impl Level {
    /// A step `way` ('u', 'd', 'l', 'r'), pushing a box if there's room beyond it: whether it
    /// moved, and whether it pushed.
    fn step(&mut self, way: char) -> Option<bool> {
        let (dx, dy) = match way {
            'u' => (0, -1),
            'd' => (0, 1),
            'l' => (-1, 0),
            _ => (1, 0),
        };
        let next = |c: usize| {
            let (x, y) = ((c % self.w) as i32 + dx, (c / self.w) as i32 + dy);
            ((0..self.w as i32).contains(&x) && (0..self.h as i32).contains(&y))
                .then(|| y as usize * self.w + x as usize)
        };
        let to = next(self.player).filter(|&c| !self.walls[c])?;
        let mut pushed = false;
        if self.boxes[to] {
            let beyond = next(to).filter(|&c| !self.walls[c] && !self.boxes[c])?;
            self.boxes[to] = false;
            self.boxes[beyond] = true;
            pushed = true;
        }
        self.player = to;
        Some(pushed)
    }

    fn solved(&self) -> bool { (0..self.w * self.h).all(|c| !self.boxes[c] || self.goals[c]) }

    fn box_cells(&self) -> Vec<usize> { (0..self.w * self.h).filter(|&c| self.boxes[c]).collect() }
}

fn solutions() -> BTreeMap<u8, String> {
    SOLUTIONS
        .lines()
        .filter(|l| !l.starts_with(';'))
        .map(|l| {
            let (n, moves) = l.split_once(' ').unwrap();
            (n.parse().unwrap(), moves.to_string())
        })
        .collect()
}

fn event(way: char) -> Event {
    match way.to_ascii_lowercase() {
        'u' => Event::Up,
        'd' => Event::Down,
        'l' => Event::Left,
        _ => Event::Right,
    }
}

/// The game as the app keeps it: the level's number, the player's cell, the boxes' cells, the
/// moves, and the moves remembered for taking back.
#[derive(Clone, Debug, PartialEq)]
struct Kept {
    number: u8,
    player: usize,
    boxes: Vec<usize>,
    moves: u16,
    history: Vec<u8>,
}

fn kept(storage: &BTreeMap<String, Vec<u8>>) -> Kept {
    let b = &storage["game"];
    assert_eq!(b[0], 1);
    let n = b[3] as usize;
    let rest = &b[4 + n..];
    let len = rest[2] as usize;
    assert_eq!(rest.len(), 3 + len);
    Kept {
        number: b[1],
        player: b[2] as usize,
        boxes: b[4..4 + n].iter().map(|&c| c as usize).collect(),
        moves: u16::from_le_bytes([rest[0], rest[1]]),
        history: rest[3..].to_vec(),
    }
}

fn record(k: &Kept) -> Vec<u8> {
    let mut b = vec![1, k.number, k.player as u8, k.boxes.len() as u8];
    b.extend(k.boxes.iter().map(|&c| c as u8));
    b.extend(k.moves.to_le_bytes());
    b.push(k.history.len() as u8);
    b.extend(&k.history);
    b
}

fn best(storage: &BTreeMap<String, Vec<u8>>, number: u8) -> u16 {
    storage
        .get("best")
        .map_or(0, |b| u16::from_le_bytes([b[2 * number as usize], b[2 * number as usize + 1]]))
}

fn run(events: &[Event], storage: BTreeMap<String, Vec<u8>>) -> Record {
    let (stop, r) = run_fixture("sokoban", events, storage);
    assert_eq!(stop, Stop::Finished);
    r
}

/// The presses that pick level `i` (in the file's order) from the levels' screen, opened from
/// the first: down ten at a time, then right.
fn choose(i: usize) -> Vec<Event> {
    let mut events = vec![Event::Menu(1)];
    events.extend(std::iter::repeat_n(Event::Down, i / 10));
    events.extend(std::iter::repeat_n(Event::Right, i % 10));
    events.push(Event::Centre);
    events
}

#[test]
fn sokoban_ships_148_levels_each_solved_on_the_model_and_through_the_app() {
    let levels = levels();
    let numbers: Vec<u8> = levels.iter().map(|l| l.number).collect();
    let want: Vec<u8> = (1..=147).chain([152]).collect();
    assert_eq!(numbers, want, "Microban but 148 to 151, 153, 154 and 155");
    let solutions = solutions();
    let mut storage = BTreeMap::new();
    for (i, level) in levels.iter().enumerate() {
        // the level's well formed, and closed: walking never leaves it
        assert!(level.player < level.w * level.h, "{}", level.number);
        assert_eq!(level.boxes.iter().filter(|&&b| b).count(), level.goals.iter().filter(|&&g| g).count());
        assert!(level.w * level.h <= 256);
        let moves = &solutions[&level.number];
        // on the model first: every step legal, pushing exactly where it says, and solved
        let mut model = level.clone();
        for ch in moves.chars() {
            let pushed = model
                .step(ch.to_ascii_lowercase())
                .unwrap_or_else(|| panic!("{}: {ch} blocked", level.number));
            assert_eq!(pushed, ch.is_ascii_uppercase(), "level {}", level.number);
        }
        assert!(model.solved(), "level {}", level.number);
        // then through the app's buttons, from its levels' screen
        let mut events = choose(i);
        events.extend(moves.chars().map(event));
        // from level 1, where the levels' screen opens
        storage.remove("game");
        let r = run(&events, storage);
        let k = kept(&r.storage);
        assert_eq!((k.number, k.player, k.boxes.clone()), (level.number, model.player, model.box_cells()));
        assert_eq!(k.moves as usize, moves.len());
        assert_eq!(best(&r.storage, level.number) as usize, moves.len(), "level {}", level.number);
        storage = r.storage;
    }
    // all solved
    let solved = (1..=155u8).filter(|&n| best(&storage, n) > 0).count();
    assert_eq!(solved, 148);
}

#[test]
fn sokoban_walks_and_pushes_as_the_rules_say() {
    use Event::*;
    let mut level = levels()[0].clone();
    // level 1: the player at 20; a box to its left already on its goal, against a wall; one
    // below right
    let presses = [Left, Right, Down, Down, Left, Up, Up, Up, Right, Down, Down, Right, Down, Left, Up];
    let r = run(&presses, BTreeMap::new());
    assert_eq!(r.menu, ["Start over", "Levels", "Forget progress"]);
    let mut moved = 0;
    for p in presses {
        let way = match p {
            Up => 'u',
            Down => 'd',
            Left => 'l',
            _ => 'r',
        };
        if level.step(way).is_some() {
            moved += 1;
        }
    }
    let k = kept(&r.storage);
    assert_eq!(
        (k.number, k.player, k.boxes.clone(), k.moves as usize),
        (1, level.player, level.box_cells(), moved)
    );
    assert!(moved < presses.len(), "some were blocked");
    assert_eq!(k.history.len(), moved);
}

#[test]
fn sokoban_centre_takes_moves_back_pulling_back_what_they_pushed() {
    use Event::*;
    let start = levels()[0].clone();
    // a step right, a step down that's blocked (a box with a wall beyond), and the centre: the
    // step right taken back
    let r = run(&[Right, Down, Centre], BTreeMap::new());
    let k = kept(&r.storage);
    assert_eq!(
        (k.player, k.boxes.clone(), k.moves, k.history.len()),
        (start.player, start.box_cells(), 0, 0)
    );
    // a push taken back: the box comes back too
    let mut events = vec![Down, Right, Down];
    let mut model = start.clone();
    for w in ['d', 'r', 'd'] {
        model.step(w);
    }
    let r = run(&events, BTreeMap::new());
    let pushed = kept(&r.storage);
    assert_eq!(pushed.boxes, model.box_cells());
    assert!(pushed.history.iter().any(|&h| h & 4 != 0), "a push remembered");
    events.extend([Centre, Centre, Centre, Centre]);
    let r = run(&events, BTreeMap::new());
    let k = kept(&r.storage);
    assert_eq!(
        (k.player, k.boxes.clone(), k.moves, k.history.len()),
        (start.player, start.box_cells(), 0, 0)
    );
    // the last 255 are remembered, no more
    let mut events: Vec<Event> = std::iter::repeat_n([Right, Left], 150).flatten().collect();
    let r = run(&events, BTreeMap::new());
    let k = kept(&r.storage);
    assert_eq!((k.moves, k.history.len()), (300, 255));
    events.extend(std::iter::repeat_n(Centre, 300));
    let r = run(&events, BTreeMap::new());
    assert_eq!(kept(&r.storage).moves, 45);
}

#[test]
fn sokoban_solved_keeps_the_fewest_moves_and_goes_on_to_the_next() {
    use Event::*;
    let moves = solutions()[&1].clone();
    let play: Vec<Event> = moves.chars().map(event).collect();
    let r = run(&play, BTreeMap::new());
    assert_eq!(best(&r.storage, 1) as usize, moves.len());
    // a note over the level; presses that would walk do nothing now
    let note = r.frames.last().unwrap().clone();
    assert!(note.get(8, 30));
    let mut more = play.clone();
    more.extend([Left, Up]);
    let r = run(&more, BTreeMap::new());
    assert_eq!(kept(&r.storage).moves as usize, moves.len());
    // more moves than the best keep the best; fewer take its place
    for (was, now) in [(moves.len() - 1, moves.len() - 1), (moves.len() + 5, moves.len())] {
        let mut b = vec![0u8; 312];
        b[2..4].copy_from_slice(&(was as u16).to_le_bytes());
        let r = run(&play, BTreeMap::from([("best".to_string(), b)]));
        assert_eq!(best(&r.storage, 1) as usize, now);
    }
    // the centre goes on to level 2, at its start
    let mut events = play.clone();
    events.push(Centre);
    let r = run(&events, BTreeMap::new());
    let k = kept(&r.storage);
    let two = levels()[1].clone();
    assert_eq!((k.number, k.player, k.boxes.clone(), k.moves), (2, two.player, two.box_cells(), 0));
}

#[test]
fn sokoban_levels_screen_picks_any_level_and_goes_back_to_this_one() {
    use Event::*;
    let levels = levels();
    // from level 1: left goes round to the last, the dial ten at a time
    let r = run(&[Right, Menu(1), Left, Centre], BTreeMap::new());
    assert_eq!(kept(&r.storage).number, 152);
    let r = run(&[Menu(1), Down, Down, Right, Centre], BTreeMap::new());
    assert_eq!(kept(&r.storage).number, 22);
    let r = run(&[Menu(1), Down, Down, Up, Centre], BTreeMap::new());
    assert_eq!(kept(&r.storage).number, 11);
    // the level being played picked again goes on where it was; another starts at its start
    let r = run(&[Right, Menu(1), Right, Left, Centre], BTreeMap::new());
    assert_eq!((kept(&r.storage).number, kept(&r.storage).moves), (1, 1));
    let r = run(&[Right, Menu(1), Right, Centre], BTreeMap::new());
    let k = kept(&r.storage);
    assert_eq!((k.number, k.player, k.moves), (2, levels[1].player, 0));
    // the menu again closes it, and the screens differ: a picture of the level, not the level
    let r = run(&[Menu(1), Menu(1)], BTreeMap::new());
    assert_ne!(r.frames[1], r.frames[0]);
    assert_eq!(r.frames[2], r.frames[0]);
}

#[test]
fn sokoban_scrolls_a_level_too_big_for_the_screen() {
    let levels = levels();
    // level 99, 22 cells across: at 8 pixels a cell, wider than the screen
    let i = levels.iter().position(|l| l.number == 99).unwrap();
    assert!(levels[i].w * 8 > 128);
    let mut events = choose(i);
    let moves = solutions()[&99].clone();
    events.extend(moves.chars().map(event));
    let r = run(&events, BTreeMap::new());
    assert_eq!(best(&r.storage, 99) as usize, moves.len());
    // the view follows the player: the frames' left edges change as it goes
    let start = r.frames.len() - moves.len() - 1;
    let edges: std::collections::BTreeSet<Vec<bool>> =
        r.frames[start..].iter().map(|f| (0..98).map(|y| f.get(0, y)).collect()).collect();
    assert!(edges.len() > 2, "{} different left edges", edges.len());
}

#[test]
fn sokoban_keeps_the_level_and_its_moves_across_a_restart() {
    use Event::*;
    let r = run(&[Right, Down, Right], BTreeMap::new());
    let before = kept(&r.storage);
    // opened again: the same, and what was remembered can still be taken back
    let r = run(&[], r.storage.clone());
    assert_eq!(kept(&r.storage), before);
    let r = run(&[Centre, Centre, Centre], r.storage);
    let start = levels()[0].clone();
    let k = kept(&r.storage);
    assert_eq!((k.player, k.boxes.clone(), k.moves), (start.player, start.box_cells(), 0));
    // start over, from the menu
    let r = run(&[Right, Right, Menu(0)], BTreeMap::new());
    assert_eq!(kept(&r.storage).moves, 0);
    // forgetting progress
    let moves = solutions()[&1].clone();
    let mut events: Vec<Event> = moves.chars().map(event).collect();
    events.push(Menu(2));
    let r = run(&events, BTreeMap::new());
    assert!(!r.storage.contains_key("best"));
}

#[test]
fn sokoban_refuses_kept_data_that_makes_no_sense() {
    let level = levels()[0].clone();
    let good =
        Kept { number: 1, player: level.player, boxes: level.box_cells(), moves: 3, history: vec![3, 2, 3] };
    let fresh = kept(&run(&[], BTreeMap::new()).storage);
    let wall = (0..level.w * level.h).find(|&c| level.walls[c]).unwrap();
    let floor =
        (0..level.w * level.h).find(|&c| !level.walls[c] && !level.boxes[c] && c != level.player).unwrap();
    let mut bad: Vec<(&str, Vec<u8>)> = vec![];
    let mut b = record(&good);
    b[0] = 2;
    bad.push(("a format to come", b));
    for (why, number) in [("a level left out", 148), ("no such level", 200), ("level 0", 0)] {
        bad.push((why, record(&Kept { number, ..good.clone() })));
    }
    bad.push(("the player in a wall", record(&Kept { player: wall, ..good.clone() })));
    bad.push(("the player on a box", record(&Kept { player: good.boxes[0], ..good.clone() })));
    bad.push(("off the map", record(&Kept { player: 200, ..good.clone() })));
    bad.push(("a box in a wall", record(&Kept { boxes: vec![good.boxes[0], wall], ..good.clone() })));
    bad.push(("two boxes in one place", record(&Kept { boxes: vec![floor, floor], ..good.clone() })));
    bad.push(("a box short", record(&Kept { boxes: vec![floor], ..good.clone() })));
    bad.push((
        "a box too many",
        record(&Kept { boxes: vec![good.boxes[0], good.boxes[1], floor], ..good.clone() }),
    ));
    bad.push(("too many moves", record(&Kept { moves: 10_000, ..good.clone() })));
    bad.push(("a move that isn't one", record(&Kept { history: vec![3, 8], ..good.clone() })));
    let mut b = record(&good);
    b.pop();
    bad.push(("cut short", b));
    let mut b = record(&good);
    b.push(0);
    bad.push(("a byte too many", b));
    for (why, b) in bad {
        let r = run(&[], BTreeMap::from([("game".to_string(), b)]));
        assert_eq!(kept(&r.storage), fresh, "{why}: level 1 from its start");
    }
    // the good one is taken, and a history that doesn't fit the map is forgotten when it's
    // reached, not followed
    let r = run(&[], BTreeMap::from([("game".to_string(), record(&good))]));
    assert_eq!(kept(&r.storage), good);
    let odd = Kept { history: vec![3], ..good.clone() };
    let r = run(&[Event::Centre, Event::Centre], BTreeMap::from([("game".to_string(), record(&odd))]));
    let k = kept(&r.storage);
    assert_eq!((k.player, k.history.len()), (good.player, 0));
    // best moves of the wrong length are none
    let r = run(&[Event::Menu(1)], BTreeMap::from([("best".to_string(), vec![1; 311])]));
    let none = run(&[Event::Menu(1)], BTreeMap::new());
    assert_eq!(r.frames[1], none.frames[1]);
}
