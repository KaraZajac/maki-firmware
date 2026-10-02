//! The Show QR example (sdk/examples/showqr), as `maki build` packed it and maki runs it: what the
//! computer sends, in any language, shown as a QR code that reads back as it was sent, and as text
//! on the next page; the last five kept, newest first, and gone through with left and right and the
//! jog dial; and what maki's screen can't show at two pixels a module refused with why. Rebuild the
//! fixture after changing the app: `maki build sdk/examples/showqr`, then copy
//! `sdk/target/maki/com.leviathan.maki.showqr.maki` to `tests/fixtures/showqr.maki`.

mod harness;

use std::collections::BTreeMap;

use harness::*;
use maki_wasm::*;

const SHOWN: u8 = 0;
const TOO_LONG: u8 = 1;
const NOT_TEXT: u8 = 2;
const UNKNOWN: u8 = 4;

/// Japanese, which the qrcode crate alone writes partly in Kanji mode, for phones to misread: maki
/// writes it as its bytes.
const JAPANESE: &str = "\u{65e5}\u{672c}\u{8a9e}\u{306e}\u{30c6}\u{30ad}\u{30b9}\u{30c8}\u{3067}\u{3059}\u{3002}\u{3053}\u{308c}\u{306f}\u{9577}\u{3044}\u{6587}\u{7ae0}\u{3067}\u{3059}\u{3002}";

fn show(text: &[u8]) -> Vec<u8> { [&b"S"[..], text].concat() }

/// The app run on these events, a message for each `Message` from `inbox`, from `storage`.
fn run(events: &[Event], inbox: &[Vec<u8>], storage: BTreeMap<String, Vec<u8>>) -> Record {
    let (stop, record) = run_record(
        "showqr",
        Record {
            events: events.iter().copied().collect(),
            inbox: inbox.iter().cloned().collect(),
            storage,
            ..Default::default()
        },
    );
    assert_eq!(stop, Stop::Finished);
    record
}

/// Each of `texts` sent in turn: the app's answers, and what it did.
fn sent(texts: &[&[u8]]) -> Record {
    let inbox: Vec<Vec<u8>> = texts.iter().map(|t| show(t)).collect();
    run(&vec![Event::Message; inbox.len()], &inbox, BTreeMap::new())
}

/// Whether `frame` has `text` at (x, y), in the box it takes.
fn shows(frame: &Canvas, x: i32, y: i32, text: &str, style: Style) -> bool {
    let mut want = Canvas::default();
    want.text(x, y, text, style, Color::Light);
    let w = Canvas::text_width(text, style);
    (y..y + style.height()).all(|row| (x..x + w).all(|col| frame.get(col, row) == want.get(col, row)))
}

/// The squares down the left edge that say which of those kept shows: how many, and which is
/// filled (`None` if there are none).
fn which(frame: &Canvas) -> (usize, Option<usize>) {
    let lit = |y: i32| (3..7).filter(|&x| frame.get(x, y)).count();
    let tops: Vec<i32> = (1..HEIGHT as i32).filter(|&y| lit(y) == 4 && lit(y - 1) == 0).collect();
    let filled = tops.iter().position(|&y| (y..y + 4).all(|row| lit(row) == 4));
    (tops.len(), filled)
}

/// `text` broken into lines as wide as the text page holds (119 pixels of maki's small font),
/// between words, and a word too long for a line by characters: for texts whose words each fit a
/// line, or that are one word.
fn wrapped(text: &str) -> Vec<String> {
    let fits = |s: &str| Canvas::text_width(s, Style::Small) <= 119;
    let mut lines = Vec::new();
    for own in text.split('\n') {
        let mut line = String::new();
        for word in own.split(' ') {
            let with = if line.is_empty() { word.to_string() } else { format!("{line} {word}") };
            if line.is_empty() || fits(&with) {
                line = with;
            } else {
                lines.push(std::mem::replace(&mut line, word.to_string()));
            }
        }
        while !fits(&line) {
            let n =
                line.char_indices().map(|(i, _)| i).filter(|&i| i > 0 && fits(&line[..i])).last().unwrap();
            lines.push(line[..n].to_string());
            line = line[n..].to_string();
        }
        lines.push(line);
    }
    lines
}

/// Whether the text page shows `lines` from its first row.
fn page_shows(frame: &Canvas, lines: &[String]) -> bool {
    shows(frame, 2, 0, "From the computer", Style::Small)
        && lines.iter().take(8).enumerate().all(|(i, l)| shows(frame, 2, 14 + 12 * i as i32, l, Style::Small))
}

#[test]
fn showqr_shows_what_it_is_sent_as_a_qr_code_that_reads_back_and_keeps_it() {
    let link = "https://maki.netslum.io/docs/confirm";
    let r = run(
        &[Event::Message, Event::Message, Event::Centre],
        &[show(link.as_bytes()), b"?".to_vec()],
        BTreeMap::new(),
    );
    assert_eq!(r.menu, ["Delete this", "Delete all"]);
    // nothing to show, then the code, which reads back as it was sent; one alone, so no squares
    assert!(shows(
        &r.frames[0],
        (WIDTH as i32 - Canvas::text_width("Nothing to show", Style::Bold)) / 2,
        14,
        "Nothing to show",
        Style::Bold
    ));
    assert_eq!(read_qr(&r.frames[0]), None);
    assert_eq!(read_qr(&r.frames[1]).as_deref(), Some(link));
    assert_eq!(which(&r.frames[1]), (0, None));
    // as big as fits, in the middle: two pixels a module or more
    let (l, t, rt, b) = lit_box(&r.frames[1]);
    assert!((l + rt - (WIDTH as i32 - 1)).abs() <= 1 && (t + b - (HEIGHT as i32 - 1)).abs() <= 1, "centred");
    // version 3: 29 modules and two of quiet zone each side, three pixels each
    assert_eq!((rt - l + 1, b - t + 1), (3 * (29 + 4), 3 * (29 + 4)));
    // asked what it shows, it says
    assert_eq!(r.replies, [vec![SHOWN], [&[SHOWN][..], link.as_bytes()].concat()]);
    // the centre turns to the text, under where it's from
    assert!(page_shows(&r.frames[3], &wrapped(link)));
    assert_eq!(read_qr(&r.frames[3]), None);
    // kept, as it was sent, and shown again when it's opened
    assert_eq!(r.storage["kept"], [&(link.len() as u16).to_le_bytes()[..], link.as_bytes()].concat());
    let opened = run(&[Event::Centre, Event::Centre], &[], r.storage.clone());
    assert_eq!(opened.frames[0], r.frames[1]);
    assert_eq!((&opened.frames[1], &opened.frames[2]), (&r.frames[3], &r.frames[1]));
    // what phones join and pay: a network, an address; and text in other languages, which maki
    // writes as its bytes (that the qrcode crate alone would partly write in Kanji mode too)
    for text in [
        "WIFI:T:WPA;S:Caf\u{e9} Wi-Fi;P:correct horse battery staple;;",
        "bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq?amount=0.0007",
        "Gr\u{fc}\u{df}e aus K\u{f6}ln, 5 \u{20ac}",
        JAPANESE,
        "\u{391}\u{392}\u{393}\u{394}\u{395}\u{396}\u{397}\u{398}",
        "\u{2192}\u{2192}\u{2192} \u{2605}\u{2605}\u{2605}",
        "two\nlines",
    ] {
        let r = sent(&[text.as_bytes()]);
        assert_eq!(r.replies, [vec![SHOWN]], "{text}");
        assert_eq!(read_qr(&r.frames[1]).as_deref(), Some(text));
    }
}

fn lit_box(c: &Canvas) -> (i32, i32, i32, i32) {
    let lit: Vec<(i32, i32)> = (0..HEIGHT as i32)
        .flat_map(|y| (0..WIDTH as i32).map(move |x| (x, y)))
        .filter(|&(x, y)| c.get(x, y))
        .collect();
    let xs = || lit.iter().map(|p| p.0);
    let ys = || lit.iter().map(|p| p.1);
    (xs().min().unwrap(), ys().min().unwrap(), xs().max().unwrap(), ys().max().unwrap())
}

#[test]
fn showqr_keeps_the_last_five_newest_first_and_goes_through_them() {
    use Event::*;
    let texts: Vec<String> = (1..=6).map(|i| format!("https://example.com/{i}")).collect();
    let mut events = vec![Message; 6];
    // older, older, round to the newest, then the dial: newer (round to the oldest), older
    events.extend([Right, Right, Left, Left, Up, Down, Down]);
    let inbox: Vec<Vec<u8>> = texts.iter().map(|t| show(t.as_bytes())).collect();
    let r = run(&events, &inbox, BTreeMap::new());
    assert_eq!(r.replies, vec![vec![SHOWN]; 6]);
    // the sixth pushed the first out; each new one showed as it came
    let read = |i: usize| read_qr(&r.frames[i]);
    for (i, frame) in (1..=6).enumerate() {
        assert_eq!(read(frame).as_deref(), Some(texts[i].as_str()));
    }
    let at = |n: usize| Some(texts[n - 1].clone());
    let shown: Vec<Option<String>> = (7..=13).map(read).collect();
    assert_eq!(shown, [at(5), at(4), at(5), at(6), at(2), at(6), at(5)]);
    // a square for each kept down the left edge, this one's filled
    assert_eq!(which(&r.frames[6]), (5, Some(0)));
    assert_eq!(which(&r.frames[8]), (5, Some(2)));
    assert_eq!(which(&r.frames[11]), (5, Some(4)));
    assert_eq!(which(&r.frames[2]), (2, Some(0)));
    // kept newest first, each its length and then itself
    let mut kept = Vec::new();
    for t in texts[1..].iter().rev() {
        kept.extend((t.len() as u16).to_le_bytes());
        kept.extend(t.as_bytes());
    }
    assert_eq!(r.storage["kept"], kept);

    // the same again moves to the front, and isn't kept twice
    let again = run(&[Message, Right], &[show(texts[2].as_bytes())], r.storage.clone());
    assert_eq!(read_qr(&again.frames[1]).as_deref(), Some(texts[2].as_str()));
    assert_eq!(read_qr(&again.frames[2]).as_deref(), Some(texts[5].as_str()));
    assert_eq!(which(&again.frames[1]), (5, Some(0)));

    // the menu deletes the one showing, then all of them
    let deleted = run(&[Right, Menu(0), Menu(1)], &[], r.storage.clone());
    assert_eq!(read_qr(&deleted.frames[2]).as_deref(), Some(texts[3].as_str()));
    assert_eq!(which(&deleted.frames[2]), (4, Some(1)));
    assert_eq!(deleted.frames[3], run(&[], &[], BTreeMap::new()).frames[0]);
    assert!(!deleted.storage.contains_key("kept"));
    // the last one deleted is the one before it, showing
    let last = run(&[Left, Menu(0)], &[], r.storage.clone());
    assert_eq!(read_qr(&last.frames[2]).as_deref(), Some(texts[2].as_str()));
}

#[test]
fn showqr_shows_the_text_a_page_at_a_time_the_dial_scrolling_it() {
    use Event::*;
    let words = "the quick brown fox jumps over the lazy dog and keeps on running far past the farm and the river \
                 until night falls and the stars come out";
    let lines = wrapped(words);
    assert!((4..=8).contains(&lines.len()), "{lines:?}");
    let r = run(&[Message, Centre, Down, Right], &[show(words.as_bytes())], BTreeMap::new());
    assert!(page_shows(&r.frames[2], &lines));
    // all of it on a page: the dial has nowhere to go, nor have left and right with one kept
    assert_eq!((&r.frames[3], &r.frames[4]), (&r.frames[2], &r.frames[2]));
    // more lines than a page: the dial scrolls, as far as the last line and no further
    let many: Vec<String> = (1..=12).map(|i| format!("line {i}")).collect();
    let mut events = vec![Message, Centre, Down, Down, Up];
    events.extend([Down; 6]);
    let r = run(&events, &[show(many.join("\n").as_bytes())], BTreeMap::new());
    assert!(page_shows(&r.frames[2], &many));
    assert!(page_shows(&r.frames[3], &many[1..]) && page_shows(&r.frames[4], &many[2..]));
    assert!(page_shows(&r.frames[5], &many[1..]));
    assert!(page_shows(&r.frames[8], &many[4..]));
    assert_eq!(
        r.frames[8..],
        [r.frames[8].clone(), r.frames[8].clone(), r.frames[8].clone(), r.frames[8].clone()]
    );
    // marks at the right say there's more above, or below
    let marks =
        |c: &Canvas, y0: i32| (y0..y0 + 3).any(|y| (WIDTH as i32 - 6..WIDTH as i32).any(|x| c.get(x, y)));
    assert!(!marks(&r.frames[2], 16) && marks(&r.frames[2], 103));
    assert!(marks(&r.frames[3], 16) && marks(&r.frames[3], 103));
    assert!(marks(&r.frames[8], 16) && !marks(&r.frames[8], 103));

    // a line of its own for each new line, a blank one for an empty line; a word too long for a
    // line broken where it must be
    let r = run(&[Message, Centre], &[show(b"first\n\nthird")], BTreeMap::new());
    assert!(page_shows(&r.frames[2], &["first".into(), String::new(), "third".into()]));
    let long = "x".repeat(60);
    let r = run(&[Message, Centre], &[show(long.as_bytes())], BTreeMap::new());
    let lines = wrapped(&long);
    assert!(lines.len() > 1 && page_shows(&r.frames[2], &lines), "{lines:?}");

    // which it is, at the top right, when more are kept
    let r = run(&[Message, Message, Centre, Right], &[show(b"one"), show(b"two")], BTreeMap::new());
    let x = WIDTH as i32 - 2 - Canvas::text_width("1/2", Style::Small);
    assert!(shows(&r.frames[3], x, 0, "1/2", Style::Small) && page_shows(&r.frames[3], &["two".into()]));
    let x = WIDTH as i32 - 2 - Canvas::text_width("2/2", Style::Small);
    assert!(shows(&r.frames[4], x, 0, "2/2", Style::Small) && page_shows(&r.frames[4], &["one".into()]));
}

#[test]
fn showqr_refuses_what_it_cannot_show_saying_why_and_keeps_what_it_had() {
    let digits = |n: usize| "7".repeat(n).into_bytes();
    let cases: Vec<(Vec<u8>, u8)> = vec![
        // as much as a version 8 code holds, two pixels a module on maki's screen, and no more
        (b"a".repeat(192), SHOWN),
        (b"a".repeat(193), TOO_LONG),
        (b"A".repeat(279), SHOWN),
        (b"A".repeat(280), TOO_LONG),
        (digits(461), SHOWN),
        (digits(462), TOO_LONG),
        (digits(600), TOO_LONG),
        // not text it shows
        (Vec::new(), NOT_TEXT),
        (b"   \n ".to_vec(), NOT_TEXT),
        (b"\xff\xfe".to_vec(), NOT_TEXT),
        (b"tab\there".to_vec(), NOT_TEXT),
        (b"windows\r\nline".to_vec(), NOT_TEXT),
        (b"bell\x07".to_vec(), NOT_TEXT),
    ];
    let mut inbox: Vec<Vec<u8>> = vec![show(b"kept")];
    inbox.extend(cases.iter().map(|(t, _)| show(t)));
    // what isn't a message of its own
    for m in [&b""[..], b"X", b"??", b"s"] {
        inbox.push(m.to_vec());
    }
    inbox.push(b"?".to_vec());
    let r = run(&vec![Event::Message; inbox.len()], &inbox, BTreeMap::new());
    let want: Vec<Vec<u8>> = std::iter::once(vec![SHOWN])
        .chain(cases.iter().map(|&(_, c)| vec![c]))
        .chain(std::iter::repeat_n(vec![UNKNOWN], 4))
        .chain(std::iter::once([&[SHOWN][..], &b"7".repeat(461)].concat()))
        .collect();
    assert_eq!(r.replies.len(), want.len());
    for (i, (got, want)) in r.replies.iter().zip(&want).enumerate() {
        assert_eq!(got, want, "message {i}");
    }

    // a refusal says why on maki until the next press, and changes nothing else
    let r = run(
        &[Event::Message, Event::Message, Event::Timeout],
        &[show(b"kept"), show(&b"a".repeat(300))],
        BTreeMap::new(),
    );
    assert_ne!(r.frames[2], r.frames[1]);
    assert!(shows(
        &r.frames[2],
        (WIDTH as i32 - Canvas::text_width("too long for a QR code", Style::Small)) / 2,
        48,
        "too long for a QR code",
        Style::Small
    ));
    assert_eq!(r.frames[3], r.frames[1]);
    assert_eq!(r.storage["kept"], b"\x04\0kept");

    // what was kept before is read as this version keeps it: whole, readable, five at most
    let mut kept = Vec::new();
    for t in [&b"ok"[..], b"tab\there", b"\xff", b"two", b"3", b"4", b"5", b"6"] {
        kept.extend((t.len() as u16).to_le_bytes());
        kept.extend(t);
    }
    kept.extend([9, 0, b'c', b'u', b't']);
    let r = run(&[Event::Message], &[b"?".to_vec()], BTreeMap::from([("kept".to_string(), kept)]));
    assert_eq!(r.replies, [b"\0ok".to_vec()]);
    assert_eq!(read_qr(&r.frames[0]).as_deref(), Some("ok"));
    assert_eq!(which(&r.frames[0]), (5, Some(0)));
    let r = run(&[], &[], BTreeMap::from([("kept".to_string(), vec![200, 0, b'x'])]));
    assert_eq!(r.frames[0], run(&[], &[], BTreeMap::new()).frames[0]);
}

/// Texts and the version of the QR code maki draws for each (`None`: past 8, too long for maki's
/// screen): maki desktop's `src/shared/showqr.test.ts` has the same, which it works out before it
/// sends, and says on its Connections page.
fn versions() -> Vec<(String, Option<i32>)> {
    vec![
        ("https://maki.netslum.io".into(), Some(2)),
        ("https://maki.netslum.io/docs/confirm".into(), Some(3)),
        ("WIFI:T:WPA;S:Caf\u{e9} Wi-Fi;P:correct horse battery staple;;".into(), Some(4)),
        ("HTTPS://MAKI.NETSLUM.IO/DOCS/".into(), Some(2)),
        ("bitcoin:BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ?amount=0.0007".into(), Some(4)),
        (format!("x{}", "7".repeat(220)), Some(5)),
        (JAPANESE.into(), Some(4)),
        ("\u{391}\u{392}\u{393}\u{394}\u{395}\u{396}\u{397}\u{398}".into(), Some(1)),
        ("\u{2192}\u{2192}\u{2192} \u{2605}\u{2605}\u{2605}".into(), Some(2)),
        ("a".repeat(192), Some(8)),
        ("a".repeat(193), None),
        ("A".repeat(279), Some(8)),
        ("A".repeat(280), None),
        ("7".repeat(461), Some(8)),
        ("7".repeat(462), None),
        (format!("{}{}", "\u{3042}".repeat(60), "x".repeat(12)), Some(8)),
        (format!("{}{}", "\u{3042}".repeat(60), "x".repeat(13)), None),
        (format!("ORDER {} PAID", "1234567890".repeat(20)), Some(5)),
        // ā ends in a byte Shift JIS starts a pair with: the first capital after it goes in that pair
        (format!("{}{}", "\u{101}".repeat(40), "B".repeat(30)), Some(5)),
        (format!("{}{}", "\u{101}".repeat(40), "b".repeat(30)), Some(6)),
    ]
}

#[test]
fn showqr_draws_each_text_at_the_version_maki_desktop_works_out() {
    // the side of a version's code, as big as it fits maki's 110 pixels: 17 + 4v modules, and two
    // of quiet zone each side, as many pixels each as fit
    let version_of = |side: i32| {
        (1..=40).find(|&v: &i32| {
            let m = 17 + 4 * v + 4;
            m <= HEIGHT as i32 && m * (HEIGHT as i32 / m) == side
        })
    };
    for (text, version) in versions() {
        let r = sent(&[text.as_bytes()]);
        match version {
            Some(v) => {
                assert_eq!(r.replies, [vec![SHOWN]], "{text}");
                let (l, _, rt, _) = lit_box(&r.frames[1]);
                assert_eq!(version_of(rt - l + 1), Some(v), "{text}");
                assert_eq!(read_qr(&r.frames[1]).as_deref(), Some(text.as_str()));
            }
            None => assert_eq!(r.replies, [vec![TOO_LONG]], "{text}"),
        }
    }
}

#[test]
fn showqr_shows_any_text_it_takes_and_it_reads_back_as_it_was_sent() {
    // texts in many scripts, made the same way each time: pieces chosen by a counter
    let pieces = [
        "hello ",
        "Wi-Fi",
        "1234567",
        "ABC-123 ",
        "https://",
        ".com/",
        "\u{65e5}\u{672c}\u{8a9e}",
        "\u{306e}\u{30c6}\u{30ad}\u{30b9}\u{30c8}",
        "\u{3053}\u{308c}\u{306f}\u{9577}\u{3044}",
        "\u{4e2d}\u{6587}\u{6d4b}\u{8bd5}",
        "\u{d55c}\u{ad6d}\u{c5b4}",
        "\u{41f}\u{420}\u{418}\u{412}\u{415}\u{422} ",
        "\u{43f}\u{440}\u{438}\u{432}\u{435}\u{442} ",
        "\u{391}\u{392}\u{393}\u{394}\u{395}",
        "\u{3b1}\u{3b2}\u{3b3}",
        "\u{1f600}",
        "\u{20ac}",
        "\u{201c}q\u{201d}",
        "\u{2026}",
        "\u{df}",
        "\u{101}",
        "\u{101}B",
        "\u{e9}",
        "\u{2192}\u{2605}",
        " ",
        "\n",
        "x",
    ];
    let mut seed: u64 = 1;
    let mut next = |n: usize| {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((seed >> 33) as usize) % n
    };
    // up to nine pieces of 15 bytes at most: 135 bytes, which any version 8 code holds; each with
    // something besides spaces
    let mut texts: Vec<String> = Vec::new();
    for _ in 0..600 {
        let count = 1 + next(9);
        let text: String = (0..count).map(|_| pieces[next(pieces.len())]).collect();
        texts.push(if text.trim().is_empty() { format!("{text}x") } else { text });
    }
    // plenty that the qrcode crate alone would write partly in Kanji mode, which phones misread
    let kanji = |t: &str| {
        use qrcode::optimize::{Optimizer, Parser};
        use qrcode::types::{Mode, Version};
        Optimizer::new(Parser::new(t.as_bytes()), Version::Normal(9)).any(|s| s.mode == Mode::Kanji)
    };
    assert!(texts.iter().filter(|t| kanji(t)).count() >= 100);
    let inbox: Vec<Vec<u8>> = texts.iter().map(|t| show(t.as_bytes())).collect();
    let r = run(&vec![Event::Message; inbox.len()], &inbox, BTreeMap::new());
    for (i, text) in texts.iter().enumerate() {
        assert_eq!(r.replies[i], [SHOWN], "{text:?}");
        // the code each was shown as, read as maki's camera reads one
        assert_eq!(read_qr(&r.frames[i + 1]).as_deref(), Some(text.as_str()), "{text:?}");
    }
}
