//! Sites, as maki shows and matches them.
//!
//! maki puts the site on its screen and asks the owner to approve, so what it shows must mean what
//! it says. Only plain ASCII hostnames are accepted: an international domain arrives as punycode
//! (`xn--...`) and is shown that way, never as Unicode that could imitate another site.

/// A hostname maki is willing to display: lowercase ASCII letters, digits, dots and hyphens.
pub fn valid(site: &str) -> bool {
    !site.is_empty()
        && site.len() <= 253
        && site.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !site.starts_with('.')
        && !site.ends_with('.')
        && !site.contains("..")
}

/// The site a saved entry is for. Entries may hold a full URL ("https://www.github.com/login");
/// reduce it to the hostname, without "www.".
pub fn normalize(saved: &str) -> String {
    let s = saved.trim().to_ascii_lowercase();
    let s = s.split_once("://").map(|(_, rest)| rest.to_string()).unwrap_or(s);
    let host = s.split(['/', ':', '?', '#']).next().unwrap_or("");
    host.strip_prefix("www.").unwrap_or(host).to_string()
}

/// Does an entry saved for `saved` cover a request from `requested`? The same host, or a
/// subdomain of it: an entry for github.com serves gist.github.com, never evilgithub.com. An
/// entry that doesn't name a host with a dot in it ("GitHub", "bank") covers nothing: it would
/// otherwise match whole top-level domains.
pub fn covers(saved: &str, requested: &str) -> bool {
    let saved = normalize(saved);
    valid(&saved) && saved.contains('.') && (requested == saved || requested.ends_with(&format!(".{saved}")))
}

/// A site as maki's screen shows it: in lines of at most `width` characters, broken after dots
/// where possible, at most `max_lines` of them. When it can't all fit, the start is cut and
/// marked with '…'. The end ("github.com") is what says whose site it is, so the end is what
/// always shows.
pub fn lines(site: &str, width: usize, max_lines: usize) -> Vec<String> {
    let width = width.max(2);
    let room = width * max_lines.max(1);
    let chars: Vec<char> = site.chars().collect();
    let text: Vec<char> = if chars.len() > room {
        // cut where a label starts, if the cut lands on a dot: "…example" rather than "….example"
        let mut tail = &chars[chars.len() - (room - 1)..];
        if tail.first() == Some(&'.') {
            tail = &tail[1..];
        }
        core::iter::once('…').chain(tail.iter().copied()).collect()
    } else {
        chars
    };
    let mut out: Vec<String> = Vec::new();
    let mut rest: &[char] = &text;
    while rest.len() > width {
        // after the last dot that fits, unless that would leave the line mostly empty
        let cut = match rest[..width].iter().rposition(|&c| c == '.') {
            Some(dot) if dot + 1 >= width / 2 => dot + 1,
            _ => width,
        };
        out.push(rest[..cut].iter().collect());
        rest = &rest[cut..];
    }
    out.push(rest.iter().collect());
    if out.len() > max_lines.max(1) {
        // breaking at dots cost lines it didn't have: break evenly instead
        out = text.chunks(width).map(|c| c.iter().collect()).collect();
    }
    out
}
