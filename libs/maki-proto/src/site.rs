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
    let host = s.split(|c| c == '/' || c == ':' || c == '?' || c == '#').next().unwrap_or("");
    host.strip_prefix("www.").unwrap_or(host).to_string()
}

/// Does an entry saved for `saved` cover a request from `requested`? The same host, or a
/// subdomain of it: an entry for github.com serves gist.github.com, never evilgithub.com.
pub fn covers(saved: &str, requested: &str) -> bool {
    let saved = normalize(saved);
    !saved.is_empty() && (requested == saved || requested.ends_with(&format!(".{saved}")))
}
