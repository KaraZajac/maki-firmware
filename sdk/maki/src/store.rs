//! `maki store`: the maki store's side (ARCHITECTURE.md, "The store"). Root keys are made and
//! used offline, on a computer that stays offline, and sign roots only; the catalogue key signs
//! stamps and revocation lists, and expires within a year. maki checks everything these make
//! against the root its firmware carries, or a newer one that root's keys signed.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use maki_bundle::DeveloperKey as Key;
use maki_store::{Revocations, Revoked, Root, SignedRevocations, SignedRoot, SignedStamp, Stamp};
use sha2::{Digest, Sha256};

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn unhex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// A store key's file: its secret, in hex, as `maki keygen` writes a developer key.
pub fn load(path: &str) -> Result<Key, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    unhex32(&text).map(|s| Key::from_bytes(&s)).ok_or_else(|| format!("{path}: not a key"))
}

/// A public key: 64 hex digits, or a key file's.
pub fn public(spec: &str) -> Result<[u8; 32], String> {
    match unhex32(spec) {
        Some(k) => Ok(k),
        None => Ok(load(spec)?.verifying_key().to_bytes()),
    }
}

fn write_key(path: &str, seed: &[u8; 32]) -> Result<(), String> {
    if Path::new(path).exists() {
        return Err(format!("{path} exists: a store key is never replaced by accident"));
    }
    crate::key::write_private(Path::new(path), format!("{}\n", hex(seed)).as_bytes())
        .map_err(|e| format!("{path}: {e}"))?;
    println!("{path}: public key {}", hex(Key::from_bytes(seed).verifying_key().as_bytes()));
    Ok(())
}

/// A new store key, and its 24 words (BIP39) for paper: `recover` makes the key again from them.
pub fn keygen(path: &str) -> Result<(), String> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("no randomness: {e}"))?;
    write_key(path, &seed)?;
    println!("\nIts 24 words, to keep on paper (`maki store recover` makes the key again from them):\n");
    for (row, words) in maki_seed::to_words(&seed).chunks(4).enumerate() {
        let line: Vec<String> =
            words.iter().enumerate().map(|(i, w)| format!("{:>2}. {w:<9}", row * 4 + i + 1)).collect();
        println!("  {}", line.join(" "));
    }
    Ok(())
}

/// A store key made again from its 24 words, read from standard input.
pub fn recover(path: &str) -> Result<(), String> {
    eprintln!("The key's 24 words, then enter:");
    let mut text = String::new();
    std::io::stdin().read_line(&mut text).map_err(|e| e.to_string())?;
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.len() != 24 {
        return Err(format!("{} words: a store key has 24", words.len()));
    }
    let entropy = maki_seed::to_entropy(&words).map_err(|e| match e {
        maki_seed::Error::UnknownWord(i) => format!("word {} isn't on the BIP39 list", i + 1),
        _ => "those words don't add up: one is wrong, or two are swapped".to_string(),
    })?;
    let seed: [u8; 32] = entropy.try_into().map_err(|_| "those words aren't a key".to_string())?;
    write_key(path, &seed)
}

/// A root, signed by `sign` (its own keys; to replace another root, that one's too).
#[allow(clippy::too_many_arguments)]
pub fn root(
    version: u32,
    threshold: u8,
    keys: Vec<[u8; 32]>,
    catalogue: [u8; 32],
    expires_days: u64,
    sign: &[Key],
    out: &str,
) -> Result<(), String> {
    let root = Root { version, threshold, keys, catalogue, catalogue_expires: now() + expires_days * 86400 };
    let signed = SignedRoot::sign(root, &sign.iter().collect::<Vec<_>>());
    signed.trust_first().map_err(|e| format!("this root wouldn't be trusted: {e}"))?;
    std::fs::write(out, signed.encode()).map_err(|e| format!("{out}: {e}"))?;
    println!(
        "{out}: root {version}, {} of {} keys, catalogue key {} for {expires_days} days",
        threshold,
        signed.root.keys.len(),
        hex(&catalogue)
    );
    Ok(())
}

/// The bundle with the store's stamp.
pub fn stamp(bundle: &str, catalogue: &Key, out: &str) -> Result<(), String> {
    let bytes = std::fs::read(bundle).map_err(|e| format!("{bundle}: {e}"))?;
    let b = maki_bundle::read(&bytes).map_err(|e| format!("{bundle}: {e}"))?;
    let stamp = SignedStamp::sign(Stamp::of(&b, now()), catalogue);
    let stamped = maki_bundle::with_stamp(&bytes, &stamp.encode()).map_err(|e| format!("{bundle}: {e}"))?;
    std::fs::write(out, stamped).map_err(|e| format!("{out}: {e}"))?;
    println!("{out}: {} {} stamped", b.manifest.id, b.manifest.version);
    Ok(())
}

/// A revocation list from a text file, a line an entry, with why after it:
///
/// ```text
/// app com.example.bad Steals TOTP codes.
/// up-to com.example.ssh 2 Signed without asking.
/// developer <64 hex digits> The developer's key was stolen.
/// ```
pub fn revoke(catalogue: &Key, version: u32, expires_days: u64, list: &str, out: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(list).map_err(|e| format!("{list}: {e}"))?;
    let mut entries = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bad = || format!("{list}:{}: app ID WHY, up-to ID VERSION WHY, or developer KEY WHY", n + 1);
        let mut words = line.splitn(2, ' ');
        let kind = words.next().unwrap_or("");
        let rest = words.next().ok_or_else(bad)?;
        let (what, why) = match kind {
            "app" => {
                let (id, why) = rest.split_once(' ').ok_or_else(bad)?;
                (Revoked::App(id.into()), why)
            }
            "up-to" => {
                let mut w = rest.splitn(3, ' ');
                let (id, v, why) =
                    (w.next().ok_or_else(bad)?, w.next().ok_or_else(bad)?, w.next().ok_or_else(bad)?);
                (Revoked::UpTo(id.into(), v.parse().map_err(|_| bad())?), why)
            }
            "developer" => {
                let (key, why) = rest.split_once(' ').ok_or_else(bad)?;
                (Revoked::Developer(unhex32(key).ok_or_else(bad)?), why)
            }
            _ => return Err(bad()),
        };
        entries.push((what, why.trim().to_string()));
    }
    let n = entries.len();
    let signed = SignedRevocations::sign(
        Revocations { version, expires: now() + expires_days * 86400, entries },
        catalogue,
    );
    std::fs::write(out, signed.encode()).map_err(|e| format!("{out}: {e}"))?;
    println!("{out}: revocation list {version}, {n} entries");
    Ok(())
}

/// What a root, a revocation list or a stamped bundle says.
pub fn show(path: &str) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    if let Ok(r) = SignedRoot::decode(&bytes) {
        let root = &r.root;
        println!("root {}: {} of these keys sign the next", root.version, root.threshold);
        for k in &root.keys {
            println!(
                "  {}{}",
                hex(k),
                if r.signatures.iter().any(|(s, _)| s == k) { " (signed this)" } else { "" }
            );
        }
        println!("catalogue key {} until {} (unix)", hex(&root.catalogue), root.catalogue_expires);
        match r.trust_first() {
            Ok(_) => println!("signed by enough of its own keys"),
            Err(e) => println!("not trusted on its own: {e}"),
        }
        return Ok(());
    }
    if let Ok(l) = SignedRevocations::decode(&bytes) {
        println!("revocation list {}, until {} (unix)", l.list.version, l.list.expires);
        for (what, why) in &l.list.entries {
            println!("  {what:?}: {why}");
        }
        return Ok(());
    }
    let b = maki_bundle::read(&bytes)
        .map_err(|e| format!("{path}: not a root, a revocation list or a bundle ({e})"))?;
    match b.stamp.map(SignedStamp::decode) {
        Some(Ok(s)) => println!(
            "{} {}: stamped at {} (unix); check it with a root on maki",
            s.stamp.id, s.stamp.version, s.stamp.issued
        ),
        Some(Err(e)) => println!("{}: a stamp maki can't read ({e})", b.manifest.id),
        None => println!("{}: sideloaded, no stamp", b.manifest.id),
    }
    Ok(())
}

/// The newest root of the store in `dir`: roots/1.bin, trusted on its own, then each next one
/// that replaces it, as maki desktop follows them.
pub fn latest_root(dir: &Path) -> Result<Root, String> {
    let read = |n: u32| -> Result<Option<SignedRoot>, String> {
        let path = dir.join("roots").join(format!("{n}.bin"));
        match std::fs::read(&path) {
            Ok(b) => SignedRoot::decode(&b).map(Some).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    };
    let first = read(1)?.ok_or_else(|| format!("{}: no roots/1.bin", dir.display()))?;
    let mut root = first.trust_first().map_err(|e| format!("roots/1.bin: {e}"))?.clone();
    if root.version != 1 {
        return Err(format!("roots/1.bin is root {}", root.version));
    }
    while let Some(next) = read(root.version + 1)? {
        let n = root.version + 1;
        let taken = next.replaces(&root).map_err(|e| format!("roots/{n}.bin: {e}"))?;
        if taken.version != n {
            return Err(format!("roots/{n}.bin is root {}", taken.version));
        }
        root = taken.clone();
    }
    Ok(root)
}

fn base64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() { A[(n >> (18 - 6 * i)) as usize & 63] as char } else { '=' });
        }
    }
    out
}

fn bundles(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        if path.is_dir() {
            bundles(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "maki") {
            out.push(path);
        }
    }
    Ok(())
}

/// What the store says about an app beside its bundles, in `apps/ID/app.toml`: where its source
/// is, which the store built it from before stamping it (`maki reproduce`), and its category.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct About {
    category: Option<String>,
    source: Option<Source>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    /// A Git repository, https.
    repo: String,
    /// The commit built, in full.
    commit: String,
    /// The app's directory in it, if it isn't the top.
    #[serde(default)]
    path: String,
}

fn about(dir: &Path, id: &str) -> Result<Option<About>, String> {
    let path = dir.join("apps").join(id).join("app.toml");
    let Ok(text) = std::fs::read_to_string(&path) else { return Ok(None) };
    let about: About = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Some(s) = &about.source {
        let hex = s.commit.len() == 40
            && s.commit.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
        if !s.repo.starts_with("https://")
            || !hex
            || s.path.starts_with('/')
            || s.path.split('/').any(|p| p == "..")
        {
            return Err(format!(
                "{}: a source is an https repository, a whole commit ID and a path in it",
                path.display()
            ));
        }
    }
    Ok(Some(about))
}

/// The newest of maki's firmware and of maki desktop, as maki desktop updates them: what the
/// store's `releases.toml` says, signed into the index (`--releases`), so maki desktop takes a
/// file only if it's what the store signed for.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Releases {
    firmware: Option<Release>,
    desktop: Option<Release>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Release {
    /// As the release is tagged: `preview-2026-10-01`, `0.1.2`.
    name: String,
    /// The commit it's built from, in full.
    commit: String,
    /// When it was made, YYYY-MM-DD.
    date: String,
    /// Where it's described, https.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    files: Vec<ReleaseFile>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseFile {
    name: String,
    /// What it runs on, for files that run (`linux-x86_64`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    platform: Option<String>,
    /// Where it's fetched from, https.
    url: String,
    bytes: u64,
    sha256: String,
}

/// The biggest file a release may have: maki desktop's AppImage is over a hundred megabytes.
const MAX_RELEASE_FILE: u64 = 512 * 1024 * 1024;

/// `releases.toml`, checked: every name plain, every address https, every hash whole, and
/// the firmware's three files exactly.
fn releases(path: &str) -> Result<serde_json::Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let r: Releases = toml::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    let plain = |s: &str| {
        !s.is_empty()
            && s.len() <= 64
            && !s.starts_with('.')
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    };
    let lower_hex = |s: &str, n: usize| {
        s.len() == n && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let check = |what: &str, rel: &Release| -> Result<(), String> {
        let bad = |why: &str| Err(format!("{path}: {what}: {why}"));
        if !plain(&rel.name) {
            return bad("its name is letters, digits, dots, dashes and underscores");
        }
        if !lower_hex(&rel.commit, 40) {
            return bad("its commit is a whole commit ID, 40 lowercase hex digits");
        }
        let d = rel.date.as_bytes();
        if !(d.len() == 10
            && d[4] == b'-'
            && d[7] == b'-'
            && rel.date.replace('-', "").bytes().all(|b| b.is_ascii_digit()))
        {
            return bad("its date is YYYY-MM-DD");
        }
        if rel.notes.as_ref().is_some_and(|n| !n.starts_with("https://")) {
            return bad("its notes are an https address");
        }
        if rel.files.is_empty() {
            return bad("it has no files");
        }
        for f in &rel.files {
            if !plain(&f.name) || f.platform.as_deref().is_some_and(|p| !plain(p)) {
                return bad(&format!("{}: a file's name and platform are plain words", f.name));
            }
            if !f.url.starts_with("https://") {
                return bad(&format!("{}: its address is https", f.name));
            }
            if f.bytes == 0 || f.bytes > MAX_RELEASE_FILE {
                return bad(&format!("{}: its size is 1 byte to 512 MiB", f.name));
            }
            if !lower_hex(&f.sha256, 64) {
                return bad(&format!("{}: its SHA-256 is 64 lowercase hex digits", f.name));
            }
        }
        Ok(())
    };
    let mut out = serde_json::Map::new();
    if let Some(fw) = &r.firmware {
        check("firmware", fw)?;
        let mut names: Vec<&str> = fw.files.iter().map(|f| f.name.as_str()).collect();
        names.sort();
        if names != ["loader.uf2", "swap.uf2", "xous.uf2"] {
            return Err(format!("{path}: firmware: its files are loader.uf2, xous.uf2 and swap.uf2"));
        }
        out.insert("firmware".into(), serde_json::to_value(fw).map_err(|e| e.to_string())?);
    }
    if let Some(desktop) = &r.desktop {
        check("desktop", desktop)?;
        out.insert("desktop".into(), serde_json::to_value(desktop).map_err(|e| e.to_string())?);
    }
    Ok(serde_json::Value::Object(out))
}

/// The store's index: its newest stamped bundle of each app under `dir`/apps, every stamp
/// checked against the store's newest root, signed by the catalogue key that root names. With
/// each, what its `app.toml` says, if it has one; and with `releases`, the newest firmware and
/// maki desktop (`releases.toml`).
pub fn index(
    dir: &Path,
    catalogue: &Key,
    version: Option<u32>,
    expires_days: u64,
    releases_file: Option<&str>,
) -> Result<(), String> {
    let releases = releases_file.map(releases).transpose()?;
    let root = latest_root(dir)?;
    if catalogue.verifying_key().to_bytes() != root.catalogue {
        return Err(format!(
            "that isn't the catalogue key root {} names ({})",
            root.version,
            hex(&root.catalogue)
        ));
    }
    let now = now();
    let mut found = Vec::new();
    let apps_dir = dir.join("apps");
    if apps_dir.exists() {
        bundles(&apps_dir, &mut found)?;
    }
    let mut newest: std::collections::BTreeMap<String, (u32, serde_json::Value)> = Default::default();
    for path in found {
        let shown = path.strip_prefix(dir).unwrap_or(&path).to_string_lossy().replace('\\', "/");
        let bytes = std::fs::read(&path).map_err(|e| format!("{shown}: {e}"))?;
        let b = maki_bundle::read(&bytes).map_err(|e| format!("{shown}: {e}"))?;
        let stamp = b.stamp.ok_or_else(|| format!("{shown}: not stamped"))?;
        SignedStamp::decode(stamp)
            .and_then(|s| s.check(&root, Some(now), &b))
            .map_err(|e| format!("{shown}: {e}"))?;
        let m = &b.manifest;
        if newest.get(&m.id).is_some_and(|(v, _)| *v >= m.version) {
            continue;
        }
        let icon = b.icon.map(|i| base64(&i.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<_>>()));
        let about = about(dir, &m.id)?;
        let mut entry = serde_json::json!({
            "id": m.id,
            "name": m.name,
            "kind": if m.kind == maki_bundle::Kind::Native { "native" } else { "wasm" },
            "version": m.version,
            "label": m.label,
            "description": m.description,
            "developer": hex(&b.developer),
            "permissions": m.permissions.iter().map(|(p, why)| serde_json::json!({ "name": p.name(), "reason": why })).collect::<Vec<_>>(),
            "storage_kib": m.storage_kib,
            "memory_kib": m.memory_kib,
            "backup": m.backup,
            "bytes": bytes.len(),
            "sha256": hex(&Sha256::digest(&bytes)),
            "path": shown,
            "icon": icon,
        });
        if let Some(about) = about {
            if let Some(category) = about.category {
                entry["category"] = category.into();
            }
            if let Some(s) = about.source {
                entry["source"] = serde_json::json!({ "repo": s.repo, "commit": s.commit, "path": s.path });
            }
        }
        newest.insert(m.id.clone(), (m.version, entry));
    }
    let index_path = dir.join("index.json");
    let version = match version {
        Some(v) => v,
        None => std::fs::read(&index_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v["version"].as_u64())
            .map(|v| v as u32 + 1)
            .unwrap_or(1),
    };
    let n = newest.len();
    let mut index = serde_json::json!({
        "format": 1,
        "version": version,
        "expires": now + expires_days * 86400,
        "root": root.version,
        "apps": newest.into_values().map(|(_, e)| e).collect::<Vec<_>>(),
    });
    if let Some(releases) = releases {
        index["releases"] = releases;
    }
    let mut text = serde_json::to_string_pretty(&index).map_err(|e| e.to_string())?;
    text.push('\n');
    let signature = maki_store::sign_index(text.as_bytes(), catalogue);
    std::fs::write(&index_path, &text).map_err(|e| format!("{}: {e}", index_path.display()))?;
    let sig_path = dir.join("index.sig");
    std::fs::write(&sig_path, signature).map_err(|e| format!("{}: {e}", sig_path.display()))?;
    println!("{}: index {version}, {n} apps, for {expires_days} days", index_path.display());
    Ok(())
}

/// Stamps a bundle into the store in `dir` (apps/ID/VERSION.maki), then signs a new index.
pub fn add(dir: &Path, bundle: &str, catalogue: &Key, expires_days: u64) -> Result<(), String> {
    let bytes = std::fs::read(bundle).map_err(|e| format!("{bundle}: {e}"))?;
    let b = maki_bundle::read(&bytes).map_err(|e| format!("{bundle}: {e}"))?;
    let app_dir = dir.join("apps").join(&b.manifest.id);
    std::fs::create_dir_all(&app_dir).map_err(|e| format!("{}: {e}", app_dir.display()))?;
    let out = app_dir.join(format!("{}.maki", b.manifest.version));
    stamp(bundle, catalogue, &out.to_string_lossy())?;
    index(dir, catalogue, None, expires_days, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "url = \"https://example.com/f\"\nbytes = 10\nsha256 = \"\
                        0000000000000000000000000000000000000000000000000000000000000000\"\n";

    fn firmware(names: &[&str]) -> String {
        let mut t = String::from(
            "[firmware]\nname = \"preview-2026-10-01\"\ncommit = \"0123456789abcdef0123456789abcdef01234567\"\n\
             date = \"2026-10-01\"\n",
        );
        for n in names {
            t.push_str(&format!("[[firmware.files]]\nname = \"{n}\"\n{FILE}"));
        }
        t
    }

    fn parsed(text: &str) -> Result<serde_json::Value, String> {
        let dir = std::env::temp_dir().join(format!("maki-releases-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{:x}.toml", Sha256::digest(text.as_bytes())[0]));
        std::fs::write(&path, text).unwrap();
        releases(path.to_str().unwrap())
    }

    #[test]
    fn firmware_is_its_three_files() {
        let r = parsed(&firmware(&["loader.uf2", "xous.uf2", "swap.uf2"])).unwrap();
        assert_eq!(r["firmware"]["name"], "preview-2026-10-01");
        assert_eq!(r["firmware"]["files"].as_array().unwrap().len(), 3);
        assert!(r.get("desktop").is_none());
        assert!(parsed(&firmware(&["loader.uf2", "xous.uf2"])).is_err());
        assert!(parsed(&firmware(&["loader.uf2", "xous.uf2", "swap.uf2", "extra.uf2"])).is_err());
    }

    #[test]
    fn names_addresses_and_hashes_are_checked() {
        let good = firmware(&["loader.uf2", "xous.uf2", "swap.uf2"]);
        assert!(parsed(&good.replace("https://example.com/f", "http://example.com/f")).is_err());
        assert!(parsed(&good.replace("bytes = 10", "bytes = 0")).is_err());
        assert!(parsed(&good.replace("\"0000000000", "\"ABCDEF0000")).is_err());
        assert!(parsed(&good.replace("preview-2026-10-01\"", "../up\"")).is_err());
        assert!(parsed(&good.replace("2026-10-01\"\n", "1 Oct\"\n")).is_err());
        assert!(parsed(&good.replace("0123456789abcdef0123456789abcdef01234567", "0123456")).is_err());
        assert!(parsed(&format!("{good}surprise = 1\n")).is_err(), "nothing unknown");
    }

    #[test]
    fn desktop_files_say_what_they_run_on() {
        let text = format!(
            "[desktop]\nname = \"0.1.2\"\ncommit = \"0123456789abcdef0123456789abcdef01234567\"\n\
             date = \"2026-10-01\"\n[[desktop.files]]\nname = \"maki-desktop-0.1.2-x86_64.AppImage\"\n\
             platform = \"linux-x86_64\"\n{FILE}"
        );
        let r = parsed(&text).unwrap();
        assert_eq!(r["desktop"]["files"][0]["platform"], "linux-x86_64");
        assert!(parsed(&text.replace("linux-x86_64", "linux x86")).is_err());
    }
}
