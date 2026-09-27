//! The developer's key: made once, kept on this computer, used to sign every bundle. Updates
//! to an app must be signed with the key that signed it first, so keep it safe and backed up.

use std::path::PathBuf;

use maki_bundle::DeveloperKey;

/// `--key`, else `$MAKI_KEY`, else `$XDG_CONFIG_HOME/maki/developer.key` (or `~/.config/...`).
pub fn path(flag: Option<&str>) -> Result<PathBuf, String> {
    if let Some(p) = flag {
        return Ok(PathBuf::from(p));
    }
    if let Ok(p) = std::env::var("MAKI_KEY") {
        return Ok(PathBuf::from(p));
    }
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok_or("no home directory: use --key")?;
    Ok(config.join("maki").join("developer.key"))
}

pub fn load(flag: Option<&str>) -> Result<DeveloperKey, String> {
    let path = path(flag)?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("{}: {e}\nmake a developer key first: maki keygen", path.display()))?;
    let hex = text.trim();
    if hex.len() != 64 {
        return Err(format!("{}: not a developer key", path.display()));
    }
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| format!("{}: not a developer key", path.display()))?;
    }
    Ok(DeveloperKey::from_bytes(&seed))
}

pub fn generate(flag: Option<&str>, force: bool) -> Result<(PathBuf, DeveloperKey), String> {
    let path = path(flag)?;
    if path.exists() && !force {
        return Err(format!(
            "{} exists: that's your developer key, and apps signed with it can only be updated with it.\n\
             Pass --force to replace it anyway.",
            path.display()
        ));
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("no randomness: {e}"))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    write_private(&path, format!("{hex}\n").as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((path, DeveloperKey::from_bytes(&seed)))
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    f.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> { std::fs::write(path, bytes) }
