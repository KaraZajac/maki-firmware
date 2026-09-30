//! `maki.toml`, as developers write it, into the manifest bundles carry.

use std::collections::BTreeMap;
use std::path::Path;

use maki_bundle::{Curve, Kind, Manifest, Permission, Wallet};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Toml {
    id: String,
    name: String,
    version: u32,
    #[serde(default)]
    label: String,
    #[serde(default = "wasm")]
    kind: String,
    #[serde(default)]
    api: Option<u16>,
    #[serde(default)]
    firmware: String,
    /// KiB
    #[serde(default)]
    storage: u32,
    /// KiB
    #[serde(default = "memory")]
    memory: u32,
    #[serde(default = "yes")]
    backup: bool,
    #[serde(default)]
    description: String,
    /// The icon, relative to maki.toml: a 64x64 PNG or PBM.
    #[serde(default)]
    icon: Option<String>,
    /// What it asks for: `keys = "why it needs them"`.
    #[serde(default)]
    permissions: BTreeMap<String, String>,
    /// With the wallet permission: `[wallet] paths = ["m/84'/0'"]`.
    #[serde(default)]
    wallet: Option<WalletToml>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletToml {
    #[serde(default = "secp256k1")]
    curve: String,
    paths: Vec<String>,
}

fn secp256k1() -> String { "secp256k1".into() }

fn wasm() -> String { "wasm".into() }
fn memory() -> u32 { 64 }
fn yes() -> bool { true }

pub struct Project {
    pub manifest: Manifest,
    pub icon: Option<std::path::PathBuf>,
}

pub fn load(path: &Path) -> Result<Project, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let t: Toml = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let kind = match t.kind.as_str() {
        "wasm" => Kind::Wasm,
        "native" => Kind::Native,
        other => return Err(format!("kind \"{other}\": wasm or native")),
    };
    let mut permissions = Vec::new();
    for (name, reason) in &t.permissions {
        let p = Permission::from_name(name).ok_or_else(|| {
            let known: Vec<&str> = Permission::ALL.iter().map(|p| p.name()).collect();
            format!("no permission \"{name}\"; there are {}", known.join(", "))
        })?;
        permissions.push((p, reason.clone()));
    }
    permissions.sort_by_key(|(p, _)| *p);
    // what maki would refuse, said here, in the words of maki.toml
    let long = |what: String, text: &str, max: usize| {
        if text.len() > max {
            Err(format!("{}: {what} is {} bytes; {max} at most", path.display(), text.len()))
        } else if text.chars().any(|c| c.is_control()) {
            Err(format!("{}: {what} has a control character (a line break, say) in it", path.display()))
        } else {
            Ok(())
        }
    };
    long("id".into(), &t.id, maki_bundle::MAX_ID)?;
    long("name".into(), &t.name, maki_bundle::MAX_NAME)?;
    long("label".into(), &t.label, maki_bundle::MAX_LABEL)?;
    long("description".into(), &t.description, maki_bundle::MAX_DESCRIPTION)?;
    for (p, reason) in &permissions {
        long(format!("the reason for {}", p.name()), reason, maki_bundle::MAX_REASON)?;
    }
    let wallet = match (t.wallet, permissions.iter().any(|(p, _)| *p == Permission::Wallet)) {
        (None, false) => None,
        (None, true) => {
            return Err(format!(
                "{}: the wallet permission names its paths: [wallet] paths = [\"m/84'/0'\"]",
                path.display()
            ));
        }
        (Some(_), false) => {
            return Err(format!("{}: [wallet] needs the wallet permission too", path.display()));
        }
        (Some(w), true) => Some(wallet(path, w)?),
    };
    let manifest = Manifest {
        id: t.id,
        name: t.name,
        version: t.version,
        label: t.label,
        kind,
        api: if kind == Kind::Wasm { t.api.unwrap_or(maki_wasm::API_VERSION) } else { 0 },
        // a native app is built for the firmware whose app service the SDK speaks
        firmware: if kind == Kind::Native && t.firmware.is_empty() {
            maki_native::service::FIRMWARE.into()
        } else {
            t.firmware
        },
        permissions,
        storage_kib: t.storage,
        memory_kib: t.memory,
        backup: t.backup,
        description: t.description,
        wallet,
    };
    let icon = t.icon.map(|i| path.parent().unwrap_or(Path::new(".")).join(i));
    Ok(Project { manifest, icon })
}

/// `[wallet]`, checked as maki checks it, and said in maki.toml's words.
fn wallet(path: &Path, w: WalletToml) -> Result<Wallet, String> {
    let curve = match w.curve.as_str() {
        "secp256k1" => Curve::Secp256k1,
        "ed25519" => Curve::Ed25519,
        other => {
            return Err(format!(
                "{}: [wallet] curve \"{other}\": maki's wallets are secp256k1 or ed25519",
                path.display()
            ));
        }
    };
    if w.paths.is_empty() || w.paths.len() > maki_bundle::MAX_WALLET_PATHS {
        return Err(format!(
            "{}: [wallet] names 1 to {} paths",
            path.display(),
            maki_bundle::MAX_WALLET_PATHS
        ));
    }
    let mut paths: Vec<Vec<u32>> = Vec::new();
    for text in &w.paths {
        let p = maki_hd::parse_path(text)
            .ok_or_else(|| format!("{}: [wallet] \"{text}\" isn't a path (m/84'/0', say)", path.display()))?;
        if !maki_hd::prefix_ok(&p) {
            return Err(format!(
                "{}: [wallet] \"{text}\": a wallet's path is a purpose and a coin type at least, both hardened (m/84'/0'), so no app gets every coin's keys",
                path.display()
            ));
        }
        if paths.contains(&p) {
            return Err(format!("{}: [wallet] names \"{text}\" twice", path.display()));
        }
        paths.push(p);
    }
    Ok(Wallet { curve, paths })
}
