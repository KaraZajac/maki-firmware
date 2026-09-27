//! `maki.toml`, as developers write it, into the manifest bundles carry.

use std::collections::BTreeMap;
use std::path::Path;

use maki_bundle::{Kind, Manifest, Permission};
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
}

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
    let manifest = Manifest {
        id: t.id,
        name: t.name,
        version: t.version,
        label: t.label,
        kind,
        api: if kind == Kind::Wasm { t.api.unwrap_or(maki_wasm::API_VERSION) } else { 0 },
        // a native app is built for the firmware whose app service the SDK speaks
        firmware: if kind == Kind::Native && t.firmware.is_empty() { maki_native::service::FIRMWARE.into() } else { t.firmware },
        permissions,
        storage_kib: t.storage,
        memory_kib: t.memory,
        backup: t.backup,
        description: t.description,
    };
    let icon = t.icon.map(|i| path.parent().unwrap_or(Path::new(".")).join(i));
    Ok(Project { manifest, icon })
}
