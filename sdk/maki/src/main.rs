//! `maki`: make apps for maki.
//!
//! ```text
//! maki keygen                  make your developer key, once
//! maki new DIR                 start an app
//! maki build [DIR]             build the app in DIR (cargo, wasm32), then pack and sign it
//! maki pack                    pack and sign maki.toml's app from a .wasm you built
//! maki inspect APP.maki        what a bundle holds, and whether maki would run it
//! maki run APP.maki            try it: in the terminal, or scripted with --press
//! maki install APP.maki        install it on maki, through maki desktop
//! ```

mod icon;
mod key;
mod store;
mod manifest;
mod sim;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use maki_bundle::{fingerprint, Kind};
use maki_wasm::Stop;
use sha2::{Digest, Sha256};

const USAGE: &str = "\
maki: make apps for maki

  maki keygen [--key FILE] [--force]
      Make your developer key. Every bundle you make is signed with it, and updates to an app
      must be signed with the key that signed it first: keep it safe and backed up.
  maki new DIR [--id ID] [--name NAME]
      Start an app in DIR: its Cargo.toml (using this SDK), maki.toml and a first screen.
  maki build [DIR] [--key FILE] [-o OUT]
      Build the app in DIR (default .) for wasm32 with cargo, then pack and sign it.
  maki pack [--manifest maki.toml] --code APP.wasm [--icon FILE] [--key FILE] [-o OUT]
      Pack and sign an app you built yourself.
  maki inspect APP.maki
      Show what a bundle holds and check it as maki would.
  maki reproduce APP.maki [DIR]
      Build the app in DIR (default .) from its source and check that the bundle is what it
      makes: its manifest, icon and code. The maki store does this before it stamps an app.
  maki store ...
      The maki store's side: its keys, roots, stamps, revocation lists and index (maki store
      for more).
  maki install APP.maki
      Install it on the maki plugged in, through maki desktop (which must be running): maki
      shows what it is and what it may do, and installs it if you say so there.
  maki run APP.maki [--press left,right*2,centre,menu:0,timeout,exit] [--shot OUT.png]
                    [--frames DIR] [--scale N] [--verified] [--storage FILE] [--motion X,Y,Z]
      Run it as maki would. Without --press, in this terminal: arrow keys, enter for the
      centre, m for the menu (left and right together), q to leave; y or n answers an ask,
      and a scan takes what you type. With --press, the presses in order, then Exit (yes or
      no answers an ask, msg:TEXT sends a message, qr:TEXT is the next scan, tilt:X;Y;Z moves
      the accelerometer); --shot saves the last frame, --frames every frame. Apps' keys come
      from the BIP39 test phrase, never anything real.

  The developer key is --key, else $MAKI_KEY, else ~/.config/maki/developer.key.";

struct Args {
    positional: Vec<String>,
    flags: Vec<(String, Option<String>)>,
}

impl Args {
    fn parse(argv: &[String]) -> Result<Args, String> {
        const VALUED: &[&str] = &[
            "--key", "-o", "--manifest", "--code", "--icon", "--press", "--shot", "--frames", "--scale", "--storage", "--id",
            "--name", "--motion", "--keys", "--threshold", "--catalogue", "--expires-days", "--sign", "--version", "--list",
        ];
        let mut positional = Vec::new();
        let mut flags = Vec::new();
        let mut it = argv.iter();
        while let Some(a) = it.next() {
            if VALUED.contains(&a.as_str()) {
                let v = it.next().ok_or_else(|| format!("{a} needs a value"))?;
                flags.push((a.clone(), Some(v.clone())));
            } else if a.starts_with('-') {
                flags.push((a.clone(), None));
            } else {
                positional.push(a.clone());
            }
        }
        Ok(Args { positional, flags })
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.flags.iter().rev().find(|(n, _)| n == name).and_then(|(_, v)| v.as_deref())
    }

    fn has(&self, name: &str) -> bool { self.flags.iter().any(|(n, _)| n == name) }

    fn only(&self, allowed: &[&str]) -> Result<(), String> {
        for (n, _) in &self.flags {
            if !allowed.contains(&n.as_str()) {
                return Err(format!("{n} isn't an option here"));
            }
        }
        Ok(())
    }
}

fn describe(stop: &Stop) -> String {
    match stop {
        Stop::Finished => "finished".into(),
        Stop::Exited => "stopped: it waited again after being told to exit".into(),
        Stop::NotResponding => "stopped: not responding (it worked too long without waiting)".into(),
        Stop::Aborted(why) | Stop::Failed(why) => format!("stopped: {why}"),
        Stop::Crashed(why) => format!("crashed: {why}"),
    }
}

/// Packs and signs, checking the code as maki will.
fn pack(manifest_path: &Path, code_path: &Path, icon_flag: Option<&str>, key_flag: Option<&str>, out: &Path) -> Result<(), String> {
    let project = manifest::load(manifest_path)?;
    let m = &project.manifest;
    let code = std::fs::read(code_path).map_err(|e| format!("{}: {e}", code_path.display()))?;
    if m.kind == Kind::Wasm {
        maki_wasm::admit(m, &code).map_err(|e| format!("{}: maki wouldn't take it: {e}", code_path.display()))?;
    }
    let icon_path = icon_flag.map(PathBuf::from).or(project.icon.clone()).or_else(|| {
        let dir = manifest_path.parent().unwrap_or(Path::new("."));
        ["icon.png", "icon.pbm"].iter().map(|n| dir.join(n)).find(|p| p.exists())
    });
    let icon = icon_path.as_deref().map(icon::load).transpose()?;
    let key = key::load(key_flag)?;
    let bundle = maki_bundle::write(m, &code, icon.as_ref(), &key).map_err(|e| format!("can't pack it: {e}"))?;
    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    std::fs::write(out, &bundle).map_err(|e| format!("{}: {e}", out.display()))?;
    println!(
        "{}: {} {} ({}), {} bytes, signed by {}{}",
        out.display(),
        m.name,
        if m.label.is_empty() { format!("version {}", m.version) } else { m.label.clone() },
        m.id,
        bundle.len(),
        fingerprint(key.verifying_key().as_bytes()),
        if icon.is_none() { "; no icon, so maki shows its initial" } else { "" }
    );
    Ok(())
}

/// Builds the app in `dir` from its source and checks that `bundle` is what it makes: the same
/// manifest, icon and code. The maki store runs this before it stamps anything, and anyone can,
/// to see that an app is its source. Builds are the same wherever they're made, given the same
/// Rust (the source can pin it, with rust-toolchain.toml).
fn reproduce(bundle_path: &Path, dir: &Path) -> Result<(), String> {
    let bytes = std::fs::read(bundle_path).map_err(|e| format!("{}: {e}", bundle_path.display()))?;
    let b = maki_bundle::read(&bytes).map_err(|e| format!("{}: {e}", bundle_path.display()))?;
    let manifest_path = dir.join("maki.toml");
    let project = manifest::load(&manifest_path)?;
    let (wasm, _) = cargo_build(dir)?;
    let code = std::fs::read(&wasm).map_err(|e| format!("{}: {e}", wasm.display()))?;
    let icon_path = project.icon.clone().or_else(|| ["icon.png", "icon.pbm"].iter().map(|n| dir.join(n)).find(|p| p.exists()));
    let icon = icon_path.as_deref().map(icon::load).transpose()?;
    let rustc = std::process::Command::new(std::env::var("RUSTC").unwrap_or("rustc".into()))
        .arg("-V")
        .current_dir(dir)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let sha = |b: &[u8]| -> String { Sha256::digest(b).iter().take(8).map(|x| format!("{x:02x}")).collect() };
    let mut differs = Vec::new();
    if project.manifest != b.manifest {
        differs.push("the manifest (maki.toml says something else)".to_string());
    }
    if icon.as_ref() != b.icon.as_ref() {
        differs.push("the icon".to_string());
    }
    if code != b.code {
        differs.push(format!(
            "the code: built {} bytes ({}…), the bundle has {} ({}…)",
            code.len(),
            sha(&code),
            b.code.len(),
            sha(b.code)
        ));
    }
    let m = &b.manifest;
    if differs.is_empty() {
        println!("{} {} ({}) is what {} builds to, with {rustc}", m.name, m.version, m.id, dir.display());
        Ok(())
    } else {
        Err(format!(
            "{} {} ({}) isn't what {} builds to, with {rustc}: {}. (Built with another Rust? The source can pin it in rust-toolchain.toml.)",
            m.name,
            m.version,
            m.id,
            dir.display(),
            differs.join("; ")
        ))
    }
}

/// Builds the cdylib in `dir` for wasm32 and returns the .wasm and cargo's target directory.
/// Apps get a 16 KiB stack rather than wasm-ld's 1 MiB (it lives in the app's memory), unless
/// the developer set flags of their own.
fn cargo_build(dir: &Path) -> Result<(PathBuf, PathBuf), String> {
    let mut cargo = std::process::Command::new(std::env::var("CARGO").unwrap_or("cargo".into()));
    const FLAGS: &str = "CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS";
    if std::env::var_os(FLAGS).is_none() && std::env::var_os("RUSTFLAGS").is_none() {
        cargo.env(FLAGS, "-C link-arg=-zstack-size=16384");
    }
    let output = cargo
        .args(["build", "--release", "--target", "wasm32-unknown-unknown", "--message-format=json-render-diagnostics"])
        .current_dir(dir)
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| format!("cargo: {e}"))?;
    if !output.status.success() {
        return Err("cargo build failed".into());
    }
    let mut wasm = None;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        if msg["reason"] != "compiler-artifact" {
            continue;
        }
        let manifest_dir = msg["manifest_path"].as_str().map(|p| Path::new(p).parent().unwrap().to_path_buf());
        let here = std::fs::canonicalize(dir).ok();
        if manifest_dir.as_ref().and_then(|d| std::fs::canonicalize(d).ok()) != here {
            continue;
        }
        for f in msg["filenames"].as_array().into_iter().flatten() {
            if let Some(f) = f.as_str().filter(|f| f.ends_with(".wasm")) {
                wasm = Some(PathBuf::from(f));
            }
        }
    }
    let wasm = wasm.ok_or("cargo built no .wasm: is the crate a cdylib (crate-type = [\"cdylib\"])?")?;
    // .../target/wasm32-unknown-unknown/release/app.wasm
    let target = wasm.ancestors().nth(3).map(Path::to_path_buf).unwrap_or_else(|| dir.join("target"));
    Ok((wasm, target))
}

fn inspect(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let b = maki_bundle::read(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let m = &b.manifest;
    println!("{} {} ({})", m.name, if m.label.is_empty() { format!("version {}", m.version) } else { format!("{} (version {})", m.label, m.version) }, m.id);
    if !m.description.is_empty() {
        println!("  {}", m.description);
    }
    println!("  developer key {}", fingerprint(&b.developer));
    match b.stamp.map(maki_store::SignedStamp::decode) {
        None => println!("  where from    sideloaded: not reviewed by anyone"),
        Some(Ok(s)) => println!(
            "  where from    the maki store, stamped at {} (unix; maki checks the stamp against its root)",
            s.stamp.issued
        ),
        Some(Err(e)) => println!("  where from    a store stamp maki can't read ({e}): maki won't install it"),
    }
    match m.kind {
        Kind::Wasm => println!("  code          WebAssembly, {} bytes, host API {}", b.code.len(), m.api),
        Kind::Native => println!("  code          native, {} bytes, for {}", b.code.len(), m.firmware),
    }
    println!("  memory        {} KiB, storage {} KiB, backup {}", m.memory_kib, m.storage_kib, if m.backup { "on" } else { "off" });
    if m.permissions.is_empty() {
        println!("  permissions   none beyond the basics");
    }
    for (p, reason) in &m.permissions {
        println!("  permission    {}: {}", p.title(), p.warning());
        if !reason.is_empty() {
            println!("                the developer says: \"{reason}\"");
        }
    }
    let hash: String = b.hash.iter().map(|x| format!("{x:02x}")).collect();
    println!("  sha-256       {hash}");
    if let Some(icon) = &b.icon {
        print!("{}", icon::render(icon));
    }
    match maki_wasm::admit(m, b.code) {
        Ok(_) => println!("maki would run it"),
        Err(e) => println!("maki wouldn't run it: {e}"),
    }
    Ok(())
}

fn run(args: &Args) -> Result<(), String> {
    let path = PathBuf::from(args.positional.get(1).ok_or("which bundle?")?);
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let b = maki_bundle::read(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let m = b.manifest.clone();
    if m.kind != Kind::Wasm {
        return Err("the simulator runs WebAssembly apps only".into());
    }
    let limits = maki_wasm::admit(&m, b.code).map_err(|e| format!("maki wouldn't run it: {e}"))?;
    let options = sim::Options {
        presses: args.value("--press").map(sim::parse_presses).transpose()?,
        shot: args.value("--shot").map(PathBuf::from),
        frames: args.value("--frames").map(PathBuf::from),
        scale: args.value("--scale").map(|s| s.parse().map_err(|_| "--scale: a number")).transpose()?.unwrap_or(4),
        verified: args.has("--verified"),
        storage: args.value("--storage").map(PathBuf::from),
        sideloaded: true,
        developer: b.developer,
        motion: args.value("--motion").map(|m| sim::parse_xyz(m).ok_or("--motion X,Y,Z in milli-g")).transpose()?.unwrap_or([0, 0, 1000]),
    };
    if let Some(dir) = &options.frames {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let interactive = options.presses.is_none();
    let sim = sim::Sim::new(m, options);
    let handle = sim.handle();
    if interactive {
        crossterm::terminal::enable_raw_mode().map_err(|e| format!("terminal: {e}"))?;
        print!("\x1b[2J\x1b[?25l");
    }
    let stop = maki_wasm::run(b.code, Box::new(sim), limits);
    if interactive {
        crossterm::terminal::disable_raw_mode().ok();
        print!("\x1b[?25h");
    }
    handle.finish()?;
    println!("{}", describe(&stop));
    match stop {
        Stop::Finished => Ok(()),
        _ => Err(String::new()),
    }
}

/// A new app in `dir`, ready for `maki build`.
fn new_app(dir: &Path, id: Option<&str>, name: Option<&str>) -> Result<(), String> {
    if dir.exists() && dir.read_dir().map(|mut d| d.next().is_some()).unwrap_or(true) {
        return Err(format!("{} isn't empty", dir.display()));
    }
    let base = dir.file_name().and_then(|n| n.to_str()).ok_or("name the app's directory")?;
    let crate_name: String =
        base.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' }).collect();
    let id = id.map(String::from).unwrap_or_else(|| format!("org.example.{}", crate_name.trim_matches('-')));
    if !maki_bundle::id_ok(&id) {
        return Err(format!("\"{id}\" isn't an app ID: reverse-DNS, lower case (org.example.{crate_name})"));
    }
    let name = name.map(String::from).unwrap_or_else(|| {
        let mut c = base.chars();
        c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default()
    });
    let sdk = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("maki-app");
    let files = [
        (
            "Cargo.toml",
            format!(
                "# its own workspace, wherever it's put\n[workspace]\n\n[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\npublish = false\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[dependencies]\nmaki-app = {{ path = {:?} }}\n\n[profile.release]\nopt-level = \"z\"\nlto = true\ncodegen-units = 1\npanic = \"abort\"\nstrip = true\n",
                sdk.display().to_string()
            ),
        ),
        (
            "maki.toml",
            format!(
                "id = \"{id}\"\nname = \"{name}\"\nversion = 1\nlabel = \"0.1\"\nstorage = 1\nmemory = 64\nbackup = true\ndescription = \"\"\n# icon = \"icon.png\"   # 64x64, light shapes on dark\n\n[permissions]\n"
            ),
        ),
        (
            "src/lib.rs",
            format!(
                "#![no_std]\n\nuse maki_app::*;\n\nfn main() {{\n    let mut presses = 0u32;\n    loop {{\n        screen::clear(Color::Dark);\n        screen::text_centred(30, {name:?}, Style::Bold, Color::Light);\n        let mut line = Buf::<32>::new();\n        let _ = core::fmt::Write::write_fmt(&mut line, format_args!(\"{{presses}} presses\"));\n        screen::text_centred(56, line.as_str(), Style::Regular, Color::Light);\n        screen::present();\n        match wait(None) {{\n            Event::Centre => presses += 1,\n            Event::Exit => return,\n            _ => {{}}\n        }}\n    }}\n}}\n\nmaki_app::main!(main);\n"
            ),
        ),
        (".cargo/config.toml", "[target.wasm32-unknown-unknown]\nrustflags = [\"-C\", \"link-arg=-zstack-size=16384\"]\n".to_string()),
        (".gitignore", "/target\n*.maki\n".to_string()),
    ];
    for (path, text) in files {
        let path = dir.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| format!("{}: {e}", path.display()))?;
        std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    println!("{}: {name} ({id}). Next: maki build {}", dir.display(), dir.display());
    Ok(())
}

/// maki desktop's local socket, as it makes it (desktop: src/main/bridge.ts).
#[cfg(unix)]
fn desktop() -> Result<std::os::unix::net::UnixStream, String> {
    let dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    // SAFETY: getuid has no preconditions and can't fail
    let path = dir.join(format!("maki-{}.sock", unsafe { libc::getuid() }));
    std::os::unix::net::UnixStream::connect(&path).map_err(|e| format!("maki desktop isn't running ({}: {e})", path.display()))
}

#[cfg(windows)]
fn desktop() -> Result<std::fs::File, String> {
    let user = std::env::var("USERNAME").map_err(|_| "no USERNAME".to_string())?;
    let path = format!(r"\\.\pipe\maki-{user}");
    std::fs::OpenOptions::new().read(true).write(true).open(&path).map_err(|e| format!("maki desktop isn't running ({path}: {e})"))
}

fn install(path: &Path) -> Result<(), String> {
    use std::io::{BufRead, Write};
    let path = std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let b = maki_bundle::read(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    maki_wasm::admit(&b.manifest, b.code).map_err(|e| format!("maki won't take it: {e}"))?;
    let mut stream = desktop()?;
    let request = serde_json::json!({ "id": 1, "type": "install", "path": path.to_string_lossy() });
    writeln!(stream, "{request}").map_err(|e| format!("maki desktop: {e}"))?;
    println!(
        "{} {}: go through it on maki (developer key {})",
        b.manifest.name,
        if b.manifest.label.is_empty() { format!("version {}", b.manifest.version) } else { b.manifest.label.clone() },
        fingerprint(&b.developer)
    );
    let mut line = String::new();
    std::io::BufReader::new(stream).read_line(&mut line).map_err(|e| format!("maki desktop: {e}"))?;
    let reply: serde_json::Value = serde_json::from_str(&line).map_err(|_| format!("maki desktop said: {line}"))?;
    if reply["ok"] != true {
        return Err(format!("maki desktop: {}", reply["error"].as_str().unwrap_or("failed")));
    }
    match reply["approval"].as_str().unwrap_or("") {
        "approved" => {
            println!("installed");
            Ok(())
        }
        "refused" => Err(format!("maki won't install it: {}", reply["reason"].as_str().unwrap_or(""))),
        "denied" => Err("cancelled on maki".into()),
        "locked" => Err("maki is locked: enter its PIN first".into()),
        other => Err(format!("not installed: {other}")),
    }
}

fn main_inner(argv: &[String]) -> Result<(), String> {
    let args = Args::parse(argv)?;
    match args.positional.first().map(String::as_str) {
        Some("keygen") => {
            args.only(&["--key", "--force"])?;
            let (path, key) = key::generate(args.value("--key"), args.has("--force"))?;
            println!("{}: your developer key, {}", path.display(), fingerprint(key.verifying_key().as_bytes()));
            println!("Keep it safe and back it up: updates to your apps must be signed with it.");
            Ok(())
        }
        Some("new") => {
            args.only(&["--id", "--name"])?;
            new_app(Path::new(args.positional.get(1).ok_or("where? maki new DIR")?), args.value("--id"), args.value("--name"))
        }
        Some("pack") => {
            args.only(&["--manifest", "--code", "--icon", "--key", "-o"])?;
            let manifest = PathBuf::from(args.value("--manifest").unwrap_or("maki.toml"));
            let code = PathBuf::from(args.value("--code").ok_or("--code: the .wasm to pack")?);
            let project = manifest::load(&manifest)?;
            let out = args.value("-o").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(format!("{}.maki", project.manifest.id)));
            pack(&manifest, &code, args.value("--icon"), args.value("--key"), &out)
        }
        Some("build") => {
            args.only(&["--key", "-o"])?;
            let dir = PathBuf::from(args.positional.get(1).map(String::as_str).unwrap_or("."));
            let manifest = dir.join("maki.toml");
            let project = manifest::load(&manifest)?;
            let (wasm, target) = cargo_build(&dir)?;
            let out = args
                .value("-o")
                .map(PathBuf::from)
                .unwrap_or_else(|| target.join("maki").join(format!("{}.maki", project.manifest.id)));
            pack(&manifest, &wasm, None, args.value("--key"), &out)
        }
        Some("inspect") => {
            args.only(&[])?;
            inspect(Path::new(args.positional.get(1).ok_or("which bundle?")?))
        }
        Some("reproduce") => {
            args.only(&[])?;
            let bundle = args.positional.get(1).ok_or("which bundle?")?;
            reproduce(Path::new(bundle), Path::new(args.positional.get(2).map(String::as_str).unwrap_or(".")))
        }
        Some("install") => {
            args.only(&[])?;
            install(Path::new(args.positional.get(1).ok_or("which bundle?")?))
        }
        Some("run") => {
            args.only(&["--press", "--shot", "--frames", "--scale", "--verified", "--storage", "--motion"])?;
            run(&args)
        }
        Some("store") => store_command(&args),
        Some("help") | None if args.has("--help") || args.has("-h") || args.positional.is_empty() => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("no command \"{other}\"\n\n{USAGE}")),
        None => Err(USAGE.into()),
    }
}

/// `maki store ...`: see STORE_USAGE.
fn store_command(args: &Args) -> Result<(), String> {
    let arg = |i: usize, what: &str| args.positional.get(i).map(String::as_str).ok_or_else(|| format!("{what}?\n\n{STORE_USAGE}"));
    let num = |name: &str| -> Result<u64, String> {
        args.value(name).ok_or_else(|| format!("{name}?"))?.parse().map_err(|_| format!("{name}: a number"))
    };
    match args.positional.get(1).map(String::as_str) {
        Some("keygen") => {
            args.only(&[])?;
            store::keygen(arg(2, "which file")?)
        }
        Some("recover") => {
            args.only(&[])?;
            store::recover(arg(2, "which file")?)
        }
        Some("root") => {
            args.only(&["--version", "--threshold", "--keys", "--catalogue", "--expires-days", "--sign", "-o"])?;
            let keys = args.value("--keys").ok_or("--keys: the root keys, comma-separated")?.split(',').map(store::public).collect::<Result<Vec<_>, _>>()?;
            let catalogue = store::public(args.value("--catalogue").ok_or("--catalogue: the catalogue key")?)?;
            let sign = args.value("--sign").ok_or("--sign: the root key files that sign it")?.split(',').map(store::load).collect::<Result<Vec<_>, _>>()?;
            store::root(num("--version")? as u32, num("--threshold")? as u8, keys, catalogue, num("--expires-days")?, &sign, args.value("-o").unwrap_or("root.bin"))
        }
        Some("stamp") => {
            args.only(&["--catalogue", "-o"])?;
            let bundle = arg(2, "which bundle")?;
            let catalogue = store::load(args.value("--catalogue").ok_or("--catalogue: the catalogue key file")?)?;
            store::stamp(bundle, &catalogue, args.value("-o").unwrap_or(bundle))
        }
        Some("revoke") => {
            args.only(&["--catalogue", "--version", "--expires-days", "--list", "-o"])?;
            let catalogue = store::load(args.value("--catalogue").ok_or("--catalogue: the catalogue key file")?)?;
            let list = args.value("--list").ok_or("--list: the entries, a line each")?;
            store::revoke(&catalogue, num("--version")? as u32, num("--expires-days")?, list, args.value("-o").unwrap_or("revocations.bin"))
        }
        Some("show") => {
            args.only(&[])?;
            store::show(arg(2, "which file")?)
        }
        Some("index") => {
            args.only(&["--catalogue", "--version", "--expires-days"])?;
            let dir = arg(2, "which store directory")?;
            let catalogue = store::load(args.value("--catalogue").ok_or("--catalogue: the catalogue key file")?)?;
            let version = if args.value("--version").is_some() { Some(num("--version")? as u32) } else { None };
            let days = if args.value("--expires-days").is_some() { num("--expires-days")? } else { 30 };
            store::index(std::path::Path::new(dir), &catalogue, version, days)
        }
        Some("add") => {
            args.only(&["--catalogue", "--expires-days"])?;
            let (dir, bundle) = (arg(2, "which store directory")?, arg(3, "which bundle")?);
            let catalogue = store::load(args.value("--catalogue").ok_or("--catalogue: the catalogue key file")?)?;
            let days = if args.value("--expires-days").is_some() { num("--expires-days")? } else { 30 };
            store::add(std::path::Path::new(dir), bundle, &catalogue, days)
        }
        _ => Err(STORE_USAGE.into()),
    }
}

const STORE_USAGE: &str = "maki store: the maki store's side. Root keys stay offline and sign roots; the catalogue key
signs stamps and revocation lists.

  maki store keygen FILE
      A store key (a root key or the catalogue key), its public key printed, and its 24 words
      to keep on paper.
  maki store recover FILE
      A store key made again from its 24 words (typed in).
  maki store root --version N --threshold T --keys KEY,KEY,KEY --catalogue KEY --expires-days D
                  --sign FILE,FILE [-o root.bin]
      A root: the root keys (hex, or key files), how many must sign, the catalogue key and when
      it expires, signed by root keys: its own, and to replace another root, that one's too.
  maki store stamp BUNDLE.maki --catalogue FILE [-o OUT.maki]
      The bundle, stamped: from the maki store. Only after it's been reviewed and rebuilt.
  maki store revoke --catalogue FILE --version N --expires-days D --list FILE [-o revocations.bin]
      A revocation list from a text file: `app ID WHY`, `up-to ID VERSION WHY` or
      `developer KEY WHY`, a line each.
  maki store show FILE
      What a root, a revocation list or a bundle's stamp says.
  maki store add DIR BUNDLE.maki --catalogue FILE [--expires-days 30]
      Stamps the bundle into the store in DIR (apps/ID/VERSION.maki) and signs a new index.
  maki store index DIR --catalogue FILE [--version N] [--expires-days 30]
      Signs the index of the store in DIR: the newest stamped bundle of each app, every stamp
      checked against the newest root in roots/. maki desktop shows it, and won't use it once
      it has expired.

  A store is a directory of files to publish anywhere maki desktop can fetch them:
  roots/1.bin, roots/2.bin, ... (each root signed to replace the one before), revocations.bin,
  index.json with index.sig, and apps/.";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match main_inner(&argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("{e}");
            }
            ExitCode::FAILURE
        }
    }
}
