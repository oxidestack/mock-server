//! Embeds MockServer's dashboard UI bundle so `GET /mockserver/dashboard` serves it the way upstream serves the bundle
//! from its jar (`DashboardHandler`). The bundle is the first of:
//! 1. the directory in `MOCK_SERVER_DASHBOARD_DIR` (the Docker image's `ui` stage);
//! 2. `dashboard/`, when `make dashboard` (`scripts/build-dashboard.sh`) has built one there;
//! 3. a bundle this script builds itself with `scripts/build-dashboard.sh` into `<target>/dashboard-bundle`, as
//!    upstream's `build-ui` Maven profile builds `mockserver-ui` whenever its sources are there. It needs
//!    the `upstream/mockserver` submodule and node 22 on PATH, or `MOCK_SERVER_DASHBOARD_NODE=download`, which
//!    installs node from nodejs.org as `frontend-maven-plugin` does (never by default: `npm ci` is the only network
//!    use of a default build). The script's stamp skips npm when the bundle is current.
//!
//! Without any of them the binary embeds nothing, `GET /mockserver/dashboard` answers 404 and a `cargo:warning` names
//! what is missing, as upstream's jar built without `mockserver-ui/`. Each file is stored gzip-compressed (the bundle
//! is ~19 MB raw, ~5 MB compressed) and inflated once, on first use, by `control::dashboard`.
//!
//! `dashboard/` is tracked (its `.gitignore`), so it always exists and cargo can watch it: a missing
//! `rerun-if-changed` path counts as always stale and would rebuild the crate on every build. For the same reason the
//! UI sources are watched only when the submodule has them, and its (always present) directory otherwise.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "src/public_suffix/generate.rs"]
mod public_suffix;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=MOCK_SERVER_DASHBOARD_DIR");
    println!("cargo:rerun-if-env-changed=MOCK_SERVER_DASHBOARD_NODE");
    build_info();
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    public_suffix_trie(&manifest_dir, &out_dir);
    // A bundle built here is not watched: it is this script's own output (written after cargo's timestamp of this run,
    // it would make every next build rerun the script); its inputs are.
    let dir = match std::env::var_os("MOCK_SERVER_DASHBOARD_DIR").filter(|d| !d.is_empty()) {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            if dir.exists() {
                println!("cargo:rerun-if-changed={}", dir.display());
            }
            dir
        }
        None => {
            let dashboard = manifest_dir.join("dashboard");
            println!("cargo:rerun-if-changed={}", dashboard.display());
            if dashboard.join("index.html").is_file() { dashboard } else { build_bundle(&manifest_dir, &out_dir) }
        }
    };

    let mut files = Vec::new();
    collect(&dir, &dir, &mut files);
    files.sort();
    if !files.iter().any(|(path, _)| path == "/index.html") {
        if std::env::var_os("MOCK_SERVER_DASHBOARD_DIR").is_some_and(|d| !d.is_empty()) {
            println!("cargo:warning=dashboard UI not embedded: no index.html in {} (MOCK_SERVER_DASHBOARD_DIR)", dir.display());
        }
        files.clear();
    }
    // The bundle's directories, which upstream's class loader also finds (an empty 200): the root and every parent.
    let mut directories: Vec<String> = Vec::new();
    for (path, _) in &files {
        let mut parent = path.as_str();
        while let Some((up, _)) = parent.rsplit_once('/') {
            directories.push(up.to_string());
            parent = up;
        }
    }
    directories.sort();
    directories.dedup();

    let blobs = out_dir.join("dashboard");
    let _ = std::fs::remove_dir_all(&blobs);
    std::fs::create_dir_all(&blobs).unwrap();
    let mut table = String::from("/// The embedded bundle: (path under `/mockserver/dashboard`, gzip-compressed bytes).\n");
    table.push_str("pub static FILES: &[(&str, &[u8])] = &[\n");
    for (index, (path, source)) in files.iter().enumerate() {
        let blob = blobs.join(format!("{index}.gz"));
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&std::fs::read(source).unwrap()).unwrap();
        std::fs::write(&blob, encoder.finish().unwrap()).unwrap();
        table.push_str(&format!("    ({path:?}, include_bytes!({:?})),\n", blob.display().to_string()));
    }
    table.push_str("];\n/// Its directories, without the trailing `/` (the root is `\"\"`).\n");
    table.push_str(&format!("pub static DIRECTORIES: &[&str] = &{directories:?};\n"));
    std::fs::write(out_dir.join("dashboard.rs"), table).unwrap();
}

/// Guava's public-suffix trie, built from the unmodified Public Suffix List (MPL-2.0) kept in `third_party/publicsuffix/`
/// (`src/public_suffix/generate.rs`), into `<OUT_DIR>/public_suffix/{trie_data,string_pool}.bin` (UTF-16BE), which
/// `cors_origin` embeds.
fn public_suffix_trie(manifest_dir: &Path, out_dir: &Path) {
    let list = manifest_dir.join("third_party/publicsuffix/public_suffix_list.dat");
    println!("cargo:rerun-if-changed={}", list.display());
    println!("cargo:rerun-if-changed=src/public_suffix/generate.rs");
    let text = std::fs::read_to_string(&list).unwrap_or_else(|e| panic!("{}: {e}", list.display()));
    let (trie, pool) = public_suffix::generate(&text, &public_suffix::GUAVA_EXTRA_RULES);
    let dir = out_dir.join("public_suffix");
    std::fs::create_dir_all(&dir).unwrap();
    let bytes = |units: &[u16]| units.iter().flat_map(|u| u.to_be_bytes()).collect::<Vec<u8>>();
    std::fs::write(dir.join("trie_data.bin"), bytes(&trie)).unwrap();
    std::fs::write(dir.join("string_pool.bin"), bytes(&pool)).unwrap();
}

/// The labels of `mock_server_native_build_info` (src/metrics.rs) only a build script knows: the compiler's version, the
/// target triple, and the commit from `MOCK_SERVER_GIT_HASH` (`unknown` without it). The commit is not asked of
/// git: watching `.git` for it would rebuild the whole crate after every commit.
fn build_info() {
    println!("cargo:rerun-if-env-changed=MOCK_SERVER_GIT_HASH");
    let rustc = std::env::var_os("RUSTC")
        .and_then(|rustc| Command::new(rustc).arg("--version").output().ok())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|version| version.split_whitespace().nth(1).map(str::to_string))
        .unwrap_or_else(|| "unknown".into());
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    let git_hash = std::env::var("MOCK_SERVER_GIT_HASH").ok().filter(|h| !h.trim().is_empty()).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=MOCK_SERVER_RUSTC={rustc}");
    println!("cargo:rustc-env=MOCK_SERVER_TARGET={target}");
    println!("cargo:rustc-env=MOCK_SERVER_GIT_HASH={}", git_hash.trim());
}

/// Builds the bundle with `scripts/build-dashboard.sh` into `<target>/dashboard-bundle` and returns that directory,
/// which holds a bundle only when the build succeeded (or was current); otherwise a `cargo:warning` says why. The
/// working copy, the bundle, its notices and any downloaded node all stay under the target directory: the default
/// build writes nothing into the source tree.
fn build_bundle(manifest_dir: &Path, out_dir: &Path) -> PathBuf {
    let script = manifest_dir.join("scripts/build-dashboard.sh");
    let ui = manifest_dir.join("upstream/mockserver/mockserver-ui");
    for input in [script.clone(), manifest_dir.join("scripts/dashboard-vite.config.ts"),
                  manifest_dir.join("scripts/dashboard-notices.py")] {
        println!("cargo:rerun-if-changed={}", input.display());
    }
    if ui.exists() {
        println!("cargo:rerun-if-changed={}", ui.display());
        // build-dashboard.sh's `siblings`: read by mockserver-ui's build from outside its directory.
        let rust_client = manifest_dir.join("upstream/mockserver/mockserver-client-rust/Cargo.toml");
        println!("cargo:rerun-if-changed={}", rust_client.display());
    } else {
        // The submodule's directory exists (empty) before `git submodule update --init`, which then changes it.
        let submodule = manifest_dir.join("upstream/mockserver");
        if submodule.exists() {
            println!("cargo:rerun-if-changed={}", submodule.display());
        }
    }
    // OUT_DIR is <target>[/<triple>]/<profile>/build/<package>-<hash>/out: one bundle per target directory, shared by
    // every profile and by `make dashboard`'s working copy (node_modules).
    let target = out_dir.ancestors().nth(4).unwrap_or(out_dir).to_path_buf();
    let bundle = target.join("dashboard-bundle");
    let log = target.join("dashboard-build.log");
    let not_embedded = "dashboard UI not embedded, `GET /mockserver/dashboard` answers 404";
    let Ok(log_file) = std::fs::File::create(&log) else {
        println!("cargo:warning={not_embedded}: cannot write {}", log.display());
        return bundle;
    };
    let mut command = Command::new("bash");
    // What cargo sets for build scripts means something else to npm and node packages (`DEBUG`, `HOST`, `TARGET`).
    for name in ["DEBUG", "HOST", "TARGET", "PROFILE", "OPT_LEVEL", "NUM_JOBS", "OUT_DIR"] {
        command.env_remove(name);
    }
    command.arg(&script)
        .env("DASHBOARD_OUT", &bundle)
        .env("DASHBOARD_WORK", target.join("dashboard-ui"))
        .env("DASHBOARD_NOTICES", target.join("DASHBOARD-THIRD-PARTY-NOTICES.txt"))
        .env("DASHBOARD_AUTO", "1")
        .stdout(log_file.try_clone().unwrap())
        .stderr(log_file);
    if std::env::var("MOCK_SERVER_DASHBOARD_NODE").is_ok_and(|v| v == "download") {
        command.env("DASHBOARD_NODE", "download");
    } else {
        command.env_remove("DASHBOARD_NODE");
    }
    let status = command.status();
    // Without a bundle, a later PATH (node installed, another shell) retries; with one, PATH is not an input.
    let retry = || println!("cargo:rerun-if-env-changed=PATH");
    let output = std::fs::read_to_string(&log).unwrap_or_default();
    match status.as_ref().ok().and_then(|s| s.code()) {
        Some(0) => {}
        Some(2) => {
            let missing = output.lines().rev().find_map(|l| l.strip_prefix("missing: ")).unwrap_or("a prerequisite");
            println!("cargo:warning={not_embedded}: missing {missing}; `make dashboard` builds it into dashboard/");
            let _ = std::fs::remove_dir_all(&bundle);
            retry();
        }
        _ => {
            let last = output.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim();
            println!("cargo:warning={not_embedded}: scripts/build-dashboard.sh failed ({last}); log: {}", log.display());
            let _ = std::fs::remove_dir_all(&bundle);
            retry();
        }
    }
    bundle
}

/// Every regular file under `dir`, as (`/relative/path`, absolute path); dotfiles (`.gitignore`, the build's `.stamp`)
/// are not part of the bundle.
fn collect(root: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect(root, &path, files);
        } else if path.is_file() {
            let relative = path.strip_prefix(root).unwrap().components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            files.push((format!("/{relative}"), path));
        }
    }
}
