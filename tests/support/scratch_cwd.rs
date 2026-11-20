//! In-process servers resolve a relative `directoryToSaveDynamicSSLCertificate` (default `.`) against
//! the process's working directory, which for `cargo test` is the repository root. Upstream does the same, so the
//! server stays as it is; the harness moves the whole test process into a scratch directory instead, once, before the
//! first server starts. Every path the tests read is absolute (`CARGO_MANIFEST_DIR`), so nothing else notices.
//! Included with `#[path]` by the test binaries that start servers in-process.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::OnceLock;

static ROOT_BEFORE: OnceLock<Vec<String>> = OnceLock::new();

fn root_entries() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(env!("CARGO_MANIFEST_DIR"))
        .expect("read repo root")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Moves the process into a fresh scratch directory under `target/scratch/in-process-cwd/` (idempotent) and
/// remembers what the repository root held before; returns the directory.
pub fn enter() -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        raise_open_file_limit();
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/scratch/in-process-cwd").join(std::process::id().to_string());
        std::fs::create_dir_all(&dir).expect("create in-process scratch cwd");
        // after the scratch dir exists: a checkout with no `target/` yet (CARGO_TARGET_DIR elsewhere) gains it here
        let _ = ROOT_BEFORE.set(root_entries());
        std::env::set_current_dir(&dir).expect("enter in-process scratch cwd");
        dir
    })
    .clone()
}

/// The in-process test binaries hold hundreds of servers and their connections at once, which a host's default soft
/// `ulimit -n` of 1024 (Ubuntu's; macOS raises its own) cannot hold (EMFILE). Raises the soft limit to the hard one, as far as
/// the platform lets the process (macOS caps it at `OPEN_MAX`), once, before the first server starts.
fn raise_open_file_limit() {
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `limit` is a valid out-pointer for the duration of both calls.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 || limit.rlim_cur >= limit.rlim_max {
            return;
        }
        let mut wanted = libc::rlimit { rlim_cur: limit.rlim_max, rlim_max: limit.rlim_max };
        if libc::setrlimit(libc::RLIMIT_NOFILE, &wanted) != 0 {
            // macOS refuses `RLIM_INFINITY` as a soft limit: settle for what `OPEN_MAX` allows
            wanted.rlim_cur = limit.rlim_max.min(10240);
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &wanted);
        }
    }
}

/// Fails if the repository root gained an entry since [`enter`] (a server wrote into the repository again).
pub fn assert_repository_root_untouched() {
    let Some(before) = ROOT_BEFORE.get() else { return };
    let added: Vec<String> = root_entries().into_iter().filter(|n| !before.contains(n)).collect();
    assert!(added.is_empty(), "an in-process server wrote into the repository root: {added:?}; it should have landed in the scratch cwd");
}
