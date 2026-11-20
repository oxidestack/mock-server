//! The `docker run` bind mounts of the oracle containers the harness starts (`tests/files`, `{{scratch}}`,
//! `/libs`, a properties file). `-v <src>:<dst>` creates a missing source as an empty directory and mounts that, so a
//! path the Docker VM cannot see (a checkout outside the Docker VM's mounts, a stale view of a re-created worktree) turned
//! into an oracle that read no files and a golden recorded from it; `--mount type=bind` refuses a missing source
//! instead ("bind source path does not exist"), which `docker run`'s exit status reports. `make oracle` does the same.
//! Included with `#[path]` by the test binaries that start oracle containers.

#![allow(dead_code)]

use std::path::Path;

/// `docker run` arguments bind-mounting `src` at `dst`, read-only when `read_only`. Each field is quoted for the
/// option's CSV syntax, so a path holding a comma or a quote stays one field.
pub fn bind(src: &Path, dst: &Path, read_only: bool) -> [String; 2] {
    let field = |s: String| format!("\"{}\"", s.replace('"', "\"\""));
    let mut spec = format!("type=bind,{},{}", field(format!("source={}", src.display())), field(format!("target={}", dst.display())));
    if read_only {
        spec.push_str(",readonly");
    }
    ["--mount".to_string(), spec]
}

/// [`bind`] at the same path inside the container.
pub fn bind_same(path: &Path, read_only: bool) -> [String; 2] {
    bind(path, path, read_only)
}

#[test]
fn bind_quotes_each_path_field() {
    let [flag, spec] = bind(Path::new("/a,b/\"c\""), Path::new("/libs"), true);
    assert_eq!(flag, "--mount");
    assert_eq!(spec, r#"type=bind,"source=/a,b/""c""","target=/libs",readonly"#);
}
