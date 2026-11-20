//! `TemplatedFilePathGuard` (9.2.0): confines a `FILE` body path that was rendered against the request
//! (`templatedFilePath`). The literal text before the first template expression, cut back to its last path separator,
//! is the base directory; it must name a directory (not empty, `./`, `/` or a drive). The rendered rest must be a plain
//! relative path below it: no `.`/`..`/empty segment, no `\`, `:`, `%`, control or line-separator character, and once
//! symbolic links are resolved the file must still be under the resolved base. Like `FileReader`, the class path roots
//! (`crate::class_path`) are tried before the file system.

use crate::templates::Engine;
use std::path::{Path, PathBuf};

/// Why a confined read failed: the guard's `IllegalArgumentException`, or the `IOException` of resolving or reading.
#[derive(Debug, Clone)]
pub struct Failure {
    /// The Java class of the exception.
    pub class: &'static str,
    pub message: String,
    /// `FileSystemException.getFile()` / `getReason()`, when the class is one.
    pub file: Option<String>,
    pub reason: Option<String>,
}

impl Failure {
    fn outside(template: &str, base: &str) -> Failure {
        Failure {
            class: "java.lang.IllegalArgumentException",
            message: format!("templated file path \"{template}\" rendered to a path outside its base directory \"{base}\""),
            file: None,
            reason: None,
        }
    }

    /// `UnixException.translateToIOException(file, null)` of a failed `toRealPath` or open.
    fn file_system(e: &std::io::Error, file: &str) -> Failure {
        let (class, reason) = match e.kind() {
            std::io::ErrorKind::NotFound => ("java.nio.file.NoSuchFileException", None),
            std::io::ErrorKind::PermissionDenied => ("java.nio.file.AccessDeniedException", None),
            _ => ("java.nio.file.FileSystemException", Some(os_reason(e))),
        };
        let message = match &reason {
            Some(reason) => format!("{file}: {reason}"),
            None => file.to_string(),
        };
        Failure { class, message, file: Some(file.to_string()), reason }
    }

    /// A plain `IOException` of reading an open stream (a directory: `Is a directory`).
    fn io(e: &std::io::Error) -> Failure {
        Failure { class: "java.io.IOException", message: os_reason(e), file: None, reason: None }
    }
}

/// The C library's `strerror` text, without Rust's ` (os error N)`.
fn os_reason(e: &std::io::Error) -> String {
    let text = e.to_string();
    match text.rfind(" (os error ") {
        Some(at) => text[..at].to_string(),
        None => text,
    }
}

/// `firstTemplateMarker`: where the first template expression starts (`$` or `#` for Velocity, `{{` for
/// Mustache), `None` when the path has none and is used literally.
pub fn first_template_marker(path: &str, engine: Engine) -> Option<usize> {
    match engine {
        Engine::Velocity => path.find(['$', '#']),
        Engine::Mustache => path.find("{{"),
        _ => None,
    }
}

/// `baseDirectory`: the literal prefix up to and including its last `/` or `\`; empty when there is none.
fn base_directory(template: &str, marker: usize) -> &str {
    let prefix = &template[..marker];
    match prefix.rfind(['/', '\\']) {
        Some(at) => &prefix[..=at],
        None => "",
    }
}

/// `isUnsafe`: a control character (`Cc`) or a line or paragraph separator.
pub fn is_unsafe(c: char) -> bool {
    c.is_control() || c == '\u{2028}' || c == '\u{2029}'
}

/// `printable`: the path with each unsafe character written `\xNN` (or `\xNNNN` above 0xFF).
pub fn printable(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if is_unsafe(c) {
            let code = c as u32;
            out.push_str(&if code <= 0xFF { format!("\\x{code:02X}") } else { format!("\\x{code:04X}") });
        } else {
            out.push(c);
        }
    }
    out
}

/// `namesADirectory`: the base has a segment that is neither empty, `.` nor a drive (`C:`).
fn names_a_directory(base: &str) -> bool {
    base.split(['/', '\\']).any(|segment| {
        let chars: Vec<char> = segment.chars().collect();
        let dot = chars == ['.'];
        let drive = chars.len() == 2 && chars[0].is_alphabetic() && chars[1] == ':';
        !chars.is_empty() && !dot && !drive
    })
}

/// `checkRenderedPath`: the number of request-influenced segments, or the refusal.
fn check_rendered_path(template: &str, base: &str, rendered: &str) -> Result<usize, Failure> {
    if !names_a_directory(base) || !rendered.starts_with(base) {
        return Err(Failure::outside(template, base));
    }
    let rest = &rendered[base.len()..];
    let segments: Vec<&str> = rest.split('/').collect();
    for segment in &segments {
        if segment.is_empty() || *segment == "." || *segment == ".." {
            return Err(Failure::outside(template, base));
        }
        if segment.chars().any(|c| is_unsafe(c) || c == '\\' || c == ':' || c == '%') {
            return Err(Failure::outside(template, base));
        }
    }
    Ok(segments.len())
}

/// `Path.toString()` of `Paths.get(path)` on Unix: repeated `/` collapsed, a trailing `/` dropped; `.` for empty.
fn java_path_string(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if !(c == '/' && out.ends_with('/')) {
            out.push(c);
        }
    }
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

/// `Path.toRealPath()`: the canonical path, or the `IOException` naming the path as given.
fn real_path(path: &Path) -> Result<PathBuf, Failure> {
    std::fs::canonicalize(path).map_err(|e| Failure::file_system(&e, &path.to_string_lossy()))
}

/// `readContained`: both resolved, the target strictly under the base, then read without following a link.
fn read_contained(template: &str, base_directory: &str, target: &Path, base: &Path) -> Result<Vec<u8>, Failure> {
    let real_base = real_path(base)?;
    let real_target = real_path(target)?;
    if !real_target.starts_with(&real_base) || real_target == real_base {
        return Err(Failure::outside(template, base_directory));
    }
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let shown = real_target.to_string_lossy().into_owned();
    let mut file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&real_target).map_err(|e| Failure::file_system(&e, &shown))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|e| Failure::io(&e))?;
    Ok(bytes)
}

/// `readConfined`: confines `rendered` (rendered from `template`, whose first template expression is at `marker`) to
/// the template's base directory and reads it, from the class path roots first, then the file system.
pub fn read_confined(template: &str, marker: usize, rendered: &str) -> Result<Vec<u8>, Failure> {
    let base_directory = base_directory(template, marker);
    let request_segments = check_rendered_path(template, base_directory, rendered)?;
    let Some(resource) = swagger_parser::java::classpath::find_resource(rendered) else {
        let target = PathBuf::from(java_path_string(rendered));
        return read_contained(template, base_directory, &target, Path::new(&java_path_string(base_directory)));
    };
    if resource.archive().is_some() {
        // an archive entry cannot be a symlink, and the class path finds it by exactly the checked name
        return resource.read_bytes().map_err(|e| Failure::io(&e));
    }
    let resource_path = PathBuf::from(resource.as_str());
    let mut class_path_base = Some(resource_path.as_path());
    for _ in 0..request_segments {
        class_path_base = class_path_base.and_then(Path::parent);
    }
    let Some(class_path_base) = class_path_base.filter(|b| !b.as_os_str().is_empty()) else {
        return Err(Failure::outside(template, base_directory));
    };
    read_contained(template, base_directory, &resource_path, class_path_base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_escapes_control_and_separator_characters() {
        assert_eq!(printable("a\u{0}b\u{7f}c\u{2028}"), "a\\x00b\\x7Fc\\x2028");
    }

    #[test]
    fn a_base_must_name_a_directory() {
        assert!(!names_a_directory(""));
        assert!(!names_a_directory("./"));
        assert!(!names_a_directory("/"));
        assert!(!names_a_directory("C:\\"));
        assert!(names_a_directory("mocks/"));
    }
}
