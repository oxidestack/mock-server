//! `staticFilesDirectory` (upstream 9.2.0 #35, `StaticFileDirectory`): `GET` and `HEAD` requests that match no
//! expectation and are not proxied are answered from a directory. The request path chooses the file, so it is
//! confined as a templated file path is:
//! - the path is percent-decoded once; it must then be a plain relative path with no empty segment and no segment
//!   starting with `.` (so no `.`, `..` or hidden file), and no `\`, `:`, `%` (drive letters, NTFS streams, double
//!   encoding) or control character, NUL included;
//! - once symlinks are resolved the file must still be a regular, non-hidden file inside the directory's real path,
//!   which is resolved once when the server starts;
//! - a directory is never listed: a path ending in `/` names that directory's `index.html`.
//!
//! The reads run on the bounded file read pool ([`crate::overload::Overload::file_read`]).

use std::io::Read;
use std::path::{Path, PathBuf};

use bytes::Bytes;

/// `MAX_FILE_SIZE_IN_BYTES`: a larger file is not served (a WARN and the usual 404).
pub const MAX_FILE_SIZE_IN_BYTES: u64 = 50 * 1024 * 1024;
const INDEX_FILE: &str = "index.html";
const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";
/// `CONTENT_TYPES`: by lower-case file extension.
const CONTENT_TYPES: [(&str, &str); 29] = [
    ("json", "application/json"),
    ("map", "application/json"),
    ("html", "text/html"),
    ("htm", "text/html"),
    ("css", "text/css"),
    ("js", "text/javascript"),
    ("mjs", "text/javascript"),
    ("txt", "text/plain"),
    ("csv", "text/csv"),
    ("md", "text/markdown"),
    ("xml", "application/xml"),
    ("yaml", "application/yaml"),
    ("yml", "application/yaml"),
    ("svg", "image/svg+xml"),
    ("png", "image/png"),
    ("jpg", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("gif", "image/gif"),
    ("webp", "image/webp"),
    ("ico", "image/x-icon"),
    ("pdf", "application/pdf"),
    ("zip", "application/zip"),
    ("gz", "application/gzip"),
    ("wasm", "application/wasm"),
    ("woff", "font/woff"),
    ("woff2", "font/woff2"),
    ("ttf", "font/ttf"),
    ("mp3", "audio/mpeg"),
    ("mp4", "video/mp4"),
];

/// The directory, resolved to its real path when the server starts.
#[derive(Debug, Clone)]
pub struct StaticFileDirectory {
    real_directory: PathBuf,
    max_file_size_in_bytes: u64,
}

/// A file to answer with: its content type, and its bytes (none for `HEAD`, which answers with the size).
#[derive(Debug, PartialEq, Eq)]
pub struct StaticFile {
    pub content_type: &'static str,
    pub size: u64,
    pub body: Option<Bytes>,
}

impl StaticFileDirectory {
    /// `open`: `None` for a blank `directory`; `Err` when it does not exist or is not a directory.
    pub fn open(directory: &str) -> std::io::Result<Option<StaticFileDirectory>> {
        if directory.trim().is_empty() {
            return Ok(None);
        }
        let real_directory = std::fs::canonicalize(directory.trim())?;
        if !real_directory.is_dir() {
            return Err(std::io::Error::other("not a directory"));
        }
        Ok(Some(StaticFileDirectory { real_directory, max_file_size_in_bytes: MAX_FILE_SIZE_IN_BYTES }))
    }

    pub fn directory(&self) -> &Path {
        &self.real_directory
    }

    /// `isServableMethod`: checked before any file system access.
    pub fn is_servable_method(method: &str) -> bool {
        method == "GET" || method == "HEAD"
    }

    /// `respond`: the file the request path names; `Ok(None)` when it names none that may be served, `Err` when
    /// it cannot be read or is larger than the size limit.
    pub fn respond(&self, method: &str, path: &str) -> std::io::Result<Option<StaticFile>> {
        if !Self::is_servable_method(method) {
            return Ok(None);
        }
        let Some(file) = self.resolve(path) else { return Ok(None) };
        let size = std::fs::metadata(&file)?.len();
        if size > self.max_file_size_in_bytes {
            return Err(self.too_large());
        }
        let content_type = content_type(&file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
        if method == "HEAD" {
            return Ok(Some(StaticFile { content_type, size, body: None }));
        }
        let mut bytes = Vec::new();
        open_no_follow(&file)?.take(self.max_file_size_in_bytes + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > self.max_file_size_in_bytes {
            return Err(self.too_large());
        }
        Ok(Some(StaticFile { content_type, size, body: Some(Bytes::from(bytes)) }))
    }

    /// `resolve`: the real path of the regular, non-hidden file inside the directory that `request_path` names.
    fn resolve(&self, request_path: &str) -> Option<PathBuf> {
        let relative = relative_path(request_path)?;
        let real_file = std::fs::canonicalize(self.real_directory.join(relative)).ok()?;
        if !real_file.starts_with(&self.real_directory) || real_file == self.real_directory {
            return None;
        }
        let inside = real_file.strip_prefix(&self.real_directory).ok()?;
        if inside.components().any(|segment| segment.as_os_str().to_string_lossy().starts_with('.')) {
            return None;
        }
        std::fs::symlink_metadata(&real_file).ok().filter(std::fs::Metadata::is_file).map(|_| real_file)
    }

    fn too_large(&self) -> std::io::Error {
        std::io::Error::other(format!("file is larger than the {} byte limit for static files", self.max_file_size_in_bytes))
    }
}

/// `Files.newInputStream(file, NOFOLLOW_LINKS)`.
fn open_no_follow(file: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(file)
}

/// `relativePath`: the checked path relative to the directory, or `None` when it is not a plain relative path.
fn relative_path(request_path: &str) -> Option<String> {
    if !request_path.starts_with('/') {
        return None;
    }
    let decoded = match request_path.contains('%') {
        // decoded once: "+" is a literal plus in a path, and a "%" left after decoding is refused below
        true => url_decode(request_path)?,
        false => request_path.to_string(),
    };
    let mut relative = decoded[1..].to_string();
    if relative.is_empty() || relative.ends_with('/') {
        relative.push_str(INDEX_FILE);
    }
    for segment in relative.split('/') {
        if segment.is_empty() || segment.starts_with('.') {
            return None;
        }
    }
    if relative.chars().any(|c| c == '\\' || c == ':' || c == '%' || is_unsafe(c)) {
        return None;
    }
    Some(relative)
}

/// `TemplatedFilePathGuard.isUnsafe`: a control character, or a line or paragraph separator.
fn is_unsafe(c: char) -> bool {
    c.is_control() || c == '\u{2028}' || c == '\u{2029}'
}

/// `URLDecoder.decode(path, UTF_8)` with `+` kept: each run of `%XX` escapes decoded as UTF-8 (malformed sequences
/// replaced), `None` for an incomplete or non-hex escape (`IllegalArgumentException`).
fn url_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            let next = s[i..].find('%').map_or(s.len(), |n| i + n);
            out.push_str(&s[i..next]);
            i = next;
            continue;
        }
        let mut run = Vec::new();
        while i < bytes.len() && bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            // `Integer.parseInt(hex, 16)`, which takes a sign; a negative value is refused
            let value = i32::from_str_radix(hex, 16).ok().filter(|v| *v >= 0)?;
            run.push(value as u8);
            i += 3;
        }
        out.push_str(&String::from_utf8_lossy(&run));
    }
    Some(out)
}

/// `contentType`: by the file name's extension, ignoring case.
fn content_type(file_name: &str) -> &'static str {
    match file_name.rfind('.') {
        Some(dot) if dot + 1 < file_name.len() => {
            let extension = file_name[dot + 1..].to_lowercase();
            CONTENT_TYPES.iter().find(|(e, _)| *e == extension).map_or(DEFAULT_CONTENT_TYPE, |(_, t)| t)
        }
        _ => DEFAULT_CONTENT_TYPE,
    }
}

/// `openStaticFileDirectory`'s startup line: the directory served (INFO), or why none is (WARN).
pub fn log_opened(state: &crate::state::State, directory: &str, opened: &std::io::Result<Option<StaticFileDirectory>>) {
    use crate::recorded::{Kind, LogEntry};
    match opened {
        Ok(None) => {}
        Ok(Some(opened)) => crate::log::info_event(
            state,
            LogEntry::new(Kind::ServerConfiguration, "serving GET and HEAD requests that match no expectation from staticFilesDirectory {}")
                .args([opened.directory().to_string_lossy().as_ref()]),
        ),
        Err(_) => crate::log::warn_event(
            state,
            LogEntry::new(Kind::Warn, "staticFilesDirectory {} is not a readable directory, so requests that match no expectation get a 404").args([directory]),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `respond` on a file over the size limit (50 MiB, too large for a scenario): an error, so the caller logs a WARN
    /// and answers the usual 404; `HEAD` checks the size before answering too.
    #[test]
    fn a_file_over_the_size_limit_is_not_served() {
        let files = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/static");
        let directory = StaticFileDirectory { max_file_size_in_bytes: 19, ..StaticFileDirectory::open(&files.to_string_lossy()).expect("readable").expect("set") };
        for method in ["GET", "HEAD"] {
            let refused = directory.respond(method, "/app.js").expect_err("20 bytes over a 19-byte limit");
            assert_eq!(refused.to_string(), "file is larger than the 19 byte limit for static files");
        }
        let served = StaticFileDirectory { max_file_size_in_bytes: 20, ..directory };
        assert_eq!(served.respond("GET", "/app.js").expect("read").map(|f| f.size), Some(20));
    }
}
