//! The class path the in-JVM server resolves resources on (`FileReader.openStreamToFileFromClassPathOrPath`,
//! `ClasspathHelper.loadFileFromClasspath`, `FilePath.expandFilePathGlobs`' ClassGraph scan). The binary has no JVM:
//! the mock-server startup property `mockServer.classPath` (or `MOCK_SERVER_CLASS_PATH`) lists its roots,
//! directories and jars separated like `java.class.path` (`:`, `;` on Windows), and the Java launcher fills it from
//! the test JVM's `java.class.path` (`docs/java-launcher.md`). The roots are swagger-parser-rs' `java::classpath`,
//! process-wide like a JVM's class path; without the property there are none, and every location is a file path.

use crate::config::Config;

pub const PROPERTY: &str = "mockServer.classPath";
pub const ENVIRONMENT: &str = "MOCK_SERVER_CLASS_PATH";

const SEPARATOR: char = if cfg!(windows) { ';' } else { ':' };

/// Makes the configured roots the class path, when the configuration names any (a server started without the
/// property leaves the class path as it is).
pub fn install(config: &Config) {
    if let Some(list) = config.class_path() {
        swagger_parser::java::classpath::set_classpath_roots(list.split(SEPARATOR).filter(|r| !r.trim().is_empty()).map(str::to_string).collect());
    }
}

/// `ClassLoader.getResourceAsStream(name)`: the resource's bytes, `None` when no root has it.
pub fn resource(name: &str) -> Option<Vec<u8>> {
    swagger_parser::java::classpath::find_resource(name).and_then(|p| p.read_bytes().ok())
}

/// `FileReader.openStreamToFileFromClassPathOrPath`: the class path resource, else the file (a relative path
/// against the working directory).
pub fn read_or_file(path: &str) -> std::io::Result<Vec<u8>> {
    match resource(path) {
        Some(bytes) => Ok(bytes),
        None => std::fs::read(path),
    }
}

/// The class path half of `FilePath.expandFilePathGlobs`: the resources with the pattern's extension whose name the
/// glob matches (`*` and `?` stay within one name, as `PathMatcher`'s `glob:` does).
pub fn glob(patterns: &[String], extension: &str) -> Vec<String> {
    let options = glob::MatchOptions { case_sensitive: true, require_literal_separator: true, require_literal_leading_dot: false };
    let compiled: Vec<glob::Pattern> = patterns.iter().filter_map(|p| glob::Pattern::new(p).ok()).collect();
    if compiled.is_empty() {
        return Vec::new();
    }
    swagger_parser::java::classpath::resources_with_extension(extension).into_iter().filter(|name| compiled.iter().any(|p| p.matches_with(name, options))).collect()
}

/// `FileReader.readFileFromClassPathOrPath`: [`read_or_file`] decoded as UTF-8 (malformed bytes replaced, as
/// `new String(bytes, UTF_8)` does).
pub fn read_string_or_file(path: &str) -> std::io::Result<String> {
    read_or_file(path).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Where `ClassLoader.getResource(name)` finds a resource: a file under a directory root, or an entry of a jar root.
#[derive(Debug, Clone, PartialEq)]
pub enum Location {
    /// The resource's file, canonical (the class loader holds its roots as canonical `file:` URLs).
    File(std::path::PathBuf),
    /// The canonical jar file and the entry's name in it.
    Jar { jar: std::path::PathBuf, entry: String },
}

impl Location {
    /// `URL.getPath()` of the resource's URL: the file's path, or `file:<jar>!/<entry>` for a `jar:` URL.
    pub fn url_path(&self) -> String {
        match self {
            Location::File(path) => path.display().to_string(),
            Location::Jar { jar, entry } => format!("file:{}!/{entry}", jar.display()),
        }
    }

    /// `URL.toExternalForm()`: `file:<path>` or `jar:file:<jar>!/<entry>`.
    pub fn url(&self) -> String {
        match self {
            Location::File(path) => format!("file:{}", path.display()),
            Location::Jar { .. } => format!("jar:{}", self.url_path()),
        }
    }

    /// The resource's bytes.
    pub fn read(&self) -> std::io::Result<Vec<u8>> {
        match self {
            Location::File(path) => std::fs::read(path),
            Location::Jar { jar, entry } => swagger_parser::java::path::JavaPath::in_archive(&jar.display().to_string(), entry).read_bytes(),
        }
    }
}

/// `ClassLoader.getResource(name)`: where the class path has the resource, `None` when no root has it.
pub fn locate(name: &str) -> Option<Location> {
    let found = swagger_parser::java::classpath::find_resource(name)?;
    let canonical = |path: &str| std::fs::canonicalize(path).unwrap_or_else(|_| std::path::PathBuf::from(path));
    Some(match found.archive() {
        Some(jar) => Location::Jar { jar: canonical(jar), entry: name.to_string() },
        None => Location::File(canonical(found.as_str())),
    })
}

/// `FilePath.absolutePathFromClassPathOrPath`: the path of the resource's URL ([`Location::url_path`]), else
/// `File.getAbsolutePath` (a relative name appended to the working directory as written, `./x` staying `./x`).
pub fn absolute_path(name: &str) -> String {
    if let Some(location) = locate(name) {
        return location.url_path();
    }
    let path = std::path::Path::new(name);
    if path.is_absolute() {
        return name.to_string();
    }
    std::env::current_dir().map_or_else(|_| name.to_string(), |dir| dir.join(path).display().to_string())
}
