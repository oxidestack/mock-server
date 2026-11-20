//! The JVM's own system properties (`System.getProperties()` less the `-D` options), as MockServer's image has them:
//! what `systemValue.property` reads for an allow-listed name nobody set with `-D`. The JVM's identity
//! (`java.*`, `jdk.*`, `sun.*`) is the oracle image's Temurin build; what the JVM reads from the machine it runs on
//! (`os.*`, `user.*`) a server measures from its own process ([`measured`]); a test configuration has the values the
//! oracle image reported when the goldens were recorded ([`IMAGE`]).

use std::collections::HashMap;

/// The oracle image's JVM properties (`mockserver/mockserver:9.2.0`, arm64, recorded by
/// `tests/scenarios/templates_system_value_jvm.json`; `os.version` is the recording VM's kernel, as
/// `-XshowSettings:properties` in the image shows it), as its `org.mockserver.cli.Main` sees them with no arguments.
pub const IMAGE: &[(&str, &str)] = &[
    ("file.encoding", "UTF-8"),
    ("file.separator", "/"),
    ("java.class.path", "/mockserver.jar:/mockserver-deps.jar:/libs/*:/extensions/*"),
    ("java.class.version", "70.0"),
    ("java.home", "/usr/lib/jvm/temurin25-trimmed"),
    ("java.io.tmpdir", "/tmp"),
    ("java.library.path", "/usr/java/packages/lib:/usr/lib64:/lib64:/lib:/usr/lib"),
    ("java.runtime.name", "OpenJDK Runtime Environment"),
    ("java.runtime.version", "26.0.2.1+1"),
    ("java.specification.name", "Java Platform API Specification"),
    ("java.specification.vendor", "Oracle Corporation"),
    ("java.specification.version", "26"),
    ("java.vendor", "Eclipse Adoptium"),
    ("java.vendor.url", "https://adoptium.net/"),
    ("java.vendor.url.bug", "https://github.com/adoptium/adoptium-support/issues"),
    ("java.vendor.version", "Temurin-26.0.2.1+1"),
    ("java.version", "26.0.2.1"),
    ("java.version.date", "2026-08-18"),
    ("java.vm.info", "mixed mode, sharing"),
    ("java.vm.name", "OpenJDK 64-Bit Server VM"),
    ("java.vm.specification.name", "Java Virtual Machine Specification"),
    ("java.vm.specification.vendor", "Oracle Corporation"),
    ("java.vm.specification.version", "26"),
    ("java.vm.vendor", "Eclipse Adoptium"),
    ("java.vm.version", "26.0.2.1+1"),
    ("jdk.debug", "release"),
    ("line.separator", "\n"),
    ("native.encoding", "UTF-8"),
    ("os.arch", "aarch64"),
    ("os.name", "Linux"),
    ("os.version", "6.8.0-64-generic"),
    ("path.separator", ":"),
    ("stderr.encoding", "UTF-8"),
    ("stdin.encoding", "UTF-8"),
    ("stdout.encoding", "UTF-8"),
    ("sun.arch.data.model", "64"),
    ("sun.boot.library.path", "/usr/lib/jvm/temurin25-trimmed/lib"),
    ("sun.cpu.endian", "little"),
    ("sun.io.unicode.encoding", "UnicodeLittle"),
    ("sun.java.command", "org.mockserver.cli.Main"),
    ("sun.java.launcher", "SUN_STANDARD"),
    ("sun.jnu.encoding", "UTF-8"),
    ("sun.management.compiler", "HotSpot 64-Bit Tiered Compilers"),
    ("user.dir", "/home/nonroot"),
    ("user.home", "/home/nonroot"),
    ("user.language", "en"),
    ("user.name", "nonroot"),
    ("user.timezone", "GMT"),
];

/// The properties a server started with `args` (the program arguments after the image's `-D` options) has on this
/// machine: the image's, with what the JVM takes from the machine read from this process.
pub fn measured(args: &[String], env: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut properties: HashMap<&str, String> = IMAGE.iter().map(|(k, v)| (*k, v.to_string())).collect();
    properties.insert("os.name", os_name().to_string());
    properties.insert("os.arch", os_arch().to_string());
    if let Some(release) = kernel_release() {
        properties.insert("os.version", release);
    }
    let (name, home) = account();
    // `java_props_md.c`: the password entry's name and home directory; without one, `HOME` for the home and `?`.
    properties.insert("user.name", name.unwrap_or_else(|| "?".into()));
    properties.insert("user.home", home.or_else(|| env.get("HOME").filter(|h| !h.is_empty()).cloned()).unwrap_or_else(|| "?".into()));
    if let Ok(dir) = std::env::current_dir() {
        properties.insert("user.dir", dir.to_string_lossy().into_owned());
    }
    properties.insert("user.timezone", time_zone(env));
    let program: Vec<&str> = args.iter().map(String::as_str).filter(|a| !a.starts_with("-D")).collect();
    properties.insert("sun.java.command", std::iter::once("org.mockserver.cli.Main").chain(program).collect::<Vec<_>>().join(" "));
    properties.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

/// `os.name` as the JDK names this operating system.
fn os_name() -> &'static str {
    match std::env::consts::OS {
        "linux" => "Linux",
        "macos" => "Mac OS X",
        "windows" => "Windows",
        "freebsd" => "FreeBSD",
        other => other,
    }
}

/// `os.arch` as the JDK names this architecture.
fn os_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" if cfg!(target_os = "macos") => "x86_64",
        "x86_64" => "amd64",
        "x86" => "x86",
        other => other,
    }
}

/// `uname -r`.
fn kernel_release() -> Option<String> {
    // SAFETY: `utsname` is plain data and `uname` fills it; its fields are NUL-terminated.
    unsafe {
        let mut name: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut name) != 0 {
            return None;
        }
        Some(std::ffi::CStr::from_ptr(name.release.as_ptr()).to_string_lossy().into_owned()).filter(|r| !r.is_empty())
    }
}

/// The user name and home directory of this process's password entry, when it has one.
fn account() -> (Option<String>, Option<String>) {
    // SAFETY: `getpwuid` returns null or an entry whose strings are NUL-terminated; they are copied before any other
    // call could reuse its storage.
    unsafe {
        let entry = libc::getpwuid(libc::getuid());
        if entry.is_null() {
            return (None, None);
        }
        let text = |p: *const libc::c_char| (!p.is_null()).then(|| std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()).filter(|s| !s.is_empty());
        (text((*entry).pw_name), text((*entry).pw_dir))
    }
}

/// `user.timezone` once `TimeZone.getDefault()` ran (`TimeZone_md.c`): `TZ`, else `/etc/timezone`, else the zone
/// `/etc/localtime` links to, else `GMT`.
fn time_zone(env: &HashMap<String, String>) -> String {
    if let Some(tz) = env.get("TZ").map(|tz| tz.trim_start_matches(':')).filter(|tz| !tz.is_empty()) {
        return tz.to_string();
    }
    if cfg!(target_os = "linux") && let Some(zone) = std::fs::read_to_string("/etc/timezone").ok().map(|z| z.trim().to_string()).filter(|z| !z.is_empty()) {
        return zone;
    }
    std::fs::read_link("/etc/localtime")
        .ok()
        .and_then(|target| target.to_string_lossy().split_once("zoneinfo/").map(|(_, zone)| zone.to_string()))
        .filter(|zone| !zone.is_empty())
        .unwrap_or_else(|| "GMT".into())
}
