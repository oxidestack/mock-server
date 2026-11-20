//! The process's own figures, read when asked: the Prometheus client guidelines' standard `process_*` set. On Linux they come from `/proc/self/{stat,statm,limits,fd}` (and `btime` in `/proc/stat`), on macOS
//! from `proc_pidinfo` and `getrlimit`, and the CPU times and the peak RSS from `getrusage` everywhere. A figure the
//! platform cannot give is `None`, and its series is left out rather than faked.

/// One reading of the process's figures.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcessStats {
    pub cpu_user_seconds: f64,
    pub cpu_system_seconds: f64,
    pub max_resident_bytes: f64,
    pub resident_bytes: Option<f64>,
    pub virtual_bytes: Option<f64>,
    /// The address-space limit (`RLIMIT_AS`), the kernel's `RLIM_INFINITY` when there is none.
    pub virtual_max_bytes: Option<f64>,
    pub open_fds: Option<f64>,
    /// The open-files limit (`RLIMIT_NOFILE`, soft).
    pub max_fds: Option<f64>,
    /// Since the Unix epoch.
    pub start_time_seconds: Option<f64>,
    pub threads: Option<f64>,
}

/// Reads the figures now.
pub fn read() -> ProcessStats {
    // SAFETY: `getrusage` fills the struct it is given.
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        usage
    };
    let seconds = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    let mut stats = ProcessStats {
        cpu_user_seconds: seconds(usage.ru_utime),
        cpu_system_seconds: seconds(usage.ru_stime),
        // `ru_maxrss` is bytes on macOS and kilobytes elsewhere.
        max_resident_bytes: if cfg!(target_os = "macos") { usage.ru_maxrss as f64 } else { usage.ru_maxrss as f64 * 1024.0 },
        ..ProcessStats::default()
    };
    platform(&mut stats);
    stats
}

#[cfg(target_os = "linux")]
fn platform(stats: &mut ProcessStats) {
    let read = |path: &str| std::fs::read_to_string(path).ok();
    // SAFETY: `sysconf` only reads configuration values.
    let (page_size, ticks) = unsafe { (libc::sysconf(libc::_SC_PAGESIZE), libc::sysconf(libc::_SC_CLK_TCK)) };
    if let Some(stat) = read("/proc/self/stat").as_deref().and_then(linux::stat) {
        stats.virtual_bytes = Some(stat.vsize as f64);
        stats.threads = Some(stat.num_threads as f64);
        let boot = read("/proc/stat").as_deref().and_then(linux::boot_time);
        if let (Some(boot), true) = (boot, ticks > 0) {
            stats.start_time_seconds = Some(boot as f64 + stat.start_ticks as f64 / ticks as f64);
        }
    }
    if let (Some(pages), true) = (read("/proc/self/statm").as_deref().and_then(linux::statm_resident), page_size > 0) {
        stats.resident_bytes = Some(pages as f64 * page_size as f64);
    }
    if let Some(limits) = read("/proc/self/limits") {
        stats.max_fds = linux::limit(&limits, "Max open files").map(|v| v as f64);
        stats.virtual_max_bytes = linux::limit(&limits, "Max address space").map(|v| v as f64);
    }
    // The directory handle this listing holds is one of the fds it counts, as every `/proc` collector counts it.
    stats.open_fds = std::fs::read_dir("/proc/self/fd").ok().map(|entries| entries.count() as f64);
}

#[cfg(target_os = "macos")]
fn platform(stats: &mut ProcessStats) {
    use std::mem::{size_of, zeroed};
    // SAFETY: each `proc_pidinfo` call is given a buffer of the size it is told; a short answer is discarded.
    unsafe {
        let pid = libc::getpid();
        let mut task: libc::proc_taskinfo = zeroed();
        let size = size_of::<libc::proc_taskinfo>() as libc::c_int;
        if libc::proc_pidinfo(pid, libc::PROC_PIDTASKINFO, 0, (&mut task as *mut libc::proc_taskinfo).cast(), size) == size {
            stats.resident_bytes = Some(task.pti_resident_size as f64);
            stats.virtual_bytes = Some(task.pti_virtual_size as f64);
            stats.threads = Some(task.pti_threadnum as f64);
        }
        let mut bsd: libc::proc_bsdinfo = zeroed();
        let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
        if libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&mut bsd as *mut libc::proc_bsdinfo).cast(), size) == size {
            stats.start_time_seconds = Some(bsd.pbi_start_tvsec as f64 + bsd.pbi_start_tvusec as f64 / 1e6);
        }
        // Without a buffer the call answers an upper bound of the size the list needs; with one, the bytes it filled.
        let needed = libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0);
        if needed > 0 {
            let capacity = needed as usize / libc::PROC_PIDLISTFD_SIZE as usize + 16;
            let mut fds: Vec<libc::proc_fdinfo> = vec![zeroed(); capacity];
            let bytes = (capacity * libc::PROC_PIDLISTFD_SIZE as usize) as libc::c_int;
            let filled = libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), bytes);
            if filled > 0 {
                stats.open_fds = Some((filled / libc::PROC_PIDLISTFD_SIZE) as f64);
            }
        }
    }
    stats.max_fds = rlimit(libc::RLIMIT_NOFILE);
    stats.virtual_max_bytes = rlimit(libc::RLIMIT_AS);
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform(_: &mut ProcessStats) {}

/// The soft limit of `resource`.
#[cfg(target_os = "macos")]
fn rlimit(resource: libc::c_int) -> Option<f64> {
    // SAFETY: `getrlimit` fills the struct it is given.
    unsafe {
        let mut limit: libc::rlimit = std::mem::zeroed();
        (libc::getrlimit(resource, &mut limit) == 0).then_some(limit.rlim_cur as f64)
    }
}

/// Parsers of the `/proc` files (proc(5)), kept platform-neutral so they are tested everywhere.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod linux {
    pub struct Stat {
        pub num_threads: u64,
        pub start_ticks: u64,
        pub vsize: u64,
    }

    /// `/proc/[pid]/stat`: fields 20 (`num_threads`), 22 (`starttime`, clock ticks after boot) and 23 (`vsize`).
    /// The command name (field 2) is parenthesised and may hold spaces and parentheses, so fields count from the last `)`.
    pub fn stat(text: &str) -> Option<Stat> {
        let rest = &text[text.rfind(')')? + 1..];
        let fields: Vec<&str> = rest.split_whitespace().collect();
        // `rest` starts at field 3 (`state`).
        let field = |n: usize| fields.get(n - 3)?.parse::<u64>().ok();
        Some(Stat { num_threads: field(20)?, start_ticks: field(22)?, vsize: field(23)? })
    }

    /// `/proc/[pid]/statm`: the second figure, resident pages.
    pub fn statm_resident(text: &str) -> Option<u64> {
        text.split_whitespace().nth(1)?.parse().ok()
    }

    /// `/proc/stat`'s `btime`: boot time, seconds since the epoch.
    pub fn boot_time(text: &str) -> Option<u64> {
        text.lines().find_map(|l| l.strip_prefix("btime "))?.trim().parse().ok()
    }

    /// `/proc/[pid]/limits`: the soft limit on the line named `name`; `unlimited` is `RLIM_INFINITY` (all ones).
    pub fn limit(text: &str, name: &str) -> Option<u64> {
        let line = text.lines().find(|l| l.starts_with(name))?;
        match line[name.len()..].split_whitespace().next()? {
            "unlimited" => Some(u64::MAX),
            soft => soft.parse().ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::linux;

    #[test]
    fn parses_proc_stat_past_a_command_name_with_spaces_and_parentheses() {
        let text = "4242 (mock (server) rs) S 1 4242 4242 0 -1 4194560 2000 0 0 0 150 30 0 0 20 0 17 0 98765 123456789 2560 \
                    18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n";
        let stat = linux::stat(text).unwrap();
        assert_eq!((stat.num_threads, stat.start_ticks, stat.vsize), (17, 98765, 123456789));
        assert!(linux::stat("4242 (cut) S 1 2").is_none());
    }

    #[test]
    fn parses_statm_and_btime() {
        assert_eq!(linux::statm_resident("30000 2560 900 400 0 5000 0\n"), Some(2560));
        assert_eq!(linux::boot_time("cpu  1 2 3\nintr 5\nctxt 9\nbtime 1760000000\nprocesses 7\n"), Some(1_760_000_000));
        assert_eq!(linux::boot_time("cpu  1 2 3\n"), None);
    }

    #[test]
    fn parses_soft_limits_and_unlimited() {
        let text = "Limit                     Soft Limit           Hard Limit           Units     \n\
                    Max cpu time              unlimited            unlimited            seconds   \n\
                    Max open files            1024                 524288               files     \n\
                    Max address space         unlimited            unlimited            bytes     \n";
        assert_eq!(linux::limit(text, "Max open files"), Some(1024));
        assert_eq!(linux::limit(text, "Max address space"), Some(u64::MAX));
        assert_eq!(linux::limit(text, "Max locked memory"), None);
    }

    /// The reading on the platform the tests run on: every figure the platform gives is present and plausible.
    #[test]
    fn reads_this_process() {
        let stats = super::read();
        assert!(stats.cpu_user_seconds + stats.cpu_system_seconds > 0.0);
        assert!(stats.max_resident_bytes > 0.0);
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            let resident = stats.resident_bytes.unwrap();
            assert!(resident > 0.0 && resident <= stats.virtual_bytes.unwrap());
            assert!(stats.threads.unwrap() >= 1.0);
            let open = stats.open_fds.unwrap();
            assert!(open >= 3.0 && open <= stats.max_fds.unwrap(), "{stats:?}");
            assert!(stats.virtual_max_bytes.unwrap() > 0.0);
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
            let start = stats.start_time_seconds.unwrap();
            assert!(start > 1.5e9 && start <= now + 1.0, "{stats:?}");
        }
    }
}
