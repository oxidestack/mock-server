//! The JDK's process-wide `InetAddress` negative lookup cache, shared by every client that resolves a name the way
//! 8.0.0's JVM does: the forwarding and proxy client (Netty's default resolver calls `InetAddress.getByName`), the
//! `HttpURLConnection` routes, the SSRF guard's `InetAddress.getByName`, MQTT (Paho) and the broker dial (AMQP,
//! Kafka, Schema Registry). A host whose lookup failed is not looked up again for [`NEGATIVE_LOOKUP_TTL`]; the
//! `UnknownHostException` thrown meanwhile carries the host alone instead of the resolver's text.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// How long a failed lookup is remembered: the JDK's `networkaddress.cache.negative.ttl` default (10 s).
const NEGATIVE_LOOKUP_TTL: Duration = Duration::from_secs(10);

/// The cache, keyed by the host as written. Each entry keeps the failure's text, so a client that shows the
/// resolver's text sees the same one.
static NEGATIVE_LOOKUPS: LazyLock<Mutex<HashMap<String, (Instant, String)>>> = LazyLock::new(Default::default);

/// A lookup answered from the negative cache: its `Display` is the original failure's text.
#[derive(Debug)]
pub struct CachedLookupFailure(String);

impl std::fmt::Display for CachedLookupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CachedLookupFailure {}

/// Whether a failed [`lookup`] came from the negative cache rather than a fresh lookup.
pub fn is_cached_lookup_failure(e: &std::io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<CachedLookupFailure>())
}

/// `host`'s cached lookup failure at `now`, if one is younger than [`NEGATIVE_LOOKUP_TTL`].
fn cached_lookup_failure(host: &str, now: Instant) -> Option<std::io::Error> {
    let mut cache = NEGATIVE_LOOKUPS.lock();
    cache.retain(|_, (at, _)| now.saturating_duration_since(*at) < NEGATIVE_LOOKUP_TTL);
    cache.get(host).map(|(_, message)| std::io::Error::other(CachedLookupFailure(message.clone())))
}

fn remember(host: &str, e: &std::io::Error) {
    NEGATIVE_LOOKUPS.lock().insert(host.to_string(), (Instant::now(), e.to_string()));
}

/// `host` as an IP literal (bracketed or not), which never reaches the resolver or the cache.
fn literal(host: &str, port: u16) -> Option<Vec<SocketAddr>> {
    host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>().ok().map(|ip| vec![SocketAddr::new(ip, port)])
}

/// Resolves `host` through the negative cache, remembering a failure.
pub async fn lookup(host: &str, port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
    if let Some(addresses) = literal(host, port) {
        return Ok(addresses);
    }
    if let Some(cached) = cached_lookup_failure(host, Instant::now()) {
        return Err(cached);
    }
    // The resolver runs on the blocking pool. A runtime shutting down cancels it: that is no answer from the
    // resolver, so it is not remembered (it would fail every lookup of the host, process-wide, for 10 s).
    let target = (host.to_string(), port);
    let resolved = tokio::task::spawn_blocking(move || std::net::ToSocketAddrs::to_socket_addrs(&target).map(Iterator::collect::<Vec<_>>)).await;
    match resolved {
        Ok(Ok(addresses)) => Ok(addresses),
        Ok(Err(e)) => {
            remember(host, &e);
            Err(e)
        }
        Err(cancelled) => Err(std::io::Error::other(cancelled)),
    }
}

/// [`lookup`] for a caller off the async runtime (the lookup blocks).
pub fn lookup_blocking(host: &str, port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
    if let Some(addresses) = literal(host, port) {
        return Ok(addresses);
    }
    if let Some(cached) = cached_lookup_failure(host, Instant::now()) {
        return Err(cached);
    }
    match std::net::ToSocketAddrs::to_socket_addrs(&(host, port)) {
        Ok(addresses) => Ok(addresses.collect()),
        Err(e) => {
            remember(host, &e);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_lookup_is_cached_for_ten_seconds_by_the_host_as_written() {
        let failed_at = Instant::now();
        NEGATIVE_LOOKUPS.lock().insert("negative-ttl.invalid".into(), (failed_at, "failed to lookup address information".into()));
        let cached = cached_lookup_failure("negative-ttl.invalid", failed_at + Duration::from_millis(9_999)).unwrap();
        assert!(is_cached_lookup_failure(&cached));
        assert_eq!(cached.to_string(), "failed to lookup address information");
        assert!(cached_lookup_failure("NEGATIVE-TTL.invalid", failed_at).is_none());
        assert!(cached_lookup_failure("negative-ttl.invalid", failed_at + NEGATIVE_LOOKUP_TTL).is_none());
        assert!(!NEGATIVE_LOOKUPS.lock().contains_key("negative-ttl.invalid"));
        assert!(!is_cached_lookup_failure(&std::io::Error::other("failed to lookup address information")));
    }

    #[test]
    fn the_blocking_and_async_lookups_share_one_cache() {
        let host = "shared-negative-cache-unit.invalid";
        let first = lookup_blocking(host, 80).unwrap_err();
        assert!(!is_cached_lookup_failure(&first));
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let second = runtime.block_on(lookup(host, 80)).unwrap_err();
        assert!(is_cached_lookup_failure(&second));
        assert_eq!(second.to_string(), first.to_string());
    }
}
