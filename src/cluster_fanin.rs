//! The opt-in cluster scatter-gather (fan-in) for `verify` and `retrieve` (`org.mockserver.cluster`:
//! `ClusterFanIn`, `HttpClusterPeerAccessor`, `ClusterFanInException`; T1.9).
//!
//! The event log is per node. With `clusterVerifyFanIn=true` and a non-empty `clusterVerifyFanInPeers`, a retrieve of
//! `REQUESTS` or `REQUEST_RESPONSES` and a count verify (no `httpResponse`, no `expectationId`) also ask every peer for
//! its LOCAL matches (`fanInLocalOnly=true`, the recursion guard) and merge them with this node's. Fail closed: a peer
//! that cannot be reached is reported, never dropped. The two properties are read at each use, a
//! `PUT /mockserver/configuration` included (upstream 0e8566814; the 8.0.0 process read `HttpState`'s startup
//! copy).

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::client::{self, Outbound, Route};
use crate::config::Config;
use crate::recorded::Exchange;

/// Queries one peer's LOCAL log; the items are the JSON the peer's `retrieve` served (a request in flat form, or a
/// `{httpRequest, httpResponse, timestamp}` pair). Implementations must ask the peer in local-only mode and fail (with the reason) on
/// anything but a 2xx answer that parses.
pub trait PeerAccessor: Send + Sync {
    fn retrieve_requests(&self, peer_base_url: &str, filter: Option<&Value>) -> Result<Vec<Value>, String>;
    fn retrieve_request_responses(&self, peer_base_url: &str, filter: Option<&Value>) -> Result<Vec<Value>, String>;
}

/// The merged remote results plus the peers that could not be reached, with the reason for each.
pub struct FanInResult<T> {
    pub merged: T,
    pub unreachable_peers: Vec<String>,
    /// `(peer, error)` per unreachable peer, for the caller's WARN entries.
    pub failures: Vec<(String, String)>,
}

impl<T> FanInResult<T> {
    pub fn has_unreachable_peers(&self) -> bool {
        !self.unreachable_peers.is_empty()
    }
}

/// `ClusterFanInException`: what a retrieve that cannot reach every peer answers (502).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterFanInException {
    pub unreachable_peers: Vec<String>,
}

impl ClusterFanInException {
    pub fn new(unreachable_peers: Vec<String>) -> Self {
        ClusterFanInException { unreachable_peers }
    }

    /// `Throwable.getMessage()`; the peers print as a Java `List`.
    pub fn message(&self) -> String {
        format!("cluster verify/retrieve fan-in could not reach peer(s): [{}]", self.unreachable_peers.join(", "))
    }
}

impl std::fmt::Display for ClusterFanInException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

/// `ClusterFanIn`: the coordinator.
pub struct ClusterFanIn {
    enabled: bool,
    peers_raw: Option<String>,
    /// The server's configuration, read at each use in place of `enabled` and `peers_raw` when present.
    live: Option<Config>,
    accessor: Arc<dyn PeerAccessor>,
}

impl ClusterFanIn {
    pub fn new(enabled: bool, peers: Option<String>, accessor: Arc<dyn PeerAccessor>) -> ClusterFanIn {
        ClusterFanIn { enabled, peers_raw: peers, live: None, accessor }
    }

    /// `new ClusterFanIn(configuration, logger, peerAccessor)`: the server's configuration and `accessor`.
    pub fn with_accessor(config: &Config, accessor: Arc<dyn PeerAccessor>) -> ClusterFanIn {
        ClusterFanIn { enabled: false, peers_raw: None, live: Some(config.clone()), accessor }
    }

    /// The coordinator `HttpState` builds: the server's configuration and the HTTP accessor.
    pub fn from_config(config: &Config) -> ClusterFanIn {
        ClusterFanIn::with_accessor(config, Arc::new(HttpClusterPeerAccessor::from_config(config)))
    }

    /// Active only when enabled AND at least one peer is configured; enabled with none is a safe no-op.
    pub fn enabled(&self) -> bool {
        let enabled = match &self.live {
            Some(config) => config.bool_property("clusterVerifyFanIn", false),
            None => self.enabled,
        };
        enabled && !self.peers().is_empty()
    }

    /// The configured peer base URLs, split on `,`, trimmed, blanks dropped.
    pub fn peers(&self) -> Vec<String> {
        let live = self.live.as_ref().map(|config| config.property("clusterVerifyFanInPeers"));
        match live.as_ref().unwrap_or(&self.peers_raw) {
            Some(raw) if !raw.trim().is_empty() => raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            _ => Vec::new(),
        }
    }

    /// Every peer's LOCAL matching requests, concatenated (remote only; the caller merges with its own).
    pub fn fan_in_requests(&self, filter: Option<&Value>) -> FanInResult<Vec<Value>> {
        self.gather(|peer| self.accessor.retrieve_requests(peer, filter))
    }

    /// Every peer's LOCAL matching request-response pairs, concatenated.
    pub fn fan_in_request_responses(&self, filter: Option<&Value>) -> FanInResult<Vec<Value>> {
        self.gather(|peer| self.accessor.retrieve_request_responses(peer, filter))
    }

    fn gather<T>(&self, mut ask: impl FnMut(&str) -> Result<Vec<T>, String>) -> FanInResult<Vec<T>> {
        let mut merged = Vec::new();
        let mut unreachable_peers = Vec::new();
        let mut failures = Vec::new();
        for peer in self.peers() {
            match ask(&peer) {
                Ok(mut items) => merged.append(&mut items),
                Err(error) => {
                    failures.push((peer.clone(), error));
                    unreachable_peers.push(peer);
                }
            }
        }
        FanInResult { merged, unreachable_peers, failures }
    }
}

// ---------------------------------------------------------------------------------------------------------
// the HTTP accessor
// ---------------------------------------------------------------------------------------------------------

/// `HttpClusterPeerAccessor`: `PUT <peer>/mockserver/retrieve?type=…&format=JSON&fanInLocalOnly=true` with the filter
/// as the body. `clusterFanInPeerAuthToken` goes verbatim as `Authorization`.
pub struct HttpClusterPeerAccessor {
    timeout: Duration,
    token: String,
}

/// The runtime a (synchronous) fan-in waits on, apart from the server's own: a peer may be served by this very
/// process (tests), so the caller's worker must be free to serve it.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: std::sync::LazyLock<tokio::runtime::Runtime> = std::sync::LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("cluster-fan-in").enable_all().build().expect("fan-in runtime")
    });
    &RUNTIME
}

fn block<T: Send + 'static>(fut: impl std::future::Future<Output = T> + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    runtime().spawn(async move {
        let _ = tx.send(fut.await);
    });
    let wait = move || rx.recv().expect("the fan-in task answers");
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(wait),
        _ => wait(),
    }
}

impl HttpClusterPeerAccessor {
    pub fn new(timeout: Duration, token: Option<&str>) -> Self {
        HttpClusterPeerAccessor { timeout, token: token.map(|t| t.trim().to_string()).unwrap_or_default() }
    }

    pub fn from_config(config: &Config) -> Self {
        let millis = config.int_property("maxSocketTimeoutInMillis", 20_000);
        let timeout = Duration::from_millis(if millis > 0 { millis as u64 } else { 20_000 });
        HttpClusterPeerAccessor::new(timeout, config.property("clusterFanInPeerAuthToken").as_deref())
    }

    fn peer_retrieve(&self, peer_base_url: &str, kind: &str, filter: Option<&Value>) -> Result<String, String> {
        let base = peer_base_url.strip_suffix('/').unwrap_or(peer_base_url);
        let target = parse_base(base).ok_or_else(|| format!("Illegal character in peer URL: {base}"))?;
        let body = filter.map(crate::json::pretty).unwrap_or_default();
        let mut headers = vec![("Host".to_string(), crate::forward::host_header(&target.host, target.port, target.secure)), ("content-type".into(), "application/json".into())];
        if !self.token.is_empty() {
            headers.push(("authorization".into(), self.token.clone()));
        }
        headers.push(("content-length".into(), body.len().to_string()));
        let outbound = Outbound {
            method: "PUT".into(),
            target: format!("{}/mockserver/retrieve?type={kind}&format=JSON&fanInLocalOnly=true", target.path),
            headers,
            body: body.into_bytes().into(),
            http2: false,
            may_stream: false,
            decoded_body: None,
        };
        let timeout = self.timeout;
        let (host, port, secure) = (target.host.clone(), target.port, target.secure);
        let answer = block(async move { client::send_with_timeout(Route::Direct, &host, port, secure, &outbound, timeout).await });
        match answer {
            Some(Ok(upstream)) if (200..300).contains(&upstream.status) => Ok(String::from_utf8_lossy(&upstream.body).into_owned()),
            Some(Ok(upstream)) => Err(format!("peer {peer_base_url} returned status {}", upstream.status)),
            Some(Err(e)) => Err(e.exception_message().unwrap_or_else(|| "request timed out".into())),
            None => Err("request timed out".into()),
        }
    }
}

struct PeerTarget {
    host: String,
    port: u16,
    secure: bool,
    /// The base URL's own path, which precedes `/mockserver/retrieve`.
    path: String,
}

fn parse_base(base: &str) -> Option<PeerTarget> {
    let (secure, rest) = if let Some(r) = base.strip_prefix("https://") {
        (true, r)
    } else {
        (false, base.strip_prefix("http://")?)
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, String::new()),
    };
    let default_port = if secure { 443 } else { 80 };
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']')?;
        (h, if after.is_empty() { default_port } else { after.strip_prefix(':')?.parse::<u16>().ok()? })
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().ok()?),
            None => (authority, default_port),
        }
    };
    if host.is_empty() || host.contains(char::is_whitespace) {
        return None;
    }
    Some(PeerTarget { host: host.to_string(), port, secure, path })
}

/// A peer with no matching traffic answers `[]` (or blank): no remote matches, not a failure.
fn is_empty_json_array(body: &str) -> bool {
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    compact.is_empty() || compact == "[]"
}

fn parse_array(body: &str) -> Result<Vec<Value>, String> {
    match serde_json::from_str::<Value>(body) {
        Ok(Value::Array(items)) => Ok(items),
        Ok(other) => Ok(vec![other]),
        Err(e) => Err(format!("unparsable answer from peer: {e}")),
    }
}

impl PeerAccessor for HttpClusterPeerAccessor {
    fn retrieve_requests(&self, peer_base_url: &str, filter: Option<&Value>) -> Result<Vec<Value>, String> {
        let body = self.peer_retrieve(peer_base_url, "REQUESTS", filter)?;
        if is_empty_json_array(&body) {
            return Ok(Vec::new());
        }
        parse_array(&body)
    }

    fn retrieve_request_responses(&self, peer_base_url: &str, filter: Option<&Value>) -> Result<Vec<Value>, String> {
        let body = self.peer_retrieve(peer_base_url, "REQUEST_RESPONSES", filter)?;
        if is_empty_json_array(&body) {
            return Ok(Vec::new());
        }
        parse_array(&body)
    }
}

/// A request as a peer's `retrieve` served it: the model fields the input form leaves out (`keepAlive`, `secure`,
/// `protocol`) are read back too, so it renders again as the peer rendered it.
pub(crate) fn request_from_json(v: &Value) -> crate::request::HttpRequest {
    let mut request = crate::forward::request_from_json(v);
    // The flat form's maps are in the peer's own order, which the input form's map reading does not keep.
    let flat_map = |key: &str| -> Option<crate::request::MultiMap> {
        let object = v.get(key)?.as_object()?;
        Some(object.iter().map(|(k, vs)| (k.clone(), vs.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_else(|| vs.as_str().map(|x| vec![x.to_string()]).unwrap_or_default()))).collect())
    };
    if let Some(headers) = flat_map("headers") {
        request.headers = headers;
    }
    if let Some(query) = flat_map("queryStringParameters") {
        request.query = query;
    }
    request.keep_alive = v.get("keepAlive").and_then(Value::as_bool).unwrap_or(true);
    request.secure = v.get("secure").and_then(Value::as_bool).unwrap_or(false);
    request.protocol = if v.get("protocol").and_then(Value::as_str) == Some("HTTP_2") { "HTTP_2" } else { "HTTP_1_1" };
    request
}

/// A `LogEventRequestAndResponse` as a peer serialised it, as an exchange that renders back the same.
pub(crate) fn exchange_from_json(v: &Value) -> Exchange {
    let request = v.get("httpRequest").cloned().unwrap_or(Value::Object(Default::default()));
    let timestamp = v
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|t| chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S%.3f").ok())
        .and_then(|t| t.and_local_timezone(chrono::Local).single())
        .unwrap_or_else(chrono::Local::now);
    Exchange {
        request: request_from_json(&request),
        response: v.get("httpResponse").cloned().unwrap_or(Value::Null),
        timestamp,
        recorded: None,
        recorded_input: None,
        expectation_id: None,
        entry: None,
        no_match: false,
        shown_request: Some(request),
    }
}
