//! Rust ports of the cluster verify/retrieve fan-in unit tests of `mockserver-core` (T1.9), method for
//! method, against `mock_server::cluster_fanin` and, for the `HttpState` ones, a real in-process server:
//! - `ClusterFanInTest` (8): `ClusterFanIn` with an in-memory `PeerAccessor`.
//! - `HttpClusterPeerAccessorTest` (9): `HttpClusterPeerAccessor` against a tiny HTTP server on a thread (the JDK
//!   `HttpServer` of the original).
//! - `HttpStateClusterFanInTest` (6): a server whose coordinator is replaced (`Server::set_cluster_fan_in`, upstream's
//!   `HttpState.setClusterFanIn`), local traffic arriving as real requests (upstream logs `RECEIVED_REQUEST` entries
//!   directly); the peers' items are the JSON a peer's `retrieve` would serve.
//! - `HttpStateClusteredListenerWiringTest` (2 methods x the 2 parameters): a spy `StateBackend` handed to the server
//!   (`Server::start_with_state_backend`, upstream's `StateBackendFactory.register`). Adapted: a non-clustered
//!   backend gets no listener at all here (the `Store` is authoritative, so there is no expectations reconcile
//!   listener to register), where upstream registers its one unconditional listener (docs/divergences.md).
//!
//! The peer accessor trait carries JSON items (a request in flat form, a `{httpRequest, httpResponse, timestamp}`
//! pair) rather than model objects, so a stub needs no internal types.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use mock_server::cluster_fanin::{ClusterFanIn, FanInResult, HttpClusterPeerAccessor, PeerAccessor};
use mock_server::state_backend::memory::InMemoryStateBackend;
use mock_server::state_backend::{BlobStore, ExpectationEntry, InvalidationListener, KeyValueStore, StateBackend, Versioned};
use mock_server::Config;
use serde_json::{json, Value};

use crate::common;

// ---------------------------------------------------------------------------------------------------------
// ClusterFanInTest
// ---------------------------------------------------------------------------------------------------------

/// A fake peer accessor holding each peer's LOCAL log in memory; an unreachable peer fails as the HTTP one does on
/// a connect failure.
#[derive(Default)]
struct FakePeerAccessor {
    requests_by_peer: Mutex<HashMap<String, Vec<Value>>>,
    pairs_by_peer: Mutex<HashMap<String, Vec<Value>>>,
    unreachable: Mutex<Vec<String>>,
    queried_peers: Mutex<Vec<String>>,
}

impl FakePeerAccessor {
    fn answer(&self, peer: &str, by_peer: &Mutex<HashMap<String, Vec<Value>>>) -> Result<Vec<Value>, String> {
        self.queried_peers.lock().unwrap().push(peer.to_string());
        if self.unreachable.lock().unwrap().iter().any(|p| p == peer) {
            return Err(format!("connection refused: {peer}"));
        }
        Ok(by_peer.lock().unwrap().get(peer).cloned().unwrap_or_default())
    }
}

impl PeerAccessor for FakePeerAccessor {
    fn retrieve_requests(&self, peer: &str, _filter: Option<&Value>) -> Result<Vec<Value>, String> {
        self.answer(peer, &self.requests_by_peer)
    }

    fn retrieve_request_responses(&self, peer: &str, _filter: Option<&Value>) -> Result<Vec<Value>, String> {
        self.answer(peer, &self.pairs_by_peer)
    }
}

fn requests(count: usize) -> Vec<Value> {
    (0..count).map(|i| json!({"path": format!("/path{i}")})).collect()
}

fn fan_in(properties: &[(&str, &str)], accessor: &Arc<FakePeerAccessor>) -> ClusterFanIn {
    let config = properties.iter().fold(Config::for_tests(), |c, (k, v)| c.with_property(k, v));
    ClusterFanIn::with_accessor(&config, accessor.clone())
}

#[test]
fn enabled_is_false_by_default() {
    let fan_in = fan_in(&[], &Arc::default());
    assert!(!fan_in.enabled());
}

#[test]
fn enabled_is_false_when_flag_on_but_no_peers() {
    let fan_in = fan_in(&[("clusterVerifyFanIn", "true"), ("clusterVerifyFanInPeers", "")], &Arc::default());
    assert!(!fan_in.enabled());
}

#[test]
fn enabled_is_true_when_flag_on_and_peers_configured() {
    let fan_in = fan_in(&[("clusterVerifyFanIn", "true"), ("clusterVerifyFanInPeers", "http://b:1080")], &Arc::default());
    assert!(fan_in.enabled());
}

#[test]
fn peers_are_parsed_trimmed_and_blanks_dropped() {
    let fan_in = fan_in(&[("clusterVerifyFanInPeers", " http://b:1080 , ,http://c:1080,")], &Arc::default());
    assert_eq!(fan_in.peers(), vec!["http://b:1080", "http://c:1080"]);
}

#[test]
fn fan_in_requests_aggregates_counts_across_peers() {
    let accessor = Arc::new(FakePeerAccessor::default());
    accessor.requests_by_peer.lock().unwrap().insert("http://b:1080".into(), requests(3));
    accessor.requests_by_peer.lock().unwrap().insert("http://c:1080".into(), requests(2));
    let fan_in = fan_in(&[("clusterVerifyFanIn", "true"), ("clusterVerifyFanInPeers", "http://b:1080,http://c:1080")], &accessor);

    let result: FanInResult<Vec<Value>> = fan_in.fan_in_requests(Some(&json!({"path": "/api"})));

    // remote-only merge: 3 (node B) + 2 (node C) = 5; the caller adds its own local count
    assert_eq!(result.merged.len(), 5);
    assert!(!result.has_unreachable_peers());
    assert!(result.unreachable_peers.is_empty());
    // both peers were queried (fan-in is a scatter to every configured peer)
    let mut queried = accessor.queried_peers.lock().unwrap().clone();
    queried.sort();
    assert_eq!(queried, vec!["http://b:1080", "http://c:1080"]);
}

#[test]
fn fan_in_requests_fails_closed_on_unreachable_peer() {
    let accessor = Arc::new(FakePeerAccessor::default());
    accessor.requests_by_peer.lock().unwrap().insert("http://b:1080".into(), requests(4));
    accessor.unreachable.lock().unwrap().push("http://c:1080".into());
    let fan_in = fan_in(&[("clusterVerifyFanIn", "true"), ("clusterVerifyFanInPeers", "http://b:1080,http://c:1080")], &accessor);

    let result = fan_in.fan_in_requests(Some(&json!({"path": "/api"})));

    // the reachable peer's traffic is still gathered, but the unreachable peer is reported so the caller can fail
    // closed rather than trust a partial (under-counted) result
    assert_eq!(result.merged.len(), 4);
    assert!(result.has_unreachable_peers());
    assert_eq!(result.unreachable_peers, vec!["http://c:1080"]);
}

#[test]
fn fan_in_request_responses_aggregates_across_peers() {
    let accessor = Arc::new(FakePeerAccessor::default());
    accessor.pairs_by_peer.lock().unwrap().insert("http://b:1080".into(), vec![json!({"httpRequest": {"path": "/x"}}), json!({"httpRequest": {"path": "/y"}})]);
    accessor.pairs_by_peer.lock().unwrap().insert("http://c:1080".into(), vec![json!({"httpRequest": {"path": "/z"}})]);
    let fan_in = fan_in(&[("clusterVerifyFanIn", "true"), ("clusterVerifyFanInPeers", "http://b:1080,http://c:1080")], &accessor);

    let result = fan_in.fan_in_request_responses(Some(&json!({"path": "/api"})));

    assert_eq!(result.merged.len(), 3);
    assert!(!result.has_unreachable_peers());
}

#[test]
fn disabled_fan_in_does_not_query_peers() {
    // `enabled()` is the caller's gate; with the flag off the coordinator is not consulted
    let accessor = Arc::new(FakePeerAccessor::default());
    let fan_in = fan_in(&[("clusterVerifyFanIn", "false"), ("clusterVerifyFanInPeers", "http://b:1080")], &accessor);
    assert!(!fan_in.enabled());
}

// ---------------------------------------------------------------------------------------------------------
// HttpClusterPeerAccessorTest
// ---------------------------------------------------------------------------------------------------------

/// What the stub peer saw last, and what it answers.
#[derive(Default)]
struct Peer {
    last_uri: Mutex<Option<String>>,
    last_method: Mutex<Option<String>>,
    last_authorization: Mutex<Option<String>>,
    status_to_return: Mutex<Option<u16>>,
    body_to_return: Mutex<Option<String>>,
    /// When set, a query whose Authorization header does not match is refused with 401 (an authenticated cluster).
    required_authorization: Mutex<Option<String>>,
}

/// A tiny in-process HTTP server on a thread as the "peer", answering `/mockserver/retrieve`.
struct PeerServer {
    base_url: String,
    state: Arc<Peer>,
    stop: Arc<AtomicBool>,
    port: u16,
}

impl PeerServer {
    fn start() -> PeerServer {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Peer::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (served, stopping) = (state.clone(), stop.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stopping.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(mut stream) = stream else { continue };
                let _ = Self::handle(&served, &mut stream);
            }
        });
        PeerServer { base_url: format!("http://127.0.0.1:{port}"), state, stop, port }
    }

    fn handle(peer: &Peer, stream: &mut std::net::TcpStream) -> std::io::Result<()> {
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                return Ok(());
            }
            raw.extend_from_slice(&chunk[..n]);
            if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
        let mut lines = head.lines();
        let mut request_line = lines.next().unwrap_or_default().split(' ');
        *peer.last_method.lock().unwrap() = request_line.next().map(str::to_string);
        *peer.last_uri.lock().unwrap() = request_line.next().map(str::to_string);
        let mut authorization = None;
        let mut length = 0usize;
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                match name.trim().to_ascii_lowercase().as_str() {
                    "authorization" => authorization = Some(value.trim().to_string()),
                    "content-length" => length = value.trim().parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        *peer.last_authorization.lock().unwrap() = authorization.clone();
        while raw.len() < head_end + length {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..n]);
        }
        let required = peer.required_authorization.lock().unwrap().clone();
        let (status, body) = if required.is_some() && required != authorization {
            (401, "unauthorized".to_string())
        } else {
            (peer.status_to_return.lock().unwrap().unwrap_or(200), peer.body_to_return.lock().unwrap().clone().unwrap_or_else(|| "[]".into()))
        };
        write!(stream, "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())?;
        stream.flush()
    }
}

impl Drop for PeerServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn accessor() -> HttpClusterPeerAccessor {
    HttpClusterPeerAccessor::from_config(&Config::for_tests())
}

fn accessor_with_token(token: &str) -> HttpClusterPeerAccessor {
    HttpClusterPeerAccessor::from_config(&Config::for_tests().with_property("clusterFanInPeerAuthToken", token))
}

fn api() -> Value {
    json!({"path": "/api"})
}

#[test]
fn sends_local_only_marker_to_prevent_recursion() {
    let peer = PeerServer::start();
    accessor().retrieve_requests(&peer.base_url, Some(&api())).unwrap();

    assert_eq!(peer.state.last_method.lock().unwrap().as_deref(), Some("PUT"));
    let uri = peer.state.last_uri.lock().unwrap().clone().unwrap();
    assert!(uri.contains("fanInLocalOnly=true"), "peer query MUST carry the local-only recursion guard: {uri}");
    assert!(uri.contains("type=REQUESTS"), "{uri}");
    assert!(uri.contains("format=JSON"), "{uri}");
}

#[test]
fn empty_array_response_yields_empty_list_not_an_error() {
    let peer = PeerServer::start();
    *peer.state.body_to_return.lock().unwrap() = Some("[]".into());
    assert!(accessor().retrieve_requests(&peer.base_url, Some(&api())).unwrap().is_empty());
}

#[test]
fn request_responses_uses_request_responses_type() {
    let peer = PeerServer::start();
    *peer.state.body_to_return.lock().unwrap() = Some("[]".into());
    let result = accessor().retrieve_request_responses(&peer.base_url, Some(&api())).unwrap();
    assert!(peer.state.last_uri.lock().unwrap().clone().unwrap().contains("type=REQUEST_RESPONSES"));
    assert!(result.is_empty());
}

#[test]
fn non_success_status_throws_so_caller_fails_closed() {
    let peer = PeerServer::start();
    *peer.state.status_to_return.lock().unwrap() = Some(500);
    *peer.state.body_to_return.lock().unwrap() = Some("error".into());
    let error = accessor().retrieve_requests(&peer.base_url, Some(&api())).expect_err("a non-2xx peer response fails (fail-closed)");
    assert!(error.contains("500"), "{error}");
}

#[test]
fn no_auth_token_sends_no_authorization_header_preserving_legacy_behaviour() {
    let peer = PeerServer::start();
    accessor().retrieve_requests(&peer.base_url, Some(&api())).unwrap();
    assert_eq!(*peer.state.last_authorization.lock().unwrap(), None, "default accessor must not present a credential");
}

#[test]
fn auth_token_is_presented_verbatim_as_control_plane_authorization_header() {
    let peer = PeerServer::start();
    accessor_with_token("Bearer eyJraff").retrieve_requests(&peer.base_url, Some(&api())).unwrap();
    assert_eq!(peer.state.last_authorization.lock().unwrap().as_deref(), Some("Bearer eyJraff"));
}

#[test]
fn authenticated_peer_accepts_query_when_token_presented() {
    let peer = PeerServer::start();
    *peer.state.required_authorization.lock().unwrap() = Some("Bearer shared-cluster-jwt".into());
    *peer.state.body_to_return.lock().unwrap() = Some("[]".into());
    let result = accessor_with_token("Bearer shared-cluster-jwt").retrieve_requests(&peer.base_url, Some(&api())).unwrap();
    assert!(result.is_empty());
    assert_eq!(peer.state.last_authorization.lock().unwrap().as_deref(), Some("Bearer shared-cluster-jwt"));
}

#[test]
fn authenticated_peer_rejects_unauthenticated_query_failing_closed() {
    let peer = PeerServer::start();
    *peer.state.required_authorization.lock().unwrap() = Some("Bearer shared-cluster-jwt".into());
    let error = accessor().retrieve_requests(&peer.base_url, Some(&api())).expect_err("the authed peer answers 401 (fail-closed)");
    assert!(error.contains("401"), "401 from an authed peer must propagate: {error}");
}

#[test]
fn unreachable_peer_throws() {
    // a port with nothing listening (the original dials the privileged port 1; a bound-then-released one could be
    // handed out again before the dial)
    let dead = crate::tcp_port::dead_port();
    assert!(accessor().retrieve_requests(&format!("http://127.0.0.1:{dead}"), Some(&api())).is_err(), "an unreachable peer fails (fail-closed)");
}

// ---------------------------------------------------------------------------------------------------------
// HttpStateClusterFanInTest
// ---------------------------------------------------------------------------------------------------------

/// A simulated peer log: a fixed number of matching items, or a failure when "unreachable".
struct FixedPeerAccessor {
    remote_matches: usize,
    unreachable: bool,
    queries: AtomicUsize,
}

impl FixedPeerAccessor {
    fn new(remote_matches: usize, unreachable: bool) -> Arc<FixedPeerAccessor> {
        Arc::new(FixedPeerAccessor { remote_matches, unreachable, queries: AtomicUsize::new(0) })
    }

    fn answer(&self, item: Value) -> Result<Vec<Value>, String> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        if self.unreachable {
            return Err("refused".into());
        }
        Ok(vec![item; self.remote_matches])
    }
}

/// `Arc` so the test keeps a handle on the query counter after the coordinator takes the accessor.
struct SharedAccessor(Arc<FixedPeerAccessor>);

impl PeerAccessor for SharedAccessor {
    fn retrieve_requests(&self, _peer: &str, _filter: Option<&Value>) -> Result<Vec<Value>, String> {
        self.0.answer(json!({"path": "/api"}))
    }

    fn retrieve_request_responses(&self, _peer: &str, _filter: Option<&Value>) -> Result<Vec<Value>, String> {
        self.0.answer(json!({"httpRequest": {"path": "/api"}}))
    }
}

/// A server with one local request to `/api` logged (upstream logs a `RECEIVED_REQUEST` entry).
async fn server_with_local_request() -> common::Running {
    let running = common::start(&[]).await;
    common::send(running.port, "GET", "/api", "").await;
    running
}

fn enable_fan_in(running: &common::Running, remote_matches: usize, unreachable: bool) -> Arc<FixedPeerAccessor> {
    let accessor = FixedPeerAccessor::new(remote_matches, unreachable);
    let config = Config::for_tests().with_property("clusterVerifyFanIn", "true").with_property("clusterVerifyFanInPeers", "http://peer-b:1080");
    running.server.set_cluster_fan_in(ClusterFanIn::with_accessor(&config, Arc::new(SharedAccessor(accessor.clone()))));
    accessor
}

async fn verify(port: u16, exactly: u32) -> common::Response {
    let body = json!({"httpRequest": {"path": "/api"}, "times": {"atLeast": exactly, "atMost": exactly}});
    common::send(port, "PUT", "/mockserver/verify", &body.to_string()).await
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_count_merges_remote_matches_across_cluster() {
    let running = server_with_local_request().await; // 1 local match
    enable_fan_in(&running, 2, false); // + 2 remote matches = 3 fleet-wide

    // exactly(3) must PASS fleet-wide even though only 1 request hit this node
    assert_eq!(verify(running.port, 3).await.status, 202);
    // exactly(1), the old per-node answer, must now FAIL, because the fleet served 3
    assert_eq!(verify(running.port, 1).await.status, 406);
    running.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn retrieve_requests_concatenates_remote() {
    let running = server_with_local_request().await; // 1 local
    enable_fan_in(&running, 2, false); // + 2 remote

    let r = common::send(running.port, "PUT", "/mockserver/retrieve", &api().to_string()).await;
    assert_eq!(r.status, 200);
    // 1 local + 2 remote = 3 request definitions returned
    assert_eq!(serde_json::from_str::<Vec<Value>>(&r.body).unwrap().len(), 3);
    running.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn retrieve_request_responses_concatenates_remote_for_dashboard_traffic_view() {
    let running = common::start(&[]).await;
    common::expect(running.port, &json!({"httpRequest": {"path": "/api"}, "httpResponse": {"body": "local"}})).await;
    common::send(running.port, "GET", "/api", "").await; // 1 local request/response pair
    enable_fan_in(&running, 2, false); // + 2 remote pairs = 3 fleet-wide

    let r = common::send(running.port, "PUT", "/mockserver/retrieve?type=REQUEST_RESPONSES", &api().to_string()).await;
    assert_eq!(r.status, 200);
    assert_eq!(serde_json::from_str::<Vec<Value>>(&r.body).unwrap().len(), 3, "REQUEST_RESPONSES retrieve must aggregate remote peer traffic");
    running.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn fan_in_local_only_retrieve_does_not_recurse() {
    let running = server_with_local_request().await;
    let accessor = enable_fan_in(&running, 5, false);

    // a peer fan-in query carries fanInLocalOnly=true: it MUST serve only the local log
    let r = common::send(running.port, "PUT", "/mockserver/retrieve?fanInLocalOnly=true", &api().to_string()).await;
    assert_eq!(r.status, 200);
    assert_eq!(serde_json::from_str::<Vec<Value>>(&r.body).unwrap().len(), 1, "local-only retrieve must not include remote traffic");
    assert_eq!(accessor.queries.load(Ordering::SeqCst), 0, "peers must not be queried for a local-only retrieve (recursion guard)");
    running.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_fails_closed_when_peer_unreachable() {
    let running = server_with_local_request().await;
    enable_fan_in(&running, 0, true); // peer unreachable

    // the local count alone (1) would satisfy exactly(1), yet an unreachable peer fails the verification
    let r = verify(running.port, 1).await;
    assert_eq!(r.status, 406);
    assert!(r.body.contains("peer"), "{}", r.body);
    running.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn retrieve_fails_closed_when_peer_unreachable() {
    let running = server_with_local_request().await;
    enable_fan_in(&running, 0, true);

    let r = common::send(running.port, "PUT", "/mockserver/retrieve", &api().to_string()).await;
    assert_eq!(r.status, 502, "retrieve must fail closed (502) when a peer is unreachable");
    running.server.shutdown().await;
}

// ---------------------------------------------------------------------------------------------------------
// HttpStateClusteredListenerWiringTest
// ---------------------------------------------------------------------------------------------------------

const CHAOS_SERVICE_NAMESPACE: &str = "chaos-service";
const CROSS_PROTOCOL_BUS_NAMESPACE: &str = "cross-protocol-bus";

/// An in-memory backend that reports a parameterised `is_clustered()`, records every listener registered on it and
/// wraps each CRUD-entity store so a reconcile read of it is observable.
struct RecordingStateBackend {
    inner: InMemoryStateBackend,
    clustered: bool,
    registered_listeners: Mutex<Vec<Arc<dyn InvalidationListener>>>,
    read_namespaces: Arc<Mutex<HashSet<String>>>,
    spy_stores: Mutex<HashMap<String, Arc<dyn KeyValueStore<Value>>>>,
}

impl RecordingStateBackend {
    fn new(clustered: bool) -> Arc<RecordingStateBackend> {
        Arc::new(RecordingStateBackend {
            inner: InMemoryStateBackend::new(1000),
            clustered,
            registered_listeners: Mutex::default(),
            read_namespaces: Arc::default(),
            spy_stores: Mutex::default(),
        })
    }
}

impl StateBackend for RecordingStateBackend {
    fn expectations(&self) -> &dyn KeyValueStore<ExpectationEntry> {
        self.inner.expectations()
    }

    fn scenario_states(&self) -> &dyn KeyValueStore<String> {
        self.inner.scenario_states()
    }

    fn shared_times_counters(&self) -> Option<&dyn KeyValueStore<i32>> {
        self.inner.shared_times_counters()
    }

    fn crud_entities(&self, namespace: &str) -> Arc<dyn KeyValueStore<Value>> {
        // memoised, so the store a registry captures at attach time is the one a firing listener reads
        self.spy_stores
            .lock()
            .unwrap()
            .entry(namespace.to_string())
            .or_insert_with(|| Arc::new(ReadRecordingStore { namespace: namespace.to_string(), delegate: self.inner.crud_entities(namespace), read_namespaces: self.read_namespaces.clone() }))
            .clone()
    }

    fn blobs(&self) -> &dyn BlobStore {
        self.inner.blobs()
    }

    fn add_invalidation_listener(&self, listener: Arc<dyn InvalidationListener>) {
        self.registered_listeners.lock().unwrap().push(listener.clone());
        self.inner.add_invalidation_listener(listener);
    }

    fn node_id(&self) -> &str {
        self.inner.node_id()
    }

    fn is_clustered(&self) -> bool {
        self.clustered
    }
}

/// Delegating store that records its namespace whenever `entries()` is read, the read every reconcile performs.
struct ReadRecordingStore {
    namespace: String,
    delegate: Arc<dyn KeyValueStore<Value>>,
    read_namespaces: Arc<Mutex<HashSet<String>>>,
}

impl KeyValueStore<Value> for ReadRecordingStore {
    fn get(&self, key: &str) -> Option<Versioned<Value>> {
        self.delegate.get(key)
    }

    fn put(&self, key: &str, value: Value) -> u64 {
        self.delegate.put(key, value)
    }

    fn put_if_absent(&self, key: &str, value: Value) -> Option<Versioned<Value>> {
        self.delegate.put_if_absent(key, value)
    }

    fn compare_and_set(&self, key: &str, expected_version: u64, value: Value) -> bool {
        self.delegate.compare_and_set(key, expected_version, value)
    }

    fn compare_and_remove(&self, key: &str, expected_version: u64) -> bool {
        self.delegate.compare_and_remove(key, expected_version)
    }

    fn remove(&self, key: &str) -> bool {
        self.delegate.remove(key)
    }

    fn entries(&self) -> Vec<(String, Versioned<Value>)> {
        self.read_namespaces.lock().unwrap().insert(self.namespace.clone());
        self.delegate.entries()
    }

    fn size(&self) -> usize {
        self.delegate.size()
    }

    fn clear(&self) {
        self.delegate.clear()
    }

    fn set_max_size(&self, max_size: usize) {
        self.delegate.set_max_size(max_size)
    }

    fn add_invalidation_listener(&self, listener: Arc<dyn InvalidationListener>) {
        self.delegate.add_invalidation_listener(listener)
    }
}

async fn start_with_spy_backend(clustered: bool) -> (mock_server::Server, Arc<RecordingStateBackend>) {
    let backend = RecordingStateBackend::new(clustered);
    crate::scratch_cwd::enter();
    let server = mock_server::Server::start_with_state_backend(Config::for_tests(), backend.clone()).await.expect("the server starts");
    (server, backend)
}

#[tokio::test(flavor = "multi_thread")]
async fn registers_chaos_and_bus_listeners_only_when_clustered() {
    for clustered in [false, true] {
        let (server, backend) = start_with_spy_backend(clustered).await;
        // Clustered: the chaos-registry, cross-protocol-bus and expectations reconcile listeners (3). Dropping either
        // clustered registration fails this. Adapted: a non-clustered backend gets none here, where upstream
        // registers its one unconditional expectations listener (1).
        let expected = if clustered { 3 } else { 0 };
        assert_eq!(backend.registered_listeners.lock().unwrap().len(), expected, "wrong number of invalidation listeners for clustered={clustered}");
        server.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn fired_listeners_reconcile_chaos_and_bus_only_when_clustered() {
    for clustered in [false, true] {
        let (server, backend) = start_with_spy_backend(clustered).await;
        // Fire every registered listener (both notification branches) and observe which CRUD-entity stores get
        // read as a result of the reconciles they drive.
        let listeners = backend.registered_listeners.lock().unwrap().clone();
        for listener in listeners {
            listener.on_changed("some-key");
            listener.on_cleared();
        }
        let read = backend.read_namespaces.lock().unwrap().clone();
        if clustered {
            assert!(read.contains(CHAOS_SERVICE_NAMESPACE), "clustered: the chaos reconcile listener must be wired (read {read:?})");
            assert!(read.contains(CROSS_PROTOCOL_BUS_NAMESPACE), "clustered: the cross-protocol-bus reconcile listener must be wired (read {read:?})");
        } else {
            assert!(!read.contains(CHAOS_SERVICE_NAMESPACE), "non-clustered: no chaos reconcile listener, so no chaos-service read");
            assert!(!read.contains(CROSS_PROTOCOL_BUS_NAMESPACE), "non-clustered: no bus reconcile listener, so no bus read");
        }
        server.shutdown().await;
    }
}
