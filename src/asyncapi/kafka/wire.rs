//! The Kafka protocol client under the publishers and subscribers: connections (plaintext or TLS, with SASL
//! PLAIN, SCRAM-SHA-256/512 or unsecured OAUTHBEARER), API-version negotiation, and cluster metadata, over the
//! `kafka-protocol` message codecs.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use kafka_protocol::messages::{
    ApiKey, ApiVersionsRequest, ApiVersionsResponse, MetadataRequest, MetadataResponse, RequestHeader, ResponseHeader, SaslAuthenticateRequest,
    SaslAuthenticateResponse, SaslHandshakeRequest, SaslHandshakeResponse, TopicName, metadata_request::MetadataRequestTopic,
};
use kafka_protocol::protocol::{Decodable, Encodable, HeaderVersion, Request, StrBytes};
use kafka_protocol::records::{Compression, RecordBatchDecoder, RecordSet};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::tls::{DialError, Stream};

use super::super::broker::{Error, ErrorKind};

/// `request.timeout.ms`'s default.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// `security.protocol`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Plaintext,
    Ssl,
    SaslPlaintext,
    SaslSsl,
}

impl Protocol {
    fn tls(self) -> bool {
        matches!(self, Protocol::Ssl | Protocol::SaslSsl)
    }

    fn sasl(self) -> bool {
        matches!(self, Protocol::SaslPlaintext | Protocol::SaslSsl)
    }
}

/// A SASL mechanism with the credentials from `sasl.jaas.config`.
#[derive(Clone, Debug)]
pub enum Sasl {
    /// The mechanism as configured (the broker compares it exactly).
    Plain { mechanism: String, username: String, password: String },
    Scram { sha512: bool, mechanism: String, username: String, password: String },
    /// `OAuthBearerLoginModule` with its unsecured (`alg: none`) token.
    OAuthBearer { token: String },
    /// A mechanism with no SASL client, or one whose login module gave no credentials.
    Unusable { mechanism: String },
}

impl Sasl {
    fn mechanism(&self) -> &str {
        match self {
            Sasl::Plain { mechanism, .. } | Sasl::Scram { mechanism, .. } | Sasl::Unusable { mechanism } => mechanism,
            Sasl::OAuthBearer { .. } => "OAUTHBEARER",
        }
    }
}

/// What a client connects with.
#[derive(Clone)]
pub struct Settings {
    pub bootstrap: Vec<(String, u16)>,
    pub protocol: Protocol,
    pub sasl: Option<Sasl>,
    pub tls: Option<Arc<rustls::ClientConfig>>,
    pub client_id: String,
    /// `NetworkClient`'s correlation id: one counter per client across its connections, the first request 0.
    pub correlation: Arc<AtomicI32>,
}

/// Our highest version of each API, capped by what the broker supports.
fn our_max(key: i16) -> i16 {
    match ApiKey::try_from(key) {
        Ok(ApiKey::Produce) => 13,
        Ok(ApiKey::Fetch) => 18,
        Ok(ApiKey::ListOffsets) => 11,
        Ok(ApiKey::Metadata) => 13,
        Ok(ApiKey::OffsetCommit) => 9,
        Ok(ApiKey::OffsetFetch) => 9,
        Ok(ApiKey::FindCoordinator) => 6,
        Ok(ApiKey::JoinGroup) => 9,
        Ok(ApiKey::Heartbeat) => 4,
        Ok(ApiKey::LeaveGroup) => 5,
        Ok(ApiKey::SyncGroup) => 5,
        Ok(ApiKey::SaslHandshake) => 1,
        Ok(ApiKey::ApiVersions) => 5,
        Ok(ApiKey::InitProducerId) => 5,
        Ok(ApiKey::SaslAuthenticate) => 2,
        _ => 0,
    }
}

/// The version whose layout the codec encodes: `ListOffsets` 11 (KIP-1023, listing by the earliest pending upload
/// offset) changes no field of version 10, which is the newest `kafka-protocol` has.
fn codec_version(key: i16, version: i16) -> i16 {
    match ApiKey::try_from(key) {
        Ok(ApiKey::ListOffsets) => version.min(10),
        _ => version,
    }
}

/// One connection to one broker.
pub struct Connection {
    stream: Box<dyn Stream>,
    correlation: Arc<AtomicI32>,
    versions: HashMap<i16, (i16, i16)>,
    client_id: String,
    pub node: i32,
    /// Set while a request awaits its response: a request abandoned half way leaves the stream unusable.
    in_flight: bool,
    /// While SASL authenticates, `SaslClientAuthenticator`'s own correlation id: its requests count from
    /// `Integer.MAX_VALUE - 7` (a range the `NetworkClient` never reaches), not from the client's counter.
    reserved: Option<i32>,
}

/// `SaslClientAuthenticator.MIN_RESERVED_CORRELATION_ID`.
const MIN_RESERVED_CORRELATION: i32 = i32::MAX - 7;

/// A failure the client retries (the network, a broker going away).
pub fn network(message: impl Into<String>) -> Error {
    Error::new(message)
}

impl Connection {
    /// A connection to `node` at `host:port`, negotiated and authenticated; `cluster` is the cluster id the
    /// client's metadata knows (see `negotiate`).
    pub async fn open(host: &str, port: u16, settings: &Settings, node: i32, cluster: Option<&str>) -> Result<Connection, Error> {
        let tls = if settings.protocol.tls() { Some(settings.tls.clone().ok_or_else(|| Error::new("no TLS configuration"))?) } else { None };
        // kafka-clients' `SslFactory` builds its engine with `createSSLEngine(host, port)`: the JDK's SNI rule.
        let stream = super::super::tls::dial(host, port, REQUEST_TIMEOUT, tls, super::super::tls::Sni::Jdk).await.map_err(|e| match e {
            DialError::Timeout => network(format!("Connection to node {node} ({host}:{port}) could not be established.")),
            DialError::Lookup(e) | DialError::Connect(e) => network(format!("Connection to node {node} ({host}:{port}) could not be established: {e}")),
            // `SslTransportLayer` reads the peer's close mid-handshake as an `EOFException`, a disconnect the client
            // retries (until `max.block.ms`), not an `SslAuthenticationException`.
            DialError::Handshake(e) if super::super::tls::is_handshake_eof(&e) => network(format!("Connection to node {node} ({host}:{port}) terminated during authentication.")),
            DialError::Handshake(e) => Error::caused("SSL handshake failed", Error::of_kind(ErrorKind::Tls, e.to_string())),
        })?;
        let mut connection = Connection { stream, correlation: settings.correlation.clone(), versions: HashMap::new(), client_id: settings.client_id.clone(), node, in_flight: false, reserved: None };
        if settings.protocol.sasl() {
            // `Selector` authenticates a channel as it connects, before the `NetworkClient` sends its own
            // `ApiVersions`: the authenticator's `ApiVersions` (v0, no body), `SaslHandshake`, `SaslAuthenticate`.
            let sasl = settings.sasl.clone().ok_or_else(|| Error::new("no SASL configuration"))?;
            connection.reserved = Some(MIN_RESERVED_CORRELATION);
            let result = connection.sasl_versions().await;
            let result = match result {
                Ok(()) => connection.authenticate(&sasl).await,
                Err(e) => Err(e),
            };
            connection.reserved = None;
            result?;
        }
        connection.negotiate(cluster).await?;
        Ok(connection)
    }

    /// `ApiVersions`: v5 (kafka-clients 4.4.0's latest, KIP-1242), or, when the broker is older
    /// (`UNSUPPORTED_VERSION`), the highest version its answer lists for `ApiVersions` (v0 when it lists none).
    /// `cluster` is the cluster id the client's metadata knows, sent with this node's id when the node is a broker
    /// (not a bootstrap address): `NetworkClient` with `metadata.recovery.strategy` `rebootstrap` and
    /// `metadata.cluster.check.enable`, both defaults. A broker that finds them stale answers
    /// `REBOOTSTRAP_REQUIRED`; any other error disconnects.
    async fn negotiate(&mut self, cluster: Option<&str>) -> Result<(), Error> {
        let identity = cluster.filter(|_| self.node >= 0).map(|c| (c, self.node));
        let mut version = our_max(ApiKey::ApiVersions as i16);
        let mut retried = false;
        let response = loop {
            let response = self.api_versions(version, identity).await?;
            match response.error_code {
                0 => break response,
                REBOOTSTRAP_REQUIRED => {
                    let (cluster, node) = (cluster.unwrap_or("null"), self.node);
                    return Err(network(format!("{REBOOTSTRAP} for cluster {cluster} and node {node}.")));
                }
                35 if version > 0 && !retried => {
                    retried = true;
                    version = response
                        .api_keys
                        .iter()
                        .find(|k| k.api_key == ApiKey::ApiVersions as i16)
                        .map(|k| k.max_version.clamp(0, our_max(ApiKey::ApiVersions as i16)))
                        .unwrap_or(0);
                }
                code => {
                    let node = self.node;
                    return Err(network(format!("Received error {code} from node {node} when making an ApiVersionsRequest. Disconnecting.")));
                }
            }
        };
        self.versions = response.api_keys.iter().map(|k| (k.api_key, (k.min_version, k.max_version))).collect();
        Ok(())
    }

    /// One `ApiVersions` round at `version`. `kafka-protocol` encodes the request up to v4, so v5's body is written
    /// here: v4's two compact strings, then `ClusterId` (compact nullable string) and `NodeId` (int32, -1 when
    /// unset), then the tagged fields. The v5 response has v4's layout.
    async fn api_versions(&mut self, version: i16, identity: Option<(&str, i32)>) -> Result<ApiVersionsResponse, Error> {
        let key = ApiKey::ApiVersions as i16;
        let mut body = BytesMut::new();
        if version >= 5 {
            put_compact_string(&mut body, Some(SOFTWARE_NAME));
            put_compact_string(&mut body, Some(SOFTWARE_VERSION));
            put_compact_string(&mut body, identity.map(|(cluster, _)| cluster));
            body.put_i32(identity.map_or(-1, |(_, node)| node));
            body.put_u8(0);
        } else {
            let request = ApiVersionsRequest::default()
                .with_client_software_name(StrBytes::from_static_str(SOFTWARE_NAME))
                .with_client_software_version(StrBytes::from_static_str(SOFTWARE_VERSION));
            request.encode(&mut body, version).map_err(|e| Error::new(e.to_string()))?;
        }
        let header_version = ApiVersionsRequest::header_version(version.min(4));
        let response = self.round_trip(key, version, header_version, ApiVersionsResponse::header_version(version.min(4)), body).await?;
        decode_response::<ApiVersionsResponse>(key, version.min(4), response)
    }

    /// The authenticator's `ApiVersions` round: v0, which every broker answers; its versions pick the SASL requests'.
    async fn sasl_versions(&mut self) -> Result<(), Error> {
        let response = self.api_versions(0, None).await?;
        if response.error_code != 0 {
            let node = self.node;
            return Err(network(format!("Received error {} from node {node} when making an ApiVersionsRequest. Disconnecting.", response.error_code)));
        }
        self.versions = response.api_keys.iter().map(|k| (k.api_key, (k.min_version, k.max_version))).collect();
        Ok(())
    }

    async fn authenticate(&mut self, sasl: &Sasl) -> Result<(), Error> {
        if let Sasl::Unusable { mechanism } = sasl {
            // Not an authentication failure: the connection fails and the client keeps retrying.
            return Err(network(format!("Failed to create SaslClient with mechanism {mechanism}")));
        }
        let request = SaslHandshakeRequest::default().with_mechanism(StrBytes::from_string(sasl.mechanism().to_string()));
        let handshake: SaslHandshakeResponse = self.send(request).await?;
        if handshake.error_code != 0 {
            let enabled: Vec<String> = handshake.mechanisms.iter().map(|m| m.to_string()).collect();
            let (mechanism, enabled) = (sasl.mechanism(), enabled.join(", "));
            return Err(network(format!("Client SASL mechanism '{mechanism}' not enabled in the server, enabled mechanisms are [{enabled}]")));
        }
        match sasl {
            Sasl::Unusable { .. } => unreachable!("handled above"),
            Sasl::Plain { username, password, .. } => {
                self.sasl_step(Bytes::from(format!("\0{username}\0{password}"))).await?;
            }
            Sasl::OAuthBearer { token } => {
                self.sasl_step(Bytes::from(format!("n,,\x01auth=Bearer {token}\x01\x01"))).await?;
            }
            Sasl::Scram { sha512, username, password, .. } => {
                let nonce: String = {
                    use rand_core::RngCore;
                    let mut bytes = [0u8; 24];
                    rand_core::OsRng.fill_bytes(&mut bytes);
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
                };
                let user = username.replace('=', "=3D").replace(',', "=2C");
                let client_first_bare = format!("n={user},r={nonce}");
                let server_first = self.sasl_step(Bytes::from(format!("n,,{client_first_bare}"))).await?;
                let server_first = String::from_utf8_lossy(&server_first).into_owned();
                let field = |k: &str| server_first.split(',').find_map(|p| p.strip_prefix(&format!("{k}=")).map(str::to_string));
                let (Some(server_nonce), Some(salt), Some(iterations)) = (field("r"), field("s"), field("i").and_then(|i| i.parse::<u32>().ok())) else {
                    return Err(Error::of_kind(ErrorKind::Authentication, "Invalid server first message"));
                };
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD;
                let salt = b64.decode(salt).map_err(|e| Error::of_kind(ErrorKind::Authentication, e.to_string()))?;
                let (algorithm, hmac, digest) = if *sha512 {
                    (ring::pbkdf2::PBKDF2_HMAC_SHA512, ring::hmac::HMAC_SHA512, &ring::digest::SHA512)
                } else {
                    (ring::pbkdf2::PBKDF2_HMAC_SHA256, ring::hmac::HMAC_SHA256, &ring::digest::SHA256)
                };
                let mut salted = vec![0u8; digest.output_len()];
                ring::pbkdf2::derive(algorithm, std::num::NonZeroU32::new(iterations.max(1)).unwrap(), &salt, password.as_bytes(), &mut salted);
                let sign = |key: &[u8], data: &[u8]| ring::hmac::sign(&ring::hmac::Key::new(hmac, key), data).as_ref().to_vec();
                let client_key = sign(&salted, b"Client Key");
                let stored_key = ring::digest::digest(digest, &client_key).as_ref().to_vec();
                let client_final_without_proof = format!("c=biws,r={server_nonce}");
                let auth_message = format!("{client_first_bare},{server_first},{client_final_without_proof}");
                let signature = sign(&stored_key, auth_message.as_bytes());
                let proof: Vec<u8> = client_key.iter().zip(&signature).map(|(a, b)| a ^ b).collect();
                self.sasl_step(Bytes::from(format!("{client_final_without_proof},p={}", b64.encode(proof)))).await?;
            }
        }
        Ok(())
    }

    /// One `SaslAuthenticate` round: the server's bytes, or `SaslAuthenticationException` with its message.
    async fn sasl_step(&mut self, bytes: Bytes) -> Result<Bytes, Error> {
        let response: SaslAuthenticateResponse = self.send(SaslAuthenticateRequest::default().with_auth_bytes(bytes)).await?;
        if response.error_code != 0 {
            let message = response.error_message.map(|m| m.to_string()).unwrap_or_else(|| "Authentication failed".into());
            return Err(Error::of_kind(ErrorKind::Authentication, message));
        }
        Ok(response.auth_bytes)
    }

    /// The version to send: ours capped by the broker's.
    pub fn version(&self, key: i16) -> Option<i16> {
        let (min, max) = *self.versions.get(&key)?;
        let v = our_max(key).min(max);
        (v >= min).then_some(v)
    }

    /// A request at the highest version both sides support.
    pub async fn send<R: Request>(&mut self, request: R) -> Result<R::Response, Error> {
        self.send_with(|_| request).await
    }

    /// A request built for the version it will go out at (fields differ between versions, and the codec refuses a
    /// field the version does not have).
    pub async fn send_with<R: Request>(&mut self, build: impl FnOnce(i16) -> R) -> Result<R::Response, Error> {
        let version = self.version(R::KEY).ok_or_else(|| Error::new(format!("The node does not support {:?}", ApiKey::try_from(R::KEY))))?;
        self.exchange(build(version), version).await
    }

    async fn exchange<R: Request>(&mut self, request: R, version: i16) -> Result<R::Response, Error> {
        let codec = codec_version(R::KEY, version);
        let mut body = BytesMut::new();
        request.encode(&mut body, codec).map_err(|e| Error::new(e.to_string()))?;
        let response = self.round_trip(R::KEY, version, R::header_version(codec), R::Response::header_version(codec), body).await?;
        decode_response::<R::Response>(R::KEY, codec, response)
    }

    /// Sends one request (its encoded body) and reads its answer: the response body after its header.
    async fn round_trip(&mut self, key: i16, version: i16, header_version: i16, response_header_version: i16, request: BytesMut) -> Result<Bytes, Error> {
        let correlation = match self.reserved {
            Some(next) => {
                self.reserved = Some(if next == i32::MAX { MIN_RESERVED_CORRELATION } else { next + 1 });
                next
            }
            None => self.correlation.fetch_add(1, Ordering::SeqCst),
        };
        let header = RequestHeader::default()
            .with_request_api_key(key)
            .with_request_api_version(version)
            .with_correlation_id(correlation)
            .with_client_id(Some(StrBytes::from_string(self.client_id.clone())));
        let mut body = BytesMut::new();
        header.encode(&mut body, header_version).map_err(|e| Error::new(e.to_string()))?;
        body.extend_from_slice(&request);
        let mut frame = BytesMut::with_capacity(body.len() + 4);
        frame.put_i32(body.len() as i32);
        frame.extend_from_slice(&body);
        let io = async {
            self.stream.write_all(&frame).await?;
            self.stream.flush().await?;
            let length = self.stream.read_i32().await?;
            // `NetworkReceive`'s `InvalidReceiveException`; a client's `Selector` sets no upper bound
            // (`NetworkReceive.UNLIMITED`, `ClientUtils.createNetworkClient`). The buffer grows as the frame arrives.
            if length < 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Invalid receive (size = {length})")));
            }
            let mut response = Vec::with_capacity((length as usize).min(1 << 20));
            (&mut self.stream).take(length as u64).read_to_end(&mut response).await?;
            if response.len() < length as usize {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            Ok::<_, std::io::Error>(response)
        };
        // A `JoinGroup` is answered when the rebalance completes: up to `max.poll.interval.ms` plus 5 s.
        let timeout = if key == ApiKey::JoinGroup as i16 { Duration::from_millis(305_000) } else { REQUEST_TIMEOUT };
        self.in_flight = true;
        let response = tokio::time::timeout(timeout, io)
            .await
            .map_err(|_| network(format!("Disconnected from node {}", self.node)))?
            .map_err(|e| network(format!("Disconnected from node {}: {e}", self.node)))?;
        self.in_flight = false;
        let mut response = Bytes::from(response);
        let header = ResponseHeader::decode(&mut response, response_header_version).map_err(|e| Error::new(e.to_string()))?;
        if header.correlation_id != correlation {
            return Err(network("Correlation id mismatch"));
        }
        Ok(response)
    }
}

/// `ApiVersionsRequest.ClientSoftwareName` / `ClientSoftwareVersion` as kafka-clients 4.4.0 sends them.
const SOFTWARE_NAME: &str = "apache-kafka-java";
const SOFTWARE_VERSION: &str = "4.4.0";
/// `Errors.REBOOTSTRAP_REQUIRED` (KIP-1242).
const REBOOTSTRAP_REQUIRED: i16 = 129;
/// `NetworkClient.handleApiVersionsResponse`'s log line for it, the start of the error `negotiate` returns.
const REBOOTSTRAP: &str = "Rebootstrap requested by server due to cluster metadata mismatch";

/// A compact (nullable) string: its length plus one as an unsigned varint (0 for null), then its UTF-8 bytes.
fn put_compact_string(buf: &mut BytesMut, value: Option<&str>) {
    let mut length = value.map_or(0, |s| s.len() as u32 + 1);
    while length >= 0x80 {
        buf.put_u8((length as u8 & 0x7f) | 0x80);
        length >>= 7;
    }
    buf.put_u8(length as u8);
    if let Some(s) = value {
        buf.put_slice(s.as_bytes());
    }
}

/// A response body at `version`.
fn decode_response<T: Decodable>(key: i16, version: i16, mut response: Bytes) -> Result<T, Error> {
    let body = response.clone();
    match T::decode(&mut response, version) {
        // `ApiVersionsResponse.parse`: a broker that does not know the request's version answers
        // `UNSUPPORTED_VERSION` in v0's layout, read as v0 when the requested version does not parse.
        Err(_) if key == ApiKey::ApiVersions as i16 && version > 0 => T::decode(&mut body.clone(), 0).map_err(|e| Error::new(format!("Error reading response: {e}"))),
        other => other.map_err(|e| Error::new(format!("Error reading response: {e}"))),
    }
}

/// A partition's leader as the metadata last said.
#[derive(Clone, Debug)]
pub struct PartitionMeta {
    pub partition: i32,
    pub leader: i32,
    pub error: i16,
    /// `PartitionMetadata.leaderEpoch`: -1 when the broker did not say.
    pub leader_epoch: i32,
    /// The racks of its replicas, in replica order, for the replicas whose broker the same response lists with a
    /// rack (`MetadataResponse.toPartitionInfo`: an unlisted replica is a node without a rack).
    pub replica_racks: Vec<String>,
}

/// The brokers and topics a client knows about, and its connections.
pub struct Cluster {
    pub settings: Settings,
    brokers: Mutex<HashMap<i32, (String, u16)>>,
    connections: Mutex<HashMap<i32, Arc<tokio::sync::Mutex<Option<Connection>>>>>,
    topics: Mutex<HashMap<String, (i16, Vec<PartitionMeta>)>>,
    /// The topic ids of the last Metadata responses (v10+), which Produce and Fetch v13+ name topics by.
    topic_ids: Mutex<HashMap<String, uuid::Uuid>>,
    /// The cluster id of the last Metadata response (`MetadataUpdater.clusterId`), sent in `ApiVersions` to brokers.
    cluster_id: Mutex<Option<String>>,
    /// A fatal failure (authentication) that ends every wait.
    fatal: Mutex<Option<Error>>,
}

impl Cluster {
    pub fn new(settings: Settings) -> Cluster {
        Cluster {
            settings,
            brokers: Mutex::new(HashMap::new()),
            connections: Mutex::new(HashMap::new()),
            topics: Mutex::new(HashMap::new()),
            topic_ids: Mutex::new(HashMap::new()),
            cluster_id: Mutex::new(None),
            fatal: Mutex::new(None),
        }
    }

    pub fn fatal(&self) -> Option<Error> {
        self.fatal.lock().clone()
    }

    fn address(&self, node: i32) -> Option<(String, u16)> {
        if node < 0 {
            return self.settings.bootstrap.get((-node - 1) as usize).cloned();
        }
        self.brokers.lock().get(&node).cloned()
    }

    /// A request to `node` (a broker id, or `-1 - i` for the `i`th bootstrap server) on its connection, opened
    /// when needed; a failed connection is dropped so the next call reconnects.
    pub async fn send<R: Request>(&self, node: i32, request: R) -> Result<R::Response, Error> {
        self.send_with(node, |_| request).await
    }

    /// `send` with the request built for the version it goes out at.
    pub async fn send_with<R: Request>(&self, node: i32, build: impl FnOnce(i16) -> R) -> Result<R::Response, Error> {
        let slot = self.connections.lock().entry(node).or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None))).clone();
        let mut guard = slot.lock().await;
        if guard.as_ref().is_some_and(|c| c.in_flight) {
            *guard = None;
        }
        if guard.is_none() {
            let (host, port) = self.address(node).ok_or_else(|| network(format!("Unknown node {node}")))?;
            let cluster = self.cluster_id.lock().clone();
            match Connection::open(&host, port, &self.settings, node, cluster.as_deref()).await {
                Ok(c) => *guard = Some(c),
                Err(e) => {
                    if e.has_kind(ErrorKind::Authentication) || e.has_kind(ErrorKind::Tls) {
                        *self.fatal.lock() = Some(e.clone());
                    }
                    if e.message.starts_with(REBOOTSTRAP) {
                        self.rebootstrap();
                    }
                    return Err(e);
                }
            }
        }
        let result = guard.as_mut().expect("connected").send_with(build).await;
        if result.is_err() {
            *guard = None;
        }
        result
    }

    /// The API version `node`'s connection uses for `key` (after a request on it).
    pub async fn version(&self, node: i32, key: i16) -> Option<i16> {
        let slot = self.connections.lock().get(&node).cloned()?;
        let guard = slot.lock().await;
        guard.as_ref().and_then(|c| c.version(key))
    }

    /// The nodes to try for a cluster-wide request: known brokers, then the bootstrap servers.
    fn candidates(&self) -> Vec<i32> {
        let mut nodes: Vec<i32> = self.brokers.lock().keys().copied().collect();
        nodes.sort();
        nodes.extend((0..self.settings.bootstrap.len() as i32).map(|i| -1 - i));
        nodes
    }

    /// A request any broker can answer.
    pub async fn send_any<R: Request + Clone>(&self, request: R) -> Result<(i32, R::Response), Error> {
        let mut last = network("No brokers available");
        for node in self.candidates() {
            match self.send(node, request.clone()).await {
                Ok(r) => return Ok((node, r)),
                Err(e) => {
                    if e.has_kind(ErrorKind::Authentication) || e.has_kind(ErrorKind::Tls) {
                        return Err(e);
                    }
                    last = e;
                }
            }
        }
        Err(last)
    }

    /// `send_any` with the request built for the version it goes out at.
    pub async fn send_any_with<R: Request, F: Fn(i16) -> R>(&self, build: F) -> Result<(i32, R::Response), Error> {
        let mut last = network("No brokers available");
        for node in self.candidates() {
            match self.send_with(node, &build).await {
                Ok(r) => return Ok((node, r)),
                Err(e) => {
                    if e.has_kind(ErrorKind::Authentication) || e.has_kind(ErrorKind::Tls) {
                        return Err(e);
                    }
                    last = e;
                }
            }
        }
        Err(last)
    }

    /// `Metadata` for `topics` (auto-creating them when the broker allows it); updates what is known.
    pub async fn refresh(&self, topics: &[String]) -> Result<MetadataResponse, Error> {
        let request = MetadataRequest::default()
            .with_topics(Some(topics.iter().map(|t| MetadataRequestTopic::default().with_name(Some(TopicName(StrBytes::from_string(t.clone()))))).collect()))
            .with_allow_auto_topic_creation(true);
        let (_, response) = self.send_any(request).await?;
        *self.cluster_id.lock() = response.cluster_id.as_ref().map(|c| c.to_string());
        {
            let mut brokers = self.brokers.lock();
            for b in &response.brokers {
                brokers.insert(b.node_id.0, (b.host.to_string(), b.port as u16));
            }
        }
        {
            let racks: HashMap<i32, String> =
                response.brokers.iter().filter_map(|b| b.rack.as_ref().map(|r| (b.node_id.0, r.to_string()))).collect();
            let mut known = self.topics.lock();
            let mut ids = self.topic_ids.lock();
            for t in &response.topics {
                let Some(name) = &t.name else { continue };
                if !t.topic_id.is_nil() {
                    ids.insert(name.0.to_string(), t.topic_id);
                }
                let partitions = t.partitions
                    .iter()
                    .map(|p| PartitionMeta {
                        partition: p.partition_index,
                        leader: p.leader_id.0,
                        error: p.error_code,
                        leader_epoch: p.leader_epoch,
                        replica_racks: p.replica_nodes.iter().filter_map(|n| racks.get(&n.0).cloned()).collect(),
                    })
                    .collect();
                known.insert(name.0.to_string(), (t.error_code, partitions));
            }
        }
        Ok(response)
    }

    /// The topic's partitions with a leader each, or its error code.
    pub fn partitions(&self, topic: &str) -> Option<(i16, Vec<PartitionMeta>)> {
        self.topics.lock().get(topic).cloned()
    }

    /// The topic's id (nil when the broker did not say), for the requests that name topics by id.
    pub fn topic_id(&self, topic: &str) -> uuid::Uuid {
        self.topic_ids.lock().get(topic).copied().unwrap_or_default()
    }

    /// The name of the topic with this id.
    pub fn topic_name(&self, id: uuid::Uuid) -> Option<String> {
        self.topic_ids.lock().iter().find(|(_, i)| **i == id).map(|(n, _)| n.clone())
    }

    /// A broker learnt outside a metadata response (a coordinator).
    pub fn add_broker(&self, node: i32, host: String, port: u16) {
        self.brokers.lock().insert(node, (host, port));
    }

    pub fn forget_connections(&self) {
        self.connections.lock().clear();
    }

    /// `MetadataUpdater.rebootstrap` after `REBOOTSTRAP_REQUIRED`: the brokers and cluster id are forgotten and every
    /// connection dropped, so the next request dials the bootstrap servers and fetches fresh metadata.
    fn rebootstrap(&self) {
        self.brokers.lock().clear();
        *self.cluster_id.lock() = None;
        self.forget_connections();
    }
}

/// `Errors`' default messages, for an error code the broker answered without its own message.
pub fn error_message(code: i16) -> String {
    match code {
        1 => "The requested offset is not within the range of offsets maintained by the server.",
        2 => "This message has failed its CRC checksum, exceeds the valid size, has a null key for a compacted topic, or is otherwise corrupt.",
        3 => "This server does not host this topic-partition.",
        5 => "There is no leader for this topic-partition as we are in the middle of a leadership election.",
        6 => "For requests intended only for the leader, this error indicates that the broker is not the current leader. For requests intended for any \
            replica, this error indicates that the broker is not a replica of the topic partition.",
        7 => "The request timed out.",
        10 => "The request included a message larger than the max message size the server will accept.",
        13 => "The server disconnected before a response was received.",
        14 => "The coordinator is loading and hence can't process requests.",
        15 => "The coordinator is not available.",
        16 => "This is not the correct coordinator.",
        17 => "The request attempted to perform an operation on an invalid topic.",
        18 => "The request included message batch larger than the configured segment size on the server.",
        19 => "Messages are rejected since there are fewer in-sync replicas than required.",
        20 => "Messages are written to the log, but to fewer in-sync replicas than required.",
        21 => "Produce request specified an invalid value for required acks.",
        22 => "Specified group generation id is not valid.",
        25 => "The coordinator is not aware of this member.",
        27 => "The group is rebalancing, so a rejoin is needed.",
        29 => "Topic authorization failed.",
        30 => "Group authorization failed.",
        31 => "Cluster authorization failed.",
        45 => "The broker received an out of order sequence number.",
        46 => "The broker received a duplicate sequence number.",
        47 => "Producer attempted to produce with an old epoch.",
        58 => "SASL Authentication failed.",
        59 => "This exception is raised by the broker if it could not locate the producer metadata associated with the producerId in question. This could \
            happen if, for instance, the producer's records were deleted because their retention time had elapsed. Once the last records of the producerId \
            are removed, the producer's metadata is removed from the broker, and future appends by the producer will return this exception.",
        79 => "The group member needs to have a valid member id before actually entering a consumer group.",
        _ => "The server experienced an unexpected error when processing the request.",
    }
    .to_string()
}

/// Whether the producer or consumer retries after this error code (`RetriableException`).
pub fn retriable(code: i16) -> bool {
    matches!(code, 2 | 3 | 5 | 6 | 7 | 13 | 14 | 15 | 16 | 19 | 20 | 56 | 74 | 75)
}

/// `Utils.murmur2`.
pub fn murmur2(data: &[u8]) -> i32 {
    let length = data.len() as i32;
    let seed: i32 = 0x9747b28cu32 as i32;
    let m: i32 = 0x5bd1e995;
    let r = 24;
    let mut h: i32 = seed ^ length;
    let length4 = data.len() / 4;
    for i in 0..length4 {
        let i4 = i * 4;
        let mut k: i32 =
            (data[i4] as i32 & 0xff) + ((data[i4 + 1] as i32 & 0xff) << 8) + ((data[i4 + 2] as i32 & 0xff) << 16) + ((data[i4 + 3] as i32 & 0xff) << 24);
        k = k.wrapping_mul(m);
        k ^= ((k as u32) >> r) as i32;
        k = k.wrapping_mul(m);
        h = h.wrapping_mul(m);
        h ^= k;
    }
    let tail = data.len() & !3;
    let rest = data.len() % 4;
    if rest == 3 {
        h ^= (data[tail + 2] as i32 & 0xff) << 16;
    }
    if rest >= 2 {
        h ^= (data[tail + 1] as i32 & 0xff) << 8;
    }
    if rest >= 1 {
        h ^= data[tail] as i32 & 0xff;
        h = h.wrapping_mul(m);
    }
    h ^= ((h as u32) >> 13) as i32;
    h = h.wrapping_mul(m);
    h ^= ((h as u32) >> 15) as i32;
    h
}

/// `BuiltInPartitioner.partitionForKey`.
pub fn partition_for_key(key: &[u8], partitions: usize) -> i32 {
    ((murmur2(key) & 0x7fffffff) as usize % partitions.max(1)) as i32
}

/// Reads a length-prefixed consumer-protocol structure (`ConsumerProtocol`): the version, then the fields.
pub fn read_versioned<T: Decodable>(mut data: Bytes) -> Result<(i16, T), Error> {
    if data.remaining() < 2 {
        return Err(Error::new("truncated consumer protocol data"));
    }
    let version = data.get_i16();
    let value = T::decode(&mut data, version).map_err(|e| Error::new(e.to_string()))?;
    Ok((version, value))
}

pub fn write_versioned<T: Encodable>(value: &T, version: i16) -> Result<Bytes, Error> {
    let mut out = BytesMut::new();
    out.put_i16(version);
    value.encode(&mut out, version).map_err(|e| Error::new(e.to_string()))?;
    Ok(out.freeze())
}

/// One record batch of a fetch answer, inflated as kafka-clients does for every `compression.type`: gzip and
/// snappy through `kafka-protocol`'s codecs, lz4 (the LZ4 frame format, `Lz4BlockInputStream`) and zstd (one or more
/// frames, `ZstdInputStreamNoFinalizer`) in pure Rust.
pub fn decode_record_batch(buf: &mut Bytes) -> Result<RecordSet, Error> {
    use kafka_protocol::compression::{Decompressor, Gzip, Snappy};
    use std::io::Read;
    let inflate = |data: &mut Bytes, compression: Compression| {
        match compression {
            Compression::None => Ok::<Bytes, _>(data.split_off(0)),
            Compression::Gzip => Gzip::decompress(data, |b| Ok(b.split_off(0))),
            Compression::Snappy => Snappy::decompress(data, |b| Ok(b.split_off(0))),
            Compression::Lz4 => {
                let mut out = Vec::new();
                lz4_flex::frame::FrameDecoder::new(data.as_ref()).read_to_end(&mut out)?;
                Ok(Bytes::from(out))
            }
            Compression::Zstd => {
                let mut out = Vec::new();
                let mut input: &[u8] = data.as_ref();
                while !input.is_empty() {
                    let mut frame = ruzstd::decoding::StreamingDecoder::new(&mut input).map_err(|e| std::io::Error::other(e.to_string()))?;
                    frame.read_to_end(&mut out)?;
                }
                Ok(Bytes::from(out))
            }
        }
    };
    RecordBatchDecoder::decode_with_custom_compression(buf, Some(inflate)).map_err(|e| Error::new(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The versions we send are kafka-clients 4.4.0's stable maxima (`ApiKeys.latestVersion(false)`); InitProducerId 6
    /// is `latestVersionUnstable`. OffsetCommit and OffsetFetch stop at the newest version `kafka-protocol` encodes.
    #[test]
    fn our_versions_reach_the_clients_stable_maxima() {
        for (key, want) in [
            (ApiKey::Produce, 13),
            (ApiKey::Fetch, 18),
            (ApiKey::ListOffsets, 11),
            (ApiKey::Metadata, 13),
            (ApiKey::FindCoordinator, 6),
            (ApiKey::JoinGroup, 9),
            (ApiKey::LeaveGroup, 5),
            (ApiKey::InitProducerId, 5),
            (ApiKey::OffsetCommit, 9),
            (ApiKey::OffsetFetch, 9),
        ] {
            assert_eq!(our_max(key as i16), want, "{key:?}");
        }
        // ListOffsets 11 is encoded with version 10's layout.
        assert_eq!(codec_version(ApiKey::ListOffsets as i16, 11), 10);
        assert_eq!(codec_version(ApiKey::Fetch as i16, 18), 18);
    }

    /// A negative frame size is refused; a size past the broker's `socket.request.max.bytes` is read on (the broker
    /// here closes before sending it).
    #[tokio::test]
    async fn negative_frames_are_refused_and_large_ones_read() {
        for (length, want) in [(-5, "Invalid receive (size = -5)"), (i32::MAX, "unexpected end of file")] {
            let (client, mut broker) = tokio::io::duplex(1024);
            let mut connection = Connection {
                stream: Box::new(client),
                correlation: Arc::new(AtomicI32::new(0)),
                versions: HashMap::new(),
                client_id: "c".into(),
                node: 1,
                in_flight: false,
                reserved: None,
            };
            tokio::spawn(async move {
                let mut request = [0u8; 256];
                let _ = broker.read(&mut request).await;
                let _ = broker.write_all(&length.to_be_bytes()).await;
                tokio::time::sleep(Duration::from_secs(1)).await;
            });
            let error = connection.exchange(ApiVersionsRequest::default(), 0).await.unwrap_err();
            assert_eq!(error.message, format!("Disconnected from node 1: {want}"));
        }
    }

    /// A fake broker on an ephemeral port: answers each request (api key, version, body after the request header)
    /// with `answer`'s response body, behind a v0 response header (v1 for flexible non-ApiVersions requests), and
    /// records every request it receives.
    async fn fake_broker(
        answer: fn(i16, i16, &[u8]) -> Bytes,
    ) -> (u16, Arc<Mutex<Vec<(i16, i16, Vec<u8>)>>>, tokio::task::JoinHandle<()>) {
        use kafka_protocol::protocol::decode_request_header_from_buffer;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let log = log.clone();
                tokio::spawn(async move {
                    loop {
                        let Ok(length) = socket.read_i32().await else { return };
                        let mut frame = vec![0u8; length as usize];
                        if socket.read_exact(&mut frame).await.is_err() {
                            return;
                        }
                        let mut buf = Bytes::from(frame);
                        let header = decode_request_header_from_buffer(&mut buf).unwrap();
                        let (key, version) = (header.request_api_key, header.request_api_version);
                        log.lock().push((key, version, buf.to_vec()));
                        let body = answer(key, version, &buf);
                        let mut out = BytesMut::new();
                        out.put_i32(header.correlation_id);
                        if key == ApiKey::Metadata as i16 && version >= 9 {
                            out.put_u8(0);
                        }
                        out.extend_from_slice(&body);
                        let mut framed = BytesMut::new();
                        framed.put_i32(out.len() as i32);
                        framed.extend_from_slice(&out);
                        if socket.write_all(&framed).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (port, seen, task)
    }

    /// An `ApiVersions` answer with `error`, listing ApiVersions up to `max` and Metadata 0-12.
    fn api_versions_answer(error: i16, max: i16, version: i16) -> Bytes {
        use kafka_protocol::messages::api_versions_response::ApiVersion;
        let response = ApiVersionsResponse::default().with_error_code(error).with_api_keys(vec![
            ApiVersion::default().with_api_key(ApiKey::ApiVersions as i16).with_min_version(0).with_max_version(max),
            ApiVersion::default().with_api_key(ApiKey::Metadata as i16).with_min_version(0).with_max_version(12),
        ]);
        let mut out = BytesMut::new();
        response.encode(&mut out, version.min(4)).unwrap();
        out.freeze()
    }

    fn settings(port: u16) -> Settings {
        Settings {
            bootstrap: vec![("127.0.0.1".into(), port)],
            protocol: Protocol::Plaintext,
            sasl: None,
            tls: None,
            client_id: "producer-1".into(),
            correlation: Arc::new(AtomicI32::new(0)),
        }
    }

    /// The v5 body after the request header: client software name and version (4.4.0), `ClusterId`, `NodeId`, no
    /// tagged fields.
    fn v5_body(cluster: Option<&str>, node: i32) -> Vec<u8> {
        let mut out = b"\x12apache-kafka-java\x064.4.0".to_vec();
        match cluster {
            Some(c) => {
                out.push(c.len() as u8 + 1);
                out.extend_from_slice(c.as_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&node.to_be_bytes());
        out.push(0);
        out
    }

    /// kafka-clients 4.4.0 sends ApiVersions v5: to a bootstrap address `ClusterId` null and `NodeId` -1 (even when a
    /// cluster id is known), to a broker the known cluster id and its node id, and null/-1 again while no cluster id
    /// is known.
    #[tokio::test]
    async fn api_versions_v5_carries_the_cluster_id_and_node_id_to_brokers() {
        let (port, seen, task) = fake_broker(|_, version, _| api_versions_answer(0, 5, version)).await;
        for (node, cluster) in [(-1, None), (-1, Some("Kp1sc0a8QdG")), (3, Some("Kp1sc0a8QdG")), (3, None)] {
            let connection = Connection::open("127.0.0.1", port, &settings(port), node, cluster).await.unwrap();
            assert_eq!(connection.version(ApiKey::ApiVersions as i16), Some(5));
        }
        let seen = seen.lock().clone();
        task.abort();
        let want = [v5_body(None, -1), v5_body(None, -1), v5_body(Some("Kp1sc0a8QdG"), 3), v5_body(None, -1)];
        assert_eq!(seen.len(), want.len());
        for ((key, version, body), want) in seen.into_iter().zip(want) {
            assert_eq!((key, version), (ApiKey::ApiVersions as i16, 5));
            assert_eq!(body, want);
        }
    }

    /// `UNSUPPORTED_VERSION` retries at the broker's listed version (v3 here, in v3's layout); any other error
    /// disconnects.
    #[tokio::test]
    async fn api_versions_falls_back_to_the_broker_version_and_disconnects_on_errors() {
        let (port, seen, task) = fake_broker(|_, version, _| if version == 5 { api_versions_answer(35, 3, 0) } else { api_versions_answer(0, 3, version) }).await;
        let connection = Connection::open("127.0.0.1", port, &settings(port), -1, None).await.unwrap();
        assert_eq!(connection.version(ApiKey::ApiVersions as i16), Some(3));
        assert_eq!(seen.lock().iter().map(|(_, v, _)| *v).collect::<Vec<_>>(), vec![5, 3]);
        assert_eq!(seen.lock()[1].2, b"\x12apache-kafka-java\x064.4.0\x00".to_vec());
        task.abort();
        let (port, _, task) = fake_broker(|_, version, _| api_versions_answer(31, 5, version)).await;
        let error = Connection::open("127.0.0.1", port, &settings(port), 2, None).await.err().unwrap();
        assert_eq!(error.message, "Received error 31 from node 2 when making an ApiVersionsRequest. Disconnecting.");
        task.abort();
    }

    /// A broker answering `REBOOTSTRAP_REQUIRED` makes the client forget its brokers and cluster id and drop its
    /// connections: the next cluster-wide request goes to the bootstrap server, with `ClusterId` null and `NodeId` -1.
    #[tokio::test]
    async fn rebootstrap_required_forgets_the_brokers() {
        static PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
        let (port, seen, task) = fake_broker(|key, version, body| {
            if key == ApiKey::Metadata as i16 {
                use kafka_protocol::messages::{BrokerId, metadata_response::MetadataResponseBroker};
                let broker = MetadataResponseBroker::default().with_node_id(BrokerId(7)).with_host(StrBytes::from_static_str("127.0.0.1")).with_port(PORT.load(Ordering::SeqCst) as i32);
                let response = MetadataResponse::default().with_cluster_id(Some(StrBytes::from_static_str("Kp1sc0a8QdG"))).with_brokers(vec![broker]);
                let mut out = BytesMut::new();
                response.encode(&mut out, version).unwrap();
                return out.freeze();
            }
            // To the broker (a known cluster id): stale metadata.
            let error = if body.ends_with(&[0, 0, 0, 7, 0]) { REBOOTSTRAP_REQUIRED } else { 0 };
            api_versions_answer(error, 5, version)
        })
        .await;
        PORT.store(port, Ordering::SeqCst);
        let cluster = Cluster::new(settings(port));
        cluster.refresh(&[]).await.unwrap();
        assert_eq!(cluster.address(7), Some(("127.0.0.1".into(), port)));
        assert_eq!(cluster.cluster_id.lock().as_deref(), Some("Kp1sc0a8QdG"));
        let error = cluster.send(7, MetadataRequest::default()).await.err().unwrap();
        assert_eq!(error.message, "Rebootstrap requested by server due to cluster metadata mismatch for cluster Kp1sc0a8QdG and node 7.");
        assert_eq!(cluster.address(7), None);
        assert_eq!(*cluster.cluster_id.lock(), None);
        assert_eq!(cluster.candidates(), vec![-1]);
        assert!(cluster.connections.lock().is_empty());
        cluster.refresh(&[]).await.unwrap();
        let seen = seen.lock().clone();
        task.abort();
        let api_versions: Vec<Vec<u8>> = seen.into_iter().filter(|(k, _, _)| *k == ApiKey::ApiVersions as i16).map(|(_, _, b)| b).collect();
        // The bootstrap connection, the broker's (refused), then the bootstrap server again after the rebootstrap.
        assert_eq!(api_versions, vec![v5_body(None, -1), v5_body(Some("Kp1sc0a8QdG"), 7), v5_body(None, -1)]);
    }

    /// A batch of two records compressed with `compression`, the codec's bytes written by `deflate`.
    fn compressed_batch(compression: Compression, deflate: fn(&[u8]) -> Vec<u8>) -> Bytes {
        use kafka_protocol::records::{Record, RecordBatchEncoder, RecordEncodeOptions, TimestampType};
        let record = |offset: i64, value: &'static str| Record {
            transactional: false,
            control: false,
            delete_horizon: false,
            partition_leader_epoch: -1,
            producer_id: -1,
            producer_epoch: -1,
            timestamp_type: TimestampType::Creation,
            offset,
            sequence: offset as i32,
            timestamp: 1,
            key: None,
            value: Some(Bytes::from_static(value.as_bytes())),
            headers: Default::default(),
        };
        let records = [record(0, "{\"n\":1}"), record(1, "{\"n\":2}")];
        let mut out = BytesMut::new();
        RecordBatchEncoder::encode_with_custom_compression(
            &mut out,
            records.iter(),
            &RecordEncodeOptions { version: 2, compression },
            Some(|raw: &mut BytesMut, out: &mut BytesMut, _: Compression| {
                out.put_slice(&deflate(raw));
                Ok(())
            }),
        )
        .unwrap();
        out.freeze()
    }

    /// Batches as kafka-clients' `Lz4BlockOutputStream` and `ZstdOutputStream` write them are inflated (the zstd one as
    /// two frames, which `ZstdInputStreamNoFinalizer` reads on).
    #[test]
    fn lz4_and_zstd_batches_are_decoded() {
        use std::io::Write;
        let lz4 = |raw: &[u8]| {
            let mut encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
            encoder.write_all(raw).unwrap();
            encoder.finish().unwrap()
        };
        let zstd = |raw: &[u8]| {
            let (first, second) = raw.split_at(raw.len() / 2);
            let level = ruzstd::encoding::CompressionLevel::Fastest;
            let mut out = ruzstd::encoding::compress_to_vec(first, level);
            out.extend(ruzstd::encoding::compress_to_vec(second, level));
            out
        };
        for (compression, deflate) in [(Compression::Lz4, lz4 as fn(&[u8]) -> Vec<u8>), (Compression::Zstd, zstd), (Compression::None, |r: &[u8]| r.to_vec())] {
            let mut buf = compressed_batch(compression, deflate);
            let set = decode_record_batch(&mut buf).unwrap();
            assert_eq!(set.compression, compression);
            let values: Vec<_> = set.records.iter().map(|r| (r.offset, r.value.clone().unwrap())).collect();
            assert_eq!(values, vec![(0, Bytes::from_static(b"{\"n\":1}")), (1, Bytes::from_static(b"{\"n\":2}"))], "{compression:?}");
            assert!(!buf.has_remaining());
        }
    }

    /// `UtilsTest.testMurmur2` vectors.
    #[test]
    fn murmur2_matches_kafka() {
        let cases: &[(&[u8], i32)] = &[
            (b"21", -973932308),
            (b"foobar", -790332482),
            (b"a-little-bit-long-string", -985981536),
            (b"a-little-bit-longer-string", -1486304829),
            (b"lkjh234lh9fiuh90y23oiuhsafujhadof229phr9h19h89h8", -58897971),
            (b"abc", 479470107),
        ];
        for (data, want) in cases {
            assert_eq!(murmur2(data), *want, "{:?}", String::from_utf8_lossy(data));
        }
    }
}
