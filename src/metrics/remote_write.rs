//! `PrometheusRemoteWriteExporter` (`prometheusRemoteWriteEnabled`): every `prometheusRemoteWriteIntervalSeconds`,
//! the families `GET /mockserver/metrics` serves ([`super::snapshots`]) are encoded as a Remote-Write v1
//! `WriteRequest` or 2.0 `Request` (`prometheusRemoteWriteProtocolVersion`), Snappy-compressed in the raw block format
//! and POSTed to `prometheusRemoteWriteUrl`. Fail-soft throughout: a failed push is logged and the next one runs.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;

use super::{bucket_bound, Attributes, Data, Snapshot};

/// `RemoteWriteEncoder`: the protocol version a push is encoded in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoder {
    /// `RemoteWriteV1Encoder`.
    V1,
    /// `RemoteWriteV2Encoder`.
    V2,
}

impl Encoder {
    /// `PrometheusRemoteWriteExporter.selectEncoder`: `v2` (trimmed, any case) selects 2.0; anything else, blank or
    /// absent fails safe to v1.
    pub fn select(version: Option<&str>) -> Encoder {
        match version {
            Some(v) if v.trim().eq_ignore_ascii_case("v2") => Encoder::V2,
            _ => Encoder::V1,
        }
    }

    /// The uncompressed protobuf body, every sample stamped `timestamp_millis`.
    pub fn encode(&self, snapshots: &[Snapshot], timestamp_millis: i64) -> Vec<u8> {
        match self {
            Encoder::V1 => encode_v1(snapshots, timestamp_millis),
            Encoder::V2 => encode_v2(snapshots, timestamp_millis),
        }
    }

    pub fn content_type(&self) -> &'static str {
        match self {
            Encoder::V1 => "application/x-protobuf",
            Encoder::V2 => "application/x-protobuf;proto=io.prometheus.write.v2.Request",
        }
    }

    /// The `X-Prometheus-Remote-Write-Version` header.
    pub fn protocol_version_header(&self) -> &'static str {
        match self {
            Encoder::V1 => "0.1.0",
            Encoder::V2 => "2.0.0",
        }
    }
}

/// `SnappyBlock.compress`: Snappy's raw block format, not the framed one.
pub fn compress(raw: &[u8]) -> Vec<u8> {
    snap::raw::Encoder::new().compress_vec(raw).unwrap_or_default()
}

/// A protobuf message under construction (`CodedOutputStream`).
#[derive(Default)]
struct Message(Vec<u8>);

impl Message {
    fn varint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.0.push((v as u8) | 0x80);
            v >>= 7;
        }
        self.0.push(v as u8);
    }

    fn tag(&mut self, field: u32, wire_type: u32) {
        self.varint(u64::from(field << 3 | wire_type));
    }

    /// `writeByteArray` / `writeString`: a length-delimited field.
    fn bytes(&mut self, field: u32, value: &[u8]) {
        self.tag(field, 2);
        self.varint(value.len() as u64);
        self.0.extend_from_slice(value);
    }

    /// `writeDouble`.
    fn double(&mut self, field: u32, value: f64) {
        self.tag(field, 1);
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    /// `writeInt64` / `writeInt32` / `writeUInt32`: a varint, negatives as their 64-bit two's complement.
    fn int(&mut self, field: u32, value: i64) {
        self.tag(field, 0);
        self.varint(value as u64);
    }
}

/// One series of a family in Prometheus text naming: its name, labels, an `le` label, and value.
type Series<'a> = (String, &'a Attributes, Option<String>, f64);

/// The samples a family stands for, as the text exposition writes them: a counter's `_total`, a gauge's own name, a
/// histogram's cumulative `_bucket{le}` series (`+Inf` the total), `_count` and `_sum`.
fn series(snapshot: &Snapshot) -> Vec<Series<'_>> {
    let base = &snapshot.name;
    match &snapshot.data {
        Data::Counter(points) => points.iter().map(|(l, v)| (format!("{base}_total"), l, None, *v)).collect(),
        Data::Gauge(points) => points.iter().map(|(l, v)| (base.clone(), l, None, *v)).collect(),
        Data::Histogram(points) => {
            let mut out = Vec::new();
            for p in points {
                let mut cumulative = 0;
                let mut positive_inf = false;
                for (bound, n) in &p.buckets {
                    cumulative += n;
                    let infinite = *bound == f64::INFINITY;
                    let value = if infinite { p.count } else { cumulative };
                    out.push((format!("{base}_bucket"), &p.labels, Some(bucket_bound(*bound)), value as f64));
                    positive_inf |= infinite;
                }
                if !positive_inf {
                    out.push((format!("{base}_bucket"), &p.labels, Some("+Inf".into()), p.count as f64));
                }
                out.push((format!("{base}_count"), &p.labels, None, p.count as f64));
                out.push((format!("{base}_sum"), &p.labels, None, p.sum));
            }
            out
        }
    }
}

/// `__name__`, the point's labels and any `le`, sorted by name as Remote-Write requires.
fn sorted_labels<'a>(name: &'a str, labels: &'a Attributes, le: Option<&'a str>) -> Vec<(&'a str, &'a str)> {
    let mut all: Vec<(&str, &str)> = vec![("__name__", name)];
    all.extend(labels.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    if let Some(le) = le {
        all.push(("le", le));
    }
    all.sort_by(|a, b| a.0.cmp(b.0));
    all
}

fn sample(value: f64, timestamp: i64) -> Vec<u8> {
    let mut m = Message::default();
    m.double(1, value);
    m.int(2, timestamp);
    m.0
}

/// `WriteRequest { repeated TimeSeries timeseries = 1 }`, `TimeSeries { repeated Label labels = 1; repeated Sample
/// samples = 2 }`, `Label { string name = 1; string value = 2 }`, `Sample { double value = 1; int64 timestamp = 2 }`.
fn encode_v1(snapshots: &[Snapshot], timestamp: i64) -> Vec<u8> {
    let mut body = Message::default();
    for snapshot in snapshots {
        for (name, labels, le, value) in series(snapshot) {
            let mut ts = Message::default();
            for (k, v) in sorted_labels(&name, labels, le.as_deref()) {
                let mut label = Message::default();
                label.bytes(1, k.as_bytes());
                label.bytes(2, v.as_bytes());
                ts.bytes(1, &label.0);
            }
            ts.bytes(2, &sample(value, timestamp));
            body.bytes(1, &ts.0);
        }
    }
    body.0
}

/// The interned strings of one 2.0 request, in index order; index 0 is the empty string.
#[derive(Default)]
struct Symbols {
    order: Vec<String>,
    index: std::collections::HashMap<String, u64>,
}

impl Symbols {
    fn intern(&mut self, value: &str) -> u64 {
        if let Some(i) = self.index.get(value) {
            return *i;
        }
        let i = self.order.len() as u64;
        self.order.push(value.to_string());
        self.index.insert(value.to_string(), i);
        i
    }
}

/// `Request { repeated string symbols = 4; repeated TimeSeries timeseries = 5 }`, `TimeSeries { repeated uint32
/// labels_refs = 1 [packed]; repeated Sample samples = 2; Metadata metadata = 5 }`, `Metadata { MetricType type = 1;
/// uint32 help_ref = 3 }`; every string interned once, the symbols written before the series that refer to them.
fn encode_v2(snapshots: &[Snapshot], timestamp: i64) -> Vec<u8> {
    let mut symbols = Symbols::default();
    symbols.intern("");
    let mut all_series = Vec::new();
    for snapshot in snapshots {
        let help = if snapshot.help.trim().is_empty() { 0 } else { symbols.intern(&snapshot.help) };
        let kind = match snapshot.data {
            Data::Counter(_) => 1,
            Data::Gauge(_) => 2,
            Data::Histogram(_) => 3,
        };
        for (name, labels, le, value) in series(snapshot) {
            let mut refs = Message::default();
            for (k, v) in sorted_labels(&name, labels, le.as_deref()) {
                let k = symbols.intern(k);
                refs.varint(k);
                let v = symbols.intern(v);
                refs.varint(v);
            }
            let mut metadata = Message::default();
            metadata.int(1, kind);
            if help > 0 {
                metadata.int(3, help as i64);
            }
            let mut ts = Message::default();
            ts.bytes(1, &refs.0);
            ts.bytes(2, &sample(value, timestamp));
            ts.bytes(5, &metadata.0);
            all_series.push(ts.0);
        }
    }
    let mut body = Message::default();
    for symbol in &symbols.order {
        body.bytes(4, symbol.as_bytes());
    }
    for ts in all_series {
        body.bytes(5, &ts);
    }
    body.0
}

/// `PrometheusRemoteWriteExporter.parseHeaders`: `k=v,k2=v2`, keys and values trimmed, split at the first `=`;
/// entries without one or with an empty key are skipped; a repeated key keeps its first place and its last value.
pub fn parse_headers(raw: Option<&str>) -> Vec<(String, String)> {
    let mut parsed: Vec<(String, String)> = Vec::new();
    for entry in raw.unwrap_or_default().split(',') {
        let Some((key, value)) = entry.split_once('=').filter(|(k, _)| !k.is_empty()) else { continue };
        let (key, value) = (key.trim(), value.trim());
        if !key.is_empty() {
            put(&mut parsed, key, value);
        }
    }
    parsed
}

fn put(headers: &mut Vec<(String, String)>, key: &str, value: &str) {
    match headers.iter_mut().find(|(k, _)| k == key) {
        Some(existing) => existing.1 = value.to_string(),
        None => headers.push((key.to_string(), value.to_string())),
    }
}

/// `PrometheusRemoteWriteExporter.resolveHeaders`: `Authorization` from the bearer token, else basic auth, then the
/// custom headers over it, so a configured `Authorization` wins.
pub fn resolve_headers(bearer_token: Option<&str>, username: Option<&str>, password: Option<&str>, custom: Option<&str>) -> Vec<(String, String)> {
    fn not_blank(v: Option<&str>) -> Option<&str> {
        v.filter(|v| !v.trim().is_empty())
    }
    let mut resolved = Vec::new();
    if let Some(token) = not_blank(bearer_token) {
        resolved.push(("Authorization".to_string(), format!("Bearer {}", token.trim())));
    } else if let Some(user) = not_blank(username) {
        let credentials = format!("{}:{}", user.trim(), password.unwrap_or_default());
        resolved.push(("Authorization".to_string(), format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(credentials))));
    }
    for (k, v) in parse_headers(custom) {
        put(&mut resolved, &k, &v);
    }
    resolved
}

/// A configured exporter: where it pushes, in which version, with which extra headers.
pub struct Exporter {
    url: String,
    target: crate::telemetry::Target,
    pub encoder: Encoder,
    headers: Vec<(String, String)>,
}

impl Exporter {
    /// `None` for a URL that is not `http(s)://`.
    pub fn new(url: &str, encoder: Encoder, headers: Vec<(String, String)>) -> Option<Exporter> {
        let url = url.trim();
        Some(Exporter { url: url.to_string(), target: crate::telemetry::Target::parse(url)?, encoder, headers })
    }

    /// `pushOnce`: encode, compress and POST `snapshots`; the warning upstream logs when the push failed or was
    /// answered with anything but 2xx.
    pub async fn push_once(&self, config: &crate::Config, snapshots: &[Snapshot]) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        let body = compress(&self.encoder.encode(snapshots, now));
        let mut headers = vec![
            ("Content-Type".to_string(), self.encoder.content_type().to_string()),
            ("Content-Encoding".to_string(), "snappy".to_string()),
            ("X-Prometheus-Remote-Write-Version".to_string(), self.encoder.protocol_version_header().to_string()),
        ];
        headers.extend(self.headers.iter().cloned());
        match self.target.send(config, headers, body, Duration::from_secs(10), Duration::from_secs(30)).await {
            Ok((status, _)) if (200..300).contains(&status) => Ok(()),
            Ok((status, answer)) => Err(format!("Prometheus remote-write POST to {} returned HTTP {status}{}", self.url, body_prefix(&answer))),
            Err(message) => Err(format!("Prometheus remote-write POST to {} failed: {message}", self.url)),
        }
    }
}

/// `bodyPrefix`: up to 256 bytes of the answer, whitespace runs collapsed, after ` - `.
fn body_prefix(body: &[u8]) -> String {
    if body.is_empty() {
        return String::new();
    }
    let text = String::from_utf8_lossy(&body[..body.len().min(256)]);
    format!(" - {}", text.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// `startIfEnabled`: with `prometheusRemoteWriteEnabled` and a `prometheusRemoteWriteUrl`, pushes every
/// `prometheusRemoteWriteIntervalSeconds` (at least 1, default 60) after the first interval, until the server stops.
/// Returns whether it started.
pub fn start(state: &Arc<crate::state::State>) -> bool {
    let config = &state.config;
    if !config.bool_property("prometheusRemoteWriteEnabled", false) {
        return false;
    }
    let Some(url) = config.property("prometheusRemoteWriteUrl").filter(|u| !u.trim().is_empty()) else {
        crate::log::warn(state, "Prometheus remote-write is enabled but no URL is configured (mockserver.prometheusRemoteWriteUrl); skipping");
        return false;
    };
    let interval = Duration::from_secs(config.int_property("prometheusRemoteWriteIntervalSeconds", 60).max(1) as u64);
    let encoder = Encoder::select(config.property("prometheusRemoteWriteProtocolVersion").as_deref());
    let headers = resolve_headers(
        config.property("prometheusRemoteWriteBearerToken").as_deref(),
        config.property("prometheusRemoteWriteBasicAuthUsername").as_deref(),
        config.property("prometheusRemoteWriteBasicAuthPassword").as_deref(),
        config.property("prometheusRemoteWriteHeaders").as_deref(),
    );
    let auth = if headers.iter().any(|(k, _)| k == "Authorization") { "configured" } else { "none" };
    let Some(exporter) = Exporter::new(&url, encoder, headers) else {
        crate::log::warn(state, &format!("failed to start Prometheus remote-write export (unsupported URL {}); continuing without it", url.trim()));
        return false;
    };
    crate::log::info(
        state,
        &format!("Prometheus remote-write export enabled (url {}, interval {}s, version {}, auth {auth})", url.trim(), interval.as_secs(), encoder.protocol_version_header()),
    );
    let weak = Arc::downgrade(state);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.tick().await;
        loop {
            tick.tick().await;
            let Some(state) = weak.upgrade().filter(|s| s.is_running()) else {
                return;
            };
            // The registry holds MockServer's families only while `metricsEnabled`.
            let snapshots = if super::enabled(&state.config) { super::snapshots(&state) } else { Vec::new() };
            if let Err(warning) = exporter.push_once(&state.config, &snapshots).await {
                crate::log::warn(&state, &warning);
            }
        }
    });
    true
}

/// Ports of `RemoteWriteV1EncoderTest`, `RemoteWriteV2EncoderTest` and `PrometheusRemoteWriteExporterTest`. The bodies
/// are read back with an independent protobuf reader, not the encoder.
#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::time::Duration;

    use super::*;
    use crate::metrics::HistogramPoint;

    const TIMESTAMP: i64 = 1_700_000_000_123;

    fn labels(pairs: &[(&str, &str)]) -> Attributes {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// The registry of both encoder tests: a counter, a gauge and a classic histogram with bounds 1.0 and 2.5 that
    /// observed 0.5, 2.0 and 5.0.
    fn registry() -> Vec<Snapshot> {
        vec![
            Snapshot { name: "test_counter".into(), help: "a test counter".into(), data: Data::Counter(vec![(labels(&[("method", "GET")]), 5.0)]) },
            Snapshot { name: "test_gauge".into(), help: "a test gauge".into(), data: Data::Gauge(vec![(labels(&[("state", "active")]), 42.0)]) },
            Snapshot {
                name: "test_histogram".into(),
                help: "a test histogram".into(),
                data: Data::Histogram(vec![HistogramPoint { labels: labels(&[("path", "/x")]), buckets: vec![(1.0, 1), (2.5, 1), (f64::INFINITY, 1)], count: 3, sum: 7.5, exemplars: Vec::new() }]),
            },
        ]
    }

    /// A protobuf reader: each field's number and its varint, fixed64 or length-delimited payload.
    enum Field<'a> {
        Varint(u64),
        Fixed64([u8; 8]),
        Bytes(&'a [u8]),
    }

    fn read_varint(bytes: &[u8], at: &mut usize) -> u64 {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let b = bytes[*at];
            *at += 1;
            value |= u64::from(b & 0x7f) << shift;
            if b < 0x80 {
                return value;
            }
            shift += 7;
        }
    }

    fn fields(bytes: &[u8]) -> Vec<(u64, Field<'_>)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let tag = read_varint(bytes, &mut at);
            let field = match tag & 7 {
                0 => Field::Varint(read_varint(bytes, &mut at)),
                1 => {
                    at += 8;
                    Field::Fixed64(bytes[at - 8..at].try_into().unwrap())
                }
                2 => {
                    let length = read_varint(bytes, &mut at) as usize;
                    at += length;
                    Field::Bytes(&bytes[at - length..at])
                }
                other => panic!("unexpected wire type {other}"),
            };
            out.push((tag >> 3, field));
        }
        out
    }

    fn text(field: &Field<'_>) -> String {
        match field {
            Field::Bytes(b) => String::from_utf8(b.to_vec()).unwrap(),
            _ => panic!("not a string"),
        }
    }

    fn decode_sample(bytes: &[u8]) -> (f64, i64) {
        let (mut value, mut timestamp) = (0.0, 0);
        for (n, f) in fields(bytes) {
            match (n, f) {
                (1, Field::Fixed64(b)) => value = f64::from_le_bytes(b),
                (2, Field::Varint(v)) => timestamp = v as i64,
                _ => {}
            }
        }
        (value, timestamp)
    }

    /// A decoded series: value, timestamp, metric type (v2 only, else -1) and the labels in wire order.
    struct Decoded {
        value: f64,
        timestamp: i64,
        metric_type: i64,
        order: Vec<String>,
    }

    /// The key both decoders file a series under: its labels sorted by name.
    fn key(pairs: &[(&str, &str)]) -> String {
        format!("{:?}", pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<BTreeMap<_, _>>())
    }

    fn file(series: &mut HashMap<String, Decoded>, wire: Vec<(String, String)>, value: f64, timestamp: i64, metric_type: i64) {
        let order = wire.iter().map(|(k, _)| k.clone()).collect();
        let sorted: BTreeMap<String, String> = wire.into_iter().collect();
        series.insert(format!("{sorted:?}"), Decoded { value, timestamp, metric_type, order });
    }

    fn decode_v1(bytes: &[u8]) -> HashMap<String, Decoded> {
        let mut series = HashMap::new();
        for (n, ts) in fields(bytes) {
            let Field::Bytes(ts) = ts else { continue };
            assert_eq!(n, 1);
            let mut wire = Vec::new();
            let mut sample = (0.0, 0);
            for (n, f) in fields(ts) {
                match (n, f) {
                    (1, Field::Bytes(label)) => {
                        let parts = fields(label);
                        wire.push((text(&parts[0].1), text(&parts[1].1)));
                    }
                    (2, Field::Bytes(s)) => sample = decode_sample(s),
                    _ => {}
                }
            }
            file(&mut series, wire, sample.0, sample.1, -1);
        }
        series
    }

    fn decode_v2(bytes: &[u8]) -> (Vec<String>, HashMap<String, Decoded>) {
        let mut symbols = Vec::new();
        let mut raw_series = Vec::new();
        for (n, f) in fields(bytes) {
            match n {
                4 => symbols.push(text(&f)),
                5 => raw_series.push(f),
                _ => {}
            }
        }
        let mut series = HashMap::new();
        for ts in raw_series {
            let Field::Bytes(ts) = ts else { continue };
            let (mut refs, mut sample, mut metric_type) = (Vec::new(), (0.0, 0), -1);
            for (n, f) in fields(ts) {
                match (n, f) {
                    (1, Field::Bytes(packed)) => {
                        let mut at = 0;
                        while at < packed.len() {
                            refs.push(read_varint(packed, &mut at) as usize);
                        }
                    }
                    (2, Field::Bytes(s)) => sample = decode_sample(s),
                    (5, Field::Bytes(m)) => {
                        for (n, f) in fields(m) {
                            if let (1, Field::Varint(v)) = (n, f) {
                                metric_type = v as i64;
                            }
                        }
                    }
                    _ => {}
                }
            }
            let wire = refs.chunks(2).map(|p| (symbols[p[0]].clone(), symbols[p[1]].clone())).collect();
            file(&mut series, wire, sample.0, sample.1, metric_type);
        }
        (symbols, series)
    }

    fn round_trip(encoded: &[u8]) -> Vec<u8> {
        let back = snap::raw::Decoder::new().decompress_vec(&compress(encoded)).unwrap();
        assert_eq!(back, encoded, "snappy round-trips the body losslessly");
        back
    }

    #[test]
    fn v1_encodes_counter_gauge_and_classic_histogram() {
        let series = decode_v1(&round_trip(&Encoder::V1.encode(&registry(), TIMESTAMP)));
        let counter = &series[&key(&[("__name__", "test_counter_total"), ("method", "GET")])];
        assert_eq!((counter.value, counter.timestamp), (5.0, TIMESTAMP));
        assert_eq!(series[&key(&[("__name__", "test_gauge"), ("state", "active")])].value, 42.0);
        let bucket = |le: &str| &series[&key(&[("__name__", "test_histogram_bucket"), ("path", "/x"), ("le", le)])];
        assert_eq!((bucket("1.0").value, bucket("2.5").value, bucket("+Inf").value), (1.0, 2.0, 3.0));
        assert_eq!(series[&key(&[("__name__", "test_histogram_count"), ("path", "/x")])].value, 3.0);
        assert_eq!(series[&key(&[("__name__", "test_histogram_sum"), ("path", "/x")])].value, 7.5);
        assert!(!series.contains_key(&key(&[])));
        // the wire order is sorted by name: __name__ < le < path, __name__ < method
        assert_eq!(bucket("1.0").order, ["__name__", "le", "path"]);
        assert_eq!(bucket("+Inf").order, ["__name__", "le", "path"]);
        assert_eq!(counter.order, ["__name__", "method"]);
    }

    #[test]
    fn v2_encodes_counter_gauge_and_classic_histogram_with_symbol_table() {
        let (symbols, series) = decode_v2(&round_trip(&Encoder::V2.encode(&registry(), TIMESTAMP)));
        assert_eq!(symbols[0], "");
        let counter = &series[&key(&[("__name__", "test_counter_total"), ("method", "GET")])];
        assert_eq!((counter.value, counter.timestamp, counter.metric_type), (5.0, TIMESTAMP, 1));
        let gauge = &series[&key(&[("__name__", "test_gauge"), ("state", "active")])];
        assert_eq!((gauge.value, gauge.metric_type), (42.0, 2));
        let bucket = |le: &str| &series[&key(&[("__name__", "test_histogram_bucket"), ("path", "/x"), ("le", le)])];
        assert_eq!((bucket("1.0").value, bucket("2.5").value, bucket("+Inf").value), (1.0, 2.0, 3.0));
        assert_eq!(bucket("+Inf").metric_type, 3);
        assert_eq!(series[&key(&[("__name__", "test_histogram_count"), ("path", "/x")])].value, 3.0);
        assert_eq!(series[&key(&[("__name__", "test_histogram_sum"), ("path", "/x")])].value, 7.5);
        assert!(!series.contains_key(&key(&[])));
        assert_eq!(bucket("1.0").order, ["__name__", "le", "path"]);
        assert_eq!(bucket("+Inf").order, ["__name__", "le", "path"]);
        assert_eq!(counter.order, ["__name__", "method"]);
        // interning: "/x" (five series) and __name__ (every series) once each; the help string is a symbol
        assert_eq!(symbols.iter().filter(|s| *s == "/x").count(), 1);
        assert_eq!(symbols.iter().filter(|s| *s == "__name__").count(), 1);
        assert!(symbols.iter().any(|s| s == "a test counter"));
    }

    /// One remote-write POST received by a sink: its request head (names lower-cased) and body; answered 204.
    async fn receive(sink: &tokio::net::TcpListener) -> (String, HashMap<String, String>, Vec<u8>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut c, _) = tokio::time::timeout(Duration::from_secs(10), sink.accept()).await.expect("a push within 10 s").unwrap();
        let mut raw = Vec::new();
        let mut buf = [0u8; 16384];
        loop {
            if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&raw[..end]).to_string();
                let headers: HashMap<String, String> =
                    head.lines().skip(1).filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
                let length: usize = headers["content-length"].parse().unwrap();
                if raw.len() >= end + 4 + length {
                    let _ = c.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
                    let request_line = head.lines().next().unwrap_or_default().to_string();
                    return (request_line, headers, raw[end + 4..end + 4 + length].to_vec());
                }
            }
            let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await.expect("the push's body").unwrap();
            assert!(n > 0, "push connection closed early");
            raw.extend_from_slice(&buf[..n]);
        }
    }

    fn counter(name: &str, value: f64) -> Vec<Snapshot> {
        vec![Snapshot { name: name.into(), help: "h".into(), data: Data::Counter(vec![(Vec::new(), value)]) }]
    }

    #[tokio::test]
    async fn push_once_sends_compressed_remote_write_with_headers_and_body() {
        let sink = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}/api/v1/write", sink.local_addr().unwrap().port());
        let exporter = Exporter::new(&url, Encoder::V1, vec![("X-Scope-OrgID".into(), "tenant-a".into())]).unwrap();
        let config = crate::Config::for_tests();
        let snapshots = counter("test_push", 3.0);
        let (pushed, received) = tokio::join!(exporter.push_once(&config, &snapshots), receive(&sink));
        assert_eq!(pushed, Ok(()));
        let (request_line, headers, body) = received;
        assert!(request_line.starts_with("POST /api/v1/write "), "{request_line}");
        assert_eq!(headers["content-encoding"], "snappy");
        assert_eq!(headers["content-type"], "application/x-protobuf");
        assert_eq!(headers["x-prometheus-remote-write-version"], "0.1.0");
        assert_eq!(headers["x-scope-orgid"], "tenant-a");
        let body = snap::raw::Decoder::new().decompress_vec(&body).unwrap();
        assert!(body.windows(15).any(|w| w == b"test_push_total"));
    }

    #[tokio::test]
    async fn push_once_with_v2_encoder_sends_v2_content_type_and_version_headers() {
        let sink = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}/api/v1/write", sink.local_addr().unwrap().port());
        let exporter = Exporter::new(&url, Encoder::V2, Vec::new()).unwrap();
        let config = crate::Config::for_tests();
        let snapshots = counter("test_push_v2", 2.0);
        let (pushed, (_, headers, _)) = tokio::join!(exporter.push_once(&config, &snapshots), receive(&sink));
        assert_eq!(pushed, Ok(()));
        assert_eq!(headers["content-encoding"], "snappy");
        assert_eq!(headers["content-type"], "application/x-protobuf;proto=io.prometheus.write.v2.Request");
        assert_eq!(headers["x-prometheus-remote-write-version"], "2.0.0");
    }

    #[test]
    fn v2_encoder_reports_v2_content_type_and_version() {
        assert_eq!(Encoder::V2.content_type(), "application/x-protobuf;proto=io.prometheus.write.v2.Request");
        assert_eq!(Encoder::V2.protocol_version_header(), "2.0.0");
    }

    #[test]
    fn select_encoder_chooses_v2_only_for_v2_and_fails_safe_to_v1_otherwise() {
        assert_eq!(Encoder::select(Some("v2")), Encoder::V2);
        assert_eq!(Encoder::select(Some(" V2 ")), Encoder::V2);
        for version in [Some("v1"), Some("V1"), Some(""), Some("  "), Some("nonsense"), None] {
            assert_eq!(Encoder::select(version), Encoder::V1, "version={version:?}");
        }
    }

    /// PrometheusRemoteWriteProtocolVersionConfigurationTest: defaultsToV1WhenUnset, honoursSystemPropertyOverride,
    /// roundTripsViaSetter (a property set on the configuration is both).
    #[test]
    fn protocol_version_configuration_defaults_to_v1_and_honours_override() {
        let effective = |config: &crate::Config| crate::config::effective_json(config)["prometheusRemoteWriteProtocolVersion"].clone();
        let version = |config: &crate::Config| config.property("prometheusRemoteWriteProtocolVersion");
        let unset = crate::Config::for_tests();
        assert_eq!(effective(&unset), "v1");
        assert_eq!(Encoder::select(version(&unset).as_deref()), Encoder::V1);
        let config = crate::Config::for_tests().with_property("prometheusRemoteWriteProtocolVersion", "v2");
        assert_eq!(effective(&config), "v2");
        assert_eq!(Encoder::select(version(&config).as_deref()), Encoder::V2);
    }

    #[tokio::test]
    async fn push_once_is_fail_soft_when_endpoint_unreachable() {
        // A refusing port: the POST fails and comes back as the warning upstream logs, never a panic.
        let exporter = Exporter::new("http://127.0.0.1:1/api/v1/write", Encoder::V1, Vec::new()).unwrap();
        let pushed = exporter.push_once(&crate::Config::for_tests(), &counter("test_soft", 1.0)).await;
        let warning = pushed.unwrap_err();
        assert!(warning.starts_with("Prometheus remote-write POST to http://127.0.0.1:1/api/v1/write failed: "), "{warning}");
    }

    fn authorization(headers: &[(String, String)]) -> Option<&str> {
        headers.iter().find(|(k, _)| k == "Authorization").map(|(_, v)| v.as_str())
    }

    #[test]
    fn bearer_token_takes_precedence_over_basic_auth() {
        assert_eq!(authorization(&resolve_headers(Some("my-token"), Some("user"), Some("pass"), Some(""))), Some("Bearer my-token"));
    }

    #[test]
    fn basic_auth_used_when_no_bearer_token() {
        let expected = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("user:pass"));
        assert_eq!(authorization(&resolve_headers(Some(""), Some("user"), Some("pass"), Some(""))), Some(expected.as_str()));
    }

    #[test]
    fn custom_header_overrides_derived_auth_header() {
        let resolved = resolve_headers(Some("my-token"), Some(""), Some(""), Some("Authorization=Custom xyz,X-Extra=1"));
        assert_eq!(authorization(&resolved), Some("Custom xyz"));
        assert!(resolved.contains(&("X-Extra".into(), "1".into())));
    }

    #[test]
    fn no_auth_when_neither_bearer_nor_basic_configured() {
        assert_eq!(authorization(&resolve_headers(Some(""), Some(""), Some(""), Some(""))), None);
    }

    #[test]
    fn parse_headers_trims_and_skips_malformed_entries() {
        let parsed = parse_headers(Some(" A = 1 , B=2, ,noEquals, =emptyKey, C=has=equals "));
        assert_eq!(parsed, [("A".to_string(), "1".to_string()), ("B".into(), "2".into()), ("C".into(), "has=equals".into())]);
    }

    #[test]
    fn parse_headers_on_blank_returns_empty_map() {
        assert!(parse_headers(None).is_empty());
        assert!(parse_headers(Some("   ")).is_empty());
    }

    fn state(properties: &[(&str, &str)]) -> std::sync::Arc<crate::state::State> {
        let mut config = crate::Config::for_tests();
        for (k, v) in properties {
            config = config.with_property(k, v);
        }
        crate::state::State::new(config, Vec::new())
    }

    #[tokio::test]
    async fn start_if_enabled_returns_null_when_disabled() {
        assert!(!start(&state(&[("prometheusRemoteWriteEnabled", "false")])));
    }

    #[tokio::test]
    async fn start_if_enabled_returns_null_when_url_blank() {
        assert!(!start(&state(&[("prometheusRemoteWriteEnabled", "true"), ("prometheusRemoteWriteUrl", "")])));
    }

    #[tokio::test]
    async fn start_if_enabled_starts_when_enabled_with_url() {
        assert!(start(&state(&[("prometheusRemoteWriteEnabled", "true"), ("prometheusRemoteWriteUrl", "http://127.0.0.1:1/api/v1/write")])));
    }

    /// End to end: a server started with `metricsEnabled` and remote write on pushes the families its exposition
    /// serves, every `prometheusRemoteWriteIntervalSeconds`.
    #[tokio::test(flavor = "multi_thread")]
    async fn server_pushes_its_metrics_every_interval() {
        let sink = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}/api/v1/write", sink.local_addr().unwrap().port());
        let config = crate::Config::for_tests()
            .with_property("metricsEnabled", "true")
            .with_property("prometheusRemoteWriteEnabled", "true")
            .with_property("prometheusRemoteWriteIntervalSeconds", "1")
            .with_property("prometheusRemoteWriteProtocolVersion", "v2")
            .with_property("prometheusRemoteWriteBearerToken", "t0k")
            .with_property("prometheusRemoteWriteUrl", &url);
        let server = crate::Server::start(config).await.unwrap();
        let (_, headers, body) = receive(&sink).await;
        let _ = server.stop_async().await;
        assert_eq!(headers["authorization"], "Bearer t0k");
        assert_eq!(headers["x-prometheus-remote-write-version"], "2.0.0");
        let (symbols, series) = decode_v2(&snap::raw::Decoder::new().decompress_vec(&body).unwrap());
        assert!(symbols.iter().any(|s| s == "Mock Server build information"));
        assert_eq!(series[&key(&[("__name__", "mock_server_cluster_members")])].value, 1.0);
        assert!(series.contains_key(&key(&[("__name__", "mock_server_request_duration_seconds_bucket"), ("le", "+Inf")])));
        // Remote-Write carries what the scrape has, ours included.
        assert!(symbols.iter().any(|s| s == "mock_server_native_build_info") && symbols.iter().any(|s| s == "process_cpu_seconds_total"));
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            assert!(series[&key(&[("__name__", "process_threads")])].value >= 1.0);
            assert!(series[&key(&[("__name__", "process_open_fds")])].value >= 3.0);
        }
    }
}
