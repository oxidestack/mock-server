//! Live brokers for the `*LiveBrokerIntegrationTest` ports: the images upstream's Testcontainers suites use
//! (`test-container-images.properties`), started with the `docker` CLI (whatever context it points at, the Docker VM's
//! here). They run only with `MOCK_SERVER_BROKER_TESTS=1` (`make broker-tests`) and a reachable Docker daemon;
//! otherwise each test says why and passes, as upstream's `Assume.assumeTrue(dockerAvailable)` skips.
//! `MOCK_SERVER_REQUIRE_DOCKER=1` makes a missing Docker a failure instead, for a machine meant to have one (CI).

use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const MOSQUITTO: &str = "eclipse-mosquitto:2.0.22";
pub const RABBITMQ: &str = "rabbitmq:3.13-management";
pub const CP_KAFKA: &str = "confluentinc/cp-kafka:7.6.1";

/// Whether live-broker tests run; prints why not.
pub fn enabled(test: &str) -> bool {
    if std::env::var("MOCK_SERVER_BROKER_TESTS").ok().as_deref() != Some("1") {
        eprintln!("{test}: skipped, live-broker tests run with MOCK_SERVER_BROKER_TESTS=1 (make broker-tests)");
        return false;
    }
    static DOCKER: OnceLock<bool> = OnceLock::new();
    let available = *DOCKER.get_or_init(|| Command::new("docker").args(["info", "--format", "{{.ServerVersion}}"]).output().is_ok_and(|o| o.status.success()));
    let required = std::env::var("MOCK_SERVER_REQUIRE_DOCKER").ok().as_deref() == Some("1");
    assert!(available || !required, "{test}: MOCK_SERVER_REQUIRE_DOCKER=1, but Docker is not available");
    if !available {
        eprintln!("{test}: skipped, Docker is not available");
    }
    available
}

/// Containers to remove when the test process exits.
static STARTED: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// Networks to remove when the test process exits, after the containers on them.
static NETWORKS: Mutex<Vec<String>> = Mutex::new(Vec::new());

extern "C" fn remove_containers() {
    let ids = STARTED.lock().map(|v| v.clone()).unwrap_or_default();
    if !ids.is_empty() {
        let _ = Command::new("docker").arg("rm").arg("-f").args(&ids).output();
    }
    let networks = NETWORKS.lock().map(|v| v.clone()).unwrap_or_default();
    if !networks.is_empty() {
        let _ = Command::new("docker").args(["network", "rm"]).args(&networks).output();
    }
}

fn register_cleanup() {
    static REGISTERED: OnceLock<()> = OnceLock::new();
    REGISTERED.get_or_init(|| unsafe {
        libc::atexit(remove_containers);
    });
}

/// A unique container or network name, `msrs-broker-<pid>-<8 hex>`.
pub fn unique_name() -> String {
    format!("msrs-broker-{}-{}", std::process::id(), uuid::Uuid::new_v4().simple().to_string().get(..8).unwrap_or("x"))
}

/// A Docker bridge network, removed when the test process exits (statics are never dropped).
pub fn network() -> String {
    register_cleanup();
    let name = unique_name();
    let out = Command::new("docker").args(["network", "create", "--label", "mock-server-broker-tests=1", &name]).output().expect("docker network create");
    assert!(out.status.success(), "docker network create: {}", String::from_utf8_lossy(&out.stderr));
    NETWORKS.lock().unwrap().push(name.clone());
    name
}

pub struct Container {
    pub id: String,
    pub name: String,
}

pub struct Spec<'a> {
    pub image: &'a str,
    /// `(host port or 0 for any, container port)`.
    pub ports: Vec<(u16, u16)>,
    pub env: Vec<(String, String)>,
    /// Files copied in before start: `(path in the container, contents)`.
    pub files: Vec<(&'a str, Vec<u8>)>,
    pub command: Vec<String>,
    pub network: Option<&'a str>,
    /// A log line (substring) that means ready.
    pub ready: &'a str,
    /// The container's name (and network alias), when another container must know it up front; else a unique one.
    pub name: Option<String>,
}

impl Spec<'_> {
    pub fn new(image: &str) -> Spec<'_> {
        Spec { image, ports: Vec::new(), env: Vec::new(), files: Vec::new(), command: Vec::new(), network: None, ready: "", name: None }
    }
}

impl Container {
    pub fn start(spec: Spec) -> Container {
        Container::try_start(spec).unwrap_or_else(|e| panic!("docker start: {e}"))
    }

    /// Starts the container `spec(port)` describes, `port` a host port probed free ([`free_port`]) and
    /// released, for a container that must know its host port up front (Kafka advertises it). While Docker cannot
    /// publish it ("port is already allocated", "address already in use": another process took it first) the
    /// container is started again on a fresh port, up to [`crate::tcp_port::START_ATTEMPTS`] times. Returns the port
    /// too. (The Docker VM forwards published ports to the Mac on its own; a Mac-side listener on the port is not seen.)
    pub fn start_on_free_port<'a>(spec: impl Fn(u16) -> Spec<'a>) -> (Container, u16) {
        let mut attempt = 1;
        loop {
            let port = free_port();
            match Container::try_start(spec(port)) {
                Ok(container) => return (container, port),
                Err(e) if attempt < crate::tcp_port::START_ATTEMPTS && (e.contains("port is already allocated") || e.contains("address already in use")) => {
                    eprintln!("host port {port} was taken before Docker published it; starting again on a fresh one");
                    attempt += 1;
                }
                Err(e) => panic!("docker start: {e}"),
            }
        }
    }

    /// `docker start`'s error text when the container could not start (it is removed then).
    fn try_start(spec: Spec) -> Result<Container, String> {
        register_cleanup();
        let name = spec.name.clone().unwrap_or_else(unique_name);
        let mut create = Command::new("docker");
        create.args(["create", "--name", &name, "--label", "mock-server-broker-tests=1"]);
        for (host, container) in &spec.ports {
            let mapping = if *host == 0 { format!("127.0.0.1::{container}") } else { format!("127.0.0.1:{host}:{container}") };
            create.args(["-p", &mapping]);
        }
        for (k, v) in &spec.env {
            create.args(["-e", &format!("{k}={v}")]);
        }
        if let Some(network) = spec.network {
            create.args(["--network", network, "--network-alias", &name]);
        }
        create.arg(spec.image).args(&spec.command);
        let out = create.output().expect("docker create");
        assert!(out.status.success(), "docker create: {}", String::from_utf8_lossy(&out.stderr));
        let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
        STARTED.lock().unwrap().push(id.clone());
        for (path, contents) in &spec.files {
            let dir = std::env::temp_dir().join(format!("{name}-{}", path.replace('/', "_")));
            std::fs::write(&dir, contents).unwrap();
            let out = Command::new("docker").args(["cp", &dir.to_string_lossy(), &format!("{id}:{path}")]).output().unwrap();
            assert!(out.status.success(), "docker cp: {}", String::from_utf8_lossy(&out.stderr));
            let _ = std::fs::remove_file(dir);
        }
        let container = Container { id, name };
        let out = Command::new("docker").args(["start", &container.id]).output().unwrap();
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).into_owned()); // `Drop` removes it
        }
        container.await_log(spec.ready, Duration::from_secs(120));
        Ok(container)
    }

    pub fn logs(&self) -> String {
        let out = Command::new("docker").args(["logs", &self.id]).output().unwrap();
        format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    }

    pub fn await_log(&self, line: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !self.logs().contains(line) {
            assert!(Instant::now() < deadline, "{} not ready within {timeout:?}:\n{}", self.name, self.logs());
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// The host port a container port is published on.
    pub fn port(&self, container_port: u16) -> u16 {
        let out = Command::new("docker").args(["port", &self.id, &container_port.to_string()]).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        text
            .lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .and_then(|p| p.trim().parse().ok())
            .unwrap_or_else(|| panic!("no host port for {container_port}: {text}"))
    }

    /// `docker stop` then, when `restart`, `docker start` again (the published ports are kept).
    pub fn stop(&self) {
        let out = Command::new("docker").args(["stop", &self.id]).output().unwrap();
        assert!(out.status.success(), "docker stop: {}", String::from_utf8_lossy(&out.stderr));
    }

    pub fn restart(&self, ready: &str) {
        let before = self.logs().matches(ready).count();
        let out = Command::new("docker").args(["start", &self.id]).output().unwrap();
        assert!(out.status.success(), "docker start: {}", String::from_utf8_lossy(&out.stderr));
        let deadline = Instant::now() + Duration::from_secs(120);
        while self.logs().matches(ready).count() <= before {
            assert!(Instant::now() < deadline, "{} did not restart:
{}", self.name, self.logs());
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.id]).output();
        if let Ok(mut started) = STARTED.lock() {
            started.retain(|id| id != &self.id);
        }
    }
}

/// Runs a broker adapter's future to completion from a synchronous test, on a runtime shared by the tests that
/// keeps the adapters' background tasks (poll loops, senders) running between calls, as the Java clients' own
/// threads do.
pub fn block<F: std::future::Future>(future: F) -> F::Output {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("test runtime")).block_on(future)
}

/// A free host port, probed and released: see [`Container::start_on_free_port`] for the retry it needs.
pub fn free_port() -> u16 {
    crate::tcp_port::free_tcp_port()
}

/// Polls `condition` every 200 ms until it holds or `timeout` passes.
pub fn eventually<T>(timeout: Duration, mut condition: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(v) = condition() {
            return Some(v);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// A Mosquitto 2 broker with a single listener and the given extra configuration (`mosquitto -c <conf>`).
pub fn mosquitto(port: u16, extra_config: &str, extra_files: Vec<(&str, Vec<u8>)>, command: Option<&str>) -> Container {
    let mut spec = Spec::new(MOSQUITTO);
    spec.ports = vec![(0, port)];
    spec.files = vec![("/mosquitto/config/mosquitto.conf", format!("listener {port}\n{extra_config}").into_bytes())];
    spec.files.extend(extra_files);
    spec.command = match command {
        Some(c) => vec!["sh".into(), "-c".into(), c.into()],
        None => vec!["mosquitto".into(), "-c".into(), "/mosquitto/config/mosquitto.conf".into()],
    };
    spec.ready = " running";
    Container::start(spec)
}

/// A single-node KRaft Kafka (`cp-kafka`, as Testcontainers' `KafkaContainer` configures it): the `PLAINTEXT`
/// listener advertised on a host port for the clients, `BROKER` for inter-broker traffic. `env` adds or overrides
/// broker settings (e.g. to make `PLAINTEXT` a SASL listener).
pub struct Kafka {
    /// Kept so the broker lives as long as its handle.
    #[allow(dead_code)]
    pub container: Container,
    pub bootstrap: String,
    /// The cluster's other brokers, kept alive with it.
    #[allow(dead_code)]
    pub peers: Vec<Container>,
}

pub fn kafka(env: &[(&str, &str)]) -> Kafka {
    let (container, port) = Container::start_on_free_port(|port| kafka_spec(port, env));
    Kafka { container, bootstrap: format!("localhost:{port}"), peers: Vec::new() }
}

/// A two-broker KRaft cluster whose brokers have racks, on a network of its own: node 1 (`broker.rack`
/// `a`, also the cluster's only controller) and node 2 (`b`, broker only). Each advertises `PLAINTEXT` on a host
/// port and `BROKER` under its container name; `container` is node 1, `bootstrap` names it alone (the metadata names
/// both).
pub fn kafka_racked() -> Kafka {
    let network = network();
    let controller = unique_name();
    let node = |id: &str, rack: &str, name: &str, port: u16| {
        let mut env = vec![
            ("KAFKA_NODE_ID".to_string(), id.to_string()),
            ("KAFKA_BROKER_RACK".into(), rack.into()),
            ("KAFKA_CONTROLLER_QUORUM_VOTERS".into(), format!("1@{controller}:9094")),
            ("KAFKA_ADVERTISED_LISTENERS".into(), format!("PLAINTEXT://localhost:{port},BROKER://{name}:9093")),
        ];
        if id != "1" {
            env.push(("KAFKA_PROCESS_ROLES".into(), "broker".into()));
            env.push(("KAFKA_LISTENERS".into(), "PLAINTEXT://0.0.0.0:9092,BROKER://0.0.0.0:9093".into()));
        }
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let mut spec = kafka_spec(port, &env);
        spec.name = Some(name.to_string());
        spec.network = Some(&network);
        spec
    };
    let (container, port) = Container::start_on_free_port(|port| node("1", "a", &controller, port));
    let second = unique_name();
    let (peer, _) = Container::start_on_free_port(|port| node("2", "b", &second, port));
    Kafka { container, bootstrap: format!("localhost:{port}"), peers: vec![peer] }
}

fn kafka_spec<'a>(port: u16, env: &[(&str, &str)]) -> Spec<'a> {
    let mut spec = Spec::new(CP_KAFKA);
    spec.ports = vec![(port, 9092)];
    let mut settings: Vec<(String, String)> = [
        ("KAFKA_NODE_ID", "1"),
        ("KAFKA_PROCESS_ROLES", "broker,controller"),
        ("KAFKA_LISTENERS", "PLAINTEXT://0.0.0.0:9092,BROKER://0.0.0.0:9093,CONTROLLER://0.0.0.0:9094"),
        ("KAFKA_LISTENER_SECURITY_PROTOCOL_MAP", "BROKER:PLAINTEXT,PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT"),
        ("KAFKA_INTER_BROKER_LISTENER_NAME", "BROKER"),
        ("KAFKA_CONTROLLER_LISTENER_NAMES", "CONTROLLER"),
        ("KAFKA_CONTROLLER_QUORUM_VOTERS", "1@localhost:9094"),
        ("KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR", "1"),
        ("KAFKA_OFFSETS_TOPIC_NUM_PARTITIONS", "1"),
        ("KAFKA_TRANSACTION_STATE_LOG_MIN_ISR", "1"),
        ("KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR", "1"),
        ("KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS", "0"),
        ("CLUSTER_ID", "4L6g3nShT-eMCtK--X86sw"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    settings.push(("KAFKA_ADVERTISED_LISTENERS".into(), format!("PLAINTEXT://localhost:{port},BROKER://localhost:9093")));
    for (k, v) in env {
        settings.retain(|(name, _)| name != k);
        settings.push((k.to_string(), v.to_string()));
    }
    spec.env = settings;
    spec.ready = "Kafka Server started";
    spec
}

/// Reads the first record of partition 0 of `topic` from the earliest offset with an independent client (`rskafka`),
/// waiting up to 30 s; the originals use a plain `KafkaConsumer`.
pub fn consume_one(bootstrap: &str, topic: &str, sasl: Option<(&str, &str)>) -> Option<rskafka::record::Record> {
    let (bootstrap, topic, sasl) = (bootstrap.to_string(), topic.to_string(), sasl.map(|(u, p)| (u.to_string(), p.to_string())));
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async move {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut builder = rskafka::client::ClientBuilder::new(vec![bootstrap]);
        if let Some((username, password)) = sasl {
            builder = builder.sasl_config(rskafka::client::SaslConfig::Plain(rskafka::client::Credentials::new(username, password)));
        }
        let client = builder.build().await.ok()?;
        while tokio::time::Instant::now() < deadline {
            if let Ok(partition) = client.partition_client(topic.clone(), 0, rskafka::client::partition::UnknownTopicHandling::Retry).await && let Ok((records, _)) = partition.fetch_records(0, 1..1_000_000, 500).await && let Some(r) = records.into_iter().next() {
                return Some(r.record);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        None
    })
}
