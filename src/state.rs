//! Everything shared between connections.

pub mod cluster;

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use tokio::sync::watch;

use crate::Config;

pub struct State {
    pub config: Config,
    /// Every bound port, in binding order: the configured ones, then those added by `PUT /mockserver/bind`.
    ports: RwLock<Vec<u16>>,
    /// The first of `ports` (0 while there is none), which every console line carries: read without the lock.
    first_port: std::sync::atomic::AtomicU16,
    /// Value of the `x-forwarded-by` loop marker this instance adds to requests it proxies (§3.8).
    pub forwarded_by: String,
    /// This instance's id in `x-mockserver-forwarded-by` (the forward loop guard, [`crate::forward_loop`]).
    pub forward_loop_id: String,
    /// `host:port` spellings that mean "this server" (§3.8, `PortUnificationHandler.java:544-583`).
    local_hosts: RwLock<HashSet<String>>,
    /// This server's number among the `local_hosts` of the process (see [`LOCAL_HOSTS_IDS`]); `local_hosts` only grows.
    local_hosts_id: u64,
    /// Host names and addresses of this machine, for `local_hosts` of ports bound later.
    local_names: Vec<String>,
    pub stopped: watch::Sender<bool>,
    /// Set when stopping begins: listeners close, in-flight requests drain, then `stopped` is set.
    pub closing: watch::Sender<bool>,
    stopping: std::sync::atomic::AtomicBool,
    /// `Scheduler.shutdown()` in `LifeCycle.stopAsync`: set after the drain, just before the connections close. From
    /// then on, control-plane work upstream offloads onto the scheduler answers `503` instead (fe354ebd5).
    scheduler_shut_down: std::sync::atomic::AtomicBool,
    /// Requests being processed (`LifeCycle.requestsInFlight`).
    in_flight: InFlightCount,
    /// Accepted connections, closed when a stop has drained.
    pub connections: crate::server::OpenConnections,
    pub log_level: String,
    pub store: crate::store::Store,
    /// The controllable clock (`TimeService`), shared with the store's time-to-live checks.
    pub clock: Arc<crate::clock::Clock>,
    pub log: crate::recorded::RequestLog,
    pub callbacks: crate::callback::Registry,
    pub breakpoints: crate::breakpoint::Breakpoints,
    pub crud: crate::crud::Registry,
    /// `None` when the TLS configuration could not be built (logged at startup).
    pub tls: Option<crate::tls::Tls>,
    /// gRPC service descriptors (not cleared by `reset`).
    pub grpc: crate::grpc::Descriptors,
    /// The foreign runtime; none exists yet.
    pub foreign: Option<std::sync::Arc<dyn crate::foreign::ForeignRuntime>>,
    pub velocity_sandbox_warning: crate::foreign::SandboxWarning,
    /// `OpenAPIParser`'s parse cache, as far as it decides when a spec's load problems are logged.
    pub openapi_parses: Arc<crate::openapi::ParseCache>,
    /// The template engines' seeded `faker`s (`templateFakerSeed`).
    pub template_fakers: crate::templates::Fakers,
    /// The template engines' seeded `lists` helpers (`templateFakerSeed`).
    pub template_lists: crate::templates::Lists,
    /// The names `systemValue` was refused that this server has logged.
    pub template_system_values_refused: crate::templates::system_value::Refused,
    /// The Velocity engines of the server's handlers.
    pub velocity_engines: crate::templates::VelocityEngines,
    /// `TemplateDryRun`: `PUT /mockserver/template/test`'s running dry runs and engine.
    pub template_dry_runs: crate::templates::dry_run::DryRuns,
    /// Callback classes from `callbackPlugins`, loaded at startup.
    pub callback_plugins: crate::class_callback::Plugins,
    /// Uploaded WASM rule modules (`WasmStore`).
    pub wasm: crate::wasm::Modules,
    /// `FileStore` (`PUT /mockserver/files/*`).
    pub files: crate::files::FileStore,
    /// `MockServer.registerListener`: called with the active expectations whenever they change.
    pub listeners: parking_lot::Mutex<Vec<Listener>>,
    /// `ExpectationFileSystemPersistence`'s per-server state: the once-only backup of unloadable entries.
    pub persistence: crate::persistence::Persistence,
    /// `CassetteRegistry`.
    pub cassettes: crate::cassettes::Registry,
    /// `LlmQuotaRegistry`.
    pub llm_quotas: crate::llm::chaos::Quotas,
    /// `RateLimitRegistry`.
    pub rate_limits: crate::rate_limit::Registry,
    /// `Scheduler`'s overload bounds: `maxPendingDelayedResponses`, `maxQueuedTemplateActions`.
    pub overload: crate::overload::Overload,
    /// `DriftStore`, `PercentileTracker` and `DriftAlertNotifier`'s cooldowns.
    pub drift: crate::drift::Drift,
    /// `ExpectationInitializerLoader.lintDigests`: per initialisation file, the digest of the lint problems its last
    /// load reported, so a reload finding the same ones logs no WARN.
    pub lint_digests: std::sync::Mutex<std::collections::HashMap<String, i32>>,
    /// The runtime LLM completion services (`LlmCompletionService`) of stub generation and semantic drift analysis.
    pub llm: crate::llm::service::Services,
    /// `TcpChaosRegistry` and `PreemptionSimulator`.
    pub chaos: crate::chaos::Chaos,
    /// MCP sessions (`McpSessionManager`).
    pub mcp: crate::mcp::Sessions,
    /// The OpenTelemetry tracer (`GenAiSpans`, `RequestSpans`).
    pub telemetry: crate::telemetry::Telemetry,
    /// The HTTP/3 listener, when `http3Port` started one.
    pub http3: std::sync::OnceLock<crate::http3::Http3>,
    /// The DNS listener, when `dnsEnabled` started one.
    pub dns: std::sync::OnceLock<crate::dns::Dns>,
    /// `LoadScenarioRegistry` and `LoadScenarioOrchestrator`.
    pub load: crate::load::Load,
    /// `HttpState.mockMode` (`None` until set); `setMode` also writes `attemptToProxyIfNoMatchingExpectation`.
    pub mode: parking_lot::Mutex<Option<&'static str>>,
    /// `ScimResourceStore`.
    pub scim: Arc<crate::scim::Scim>,
    /// `OidcAuthorizationStore`.
    pub oidc: Arc<crate::oidc::Oidc>,
    /// `SamlAssertionStore`.
    pub saml: Arc<crate::saml::Saml>,
    /// The loaded AsyncAPI spec and its broker connections.
    pub asyncapi: crate::asyncapi::AsyncApi,
    /// `stateBackend`'s resolved backend (`crate::state_backend`). Not yet consumed by the
    /// dataplane: `store` and `scenario` stay authoritative (see `crate::state_backend`'s module doc), and the clustered
    /// reconcile path is built on this later.
    pub state_backend: Arc<dyn crate::state_backend::StateBackend>,
    /// `HttpState.clusterFanIn`: the opt-in verify/retrieve scatter-gather across peers.
    pub cluster_fan_in: parking_lot::RwLock<Arc<crate::cluster_fanin::ClusterFanIn>>,
    /// `(maxExpectations, maxLogEntries)` at startup. The 8.0.0 process served these from the MCP
    /// `mockserver://configuration` resource whatever a later `PUT /mockserver/configuration` said; with
    /// one configuration (upstream 0e8566814) the resource reads the live values instead.
    pub mcp_config_defaults: (i64, i64),
    /// `(ringBufferSize, maxWebSocketExpectations)` as the server started: init-only, a configuration update that
    /// supplies another value is warned about and reset to these (`HttpState.applyConfigurationUpdate`).
    pub init_only_in_force: (i64, i64),
    /// `staticFilesDirectory`, opened once at startup (`HttpActionHandler.openStaticFileDirectory`): `None` when it
    /// is unset or not a readable directory.
    pub static_files: Option<crate::static_files::StaticFileDirectory>,
    /// `AuditStore` and `AuditFileSink` (`controlPlaneAuditEnabled`).
    pub audit: crate::audit::Audit,
    /// The namespaces `XML_SCHEMA` compiles have reported without a grammar (not cleared by `reset`).
    pub xsd_reported: crate::xsd::Reported,
    /// The forward connection pool (`HttpActionHandler`'s `NettyHttpClient`), closed by [`State::stop`].
    pub forward_connections: crate::client::ForwardConnections,
    /// The tokio runtime the state was built on: `Server::start` builds it there and spawns its accept loops on
    /// the same runtime, so this is the one serving the listeners, an embedder's own included. The scrape and OTLP
    /// read its `RuntimeMetrics` (`crate::metrics::tokio_snapshots`); `None` outside a runtime.
    pub runtime: Option<tokio::runtime::Handle>,
}

pub type Listener = Arc<dyn Fn(&[serde_json::Value]) + Send + Sync>;

/// `LifeCycle.requestsInFlight`, counted per worker thread: one counter that every request incremented and
/// decremented had each request worker take its cache line from the others twice per request. A request's token
/// names the counter it was counted on, which it is taken off again whatever thread completes it.
#[derive(Default)]
struct InFlightCount([PaddedCount; IN_FLIGHT_SHARDS]);

const IN_FLIGHT_SHARDS: usize = 16;

#[derive(Default)]
#[repr(align(128))]
struct PaddedCount(std::sync::atomic::AtomicUsize);

/// A request counted in flight: see [`State::request_started`].
pub struct InFlightToken(usize);

thread_local! {
    /// This thread's [`InFlightCount`] counter, handed out in turn.
    static IN_FLIGHT_SHARD: usize = {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % IN_FLIGHT_SHARDS
    };
}

impl State {
    /// The client certificate the forwarding client offers to `host` over TLS (`crate::tls::forward_identity`).
    pub fn forward_identity(&self, host: &str) -> Option<crate::tls::ForwardIdentity> {
        crate::tls::forward_identity(&self.config, self.tls.as_ref(), host)
    }

    /// Whether INFO events are logged, and so kept for `retrieve?type=LOGS`.
    pub fn info_enabled(&self) -> bool {
        !matches!(self.log_level.as_str(), "OFF" | "ERROR" | "WARN")
    }

    /// SECURITY: `JsonSchemaValidator.JSON_SCHEMA_ALLOW_REMOTE_REFS_PROPERTY` —
    /// `jsonSchemaAllowRemoteRefs`, default deny. Every place that compiles a request matcher from untrusted
    /// input (an expectation, a verify/breakpoint filter, an initializer file) reads this once and carries it
    /// through the compile with `crate::matcher::string::with_remote_refs_policy`.
    pub fn json_schema_allow_remote_refs(&self) -> bool {
        self.config.bool_property("jsonSchemaAllowRemoteRefs", false)
    }

    pub fn new(config: Config, ports: Vec<u16>) -> Arc<State> {
        // `Server::start` builds the backend itself (a clustered one can fail to start) and uses
        // `new_with_backend`; a direct `State::new` call (`Config::for_tests()`-based tests, `src/telemetry.rs`)
        // never selects a clustered one.
        let state_backend = crate::state_backend::create(&config).unwrap_or_else(|e| {
            eprintln!("ERROR state backend: {e}; using the in-memory backend");
            crate::state_backend::build(crate::state_backend::Kind::Memory, config.int_property("maxExpectations", crate::config::default_max_expectations(&config)).max(0) as usize)
        });
        Self::new_with_backend(config, ports, state_backend)
    }

    /// [`State::new`] with the state backend already built (`state_backend::create`).
    pub fn new_with_backend(config: Config, ports: Vec<u16>, state_backend: Arc<dyn crate::state_backend::StateBackend>) -> Arc<State> {
        // Before the TLS context, which reads its PEM files from the class path too.
        crate::class_path::install(&config);
        let mut names = vec!["localhost".to_string(), "127.0.0.1".into(), "::1".into(), "[::1]".into(), "0:0:0:0:0:0:0:1".into()];
        if let Ok(host) = std::env::var("HOSTNAME") {
            names.push(host);
        }
        if let Some(host) = system_hostname() {
            names.push(host);
        }
        names.extend(local_ips());
        let mut local_hosts = HashSet::new();
        add_local_hosts(&mut local_hosts, &names, &ports);
        let cluster_fan_in = crate::cluster_fanin::ClusterFanIn::from_config(&config);
        let tls = match crate::tls::Tls::new(&config) {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("ERROR TLS disabled: {e}");
                None
            }
        };
        let log = crate::recorded::RequestLog::new(crate::config::max_log_entries(&config).max(0) as usize)
            .with_limits(config.int_property("maxLoggedBodyBytes", 0).max(0) as usize, crate::config::max_event_log_size_in_bytes(&config) as u64);
        let mcp_config_defaults = (config.int_property("maxExpectations", crate::config::default_max_expectations(&config)), config.int_property("maxLogEntries", crate::config::default_max_log_entries(&config)));
        let init_only_in_force = {
            let effective = crate::config::effective_json(&config);
            let int = |name: &str| effective.get(name).and_then(serde_json::Value::as_i64).unwrap_or(0);
            (int("ringBufferSize"), int("maxWebSocketExpectations"))
        };
        let overload = crate::overload::Overload::new(&config);
        let callback_plugins = crate::class_callback::Plugins::load(&config.property("callbackPlugins").unwrap_or_default(), |line| eprintln!("{line}"));
        let clock = Arc::new(crate::clock::Clock::default());
        let forward_connections = crate::client::ForwardConnections::for_config(&config);
        let static_files_directory = config.property("staticFilesDirectory").unwrap_or_default();
        let static_files = crate::static_files::StaticFileDirectory::open(&static_files_directory);
        let state = Arc::new(State {
            log,
            log_level: config.log_level(),
            config,
            first_port: std::sync::atomic::AtomicU16::new(ports.first().copied().unwrap_or_default()),
            ports: RwLock::new(ports),
            forwarded_by: format!("MockServer_{}", uuid::Uuid::new_v4()),
            forward_loop_id: crate::forward_loop::new_instance_id(),
            local_hosts: RwLock::new(local_hosts),
            local_hosts_id: LOCAL_HOSTS_IDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            local_names: names,
            stopped: watch::channel(false).0,
            closing: watch::channel(false).0,
            stopping: Default::default(),
            scheduler_shut_down: Default::default(),
            template_fakers: Default::default(),
            template_lists: Default::default(),
            template_system_values_refused: Default::default(),
            velocity_engines: Default::default(),
            template_dry_runs: Default::default(),
            in_flight: Default::default(),
            connections: Default::default(),
            store: crate::store::Store::with_clock(clock.clone()),
            clock,
            callbacks: crate::callback::Registry::with_max_clients(init_only_in_force.1.max(0) as usize),
            breakpoints: Default::default(),
            crud: Default::default(),
            tls,
            grpc: Default::default(),
            foreign: None,
            velocity_sandbox_warning: Default::default(),
            openapi_parses: Default::default(),
            callback_plugins,
            wasm: Default::default(),
            files: Default::default(),
            listeners: Default::default(),
            persistence: Default::default(),
            cassettes: Default::default(),
            llm_quotas: Default::default(),
            rate_limits: Default::default(),
            overload,
            drift: Default::default(),
            lint_digests: Default::default(),
            llm: Default::default(),
            chaos: Default::default(),
            mcp: Default::default(),
            telemetry: Default::default(),
            http3: Default::default(),
            dns: Default::default(),
            load: Default::default(),
            mode: Default::default(),
            scim: Default::default(),
            oidc: Default::default(),
            saml: Default::default(),
            asyncapi: Default::default(),
            audit: Default::default(),
            xsd_reported: Default::default(),
            forward_connections,
            runtime: tokio::runtime::Handle::try_current().ok(),
            cluster_fan_in: parking_lot::RwLock::new(Arc::new(cluster_fan_in)),
            state_backend,
            mcp_config_defaults,
            init_only_in_force,
            static_files: static_files.as_ref().ok().cloned().flatten(),
        });
        crate::log::configure_java_logger(&state);
        crate::static_files::log_opened(&state, &static_files_directory, &static_files);
        // The hooks below are asked for every line and entry of every request: upgrading a weak reference wrote the
        // server's reference count, which every request worker shares, twice each time.
        // SAFETY (each of them): the hook lives in this server's `log` and is called only through it, so while it runs
        // the server is borrowed and not dropped; the weak reference keeps its allocation.
        let redaction = Arc::downgrade(&state);
        state.log.set_redaction_hook(Arc::new(move || {
            let state = unsafe { &*redaction.as_ptr() };
            crate::log::redacting(state).then(|| state.config.fixture_body_redact_fields())
        }));
        let console = Arc::downgrade(&state);
        state.log.set_console_hook(Arc::new(move |level, kind, text, compact, portless| {
            let state = unsafe { &*console.as_ptr() };
            crate::log::log_entry(state, level, kind, text, compact, portless);
        }));
        // Asked a few times for every request. Upgrading the weak reference wrote the server's reference count,
        // which every request worker shares, twice each time.
        let gate = Arc::downgrade(&state);
        state.log.set_console_gate(Arc::new(move |level, kind| {
            // SAFETY: the gate lives in this server's `log` and is called only through it, so while it runs the server
            // is borrowed and not dropped; the weak reference keeps its allocation.
            let state = unsafe { &*gate.as_ptr() };
            crate::log::console_wanted(state, level, kind)
        }));
        state.store.set_max_expectations(mcp_config_defaults.0.max(0) as usize);
        state.store.set_max_bytes(state.config.int_property("maxExpectationsSizeInBytes", 0).max(0) as u64);
        let warn = Arc::downgrade(&state);
        state.store.on_byte_budget_reached(Box::new(move |budget| {
            if let Some(state) = warn.upgrade() {
                // `RequestMatchers.announceByteEvictionIfNeeded`
                crate::log::warn_event(&state, crate::recorded::LogEntry::at(crate::recorded::Level::Warn, format!(
                    "expectation byte budget reached (maxExpectationsSizeInBytes={budget} bytes) — evicting the oldest, lowest-priority expectations to bound the memory their request-matcher and response bodies retain. Reduce the size or number of stored expectations, or raise maxExpectationsSizeInBytes (0 disables the byte bound, leaving only maxExpectations). Evicted expectations no longer match."
                )));
            }
        }));
        // `CrossProtocolEventBus.getInstance().setScenarioManager(requestMatchers.getScenarioManager())`
        state.bus().set_scenario_manager(state.scenarios().clone());
        // `HttpState`: `ChaosProfileLibrary` and `LoadScenarioRegistry` are built on the state backend, clustered or not.
        state.chaos.experiments.attach_library(&*state.state_backend);
        state.load.attach_registry(&*state.state_backend);
        state.link_clustered_store();
        crate::llm::service::install_semantic_matching(&state);
        // `OpenAiResponsesStore.getInstance().setMaxSizeInBytes(configuration.maxOpenAiResponsesSizeInBytes())`
        crate::llm::responses::apply_configuration(&state.config);
        state
    }

    /// `HttpState`'s wiring of a clustered backend (`HttpState.java:263-345`): the expectation store becomes a view
    /// over the backend's `expectations` (write-through, shared `Times`), and an invalidation listener reconciles it
    /// when another node changes anything. A non-clustered backend leaves the store exactly as it was.
    fn link_clustered_store(self: &Arc<Self>) {
        if !self.state_backend.is_clustered() {
            return;
        }
        let (for_build, for_times, for_listener) = (Arc::downgrade(self), Arc::downgrade(self), Arc::downgrade(self));
        let for_warn = Arc::downgrade(self);
        let link = cluster::ClusterLink::new(
            self.state_backend.clone(),
            move || for_times.upgrade().is_none_or(|s| s.config.bool_property("clusterSharedTimesEnabled", true)),
            move |json| {
                let state = for_build.upgrade()?;
                Some(crate::control::compile_expectation(&state, json.as_object()?))
            },
            move |text| {
                if let Some(state) = for_warn.upgrade() {
                    crate::log::warn_event(&state, crate::recorded::LogEntry::at(crate::recorded::Level::Warn, text));
                }
            },
        );
        self.store.attach_cluster(link);
        // `RequestMatchers.setStateBackend` / `CrossProtocolEventBus.setStateBackend`: scenario states are the
        // backend's, the bus replicates; a listener of its own reconciles the bus (`HttpState.java:333-346`).
        self.scenarios().attach_backend(self.state_backend.clone());
        self.bus().attach_backend(&self.state_backend);
        // `HttpState.java:271-310`: the chaos registries replicate through their own CRUD stores, reconciled by a
        // listener of its own.
        let chaos = &self.chaos;
        chaos.service.set_state_backend(&*self.state_backend);
        chaos.tcp.set_state_backend(&*self.state_backend);
        chaos.grpc.set_state_backend(&*self.state_backend);
        let for_chaos = Arc::downgrade(self);
        self.state_backend.add_invalidation_listener(Arc::new(cluster::StoreInvalidation {
            reconcile: Box::new(move || {
                if let Some(state) = for_chaos.upgrade() {
                    state.chaos.service.reconcile_from_backend();
                    state.chaos.tcp.reconcile_from_backend();
                    state.chaos.grpc.reconcile_from_backend();
                }
            }),
        }));
        let for_bus = Arc::downgrade(self);
        self.state_backend.add_invalidation_listener(Arc::new(cluster::StoreInvalidation {
            reconcile: Box::new(move || {
                if let Some(state) = for_bus.upgrade() {
                    state.bus().reconcile_bus();
                }
            }),
        }));
        self.state_backend.add_invalidation_listener(Arc::new(cluster::StoreInvalidation {
            reconcile: Box::new(move || {
                if let Some(state) = for_listener.upgrade() {
                    state.store.reconcile_from_backend();
                }
            }),
        }));
    }

    /// This server's scenario states and cross-protocol event bus.
    pub fn scenarios(&self) -> &Arc<crate::scenario::Scenarios> {
        &self.store.scenarios
    }

    /// This server's cross-protocol event bus.
    pub fn bus(&self) -> &Arc<crate::scenario::CrossProtocolBus> {
        &self.store.bus
    }

    /// `Scheduler.shutdown()`: control-plane work upstream offloads onto the scheduler answers `503` from now on.
    pub fn shut_down_scheduler(&self) {
        self.scheduler_shut_down.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// `executor.isShutdown()` on the scheduler's executor.
    pub fn scheduler_is_shut_down(&self) -> bool {
        self.scheduler_shut_down.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// `requestProcessingStarted`: the request's token, which [`State::request_completed`] takes back.
    pub fn request_started(&self) -> InFlightToken {
        let shard = IN_FLIGHT_SHARD.with(|s| *s);
        self.in_flight.0[shard].0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        InFlightToken(shard)
    }

    /// `requestProcessingComplete`: never below zero.
    pub fn request_completed(&self, token: InFlightToken) {
        let _ = self.in_flight.0[token.0].0.try_update(std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst, |n| Some(n.saturating_sub(1)));
    }

    /// [`State::request_started`] without a token, for an embedder's requests.
    pub fn request_started_untracked(&self) {
        self.in_flight.0[0].0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// [`State::request_completed`] of a request counted without a token: one is taken off any counter that holds one,
    /// never below zero in all.
    pub fn request_completed_untracked(&self) {
        for count in &self.in_flight.0 {
            if count.0.try_update(std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst, |n| n.checked_sub(1)).is_ok() {
                return;
            }
        }
    }

    pub fn requests_in_flight(&self) -> usize {
        self.in_flight.0.iter().map(|c| c.0.load(std::sync::atomic::Ordering::SeqCst)).sum()
    }

    pub fn is_running(&self) -> bool {
        !*self.stopped.borrow()
    }

    /// `LifeCycle.stopAsync`: stops accepting connections, waits up to `stopDrainMillis` for in-flight requests,
    /// then stops. A second call waits for the first.
    pub async fn stop(self: &Arc<Self>) {
        if self.stopping.swap(true, std::sync::atomic::Ordering::SeqCst) {
            let _ = self.stopped.subscribe().wait_for(|s| *s).await;
            return;
        }
        // `stopAsync`: announced before the listeners close. Neither this nor the drain line can be read back over
        // HTTP once the server has stopped (docs/divergences.md).
        use crate::recorded::{Kind, Level, LogEntry};
        let ports = self.ports();
        let stopped = match ports.as_slice() {
            [port] => format!("stopped for port: {port}"),
            _ => format!("stopped for ports: [{}]", ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")),
        };
        crate::log::info_event(self, LogEntry::new(Kind::ServerConfiguration, stopped));
        // `send_replace`, not `send`: `send` keeps the old value while nothing subscribes, and a listener task that
        // has not run yet subscribes later, so it would never see the stop.
        self.closing.send_replace(true);
        // the DNS socket is closed before a stop, or a start this stop refuses, returns
        if let Some(dns) = self.dns.get() {
            dns.stop().await;
        }
        let drain = self.config.int_property("stopDrainMillis", 15_000);
        if drain > 0 && self.requests_in_flight() > 0 {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(drain as u64);
            while self.requests_in_flight() > 0 && std::time::Instant::now() < deadline {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            let remaining = self.requests_in_flight();
            if remaining > 0 {
                let text = format!("graceful shutdown drain timeout of {drain}ms elapsed with {remaining} request(s) still in flight, proceeding with shutdown");
                crate::log::warn_event(self, LogEntry::new(Kind::ServerConfiguration, text).level(Level::Warn));
            }
        }
        self.callbacks.reset();
        // the persistence listeners are unregistered on stop, as upstream does
        self.log.clear_hooks();
        self.asyncapi.shutdown().await;
        // a clustered state backend leaves its cluster
        let backend = self.state_backend.clone();
        let _ = tokio::task::spawn_blocking(move || backend.close()).await;
        // `scheduler.shutdown()`, after `httpState.stop()`: until the connections close, offloaded control-plane work
        // answers `503` (fe354ebd5)
        self.shut_down_scheduler();
        if let Some(h3) = self.http3.get() {
            h3.stop().await;
        }
        // the worker event loop group's shutdown closes every channel still open, the pooled forward ones too
        self.connections.close_all();
        self.forward_connections.close();
        self.llm.close();
        self.stopped.send_replace(true);
    }

    /// `HttpState.setClusterFanIn`: the test seam that injects a coordinator (with a stub peer accessor).
    pub fn set_cluster_fan_in(&self, fan_in: crate::cluster_fanin::ClusterFanIn) {
        *self.cluster_fan_in.write() = Arc::new(fan_in);
    }

    /// The coordinator, cloned out of its lock.
    pub fn cluster_fan_in(&self) -> Arc<crate::cluster_fanin::ClusterFanIn> {
        self.cluster_fan_in.read().clone()
    }

    pub fn is_local_host(&self, host: &str) -> bool {
        // Every unmatched request asks with its `Host`, nearly always the one its worker last found local: the set only
        // grows, so that one stays local, and no lock shared with the other workers is taken.
        if LAST_LOCAL_HOST.with_borrow(|(id, last)| *id == self.local_hosts_id && last == host) {
            return true;
        }
        // a host already in lower case is looked up as it is
        let lower = if host.bytes().any(|b| b.is_ascii_uppercase()) { std::borrow::Cow::Owned(host.to_ascii_lowercase()) } else { std::borrow::Cow::Borrowed(host) };
        let local = self.local_hosts.read().unwrap().contains(lower.as_ref());
        if local {
            LAST_LOCAL_HOST.with_borrow_mut(|(id, last)| {
                *id = self.local_hosts_id;
                last.clear();
                last.push_str(host);
            });
        }
        local
    }

    pub fn ports(&self) -> Vec<u16> {
        self.ports.read().unwrap().clone()
    }

    /// The first configured port, which MockServer's console log lines carry.
    pub fn first_port(&self) -> u16 {
        self.first_port.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// This server's number, which no other server of the process has (see [`LOCAL_HOSTS_IDS`]).
    pub fn id(&self) -> u64 {
        self.local_hosts_id
    }

    /// Requests addressed to `port` count as local, without it being a bound TCP port (the HTTP/3 listener's
    /// `buildLocalAddresses`).
    pub fn add_local_port(&self, port: u16) {
        add_local_hosts(&mut self.local_hosts.write().unwrap(), &self.local_names, &[port]);
    }

    /// Records ports bound after startup; requests addressed to them count as local too.
    pub fn add_ports(&self, ports: &[u16]) {
        let mut bound = self.ports.write().unwrap();
        bound.extend_from_slice(ports);
        self.first_port.store(bound.first().copied().unwrap_or_default(), std::sync::atomic::Ordering::Relaxed);
        drop(bound);
        add_local_hosts(&mut self.local_hosts.write().unwrap(), &self.local_names, ports);
    }
}

/// Numbers each server's `local_hosts` (from 1), so that what a worker remembers of one ([`LAST_LOCAL_HOST`]) is never
/// taken for another's, even one built where a dropped one was.
static LOCAL_HOSTS_IDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

thread_local! {
    /// The `Host` this worker last found local, and the number of the `local_hosts` it is in.
    static LAST_LOCAL_HOST: std::cell::RefCell<(u64, String)> = const { std::cell::RefCell::new((0, String::new())) };
}

fn add_local_hosts(local_hosts: &mut HashSet<String>, names: &[String], ports: &[u16]) {
    for name in names {
        for port in ports {
            if *port == 80 || *port == 443 {
                local_hosts.insert(name.to_ascii_lowercase());
            } else {
                local_hosts.insert(format!("{}:{port}", name.to_ascii_lowercase()));
            }
        }
    }
}

fn system_hostname() -> Option<String> {
    std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Addresses of this host's interfaces, found by asking the OS which source address it would route from.
fn local_ips() -> Vec<String> {
    let mut ips = Vec::new();
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") && socket.connect("8.8.8.8:80").is_ok() && let Ok(addr) = socket.local_addr() {
        ips.push(addr.ip().to_string());
    }
    ips
}
