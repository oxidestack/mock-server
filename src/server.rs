//! Listening sockets. Each connection is sniffed: the HTTP/2 prior-knowledge preface goes to hyper, anything
//! else to the HTTP/1.x loop in `http1`.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::chaos::io::ChaosIo;
use crate::write_stall::WriteStallIo;
use crate::handler::Connection;
use crate::recorded::{Kind, Level, LogEntry};
use crate::state::State;
use crate::rewind::Rewind;
use crate::socks::Sniff;
use crate::{Config, http1};

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub struct Server {
    state: Arc<State>,
    ports: Vec<u16>,
    stopped: watch::Receiver<bool>,
}

impl Server {
    /// Binds every configured port and starts serving. Returns once all ports are listening.
    pub async fn start(config: Config) -> std::io::Result<Server> {
        if crate::client::proxy_conflict(&config) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, crate::client::PROXY_CONFLICT));
        }
        // `LifeCycle`'s constructor starts the extensions before `MockServer.createServerBootstrap` checks anything
        // A named extension no callback provider exports refuses start-up here
        crate::extensions::load(&config, |line| eprintln!("{line}")).map_err(std::io::Error::other)?;
        // `MockServer.createServerBootstrap`: `requireUsableControlPlaneMutualTls` first, before anything is bound
        if let Some(message) = crate::auth::unusable_control_plane_mtls(&config).or_else(|| crate::tls::unusable_data_plane_mtls(&config)) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, message));
        }
        // `requireUsableControlPlaneBasicAuthentication`, between the two mTLS checks upstream (both refuse alike)
        if let Err(message) = crate::auth_basic::startup_check(&config) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, message));
        }
        // `StateBackendFactory.create`: build the backend before binding any port, so a
        // clustered one that cannot join its cluster fails fast without occupying one. A clustered backend has
        // joined the cluster and finished its initial state transfer by the time it is returned.
        let state_backend = crate::state_backend::create(&config).map_err(std::io::Error::other)?;
        Server::start_with_state_backend(config, state_backend).await
    }

    /// [`Server::start`] on a backend the caller built: `StateBackendFactory.register(configuration -> backend)`,
    /// the seam upstream's tests inject a spy backend through.
    pub async fn start_with_state_backend(config: Config, state_backend: Arc<dyn crate::state_backend::StateBackend>) -> std::io::Result<Server> {
        let mut listeners = Vec::new();
        // `transparentProxyTproxy=true` requires `IP_TRANSPARENT` on the listener before the bind (a later TPROXY
        // iptables rule delivers traffic addressed elsewhere to this socket) — `MockServerIpTransparentHelper`.
        let mut tproxy_outcome = TproxyBindOutcome::NotRequested;
        let mut retried_ports = Vec::new();
        for port in &config.ports {
            let bound = bind_port(&config, *port).map_err(|source| std::io::Error::new(source.kind(), BindFailure { ports: config.ports.clone(), port: *port, source }))?;
            tproxy_outcome = tproxy_outcome.or(bound.tproxy);
            retried_ports.extend(bound.retried);
            listeners.push((TcpListener::from_std(bound.listener)?, bound.accepted));
        }
        let ports: Vec<u16> = listeners.iter().map(|(l, _)| l.local_addr().map(|a| a.port())).collect::<Result<_, _>>()?;
        // A dynamic CA is generated in memory by building the TLS context and written on its first use
        // (`crate::tls::write_dynamic_authority`): a TLS context's, or `proxySetupLogging`'s block below.
        let state = State::new_with_backend(config, ports.clone(), state_backend);
        // `proactivelyInitialiseTLS` builds the server's context, so the CA, at startup; its first TLS use logs it.
        if state.config.bool_property("proactivelyInitialiseTLS", false) && let (Some((key, certificate)), Some(tls)) = (crate::tls::materialize_dynamic_authority(&state.config), state.tls.as_ref()) {
            tls.created_dynamic_authority(key, certificate);
        }
        match tproxy_outcome {
            TproxyBindOutcome::NotRequested => {}
            TproxyBindOutcome::WarnedNotEnabled => {
                crate::log::warn(&state, "transparentProxyTproxy=true requires transparentProxyEnabled=true; IP_TRANSPARENT not applied");
            }
            TproxyBindOutcome::Applied => {
                crate::log::info(&state, "IP_TRANSPARENT socket option applied (TPROXY mode enabled)");
            }
        }
        // `LifeCycle.bindPort`: an ephemeral port the loopback probe found shadowed, given up for another one
        for message in retried_ports {
            crate::log::info_event(&state, LogEntry::new(Kind::ServerConfiguration, message));
        }
        crate::telemetry::start(&state);
        crate::telemetry::start_metrics(&state);
        crate::metrics::remote_write::start(&state);
        // What upstream logs before `startedServer` stamps the port: persistence and the initialisation files
        // (`HttpState`), then the server's and the forwarding client's `NettySslContextFactory`.
        crate::recorded::portless(async {
            // `RequestMatchers`' constructor (`HttpState`), before the persistence.
            if state.log_level == "TRACE" {
                let size = state.config.int_property("maxExpectations", crate::config::default_max_expectations(&state.config));
                let entry = LogEntry::at(Level::Trace, format!("expectation circular priority queue created, with size {size}"));
                crate::log::entry(&state, &entry);
                state.log.message(entry);
            }
            crate::persistence::start(&state);
            crate::init::load(&state)?;
            // `ExpectationFileWatcher`, the last of `HttpState`'s parts.
            crate::init::watch(&state);
            crate::load::preload(&state);
            // `HttpState`'s `MemoryMonitoring`, after the load scenarios
            crate::memory_csv::start(&state);
            // `HttpState`'s constructor, after the memory monitoring and before the gRPC descriptors.
            if state.log_level == "TRACE" {
                let size = crate::config::ring_buffer_size(&state.config);
                let entry = LogEntry::at(Level::Trace, format!("log ring buffer created, with size {size}"));
                crate::log::entry(&state, &entry);
                state.log.message(entry);
            }
            load_grpc_descriptors(&state);
            // `HttpState.reportTrustedHostSuffixProblems`: rejected (public) suffixes at ERROR, unusable ones at WARN
            let suffixes = state.config.property("controlPlaneTrustedHostSuffixes").unwrap_or_default();
            for message in crate::cors_origin::trusted_host_suffix_errors(&suffixes) {
                let message = crate::cors_origin::escape_for_log(&message);
                crate::log::error_event(&state, LogEntry::new(Kind::ServerConfiguration, "{}").args([message]));
            }
            for message in crate::cors_origin::trusted_host_suffix_warnings(&suffixes) {
                let message = crate::cors_origin::escape_for_log(&message);
                crate::log::warn_event(&state, LogEntry::new(Kind::ServerConfiguration, "{}").args([message]));
            }
            // `SystemValueTemplateHelper.logAllowList`
            crate::templates::system_value::log_allow_list(&state);
            // `requireUsableControlPlaneBasicAuthentication`, when it does not refuse: each weak hash, then AllowInsecure
            for (format, args) in crate::auth_basic::startup_check(&state.config).unwrap_or_default() {
                crate::log::warn_event(&state, LogEntry::new(Kind::ServerConfiguration, format).args(args));
            }
            // `DataPlaneMutualTlsTrust.requireUsableDataPlaneMutualTls(configuration)`, when it does not refuse
            if let Some((warning, chain)) = crate::tls::data_plane_mtls_startup_warning(&state.config) {
                crate::log::warn_event(&state, LogEntry::new(Kind::ServerConfiguration, warning).args(chain));
            }
            for for_server in [true, false] {
                for warning in crate::tls::context_warnings(&state.config, for_server) {
                    crate::log::warn_event(&state, LogEntry::at(Level::Warn, warning));
                }
            }
            Ok::<_, String>(())
        })
        .await
        .map_err(std::io::Error::other)?;
        // `startDnsServer`, `startHttp3Server`: a listener that cannot start stops what is started (`stopped for
        // port: N`) and refuses the start. The TCP listeners are bound but not yet served, so a refused start has
        // closed them when it returns (`RefusedStart.assertStopped`); a connection made meanwhile waits in the backlog.
        if let Err(failure) = crate::dns::start(&state).and_then(|()| crate::http3::start(&state)) {
            drop(listeners);
            state.stop().await;
            return Err(std::io::Error::other(failure));
        }
        // `AsyncApiControlPlaneImpl.registerIfAvailable`, in the standalone jar, after the DNS and HTTP/3 listeners
        // started: an SLF4J `LOG.info` (no port, no type).
        crate::log::info_plain(&state, "AsyncAPI control-plane registered");
        for (listener, accepted) in listeners {
            tokio::spawn(accept_loop(state.clone(), listener, accepted));
        }
        // `LifeCycle.logUpcomingDefaultChanges`, once per start (upstream: once per JVM, which runs one server)
        for warning in state.config.upcoming_default_change_warnings() {
            crate::log::warn_event(&state, LogEntry::new(Kind::ServerConfiguration, warning));
        }
        crate::log::info_event(&state, LogEntry::new(Kind::ServerConfiguration, started_message(&ports)));
        // `LifeCycle.logProxySetup`: under `proxySetupLogging`, the CA is loaded (and logged), written out, and the
        // setup block logged.
        if state.config.bool_property("proxySetupLogging", false) {
            log_authority_loaded(&state);
            if let Ok(setup) = crate::tls::ProxySetup::new(&state.config, ports.first().copied()) {
                let entry = LogEntry::new(Kind::ServerConfiguration, setup.copy_paste_text());
                if setup.using_default_ca { crate::log::warn_event(&state, entry.level(Level::Warn)) } else { crate::log::info_event(&state, entry) }
            }
        }
        // `LifeCycle.startupWarmup`: one plain-HTTP `PUT /mockserver/status` to the first port. Upstream sends it from
        // a thread of its own, which has always answered before a client's first request reaches a fresh server; it is
        // awaited here (loopback, 2 s timeouts) so that it is just as surely counted before anything a caller sends.
        if state.config.bool_property("startupWarmup", true) && let Some(&port) = ports.first().filter(|p| **p > 0) {
            startup_warmup(state.clone(), port).await;
        }
        let stopped = state.stopped.subscribe();
        Ok(Server { state, ports, stopped })
    }

    /// Registers `callbacks` under the callback class name `class`, for expectations that name it.
    pub fn register_callback_class(&self, class: &str, callbacks: crate::class_callback::CallbackClass) {
        self.state.config.callback_classes.register(class, callbacks);
    }

    /// `registerListener`: `listener` is called with the active expectations (input JSON form, as `retrieve`
    /// returns them) each time they change.
    pub fn register_listener(&self, listener: impl Fn(&[serde_json::Value]) + Send + Sync + 'static) -> &Self {
        self.state.listeners.lock().push(Arc::new(listener));
        self
    }

    /// `Metrics.get`: the value of a `Metrics.Name` (`"WEBSOCKET_CALLBACK_CLIENTS_COUNT"`, …), `None` for an unknown name.
    pub fn metric(&self, name: &str) -> Option<i64> {
        crate::metrics::get(&self.state, name)
    }

    /// An in-process object callback (upstream's "via local JVM"): expectations whose `httpResponseObjectCallback` or
    /// `httpForwardObjectCallback` names `client_id` call `callbacks` directly, without a WebSocket client.
    pub fn register_object_callback(&self, client_id: &str, callbacks: crate::class_callback::CallbackClass) {
        self.state.callbacks.register_local(client_id, callbacks);
    }

    /// `TcpChaosRegistry.put`: registers the TCP chaos profile `chaos` (`TcpChaosProfileDTO` JSON) for `host`, with
    /// a TTL when `ttl_millis > 0`. The error is the profile's first range violation.
    pub fn put_tcp_chaos(&self, host: &str, chaos: &serde_json::Value, ttl_millis: i64) -> Result<(), String> {
        let profile = <crate::chaos::TcpChaosProfile as crate::chaos::HostProfile>::from_json(chaos).map_err(|e| e.text())?;
        self.state.chaos.tcp.put(host, profile, ttl_millis);
        Ok(())
    }

    /// `PreemptionSimulator.start` with a `PreemptionRequest` given as JSON.
    pub fn start_preemption(&self, request: &serde_json::Value) -> Result<(), String> {
        self.state.chaos.preemption.start_json(&self.state, request)
    }

    /// `McpToolRegistry.callTool`: runs an MCP tool as `tools/call` would, answering its result object.
    pub async fn call_mcp_tool(&self, name: &str, arguments: &serde_json::Value) -> serde_json::Value {
        crate::mcp::tools::call(&self.state, name, arguments).await
    }

    /// `GenAiSpanExporter.startWithProcessor` with an in-memory exporter: from now on this server's spans are
    /// captured (replacing any OTLP export) until [`Server::stop_spans`].
    pub fn capture_spans(&self) -> crate::SpanCapture {
        self.state.telemetry.capture()
    }

    /// `GenAiSpanExporter.stop`: no more spans are built.
    pub fn stop_spans(&self) {
        self.state.telemetry.stop();
    }

    /// `ConfigurationProperties.<name>(value)` while the server runs: `name` (without `mockserver.`) takes `value`
    /// from now on, as a `PUT /mockserver/configuration` value would, and `GET /mockserver/config` reports it with
    /// the `system-property` source (upstream's setter writes a system property).
    pub fn set_property(&self, name: &str, value: &str) {
        self.state.config.set_embedder_property(name, value.to_string());
    }

    /// `HttpState.setClusterFanIn`: replaces the verify/retrieve fan-in coordinator (ports inject a stub
    /// [`PeerAccessor`](crate::cluster_fanin::PeerAccessor)).
    pub fn set_cluster_fan_in(&self, fan_in: crate::cluster_fanin::ClusterFanIn) {
        self.state.set_cluster_fan_in(fan_in);
    }

    /// `MockServer.getHttp3Port`: the HTTP/3 listener's UDP port, when `http3Port` started one.
    pub fn http3_port(&self) -> Option<u16> {
        self.state.http3.get().map(|h3| h3.port)
    }

    /// `MockServer.getDnsPort`: the DNS listener's UDP port, when `dnsEnabled` started one.
    pub fn dns_port(&self) -> Option<u16> {
        self.state.dns.get().map(|d| d.port)
    }

    /// `DnsIntentRegistry.recover`: the name a DNS answer of this process gave `ip` for.
    pub fn dns_intent(&self, ip: std::net::IpAddr) -> Option<String> {
        crate::dns::intent(ip)
    }

    /// `MockServer.getHttp3ActiveConnectionCount`.
    pub fn http3_active_connections(&self) -> usize {
        self.state.http3.get().map_or(0, |h3| h3.active_connections())
    }

    /// `HttpState.setControlPlaneAuthenticationHandler`: `authenticator` decides control-plane authentication in place
    /// of the configured handlers, answering the verified scopes (for `controlPlaneScopeMapping`) or `None` to reject.
    /// `((LifeCycle) mockServer).bindVerifier = verifier`: the loopback shadow check and retry candidates later binds
    /// (`PUT /mockserver/bind`) use; `None` restores the real probe.
    pub fn set_bind_verifier(&self, verifier: Option<Arc<dyn crate::loopback_probe::BindVerifier>>) {
        self.state.config.bind_verifier.set(verifier);
    }

    pub fn set_control_plane_authenticator(&self, authenticator: impl Fn(&crate::request::HttpRequest) -> Option<Vec<String>> + Send + Sync + 'static) {
        self.state.config.control_plane_authenticator.set(Some(Arc::new(authenticator)));
    }

    /// This server's AsyncAPI control plane (`AsyncApiControlPlaneImpl`), for ports that install stub broker
    /// connections into it or look at it after the server stopped.
    pub fn asyncapi(&self) -> &crate::asyncapi::AsyncApi {
        &self.state.asyncapi
    }

    /// `TcpChaosRegistry.reset` and `PreemptionSimulator.reset`.
    pub fn reset_chaos(&self) {
        self.state.chaos.reset(&self.state);
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    /// Resolves when the server is asked to stop (`PUT /mockserver/stop`) or [`Server::shutdown`] is called.
    pub async fn stopped(&mut self) {
        let _ = self.stopped.wait_for(|s| *s).await;
    }

    /// Resolves once stopping has begun and the listeners are closing, before any drain.
    pub async fn closing(&self) {
        let _ = self.state.closing.subscribe().wait_for(|s| *s).await;
    }

    /// Stops as `PUT /mockserver/stop` does: no new connections, in-flight requests drained up to `stopDrainMillis`.
    pub async fn shutdown(self) {
        self.state.stop().await;
    }

    /// `stopAsync`: the stop runs in the background; the handle resolves once it has finished.
    pub fn stop_async(&self) -> tokio::task::JoinHandle<()> {
        let state = self.state.clone();
        tokio::spawn(async move { state.stop().await })
    }

    /// `Scheduler.shutdown()` alone, as a stop does after its drain (`HttpStateSchedulerShutdownTest`): the listeners
    /// stay open, and control-plane work upstream offloads onto the scheduler answers `503` from now on.
    pub fn shut_down_scheduler(&self) {
        self.state.shut_down_scheduler();
    }

    pub fn is_running(&self) -> bool {
        self.state.is_running()
    }

    /// `getRequestsInFlight`: requests being processed now.
    pub fn requests_in_flight(&self) -> usize {
        self.state.requests_in_flight()
    }

    /// `getInboundConnectionCount`: the TCP connections open on every bound port, each CONNECT or SOCKS tunnel counting
    /// twice (upstream's loopback leg); HTTP/3 is not counted.
    pub fn inbound_connection_count(&self) -> usize {
        self.state.connections.inbound_count()
    }

    /// The scheduler's live counts by name, read whether or not `metricsEnabled` (the oracle harness
    /// waits on them where a scenario's fixed sleep stands for "the server has admitted that request"):
    /// `delayedResponses` and `sideActions` (slots held in those two `maxPendingDelayedResponses` budgets),
    /// `pendingDelayed` (`mock_server_pending_delayed_tasks`), `schedulerQueued` (`mock_server_scheduler_queued_tasks`),
    /// `templateQueued` (`mock_server_template_action_queued_tasks`) and `templateRunning` (renders holding a template
    /// thread), and `templateDryRuns` (template dry runs holding one of their slots); `None` for any
    /// other name.
    pub fn scheduler_count(&self, name: &str) -> Option<usize> {
        let overload = &self.state.overload;
        match name {
            "schedulerQueued" => Some(crate::metrics::scheduler_queued(&self.state)),
            "templateDryRuns" => Some(self.state.template_dry_runs.running()),
            _ => overload.count(name),
        }
    }

    /// `requestProcessingStarted` / `requestProcessingComplete`, for an embedding application that processes
    /// requests of its own under the server's drain.
    pub fn request_processing_started(&self) {
        self.state.request_started_untracked();
    }

    pub fn request_processing_complete(&self) {
        self.state.request_completed_untracked();
    }
}

/// The warm-up request, as `HttpURLConnection` sends it (connect and read timeouts of 2 s); the answer is read and
/// dropped. A failure is only logged at TRACE.
async fn startup_warmup(state: Arc<State>, port: u16) {
    use tokio::io::AsyncWriteExt;
    let timeout = std::time::Duration::from_secs(2);
    let exchange = async {
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(("127.0.0.1", port))).await.map_err(|_| "connect timed out".to_string())?.map_err(|e| e.to_string())?;
        let user_agent = "Java/26.0.2.1";
        let request = format!("PUT /mockserver/status HTTP/1.1\r\nUser-Agent: {user_agent}\r\nHost: 127.0.0.1:{port}\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n");
        stream.write_all(request.as_bytes()).await.map_err(|e| e.to_string())?;
        let mut answer = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let n = tokio::time::timeout(timeout, stream.read(&mut buffer)).await.map_err(|_| "Read timed out".to_string())?.map_err(|e| e.to_string())?;
            if n == 0 {
                return Ok(());
            }
            answer.extend_from_slice(&buffer[..n]);
            if let Some(end) = answer.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&answer[..end]).to_ascii_lowercase();
                let length = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse::<usize>().ok()).unwrap_or(0);
                if answer.len() >= end + 4 + length {
                    return Ok::<_, String>(());
                }
            }
        }
    };
    if let Err(error) = exchange.await && state.log_level == "TRACE" {
        let entry = LogEntry::new(Kind::ServerConfiguration, "exception during start-up warm-up request (ignored):{}".to_string()).level(Level::Trace).args([error]);
        crate::log::entry(&state, &entry);
        state.log.message(entry);
    }
}

/// `HttpState.initGrpcDescriptorStore`: under `grpcEnabled`, the descriptor sets of `grpcDescriptorDirectory` and the
/// `.proto` files of `grpcProtoDirectory` (compiled with `grpcProtocPath`) are loaded; one that fails is logged and
/// skipped.
fn load_grpc_descriptors(state: &State) {
    if !state.config.bool_property("grpcEnabled", true) {
        return;
    }
    if let Some(directory) = state.config.property("grpcDescriptorDirectory").filter(|d| !d.trim().is_empty()) {
        for (path, error) in state.grpc.load_directory(std::path::Path::new(directory.trim())) {
            let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Warn, "failed to load gRPC descriptor from {}:{}").args([path.to_string(), error.to_string()]);
            crate::log::entry(state, &entry);
        }
    }
    if let Some(directory) = state.config.property("grpcProtoDirectory").filter(|d| !d.trim().is_empty()) {
        let protoc = state.config.property("grpcProtocPath").filter(|p| !p.is_empty()).unwrap_or_else(|| "protoc".to_string());
        let directory = std::path::Path::new(&directory);
        let Ok(entries) = std::fs::read_dir(directory) else { return };
        let mut files: Vec<std::path::PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|x| x == "proto")).collect();
        files.sort();
        for file in files {
            if let Err(error) = compile_proto(&protoc, &file, directory).and_then(|bytes| state.grpc.load(&bytes)) {
                let entry = LogEntry::at(Level::Warn, "failed to compile proto file {}:{}").kind(Kind::Warn).args([file.display().to_string(), error]);
                crate::log::warn_event(state, entry);
            }
        }
    }
}

/// `GrpcProtoFileCompiler.compile`: `protoc --descriptor_set_out=<temp> --include_imports --proto_path=<dir> <file>`,
/// the descriptor set it wrote, or `GrpcException`'s message.
fn compile_proto(protoc: &str, file: &std::path::Path, proto_path: &std::path::Path) -> Result<Vec<u8>, String> {
    let absolute = |p: &std::path::Path| std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let failed = || format!("Failed to compile proto file: {}", file.display());
    let output_file = std::env::temp_dir().join(format!("mockserver-grpc-{}.desc", uuid::Uuid::new_v4().simple()));
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(&output_file).map_err(|_| failed())?;
    }
    let result = (|| {
        let output = std::process::Command::new(protoc)
            .arg(format!("--descriptor_set_out={}", absolute(&output_file).display()))
            .arg("--include_imports")
            .arg(format!("--proto_path={}", absolute(proto_path).display()))
            .arg(absolute(file))
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|_| failed())?;
        if !output.status.success() {
            // `redirectErrorStream(true)`: one stream, stdout and stderr together.
            let text = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            return Err(format!("protoc failed (exit code {}): {text}", output.status.code().unwrap_or(-1)));
        }
        std::fs::read(&output_file).map_err(|_| failed())
    })();
    let _ = std::fs::remove_file(&output_file);
    result
}

/// `PUT /mockserver/bind`: listens on further ports (0 = any free one) and returns the ports it bound. Like upstream,
/// ports are bound one after another and the first failure stops the call.
pub fn bind(state: &Arc<State>, requested: &[u16]) -> Result<Vec<u16>, String> {
    let mut bound = Vec::new();
    for port in requested {
        let (listener, accepted) = bind_port(&state.config, *port)
            .and_then(|bound| {
                // `LifeCycle.bindPort` logs each ephemeral port it gave up as shadowed while binding
                for message in bound.retried {
                    crate::log::info_event(state, LogEntry::new(Kind::ServerConfiguration, message));
                }
                Ok((TcpListener::from_std(bound.listener)?, bound.accepted))
            })
            // Upstream appends " port already in use: <cause>" only when the cause chain holds a java.net.BindException:
            // the loopback probe's, while the oracle's epoll transport fails a plain bind with Netty's NativeIoException.
            .map_err(|e| match e.get_ref().and_then(|e| e.downcast_ref::<crate::loopback_probe::BindException>()) {
                Some(bind) => format!("Exception while binding MockServer to port {port} port already in use: {bind}"),
                None => format!("Exception while binding MockServer to port {port}"),
            })?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        state.add_ports(&[port]);
        tokio::spawn(accept_loop(state.clone(), listener, accepted));
        bound.push(port);
    }
    Ok(bound)
}

/// Whether `bind_std_listener` applied `IP_TRANSPARENT`, and why not if it didn't; `.or` keeps the most informative
/// outcome across every listener bound this call (matches upstream applying the option once, to the bootstrap).
#[derive(Clone, Copy, PartialEq, Eq)]
enum TproxyBindOutcome {
    NotRequested,
    WarnedNotEnabled,
    Applied,
}

impl TproxyBindOutcome {
    fn or(self, other: Self) -> Self {
        use TproxyBindOutcome::*;
        match (self, other) {
            (Applied, _) | (_, Applied) => Applied,
            (WarnedNotEnabled, _) | (_, WarnedNotEnabled) => WarnedNotEnabled,
            _ => NotRequested,
        }
    }
}

/// A `std::net::TcpListener` bound the way `MockServer.java`'s `ServerBootstrap` would: non-blocking, and with
/// `IP_TRANSPARENT` applied first when `transparentProxyTproxy=true` and `transparentProxyEnabled=true`
/// (`crate::proxy_resolvers::bind_transparent`, Linux-only; a `setsockopt` failure — most likely missing
/// `CAP_NET_ADMIN` — fails the bind itself, matching upstream: this is deliberate, not a soft fallback).
/// A port of the server that could not be bound (`LifeCycle.bindPorts`): its text is the exception `Main` logs with
/// `exception binding to port(s) [..]` and `exception while starting:{}`, without the JVM's stack frames.
#[derive(Debug)]
pub struct BindFailure {
    /// Every port the server was asked for, as `exception binding to port(s)` lists them.
    pub ports: Vec<u16>,
    pub port: u16,
    pub source: std::io::Error,
}

impl std::fmt::Display for BindFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.source.get_ref().is_some_and(|e| e.is::<UnresolvedAddress>()) {
            return write!(f, "java.lang.RuntimeException: Exception while binding MockServer to port {}\nCaused by: java.nio.channels.UnresolvedAddressException", self.port);
        }
        if let Some(bind) = self.source.get_ref().and_then(|e| e.downcast_ref::<crate::loopback_probe::BindException>()) {
            return write!(f, "java.lang.RuntimeException: Exception while binding MockServer to port {}\nCaused by: java.net.BindException: {bind}", self.port);
        }
        // The oracle image binds with Netty's native epoll transport, whose failure is a `NativeIoException` carrying
        // Linux's negated errno and `strerror` text (macOS numbers and spells some of them differently).
        let (errno, reason) = match self.source.kind() {
            std::io::ErrorKind::AddrInUse => (98, "Address already in use".to_string()),
            std::io::ErrorKind::PermissionDenied => (13, "Permission denied".to_string()),
            std::io::ErrorKind::AddrNotAvailable => (99, "Cannot assign requested address".to_string()),
            _ => (self.source.raw_os_error().unwrap_or(0), self.source.to_string().split(" (os error").next().unwrap_or_default().to_string()),
        };
        write!(
            f,
            "java.lang.RuntimeException: Exception while binding MockServer to port {}\nCaused by: shaded_package.io.netty.channel.unix.Errors$NativeIoException: bind(..) failed with error(-{errno}): {reason}",
            self.port
        )
    }
}

impl std::error::Error for BindFailure {}

impl BindFailure {
    /// `"exception binding to port(s) " + portBindings`, a `List`'s `toString`.
    pub fn message(&self) -> String {
        format!("exception binding to port(s) [{}]", self.ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", "))
    }
}

/// `localBoundIP` names a host that does not resolve: `new InetSocketAddress(host, port)` is unresolved, and Netty's
/// bind throws `UnresolvedAddressException`.
#[derive(Debug)]
struct UnresolvedAddress;

impl std::fmt::Display for UnresolvedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("java.nio.channels.UnresolvedAddressException")
    }
}

impl std::error::Error for UnresolvedAddress {}

/// `LifeCycle.bindPorts`: every server port binds to `localBoundIP` (an address or a host name), or to the wildcard
/// address when it is blank: Netty's `new InetSocketAddress(port)`, the IPv6 wildcard `[::]` bound dual-stack by
/// [`bind_std_listener`], so `::1` and every other IPv6 address are answered as well as IPv4.
pub(crate) fn bind_address(config: &Config, port: u16) -> std::io::Result<SocketAddr> {
    let configured = config.property("localBoundIP").unwrap_or_default();
    if configured.trim().is_empty() {
        return Ok(SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)));
    }
    if let Ok(ip) = configured.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // `InetAddress.getByName`: IPv4 first, as the JDK prefers it by default.
    let resolved: Vec<SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(configured.as_str(), port)).map(Iterator::collect).unwrap_or_default();
    resolved.iter().find(|a| a.is_ipv4()).or(resolved.first()).copied().ok_or_else(|| std::io::Error::other(UnresolvedAddress))
}

/// A listener bound by [`bind_port`]: the connections its loopback probe accepted from others, to serve first, and
/// the INFO lines of the ephemeral ports it gave up as shadowed.
struct BoundPort {
    listener: std::net::TcpListener,
    tproxy: TproxyBindOutcome,
    accepted: crate::loopback_probe::Accepted,
    retried: Vec<String>,
}

/// `LifeCycle.bindPort`: binds `port` and checks with [`crate::loopback_probe`] that connections to localhost on it
/// reach this listener rather than another application's. A shadowed port 0 is released and another one chosen
/// (up to `SHADOW_PROBE_MAX_EPHEMERAL_ATTEMPTS`); a shadowed explicit port fails like any other port conflict.
fn bind_port(config: &Config, port: u16) -> std::io::Result<BoundPort> {
    use crate::loopback_probe as probe;
    let verifier = config.bind_verifier.get();
    let operating_system_chooses_port = port == 0;
    let mut retried = Vec::new();
    let mut next = port;
    for attempt in 1.. {
        let (listener, tproxy) = match bind_address(config, next).and_then(|addr| bind_std_listener(addr, config)) {
            Ok(bound) => bound,
            // a retry's candidate port can be taken between choosing and binding it
            Err(_) if operating_system_chooses_port && attempt > 1 && attempt < probe::MAX_EPHEMERAL_ATTEMPTS => {
                next = verifier.next_candidate_port();
                continue;
            }
            Err(e) => return Err(e),
        };
        let bound_port = listener.local_addr()?.port();
        let mut accepted = Vec::new();
        // a failed check closes the listener (dropped here) and fails the bind
        let Some(shadowed) = verifier.find_shadowed_loopback(&listener, probe::accept_timeout(operating_system_chooses_port, attempt), &mut accepted)? else {
            return Ok(BoundPort { listener, tproxy, accepted, retried });
        };
        drop((listener, accepted));
        let conflict = probe::loopback_conflict(bound_port, shadowed);
        if !operating_system_chooses_port {
            return Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, probe::explicit_port_conflict(bound_port, shadowed)));
        }
        if attempt >= probe::MAX_EPHEMERAL_ATTEMPTS {
            return Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, probe::BindException(format!("no usable free port found after {attempt} attempts, the last one because {conflict}"))));
        }
        retried.push(format!("{conflict}; binding a different port"));
        next = verifier.next_candidate_port();
    }
    unreachable!()
}

/// `addr` with an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`, how a dual-stack socket reports an IPv4 peer) made
/// IPv4, as Java's `InetAddress` does.
pub(crate) fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// The listener for `addr`. A wildcard, `0.0.0.0` as well as `::`, is bound dual-stack on `[::]` (`IPV6_V6ONLY` off):
/// the JDK opens an IPv6 socket wherever the host has IPv6 and binds IPv4's any-local address as `in6addr_any` (the
/// oracle with `localBoundIP=0.0.0.0` lists `::` in `/proc/net/tcp6` and answers `::1`), while any other IPv4 address
/// is bound IPv4-mapped, so IPv4 only (`127.0.0.1` lists `::ffff:127.0.0.1` and refuses `::1`). Where the host has no
/// IPv6 the wildcard is bound as `0.0.0.0`, as the JDK falls back to an IPv4 socket there.
fn bind_std_listener(addr: SocketAddr, config: &Config) -> std::io::Result<(std::net::TcpListener, TproxyBindOutcome)> {
    use socket2::{Domain, Socket, Type};
    let ipv4_wildcard = || Ok::<_, std::io::Error>((Socket::new(Domain::IPV4, Type::STREAM, None)?, SocketAddr::from(([0, 0, 0, 0], addr.port()))));
    let (socket, addr) = if addr.ip().is_unspecified() {
        match Socket::new(Domain::IPV6, Type::STREAM, None) {
            Ok(socket) if socket.set_only_v6(false).is_ok() => (socket, SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, addr.port()))),
            _ => ipv4_wildcard()?,
        }
    } else {
        (Socket::new(if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 }, Type::STREAM, None)?, addr)
    };
    socket.set_reuse_address(true)?;
    let outcome = if config.bool_property("transparentProxyTproxy", false) {
        if !config.hot_bool(crate::config::Hot::TransparentProxyEnabled, false) {
            TproxyBindOutcome::WarnedNotEnabled
        } else if crate::proxy_resolvers::bind_transparent(&socket)? {
            TproxyBindOutcome::Applied
        } else {
            TproxyBindOutcome::NotRequested
        }
    } else {
        TproxyBindOutcome::NotRequested
    };
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok((socket.into(), outcome))
}

/// `LifeCycle.logProxySetup` loading the CA: a dynamic one is generated and written (its files logged when this
/// call wrote them), its key loaded; a configured key is loaded too; then the X509 (at DEBUG with its `toString`).
fn log_authority_loaded(state: &State) {
    crate::tls::write_dynamic_authority(state, false);
    if !state.info_enabled() {
        return;
    }
    if crate::tls::authority_private_key_source(&state.config).is_some() {
        crate::tls::log_ca_private_key_loaded(state, false);
    }
    crate::tls::log_ca_x509_loaded(state, false);
}

/// The line Testcontainers waits for (`LifeCycle.java:625-635`).
fn started_message(ports: &[u16]) -> String {
    match ports {
        [port] => format!("started on port: {port}"),
        _ => format!("started on ports: [{}]", ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")),
    }
}

/// Serves `listener`, first the connections its loopback probe accepted ([`bind_port`]).
async fn accept_loop(state: Arc<State>, listener: TcpListener, accepted: crate::loopback_probe::Accepted) {
    let mut closing = state.closing.subscribe();
    let mut early = accepted.into_iter();
    loop {
        let early_stream = early.next().and_then(|(stream, remote)| stream.set_nonblocking(true).and_then(|()| tokio::net::TcpStream::from_std(stream)).ok().map(|s| (s, remote)));
        let (stream, remote) = match early_stream {
            Some(accepted) => accepted,
            None => tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(a) => a,
                    Err(_) => continue,
                },
                // Dropping the listener refuses new connections while in-flight requests drain.
                _ = closing.wait_for(|s| *s) => return,
            },
        };
        // the dual-stack listener reports an IPv4 peer as `::ffff:a.b.c.d`; Java's `InetAddress` makes it Inet4
        let remote = canonical(remote);
        // `InboundConnectionLimiter`, ahead of the acceptor: a connection beyond the limit costs nothing but the accept
        let Some(open) = state.connections.admit(&state, &stream, remote) else { continue };
        let _ = stream.set_nodelay(true);
        let Ok(local) = stream.local_addr().map(canonical) else { continue };
        let socket = crate::chaos::io::Socket::of(&stream);
        let event_loop = OpenConnections::event_loop(&state.config, open.registration);
        let measured = crate::metrics::ServerConnection::open(&state.config, "tcp", false);
        let idle = crate::inbound::Activity::new(&state);
        idle.watch(&state, open.id, remote, event_loop);
        let conn = Connection { local, remote, client_certificates: Default::default(), proxy_target: None, client: None, socket, event_loop, write_stall: Default::default(), idle, sni: None, local_name: None };
        tokio::spawn(serve_connection(state.clone(), conn, stream, measured, open));
    }
}

/// The accepted connections a stop has not closed yet: the channels of Netty's worker event loop group, whose
/// `shutdownGracefully` at the end of `LifeCycle.stopAsync` (after the drain) closes every one still open, idle
/// keep-alive connections and requests the drain gave up on alike. Each entry is a duplicate of the connection's
/// socket descriptor, so shutting it down ends the connection however many tasks share it (an HTTP/2 writer, a
/// tunnel, a binary relay); it is released when the connection's task ends, or later when TCP chaos lets go of a
/// socket it held past that task.
#[derive(Default, Clone)]
pub struct OpenConnections(Arc<parking_lot::Mutex<Registry>>, Arc<Unlocked>);

/// What every request asks of [`OpenConnections`], read without its lock: two requests per exchange queued every
/// worker on it.
#[derive(Default)]
struct Unlocked {
    /// Whether any event loop has been blocked ([`OpenConnections::block_loop`]); until then none is waited for.
    any_blocked: std::sync::atomic::AtomicBool,
    /// [`Registry::requested_http`], kept here.
    requested_http: std::sync::atomic::AtomicU64,
}

#[derive(Default)]
struct Registry {
    next: u64,
    /// The channels registered on the worker group so far, in turn: accepted connections and the runtime LLM
    /// clients' own connections ([`OpenConnections::register_client_channel`]).
    registrations: u64,
    /// The event loops ([`OpenConnections::event_loop`]) that have handled an HTTP request, one bit each.
    served_http: u64,
    /// The event loops whose thread a runtime LLM call blocks, each until when ([`OpenConnections::block_loop`]).
    blocked: std::collections::HashMap<usize, tokio::time::Instant>,
    /// Set by [`OpenConnections::close_all`]: a connection accepted as the listeners closed is shut down at once.
    closed: bool,
    /// `InboundConnectionLimiter.openConnections`: the accepted connections still open, and the loopback legs of the
    /// tunnels they carry ([`OpenConnections::loopback_leg`]).
    inbound: usize,
    rejections: crate::inbound::RejectionLog,
    #[cfg(unix)]
    open: std::collections::HashMap<u64, std::os::fd::OwnedFd>,
}

tokio::task_local! {
    /// The worker event loop whose thread handles the current request ([`Connection::event_loop`]); unset, or `None`,
    /// off the worker group (HTTP/3, the MCP executor, the scheduler, in-process callers).
    static WORKER: Option<usize>;
}

/// Runs `work` as handled on `event_loop`'s thread (`None`: off the worker group).
pub fn on_worker<F: std::future::Future>(event_loop: Option<usize>, work: F) -> impl std::future::Future<Output = F::Output> {
    WORKER.scope(event_loop, work)
}

/// The worker event loop handling the current request, if it is handled on one.
pub fn current_worker() -> Option<usize> {
    WORKER.try_with(|w| *w).ok().flatten()
}

/// Keeps a connection in [`OpenConnections`] while its task runs, or while TCP chaos holds its socket after that.
pub struct OpenConnection {
    registry: Arc<parking_lot::Mutex<Registry>>,
    id: u64,
    /// Its place among the worker group's registrations, which picks its event loop.
    registration: u64,
}

impl Drop for OpenConnection {
    fn drop(&mut self) {
        let mut registry = self.registry.lock();
        registry.inbound -= 1;
        #[cfg(unix)]
        registry.open.remove(&self.id);
    }
}

/// The slot a tunnel's loopback leg holds for as long as the tunnel lasts ([`OpenConnections::loopback_leg`]).
pub struct LoopbackLeg {
    registry: Arc<parking_lot::Mutex<Registry>>,
    /// The worker event loop the accepted loopback connection is on: the tunnel's requests are handled there.
    pub event_loop: usize,
}

impl Drop for LoopbackLeg {
    fn drop(&mut self) {
        self.registry.lock().inbound -= 1;
    }
}

impl OpenConnections {
    /// `InboundConnectionLimiter.channelRead`: the connection is counted, or, when `maxInboundConnections` (read per
    /// accept) are already open, reset at once (`SO_LINGER` 0), counted as rejected and logged (at most every 10 s).
    fn admit(&self, state: &State, stream: &TcpStream, remote: SocketAddr) -> Option<OpenConnection> {
        let max = state.config.int_property("maxInboundConnections", 0).max(0);
        {
            let mut registry = self.0.lock();
            if max > 0 && registry.inbound as i64 >= max {
                let suppressed = registry.rejections.refused();
                drop(registry);
                let _ = socket2::SockRef::from(stream).set_linger(Some(std::time::Duration::ZERO));
                state.config.metrics.inbound_connection_rejected();
                if let Some(suppressed) = suppressed {
                    crate::inbound::log_refused(state, remote, max, suppressed);
                }
                return None;
            }
            registry.inbound += 1;
        }
        Some(self.open(stream))
    }

    /// The second slot of a CONNECT or SOCKS tunnel: upstream's relay dials the server itself for every tunnel, and that
    /// loopback connection is counted and limited as any other. `RelayConnectHandler`'s client channel shares the proxy
    /// client's event loop, but the connection it opens is accepted: registered on the worker group in turn, it takes
    /// the next event loop, which handles the tunnel's requests (scenario `llm_worker_stall_tunnel`). `None` when the
    /// limit refuses it (counted and logged as a refused connection from `client`'s loopback address); the tunnel then
    /// fails.
    pub fn loopback_leg(&self, state: &State, client: SocketAddr) -> Option<LoopbackLeg> {
        let max = state.config.int_property("maxInboundConnections", 0).max(0);
        let mut registry = self.0.lock();
        if max > 0 && registry.inbound as i64 >= max {
            let suppressed = registry.rejections.refused();
            drop(registry);
            state.config.metrics.inbound_connection_rejected();
            if let Some(suppressed) = suppressed {
                crate::inbound::log_refused(state, SocketAddr::from(([127, 0, 0, 1], client.port())), max, suppressed);
            }
            return None;
        }
        registry.inbound += 1;
        registry.registrations += 1;
        let event_loop = OpenConnections::event_loop(&state.config, registry.registrations);
        Some(LoopbackLeg { registry: self.0.clone(), event_loop })
    }

    /// `MockServer.getInboundConnectionCount`: the connections open on every bound port, a tunnel counting twice.
    pub fn inbound_count(&self) -> usize {
        self.0.lock().inbound
    }

    /// Whether connection `id` is still open.
    pub(crate) fn is_open(&self, id: u64) -> bool {
        #[cfg(unix)]
        return self.0.lock().open.contains_key(&id);
        #[cfg(not(unix))]
        {
            let _ = id;
            true
        }
    }

    /// Closes connection `id` under every task that holds it (an idle timeout).
    pub(crate) fn shut_down(&self, id: u64) {
        #[cfg(unix)]
        {
            use std::os::fd::AsFd;
            if let Some(fd) = self.0.lock().open.get(&id) {
                shut_down(fd.as_fd());
            }
        }
        #[cfg(not(unix))]
        let _ = id;
    }

    fn open(&self, stream: &TcpStream) -> OpenConnection {
        let mut registry = self.0.lock();
        registry.next += 1;
        registry.registrations += 1;
        let (id, registration) = (registry.next, registry.registrations);
        #[cfg(unix)]
        {
            use std::os::fd::AsFd;
            if registry.closed {
                shut_down(stream.as_fd());
            } else if let Ok(fd) = stream.as_fd().try_clone_to_owned() {
                registry.open.insert(id, fd);
            }
        }
        #[cfg(not(unix))]
        let _ = stream;
        OpenConnection { registry: self.0.clone(), id, registration }
    }

    /// Which of the worker group's `nioEventLoopThreadCount` event loops the `registration`th channel registered on
    /// the group is on: Netty's chooser hands them out in turn.
    fn event_loop(config: &Config, registration: u64) -> usize {
        let loops = config.int_property("nioEventLoopThreadCount", 5).clamp(1, 64) as u64;
        ((registration.saturating_sub(1)) % loops) as usize
    }

    /// A runtime LLM client's new connection (`LifeCycle` builds those `NettyHttpClient`s on the `workerGroup`):
    /// registered on the worker group in turn with the accepted connections, it takes the next event loop.
    pub(crate) fn register_client_channel(&self, config: &Config) -> usize {
        let mut registry = self.0.lock();
        registry.registrations += 1;
        OpenConnections::event_loop(config, registry.registrations)
    }

    /// `event_loop`'s thread is blocked until `until` (`NettyHttpClientLlmTransport` waiting on a call that this very
    /// loop would have to read): nothing else on it is handled meanwhile ([`OpenConnections::loop_free`]).
    pub(crate) fn block_loop(&self, event_loop: usize, until: tokio::time::Instant) {
        let mut registry = self.0.lock();
        let blocked = registry.blocked.entry(event_loop).or_insert(until);
        *blocked = (*blocked).max(until);
        self.1.any_blocked.store(true, std::sync::atomic::Ordering::Release);
    }

    /// Waits while `event_loop`'s thread is blocked ([`OpenConnections::block_loop`]): a request arriving on another
    /// connection of that loop is read only once the stall ends (scenario `llm_worker_stall_concurrent`). Whether it
    /// waited.
    pub(crate) async fn loop_free(&self, event_loop: usize) -> bool {
        if !self.1.any_blocked.load(std::sync::atomic::Ordering::Acquire) {
            return false;
        }
        let mut waited = false;
        loop {
            let until = {
                let mut registry = self.0.lock();
                match registry.blocked.get(&event_loop).copied() {
                    Some(until) if until > tokio::time::Instant::now() => until,
                    Some(_) => {
                        registry.blocked.remove(&event_loop);
                        return waited;
                    }
                    None => return waited,
                }
            };
            tokio::time::sleep_until(until).await;
            waited = true;
        }
    }

    /// A timer of a channel on `event_loop` (`schedule(task, after)`): due `after` from now, but run only once the
    /// loop is free when a runtime LLM call blocks it then ([`OpenConnections::block_loop`]).
    pub(crate) async fn loop_timer(&self, event_loop: usize, after: std::time::Duration) {
        tokio::time::sleep(after).await;
        self.loop_free(event_loop).await;
    }

    /// Whether `event_loop`'s thread is blocked now ([`OpenConnections::block_loop`]).
    pub(crate) fn is_blocked(&self, event_loop: usize) -> bool {
        self.blocked_until(event_loop).is_some()
    }

    /// Until when `event_loop`'s thread is blocked, if it is now ([`OpenConnections::block_loop`]): a timer of a
    /// channel on it due meanwhile runs only then.
    pub(crate) fn blocked_until(&self, event_loop: usize) -> Option<tokio::time::Instant> {
        self.0.lock().blocked.get(&event_loop).copied().filter(|until| *until > tokio::time::Instant::now())
    }

    /// An HTTP request is handled on `event_loop`: its thread now carries `HttpState`'s thread-local port, which every
    /// entry logged on it later is stamped with.
    pub(crate) fn served_http(&self, event_loop: usize) {
        self.0.lock().served_http |= 1 << event_loop;
    }

    /// An HTTP request reaches `HttpState` on `event_loop`'s thread, which sets its thread-local port there.
    pub(crate) fn requested_http(&self, event_loop: usize) {
        let bit = 1 << event_loop;
        // set once per event loop: read first, so the cache line is not written by every request
        if self.1.requested_http.load(std::sync::atomic::Ordering::Relaxed) & bit == 0 {
            self.1.requested_http.fetch_or(bit, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Whether a request reached `HttpState` on `event_loop`'s thread: a gRPC request `GrpcToHttpRequestHandler`
    /// refuses never does, so what it logs there carries no port until another request has.
    pub(crate) fn has_requested_http(&self, event_loop: usize) -> bool {
        self.1.requested_http.load(std::sync::atomic::Ordering::Relaxed) & 1 << event_loop != 0
    }

    /// Whether `event_loop`'s thread has handled an HTTP request: until then, what it logs carries no port (a binary
    /// connection's entries are logged on its event loop).
    pub(crate) fn has_served_http(&self, event_loop: usize) -> bool {
        self.0.lock().served_http & 1 << event_loop != 0
    }

    /// Closes every connection still open (the worker group's shutdown); later ones are closed as they arrive.
    pub fn close_all(&self) {
        let mut registry = self.0.lock();
        registry.closed = true;
        #[cfg(unix)]
        {
            use std::os::fd::AsFd;
            for fd in std::mem::take(&mut registry.open).values() {
                shut_down(fd.as_fd());
            }
        }
    }
}

/// Both directions: the peer reads end of stream, and the connection's own reads end too, so its task finishes.
#[cfg(unix)]
fn shut_down(fd: std::os::fd::BorrowedFd<'_>) {
    let _ = socket2::SockRef::from(&fd).shutdown(std::net::Shutdown::Both);
}

/// How long a new connection waits before its first bytes are read: the `connectionDelay` of the configuration (a
/// `PUT /mockserver/configuration` value, sampled from its distribution if it has one), else
/// `connectionDelayMillis`.
fn connection_delay(config: &Config) -> std::time::Duration {
    let configured = config.property("connectionDelay").and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok());
    match configured {
        Some(json) => crate::action::delay(&json).map(|d| d.sample()).unwrap_or_default(),
        None => std::time::Duration::from_millis(config.int_property("connectionDelayMillis", 0).max(0) as u64),
    }
}

/// `measured` counts the connection in `mock_server_active_connections` until this returns, and
/// `open` keeps it where a stop closes it; once handed to a [`ChaosIo`], both last until its socket closes: TCP chaos
/// may hold the socket open past this task, and a stop still closes it then.
async fn serve_connection(state: Arc<State>, mut conn: Connection, mut stream: TcpStream, mut measured: Option<crate::metrics::ServerConnection>, open: OpenConnection) {
    let mut open = Some(open);
    // `PortUnificationHandler.channelActive`: a configured connection delay holds back the first read.
    let delay = connection_delay(&state.config);
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    let mut buf = BytesMut::with_capacity(16 * 1024);
    if state.config.hot_bool(crate::config::Hot::TransparentProxyEnabled, false) {
        // `CompositeOriginalDestinationResolver`'s default chain, minus conntrack (out of scope): TPROXY, eBPF, SO_ORIGINAL_DST (`crate::proxy_resolvers::resolve`), then
        // `DnsIntentOriginalDestinationResolver` — the name a DNS answer gave the address the client connected to.
        // An explicit PROXY protocol header (read from the connection's first bytes) always wins, whichever of
        // those resolved: `TransparentProxyHandler`'s channel-level chain runs first, but a PROXY header is more
        // authoritative when present.
        use std::os::fd::AsRawFd;
        if let Some(target) = crate::proxy_resolvers::resolve(&state.config, conn.local, stream.as_raw_fd()) {
            conn.proxy_target = Some((target.ip().to_string(), target.port()));
        } else if let Some(name) = crate::dns::intent(conn.local.ip()) {
            conn.proxy_target = Some((name, conn.local.port()));
        }
        // `TransparentProxyHandler.resolveAndSetOriginalDestination`, on `channelActive`.
        if crate::log::debug_enabled(&state) {
            use crate::recorded::{Arg, Level, LogEntry};
            let channel = channel_description(&conn);
            let entry = match &conn.proxy_target {
                Some((host, port)) => LogEntry::at(Level::Debug, "transparent proxy: resolved original destination {} for channel {} via resolver chain")
                    .args([Arg::socket_address(java_inet_socket_address(host, *port)), Arg::from(channel)]),
                None => LogEntry::at(Level::Debug, "transparent proxy: using Host header fallback for channel {}").args([channel]),
            };
            crate::log::entry(&state, &entry);
            state.log.message(entry);
        }
        // `ProxyProtocolOriginalDestinationHandler` sits in front of the port unification (since b765b8271): a
        // PROXY header is consumed, and what follows it is classified as any connection's first bytes are.
        let channel = channel_description(&conn);
        let header = proxy_protocol(&state, &channel, &mut stream, &mut buf).await;
        if let Some(target) = header.destination {
            conn.proxy_target = Some(target);
        }
        if header.source.is_some() {
            conn.client = header.source;
        }
    }
    // `startServerFirstWait`: a client silent this long may be waiting for a server that speaks first
    if buf.is_empty()
        && let Some(wait) = crate::binary::server_first_wait(&state, &conn)
        && tokio::time::timeout(wait, stream.readable()).await.is_err()
    {
        conn.idle.touch();
        let stream = conn.idle.wrap(WriteStallIo::new(&state, &conn.write_stall, conn.event_loop, stream));
        return crate::binary::serve_server_first(state, conn, stream, wait).await;
    }
    // Read until the first bytes rule the HTTP/2 preface, a SOCKS handshake, TLS and an HTTP method in or out.
    let Some(taken_as_they_are) = read_until_decided(&mut stream, &mut buf, true).await else { return };
    // nothing is read on an event loop a runtime LLM call blocks: no TLS handshake, no protocol detection
    state.connections.loop_free(conn.event_loop).await;
    let first = if taken_as_they_are { First::Other } else { classify(&buf, true) };
    // what was read reached the idle handler, but for a ClientHello or a SOCKS greeting, which `SniHandler` and the
    // SOCKS handlers in front of it take
    if !matches!(first, First::Tls | First::Socks4 | First::Socks5) {
        conn.idle.touch();
    }
    match first {
        First::Socks4 => {
            log_stage(&state, &conn, "adding SOCKS4 decoders");
            let stream = conn.idle.wrap(WriteStallIo::new(&state, &conn.write_stall, conn.event_loop, stream));
            return crate::socks::serve4(state, conn, Box::new(stream), buf, false).await;
        }
        First::Socks5 => {
            log_stage(&state, &conn, "adding SOCKS5 decoders");
            let stream = conn.idle.wrap(WriteStallIo::new(&state, &conn.write_stall, conn.event_loop, stream));
            return crate::socks::serve5(state, conn, Box::new(stream), buf, false).await;
        }
        _ => {}
    }
    if first == First::Tls {
        log_stage(&state, &conn, "adding TLS decoders");
        if let Some(measured) = measured.as_mut() {
            measured.tls();
        }
        let Some(tls) = state.tls.as_ref() else { return };
        if !first_record_acceptable(&state, &conn, &mut stream, &mut buf).await {
            return;
        }
        // `SniHandler.lookup` builds the server's context (`createServerSslContext`) once a whole ClientHello is in.
        let complete = client_hello_complete(&state, &mut stream, &mut buf).await;
        // `InboundConnectionActivity.isBusy`: the server's context being built and the handshake under way
        let handshaking = conn.idle.handshake();
        let sni = client_hello_server_name(&buf);
        conn.sni = sni.clone();
        let context_built = complete && tls.server_context_needed(&state, sni.as_deref());
        if let Some(refused) = tls.refusal(sni.as_deref()) {
            tls_warnings(&state);
            return refused_context_fault(&state, &conn, refused);
        }
        if let Some(refusal) = tls.unusable_key_failure(&client_hello_offer(&buf)) {
            tls_warnings(&state);
            return unusable_key_handshake(&state, &conn, &mut stream, &refusal).await;
        }
        let acceptor = tls.acceptor();
        tls_warnings(&state);
        // Fallible: the connection is closed only after the fault is logged, as Netty's `exceptionCaught` logs before
        // `ctx.close()`; a client that saw the close and then reset must not find the entry arriving after it.
        let started = std::time::Instant::now();
        let io = conn.idle.wrap(WriteStallIo::new(&state, &conn.write_stall, conn.event_loop, stream));
        let handshake = inbound_handshake(&state, conn.event_loop, acceptor.accept(Rewind { prefix: buf, inner: io }).into_fallible()).await;
        handshake_measured(&state, started, &handshake, measured.as_mut());
        let tls_stream = match handshake {
            Some(Ok(tls_stream)) => {
                handshaking.completed();
                tls_stream
            }
            Some(Err((e, io))) => {
                tls_fault(&state, &conn, &e);
                return drop(io);
            }
            None => return,
        };
        let session = tls_stream.get_ref().1;
        if let Some(chain) = session.peer_certificates() {
            conn.client_certificates = Arc::new(chain.iter().filter_map(|c| crate::tls::client_cert::describe(c)).collect());
        }
        let alpn = session.alpn_protocol().map(<[u8]>::to_vec);
        let h2 = alpn.as_deref() == Some(b"h2");
        // TCP chaos acts on the decrypted bytes, as `TcpChaosHandler` sits after the `SslHandler`.
        let io = ChaosIo::new(&state, conn.remote, conn.socket, crate::tls::flush_on_read::FlushOnRead::new(tls_stream)).holding(Some((measured.take(), open.take())));
        if h2 {
            log_alpn(&state, alpn.as_deref());
            log_stage_in_tls(&state, &conn, "adding HTTP2 decoders", context_built);
            // `switchToHttp2Multiplex` asks for the client's certificates
            log_no_client_certificate(&state, &conn);
            serve_h2(state, conn, io, true, false).await;
        } else {
            Box::pin(serve_unified_inner(state, conn, io, true, Some(context_built), alpn)).await;
        }
    } else if first == First::H2c {
        log_stage(&state, &conn, "adding HTTP2 cleartext (h2c) decoders");
        let stream = conn.idle.wrap(WriteStallIo::new(&state, &conn.write_stall, conn.event_loop, stream));
        let io = ChaosIo::new(&state, conn.remote, conn.socket, Rewind { prefix: buf, inner: stream }).holding(Some((measured.take(), open.take())));
        serve_h2(state, conn, io, false, false).await;
    } else if is_binary(&state, first) {
        log_stage(&state, &conn, "adding binary decoder");
        let stream = conn.idle.wrap(WriteStallIo::new(&state, &conn.write_stall, conn.event_loop, stream));
        crate::binary::serve(state, conn, stream, buf, false).await;
    } else if state.config.hot_bool(crate::config::Hot::TlsMutualAuthenticationRequired, false)
        && state.config.bool_property("controlPlaneTLSMutualAuthenticationRequired", false)
    {
        log_stage(&state, &conn, "adding HTTP decoders");
        no_tls_for_connection(&state, &conn, stream).await;
    } else {
        log_stage(&state, &conn, "adding HTTP decoders");
        let stream = conn.idle.wrap(WriteStallIo::new(&state, &conn.write_stall, conn.event_loop, stream));
        let io = ChaosIo::new(&state, conn.remote, conn.socket, Rewind { prefix: buf, inner: stream }).holding(Some((measured.take(), open.take())));
        state.connections.served_http(conn.event_loop);
        http1::serve(state, conn, io, BytesMut::new(), false).await;
    }
}

/// `PortUnificationHandler.switchToHttp` with both mutual-TLS flags and no TLS upstream: before any request is parsed
/// the connection is told to upgrade (426, no reason phrase in the logged response) and disconnected. The handler
/// then fails in its own decoder, which `exceptionCaught` logs twice (on the read and again when the channel closes).
/// All three entries are logged on Netty's event loop, whose thread never had `HttpState.setPort`, so the console
/// shows them with no port.
async fn no_tls_for_connection(state: &State, conn: &Connection, mut stream: TcpStream) {
    use crate::recorded::{Arg, Level, LogEntry};
    use tokio::io::AsyncWriteExt;
    let response = serde_json::json!({"statusCode": 426, "headers": {"Upgrade": ["TLS/1.2, HTTP/1.1"], "Connection": ["Upgrade"]}});
    if state.info_enabled() {
        let entry = LogEntry::new(crate::recorded::Kind::Info, "no tls for connection:{}returning response:{}")
            .args([Arg::socket_address(format!("/{}", java_socket_address(conn.local))), Arg::from(&response)])
            .without_port();
        crate::log::info_event(state, entry);
    }
    let _ = stream.write_all(b"HTTP/1.1 426 Upgrade Required\r\nUpgrade: TLS/1.2, HTTP/1.1\r\nConnection: Upgrade\r\ncontent-length: 0\r\n\r\n").await;
    let _ = stream.shutdown().await;
    let id = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    for _ in 0..2 {
        let message = format!(
            "SSL or decoder fault caught by port unification handler -> closing pipeline [id: 0x{id}, L:/{} ! R:/{}]\nshaded_package.io.netty.handler.codec.DecoderException: PortUnificationHandler.decode() must consume the inbound data or change its state if it did not decode anything.",
            java_socket_address(conn.local), java_socket_address(conn.remote)
        );
        crate::log::warn_event(state, LogEntry::at(Level::Warn, message).without_port());
    }
}

/// `SniHandler.onLookupComplete` when `createServerSslContext` failed ([`crate::tls::Tls::refusal`]): its SEVERE entry, if
/// any, then the `DecoderException` `PortUnificationHandler.exceptionCaught` logs as an "SSL or decoder fault" with the
/// exception as the entry's throwable (Java frames left out), not in its message.
/// A handshake with a fixed certificate whose key this TLS stack cannot serve to this client (a DSA key;
/// an Ed448 key the client's schemes rule out): the oracle's JDK fails it as `refusal.reason` with a fatal
/// alert (after its ServerHello in TLS 1.3, and for an `internal_error` in TLS 1.2 too, which this sends in the clear
/// before any), and `ClientTlsHandshakeFailureLog` logs it. Logged before the alert goes out, as the other failed
/// handshakes are logged before the close.
async fn unusable_key_handshake<S: tokio::io::AsyncWrite + Unpin + ?Sized>(state: &State, conn: &Connection, stream: &mut S, refusal: &crate::tls::KeyRefusal) {
    use tokio::io::AsyncWriteExt;
    let reason = &refusal.reason;
    let causes = format!("{reason} {} ", reason.split_once(": ").map_or(reason.as_str(), |(_, message)| message));
    if let Some(context) = state.tls.as_ref() {
        context.handshake_failures.log(state, crate::tls::handshake_failures::Transport::Tcp, conn.remote, reason, &causes);
    }
    // a fatal (2) alert record
    let _ = stream.write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, refusal.alert]).await;
    let _ = stream.flush().await;
}

fn refused_context_fault(state: &State, conn: &Connection, (sni, cause, severe): (Option<String>, String, Option<String>)) {
    use crate::recorded::{Level, LogEntry};
    if let Some(severe) = severe {
        // `BCKeyAndCertificateFactory` logs the generation failure's message with the exception as its throwable
        const GENERATION: &str = "exception while generating private key and X509 certificate\n";
        let entry = match severe.strip_prefix(GENERATION) {
            Some(cause) => LogEntry::at(Level::Error, GENERATION.trim_end()).throwable(cause),
            None => LogEntry::at(Level::Error, severe),
        };
        crate::log::error_event(state, entry);
    }
    let id = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    let target = sni.clone().unwrap_or_default();
    let sni = sni.map(|name| format!(" (SNI: {name})")).unwrap_or_default();
    let message = format!("SSL or decoder fault caught by port unification handler -> closing pipeline [id: 0x{id}, L:/{} - R:/{}]{sni}", java_socket_address(conn.local), java_socket_address(conn.remote));
    let throwable = format!("shaded_package.io.netty.handler.codec.DecoderException: Failed to get the SslContext for {target}\n{cause}");
    if matches!(state.log_level.as_str(), "OFF" | "ERROR") {
        return;
    }
    // the console prints the exception and its causes after the message; the event log keeps them on the entry
    let lines: Vec<&str> = throwable.lines().map(|line| line.strip_prefix("Caused by: ").unwrap_or(line)).collect();
    let entry = LogEntry::at(Level::Warn, message).throwable(&throwable).throwable_bean(bounded_fault_bean(&lines));
    // logged on the channel's event loop, whose thread carries a port only once it has handled an HTTP request
    let entry = if state.connections.has_served_http(conn.event_loop) { entry } else { entry.without_port() };
    crate::log::entry_with_throwable(state, Level::Warn, &entry, None, &throwable);
    state.log.message(entry);
}

/// `ExceptionHandling.boundedFault(throwable)` as the event log's JSON shows it: `lines` is the exception and its
/// causes, outermost first, one `Throwable.toString` each. When a message is longer than `MAX_FAULT_MESSAGE_LENGTH`
/// (256 UTF-16 units), the throwable is a `RedactedThrowable` copy whose every message leads with the original class
/// name and is cut by `StringUtils.abbreviate`; otherwise it is the original, its messages without class names. The
/// JVM frames are not reproduced (`stackTrace` empty, docs/divergences.md).
fn bounded_fault_bean(lines: &[&str]) -> serde_json::Value {
    use serde_json::{Map, Value};
    const MAX_FAULT_MESSAGE_LENGTH: usize = 256;
    let split = |line: &'_ str| -> (String, Option<String>) {
        match line.split_once(": ") {
            Some((class, message)) => (class.to_string(), Some(message.to_string())),
            None => (line.to_string(), None),
        }
    };
    let units = |text: &str| text.encode_utf16().count();
    let copied = lines.iter().any(|line| split(line).1.is_some_and(|message| units(&message) > MAX_FAULT_MESSAGE_LENGTH));
    // `StringUtils.abbreviate(message, 256)`: the first 253 units and "..."
    let abbreviate = |message: &str| -> String {
        if units(message) <= MAX_FAULT_MESSAGE_LENGTH {
            return message.to_string();
        }
        let mut cut = String::new();
        let mut taken = 0;
        for c in message.chars() {
            taken += c.len_utf16();
            if taken > MAX_FAULT_MESSAGE_LENGTH - 3 {
                break;
            }
            cut.push(c);
        }
        cut + "..."
    };
    let mut bean: Option<Value> = None;
    for line in lines.iter().rev() {
        let (class, message) = split(line);
        let shown = match (copied, message) {
            (true, Some(message)) => Some(format!("{class}: {}", abbreviate(&message))),
            (true, None) => Some(class),
            (false, message) => message,
        };
        let mut throwable = Map::new();
        if let Some(cause) = bean.take() {
            throwable.insert("cause".into(), cause);
        }
        if let Some(shown) = shown {
            throwable.insert("localizedMessage".into(), Value::String(shown.clone()));
            throwable.insert("message".into(), Value::String(shown));
        }
        throwable.insert("stackTrace".into(), Value::Array(Vec::new()));
        bean = Some(Value::Object(throwable));
    }
    bean.unwrap_or(Value::Null)
}

/// `PortUnificationHandler.exceptionCaught` for a failed TLS handshake. A peer that simply went away (end of stream,
/// reset) is not logged. An engine failure the oracle's JDK reports as an `SSLHandshakeException` or a plain
/// `SSLException` goes to `ClientTlsHandshakeFailureLog` (b765b8271: WARN once per client address, then DEBUG,
/// [`crate::tls::handshake_failures`]); a malformed record Netty's decoder rejects before the engine sees it is a WARN
/// "SSL or decoder fault" naming the closed channel as Netty prints it.
fn tls_fault(state: &State, conn: &Connection, error: &std::io::Error) {
    use crate::recorded::{Level, LogEntry};
    // A fixed certificate the validator refused left this handshake without a certificate: Netty's decoder fault.
    if let Some(refused) = state.tls.as_ref().and_then(|tls| tls.take_refused()) {
        return refused_context_fault(state, conn, refused);
    }
    use rustls::{AlertDescription as Alert, Error as Tls};
    use std::io::ErrorKind;
    if matches!(error.kind(), ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted | ErrorKind::TimedOut) {
        return;
    }
    let tls = error.get_ref().and_then(|e| e.downcast_ref::<Tls>());
    match tls {
        Some(Tls::AlertReceived(Alert::CloseNotify)) => {}
        Some(failure) => match jdk_handshake_failure(failure) {
            Some(reason) => {
                // `allMessages`: the `DecoderException`'s message (its cause's `toString`), then the cause's own
                let causes = format!("{reason} {} ", reason.split_once(": ").map_or(reason.as_str(), |(_, message)| message));
                if let Some(context) = state.tls.as_ref() {
                    context.handshake_failures.log(state, crate::tls::handshake_failures::Transport::Tcp, conn.remote, &reason, &causes);
                }
            }
            None => {
                let id = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
                let message = format!("SSL or decoder fault caught by port unification handler -> closing pipeline [id: 0x{id}, L:/{} ! R:/{}]", java_socket_address(conn.local), java_socket_address(conn.remote));
                crate::log::warn_event(state, LogEntry::at(Level::Warn, message));
            }
        },
        None => {}
    }
}

/// `Throwable.toString` of the exception the oracle's JDK `SSLEngine` fails an inbound handshake with, for the
/// failures `ExceptionHandling.sslHandshakeException` counts (exactly an `SSLHandshakeException` or `SSLException`,
/// so not an `SSLProtocolException`); `None` for one Netty or the engine reports otherwise, a decoder fault.
fn jdk_handshake_failure(failure: &rustls::Error) -> Option<String> {
    use rustls::{ContentType, Error as Tls, InvalidMessage, PeerIncompatible};
    const HANDSHAKE: &str = "javax.net.ssl.SSLHandshakeException";
    Some(match failure {
        // a record Netty's `SslHandler` refuses before the engine reads it
        Tls::InvalidMessage(InvalidMessage::HandshakePayloadTooLarge) => return None,
        Tls::AlertReceived(alert) => {
            // `Alert.createSSLException` for a fatal alert the peer sent (`TransportContext.fatal`)
            let (name, handshake_only) = crate::tls::handshake_failures::jdk_alert(u8::from(*alert)).unwrap_or(("unknown", true));
            match name {
                "unexpected_message" => return None,
                _ if handshake_only => format!("{HANDSHAKE}: ({name}) Received fatal alert: {name}"),
                _ => format!("javax.net.ssl.SSLException: ({name}) Received fatal alert: {name}"),
            }
        }
        // `SSLEngineInputRecord`: a first record that is neither a handshake nor an alert
        Tls::InappropriateMessage { got_type: ContentType::ApplicationData | ContentType::ChangeCipherSpec, .. } => "javax.net.ssl.SSLException: Unrecognized SSL message, plaintext connection?".into(),
        Tls::InvalidMessage(_) => format!("{HANDSHAKE}: (decode_error) Illegal handshake message: client_hello"),
        Tls::PeerIncompatible(PeerIncompatible::NoCipherSuitesInCommon) => format!("{HANDSHAKE}: (handshake_failure) no cipher suites in common"),
        // `CertificateMessage`'s consumer when a required client certificate chain is empty (TLS 1.3's alert; read off
        // the oracle)
        Tls::NoCertificatesPresented => format!("{HANDSHAKE}: (certificate_required) Empty client certificate chain"),
        // no text of the JDK's is known for the rest: rustls's own reason stands in for it
        other => format!("{HANDSHAKE}: {other}"),
    })
}

/// The WARN texts `CertificateConfigurationValidator` queued while the server's TLS context was built.
fn tls_warnings(state: &State) {
    for entry in state.tls.as_ref().map(|tls| tls.take_warnings()).unwrap_or_default() {
        crate::log::warn_event(state, entry);
    }
}

/// What a PROXY protocol header said: the destination (`REMOTE_SOCKET`) and the client (`PROXY_PROTOCOL_SOURCE`).
#[derive(Default)]
struct ProxyHeader {
    destination: Option<(String, u16)>,
    source: Option<SocketAddr>,
}

/// `ProxyProtocolOriginalDestinationHandler`, in front of the port unification: a leading PROXY protocol v1 line or
/// v2 header is consumed (a v1 line that does not parse too) and anything else is left in `buf` untouched. Bytes that
/// stop matching a signature are passed on at once; bytes that are only the start of one are passed on once the client
/// has been silent for [`UNDECIDED_PROTOCOL_WAIT`]. Its WARN and DEBUG entries follow it.
async fn proxy_protocol(state: &State, channel: &str, stream: &mut TcpStream, buf: &mut BytesMut) -> ProxyHeader {
    use crate::recorded::{Arg, Level, LogEntry};
    const V1: &[u8] = b"PROXY ";
    const V2: &[u8] = &[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];
    const MAX_V1_LINE: usize = 108;
    const MAX_V2_ADDRESS: usize = 1024;
    let warn = |format: &str, argument: Arg| crate::log::warn_event(state, LogEntry::at(Level::Warn, format!("transparent proxy: {format}")).args([argument]));
    let debug = |format: &str, arguments: Vec<Arg>| {
        if crate::log::debug_enabled(state) {
            let entry = LogEntry::at(Level::Debug, format).args(arguments);
            crate::log::entry(state, &entry);
            state.log.message(entry);
        }
    };
    let resolved = |host: String, port: u16, via: &str, source: Option<SocketAddr>| {
        let address = java_inet_socket_address(&host, port);
        debug(
            "transparent proxy: resolved original destination {} for channel {} via PROXY protocol {}",
            vec![Arg::socket_address(address), Arg::from(channel), Arg::from(via)],
        );
        ProxyHeader { destination: Some((host, port)), source }
    };
    // Whether the bytes received so far match `signature` for as far as they go.
    let matches = |buf: &BytesMut, signature: &[u8]| buf[..buf.len().min(signature.len())] == signature[..buf.len().min(signature.len())];
    loop {
        // (bytes wanted, whether the client's silence passes on what came so far)
        let (wanted, undecided) = match buf.first() {
            None => (1, false),
            Some(0x0D) if !matches(buf, V2) => return ProxyHeader::default(),
            Some(0x0D) if buf.len() < V2.len() => (V2.len(), true),
            Some(0x0D) if buf.len() < 16 => (16, false),
            Some(0x0D) => {
                let version = buf[12] >> 4;
                if version != 2 {
                    warn("unsupported PROXY protocol v2 version nibble ({}), passing through", serde_json::json!(version).into());
                    return ProxyHeader::default();
                }
                let address_length = u16::from_be_bytes([buf[14], buf[15]]) as usize;
                if address_length > MAX_V2_ADDRESS {
                    warn("PROXY protocol v2 address length ({} bytes) exceeds maximum, passing through", serde_json::json!(address_length).into());
                    return ProxyHeader::default();
                }
                let length = 16 + address_length;
                if buf.len() >= length {
                    let header = buf.split_to(length);
                    let (command, family, block) = (header[12] & 0x0F, header[13] >> 4, &header[16..]);
                    // `extractV2Address`: source, destination, source port, destination port.
                    let addresses = match (command, family) {
                        (0x01, 0x1) if block.len() >= 12 => {
                            let ip = |at: usize| std::net::IpAddr::from(<[u8; 4]>::try_from(&block[at..at + 4]).expect("4 bytes"));
                            Some((ip(0), ip(4), u16::from_be_bytes([block[8], block[9]]), u16::from_be_bytes([block[10], block[11]])))
                        }
                        (0x01, 0x2) if block.len() >= 36 => {
                            let ip = |at: usize| std::net::IpAddr::from(<[u8; 16]>::try_from(&block[at..at + 16]).expect("16 bytes"));
                            Some((ip(0), ip(16), u16::from_be_bytes([block[32], block[33]]), u16::from_be_bytes([block[34], block[35]])))
                        }
                        _ => None,
                    };
                    return match addresses {
                        Some((source, destination, source_port, port)) => {
                            resolved(destination.to_string(), port, "v2", Some(SocketAddr::new(source, source_port)))
                        }
                        None => {
                            debug(
                                "transparent proxy: PROXY protocol v2 header (command {}, family {}) carried no usable destination for channel {}, deferring to downstream resolution",
                                vec![serde_json::json!(command).into(), serde_json::json!(family).into(), Arg::from(channel)],
                            );
                            ProxyHeader::default()
                        }
                    };
                }
                (length, false)
            }
            Some(_) if !matches(buf, V1) => return ProxyHeader::default(),
            Some(_) if buf.len() < V1.len() => (V1.len(), true),
            Some(_) => match buf.windows(2).position(|w| w == b"\r\n") {
                Some(end) => {
                    let line: String = buf[..end].iter().map(|&b| if b < 0x80 { b as char } else { '\u{FFFD}' }).collect();
                    let _ = buf.split_to(end + 2);
                    // `parseAndApply`: `split("\\s+")` into PROXY, protocol, source, destination, ports.
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    let parsed = match parts.as_slice() {
                        ["PROXY", "UNKNOWN", ..] => {
                            debug("transparent proxy: PROXY protocol UNKNOWN received for channel {}, deferring to downstream resolution", vec![Arg::from(channel)]);
                            return ProxyHeader::default();
                        }
                        ["PROXY", protocol @ ("TCP4" | "TCP6"), source, destination, source_port, port, ..] => {
                            port.parse::<i32>().ok().filter(|p| (0..=65535).contains(p)).map(|p| {
                                // `v1Source`: an IP literal and a port in range, else none.
                                let source = source
                                    .parse::<std::net::IpAddr>()
                                    .ok()
                                    .zip(source_port.parse::<i32>().ok().filter(|p| (0..=65535).contains(p)))
                                    .map(|(ip, port)| SocketAddr::new(ip, port as u16));
                                (protocol.to_string(), destination.to_string(), p as u16, source)
                            })
                        }
                        _ => None,
                    };
                    return match parsed {
                        Some((protocol, host, port, source)) => resolved(host, port, &format!("v1 ({protocol})"), source),
                        None => {
                            warn("malformed PROXY protocol v1 header: \"{}\", passing through", Arg::from(line));
                            ProxyHeader::default()
                        }
                    };
                }
                None if buf.len() > MAX_V1_LINE => {
                    warn("PROXY protocol v1 header exceeds maximum length ({} bytes) without CRLF terminator, passing through", serde_json::json!(buf.len()).into());
                    return ProxyHeader::default();
                }
                None => (buf.len() + 1, false),
            },
        };
        while buf.len() < wanted {
            let read = match undecided {
                true => match tokio::time::timeout(UNDECIDED_PROTOCOL_WAIT, stream.read_buf(buf)).await {
                    Ok(read) => read,
                    // `startUndecidedWait`: the client fell silent on the start of a signature
                    Err(_) => return ProxyHeader::default(),
                },
                false => stream.read_buf(buf).await,
            };
            match read {
                Ok(0) | Err(_) => return ProxyHeader::default(),
                Ok(_) => {}
            }
        }
    }
}

/// Netty's `Channel.toString` for an accepted connection: `[id: 0x…, L:/local - R:/remote]`.
pub(crate) fn channel_description(conn: &Connection) -> String {
    let id = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    netty_channel(&id, conn.local, conn.remote)
}

fn netty_channel(id: &str, local: SocketAddr, remote: SocketAddr) -> String {
    format!("[id: 0x{id}, L:/{} - R:/{}]", java_socket_address(local), java_socket_address(remote))
}

/// The handlers `MockServerUnificationInitializer` puts in front of the unification handler (b765b8271): the
/// write-stall and inbound-idle timeouts (each `addFirst`, so the later one first) behind `ReadAfterFailedWrite`'s.
const UNIFICATION_PIPELINE: [&str; 5] = ["ReadAfterFailedWrite$OutputEnded#0", "write-stall", "inbound-idle", "PortUnificationHandler#0", "DefaultChannelPipeline$TailContext#0"];

/// `PortUnificationHandler.logStage`, at TRACE: the decoders a connection's first bytes chose, its channel and the
/// pipeline's handler names: on a plain connection the initializer's handlers, the unification handler's and the tail's.
fn log_stage(state: &State, conn: &Connection, stage: &str) {
    log_stage_in(state, conn, stage, &UNIFICATION_PIPELINE);
}

/// [`log_stage`] for the second pass, on the bytes inside TLS: the `SslHandler` and the `LoggingHandler` the first
/// pass added at TRACE come first. `addLoggingHandler` puts it after an `SslHandler`, else first; the `SniHandler`
/// has become the `SslHandler` by then only when the server's context was cached, not when the handshake built it
/// (`context_built`, [`crate::tls::Tls::server_context_needed`]).
fn log_stage_in_tls(state: &State, conn: &Connection, stage: &str, context_built: bool) {
    let front = if context_built { ["LoggingHandler#0", "SslHandler#0"] } else { ["SslHandler#0", "LoggingHandler#0"] };
    let pipeline: Vec<&str> = front.into_iter().chain(UNIFICATION_PIPELINE).collect();
    log_stage_in(state, conn, stage, &pipeline);
}

fn log_stage_in(state: &State, conn: &Connection, stage: &str, pipeline: &[&str]) {
    if state.log_level != "TRACE" {
        return;
    }
    use crate::recorded::Arg;
    let names = Arg::with_text(serde_json::json!(pipeline), format!("[{}]", pipeline.join(", ")));
    let entry = LogEntry::at(Level::Trace, format!("{stage} for channel:{{}}pipeline:{{}}")).args([Arg::from(channel_description(conn)), names]);
    crate::log::entry(state, &entry);
    state.log.message(entry);
}

/// `SniHandler.getALPNProtocol`, at TRACE: the second unification pass asks for the protocol the handshake negotiated
/// (only with `http2Enabled`, which it checks first), and the first ask logs a non-blank one as the peer named it.
fn log_alpn(state: &State, alpn: Option<&[u8]>) {
    let Some(alpn) = alpn.filter(|a| !a.trim_ascii().is_empty()) else { return };
    if state.log_level != "TRACE" || !state.config.bool_property("http2Enabled", true) {
        return;
    }
    let entry = LogEntry::at(Level::Trace, "found ALPN protocol:{}").args([crate::recorded::Arg::from(String::from_utf8_lossy(alpn).into_owned())]);
    crate::log::entry(state, &entry);
    state.log.message(entry);
}

/// `SniHandler.retrieveClientCertificates`, at TRACE, on a TLS connection whose client sent no certificate: each ask
/// logs again, as a failed ask caches nothing (the HTTP/2 pipeline's set-up asks once; on HTTP/1.1 the codec's set-up
/// and `EarlyMatchingHandler`'s first request ask once each).
pub(crate) fn log_no_client_certificate(state: &State, conn: &Connection) {
    if state.log_level != "TRACE" || !conn.client_certificates.is_empty() {
        return;
    }
    let entry = LogEntry::at(Level::Trace, "no client certificate chain as client did not complete mTLS");
    crate::log::entry(state, &entry);
    state.log.message(entry);
}

/// Bytes of no protocol `PortUnificationHandler` knows, and `assumeAllRequestsAreHttp` is off:
/// `switchToBinaryRequestProxying`.
fn is_binary(state: &State, first: First) -> bool {
    first == First::Other && !state.config.bool_property("assumeAllRequestsAreHttp", false)
}

/// What a connection's first bytes are, as `PortUnificationHandler.decode` tells: a SOCKS4 request, a SOCKS5 greeting,
/// a TLS record, the HTTP/2 preface or an HTTP method, in that order (`outer`: the first two only before any TLS);
/// `Wait` while they are only the start of one, and `Other` once they cannot become any.
#[derive(Debug, Clone, Copy, PartialEq)]
enum First {
    Wait,
    Socks4,
    Socks5,
    Tls,
    H2c,
    Http,
    Other,
}

fn classify(buf: &[u8], outer: bool) -> First {
    if buf.is_empty() {
        return First::Wait;
    }
    match crate::socks::sniff(buf) {
        Sniff::Socks4 => return First::Socks4,
        Sniff::Socks5 => return First::Socks5,
        Sniff::More => return First::Wait,
        Sniff::No => {}
    }
    if outer {
        match probe_tls(buf) {
            TlsProbe::More => return First::Wait,
            TlsProbe::Tls => return First::Tls,
            TlsProbe::No => {}
        }
        if H2_PREFACE.starts_with(&buf[..buf.len().min(H2_PREFACE.len())]) {
            return if buf.len() >= H2_PREFACE.len() { First::H2c } else { First::Wait };
        }
    }
    match crate::binary::is_http(buf) {
        Some(true) => First::Http,
        Some(false) => First::Other,
        None => First::Wait,
    }
}

/// `PortUnificationHandler.UNDECIDED_PROTOCOL_WAIT_MILLIS`: how long first bytes that are only the start of a known
/// protocol are held once the client falls silent, before they are taken for what they are.
pub(crate) const UNDECIDED_PROTOCOL_WAIT: std::time::Duration = std::time::Duration::from_millis(1000);

/// Reads until [`classify`] can tell what the first bytes are. `Some(true)` when they are to be taken as they are
/// (`takeBytesReceivedAsTheyAre`, which makes them binary): the client fell silent for [`UNDECIDED_PROTOCOL_WAIT`]
/// while they were undecided, or closed (`decodeLast`). `None` when the client closed having sent nothing.
async fn read_until_decided<S: tokio::io::AsyncRead + Unpin>(stream: &mut S, buf: &mut BytesMut, outer: bool) -> Option<bool> {
    while classify(buf, outer) == First::Wait {
        // nothing received yet starts no wait: a connection waits for its client's first byte
        let read = if buf.is_empty() {
            Ok(stream.read_buf(buf).await)
        } else {
            tokio::time::timeout(UNDECIDED_PROTOCOL_WAIT, stream.read_buf(buf)).await
        };
        match read {
            Ok(Ok(0)) | Ok(Err(_)) if buf.is_empty() => return None,
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return Some(true),
            Ok(Ok(_)) => {}
        }
    }
    Some(false)
}

/// `PortUnificationHandler` again, on a stream whose first bytes are still to be classified: inside TLS, or after a
/// SOCKS5 greeting whose methods were all refused (`Socks5ProxyHandler` answers `UNACCEPTED` and leaves the connection
/// to the `PortUnificationHandler` still behind it). A SOCKS handshake, binary, else HTTP/1.1.
pub(crate) fn serve_unified<S: Io + 'static>(
    state: Arc<State>,
    conn: Connection,
    stream: S,
    secure: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(serve_unified_inner(state, conn, stream, secure, None, None))
}

/// `in_tls`: the pass on the bytes a TLS connection decrypted, whose stage is logged (`log_stage_in_tls`, given whether
/// the handshake built the server's context), after the protocol its handshake negotiated (`alpn`, [`log_alpn`])
/// unless the bytes are SOCKS.
async fn serve_unified_inner<S: Io + 'static>(state: Arc<State>, conn: Connection, mut stream: S, secure: bool, in_tls: Option<bool>, alpn: Option<Vec<u8>>) {
    let mut buf = BytesMut::with_capacity(16 * 1024);
    // the idle close, asked of a connection still waiting for its first bytes: the stream is shut down, which inside
    // TLS sends the `close_notify` first
    let decided = {
        let closer = conn.idle.closer();
        tokio::select! {
            decided = read_until_decided(&mut stream, &mut buf, false) => Some(decided),
            _ = closer.requested() => None,
        }
    };
    let Some(decided) = decided else {
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
        return;
    };
    let Some(taken_as_they_are) = decided else { return };
    let first = if taken_as_they_are { First::Other } else { classify(&buf, false) };
    let stage = match first {
        First::Socks4 => "adding SOCKS4 decoders",
        First::Socks5 => "adding SOCKS5 decoders",
        _ if is_binary(&state, first) => "adding binary decoder",
        _ => "adding HTTP decoders",
    };
    if let Some(context_built) = in_tls {
        if !matches!(first, First::Socks4 | First::Socks5) {
            log_alpn(&state, alpn.as_deref());
        }
        log_stage_in_tls(&state, &conn, stage, context_built);
    }
    match first {
        First::Socks4 => crate::socks::serve4(state, conn, Box::new(stream), buf, secure).await,
        First::Socks5 => crate::socks::serve5(state, conn, Box::new(stream), buf, secure).await,
        _ if is_binary(&state, first) => crate::binary::serve(state, conn, stream, buf, secure).await,
        _ => {
            state.connections.served_http(conn.event_loop);
            http1::serve(state, conn, stream, buf, secure).await
        }
    }
}

/// `InetSocketAddress.toString` of `new InetSocketAddress(host, port)`: `/ip:port` for a literal address, else
/// `host/ip:port` resolved (IPv4 first, as `java.net.preferIPv6Addresses` is false) or `host/<unresolved>:port`.
fn java_inet_socket_address(host: &str, port: u16) -> String {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => format!("/{}:{port}", java_host_address(ip)),
        Err(_) => match crate::inet_address::lookup_blocking(host, port).ok().and_then(|a| a.into_iter().min_by_key(SocketAddr::is_ipv6)) {
            Some(address) => format!("{host}/{}:{port}", java_host_address(address.ip())),
            None => format!("{host}/<unresolved>:{port}"),
        },
    }
}

/// `InetAddress.getHostAddress` as `InetSocketAddress.toString` prints it: an IPv6 address uncompressed
/// (`0:0:0:0:0:0:0:1`) and bracketed.
pub(crate) fn java_host_address(ip: std::net::IpAddr) -> String {
    match ip.to_canonical() {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => format!("[{}]", v6.segments().iter().map(|s| format!("{s:x}")).collect::<Vec<_>>().join(":")),
    }
}

/// A socket address as a request records it (`InetSocketAddress.toString` without its leading `/`,
/// `FullHttpRequestToMockServerHttpRequest`) and as Jackson writes it: `127.0.0.1:1080`, `[0:0:0:0:0:0:0:1]:1080`.
pub(crate) fn java_socket_address(address: SocketAddr) -> String {
    format!("{}:{}", java_socket_host(address), address.port())
}

/// [`java_host_address`] of an address a socket reports (an accepted connection's peer or local address): the JDK
/// keeps a non-zero `sin6_scope_id` as the `Inet6Address`'s numeric scope, so a scoped (link-local) address prints
/// `%<scope id>` inside the brackets, `[fe80:0:0:0:987a:2bff:fe3e:312c%2]` (the 9.1.0 oracle). An
/// IPv4-mapped address becomes an `Inet4Address` and drops it.
pub(crate) fn java_socket_host(address: SocketAddr) -> String {
    match address {
        SocketAddr::V6(v6) if v6.scope_id() != 0 && v6.ip().to_ipv4_mapped().is_none() => {
            format!("[{}%{}]", java_host_address(std::net::IpAddr::V6(*v6.ip())).trim_matches(['[', ']']), v6.scope_id())
        }
        _ => java_host_address(address.ip()),
    }
}

/// `PortUnificationHandler.localAddressesCache`: the (local address, port extension) pairs seen so far, process-wide
/// as the static map is JVM-wide, never cleared (not by `reset`). An entry is a local IP and port and whether the port
/// extension is empty (`calculatePortExtension`: port 443 over TLS, port 80 in the clear).
static LOCAL_ADDRESSES_SEEN: std::sync::LazyLock<parking_lot::Mutex<std::collections::HashSet<(std::net::IpAddr, u16, bool)>>> =
    std::sync::LazyLock::new(Default::default);

/// `PortUnificationHandler.getLocalAddresses`, called as a connection switches to HTTP/1.1 or HTTP/2: the first time
/// a local address and port extension is seen, `calculateLocalAddresses` calls `getCanonicalHostName()` and
/// `getHostName()` on the channel's local `InetAddress`, which keeps the name, so every request on that one
/// connection prints its `localAddress` as `<name>/<ip>:<port>` (`InetSocketAddress.toString`): in templates, the
/// recorded request and the log alike. Later connections, and every other one on the same address, have an
/// `InetAddress` of their own without a name. The startup warm-up takes 127.0.0.1 on the first port this way
/// (read from the 9.2.0 oracle).
pub(crate) async fn name_first_local_address(conn: &mut Connection, secure: bool) {
    if conn.local_name.is_some() {
        return;
    }
    let local = conn.local;
    let plain = (local.port() == 443 && secure) || (local.port() == 80 && !secure);
    if !LOCAL_ADDRESSES_SEEN.lock().insert((local.ip(), local.port(), plain)) {
        return;
    }
    if let Ok(name) = tokio::task::spawn_blocking(move || java_host_name(local)).await {
        conn.local_name = Some(name.into());
    }
}

/// [`java_socket_address`] of the connection's local address as `localAddress` prints it: with the host name
/// [`name_first_local_address`] gave it, `localhost/127.0.0.1:1080`.
pub(crate) fn java_local_address(conn: &Connection) -> String {
    match &conn.local_name {
        Some(name) => format!("{name}/{}", java_socket_address(conn.local)),
        None => java_socket_address(conn.local),
    }
}

/// `InetAddress.getHostName()` of an address a socket reports (`InetAddress.getHostFromNameService`): the name a
/// reverse lookup gives, if looking that name up gives the address back, else the address's literal
/// (`getHostAddress`, a scoped IPv6 address with its `%<scope id>`).
fn java_host_name(address: SocketAddr) -> String {
    use std::net::ToSocketAddrs;
    let literal = java_socket_host(address).trim_matches(['[', ']']).to_string();
    let Some(name) = reverse_lookup(address) else { return literal };
    let confirmed = (name.as_str(), 0).to_socket_addrs().map(|mut found| found.any(|a| a.ip().to_canonical() == address.ip().to_canonical())).unwrap_or(false);
    if confirmed { name } else { literal }
}

/// `getnameinfo` with `NI_NAMEREQD`: the address's host name, `None` when it has none.
fn reverse_lookup(address: SocketAddr) -> Option<String> {
    let socket = socket2::SockAddr::from(SocketAddr::new(address.ip(), 0));
    let socket = match address {
        SocketAddr::V6(v6) => socket2::SockAddr::from(SocketAddr::V6(std::net::SocketAddrV6::new(*v6.ip(), 0, 0, v6.scope_id()))),
        SocketAddr::V4(_) => socket,
    };
    let mut host = [0 as libc::c_char; 1025];
    // SAFETY: `socket` is a valid socket address of `socket.len()` bytes, and `host` a buffer of the length passed,
    // which `getnameinfo` NUL-terminates on success; no service buffer is asked for.
    let rc = unsafe {
        libc::getnameinfo(socket.as_ptr() as *const libc::sockaddr, socket.len(), host.as_mut_ptr(), host.len() as libc::socklen_t, std::ptr::null_mut(), 0, libc::NI_NAMEREQD)
    };
    if rc != 0 {
        return None;
    }
    // SAFETY: NUL-terminated by `getnameinfo` on success (see above).
    let name = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) };
    name.to_str().ok().filter(|n| !n.is_empty()).map(str::to_string)
}

/// Anything a connection can be served over.
pub trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

/// `RelayConnectHandler`: after `200` to a CONNECT (or the success reply to a SOCKS command), the tunnel is served as
/// MockServer itself with the target as the connection's remote socket. Upstream's loopback always dials MockServer's
/// own port, never the connection's remote socket (`proxyRemoteHost`, a PROXY protocol header), since b765b8271, so
/// nothing is dialled before the success reply and a dead target fails only the tunnelled requests forwarded to it
/// (scenario socks_connect_failure). The first tunnelled bytes decide
/// (`RelayTlsDetectionHandler`, upstream fix 40939d794 after 8.0.0, which assumed TLS for a cleartext CONNECT and closed
/// it unanswered, and spoke only HTTP/1.1 inside a CONNECT sent over TLS): a TLS record is terminated here with a leaf
/// for the target, the h2c preface is served as cleartext HTTP/2, anything else as HTTP/1.1. `secure` is whether the
/// tunnel itself arrived over TLS. The tunnel runs on a task of its own: polled on top of the connection that carried
/// the CONNECT, a TLS-carried tunnel's request handling (minting a leaf for its forward) overflowed a debug build's
/// worker stack; dropping the outer connection still ends it.
pub fn serve_tunnel(
    state: Arc<State>,
    conn: Connection,
    io: Box<dyn Io>,
    secure: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    // the relay is what a write stall on this connection cuts, whatever it carries (`UpstreamProxyRelayHandler`)
    conn.write_stall.set(crate::write_stall::Protocol::Tunnel);
    conn.idle.tunnel();
    struct AbortOnDrop(tokio::task::AbortHandle);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    Box::pin(async move {
        let task = tokio::spawn(tunnel(state, conn, io, secure));
        let _abort = AbortOnDrop(task.abort_handle());
        let _ = task.await;
    })
}

async fn tunnel(state: Arc<State>, mut conn: Connection, mut io: Box<dyn Io>, secure: bool) {
    let mut buf = BytesMut::new();
    match classify_tunnel(&state, &mut io, &mut buf).await {
        None => return,
        Some(Tunnelled::H2c) => {
            let io = ChaosIo::loopback(&state, conn.socket, Rewind { prefix: buf, inner: io });
            return serve_h2(state, conn, io, secure, true).await;
        }
        Some(Tunnelled::Http1) => {
            // the bytes read to classify the tunnel are read again through the chaos wrapper, as the loopback leg reads them
            let io = ChaosIo::loopback(&state, conn.socket, Rewind { prefix: buf, inner: io });
            return http1::serve(state, conn, io, BytesMut::new(), secure).await;
        }
        Some(Tunnelled::Tls) => {}
    }
    let Some(tls) = state.tls.as_ref() else { return };
    // `RelayConnectHandler` builds the server's context (`createServerSslContext`) as soon as it sees TLS.
    tls.server_context_needed(&state, client_hello_server_name(&buf).as_deref());
    let acceptor = tls.acceptor();
    tls_warnings(&state);
    // the fault is logged before the connection closes
    let started = std::time::Instant::now();
    let handshaking = conn.idle.handshake();
    let handshake = inbound_handshake(&state, conn.event_loop, acceptor.accept(Rewind { prefix: buf, inner: io }).into_fallible()).await;
    handshake_measured(&state, started, &handshake, None);
    let tls_stream = match handshake {
        Some(Ok(tls_stream)) => {
            handshaking.completed();
            tls_stream
        }
        Some(Err((e, io))) => {
            relay_tls_fault(&state, &conn, &e);
            return drop(io);
        }
        None => return,
    };
    let session = tls_stream.get_ref().1;
    if let Some(chain) = session.peer_certificates() {
        conn.client_certificates = Arc::new(chain.iter().filter_map(|c| crate::tls::client_cert::describe(c)).collect());
    }
    // TCP chaos acts on the decrypted bytes of the loopback leg, as `TcpChaosHandler` sits after the `SslHandler`
    let tls_stream = crate::tls::flush_on_read::FlushOnRead::new(tls_stream);
    let h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");
    let tls_stream = ChaosIo::loopback(&state, conn.socket, tls_stream);
    if h2 {
        serve_h2(state, conn, tls_stream, true, true).await;
    } else {
        http1::serve(state, conn, tls_stream, BytesMut::new(), true).await;
    }
}

/// A TLS handshake the server terminates (`SniHandler` on the unified port, `RelayConnectHandler` in a CONNECT or SOCKS
/// tunnel), bounded as `SslHandler.setHandshakeTimeoutMillis` bounds it: by `socketConnectionTimeoutInMillis` when
/// positive, else Netty's 10 s default (upstream 9f8deba46, after 8.0.0; 8.0.0 always waits the 10 s). `None` when it
/// timed out: the connection is closed with nothing more written and nothing logged, as both images do.
/// The timeout is a task on the connection's `event_loop`, run late
/// when a runtime LLM call blocks it ([`OpenConnections::loop_timer`]).
async fn inbound_handshake<T>(state: &State, event_loop: usize, handshake: impl std::future::Future<Output = T>) -> Option<T> {
    tokio::select! {
        biased;
        done = handshake => Some(done),
        () = state.connections.loop_timer(event_loop, crate::client::handshake_timeout(&state.config)) => None,
    }
}

/// `PortUnificationHandler.decode` on a binary connection in the clear whose read opens a TLS handshake (a protocol
/// that turns TLS on part way through, as PostgreSQL's and MySQL's SSLRequest do): `enableTls` puts the `SniHandler`
/// in front, so the handshake is answered as one at the start of a connection is (the server's context, its
/// protocols and client-certificate requirement), and what is decrypted from then on goes to the binary handler.
/// `prefix` holds the handshake's first bytes. `None` once the connection has been dealt with (a refused context or
/// a failed handshake, logged as at the start of a connection).
pub(crate) async fn accept_binary_tls(state: &Arc<State>, conn: &mut Connection, stream: Box<dyn Io>, prefix: BytesMut) -> Option<Box<dyn Io>> {
    let tls = state.tls.as_ref()?;
    let sni = client_hello_server_name(&prefix);
    conn.sni = sni.clone();
    tls.server_context_needed(state, sni.as_deref());
    if let Some(refused) = tls.refusal(sni.as_deref()) {
        tls_warnings(state);
        refused_context_fault(state, conn, refused);
        return None;
    }
    if let Some(refusal) = tls.unusable_key_failure(&client_hello_offer(&prefix)) {
        tls_warnings(state);
        let mut stream = stream;
        unusable_key_handshake(state, conn, &mut stream, &refusal).await;
        return None;
    }
    let acceptor = tls.acceptor();
    tls_warnings(state);
    let handshaking = conn.idle.handshake();
    match inbound_handshake(state, conn.event_loop, acceptor.accept(Rewind { prefix, inner: stream }).into_fallible()).await? {
        Ok(tls_stream) => {
            handshaking.completed();
            if let Some(chain) = tls_stream.get_ref().1.peer_certificates() {
                conn.client_certificates = Arc::new(chain.iter().filter_map(|c| crate::tls::client_cert::describe(c)).collect());
            }
            Some(Box::new(crate::tls::flush_on_read::FlushOnRead::new(tls_stream)))
        }
        Err((e, io)) => {
            tls_fault(state, conn, &e);
            drop(io);
            None
        }
    }
}

/// A terminated TLS handshake into `mock_server_tls_handshake_duration_seconds`: the negotiated version,
/// or why it failed, which also ends the connection with that `error_type`.
fn handshake_measured<S, I>(
    state: &State,
    started: std::time::Instant,
    handshake: &Option<Result<tokio_rustls::server::TlsStream<S>, (std::io::Error, I)>>,
    connection: Option<&mut crate::metrics::ServerConnection>,
) {
    let outcome = match handshake {
        Some(Ok(stream)) => Ok(match stream.get_ref().1.protocol_version() {
            Some(rustls::ProtocolVersion::TLSv1_3) => Some("1.3"),
            Some(rustls::ProtocolVersion::TLSv1_2) => Some("1.2"),
            _ => None,
        }),
        Some(Err((e, _))) => Err(handshake_error_type(e)),
        None => Err("timeout"),
    };
    if let (Err(error), Some(connection)) = (outcome, connection) {
        connection.failed(error);
    }
    crate::metrics::tls_handshake(&state.config, started.elapsed().as_secs_f64(), outcome);
}

/// A failed handshake's `error_type`: the kind of TLS error rustls raised, or `connection_closed` when the peer went
/// away (a fixed, low-cardinality set).
fn handshake_error_type(error: &std::io::Error) -> &'static str {
    use std::io::ErrorKind;
    match error.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()) {
        Some(rustls::Error::AlertReceived(_)) => "alert_received",
        Some(rustls::Error::InvalidCertificate(_)) => "invalid_certificate",
        Some(rustls::Error::NoCertificatesPresented) => "no_certificates_presented",
        Some(rustls::Error::PeerIncompatible(_)) => "peer_incompatible",
        Some(rustls::Error::PeerMisbehaved(_)) => "peer_misbehaved",
        Some(rustls::Error::InvalidMessage(_) | rustls::Error::InappropriateMessage { .. } | rustls::Error::InappropriateHandshakeMessage { .. }) => "invalid_message",
        Some(_) => "tls_error",
        None if matches!(error.kind(), ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted) => "connection_closed",
        None if error.kind() == ErrorKind::TimedOut => "timeout",
        None => "io_error",
    }
}

/// `UpstreamProxyRelayHandler.exceptionCaught` for a TLS handshake that failed inside a tunnel: whatever the cause (a
/// malformed record, a client that does not trust the CA), one WARN naming the closed channel, as the 8.0.0 oracle
/// logs it for CONNECT and SOCKS tunnels alike (scenario tunnel_tls_faults). A peer that simply went away is not logged.
fn relay_tls_fault(state: &State, conn: &Connection, error: &std::io::Error) {
    use crate::recorded::{Level, LogEntry};
    use std::io::ErrorKind;
    if let Some((_, _, Some(severe))) = state.tls.as_ref().and_then(|tls| tls.take_refused()) {
        crate::log::error_event(state, LogEntry::at(Level::Error, severe));
    }
    if matches!(error.kind(), ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted | ErrorKind::TimedOut) {
        return;
    }
    let tls = error.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>());
    if matches!(tls, Some(rustls::Error::AlertReceived(rustls::AlertDescription::CloseNotify))) {
        return;
    }
    let id = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    let message = format!("SSL or decoder fault caught by upstream relay handler -> closing pipeline [id: 0x{id}, L:/{} ! R:/{}]", java_socket_address(conn.local), java_socket_address(conn.remote));
    crate::log::warn_event(state, LogEntry::at(Level::Warn, message));
}

/// What a tunnel's client speaks, by its first bytes.
#[derive(Debug, PartialEq)]
pub(crate) enum Tunnelled {
    Tls,
    /// The cleartext HTTP/2 prior-knowledge preface.
    H2c,
    Http1,
}

/// `RelayTlsDetectionHandler.decode`, for CONNECT and SOCKS tunnels alike (the client sends nothing before the
/// tunnel's success reply, so its first bytes are the tunnelled protocol's): at least a TLS record header's five bytes
/// are read into `buf`, and while HTTP/2 is enabled (as `PortUnificationHandler` gates it) a prefix of the h2c preface
/// waits for the whole preface. `None` when the client goes away first.
pub(crate) async fn classify_tunnel(state: &State, io: &mut Box<dyn Io>, buf: &mut BytesMut) -> Option<Tunnelled> {
    let http2 = state.config.bool_property("http2Enabled", true);
    while buf.len() < 5 || (http2 && buf.len() < H2_PREFACE.len() && H2_PREFACE.starts_with(buf)) {
        buf.reserve(4096);
        match io.read_buf(buf).await {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
    }
    // `SslHandler.isEncrypted`: a TLS record header (content type 20..=23, major version 3).
    Some(if (20..=23).contains(&buf[0]) && buf[1] == 3 {
        Tunnelled::Tls
    } else if http2 && buf.starts_with(H2_PREFACE) {
        Tunnelled::H2c
    } else {
        Tunnelled::Http1
    })
}

/// First byte of a TLS record carrying a handshake (the ClientHello).
const TLS_HANDSHAKE: u8 = 0x16;

#[derive(Debug, PartialEq)]
enum TlsProbe {
    /// Too few bytes to tell: read more.
    More,
    Tls,
    No,
}

/// Netty's `SslHandler.isEncrypted` as `PortUnificationHandler` applies it: a record type of 20 to 24, major version 3
/// and a non-empty payload (five bytes are needed to say).
fn probe_tls(buf: &[u8]) -> TlsProbe {
    match buf.first() {
        Some(20..=24) if buf.len() < 5 => TlsProbe::More,
        Some(20..=24) if buf[1] == 3 && u16::from_be_bytes([buf[3], buf[4]]) > 0 => TlsProbe::Tls,
        _ => TlsProbe::No,
    }
}

/// Whether the first record holds a whole handshake message (read on until the record is in, within the handshake
/// timeout): what Netty's `AbstractSniHandler` waits for before its `lookup`, which a truncated ClientHello never
/// reaches (scenario `transparent_proxy_protocol`), while a complete one that does not parse does (`unification_tls_faults`).
/// A ClientHello spread over several records is not followed and counts as incomplete.
async fn client_hello_complete(state: &State, stream: &mut TcpStream, buf: &mut BytesMut) -> bool {
    let record = 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let read = async {
        while buf.len() < record {
            match stream.read_buf(buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    };
    let _ = tokio::time::timeout(crate::client::handshake_timeout(&state.config), read).await;
    if buf.len() < record.min(9) || buf[0] != TLS_HANDSHAKE {
        return false;
    }
    let message = 4 + (usize::from(buf[6]) << 16 | usize::from(buf[7]) << 8 | usize::from(buf[8]));
    5 + message <= record && buf.len() >= record
}

/// The `server_name` extension's host name of the ClientHello in the first TLS record of `buf`, if any.
fn client_hello_take<'a>(input: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, rest) = (input.get(..n)?, input.get(n..)?);
    *input = rest;
    Some(head)
}

fn client_hello_length(input: &mut &[u8], width: usize) -> Option<usize> {
    Some(client_hello_take(input, width)?.iter().fold(0usize, |n, b| n << 8 | usize::from(*b)))
}

/// A buffered ClientHello's `legacy_version` and its extensions' block.
fn client_hello_parts(buf: &[u8]) -> Option<(u16, &[u8])> {
    let (take, length) = (client_hello_take, client_hello_length);
    let mut hello = buf.get(9..)?; // record header, handshake type and length
    let version = length(&mut hello, 2)? as u16;
    take(&mut hello, 32)?; // random
    let n = length(&mut hello, 1)?;
    take(&mut hello, n)?; // session id
    let n = length(&mut hello, 2)?;
    take(&mut hello, n)?; // cipher suites
    let n = length(&mut hello, 1)?;
    take(&mut hello, n)?; // compression methods
    let n = length(&mut hello, 2)?;
    Some((version, take(&mut hello, n)?))
}

/// The data of a buffered ClientHello's extension of type `wanted`.
fn client_hello_extension(buf: &[u8], wanted: usize) -> Option<&[u8]> {
    let (_, mut extensions) = client_hello_parts(buf)?;
    while !extensions.is_empty() {
        let kind = client_hello_length(&mut extensions, 2)?;
        let n = client_hello_length(&mut extensions, 2)?;
        let data = client_hello_take(&mut extensions, n)?;
        if kind == wanted {
            return Some(data);
        }
    }
    None
}

/// What a buffered ClientHello offers that decides whether the fixed certificate's key can serve it.
fn client_hello_offer(buf: &[u8]) -> crate::tls::ClientOffer {
    let schemes = |kind: usize| {
        client_hello_extension(buf, kind).map(|mut data| {
            let n = client_hello_length(&mut data, 2).unwrap_or(0);
            let list = client_hello_take(&mut data, n).unwrap_or_default();
            list.as_chunks::<2>().0.iter().map(|v| u16::from_be_bytes([v[0], v[1]])).collect::<Vec<u16>>()
        })
    };
    crate::tls::ClientOffer {
        versions: client_hello_versions(buf),
        signature_schemes: schemes(13).unwrap_or_default(),
        certificate_schemes: schemes(50),
        cipher_suites: client_hello_cipher_suites(buf),
    }
}

/// A buffered ClientHello's cipher suites.
fn client_hello_cipher_suites(buf: &[u8]) -> Vec<u16> {
    let (take, length) = (client_hello_take, client_hello_length);
    let suites = || {
        let mut hello = buf.get(9..)?;
        take(&mut hello, 34)?; // legacy_version, random
        let n = length(&mut hello, 1)?;
        take(&mut hello, n)?; // session id
        let n = length(&mut hello, 2)?;
        take(&mut hello, n)
    };
    suites().map(|list| list.as_chunks::<2>().0.iter().map(|v| u16::from_be_bytes([v[0], v[1]])).collect()).unwrap_or_default()
}

/// The protocol versions a buffered ClientHello offers: its `supported_versions` list, else its `legacy_version`.
fn client_hello_versions(buf: &[u8]) -> Vec<u16> {
    if let Some(mut data) = client_hello_extension(buf, 43) {
        let n = client_hello_length(&mut data, 1).unwrap_or(0);
        let list = client_hello_take(&mut data, n).unwrap_or_default();
        return list.as_chunks::<2>().0.iter().map(|v| u16::from_be_bytes([v[0], v[1]])).collect();
    }
    client_hello_parts(buf).map(|(version, _)| vec![version]).unwrap_or_default()
}

fn client_hello_server_name(buf: &[u8]) -> Option<String> {
    let (take, length) = (client_hello_take, client_hello_length);
    let mut data = client_hello_extension(buf, 0)?;
    let n = length(&mut data, 2)?;
    let mut names = take(&mut data, n)?;
    while !names.is_empty() {
        let kind = length(&mut names, 1)?;
        let n = length(&mut names, 2)?;
        let name = take(&mut names, n)?;
        if kind == 0 {
            return std::str::from_utf8(name).ok().map(str::to_string);
        }
    }
    None
}

/// What the oracle's JDK TLS engine does with a first record before any handshake, which rustls would
/// answer differently or not at all: a record over 16 KiB is waited for in full, an alert record ends the connection
/// silently, change-cipher-spec and application data get a fatal `internal_error`, and a handshake record that does not
/// start a ClientHello gets `unexpected_message`. Returns false once the connection has been dealt with.
async fn first_record_acceptable(state: &State, conn: &Connection, stream: &mut TcpStream, buf: &mut BytesMut) -> bool {
    use tokio::io::AsyncWriteExt;
    let length = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    // a handshake record's first byte says whether it starts a ClientHello, which decides the alert a bad one gets
    while buf[0] == TLS_HANDSHAKE && buf.len() < 6 {
        match stream.read_buf(buf).await {
            Ok(0) | Err(_) => return false,
            Ok(_) => {}
        }
    }
    while length > 16_384 && length <= 18_432 && buf.len() < 5 + length {
        match stream.read_buf(buf).await {
            Ok(0) | Err(_) => return false,
            Ok(_) => {}
        }
    }
    let decoder_fault = || std::io::Error::other(rustls::Error::InvalidMessage(rustls::InvalidMessage::HandshakePayloadTooLarge));
    let refused = match buf[0] {
        21 => {
            tls_fault(state, conn, &decoder_fault());
            return false;
        }
        20 | 23 => 80, // internal_error
        TLS_HANDSHAKE if buf[5] != 1 => 10, // unexpected_message
        _ => return true,
    };
    let _ = stream.write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, refused]).await;
    // logged before the close, as Netty's `exceptionCaught` does
    if refused == 10 {
        tls_fault(state, conn, &decoder_fault());
    } else {
        tls_fault(state, conn, &std::io::Error::other(rustls::Error::General(String::new())));
    }
    let _ = stream.shutdown().await;
    false
}

/// `relay`: a CONNECT or SOCKS tunnel's HTTP/2 (see [`crate::h2::serve`]).
pub async fn serve_h2<S>(state: Arc<State>, conn: Connection, io: S, secure: bool, relay: bool)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    state.connections.served_http(conn.event_loop);
    crate::h2::serve(state, conn, io, secure, relay).await;
}




#[cfg(test)]
mod tests {
    use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

    // Expected values are the 9.1.0 oracle's own renderings: a request from a link-local peer on the
    // container's eth0 (interface index 2), read back through a Velocity template's `request.remoteAddress` and
    // `localAddress`, the recorded request and HAR's `serverIPAddress`.
    #[test]
    fn a_scoped_ipv6_peer_renders_with_its_numeric_scope_id() {
        let link_local: Ipv6Addr = "fe80::987a:2bff:fe3e:312c".parse().unwrap();
        let peer = SocketAddr::V6(SocketAddrV6::new(link_local, 56896, 0, 2));
        assert_eq!(super::java_socket_address(peer), "[fe80:0:0:0:987a:2bff:fe3e:312c%2]:56896");
    }

    #[test]
    fn an_unscoped_ipv6_peer_renders_without_a_scope() {
        let peer = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 37462, 0, 0));
        assert_eq!(super::java_socket_address(peer), "[0:0:0:0:0:0:0:1]:37462");
    }

    #[test]
    fn a_channel_description_prints_ipv6_ends_as_netty_does() {
        let local = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1080, 0, 0));
        let remote = SocketAddr::V6(SocketAddrV6::new("::ffff:127.0.0.1".parse().unwrap(), 48712, 0, 0));
        assert_eq!(super::netty_channel("b3b9c7e8", local, remote), "[id: 0xb3b9c7e8, L:/[0:0:0:0:0:0:0:1]:1080 - R:/127.0.0.1:48712]");
    }

    #[test]
    fn an_ipv4_mapped_peer_renders_as_its_ipv4_address() {
        let peer = SocketAddr::V6(SocketAddrV6::new("::ffff:127.0.0.1".parse().unwrap(), 52958, 0, 2));
        assert_eq!(super::java_socket_address(peer), "127.0.0.1:52958");
    }

    /// One request on `stream` (keep-alive), answered with a `content-length`: its body.
    async fn exchange(stream: &mut tokio::net::TcpStream, request: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let n = stream.read(&mut buffer).await.unwrap();
            assert!(n > 0, "closed after {}", String::from_utf8_lossy(&answer));
            answer.extend_from_slice(&buffer[..n]);
            if let Some(end) = answer.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&answer[..end]).to_ascii_lowercase();
                let length = head.lines().find_map(|l| l.strip_prefix("content-length:")).map(|v| v.trim().parse::<usize>().unwrap()).unwrap_or(0);
                if answer.len() >= end + 4 + length {
                    return String::from_utf8_lossy(&answer[end + 4..end + 4 + length]).into_owned();
                }
            }
        }
    }

    // Expected values are the 9.2.0 oracle's own: a private container started with
    // `MOCKSERVER_STARTUP_WARMUP=false` and `--no-healthcheck`, so that nothing had connected over 127.0.0.1 before;
    // the expectation `PUT` and two template requests on the first connection over 127.0.0.1 answered
    // `localhost/127.0.0.1:1080` (Velocity and Mustache alike, and the log's received requests), the next connection
    // `127.0.0.1:1080` (`PortUnificationHandler.getLocalAddresses` names the channel's `InetAddress` the first time
    // it sees a local address and port extension).
    #[tokio::test]
    async fn only_the_first_connection_on_a_local_address_renders_its_host_name() {
        let config = crate::Config::for_tests().with_property("startupWarmup", "false");
        let server = crate::Server::start(config).await.unwrap();
        let port = server.ports()[0];
        let expectations = r#"[{"httpRequest":{"path":"/v"},"httpResponseTemplate":{"templateType":"VELOCITY","template":"{\"statusCode\":200,\"body\":\"v local=$!request.localAddress\"}"},"times":{"unlimited":true}},{"httpRequest":{"path":"/m"},"httpResponseTemplate":{"templateType":"MUSTACHE","template":"{\"statusCode\":200,\"body\":\"m local={{request.localAddress}}\"}"},"times":{"unlimited":true}}]"#;
        let host = format!("Host: 127.0.0.1:{port}\r\n");
        let mut first = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        exchange(&mut first, &format!("PUT /mockserver/expectation HTTP/1.1\r\n{host}content-length: {}\r\n\r\n{expectations}", expectations.len())).await;
        assert_eq!(exchange(&mut first, &format!("GET /v HTTP/1.1\r\n{host}\r\n")).await, format!("v local=localhost/127.0.0.1:{port}"));
        assert_eq!(exchange(&mut first, &format!("GET /m HTTP/1.1\r\n{host}\r\n")).await, format!("m local=localhost/127.0.0.1:{port}"));
        let mut next = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert_eq!(exchange(&mut next, &format!("GET /v HTTP/1.1\r\n{host}\r\n")).await, format!("v local=127.0.0.1:{port}"));
        assert_eq!(exchange(&mut first, &format!("GET /v HTTP/1.1\r\n{host}\r\n")).await, format!("v local=localhost/127.0.0.1:{port}"));
    }
}
