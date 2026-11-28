//! Configuration, resolved the way MockServer's `ConfigurationProperties` and `Main` do (§6.1, §6.3).

use std::collections::HashMap;

/// Environment variable names that are not the upper-snake form of the property name (Appendix A).
const ENV_NAME_EXCEPTIONS: &[(&str, &str)] = &[
    ("validateRequestsAgainstOpenApiSpec", "MOCKSERVER_VALIDATE_REQUESTS_AGAINST_OPENAPI_SPEC"),
    ("initializationOpenAPIPath", "MOCKSERVER_INITIALIZATION_OPENAPI_PATH"),
    ("openAPIContextPathPrefix", "MOCKSERVER_OPENAPI_CONTEXT_PATH_PREFIX"),
    ("openAPIResponseValidation", "MOCKSERVER_OPENAPI_RESPONSE_VALIDATION"),
    ("validateProxyOpenAPISpec", "MOCKSERVER_VALIDATE_PROXY_OPENAPI_SPEC"),
    (
        "maximumNumberOfRequestToReturnInVerificationFailure",
        "MOCKSERVER_MAXIMUM_NUMBER_OF_REQUESTS_TO_RETURN_IN_VERIFICATION_FAILURE",
    ),
    ("proxyAuthenticationRealm", "MOCKSERVER_PROXY_SERVER_REALM"),
    ("controlPlaneTLSMutualAuthenticationCAChain", "MOCKSERVER_CONTROL_PLANE_TLS_MUTUAL_AUTHENTICATION_CERTIFICATE_CHAIN"),
    ("controlPlanePrivateKeyPath", "MOCKSERVER_CONTROL_PLANE_TLS_PRIVATE_KEY_PATH"),
    ("controlPlaneX509CertificatePath", "MOCKSERVER_CONTROL_PLANE_TLS_X509_CERTIFICATE_PATH"),
    ("directoryToSaveDynamicSSLCertificate", "MOCKSERVER_CERTIFICATE_DIRECTORY_TO_SAVE_DYNAMIC_SSL_CERTIFICATE"),
    ("certificateAuthorityCertificate", "MOCKSERVER_CERTIFICATE_AUTHORITY_X509_CERTIFICATE"),
    ("privateKeyPath", "MOCKSERVER_TLS_PRIVATE_KEY_PATH"),
    ("x509CertificatePath", "MOCKSERVER_TLS_X509_CERTIFICATE_PATH"),
    ("forwardProxyTLSX509CertificatesTrustManagerType", "MOCKSERVER_FORWARD_PROXY_TLS_X509_CERTIFICATES_TRUST_MANAGER_TYPE"),
    ("forwardProxyPrivateKey", "MOCKSERVER_FORWARD_PROXY_TLS_PRIVATE_KEY"),
    ("forwardProxyCertificateChain", "MOCKSERVER_FORWARD_PROXY_TLS_X509_CERTIFICATE_CHAIN"),
];

/// Resolved server configuration.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Ports to listen on; `0` picks a free port.
    pub ports: Vec<u16>,
    /// `-D` system properties given on the command line, keyed `mockserver.<name>`.
    system_properties: HashMap<String, String>,
    /// Entries of the properties file.
    file_properties: HashMap<String, String>,
    /// The file is a `.json` one, which supplies `logLevel` to the property cache; a `.properties` one does not
    /// (see `crate::property_file`).
    file_is_json: bool,
    /// What `ConfigurationProperties.<clinit>` logged with `alwaysLog` while loading, printed by `main`.
    startup_notices: Vec<crate::property_file::StartupNotice>,
    /// Environment, captured once.
    env: HashMap<String, String>,
    /// Port-forwarding mode, as `new MockServer(remotePort, remoteHost, localPorts)`: `proxyRemotePort` (with
    /// `proxyRemoteHost`, default `localhost`) from the command line or the sources [`Config::cli_owned`] reads.
    /// Only `from_args` sets it.
    pub port_forward: Option<(String, u16)>,
    /// Values set over `PUT /mockserver/configuration`, which take precedence over every other source.
    /// Fx-hashed: once anything is set here, every property read of every request looks here first.
    runtime: std::sync::Arc<parking_lot::RwLock<rustc_hash::FxHashMap<String, String>>>,
    /// How many times anything was put in `runtime` (which is never emptied), counted after each put: while it is
    /// zero a read skips the lock, which every request worker took several times per request, and the [`Hot`]
    /// properties' kept answers hold for the count they were read at.
    runtime_generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// The startup tiers (system property, properties file, environment) of each recognised property, resolved once
    /// on first use: they do not change after startup, and resolving one formatted its key and
    /// environment name on every read. Emptied by [`Config::sources_changed`] whenever a tier changes.
    startup_cache: std::sync::OnceLock<std::sync::Arc<StartupCache>>,
    /// Values an embedder set through `Server::set_property` (upstream's `ConfigurationProperties.<name>(value)`,
    /// which writes a system property that `PUT /mockserver/configuration` never touches). The effective
    /// configuration reports them with the `system-property` source.
    embedder_set: std::sync::Arc<parking_lot::RwLock<HashMap<String, String>>>,
    /// Callback classes registered in-process (`crate::class_callback`).
    pub callback_classes: std::sync::Arc<crate::class_callback::Registry>,
    /// `Metrics`, shared by everything that counts (`metricsEnabled`).
    pub(crate) metrics: std::sync::Arc<crate::metrics::Metrics>,
    /// `SloSampleStore`, recorded by the forwarding client (`sloTrackingEnabled`).
    pub(crate) slo: std::sync::Arc<crate::slo::Samples>,
    /// `binaryProxyListener`: told of each proxied binary exchange.
    pub binary_proxy_listener: Option<crate::binary::BinaryProxyListener>,
    /// Told of each address a DNS or HTTP/3 listener probed, after the probe and before the bind (`crate::udp_probe`).
    pub(crate) udp_port_probed: Option<crate::udp_probe::UdpPortProbed>,
    /// `LifeCycle.bindVerifier`: the TCP listeners' loopback shadow check and retry candidates (`crate::loopback_probe`).
    pub(crate) bind_verifier: crate::loopback_probe::BindVerifierSlot,
    /// An installed control-plane authentication handler (`crate::auth::Authenticator`).
    pub(crate) control_plane_authenticator: crate::auth::AuthenticatorSlot,
    /// The remote JWK sets and resolved OIDC key locations of the derived control-plane handlers (`crate::jwks`).
    pub(crate) control_plane_jwks: crate::jwks::Handlers,
    /// A runtime LLM backend without a `baseUrl` targets its provider's public API (`api.openai.com`, …), as
    /// upstream. Only a configuration read from the command line ([`Config::from_args`]) allows it: a test or
    /// embedding configuration fails closed, so no test ever sends a request to a real provider.
    pub(crate) llm_provider_default_urls: bool,
    /// `ConfigurationProperties.heapAvailableInKB` as the oracle's container computes it on this machine (see
    /// [`heap_available_kb`]); only [`Config::from_args`] measures it. `None`: the recording VM's value, which the
    /// goldens show.
    pub(crate) heap_available_kb: Option<i64>,
    /// `Runtime.availableProcessors()` as the oracle's JVM sees it on this machine (see [`available_processors`]); only
    /// [`Config::from_args`] measures it. `None`: the recording VM's value, which the goldens show.
    pub(crate) available_processors: Option<usize>,
    /// `TimeService.fixedTime(true)` as it pins `nanoTime`: [`Config::nano_time`] returns one constant instant
    /// (`FIXED_NANOS_FOR_TESTS`), so every elapsed-time reader routed through it measures nothing. Only a test sets it,
    /// through [`Config::with_fixed_nano_time`].
    fixed_nano_time: bool,
    /// Skips the `SO_ORIGINAL_DST` lookup of the transparent-proxy resolver chain: on a host whose NAT keeps conntrack on (a Docker
    /// host) it answers a direct connection with the connection's own local address, as upstream's resolver does, so an in-process test
    /// of the Host-header fallback cannot rely on it. Set by [`Config::for_tests`] only.
    skip_so_original_dst: bool,
    /// The JVM's own system properties (`crate::jvm_properties`) as this process measures them; only
    /// [`Config::from_args`] measures them. `None`: the oracle image's, which the goldens show.
    jvm_properties: Option<std::sync::Arc<Vec<(String, String)>>>,
}

impl Config {
    /// One free port, no environment, for in-process tests.
    pub fn for_tests() -> Self {
        Config { ports: vec![0], skip_so_original_dst: true, ..Config::default() }
    }

    /// `Configuration.binaryProxyListener`: `listener` hears of each proxied binary exchange, on a thread of its own.
    pub fn with_binary_proxy_listener(mut self, listener: impl Fn(crate::binary::BinaryExchange) + Send + Sync + 'static) -> Self {
        self.binary_proxy_listener = Some(crate::binary::BinaryProxyListener(std::sync::Arc::new(listener)));
        self
    }

    /// Calls `probed` with each address a DNS or HTTP/3 listener's start checked for a socket on the IPv4 wildcard, right after
    /// the check and before the bind: the seam (`MockServer.dnsPortShadowedOnIpv4`, `Http3Server.shadowedOnIpv4`) through which a test takes the
    /// port meanwhile, as another application could.
    pub fn with_udp_port_probed(mut self, probed: impl Fn(std::net::SocketAddr) + Send + Sync + 'static) -> Self {
        self.udp_port_probed = Some(crate::udp_probe::UdpPortProbed(std::sync::Arc::new(probed)));
        self
    }

    /// Pins [`Config::nano_time`] for this server, as upstream's tests pin `TimeService.nanoTime` with the `FixedTime`
    /// rule: the missing-usage line's once-a-minute limiter then never sees its window end.
    pub fn with_fixed_nano_time(mut self) -> Self {
        self.fixed_nano_time = true;
        self
    }

    /// Whether the transparent-proxy chain leaves out `SO_ORIGINAL_DST` (see the field).
    pub fn skips_so_original_dst(&self) -> bool {
        self.skip_so_original_dst
    }

    /// `TimeService.nanoTime()`: the real monotonic clock, or `FIXED_NANOS_FOR_TESTS` once a test pinned it.
    pub(crate) fn nano_time(&self) -> std::time::Instant {
        static FIXED_NANOS_FOR_TESTS: std::sync::LazyLock<std::time::Instant> = std::sync::LazyLock::new(std::time::Instant::now);
        if self.fixed_nano_time { *FIXED_NANOS_FOR_TESTS } else { std::time::Instant::now() }
    }

    /// Registers `callbacks` under the callback class name `class`.
    pub fn with_callback_class(self, class: &str, callbacks: crate::class_callback::CallbackClass) -> Self {
        self.callback_classes.register(class, callbacks);
        self
    }

    pub fn with_property(mut self, name: &str, value: &str) -> Self {
        self.system_properties.insert(format!("mockserver.{name}"), value.to_string());
        self.sources_changed();
        self
    }

    /// A list or set property: the elements an update gave (each whole, a null one kept), else the configured text split
    /// on commas, trimmed, blanks dropped. `None` when nothing configures it.
    pub fn list_property(&self, name: &str) -> Option<Vec<Option<String>>> {
        let text = self.property(name)?;
        if self.runtime_value(name).is_some() && let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(&text) {
            return Some(items.into_iter().map(|item| item.as_str().map(str::to_string)).collect());
        }
        Some(match name {
            // `loadGenerationMetricLabels()`: split on commas, trimmed, blanks dropped
            "loadGenerationMetricLabels" => text.split(',').map(str::trim).filter(|v| !v.is_empty()).map(|v| Some(v.to_string())).collect(),
            // the required claims and scopes: nothing when blank, else `String.split(",")` untrimmed
            "controlPlaneJWTAuthenticationRequiredClaims" | "controlPlaneOidcRequiredScopes" if text.trim().is_empty() => Vec::new(),
            _ => java_split_comma(&text).into_iter().map(Some).collect(),
        })
    }

    /// An environment variable of the server's process, as the scenario harness sets one (`"env"`).
    pub fn with_env(mut self, name: &str, value: &str) -> Self {
        self.env.insert(name.to_string(), value.to_string());
        self.sources_changed();
        self
    }

    /// The text of the properties file the server reads (`/config/mockserver.properties` in the image), as the scenario
    /// harness mounts one (`"propertiesFile"`): parsed as `Properties.load` does, in place of reading a path.
    pub fn with_property_file_text(mut self, text: &str) -> Self {
        self.file_properties = parse_properties(text);
        self.sources_changed();
        self
    }

    /// A runtime value (`PUT /mockserver/configuration`), else [`Config::startup_property_outside_file`]. The console's
    /// `logLevelOverrides`, `disableLogging` and `compactLogFormat` and the dashboard's `logLevelOverrides` are read this
    /// way: a value set over the API reaches both (upstream 0e8566814, the oracle's behaviour; process
    /// scenario `console_runtime_configuration_reaches_console`).
    pub fn property_outside_file(&self, name: &str) -> Option<String> {
        if let Some(value) = self.runtime_value(name) {
            return Some(value);
        }
        self.startup_property_outside_file(name)
    }

    /// [`Config::startup_property`] without the properties-file tier: on the oracle a value in the file (`.properties`
    /// or `.json`) of the console's `logLevelOverrides`, `disableLogging` and `compactLogFormat` and the dashboard's
    /// `logLevelOverrides` changes nothing, neither `Main`'s startup dump nor a later request line, while the system
    /// property and the environment variable do (the same shape as a `.properties` file's `logLevel`, see
    /// `crate::property_file`).
    pub fn startup_property_outside_file(&self, name: &str) -> Option<String> {
        match self.startup_cache().outside_file.get(name) {
            Some(value) => value.clone(),
            None => self.resolve_startup_property_outside_file(name),
        }
    }

    fn resolve_startup_property_outside_file(&self, name: &str) -> Option<String> {
        self.system_properties
            .get(&format!("mockserver.{name}"))
            .or_else(|| self.env.get(&env_name(name)).filter(|v| !v.trim().is_empty()))
            .map(|v| unquote(v).to_string())
    }

    /// The class path roots (`crate::class_path`): the `mockServer.classPath` system property, then the
    /// `MOCK_SERVER_CLASS_PATH` environment variable, the first that is not blank. Outside `mockserver.*`, so
    /// upstream's unrecognised-key check never sees it.
    pub fn class_path(&self) -> Option<String> {
        let not_blank = |v: &&String| !v.trim().is_empty();
        self.system_properties.get(crate::class_path::PROPERTY).filter(not_blank).or_else(|| self.env.get(crate::class_path::ENVIRONMENT).filter(not_blank)).cloned()
    }

    /// `readPropertyHierarchically`: system property, then properties file, then env var, then `None`.
    pub fn property(&self, name: &str) -> Option<String> {
        if let Some(value) = self.runtime_value(name) {
            return Some(value);
        }
        self.startup_property(name)
    }

    /// [`Config::property`] handed to `read` as it is held, not copied.
    pub fn read_property<R>(&self, name: &str, read: impl FnOnce(Option<&str>) -> R) -> R {
        if self.runtime_generation.load(std::sync::atomic::Ordering::Acquire) != 0 {
            let runtime = self.runtime.read();
            if let Some(value) = runtime.get(name) {
                return read(Some(value));
            }
        }
        self.read_startup_property(name, read)
    }

    /// [`Config::startup_property`] handed to `read` as it is held, not copied.
    fn read_startup_property<R>(&self, name: &str, read: impl FnOnce(Option<&str>) -> R) -> R {
        if MILLIS_ALIASES.iter().any(|(alias, ..)| *alias == name) {
            return read(self.startup_property(name).as_deref());
        }
        self.read_cached_startup_property(name, read)
    }

    /// The startup tiers' value of `name` (no `…InMillis` alias resolved), handed to `read` as it is held.
    fn read_cached_startup_property<R>(&self, name: &str, read: impl FnOnce(Option<&str>) -> R) -> R {
        let cache = self.startup_cache();
        if let Some(value) = cache.full.get(name) {
            return read(value.as_deref());
        }
        if let Some(value) = cache.others.read().get(name) {
            return read(value.as_deref());
        }
        let value = self.resolve_startup_property(name).map(|v| startup_read(name, v));
        let result = read(value.as_deref());
        // the code reads a bounded set of names; past this many, a name is resolved each time rather than kept
        let mut others = cache.others.write();
        if others.len() < 256 {
            others.insert(name.to_string(), value);
        }
        result
    }

    /// A value `PUT /mockserver/configuration` (or an embedder) set, without locking while none was ever set.
    fn runtime_value(&self, name: &str) -> Option<String> {
        if self.runtime_generation.load(std::sync::atomic::Ordering::Acquire) == 0 {
            return None;
        }
        self.runtime.read().get(name).cloned()
    }

    /// The startup tiers of the recognised properties, resolved on first use (see `startup_cache`).
    fn startup_cache(&self) -> &StartupCache {
        self.startup_cache.get_or_init(|| {
            let names = recognised_properties().iter().filter_map(|(key, _)| key.strip_prefix("mockserver."));
            std::sync::Arc::new(StartupCache {
                full: names.clone().map(|name| (name, self.resolve_startup_property(name).map(|v| startup_read(name, v)))).collect(),
                outside_file: names.map(|name| (name, self.resolve_startup_property_outside_file(name))).collect(),
                others: Default::default(),
                hot: std::array::from_fn(|_| std::sync::atomic::AtomicU64::new(HOT_UNKNOWN)),
            })
        })
    }

    /// A startup tier changed: what [`Config::startup_cache`] resolved is dropped.
    fn sources_changed(&mut self) {
        self.startup_cache = std::sync::OnceLock::new();
    }

    /// An environment variable of the server's process (`System.getenv`); none for a test configuration.
    pub fn env_var(&self, name: &str) -> Option<String> {
        self.env.get(name).cloned()
    }

    /// Every environment variable of the server's process.
    pub fn env_vars(&self) -> Vec<(String, String)> {
        self.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// Every `-D` system property given on the command line.
    pub fn system_property_values(&self) -> Vec<(String, String)> {
        self.system_properties.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// `System.getProperties()`: the JVM's own properties (`crate::jvm_properties`) under the `-D` ones, which
    /// replace them as a `-D` option replaces a JVM default.
    pub fn all_system_property_values(&self) -> Vec<(String, String)> {
        let jvm: Vec<(String, String)> = match &self.jvm_properties {
            Some(measured) => measured.as_ref().clone(),
            None => crate::jvm_properties::IMAGE.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        };
        let mut all: HashMap<String, String> = jvm.into_iter().collect();
        all.extend(self.system_property_values());
        all.into_iter().collect()
    }

    /// [`Config::property`] as the server started with it, ignoring runtime changes.
    pub fn startup_property(&self, name: &str) -> Option<String> {
        // `readLongPropertyWithMillisAlias`: the `…InMillis` property is read only while the older name (its primary)
        // gives the default, or nothing that parses as a long
        if let Some(&(_, primary, default)) = MILLIS_ALIASES.iter().find(|(alias, ..)| *alias == name) && let Some(value) = self.startup_property(primary).and_then(|v| v.parse::<i64>().ok()).filter(|v| *v != default) {
            return Some(value.to_string());
        }
        self.read_cached_startup_property(name, |v| v.map(str::to_string))
    }

    fn resolve_startup_property(&self, name: &str) -> Option<String> {
        let key = format!("mockserver.{name}");
        self.system_properties
            .get(&key)
            .or_else(|| self.file_properties.get(&key))
            .or_else(|| self.env.get(&env_name(name)).filter(|v| !v.trim().is_empty()))
            .map(|v| unquote(v).to_string())
    }

    /// Sets a property at runtime (`ConfigurationDTO.applyTo`).
    pub fn set_runtime(&self, name: &str, value: String) {
        self.runtime.write().insert(name.to_string(), value);
        self.runtime_generation.fetch_add(1, std::sync::atomic::Ordering::Release);
    }

    /// How many runtime values were set so far: what is read of the configuration at one count is what it said then.
    pub fn runtime_generation(&self) -> u64 {
        // Acquire: a read at this generation sees every runtime value counted into it
        self.runtime_generation.load(std::sync::atomic::Ordering::Acquire)
    }

    /// `ConfigurationProperties.<name>(value)` from an embedder: takes effect like [`Config::set_runtime`], but the
    /// effective configuration reports it as a `system-property`.
    pub fn set_embedder_property(&self, name: &str, value: String) {
        self.runtime.write().insert(name.to_string(), value.clone());
        self.embedder_set.write().insert(name.to_string(), value);
        self.runtime_generation.fetch_add(1, std::sync::atomic::Ordering::Release);
    }

    /// [`Config::read_property`] of a property every request reads, not looked up while it has no value: a lookup
    /// hashed and compared the name, and a request made some twenty.
    pub fn read_hot<R>(&self, hot: Hot, read: impl FnOnce(Option<&str>) -> R) -> R {
        match self.hot_state(hot) {
            HOT_ABSENT => read(None),
            _ => self.read_property(hot.name(), read),
        }
    }

    /// [`Config::bool_property`] of a property every request reads (see [`Config::read_hot`]).
    pub fn hot_bool(&self, hot: Hot, default: bool) -> bool {
        match self.hot_state(hot) {
            HOT_ABSENT => default,
            HOT_TRUE => true,
            _ => false,
        }
    }

    /// [`Config::int_property`] of a property every request reads (see [`Config::read_hot`]).
    pub fn hot_int(&self, hot: Hot, default: i64) -> i64 {
        match self.hot_state(hot) {
            HOT_ABSENT => default,
            _ => self.int_property(hot.name(), default),
        }
    }

    /// Whether `hot` has no value, `true`, or another value: as read at the current runtime generation, else read now
    /// and kept for it. A value set over the API afterwards counts the generation on, so what was kept is read again.
    fn hot_state(&self, hot: Hot) -> u64 {
        use std::sync::atomic::Ordering;
        // Acquire: a read at this generation sees every runtime value counted into it
        let generation = self.runtime_generation.load(Ordering::Acquire);
        let slot = &self.startup_cache().hot[hot as usize];
        let kept = slot.load(Ordering::Relaxed);
        if kept & HOT_STATE != HOT_UNKNOWN && kept >> 2 == generation {
            return kept & HOT_STATE;
        }
        let state = self.read_property(hot.name(), |v| match v {
            None => HOT_ABSENT,
            Some(v) if v.trim().eq_ignore_ascii_case("true") => HOT_TRUE,
            Some(_) => HOT_OTHER,
        });
        // read at `generation` or a later one, kept for `generation`: a value set meanwhile has it read again
        slot.store(generation << 2 | state, Ordering::Relaxed);
        state
    }

    pub fn bool_property(&self, name: &str, default: bool) -> bool {
        self.read_property(name, |v| v.map(|v| v.trim().eq_ignore_ascii_case("true")).unwrap_or(default))
    }

    pub fn int_property(&self, name: &str, default: i64) -> i64 {
        self.read_property(name, |v| v.and_then(|v| v.trim().parse().ok()).unwrap_or(default))
    }

    /// [`Config::int_property`] as the server started with it, ignoring runtime changes.
    pub fn int_startup_property(&self, name: &str, default: i64) -> i64 {
        self.read_startup_property(name, |v| v.and_then(|v| v.trim().parse().ok()).unwrap_or(default))
    }

    /// Whether [`Config::property`] gives `name` a value that is not blank; nothing is copied.
    pub fn has_property(&self, name: &str) -> bool {
        self.read_property(name, |v| v.is_some_and(|v| !v.trim().is_empty()))
    }

    /// [`Config::bool_property`] as the server started with it, ignoring runtime changes.
    pub fn bool_startup_property(&self, name: &str, default: bool) -> bool {
        self.read_startup_property(name, |v| v.map(|v| v.trim().eq_ignore_ascii_case("true")).unwrap_or(default))
    }

    /// `matchExactCase`: data-plane matching of the method, the path and `REGEX` bodies is case-sensitive. Read when an
    /// expectation is compiled (`HttpRequestPropertiesMatcher.apply`), so a change reaches the expectations created
    /// after it. A `PUT /mockserver/configuration` value counts (upstream 0e8566814); the 8.0.0 process read
    /// its startup copy (scenario `match_exact_case`, its `diverge` steps).
    pub fn match_exact_case(&self) -> bool {
        self.bool_property("matchExactCase", false)
    }

    /// `getRemoteAddressWithFallback`'s fallback: the live `proxyRemoteHost`, when not blank, with a `proxyRemotePort`.
    /// Read at each unmatched request, so a `PUT /mockserver/configuration` sets or (with a blank host) clears the
    /// remote; the 8.0.0 oracle honours it (scenario `proxy_remote_host_runtime`). A startup port forward
    /// ([`Config::port_forward`], upstream's `REMOTE_SOCKET` channel attribute) comes first.
    pub fn proxy_remote(&self) -> Option<(String, u16)> {
        // asked of every unmatched request: nothing is copied while no host is set
        if !self.has_property("proxyRemoteHost") {
            return None;
        }
        let host = self.property("proxyRemoteHost").filter(|h| !h.trim().is_empty())?;
        let port = self.property("proxyRemotePort")?.trim().parse::<u16>().ok()?;
        Some((host, port))
    }

    /// `redactSecretsInLog`: gates `MockServerEventLog`'s masking of sensitive headers/query-string values and
    /// (with [`Config::fixture_body_redact_fields`]) JSON body fields on the event log's retrieved views
    /// (`retrieve?type=REQUESTS|REQUEST_RESPONSES|RECORDED_EXPECTATIONS|LOGS&format=LOG_ENTRIES`, and every
    /// format derived from the redacted REQUESTS/REQUEST_RESPONSES lists), read when a view is
    /// rendered. A `PUT /mockserver/configuration` value counts (upstream 0e8566814); the 8.0.0 process
    /// read the event log's startup copy (scenario `redact_secrets_in_log`, its `diverge` steps).
    pub fn redact_secrets_in_log(&self) -> bool {
        self.bool_property("redactSecretsInLog", false)
    }

    /// `fixtureBodyRedactFields` as consulted by the event-log redactor: comma-separated JSON field names, read like
    /// [`Config::redact_secrets_in_log`].
    pub fn fixture_body_redact_fields(&self) -> Vec<String> {
        self.property("fixtureBodyRedactFields")
            .unwrap_or_default()
            .split(',')
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty())
            .collect()
    }

    /// `redactSecretsInRecordedExpectations`: gates `FixtureRedactor`'s (no-arg constructor: default sensitive
    /// headers and query-string values, no JSON body fields) masking on `retrieve?type=RECORDED_EXPECTATIONS`'s
    /// own JSON/JAVA/JAVASCRIPT/PYTHON/GO/CSHARP/RUBY/RUST/PHP/OPENAPI/POSTMAN/BRUNO/HAR forms — a
    /// *separate* property from [`Config::redact_secrets_in_log`], which never touches
    /// `RECORDED_EXPECTATIONS`. `LOG_ENTRIES` and `CURL` are unaffected either way (confirmed against the
    /// oracle: `HttpState.postProcessRecordedExpectations` is not on either path). Read at each retrieve; a
    /// `PUT /mockserver/configuration` value counts (upstream 0e8566814), which on the 8.0.0 process it did
    /// not (`HttpState` read its startup copy; scenario `redact_secrets_in_recorded_expectations`).
    pub fn redact_secrets_in_recorded_expectations(&self) -> bool {
        self.bool_property("redactSecretsInRecordedExpectations", false)
    }

    /// `deduplicateRecordedExpectations`: `retrieve?type=RECORDED_EXPECTATIONS` runs
    /// `RecordedExpectationPostProcessor.deduplicateAndTemplatize` (`HttpState.postProcessRecordedExpectations`).
    /// Read at each retrieve, like [`Config::redact_secrets_in_recorded_expectations`].
    pub fn deduplicate_recorded_expectations(&self) -> bool {
        self.bool_property("deduplicateRecordedExpectations", false)
    }

    /// `templatizeRecordedValues`: [`Config::deduplicate_recorded_expectations`] also generalises volatile values.
    pub fn templatize_recorded_values(&self) -> bool {
        self.bool_property("templatizeRecordedValues", false)
    }

    pub fn log_level(&self) -> String {
        let level = if let Some(level) = self.runtime_value("logLevel") {
            level.to_ascii_uppercase()
        } else {
            self.cli_owned("logLevel", "LOG_LEVEL").unwrap_or_else(|| "INFO".into()).to_ascii_uppercase()
        };
        normalize_log_level(&level)
    }

    /// The settings `Main` resolves itself (`Arguments`: `serverPort`, `proxyRemoteHost`, `proxyRemotePort` and
    /// `logLevel`), without a command-line option: the `mockserver.<name>` system property, `MOCKSERVER_<SHORT>`,
    /// `<SHORT>`, then the properties file. Blank values are dropped from each source before precedence applies
    /// (`Main.java:308,314`), so a blank `MOCKSERVER_PROXY_REMOTE_PORT` leaves `PROXY_REMOTE_PORT` in charge.
    fn cli_owned(&self, name: &str, short: &str) -> Option<String> {
        let key = format!("mockserver.{name}");
        fn non_blank(v: Option<&String>) -> Option<&String> {
            v.filter(|v| !v.trim().is_empty())
        }
        non_blank(self.system_properties.get(&key))
            .or_else(|| non_blank(self.env.get(&format!("MOCKSERVER_{short}"))))
            // `Main.java:331`: the image sets `SERVER_PORT=1080` for every container, so that default gives way to a
            // `mockserver.serverPort` in the properties file.
            .or_else(|| non_blank(self.env.get(short)).filter(|v| !(short == "SERVER_PORT" && v.as_str() == "1080" && self.file_properties.contains_key(&key))))
            // a `.properties` file never supplies `logLevel` (see `crate::property_file`)
            .or_else(|| non_blank(self.file_properties.get(&key)).filter(|_| name != "logLevel" || self.file_is_json))
            .map(|v| unquote(v).to_string())
    }

    /// `Main.startServer`'s "using environment variables … and system properties … and command line options" message
    ///, as the log layout renders it: each of the three maps as `[\n\tk=v,\n\tk=v\n]` indented by two
    /// spaces after a blank line. `cli` is what the command line supplied for `serverPort`, `proxyRemotePort`,
    /// `proxyRemoteHost` and `logLevel`. A setting the command line or a system property already supplies is dropped
    /// from the sources below it, exactly as `Main` does. Entries come out in `HashMap` order.
    pub fn startup_dump(&self, cli: &[(&str, String)]) -> String {
        let mut parsed: HashMap<String, String> = HashMap::new();
        let mut command_line: Vec<(String, String)> = Vec::new();
        for (name, value) in cli {
            parsed.insert((*name).to_string(), value.clone());
            command_line.push(((*name).to_string(), value.clone()));
        }
        let mut environment: HashMap<String, String> = self
            .env
            .iter()
            .filter(|(k, v)| k.starts_with("MOCKSERVER_") && k.as_str() != "MOCKSERVER_LAUNCHER" && !v.trim().is_empty())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let cli_log_level = cli.iter().any(|(n, _)| *n == "logLevel");
        let mut properties: HashMap<String, String> = self
            .system_properties
            .iter()
            .filter(|(k, v)| {
                k.starts_with("mockserver") && k.as_str() != "mockserver.launcherName" && !v.trim().is_empty() && !(cli_log_level && k.as_str() == "mockserver.logLevel")
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (name, short) in [("serverPort", "SERVER_PORT"), ("proxyRemoteHost", "PROXY_REMOTE_HOST"), ("proxyRemotePort", "PROXY_REMOTE_PORT")] {
            let sys = format!("mockserver.{name}");
            let long = format!("MOCKSERVER_{short}");
            if !parsed.contains_key(name) {
                if let Some(value) = properties.get(&sys) {
                    parsed.insert(name.to_string(), value.clone());
                    environment.remove(&long);
                } else if let Some(value) = environment.get(&long) {
                    parsed.insert(name.to_string(), value.clone());
                } else if let Some(value) = self.env.get(short).filter(|v| !v.trim().is_empty()) {
                    let image_default = name == "serverPort" && value == "1080" && self.file_properties.contains_key(&sys);
                    if !image_default {
                        environment.insert(short.to_string(), value.clone());
                        parsed.insert(name.to_string(), value.clone());
                    }
                }
            } else {
                properties.remove(&sys);
                environment.remove(&long);
                environment.remove(short);
            }
            if !parsed.contains_key(name) && let Some(value) = self.file_properties.get(&sys) {
                parsed.insert(name.to_string(), value.clone());
            }
        }
        let render = |entries: Vec<(String, String)>| {
            let body: Vec<String> = java_hash_map_order(entries).into_iter().map(|(k, v)| format!("{k}={v}")).collect();
            let text = format!("[\n\t{}\n]", body.join(",\n\t"));
            text.lines().map(|l| format!("  {l}")).collect::<Vec<_>>().join("\n")
        };
        let command_line: Vec<(String, String)> = {
            // a later duplicate overwrites, as `HashMap.put`
            let mut unique: Vec<(String, String)> = Vec::new();
            for (k, v) in command_line {
                match unique.iter_mut().find(|(uk, _)| *uk == k) {
                    Some(slot) => slot.1 = v,
                    None => unique.push((k, v)),
                }
            }
            unique
        };
        let mut env_entries: Vec<(String, String)> = environment.into_iter().collect();
        env_entries.sort();
        let mut property_entries: Vec<(String, String)> = properties.into_iter().collect();
        // `System.getProperties()` is a `ConcurrentHashMap` of about a hundred entries (a 128-slot table): its order is
        // the insertion order into the dump's own `HashMap`, which only matters between keys sharing a bucket there.
        property_entries.sort_by_key(|(k, _)| {
            let h = java_string_hash(k) as u32;
            (((h ^ (h >> 16)) & 0x7fff_ffff) & 127, k.clone())
        });
        let (environment, properties, command_line) = (render(env_entries), render(property_entries), render(command_line));
        if crate::log::compact_enabled(self) {
            // `getCompactMessage`: each map's text on one line, cut at 120 characters
            let compact = [&environment, &properties, &command_line].map(|text| crate::log_entry::compact_argument("", &serde_json::Value::Null, text));
            return crate::log_entry::compact_message("using environment variables:{}and system properties:{}and command line options:{}", &compact);
        }
        format!("using environment variables:\n\n{environment}\n\n and system properties:\n\n{properties}\n\n and command line options:\n\n{command_line}\n")
    }

    /// Builds the configuration from command-line arguments and the process environment.
    pub fn from_args(args: &[String], env: HashMap<String, String>) -> Result<Config, ConfigError> {
        let jvm_heap = JvmHeapOptions::from_env(&env);
        // `-XX:ActiveProcessorCount` in a JVM options variable the image reads sets the processors the JVM reports
        let available_processors = measured_available_processors(jvm_heap.active_processors.or_else(|| env.get(ACTIVE_PROCESSOR_COUNT_ENV).and_then(|v| v.trim().parse().ok())));
        let heap_available_kb = Some(measured_heap_available_kb(env.get(CONTAINER_MEMORY_ENV).and_then(|v| v.trim().parse().ok()), available_processors, &jvm_heap));
        let available_processors = Some(available_processors);
        let jvm_properties = Some(std::sync::Arc::new(crate::jvm_properties::measured(args, &env)));
        let mut config = Config { env, llm_provider_default_urls: true, heap_available_kb, available_processors, jvm_properties, ..Config::default() };
        let mut cli_ports: Option<String> = None;
        let mut cli_log_level: Option<String> = None;
        let mut cli_remote_port: Option<u16> = None;
        let mut cli_remote_host: Option<String> = None;
        let mut i = 0;
        // A dangling flag with no following token is a parse-level failure — upstream's picocli raises a
        // `ParameterException` for it (`Main.java`'s `setParameterExceptionHandler`), which exits 2.
        let value = |i: &mut usize, flag: &str| -> Result<String, ConfigError> {
            *i += 1;
            args.get(*i).cloned().ok_or_else(|| ConfigError::missing_value(format!("missing value for {flag}")))
        };
        while i < args.len() {
            let arg = args[i].as_str();
            match arg {
                "run" => {}
                "-serverPort" | "-p" | "--port" => cli_ports = Some(value(&mut i, arg)?),
                "-logLevel" | "-l" | "--log-level" => {
                    let level = value(&mut i, arg)?;
                    if !VALID_LOG_LEVELS.contains(&level.as_str()) {
                        return Err(ConfigError::invalid(format!(
                            "logLevel value \"{level}\" is invalid, please specify one of SL4J levels: \"TRACE\", \"DEBUG\", \"INFO\", \"WARN\", \"ERROR\", \"OFF\" or the Java Logger levels: \"FINEST\", \"FINE\", \"INFO\", \"WARNING\", \"SEVERE\", \"OFF\""
                        )));
                    }
                    cli_log_level = Some(level);
                }
                "-proxyRemotePort" => {
                    let v = value(&mut i, arg)?;
                    cli_remote_port = Some(remote_port(&v).map_err(ConfigError::invalid)?);
                }
                "-proxyRemoteHost" => {
                    let host = value(&mut i, arg)?;
                    if !host.trim().is_empty() && !is_valid_remote_host(&host) {
                        return Err(ConfigError::invalid(format!(
                            "proxyRemoteHost value \"{host}\" is invalid, please specify a host name i.e. \"localhost\" or \"127.0.0.1\""
                        )));
                    }
                    cli_remote_host = Some(host);
                }
                "--init" => {
                    let v = value(&mut i, arg)?;
                    config.system_properties.insert("mockserver.initializationJsonPath".into(), v);
                }
                _ if arg.starts_with("-D") => {
                    if let Some((k, v)) = arg[2..].split_once('=') {
                        config.system_properties.insert(k.to_string(), v.to_string());
                    }
                }
                _ if arg.starts_with("--port=") => cli_ports = Some(arg["--port=".len()..].to_string()),
                _ => eprintln!("WARN ignoring unsupported argument {arg}"),
            }
            i += 1;
        }
        config.load_property_file();

        // `Main`: without the command-line options, the system property, `MOCKSERVER_PROXY_REMOTE_*`, `PROXY_REMOTE_*`
        // or the properties file, like `serverPort`.
        let remote_port_resolved = match cli_remote_port {
            Some(port) => Some(port),
            None => config
                .cli_owned("proxyRemotePort", "PROXY_REMOTE_PORT")
                .map(|v| remote_port(&v))
                .transpose()
                .map_err(ConfigError::invalid)?,
        };
        let remote_host = cli_remote_host.or_else(|| config.cli_owned("proxyRemoteHost", "PROXY_REMOTE_HOST"));
        config.port_forward = remote_port_resolved.map(|port| {
            let host = remote_host.filter(|h| !h.trim().is_empty()).unwrap_or_else(|| "localhost".into());
            (host.trim().to_string(), port)
        });
        if let Some(level) = cli_log_level {
            config.system_properties.insert("mockserver.logLevel".into(), level);
        }
        config.sources_changed();
        let ports = cli_ports.or_else(|| config.cli_owned("serverPort", "SERVER_PORT")).ok_or_else(|| {
            ConfigError {
                no_port: true,
                ..ConfigError::invalid("ERROR:  no port specified — set a port with -p/--port, -serverPort, SERVER_PORT or mockserver.serverPort")
            }
        })?;
        config.ports = ports
            .split(',')
            .map(|p| p.trim().parse::<u16>().map_err(|_| ConfigError::invalid(format!("invalid port \"{p}\""))))
            .collect::<Result<_, _>>()?;
        // `Main`: standalone launch (jar/Docker/CLI — this binary) prints the proxy setup block at startup by
        // default, unless the user explicitly configured `proxySetupLogging` in ANY source (-D, env var, or
        // the properties file). Embedded use of `Server::start` directly (not through this CLI parser) keeps
        // the raw default (`false`, `src/server.rs`'s `bool_property` fallback) so it stays silent, matching
        // `ConfigurationProperties.proxySetupLogging()`'s embedded default.
        if config.property("proxySetupLogging").is_none() {
            config.system_properties.insert("mockserver.proxySetupLogging".into(), "true".into());
        }
        config.sources_changed();
        Ok(config)
    }
}

/// A [`Config::from_args`] failure: the message to print, and the exit code a real shell/CI caller would
/// observe. Upstream splits this at `Main.java`'s two exception handlers: an unparseable command line — here,
/// only a dangling flag with no following value — is picocli's `ParameterException`
/// (`setParameterExceptionHandler`), which exits 2; an invalid value (a malformed port, host or log level) or an
/// unresolvable port is `RunCommand.run()`'s own `catch (IllegalArgumentException)` branch, which prints and
/// returns without ever calling `System.exit`, leaving the documented exit code at 0 (`shouldExitZeroForInvalid­
/// ServerPortUsageError`, `MainTest.java`).
#[derive(Debug)]
pub struct ConfigError {
    pub message: String,
    pub exit_code: u8,
    /// No `serverPort` from any source: `Main` prints the `run` usage and a "no port specified" error instead.
    pub no_port: bool,
}

impl ConfigError {
    fn missing_value(message: impl Into<String>) -> Self {
        ConfigError { message: message.into(), exit_code: 2, no_port: false }
    }

    fn invalid(message: impl Into<String>) -> Self {
        ConfigError { message: message.into(), exit_code: 0, no_port: false }
    }
}

/// The iteration order of a `java.util.HashMap<String, String>` holding `entries` (inserted in the order given): by
/// bucket (`hash ^ hash >>> 16`, masked by the table size, which starts at 16 and doubles past a 0.75 load), insertion
/// order within a bucket.
fn java_hash_map_order(entries: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut table = 16usize;
    while entries.len() * 4 > table * 3 {
        table *= 2;
    }
    let mut keyed: Vec<(usize, usize, (String, String))> = entries
        .into_iter()
        .enumerate()
        .map(|(i, e)| {
            let h = java_string_hash(&e.0) as u32;
            (((h ^ (h >> 16)) as usize) & (table - 1), i, e)
        })
        .collect();
    keyed.sort_by_key(|(b, i, _)| (*b, *i));
    keyed.into_iter().map(|(_, _, e)| e).collect()
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// `Main.Arguments`' SLF4J levels plus the Java Logger levels `Main.validateArguments` also accepts.
pub(crate) const VALID_LOG_LEVELS: [&str; 10] = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "OFF", "FINEST", "FINE", "WARNING", "SEVERE"];

/// `ConfigurationProperties.getSLF4JOrJavaLoggerToSLF4JLevelMapping` (upstream, confirmed against its
/// source): both the SLF4J and the java.util.logging spelling of a level are accepted everywhere
/// `logLevel` is read (CLI, system property, env var, properties file, runtime `PUT
/// /mockserver/configuration`), but every console/event-log gate (`src/log.rs`,
/// `State::info_enabled`) and `Config::log_level()`'s own callers compare against the SLF4J spelling
/// literally `-logLevel WARNING` (java.util.logging) did not suppress the startup
/// INFO line the way `-logLevel WARN` (SLF4J) does, because the value was kept verbatim. `INFO` and
/// `OFF` are spelled the same in both vocabularies, so only the other four need mapping; an
/// already-validated value (`VALID_LOG_LEVELS`) that isn't one of the four JUL names passes through
/// unchanged.
fn normalize_log_level(level: &str) -> String {
    match level {
        "FINEST" => "TRACE",
        "FINE" => "DEBUG",
        "WARNING" => "WARN",
        "SEVERE" => "ERROR",
        other => other,
    }
    .to_string()
}

/// `Main.validateArguments`' `validIpAddressRegex` or `validHostnameRegex` (`Main.java`), ported verbatim.
pub(crate) fn is_valid_remote_host(value: &str) -> bool {
    static IP: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$").unwrap()
    });
    static HOSTNAME: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$").unwrap()
    });
    IP.is_match(value) || HOSTNAME.is_match(value)
}

fn remote_port(v: &str) -> Result<u16, String> {
    v.trim().parse::<u16>().map_err(|_| format!("proxyRemotePort value \"{v}\" is invalid, please specify a port i.e. \"1080\""))
}

/// [`Config::startup_property`] and [`Config::startup_property_outside_file`] of every recognised property.
#[derive(Debug)]
struct StartupCache {
    full: rustc_hash::FxHashMap<&'static str, Option<String>>,
    outside_file: rustc_hash::FxHashMap<&'static str, Option<String>>,
    /// `full` for the names outside the recognised list (`proxyPass`, `proxyPassMappings`, …), each resolved when
    /// first read: the startup tiers do not change once the configuration is built.
    others: parking_lot::RwLock<rustc_hash::FxHashMap<String, Option<String>>>,
    /// Each [`Hot`] property's state (`HOT_…`, the low two bits) and the runtime generation it was read at (the bits
    /// above).
    hot: [std::sync::atomic::AtomicU64; Hot::COUNT],
}

/// The properties every request reads, each kept in [`StartupCache::hot`] at its index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hot {
    AttachMismatchDiagnosticToResponse,
    AttemptToProxyIfNoMatchingExpectation,
    ClosestMatchHintEnabled,
    ConnectionLifecycleChaosEnabled,
    DataPlaneAuthenticationRequired,
    DefaultResponseHeaders,
    DetailedMatchFailures,
    DetailedVerificationFailures,
    EnableCorsForAllResponses,
    ForwardProxyBlockPrivateNetworks,
    GlobalResponseDelayMillis,
    Http3Port,
    LivenessHttpGetPath,
    MaxRequestBodySize,
    MetricsEnabled,
    OpenApiResponseValidation,
    OtelGenerateTraceId,
    OtelPropagateTraceContext,
    ProxyPass,
    ProxyPassMappings,
    TlsMutualAuthenticationRequired,
    TransparentProxyEnabled,
}

impl Hot {
    const COUNT: usize = Hot::TransparentProxyEnabled as usize + 1;

    /// The property's name.
    pub const fn name(self) -> &'static str {
        match self {
            Hot::AttachMismatchDiagnosticToResponse => "attachMismatchDiagnosticToResponse",
            Hot::AttemptToProxyIfNoMatchingExpectation => "attemptToProxyIfNoMatchingExpectation",
            Hot::ClosestMatchHintEnabled => "closestMatchHintEnabled",
            Hot::ConnectionLifecycleChaosEnabled => "connectionLifecycleChaosEnabled",
            Hot::DataPlaneAuthenticationRequired => "dataPlaneAuthenticationRequired",
            Hot::DefaultResponseHeaders => "defaultResponseHeaders",
            Hot::DetailedMatchFailures => "detailedMatchFailures",
            Hot::DetailedVerificationFailures => "detailedVerificationFailures",
            Hot::EnableCorsForAllResponses => "enableCORSForAllResponses",
            Hot::ForwardProxyBlockPrivateNetworks => "forwardProxyBlockPrivateNetworks",
            Hot::GlobalResponseDelayMillis => "globalResponseDelayMillis",
            Hot::Http3Port => "http3Port",
            Hot::LivenessHttpGetPath => "livenessHttpGetPath",
            Hot::MaxRequestBodySize => "maxRequestBodySize",
            Hot::MetricsEnabled => "metricsEnabled",
            Hot::OpenApiResponseValidation => "openAPIResponseValidation",
            Hot::OtelGenerateTraceId => "otelGenerateTraceId",
            Hot::OtelPropagateTraceContext => "otelPropagateTraceContext",
            Hot::ProxyPass => "proxyPass",
            Hot::ProxyPassMappings => "proxyPassMappings",
            Hot::TlsMutualAuthenticationRequired => "tlsMutualAuthenticationRequired",
            Hot::TransparentProxyEnabled => "transparentProxyEnabled",
        }
    }
}

/// A [`Hot`] property's state: not read at the generation kept beside it; without a value; `true`; another value.
const HOT_UNKNOWN: u64 = 0;
const HOT_ABSENT: u64 = 1;
const HOT_TRUE: u64 = 2;
const HOT_OTHER: u64 = 3;
/// The bits of a kept [`Hot`] state.
const HOT_STATE: u64 = 3;

/// `mockserver.fooBarBaz` → `MOCKSERVER_FOO_BAR_BAZ`, except for the literal names in [`ENV_NAME_EXCEPTIONS`].
pub fn env_name(name: &str) -> String {
    if let Some((_, env)) = ENV_NAME_EXCEPTIONS.iter().find(|(n, _)| *n == name) {
        return env.to_string();
    }
    let mut out = String::from("MOCKSERVER_");
    let chars: Vec<char> = name.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        let prev_lower = i > 0 && (chars[i - 1].is_ascii_lowercase() || chars[i - 1].is_ascii_digit());
        let next_lower = chars.get(i + 1).is_some_and(|n| n.is_ascii_lowercase());
        let prev_upper = i > 0 && chars[i - 1].is_ascii_uppercase();
        if c.is_ascii_uppercase() && (prev_lower || (prev_upper && next_lower)) {
            out.push('_');
        }
        out.push(c.to_ascii_uppercase());
    }
    out
}

/// Every configuration property with its effective value, as `ConfigurationSerializer` writes a `Configuration`:
/// the defaults (captured from the oracle), overlaid with what is configured here, typed like the default.
///
/// Rebuilds a fresh map rather than mutating a clone of `DEFAULTS` in place, and never calls
/// `serde_json::Map::remove` on it: with the `preserve_order` feature `Map` is backed by an `IndexMap`, whose
/// `remove` is `swap_remove` — it would move the last-inserted entry into the removed slot and corrupt the
/// alphabetical order the oracle's Jackson serializer produces (`configuration_defaults.json` was captured in
/// that order). Omitting an entry by never pushing it keeps the order intact for free.
pub fn effective_json(config: &Config) -> serde_json::Value {
    effective_json_live(config, None)
}

/// [`effective_json`] with the live subject alternative name sets (domains, IPs) a running server holds in place of the
/// configured seeds: upstream reads them back from the `Configuration` that every request's `Host` name grows.
pub fn effective_json_live(config: &Config, sans: Option<(Vec<String>, Vec<String>)>) -> serde_json::Value {
    use serde_json::Value;
    static DEFAULTS: std::sync::LazyLock<serde_json::Map<String, Value>> =
        std::sync::LazyLock::new(|| serde_json::from_str(include_str!("configuration_defaults.json")).expect("valid JSON"));
    let mut out = serde_json::Map::with_capacity(DEFAULTS.len());
    for (name, default) in DEFAULTS.iter() {
        // `actionHandlerThreadCount`'s default follows the processors
        let derived_default;
        let default = if name == "actionHandlerThreadCount" {
            derived_default = Value::from(default_action_handler_thread_count(config));
            &derived_default
        } else {
            default
        };
        if credentials::OMITTED_CREDENTIAL_PROPERTIES.contains(&name.as_str()) {
            // write-only: never disclosed, whether set or not (ConfigurationDTO @JsonIgnore-d getter)
            continue;
        }
        let mut value = if name == "logLevel" {
            // Reporting only: upstream's SLF4J/JUL mapping table reports OFF as ERROR while every gate
            // (console, event log) still treats OFF as silent, so `log_level()` itself keeps "OFF".
            let level = config.log_level();
            Value::String(if level == "OFF" { "ERROR".into() } else { level })
        } else if name == "ringBufferSize" {
            Value::from(ring_buffer_size(config))
        } else if (name == "maxExpectations" || name == "maxLogEntries") && config.property(name).is_none() {
            // `Configuration.maxExpectations`/`maxLogEntries`: the instance's `devMode` supplies 1000 until a value is set.
            Value::from(if name == "maxExpectations" { max_expectations(config) } else { max_log_entries(config) })
        } else if (name == "maxPendingDelayedResponses" || name == "maxQueuedTemplateActions") && config.property(name).is_none() {
            Value::from(default_max_pending_actions(config))
        } else if name == "maxEventLogSizeInBytes" {
            Value::from(max_event_log_size_in_bytes(config))
        } else if name == "maxOpenAiResponsesSizeInBytes" {
            Value::from(max_open_ai_responses_size_in_bytes(config))
        } else if name == "extensionListenerMaxBytes" {
            Value::from(extension_listener_max_bytes(config))
        } else if name == "binaryMessageFraming" {
            // `BinaryMessageFraming.valueOf(value.trim().toUpperCase())`, RAW for anything else
            let framing = config.property(name).map(|v| v.trim().to_uppercase()).unwrap_or_default();
            let known = ["RAW", "POSTGRESQL", "MYSQL", "REDIS", "LENGTH_PREFIX"];
            Value::String(if known.contains(&framing.as_str()) { framing } else { "RAW".into() })
        } else if name == "dynamicallyCreateCertificateAuthorityCertificate" && config.bool_property("proxySetup", false) {
            // `proxySetup` forces dynamic CA generation (`Configuration.dynamicallyCreateCertificateAuthorityCertificate`).
            Value::Bool(true)
        } else if let Some(live) = sans.as_ref().and_then(|(domains, ips)| match name.as_str() {
            "sslSubjectAlternativeNameDomains" => Some(domains),
            "sslSubjectAlternativeNameIps" => Some(ips),
            _ => None,
        }) {
            Value::Array(live.iter().cloned().map(Value::String).collect())
        } else if let Some(items) = default.is_array().then(|| config.list_property(name)).flatten() {
            Value::Array(items.into_iter().map(|item| item.map_or(Value::Null, Value::String)).collect())
        } else if let Some(configured) = config.property(name) {
            typed(&configured, default).unwrap_or_else(|| default.clone())
        } else {
            default.clone()
        };
        if let Value::Array(items) = &value && SET_PROPERTIES.contains(&name.as_str()) {
            value = Value::Array(java_hash_order(items));
        }
        if credentials::WHOLE_VALUE_MASKED_PROPERTIES.contains(&name.as_str()) {
            // `default` is the JSON `null` sentinel for these — absent (never configured) or cleared to ""
            // both fail this check, which is exactly "no credential to disclose" (matches the oracle: GET
            // masks to null, which Jackson's NON_NULL inclusion then omits, never to the bare mask).
            let Value::String(set) = &value else { continue };
            if set.is_empty() {
                continue;
            }
            value = Value::String(credentials::REDACTED_VALUE.to_string());
        } else if credentials::EMBEDDED_MASKED_PROPERTIES.contains(&name.as_str()) && let Value::String(raw) = &value {
            value = Value::String(credentials::redact_sensitive_value(name, raw));
        }
        out.insert(name.clone(), value);
    }
    // Properties that are absent until they are set (a null Jackson leaves out), in the alphabetical place Jackson writes them.
    let mut added = false;
    for (name, kind) in OPTIONAL_PROPERTIES {
        // `Configuration.proxyPassMappings()` falls back to the `proxyPass` property while none was set on the instance
        let fallback = || (*name == "proxyPassMappings").then(|| config.property("proxyPass")).flatten().map(|text| crate::config_objects::proxy_pass_property(&text).to_string());
        let Some(configured) = config.property(name).or_else(fallback) else { continue };
        let Some(value) = optional_value(*kind, &configured) else { continue };
        out.insert((*name).to_string(), value);
        added = true;
    }
    if added {
        let mut entries: Vec<(String, Value)> = std::mem::take(&mut out).into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        out.extend(entries);
    }
    Value::Object(out)
}

/// The JSON type of an optional property.
#[derive(Clone, Copy)]
enum OptionalKind {
    Text,
    Long,
    Int,
    StringMap,
    /// `controlPlaneScopeMapping`: scope to role, roles read leniently ([`scope_mapping_role`]).
    ScopeMapping,
    /// `connectionDelay`: held as the JSON it prints (`config_objects`).
    Object,
    /// `proxyPassMappings`: the mappings as read; printing derives the target's parts and can fail (`config_objects`).
    ProxyPass,
}

/// DTO properties whose default is null: `GET /mockserver/configuration` leaves them out until one is set.
const OPTIONAL_PROPERTIES: &[(&str, OptionalKind)] = &[
    ("clusterTransportConfig", OptionalKind::Text),
    ("forwardHttpProxy", OptionalKind::Text),
    ("forwardHttpsProxy", OptionalKind::Text),
    ("forwardSocksProxy", OptionalKind::Text),
    ("globalResponseDelayMillis", OptionalKind::Long),
    ("logLevelOverrides", OptionalKind::StringMap),
    ("proxyRemotePort", OptionalKind::Int),
    ("controlPlaneScopeMapping", OptionalKind::ScopeMapping),
    ("connectionDelay", OptionalKind::Object),
    ("proxyPassMappings", OptionalKind::ProxyPass),
];

fn optional_value(kind: OptionalKind, stored: &str) -> Option<serde_json::Value> {
    use serde_json::Value;
    match kind {
        OptionalKind::Text => (!stored.is_empty()).then(|| Value::String(stored.to_string())),
        OptionalKind::Long | OptionalKind::Int => stored.trim().parse::<i64>().ok().map(Value::from),
        // an empty map is as good as none: the serializer leaves it out
        OptionalKind::StringMap => match serde_json::from_str::<Value>(stored) {
            Ok(Value::Object(map)) if !map.is_empty() => Some(Value::Object(map)),
            _ => None,
        },
        OptionalKind::Object => serde_json::from_str::<Value>(stored).ok().filter(|v| !v.is_null()),
        OptionalKind::ProxyPass => serde_json::from_str::<Value>(stored)
            .ok()
            .and_then(|v| crate::config_objects::print_proxy_pass_mappings(&v).ok())
            .filter(|v| v.as_array().is_some_and(|a| !a.is_empty())),
        // an update holds the map as JSON; a system property, properties file or environment variable holds
        // `scope=role,scope=role` text. Either way only recognised roles survive, and an empty map is left out.
        OptionalKind::ScopeMapping => {
            let mut out = serde_json::Map::new();
            match serde_json::from_str::<Value>(stored) {
                Ok(Value::Object(map)) => {
                    for (scope, role) in map {
                        if let Some(role) = role.as_str().and_then(scope_mapping_role) {
                            out.insert(scope, Value::String(role.to_string()));
                        }
                    }
                }
                _ => {
                    // `ConfigurationProperties.parseScopeMapping`: pairs of `scope=role`, both sides trimmed, a pair
                    // without `=`, with a blank side or with an unrecognised role skipped (so a typo cannot widen access)
                    for pair in stored.split(',') {
                        let Some((scope, role)) = pair.split_once('=') else { continue };
                        let scope = scope.trim();
                        if let (false, Some(role)) = (scope.is_empty(), scope_mapping_role(role)) {
                            out.insert(scope.to_string(), Value::String(role.to_string()));
                        }
                    }
                }
            }
            (!out.is_empty()).then_some(Value::Object(out))
        }
    }
}

/// The `ControlPlaneRole` a `controlPlaneScopeMapping` value names: trimmed, case-insensitive, anything else none.
fn scope_mapping_role(text: &str) -> Option<&'static str> {
    match text.trim().to_ascii_uppercase().as_str() {
        "READ" => Some("READ"),
        "MUTATE" => Some("MUTATE"),
        "ADMIN" => Some("ADMIN"),
        _ => None,
    }
}

/// The properties `ConfigurationDTO` holds as a `Set<String>` (written in hash order, not insertion order).
const SET_PROPERTIES: &[&str] = &[
    "controlPlaneJWTAuthenticationRequiredClaims",
    "controlPlaneOidcRequiredScopes",
    "sslSubjectAlternativeNameDomains",
    "sslSubjectAlternativeNameIps",
];

/// `String.split(",")`: inner empty strings stay, trailing ones are dropped, and text without a comma is one element.
fn java_split_comma(text: &str) -> Vec<String> {
    let mut parts: Vec<String> = text.split(',').map(str::to_string).collect();
    if parts.len() > 1 {
        while parts.last().is_some_and(String::is_empty) {
            parts.pop();
        }
    }
    parts
}

/// Sets whose instance setter refuses a null element, after the properties ahead of it in the update are in force.
pub const NULL_REFUSING_SETS: &[&str] = &["sslSubjectAlternativeNameDomains", "sslSubjectAlternativeNameIps"];

/// `String.hashCode`.
fn java_string_hash(s: &str) -> i32 {
    s.encode_utf16().fold(0i32, |h, c| h.wrapping_mul(31).wrapping_add(c as i32))
}

/// A `HashSet<String>`'s iteration order: duplicates dropped, then by bucket (`hash ^ hash >>> 16`, masked by the table
/// size), insertion order within a bucket. The table starts at 16 slots and doubles whenever the load passes 0.75.
fn java_hash_order(items: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut unique: Vec<&serde_json::Value> = Vec::new();
    for item in items {
        if !unique.contains(&item) {
            unique.push(item);
        }
    }
    let mut table = 16usize;
    while unique.len() * 4 > table * 3 {
        table *= 2;
    }
    let bucket = |v: &serde_json::Value| {
        let h = java_string_hash(v.as_str().unwrap_or("")) as u32;
        ((h ^ (h >> 16)) as usize) & (table - 1)
    };
    let mut ordered: Vec<(usize, usize, &serde_json::Value)> = unique.iter().enumerate().map(|(i, v)| (bucket(v), i, *v)).collect();
    ordered.sort_by_key(|(b, i, _)| (*b, *i));
    ordered.into_iter().map(|(_, _, v)| v.clone()).collect()
}

/// `Configuration.ringBufferSize`: the explicit value, else `min(maxLogEntries, 16384)`, rounded up to a power of two
/// either way (the disruptor's requirement).
pub fn ring_buffer_size(config: &Config) -> i64 {
    let size = match config.property("ringBufferSize").and_then(|v| v.trim().parse::<i64>().ok()) {
        Some(explicit) => explicit,
        None => max_log_entries(config).min(16384),
    };
    next_power_of_two(size)
}

/// `ConfigurationProperties.heapAvailableInKB` of the oracle container the goldens were recorded in: the 32 GiB Docker VM
/// (`align_up(0.45 * 33587785728, 2 MiB) / 1024 - 20480`). It reproduces the goldens' `maxEventLogSizeInBytes` and
/// `maxOpenAiResponsesSizeInBytes` (754764800, a twentieth), and is what a test or embedding configuration uses: the
/// value follows the machine the oracle ran on, not this process's.
pub const ORACLE_HEAP_AVAILABLE_KB: i64 = 14_741_504;

/// The memory of the container the oracle that recorded the goldens ran in (the Docker VM's, no limit set):
/// [`ORACLE_HEAP_AVAILABLE_KB`] is derived from it. The process-scenario harness pins our binary to it through
/// [`CONTAINER_MEMORY_ENV`].
pub const ORACLE_CONTAINER_MEMORY_BYTES: u64 = 33_587_785_728;

/// An environment variable that names the container memory, in bytes, the heap-derived defaults are sized from, in
/// place of the cgroup limit or the machine's memory: how a test pins the binary to the memory of the VM the goldens
/// were recorded in.
pub const CONTAINER_MEMORY_ENV: &str = "MOCK_SERVER_CONTAINER_MEMORY_BYTES";

/// The processors of the machine the oracle that recorded the goldens ran on (`-XX:ActiveProcessorCount`, pinned for
/// every oracle container by `ORACLE_ACTIVE_PROCESSORS` in `oracle.env`): what a test or embedding
/// configuration sizes `actionHandlerThreadCount` from. The process-scenario harness pins our binary to it through
/// [`ACTIVE_PROCESSOR_COUNT_ENV`].
pub const ORACLE_ACTIVE_PROCESSORS: usize = 6;

/// An environment variable that names the processor count `actionHandlerThreadCount` defaults from, in place of the
/// processors this process may use: how a test pins the binary to the machine the goldens were recorded on.
pub const ACTIVE_PROCESSOR_COUNT_ENV: &str = "MOCK_SERVER_ACTIVE_PROCESSOR_COUNT";

/// `Runtime.availableProcessors()` as the configuration supplies it.
pub fn available_processors(config: &Config) -> usize {
    config.available_processors.unwrap_or(ORACLE_ACTIVE_PROCESSORS)
}

/// The processors this process may use (the cgroup CPU quota and affinity count, as a containerised JVM's
/// `availableProcessors`), or `pinned` ([`ACTIVE_PROCESSOR_COUNT_ENV`]) when it is positive.
fn measured_available_processors(pinned: Option<usize>) -> usize {
    pinned.filter(|&n| n > 0).unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from))
}

/// The default `actionHandlerThreadCount`: `Math.max(5, Runtime.getRuntime().availableProcessors())`.
pub fn default_action_handler_thread_count(config: &Config) -> i64 {
    available_processors(config).max(5) as i64
}

/// `BASE_MEMORY_IN_KB`: what upstream reserves for JVM internals before sizing stores from the heap ceiling.
const BASE_MEMORY_IN_KB: i64 = 20 * 1024;

/// The image's `-XX:MaxRAMPercentage=45.0` (its ENTRYPOINT): the JVM heap ceiling is this share of the container's
/// memory, the cgroup limit when one is set, else the machine's, unless a heap flag sets it ([`JvmHeapOptions`]). The
/// ENTRYPOINT's flag follows `JAVA_TOOL_OPTIONS` and `JDK_JAVA_OPTIONS` and precedes `_JAVA_OPTIONS`.
const MAX_RAM_PERCENTAGE: f64 = 45.0;

/// `MinRAMPercentage`'s default: below this share of the memory being under [`DEFAULT_MAX_HEAP_SIZE`], the heap is this share.
const MIN_RAM_PERCENTAGE: f64 = 50.0;

/// HotSpot's default `MaxHeapSize` (`ScaleForWordSize(96M)`, 13/10 of it on a 64-bit VM): the floor of the ergonomic ceiling.
const DEFAULT_MAX_HEAP_SIZE: u64 = 96 * 1024 * 1024 * 13 / 10;

/// HotSpot's default `MaxRAM` on a 64-bit VM: the most memory the ceiling is sized from unless `-XX:MaxRAM` says otherwise.
const DEFAULT_MAX_RAM: u64 = 128 << 30;

/// `os::is_server_class_machine`: at least this much memory (2 GiB less 256 MiB) and 2 processors, else the JVM is not
/// server class and picks the Serial collector in place of G1.
const SERVER_CLASS_MEMORY: u64 = 1792 << 20;

/// ZGC's heap alignment (`ZGranuleSize`), and the floor of every other collector's: their card table's alignment
/// constraint, 512-byte cards times the VM's 4 KiB pages (`GCArguments::initialize_heap_flags_and_sizes`).
const HEAP_ALIGNMENT: u64 = 2 * 1024 * 1024;

/// The environment variables the image's `java` reads options from, in the order HotSpot applies them (a later flag
/// wins): `JAVA_TOOL_OPTIONS` before the command line, `JDK_JAVA_OPTIONS` (the launcher's) at its head, `_JAVA_OPTIONS`
/// after it. The ENTRYPOINT's own flags set neither the heap nor the collector.
const JVM_OPTION_VARIABLES: [&str; 3] = ["JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"];

/// The image's `ENV JAVA_TOOL_OPTIONS`: a user's `JAVA_TOOL_OPTIONS` replaces it, collector included.
const IMAGE_JAVA_TOOL_OPTIONS: &str = "-XX:+UseZGC";

/// The garbage collector the JVM options select, which decides how the heap ceiling is aligned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Collector {
    Z,
    /// G1, named or chosen on a server-class machine.
    G1,
    /// HotSpot's choice when no collector is named, until the memory and processors are known ([`JvmHeapOptions::resolved`]):
    /// G1 on a server-class machine, else Serial.
    Ergonomic,
    /// Serial: the 2 MiB floor only, and `Runtime.maxMemory()` is 64 KiB under the heap (the survivor space it leaves out).
    Serial,
    /// Parallel: the 2 MiB floor; its `Runtime.maxMemory()` leaves out the young generation's maximum survivor space, about
    /// a ninth of the heap ([`JvmHeapOptions::reported`]).
    Parallel,
    /// Shenandoah aligns the heap to its region size, with no 2 MiB floor (measured on the oracle).
    Shenandoah,
    /// Epsilon aligns to the 4 KiB page only (measured on the oracle).
    Epsilon,
}

/// What the image's JVM options say about the heap: the last `-Xmx` / `-XX:MaxHeapSize` and the last
/// collector selected, read as the image's `java` reads them.
#[derive(Debug, Clone, Copy, PartialEq)]
struct JvmHeapOptions {
    max_heap_bytes: Option<u64>,
    collector: Collector,
    /// `-XX:MaxRAM`: replaces the memory the percentage is taken of, whatever the machine has.
    max_ram: Option<u64>,
    max_ram_percentage: f64,
    min_ram_percentage: f64,
    /// `-XX:ActiveProcessorCount`.
    active_processors: Option<usize>,
}

impl JvmHeapOptions {
    /// The image's defaults: no heap flag, ZGC.
    const IMAGE: JvmHeapOptions = JvmHeapOptions {
        max_heap_bytes: None,
        collector: Collector::Z,
        max_ram: None,
        max_ram_percentage: MAX_RAM_PERCENTAGE,
        min_ram_percentage: MIN_RAM_PERCENTAGE,
        active_processors: None,
    };

    fn from_env(env: &HashMap<String, String>) -> JvmHeapOptions {
        let mut options = JvmHeapOptions { collector: Collector::Ergonomic, ..JvmHeapOptions::IMAGE };
        for name in JVM_OPTION_VARIABLES {
            if name == "_JAVA_OPTIONS" {
                // the ENTRYPOINT's own flag, after the two variables the launcher reads first
                options.max_ram_percentage = MAX_RAM_PERCENTAGE;
            }
            let value = match env.get(name) {
                Some(value) => value.as_str(),
                None if name == "JAVA_TOOL_OPTIONS" => IMAGE_JAVA_TOOL_OPTIONS,
                None => continue,
            };
            for token in value.split_whitespace() {
                if let Some(size) = token.strip_prefix("-Xmx").or_else(|| token.strip_prefix("-XX:MaxHeapSize=")) {
                    if let Some(bytes) = jvm_memory_size(size) {
                        options.max_heap_bytes = Some(bytes);
                    }
                } else if let Some(size) = token.strip_prefix("-XX:MaxRAM=") {
                    if let Some(bytes) = jvm_memory_size(size).filter(|bytes| *bytes > 0) {
                        options.max_ram = Some(bytes);
                    }
                } else if let Some(percentage) = token.strip_prefix("-XX:MaxRAMPercentage=") {
                    if let Some(value) = jvm_percentage(percentage) {
                        options.max_ram_percentage = value;
                    }
                } else if let Some(percentage) = token.strip_prefix("-XX:MinRAMPercentage=") {
                    if let Some(value) = jvm_percentage(percentage) {
                        options.min_ram_percentage = value;
                    }
                } else if let Some(count) = token.strip_prefix("-XX:ActiveProcessorCount=") {
                    if let Some(count) = count.parse::<usize>().ok().filter(|count| *count > 0) {
                        options.active_processors = Some(count);
                    }
                } else if let Some(gc) = token.strip_prefix("-XX:+Use").and_then(|t| t.strip_suffix("GC")) {
                    options.collector = match gc {
                        "Z" => Collector::Z,
                        "G1" => Collector::G1,
                        "Serial" => Collector::Serial,
                        "Parallel" => Collector::Parallel,
                        "Shenandoah" => Collector::Shenandoah,
                        "Epsilon" => Collector::Epsilon,
                        _ => continue,
                    };
                }
            }
        }
        options
    }

    /// The collector HotSpot ends up with: a named one, else G1 on a server-class machine (2 processors and
    /// [`SERVER_CLASS_MEMORY`] of the physical memory, `MaxRAM` aside) and Serial on any other. An unknown
    /// memory is not held against the machine.
    fn resolved(&self, memory: Option<u64>, processors: usize) -> JvmHeapOptions {
        let server_class = processors >= 2 && memory.is_none_or(|memory| memory >= SERVER_CLASS_MEMORY);
        let collector = match self.collector {
            Collector::Ergonomic if server_class => Collector::G1,
            Collector::Ergonomic => Collector::Serial,
            named => named,
        };
        JvmHeapOptions { collector, ..*self }
    }

    /// HotSpot's `MaxHeapSize` when no heap flag sets it (`Arguments::set_heap_size`): the memory (`MaxRAM` when given, else
    /// the physical memory up to the default `MaxRAM`) times `MaxRAMPercentage`, or `MinRAMPercentage` of it when that
    /// is under the default `MaxHeapSize`, and never less than the default `MaxHeapSize` otherwise. `None` without a memory.
    fn ergonomic_ceiling(&self, memory: Option<u64>) -> Option<u64> {
        let memory = self.max_ram.or_else(|| memory.map(|memory| memory.min(DEFAULT_MAX_RAM)))?;
        let reasonable_max = (memory as f64 * self.max_ram_percentage / 100.0) as u64;
        let reasonable_min = (memory as f64 * self.min_ram_percentage / 100.0) as u64;
        Some(if reasonable_min < DEFAULT_MAX_HEAP_SIZE { reasonable_min } else { reasonable_max.max(DEFAULT_MAX_HEAP_SIZE) })
    }

    /// HotSpot's heap alignment for a `max_heap` ceiling: ZGC's granule; G1's region size when it is larger
    /// (`G1HeapRegion::setup_heap_region_size`: a 2048th of the ceiling within 1-32 MiB, rounded down to a power of two);
    /// Shenandoah's region, the same within 256 KiB-32 MiB and with no floor; Epsilon's page.
    fn alignment(&self, max_heap: u64) -> u64 {
        let region = |min: u64, max: u64| {
            let region = (max_heap / 2048).clamp(min, max);
            1u64 << (63 - region.leading_zeros())
        };
        match self.collector {
            Collector::G1 | Collector::Ergonomic => region(1 << 20, 32 << 20).max(HEAP_ALIGNMENT),
            Collector::Shenandoah => region(256 << 10, 32 << 20),
            Collector::Epsilon => 4096,
            Collector::Z | Collector::Serial | Collector::Parallel => HEAP_ALIGNMENT,
        }
    }

    /// `Runtime.maxMemory()` for a heap `ceiling` aligned as [`alignment`](Self::alignment) says, which is what upstream
    /// sizes the defaults from: Serial's leaves out one 64 KiB survivor space (measured on the oracle; the other collectors'
    /// is the whole ceiling), and Parallel's leaves out the maximum survivor space of its young generation
    /// (`ParallelScavengeHeap::max_capacity`: the reserved heap less `max_survivor_size(young max)`): the young generation
    /// is a third of the heap (`NewRatio=2`) aligned down to 64 KiB, its survivor space a third of that (`MinSurvivorRatio=3`)
    /// aligned down to 512 KiB (fitted to the oracle at six ceilings from 100352 KB to 20000768 KB).
    fn reported(&self, ceiling: u64) -> u64 {
        match self.collector {
            Collector::Serial => ceiling.saturating_sub(64 << 10),
            Collector::Parallel => {
                let young = ceiling / 3 / (64 << 10) * (64 << 10);
                ceiling.saturating_sub(young / 3 / (512 << 10) * (512 << 10))
            }
            _ => ceiling,
        }
    }
}

/// A JVM percentage flag's value (`-XX:MaxRAMPercentage=25`): a number within 0 to 100, else `None`, which the JVM refuses.
fn jvm_percentage(text: &str) -> Option<f64> {
    text.parse::<f64>().ok().filter(|value| (0.0..=100.0).contains(value))
}

/// A JVM memory size (`-Xmx512m`): digits with an optional `k`, `m`, `g` or `t` (either case), bytes without one;
/// `None` for what the JVM refuses.
fn jvm_memory_size(text: &str) -> Option<u64> {
    let (digits, shift) = match text.as_bytes().last()? {
        b'k' | b'K' => (&text[..text.len() - 1], 10),
        b'm' | b'M' => (&text[..text.len() - 1], 20),
        b'g' | b'G' => (&text[..text.len() - 1], 30),
        b't' | b'T' => (&text[..text.len() - 1], 40),
        _ => (text, 0),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(1 << shift)
}

/// `heapAvailableInKB()`: the heap ceiling less [`BASE_MEMORY_IN_KB`], in KB, as the configuration supplies it.
pub fn heap_available_kb(config: &Config) -> i64 {
    config.heap_available_kb.unwrap_or(ORACLE_HEAP_AVAILABLE_KB)
}

/// `NettyDirectMemoryLimit.MINIMUM_LIMIT_BYTES`.
const NETTY_DIRECT_MEMORY_MINIMUM: u64 = 64 << 20;

/// The bytes of Netty direct memory the oracle's JVM allows (`PlatformDependent.maxDirectMemory()`): the
/// JVM option `-Dio.netty.maxDirectMemory=<bytes>` of a variable the image reads, as given (a negative value: Netty's
/// own default, the heap), else `-XX:MaxDirectMemorySize=<size>`, else `NettyDirectMemoryLimit.defaultLimitBytes` of the
/// heap ceiling: a quarter of the heap, at least 64 MiB, never more than the heap. `None` when no heap is known (a
/// ceiling of 0, as upstream's undefined one).
pub fn netty_max_direct_memory(config: &Config) -> Option<u64> {
    let (mut netty, mut jvm) = (None, None);
    for name in JVM_OPTION_VARIABLES {
        for token in config.env.get(name).map(String::as_str).unwrap_or_default().split_whitespace() {
            if let Some(value) = token.strip_prefix("-Dio.netty.maxDirectMemory=") {
                netty = value.parse::<i64>().ok().or(netty);
            } else if let Some(size) = token.strip_prefix("-XX:MaxDirectMemorySize=") {
                jvm = jvm_memory_size(size).or(jvm);
            }
        }
    }
    let heap = match config.heap_available_kb {
        Some(0) => 0,
        _ => (heap_available_kb(config) + BASE_MEMORY_IN_KB) as u64 * 1024,
    };
    match (netty, jvm) {
        (Some(bytes), _) if bytes >= 0 => Some(bytes as u64),
        (Some(_), _) => (heap > 0).then_some(heap),
        (None, Some(bytes)) => Some(bytes),
        (None, None) => (heap > 0).then(|| heap.min(NETTY_DIRECT_MEMORY_MINIMUM.max(heap / 4))),
    }
}

/// The oracle image's `heapAvailableInKB` on this machine: `computeHeapAvailableInKB` over the ceiling the JVM options
/// set, else the one HotSpot derives from the container memory ([`heap_ceiling_with`]) or from `pinned`
/// ([`CONTAINER_MEMORY_ENV`]); 0 when neither is known, as upstream's undefined ceiling. `processors` is what the JVM
/// reports, which with the memory decides the collector a JVM that names none picks.
fn measured_heap_available_kb(pinned: Option<u64>, processors: usize, jvm: &JvmHeapOptions) -> i64 {
    let memory = pinned.or_else(container_memory_bytes);
    let jvm = jvm.resolved(memory, processors);
    match jvm.max_heap_bytes {
        Some(max) => heap_available_kb_of_ceiling(jvm.reported(max.div_ceil(jvm.alignment(max)) * jvm.alignment(max))),
        None => heap_available_kb_of(memory, &jvm),
    }
}

/// `computeHeapAvailableInKB` for a container with `memory` bytes (`None`: unknown, 0).
fn heap_available_kb_of(memory: Option<u64>, jvm: &JvmHeapOptions) -> i64 {
    heap_ceiling_with(memory, jvm).map_or(0, heap_available_kb_of_ceiling)
}

/// `computeHeapAvailableInKB` for a heap ceiling of `max` bytes.
fn heap_available_kb_of_ceiling(max: u64) -> i64 {
    if max > 0 { ((max / 1024) as i64 - BASE_MEMORY_IN_KB).max(0) } else { 0 }
}

/// HotSpot's `MaxHeapSize` for `memory` under the image's own options: what the tests pin the oracle's ceiling to.
#[cfg(test)]
fn heap_ceiling_bytes(memory: u64) -> u64 {
    heap_ceiling_with(Some(memory), &JvmHeapOptions::IMAGE).expect("a memory is given")
}

/// HotSpot's `MaxHeapSize` for `memory` ([`JvmHeapOptions::ergonomic_ceiling`]), aligned up to the heap alignment of the
/// collector `jvm` selects, as `Runtime.maxMemory()` reports it ([`JvmHeapOptions::reported`]); `None` when no memory is known and no `MaxRAM` given.
fn heap_ceiling_with(memory: Option<u64>, jvm: &JvmHeapOptions) -> Option<u64> {
    let ceiling = jvm.ergonomic_ceiling(memory)?;
    let alignment = jvm.alignment(ceiling);
    Some(jvm.reported(ceiling.div_ceil(alignment) * alignment))
}

/// `os::physical_memory()` as a containerised JVM sees it: the cgroup memory limit (v2 `memory.max`, v1
/// `memory.limit_in_bytes`) when it is below the machine's memory, else the machine's.
fn container_memory_bytes() -> Option<u64> {
    let physical = physical_memory_bytes();
    let limit = ["/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"]
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok()?.trim().parse::<u64>().ok());
    match (limit, physical) {
        (Some(limit), Some(physical)) => Some(limit.min(physical)),
        (limit, physical) => physical.or(limit),
    }
}

#[cfg(unix)]
fn physical_memory_bytes() -> Option<u64> {
    // SAFETY: sysconf only reads system constants.
    let (pages, page_size) = unsafe { (libc::sysconf(libc::_SC_PHYS_PAGES), libc::sysconf(libc::_SC_PAGESIZE)) };
    (pages > 0 && page_size > 0).then(|| pages as u64 * page_size as u64)
}

#[cfg(not(unix))]
fn physical_memory_bytes() -> Option<u64> {
    None
}

/// `heapBasedDefaultOrFloor`: `heap / per_entry_kb` capped at `cap`, `min(floor, cap)` when that is not positive.
fn heap_based_default_or_floor(heap_kb: i64, per_entry_kb: i64, cap: i64, floor: i64) -> i64 {
    let heap_based = (heap_kb / per_entry_kb).min(cap);
    if heap_based > 0 { heap_based } else { floor.min(cap) }
}

/// The default `maxPendingDelayedResponses` and `maxQueuedTemplateActions` (`defaultMaxPendingActions`):
/// `heapBasedDefaultOrFloor(heap, 64, 100000, 1000)`.
pub fn default_max_pending_actions(config: &Config) -> i64 {
    heap_based_default_or_floor(heap_available_kb(config), 64, 100_000, 1000)
}

/// The default `maxExpectations`: `heapBasedDefaultOrFloor(heap, 10, 15000, 1000)`.
pub fn default_max_expectations(config: &Config) -> i64 {
    heap_based_default_or_floor(heap_available_kb(config), 10, 15_000, 1000)
}

/// The default `maxLogEntries`: `heapBasedDefaultOrFloor(heap, 8, 250000, 1000)`.
pub fn default_max_log_entries(config: &Config) -> i64 {
    heap_based_default_or_floor(heap_available_kb(config), 8, DEFAULT_MAX_LOG_ENTRIES, 1000)
}

/// True at DEBUG and TRACE, the levels whose event-log defaults keep their own divisors (`isDebugOrTrace`).
fn debug_or_trace(config: &Config) -> bool {
    matches!(config.log_level().as_str(), "DEBUG" | "TRACE")
}

/// `heapFraction`: a `divisor`th of the heap budget, in whole KB; 0 when the ceiling is undefined.
fn heap_fraction(config: &Config, divisor: i64) -> i64 {
    let heap = heap_available_kb(config);
    if heap <= 0 { 0 } else { heap / divisor * 1024 }
}

/// `Configuration.maxEventLogInFlightBytes`: the larger of the retention budget `max_bytes` and a seventh of the heap (a
/// twelfth at DEBUG and TRACE); 0 when the budget is 0.
pub fn event_log_in_flight_bytes(config: &Config, max_bytes: u64) -> u64 {
    if max_bytes == 0 {
        return 0;
    }
    max_bytes.max(heap_fraction(config, if debug_or_trace(config) { 12 } else { 7 }) as u64)
}

/// `maxLogEntries`' default cap (`heapBasedDefaultOrFloor(heap, 8, 250000, …)`).
pub const DEFAULT_MAX_LOG_ENTRIES: i64 = 250_000;

/// `Configuration.maxLogEntries`: the explicit value, else 1000 under `devMode`, else the heap-based default.
pub fn max_log_entries(config: &Config) -> i64 {
    dev_mode_default(config, "maxLogEntries", 1000, default_max_log_entries(config))
}

/// `Configuration.maxExpectations`: the explicit value, else 1000 under `devMode`, else the heap-based default.
pub fn max_expectations(config: &Config) -> i64 {
    dev_mode_default(config, "maxExpectations", 1000, default_max_expectations(config))
}

/// `Configuration.maxHeaderSize`: the value set, at least 1, else 256 KiB (`DEFAULT_MAX_HEADER_SIZE`).
pub fn max_header_size(config: &Config) -> i64 {
    config.int_property("maxHeaderSize", 256 * 1024).max(1)
}

/// `Configuration.maxInitialLineLength`: the value set, at least 1, else 64 KiB (`DEFAULT_MAX_INITIAL_LINE_LENGTH`).
pub fn max_initial_line_length(config: &Config) -> i64 {
    config.int_property("maxInitialLineLength", 64 * 1024).max(1)
}

/// `Configuration.maxEventLogSizeInBytes`: the explicit value clamped to at least 0 (an unparsable one falls back to
/// the default), else `defaultMaxEventLogSizeInBytes`: a twentieth of the heap budget (9.1.0, upstream #200), a twelfth
/// at DEBUG and TRACE, in whole KB.
pub fn max_event_log_size_in_bytes(config: &Config) -> i64 {
    if let Some(explicit) = config.property("maxEventLogSizeInBytes").and_then(|v| v.trim().parse::<i64>().ok()) {
        return explicit.max(0);
    }
    heap_fraction(config, if debug_or_trace(config) { 12 } else { 20 })
}

/// `Configuration.maxOpenAiResponsesSizeInBytes`: the explicit value clamped to at least 0 (an unparsable one falls
/// back to the default), else `defaultMaxOpenAiResponsesSizeInBytes`, a twentieth of the heap budget in whole KB.
pub fn max_open_ai_responses_size_in_bytes(config: &Config) -> u64 {
    if let Some(explicit) = config.property("maxOpenAiResponsesSizeInBytes").and_then(|v| v.trim().parse::<i64>().ok()) {
        return explicit.max(0) as u64;
    }
    heap_fraction(config, 20) as u64
}

/// `Configuration.extensionListenerMaxBytes` (9.2.0): an explicit value of at least 1, else
/// `defaultExtensionListenerMaxBytes`, a twentieth of the heap budget in whole KB (16 MiB without one).
pub fn extension_listener_max_bytes(config: &Config) -> i64 {
    if let Some(explicit) = config.property("extensionListenerMaxBytes").and_then(|v| v.trim().parse::<i64>().ok()).filter(|v| *v >= 1) {
        return explicit;
    }
    match heap_fraction(config, 20) {
        0 => 16 * 1024 * 1024,
        fraction => fraction,
    }
}

/// `Configuration.nextPowerOfTwo`: the smallest power of two that is at least `value` (1 for anything below), capped at 2^30.
fn next_power_of_two(value: i64) -> i64 {
    (0..30).map(|i| 1i64 << i).find(|p| *p >= value).unwrap_or(1 << 30)
}

/// The value of an instance setting that `devMode` replaces until one is set: `dev` while the `devMode` property is on.
fn dev_mode_default(config: &Config, name: &str, dev: i64, normal: i64) -> i64 {
    if let Some(explicit) = config.property(name).and_then(|v| v.trim().parse::<i64>().ok()) {
        return explicit;
    }
    if config.bool_property("devMode", false) { dev } else { normal }
}

/// Source-tier labels of the effective-configuration diagnostic (`ConfigurationProperties.SOURCE_*`).
pub const SOURCE_SYSTEM_PROPERTY: &str = "system-property";
pub const SOURCE_PROPERTIES_FILE: &str = "properties-file";
pub const SOURCE_ENVIRONMENT_VARIABLE: &str = "environment-variable";
pub const SOURCE_DEFAULT: &str = "default";

/// One row of the effective configuration (`ConfigurationProperties.ResolvedProperty`): the `mockserver.*` key, the
/// value in effect (already redacted when sensitive, the built-in default when no tier supplies one) and the tier
/// that supplied it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProperty {
    pub name: &'static str,
    pub value: String,
    pub source: &'static str,
    /// For a property set away from its default: that built-in default, redacted like the value (`None` when unknown).
    pub default: Option<String>,
}

/// The mock-server properties ("The rule": outside upstream's names). They are honoured, so the startup
/// key check knows them, but they stay out of [`recognised_properties`], whose table the oracle's configuration dump
/// echoes.
pub const RS_PROPERTIES: [&str; 2] = ["callbackPlugins", "blobStoreModules"];

/// Every recognised property with its `MOCKSERVER_*` environment key, sorted by name: the `MOCKSERVER_*` constants of
/// upstream's `ConfigurationProperties` (the constant's value is the key, its name the environment variable).
pub(crate) fn recognised_properties() -> &'static [(&'static str, &'static str)] {
    static TABLE: std::sync::LazyLock<Vec<(&'static str, &'static str)>> = std::sync::LazyLock::new(|| {
        include_str!("effective_config_properties.txt").lines().filter_map(|line| line.split_once(' ')).collect()
    });
    &TABLE
}

/// `ConfigurationProperties.isNotBlank`.
fn not_blank(value: Option<&String>) -> Option<&String> {
    value.filter(|v| !v.trim().is_empty())
}

/// `resolveExplicitValue`: the first non-blank tier value, with one pair of surrounding quotes removed exactly as
/// `readPropertyHierarchically` does (`value.replaceAll("^\"|\"$", "")`, so a lone `"` becomes empty).
fn strip_quotes(value: &str) -> String {
    if value.starts_with('"') && value.ends_with('"') {
        let inner = value.get(1..value.len().saturating_sub(1)).unwrap_or("");
        return inner.to_string();
    }
    value.to_string()
}

/// The built-in default of every property as `GET /mockserver/config` shows it (`builtInDefaultValues`, read from each
/// property's getter on the oracle with nothing configured; credentials already masked), by `mockserver.*` key.
fn effective_config_defaults() -> &'static HashMap<&'static str, &'static str> {
    static TABLE: std::sync::LazyLock<HashMap<&'static str, &'static str>> = std::sync::LazyLock::new(|| {
        include_str!("effective_config_defaults.txt").lines().filter_map(|line| line.split_once('\t')).collect()
    });
    &TABLE
}

/// The getters that read only an explicit value and derive their default anew on each read (`explicitProperty`,
/// `explicitIntegerProperty`), so a blank system property or file entry leaves no raw value behind: the view shows the
/// derived default for them, where every other getter's cached raw value (the blank itself) is shown.
const UNCACHED_DEFAULT_PROPERTIES: [&str; 5] = ["maxExpectations", "maxLogEntries", "maxEventLogSizeInBytes", "maxExpectationsSizeInBytes", "ringBufferSize"];

impl Config {
    /// The effective configuration (`ConfigurationProperties.effectiveConfiguration`): one row per recognised property,
    /// sorted by name, resolved system property > properties file > environment variable, then the built-in default,
    /// with sensitive values redacted. A property at its default shows that default's value; any other also carries its
    /// built-in default. Reads the sources the server started with: `PUT /mockserver/configuration` writes a
    /// `Configuration` instance upstream and never the property store this reports (confirmed against the oracle).
    pub fn effective_configuration(&self) -> Vec<ResolvedProperty> {
        recognised_properties()
            .iter()
            .map(|&(name, env_key)| {
                let short = name.strip_prefix("mockserver.").unwrap_or(name);
                let embedded = self.embedder_set.read().get(short).cloned();
                let system = embedded.as_ref().or_else(|| self.system_properties.get(name));
                let tiers = [
                    (SOURCE_SYSTEM_PROPERTY, not_blank(system)),
                    (SOURCE_PROPERTIES_FILE, not_blank(self.file_properties.get(name))),
                    (SOURCE_ENVIRONMENT_VARIABLE, not_blank(self.env.get(env_key))),
                ];
                match tiers.into_iter().find_map(|(source, value)| value.map(|v| (source, v))) {
                    Some((source, raw)) => ResolvedProperty {
                        name,
                        value: credentials::redact_sensitive_value(name, &strip_quotes(raw)),
                        source,
                        default: self.overridden_default_value(name),
                    },
                    None => {
                        // a blank system property or file entry is what `readPropertyHierarchically` resolves and
                        // caches (the environment tier is skipped when blank), and the getter's raw value is shown
                        let blank = system.or_else(|| self.file_properties.get(name)).filter(|_| !UNCACHED_DEFAULT_PROPERTIES.contains(&short));
                        let value = match blank {
                            _ if credentials::is_sensitive_property_name(name) => credentials::REDACTED_VALUE.to_string(),
                            Some(raw) => strip_quotes(raw),
                            None => self.built_in_default(name).unwrap_or_else(|| "(default)".into()),
                        };
                        ResolvedProperty { name, value, source: SOURCE_DEFAULT, default: None }
                    }
                }
            })
            .collect()
    }

    /// `redactedOverriddenDefaultValue`: the built-in default beside an overridden property's value, `None` when the
    /// getter does not read it through the property store (`propertyFile`).
    fn overridden_default_value(&self, name: &str) -> Option<String> {
        if credentials::is_sensitive_property_name(name) {
            return Some(credentials::REDACTED_VALUE.to_string());
        }
        if name == "mockserver.propertyFile" {
            return None;
        }
        self.built_in_default(name).map(|value| credentials::redact_sensitive_value(name, &value))
    }

    /// The built-in default of one property: derived now for the heap-, `devMode`- and `maxLogEntries`-dependent sizes and
    /// the CPU-derived `actionHandlerThreadCount`, else the oracle's.
    fn built_in_default(&self, name: &str) -> Option<String> {
        let short = name.strip_prefix("mockserver.").unwrap_or(name);
        if short == "propertyFile" {
            // `propertyFile()` reads `System.getProperty` itself, so its typed result is shown (the image always sets it)
            return Some("mockserver.properties".into());
        }
        let dev_mode = || self.bool_property("devMode", false);
        let derived = match short {
            "maxExpectations" => Some(if dev_mode() { 1000 } else { default_max_expectations(self) }),
            "maxLogEntries" => Some(if dev_mode() { 1000 } else { default_max_log_entries(self) }),
            "maxEventLogSizeInBytes" => Some(heap_fraction(self, if debug_or_trace(self) { 12 } else { 20 })),
            "maxOpenAiResponsesSizeInBytes" => Some(heap_fraction(self, 20)),
            // `ringBufferSize()`: the raw size, `maxLogEntries` (explicit or derived) capped at 16384, before
            // `Configuration` rounds it to a power of two (`config_precedence`: `maxLogEntries` 1212 gives 1212)
            "ringBufferSize" => Some(max_log_entries(self).min(16384)),
            "actionHandlerThreadCount" => Some(default_action_handler_thread_count(self)),
            "maxPendingDelayedResponses" | "maxQueuedTemplateActions" => Some(default_max_pending_actions(self)),
            _ => None,
        };
        derived.map(|v| v.to_string()).or_else(|| effective_config_defaults().get(name).map(|v| (*v).to_string()))
    }

    /// `ConfigurationProperties.isExplicitlyConfigured`: a system property, file entry or environment variable that is
    /// not blank supplies the property, or it was set at runtime (an embedder's setter, `PUT /mockserver/configuration`).
    pub fn is_explicitly_configured(&self, name: &str) -> bool {
        let key = format!("mockserver.{name}");
        self.runtime_value(name).is_some()
            || not_blank(self.system_properties.get(&key)).is_some()
            || not_blank(self.file_properties.get(&key)).is_some()
            || not_blank(self.env.get(&env_name(name))).is_some()
    }

    /// `UpcomingDefaultChanges.warnings`: the start-up warnings for the defaults a future major release changes to
    /// secure values, each given only while its property is left at the default (setting it to any value removes it).
    pub fn upcoming_default_change_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if !self.is_explicitly_configured("forwardProxyBlockPrivateNetworks") && !self.hot_bool(crate::config::Hot::ForwardProxyBlockPrivateNetworks, false) {
            warnings.push("forwardProxyBlockPrivateNetworks is not set, so forward and proxy actions can reach loopback, private-network and cloud-metadata addresses; a future major release will change its default to true, which blocks them. Set mockserver.forwardProxyBlockPrivateNetworks (or MOCKSERVER_FORWARD_PROXY_BLOCK_PRIVATE_NETWORKS) to true to adopt the new default now, or to false to keep reaching those addresses; either value removes this warning".to_string());
        }
        if !self.is_explicitly_configured("localBoundIP") && self.property("localBoundIP").unwrap_or_default().trim().is_empty() {
            warnings.push("localBoundIP is not set, so MockServer listens on every network interface and can be reached from other machines; a future major release will change its default to 127.0.0.1, which only this machine can reach. Set mockserver.localBoundIP (or MOCKSERVER_LOCAL_BOUND_IP) to 127.0.0.1 to adopt the new default now, or to 0.0.0.0 to keep listening on every interface, as a container or a shared test environment needs; either value removes this warning".to_string());
        }
        if !self.is_explicitly_configured("attemptToProxyIfNoMatchingExpectation") && self.hot_bool(crate::config::Hot::AttemptToProxyIfNoMatchingExpectation, true) {
            warnings.push("attemptToProxyIfNoMatchingExpectation is not set, so a request that matches no expectation is forwarded to the host it names, which makes MockServer an open proxy for anyone who can reach it; a future major release will change its default to false, which returns 404 instead. Set mockserver.attemptToProxyIfNoMatchingExpectation (or MOCKSERVER_ATTEMPT_TO_PROXY_IF_NO_MATCHING_EXPECTATION) to false to adopt the new default now, or to true to keep proxying unmatched requests; either value removes this warning".to_string());
        }
        let limits: Vec<String> = [
            ("maxInitialLineLength", max_initial_line_length(self), 8192),
            ("maxHeaderSize", max_header_size(self), 16384),
            ("maxChunkSize", self.int_property("maxChunkSize", i64::from(i32::MAX)).max(1), 16384),
        ]
        .into_iter()
        .filter(|(name, value, next)| !self.is_explicitly_configured(name) && value > next)
        .map(|(name, value, next)| format!("mockserver.{name} ({value} bytes now, {next} later)"))
        .collect();
        if !limits.is_empty() {
            warnings.push(format!("the HTTP parsing limits {} are not set, and a future major release will lower their defaults to the values shown; a request whose first line or headers exceed the new limits will then be refused with 414 or 431. Set each property to its new value to adopt it now, or to its current value to keep it; a property that is set is left out of this warning", limits.join(", ")));
        }
        warnings
    }

    /// `findUnrecognisedConfigurationKeys` over the sources the server started with: system properties, environment
    /// variables and properties-file keys in MockServer's namespace that are not recognised.
    pub fn unrecognised_configuration(&self) -> Vec<crate::property_file::Unrecognised> {
        let system: Vec<&str> = self.system_properties.keys().map(String::as_str).collect();
        let environment: Vec<&str> = self.env.keys().map(String::as_str).collect();
        let file: Vec<&str> = self.file_properties.keys().map(String::as_str).collect();
        crate::property_file::unrecognised_properties(&system, &environment, &file, recognised_properties())
    }

    /// `effectiveConfigurationAsJson`: `[{"name":..,"value":..,"source":..[,"default":..]},..]`, hand-built compact JSON,
    /// then one `unrecognised` entry per unrecognised key. `non_default_only` (`?nonDefault=true`) leaves out the
    /// properties at their built-in default.
    pub fn effective_configuration_json(&self, non_default_only: bool) -> String {
        let mut rows: Vec<String> = self
            .effective_configuration()
            .iter()
            .filter(|p| !non_default_only || p.source != SOURCE_DEFAULT)
            .map(|p| {
                let default = p.default.as_ref().map(|d| format!(",\"default\":{}", json_string(d))).unwrap_or_default();
                format!("{{\"name\":{},\"value\":{},\"source\":{}{default}}}", json_string(p.name), json_string(&p.value), json_string(p.source))
            })
            .collect();
        for p in self.unrecognised_configuration() {
            let suggestions: Vec<String> = p.suggestions.iter().map(|s| json_string(s)).collect();
            let only = if p.system_property_only.is_some() { ",\"systemPropertyOnly\":true" } else { "" };
            rows.push(format!(
                "{{\"name\":{},\"value\":\"(ignored)\",\"source\":\"unrecognised\",\"setAs\":{},\"suggestions\":[{}]{only}}}",
                json_string(&p.name),
                json_string(p.set_as.text()),
                suggestions.join(",")
            ));
        }
        format!("[{}]", rows.join(","))
    }

    /// `effectiveConfigurationAsText`, what `--print-config` prints: one `name = value   [source]` line per property
    /// (ending `   (default: ..)` for one set away from its default), then the unrecognised keys with their hints.
    pub fn effective_configuration_text(&self) -> String {
        let mut out = String::from("MockServer effective configuration (value and the source that supplied it):\n");
        for p in self.effective_configuration() {
            out.push_str(&format!("  {} = {}   [{}]", p.name, p.value, p.source));
            if let Some(default) = &p.default {
                out.push_str(&format!("   (default: {default})"));
            }
            out.push('\n');
        }
        let unrecognised = self.unrecognised_configuration();
        if !unrecognised.is_empty() {
            out.push_str("Unrecognised configuration, ignored (names only):\n");
            for p in unrecognised {
                out.push_str(&format!("  {}   [{}]", p.name, p.set_as.text()));
                if let Some(hint) = p.hint() {
                    out.push_str(&format!("   {hint}"));
                }
                out.push('\n');
            }
        }
        out
    }

    /// A configuration for `--print-config`: the `-D` options, the properties file and the environment, with no port
    /// or other launch requirement (upstream handles the flag before parsing anything).
    pub fn for_print_config(args: &[String], env: HashMap<String, String>) -> Config {
        let mut config = Config { env, ..Config::default() };
        for arg in args {
            if let Some((k, v)) = arg.strip_prefix("-D").and_then(|rest| rest.split_once('=')) {
                config.system_properties.insert(k.to_string(), v.to_string());
            }
        }
        config.load_property_file();
        config.sources_changed();
        config
    }

    /// The properties file named by `mockserver.propertyFile` / `MOCKSERVER_PROPERTY_FILE` (default
    /// `mockserver.properties`), when it can be read. Also collects what upstream logs with `alwaysLog` while the
    /// configuration loads (`crate::property_file`): an unreadable file the operator named, a JSON file that does not
    /// parse, the dump of the entries and the unrecognised keys.
    fn load_property_file(&mut self) {
        let docker_default = "/config/mockserver.properties";
        let from_property = self.system_properties.get("mockserver.propertyFile").cloned();
        let from_env = self.env.get("MOCKSERVER_PROPERTY_FILE").cloned();
        let property_file = from_property
            .clone()
            .filter(|p| p != docker_default || from_env.is_none())
            .or_else(|| from_env.clone())
            .unwrap_or_else(|| "mockserver.properties".into());
        // `propertyFileExplicitlyConfigured`: the environment variable, or a system property that is not the image's default
        let explicit = from_env.as_deref().is_some_and(|v| !v.trim().is_empty()) || from_property.as_deref().is_some_and(|p| !p.trim().is_empty() && p != docker_default);
        let loaded = crate::property_file::load(&property_file, explicit);
        self.file_is_json = property_file.ends_with(".json");
        self.file_properties = loaded.entries.iter().cloned().collect();
        self.startup_notices = loaded.notices;
        self.sources_changed();
        // the level the property cache holds when the dump and the key check run
        let level = level_number(&self.property_cache_log_level());
        if !loaded.entries.is_empty() && level.is_some_and(|l| l <= 20) {
            self.startup_notices.push(crate::property_file::StartupNotice {
                level: crate::recorded::Level::Info,
                message: crate::property_file::dump_message(&property_file, &loaded.entries),
                throwable: None,
            });
        }
        if level.is_some_and(|l| l <= 30) {
            let system: Vec<&str> = self.system_properties.keys().map(String::as_str).collect();
            let environment: Vec<&str> = self.env.keys().map(String::as_str).collect();
            let file: Vec<&str> = loaded.entries.iter().map(|(k, _)| k.as_str()).collect();
            for key in crate::property_file::unrecognised_properties(&system, &environment, &file, recognised_properties()) {
                self.startup_notices.push(crate::property_file::StartupNotice {
                    level: crate::recorded::Level::Warn,
                    message: key.warning(),
                    throwable: None,
                });
            }
        }
    }

    /// `logLevel` as `ConfigurationProperties`' property cache holds it once the file has been read: system property,
    /// then (for a `.json` file only) the file, then `MOCKSERVER_LOG_LEVEL`, then `INFO`.
    fn property_cache_log_level(&self) -> String {
        let not_blank = |v: Option<&String>| v.filter(|v| !v.trim().is_empty()).cloned();
        let file = if self.file_is_json { not_blank(self.file_properties.get("mockserver.logLevel")) } else { None };
        let level = not_blank(self.system_properties.get("mockserver.logLevel"))
            .or(file)
            .or_else(|| not_blank(self.env.get("MOCKSERVER_LOG_LEVEL")))
            .map_or_else(|| "INFO".to_string(), |v| unquote(&v).to_string())
            .to_ascii_uppercase();
        normalize_log_level(&level)
    }

    /// What `ConfigurationProperties.<clinit>` logged with `alwaysLog` while the configuration loaded.
    pub fn startup_notices(&self) -> &[crate::property_file::StartupNotice] {
        &self.startup_notices
    }

    /// The startup sources [`jvm_policy::findings`] reads (system properties, properties file, environment).
    pub fn jvm_policy_sources(&self) -> jvm_policy::Sources<'_> {
        jvm_policy::Sources { system_properties: &self.system_properties, file: &self.file_properties, env: &self.env }
    }
}

/// `org.slf4j.event.Level.toInt` of a level name; `None` for `OFF` (no level is enabled).
fn level_number(name: &str) -> Option<i32> {
    Some(match name {
        "TRACE" => 0,
        "DEBUG" => 10,
        "WARN" => 30,
        "ERROR" => 40,
        "OFF" => return None,
        _ => 20,
    })
}

/// `ConfigurationProperties.jsonEscape` around a string: `"`, `\`, `\n`, `\r`, `\t` escaped, other control characters
/// as `\u00xx`, everything else (including non-ASCII) verbatim.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `value` read as the type of `default` (`None` when it cannot be).
pub fn typed(value: &str, default: &serde_json::Value) -> Option<serde_json::Value> {
    use serde_json::Value;
    Some(match default {
        Value::Bool(_) => Value::Bool(value.trim().eq_ignore_ascii_case("true")),
        // a `Double` property as Jackson writes it (`Double.toString`): 5 is written 5.0, 0.0002 2.0E-4
        Value::Number(n) if n.is_f64() => crate::model::number(&java_compat::double_to_string(value.trim().parse::<f64>().ok()?)),
        // an `Integer`/`Long` property: `Integer.parseInt` refuses a fraction ("1.5"), the default stands
        Value::Number(_) => Value::from(value.trim().parse::<i64>().ok()?),
        Value::Array(_) => Value::Array(value.split(',').map(str::trim).filter(|v| !v.is_empty()).map(|v| Value::String(v.to_string())).collect()),
        Value::Object(_) => serde_json::from_str(value).ok()?,
        _ => Value::String(value.to_string()),
    })
}

/// `(…InMillis property, its primary, the default)`: `ConfigurationProperties.readLongPropertyWithMillisAlias`, for the
/// three timeouts whose older name still comes first.
const MILLIS_ALIASES: &[(&str, &str, i64)] = &[
    ("maxFutureTimeoutInMillis", "maxFutureTimeout", 90_000),
    ("maxSocketTimeoutInMillis", "maxSocketTimeout", 20_000),
    ("socketConnectionTimeoutInMillis", "socketConnectionTimeout", 20_000),
];

/// The numeric properties `ConfigurationProperties` reads with a floor (`Math.max(floor, read…Property(…))`), whatever
/// tier supplied the value (`config_clamped_values_low`).
const STARTUP_FLOORS: &[(&str, i64)] = &[
    ("maxRequestBodySize", 1),
    ("maxResponseBodySize", 1),
    ("maxHeaderSize", 1),
    ("maxInitialLineLength", 1),
    ("watchInitializationJsonPollPeriodMillis", 1),
    ("forwardConnectionPoolMaxIdlePerKey", 1),
    ("forwardConnectionPoolMaxTotalPerKey", 1),
    ("forwardSocketKeepAliveIdleSeconds", 1),
    ("forwardSocketKeepAliveIntervalSeconds", 1),
    ("forwardSocketKeepAliveCount", 1),
    ("forwardProxyCircuitBreakerFailureThreshold", 1),
    ("forwardProxyCircuitBreakerWindowMillis", 1),
    ("llmEmbeddingMaxResponseValues", 1),
    ("llmEmbeddingMaxInputCharacters", 1),
    ("otelMetricsExportIntervalSeconds", 1),
    ("prometheusRemoteWriteIntervalSeconds", 1),
    ("inboundConnectionIdleTimeoutMillis", 0),
    ("maxInboundConnections", 0),
    ("responseWriteStallTimeoutMillis", 0),
    ("preemptionSimulationMaxDrainMillis", 0),
    ("stopDrainMillis", 0),
    ("http3MaxIdleTimeout", 0),
    ("http3InitialMaxData", 0),
    ("http3InitialMaxStreamDataBidirectional", 0),
    ("http3InitialMaxStreamsBidirectional", 0),
    ("http3QpackMaxTableCapacity", 0),
    ("http3AltSvcMaxAge", 0),
    ("maxLoggedBodyBytes", 0),
    ("forwardConnectionPoolIdleTimeoutMillis", 0),
    ("forwardProxyRetryCount", 0),
    ("forwardLoopMaxHops", 0),
    ("forwardProxyRetryBackoffMillis", 0),
    ("maxStreamingCaptureBytes", 0),
    ("streamIdleTimeoutSeconds", 0),
    ("forwardBinaryServerFirstWaitMillis", 0),
    // the extension SPI's limits (9.2.0): `Math.max(1, …)`
    ("extensionStartTimeoutMillis", 1),
    ("extensionAdminMaxInFlight", 1),
    ("extensionAdminTimeoutMillis", 1),
    ("extensionListenerQueueSize", 1),
    ("extensionHelperTimeoutMillis", 1),
    ("extensionHelperMaxInFlight", 1),
    ("extensionDataPlaneMaxInFlight", 1),
    ("extensionDataPlaneTimeoutMillis", 1),
];

/// A startup value (system property, properties file or environment) as `ConfigurationProperties`' getter reads it:
/// the floors above, the ranges and fallbacks of the properties its getter validates. A value that does not parse is
/// left alone (its default stands, see [`typed`]). Runtime values (`PUT /mockserver/configuration`) are read by
/// [`coerce_update`] instead, which refuses or keeps several of these.
fn startup_read(name: &str, value: String) -> String {
    let int = || value.trim().parse::<i64>().ok();
    if let Some(&(_, floor)) = STARTUP_FLOORS.iter().find(|(n, _)| *n == name) {
        return int().map_or(value.clone(), |v| v.max(floor).to_string());
    }
    match name {
        // `maxLlmConversationBodySize`: clamped to 16 KiB..64 MiB (logged)
        "maxLlmConversationBodySize" => int().map_or(value.clone(), |v| v.clamp(16_384, 67_108_864).to_string()),
        // `driftSampleRate`: clamped to 0.0..1.0 (logged)
        "driftSampleRate" => value.trim().parse::<f64>().ok().map_or(value.clone(), |v| v.clamp(0.0, 1.0).to_string()),
        // a non-positive validity is the default, 397 days
        "sslCertificateLeafValidityInDays" => int().map_or(value.clone(), |v| if v <= 0 { "397".into() } else { v.to_string() }),
        // anything but 1, 2, 4 or 8 bytes is read as 4 (reported once)
        "binaryMessageLengthPrefixBytes" => int().filter(|v| [1, 2, 4, 8].contains(v)).unwrap_or(4).to_string(),
        "binaryMessageLengthPrefixOffset" => int().filter(|v| *v >= 0).unwrap_or(0).to_string(),
        "binaryMessageLengthPrefixByteOrder" => {
            let order = value.trim().to_uppercase();
            if order == "LITTLE_ENDIAN" { order } else { "BIG_ENDIAN".into() }
        }
        _ => value,
    }
}

/// `ConfigurationDTO` fields held as a Java `Integer` (the rest of the numeric ones are `Long`, or `Double` where the
/// default has a fraction): Jackson refuses a value outside 32 bits for these.
const INTEGER_PROPERTIES: &[&str] = &[
    "breakpointMaxHeld", "maxExpectations", "maxLogEntries", "maxLoggedBodyBytes", "ringBufferSize", "maxWebSocketExpectations",
    "webSocketProxyMaxRecordedFrames", "webSocketProxyIdleTimeoutSeconds", "nioEventLoopThreadCount", "actionHandlerThreadCount",
    "clientNioEventLoopThreadCount", "webSocketClientEventLoopThreadCount", "maxInitialLineLength", "maxHeaderSize", "maxChunkSize",
    "corsMaxAgeInSeconds", "maximumNumberOfRequestToReturnInVerificationFailure", "proxyRemotePort", "maxSubjectAlternativeNames",
    "sslCertificateLeafValidityInDays", "rateLimitMaxNamedQuotas", "sloWindowMaxSamples", "loadGenerationMaxVirtualUsers",
    "loadGenerationMaxInFlightRequests", "loadGenerationMaxRequestsPerSecond", "loadGenerationMaxSteps", "loadGenerationMaxStages",
    "loadGenerationMaxConcurrentScenarios", "wasmMaxMemoryPages", "dnsPort", "http3Port", "forwardConnectionPoolMaxIdlePerKey",
    "forwardConnectionPoolMaxTotalPerKey", "forwardSocketKeepAliveIdleSeconds", "forwardSocketKeepAliveIntervalSeconds",
    "forwardSocketKeepAliveCount", "forwardProxyRetryCount", "forwardProxyCircuitBreakerFailureThreshold", "maxRequestBodySize",
    "maxGrpcMessageSize", "maxResponseBodySize", "maxLlmConversationBodySize", "controlPlaneAuditMaxEntries", "maxStreamingCaptureBytes",
    "streamIdleTimeoutSeconds", "blobStoreRestoreTimeoutSeconds", "asyncRecordedMessageMaxEntries", "llmOptimisationMaxCalls",
    "soBacklog", "maxInboundConnections", "maxPendingDelayedResponses", "maxQueuedTemplateActions", "binaryMessageLengthPrefixBytes",
    "binaryMessageLengthPrefixOffset", "llmEmbeddingMaxResponseValues", "llmEmbeddingMaxInputCharacters",
    "forwardLoopMaxHops", "maxLoggedMatchFailures", "extensionAdminMaxInFlight", "extensionListenerQueueSize",
    "extensionHelperMaxInFlight", "extensionDataPlaneMaxInFlight",
];

/// The numeric properties whose `Configuration` getter (or setter) clamps to a floor: HTTP/3 limits, the drain and
/// stream timeouts at zero, the two export intervals at one second, the body size limits at one byte, the inbound
/// connection limits and the write-stall timeout at zero.
const NUMERIC_FLOORS: &[(&str, i128)] = &[
    ("http3MaxIdleTimeout", 0),
    ("http3InitialMaxData", 0),
    ("http3InitialMaxStreamDataBidirectional", 0),
    ("http3InitialMaxStreamsBidirectional", 0),
    ("http3QpackMaxTableCapacity", 0),
    ("http3AltSvcMaxAge", 0),
    ("stopDrainMillis", 0),
    ("streamIdleTimeoutSeconds", 0),
    ("otelMetricsExportIntervalSeconds", 1),
    ("prometheusRemoteWriteIntervalSeconds", 1),
    // Read back by the upstream configuration tests (BodySizeLimit, InboundConnection, ResponseWriteStall).
    ("maxRequestBodySize", 1),
    ("maxResponseBodySize", 1),
    ("inboundConnectionIdleTimeoutMillis", 0),
    ("maxInboundConnections", 0),
    ("responseWriteStallTimeoutMillis", 0),
    ("forwardBinaryServerFirstWaitMillis", 0),
];

/// One `PUT /mockserver/configuration` value read as Jackson reads it into the property's `ConfigurationDTO` field,
/// `default` being the property's current JSON value (which fixes the field's type). `Ok(Some(text))` is the value to
/// keep (the form the runtime store holds), `Ok(None)` a value Jackson leaves as null (a JSON null, or a blank
/// string for anything but a text field), `Err` one it cannot convert, which fails the whole update.
pub fn coerce_update(name: &str, value: &serde_json::Value, default: &serde_json::Value) -> Result<Option<String>, ()> {
    use serde_json::Value;
    if value.is_null() {
        return Ok(None);
    }
    let blank = matches!(value, Value::String(s) if s.trim().is_empty());
    if name == "connectionDelay" || name == "proxyPassMappings" {
        // objects Jackson fills from a nested class: held as the JSON they print (`config_objects`)
        let read = if name == "connectionDelay" { crate::config_objects::connection_delay(value) } else { crate::config_objects::proxy_pass_mappings(value) };
        return read.map(|held| held.map(|v| v.to_string()));
    }
    if name == "controlPlaneScopeMapping" {
        // `Map<String, ControlPlaneRole>`: a role is a name or an ordinal (0 READ, 1 MUTATE, 2 ADMIN, another whole
        // number none); a JSON null is none; a fraction, boolean, array or object fails the update
        return match value {
            _ if blank => Ok(None),
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (scope, role) in map {
                    let text = match role {
                        Value::Null => continue,
                        Value::String(s) => s.clone(),
                        Value::Number(n) if n.is_i64() || n.is_u64() => {
                            n.as_u64().and_then(|i| ["READ", "MUTATE", "ADMIN"].get(i as usize)).map(|r| r.to_string()).unwrap_or_default()
                        }
                        _ => return Err(()),
                    };
                    out.insert(scope.clone(), Value::String(text));
                }
                Ok(Some(Value::Object(out).to_string()))
            }
            _ => Err(()),
        };
    }
    match default {
        Value::Bool(_) => match value {
            Value::Bool(b) => Ok(Some(b.to_string())),
            _ if blank => Ok(None),
            Value::String(s) => match s.trim() {
                "true" | "True" | "TRUE" => Ok(Some("true".into())),
                "false" | "False" | "FALSE" => Ok(Some("false".into())),
                _ => Err(()),
            },
            // a whole number is a boolean (zero is false); a fraction is not
            Value::Number(n) if n.is_i64() || n.is_u64() => Ok(Some((n.as_i64() != Some(0) && n.as_u64() != Some(0)).to_string())),
            _ => Err(()),
        },
        Value::Number(d) if d.is_f64() => match value {
            _ if blank => Ok(None),
            Value::Number(n) => n.as_f64().map(|f| Some(f.to_string())).ok_or(()),
            Value::String(s) => s.trim().parse::<f64>().map(|f| Some(f.to_string())).map_err(|_| ()),
            _ => Err(()),
        },
        Value::Number(_) => {
            let (low, high) = if INTEGER_PROPERTIES.contains(&name) { (i32::MIN as i128, i32::MAX as i128) } else { (i64::MIN as i128, i64::MAX as i128) };
            let whole: i128 = match value {
                _ if blank => return Ok(None),
                Value::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
                    (Some(i), _, _) => i as i128,
                    (None, Some(u), _) => u as i128,
                    // a fraction is cut off
                    (_, _, Some(f)) if f.is_finite() && f.abs() < 1e30 => f.trunc() as i128,
                    _ => return Err(()),
                },
                Value::String(s) => s.trim().parse::<i128>().map_err(|_| ())?,
                _ => return Err(()),
            };
            if whole < low || whole > high {
                return Err(());
            }
            let whole = NUMERIC_FLOORS.iter().find(|(n, _)| *n == name).map_or(whole, |(_, floor)| whole.max(*floor));
            Ok(Some(whole.to_string()))
        }
        Value::Array(_) => {
            let is_set = SET_PROPERTIES.contains(&name);
            let scalar = |v: &Value| -> Result<String, ()> {
                match v {
                    Value::String(s) => Ok(s.clone()),
                    Value::Number(n) => Ok(n.to_string()),
                    Value::Bool(b) => Ok(b.to_string()),
                    _ => Err(()),
                }
            };
            // Held as a JSON array: an element is a whole value, whatever commas it holds, and a null element stays one
            // (a set refuses it only when it is applied, see [`NULL_REFUSING_SETS`]).
            let held = |items: Vec<Value>| Ok(Some(Value::Array(items).to_string()));
            match value {
                _ if blank => Ok(None),
                Value::Array(items) => {
                    let mut kept: Vec<Value> = Vec::new();
                    for item in items {
                        let element = if item.is_null() { Value::Null } else { Value::String(scalar(item)?) };
                        if !is_set || !kept.contains(&element) {
                            kept.push(element);
                        }
                    }
                    held(kept)
                }
                other => held(vec![Value::String(scalar(other)?)]),
            }
        }
        Value::Object(_) => match value {
            _ if blank => Ok(None),
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (k, v) in map {
                    let text = match v {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        _ => return Err(()),
                    };
                    out.insert(k.clone(), Value::String(text));
                }
                Ok(Some(Value::Object(out).to_string()))
            }
            _ => Err(()),
        },
        _ => match value {
            Value::String(s) => Ok(Some(s.clone())),
            Value::Number(n) => Ok(Some(n.to_string())),
            Value::Bool(b) => Ok(Some(b.to_string())),
            _ => Err(()),
        },
    }
}

/// The type an optional property (null until set, so missing from the defaults) is read as: a stand-in default for
/// [`coerce_update`].
pub fn optional_default(name: &str) -> Option<serde_json::Value> {
    use serde_json::Value;
    // `forwardProxyPrivateKey` is never written back by `GET` but its path is still checked
    if FILE_MUST_EXIST_PROPERTIES.contains(&name) {
        return Some(Value::String(String::new()));
    }
    OPTIONAL_PROPERTIES.iter().find(|(n, _)| *n == name).map(|(_, kind)| match kind {
        OptionalKind::Text => Value::String(String::new()),
        OptionalKind::Long | OptionalKind::Int => Value::from(0),
        OptionalKind::StringMap | OptionalKind::ScopeMapping | OptionalKind::Object | OptionalKind::ProxyPass => Value::Object(serde_json::Map::new()),
    })
}

/// The first stored mapping the configuration cannot be written for: its position in the list, its `targetUri` and the
/// `URISyntaxException` message `URI.create` throws for it.
pub fn proxy_pass_failure(config: &Config) -> Option<(usize, String, String)> {
    let stored = config
        .property("proxyPassMappings")
        .or_else(|| config.property("proxyPass").map(|text| crate::config_objects::proxy_pass_property(&text).to_string()))
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())?;
    crate::config_objects::first_print_failure(&stored)
}

/// `ConfigurationDTO.applyTo`'s order of application: where a property comes in the update (unknown ones last).
pub fn dto_apply_position(name: &str) -> usize {
    static ORDER: std::sync::LazyLock<HashMap<&'static str, usize>> =
        std::sync::LazyLock::new(|| include_str!("configuration_dto_order.txt").lines().enumerate().map(|(i, n)| (n, i)).collect());
    ORDER.get(name).copied().unwrap_or(usize::MAX)
}

/// The properties whose instance setter runs `ConfigurationProperties.fileExists`, refusing a path that names nothing.
pub const FILE_MUST_EXIST_PROPERTIES: &[&str] = &[
    "controlPlaneTLSMutualAuthenticationCAChain",
    "controlPlanePrivateKeyPath",
    "controlPlaneX509CertificatePath",
    "tlsMutualAuthenticationCertificateChain",
    "forwardProxyTLSCustomTrustX509Certificates",
    "forwardProxyPrivateKey",
    "forwardProxyCertificateChain",
];

/// `ConfigurationProperties.fileExists`: a blank path passes, as does one that names something in the file system
/// or MockServer's bundled certificate authority (the only class path resources a certificate setting names here).
pub fn file_exists_or_blank(path: &str) -> bool {
    path.trim().is_empty()
        || std::path::Path::new(path).exists()
        || matches!(path, "org/mockserver/socket/CertificateAuthorityCertificate.pem" | "org/mockserver/socket/CertificateAuthorityPrivateKey.pem")
}

/// Credential masking for `GET`/`PUT /mockserver/configuration`, ported from the real production source (not
/// invented against the test file): `ConfigurationProperties.isSensitivePropertyName`/`redactSensitiveValue`/
/// `restoreRedactedValue`/`containsRedactionMask` and `EmbeddedCredentialRedaction` in
/// `upstream/mockserver/mockserver/mockserver-core/src/main/java/org/mockserver/configuration/`, pinned at
/// mockserver-8.0.0, the release it was verified against. Wired to every property `ConfigurationDTO.applyTo` routes
/// through `restoreRedactedValue`.
pub mod credentials {
    use std::sync::LazyLock;

    /// `ConfigurationProperties.REDACTED_VALUE`.
    pub const REDACTED_VALUE: &str = "***REDACTED***";

    /// `ConfigurationProperties.SENSITIVE_SUBSTRINGS`: matched as substrings of the lower-cased,
    /// `mockserver.`-stripped property name.
    const SENSITIVE_SUBSTRINGS: &[&str] = &[
        "password",
        "passwd",
        "pwd",
        "secret",
        "accesskey",
        "access_key",
        "apikey",
        "api_key",
        "connectionstring",
        "connection_string",
        "token",
        "bearer",
        "privatekey",
        "private_key",
        "credential",
        "passphrase",
        "signature",
        "hmac",
        "salt",
        "session",
        "otp",
        // a Kafka JAAS configuration carries the SASL username and password inline (9.2.0)
        "jaas",
    ];

    /// `ConfigurationProperties.NON_SENSITIVE_KEY_SUFFIXED_NAMES`: property names ending in `key` that are NOT
    /// credentials (connection-pool sizing limits keyed by route), so the `endsWith("key")` rule must not
    /// redact them. Keyed on the normalised (lower-cased, `mockserver.`-stripped) name.
    const NON_SENSITIVE_KEY_SUFFIXED_NAMES: &[&str] = &["forwardconnectionpoolmaxidleperkey", "forwardconnectionpoolmaxtotalperkey"];

    /// `EmbeddedCredentialRedaction.HEADER_ONLY_SENSITIVE_SUBSTRINGS`: credential-bearing in HEADER/JSON-field
    /// vocabulary but not in property-name vocabulary (e.g. `tlsMutualAuthenticationRequired` is an ordinary
    /// boolean property, but an `Authorization` header is a credential).
    const HEADER_ONLY_SENSITIVE_SUBSTRINGS: &[&str] = &["auth", "cookie", "jwt"];

    /// `ConfigurationProperties.WHOLE_VALUE_MASKED_CREDENTIAL_PROPERTIES`, normalised. The properties `GET
    /// /mockserver/configuration` returns as the bare mask — and only those get the silent unedited-round-trip
    /// short circuit in [`restore_redacted_value`].
    const WHOLE_VALUE_MASKED_CREDENTIAL_PROPERTIES: &[&str] = &["llmapikey", "prometheusremotewritebearertoken", "prometheusremotewritebasicauthpassword"];

    /// `ConfigurationProperties.HEADER_LIST_CREDENTIAL_PROPERTIES`, normalised.
    const HEADER_LIST_CREDENTIAL_PROPERTIES: &[&str] = &["prometheusremotewriteheaders"];

    /// `ConfigurationProperties.JSON_DOCUMENT_CREDENTIAL_PROPERTIES`, normalised.
    const JSON_DOCUMENT_CREDENTIAL_PROPERTIES: &[&str] = &["llmbackendsconfig"];

    /// The camelCase property names this port wires the masking machinery to: masked on read (the whole value, or
    /// the credential fields embedded in it), omitted on read, or readable despite a credential-shaped name.
    pub const WHOLE_VALUE_MASKED_PROPERTIES: &[&str] = &["llmApiKey", "prometheusRemoteWriteBearerToken", "prometheusRemoteWriteBasicAuthPassword"];
    pub const EMBEDDED_MASKED_PROPERTIES: &[&str] = &["llmBackendsConfig", "prometheusRemoteWriteHeaders"];
    /// Write-only: never disclosed by `GET /mockserver/configuration` whether set or not (`@JsonIgnore`-d
    /// getter, `@JsonProperty` setter upstream), but settable via `PUT` and readable in-process. Every one is in
    /// `ConfigurationDTO.applyTo`'s `restoreRedactedValue` set, so a value carrying the mask leaves it as it was —
    /// for `forwardProxyPrivateKey` before its file check, which would otherwise refuse the whole update.
    pub const OMITTED_CREDENTIAL_PROPERTIES: &[&str] = &[
        "clusterFanInPeerAuthToken",
        "dataPlaneBearerAuthenticationToken",
        "forwardProxyAuthenticationPassword",
        "proxyAuthenticationPassword",
        "dataPlaneBasicAuthenticationPassword",
        "dataPlaneApiKeyAuthenticationValue",
        "certificateAuthorityPrivateKey",
        "forwardProxyPrivateKey",
        "blobStoreAccessKeyId",
        "blobStoreSecretAccessKey",
        "blobStoreConnectionString",
        "controlPlaneBasicAuthenticationCredentials",
        "asyncKafkaSaslJaasConfig",
    ];
    /// `READABLE_DESPITE_CREDENTIAL_SHAPED_NAME`: disclosed in clear despite a credential-shaped name (a file
    /// path, a header *name* rather than its value, an ingest-only analytics key), but still guarded on write
    /// via [`restore_redacted_value`] — a bare mask pasted from a diagnostic surface must not overwrite them.
    pub const READABLE_DESPITE_CREDENTIAL_SHAPED_NAME: &[&str] = &["dashboardAnalyticsKey", "dataPlaneApiKeyAuthenticationHeader", "privateKeyPath", "controlPlanePrivateKeyPath"];

    /// Every property name `PUT /mockserver/configuration` must route through [`restore_redacted_value`]
    /// instead of the generic typed-coercion path.
    pub fn is_credential_dispatch_property(name: &str) -> bool {
        WHOLE_VALUE_MASKED_PROPERTIES.contains(&name) || EMBEDDED_MASKED_PROPERTIES.contains(&name) || OMITTED_CREDENTIAL_PROPERTIES.contains(&name) || READABLE_DESPITE_CREDENTIAL_SHAPED_NAME.contains(&name)
    }

    /// `ConfigurationProperties.normalisePropertyName`: lower-cased, `mockserver.`-prefix stripped.
    fn normalise_property_name(name: &str) -> String {
        let lower = name.to_ascii_lowercase();
        lower.strip_prefix("mockserver.").unwrap_or(&lower).to_string()
    }

    /// `ConfigurationProperties.isSensitivePropertyName`.
    pub fn is_sensitive_property_name(name: &str) -> bool {
        let lower = normalise_property_name(name);
        if SENSITIVE_SUBSTRINGS.iter().any(|s| lower.contains(s)) {
            return true;
        }
        lower.ends_with("key") && !NON_SENSITIVE_KEY_SUFFIXED_NAMES.contains(&lower.as_str())
    }

    /// `EmbeddedCredentialRedaction.isSensitiveName`: a header name or JSON field name that indicates its
    /// value is a credential. `-`/`_` are stripped before delegating to [`is_sensitive_property_name`], so
    /// `Api-Key` and `api_key` both reach the `apikey` rule.
    fn is_sensitive_name(name: &str) -> bool {
        if name.is_empty() {
            return false;
        }
        let normalised = name.to_ascii_lowercase().replace(['-', '_'], "");
        if HEADER_ONLY_SENSITIVE_SUBSTRINGS.iter().any(|s| normalised.contains(s)) {
            return true;
        }
        is_sensitive_property_name(&normalised)
    }

    /// `ConfigurationProperties.isWholeValueMaskedOnRead`.
    fn is_whole_value_masked_on_read(property_name: &str) -> bool {
        WHOLE_VALUE_MASKED_CREDENTIAL_PROPERTIES.contains(&normalise_property_name(property_name).as_str())
    }

    /// `ConfigurationProperties.containsRedactionMask`.
    pub fn contains_redaction_mask(value: &str) -> bool {
        value.contains(REDACTED_VALUE)
    }

    /// `ConfigurationProperties.redactSensitiveValue`, for the embedded-shape properties (the whole-value ones
    /// are masked by [`super::effective_json`] directly, since their masked/absent form also depends on
    /// whether they are SET, which this function — mirroring the Java one, which is also used by
    /// `--print-config` where an "unset" value renders as the literal string `"(default)"` rather than absence
    /// — does not decide).
    pub fn redact_sensitive_value(property_name: &str, value: &str) -> String {
        if is_sensitive_property_name(property_name) {
            return REDACTED_VALUE.to_string();
        }
        if value.is_empty() {
            return value.to_string();
        }
        let normalised = normalise_property_name(property_name);
        if HEADER_LIST_CREDENTIAL_PROPERTIES.contains(&normalised.as_str()) {
            return redact_header_list(value);
        }
        if JSON_DOCUMENT_CREDENTIAL_PROPERTIES.contains(&normalised.as_str()) {
            return redact_json_document(value);
        }
        value.to_string()
    }

    /// `ConfigurationProperties.restoreRedactedValue`: the value to write for `propertyName`, given the
    /// `incoming` PUT value and the `held` value already in force, or `None` to leave `held` untouched
    /// (silently — the operator-facing WARN log upstream emits on an unresolvable value is not implemented;
    /// see the module doc).
    pub fn restore_redacted_value(property_name: &str, incoming: &str, held: &str) -> Option<String> {
        let normalised = normalise_property_name(property_name);
        let restored = if HEADER_LIST_CREDENTIAL_PROPERTIES.contains(&normalised.as_str()) {
            restore_header_list(incoming, held)?
        } else if JSON_DOCUMENT_CREDENTIAL_PROPERTIES.contains(&normalised.as_str()) {
            restore_json_document(incoming, held)?
        } else if is_whole_value_masked_on_read(property_name) && incoming == REDACTED_VALUE {
            // the untouched GET-then-PUT round trip for a whole-value credential: read back as the bare mask
            // and sent straight in again — silently keep the held value.
            return None;
        } else {
            incoming.to_string()
        };
        if contains_redaction_mask(&restored) {
            // an edited value still carrying the mask (welded text, a buried mask, or — for a whole-value
            // credential, which has no unmasked part to merge — anything but the untouched round trip above)
            // cannot be resolved: refuse it rather than destroy the held credential or persist the mask.
            return None;
        }
        Some(restored)
    }

    // -----------------------------------------------------------------------------------------------
    // k=v,k2=v2 header list — EmbeddedCredentialRedaction's header-list half
    // -----------------------------------------------------------------------------------------------

    /// Split a `k=v,k2=v2` list into entries, re-attaching any `=`-less entry to the one before it (the format
    /// cannot escape a comma, so such an entry is the tail of the preceding value).
    fn header_entries(value: &str) -> Vec<String> {
        let mut entries: Vec<String> = Vec::new();
        for entry in value.split(',') {
            let entry_has_name_eq = entry.find('=').is_some_and(|i| i > 0);
            let last_has_name_eq = entries.last().is_some_and(|last: &String| last.find('=').is_some_and(|i| i > 0));
            if !entry_has_name_eq && last_has_name_eq {
                let last = entries.last_mut().expect("last_has_name_eq implies a last entry");
                last.push(',');
                last.push_str(entry);
            } else {
                entries.push(entry.to_string());
            }
        }
        entries
    }

    /// The header values currently held, indexed by exact (trimmed) name — last-identical-name wins, matching
    /// `PrometheusRemoteWriteExporter#parseHeaders`'s case-sensitive, additive consumption.
    fn parse_header_list(value: &str) -> std::collections::HashMap<String, String> {
        let mut parsed = std::collections::HashMap::new();
        if value.is_empty() {
            return parsed;
        }
        for entry in header_entries(value) {
            if let Some(equals) = entry.find('=').filter(|&i| i > 0) {
                let name = entry[..equals].trim().to_string();
                if !name.is_empty() {
                    parsed.insert(name, entry[equals + 1..].to_string());
                }
            }
        }
        parsed
    }

    /// `EmbeddedCredentialRedaction.redactHeaderList`.
    fn redact_header_list(value: &str) -> String {
        if value.is_empty() || !value.contains('=') {
            return value.to_string();
        }
        let mut entries = header_entries(value);
        let mut redacted = false;
        for entry in entries.iter_mut() {
            let Some(equals) = entry.find('=').filter(|&i| i > 0) else { continue };
            let name = entry[..equals].to_string();
            let header_value = entry[equals + 1..].to_string();
            if is_sensitive_name(name.trim()) && !header_value.trim().is_empty() {
                *entry = format!("{name}={REDACTED_VALUE}");
                redacted = true;
            }
        }
        if redacted { entries.join(",") } else { value.to_string() }
    }

    /// `EmbeddedCredentialRedaction.restoreHeaderList`. `None` means "leave `existing` untouched" (the whole
    /// value is unmergeable).
    fn restore_header_list(incoming: &str, existing: &str) -> Option<String> {
        if incoming.is_empty() || !incoming.contains(REDACTED_VALUE) {
            return Some(incoming.to_string());
        }
        if incoming.trim() == REDACTED_VALUE {
            return None;
        }
        if incoming == redact_header_list(existing) {
            // an unedited GET-then-PUT: keep the held value verbatim, including its formatting
            return Some(existing.to_string());
        }
        let held = parse_header_list(existing);
        let incoming_names: Vec<String> = parse_header_list(incoming).into_keys().collect();
        let mut restored: Vec<String> = Vec::new();
        for entry in header_entries(incoming) {
            let Some(equals) = entry.find('=').filter(|&i| i > 0) else {
                restored.push(entry);
                continue;
            };
            let name = &entry[..equals];
            let value = entry[equals + 1..].trim();
            if !contains_redaction_mask(value) {
                restored.push(entry.clone());
                continue;
            }
            let tail = value.strip_prefix(REDACTED_VALUE);
            let ok_tail = tail.is_some_and(|t| t.is_empty() || t.starts_with(','));
            if !ok_tail {
                // the mask is buried inside the value, or text is welded onto it — neither is a form
                // redaction produces (a masked header value is replaced WHOLE)
                return None;
            }
            let tail = tail.expect("ok_tail implies Some");
            let trimmed_name = name.trim();
            let mut held_value = held.get(trimmed_name).cloned();
            if held_value.is_none() {
                let candidates: Vec<&String> = held.keys().filter(|k| k.eq_ignore_ascii_case(trimmed_name)).collect();
                let incoming_count = incoming_names.iter().filter(|n| n.eq_ignore_ascii_case(trimmed_name)).count();
                if candidates.len() > 1 || incoming_count > 1 {
                    // two names differ only in case — distinct headers to the consumer, ambiguous to resolve
                    return None;
                }
                let Some(candidate) = candidates.first() else {
                    // nothing is held under this name at all
                    return None;
                };
                held_value = held.get(*candidate).cloned();
            }
            restored.push(format!("{name}={}{tail}", held_value.expect("resolved above")));
        }
        let merged = restored.join(",");
        if merged.is_empty() {
            // nothing survived: writing "" would pin an empty value, shadowing a property-file/env value
            return None;
        }
        if contains_redaction_mask(&merged) {
            return None;
        }
        Some(merged)
    }

    // -----------------------------------------------------------------------------------------------
    // JSON document (or, in its documented shape, a file path) — EmbeddedCredentialRedaction's other half
    // -----------------------------------------------------------------------------------------------

    /// U+FEFF, the zero-width byte-order mark.
    const BYTE_ORDER_MARK: char = '\u{FEFF}';

    static JSON_MEMBER: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r#""[^"]*"\s*:"#).expect("valid regex"));

    fn strip_leading(value: &str) -> String {
        value.trim().trim_start_matches(BYTE_ORDER_MARK).trim().to_string()
    }

    /// `EmbeddedCredentialRedaction.looksLikeJsonDocument`.
    fn looks_like_json_document(value: &str) -> bool {
        if value.is_empty() {
            return false;
        }
        let trimmed = strip_leading(value);
        trimmed.starts_with('[') || trimmed.starts_with('{') || JSON_MEMBER.is_match(&trimmed)
    }

    /// `EmbeddedCredentialRedaction.parseOrNull`. `serde_json::from_str` already fails on trailing
    /// non-whitespace tokens (unlike Jackson's default `readTree`, which is why upstream turns
    /// `FAIL_ON_TRAILING_TOKENS` on), so this matches it with no extra configuration.
    fn parse_or_null(value: &str) -> Option<serde_json::Value> {
        if !looks_like_json_document(value) {
            return None;
        }
        serde_json::from_str(&strip_leading(value)).ok()
    }

    /// `EmbeddedCredentialRedaction.isRedactableValue`: whether a sensitively-named field actually carries
    /// something worth masking.
    fn is_redactable_value(node: &serde_json::Value) -> bool {
        use serde_json::Value;
        match node {
            Value::Null => false,
            Value::String(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
            Value::Bool(_) | Value::Number(_) => true,
        }
    }

    /// `EmbeddedCredentialRedaction.redactSecretFields`.
    fn redact_secret_fields(node: &mut serde_json::Value) -> bool {
        let mut redacted = false;
        match node {
            serde_json::Value::Object(object) => {
                let names: Vec<String> = object.keys().cloned().collect();
                for name in names {
                    if is_sensitive_name(&name) {
                        if object.get(&name).is_some_and(is_redactable_value) {
                            object.insert(name, serde_json::Value::String(REDACTED_VALUE.to_string()));
                            redacted = true;
                        }
                    } else if let Some(child) = object.get_mut(&name) {
                        redacted |= redact_secret_fields(child);
                    }
                }
            }
            serde_json::Value::Array(array) => {
                for child in array.iter_mut() {
                    redacted |= redact_secret_fields(child);
                }
            }
            _ => {}
        }
        redacted
    }

    /// `EmbeddedCredentialRedaction.redactJsonDocument`.
    fn redact_json_document(value: &str) -> String {
        if !looks_like_json_document(value) {
            return value.to_string();
        }
        let Some(mut root) = parse_or_null(value) else {
            return REDACTED_VALUE.to_string();
        };
        if !redact_secret_fields(&mut root) {
            return value.to_string();
        }
        serde_json::to_string(&root).unwrap_or_else(|_| REDACTED_VALUE.to_string())
    }

    /// `EmbeddedCredentialRedaction.heldElement`: array elements are matched by their `name` field when the
    /// incoming element carries one, and by index otherwise.
    fn held_element(element: &serde_json::Value, held_array: Option<&serde_json::Value>, index: usize) -> Option<serde_json::Value> {
        let held_array = held_array?.as_array()?;
        let name = element.as_object().and_then(|o| o.get("name")).and_then(|v| v.as_str());
        if let Some(name) = name {
            return held_array.iter().find(|candidate| candidate.as_object().and_then(|o| o.get("name")).and_then(|v| v.as_str()) == Some(name)).cloned();
            // a named entry with no counterpart is new, so it has no prior secret to restore (fall-through above)
        }
        held_array.get(index).cloned()
    }

    /// `EmbeddedCredentialRedaction.restoreSecretFields`. Returns `false` when a masked credential field had
    /// no held counterpart to restore, so the document as a whole cannot be resolved.
    fn restore_secret_fields(incoming: &mut serde_json::Value, held: Option<&serde_json::Value>) -> bool {
        let mut resolved = true;
        match incoming {
            serde_json::Value::Object(object) => {
                let names: Vec<String> = object.keys().cloned().collect();
                for name in names {
                    let held_child = held.and_then(|h| h.as_object()).and_then(|o| o.get(&name)).cloned();
                    if is_sensitive_name(&name) {
                        let is_masked = matches!(object.get(&name), Some(serde_json::Value::String(s)) if s == REDACTED_VALUE);
                        if is_masked {
                            if held_child.as_ref().is_some_and(is_redactable_value) {
                                object.insert(name, held_child.expect("checked above"));
                            } else {
                                resolved = false;
                            }
                        }
                        // else: a real value supplied by the client — written as given, not recursed into
                    } else if let Some(child) = object.get_mut(&name) {
                        resolved &= restore_secret_fields(child, held_child.as_ref());
                    }
                }
            }
            serde_json::Value::Array(array) => {
                for (index, element) in array.iter_mut().enumerate() {
                    let held_elem = held_element(element, held, index);
                    resolved &= restore_secret_fields(element, held_elem.as_ref());
                }
            }
            _ => {}
        }
        resolved
    }

    /// `EmbeddedCredentialRedaction.restoreJsonDocument`. `None` means "leave `existing` untouched".
    fn restore_json_document(incoming: &str, existing: &str) -> Option<String> {
        if incoming.is_empty() || !incoming.contains(REDACTED_VALUE) {
            return Some(incoming.to_string());
        }
        if incoming.trim() == REDACTED_VALUE {
            return None;
        }
        if !looks_like_json_document(incoming) {
            // not a document, so nothing was ever masked inside it — the token is part of the value
            return Some(incoming.to_string());
        }
        if incoming == redact_json_document(existing) {
            return Some(existing.to_string());
        }
        let mut incoming_root = parse_or_null(incoming)?;
        let existing_root = parse_or_null(existing);
        if !restore_secret_fields(&mut incoming_root, existing_root.as_ref()) {
            return None;
        }
        let merged = serde_json::to_string(&incoming_root).ok()?;
        if contains_redaction_mask(&merged) {
            return None;
        }
        Some(merged)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn sensitive_property_names() {
            assert!(is_sensitive_property_name("llmApiKey"));
            assert!(is_sensitive_property_name("mockserver.llmApiKey"));
            assert!(is_sensitive_property_name("prometheusRemoteWriteBearerToken"));
            assert!(is_sensitive_property_name("dashboardAnalyticsKey")); // sensitive by NAME (the DTO exemption is a separate, explicit allow-list)
            assert!(!is_sensitive_property_name("forwardConnectionPoolMaxIdlePerKey"));
            assert!(!is_sensitive_property_name("forwardConnectionPoolMaxTotalPerKey"));
            assert!(!is_sensitive_property_name("proxyAuthenticationRealm"));
            assert!(!is_sensitive_property_name("dataPlaneBasicAuthenticationRealm")); // "authentication" is not itself sensitive
        }

        #[test]
        fn sensitive_names_cover_header_only_substrings() {
            assert!(is_sensitive_name("Authorization"));
            assert!(is_sensitive_name("Api-Key"));
            assert!(is_sensitive_name("api_key")); // punctuation stripped before the substring check
            assert!(is_sensitive_name("Cookie"));
            assert!(is_sensitive_name("X-JWT"));
            assert!(!is_sensitive_name("X-Scope-OrgID"));
            assert!(!is_sensitive_name("X-Tenant"));
        }

        #[test]
        fn redact_header_list_masks_only_the_credential_header() {
            assert_eq!(redact_header_list("Authorization=Bearer secret,X-Scope-OrgID=tenant-a"), "Authorization=***REDACTED***,X-Scope-OrgID=tenant-a");
            assert_eq!(redact_header_list("X-Scope-OrgID=tenant-a, X-Custom=abc"), "X-Scope-OrgID=tenant-a, X-Custom=abc"); // byte-identical when nothing to redact
            // a comma inside the secret cannot be escaped by this format: masked whole, tail absorbed
            assert_eq!(redact_header_list("Authorization=Bearer secret,TAIL,X-Tenant=acme"), "Authorization=***REDACTED***,X-Tenant=acme");
        }

        #[test]
        fn restore_header_list_round_trips() {
            let held = "Authorization=Bearer real-secret,X-B=2";
            // unedited round trip
            assert_eq!(restore_header_list(&redact_header_list(held), held).as_deref(), Some(held));
            // edited neighbour, masked credential restored
            assert_eq!(
                restore_header_list("Authorization=***REDACTED***,X-B=3", held).as_deref(),
                Some("Authorization=Bearer real-secret,X-B=3")
            );
            // welded text over the mask: refused
            assert_eq!(restore_header_list("Authorization=***REDACTED***-my-new-key", held), None);
            // no held value under the masked name at all: refused
            assert_eq!(restore_header_list("Api-Key=***REDACTED***", ""), None);
        }

        #[test]
        fn restore_header_list_case_insensitive_fallback_only_when_unambiguous() {
            let held = "Authorization=Bearer real-secret,X-B=2";
            // re-cased name, unambiguous: resolves
            assert_eq!(restore_header_list("authorization=***REDACTED***,X-B=3", held).as_deref(), Some("authorization=Bearer real-secret,X-B=3"));
            // two held names differing only in case: ambiguous, refused
            let ambiguous_held = "X-Api-Key=A,x-api-key=B";
            assert_eq!(restore_header_list("X-API-KEY=***REDACTED***,X-Env=prod", ambiguous_held), None);
        }

        #[test]
        fn redact_json_document_masks_credential_fields_at_any_depth_and_type() {
            let value = r#"{"tokens":["a","b"],"apiKey":9876543210,"model":"gpt-4"}"#;
            assert_eq!(redact_json_document(value), r#"{"tokens":"***REDACTED***","apiKey":"***REDACTED***","model":"gpt-4"}"#);
            // a plain file path is not a JSON document: unchanged
            assert_eq!(redact_json_document("/etc/mockserver/llm-backends.json"), "/etc/mockserver/llm-backends.json");
            // unparseable but plainly a document: masked whole rather than disclosed
            assert_eq!(redact_json_document(r#"[{"name":"openai","apiKey":"secret""#), REDACTED_VALUE);
        }

        #[test]
        fn restore_json_document_matches_array_elements_by_name_then_index() {
            let held = r#"[{"name":"openai","apiKey":"real-openai-key"},{"name":"azure","apiKey":"old-azure-key"}]"#;
            let incoming = r#"[{"name":"openai","apiKey":"***REDACTED***"},{"name":"azure","apiKey":"new-azure-key"}]"#;
            assert_eq!(
                restore_json_document(incoming, held).as_deref(),
                Some(r#"[{"name":"openai","apiKey":"real-openai-key"},{"name":"azure","apiKey":"new-azure-key"}]"#)
            );
            // a renamed backend has no held counterpart to restore from: refused
            let renamed = r#"[{"name":"openai-2","apiKey":"***REDACTED***"}]"#;
            assert_eq!(restore_json_document(renamed, r#"[{"name":"openai","apiKey":"real"}]"#), None);
        }

        #[test]
        fn restore_redacted_value_whole_credential() {
            // the untouched round trip: `None` means "leave the held value untouched" — the caller
            // (control.rs) skips writing anything, so the held value stands exactly as it was
            assert_eq!(restore_redacted_value("llmApiKey", REDACTED_VALUE, "held-secret"), None);
            // a real new value replaces it
            assert_eq!(restore_redacted_value("llmApiKey", "new-secret", "held-secret").as_deref(), Some("new-secret"));
            // clearing with an empty string is a real instruction, not a mask
            assert_eq!(restore_redacted_value("llmApiKey", "", "held-secret").as_deref(), Some(""));
            // a value merely CONTAINING the mask is neither the round trip nor a real value: refused
            assert_eq!(restore_redacted_value("llmApiKey", "sk-***REDACTED***", "held-secret"), None);
            // a property never masked on read (e.g. dataPlaneBearerAuthenticationToken) always treats the bare
            // mask as operator error, not a round trip
            assert_eq!(restore_redacted_value("dataPlaneBearerAuthenticationToken", REDACTED_VALUE, "held-token"), None);
            assert_eq!(restore_redacted_value("dataPlaneBearerAuthenticationToken", "new-token", "held-token").as_deref(), Some("new-token"));
        }

        #[test]
        fn dispatch_membership() {
            assert!(is_credential_dispatch_property("llmApiKey"));
            assert!(is_credential_dispatch_property("llmBackendsConfig"));
            assert!(is_credential_dispatch_property("clusterFanInPeerAuthToken"));
            assert!(is_credential_dispatch_property("dashboardAnalyticsKey"));
            assert!(!is_credential_dispatch_property("proxyAuthenticationRealm"));
        }

        /// Every write-only credential of `ConfigurationDTO` is credential-shaped by name, and a mask-carrying
        /// value never replaces the held one.
        #[test]
        fn write_only_credentials_refuse_the_mask() {
            for name in OMITTED_CREDENTIAL_PROPERTIES {
                assert!(is_sensitive_property_name(name), "{name}");
                assert!(is_credential_dispatch_property(name), "{name}");
                assert_eq!(restore_redacted_value(name, REDACTED_VALUE, "held"), None, "{name}");
                assert_eq!(restore_redacted_value(name, "x-***REDACTED***", "held"), None, "{name}");
                assert_eq!(restore_redacted_value(name, "new", "held").as_deref(), Some("new"), "{name}");
            }
        }
    }
}

fn unquote(v: &str) -> &str {
    v.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(v)
}

fn parse_properties(text: &str) -> HashMap<String, String> {
    crate::property_file::parse_ordered(text).into_iter().collect()
}

/// The policy for JVM-only inputs: every input that only means something to MockServer's JVM gets
/// one verdict, here, and both the server (the startup notice, the worker-thread count) and `mock-server migrate`
/// read it. [`findings`] is a pure function of the configuration sources, so `migrate` can apply the
/// table to a properties file, an environment or a compose file without a server.
pub mod jvm_policy {
    use std::collections::HashMap;

    /// What the server does with a JVM-only input.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Verdict {
        /// Honoured with the oracle's meaning.
        Support,
        /// Honoured through a Rust counterpart with the same intent.
        Map,
        /// Accepted and has no effect; the server says so once at startup.
        Warn,
        /// The deployment form cannot exist; the server behaves as the oracle does.
        Reject,
    }

    /// What a policy row matches.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Input {
        /// A configuration key (without `mockserver.`) with any non-blank value, from a system property, the
        /// properties file or its `MOCKSERVER_*` environment variable.
        Key(&'static str),
        /// Every recognised configuration key whose name starts with this, each as a [`Input::Key`].
        KeyPrefix(&'static str),
        /// A configuration key with this value (compared ignoring case).
        KeyValue(&'static str, &'static str),
        /// A configuration key naming a class: the row applies only when no callback provider supplies the class.
        ClassUnlessProvided(&'static str),
        /// An environment variable a JVM or MockServer's launch scripts read.
        Environment(&'static str),
    }

    /// One row of [`TABLE`].
    #[derive(Debug, PartialEq, Eq)]
    pub struct Policy {
        pub input: Input,
        pub verdict: Verdict,
        /// Why, in a phrase `migrate` can show.
        pub reason: &'static str,
    }

    const JVM_OPTIONS_REASON: &str = "JVM options: mock-server is not a JVM and does not read this variable; a -Dmockserver.<key>=<value> token maps to MOCKSERVER_<KEY>, every other flag has no counterpart";

    /// The policy table, in the order the startup notice lists what it finds.
    pub const TABLE: &[Policy] = &[
        Policy { input: Input::Environment("JAVA_TOOL_OPTIONS"), verdict: Verdict::Warn, reason: JVM_OPTIONS_REASON },
        Policy { input: Input::Environment("JAVA_OPTS"), verdict: Verdict::Warn, reason: JVM_OPTIONS_REASON },
        Policy { input: Input::Environment("JVM_OPTIONS"), verdict: Verdict::Warn, reason: JVM_OPTIONS_REASON },
        Policy { input: Input::Environment("MOCKSERVER_JAVA_OPTS"), verdict: Verdict::Warn, reason: JVM_OPTIONS_REASON },
        Policy { input: Input::Environment("_JAVA_OPTIONS"), verdict: Verdict::Warn, reason: JVM_OPTIONS_REASON },
        Policy { input: Input::Environment("JDK_JAVA_OPTIONS"), verdict: Verdict::Warn, reason: JVM_OPTIONS_REASON },
        Policy { input: Input::Key("useNativeTransport"), verdict: Verdict::Map, reason: "on Linux, false stops the response write-stall timeout from counting the kernel's TCP_INFO record of data sent as progress, as Netty's NIO fallback does; tokio always uses the platform's native poller" },
        Policy { input: Input::Key("nioEventLoopThreadCount"), verdict: Verdict::Map, reason: "the tokio worker-thread count" },
        Policy { input: Input::Key("actionHandlerThreadCount"), verdict: Verdict::Warn, reason: "sizes only the template-render pool: other actions run on the tokio workers" },
        Policy { input: Input::Key("clientNioEventLoopThreadCount"), verdict: Verdict::Warn, reason: "no separate forwarding-client event loop: the client runs on the tokio workers" },
        Policy { input: Input::Key("webSocketClientEventLoopThreadCount"), verdict: Verdict::Warn, reason: "no separate WebSocket-client event loop: it runs on the tokio workers" },
        Policy { input: Input::KeyPrefix("javascript"), verdict: Verdict::Warn, reason: "JavaScript templates fail as in the GraalJS-less MockServer image, so their settings have nothing to configure" },
        Policy { input: Input::KeyValue("velocityDisallowClassLoading", "false"), verdict: Verdict::Warn, reason: "Velocity templates stay sandboxed: class loading needs the JVM foreign runtime" },
        Policy { input: Input::KeyValue("forwardProxyTLSX509CertificatesTrustManagerType", "JVM"), verdict: Verdict::Map, reason: "the bundled cacerts roots stand for the JVM's default trust store" },
        Policy { input: Input::ClassUnlessProvided("initializationClass"), verdict: Verdict::Warn, reason: "Java classes are not loaded: an initializer class comes from a callback plugin" },
    ];

    /// The configuration sources the table is applied to.
    pub struct Sources<'a> {
        /// `-D` system properties, keyed `mockserver.<name>`.
        pub system_properties: &'a HashMap<String, String>,
        /// Properties-file entries, keyed `mockserver.<name>`.
        pub file: &'a HashMap<String, String>,
        pub env: &'a HashMap<String, String>,
    }

    /// One JVM-only input found in the sources.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Finding {
        pub policy: &'static Policy,
        /// The setting as the notice shows it: `mockserver.<key>=<value>` (or `MOCKSERVER_<KEY>=<value>`, by the
        /// source that supplied it), `<VARIABLE> <value>` for an environment variable; the value is left out for a
        /// sensitive key and redacted inside JVM options.
        pub setting: String,
    }

    /// The rows of [`TABLE`] the sources match, in table order. `class_provided` says whether a callback provider
    /// supplies a class (for [`Input::ClassUnlessProvided`]).
    pub fn findings(sources: &Sources, class_provided: &dyn Fn(&str) -> bool) -> Vec<Finding> {
        let mut found = Vec::new();
        for policy in TABLE {
            match policy.input {
                Input::Environment(name) => {
                    if let Some(value) = super::not_blank(sources.env.get(name)) {
                        // the image's `java` reads three of the variables: their heap flags are honoured
                        let shown = redact_jvm_options(value.trim(), image_reads(name));
                        if !shown.is_empty() {
                            found.push(Finding { policy, setting: format!("{name} {shown}") });
                        }
                    }
                }
                Input::Key(key) => found.extend(key_setting(sources, key).map(|(setting, _)| Finding { policy, setting })),
                Input::KeyPrefix(prefix) => {
                    for (name, _) in super::recognised_properties() {
                        let Some(key) = name.strip_prefix("mockserver.").filter(|k| k.starts_with(prefix)) else { continue };
                        found.extend(key_setting(sources, key).map(|(setting, _)| Finding { policy, setting }));
                    }
                }
                Input::KeyValue(key, wanted) => {
                    found.extend(key_setting(sources, key).filter(|(_, value)| value.trim().eq_ignore_ascii_case(wanted)).map(|(setting, _)| Finding { policy, setting }));
                }
                Input::ClassUnlessProvided(key) => {
                    found.extend(key_setting(sources, key).filter(|(_, class)| !class_provided(class.trim())).map(|(setting, _)| Finding { policy, setting }));
                }
            }
        }
        found
    }

    /// `key` as the effective tier supplies it (system property, properties file, environment variable, the first
    /// non-blank one): the setting as shown, and the value with one pair of quotes removed.
    fn key_setting(sources: &Sources, key: &str) -> Option<(String, String)> {
        let property = format!("mockserver.{key}");
        let environment = super::env_name(key);
        let (name, raw) = super::not_blank(sources.system_properties.get(&property))
            .map(|v| (property.clone(), v))
            .or_else(|| super::not_blank(sources.file.get(&property)).map(|v| (property.clone(), v)))
            .or_else(|| super::not_blank(sources.env.get(&environment)).map(|v| (environment.clone(), v)))?;
        let value = super::strip_quotes(raw);
        let setting = if super::credentials::is_sensitive_property_name(key) { name } else { format!("{name}={value}") };
        Some((setting, value))
    }

    /// JVM options with the value of each `-D<name>=<value>` whose name is sensitive replaced by the redaction mask,
    /// without the heap flags when `honour_heap` (a variable the image's `java` reads).
    fn redact_jvm_options(options: &str, honour_heap: bool) -> String {
        let tokens: Vec<String> = options
            .split_whitespace()
            .filter(|token| !(honour_heap && is_heap_flag(token)))
            .map(|token| match token.strip_prefix("-D").and_then(|rest| rest.split_once('=')) {
                Some((name, _)) if super::credentials::is_sensitive_property_name(name) => format!("-D{name}={}", super::credentials::REDACTED_VALUE),
                _ => token.to_string(),
            })
            .collect();
        tokens.join(" ")
    }

    /// A JVM flag the heap-derived defaults are sized from as the image's JVM sizes them: the heap
    /// ceiling (`-Xmx`, `-XX:MaxHeapSize=`, `-XX:MaxRAM=`, `-XX:MaxRAMPercentage=`, `-XX:MinRAMPercentage=`) and the
    /// collector, whose alignment rounds it.
    pub fn is_heap_flag(token: &str) -> bool {
        token.starts_with("-Xmx")
            || token.starts_with("-XX:MaxHeapSize=")
            || token.starts_with("-XX:MaxRAM=")
            || token.starts_with("-XX:MaxRAMPercentage=")
            || token.starts_with("-XX:MinRAMPercentage=")
            || ["-XX:+UseZGC", "-XX:+UseG1GC", "-XX:+UseSerialGC", "-XX:+UseParallelGC", "-XX:+UseShenandoahGC", "-XX:+UseEpsilonGC"].contains(&token)
    }

    /// Whether the image's `java` reads JVM options from the environment variable `name`: its heap flags are then
    /// honoured ([`is_heap_flag`]).
    pub fn image_reads(name: &str) -> bool {
        super::JVM_OPTION_VARIABLES.contains(&name)
    }

    /// The verdict of one token of a JVM options variable, for `migrate`: `-Dmockserver.<key>=<value>`
    /// and `-XX:ActiveProcessorCount=<n>` (the worker count) map, every other token is a JVM flag without effect
    /// (a heap flag in a variable the image reads aside, [`image_reads`]).
    pub fn jvm_option_verdict(token: &str) -> Verdict {
        if token.starts_with("-Dmockserver.") || token.starts_with("-XX:ActiveProcessorCount=") { Verdict::Map } else { Verdict::Warn }
    }

    /// The startup notice: one line naming the warn-verdict findings, or `None` without any.
    pub fn notice(findings: &[Finding]) -> Option<String> {
        let warned: Vec<&str> = findings.iter().filter(|f| f.policy.verdict == Verdict::Warn).map(|f| f.setting.as_str()).collect();
        (!warned.is_empty()).then(|| format!("JVM-only settings have no effect in mock-server: [{}]", warned.join(", ")))
    }

    /// `nioEventLoopThreadCount` mapped to the tokio worker-thread count: a positive integer set explicitly, else
    /// `None` (tokio's default, the available cores; Netty also reads 0 as its own default).
    pub fn worker_threads(config: &super::Config) -> Option<usize> {
        config.property("nioEventLoopThreadCount").and_then(|v| v.trim().parse::<usize>().ok()).filter(|&n| n > 0)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
            pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
        }

        fn settings(system: &[(&str, &str)], file: &[(&str, &str)], env: &[(&str, &str)], provided: bool) -> Vec<(String, Verdict)> {
            let (system, file, env) = (map(system), map(file), map(env));
            findings(&Sources { system_properties: &system, file: &file, env: &env }, &|_| provided).into_iter().map(|f| (f.setting, f.policy.verdict)).collect()
        }

        #[test]
        fn the_table_covers_every_jvm_option_input() {
            let inputs: Vec<Input> = TABLE.iter().map(|p| p.input).collect();
            for env in ["JAVA_OPTS", "JAVA_TOOL_OPTIONS", "JVM_OPTIONS", "MOCKSERVER_JAVA_OPTS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"] {
                assert!(inputs.contains(&Input::Environment(env)), "{env}");
            }
            for key in ["useNativeTransport", "nioEventLoopThreadCount", "actionHandlerThreadCount", "clientNioEventLoopThreadCount", "webSocketClientEventLoopThreadCount"] {
                assert!(inputs.contains(&Input::Key(key)), "{key}");
            }
            let verdict = |input: Input| TABLE.iter().find(|p| p.input == input).map(|p| p.verdict);
            assert_eq!(verdict(Input::Key("nioEventLoopThreadCount")), Some(Verdict::Map));
            assert_eq!(verdict(Input::Key("useNativeTransport")), Some(Verdict::Map));
            assert_eq!(verdict(Input::KeyPrefix("javascript")), Some(Verdict::Warn));
            assert_eq!(verdict(Input::KeyValue("velocityDisallowClassLoading", "false")), Some(Verdict::Warn));
            assert_eq!(verdict(Input::KeyValue("forwardProxyTLSX509CertificatesTrustManagerType", "JVM")), Some(Verdict::Map));
            assert_eq!(verdict(Input::ClassUnlessProvided("initializationClass")), Some(Verdict::Warn));
        }

        #[test]
        fn every_configuration_key_in_the_table_is_a_recognised_one() {
            let recognised = |key: &str| super::super::recognised_properties().iter().any(|(name, _)| name.strip_prefix("mockserver.") == Some(key));
            for policy in TABLE {
                match policy.input {
                    Input::Key(key) | Input::KeyValue(key, _) | Input::ClassUnlessProvided(key) => assert!(recognised(key), "{key}"),
                    Input::KeyPrefix(prefix) => assert!(super::super::recognised_properties().iter().any(|(name, _)| name.starts_with(&format!("mockserver.{prefix}"))), "{prefix}"),
                    Input::Environment(_) => {}
                }
            }
        }

        #[test]
        fn findings_come_in_table_order_named_by_the_tier_that_supplied_them() {
            let found = settings(
                &[("mockserver.useNativeTransport", "false"), ("mockserver.actionHandlerThreadCount", "3")],
                &[("mockserver.javascriptDisallowedText", "eval"), ("mockserver.actionHandlerThreadCount", "9")],
                &[("JAVA_TOOL_OPTIONS", " -Xmx256m  -XX:MaxMetaspaceSize=64m "), ("MOCKSERVER_NIO_EVENT_LOOP_THREAD_COUNT", "2"), ("MOCKSERVER_CLIENT_NIO_EVENT_LOOP_THREAD_COUNT", "")],
                false,
            );
            assert_eq!(found, vec![
                ("JAVA_TOOL_OPTIONS -XX:MaxMetaspaceSize=64m".to_string(), Verdict::Warn),
                ("mockserver.useNativeTransport=false".to_string(), Verdict::Map),
                ("MOCKSERVER_NIO_EVENT_LOOP_THREAD_COUNT=2".to_string(), Verdict::Map),
                ("mockserver.actionHandlerThreadCount=3".to_string(), Verdict::Warn),
                ("mockserver.javascriptDisallowedText=eval".to_string(), Verdict::Warn),
            ]);
        }

        #[test]
        fn conditional_rows_apply_only_to_their_value() {
            assert!(settings(&[("mockserver.velocityDisallowClassLoading", "true")], &[], &[("MOCKSERVER_FORWARD_PROXY_TLS_X509_CERTIFICATES_TRUST_MANAGER_TYPE", "ANY")], false).is_empty());
            assert_eq!(settings(&[("mockserver.velocityDisallowClassLoading", "\"FALSE\"")], &[], &[("MOCKSERVER_FORWARD_PROXY_TLS_X509_CERTIFICATES_TRUST_MANAGER_TYPE", "jvm")], false), vec![
                ("mockserver.velocityDisallowClassLoading=FALSE".to_string(), Verdict::Warn),
                ("MOCKSERVER_FORWARD_PROXY_TLS_X509_CERTIFICATES_TRUST_MANAGER_TYPE=jvm".to_string(), Verdict::Map),
            ]);
            assert_eq!(settings(&[], &[], &[("MOCKSERVER_INITIALIZATION_CLASS", "org.example.Init")], false), vec![("MOCKSERVER_INITIALIZATION_CLASS=org.example.Init".to_string(), Verdict::Warn)]);
            assert!(settings(&[], &[], &[("MOCKSERVER_INITIALIZATION_CLASS", "org.example.Init")], true).is_empty());
        }

        #[test]
        fn sensitive_jvm_options_are_redacted() {
            let found = settings(&[], &[], &[("JAVA_OPTS", "-Djavax.net.ssl.keyStorePassword=secret -Djavax.net.ssl.keyStore=/ks.jks -Dmockserver.logLevel=WARN")], false);
            assert_eq!(found[0].0, "JAVA_OPTS -Djavax.net.ssl.keyStorePassword=***REDACTED*** -Djavax.net.ssl.keyStore=/ks.jks -Dmockserver.logLevel=WARN");
        }

        #[test]
        fn the_notice_names_only_warn_verdicts() {
            let (system, file, env) = (map(&[("mockserver.nioEventLoopThreadCount", "4")]), HashMap::new(), map(&[("JAVA_TOOL_OPTIONS", "-Xss1m")]));
            let found = findings(&Sources { system_properties: &system, file: &file, env: &env }, &|_| false);
            assert_eq!(notice(&found).as_deref(), Some("JVM-only settings have no effect in mock-server: [JAVA_TOOL_OPTIONS -Xss1m]"));
            assert_eq!(notice(&found[1..]), None);
        }

        /// `useNativeTransport=false` turns off the Linux `TCP_INFO` progress check of
        /// `write_stall` as upstream's NIO fallback does, so it is no longer an input without effect.
        #[test]
        fn use_native_transport_is_mapped_not_warned() {
            let (system, file, env) = (map(&[("mockserver.useNativeTransport", "false")]), HashMap::new(), HashMap::new());
            let found = findings(&Sources { system_properties: &system, file: &file, env: &env }, &|_| false);
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].policy.verdict, Verdict::Map);
            assert!(found[0].policy.reason.contains("Linux") && found[0].policy.reason.contains("TCP_INFO"), "{}", found[0].policy.reason);
            assert_eq!(notice(&found), None);
        }

        #[test]
        fn jvm_option_tokens_map_or_warn() {
            assert_eq!(jvm_option_verdict("-Dmockserver.logLevel=WARN"), Verdict::Map);
            assert_eq!(jvm_option_verdict("-XX:ActiveProcessorCount=2"), Verdict::Map);
            assert_eq!(jvm_option_verdict("-Xmx256m"), Verdict::Warn);
        }

        #[test]
        fn heap_flags_leave_the_notice_only_where_the_image_reads_them() {
            let found = settings(&[], &[], &[("JAVA_TOOL_OPTIONS", "-XX:+UseZGC -Xmx512m"), ("_JAVA_OPTIONS", "-XX:MaxHeapSize=1g -Xss1m"), ("JAVA_OPTS", "-Xmx1g")], false);
            assert_eq!(found, vec![("JAVA_OPTS -Xmx1g".to_string(), Verdict::Warn), ("_JAVA_OPTIONS -Xss1m".to_string(), Verdict::Warn)]);
        }

        #[test]
        fn only_a_positive_explicit_count_sets_the_workers() {
            let config = |v: &str| super::super::Config::default().with_property("nioEventLoopThreadCount", v);
            assert_eq!(worker_threads(&super::super::Config::default()), None);
            assert_eq!(worker_threads(&config("3")), Some(3));
            assert_eq!(worker_threads(&config(" 7 ")), Some(7));
            assert_eq!(worker_threads(&config("0")), None);
            assert_eq!(worker_threads(&config("many")), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::env_name;

    #[test]
    fn env_names() {
        assert_eq!(env_name("initializationJsonPath"), "MOCKSERVER_INITIALIZATION_JSON_PATH");
        assert_eq!(env_name("enableCORSForAllResponses"), "MOCKSERVER_ENABLE_CORS_FOR_ALL_RESPONSES");
        assert_eq!(env_name("maxLogEntries"), "MOCKSERVER_MAX_LOG_ENTRIES");
        assert_eq!(env_name("privateKeyPath"), "MOCKSERVER_TLS_PRIVATE_KEY_PATH");
    }

    #[test]
    fn startup_property_outside_file_skips_the_file_tier() {
        let overrides = r#"{"CREATED_EXPECTATION":"ERROR"}"#;
        let from_file = super::Config::default().with_property_file_text(&format!("mockserver.logLevelOverrides={overrides}\n"));
        assert_eq!(from_file.startup_property("logLevelOverrides").as_deref(), Some(overrides));
        assert_eq!(from_file.startup_property_outside_file("logLevelOverrides"), None);
        let from_env = super::Config::default().with_env("MOCKSERVER_LOG_LEVEL_OVERRIDES", overrides);
        assert_eq!(from_env.startup_property_outside_file("logLevelOverrides").as_deref(), Some(overrides));
    }

    /// The heap ceiling the oracle image derives from its container's memory (45%, ZGC's 2 MiB alignment,
    /// less 20 MiB), and the 9.1.0 event-log divisors over it.
    #[test]
    fn heap_derived_defaults_follow_the_oracle_image() {
        // the 32 GiB Docker VM the goldens were recorded in: 754764800 = a twentieth, as they show
        assert_eq!(super::heap_available_kb_of(Some(super::ORACLE_CONTAINER_MEMORY_BYTES), &super::JvmHeapOptions::IMAGE), super::ORACLE_HEAP_AVAILABLE_KB);
        let pinned = config_from(&["-serverPort", "0"], &[(super::CONTAINER_MEMORY_ENV, &super::ORACLE_CONTAINER_MEMORY_BYTES.to_string())]);
        assert_eq!(super::heap_available_kb(&pinned), super::ORACLE_HEAP_AVAILABLE_KB, "the binary pinned to the recording VM");
        assert!(super::heap_available_kb(&config_from(&["-serverPort", "0"], &[])) > 0, "measured on this machine");
        assert_eq!(super::heap_available_kb_of(None, &super::JvmHeapOptions::IMAGE), 0, "an unknown ceiling, as upstream's undefined one");
        assert_eq!(super::heap_available_kb_of(Some(1 << 20), &super::JvmHeapOptions::IMAGE), 0, "floored at 0 below BASE_MEMORY_IN_KB");
        let level = |level: &str| super::Config::default().with_property("logLevel", level);
        for (level_name, retained, in_flight) in [("INFO", 20, 7), ("WARN", 20, 7), ("ERROR", 20, 7), ("OFF", 20, 7), ("DEBUG", 12, 12), ("TRACE", 12, 12)] {
            let config = level(level_name);
            let heap = super::ORACLE_HEAP_AVAILABLE_KB;
            assert_eq!(super::max_event_log_size_in_bytes(&config), heap / retained * 1024, "{level_name}");
            assert_eq!(super::event_log_in_flight_bytes(&config, 1), (heap / in_flight * 1024) as u64, "{level_name}");
        }
        assert_eq!(super::max_event_log_size_in_bytes(&level("INFO")), 754_764_800);
        assert_eq!(super::event_log_in_flight_bytes(&level("INFO"), 0), 0, "no retention budget, no in-flight cap");
        assert_eq!(super::event_log_in_flight_bytes(&level("INFO"), u64::MAX / 2), u64::MAX / 2, "a larger budget raises the cap");
        let small = super::Config { heap_available_kb: Some(64 * 1024), ..super::Config::default() };
        assert_eq!((super::max_log_entries(&small), super::max_expectations(&small)), (8192, 6553), "heap/8 and heap/10 below their caps");
        let none = super::Config { heap_available_kb: Some(0), ..super::Config::default() };
        assert_eq!((super::max_log_entries(&none), super::max_expectations(&none), super::max_event_log_size_in_bytes(&none)), (1000, 1000, 0));
        assert_eq!((super::max_log_entries(&level("INFO")), super::max_expectations(&level("INFO"))), (250_000, 15_000));
    }

    /// A heap flag in the JVM options the image reads sets the ceiling; the values are the 9.1.0 image's
    /// `maxLogEntries` (heap/8) and `maxEventLogSizeInBytes` (heap/20 KB) read back as `heapAvailableInKB`.
    #[test]
    fn jvm_heap_flags_set_the_ceiling() {
        let heap = |env: &[(&str, &str)]| {
            let env: std::collections::HashMap<String, String> = env.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect();
            super::measured_heap_available_kb(Some(super::ORACLE_CONTAINER_MEMORY_BYTES), super::ORACLE_ACTIVE_PROCESSORS, &super::JvmHeapOptions::from_env(&env))
        };
        assert_eq!(heap(&[]), super::ORACLE_HEAP_AVAILABLE_KB, "no flag: 45% of the memory");
        assert_eq!(heap(&[("JAVA_TOOL_OPTIONS", "-Xmx512m")]) / 8, 62976);
        assert_eq!(heap(&[("JAVA_TOOL_OPTIONS", "-Xmx1000001k")]) / 20, 49049, "G1 below 4 GiB: 2 MiB");
        assert_eq!(heap(&[("JAVA_TOOL_OPTIONS", "-Xmx20000001k")]) / 20, 999219, "G1: its 8 MiB region");
        assert_eq!(heap(&[("JAVA_TOOL_OPTIONS", "-XX:+UseZGC -Xmx20000001k")]) / 20, 999014, "ZGC: 2 MiB");
        assert_eq!(heap(&[("JAVA_TOOL_OPTIONS", "-XX:+UseZGC -Xmx1g -XX:MaxHeapSize=300m"), ("_JAVA_OPTIONS", "-Xmx700m")]) / 20, 34816);
        assert_eq!(heap(&[("JAVA_TOOL_OPTIONS", "-XX:+UseZGC -XX:MaxHeapSize=300m"), ("JDK_JAVA_OPTIONS", "-Xmx100m")]) / 8, 10240);
        assert_eq!(heap(&[("JAVA_OPTS", "-Xmx100m")]), super::ORACLE_HEAP_AVAILABLE_KB, "a variable the image does not read");
        assert_eq!((super::jvm_memory_size("1048576"), super::jvm_memory_size("2G"), super::jvm_memory_size("1x"), super::jvm_memory_size("m")), (Some(1 << 20), Some(2 << 30), None, None));
    }

    /// `-XX:MaxRAM`, `-XX:MaxRAMPercentage` and `-XX:MinRAMPercentage`, the collector the JVM picks when none is
    /// named, and the Shenandoah and Epsilon alignments; every expected ceiling is a `MaxHeapSize` the oracle image's JVM
    /// (`java -XX:+PrintFlagsFinal`, Temurin 25) printed for the same flags and memory.
    #[test]
    fn jvm_ram_flags_size_the_ceiling_as_hotspot_does() {
        const GIB: u64 = 1 << 30;
        let ceiling = |flags: &str, memory: u64, processors: usize| {
            let env: std::collections::HashMap<String, String> = [("JAVA_TOOL_OPTIONS".to_string(), format!("-XX:+UseZGC {flags}"))].into();
            let jvm = super::JvmHeapOptions::from_env(&env).resolved(Some(memory), processors);
            super::heap_ceiling_with(Some(memory), &jvm)
        };
        let vm = 12_515_708_928;
        assert_eq!(ceiling("", vm, 6), Some(5_632_950_272), "the image's 45%");
        // JAVA_TOOL_OPTIONS precedes the ENTRYPOINT's own 45.0; _JAVA_OPTIONS follows it
        assert_eq!(ceiling("-XX:MaxRAMPercentage=25", vm, 6), Some(5_632_950_272));
        let after = |flags: &str| {
            let env: std::collections::HashMap<String, String> = [("_JAVA_OPTIONS".to_string(), flags.to_string())].into();
            super::heap_ceiling_with(Some(vm), &super::JvmHeapOptions::from_env(&env).resolved(Some(vm), 6))
        };
        assert_eq!(after("-XX:MaxRAMPercentage=25"), Some(3_128_950_784));
        assert_eq!(after("-XX:MaxRAMPercentage=25 -XX:MaxRAMPercentage=30"), Some(3_755_999_232), "the last wins");
        assert_eq!(after("-XX:MaxRAMPercentage=150"), Some(5_632_950_272), "out of range, refused by the JVM, ignored here");
        assert_eq!(after("-XX:MaxRAM=4g -XX:MaxRAMPercentage=25"), Some(GIB), "MaxRAM replaces the memory");
        assert_eq!(after("-XX:MaxRAM=64g -XX:MaxRAMPercentage=25"), Some(16 * GIB), "even above the machine's");
        assert_eq!(after("-XX:MaxRAM=1g -XX:MaxRAMPercentage=80"), Some(859_832_320));
        assert_eq!(after("-XX:MaxRAMPercentage=33.3 -XX:MaxRAM=7g"), Some(2_503_999_488));
        assert_eq!(after("-XX:MaxRAM=300m -XX:MaxRAMPercentage=20"), Some(132_120_576), "the default MaxHeapSize is the floor");
        assert_eq!(after("-XX:MaxRAM=100m -XX:MaxRAMPercentage=20"), Some(52_428_800), "half of a small memory, below that floor");
        assert_eq!(after("-XX:MaxRAM=100m -XX:MinRAMPercentage=80"), Some(83_886_080));
        assert_eq!(ceiling("", 64 << 20, 6), Some(33_554_432));
        assert_eq!(ceiling("", 256 << 20, 6), Some(132_120_576));
        assert_eq!(super::heap_ceiling_with(None, &super::JvmHeapOptions::IMAGE), None, "no memory, no ceiling");
        assert_eq!(super::heap_ceiling_with(Some(1000 * GIB), &super::JvmHeapOptions::IMAGE), super::heap_ceiling_with(Some(128 * GIB), &super::JvmHeapOptions::IMAGE), "the default MaxRAM caps the memory");
    }

    /// A JVM that names no collector picks G1 only on a server-class machine, Serial otherwise (2 processors,
    /// 1792 MiB), which aligns a large `-Xmx` to 2 MiB in place of G1's region; Shenandoah's region has no 2 MiB floor and
    /// Epsilon aligns to a page. The ceilings are the image JVM's `MaxHeapSize` for `-Xmx5000001k` and `-Xmx20000001k`.
    #[test]
    fn jvm_collector_ergonomics_and_alignment() {
        let kb = |flags: &str, memory: u64, processors: usize| {
            let env: std::collections::HashMap<String, String> = [("JAVA_TOOL_OPTIONS".to_string(), flags.to_string())].into();
            let jvm = super::JvmHeapOptions::from_env(&env).resolved(Some(memory), processors);
            let max = jvm.max_heap_bytes.unwrap();
            max.div_ceil(jvm.alignment(max)) * jvm.alignment(max)
        };
        let big = 32 << 30;
        let serial = super::JvmHeapOptions::from_env(&[("JAVA_TOOL_OPTIONS".to_string(), "-XX:+UseSerialGC -Xmx3000001k".to_string())].into()).resolved(Some(big), 6);
        assert_eq!(serial.reported(3_072_327_680), 3_072_327_680 - 65_536, "Serial's maxMemory: 3000256 KB (oracle, -Xmx3000001k)");
        // Parallel's maxMemory less the young generation's maximum survivor space; each pair is an aligned
        // ceiling and the reduction in KB the oracle's maxEventLogSizeInBytes implies (`-XX:+UseParallelGC -Xmx<n>k`)
        let parallel = super::JvmHeapOptions::from_env(&[("JAVA_TOOL_OPTIONS".to_string(), "-XX:+UseParallelGC -Xmx20000001k".to_string())].into()).resolved(Some(big), 6);
        for (ceiling_kb, reduction_kb) in [(20_000_768u64, 2_222_080u64), (100_352, 10_752), (6_000_640, 666_624), (3_000_320, 333_312), (1_001_472, 111_104), (12_001_280, 1_333_248)] {
            assert_eq!(parallel.reported(ceiling_kb * 1024), (ceiling_kb - reduction_kb) * 1024, "Parallel's maxMemory at {ceiling_kb} KB");
        }
        let ergonomic = super::JvmHeapOptions::from_env(&[("JAVA_TOOL_OPTIONS".to_string(), String::new())].into()).resolved(Some(1 << 30), 6);
        assert_eq!(super::heap_ceiling_with(Some(32 << 30), &ergonomic).map(|ceiling| ceiling % (2 << 20)), Some((2 << 20) - 65_536), "no flags, not server class: Serial, 64 KiB under a 2 MiB multiple");
        assert_eq!(kb("-Xmx20000001k", big, 6), 20_484_980_736, "server class: G1, 8 MiB region");
        assert_eq!(kb("-Xmx20000001k", big, 1), 20_480_786_432, "one processor: Serial, 2 MiB");
        assert_eq!(kb("-Xmx20000001k", 1 << 30, 6), kb("-Xmx20000001k", big, 1), "under 1792 MiB: Serial");
        assert_eq!(kb("-Xmx20000001k", 1792 << 20, 2), 20_484_980_736, "1792 MiB and 2 processors are server class");
        assert_eq!(kb("-XX:+UseG1GC -Xmx20000001k", 1 << 30, 1), 20_484_980_736, "a named collector is not ergonomic");
        assert_eq!(kb("-XX:+UseShenandoahGC -Xmx5001m", big, 6), 5_244_977_152);
        assert_eq!(kb("-XX:+UseShenandoahGC -Xmx20000001k", big, 6), 20_484_980_736);
        assert_eq!(kb("-XX:+UseShenandoahGC -Xmx100001k", big, 6), 102_498_304, "256 KiB regions");
        assert_eq!(kb("-XX:+UseShenandoahGC -Xmx3000001k", big, 6), 3_072_327_680, "1 MiB regions");
        assert_eq!(kb("-XX:+UseShenandoahGC -Xmx12000001k", big, 6), 12_289_310_720, "4 MiB regions");
        assert_eq!(kb("-XX:+UseShenandoahGC -Xmx200000001k", big, 6), 204_816_252_928, "32 MiB regions at most");
        assert_eq!(kb("-XX:+UseEpsilonGC -Xmx20000001k", big, 6), 20_480_004_096);
        assert_eq!(kb("-XX:+UseSerialGC -Xmx5000001k", big, 6), 5_121_245_184);
        assert_eq!(kb("-XX:+UseParallelGC -Xmx5000001k", big, 6), 5_121_245_184);
    }

    /// `actionHandlerThreadCount` defaults to max(5, processors), the recording machine's in a test
    /// configuration and the measured (or pinned) count in the binary; `oracle.env` pins the oracle to the same machine.
    #[test]
    fn processor_derived_default_follows_the_oracle_machine() {
        let pin = |key: &str| include_str!("../oracle.env").lines().find_map(|line| line.strip_prefix(key)?.strip_prefix('=')).unwrap().to_string();
        assert_eq!(pin("ORACLE_ACTIVE_PROCESSORS"), super::ORACLE_ACTIVE_PROCESSORS.to_string());
        assert_eq!(pin("ORACLE_MAX_HEAP_BYTES"), super::heap_ceiling_bytes(super::ORACLE_CONTAINER_MEMORY_BYTES).to_string());
        assert_eq!(((super::ORACLE_HEAP_AVAILABLE_KB + super::BASE_MEMORY_IN_KB) * 1024).to_string(), pin("ORACLE_MAX_HEAP_BYTES"));
        let test = super::Config::default();
        assert_eq!(super::default_action_handler_thread_count(&test), 6);
        assert_eq!(super::effective_json(&test)["actionHandlerThreadCount"], 6);
        assert_eq!(test.built_in_default("mockserver.actionHandlerThreadCount").as_deref(), Some("6"));
        let explicit = super::Config::default().with_property("actionHandlerThreadCount", "11");
        assert_eq!(super::effective_json(&explicit)["actionHandlerThreadCount"], 11);
        let two = config_from(&["-serverPort", "0"], &[(super::ACTIVE_PROCESSOR_COUNT_ENV, "2")]);
        assert_eq!((super::available_processors(&two), super::default_action_handler_thread_count(&two)), (2, 5), "at least 5");
        let sixteen = config_from(&["-serverPort", "0"], &[(super::ACTIVE_PROCESSOR_COUNT_ENV, "16")]);
        assert_eq!(super::effective_json(&sixteen)["actionHandlerThreadCount"], 16);
        let measured = config_from(&["-serverPort", "0"], &[]);
        assert_eq!(super::available_processors(&measured), std::thread::available_parallelism().map_or(1, usize::from), "measured on this machine");
        assert_eq!(super::measured_available_processors(Some(0)), std::thread::available_parallelism().map_or(1, usize::from), "0 pins nothing");
    }

    /// `NettyDirectMemoryLimit`: a quarter of the heap, at least 64 MiB, never more than the heap, unless
    /// `io.netty.maxDirectMemory` or `-XX:MaxDirectMemorySize` says.
    #[test]
    fn netty_direct_memory_limit_follows_the_heap_and_the_options() {
        let limit = |env: &[(&str, &str)]| {
            let config = env.iter().fold(super::Config::for_tests(), |c, (k, v)| c.with_env(k, v));
            super::netty_max_direct_memory(&config)
        };
        let heap = (super::ORACLE_HEAP_AVAILABLE_KB + super::BASE_MEMORY_IN_KB) as u64 * 1024;
        assert_eq!(limit(&[]), Some(heap / 4), "no option: a quarter of the heap");
        assert_eq!(limit(&[("JDK_JAVA_OPTIONS", "-Dio.netty.maxDirectMemory=8388608")]), Some(8_388_608));
        assert_eq!(limit(&[("JAVA_TOOL_OPTIONS", "-Dio.netty.maxDirectMemory=0")]), Some(0));
        assert_eq!(limit(&[("JDK_JAVA_OPTIONS", "-Dio.netty.maxDirectMemory=-1")]), Some(heap), "-1: Netty's own default");
        assert_eq!(limit(&[("JDK_JAVA_OPTIONS", "-XX:MaxDirectMemorySize=16m")]), Some(16 << 20));
        assert_eq!(limit(&[("JAVA_OPTS", "-Dio.netty.maxDirectMemory=1")]), Some(heap / 4), "a variable the image does not read");
        let mut small = super::Config::for_tests();
        small.heap_available_kb = Some(100 * 1024 - super::BASE_MEMORY_IN_KB);
        assert_eq!(super::netty_max_direct_memory(&small), Some(64 << 20), "a quarter of 100 MiB is under the floor");
        small.heap_available_kb = Some(40 * 1024 - super::BASE_MEMORY_IN_KB);
        assert_eq!(super::netty_max_direct_memory(&small), Some(40 << 20), "never more than the heap");
        small.heap_available_kb = Some(0);
        assert_eq!(super::netty_max_direct_memory(&small), None, "no heap known");
    }

    fn config_from(args: &[&str], env: &[(&str, &str)]) -> super::Config {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        super::Config::from_args(&args, env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()).unwrap()
    }

    /// The startup tiers resolved once answer as resolving each read did: for every recognised property, in
    /// both forms, a later tier change drops what was resolved, and a runtime value still comes first.
    #[test]
    fn startup_cache_answers_as_resolving_each_read() {
        let config = config_from(
            &["-Dmockserver.maxExpectations=\"7\"", "-Dmockserver.disableLogging=true"],
            &[("SERVER_PORT", "1234"), ("MOCKSERVER_LOG_LEVEL_OVERRIDES", "{}"), ("MOCKSERVER_VALIDATE_PROXY_OPENAPI_SPEC", "x"), ("MOCKSERVER_HTTP3_PORT", " ")],
        )
        .with_property_file_text("mockserver.metricsEnabled=true\nmockserver.compactLogFormat=true\n");
        for (key, _) in super::recognised_properties() {
            let name = key.strip_prefix("mockserver.").unwrap();
            assert_eq!(config.startup_property(name), config.resolve_startup_property(name), "{name}");
            assert_eq!(config.startup_property_outside_file(name), config.resolve_startup_property_outside_file(name), "{name}");
        }
        assert_eq!(config.property("maxExpectations").as_deref(), Some("7"));
        assert_eq!(config.property("metricsEnabled").as_deref(), Some("true"));
        assert_eq!(config.property_outside_file("compactLogFormat"), None);
        assert_eq!(config.property("validateProxyOpenAPISpec").as_deref(), Some("x"));
        assert_eq!(config.property("http3Port"), None);
        assert_eq!(config.property("notAProperty"), None);
        let config = config.with_property("metricsEnabled", "false").with_env("MOCKSERVER_HTTP3_PORT", "9");
        assert_eq!(config.property("metricsEnabled").as_deref(), Some("false"));
        assert_eq!(config.property("http3Port").as_deref(), Some("9"));
        let shared = config.clone();
        config.set_runtime("metricsEnabled", "runtime".into());
        assert_eq!(shared.property("metricsEnabled").as_deref(), Some("runtime"));
        assert_eq!(shared.startup_property("metricsEnabled").as_deref(), Some("false"));
    }

    /// A hot property answers as reading it does: unset or set at startup, then set at runtime after it was read, in
    /// the configuration and a clone sharing its runtime values.
    #[test]
    fn hot_properties_answer_as_reading_them() {
        use super::Hot;
        let config = super::Config::for_tests().with_property("metricsEnabled", "TRUE ").with_property("maxRequestBodySize", "12");
        assert!(config.hot_bool(Hot::MetricsEnabled, false));
        assert_eq!(config.hot_int(Hot::MaxRequestBodySize, 7), 12);
        assert_eq!(config.hot_int(Hot::Http3Port, 7), 7);
        assert!(config.hot_bool(Hot::ClosestMatchHintEnabled, true));
        assert!(!config.hot_bool(Hot::TransparentProxyEnabled, false));
        assert!(!config.read_hot(Hot::ProxyPass, |v| v.is_some()));
        let shared = config.clone();
        config.set_runtime("closestMatchHintEnabled", "false".into());
        config.set_runtime("transparentProxyEnabled", "true".into());
        config.set_runtime("metricsEnabled", "no".into());
        config.set_runtime("proxyPass", "[]".into());
        config.set_runtime("http3Port", "9".into());
        for config in [&config, &shared] {
            assert!(!config.hot_bool(Hot::ClosestMatchHintEnabled, true));
            assert!(config.hot_bool(Hot::TransparentProxyEnabled, false));
            assert!(!config.hot_bool(Hot::MetricsEnabled, true));
            assert_eq!(config.read_hot(Hot::ProxyPass, |v| v.map(str::to_string)).as_deref(), Some("[]"));
            assert_eq!(config.hot_int(Hot::Http3Port, 7), 9);
        }
    }

    /// `Main`: `proxyRemotePort`/`proxyRemoteHost` resolve like `serverPort` — command line, then the
    /// `mockserver.*` system property, then `MOCKSERVER_PROXY_REMOTE_*`, then `PROXY_REMOTE_*` (the
    /// docker_compose_remote_host_and_port_by_environment_variable container case).
    #[test]
    fn port_forwarding_from_the_environment() {
        assert_eq!(config_from(&[], &[("SERVER_PORT", "1234"), ("PROXY_REMOTE_HOST", "target"), ("PROXY_REMOTE_PORT", "4567")]).port_forward, Some(("target".into(), 4567)));
        assert_eq!(config_from(&[], &[("SERVER_PORT", "1234"), ("MOCKSERVER_PROXY_REMOTE_PORT", "4567"), ("PROXY_REMOTE_PORT", "1")]).port_forward, Some(("localhost".into(), 4567)));
        assert_eq!(config_from(&["-Dmockserver.proxyRemotePort=99"], &[("SERVER_PORT", "1234"), ("PROXY_REMOTE_PORT", "1")]).port_forward, Some(("localhost".into(), 99)));
        assert_eq!(config_from(&["-proxyRemotePort", "7"], &[("SERVER_PORT", "1234"), ("PROXY_REMOTE_PORT", "1"), ("PROXY_REMOTE_HOST", "h")]).port_forward, Some(("h".into(), 7)));
        assert_eq!(config_from(&[], &[("SERVER_PORT", "1234"), ("PROXY_REMOTE_HOST", "target")]).port_forward, None);
        // blank values drop out before precedence
        assert_eq!(config_from(&[], &[("SERVER_PORT", "1234"), ("MOCKSERVER_PROXY_REMOTE_PORT", " "), ("PROXY_REMOTE_PORT", "4567")]).port_forward, Some(("localhost".into(), 4567)));
        assert_eq!(config_from(&["-Dmockserver.serverPort="], &[("MOCKSERVER_SERVER_PORT", ""), ("SERVER_PORT", "1234")]).ports, vec![1234]);
    }

    /// `Main`: standalone launch (this binary) auto-enables `proxySetupLogging` unless the user configured it
    /// themselves in any source, matching `MainCliTest.explicitProxySetupLoggingFalseIsPreservedByStandaloneLauncher`
    ///. `src/server.rs`'s own `bool_property` fallback stays `false` for embedded `Server::start`
    /// callers that never go through this parser.
    #[test]
    fn proxy_setup_logging_defaults_to_true_unless_configured() {
        assert_eq!(config_from(&["-serverPort", "0"], &[]).property("proxySetupLogging"), Some("true".into()));
        // explicit -D opt-out is preserved
        assert_eq!(
            config_from(&["-serverPort", "0", "-Dmockserver.proxySetupLogging=false"], &[]).property("proxySetupLogging"),
            Some("false".into())
        );
        // explicit env-var opt-out is preserved
        assert_eq!(
            config_from(&["-serverPort", "0"], &[("MOCKSERVER_PROXY_SETUP_LOGGING", "false")]).property("proxySetupLogging"),
            Some("false".into())
        );
        // explicit true is a no-op, not a second insertion
        assert_eq!(
            config_from(&["-serverPort", "0", "-Dmockserver.proxySetupLogging=true"], &[]).property("proxySetupLogging"),
            Some("true".into())
        );
    }

    fn print_config_from(args: &[&str], env: &[(&str, &str)]) -> super::Config {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        super::Config::for_print_config(&args, env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())
    }

    fn resolved(config: &super::Config, name: &str) -> (String, &'static str) {
        let row = config.effective_configuration().into_iter().find(|p| p.name == name).unwrap();
        (row.value, row.source)
    }

    /// `ConfigurationPropertiesEffectiveConfigTest`: system property, then properties file, then environment variable,
    /// then the default; blank tier values drop out; one pair of surrounding quotes is stripped.
    #[test]
    fn effective_configuration_source_precedence() {
        let name = "mockserver.maxExpectations";
        let sys = print_config_from(&["-Dmockserver.maxExpectations=sys"], &[("MOCKSERVER_MAX_EXPECTATIONS", "env")]);
        assert_eq!(resolved(&sys, name), ("sys".into(), "system-property"));
        let env = print_config_from(&[], &[("MOCKSERVER_MAX_EXPECTATIONS", "env")]);
        assert_eq!(resolved(&env, name), ("env".into(), "environment-variable"));
        let mut file = print_config_from(&[], &[("MOCKSERVER_MAX_EXPECTATIONS", "env")]);
        file.file_properties.insert(name.into(), "file".into());
        file.sources_changed();
        assert_eq!(resolved(&file, name), ("file".into(), "properties-file"));
        let none = print_config_from(&[], &[]);
        // the built-in default the oracle reports (`effective_config_tiers`: `"default":"15000"`)
        assert_eq!(resolved(&none, name), ("15000".into(), "default"));
        let blank = print_config_from(&["-Dmockserver.maxExpectations=  "], &[("MOCKSERVER_MAX_EXPECTATIONS", "env")]);
        assert_eq!(resolved(&blank, name), ("env".into(), "environment-variable"));
        let quoted = print_config_from(&["-Dmockserver.maxExpectations=\"quoted\""], &[]);
        assert_eq!(resolved(&quoted, name), ("quoted".into(), "system-property"));
        let lone_quote = print_config_from(&["-Dmockserver.maxExpectations=\""], &[]);
        assert_eq!(resolved(&lone_quote, name), (String::new(), "system-property"));
    }

    /// The text and JSON forms redact like `GET /mockserver/configuration` and never print a credential.
    #[test]
    fn effective_configuration_renders_redacted_text_and_json() {
        let config = print_config_from(&["-Dmockserver.llmApiKey=do-not-print-me", "-Dmockserver.maxExpectations=777"], &[]);
        let text = config.effective_configuration_text();
        assert!(text.starts_with("MockServer effective configuration (value and the source that supplied it):\n"));
        assert!(text.contains("  mockserver.maxExpectations = 777   [system-property]   (default: 15000)\n"));
        assert!(text.contains("  mockserver.llmApiKey = ***REDACTED***   [system-property]   (default: ***REDACTED***)\n"));
        assert!(text.contains("  mockserver.metricsEnabled = false   [default]\n"));
        let json = config.effective_configuration_json(false);
        assert!(json.contains("{\"name\":\"mockserver.llmApiKey\",\"value\":\"***REDACTED***\",\"source\":\"system-property\",\"default\":\"***REDACTED***\"}"));
        let non_default = config.effective_configuration_json(true);
        assert!(non_default.contains("\"mockserver.maxExpectations\"") && !non_default.contains("\"mockserver.metricsEnabled\""));
        assert!(!text.contains("do-not-print-me") && !json.contains("do-not-print-me"));
    }

    /// `ConfigurationPropertiesRedactionTest.shouldRedactEveryCredentialShapedPropertyOnTheRealSurface`, over the
    /// recognised-property table: every credential-shaped name is masked unless documented as a non-credential.
    #[test]
    fn every_credential_shaped_property_on_the_real_surface_is_redacted() {
        const KNOWN_NON_CREDENTIALS: &[&str] = &[
            "forwardconnectionpoolmaxidleperkey",
            "forwardconnectionpoolmaxtotalperkey",
            "corsallowcredentials",
            "redactsecretsinlog",
            "redactsecretsinrecordedexpectations",
            "dataplaneapikeyauthenticationheader",
        ];
        let names = super::recognised_properties();
        assert!(names.len() > 100, "the property table must be the real surface");
        let looks_like_credential = |bare: &str| {
            ["key", "token", "secret", "password", "passphrase", "credential", "credentials"].iter().any(|s| bare.ends_with(s))
                || ["apikey", "accesskey", "privatekey", "connectionstring"].iter().any(|s| bare.contains(s))
        };
        let unredacted: Vec<&str> = names
            .iter()
            .map(|(name, _)| *name)
            .filter(|name| {
                let bare = name.trim_start_matches("mockserver.").to_ascii_lowercase();
                !KNOWN_NON_CREDENTIALS.contains(&bare.as_str()) && looks_like_credential(&bare) && !super::credentials::is_sensitive_property_name(name)
            })
            .collect();
        assert!(unredacted.is_empty(), "credential-shaped properties that are not redacted: {unredacted:?}");
    }

    #[test]
    fn properties_files_unescape_like_java() {
        let parsed = super::parse_properties("a.b=\"\\\"x\\\"\"\nc=line\\nbreak \\u0041\\\\\n# comment\n");
        assert_eq!(parsed["a.b"], "\"\"x\"\"");
        assert_eq!(parsed["c"], "line\nbreak A\\");
    }
}

/// `HttpState.warnIfLoweringTlsPosture`: what a `PUT /mockserver/configuration` update (already parsed, before it is
/// applied) does to the TLS posture, one phrase per change, in upstream's order. The comparison is against the
/// configuration in force, earlier updates included (upstream 0e8566814). The 8.0.0 process compared with
/// its startup copy, which the handler's updates never reached.
pub fn tls_posture_changes(config: &Config, update: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    use serde_json::Value;
    let mut lowered = Vec::new();
    let supplied_text = |name: &str| -> Option<String> {
        match update.get(name)? {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    };
    let supplied_false = |name: &str| matches!(update.get(name).and_then(|v| coerce_update(name, v, &Value::Bool(false)).ok().flatten()).as_deref(), Some("false"));
    let started = |name: &str, default: &str| config.property(name).unwrap_or_else(|| default.to_string());

    if supplied_text("forwardProxyTLSX509CertificatesTrustManagerType").is_some_and(|t| t.eq_ignore_ascii_case("ANY")) {
        let current = started("forwardProxyTLSX509CertificatesTrustManagerType", "ANY");
        let current = match current.trim() {
            valid @ ("ANY" | "JVM" | "CUSTOM") => valid.to_string(),
            // the enum lookup fails and upstream reads that as no value
            _ => "null".to_string(),
        };
        if current != "ANY" {
            lowered.push(format!("forwardProxyTLSX509CertificatesTrustManagerType {current} -> ANY (upstream certificate validation disabled)"));
        }
    }
    if supplied_false("tlsMutualAuthenticationRequired") && config.hot_bool(crate::config::Hot::TlsMutualAuthenticationRequired, false) {
        lowered.push("tlsMutualAuthenticationRequired true -> false (client certificate no longer required)".to_string());
    }
    if supplied_false("forwardProxyTLSHostnameVerificationEnabled") && config.bool_property("forwardProxyTLSHostnameVerificationEnabled", true) {
        lowered.push("forwardProxyTLSHostnameVerificationEnabled true -> false (upstream host name no longer verified)".to_string());
    }
    for (name, default) in [
        ("privateKeyPath", ""),
        ("x509CertificatePath", ""),
        ("certificateAuthorityCertificate", "org/mockserver/socket/CertificateAuthorityCertificate.pem"),
        ("certificateAuthorityPrivateKey", "org/mockserver/socket/PKCS8CertificateAuthorityPrivateKey.pem"),
        ("tlsMutualAuthenticationCertificateChain", ""),
    ] {
        if let Some(new) = supplied_text(name) {
            let old = started(name, default);
            if new != old {
                lowered.push(format!("{name} repointed (\"{old}\" -> \"{new}\")"));
            }
        }
    }
    lowered
}

#[cfg(test)]
mod scope_mapping_and_posture_tests {
    use super::*;
    use serde_json::json;

    fn update(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn scope_mapping_update_reads_roles_like_the_oracle() {
        let d = json!({});
        let name = "controlPlaneScopeMapping";
        let held = |v: serde_json::Value| coerce_update(name, &v, &d).unwrap().and_then(|text| optional_value(OptionalKind::ScopeMapping, &text));
        assert_eq!(held(json!({"a": "admin", "b": " Mutate ", "c": "superuser", "d": ""})), Some(json!({"a": "ADMIN", "b": "MUTATE"})));
        assert_eq!(held(json!({"a": 0, "b": 1, "c": 2, "d": 3, "e": -1})), Some(json!({"a": "READ", "b": "MUTATE", "c": "ADMIN"})));
        assert_eq!(held(json!({"a": null, "b": "read"})), Some(json!({"b": "READ"})));
        assert_eq!(held(json!({"": "admin"})), Some(json!({"": "ADMIN"})));
        assert_eq!(held(json!({})), None);
        assert_eq!(coerce_update(name, &json!(""), &d), Ok(None));
        for refused in [json!({"a": 1.5}), json!({"a": true}), json!({"a": {"x": 1}}), json!({"a": ["x"]}), json!(5), json!(["a=admin"]), json!("a=admin")] {
            assert_eq!(coerce_update(name, &refused, &d), Err(()), "{refused}");
        }
    }

    #[test]
    fn scope_mapping_text_is_parsed_fail_closed() {
        let parsed = |text: &str| optional_value(OptionalKind::ScopeMapping, text);
        assert_eq!(parsed("platform-admins=admin,qa-team=Mutate, viewers = read "), Some(json!({"platform-admins": "ADMIN", "qa-team": "MUTATE", "viewers": "READ"})));
        assert_eq!(parsed("ops=superuser,bare-scope,=admin,trailing="), None);
        assert_eq!(parsed("ops=superuser,viewers=read"), Some(json!({"viewers": "READ"})));
        assert_eq!(parsed("viewers=read,viewers=mutate"), Some(json!({"viewers": "MUTATE"})));
        assert_eq!(parsed(""), None);
    }

    #[test]
    fn posture_is_compared_with_the_configuration_in_force() {
        let config = Config::default();
        // the defaults (trust ANY, no mutual TLS, host names verified): only the host name check can be lowered
        let lowered = tls_posture_changes(&config, &update(json!({
            "forwardProxyTLSX509CertificatesTrustManagerType": "ANY",
            "tlsMutualAuthenticationRequired": false,
            "forwardProxyTLSHostnameVerificationEnabled": false,
            "privateKeyPath": "",
            "certificateAuthorityPrivateKey": "zzz",
        })));
        assert_eq!(lowered, vec![
            "forwardProxyTLSHostnameVerificationEnabled true -> false (upstream host name no longer verified)".to_string(),
            "certificateAuthorityPrivateKey repointed (\"org/mockserver/socket/PKCS8CertificateAuthorityPrivateKey.pem\" -> \"zzz\")".to_string(),
        ]);
        // an update that is not a downgrade, or restores the value in force, says nothing
        assert!(tls_posture_changes(&config, &update(json!({"forwardProxyTLSHostnameVerificationEnabled": true, "tlsMutualAuthenticationRequired": true, "x509CertificatePath": ""}))).is_empty());
        // runtime changes move the baseline (one configuration, upstream 0e8566814)
        config.set_runtime("forwardProxyTLSX509CertificatesTrustManagerType", "JVM".into());
        assert_eq!(tls_posture_changes(&config, &update(json!({"forwardProxyTLSX509CertificatesTrustManagerType": "ANY"}))), vec![
            "forwardProxyTLSX509CertificatesTrustManagerType JVM -> ANY (upstream certificate validation disabled)".to_string(),
        ]);
        config.set_runtime("tlsMutualAuthenticationRequired", "true".into());
        assert_eq!(tls_posture_changes(&config, &update(json!({"tlsMutualAuthenticationRequired": false}))).len(), 1);
    }
}

#[cfg(test)]
mod dto_coercion_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn booleans_follow_jackson() {
        let d = json!(false);
        assert_eq!(coerce_update("x", &json!("TRUE"), &d), Ok(Some("true".into())));
        assert_eq!(coerce_update("x", &json!(0), &d), Ok(Some("false".into())));
        assert_eq!(coerce_update("x", &json!(2), &d), Ok(Some("true".into())));
        assert_eq!(coerce_update("x", &json!(""), &d), Ok(None));
        assert_eq!(coerce_update("x", &json!(null), &d), Ok(None));
        assert_eq!(coerce_update("x", &json!("yes"), &d), Err(()));
        assert_eq!(coerce_update("x", &json!(1.5), &d), Err(()));
        assert_eq!(coerce_update("x", &json!([true]), &d), Err(()));
    }

    #[test]
    fn integers_are_32_bit_longs_are_64_bit() {
        let d = json!(0);
        assert_eq!(coerce_update("corsMaxAgeInSeconds", &json!(2147483647), &d), Ok(Some("2147483647".into())));
        assert_eq!(coerce_update("corsMaxAgeInSeconds", &json!(2147483648u64), &d), Err(()));
        assert_eq!(coerce_update("stopDrainMillis", &json!(2147483648u64), &d), Ok(Some("2147483648".into())));
        assert_eq!(coerce_update("stopDrainMillis", &json!(u64::MAX), &d), Err(()));
        assert_eq!(coerce_update("corsMaxAgeInSeconds", &json!(1.9), &d), Ok(Some("1".into())));
        assert_eq!(coerce_update("corsMaxAgeInSeconds", &json!(" 5 "), &d), Ok(Some("5".into())));
        assert_eq!(coerce_update("corsMaxAgeInSeconds", &json!("1.5"), &d), Err(()));
        assert_eq!(coerce_update("http3AltSvcMaxAge", &json!(-1), &d), Ok(Some("0".into())));
        assert_eq!(coerce_update("otelMetricsExportIntervalSeconds", &json!(0), &d), Ok(Some("1".into())));
    }

    #[test]
    fn lists_keep_their_elements_whole() {
        let d = json!(["a"]);
        assert_eq!(coerce_update("sslSubjectAlternativeNameIps", &json!(["x", "y", "x"]), &d), Ok(Some(r#"["x","y"]"#.into())));
        // a null element is held; the SAN sets refuse it when the update is applied
        assert_eq!(coerce_update("sslSubjectAlternativeNameIps", &json!(["x", null]), &d), Ok(Some(r#"["x",null]"#.into())));
        assert_eq!(coerce_update("loadGenerationMetricLabels", &json!(["a", null, "a,b"]), &d), Ok(Some(r#"["a",null,"a,b"]"#.into())));
        assert_eq!(coerce_update("loadGenerationMetricLabels", &json!("a,b"), &d), Ok(Some(r#"["a,b"]"#.into())));
        assert_eq!(coerce_update("loadGenerationMetricLabels", &json!([1, 2]), &d), Ok(Some(r#"["1","2"]"#.into())));
        assert_eq!(coerce_update("loadGenerationMetricLabels", &json!({"a": 1}), &d), Err(()));
    }

    #[test]
    fn a_hash_set_iterates_by_bucket() {
        let order = |names: &[&str]| java_hash_order(&names.iter().map(|n| json!(n)).collect::<Vec<_>>());
        // the oracle's defaults: "0.0.0.0" sorts ahead of "127.0.0.1" although the code lists them the other way round
        assert_eq!(order(&["127.0.0.1", "0.0.0.0"]), vec![json!("0.0.0.0"), json!("127.0.0.1")]);
        assert_eq!(order(&["10.0.0.1", "1.2.3.4", "5.6.7.8", "1.2.3.4"]), vec![json!("1.2.3.4"), json!("5.6.7.8"), json!("10.0.0.1")]);
    }

    #[test]
    fn ring_buffer_rounds_up() {
        assert_eq!(next_power_of_two(0), 1);
        assert_eq!(next_power_of_two(5), 8);
        assert_eq!(next_power_of_two(1024), 1024);
        assert_eq!(next_power_of_two(16391), 32768);
    }
}
