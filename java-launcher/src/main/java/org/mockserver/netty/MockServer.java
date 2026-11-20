package org.mockserver.netty;

import io.github.oxidestack.mockserver.launcher.DnsStartFailure;
import io.github.oxidestack.mockserver.launcher.MockServerProcess;
import org.mockserver.configuration.Configuration;
import org.mockserver.configuration.ConfigurationProperties;
import org.mockserver.lifecycle.LifeCycle;
import org.mockserver.netty.dns.DnsStartupException;
import org.mockserver.proxyconfiguration.ProxyConfiguration;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * MockServer 9.2.0's {@code org.mockserver.netty.MockServer} over a separate server process: the mock-server
 * binary by default ({@link io.github.oxidestack.mockserver.launcher.BinaryLauncher}), so upstream's {@code ClientAndServer}, JUnit
 * rule, JUnit 5 extension, Spring test listener and Spring Boot starter run unchanged with this jar in place of
 * {@code mockserver-netty} (it began as conformance/upstream's stand-in).
 * Constructors start the process with this JVM's {@code mockserver.*} system properties (what
 * {@code ConfigurationProperties} setters write) plus every field set on the {@link Configuration} passed in.
 * It is a {@link LifeCycle} so code written against upstream compiles against it, but that in-JVM state never sees
 * traffic: methods that read the server's internals throw {@link UnsupportedOperationException}.
 */
public class MockServer extends LifeCycle {

    private final MockServerProcess process;
    private final InetSocketAddress remoteSocket;
    private final Map<String, String> properties;

    public MockServer(final Integer... localPorts) {
        this(null, (List<ProxyConfiguration>) null, localPorts);
    }

    public MockServer(final Configuration configuration, final Integer... localPorts) {
        this(configuration, (List<ProxyConfiguration>) null, localPorts);
    }

    public MockServer(final ProxyConfiguration proxyConfiguration, final Integer... localPorts) {
        this(null, List.of(proxyConfiguration), localPorts);
    }

    public MockServer(final Configuration configuration, final List<ProxyConfiguration> proxyConfigurations, final Integer... localPorts) {
        this(configuration, proxyConfigurations, null, null, localPorts);
    }

    public MockServer(final Integer remotePort, final String remoteHost, final Integer... localPorts) {
        this(null, (List<ProxyConfiguration>) null, remoteHost, remotePort, localPorts);
    }

    public MockServer(final Configuration configuration, final Integer remotePort, final String remoteHost, final Integer... localPorts) {
        this(configuration, (List<ProxyConfiguration>) null, remoteHost, remotePort, localPorts);
    }

    public MockServer(final Configuration configuration, final ProxyConfiguration proxyConfiguration, final String remoteHost, final Integer remotePort, final Integer... localPorts) {
        this(configuration, List.of(proxyConfiguration), remoteHost, remotePort, localPorts);
    }

    public MockServer(final Configuration configuration, final List<ProxyConfiguration> proxyConfigurations, String remoteHost, final Integer remotePort, final Integer... localPorts) {
        super(configuration);
        if (remotePort != null && (remoteHost == null || remoteHost.isBlank())) {
            remoteHost = "localhost";
        }
        this.remoteSocket = remotePort != null ? new InetSocketAddress(remoteHost, remotePort) : null;
        Map<String, String> properties = systemProperties();
        properties.putAll(configurationProperties(configuration));
        properties.putAll(proxyProperties(proxyConfigurations));
        this.properties = properties;
        try {
            this.process = MockServerProcess.start(localPorts == null ? List.of() : Arrays.asList(localPorts), properties, remoteHost, remotePort);
        } catch (MockServerProcess.StartFailure failure) {
            // upstream's constructor fails with DnsStartupException when the DNS listener cannot start
            DnsStartupException dns = DnsStartFailure.of(failure);
            throw dns != null ? dns : failure;
        }
    }

    /** What {@code ConfigurationProperties} setters left in the test JVM, as the in-JVM server would read it. */
    private static Map<String, String> systemProperties() {
        Map<String, String> properties = new LinkedHashMap<>();
        System.getProperties().stringPropertyNames().stream().sorted().forEach(name -> {
            if (name.startsWith("mockserver.")) {
                properties.put(name.substring("mockserver.".length()), System.getProperty(name));
            }
        });
        return properties;
    }

    /**
     * Every field of {@code configuration} that differs from a fresh {@link Configuration}, as the system properties
     * upstream's own {@code ConfigurationProperties.<field>(value)} setter writes for it (field and property names
     * differ, e.g. {@code proxyPassMappings} is {@code mockserver.proxyPass} as JSON). The test JVM's properties
     * are restored afterwards.
     */
    private static Map<String, String> configurationProperties(Configuration configuration) {
        Map<String, String> properties = new LinkedHashMap<>();
        if (configuration == null) {
            return properties;
        }
        Configuration defaults = new Configuration();
        for (Field field : Configuration.class.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers()) || derived(field)) {
                continue;
            }
            try {
                field.setAccessible(true);
                Object value = field.get(configuration);
                if (value == null || Objects.equals(value, field.get(defaults))) {
                    continue;
                }
                Map<String, String> written = viaConfigurationProperties(field.getName(), value);
                if (written == null) {
                    String text = propertyValue(value);
                    if (text == null) {
                        throw new UnsupportedOperationException("in-JVM: Configuration." + field.getName() + " (" + value.getClass().getName() + ") cannot be passed to a server process");
                    }
                    written = Map.of(field.getName(), text);
                }
                properties.putAll(written);
            } catch (IllegalAccessException e) {
                throw new IllegalStateException(e);
            }
        }
        return properties;
    }

    /** Bookkeeping fields of master's Configuration that count its own updates rather than hold a setting. */
    private static final java.util.Set<String> DERIVED_FIELDS = java.util.Set.of("deferredSnapshotPublications", "completedAtomicUpdates");

    /**
     * Whether {@code field} holds state Configuration derives from its settings rather than a setting: its memos
     * (its own nested types: ResolvedLogLevel, ResolvedDefault, ...), the published snapshots of the server TLS and
     * control-plane authentication settings, change counters and the dynamic SAN insertion order.
     */
    private static boolean derived(Field field) {
        Class<?> type = field.getType();
        return type.getDeclaringClass() == Configuration.class || DERIVED_FIELDS.contains(field.getName())
            || type.getSimpleName().equals("ServerTlsSettings") || type.getSimpleName().equals("ControlPlaneAuthenticationSettings")
            || java.util.concurrent.atomic.AtomicLong.class.isAssignableFrom(type) || java.util.Deque.class.isAssignableFrom(type);
    }

    /** Configuration fields whose getter falls back to a differently named ConfigurationProperties getter. */
    private static final Map<String, String> SETTER_ALIASES = Map.of(
        "maxFutureTimeoutInMillis", "maxFutureTimeout",
        "maxSocketTimeoutInMillis", "maxSocketTimeout",
        "proxyPassMappings", "proxyPass",
        "socketConnectionTimeoutInMillis", "socketConnectionTimeout");

    /** The mockserver.* system properties {@code ConfigurationProperties.<name>(value)} writes, or null without such a setter. */
    private static Map<String, String> viaConfigurationProperties(String field, Object value) {
        String name = SETTER_ALIASES.getOrDefault(field, field);
        if (value instanceof InetSocketAddress) {
            // the InetSocketAddress setters write toString() ("host/<unresolved>:port"), which the server rejects
            value = propertyValue(value);
        }
        Method setter = null;
        for (Method m : ConfigurationProperties.class.getMethods()) {
            if (m.getName().equals(name) && Modifier.isStatic(m.getModifiers()) && m.getParameterCount() == 1
                && wrap(m.getParameterTypes()[0]).isInstance(value)) {
                setter = m;
                break;
            }
        }
        if (setter == null) {
            return null;
        }
        Map<String, String> before = mockserverSystemProperties();
        Map<String, String> written = new LinkedHashMap<>();
        try {
            setter.invoke(null, value);
            Map<String, String> after = mockserverSystemProperties();
            after.forEach((k, v) -> {
                if (!v.equals(before.get(k))) {
                    written.put(k.substring("mockserver.".length()), v);
                }
            });
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("ConfigurationProperties." + name, e);
        } finally {
            restore(before);
        }
        return written;
    }

    private static Map<String, String> mockserverSystemProperties() {
        Map<String, String> properties = new LinkedHashMap<>();
        for (String name : System.getProperties().stringPropertyNames()) {
            if (name.startsWith("mockserver.")) {
                properties.put(name, System.getProperty(name));
            }
        }
        return properties;
    }

    /** Puts the test JVM's mockserver.* properties (and ConfigurationProperties' cache) back as they were. */
    private static void restore(Map<String, String> before) {
        try {
            Method set = ConfigurationProperties.class.getDeclaredMethod("setProperty", String.class, String.class);
            Method clear = ConfigurationProperties.class.getDeclaredMethod("clearProperty", String.class);
            set.setAccessible(true);
            clear.setAccessible(true);
            for (Map.Entry<String, String> now : mockserverSystemProperties().entrySet()) {
                String old = before.get(now.getKey());
                if (old == null) {
                    clear.invoke(null, now.getKey());
                } else if (!old.equals(now.getValue())) {
                    set.invoke(null, now.getKey(), old);
                }
            }
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Class<?> wrap(Class<?> type) {
        if (!type.isPrimitive()) {
            return type;
        }
        return type == boolean.class ? Boolean.class : type == int.class ? Integer.class : type == long.class ? Long.class
            : type == double.class ? Double.class : type == float.class ? Float.class : type == short.class ? Short.class
            : type == byte.class ? Byte.class : Character.class;
    }

    private static String propertyValue(Object value) {
        if (value instanceof String || value instanceof Number || value instanceof Boolean || value instanceof Enum) {
            return value instanceof Enum ? ((Enum<?>) value).name() : value.toString();
        }
        if (value instanceof InetSocketAddress) {
            InetSocketAddress address = (InetSocketAddress) value;
            return address.getHostString() + ":" + address.getPort();
        }
        if (value instanceof Collection) {
            List<String> items = new java.util.ArrayList<>();
            for (Object item : (Collection<?>) value) {
                String text = propertyValue(item);
                if (text == null) {
                    return null;
                }
                items.add(text);
            }
            return String.join(",", items);
        }
        return null;
    }

    private static Map<String, String> proxyProperties(List<ProxyConfiguration> proxyConfigurations) {
        Map<String, String> properties = new LinkedHashMap<>();
        if (proxyConfigurations == null) {
            return properties;
        }
        for (ProxyConfiguration proxy : proxyConfigurations) {
            String name;
            switch (proxy.getType()) {
                case HTTP:
                    name = "forwardHttpProxy";
                    break;
                case HTTPS:
                    name = "forwardHttpsProxy";
                    break;
                default:
                    name = "forwardSocksProxy";
                    break;
            }
            properties.put(name, propertyValue(proxy.getProxyAddress()));
            if (proxy.getUsername() != null) {
                properties.put("forwardProxyAuthenticationUsername", proxy.getUsername());
            }
            if (proxy.getPassword() != null) {
                properties.put("forwardProxyAuthenticationPassword", proxy.getPassword());
            }
        }
        return properties;
    }

    private static UnsupportedOperationException inJvm(String method) {
        return new UnsupportedOperationException("in-JVM: MockServer." + method + " reads the server's internals");
    }

    public InetSocketAddress getRemoteAddress() {
        return remoteSocket;
    }

    @Override
    public MockServer registerListener(org.mockserver.lifecycle.ExpectationsListener listener) {
        throw inJvm("registerListener");
    }

    @Override
    public boolean isRunning() {
        return process.isAlive();
    }

    @Override
    public List<Integer> getLocalPorts() {
        return process.isAlive() ? process.boundPorts() : process.ports();
    }

    @Override
    @Deprecated
    public Integer getPort() {
        return getLocalPort();
    }

    @Override
    public int getLocalPort() {
        return process.ports().get(0);
    }

    @Override
    public List<Integer> bindServerPorts(final List<Integer> requestedPortBindings) {
        return process.bind(requestedPortBindings);
    }

    @Override
    public CompletableFuture<String> stopAsync() {
        process.stop();
        return super.stopAsync();
    }

    @Override
    public void stop() {
        process.stop();
        super.stop();
    }

    /**
     * From the process's own {@code GET /mockserver/http3status}, as upstream's handler reports it. The QUIC listener
     * starts after the HTTP port is ready, so with an {@code http3Port} configured this waits up to 10s for it.
     */
    public int getHttp3Port() {
        int configured;
        try {
            configured = Integer.parseInt(properties.getOrDefault("http3Port", "0").trim());
        } catch (NumberFormatException e) {
            configured = 0;
        }
        long deadline = System.currentTimeMillis() + (configured > 0 ? 10_000 : 0);
        while (true) {
            int port = process.http3Status()[0];
            if (port > 0 || System.currentTimeMillis() >= deadline) {
                return port;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return port;
            }
        }
    }

    /** The process's DNS listener port, from its status ({@code dnsPort}), or -1 without DNS mocking. */
    public int getDnsPort() {
        return process.dnsPort();
    }

    /**
     * The inbound TCP connections the server process holds open on its ports (HTTP/3 ones are counted by
     * {@link #getHttp3ActiveConnectionCount()}), read from the operating system's socket table.
     */
    public int getInboundConnectionCount() {
        return process.inboundConnectionCount();
    }

    // Upstream's package-private start-up seams, which its tests override in subclasses. The server process binds its
    // own ports, so these are never called here and an override changes nothing.

    boolean quicNativeAvailable() {
        throw inJvm("quicNativeAvailable");
    }

    boolean dnsPortShadowedOnIpv4(InetSocketAddress listenerAddress) {
        throw inJvm("dnsPortShadowedOnIpv4");
    }

    int nextDnsPortCandidate() {
        throw inJvm("nextDnsPortCandidate");
    }

    public int getHttp3ActiveConnectionCount() {
        return process.http3Status()[1];
    }

    @Override
    public int getRequestsInFlight() {
        throw inJvm("getRequestsInFlight");
    }

    @Override
    public void requestProcessingStarted() {
        throw inJvm("requestProcessingStarted");
    }

    @Override
    public void requestProcessingComplete() {
        throw inJvm("requestProcessingComplete");
    }

    @Override
    public org.mockserver.scheduler.Scheduler getScheduler() {
        throw inJvm("getScheduler");
    }
}
