package org.mockserver.integration;

import org.mockserver.client.MockServerClient;
import org.mockserver.configuration.Configuration;
import org.mockserver.lifecycle.ExpectationsListener;
import org.mockserver.log.model.LogEntry;
import org.mockserver.netty.MockServer;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import static org.mockserver.configuration.ClientConfiguration.clientConfiguration;
import static org.mockserver.configuration.Configuration.configuration;

/**
 * MockServer 9.2.0's {@code ClientAndServer}: the same API, with the server started as a separate process by
 * the process-backed {@link MockServer}.
 */
public class ClientAndServer extends MockServerClient {

    public static ClientAndServer startClientAndServer(List<Integer> ports) {
        return startClientAndServer(ports.toArray(new Integer[0]));
    }

    public static ClientAndServer startClientAndServer(Configuration configuration, List<Integer> ports) {
        return startClientAndServer(configuration, ports.toArray(new Integer[0]));
    }

    public static ClientAndServer startClientAndServer(Integer... port) {
        return new ClientAndServer(null, null, null, port);
    }

    public static ClientAndServer startClientAndServer(Configuration configuration, Integer... port) {
        return new ClientAndServer(configuration, port);
    }

    public static ClientAndServer startClientAndServer(String remoteHost, Integer remotePort, Integer... port) {
        return new ClientAndServer(null, remoteHost, remotePort, port);
    }

    public static ClientAndServer startClientAndServer(Configuration configuration, String remoteHost, Integer remotePort, Integer... port) {
        return new ClientAndServer(configuration, remoteHost, remotePort, port);
    }

    private final MockServer mockServer;

    public ClientAndServer(Integer... ports) {
        this(null, null, null, ports);
    }

    public ClientAndServer(Configuration configuration, Integer... ports) {
        this(configuration, null, null, ports);
    }

    public ClientAndServer(String remoteHost, Integer remotePort, Integer... ports) {
        this(null, remoteHost, remotePort, ports);
    }

    public ClientAndServer(Configuration configuration, String remoteHost, Integer remotePort, Integer... ports) {
        super(clientConfiguration(configuration != null ? configuration : configuration()), new CompletableFuture<>());
        this.mockServer = remotePort != null
            ? new MockServer(configuration, remotePort, remoteHost, ports)
            : new MockServer(configuration, ports);
        portFuture.complete(mockServer.getLocalPort());
    }

    @Override
    public ClientAndServer openUI() {
        return this;
    }

    @Override
    public ClientAndServer openUI(TimeUnit timeUnit, long pause) {
        return this;
    }

    public boolean isRunning() {
        return mockServer.isRunning();
    }

    public boolean hasStarted() {
        return mockServer.isRunning();
    }

    @Override
    @SuppressWarnings({"rawtypes", "unchecked"})
    public CompletableFuture stopAsync() {
        return mockServer.stopAsync().thenComposeAsync(s -> stop(true));
    }

    @Override
    public void stop() {
        mockServer.stop();
        super.stop();
    }

    public Integer getPort() {
        return mockServer.getLocalPort();
    }

    public Integer getLocalPort() {
        return mockServer.getLocalPort();
    }

    public List<Integer> getLocalPorts() {
        return mockServer.getLocalPorts();
    }

    /** The DNS listener's UDP port, or -1 if DNS mocking ({@code dnsEnabled}) is not on. */
    public int getDnsPort() {
        return mockServer.getDnsPort();
    }

    public InetSocketAddress getRemoteAddress() {
        return mockServer.getRemoteAddress();
    }

    public ClientAndServer registerListener(ExpectationsListener expectationsListener) {
        mockServer.registerListener(expectationsListener);
        return this;
    }

    public static void setLogEventListener(Consumer<LogEntry> listener) {
        throw new UnsupportedOperationException("in-JVM: ClientAndServer.setLogEventListener observes the server's log");
    }
}
