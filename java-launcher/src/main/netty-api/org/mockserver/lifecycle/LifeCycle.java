package org.mockserver.lifecycle;

import org.mockserver.codec.HeldRequestAccounting;
import org.mockserver.configuration.Configuration;
import org.mockserver.extension.ExtensionRegistry;
import org.mockserver.scheduler.Scheduler;
import org.mockserver.stop.Stoppable;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * The public surface of MockServer 9.2.0's {@code org.mockserver.lifecycle.LifeCycle} (in {@code mockserver-netty},
 * which this jar replaces), without its Netty server: {@code org.mockserver.netty.MockServer} implements it over a
 * server process. Methods that read an in-JVM server's internals throw {@link UnsupportedOperationException}.
 * <p>
 * Its own source root ({@code src/main/netty-api}), because conformance/upstream compiles the launcher's other
 * sources against the real {@code mockserver-netty} jar, whose {@code LifeCycle} must stay in effect there.
 */
public abstract class LifeCycle implements Stoppable {

    protected LifeCycle(Configuration configuration) {
        // the configuration reaches the server process as properties (org.mockserver.netty.MockServer)
    }

    public abstract boolean isRunning();

    public abstract List<Integer> getLocalPorts();

    public abstract int getLocalPort();

    /**
     * @deprecated use getLocalPort instead of getPort
     */
    @Deprecated
    public Integer getPort() {
        return getLocalPort();
    }

    public abstract List<Integer> bindServerPorts(List<Integer> requestedPortBindings);

    public CompletableFuture<String> stopAsync() {
        return CompletableFuture.completedFuture("stopped for port" + (getLocalPorts().size() == 1 ? ": " + getLocalPorts().get(0) : "s: " + getLocalPorts()));
    }

    public void stop() {
    }

    @Override
    public void close() {
        stop();
    }

    public void requestProcessingStarted() {
        throw inJvm("requestProcessingStarted");
    }

    public void requestProcessingComplete() {
        throw inJvm("requestProcessingComplete");
    }

    public int getRequestsInFlight() {
        throw inJvm("getRequestsInFlight");
    }

    public Scheduler getScheduler() {
        throw inJvm("getScheduler");
    }

    public HeldRequestAccounting getHeldRequestAccounting() {
        throw inJvm("getHeldRequestAccounting");
    }

    public ExtensionRegistry getExtensionRegistry() {
        throw inJvm("getExtensionRegistry");
    }

    public LifeCycle registerListener(ExpectationsListener expectationsListener) {
        throw inJvm("registerListener");
    }

    private static UnsupportedOperationException inJvm(String method) {
        return new UnsupportedOperationException("in-JVM: LifeCycle." + method + " reads the server's internals");
    }
}
