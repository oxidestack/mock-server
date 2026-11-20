package io.github.oxidestack.mockserver.launcher;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Starts the server process behind {@code org.mockserver.netty.MockServer}. The default is {@link BinaryLauncher},
 * which runs the mock-server binary; a {@code META-INF/services/io.github.oxidestack.mockserver.launcher.ServerLauncher} entry
 * replaces it (conformance/upstream registers one that also runs MockServer 9.2.0's jar as {@code oracle-process}).
 */
public interface ServerLauncher {

    /**
     * Starts a server listening on {@code ports} (already resolved: none is 0), with each {@code properties} entry
     * as {@code -Dmockserver.<name>=<value>}, proxying to {@code remoteHost:remotePort} when {@code remotePort} is
     * set. Returns as soon as the process runs; {@link MockServerProcess} waits until it is ready.
     */
    Process launch(List<Integer> ports, Map<String, String> properties, String remoteHost, Integer remotePort) throws IOException;

    /**
     * The last of what {@code process} (one this launcher started) wrote, once it has exited, or "" where the
     * launcher keeps none. {@link MockServerProcess} reads it when the server exits before it is ready, to report
     * why (a DNS listener that could not start is upstream's {@code DnsStartupException}).
     */
    default String output(Process process) {
        return "";
    }

    /** What this launcher starts, for error messages ("mock-server", "oracle-process", ...). */
    default String describe() {
        return getClass().getSimpleName();
    }
}
