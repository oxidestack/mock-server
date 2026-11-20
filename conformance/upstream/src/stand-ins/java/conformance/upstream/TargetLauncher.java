package conformance.upstream;

import io.github.oxidestack.mockserver.launcher.ServerLauncher;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Starts the servers behind the launcher's process-backed {@code MockServer} and {@code ClientAndServer}
 * (java-launcher/) as the {@code -Dtarget} process, through {@link ServerProcess#launch}, so they are
 * logged per test class and stopped by {@link UpstreamRunner}. Registered in
 * {@code META-INF/services/io.github.oxidestack.mockserver.launcher.ServerLauncher}.
 */
public final class TargetLauncher implements ServerLauncher {

    @Override
    public Process launch(List<Integer> ports, Map<String, String> properties, String remoteHost, Integer remotePort) {
        return ServerProcess.launch(new ArrayList<>(ports), properties, remoteHost, remotePort);
    }

    @Override
    public String describe() {
        return TargetServer.target();
    }
}
