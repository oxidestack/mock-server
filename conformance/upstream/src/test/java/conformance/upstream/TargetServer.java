package conformance.upstream;

import org.junit.rules.ExternalResource;
import org.mockserver.client.MockServerClient;
import org.mockserver.configuration.ConfigurationProperties;
import org.mockserver.integration.ClientAndServer;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The server under test, chosen by {@code -Dtarget}:
 * <ul>
 *   <li>{@code oracle-jvm}: MockServer 9.2.0 in the test JVM, exactly as upstream's own concrete tests start it;</li>
 *   <li>{@code oracle-process}: MockServer 9.2.0's runnable jar as a separate process;</li>
 *   <li>{@code rs-process}: the mock-server binary as a separate process.</li>
 * </ul>
 * Processes run on the host on a free port, so the suites' loopback echo servers and {@code Host: localhost:port}
 * requests behave as upstream intends (inventory §3). JUnit 4 class rule.
 */
public final class TargetServer extends ExternalResource {

    private final Map<String, String> properties;
    private final String testClass;
    private int port;
    private ServerProcess process;
    private ClientAndServer inJvm;

    private TargetServer(Class<?> testClass, Map<String, String> properties) {
        this.testClass = testClass.getSimpleName();
        this.properties = properties;
    }

    /** A server with default configuration for {@code testClass}. */
    public static TargetServer forClass(Class<?> testClass) {
        return new TargetServer(testClass, new LinkedHashMap<>());
    }

    /** A server started with {@code mockserver.<name>=<value>} properties. */
    public static TargetServer forClass(Class<?> testClass, Map<String, String> properties) {
        return new TargetServer(testClass, new LinkedHashMap<>(properties));
    }

    public static String target() {
        return System.getProperty("target", "oracle-process");
    }

    public int port() {
        return port;
    }

    public MockServerClient client() {
        return new MockServerClient("localhost", port);
    }

    @Override
    protected void before() {
        ServerProcess.owner(testClass);
        if (target().equals("oracle-jvm")) {
            port = ServerProcess.freePort();
            properties.forEach((k, v) -> System.setProperty("mockserver." + k, v));
            ConfigurationProperties.logLevel("WARN");
            inJvm = ClientAndServer.startClientAndServer(port);
            return;
        }
        process = ServerProcess.start(List.of(), properties, null, null);
        port = process.ports().get(0);
    }

    @Override
    protected void after() {
        if (inJvm != null) {
            inJvm.stop();
        }
        if (process != null) {
            process.stop();
        }
    }
}
