package conformance.upstream;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * A server under test running as a separate host process: MockServer 9.2.0's runnable jar ({@code oracle-process})
 * or the mock-server binary ({@code rs-process}), on free ports, with {@code -Dmockserver.<name>=<value>}
 * properties. Every live process is tracked so {@link UpstreamRunner} can stop what a test class left running,
 * including the ones upstream's {@code new MockServer(...)} starts: the launcher's process-backed MockServer
 * (java-launcher/) starts them through {@link #launch}, registered as its {@code ServerLauncher}.
 */
public final class ServerProcess {

    private static final Set<Process> LIVE = ConcurrentHashMap.newKeySet();
    private static final AtomicInteger SEQUENCE = new AtomicInteger();
    private static volatile String owner = "server";
    /** Whether the mock-server binary has been checked for the dashboard bundle, and what is wrong if it lacks it. */
    private static volatile boolean bundleChecked;
    private static volatile String bundleMissing;

    private final Process process;
    private final List<Integer> ports;

    private ServerProcess(Process process, List<Integer> ports) {
        this.process = process;
        this.ports = ports;
    }

    /** Names the log files of processes started from now on (the running test class). */
    public static void owner(String name) {
        owner = name;
    }

    /**
     * Starts the target on {@code requestedPorts} (0 or none = a free port) and waits until
     * {@code PUT /mockserver/status} answers 200. When the target exits before it is ready because another process
     * took a port chosen here (between {@link #freePort} and the target's bind), it is started again on new free
     * ports, up to five times; requested ports are never replaced (as java-launcher's MockServerProcess).
     */
    public static ServerProcess start(List<Integer> requestedPorts, Map<String, String> properties, String remoteHost, Integer remotePort) {
        List<Integer> requested = new ArrayList<>();
        for (Integer p : requestedPorts) {
            requested.add(p == null ? 0 : p);
        }
        if (requested.isEmpty()) {
            requested.add(0);
        }
        for (int attempt = 1; ; attempt++) {
            List<Integer> ports = new ArrayList<>();
            for (Integer p : requested) {
                ports.add(p == 0 ? freePort() : p);
            }
            ServerProcess server = new ServerProcess(launch(ports, properties, remoteHost, remotePort), ports);
            try {
                server.awaitReady();
                return server;
            } catch (IllegalStateException refused) {
                boolean chosenPortTaken = false;
                for (int i = 0; i < ports.size(); i++) {
                    chosenPortTaken |= requested.get(i) == 0 && portTaken(ports.get(i));
                }
                if (server.process.isAlive() || !chosenPortTaken || attempt == 5 || Thread.currentThread().isInterrupted()) {
                    throw refused;
                }
            }
        }
    }

    /** Whether another process holds {@code port}: a localhost connection is answered, or the wildcard bind fails. */
    private static boolean portTaken(int port) {
        for (String host : List.of("127.0.0.1", "::1")) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), 200);
                return true;
            } catch (IOException refused) {
                // nothing listening there
            }
        }
        try (ServerSocket s = new ServerSocket(port)) {
            return false;
        } catch (IOException inUse) {
            return true;
        }
    }

    /**
     * Starts the target on {@code ports} (none is 0) without waiting for it, and tracks the process for
     * {@link #stopAll}. Its command line goes first into a log file named after the running test class.
     */
    public static Process launch(List<Integer> ports, Map<String, String> properties, String remoteHost, Integer remotePort) {
        String portList = ports.stream().map(String::valueOf).collect(Collectors.joining(","));
        List<String> command = new ArrayList<>();
        String target = TargetServer.target();
        switch (target) {
            case "oracle-process":
                command.add(new File(System.getProperty("java.home"), "bin/java").getPath());
                properties.forEach((k, v) -> command.add("-Dmockserver." + k + "=" + v));
                command.add("-cp");
                // sut-cwd: resources the suites make the server load by classpath-relative path; callbackLibs: the
                // callback classes the suites name, after MockServer's own jar so they never shadow it
                // oracle-quic: the QUIC natives the runnable jar of master leaves out (pom.xml, oracle-quic-natives)
                command.add(System.getProperty("oracleJar") + File.pathSeparator + new File(System.getProperty("oracleJar")).getParentFile().getParent() + "/oracle-quic/*"
                    + File.pathSeparator + System.getProperty("sutCwd", ".")
                    + File.pathSeparator + System.getProperty("callbackLibs", ""));
                command.add("org.mockserver.cli.Main");
                command.add("-serverPort");
                command.add(portList);
                break;
            case "rs-process":
                requireDashboardBundle();
                command.add(System.getProperty("mockServerBin"));
                command.add("-serverPort");
                command.add(portList);
                properties.forEach((k, v) -> command.add("-Dmockserver." + k + "=" + v));
                // the Rust counterparts of the callback classes on the oracle's class path (make plugins)
                File plugin = new File(System.getProperty("rsCallbackPlugins", "."), System.mapLibraryName("mock_server_integration_testing_callbacks"));
                if (!properties.containsKey("callbackPlugins") && plugin.isFile()) {
                    command.add("-Dmockserver.callbackPlugins=" + plugin.getPath());
                }
                break;
            default:
                throw new IllegalStateException("no server process for -Dtarget=" + target);
        }
        if (remotePort != null) {
            command.add("-proxyRemotePort");
            command.add(String.valueOf(remotePort));
            if (remoteHost != null && !remoteHost.isEmpty()) {
                command.add("-proxyRemoteHost");
                command.add(remoteHost);
            }
        }
        File logDir = new File(System.getProperty("logDir", "target/server-logs"));
        logDir.mkdirs();
        File log = new File(logDir, owner + "-" + SEQUENCE.incrementAndGet() + ".log");
        try {
            java.nio.file.Files.write(log.toPath(), (String.join(" ", command) + "\n").getBytes(StandardCharsets.UTF_8));
            ProcessBuilder builder = new ProcessBuilder(command)
                .directory(new File(System.getProperty("sutCwd", ".")))
                .redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.appendTo(log));
            withoutProviderCredentials(builder.environment());
            Process process = builder.start();
            LIVE.add(process);
            return process;
        } catch (IOException e) {
            throw new IllegalStateException("could not start " + target, e);
        }
    }

    /**
     * Environment variables through which a server under test could reach a real LLM provider: the ones
     * {@code LlmBackendResolver} reads ({@code OLLAMA_HOST}, {@code OPENAI_API_KEY}, {@code ANTHROPIC_API_KEY},
     * {@code GEMINI_API_KEY}, and the {@code MOCKSERVER_LLM_*} forms of the {@code mockserver.llm*} properties)
     * and the credential families of the other providers. They are removed for every target, so a test (a
     * {@code detect_llm_drift} without a backend, say) never sends a request with the developer's keys.
     */
    static final java.util.List<String> PROVIDER_CREDENTIAL_PREFIXES = java.util.Arrays.asList(
        "OPENAI_", "ANTHROPIC_", "GEMINI_", "GOOGLE_", "AWS_", "MISTRAL_", "AZURE_OPENAI_", "OLLAMA_", "XAI_", "DEEPSEEK_", "GROQ_",
        "OPENROUTER_", "ORCAROUTER_", "COHERE_", "VOYAGE_", "MOCKSERVER_LLM"
    );

    static void withoutProviderCredentials(java.util.Map<String, String> environment) {
        environment.keySet().removeIf(name -> PROVIDER_CREDENTIAL_PREFIXES.stream().anyMatch(name.toUpperCase()::startsWith));
    }

    /**
     * Fails every rs-process start when the binary was built without the dashboard UI bundle: upstream's
     * DashboardRealBundleServedIntegrationTest would only skip (an assumption), hiding the missing bundle. Checked
     * once, on a server of its own with no properties, so no test's configuration affects the answer.
     */
    private static synchronized void requireDashboardBundle() {
        if (!bundleChecked) {
            bundleChecked = true;
            ServerProcess probe = start(new ArrayList<>(), Map.of(), null, null);
            try {
                HttpURLConnection c = (HttpURLConnection) new URL("http://localhost:" + probe.ports.get(0) + "/mockserver/dashboard").openConnection();
                c.setConnectTimeout(2000);
                c.setReadTimeout(10_000);
                if (c.getResponseCode() == 404) {
                    bundleMissing = System.getProperty("mockServerBin") + " has no dashboard UI bundle (GET /mockserver/dashboard"
                        + " answers 404): run `make dashboard`, then `cargo build --release` (make upstream-tests does both)";
                }
            } catch (IOException e) {
                throw new IllegalStateException("GET /mockserver/dashboard failed", e);
            } finally {
                probe.stop();
            }
        }
        if (bundleMissing != null) {
            throw new IllegalStateException(bundleMissing);
        }
    }

    public List<Integer> ports() {
        return ports;
    }

    public boolean isAlive() {
        return process.isAlive();
    }

    /** The ports the server reports as bound ({@code PUT /mockserver/status}), including ones added by bind. */
    public List<Integer> boundPorts() {
        return parsePorts(request("PUT", "/mockserver/status", ""));
    }

    /** {@code PUT /mockserver/bind}; returns the ports actually bound. */
    public List<Integer> bind(List<Integer> requested) {
        String body = "{\"ports\":[" + requested.stream().map(String::valueOf).collect(Collectors.joining(",")) + "]}";
        return parsePorts(request("PUT", "/mockserver/bind", body));
    }

    /** {@code GET /mockserver/http3status}: the live HTTP/3 port (-1 when not running) and active connections. */
    public int[] http3Status() {
        String json = request("GET", "/mockserver/http3status", null);
        return new int[]{number(json, "port"), number(json, "activeConnections")};
    }

    private static int number(String json, String field) {
        Matcher m = Pattern.compile("\"" + field + "\"\\s*:\\s*(-?\\d+)").matcher(json);
        if (!m.find()) {
            throw new IllegalStateException("no " + field + " in " + json);
        }
        return Integer.parseInt(m.group(1));
    }

    public void stop() {
        stop(process);
    }

    private static void stop(Process process) {
        LIVE.remove(process);
        process.destroy();
        try {
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                process.waitFor(10, TimeUnit.SECONDS);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Stops every process still running; called after each test class and at JVM exit. */
    public static void stopAll() {
        for (Process process : new ArrayList<>(LIVE)) {
            stop(process);
        }
    }

    static {
        Runtime.getRuntime().addShutdownHook(new Thread(ServerProcess::stopAll));
    }

    private void awaitReady() {
        long deadline = System.currentTimeMillis() + 60_000;
        while (System.currentTimeMillis() < deadline) {
            if (!process.isAlive()) {
                LIVE.remove(process);
                throw new IllegalStateException(TargetServer.target() + " exited with " + process.exitValue() + " before it was ready");
            }
            try {
                HttpURLConnection c = (HttpURLConnection) new URL("http://localhost:" + ports.get(0) + "/mockserver/status").openConnection();
                c.setRequestMethod("PUT");
                c.setConnectTimeout(500);
                c.setReadTimeout(2000);
                if (c.getResponseCode() == 200) {
                    return;
                }
            } catch (IOException notYet) {
                // not listening yet
            }
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
        stop();
        throw new IllegalStateException(TargetServer.target() + " did not become ready on port " + ports.get(0));
    }

    private String request(String method, String path, String body) {
        try {
            HttpURLConnection c = (HttpURLConnection) new URL("http://localhost:" + ports.get(0) + path).openConnection();
            c.setRequestMethod(method);
            c.setConnectTimeout(2000);
            c.setReadTimeout(10_000);
            if (body != null) {
                c.setDoOutput(true);
                try (OutputStream out = c.getOutputStream()) {
                    out.write(body.getBytes(StandardCharsets.UTF_8));
                }
            }
            int status = c.getResponseCode();
            try (InputStream in = status < 400 ? c.getInputStream() : c.getErrorStream()) {
                String text = in == null ? "" : new String(in.readAllBytes(), StandardCharsets.UTF_8);
                if (status >= 400) {
                    throw new IllegalStateException(method + " " + path + " answered " + status + ": " + text);
                }
                return text;
            }
        } catch (IOException e) {
            throw new IllegalStateException(method + " " + path + " failed", e);
        }
    }

    private static List<Integer> parsePorts(String json) {
        List<Integer> result = new ArrayList<>();
        Matcher list = Pattern.compile("\"ports\"\\s*:\\s*\\[([^\\]]*)]").matcher(json);
        if (list.find()) {
            Matcher number = Pattern.compile("\\d+").matcher(list.group(1));
            while (number.find()) {
                result.add(Integer.parseInt(number.group()));
            }
        }
        return result;
    }

    static int freePort() {
        try (ServerSocket s = new ServerSocket(0)) {
            s.setReuseAddress(true);
            return s.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
