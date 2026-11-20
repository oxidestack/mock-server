package io.github.oxidestack.mockserver.launcher;

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
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * A server running as a separate process, started by the {@link ServerLauncher} in effect, on free ports where
 * none was asked for. Live processes are tracked and stopped at JVM exit.
 */
public final class MockServerProcess {

    private static final Set<MockServerProcess> LIVE = ConcurrentHashMap.newKeySet();
    private static volatile ServerLauncher launcher;

    private final Process process;
    private final List<Integer> ports;
    private final ServerLauncher startedBy;
    private final String description;

    private MockServerProcess(Process process, List<Integer> ports, ServerLauncher launcher) {
        this.process = process;
        this.ports = ports;
        this.startedBy = launcher;
        this.description = launcher.describe();
    }

    /** The server process exited before it was ready; {@link #output()} is what it wrote, as far as kept. */
    public static final class StartFailure extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        private final transient String output;

        StartFailure(String message, String output) {
            super(output.isBlank() ? message : message + ", having written:\n" + output.strip());
            this.output = output;
        }

        /** The end of the process's output ({@link ServerLauncher#output}), "" where the launcher keeps none. */
        public String output() {
            return output;
        }
    }

    /** The launcher registered through {@link ServiceLoader}, else {@link BinaryLauncher}. */
    public static ServerLauncher launcher() {
        ServerLauncher current = launcher;
        if (current == null) {
            synchronized (MockServerProcess.class) {
                current = launcher;
                if (current == null) {
                    Iterator<ServerLauncher> found = ServiceLoader.load(ServerLauncher.class).iterator();
                    current = found.hasNext() ? found.next() : new BinaryLauncher();
                    launcher = current;
                }
            }
        }
        return current;
    }

    /** How often a start is tried when another process takes a port this class chose. */
    private static final int START_ATTEMPTS = 5;

    /**
     * Starts a server on {@code requestedPorts} (0, null or none = a free port) and waits up to 60s until
     * {@code PUT /mockserver/status} answers 200 on the first port and the process listens there itself.
     * A free port is free only when asked: another process can take it before the server binds it. When the server
     * then exits before it is ready and a port chosen here is in use, the start is tried again on new free ports for
     * the chosen ones; a port the caller asked for is never replaced, so a held one is still refused.
     */
    public static MockServerProcess start(List<Integer> requestedPorts, Map<String, String> properties, String remoteHost, Integer remotePort) {
        return start(launcher(), requestedPorts, properties, remoteHost, remotePort);
    }

    static MockServerProcess start(ServerLauncher launcher, List<Integer> requestedPorts, Map<String, String> properties, String remoteHost, Integer remotePort) {
        List<Integer> requested = new ArrayList<>();
        if (requestedPorts != null) {
            for (Integer p : requestedPorts) {
                requested.add(p == null ? 0 : p);
            }
        }
        if (requested.isEmpty()) {
            requested.add(0);
        }
        for (int attempt = 1; ; attempt++) {
            List<Integer> ports = new ArrayList<>();
            for (Integer p : requested) {
                ports.add(p == 0 ? freePort() : p);
            }
            Process process;
            try {
                process = launcher.launch(List.copyOf(ports), properties, remoteHost, remotePort);
            } catch (IOException e) {
                throw new IllegalStateException("could not start " + launcher.describe(), e);
            }
            MockServerProcess server = new MockServerProcess(process, List.copyOf(ports), launcher);
            LIVE.add(server);
            try {
                server.awaitReady(Boolean.parseBoolean(properties.get("tlsMutualAuthenticationRequired")));
                return server;
            } catch (IllegalStateException refused) {
                boolean chosenPortTaken = false;
                for (int i = 0; i < ports.size(); i++) {
                    chosenPortTaken |= requested.get(i) == 0 && portTaken(ports.get(i));
                }
                if (process.isAlive() || !chosenPortTaken || attempt == START_ATTEMPTS || Thread.currentThread().isInterrupted()) {
                    throw refused;
                }
            }
        }
    }

    /**
     * Whether another process holds {@code port}: a listener answers a connection to localhost (IPv4 or IPv6), or the
     * wildcard address cannot be bound.
     */
    static boolean portTaken(int port) {
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

    /** Stops the process: SIGTERM, then a forced kill after 10s. */
    public void stop() {
        LIVE.remove(this);
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

    /** Stops every process still running. */
    public static void stopAll() {
        for (MockServerProcess server : new ArrayList<>(LIVE)) {
            server.stop();
        }
    }

    static {
        Runtime.getRuntime().addShutdownHook(new Thread(MockServerProcess::stopAll, "mock-server launcher shutdown"));
    }

    /**
     * {@code acceptOnly}: a server that requires client certificates ({@code tlsMutualAuthenticationRequired})
     * refuses the plain-HTTP probe, so it counts as ready once its first port accepts a connection.
     */
    private void awaitReady(boolean acceptOnly) {
        long deadline = System.currentTimeMillis() + 60_000;
        while (System.currentTimeMillis() < deadline) {
            if (!process.isAlive()) {
                LIVE.remove(this);
                throw new StartFailure(description + " exited with " + process.exitValue() + " before it was ready", startedBy.output(process));
            }
            if (acceptOnly) {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress("localhost", ports.get(0)), 500);
                    socket.close();
                    if (listensOn(ports.get(0))) {
                        awaitProbesClosed();
                        return;
                    }
                    sleepBeforeRetry();
                    continue;
                } catch (IOException notYet) {
                    sleepBeforeRetry();
                    continue;
                }
            }
            HttpURLConnection c = null;
            try {
                c = (HttpURLConnection) new URL("http://localhost:" + ports.get(0) + "/mockserver/status").openConnection();
                c.setRequestMethod("PUT");
                c.setRequestProperty("Connection", "close");
                c.setConnectTimeout(500);
                c.setReadTimeout(2000);
                if (c.getResponseCode() == 200) {
                    c.getInputStream().readAllBytes();
                    if (listensOn(ports.get(0))) {
                        awaitProbesClosed();
                        return;
                    }
                }
            } catch (IOException notYet) {
                // not listening yet
            } finally {
                if (c != null) {
                    c.disconnect();
                }
            }
            sleepBeforeRetry();
        }
        stop();
        throw new IllegalStateException(description + " did not become ready on port " + ports.get(0));
    }

    private void sleepBeforeRetry() {
        try {
            Thread.sleep(50);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            stop();
            throw new IllegalStateException(e);
        }
    }

    /**
     * The launcher's own requests close their connection ({@code Connection: close}, then a disconnect), so the server
     * does not count them among its inbound connections ({@link #inboundConnectionCount}) or its
     * {@code maxInboundConnections}; an in-JVM server has no such requests.
     */
    private String request(String method, String path, String body) {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL("http://localhost:" + ports.get(0) + path).openConnection();
            c.setRequestMethod(method);
            c.setRequestProperty("Connection", "close");
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
        } finally {
            if (c != null) {
                c.disconnect();
            }
        }
    }

    /** Waits up to 5s until the server has closed the connections of the readiness probe. */
    private void awaitProbesClosed() {
        long deadline = System.currentTimeMillis() + 5_000;
        while (inboundConnectionCount() > 0 && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    /**
     * {@code MockServer.getInboundConnectionCount()} (upstream's {@code InboundConnectionLimiter.getOpenConnections()}):
     * the TCP connections the server process holds open on its listening ports, read from the operating system's
     * socket table rather than through a request, which would itself be one of them. A socket counts from accept
     * until the process closes it, whatever its TCP state (a peer's close leaves it in CLOSE_WAIT until then), as a
     * Netty channel counts until it is closed. Linux reads {@code /proc/<pid>}, other systems {@code lsof}.
     */
    public int inboundConnectionCount() {
        if (!process.isAlive()) {
            return 0;
        }
        try {
            List<long[]> sockets = sockets(process.pid());
            Set<Long> listening = new HashSet<>();
            for (long[] socket : sockets) {
                if (socket[1] == 1) {
                    listening.add(socket[0]);
                }
            }
            int open = 0;
            for (long[] socket : sockets) {
                if (socket[1] == 0 && listening.contains(socket[0])) {
                    open++;
                }
            }
            return open;
        } catch (IOException e) {
            throw new IllegalStateException("could not read the socket table of " + description, e);
        }
    }

    /**
     * Whether this process (or a process it started, for a launcher that runs the server through a wrapper) listens
     * on {@code port}: a readiness probe can be answered by another server that took a port chosen here, while this
     * process is still starting and about to fail its bind. Where the socket table cannot be read,
     * the answer is yes, as before.
     */
    private boolean listensOn(int port) {
        List<Long> pids = new ArrayList<>();
        pids.add(process.pid());
        process.descendants().forEach(child -> pids.add(child.pid()));
        try {
            for (long pid : pids) {
                for (long[] socket : sockets(pid)) {
                    if (socket[1] == 1 && socket[0] == port) {
                        return true;
                    }
                }
            }
            return false;
        } catch (IOException | RuntimeException unreadable) {
            return true;
        }
    }

    /** The TCP sockets of process {@code pid} as {local port, 1 if listening}. */
    private static List<long[]> sockets(long pid) throws IOException {
        return new File("/proc/" + pid + "/net/tcp").isFile() ? procSockets(pid) : lsofSockets(pid);
    }

    /** The process's TCP sockets as {local port, 1 if listening}, from {@code lsof}. */
    private static List<long[]> lsofSockets(long pid) throws IOException {
        String lsof = new File("/usr/sbin/lsof").canExecute() ? "/usr/sbin/lsof" : "lsof";
        Process list = new ProcessBuilder(lsof, "-nP", "-a", "-p", String.valueOf(pid), "-iTCP").redirectErrorStream(true).start();
        String output = new String(list.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        try {
            list.waitFor(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        List<long[]> sockets = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (String line : output.split("\n")) {
            // NAME is "*:1080 (LISTEN)", "127.0.0.1:1080->127.0.0.1:50000 (ESTABLISHED)" or "[::1]:1080->..."
            int tcp = line.indexOf(" TCP ");
            if (tcp < 0) {
                continue;
            }
            // COMMAND PID USER FD TYPE DEVICE ...: a socket held by several descriptors (a duplicated one) has one
            // DEVICE, the kernel's socket address, and is one connection
            String[] columns = line.trim().split("\\s+");
            if (columns.length > 5 && !seen.add(columns[5])) {
                continue;
            }
            String name = line.substring(tcp + 5).trim();
            boolean listen = name.endsWith("(LISTEN)");
            String local = name.split("->|\\s")[0];
            int colon = local.lastIndexOf(':');
            if (colon < 0) {
                continue;
            }
            try {
                sockets.add(new long[]{Long.parseLong(local.substring(colon + 1)), listen ? 1 : 0});
            } catch (NumberFormatException e) {
                // a port lsof printed by name
            }
        }
        return sockets;
    }

    /** The process's TCP sockets as {local port, 1 if listening}: its socket inodes matched in /proc/net/tcp{,6}. */
    private static List<long[]> procSockets(long pid) throws IOException {
        Set<String> inodes = new HashSet<>();
        File[] fds = new File("/proc/" + pid + "/fd").listFiles();
        if (fds != null) {
            for (File fd : fds) {
                try {
                    String target = Files.readSymbolicLink(fd.toPath()).toString();
                    if (target.startsWith("socket:[")) {
                        inodes.add(target.substring("socket:[".length(), target.length() - 1));
                    }
                } catch (IOException closedMeanwhile) {
                    // the descriptor was closed while listing
                }
            }
        }
        List<long[]> sockets = new ArrayList<>();
        for (String table : List.of("tcp", "tcp6")) {
            File file = new File("/proc/" + pid + "/net/" + table);
            if (!file.isFile()) {
                continue;
            }
            for (String line : Files.readAllLines(file.toPath())) {
                // sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
                String[] fields = line.trim().split("\\s+");
                if (fields.length < 10 || !fields[1].contains(":") || !inodes.contains(fields[9])) {
                    continue;
                }
                long port = Long.parseLong(fields[1].substring(fields[1].lastIndexOf(':') + 1), 16);
                sockets.add(new long[]{port, "0A".equals(fields[3]) ? 1 : 0});
            }
        }
        return sockets;
    }

    /**
     * {@code MockServer.getDnsPort()}: the {@code dnsPort} of the server's status ({@code PUT /mockserver/status},
     * present while {@code dnsEnabled} runs a DNS listener), else -1.
     */
    public int dnsPort() {
        if (!process.isAlive()) {
            return -1;
        }
        Matcher m = Pattern.compile("\"dnsPort\"\\s*:\\s*(\\d+)").matcher(request("PUT", "/mockserver/status", ""));
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    private static int number(String json, String field) {
        Matcher m = Pattern.compile("\"" + field + "\"\\s*:\\s*(-?\\d+)").matcher(json);
        if (!m.find()) {
            throw new IllegalStateException("no " + field + " in " + json);
        }
        return Integer.parseInt(m.group(1));
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

    /** A port free at the time of asking. */
    public static int freePort() {
        try (ServerSocket s = new ServerSocket(0)) {
            s.setReuseAddress(true);
            return s.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
