package io.github.oxidestack.mockserver.launcher;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.stream.Collectors;

/**
 * Runs the mock-server binary with MockServer's command line ({@code -serverPort}, {@code -proxyRemotePort},
 * {@code -proxyRemoteHost}, {@code -Dmockserver.<name>=<value>}). The binary is, in this order: the
 * {@code mockServer.binary} system property, the {@code MOCK_SERVER_BINARY} environment variable, or
 * {@code mock-server} on {@code PATH}. Its output goes to the file named by {@code mockServer.log} (appended),
 * else to this JVM's standard output, where the in-JVM MockServer logs too; its last 16 KiB are kept for
 * {@link #output(Process)}. It runs in the directory named by
 * {@code mockServer.workingDirectory}, else in this JVM's. The binary has no JVM: it resolves a class-path-relative
 * location (an OpenAPI spec, a file body, a template or initializer file) on the roots this launcher passes in
 * {@code MOCK_SERVER_CLASS_PATH}, this JVM's {@code java.class.path} (or {@code mockServer.classPath}), then
 * against its working directory, as the in-JVM server does.
 */
public final class BinaryLauncher implements ServerLauncher {

    public static final String BINARY_PROPERTY = "mockServer.binary";
    public static final String BINARY_ENVIRONMENT = "MOCK_SERVER_BINARY";
    public static final String LOG_PROPERTY = "mockServer.log";
    public static final String WORKING_DIRECTORY_PROPERTY = "mockServer.workingDirectory";
    public static final String CLASS_PATH_PROPERTY = "mockServer.classPath";
    /** What the binary reads its class path roots from (mock-server' {@code src/class_path.rs}). */
    public static final String CLASS_PATH_ENVIRONMENT = "MOCK_SERVER_CLASS_PATH";

    @Override
    public Process launch(List<Integer> ports, Map<String, String> properties, String remoteHost, Integer remotePort) throws IOException {
        List<String> command = new ArrayList<>();
        command.add(binary());
        command.add("-serverPort");
        command.add(ports.stream().map(String::valueOf).collect(Collectors.joining(",")));
        properties.forEach((k, v) -> command.add("-Dmockserver." + k + "=" + v));
        if (remotePort != null) {
            command.add("-proxyRemotePort");
            command.add(String.valueOf(remotePort));
            if (remoteHost != null && !remoteHost.isEmpty()) {
                command.add("-proxyRemoteHost");
                command.add(remoteHost);
            }
        }
        ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
        String classPath = classPath();
        if (classPath.isBlank()) {
            builder.environment().remove(CLASS_PATH_ENVIRONMENT);
        } else {
            // the environment, not a -D argument: a test class path can outgrow a command line
            builder.environment().put(CLASS_PATH_ENVIRONMENT, classPath);
        }
        String directory = System.getProperty(WORKING_DIRECTORY_PROPERTY, "");
        if (!directory.isBlank()) {
            builder.directory(new File(directory));
        }
        String log = System.getProperty(LOG_PROPERTY, "");
        OutputStream destination;
        if (log.isBlank()) {
            destination = System.out;
        } else {
            File file = new File(log);
            if (file.getParentFile() != null) {
                file.getParentFile().mkdirs();
            }
            destination = new FileOutputStream(file, true);
        }
        Process process;
        try {
            process = builder.start();
        } catch (IOException | RuntimeException e) {
            if (destination != System.out) {
                destination.close();
            }
            throw e;
        }
        OUTPUTS.put(process, new OutputPump(process, destination));
        return process;
    }

    /** The output of each process this launcher started, while the process is referenced. */
    private static final Map<Process, OutputPump> OUTPUTS = Collections.synchronizedMap(new WeakHashMap<>());

    @Override
    public String output(Process process) {
        OutputPump pump = OUTPUTS.get(process);
        return pump == null ? "" : pump.tail();
    }

    /**
     * Copies a process's output to the log (or this JVM's standard output) as it comes, keeping its last
     * {@link #TAIL_BYTES} bytes, which say why a server that exits before it is ready did not start.
     */
    private static final class OutputPump {
        private static final int TAIL_BYTES = 16 * 1024;
        private final byte[] tail = new byte[TAIL_BYTES];
        private int length;
        private final Thread thread;

        OutputPump(Process process, OutputStream destination) {
            InputStream in = process.getInputStream();
            thread = new Thread(() -> {
                byte[] buffer = new byte[8192];
                try {
                    for (int n; (n = in.read(buffer)) >= 0; ) {
                        keep(buffer, n);
                        try {
                            destination.write(buffer, 0, n);
                            destination.flush();
                        } catch (IOException logGone) {
                            // keep draining, so the process never blocks on a full pipe
                        }
                    }
                } catch (IOException closed) {
                    // the process is gone
                } finally {
                    if (destination != System.out) {
                        try {
                            destination.close();
                        } catch (IOException ignored) {
                            // nothing left to write
                        }
                    }
                }
            }, "mock-server output " + process.pid());
            thread.setDaemon(true);
            thread.start();
        }

        private synchronized void keep(byte[] buffer, int n) {
            if (n >= TAIL_BYTES) {
                System.arraycopy(buffer, n - TAIL_BYTES, tail, 0, TAIL_BYTES);
                length = TAIL_BYTES;
                return;
            }
            int drop = Math.max(0, length + n - TAIL_BYTES);
            System.arraycopy(tail, drop, tail, 0, length - drop);
            length -= drop;
            System.arraycopy(buffer, 0, tail, length, n);
            length += n;
        }

        /** The kept output; waits up to 2s for the rest of an exited process's output. */
        String tail() {
            try {
                thread.join(2_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            synchronized (this) {
                return new String(tail, 0, length, StandardCharsets.UTF_8);
            }
        }
    }

    /**
     * The class path the server resolves resources on: the {@code mockServer.classPath} system property when it is
     * set (blank for none), else this JVM's {@code java.class.path}, its directories and jars.
     */
    public static String classPath() {
        String property = System.getProperty(CLASS_PATH_PROPERTY);
        return property != null ? property : System.getProperty("java.class.path", "");
    }

    @Override
    public String describe() {
        return "mock-server";
    }

    /** The binary to run, or an {@link IllegalStateException} that says how to name one. */
    public static String binary() {
        String property = System.getProperty(BINARY_PROPERTY, "");
        if (!property.isBlank()) {
            return requireFile(property, "-D" + BINARY_PROPERTY);
        }
        String environment = System.getenv(BINARY_ENVIRONMENT);
        if (environment != null && !environment.isBlank()) {
            return requireFile(environment, BINARY_ENVIRONMENT);
        }
        String name = System.getProperty("os.name", "").toLowerCase().startsWith("windows") ? "mock-server.exe" : "mock-server";
        String path = System.getenv("PATH");
        if (path != null) {
            for (String dir : path.split(File.pathSeparator)) {
                File candidate = new File(dir.isEmpty() ? "." : dir, name);
                if (candidate.isFile() && candidate.canExecute()) {
                    return candidate.getPath();
                }
            }
        }
        throw new IllegalStateException("mock-server binary not found: set -D" + BINARY_PROPERTY + "=<path>, "
            + BINARY_ENVIRONMENT + "=<path>, or put " + name + " on PATH");
    }

    private static String requireFile(String path, String source) {
        File file = new File(path);
        if (!file.isFile() || !file.canExecute()) {
            throw new IllegalStateException(source + " names " + path + ", which is not an executable file");
        }
        return file.getPath();
    }
}
