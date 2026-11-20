package io.github.oxidestack.mockserver.launcher;

import com.sun.net.httpserver.HttpServer;
import org.junit.After;
import org.junit.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThrows;

/**
 * A port the stand-in chose with {@link MockServerProcess#freePort()} can be taken by another process
 * before the server binds it. The stand-in then starts again on a new free port; a port the caller asked for is never
 * replaced, so a held one is still refused. The races are staged by a launcher that takes the chosen port itself just
 * before it starts the real server (the mock-server binary, {@code -DmockServer.binary}).
 */
public class MockServerProcessPortRaceTest {

    private final List<AutoCloseable> held = new ArrayList<>();
    private MockServerProcess server;

    @After
    public void release() throws Exception {
        if (server != null) {
            server.stop();
        }
        for (AutoCloseable c : held) {
            c.close();
        }
    }

    /** Takes {@code ports.get(0)} on the first launch only, then starts the real server. */
    private static final class StealingLauncher implements ServerLauncher {
        private final BinaryLauncher binary = new BinaryLauncher();
        private final ThrowingFunction thief;
        final List<List<Integer>> launches = new ArrayList<>();

        StealingLauncher(ThrowingFunction thief) {
            this.thief = thief;
        }

        @Override
        public Process launch(List<Integer> ports, Map<String, String> properties, String remoteHost, Integer remotePort) throws IOException {
            launches.add(ports);
            if (launches.size() == 1) {
                thief.take(ports.get(0));
            }
            return binary.launch(ports, properties, remoteHost, remotePort);
        }
    }

    private interface ThrowingFunction {
        void take(int port) throws IOException;
    }

    @Test
    public void startsAgainOnANewPortWhenAChosenPortIsTakenBeforeTheServerBindsIt() {
        StealingLauncher launcher = new StealingLauncher(port -> held.add(new ServerSocket(port)));

        server = MockServerProcess.start(launcher, List.of(), Map.of(), null, null);

        assertThat("launches", launcher.launches.size(), is(2));
        int stolen = launcher.launches.get(0).get(0);
        assertThat(server.ports().get(0), not(is(stolen)));
        assertThat(server.isAlive(), is(true));
        assertThat(server.boundPorts(), is(server.ports()));
    }

    @Test
    public void doesNotTakeAForeignServerOnTheChosenPortForItsOwn() {
        StealingLauncher launcher = new StealingLauncher(port -> {
            // another server answering the readiness probe (PUT /mockserver/status) with 200
            HttpServer foreign = HttpServer.create(new InetSocketAddress(port), 0);
            foreign.createContext("/", exchange -> {
                exchange.getRequestBody().readAllBytes();
                byte[] body = "{\"ports\":[1]}".getBytes();
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
            });
            foreign.start();
            held.add(() -> foreign.stop(0));
        });

        server = MockServerProcess.start(launcher, List.of(), Map.of(), null, null);

        assertThat("launches", launcher.launches.size(), is(2));
        assertThat(server.isAlive(), is(true));
        assertThat(server.boundPorts(), is(server.ports()));
    }

    @Test
    public void refusesARequestedPortThatIsHeldWithoutTryingAnother() throws IOException {
        ServerSocket holder = new ServerSocket(0);
        held.add(holder);
        int port = holder.getLocalPort();
        StealingLauncher launcher = new StealingLauncher(p -> { });

        IllegalStateException refused = assertThrows(IllegalStateException.class,
            () -> server = MockServerProcess.start(launcher, List.of(port), Map.of(), null, null));

        assertThat(refused.getMessage(), containsString("before it was ready"));
        assertThat("launches", launcher.launches.size(), is(1));
    }
}
