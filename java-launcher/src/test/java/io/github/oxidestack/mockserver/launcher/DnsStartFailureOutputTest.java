package io.github.oxidestack.mockserver.launcher;

import org.junit.Test;
import org.mockserver.netty.dns.DnsStartupException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

/**
 * The server process reports a DNS listener that could not start with {@code DnsStartupException}'s
 * one-line message (mock-server' {@code src/udp_start.rs}, upstream's {@code Main.logStartupFailure}); the launcher
 * throws upstream's exception with that same message. The lines are what the binary printed in a conformance run of
 * {@code MockServerAutoConfigurationTest} and what {@code udp_start.rs} formats for a server that could not start.
 */
public class DnsStartFailureOutputTest {

    private static final String PORT_IN_USE = "DNS mocking is enabled (dnsEnabled=true, dnsPort=64123) but UDP port 64123 could not be opened or bound, so MockServer cannot start: free the port if another application holds it, choose a different dnsPort (0 picks a free port, and a port below 1024 can need extra privileges), or set dnsEnabled=false to run without DNS mocking (underlying error: NativeIoException: bind(..) failed with error(-98): Address already in use)";

    private static final String OUT_OF_RANGE = "DNS mocking is enabled (dnsEnabled=true, dnsPort=70000) but its server could not start on UDP port 70000, so MockServer cannot start: fix the underlying error or set dnsEnabled=false to run without DNS mocking (underlying error: IllegalArgumentException: port out of range:70000)";

    @Test
    public void aPortThatCouldNotBeBoundIsReportedWithTheProcessesMessage() {
        String output = "2026-10-18 02:13:07 8.0.1-SNAPSHOT ERROR DNS start-up failed:\n\n  " + PORT_IN_USE + "\n\n";

        DnsStartupException exception = DnsStartFailure.of(new MockServerProcess.StartFailure("mock-server exited with 1 before it was ready", output));

        assertThat(exception.getMessage(), is(PORT_IN_USE));
        assertThat(exception.isPortUnavailable(), is(true));
    }

    @Test
    public void anotherFailureIsReportedWithTheProcessesMessage() {
        String output = "exception while starting:{} \norg.mockserver.netty.dns.DnsStartupException: " + OUT_OF_RANGE
            + "\nCaused by: java.lang.IllegalArgumentException: port out of range:70000\n";

        DnsStartupException exception = DnsStartFailure.of(new MockServerProcess.StartFailure("mock-server exited with 1 before it was ready", output));

        assertThat(exception.getMessage(), is(OUT_OF_RANGE));
        assertThat(exception.isPortUnavailable(), is(false));
    }

    @Test
    public void anExitForAnotherReasonIsNoDnsStartupException() {
        String output = "exception while starting:{} \nException while binding MockServer to port 1080\n";

        assertThat(DnsStartFailure.of(new MockServerProcess.StartFailure("mock-server exited with 1 before it was ready", output)), is(nullValue()));
    }
}
