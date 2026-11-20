package io.github.oxidestack.mockserver.launcher;

import org.mockserver.netty.dns.DnsStartupException;

import java.io.IOException;
import java.net.BindException;
import java.net.SocketException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Upstream's {@link DnsStartupException} for a server process that exited because its DNS listener could not start
 *. The in-JVM {@code MockServer} constructor throws it, and code such as the Spring Boot starter's tests
 * looks for it in the cause chain. The process reports it as {@code Main.logStartupFailure} does: its one-line message,
 * {@code DNS mocking is enabled (dnsEnabled=true, dnsPort=<port>) but ... (underlying error: <cause>)}. The exception is
 * built again from that line with upstream's own factories, so its message is the process's: the root cause is
 * rebuilt with the reported simple class name and message.
 */
public final class DnsStartFailure {

    private static final Pattern REPORTED = Pattern.compile(
        "DNS mocking is enabled \\(dnsEnabled=true, dnsPort=(-?\\d+)\\) but (.*) \\(underlying error: (.*)\\)\\s*$", Pattern.MULTILINE);

    private DnsStartFailure() {
    }

    /** The {@link DnsStartupException} {@code failure}'s output reports, or null when it reports none. */
    public static DnsStartupException of(MockServerProcess.StartFailure failure) {
        Matcher reported = REPORTED.matcher(failure.output());
        if (!reported.find()) {
            return null;
        }
        int port;
        try {
            port = Integer.parseInt(reported.group(1));
        } catch (NumberFormatException e) {
            return null;
        }
        String how = reported.group(2);
        boolean portUnavailable = how.startsWith("UDP port " + port + " could not be opened or bound")
            || how.startsWith("this process is not permitted to bind UDP port " + port);
        Throwable cause = cause(reported.group(3));
        DnsStartupException exception = portUnavailable
            ? DnsStartupException.portCouldNotBeOpenedOrBound(port, cause)
            : DnsStartupException.serverCouldNotStart(port, cause);
        exception.addSuppressed(failure);
        return exception;
    }

    /** {@code underlyingError}'s text ({@code SimpleName} or {@code SimpleName: message}) as a throwable it reads back the same. */
    private static Throwable cause(String underlying) {
        int colon = underlying.indexOf(": ");
        String name = colon < 0 ? underlying : underlying.substring(0, colon);
        String message = colon < 0 ? null : underlying.substring(colon + 2);
        switch (name) {
            case "BindException":
                return new BindException(message);
            case "SocketException":
                return new SocketException(message);
            case "IOException":
                return new IOException(message);
            case "IllegalArgumentException":
                return new IllegalArgumentException(message);
            case "IllegalStateException":
                return new IllegalStateException(message);
            case "NativeIoException":
                return new NativeIoException(message);
            default:
                // a class the process does not report today: its text survives inside the message
                return new IllegalStateException(underlying);
        }
    }

    /** Netty's {@code Errors.NativeIoException}, the epoll transport's failed bind, as the process names it. */
    static final class NativeIoException extends IOException {
        private static final long serialVersionUID = 1L;

        NativeIoException(String message) {
            super(message);
        }
    }
}
