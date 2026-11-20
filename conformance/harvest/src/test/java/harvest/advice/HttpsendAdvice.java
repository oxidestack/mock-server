package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;

/**
 * Kind {@code httpsend} (B4): {@code NettyHttpClient.sendRequest(HttpRequest[, remoteAddress[, …]])}, the
 * forwarding client, each outermost call one line of httpsend.jsonl with the request as sent, the address it was sent
 * to (host and port; the port is the test's local upstream) and whether the client was given proxy configurations.
 * Replayed as a forward of that request to the server itself, read back with {@code retrieve?type=REQUESTS}: what a
 * forward puts on the wire.
 */
public class HttpsendAdvice implements Boundary {

    private static final String KEY = "httpsend";

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.httpclient.NettyHttpClient"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(HttpsendAdvice.class)
                .on(named("sendRequest").and(takesArgument(0, named("org.mockserver.model.HttpRequest"))))));
    }

    @Advice.OnMethodEnter
    public static void enter(@Advice.This Object client, @Advice.AllArguments Object[] args) {
        if (Recorder.enter(KEY)) {
            HttpsendAdvice.called(client, args);
        }
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit() {
        Recorder.exit(KEY);
    }

    public static void called(Object client, Object[] args) {
        ObjectNode c = Recorder.base("NettyHttpClient.sendRequest");
        Recorder.enter("jackson");
        try {
            org.mockserver.model.HttpRequest request = (org.mockserver.model.HttpRequest) args[0];
            c.put("request", new org.mockserver.serialization.HttpRequestSerializer(new org.mockserver.logging.MockServerLogger())
                .serialize(request));
            if (args.length > 1 && args[1] instanceof java.net.InetSocketAddress) {
                java.net.InetSocketAddress remote = (java.net.InetSocketAddress) args[1];
                c.put("remoteHost", remote.getHostString());
                c.put("remotePort", remote.getPort());
            }
            Object proxies = Recorder.field(client, "proxyConfigurations");
            c.put("proxied", proxies instanceof java.util.Collection && !((java.util.Collection<?>) proxies).isEmpty());
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.write(KEY, c);
    }
}
