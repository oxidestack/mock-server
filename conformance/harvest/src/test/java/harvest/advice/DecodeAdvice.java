package harvest.advice;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code decode} (B1): {@code FullHttpRequestToMockServerHttpRequest.mapFullHttpRequestToMockServerRequest}
 * (the six-argument overload, which the five-argument one calls), the server-side mapping of a request Netty decoded
 * into the {@code HttpRequest} a received log entry shows. Each outermost call is one line of decode.jsonl with the
 * Netty request as it reached the mapper, captured on entry (method, URI, version, headers in order with their case,
 * body bytes), the headers Netty's codec removed and the mapper puts back ({@code preservedHeaders}), the raw body
 * before decompression, the protocol, and the mapper's {@code isSecure}, client certificates and port. Replayed as the
 * same request in raw HTTP/1.1 bytes plus a retrieve of the recorded requests.
 */
public class DecodeAdvice implements Boundary {

    private static final String KEY = "decode";

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.mappers.FullHttpRequestToMockServerHttpRequest"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.mappers.FullHttpRequestToMockServerHttpRequest"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(DecodeAdvice.class)
                .on(named("mapFullHttpRequestToMockServerRequest").and(takesArguments(6)))));
    }

    @Advice.OnMethodEnter
    public static ObjectNode enter(@Advice.This Object mapper, @Advice.AllArguments Object[] args) {
        if (!Recorder.enter(KEY)) {
            return null;
        }
        return DecodeAdvice.snapshot(mapper, args);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter ObjectNode recorded, @Advice.Thrown Throwable thrown) {
        Recorder.exit(KEY);
        if (recorded != null) {
            Recorder.outcome(recorded, thrown);
            Recorder.write(KEY, recorded);
        }
    }

    public static ObjectNode snapshot(Object mapper, Object[] args) {
        ObjectNode c = Recorder.base("FullHttpRequestToMockServerHttpRequest.mapFullHttpRequestToMockServerRequest");
        Recorder.enter("jackson");
        try {
            io.netty.handler.codec.http.FullHttpRequest request = (io.netty.handler.codec.http.FullHttpRequest) args[0];
            if (request == null) {
                c.put("unserialisable", "null request");
                return c;
            }
            c.put("method", request.method().name());
            c.put("uri", request.uri());
            c.put("version", request.protocolVersion().text());
            ArrayNode headers = c.putArray("headers");
            Iterator<Map.Entry<CharSequence, CharSequence>> it = request.headers().iteratorCharSequence();
            while (it.hasNext()) {
                Map.Entry<CharSequence, CharSequence> h = it.next();
                headers.addArray().add(h.getKey().toString()).add(h.getValue().toString());
            }
            io.netty.buffer.ByteBuf content = request.content();
            byte[] body = content == null || content.refCnt() == 0 ? new byte[0] : io.netty.buffer.ByteBufUtil.getBytes(content);
            c.put("body", Base64.getEncoder().encodeToString(body));
            if (args[1] != null) {
                ArrayNode preserved = c.putArray("preservedHeaders");
                for (Object o : (List<?>) args[1]) {
                    org.mockserver.model.Header header = (org.mockserver.model.Header) o;
                    for (org.mockserver.model.NottableString value : header.getValues()) {
                        preserved.addArray().add(header.getName().getValue()).add(value.getValue());
                    }
                }
            }
            if (args[2] != null) {
                c.put("originalRawBody", Base64.getEncoder().encodeToString((byte[]) args[2]));
            }
            c.put("protocol", args[5] == null ? null : String.valueOf(args[5]));
            c.put("secure", (Boolean) Recorder.field(mapper, "isSecure"));
            c.put("clientCertificates", Recorder.field(mapper, "clientCertificates") != null);
            Object port = Recorder.field(mapper, "port");
            if (port != null) {
                c.put("port", (Integer) port);
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        return c;
    }
}
