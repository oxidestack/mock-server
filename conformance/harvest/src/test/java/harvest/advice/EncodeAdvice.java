package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import org.mockserver.logging.MockServerLogger;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code encode} (B1): {@code MockServerHttpResponseToFullHttpResponse.mapMockServerResponseToNettyResponse}
 * (what {@code MockServerHttpToNettyHttpResponseEncoder} calls), the server-side encoding of an {@code HttpResponse}
 * into the bytes a client reads. Each outermost call is one line of encode.jsonl with the response serialised by a
 * fresh {@code HttpResponseSerializer} (the JSON a client would put in an expectation), captured on entry. Replayed as
 * an expectation answering with that response and a raw request reading the answer's bytes.
 */
public class EncodeAdvice implements Boundary {

    private static final String KEY = "encode";

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.mappers.MockServerHttpResponseToFullHttpResponse"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.mappers.MockServerHttpResponseToFullHttpResponse"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(EncodeAdvice.class)
                .on(named("mapMockServerResponseToNettyResponse").and(takesArguments(1)))));
    }

    @Advice.OnMethodEnter
    public static ObjectNode enter(@Advice.Argument(0) Object response) {
        if (!Recorder.enter(KEY)) {
            return null;
        }
        return EncodeAdvice.snapshot(response);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter ObjectNode recorded, @Advice.Thrown Throwable thrown) {
        Recorder.exit(KEY);
        if (recorded != null) {
            Recorder.outcome(recorded, thrown);
            Recorder.write(KEY, recorded);
        }
    }

    public static ObjectNode snapshot(Object response) {
        ObjectNode c = Recorder.base("MockServerHttpResponseToFullHttpResponse.mapMockServerResponseToNettyResponse");
        Recorder.enter("jackson");
        try {
            if (response == null) {
                c.put("unserialisable", "null response");
            } else {
                c.put("response", new org.mockserver.serialization.HttpResponseSerializer(new MockServerLogger())
                    .serialize((org.mockserver.model.HttpResponse) response));
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        return c;
    }
}
