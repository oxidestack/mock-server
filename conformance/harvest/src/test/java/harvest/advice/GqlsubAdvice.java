package harvest.advice;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code gqlsub} (B4): {@code GraphQLSubscriptionHandler}, one line per handler built (its filter body,
 * payloads and negotiated subprotocol, through its widest constructor, which the others delegate to) and one per
 * inbound frame ({@code channelRead0}), each with the handler's identity. Replayed as an {@code httpWebSocketResponse}
 * expectation with that {@code graphqlSubscriptionFilter}, a WebSocket opened with the subprotocol and the frames sent.
 */
public class GqlsubAdvice implements Boundary {

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.mock.action.http.GraphQLSubscriptionHandler"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(Construct.class).on(isConstructor().and(takesArguments(10))))
                .visit(Advice.to(Read.class).on(named("channelRead0").and(takesArguments(2)))));
    }

    public static class Construct {
        @Advice.OnMethodExit
        public static void exit(@Advice.This Object self, @Advice.AllArguments Object[] args) {
            GqlsubAdvice.constructed(self, args);
        }
    }

    public static class Read {
        @Advice.OnMethodEnter
        public static void enter(@Advice.This Object self, @Advice.Argument(1) Object frame) {
            GqlsubAdvice.read(self, frame);
        }
    }

    public static void constructed(Object self, Object[] args) {
        ObjectNode c = Recorder.base("GraphQLSubscriptionHandler.<init>");
        c.put("call", "construct");
        c.put("handler", System.identityHashCode(self));
        Recorder.enter("jackson");
        try {
            ObjectMapper mapper = org.mockserver.serialization.ObjectMapperFactory.createObjectMapper();
            c.put("filter", args[0] == null ? null : mapper.writeValueAsString(args[0]));
            c.put("payloads", args[1] == null ? null : mapper.writeValueAsString(args[1]));
            c.put("handshaker", args[3] != null);
            c.put("inboundStreamId", (String) args[5]);
            c.put("subprotocol", (String) args[9]);
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.write("gqlsub", c);
    }

    public static void read(Object self, Object frame) {
        ObjectNode c = Recorder.base("GraphQLSubscriptionHandler.channelRead0");
        c.put("call", "frame");
        c.put("handler", System.identityHashCode(self));
        if (frame instanceof io.netty.handler.codec.http.websocketx.TextWebSocketFrame) {
            c.put("text", ((io.netty.handler.codec.http.websocketx.TextWebSocketFrame) frame).text());
        } else {
            c.put("frameType", frame == null ? null : frame.getClass().getSimpleName());
        }
        Recorder.write("gqlsub", c);
    }
}
