package harvest.advice;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import java.util.Base64;
import java.util.Map;

import static net.bytebuddy.matcher.ElementMatchers.isStatic;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;

/**
 * Kind {@code grpcweb} (B4): the static {@code GrpcWebTranslator} methods, each outermost call one line of
 * grpcweb.jsonl with the method and its arguments in order ({@code byte[]} as base64, a map as an object, null as
 * null). Replayed as a gRPC-Web call on the greeting descriptor: the request body and content-type are the arguments
 * of {@code decodeRequestBody} and the content-type predicates; the status, message and custom trailers of
 * {@code buildTrailerFrame}/{@code encodeResponseBody} are those of the expectation that answers it.
 */
public class GrpcWebAdvice implements Boundary {

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.grpc.GrpcWebTranslator"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.grpc.GrpcWebTranslator"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(GrpcWebAdvice.class)
                .on(isStatic().and(namedOneOf("decodeRequestBody", "encodeResponseBody", "buildTrailerFrame",
                    "isGrpcWebContentType", "isGrpcWebTextContentType", "responseContentType", "parseTrailerFrame")))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter("grpcweb");
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#m") String method,
                            @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
        Recorder.exit("grpcweb");
        if (outermost) {
            GrpcWebAdvice.record(method, args, thrown);
        }
    }

    public static void record(String method, Object[] args, Throwable thrown) {
        ObjectNode c = Recorder.base("GrpcWebTranslator." + method);
        c.put("method", method);
        ArrayNode array = c.putArray("args");
        for (Object arg : args) {
            if (arg == null) {
                array.addNull();
            } else if (arg instanceof byte[]) {
                array.addObject().put("bytes", Base64.getEncoder().encodeToString((byte[]) arg));
            } else if (arg instanceof Map) {
                ObjectNode map = array.addObject().putObject("map");
                for (Map.Entry<?, ?> e : ((Map<?, ?>) arg).entrySet()) {
                    map.put(String.valueOf(e.getKey()), e.getValue() == null ? null : String.valueOf(e.getValue()));
                }
            } else if (arg instanceof Boolean) {
                array.add((Boolean) arg);
            } else {
                array.add(String.valueOf(arg));
            }
        }
        Recorder.outcome(c, thrown);
        Recorder.write("grpcweb", c);
    }
}
