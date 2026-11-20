package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import static net.bytebuddy.matcher.ElementMatchers.isStatic;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;

/**
 * Kind {@code grpcstatus} (B4): the static {@code GrpcStatusMapper} methods ({@code fromCode},
 * {@code fromName}, {@code fromHttpStatus}, {@code fromHttpTransportStatus}, {@code percentEncodeMessage},
 * {@code percentDecodeMessage}, {@code stripControlCharacters}, {@code isGrpcContentType}), each outermost call one line
 * of grpcstatus.jsonl with the method and its argument. Replayed as a gRPC expectation on the greeting descriptor whose
 * response carries the argument (a {@code grpc-message}, a {@code grpc-status-name}, a status code) or a call whose
 * {@code content-type} is the argument; methods with no data-plane caller are unconvertible.
 */
public class GrpcStatusAdvice implements Boundary {

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.grpc.GrpcStatusMapper"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.grpc.GrpcStatusMapper"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(GrpcStatusAdvice.class)
                .on(isStatic().and(namedOneOf("fromCode", "fromName", "fromHttpStatus", "fromHttpTransportStatus",
                    "percentEncodeMessage", "percentDecodeMessage", "stripControlCharacters", "isGrpcContentType")))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter("grpcstatus");
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#m") String method,
                            @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
        Recorder.exit("grpcstatus");
        if (outermost) {
            GrpcStatusAdvice.record(method, args, thrown);
        }
    }

    public static void record(String method, Object[] args, Throwable thrown) {
        ObjectNode c = Recorder.base("GrpcStatusMapper." + method);
        c.put("method", method);
        Object arg = args.length > 0 ? args[0] : null;
        if (arg instanceof Integer) {
            c.put("code", (Integer) arg);
        } else if (arg != null) {
            c.put("value", String.valueOf(arg));
        }
        Recorder.outcome(c, thrown);
        Recorder.write("grpcstatus", c);
    }
}
