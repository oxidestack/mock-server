package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code grpctimeout} (B4): {@code GrpcTimeout.parseNanos(String)}, each outermost call one line of
 * grpctimeout.jsonl with the {@code grpc-timeout} value (absent for null). Replayed as a native gRPC call carrying that
 * header against an expectation delayed past short deadlines: a parsed value answers DEADLINE_EXCEEDED with the
 * deadline in milliseconds, a value parsed as absent (or long) answers the expectation.
 */
public class GrpcTimeoutAdvice implements Boundary {

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.grpc.GrpcTimeout"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.grpc.GrpcTimeout"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(GrpcTimeoutAdvice.class)
                .on(named("parseNanos").and(takesArguments(String.class)))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter("grpctimeout");
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.Argument(0) String value, @Advice.Return Long result,
                            @Advice.Thrown Throwable thrown) {
        Recorder.exit("grpctimeout");
        if (outermost) {
            GrpcTimeoutAdvice.record(value, result, thrown);
        }
    }

    public static void record(String value, Long result, Throwable thrown) {
        ObjectNode c = Recorder.base("GrpcTimeout.parseNanos");
        if (value != null) {
            c.put("value", value);
        }
        if (result != null) {
            c.put("nanos", result);
        }
        Recorder.outcome(c, thrown);
        Recorder.write("grpctimeout", c);
    }
}
