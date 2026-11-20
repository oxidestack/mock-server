package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import static net.bytebuddy.matcher.ElementMatchers.isStatic;
import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * Kind {@code traceparent} (B4): {@code W3CTraceContext.parse(traceparent, tracestate)}, the parser
 * {@code TraceContextHandler} applies to every inbound request's {@code traceparent}/{@code tracestate} headers, each call
 * one line of traceparent.jsonl with both arguments (absent for null) and the parsed context's {@code toTraceparent()}
 * and validity. Replayed as a request carrying those headers to a server with {@code otelPropagateTraceContext}, which
 * copies a valid context back onto the response (kinds/traceparent.py).
 */
public class TraceparentAdvice implements Boundary {

    private static final String KEY = "traceparent";

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.telemetry.W3CTraceContext"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.telemetry.W3CTraceContext"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(TraceparentAdvice.class)
                .on(isStatic().and(named("parse")))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter(KEY);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.Argument(0) String traceparent,
                            @Advice.Argument(1) String tracestate,
                            @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
        Recorder.exit(KEY);
        if (outermost) {
            TraceparentAdvice.parsed(traceparent, tracestate, result, thrown);
        }
    }

    public static void parsed(String traceparent, String tracestate, Object result, Throwable thrown) {
        ObjectNode c = Recorder.base("W3CTraceContext.parse");
        if (traceparent != null) {
            c.put("traceparent", traceparent);
        }
        if (tracestate != null) {
            c.put("tracestate", tracestate);
        }
        if (result instanceof org.mockserver.telemetry.W3CTraceContext) {
            org.mockserver.telemetry.W3CTraceContext context = (org.mockserver.telemetry.W3CTraceContext) result;
            c.put("valid", context.isValid());
            c.put("result", context.toTraceparent());
        }
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }
}
