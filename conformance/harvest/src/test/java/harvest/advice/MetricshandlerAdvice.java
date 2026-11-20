package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * Kind {@code metricshandler} (B4): {@code MetricsHandler.renderMetrics(ctx, request)}, the handler of
 * {@code GET /mockserver/metrics}, each call one line of metricshandler.jsonl with the handler's {@code metricsEnabled},
 * the request's headers, keep-alive and HTTP/2 stream id. Replayed as that request to {@code /mockserver/metrics}
 * (kinds/metricshandler.py).
 */
public class MetricshandlerAdvice implements Boundary {

    private static final String KEY = "metricshandler";

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.metrics.MetricsHandler"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.metrics.MetricsHandler"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(MetricshandlerAdvice.class)
                .on(named("renderMetrics"))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter(KEY);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.This Object handler, @Advice.Argument(1) Object request,
                            @Advice.Thrown Throwable thrown) {
        Recorder.exit(KEY);
        if (outermost) {
            MetricshandlerAdvice.rendered(handler, request, thrown);
        }
    }

    public static void rendered(Object handler, Object requestObject, Throwable thrown) {
        ObjectNode c = Recorder.base("MetricsHandler.renderMetrics");
        try {
            c.put("metricsEnabled", Boolean.TRUE.equals(Recorder.field(handler, "metricsEnabled")));
            org.mockserver.model.HttpRequest request = (org.mockserver.model.HttpRequest) requestObject;
            if (request.getMethod() != null) {
                c.put("method", request.getMethod().getValue());
            }
            com.fasterxml.jackson.databind.node.ArrayNode headers = c.putArray("headers");
            for (org.mockserver.model.Header header : request.getHeaderList()) {
                for (org.mockserver.model.NottableString value : header.getValues()) {
                    headers.addArray().add(header.getName().getValue()).add(value.getValue());
                }
            }
            if (request.isKeepAlive() != null) {
                c.put("keepAlive", request.isKeepAlive());
            }
            if (request.getStreamId() != null) {
                c.put("streamId", request.getStreamId());
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        }
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }
}
