package harvest.advice;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import org.mockserver.logging.MockServerLogger;

import java.util.Map;
import java.util.TreeMap;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;

/**
 * Kind {@code sse} (B4): {@code HttpSseResponseActionHandler.handle(sseResponse, ctx, request[, format])}
 * and {@code formatSseEvent(event)}, outermost call only, one line of sse.jsonl each: the {@code httpSseResponse} (as
 * an expectation serialises it), the request, its HTTP/2 stream id and keep-alive flag, the streaming format, and the
 * handler's configuration values that differ from the run's startup values.
 */
public class SseAdvice implements Boundary {

    private static final String KEY = "sse";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Map<String, String> DEFAULTS = new TreeMap<>();

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.mock.action.http.HttpSseResponseActionHandler"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        DEFAULTS.putAll(values(org.mockserver.configuration.Configuration.configuration()));
        return agent
            .type(named("org.mockserver.mock.action.http.HttpSseResponseActionHandler"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(CallAdvice.class)
                .on(namedOneOf("handle", "formatSseEvent"))));
    }

    public static class CallAdvice {
        @Advice.OnMethodEnter
        public static void enter(@Advice.This Object handler, @Advice.Origin("#m") String method, @Advice.AllArguments Object[] args) {
            if (Recorder.enter(KEY)) {
                SseAdvice.called(handler, method, args);
            }
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit() {
            Recorder.exit(KEY);
        }
    }

    private static Map<String, String> values(Object configuration) {
        Map<String, String> values = new TreeMap<>();
        for (java.lang.reflect.Method m : org.mockserver.configuration.Configuration.class.getDeclaredMethods()) {
            Class<?> r = m.getReturnType();
            boolean simple = r.isPrimitive() && r != void.class || r == String.class || r == Boolean.class || r == Integer.class
                || r == Long.class || r == Double.class || r.isEnum();
            if (m.getParameterCount() != 0 || !simple || !java.lang.reflect.Modifier.isPublic(m.getModifiers())
                || java.lang.reflect.Modifier.isStatic(m.getModifiers()) || m.getName().startsWith("get") || m.getName().equals("toString")
                || m.getName().equals("hashCode")) {
                continue;
            }
            try {
                values.put(m.getName(), String.valueOf(m.invoke(configuration)));
            } catch (Throwable ignored) {
                // not a server property
            }
        }
        return values;
    }

    public static void called(Object handler, String method, Object[] args) {
        ObjectNode c = Recorder.base("HttpSseResponseActionHandler." + method);
        Recorder.enter("jackson");
        try {
            MockServerLogger logger = new MockServerLogger();
            org.mockserver.model.HttpSseResponse sse;
            if (method.equals("formatSseEvent")) {
                c.put("call", "format");
                sse = org.mockserver.model.HttpSseResponse.sseResponse().withEvent((org.mockserver.model.SseEvent) args[0]);
            } else {
                c.put("call", "handle");
                sse = (org.mockserver.model.HttpSseResponse) args[0];
                org.mockserver.model.HttpRequest request = (org.mockserver.model.HttpRequest) args[2];
                c.put("request", new org.mockserver.serialization.HttpRequestSerializer(logger).serialize(request));
                if (request.getStreamId() != null) {
                    c.put("streamId", request.getStreamId());
                }
                c.put("format", args.length > 3 ? String.valueOf(args[3]) : "SSE");
            }
            String json = new org.mockserver.serialization.ExpectationSerializer(logger)
                .serialize(new org.mockserver.mock.Expectation(org.mockserver.model.HttpRequest.request()).thenRespondWithSse(sse));
            c.set("sse", JSON.readTree(json).get("httpSseResponse"));
            ObjectNode differences = c.putObject("configuration");
            values(Recorder.field(handler, "configuration")).forEach((name, value) -> {
                if (!value.equals(DEFAULTS.get(name))) {
                    differences.put(name, value);
                }
            });
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.write(KEY, c);
    }
}
