package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import org.mockserver.logging.MockServerLogger;

import java.util.Map;
import java.util.TreeMap;

import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code action} (B4): requests put through {@code HttpActionHandler.processAction} by the action
 * handler tests (chaos, forward chaos, GraphQL chaos, rate limits, recover-after, drift), one line of action.jsonl each,
 * outermost call only:
 * <ul>
 *   <li>{@code processAction(request, writer, ctx, localAddresses, proxying, synchronous)}, on entry: the request, the
 *   expectation the handler's {@code HttpState} returns for it (the tests stub {@code firstMatchingExpectation}; the
 *   advice asks the same stub), and the handler's configuration values that differ from the run's startup values;</li>
 *   <li>an {@code HttpForwardActionResult} built outside {@code processAction} with an already completed response
 *   future: the upstream answer a test hands its mocked forward handler (the converter serves it from a stub).</li>
 * </ul>
 */
public class ActionAdvice implements Boundary {

    private static final String KEY = "action";

    /** Startup value of every simple {@code Configuration} getter (the same rule as {@code Recorder}'s `handle`). */
    private static final Map<String, String> DEFAULTS = new TreeMap<>();

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.mock.action.http.HttpActionHandler", "org.mockserver.mock.action.http.HttpForwardActionResult",
            "org.mockserver.mock.action.http.ServiceChaosRegistry", "org.mockserver.time.TimeService"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        DEFAULTS.putAll(configurationValues(org.mockserver.configuration.Configuration.configuration()));
        return agent
            .type(named("org.mockserver.mock.action.http.HttpActionHandler"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ProcessAdvice.class)
                .on(named("processAction").and(takesArguments(6)))))
            .type(named("org.mockserver.mock.action.http.HttpForwardActionResult"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ForwardResultAdvice.class)
                .on(isConstructor())))
            .type(named("org.mockserver.mock.action.http.ServiceChaosRegistry"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ServiceChaosAdvice.class)
                .on(named("put"))))
            .type(named("org.mockserver.time.TimeService"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(AdvanceAdvice.class)
                .on(named("advance"))));
    }

    /** {@code ServiceChaosRegistry.put(host, profile[, ttlMillis])} made by a test (outside {@code processAction}). */
    public static class ServiceChaosAdvice {
        @Advice.OnMethodEnter
        public static void enter(@Advice.AllArguments Object[] args) {
            if (Recorder.enter(KEY)) {
                ActionAdvice.serviceChaos(args);
            }
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit() {
            Recorder.exit(KEY);
        }
    }

    /** {@code TimeService.advance(duration)}: the test moves its frozen clock (a pause on the wire). */
    public static class AdvanceAdvice {
        @Advice.OnMethodEnter
        public static void enter(@Advice.Argument(0) java.time.Duration duration) {
            if (Recorder.enter(KEY)) {
                ActionAdvice.advanced(duration);
            }
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit() {
            Recorder.exit(KEY);
        }
    }

    public static void serviceChaos(Object[] args) {
        ObjectNode c = Recorder.base("ServiceChaosRegistry.put");
        Recorder.enter("jackson");
        try {
            c.put("call", "serviceChaos");
            c.put("host", (String) args[0]);
            String json = new org.mockserver.serialization.ExpectationSerializer(new MockServerLogger())
                .serialize(new org.mockserver.mock.Expectation(org.mockserver.model.HttpRequest.request())
                    .withChaos((org.mockserver.model.HttpChaosProfile) args[1]));
            c.set("chaos", new com.fasterxml.jackson.databind.ObjectMapper().readTree(json).get("chaos"));
            if (args.length > 2) {
                c.put("ttlMillis", (Long) args[2]);
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.write(KEY, c);
    }

    public static void advanced(java.time.Duration duration) {
        ObjectNode c = Recorder.base("TimeService.advance");
        c.put("call", "advance");
        c.put("millis", duration.toMillis());
        Recorder.write(KEY, c);
    }

    public static class ProcessAdvice {
        @Advice.OnMethodEnter
        public static void enter(@Advice.This Object handler, @Advice.Argument(0) Object request) {
            if (Recorder.enter(KEY)) {
                ActionAdvice.processed(handler, request);
            }
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit() {
            Recorder.exit(KEY);
        }
    }

    public static class ForwardResultAdvice {
        @Advice.OnMethodExit
        public static void exit(@Advice.This Object result) {
            if (Recorder.enter(KEY)) {
                ActionAdvice.upstream(result);
            }
            Recorder.exit(KEY);
        }
    }

    private static Map<String, String> configurationValues(Object configuration) {
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
                // a getter that cannot be read in isolation is not a server property
            }
        }
        return values;
    }

    public static void processed(Object handler, Object request) {
        ObjectNode c = Recorder.base("HttpActionHandler.processAction");
        Recorder.enter("jackson");
        try {
            c.put("call", "process");
            c.put("thread", Thread.currentThread().getName());
            MockServerLogger logger = new MockServerLogger();
            c.put("request", new org.mockserver.serialization.HttpRequestSerializer(logger).serialize((org.mockserver.model.HttpRequest) request));
            Object state = Recorder.field(handler, "httpStateHandler");
            Object expectation = state == null ? null : state.getClass().getMethod("firstMatchingExpectation", org.mockserver.model.RequestDefinition.class)
                .invoke(state, request);
            if (expectation != null) {
                org.mockserver.mock.Expectation e = (org.mockserver.mock.Expectation) expectation;
                c.put("expectationIdentity", System.identityHashCode(e));
                c.put("expectation", new org.mockserver.serialization.ExpectationSerializer(logger).serialize(e));
            }
            ObjectNode differences = c.putObject("configuration");
            configurationValues(Recorder.field(handler, "configuration")).forEach((name, value) -> {
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

    public static void upstream(Object result) {
        ObjectNode c = Recorder.base("HttpForwardActionResult.<init>");
        Recorder.enter("jackson");
        try {
            c.put("call", "upstream");
            java.util.concurrent.CompletableFuture<?> future = (java.util.concurrent.CompletableFuture<?>) Recorder.field(result, "httpResponse");
            if (future == null || !future.isDone()) {
                c.put("pending", true);
            } else if (future.isCompletedExceptionally()) {
                try {
                    future.getNow(null);
                } catch (Throwable t) {
                    Throwable cause = t.getCause() != null ? t.getCause() : t;
                    c.put("failure", cause.getClass().getName() + ": " + cause.getMessage());
                }
            } else {
                Object response = future.getNow(null);
                if (response != null) {
                    c.put("response", new org.mockserver.serialization.HttpResponseSerializer(new MockServerLogger())
                        .serialize((org.mockserver.model.HttpResponse) response));
                }
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.write(KEY, c);
    }
}
