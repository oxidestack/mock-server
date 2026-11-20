package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * Kind {@code responseheaders} (B1): {@code DefaultResponseHeaders.addDefaultResponseHeaders(response)},
 * each call one line of responseheaders.jsonl with the configured {@code defaultResponseHeaders} value the instance
 * was built from (the raw text, so its parse is replayed too) and the response as it was before the call. Replayed as
 * an expectation answering that response on a server with that property (kinds/responseheaders.py).
 */
public class ResponseheadersAdvice implements Boundary {

    private static final String KEY = "responseheaders";

    /** The configured value each instance was built from (the instance keeps only the parsed list). */
    private static final Map<Object, String> CONFIGURED = Collections.synchronizedMap(new WeakHashMap<>());

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.responseheaders.DefaultResponseHeaders"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.responseheaders.DefaultResponseHeaders"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(Construct.class).on(isConstructor()))
                .visit(Advice.to(Add.class).on(named("addDefaultResponseHeaders"))));
    }

    public static class Construct {
        @Advice.OnMethodExit
        public static void exit(@Advice.This Object self, @Advice.Argument(0) Object configuration) {
            ResponseheadersAdvice.constructed(self, configuration);
        }
    }

    public static class Add {
        @Advice.OnMethodEnter
        public static ObjectNode enter(@Advice.This Object self, @Advice.Argument(0) Object response) {
            if (!Recorder.enter(KEY)) {
                return null;
            }
            return ResponseheadersAdvice.added(self, response);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter ObjectNode recorded, @Advice.Thrown Throwable thrown) {
            Recorder.exit(KEY);
            if (recorded != null) {
                Recorder.outcome(recorded, thrown);
                Recorder.write(KEY, recorded);
            }
        }
    }

    public static void constructed(Object self, Object configuration) {
        try {
            CONFIGURED.put(self, ((org.mockserver.configuration.Configuration) configuration).defaultResponseHeaders());
        } catch (Throwable ignored) {
            // an instance without a value is recorded as unserialisable
        }
    }

    public static ObjectNode added(Object self, Object response) {
        ObjectNode c = Recorder.base("DefaultResponseHeaders.addDefaultResponseHeaders");
        if (!CONFIGURED.containsKey(self)) {
            c.put("unserialisable", "configured value not seen");
            return c;
        }
        String configured = CONFIGURED.get(self);
        if (configured != null) {
            c.put("defaultResponseHeaders", configured);
        }
        if (response == null) {
            c.put("unserialisable", "null response");
            return c;
        }
        try {
            c.put("response", CorsAdvice.serialise(response));
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        }
        return c;
    }
}
