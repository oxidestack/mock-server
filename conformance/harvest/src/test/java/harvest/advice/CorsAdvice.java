package harvest.advice;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import org.mockserver.logging.MockServerLogger;

import static net.bytebuddy.matcher.ElementMatchers.isStatic;
import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * Kind {@code cors} (B1): {@code CORSHeaders.addCORSHeaders(request, response)}, each call one line of
 * cors.jsonl with the instance's five settings, the request's method and headers and the response as it was before
 * the call; and {@code CORSHeaders.isPreflightRequest(configuration, request)} with the request and its result.
 * Replayed on a server with {@code enableCORSForAllResponses} and those settings (kinds/cors.py).
 */
public class CorsAdvice implements Boundary {

    private static final String KEY = "cors";

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.cors.CORSHeaders"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.cors.CORSHeaders"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(Add.class).on(named("addCORSHeaders")))
                .visit(Advice.to(Preflight.class).on(isStatic().and(named("isPreflightRequest")))));
    }

    public static class Add {
        @Advice.OnMethodEnter
        public static ObjectNode enter(@Advice.This Object self, @Advice.Argument(0) Object request, @Advice.Argument(1) Object response) {
            if (!Recorder.enter(KEY)) {
                return null;
            }
            return CorsAdvice.added(self, request, response);
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

    public static class Preflight {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter(KEY);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.Argument(1) Object request,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit(KEY);
            if (outermost) {
                ObjectNode c = Recorder.base("CORSHeaders.isPreflightRequest");
                CorsAdvice.request(c, request);
                if (result instanceof Boolean) {
                    c.put("preflight", (Boolean) result);
                }
                Recorder.outcome(c, thrown);
                Recorder.write(KEY, c);
            }
        }
    }

    public static ObjectNode added(Object self, Object request, Object response) {
        ObjectNode c = Recorder.base("CORSHeaders.addCORSHeaders");
        try {
            ObjectNode settings = c.putObject("settings");
            settings.put("corsAllowOrigin", (String) Recorder.field(self, "corsAllowOrigin"));
            settings.put("corsAllowHeaders", (String) Recorder.field(self, "corsAllowHeaders"));
            settings.put("corsAllowMethods", (String) Recorder.field(self, "corsAllowMethods"));
            settings.put("corsAllowCredentials", String.valueOf(Recorder.field(self, "corsAllowCredentials")));
            settings.put("corsMaxAgeInSeconds", (String) Recorder.field(self, "corsMaxAge"));
            CorsAdvice.request(c, request);
            c.put("response", CorsAdvice.serialise(response));
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        }
        return c;
    }

    /** The request's method (when set) and headers, each value a [name, value] pair in order. */
    public static void request(ObjectNode c, Object requestObject) {
        try {
            org.mockserver.model.HttpRequest request = (org.mockserver.model.HttpRequest) requestObject;
            if (request.getMethod() != null && !request.getMethod().getValue().isEmpty()) {
                c.put("method", request.getMethod().getValue());
            }
            ArrayNode headers = c.putArray("headers");
            for (org.mockserver.model.Header header : request.getHeaderList()) {
                if (header.getValues().isEmpty()) {
                    headers.addArray().add(header.getName().getValue());
                }
                for (org.mockserver.model.NottableString value : header.getValues()) {
                    headers.addArray().add(header.getName().getValue()).add(value.getValue());
                }
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        }
    }

    /** An {@code HttpResponse} as the control plane's JSON (a nested call the recorder does not record). */
    public static String serialise(Object response) {
        Recorder.enter("jackson");
        try {
            return new org.mockserver.serialization.HttpResponseSerializer(new MockServerLogger())
                .serialize((org.mockserver.model.HttpResponse) response);
        } finally {
            Recorder.exit("jackson");
        }
    }
}
