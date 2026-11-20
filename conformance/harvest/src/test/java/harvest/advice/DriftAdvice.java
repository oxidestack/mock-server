package harvest.advice;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import org.mockserver.logging.MockServerLogger;

import java.util.List;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code drift} (B4): the drift and traffic-diff calls a test makes, one line of drift.jsonl each,
 * outermost only (a {@code BaselineDiffer} diffs requests with its own {@code TrafficDiffEngine}, and
 * {@code diffExpectations} calls {@code diff}):
 * <ul>
 *   <li>{@code TrafficDiffEngine.diff(expected, actual)}: both requests ({@code PUT /mockserver/diff});</li>
 *   <li>{@code BaselineDiffer.diffExpectations(baseline, current)} and {@code diff(baseline, current)} over raw
 *   interactions: both sets as expectations ({@code PUT /mockserver/baseline/compare});</li>
 *   <li>{@code DriftAnalyzer.analyse(expectation, realResponse)}: the expectation and the upstream's response (a
 *   forward next to the expectation, then {@code GET /mockserver/drift}).</li>
 * </ul>
 * Replayed by kinds/drift.py.
 */
public class DriftAdvice implements Boundary {

    private static final String KEY = "drift";

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.mock.diff.TrafficDiffEngine", "org.mockserver.mock.diff.BaselineDiffer",
            "org.mockserver.mock.drift.DriftAnalyzer"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.mock.diff.TrafficDiffEngine"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(DriftAdvice.class)
                .on(named("diff").and(takesArguments(2)))))
            .type(named("org.mockserver.mock.diff.BaselineDiffer"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(DriftAdvice.class)
                .on(namedOneOf("diff", "diffExpectations").and(takesArguments(2)))))
            .type(named("org.mockserver.mock.drift.DriftAnalyzer"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(DriftAdvice.class)
                .on(named("analyse").and(takesArguments(2)))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter(KEY);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.Origin("#m") String method,
                            @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
        Recorder.exit(KEY);
        if (outermost) {
            DriftAdvice.called(self, method, args, thrown);
        }
    }

    public static void called(Object self, String method, Object[] args, Throwable thrown) {
        String type = self.getClass().getSimpleName();
        ObjectNode c = Recorder.base(type + "." + method);
        Recorder.enter("jackson");
        try {
            ObjectMapper mapper = new ObjectMapper();
            MockServerLogger logger = new MockServerLogger();
            if (type.equals("TrafficDiffEngine")) {
                c.put("call", "diff");
                c.set("expected", request(mapper, logger, args[0]));
                c.set("actual", request(mapper, logger, args[1]));
            } else if (type.equals("BaselineDiffer")) {
                c.put("call", "baseline");
                c.put("raw", method.equals("diff"));
                c.set("baseline", set(mapper, logger, args[0]));
                c.set("current", set(mapper, logger, args[1]));
            } else {
                c.put("call", "analyse");
                org.mockserver.mock.Expectation expectation = (org.mockserver.mock.Expectation) args[0];
                if (expectation != null) {
                    c.set("expectation", mapper.readTree(new org.mockserver.serialization.ExpectationSerializer(logger).serialize(expectation)));
                    c.put("responseAction", expectation.getAction() instanceof org.mockserver.model.HttpResponse);
                }
                c.set("response", response(mapper, logger, args[1]));
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }

    private static com.fasterxml.jackson.databind.JsonNode request(ObjectMapper mapper, MockServerLogger logger, Object request) throws Exception {
        if (request == null) {
            return mapper.nullNode();
        }
        return mapper.readTree(new org.mockserver.serialization.HttpRequestSerializer(logger).serialize((org.mockserver.model.HttpRequest) request));
    }

    private static com.fasterxml.jackson.databind.JsonNode response(ObjectMapper mapper, MockServerLogger logger, Object response) throws Exception {
        if (response == null) {
            return mapper.nullNode();
        }
        return mapper.readTree(new org.mockserver.serialization.HttpResponseSerializer(logger).serialize((org.mockserver.model.HttpResponse) response));
    }

    /** A set of expectations, or of raw {@code BaselineDiffer.Interaction}s as {@code {httpRequest, httpResponse}}. */
    private static com.fasterxml.jackson.databind.JsonNode set(ObjectMapper mapper, MockServerLogger logger, Object list) throws Exception {
        if (list == null) {
            return mapper.nullNode();
        }
        ArrayNode items = mapper.createArrayNode();
        for (Object item : (List<?>) list) {
            if (item == null) {
                items.addNull();
            } else if (item instanceof org.mockserver.mock.Expectation) {
                items.add(mapper.readTree(new org.mockserver.serialization.ExpectationSerializer(logger).serialize((org.mockserver.mock.Expectation) item)));
            } else {
                ObjectNode interaction = items.addObject();
                interaction.set("httpRequest", request(mapper, logger, item.getClass().getMethod("getRequest").invoke(item)));
                interaction.set("httpResponse", response(mapper, logger, item.getClass().getMethod("getResponse").invoke(item)));
            }
        }
        return items;
    }
}
