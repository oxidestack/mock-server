package harvest.advice;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import org.mockserver.logging.MockServerLogger;
import org.mockserver.mock.Expectation;
import org.mockserver.serialization.ExpectationSerializer;

import java.util.Collection;
import java.util.List;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code fixture} (B4), one depth key, outermost call only: {@code FixtureRedactor.redact(Expectation[])}
 * with the redactor's header, body-field and query-parameter sets; {@code SseAwareExpectationConverter.convert(Expectation[])}
 * and {@code SseBodyParser.parse(text[, perChunkDelays])} with the parser's fixed inter-event delay. Expectations are
 * re-serialised by a fresh {@code ExpectationSerializer}. Replayed as recorded traffic imported into the event log, then
 * the MCP tools {@code record_llm_fixtures} (which converts SSE captures and redacts) and
 * {@code load_expectations_from_file}, and the active expectations.
 */
public class FixtureAdvice implements Boundary {

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.fixture.FixtureRedactor"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Call.class)
                .on(named("redact").and(takesArguments(1)).and(takesArgument(0, Expectation[].class)))))
            .type(named("org.mockserver.fixture.SseAwareExpectationConverter"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Call.class)
                .on(named("convert").and(takesArguments(1)))))
            .type(named("org.mockserver.fixture.SseBodyParser"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Call.class)
                .on(named("parse"))));
    }

    public static class Call {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("fixture");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.Origin("#t.#m") String method,
                                @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
            Recorder.exit("fixture");
            if (outermost) {
                FixtureAdvice.record(self, method, args, thrown);
            }
        }
    }

    public static void record(Object self, String method, Object[] args, Throwable thrown) {
        String simple = method.substring(method.lastIndexOf('.', method.lastIndexOf('.') - 1) + 1);
        ObjectNode c = Recorder.base(simple);
        c.put("call", simple);
        Recorder.enter("jackson");
        Recorder.enter("serialize");
        try {
            if (simple.startsWith("SseBodyParser.")) {
                c.put("interEventDelayMs", (Long) Recorder.field(self, "interEventDelayMs"));
                c.put("text", (String) args[0]);
                if (args.length > 1 && args[1] != null) {
                    ArrayNode delays = c.putArray("perChunkDelaysMs");
                    for (Object d : (List<?>) args[1]) {
                        delays.add(d == null ? null : String.valueOf(d));
                    }
                }
            } else {
                if (simple.startsWith("FixtureRedactor.")) {
                    strings(c.putArray("sensitiveHeaders"), Recorder.field(self, "sensitiveHeaders"));
                    strings(c.putArray("sensitiveBodyFields"), Recorder.field(self, "sensitiveBodyFields"));
                    strings(c.putArray("sensitiveQueryParams"), Recorder.field(self, "sensitiveQueryParams"));
                } else {
                    Object parser = Recorder.field(self, "sseBodyParser");
                    c.put("interEventDelayMs", (Long) Recorder.field(parser, "interEventDelayMs"));
                }
                Object[] expectations = (Object[]) args[0];
                if (expectations == null) {
                    c.putNull("expectations");
                } else {
                    ExpectationSerializer serializer = new ExpectationSerializer(new MockServerLogger());
                    ArrayNode array = c.putArray("expectations");
                    for (Object e : expectations) {
                        array.add(e == null ? null : serializer.serialize((Expectation) e));
                    }
                }
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("serialize");
            Recorder.exit("jackson");
        }
        Recorder.outcome(c, thrown);
        Recorder.write("fixture", c);
    }

    private static void strings(ArrayNode array, Object values) {
        if (values != null) {
            for (Object v : (Collection<?>) values) {
                array.add(String.valueOf(v));
            }
        }
    }
}
