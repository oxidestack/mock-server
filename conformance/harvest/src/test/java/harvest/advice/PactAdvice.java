package harvest.advice;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import org.mockserver.logging.MockServerLogger;
import org.mockserver.mock.Expectation;
import org.mockserver.serialization.ExpectationSerializer;

import java.util.List;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code pact} (B4), one depth key, outermost call only: {@code PactExporter.export(expectations,
 * consumer, provider)} with each expectation re-serialised by a fresh {@code ExpectationSerializer} (replayed as the
 * expectations upserted in order, then {@code PUT /mockserver/pact?consumer&provider}), and
 * {@code PactProviderStates.namesOf/gatingStateOf(interaction)} with the interaction JSON (replayed as a one-interaction
 * pact imported through {@code PUT /mockserver/pact/import}, whose gating state the active expectations show).
 */
public class PactAdvice implements Boundary {

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.mock.pact.PactExporter"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ExportCall.class)
                .on(named("export").and(takesArguments(3)))))
            .type(named("org.mockserver.mock.pact.PactProviderStates"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(StatesCall.class)
                .on(named("namesOf").or(named("gatingStateOf")).or(named("activate")).or(named("clear")))));
    }

    public static class ExportCall {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("pact");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
            Recorder.exit("pact");
            if (outermost) {
                PactAdvice.recordExport(args, thrown);
            }
        }
    }

    public static class StatesCall {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("pact");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#m") String method, @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
            Recorder.exit("pact");
            if (outermost) {
                PactAdvice.recordStates(method, args, thrown);
            }
        }
    }

    public static void recordExport(Object[] args, Throwable thrown) {
        ObjectNode c = Recorder.base("PactExporter.export");
        c.put("call", "export");
        Recorder.enter("jackson");
        Recorder.enter("serialize");
        try {
            ExpectationSerializer serializer = new ExpectationSerializer(new MockServerLogger());
            ArrayNode array = c.putArray("expectations");
            for (Object e : (List<?>) args[0]) {
                array.add(serializer.serialize((Expectation) e));
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("serialize");
            Recorder.exit("jackson");
        }
        c.put("consumer", (String) args[1]);
        c.put("provider", (String) args[2]);
        Recorder.outcome(c, thrown);
        Recorder.write("pact", c);
    }

    public static void recordStates(String method, Object[] args, Throwable thrown) {
        ObjectNode c = Recorder.base("PactProviderStates." + method);
        c.put("call", method);
        if (method.equals("namesOf") || method.equals("gatingStateOf")) {
            c.put("interaction", args[0] == null ? null : args[0].toString());
        } else {
            c.put("scenarioManager", args[0] != null);
            if (args.length > 1) {
                c.put("state", (String) args[1]);
            }
        }
        Recorder.outcome(c, thrown);
        Recorder.write("pact", c);
    }
}
