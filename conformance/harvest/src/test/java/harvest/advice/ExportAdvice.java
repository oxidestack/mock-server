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
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;

/**
 * Kind {@code export} (B2): {@code ExpectationExportSerializer.serializeAsOpenApi(List&lt;Expectation&gt;)},
 * each outermost call one line of export.jsonl. {@code ExpectationExportSerializerTest} builds its `Expectation`
 * list directly (no JSON, no mocking) and asserts on the returned OpenAPI text — this advice re-serialises each
 * expectation with a fresh `ExpectationSerializer` so the case can be replayed as
 * {@code PUT /mockserver/expectation} + {@code retrieve?type=ACTIVE_EXPECTATIONS&format=OPENAPI}
 * (`src/control.rs` already implements that retrieve format).
 */
public class ExportAdvice implements Boundary {

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.serialization.ExpectationExportSerializer"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ExportAdvice.class)
                .on(named("serializeAsOpenApi").and(takesArgument(0, List.class)))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter("export");
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.Argument(0) List<?> expectations, @Advice.Thrown Throwable thrown) {
        Recorder.exit("export");
        if (outermost) {
            ExportAdvice.record(expectations);
        }
    }

    public static void record(List<?> expectations) {
        ObjectNode c = Recorder.base("ExpectationExportSerializer.serializeAsOpenApi");
        Recorder.enter("jackson");
        // ExpectationSerializer.serialize is also SerializeAdvice's boundary (same class, Byte Buddy instruments it
        // regardless of which instance calls it) — hold that key open too, so this per-expectation reserialisation
        // is never treated as SerializeAdvice's own outermost call.
        Recorder.enter("serialize");
        try {
            ExpectationSerializer serializer = new ExpectationSerializer(new MockServerLogger());
            ArrayNode array = c.putArray("expectations");
            for (Object e : expectations) {
                array.add(serializer.serialize((Expectation) e));
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("serialize");
            Recorder.exit("jackson");
        }
        Recorder.write("export", c);
    }
}
