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

/**
 * Kind {@code postprocess} (B4 by the kind machinery): {@code RecordedExpectationPostProcessor.consolidate
 * (expectations, parameterizeValues)} and {@code deduplicateAndTemplatize(expectations[, templatizeValues])}, outermost
 * call only, with each expectation re-serialised by a fresh {@code ExpectationSerializer}. Replayed as the expectations'
 * exchanges imported as a recording ({@code PUT /mockserver/import?format=recording}) and the recorded expectations
 * retrieved with {@code consolidate}/{@code parameterize}, or on a server with {@code deduplicateRecordedExpectations}.
 */
public class PostprocessAdvice implements Boundary {

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.persistence.RecordedExpectationPostProcessor"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.persistence.RecordedExpectationPostProcessor"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(PostprocessAdvice.class)
                .on(named("consolidate").or(named("deduplicateAndTemplatize")))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter("postprocess");
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#m") String method, @Advice.AllArguments Object[] args,
                            @Advice.Thrown Throwable thrown) {
        Recorder.exit("postprocess");
        if (outermost) {
            record(method, args, thrown);
        }
    }

    public static void record(String method, Object[] args, Throwable thrown) {
        ObjectNode c = Recorder.base("RecordedExpectationPostProcessor." + method);
        c.put("call", method);
        c.put("flag", args.length > 1 && Boolean.TRUE.equals(args[1]));
        if (args[0] == null) {
            c.putNull("expectations");
        } else {
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
        }
        Recorder.outcome(c, thrown);
        Recorder.write("postprocess", c);
    }
}
