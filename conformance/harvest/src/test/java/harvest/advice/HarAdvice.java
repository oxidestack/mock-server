package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import org.mockserver.logging.MockServerLogger;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/** Kind {@code har} (B3): {@code HarConverter.serialize(entries)}, each outermost call one line of har.jsonl. */
public class HarAdvice implements Boundary {

    /** At the oracle's revision HarConverter was first loaded inside another class's retransformation and
     * never transformed, so the har run recorded nothing (trace.txt had no `transformed …HarConverter`). */
    @Override
    public String[] preload() {
        return new String[] {"org.mockserver.serialization.har.HarConverter"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.serialization.har.HarConverter"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(HarAdvice.class)
                .on(named("serialize").and(takesArguments(1)))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter("har");
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
        Recorder.exit("har");
        if (outermost) {
            HarAdvice.record(args, thrown);
        }
    }

    public static void record(Object[] args, Throwable thrown) {
        ObjectNode c = Recorder.base("HarConverter.serialize");
        Recorder.enter("jackson");
        try {
            MockServerLogger logger = new MockServerLogger();
            org.mockserver.serialization.HttpRequestSerializer requests = new org.mockserver.serialization.HttpRequestSerializer(logger);
            org.mockserver.serialization.HttpResponseSerializer responses = new org.mockserver.serialization.HttpResponseSerializer(logger);
            com.fasterxml.jackson.databind.node.ArrayNode entries = c.putArray("entries");
            for (Object e : (java.util.List<?>) args[0]) {
                org.mockserver.model.LogEventRequestAndResponse entry = (org.mockserver.model.LogEventRequestAndResponse) e;
                ObjectNode n = entries.addObject();
                n.put("timestamp", entry.getTimestamp());
                n.put("request", entry.getHttpRequest() == null ? null : requests.serialize((org.mockserver.model.HttpRequest) entry.getHttpRequest()));
                n.put("response", entry.getHttpResponse() == null ? null : responses.serialize(entry.getHttpResponse()));
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.outcome(c, thrown);
        Recorder.write("har", c);
    }
}
