package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * Kind {@code binaryformat} (B4): {@code BinaryArrayFormatter.byteArrayToString(bytes)}, which renders both
 * sides of a {@code BinaryMatcher} difference, each call one line of binaryformat.jsonl with the bytes as base64 (absent
 * for null). Replayed as the body of a request a BINARY body expectation does not match, the rendered difference read
 * back from the event log (kinds/binaryformat.py).
 */
public class BinaryformatAdvice implements Boundary {

    private static final String KEY = "binaryformat";

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.logging.BinaryArrayFormatter"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.logging.BinaryArrayFormatter"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(BinaryformatAdvice.class)
                .on(named("byteArrayToString"))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter(KEY);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.Argument(0) byte[] bytes, @Advice.Return String result,
                            @Advice.Thrown Throwable thrown) {
        Recorder.exit(KEY);
        if (outermost) {
            BinaryformatAdvice.formatted(bytes, result, thrown);
        }
    }

    public static void formatted(byte[] bytes, String result, Throwable thrown) {
        ObjectNode c = Recorder.base("BinaryArrayFormatter.byteArrayToString");
        if (bytes != null) {
            c.put("bytes", java.util.Base64.getEncoder().encodeToString(bytes));
        }
        if (result != null) {
            c.put("result", result);
        }
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }
}
