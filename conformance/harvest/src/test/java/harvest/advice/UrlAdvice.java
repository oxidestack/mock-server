package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import static net.bytebuddy.matcher.ElementMatchers.isStatic;
import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * Kind {@code url} (B1): {@code URLParser.returnPath(uri)} and {@code URLParser.isFullUrl(uri)} (the
 * outermost call only: {@code returnPath} calls {@code isFullUrl}), each call one line of url.jsonl with the URI and
 * the result. Replayed as an HTTP/1.1 request with that URI as its request target, whose path the received request
 * shows (kinds/url.py): the request decoder takes its path from {@code returnPath}.
 */
public class UrlAdvice implements Boundary {

    private static final String KEY = "url";

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.url.URLParser"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.url.URLParser"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(UrlAdvice.class)
                .on(isStatic().and(named("returnPath").or(named("isFullUrl"))))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter(KEY);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#m") String method, @Advice.Argument(0) String uri,
                            @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
        Recorder.exit(KEY);
        if (outermost) {
            UrlAdvice.parsed(method, uri, result, thrown);
        }
    }

    public static void parsed(String method, String uri, Object result, Throwable thrown) {
        ObjectNode c = Recorder.base("URLParser." + method);
        c.put("method", method);
        if (uri != null) {
            c.put("uri", uri);
        }
        if (result != null) {
            c.put("result", String.valueOf(result));
        }
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }
}
