package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code cassette} (B4): every call of {@code CassetteRegistry}'s {@code register}, {@code remove},
 * {@code list} and {@code reset}, one line each in cassette.jsonl, with the registry instance's identity (the tests
 * build registries with their own clocks). Replayed as the cassette endpoints of the server's one registry:
 * {@code PUT}, {@code DELETE ?path=} and {@code GET /mockserver/cassettes}, and {@code PUT /mockserver/reset}.
 */
public class CassetteAdvice implements Boundary {

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.mock.CassetteRegistry"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(CassetteAdvice.class)
                .on(named("register").and(takesArguments(String.class, String.class, int.class, String.class))
                    .or(named("remove").and(takesArguments(String.class)))
                    .or(namedOneOf("list", "reset").and(takesArguments(0))))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter("cassette");
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.This Object registry, @Advice.Origin("#m") String method,
                            @Advice.AllArguments Object[] args, @Advice.Return(typing = net.bytebuddy.implementation.bytecode.assign.Assigner.Typing.DYNAMIC) Object result,
                            @Advice.Thrown Throwable thrown) {
        Recorder.exit("cassette");
        if (outermost) {
            ObjectNode c = Recorder.base("CassetteRegistry." + method);
            c.put("call", method);
            c.put("registry", System.identityHashCode(registry));
            if (method.equals("register")) {
                c.put("path", (String) args[0]);
                c.put("filename", (String) args[1]);
                c.put("expectationCount", (Integer) args[2]);
                c.put("origin", (String) args[3]);
                if (result != null) {
                    try {
                        c.put("lastUsed", (Long) Recorder.field(result, "lastUsedEpochMillis"));
                    } catch (ReflectiveOperationException e) {
                        c.put("unserialisable", String.valueOf(e));
                    }
                }
            } else if (method.equals("remove")) {
                c.put("path", (String) args[0]);
            }
            Recorder.outcome(c, thrown);
            Recorder.write("cassette", c);
        }
    }
}
