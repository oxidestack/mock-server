package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code ssrf} (B4): {@code InetAddressValidator.validateForwardTarget(Configuration, String host)},
 * each outermost call one line of ssrf.jsonl with the host, whether {@code forwardProxyBlockPrivateNetworks} was on,
 * whether the test had replaced the host lookup on its thread ({@code lookupOnThisThread}: a name then resolves to
 * what the test chose, not to what a server would look up) and the refusal. Replayed as an {@code httpForward} to the
 * host on a server started with {@code forwardProxyBlockPrivateNetworks}.
 */
public class SsrfAdvice implements Boundary {

    private static final String KEY = "ssrf";

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.proxyconfiguration.InetAddressValidator"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(SsrfAdvice.class)
                .on(named("validateForwardTarget").and(takesArguments(2)).and(takesArgument(1, String.class)))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter(KEY);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
        Recorder.exit(KEY);
        if (outermost) {
            SsrfAdvice.called(args, thrown);
        }
    }

    public static void called(Object[] args, Throwable thrown) {
        ObjectNode c = Recorder.base("InetAddressValidator.validateForwardTarget");
        c.put("host", (String) args[1]);
        try {
            Class<?> validator = Class.forName("org.mockserver.proxyconfiguration.InetAddressValidator");
            c.put("enabled", (Boolean) validator.getMethod("isEnabled", org.mockserver.configuration.Configuration.class)
                .invoke(null, args[0]));
            java.lang.reflect.Field lookup = validator.getDeclaredField("LOOKUP_ON_THIS_THREAD");
            lookup.setAccessible(true);
            c.put("testLookup", ((ThreadLocal<?>) lookup.get(null)).get() != null);
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        }
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }
}
