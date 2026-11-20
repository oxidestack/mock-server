package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import static net.bytebuddy.matcher.ElementMatchers.isPublic;
import static net.bytebuddy.matcher.ElementMatchers.isStatic;
import static net.bytebuddy.matcher.ElementMatchers.not;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.returns;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code confput} (B4): the fluent setters of a {@code Configuration} instance, {@code
 * configuration.<name>(value)} called by a test's own code, each call one line of confput.jsonl with the setter's name, its argument as MockServer's
 * Jackson writes it, and the value the matching getter reads back afterwards (the Java side's answer, a cross-check
 * only). A running server's {@code Configuration} is the one {@code PUT /mockserver/configuration} sets and
 * {@code GET /mockserver/configuration} reads, so each call is replayed as that PUT with {@code {<name>: value}}
 * (kinds/confput.py).
 */
public class ConfputAdvice implements Boundary {

    private static final String KEY = "confput";
    private static final String CONFIGURATION = "org.mockserver.configuration.Configuration";

    @Override
    public String[] preload() {
        return new String[]{CONFIGURATION};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named(CONFIGURATION))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ConfputAdvice.class)
                .on(isPublic().and(not(isStatic())).and(takesArguments(1)).and(returns(named(CONFIGURATION))))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter(KEY);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.This Object configuration,
                            @Advice.Origin("#m") String method, @Advice.Argument(0) Object value,
                            @Advice.Thrown Throwable thrown) {
        Recorder.exit(KEY);
        if (outermost) {
            ConfputAdvice.set(configuration, method, value, thrown);
        }
    }

    /** Whether the setter was called by a test's own code: MockServer copies whole configurations through the same
     * setters (every field at its default), which no test chose. */
    private static boolean calledByTest() {
        for (StackTraceElement frame : new Throwable().getStackTrace()) {
            String type = frame.getClassName();
            // a test may call the setter reflectively (ConfigurationInstanceOnlyPropertiesTest)
            if (type.startsWith("harvest.") || type.equals(CONFIGURATION) || type.startsWith("java.lang.reflect.")
                || type.startsWith("jdk.internal.reflect.") || type.startsWith("sun.reflect.")) {
                continue;
            }
            int nested = type.indexOf('$');
            return (nested < 0 ? type : type.substring(0, nested)).endsWith("Test");
        }
        return false;
    }

    public static void set(Object configuration, String method, Object value, Throwable thrown) {
        if (!calledByTest()) {
            return;
        }
        ObjectNode c = Recorder.base("Configuration." + method);
        c.put("name", method);
        // MockServer's own mapper, as the control plane reads the PUT body with it; not itself a recorded "jackson" call
        Recorder.enter("jackson");
        Recorder.enter(KEY);
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = org.mockserver.serialization.ObjectMapperFactory.createObjectMapper();
            if (value == null) {
                c.putNull("value");
            } else {
                c.put("type", value.getClass().getName());
                c.set("value", mapper.valueToTree(value));
            }
            try {
                java.lang.reflect.Method getter = configuration.getClass().getMethod(method);
                Object read = getter.invoke(configuration);
                c.set("read", read == null ? null : mapper.valueToTree(read));
            } catch (NoSuchMethodException e) {
                c.put("noGetter", true);
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit(KEY);
            Recorder.exit("jackson");
        }
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }
}
