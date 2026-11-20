package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import org.mockserver.verify.VerificationTimes;

import static net.bytebuddy.matcher.ElementMatchers.isStatic;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code vtimes} (B4 by the kind machinery): {@code VerificationTimes}, outermost calls only.
 * {@code matches(count)} with the instance's bounds and its answer, {@code toString()} with the bounds, and a factory
 * ({@code exactly/atLeast/atMost/between}) that threw, with its method and arguments. Replayed as {@code count}
 * requests followed by {@code PUT /mockserver/verify} with the bounds as the JSON form writes them (-1 omitted), whose
 * 202 or 406 text shows both the comparison and the {@code toString()} wording.
 */
public class VtimesAdvice implements Boundary {

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.verify.VerificationTimes"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.verify.VerificationTimes"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(MatchesCall.class).on(named("matches").and(takesArguments(int.class))))
                .visit(Advice.to(ToStringCall.class).on(named("toString").and(takesArguments(0))))
                .visit(Advice.to(FactoryCall.class).on(isStatic().and(named("exactly").or(named("atLeast")).or(named("atMost")).or(named("between"))))));
    }

    public static class MatchesCall {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("vtimes");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object times, @Advice.Argument(0) int count,
                                @Advice.Return boolean result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("vtimes");
            if (outermost) {
                ObjectNode c = VtimesAdvice.bounds("matches", times);
                c.put("count", count);
                c.put("result", result);
                Recorder.outcome(c, thrown);
                Recorder.write("vtimes", c);
            }
        }
    }

    public static class ToStringCall {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("vtimes");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object times, @Advice.Return String result,
                                @Advice.Thrown Throwable thrown) {
            Recorder.exit("vtimes");
            if (outermost) {
                ObjectNode c = VtimesAdvice.bounds("toString", times);
                c.put("result", result);
                Recorder.outcome(c, thrown);
                Recorder.write("vtimes", c);
            }
        }
    }

    public static class FactoryCall {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("vtimes");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#m") String method,
                                @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
            Recorder.exit("vtimes");
            if (outermost && thrown != null) {
                ObjectNode c = Recorder.base("VerificationTimes." + method);
                c.put("call", "factory");
                c.put("method", method);
                for (int i = 0; i < args.length; i++) {
                    c.put("arg" + i, (Integer) args[i]);
                }
                Recorder.outcome(c, thrown);
                Recorder.write("vtimes", c);
            }
        }
    }

    public static ObjectNode bounds(String call, Object times) {
        ObjectNode c = Recorder.base("VerificationTimes." + call);
        c.put("call", call);
        c.put("atLeast", ((VerificationTimes) times).getAtLeast());
        c.put("atMost", ((VerificationTimes) times).getAtMost());
        return c;
    }
}
