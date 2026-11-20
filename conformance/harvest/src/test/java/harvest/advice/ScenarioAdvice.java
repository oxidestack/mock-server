package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import static net.bytebuddy.matcher.ElementMatchers.isPublic;
import static net.bytebuddy.matcher.ElementMatchers.isStatic;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;
import static net.bytebuddy.matcher.ElementMatchers.not;

/**
 * Kind {@code scenario} (B4): every public call of {@code ScenarioManager} made by a test (outermost only:
 * the single-argument overloads delegate to the composite-key ones, and a synchronous scheduler runs a timed
 * transition's {@code matchesAndTransition} inside {@code scheduleTransition}), one line each in scenario.jsonl, with
 * its arguments, its result and the manager instance's identity. For {@code scheduleTransition} the transition's
 * fields and the scenario's state when it was scheduled. Replayed through the scenario endpoints and probe
 * expectations (kinds/scenario.py).
 */
public class ScenarioAdvice implements Boundary {

    private static final String KEY = "scenario";

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.mock.ScenarioManager"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(net.bytebuddy.matcher.ElementMatchers.named("org.mockserver.mock.ScenarioManager"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ScenarioAdvice.class)
                .on(isPublic().and(not(isStatic())).and(namedOneOf("getState", "setState", "matchesState", "matchesAndTransition",
                    "transitionState", "clear", "reset", "getAllStates", "getAllStatesStructured", "scheduleTransition",
                    "cancelPendingTransition", "cancelAllPendingTransitions")))));
    }

    @Advice.OnMethodEnter
    public static String enter(@Advice.This Object manager, @Advice.Origin("#m") String method, @Advice.AllArguments Object[] args) {
        if (!Recorder.enter(KEY)) {
            return null;
        }
        if (method.equals("scheduleTransition")) {
            // the state the transition's guard will see (a nested, unrecorded getState)
            return ScenarioAdvice.stateBefore(manager, args[0]);
        }
        return "";
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter String before, @Advice.This Object manager, @Advice.Origin("#m") String method,
                            @Advice.AllArguments Object[] args, @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result,
                            @Advice.Thrown Throwable thrown) {
        Recorder.exit(KEY);
        if (before != null) {
            ScenarioAdvice.called(manager, method, args, result, thrown, before);
        }
    }

    public static String stateBefore(Object manager, Object transition) {
        try {
            Object name = transition.getClass().getMethod("getScenarioName").invoke(transition);
            return (String) manager.getClass().getMethod("getState", String.class).invoke(manager, name);
        } catch (Throwable e) {
            return "";
        }
    }

    public static void called(Object manager, String method, Object[] args, Object result, Throwable thrown, String before) {
        ObjectNode c = Recorder.base("ScenarioManager." + method);
        c.put("call", method);
        c.put("manager", System.identityHashCode(manager));
        c.put("thread", Thread.currentThread().getName());
        com.fasterxml.jackson.databind.node.ArrayNode a = c.putArray("args");
        try {
            for (Object arg : args) {
                if (arg == null) {
                    a.addNull();
                } else if (arg instanceof String) {
                    a.add((String) arg);
                } else if (arg.getClass().getName().equals("org.mockserver.model.TimedScenarioTransition")) {
                    ObjectNode t = a.addObject();
                    t.put("scenarioName", (String) arg.getClass().getMethod("getScenarioName").invoke(arg));
                    t.put("currentState", (String) arg.getClass().getMethod("getCurrentState").invoke(arg));
                    t.put("nextState", (String) arg.getClass().getMethod("getNextState").invoke(arg));
                    Object after = arg.getClass().getMethod("getTransitionAfterMs").invoke(arg);
                    if (after != null) {
                        t.put("transitionAfterMs", ((Number) after).longValue());
                    }
                } else {
                    // the Scheduler of scheduleTransition: synchronous or not
                    a.add(arg.getClass().getName() + ":" + String.valueOf(Recorder.field(arg, "synchronous")));
                }
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        }
        if (method.equals("scheduleTransition")) {
            c.put("stateBefore", before);
        }
        if (result != null) {
            c.put("result", String.valueOf(result));
        }
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }
}
