package harvest.advice;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import java.lang.reflect.Method;

import static net.bytebuddy.matcher.ElementMatchers.isStatic;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;
import static net.bytebuddy.matcher.ElementMatchers.not;

/**
 * Kinds {@code chaosexp}, {@code autohalt} and {@code chaosprofile} (B4 row 4): the calls a test makes on
 * {@code ChaosExperimentOrchestrator} (with the test's clock reading), {@code ExperimentDefinition.fromJson},
 * {@code ChaosAutoHaltMonitor} (with the clock and the monitor's effective enabled flag, threshold and window),
 * {@code ChaosProfileLibrary}, {@code SloSampleStore.record} and the service and TCP chaos registries, outermost only and
 * under one depth key (the orchestrator's own registry calls are not recorded), in order, in chaosexp.jsonl.
 * Converted by kinds/chaosexp.py.
 */
public class ChaosexpAdvice implements Boundary {

    private static final String KEY = "chaosexp";
    private static final String PKG = "org.mockserver.mock.action.http.";

    @Override
    public String[] preload() {
        return new String[]{PKG + "ChaosExperimentOrchestrator", PKG + "ChaosExperimentOrchestrator$ExperimentDefinition",
            PKG + "ChaosAutoHaltMonitor", PKG + "ChaosProfileLibrary", "org.mockserver.slo.SloSampleStore",
            PKG + "ServiceChaosRegistry", PKG + "TcpChaosRegistry"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named(PKG + "ChaosExperimentOrchestrator"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ChaosexpAdvice.class)
                .on(not(isStatic()).and(namedOneOf("start", "stop", "reset", "getStatus", "getHistory", "advanceNow",
                    "triggerScheduledStartNow", "checkSloNow")))))
            .type(named(PKG + "ChaosExperimentOrchestrator$ExperimentDefinition"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ChaosexpAdvice.class)
                .on(isStatic().and(named("fromJson")))))
            .type(named(PKG + "ChaosAutoHaltMonitor"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ChaosexpAdvice.class)
                .on(not(isStatic()).and(namedOneOf("recordError", "reset", "getHaltCount", "currentWindowSize", "setConfiguration")))))
            .type(named(PKG + "ChaosProfileLibrary"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ChaosexpAdvice.class)
                .on(namedOneOf("save", "list", "get", "delete", "isValidName"))))
            .type(named("org.mockserver.slo.SloSampleStore"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ChaosexpAdvice.class)
                .on(not(isStatic()).and(named("record")))))
            .type(namedOneOf(PKG + "ServiceChaosRegistry", PKG + "TcpChaosRegistry"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ChaosexpAdvice.class)
                .on(not(isStatic()).and(namedOneOf("put", "get", "patch", "remove", "entries", "ttlRemainingMillis",
                    "activeCountByFaultType", "activeCount", "reset")))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter(KEY);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.This(optional = true) Object self,
                            @Advice.Origin("#t") String type, @Advice.Origin("#m") String method,
                            @Advice.AllArguments Object[] args, @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result,
                            @Advice.Thrown Throwable thrown) {
        if (outermost) {
            // still inside the depth key: what serialising calls (toJson, getInstance) is not recorded
            ChaosexpAdvice.called(self, type, method, args, result, thrown);
        }
        Recorder.exit(KEY);
    }

    public static void called(Object self, String type, String method, Object[] args, Object result, Throwable thrown) {
        String simple = type.substring(type.lastIndexOf('.') + 1);
        String owner = simple.contains("$") ? simple.substring(simple.indexOf('$') + 1) : simple;
        ObjectNode c = Recorder.base(owner + "." + method);
        c.put("owner", owner);
        c.put("call", method);
        c.put("thread", Thread.currentThread().getName());
        Recorder.enter("jackson");
        try {
            ObjectMapper mapper = org.mockserver.serialization.ObjectMapperFactory.createObjectMapper();
            if (self != null) {
                c.put("identity", System.identityHashCode(self));
                try {
                    Object shared = self.getClass().getMethod("getInstance").invoke(null);
                    c.put("shared", shared == self);
                } catch (NoSuchMethodException e) {
                    // ChaosProfileLibrary: one per HttpState
                    c.put("shared", false);
                }
            }
            if (owner.equals("ChaosExperimentOrchestrator") || owner.equals("ChaosAutoHaltMonitor")) {
                java.util.function.LongSupplier clock = (java.util.function.LongSupplier) Recorder.field(self, "clock");
                c.put("now", clock.getAsLong());
            }
            if (owner.equals("ChaosAutoHaltMonitor")) {
                c.put("enabled", (Boolean) invoke(self, "autoHaltEnabled"));
                c.put("threshold", (Long) invoke(self, "errorThreshold"));
                c.put("window", (Long) invoke(self, "windowMillis"));
            }
            ArrayNode a = c.putArray("args");
            for (Object arg : args) {
                a.add(value(mapper, arg));
            }
            if (result != null) {
                c.set("result", value(mapper, result));
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }

    private static Object invoke(Object target, String name) throws ReflectiveOperationException {
        Method m = target.getClass().getDeclaredMethod(name);
        m.setAccessible(true);
        return m.invoke(target);
    }

    private static JsonNode value(ObjectMapper mapper, Object arg) throws Exception {
        String pkg = PKG + "ChaosExperimentOrchestrator$";
        if (arg == null) {
            return mapper.nullNode();
        } else if (arg instanceof String) {
            return mapper.getNodeFactory().textNode((String) arg);
        } else if (arg instanceof Number || arg instanceof Boolean) {
            return mapper.valueToTree(arg);
        } else if (arg instanceof JsonNode) {
            return ((JsonNode) arg).deepCopy();
        } else if (arg instanceof java.util.Optional) {
            java.util.Optional<?> optional = (java.util.Optional<?>) arg;
            ObjectNode o = mapper.createObjectNode();
            o.put("present", optional.isPresent());
            if (optional.isPresent()) {
                o.set("value", value(mapper, optional.get()));
            }
            return o;
        } else if (arg instanceof java.util.Collection) {
            ArrayNode a = mapper.createArrayNode();
            for (Object o : (java.util.Collection<?>) arg) {
                a.add(value(mapper, o));
            }
            return a;
        } else if (arg instanceof java.util.Map) {
            ObjectNode o = mapper.createObjectNode();
            for (java.util.Map.Entry<?, ?> e : ((java.util.Map<?, ?>) arg).entrySet()) {
                o.set(String.valueOf(e.getKey()), value(mapper, e.getValue()));
            }
            return o;
        } else if (arg instanceof org.mockserver.model.HttpChaosProfile) {
            return mapper.valueToTree(new org.mockserver.serialization.model.HttpChaosProfileDTO((org.mockserver.model.HttpChaosProfile) arg));
        } else if (arg instanceof org.mockserver.model.TcpChaosProfile) {
            return mapper.valueToTree(new org.mockserver.serialization.model.TcpChaosProfileDTO((org.mockserver.model.TcpChaosProfile) arg));
        } else if (arg.getClass().getName().equals(pkg + "ExperimentDefinition")) {
            ObjectNode o = (ObjectNode) arg.getClass().getMethod("toJson").invoke(arg);
            // toJson leaves out a non-positive delay or baseline window, which validation reads
            long delay = (Long) arg.getClass().getField("startDelayMillis").get(arg);
            long baseline = (Long) arg.getClass().getField("baselineWindowMillis").get(arg);
            if (delay != 0) {
                o.put("startDelayMillis", delay);
            }
            if (baseline != 0) {
                o.put("baselineWindowMillis", baseline);
            }
            return o;
        } else if (arg.getClass().getName().startsWith(pkg)) {
            // ExperimentStatus, ExperimentHistoryEntry
            return (JsonNode) arg.getClass().getMethod("toJson").invoke(arg);
        } else if (arg instanceof Enum) {
            return mapper.getNodeFactory().textNode(((Enum<?>) arg).name());
        }
        return mapper.getNodeFactory().textNode(arg.getClass().getName());
    }
}
