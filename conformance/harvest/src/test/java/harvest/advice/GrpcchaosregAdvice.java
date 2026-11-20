package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import static net.bytebuddy.matcher.ElementMatchers.isPublic;
import static net.bytebuddy.matcher.ElementMatchers.isStatic;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;
import static net.bytebuddy.matcher.ElementMatchers.not;

/**
 * Kind {@code grpcchaosreg} (B4): every public call of {@code GrpcChaosRegistry} made by a test (outermost
 * only: the two-argument {@code put} delegates to the TTL one), one line each in grpcchaosreg.jsonl: whether the
 * registry is the process-wide instance (the one {@code /mockserver/grpcChaos} uses) or a test's own (built with its
 * own clock), the service, the profile as its endpoint DTO, the TTL and the result. Replayed through that endpoint
 * (kinds/grpcchaosreg.py).
 */
public class GrpcchaosregAdvice implements Boundary {

    private static final String KEY = "grpcchaosreg";
    private static final String TYPE = "org.mockserver.mock.action.http.GrpcChaosRegistry";

    @Override
    public String[] preload() {
        return new String[]{TYPE};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named(TYPE))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(GrpcchaosregAdvice.class)
                .on(isPublic().and(not(isStatic())).and(namedOneOf("put", "get", "patch", "remove", "entries", "ttlRemainingMillis",
                    "activeCountByFaultType", "activeCount", "incrementMatchCount", "reset")))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter(KEY);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.This Object registry, @Advice.Origin("#m") String method,
                            @Advice.AllArguments Object[] args, @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result,
                            @Advice.Thrown Throwable thrown) {
        Recorder.exit(KEY);
        if (outermost) {
            GrpcchaosregAdvice.called(registry, method, args, result, thrown);
        }
    }

    public static void called(Object registry, String method, Object[] args, Object result, Throwable thrown) {
        ObjectNode c = Recorder.base("GrpcChaosRegistry." + method);
        c.put("call", method);
        c.put("identity", System.identityHashCode(registry));
        Recorder.enter("jackson");
        try {
            Object shared = registry.getClass().getMethod("getInstance").invoke(null);
            c.put("shared", shared == registry);
            com.fasterxml.jackson.databind.ObjectMapper mapper = org.mockserver.serialization.ObjectMapperFactory.createObjectMapper();
            com.fasterxml.jackson.databind.node.ArrayNode a = c.putArray("args");
            for (Object arg : args) {
                if (arg == null) {
                    a.addNull();
                } else if (arg instanceof String) {
                    a.add((String) arg);
                } else if (arg instanceof Long) {
                    a.add((Long) arg);
                } else if (arg instanceof org.mockserver.model.GrpcChaosProfile) {
                    a.add(mapper.valueToTree(new org.mockserver.serialization.model.GrpcChaosProfileDTO((org.mockserver.model.GrpcChaosProfile) arg)));
                } else {
                    a.add(arg.getClass().getName());
                }
            }
            if (result != null) {
                c.put("result", String.valueOf(result));
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }
}
