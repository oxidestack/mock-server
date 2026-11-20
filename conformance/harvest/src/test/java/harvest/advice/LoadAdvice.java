package harvest.advice;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
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
 * Kinds {@code ratelimit}, {@code loadreg}, {@code loadorch}, {@code loadgen}, {@code loadfeeder} and {@code slo} (B4 row
 * 10),
 * under one depth key, outermost call only (the two-argument {@code tryAcquire} delegates, {@code start} calls
 * {@code validate}, the endpoints call the generators, the evaluator, the registry and the orchestrator):
 * <ul>
 * <li>{@code RateLimitRegistry.tryAcquire}/{@code reset}: the rate limit as its DTO, the fallback key, the registry's
 * clock reading, whether it is the process-wide registry, the decision, the static {@code rateLimitMaxNamedQuotas};</li>
 * <li>{@code LoadScenarioRegistry} {@code load/get/list/contains/delete/clear}: arguments and result;</li>
 * <li>{@code LoadScenarioOrchestrator.validate/start}: the scenario through {@code LoadScenarioSerializer}, the
 * orchestrator configuration's load-generation caps, the error (null when accepted);</li>
 * <li>{@code LoadScenarioFromRecording.generate} and {@code LoadScenarioFromOpenAPI.generate}: the arguments (recorded
 * requests through {@code HttpRequestSerializer}, the profile as its DTO), the scenario generated or the exception;</li>
 * <li>{@code LoadFeeder.resolvedRows}: the feeder as the {@code feeder} of a scenario, the number of rows or the
 * exception;</li>
 * <li>{@code SloEvaluator.evaluate}: the criteria and verdict through {@code SloCriteriaSerializer}, the sample store's
 * size and the SLO configuration.</li>
 * </ul>
 * Replayed through the expectation, loadScenario and verifySLO endpoints (kinds/load.py).
 */
public class LoadAdvice implements Boundary {

    private static final String KEY = "load";
    private static final String RATE_LIMIT = "org.mockserver.ratelimit.RateLimitRegistry";
    private static final String REGISTRY = "org.mockserver.mock.action.http.LoadScenarioRegistry";
    private static final String ORCHESTRATOR = "org.mockserver.mock.action.http.LoadScenarioOrchestrator";
    private static final String FROM_RECORDING = "org.mockserver.load.LoadScenarioFromRecording";
    private static final String FROM_OPENAPI = "org.mockserver.load.LoadScenarioFromOpenAPI";
    private static final String EVALUATOR = "org.mockserver.slo.SloEvaluator";
    private static final String FEEDER = "org.mockserver.load.LoadFeeder";

    @Override
    public String[] preload() {
        return new String[]{RATE_LIMIT, REGISTRY, ORCHESTRATOR, FROM_RECORDING, FROM_OPENAPI, EVALUATOR, FEEDER};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named(RATE_LIMIT))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Instance.class)
                .on(isPublic().and(not(isStatic())).and(namedOneOf("tryAcquire", "reset")))))
            .type(named(REGISTRY))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Instance.class)
                .on(isPublic().and(not(isStatic())).and(namedOneOf("load", "get", "list", "contains", "delete", "clear")))))
            .type(named(ORCHESTRATOR))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Instance.class)
                .on(isPublic().and(not(isStatic())).and(namedOneOf("validate", "start")))))
            .type(named(EVALUATOR))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Instance.class)
                .on(isPublic().and(not(isStatic())).and(named("evaluate")))))
            .type(named(FEEDER))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Instance.class)
                .on(isPublic().and(not(isStatic())).and(named("resolvedRows")))))
            .type(namedOneOf(FROM_RECORDING, FROM_OPENAPI))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Static.class)
                .on(isPublic().and(isStatic()).and(named("generate")))));
    }

    public static class Instance {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter(KEY);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.Origin("#m") String method,
                                @Advice.AllArguments Object[] args, @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result,
                                @Advice.Thrown Throwable thrown) {
            Recorder.exit(KEY);
            if (outermost) {
                LoadAdvice.called(self, self.getClass().getName(), method, args, result, thrown);
            }
        }
    }

    public static class Static {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter(KEY);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#t") String type, @Advice.Origin("#m") String method,
                                @Advice.AllArguments Object[] args, @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result,
                                @Advice.Thrown Throwable thrown) {
            Recorder.exit(KEY);
            if (outermost) {
                LoadAdvice.called(null, type, method, args, result, thrown);
            }
        }
    }

    public static void called(Object self, String type, String method, Object[] args, Object result, Throwable thrown) {
        String simple = type.substring(type.lastIndexOf('.') + 1);
        ObjectNode c = Recorder.base(simple + "." + method);
        c.put("call", method);
        if (self != null) {
            c.put("identity", System.identityHashCode(self));
        }
        String key;
        Recorder.enter("jackson");
        try {
            ObjectMapper mapper = org.mockserver.serialization.ObjectMapperFactory.createObjectMapper();
            org.mockserver.logging.MockServerLogger logger = new org.mockserver.logging.MockServerLogger();
            switch (type) {
                case RATE_LIMIT:
                    key = "ratelimit";
                    rateLimit(c, mapper, self, method, args, result);
                    break;
                case REGISTRY:
                    key = "loadreg";
                    registry(c, mapper, args, result);
                    break;
                case ORCHESTRATOR:
                    key = "loadorch";
                    orchestrator(c, mapper, logger, self, args, result);
                    break;
                case EVALUATOR:
                    key = "slo";
                    evaluator(c, mapper, logger, self, args, result);
                    break;
                case FEEDER:
                    // the feeder as the `feeder` of a scenario (it has no DTO of its own)
                    key = "loadfeeder";
                    c.put("scenario", new org.mockserver.serialization.LoadScenarioSerializer(logger).serialize(
                        new org.mockserver.load.LoadScenario().withName("harvested").withFeeder((org.mockserver.load.LoadFeeder) self)));
                    if (result != null) {
                        c.put("rows", ((java.util.List<?>) result).size());
                    }
                    break;
                default:
                    key = "loadgen";
                    generator(c, mapper, logger, simple, args, result);
            }
        } catch (Throwable e) {
            key = type.equals(RATE_LIMIT) ? "ratelimit" : type.equals(REGISTRY) ? "loadreg" : type.equals(ORCHESTRATOR) ? "loadorch"
                : type.equals(EVALUATOR) ? "slo" : type.equals(FEEDER) ? "loadfeeder" : "loadgen";
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.outcome(c, thrown);
        Recorder.write(key, c);
    }

    private static void rateLimit(ObjectNode c, ObjectMapper mapper, Object registry, String method, Object[] args, Object result) throws Exception {
        Object shared = registry.getClass().getMethod("getInstance").invoke(null);
        c.put("shared", shared == registry);
        java.util.function.LongSupplier clock = (java.util.function.LongSupplier) Recorder.field(registry, "clock");
        c.put("now", clock.getAsLong());
        c.put("rateLimitMaxNamedQuotas", org.mockserver.configuration.ConfigurationProperties.rateLimitMaxNamedQuotas());
        if (method.equals("tryAcquire")) {
            if (args[0] == null) {
                c.putNull("rateLimit");
            } else {
                c.set("rateLimit", mapper.valueToTree(new org.mockserver.serialization.model.RateLimitDTO((org.mockserver.model.RateLimit) args[0])));
            }
            if (args[1] == null) {
                c.putNull("key");
            } else {
                c.put("key", (String) args[1]);
            }
            c.put("configuration", args.length > 2 && args[2] != null);
            if (result != null) {
                ObjectNode d = c.putObject("decision");
                for (String f : new String[]{"allowed", "limit", "remaining", "resetEpochSecond", "retryAfterSeconds"}) {
                    try {
                        java.lang.reflect.Field field = result.getClass().getField(f);
                        d.put(f, String.valueOf(field.get(result)));
                    } catch (NoSuchFieldException ignored) {
                        // not every decision field exists in every version
                    }
                }
            }
        }
    }

    private static void registry(ObjectNode c, ObjectMapper mapper, Object[] args, Object result) {
        ArrayNode a = c.putArray("args");
        for (Object arg : args) {
            if (arg == null) {
                a.addNull();
            } else if (arg instanceof com.fasterxml.jackson.databind.JsonNode) {
                a.add(((com.fasterxml.jackson.databind.JsonNode) arg).deepCopy());
            } else {
                a.add(String.valueOf(arg));
            }
        }
        if (result instanceof java.util.Optional) {
            java.util.Optional<?> optional = (java.util.Optional<?>) result;
            c.put("result", optional.isPresent() ? String.valueOf(optional.get()) : "empty");
        } else if (result != null) {
            c.put("result", String.valueOf(result));
        }
    }

    private static final String[] LOAD_CONFIGURATION = {"loadGenerationEnabled", "loadGenerationMaxVirtualUsers", "loadGenerationMaxInFlightRequests",
        "loadGenerationMaxRequestsPerSecond", "loadGenerationMaxDurationMillis", "loadGenerationMaxSteps", "loadGenerationMaxRate",
        "loadGenerationMaxStages", "loadGenerationMaxConcurrentScenarios", "loadGenerationSuppressEventLog", "sloTrackingEnabled"};

    private static void configuration(ObjectNode c, Object configuration, String[] names) throws Exception {
        ObjectNode config = c.putObject("configuration");
        for (String name : names) {
            Object value = configuration.getClass().getMethod(name).invoke(configuration);
            config.put(name, String.valueOf(value));
        }
    }

    private static void orchestrator(ObjectNode c, ObjectMapper mapper, org.mockserver.logging.MockServerLogger logger, Object orchestrator,
                                     Object[] args, Object result) throws Exception {
        Object shared = orchestrator.getClass().getMethod("getInstance").invoke(null);
        c.put("shared", shared == orchestrator);
        configuration(c, Recorder.field(orchestrator, "configuration"), LOAD_CONFIGURATION);
        org.mockserver.load.LoadScenario scenario = (org.mockserver.load.LoadScenario) args[0];
        if (scenario == null) {
            c.putNull("scenario");
        } else {
            try {
                c.put("scenario", new org.mockserver.serialization.LoadScenarioSerializer(logger).serialize(scenario));
            } catch (Throwable e) {
                c.put("unserialisable", "scenario: " + e);
            }
        }
        if (args.length > 1) {
            c.put("sender", args[1] == null ? "installed" : args[1].getClass().getName());
        }
        if (result != null) {
            c.put("error", String.valueOf(result));
        }
    }

    private static void evaluator(ObjectNode c, ObjectMapper mapper, org.mockserver.logging.MockServerLogger logger, Object evaluator,
                                  Object[] args, Object result) throws Exception {
        Object store = Recorder.field(evaluator, "sampleStore");
        c.put("storeSize", (Integer) store.getClass().getMethod("size").invoke(store));
        c.put("sharedStore", store == org.mockserver.slo.SloSampleStore.getInstance());
        org.mockserver.serialization.SloCriteriaSerializer serializer = new org.mockserver.serialization.SloCriteriaSerializer(logger);
        if (args[0] != null) {
            c.put("criteria", serializer.serialize((org.mockserver.slo.SloCriteria) args[0]));
        }
        if (result != null) {
            c.put("verdict", serializer.serialize((org.mockserver.slo.SloVerdict) result));
        }
        c.put("sloTrackingEnabled", String.valueOf(org.mockserver.configuration.ConfigurationProperties.sloTrackingEnabled()));
    }

    private static void generator(ObjectNode c, ObjectMapper mapper, org.mockserver.logging.MockServerLogger logger, String simple,
                                  Object[] args, Object result) throws Exception {
        c.put("generator", simple);
        c.put("name", args[0] == null ? null : String.valueOf(args[0]));
        int targetIndex;
        int profileIndex;
        if (simple.equals("LoadScenarioFromRecording")) {
            // generate(name, recordedRequests, mode, maxSteps, target, profile)
            if (args[1] == null) {
                c.putNull("recorded");
            } else {
                ArrayNode recorded = c.putArray("recorded");
                org.mockserver.serialization.HttpRequestSerializer requests = new org.mockserver.serialization.HttpRequestSerializer(logger);
                for (Object request : (java.util.List<?>) args[1]) {
                    if (request instanceof org.mockserver.model.HttpRequest) {
                        recorded.add(mapper.readTree(requests.serialize((org.mockserver.model.HttpRequest) request)));
                    } else {
                        recorded.add(String.valueOf(request));
                    }
                }
            }
            c.put("mode", args[2] == null ? null : String.valueOf(args[2]));
            if (args[3] == null) {
                c.putNull("maxSteps");
            } else {
                c.put("maxSteps", (Integer) args[3]);
            }
            targetIndex = 4;
            profileIndex = 5;
        } else {
            // generate(name, specUrlOrPayload, target, profile, logger)
            c.put("specUrlOrPayload", args[1] == null ? null : String.valueOf(args[1]));
            targetIndex = 2;
            profileIndex = 3;
        }
        Object target = args[targetIndex];
        if (target == null) {
            c.putNull("target");
        } else {
            ObjectNode t = c.putObject("target");
            Object host = target.getClass().getMethod("getHost").invoke(target);
            Object port = target.getClass().getMethod("getPort").invoke(target);
            Object scheme = target.getClass().getMethod("getScheme").invoke(target);
            if (host != null) {
                t.put("host", String.valueOf(host));
            }
            if (port != null) {
                t.put("port", (Integer) port);
            }
            if (scheme != null) {
                t.put("scheme", String.valueOf(scheme));
            }
        }
        Object profile = args[profileIndex];
        if (profile == null) {
            c.putNull("profile");
        } else {
            c.set("profile", mapper.valueToTree(new org.mockserver.serialization.model.LoadProfileDTO((org.mockserver.load.LoadProfile) profile)));
        }
        if (result != null) {
            c.put("scenario", new org.mockserver.serialization.LoadScenarioSerializer(logger).serialize((org.mockserver.load.LoadScenario) result));
        }
    }
}
