package harvest.advice;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import org.mockserver.logging.MockServerLogger;

import java.lang.reflect.Field;
import java.util.Map;
import java.util.TreeMap;

import static net.bytebuddy.matcher.ElementMatchers.isPublic;
import static net.bytebuddy.matcher.ElementMatchers.isStatic;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kinds {@code llmreport} and {@code llmsniff} (B4), under the LLM depth key {@code llm} of the
 * codec, handler and matcher boundaries, so that only the outermost LLM call is recorded (a codec's {@code decode} or
 * a sniffer call made while a report is built is not recorded again):
 * <ul>
 *   <li>{@code LlmOptimisationReportService.build(pairs, filter)}, {@code LlmOptimisationReportBuilder.build(exchanges, …)}
 *   and {@code LlmDatasetExporter.export(exchanges, format, redactor)}: the captured exchanges (request, response,
 *   latency), the service's filter, the dataset format and the configuration the report reads (kind
 *   {@code llmreport});</li>
 *   <li>the public static {@code LlmProviderSniffer} detection methods: their request, response, host and path
 *   arguments (kind {@code llmsniff}).</li>
 * </ul>
 * Both become recorded traffic re-imported into the event log ({@code PUT /mockserver/import?format=recording}) and
 * read back through {@code GET /mockserver/llm/optimisationReport} (see {@code kinds/llmreport.py}).
 */
public class LlmReportAdvice implements Boundary {

    /** The configuration values the report and the sniffer read, at the run's start (before any test sets one). */
    private static final Map<String, String> DEFAULTS = new TreeMap<>();

    public LlmReportAdvice() {
        DEFAULTS.putAll(configuration(null));
    }

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.llm.analysis.LlmOptimisationReportService", "org.mockserver.llm.analysis.LlmOptimisationReportBuilder",
            "org.mockserver.llm.analysis.LlmDatasetExporter", "org.mockserver.llm.client.LlmProviderSniffer"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.llm.analysis.LlmOptimisationReportService"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Report.class)
                .on(named("build").and(takesArguments(2)))))
            .type(named("org.mockserver.llm.analysis.LlmOptimisationReportBuilder"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Report.class)
                .on(named("build").and(takesArguments(5)))))
            .type(named("org.mockserver.llm.analysis.LlmDatasetExporter"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Report.class)
                .on(named("export").and(takesArguments(3)))))
            .type(named("org.mockserver.llm.client.LlmProviderSniffer"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Sniff.class)
                .on(isPublic().and(isStatic()).and(namedOneOf("sniff", "detectForAnalysis", "sniffByBodyShape", "sniffByPath",
                    "sniffByHost", "sniffByHostAndPath", "extractModelFromResponse", "extractModelFromRequest")))));
    }

    public static class Report {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("llm");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.Origin("#t.#m") String method,
                                @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
            Recorder.exit("llm");
            if (outermost) {
                LlmReportAdvice.report(self, method, args, thrown);
            }
        }
    }

    public static class Sniff {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("llm");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#m") String method, @Advice.AllArguments Object[] args,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("llm");
            if (outermost) {
                LlmReportAdvice.sniff(method, args, result, thrown);
            }
        }
    }

    private static Object field(Object target, String name) throws ReflectiveOperationException {
        for (Class<?> c = target.getClass(); c != null; c = c.getSuperclass()) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(target);
            } catch (NoSuchFieldException ignored) {
                // look further up
            }
        }
        throw new NoSuchFieldException(name);
    }

    /** The values the report service ({@code configuration}, else the static store) and the sniffer read. */
    private static Map<String, String> configuration(Object configuration) {
        Map<String, String> values = new TreeMap<>();
        org.mockserver.configuration.Configuration c = (org.mockserver.configuration.Configuration) configuration;
        values.put("llmOptimisationMaxCalls", String.valueOf(c != null ? c.llmOptimisationMaxCalls()
            : org.mockserver.configuration.ConfigurationProperties.llmOptimisationMaxCalls()));
        values.put("fixtureBodyRedactFields", String.valueOf(c != null ? c.fixtureBodyRedactFields()
            : org.mockserver.configuration.ConfigurationProperties.fixtureBodyRedactFields()));
        Object installed = null;
        try {
            Field f = org.mockserver.llm.client.LlmProviderSniffer.class.getDeclaredField("installedConfiguration");
            f.setAccessible(true);
            installed = f.get(null);
        } catch (ReflectiveOperationException ignored) {
            // the static store
        }
        org.mockserver.configuration.Configuration s = (org.mockserver.configuration.Configuration) installed;
        values.put("llmProvider", String.valueOf(s != null ? s.llmProvider() : org.mockserver.configuration.ConfigurationProperties.llmProvider()));
        values.put("llmBaseUrl", String.valueOf(s != null ? s.llmBaseUrl() : org.mockserver.configuration.ConfigurationProperties.llmBaseUrl()));
        return values;
    }

    private static void differences(ObjectNode c, Map<String, String> values) {
        ObjectNode differences = c.putObject("configuration");
        values.forEach((name, value) -> {
            if (!value.equals(DEFAULTS.get(name))) {
                differences.put(name, value);
            }
        });
    }

    private static String request(Object request) {
        return request == null ? null : new org.mockserver.serialization.HttpRequestSerializer(new MockServerLogger())
            .serialize((org.mockserver.model.HttpRequest) request);
    }

    private static String response(Object response) {
        return response == null ? null : new org.mockserver.serialization.HttpResponseSerializer(new MockServerLogger())
            .serialize((org.mockserver.model.HttpResponse) response);
    }

    private static void exchanges(ObjectNode c, Object list) {
        if (list == null) {
            c.putNull("exchanges");
            return;
        }
        ArrayNode out = c.putArray("exchanges");
        for (Object e : (java.util.List<?>) list) {
            ObjectNode n = out.addObject();
            if (e == null) {
                n.put("null", true);
            } else if (e instanceof org.mockserver.model.LogEventRequestAndResponse) {
                org.mockserver.model.LogEventRequestAndResponse pair = (org.mockserver.model.LogEventRequestAndResponse) e;
                n.put("request", request(pair.getHttpRequest()));
                n.put("response", response(pair.getHttpResponse()));
            } else {
                org.mockserver.llm.analysis.LlmOptimisationReportBuilder.CapturedExchange x =
                    (org.mockserver.llm.analysis.LlmOptimisationReportBuilder.CapturedExchange) e;
                n.put("request", request(x.getRequest()));
                n.put("response", response(x.getResponse()));
                if (x.getLatencyMs() != null) {
                    n.put("latencyMs", x.getLatencyMs());
                }
            }
        }
    }

    public static void report(Object self, String method, Object[] args, Throwable thrown) {
        String simple = method.substring(method.lastIndexOf('.', method.lastIndexOf('.') - 1) + 1);
        ObjectNode c = Recorder.base(simple);
        Recorder.enter("jackson");
        try {
            exchanges(c, args[0]);
            if (simple.startsWith("LlmOptimisationReportService.")) {
                c.put("call", "service");
                differences(c, configuration(field(self, "configuration")));
                if (args[1] != null) {
                    ObjectNode filter = c.putObject("filter");
                    for (String name : new String[]{"session", "host", "provider"}) {
                        filter.put(name, (String) field(args[1], name));
                    }
                }
            } else if (simple.startsWith("LlmOptimisationReportBuilder.")) {
                c.put("call", "builder");
                differences(c, configuration(null));
            } else {
                c.put("call", "dataset");
                c.put("format", args[1] == null ? null : ((Enum<?>) args[1]).name());
                Map<String, String> values = configuration(null);
                if (args[2] != null) {
                    // the redactor stands for the configured body fields (headers and query parameters are the defaults)
                    java.util.Set<?> fields = (java.util.Set<?>) field(args[2], "sensitiveBodyFields");
                    java.util.List<String> names = new java.util.ArrayList<>();
                    for (Object f : fields) {
                        names.add(String.valueOf(f));
                    }
                    values.put("fixtureBodyRedactFields", String.join(",", names));
                    java.util.Set<?> headers = (java.util.Set<?>) field(args[2], "sensitiveHeaders");
                    if (!new java.util.TreeSet<>(headers).equals(new java.util.TreeSet<>(org.mockserver.fixture.FixtureRedactor.defaultSensitiveHeaders()))) {
                        c.put("customRedactor", true);
                    }
                }
                differences(c, values);
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.outcome(c, thrown);
        Recorder.write("llmreport", c);
    }

    public static void sniff(String method, Object[] args, Object result, Throwable thrown) {
        ObjectNode c = Recorder.base("LlmProviderSniffer." + method);
        Recorder.enter("jackson");
        try {
            c.put("call", method);
            switch (method) {
                case "sniffByHost":
                    c.put("host", (String) args[0]);
                    break;
                case "sniffByHostAndPath":
                    c.put("host", (String) args[0]);
                    c.put("path", (String) args[1]);
                    break;
                case "extractModelFromResponse":
                    c.put("response", response(args[0]));
                    break;
                default:
                    c.put("request", request(args[0]));
                    if (args.length > 1) {
                        c.put("response", response(args[1]));
                    }
            }
            differences(c, configuration(null));
            if (thrown == null) {
                c.put("result", result instanceof java.util.Optional
                    ? ((java.util.Optional<?>) result).map(String::valueOf).orElse(null) : (String) result);
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.outcome(c, thrown);
        Recorder.write("llmsniff", c);
    }
}
