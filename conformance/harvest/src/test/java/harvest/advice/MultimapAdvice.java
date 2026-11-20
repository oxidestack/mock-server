package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import org.mockserver.logging.MockServerLogger;
import org.mockserver.model.Cookie;
import org.mockserver.model.Cookies;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.KeyMatchStyle;
import org.mockserver.model.NottableString;
import org.mockserver.model.Parameter;
import org.mockserver.model.Parameters;
import org.mockserver.serialization.HttpRequestSerializer;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code multimap} (B4 by the kind machinery): the contain-all algorithm of the {@code collections}
 * tests, outermost call only (one depth key for all three, so {@code containsAll} calling {@code containsSubset} is one
 * case). {@code NottableStringMultiMap.containsAll(logger, context, matcher)} (multi-valued, a key match style) is lifted
 * to {@code queryStringParameters}, {@code NottableStringHashMap.containsAll} (single-valued) to {@code cookies}, and
 * {@code SubSetMatcher.containsSubset(logger, context, regexStringMatcher, subset, superset)} to
 * {@code queryStringParameters} with the entries grouped by key. Each side is written by a fresh
 * {@code HttpRequestSerializer}: {@code matcher} the subset side, {@code actual} the side it is looked for in, and
 * {@code controlPlaneMatcher} the flag of the receiving map's {@code RegexStringMatcher}, so harvest.py's
 * {@code convert_match} replays it as an expectation and a request, or as a retrieve filter.
 */
public class MultimapAdvice implements Boundary {

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.collections.NottableStringMultiMap", "org.mockserver.collections.NottableStringHashMap",
            "org.mockserver.collections.SubSetMatcher"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.collections.NottableStringMultiMap").or(named("org.mockserver.collections.NottableStringHashMap")))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ContainsAllCall.class)
                .on(named("containsAll").and(takesArguments(3)))))
            .type(named("org.mockserver.collections.SubSetMatcher"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ContainsSubsetCall.class)
                .on(named("containsSubset").and(takesArguments(5)))));
    }

    public static class ContainsAllCall {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("multimap");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object matched, @Advice.Argument(2) Object matcher,
                                @Advice.Return boolean result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("multimap");
            if (outermost) {
                MultimapAdvice.recordContainsAll(matched, matcher, result, thrown);
            }
        }
    }

    public static class ContainsSubsetCall {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("multimap");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.AllArguments Object[] args,
                                @Advice.Return boolean result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("multimap");
            if (outermost) {
                MultimapAdvice.recordContainsSubset(args, result, thrown);
            }
        }
    }

    @SuppressWarnings("unchecked")
    public static void recordContainsAll(Object matched, Object matcher, boolean result, Throwable thrown) {
        boolean multi = matched.getClass().getSimpleName().equals("NottableStringMultiMap");
        ObjectNode c = Recorder.base(matched.getClass().getSimpleName() + ".containsAll");
        try {
            c.put("controlPlaneMatcher", (Boolean) Recorder.field(Recorder.field(matched, "regexStringMatcher"), "controlPlaneMatcher"));
            if (multi) {
                KeyMatchStyle style = (KeyMatchStyle) matcher.getClass().getMethod("getKeyMatchStyle").invoke(matcher);
                c.put("form", "queryStringParameters");
                c.put("keyMatchStyle", style.name());
                c.put("matcher", serialize(query((Map<NottableString, List<NottableString>>) Recorder.field(matcher, "backingMap"), style)));
                c.put("actual", serialize(query((Map<NottableString, List<NottableString>>) Recorder.field(matched, "backingMap"), KeyMatchStyle.SUB_SET)));
            } else {
                c.put("form", "cookies");
                c.put("matcher", serialize(cookies((Map<NottableString, NottableString>) Recorder.field(matcher, "backingMap"))));
                c.put("actual", serialize(cookies((Map<NottableString, NottableString>) Recorder.field(matched, "backingMap"))));
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        }
        c.put("result", result);
        Recorder.outcome(c, thrown);
        Recorder.write("multimap", c);
    }

    public static void recordContainsSubset(Object[] args, boolean result, Throwable thrown) {
        ObjectNode c = Recorder.base("SubSetMatcher.containsSubset");
        try {
            c.put("controlPlaneMatcher", (Boolean) Recorder.field(args[2], "controlPlaneMatcher"));
            c.put("form", "queryStringParameters");
            c.put("matcher", serialize(query(grouped((List<?>) args[3]), KeyMatchStyle.SUB_SET)));
            c.put("actual", serialize(query(grouped((List<?>) args[4]), KeyMatchStyle.SUB_SET)));
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        }
        c.put("result", result);
        Recorder.outcome(c, thrown);
        Recorder.write("multimap", c);
    }

    private static Map<NottableString, List<NottableString>> grouped(List<?> entries) {
        Map<NottableString, List<NottableString>> map = new LinkedHashMap<>();
        for (Object entry : entries) {
            Map.Entry<?, ?> e = (Map.Entry<?, ?>) entry;
            map.computeIfAbsent((NottableString) e.getKey(), k -> new ArrayList<>()).add((NottableString) e.getValue());
        }
        return map;
    }

    private static HttpRequest query(Map<NottableString, List<NottableString>> map, KeyMatchStyle style) {
        List<Parameter> parameters = new ArrayList<>();
        for (Map.Entry<NottableString, List<NottableString>> e : map.entrySet()) {
            parameters.add(new Parameter(e.getKey(), e.getValue()));
        }
        Parameters query = new Parameters(parameters);
        query.withKeyMatchStyle(style);
        return HttpRequest.request().withQueryStringParameters(query);
    }

    private static HttpRequest cookies(Map<NottableString, NottableString> map) {
        List<Cookie> cookies = new ArrayList<>();
        for (Map.Entry<NottableString, NottableString> e : map.entrySet()) {
            cookies.add(new Cookie(e.getKey(), e.getValue()));
        }
        return HttpRequest.request().withCookies(new Cookies(cookies));
    }

    private static String serialize(HttpRequest request) {
        Recorder.enter("jackson");
        Recorder.enter("serialize");
        try {
            return new HttpRequestSerializer(new MockServerLogger()).serialize(request);
        } finally {
            Recorder.exit("serialize");
            Recorder.exit("jackson");
        }
    }
}
