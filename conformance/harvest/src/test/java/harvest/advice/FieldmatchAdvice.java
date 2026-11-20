package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import org.mockserver.logging.MockServerLogger;
import org.mockserver.model.Body;
import org.mockserver.model.Cookies;
import org.mockserver.model.Header;
import org.mockserver.model.Headers;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.KeysAndValues;
import org.mockserver.model.KeysToMultiValues;
import org.mockserver.model.MultipartBody;
import org.mockserver.model.Not;
import org.mockserver.model.NottableSchemaString;
import org.mockserver.model.NottableString;
import org.mockserver.model.Parameters;
import org.mockserver.serialization.HttpRequestSerializer;
import org.mockserver.serialization.HttpResponseSerializer;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Map;

import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code fieldmatch} (B1): the field matchers of {@code org.mockserver.matchers} called by a test
 * directly, outermost call only (one depth key; a call from production code, e.g. inside a request matcher, is not
 * recorded). Each call is lifted to the request field that builds the same matcher: a body matcher to the request
 * body, a key/value matcher to headers, query parameters or cookies, a matcher-less {@code RegexStringMatcher} (the
 * key/value form, with numeric comparisons and accept directives) and the accept/numeric statics to a header value,
 * {@code BooleanMatcher} to keepAlive; {@code HttpResponseMatcher}/{@code StatusCodeMatcher} to a response template;
 * {@code PathGroupExtractor.extract} to a path pattern and {@code StringSimilarity.jaroWinkler} to a fuzzy body.
 * Replayed by {@code kinds/fieldmatch.py}.
 */
public class FieldmatchAdvice implements Boundary {

    static final String KEY = "fieldmatch";
    static final String HEADER = "x-harvested";

    /** Constructor arguments a matcher does not keep: XPath namespace prefixes, a multipart matcher's body. */
    public static final Map<Object, Object> BUILT_FROM = Collections.synchronizedMap(new IdentityHashMap<>());

    private static final String P = "org.mockserver.matchers.";

    @Override
    public String[] preload() {
        return new String[]{P + "RegexStringMatcher", P + "ExactStringMatcher", P + "SubStringMatcher", P + "XmlStringMatcher",
            P + "JsonPathMatcher", P + "XPathMatcher", P + "JsonSchemaMatcher", P + "XmlSchemaMatcher", P + "BinaryMatcher",
            P + "JsonStringMatcher", P + "ParameterStringMatcher", P + "MultipartMatcher", P + "MultiValueMapMatcher",
            P + "HashMapMatcher", P + "BooleanMatcher", P + "StatusCodeMatcher", P + "HttpResponseMatcher",
            P + "AcceptHeaderMatcher", P + "NumericComparisonMatcher", P + "PathGroupExtractor", P + "StringSimilarity"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(namedOneOf(P + "RegexStringMatcher", P + "ExactStringMatcher", P + "SubStringMatcher", P + "XmlStringMatcher",
                P + "JsonPathMatcher", P + "XPathMatcher", P + "JsonSchemaMatcher", P + "XmlSchemaMatcher", P + "BinaryMatcher",
                P + "JsonStringMatcher", P + "ParameterStringMatcher", P + "MultipartMatcher", P + "MultiValueMapMatcher",
                P + "HashMapMatcher", P + "BooleanMatcher", P + "StatusCodeMatcher", P + "HttpResponseMatcher"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(Matches.class).on(named("matches").and(takesArguments(2))
                    .and(takesArgument(0, org.mockserver.matchers.MatchDifference.class))))
                .visit(Advice.to(Pair.class).on(named("matches").and(takesArguments(NottableString.class, NottableString.class))))
                .visit(Advice.to(Status.class).on(named("matches").and(takesArguments(int.class))))
                .visit(Advice.to(Construct.class).on(isConstructor().and(takesArguments(3))
                    .and(takesArgument(1, String.class).or(takesArgument(1, MultipartBody.class))))))
            .type(namedOneOf(P + "AcceptHeaderMatcher", P + "NumericComparisonMatcher"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(Directive.class).on(named("matches").and(takesArguments(String.class, String.class)))))
            .type(named(P + "PathGroupExtractor"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(PathGroups.class).on(named("extract").and(takesArguments(String.class, String.class, boolean.class)))))
            .type(named(P + "StringSimilarity"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(Similarity.class).on(named("jaroWinkler").and(takesArguments(String.class, String.class)))));
    }

    /** True for an outermost call whose first caller outside {@code own} is a test class. */
    public static boolean enter(String own) {
        boolean outermost = Recorder.enter(KEY);
        return outermost && StackWalker.getInstance().walk(frames -> frames
            .map(StackWalker.StackFrame::getClassName)
            .filter(name -> !name.equals(own) && !name.startsWith("harvest."))
            .findFirst()
            .map(name -> name.split("\\$")[0].endsWith("Test"))
            .orElse(false));
    }

    public static class Construct {
        @Advice.OnMethodExit
        public static void exit(@Advice.This Object self, @Advice.AllArguments Object[] args) {
            if (args[1] instanceof MultipartBody || args[2] instanceof Map) {
                BUILT_FROM.put(self, args[1] instanceof MultipartBody ? args[1] : args[2]);
            }
        }
    }

    public static class Matches {
        @Advice.OnMethodEnter
        public static boolean enter(@Advice.Origin("#t") String type) {
            return FieldmatchAdvice.enter(type);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean record, @Advice.This Object self, @Advice.Argument(1) Object actual,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit(KEY);
            if (record) {
                FieldmatchAdvice.matched(self, null, actual, result, thrown);
            }
        }
    }

    /** {@code StatusCodeMatcher.matches(int)}. */
    public static class Status {
        @Advice.OnMethodEnter
        public static boolean enter(@Advice.Origin("#t") String type) {
            return FieldmatchAdvice.enter(type);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean record, @Advice.This Object self,
                                @Advice.Argument(value = 0, typing = Assigner.Typing.DYNAMIC) Object actual,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit(KEY);
            if (record) {
                FieldmatchAdvice.matched(self, null, actual, result, thrown);
            }
        }
    }

    /** {@code RegexStringMatcher.matches(matcher, matched)}: the matcher-less key/value form. */
    public static class Pair {
        @Advice.OnMethodEnter
        public static boolean enter(@Advice.Origin("#t") String type) {
            return FieldmatchAdvice.enter(type);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean record, @Advice.This Object self, @Advice.Argument(0) Object matcher,
                                @Advice.Argument(1) Object actual, @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result,
                                @Advice.Thrown Throwable thrown) {
            Recorder.exit(KEY);
            if (record) {
                FieldmatchAdvice.matched(self, matcher, actual, result, thrown);
            }
        }
    }

    public static class Directive {
        @Advice.OnMethodEnter
        public static boolean enter(@Advice.Origin("#t") String type) {
            return FieldmatchAdvice.enter(type);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean record, @Advice.Origin("#t") String type, @Advice.Argument(0) String matcher,
                                @Advice.Argument(1) String actual, @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result,
                                @Advice.Thrown Throwable thrown) {
            Recorder.exit(KEY);
            if (record) {
                ObjectNode c = Recorder.base(type.substring(type.lastIndexOf('.') + 1) + ".matches");
                Recorder.enter("jackson");
                try {
                    HttpRequest m = HttpRequest.request().withHeader(HEADER, matcher == null ? "" : matcher);
                    HttpRequest a = HttpRequest.request();
                    if (actual != null) {
                        a.withHeader(HEADER, actual);
                    }
                    request(c, m, a, false, false);
                    if (matcher == null) {
                        c.put("unserialisable", "null directive");
                    }
                } catch (Throwable e) {
                    c.put("unserialisable", String.valueOf(e));
                } finally {
                    Recorder.exit("jackson");
                }
                finish(c, result, thrown);
            }
        }
    }

    public static class PathGroups {
        @Advice.OnMethodEnter
        public static boolean enter(@Advice.Origin("#t") String type) {
            return FieldmatchAdvice.enter(type);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean record, @Advice.Argument(0) String pattern, @Advice.Argument(1) String path,
                                @Advice.Argument(2) boolean caseSensitive, @Advice.Thrown Throwable thrown) {
            Recorder.exit(KEY);
            if (record) {
                ObjectNode c = Recorder.base("PathGroupExtractor.extract");
                c.put("mode", "pathgroups");
                c.put("pattern", pattern);
                c.put("path", path);
                c.put("caseSensitive", caseSensitive);
                Recorder.outcome(c, thrown);
                Recorder.write(KEY, c);
            }
        }
    }

    public static class Similarity {
        @Advice.OnMethodEnter
        public static boolean enter(@Advice.Origin("#t") String type) {
            return FieldmatchAdvice.enter(type);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean record, @Advice.Argument(0) String a, @Advice.Argument(1) String b,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit(KEY);
            if (record) {
                ObjectNode c = Recorder.base("StringSimilarity.jaroWinkler");
                c.put("mode", "similarity");
                c.put("fuzzy", a);
                c.put("actualBody", b);
                if (thrown == null) {
                    c.put("similarity", (Double) result);
                }
                Recorder.outcome(c, thrown);
                Recorder.write(KEY, c);
            }
        }
    }

    // ---- lifting a matcher and its input to requests (or responses) ----

    public static void matched(Object matcher, Object pairMatcher, Object actual, Object result, Throwable thrown) {
        String type = matcher.getClass().getSimpleName();
        ObjectNode c = Recorder.base(type + ".matches");
        Recorder.enter("jackson");
        try {
            lift(c, type, matcher, pairMatcher, actual);
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        finish(c, result, thrown);
    }

    public static void finish(ObjectNode c, Object result, Throwable thrown) {
        if (thrown == null && result instanceof Boolean) {
            c.put("result", (Boolean) result);
        }
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }

    private static Object field(Object target, Class<?> declaring, String name) throws ReflectiveOperationException {
        Field f = declaring.getDeclaredField(name);
        f.setAccessible(true);
        return f.get(target);
    }

    private static boolean notted(Object matcher) throws ReflectiveOperationException {
        return Boolean.TRUE.equals(field(matcher, org.mockserver.matchers.NotMatcher.class, "not"));
    }

    private static boolean flag(Object matcher, String name) throws ReflectiveOperationException {
        return Boolean.TRUE.equals(field(matcher, matcher.getClass(), name));
    }

    private static Body<?> body(Object matcher, Body<?> body) throws ReflectiveOperationException {
        return notted(matcher) ? Not.not(body) : body;
    }

    private static NottableString nottable(Object value) {
        if (value == null || value instanceof NottableString) {
            return (NottableString) value;
        }
        return NottableString.string(String.valueOf(value));
    }

    private static void lift(ObjectNode c, String type, Object matcher, Object pairMatcher, Object actual) throws Exception {
        HttpRequest m = HttpRequest.request();
        HttpRequest a = HttpRequest.request();
        boolean controlPlane = false;
        boolean caseSensitive = false;
        switch (type) {
            case "RegexStringMatcher": {
                NottableString expected = pairMatcher != null ? (NottableString) pairMatcher
                    : (NottableString) field(matcher, matcher.getClass(), "matcher");
                NottableString given = nottable(actual);
                controlPlane = flag(matcher, "controlPlaneMatcher");
                caseSensitive = flag(matcher, "caseSensitive");
                boolean keyValue = flag(matcher, "numericComparison");
                // the regex timeout comes from the logger's configuration (MatchingTimeoutInlineSafeTest sets 300 ms)
                MockServerLogger logger = (MockServerLogger) field(matcher, matcher.getClass(), "mockServerLogger");
                if (logger != null && logger.getConfiguration() != null && logger.getConfiguration().regexMatchingTimeoutMillis() != 5000L) {
                    c.put("regexMatchingTimeoutMillis", logger.getConfiguration().regexMatchingTimeoutMillis());
                }
                if (expected == null) {
                    // a matcher-less RegexStringMatcher's matches(context, value) is always true
                    c.put("unserialisable", "no matcher");
                    return;
                }
                if (notted(matcher)) {
                    c.put("unserialisable", "notted RegexStringMatcher");
                    return;
                }
                if (keyValue || controlPlane || expected instanceof NottableSchemaString || given instanceof NottableSchemaString) {
                    // key/value form: a header value (numeric comparisons and accept directives apply there only)
                    m.withHeader(Header.header(NottableString.string(HEADER), expected));
                    if (given != null) {
                        a.withHeader(Header.header(NottableString.string(HEADER), given));
                    }
                    caseSensitive = false;
                } else {
                    if (given != null && given.isNot()) {
                        c.put("unserialisable", "notted value on the data plane");
                        return;
                    }
                    m.withBody(expected.isNot() ? Not.not(org.mockserver.model.RegexBody.regex(expected.getValue()))
                        : org.mockserver.model.RegexBody.regex(expected.getValue()));
                    if (given != null) {
                        a.withBody(given.getValue());
                    }
                }
                break;
            }
            case "ExactStringMatcher":
            case "SubStringMatcher":
            case "XmlStringMatcher": {
                NottableString expected = (NottableString) field(matcher, matcher.getClass(), "matcher");
                NottableString given = nottable(actual);
                if (given != null && given.isNot()) {
                    c.put("unserialisable", "notted value on the data plane");
                    return;
                }
                Body<?> b = type.equals("ExactStringMatcher") ? org.mockserver.model.StringBody.exact(expected.getValue())
                    : type.equals("SubStringMatcher") ? org.mockserver.model.StringBody.subString(expected.getValue())
                    : org.mockserver.model.XmlBody.xml(expected.getValue());
                m.withBody(Not.not(b, expected.isNot() != notted(matcher)));
                if (given != null) {
                    a.withBody(given.getValue());
                }
                break;
            }
            case "JsonPathMatcher":
                m.withBody(body(matcher, org.mockserver.model.JsonPathBody.jsonPath((String) field(matcher, matcher.getClass(), "matcher"))));
                stringActual(a, actual);
                break;
            case "XPathMatcher": {
                @SuppressWarnings("unchecked")
                Map<String, String> prefixes = (Map<String, String>) BUILT_FROM.get(matcher);
                m.withBody(body(matcher, new org.mockserver.model.XPathBody((String) field(matcher, matcher.getClass(), "matcher"), prefixes)));
                stringActual(a, actual);
                break;
            }
            case "JsonSchemaMatcher":
                m.withBody(body(matcher, org.mockserver.model.JsonSchemaBody.jsonSchema((String) field(matcher, matcher.getClass(), "matcher"))));
                stringActual(a, actual);
                break;
            case "XmlSchemaMatcher":
                m.withBody(body(matcher, org.mockserver.model.XmlSchemaBody.xmlSchema((String) field(matcher, matcher.getClass(), "matcher"))));
                stringActual(a, actual);
                break;
            case "JsonStringMatcher":
                m.withBody(body(matcher, new org.mockserver.model.JsonBody((String) field(matcher, matcher.getClass(), "matcher"),
                    (org.mockserver.matchers.MatchType) field(matcher, matcher.getClass(), "matchType"))));
                stringActual(a, actual);
                break;
            case "BinaryMatcher":
                m.withBody(body(matcher, new org.mockserver.model.BinaryBody((byte[]) field(matcher, matcher.getClass(), "matcher"))));
                if (actual != null) {
                    a.withBody(new org.mockserver.model.BinaryBody((byte[]) actual));
                }
                break;
            case "ParameterStringMatcher":
                controlPlane = flag(field(matcher, matcher.getClass(), "matcher"), "controlPlaneMatcher");
                m.withBody(body(matcher, new org.mockserver.model.ParameterBody((Parameters) field(matcher, matcher.getClass(), "matcherParameters"))));
                if (actual != null) {
                    a.withHeader("Content-Type", "application/x-www-form-urlencoded").withBody((String) actual);
                }
                break;
            case "MultipartMatcher": {
                MultipartBody built = (MultipartBody) BUILT_FROM.get(matcher);
                if (built == null) {
                    c.put("unserialisable", "multipart matcher built before the agent");
                    return;
                }
                controlPlane = flag(field(matcher, matcher.getClass(), "fieldsMatcher"), "controlPlaneMatcher");
                m.withBody(body(matcher, built));
                if (actual != null) {
                    org.mockserver.matchers.MultipartMatcher.MultipartInput input = (org.mockserver.matchers.MultipartMatcher.MultipartInput) actual;
                    String contentType = (String) field(input, input.getClass(), "contentTypeHeader");
                    byte[] bytes = (byte[]) field(input, input.getClass(), "body");
                    if (contentType != null) {
                        a.withHeader("Content-Type", contentType);
                    }
                    if (bytes != null) {
                        a.withBody(new org.mockserver.model.BinaryBody(bytes));
                    }
                }
                break;
            }
            case "MultiValueMapMatcher":
            case "HashMapMatcher": {
                if (notted(matcher)) {
                    c.put("unserialisable", "notted map matcher");
                    return;
                }
                controlPlane = flag(matcher, "controlPlaneMatcher");
                Object expected = field(matcher, matcher.getClass(), type.equals("HashMapMatcher") ? "keysAndValues" : "keysToMultiValues");
                if (expected == null) {
                    c.put("unserialisable", "no matcher");
                    return;
                }
                if (!keyed(m, expected) || actual != null && !keyed(a, actual)) {
                    c.put("unserialisable", "map type " + expected.getClass().getSimpleName() + "/" + (actual == null ? null : actual.getClass().getSimpleName()));
                    return;
                }
                break;
            }
            case "BooleanMatcher": {
                Boolean expected = (Boolean) field(matcher, matcher.getClass(), "matcher");
                m.withKeepAlive(expected);
                a.withKeepAlive((Boolean) actual);
                break;
            }
            case "StatusCodeMatcher": {
                HttpResponse template = HttpResponse.response()
                    .withStatusCode((Integer) field(matcher, matcher.getClass(), "exactStatusCode"))
                    .withStatusCodeRange((String) field(matcher, matcher.getClass(), "statusCodeRange"));
                response(c, template, actual == null ? null : HttpResponse.response().withStatusCode((Integer) actual));
                return;
            }
            case "HttpResponseMatcher":
                response(c, (HttpResponse) field(matcher, matcher.getClass(), "template"), (HttpResponse) actual);
                return;
            default:
                c.put("unserialisable", "unknown matcher " + type);
                return;
        }
        request(c, m, a, controlPlane, caseSensitive);
    }

    private static void stringActual(HttpRequest a, Object actual) {
        if (actual != null) {
            a.withBody((String) actual);
        }
    }

    /** Headers, query parameters or cookies by the map's type. */
    private static boolean keyed(HttpRequest request, Object map) {
        if (map instanceof Headers) {
            request.withHeaders((Headers) map);
        } else if (map instanceof Parameters) {
            request.withQueryStringParameters((Parameters) map);
        } else if (map instanceof Cookies) {
            request.withCookies((Cookies) map);
        } else {
            return false;
        }
        return true;
    }

    public static void request(ObjectNode c, HttpRequest matcher, HttpRequest actual, boolean controlPlane, boolean caseSensitive) {
        HttpRequestSerializer serializer = new HttpRequestSerializer(new MockServerLogger());
        c.put("mode", "request");
        c.put("matcher", serializer.serialize(matcher));
        c.put("actual", serializer.serialize(actual));
        c.put("controlPlaneMatcher", controlPlane);
        c.put("caseSensitive", caseSensitive);
    }

    private static void response(ObjectNode c, HttpResponse template, HttpResponse actual) {
        HttpResponseSerializer serializer = new HttpResponseSerializer(new MockServerLogger());
        c.put("mode", "response");
        c.put("template", template == null ? null : serializer.serialize(template));
        c.put("response", actual == null ? null : serializer.serialize(actual));
    }
}
