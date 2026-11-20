package harvest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import org.junit.runner.Description;
import org.junit.runner.notification.RunListener;
import harvest.advice.Boundary;
import org.mockserver.logging.MockServerLogger;
import org.mockserver.matchers.HttpRequestPropertiesMatcher;
import org.mockserver.model.RequestDefinition;
import org.mockserver.serialization.RequestDefinitionSerializer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static net.bytebuddy.matcher.ElementMatchers.isSubTypeOf;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Surefire listener that records the category-B boundary calls of inventory §4.2 while mockserver-core's own tests
 * run: control-plane deserialisers, JSON-schema validators, {@code HttpRequestPropertiesMatcher.matches}, and the
 * JSON the (de)serialiser tests pass through Jackson ({@code ObjectMapper.readValue(String, Class)} inputs,
 * {@code writeValueAsString} outputs) with the model type. Each
 * outermost call becomes one JSON line in {@code -DharvestDir}/&lt;boundary&gt;.jsonl, tagged with the running test.
 */
public class Recorder extends RunListener {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ThreadLocal<Map<String, Integer>> DEPTH = ThreadLocal.withInitial(HashMap::new);
    private static final Map<String, PrintWriter> OUT = new HashMap<>();
    private static volatile String currentTest = "";

    @Override
    public void testRunStarted(Description description) {
        new File(System.getProperty("harvestDir", "target/harvest"), "trace.txt").delete();
        trace("run-started");
        // A class first loaded while Byte Buddy retransforms another one is never transformed (its circularity lock):
        // GraphQLMatcher's retransformation loads GraphQLAstMatcher when a test loaded GraphQLMatcher first. Loading
        // them up front lets the installation retransform both.
        // In the default run at b765b8271 ExpectationSerializer was first loaded inside such a retransformation
        // (mockserver-core's tests load far more at discovery), so the classes calling it early recorded nothing until a
        // Mockito spy retransformed it mid-run; every exactly named type of the default boundaries is loaded up front too.
        for (String name : new String[]{"org.mockserver.serialization.ExpectationSerializer",
            "org.mockserver.serialization.HttpRequestSerializer", "org.mockserver.serialization.RequestDefinitionSerializer",
            "org.mockserver.serialization.VerificationSerializer", "org.mockserver.serialization.VerificationSequenceSerializer",
            "org.mockserver.serialization.HttpRequestAndHttpResponseSerializer", "org.mockserver.serialization.ConfigurationSerializer",
            "org.mockserver.serialization.PortBindingSerializer", "org.mockserver.serialization.SloCriteriaSerializer",
            "org.mockserver.serialization.LoadScenarioSerializer", "org.mockserver.serialization.OpenAPIExpectationSerializer",
            "org.mockserver.serialization.ExpectationExportSerializer", "org.mockserver.matchers.HttpRequestPropertiesMatcher",
            "org.mockserver.mock.HttpState", "org.mockserver.mock.CassetteRegistry",
            "org.mockserver.serialization.curl.HttpRequestToCurlSerializer",
            // Never transformed in the code run at b765b8271 (no ExpectationTo*Serializer call recorded)
            "org.mockserver.serialization.java.ExpectationToJavaSerializer", "org.mockserver.serialization.code.ExpectationToJavaScriptSerializer",
            "org.mockserver.serialization.code.ExpectationToPythonSerializer", "org.mockserver.serialization.code.ExpectationToGoSerializer",
            "org.mockserver.serialization.code.ExpectationToCSharpSerializer", "org.mockserver.serialization.code.ExpectationToRubySerializer",
            "org.mockserver.serialization.code.ExpectationToRustSerializer", "org.mockserver.serialization.code.ExpectationToPhpSerializer",
            "org.mockserver.openapi.OpenAPIConverter", "org.mockserver.openapi.examples.ExampleBuilder",
            "org.mockserver.openapi.JsonSchemaResponseSynthesizer", "org.mockserver.openapi.OpenAPIRequestValidator",
            "org.mockserver.openapi.OpenAPIResponseValidator", "org.mockserver.openapi.OpenApiRuntimeExpressionResolver",
            "org.mockserver.openapi.OpenApiTrafficValidator", "org.mockserver.templates.engine.helpers.ScenarioTemplateHelper",
            "org.mockserver.matchers.GraphQLAstMatcher", "org.mockserver.matchers.GraphQLMatcher",
            "org.mockserver.matchers.JsonRpcMatcher", "org.mockserver.matchers.FuzzyMatcher",
            "org.mockserver.wasm.WasmRuntime", "org.mockserver.matchers.WasmBodyMatcher", "org.mockserver.wasm.WasmResponseShaper",
            "org.mockserver.mock.action.http.HttpResponseActionHandler", "org.mockserver.log.MockServerEventLog",
            "org.mockserver.mock.action.http.HttpLlmResponseActionHandler", "org.mockserver.matchers.LlmConversationMatcher",
            "org.mockserver.llm.ProviderCodec", "org.mockserver.llm.ProviderCodecRegistry",
            "org.mockserver.llm.codec.AnthropicCodec", "org.mockserver.llm.codec.AzureOpenAiCodec", "org.mockserver.llm.codec.BedrockCodec",
            "org.mockserver.llm.codec.CohereCodec", "org.mockserver.llm.codec.DeepSeekCodec", "org.mockserver.llm.codec.GeminiCodec",
            "org.mockserver.llm.codec.GroqCodec", "org.mockserver.llm.codec.MistralCodec", "org.mockserver.llm.codec.OllamaCodec",
            "org.mockserver.llm.codec.OpenAiChatCompletionsCodec", "org.mockserver.llm.codec.OpenAiCompatibleChatCodec",
            "org.mockserver.llm.codec.OpenAiResponsesCodec", "org.mockserver.llm.codec.OpenRouterCodec", "org.mockserver.llm.codec.OrcaRouterCodec",
            "org.mockserver.llm.codec.VoyageCodec", "org.mockserver.llm.codec.XaiCodec"}) {
            preload(name);
        }
        java.util.List<Boundary> boundaries = boundaries();
        for (Boundary boundary : boundaries) {
            for (String name : boundary.preload()) {
                preload(name);
            }
        }
        AgentBuilder agent = new AgentBuilder.Default()
            .disableClassFormatChanges()
            .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
            .with(new AgentBuilder.Listener.Adapter() {
                @Override
                public void onError(String typeName, ClassLoader loader, net.bytebuddy.utility.JavaModule module, boolean loaded, Throwable throwable) {
                    trace("transform-error " + typeName + " " + throwable);
                }

                @Override
                public void onTransformation(net.bytebuddy.description.type.TypeDescription type, ClassLoader loader, net.bytebuddy.utility.JavaModule module, boolean loaded, net.bytebuddy.dynamic.DynamicType dynamicType) {
                    trace("transformed " + type.getName() + (loaded ? " (retransformed)" : ""));
                }
            })
            .ignore(net.bytebuddy.matcher.ElementMatchers.none())
            .type(namedOneOf(
                "org.mockserver.serialization.ExpectationSerializer",
                "org.mockserver.serialization.HttpRequestSerializer",
                "org.mockserver.serialization.RequestDefinitionSerializer",
                "org.mockserver.serialization.VerificationSerializer",
                "org.mockserver.serialization.VerificationSequenceSerializer",
                // HttpRequestAndHttpResponseSerializerSchemaValidationTest calls deserialize() with real
                // (unmocked) JSON; HttpRequestAndHttpResponseSerializerTest and *SerializationErrorsTest also call it,
                // some with a placeholder string on a mocked ObjectMapper — those just produce an unconvertible case.
                "org.mockserver.serialization.HttpRequestAndHttpResponseSerializer",
                // ConfigurationSerializerTest, PortBindingSerializerSchemaValidationTest,
                // SloCriteriaSerializerTest and LoadScenarioSerializerTest call deserialize() on a real, unmocked
                // instance (no Mockito @InjectMocks) with real JSON.
                "org.mockserver.serialization.ConfigurationSerializer",
                "org.mockserver.serialization.PortBindingSerializer",
                "org.mockserver.serialization.LoadScenarioSerializer",
                "org.mockserver.serialization.SloCriteriaSerializer"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(DeserializeAdvice.class)
                .on(namedOneOf("deserialize", "deserializeArray").and(takesArgument(0, String.class)))))
            .type(isSubTypeOf(org.mockserver.validator.jsonschema.JsonSchemaValidator.class))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ValidateAdvice.class)
                .on(named("isValid").and(takesArguments(String.class, boolean.class)))))
            .type(named("org.mockserver.matchers.HttpRequestPropertiesMatcher"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(MatchAdvice.class)
                .on(named("matches").and(takesArguments(2)))))
            .type(named("com.fasterxml.jackson.databind.ObjectMapper"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(ReadValueAdvice.class).on(named("readValue").and(takesArguments(String.class, Class.class))))
                .visit(Advice.to(WriteValueAdvice.class).on(named("writeValueAsString").and(takesArguments(Object.class)))))
            // ObjectMapperFactory.createObjectMapper(pretty, serialiseDefaultValues) returns an
            // ObjectWriter, not an ObjectMapper — a separate Jackson class with its own writeValueAsString(Object).
            // Several Cookies/Headers/Parameters/VerificationTimes(DTO)/body-DTO serializer tests call it exclusively
            // (no plain ObjectMapper.writeValueAsString in the same test), so without this they record nothing at
            // all (not even an unconvertible case — the call is never intercepted). Same WriteValueAdvice, same
            // "jackson" kind; the class name recorded is the real argument's, unaffected by which writer called it.
            .type(named("com.fasterxml.jackson.databind.ObjectWriter"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(WriteValueAdvice.class).on(named("writeValueAsString").and(takesArguments(Object.class)))))
            .type(isSubTypeOf(org.mockserver.templates.engine.TemplateEngine.class))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(TemplateAdvice.class)
                    .on(named("executeTemplate").and(takesArguments(String.class, org.mockserver.model.HttpRequest.class, Class.class))))
                .visit(Advice.to(RenderAdvice.class)
                    .on(named("renderTemplate").and(takesArgument(0, String.class)).and(takesArgument(1, org.mockserver.model.HttpRequest.class)))))
            .type(named("org.mockserver.openapi.OpenAPIConverter"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(OpenAPIAdvice.class)
                .on(named("buildExpectations").and(takesArgument(0, String.class)))))
            .type(named("org.mockserver.openapi.examples.ExampleBuilder"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ExampleAdvice.class)
                .on(named("fromSchema").and(takesArguments(5)))))
            .type(named("org.mockserver.openapi.JsonSchemaResponseSynthesizer"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(SynthesizeAdvice.class)
                .on(named("synthesizeResponse").and(takesArguments(String.class)))))
            .type(named("org.mockserver.openapi.OpenAPIRequestValidator"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ValidationAdvice.class)
                .on(named("validate").and(takesArguments(4)))))
            .type(named("org.mockserver.openapi.OpenAPIResponseValidator"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ValidationAdvice.class)
                .on(named("validate").and(takesArguments(4)))))
            .type(named("org.mockserver.openapi.OpenApiTrafficValidator"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ValidationAdvice.class)
                .on(named("validate").and(takesArguments(2)))))
            .type(named("org.mockserver.openapi.OpenApiRuntimeExpressionResolver"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ExpressionAdvice.class)
                .on(named("resolve").and(takesArguments(2)))))
            .type(net.bytebuddy.matcher.ElementMatchers.<net.bytebuddy.description.type.TypeDescription>nameStartsWith("org.mockserver.serialization.java.")
                .or(net.bytebuddy.matcher.ElementMatchers.nameStartsWith("org.mockserver.serialization.code."))
                .or(net.bytebuddy.matcher.ElementMatchers.named("org.mockserver.serialization.curl.HttpRequestToCurlSerializer"))
                .and(net.bytebuddy.matcher.ElementMatchers.not(net.bytebuddy.matcher.ElementMatchers.nameEndsWith("Test"))))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(CodeAdvice.class)
                .on(namedOneOf("serialize", "serializeAsJava", "toCurl").and(net.bytebuddy.matcher.ElementMatchers.isPublic()))))
            .type(net.bytebuddy.matcher.ElementMatchers.<net.bytebuddy.description.type.TypeDescription>nameStartsWith("org.mockserver.templates.engine.helpers.")
                .and(net.bytebuddy.matcher.ElementMatchers.nameEndsWith("TemplateHelper"))
                .and(net.bytebuddy.matcher.ElementMatchers.not(net.bytebuddy.matcher.ElementMatchers.named("org.mockserver.templates.engine.helpers.ScenarioTemplateHelper"))))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(HelperAdvice.class)
                .on(net.bytebuddy.matcher.ElementMatchers.isPublic()
                    .and(net.bytebuddy.matcher.ElementMatchers.not(net.bytebuddy.matcher.ElementMatchers.isConstructor()))
                    .and(net.bytebuddy.matcher.ElementMatchers.not(net.bytebuddy.matcher.ElementMatchers.isStatic()))
                    .and(net.bytebuddy.matcher.ElementMatchers.not(namedOneOf("toString", "equals", "hashCode"))))))
            // B4: body matchers called directly, each outermost call one case of kind `bodymatch`.
            .type(namedOneOf("org.mockserver.matchers.GraphQLMatcher", "org.mockserver.matchers.JsonRpcMatcher", "org.mockserver.matchers.FuzzyMatcher"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(BodyMatchAdvice.class)
                .on(named("matches").and(takesArguments(2)).and(takesArgument(1, String.class)))))
            .type(named("org.mockserver.matchers.GraphQLAstMatcher"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(BodyMatchAdvice.class)
                .on(named("matches").and(takesArguments(String.class)))))
            // B4: WASM runtime calls, the WASM body matcher, response shaping; outermost call only, kind `wasm`.
            .type(named("org.mockserver.wasm.WasmRuntime"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(WasmRuntimeAdvice.class)
                .on(namedOneOf("callMatch", "callShape"))))
            .type(named("org.mockserver.matchers.WasmBodyMatcher"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(WasmMatcherAdvice.class)
                .on(named("matches").and(takesArguments(2)).and(takesArgument(1, String.class)))))
            .type(named("org.mockserver.wasm.WasmResponseShaper"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(WasmShapeAdvice.class)
                .on(named("shape").and(takesArguments(4)))))
            .type(named("org.mockserver.mock.action.http.HttpResponseActionHandler"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(WasmShapeAdvice.class)
                .on(named("shapeResponseWithWasm").and(takesArguments(3)))))
            // B4: control-plane sequences through HttpState.handle, kind `handle`: every outermost call of
            // handle/reset and the direct state mutations tests make between them, in order, one line each.
            .type(named("org.mockserver.mock.HttpState"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(HandleAdvice.class).on(named("handle").and(takesArguments(3))))
                .visit(Advice.to(StateCallAdvice.class).on(named("reset").and(takesArguments(0)))))
            .type(named("org.mockserver.mock.CassetteRegistry"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(StateCallAdvice.class)
                .on(named("register").and(takesArguments(String.class, String.class, int.class, String.class)))))
            .type(named("org.mockserver.log.MockServerEventLog"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(EventLogAdvice.class)
                .on(named("add").and(takesArguments(1)))))
            // B4: the LLM surface under one depth key, outermost call only: provider codecs (kind `llmcodec`),
            // the LLM action handler (kind `llmhandler`) and the conversation matcher (kind `llmmatch`).
            .type(isSubTypeOf(org.mockserver.llm.ProviderCodec.class))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(LlmCodecAdvice.class)
                .on(namedOneOf("encode", "encodeStreaming", "encodeEmbedding", "encodeRerank", "decode")
                    .and(net.bytebuddy.matcher.ElementMatchers.not(net.bytebuddy.matcher.ElementMatchers.isAbstract())))))
            .type(named("org.mockserver.mock.action.http.HttpLlmResponseActionHandler"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(LlmHandlerAdvice.class)
                .on(named("handle").and(takesArguments(2))
                    .or(named("handleStreaming").and(takesArguments(2)))
                    .or(named("chaosErrorResponseOrNull").and(takesArguments(1)))
                    .or(named("enforcementErrorResponseOrNull").and(takesArguments(2)))
                    .or(named("withInferredUsageIfEnabled").and(takesArguments(3))))))
            .type(named("org.mockserver.matchers.LlmConversationMatcher"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(LlmMatcherAdvice.class)
                .on(named("matches").and(takesArguments(2)))));
        for (Boundary boundary : boundaries) {
            agent = boundary.install(agent);
        }
        agent.installOn(ByteBuddyAgent.install());
        CONFIGURATION_DEFAULTS.putAll(configurationValues(org.mockserver.configuration.Configuration.configuration()));
    }

    private static void preload(String name) {
        try {
            Class.forName(name);
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Every {@link Boundary} in package {@code harvest.advice}, found by its class file (so that adding one edits no
     * shared list), in name order. */
    private static java.util.List<Boundary> boundaries() {
        java.util.List<Boundary> found = new java.util.ArrayList<>();
        java.net.URL dir = Recorder.class.getResource("advice/");
        if (dir == null) {
            return found;
        }
        String[] names;
        try {
            names = new File(dir.toURI()).list();
        } catch (java.net.URISyntaxException e) {
            throw new IllegalStateException(e);
        }
        java.util.Arrays.sort(names);
        for (String file : names) {
            if (!file.endsWith(".class") || file.contains("$")) {
                continue;
            }
            try {
                Class<?> type = Class.forName("harvest.advice." + file.substring(0, file.length() - ".class".length()));
                if (Boundary.class.isAssignableFrom(type) && !type.isInterface() && !java.lang.reflect.Modifier.isAbstract(type.getModifiers())) {
                    found.add((Boundary) type.getDeclaredConstructor().newInstance());
                }
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException(e);
            }
        }
        return found;
    }

    // ---- B4 control-plane sequences, kind `handle` ----

    /** The run's startup value of every simple {@code Configuration} getter, taken before any test changes a static
     * property; a {@code handle} line records the getters whose value differs from it. */
    private static final Map<String, String> CONFIGURATION_DEFAULTS = new java.util.TreeMap<>();

    private static Map<String, String> configurationValues(Object configuration) {
        Map<String, String> values = new java.util.TreeMap<>();
        for (java.lang.reflect.Method m : org.mockserver.configuration.Configuration.class.getDeclaredMethods()) {
            Class<?> r = m.getReturnType();
            boolean simple = r.isPrimitive() && r != void.class || r == String.class || r == Boolean.class || r == Integer.class
                || r == Long.class || r == Double.class || r.isEnum();
            if (m.getParameterCount() != 0 || !simple || !java.lang.reflect.Modifier.isPublic(m.getModifiers())
                || java.lang.reflect.Modifier.isStatic(m.getModifiers()) || m.getName().startsWith("get") || m.getName().equals("toString")
                || m.getName().equals("hashCode")) {
                continue;
            }
            try {
                values.put(m.getName(), String.valueOf(m.invoke(configuration)));
            } catch (Throwable ignored) {
                // a getter that cannot be read in isolation is not a server property
            }
        }
        return values;
    }

    /** {@code HttpState.handle(request, writer, false)}: the request, whether it was handled, and the state's server. */
    public static void handled(Object httpState, Object[] args, Object result, Throwable thrown) {
        ObjectNode c = base("HttpState.handle");
        enter("jackson");
        try {
            c.put("call", "handle");
            c.put("request", new org.mockserver.serialization.HttpRequestSerializer(new MockServerLogger())
                .serialize((org.mockserver.model.HttpRequest) args[0]));
            c.put("warDeployment", (Boolean) args[2]);
            if (thrown == null) {
                c.put("handled", (Boolean) result);
            }
            c.put("authenticationHandler", field(httpState, "controlPlaneAuthenticationHandler") != null);
            ObjectNode differences = c.putObject("configuration");
            configurationValues(field(httpState, "configuration")).forEach((name, value) -> {
                if (!value.equals(CONFIGURATION_DEFAULTS.get(name))) {
                    differences.put(name, value);
                }
            });
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            exit("jackson");
        }
        outcome(c, thrown);
        write("handle", c);
    }

    /** {@code HttpState.reset()} or {@code CassetteRegistry.register(…)} made outside {@code handle}. */
    public static void stateCalled(String type, String method, Object[] args, Throwable thrown) {
        ObjectNode c = base(type.substring(type.lastIndexOf('.') + 1) + "." + method);
        enter("jackson");
        try {
            switch (method) {
                case "reset":
                    c.put("call", "reset");
                    break;
                case "register":
                    c.put("call", "registerCassette");
                    c.put("path", (String) args[0]);
                    c.put("filename", (String) args[1]);
                    c.put("expectationCount", (Integer) args[2]);
                    c.put("origin", (String) args[3]);
                    break;
                default:
                    throw new IllegalArgumentException(method);
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            exit("jackson");
        }
        outcome(c, thrown);
        write("handle", c);
    }

    /** A RECEIVED_REQUEST {@code MockServerEventLog.add} made outside {@code handle} (a test recording traffic by hand),
     * taken on entry: the ring buffer clears the entry it was given. */
    public static ObjectNode eventLogged(Object entryObject) {
        org.mockserver.log.model.LogEntry entry = (org.mockserver.log.model.LogEntry) entryObject;
        if (entry == null || entry.getType() != org.mockserver.log.model.LogEntry.LogMessageType.RECEIVED_REQUEST
            || !(entry.getHttpRequest() instanceof org.mockserver.model.HttpRequest)) {
            return null;
        }
        ObjectNode c = base("MockServerEventLog.add");
        enter("jackson");
        try {
            c.put("call", "receivedRequest");
            c.put("request", new org.mockserver.serialization.HttpRequestSerializer(new MockServerLogger())
                .serialize((org.mockserver.model.HttpRequest) entry.getHttpRequest()));
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            exit("jackson");
        }
        return c;
    }

    public static class EventLogAdvice {
        @Advice.OnMethodEnter
        public static ObjectNode enter(@Advice.Argument(0) Object entry) {
            return Recorder.enter("httpState") ? Recorder.eventLogged(entry) : null;
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter ObjectNode recorded) {
            Recorder.exit("httpState");
            if (recorded != null) {
                Recorder.write("handle", recorded);
            }
        }
    }

    public static class HandleAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("httpState");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.AllArguments Object[] args,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("httpState");
            if (outermost) {
                Recorder.handled(self, args, result, thrown);
            }
        }
    }

    /** Shares {@code handle}'s depth key: a reset, registration or log entry made while handling a request is part of it. */
    public static class StateCallAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("httpState");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#t") String type, @Advice.Origin("#m") String method,
                                @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
            Recorder.exit("httpState");
            if (outermost) {
                Recorder.stateCalled(type, method, args, thrown);
            }
        }
    }

    @Override
    public void testStarted(Description description) {
        // A test that leaves a boundary call unbalanced on the runner's thread (its depth never returns to
        // 0) silently turned every later call of that boundary on this thread into a nested one, so whole classes
        // were never recorded in the default run while recording alone. Each test starts at depth 0; a leak is logged.
        Map<String, Integer> depth = DEPTH.get();
        depth.values().removeIf(n -> n == 0);
        if (!depth.isEmpty()) {
            ObjectNode leak = base("depth-leak");
            leak.put("depth", String.valueOf(depth));
            write("depth-leak", leak);
            depth.clear();
        }
        if (!currentTest.startsWith(description.getClassName() + "#")) {
            trace("class " + description.getClassName());
        }
        currentTest = description.getClassName() + "#" + description.getMethodName();
    }

    /** Diagnostics of the run: class order and transformation errors, appended to <harvestDir>/trace.txt. */
    static synchronized void trace(String line) {
        File dir = new File(System.getProperty("harvestDir", "target/harvest"));
        dir.mkdirs();
        try (java.io.Writer w = new java.io.OutputStreamWriter(new FileOutputStream(new File(dir, "trace.txt"), true), StandardCharsets.UTF_8)) {
            w.write(line + "\n");
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void testRunFinished(org.junit.runner.Result result) {
        trace("run-finished");
        synchronized (OUT) {
            OUT.values().forEach(PrintWriter::close);
            OUT.clear();
        }
    }

    /** True for the outermost call of {@code key} on this thread. */
    public static boolean enter(String key) {
        return DEPTH.get().merge(key, 1, Integer::sum) == 1;
    }

    public static void exit(String key) {
        DEPTH.get().merge(key, -1, Integer::sum);
    }

    public static void deserialized(String method, Object[] args, Throwable thrown) {
        ObjectNode c = base(method);
        c.put("input", (String) args[0]);
        if (args.length > 1 && args[1] instanceof Boolean) {
            c.put("allowEmpty", (Boolean) args[1]);
        }
        outcome(c, thrown);
        write("deserialize", c);
    }

    public static void validated(String validator, String json, Object result, Throwable thrown) {
        ObjectNode c = base(validator);
        c.put("input", json);
        if (thrown == null) {
            c.put("result", result == null ? "" : result.toString());
        }
        outcome(c, thrown);
        write("validate", c);
    }

    public static void matched(Object matcher, Object actual, Object result, Throwable thrown) {
        ObjectNode c = base("HttpRequestPropertiesMatcher.matches");
        try {
            RequestDefinitionSerializer serializer = new RequestDefinitionSerializer(new MockServerLogger());
            c.put("matcher", serializer.serialize(((HttpRequestPropertiesMatcher) matcher).getHttpRequest()));
            c.put("actual", actual == null ? null : serializer.serialize((RequestDefinition) actual));
            Field controlPlane = org.mockserver.matchers.AbstractHttpRequestMatcher.class.getDeclaredField("controlPlaneMatcher");
            controlPlane.setAccessible(true);
            c.put("controlPlaneMatcher", controlPlane.getBoolean(matcher));
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        }
        if (thrown == null) {
            c.put("result", (Boolean) result);
        }
        outcome(c, thrown);
        write("match", c);
    }

    public static void jackson(String boundary, String type, String json, Throwable thrown) {
        if (json == null) {
            return;
        }
        ObjectNode c = base(boundary);
        c.put("type", type);
        c.put("input", json);
        outcome(c, thrown);
        write("jackson", c);
    }

    /** Template-related configuration getters; a case records the ones whose value differs from the default. */
    private static final String[] TEMPLATE_CONFIGURATION = {
        "javascriptDisallowedClasses", "javascriptAllowedClasses", "javascriptDisallowedText", "javascriptTemplateExecutionTimeout",
        "velocityDisallowClassLoading", "velocityDisallowedText", "mustacheDisallowedText", "templateFakerSeed"};

    public static void templated(Object engine, Object[] args, Throwable thrown) {
        ObjectNode c = base("TemplateEngine.executeTemplate");
        c.put("engine", engine.getClass().getSimpleName());
        c.put("template", (String) args[0]);
        c.put("dto", ((Class<?>) args[2]).getName());
        try {
            c.put("request", args[1] == null ? null : new org.mockserver.serialization.HttpRequestSerializer(new MockServerLogger())
                .serialize((org.mockserver.model.HttpRequest) args[1]));
            configurationDifferences(engine, c);
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        }
        outcome(c, thrown);
        write("template", c);
    }

    /** The engine's template-related configuration values that differ from the defaults, as {@code configuration}. */
    private static void configurationDifferences(Object engine, ObjectNode c) throws Exception {
        Field field = engine.getClass().getDeclaredField("configuration");
        field.setAccessible(true);
        Object configuration = field.get(engine);
        Object defaults = org.mockserver.configuration.Configuration.configuration();
        ObjectNode differences = c.putObject("configuration");
        for (String name : TEMPLATE_CONFIGURATION) {
            java.lang.reflect.Method getter = org.mockserver.configuration.Configuration.class.getMethod(name);
            Object actual = configuration == null ? null : getter.invoke(configuration);
            if (!java.util.Objects.equals(actual, getter.invoke(defaults))) {
                differences.put(name, String.valueOf(actual));
            }
        }
    }

    /** {@code TemplateEngine.renderTemplate(template, request[, iteration])}: text rendering (file bodies, delays). */
    public static void rendered(Object engine, Object[] args, Object result, Throwable thrown) {
        ObjectNode c = base("TemplateEngine.renderTemplate");
        c.put("engine", engine.getClass().getSimpleName());
        c.put("template", (String) args[0]);
        c.put("iteration", args.length > 2 && args[2] != null);
        enter("jackson");
        try {
            c.put("request", args[1] == null ? null : new org.mockserver.serialization.HttpRequestSerializer(new MockServerLogger())
                .serialize((org.mockserver.model.HttpRequest) args[1]));
            configurationDifferences(engine, c);
            if (thrown == null) {
                c.put("result", (String) result);
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            exit("jackson");
        }
        outcome(c, thrown);
        write("render", c);
    }

    /** {@code HarConverter.serialize(entries)}: each entry's timestamp, request and response as MockServer JSON. */
    public static void converted(Object converter, Object[] args, Object result, Throwable thrown) {
        ObjectNode c = base("OpenAPIConverter.buildExpectations");
        c.put("specUrlOrPayload", (String) args[0]);
        try {
            c.set("operationsAndResponses", args[1] == null ? null : JSON.valueToTree(args[1]));
            if (args.length > 2) {
                c.put("contextPathPrefix", (String) args[2]);
            }
            Field field = converter.getClass().getDeclaredField("configuration");
            field.setAccessible(true);
            Object configuration = field.get(converter);
            Boolean realistic = configuration == null
                ? org.mockserver.configuration.ConfigurationProperties.generateRealisticExampleValues()
                : ((org.mockserver.configuration.Configuration) configuration).generateRealisticExampleValues();
            c.put("generateRealisticExampleValues", realistic);
            if (result instanceof java.util.List) {
                c.put("expectations", ((java.util.List<?>) result).size());
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        }
        outcome(c, thrown);
        write("openapi", c);
    }

    private static final ObjectMapper MOCKSERVER_JSON = org.mockserver.serialization.ObjectMapperFactory.createObjectMapper();

    /** A retrieve-format serialiser ({@code serialization.java} / {@code .code}, curl): its model argument as MockServer JSON. */
    public static void coded(String serializer, Object[] args, Throwable thrown) {
        ObjectNode c = base("ToCodeSerializer.serialize");
        c.put("serializer", serializer.substring(serializer.lastIndexOf('.') + 1));
        enter("jackson");
        try {
            Object model = null;
            for (Object arg : args) {
                if (arg instanceof java.net.InetSocketAddress) {
                    c.put("remoteAddress", String.valueOf(arg));
                } else if (!(arg instanceof Integer) && model == null) {
                    model = arg;
                }
            }
            if (model instanceof Object[]) {
                model = java.util.Arrays.asList((Object[]) model);
            }
            c.put("modelType", model == null ? null
                : model instanceof java.util.List && !((java.util.List<?>) model).isEmpty()
                    ? "List<" + ((java.util.List<?>) model).get(0).getClass().getSimpleName() + ">"
                    : model.getClass().getSimpleName());
            c.put("model", model == null ? null : MOCKSERVER_JSON.writeValueAsString(model));
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            exit("jackson");
        }
        outcome(c, thrown);
        write("code", c);
    }

    /** swagger-core's JSON of a schema (Json31 for an OAS 3.1 schema), as a spec document would carry it. */
    private static com.fasterxml.jackson.databind.JsonNode schemaJson(Object schema, boolean v31) throws Exception {
        ObjectMapper mapper = v31 ? io.swagger.v3.core.util.Json31.mapper() : io.swagger.v3.core.util.Json.mapper();
        return JSON.readTree(mapper.writeValueAsString(schema));
    }

    /** True when a schema (or one nested in it) uses an OAS 3.1 field swagger-core's 3.0 mapper would drop. */
    private static boolean usesV31(Object value, java.util.Set<Object> seen) {
        if (!(value instanceof io.swagger.v3.oas.models.media.Schema) || !seen.add(value)) {
            return false;
        }
        io.swagger.v3.oas.models.media.Schema<?> s = (io.swagger.v3.oas.models.media.Schema<?>) value;
        if (s.getSpecVersion() == io.swagger.v3.oas.models.SpecVersion.V31 || (s.getTypes() != null && !(s.getTypes().size() == 1 && s.getTypes().contains(s.getType()))) || s.getConst() != null
            || s.getExclusiveMinimumValue() != null || s.getExclusiveMaximumValue() != null) {
            return true;
        }
        java.util.List<Object> nested = new java.util.ArrayList<>();
        if (s.getProperties() != null) nested.addAll(s.getProperties().values());
        if (s.getItems() != null) nested.add(s.getItems());
        if (s.getAllOf() != null) nested.addAll(s.getAllOf());
        if (s.getAnyOf() != null) nested.addAll(s.getAnyOf());
        if (s.getOneOf() != null) nested.addAll(s.getOneOf());
        if (s.getNot() != null) nested.add(s.getNot());
        nested.add(s.getAdditionalProperties());
        for (Object n : nested) {
            if (usesV31(n, seen)) {
                return true;
            }
        }
        return false;
    }

    /** {@code ExampleBuilder.fromSchema(schema, definitions, generationOptions, direction, configuration)}, outermost. */
    public static void example(Object[] args, Throwable thrown) {
        ObjectNode c = base("ExampleBuilder.fromSchema");
        enter("jackson");
        try {
            Object schema = args[0];
            java.util.Set<Object> seen = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
            boolean v31 = usesV31(schema, seen);
            if (args[1] != null) {
                for (Object definition : ((Map<?, ?>) args[1]).values()) {
                    v31 |= usesV31(definition, seen);
                }
            }
            c.put("specVersion", v31 ? "V31" : "V30");
            c.set("schema", schema == null ? null : schemaJson(schema, v31));
            if (args[1] != null) {
                ObjectNode definitions = c.putObject("definitions");
                for (Map.Entry<?, ?> e : ((Map<?, ?>) args[1]).entrySet()) {
                    definitions.set(String.valueOf(e.getKey()), e.getValue() == null ? null : schemaJson(e.getValue(), v31));
                }
            }
            if (args[2] != null) {
                org.mockserver.openapi.examples.GenerationOptions options = (org.mockserver.openapi.examples.GenerationOptions) args[2];
                ObjectNode o = c.putObject("generationOptions");
                if (options.getSeed() != null) {
                    o.put("seed", options.getSeed());
                }
                if (!options.getFieldOverrides().isEmpty()) {
                    o.set("fieldOverrides", JSON.valueToTree(options.getFieldOverrides()));
                }
                if (options.getRealisticValues() != null) {
                    o.put("realisticValues", options.getRealisticValues());
                }
            }
            c.put("direction", String.valueOf(args[3]));
            Object configuration = args[4];
            c.put("generateRealisticExampleValues", configuration == null
                ? org.mockserver.configuration.ConfigurationProperties.generateRealisticExampleValues()
                : ((org.mockserver.configuration.Configuration) configuration).generateRealisticExampleValues());
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            exit("jackson");
        }
        outcome(c, thrown);
        write("example", c);
    }

    /** {@code JsonSchemaResponseSynthesizer.synthesizeResponse(jsonSchema)}: an {@code httpResponse.generateFromSchema}. */
    public static void synthesized(Object[] args, Object result, Throwable thrown) {
        ObjectNode c = base("JsonSchemaResponseSynthesizer.synthesizeResponse");
        c.put("jsonSchema", (String) args[0]);
        if (thrown == null) {
            c.put("result", (String) result);
        }
        outcome(c, thrown);
        write("example", c);
    }

    /** An OpenAPI request/response/traffic validator call; the operation of a response validation is resolved to its
     * method and path template so the converter can send a request the traffic validator maps back onto it. */
    public static void validatedOpenApi(String type, Object[] args, Object result, Throwable thrown) {
        String simple = type.substring(type.lastIndexOf('.') + 1);
        ObjectNode c = base(simple + ".validate");
        enter("jackson");
        try {
            MockServerLogger logger = new MockServerLogger();
            org.mockserver.serialization.HttpRequestSerializer requests = new org.mockserver.serialization.HttpRequestSerializer(logger);
            org.mockserver.serialization.HttpResponseSerializer responses = new org.mockserver.serialization.HttpResponseSerializer(logger);
            c.put("specUrlOrPayload", (String) args[0]);
            if (simple.equals("OpenAPIRequestValidator")) {
                c.put("request", args[1] == null ? null : requests.serialize((org.mockserver.model.HttpRequest) args[1]));
                c.put("matchedPathTemplate", (String) args[3]);
            } else if (simple.equals("OpenAPIResponseValidator")) {
                c.put("operationId", (String) args[1]);
                c.put("response", args[2] == null ? null : responses.serialize((org.mockserver.model.HttpResponse) args[2]));
                try {
                    io.swagger.v3.oas.models.OpenAPI openAPI = org.mockserver.openapi.OpenAPIParser.buildOpenAPI((String) args[0], logger, null);
                    for (String section : new String[]{"paths", "webhooks"}) {
                        Map<String, io.swagger.v3.oas.models.PathItem> items = section.equals("paths") ? openAPI.getPaths() : openAPI.getWebhooks();
                        if (items == null || c.has("operationPath")) {
                            continue;
                        }
                        for (Map.Entry<String, io.swagger.v3.oas.models.PathItem> item : items.entrySet()) {
                            for (Map.Entry<io.swagger.v3.oas.models.PathItem.HttpMethod, io.swagger.v3.oas.models.Operation> op : item.getValue().readOperationsMap().entrySet()) {
                                if (java.util.Objects.equals(op.getValue().getOperationId(), args[1]) && !c.has("operationPath")) {
                                    c.put("operationSection", section);
                                    c.put("operationPath", item.getKey());
                                    c.put("operationMethod", op.getKey().name());
                                }
                            }
                        }
                    }
                } catch (Throwable e) {
                    c.put("operationUnresolved", String.valueOf(e));
                }
            } else {
                com.fasterxml.jackson.databind.node.ArrayNode pairs = c.putArray("pairs");
                for (Object pair : (java.util.List<?>) args[1]) {
                    ObjectNode p = pairs.addObject();
                    Object left = ((org.apache.commons.lang3.tuple.Pair<?, ?>) pair).getLeft();
                    Object right = ((org.apache.commons.lang3.tuple.Pair<?, ?>) pair).getRight();
                    p.put("request", left == null ? null : requests.serialize((org.mockserver.model.HttpRequest) left));
                    p.put("response", right == null ? null : responses.serialize((org.mockserver.model.HttpResponse) right));
                }
            }
            if (thrown == null && result != null) {
                c.put("result", String.valueOf(result));
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            exit("jackson");
        }
        outcome(c, thrown);
        write("validation", c);
    }

    /** {@code OpenApiRuntimeExpressionResolver.resolve(afterActionRequest, triggeringRequest)}, outermost. */
    public static void resolved(Object[] args, Throwable thrown) {
        ObjectNode c = base("OpenApiRuntimeExpressionResolver.resolve");
        enter("jackson");
        try {
            org.mockserver.serialization.HttpRequestSerializer requests = new org.mockserver.serialization.HttpRequestSerializer(new MockServerLogger());
            c.put("afterAction", args[0] == null ? null : requests.serialize((org.mockserver.model.HttpRequest) args[0]));
            c.put("triggering", args[1] == null ? null : requests.serialize((org.mockserver.model.HttpRequest) args[1]));
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            exit("jackson");
        }
        outcome(c, thrown);
        write("expression", c);
    }

    /** A template helper method called directly ({@code StringTemplateHelper.trim("…")}, …), outermost: its declared
     * parameter types, its arguments as JSON (null when not representable) and its result's type and text. */
    public static void helped(String type, java.lang.reflect.Method method, Object[] args, Object result, Throwable thrown) {
        ObjectNode c = base("TemplateHelper.call");
        c.put("helper", type.substring(type.lastIndexOf('.') + 1));
        c.put("method", method.getName());
        enter("jackson");
        try {
            com.fasterxml.jackson.databind.node.ArrayNode types = c.putArray("parameterTypes");
            for (Class<?> p : method.getParameterTypes()) {
                types.add(p.getName());
            }
            com.fasterxml.jackson.databind.node.ArrayNode values = c.putArray("args");
            for (Object arg : args) {
                values.add(JSON.valueToTree(arg));
            }
            if (thrown == null) {
                c.put("resultType", result == null ? null : result.getClass().getName());
                c.put("result", result == null ? null : String.valueOf(result));
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            exit("jackson");
        }
        outcome(c, thrown);
        write("helper", c);
    }

    /** A body matcher's {@code matches} called directly (B4, kind {@code bodymatch}), outermost: the matcher as the
     * expectation body that builds it (read from its fields), and the string it was given. */
    public static void bodyMatched(Object matcher, String actual, Object result, Throwable thrown) {
        String type = matcher.getClass().getSimpleName();
        ObjectNode c = base(type + ".matches");
        enter("jackson");
        try {
            ObjectNode body = c.putObject("matcher");
            switch (type) {
                case "GraphQLMatcher": {
                    Object ast = field(matcher, "astMatcher");
                    body.put("type", "GRAPHQL");
                    // the query as given (the matcher keeps it normalised; its AST matcher keeps the original)
                    body.put("query", (String) (ast != null ? field(ast, "expectedQuery") : field(matcher, "query")));
                    putIfNotNull(body, "operationName", field(matcher, "operationName"));
                    putIfNotNull(body, "variablesSchema", field(matcher, "variablesSchema"));
                    putIfNotNull(body, "selectionSetMatchType", field(matcher, "selectionSetMatchType"));
                    if (ast != null) {
                        fields(body, field(ast, "expectedFields"));
                    }
                    break;
                }
                case "GraphQLAstMatcher":
                    body.put("type", "GRAPHQL");
                    body.put("query", (String) field(matcher, "expectedQuery"));
                    body.put("selectionSetMatchType", String.valueOf(field(matcher, "mode")));
                    fields(body, field(matcher, "expectedFields"));
                    break;
                case "JsonRpcMatcher":
                    body.put("type", "JSON_RPC");
                    putIfNotNull(body, "method", field(matcher, "method"));
                    putIfNotNull(body, "paramsSchema", field(matcher, "paramsSchema"));
                    break;
                case "FuzzyMatcher":
                    body.put("type", "FUZZY");
                    putIfNotNull(body, "fuzzy", field(matcher, "matcher"));
                    body.put("threshold", (Double) field(matcher, "threshold"));
                    body.put("ignoreCase", (Boolean) field(matcher, "ignoreCase"));
                    break;
                default:
                    c.put("unserialisable", "unknown body matcher " + type);
            }
            if (matcher instanceof org.mockserver.matchers.NotMatcher) {
                Field not = org.mockserver.matchers.NotMatcher.class.getDeclaredField("not");
                not.setAccessible(true);
                if (not.getBoolean(matcher)) {
                    body.put("not", true);
                }
            }
            c.put("actual", actual);
            if (thrown == null) {
                c.put("result", (Boolean) result);
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            exit("jackson");
        }
        outcome(c, thrown);
        write("bodymatch", c);
    }

    public static Object field(Object target, String name) throws ReflectiveOperationException {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(target);
    }

    private static void putIfNotNull(ObjectNode node, String name, Object value) {
        if (value != null) {
            node.put(name, String.valueOf(value));
        }
    }

    private static void fields(ObjectNode body, Object fields) {
        if (fields instanceof java.util.List && !((java.util.List<?>) fields).isEmpty()) {
            com.fasterxml.jackson.databind.node.ArrayNode array = body.putArray("fields");
            for (Object f : (java.util.List<?>) fields) {
                array.add(String.valueOf(f));
            }
        }
    }

    public static ObjectNode base(String boundary) {
        ObjectNode c = JSON.createObjectNode();
        c.put("boundary", boundary);
        c.put("test", currentTest);
        return c;
    }

    public static void outcome(ObjectNode c, Throwable thrown) {
        if (thrown != null) {
            c.put("thrown", thrown.getClass().getName());
            c.put("message", String.valueOf(thrown.getMessage()));
        }
    }

    public static void write(String boundary, ObjectNode c) {
        synchronized (OUT) {
            PrintWriter out = OUT.computeIfAbsent(boundary, b -> {
                File dir = new File(System.getProperty("harvestDir", "target/harvest"));
                dir.mkdirs();
                try {
                    OutputStream stream = new FileOutputStream(new File(dir, b + ".jsonl"), false);
                    return new PrintWriter(new java.io.OutputStreamWriter(stream, StandardCharsets.UTF_8), true);
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            });
            // the recorder's own serialisation must not be recorded: it runs as a nested "jackson" call
            enter("jackson");
            try {
                out.println(JSON.writeValueAsString(c));
            } catch (IOException e) {
                throw new IllegalStateException(e);
            } finally {
                exit("jackson");
            }
        }
    }

    public static class DeserializeAdvice {
        @Advice.OnMethodEnter
        public static boolean enter(@Advice.Origin("#t") String type) {
            return Recorder.enter(type);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#t") String type, @Advice.Origin("#t.#m") String method,
                                @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
            Recorder.exit(type);
            if (outermost) {
                Recorder.deserialized(method, args, thrown);
            }
        }
    }

    public static class ValidateAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("isValid");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.Argument(0) String json,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("isValid");
            if (outermost) {
                Recorder.validated(self.getClass().getName(), json, result, thrown);
            }
        }
    }

    public static class ReadValueAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("jackson");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.Argument(0) String json, @Advice.Argument(1) Class<?> type,
                                @Advice.Thrown Throwable thrown) {
            Recorder.exit("jackson");
            if (outermost) {
                Recorder.jackson("ObjectMapper.readValue", type.getName(), json, thrown);
            }
        }
    }

    public static class WriteValueAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("jackson");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.Argument(0) Object value,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object json, @Advice.Thrown Throwable thrown) {
            Recorder.exit("jackson");
            if (outermost && value != null && thrown == null) {
                Recorder.jackson("ObjectMapper.writeValueAsString", value.getClass().getName(), (String) json, null);
            }
        }
    }

    public static class TemplateAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("executeTemplate");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.AllArguments Object[] args,
                                @Advice.Thrown Throwable thrown) {
            Recorder.exit("executeTemplate");
            if (outermost) {
                Recorder.templated(self, args, thrown);
            }
        }
    }

    public static class OpenAPIAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("buildExpectations");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.AllArguments Object[] args,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("buildExpectations");
            if (outermost) {
                Recorder.converted(self, args, result, thrown);
            }
        }
    }

    public static class CodeAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("toCode");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#t") String type, @Advice.AllArguments Object[] args,
                                @Advice.Thrown Throwable thrown) {
            Recorder.exit("toCode");
            if (outermost) {
                Recorder.coded(type, args, thrown);
            }
        }
    }

    public static class ExampleAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("example");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
            Recorder.exit("example");
            if (outermost) {
                Recorder.example(args, thrown);
            }
        }
    }

    public static class SynthesizeAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("example");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.AllArguments Object[] args,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("example");
            if (outermost) {
                Recorder.synthesized(args, result, thrown);
            }
        }
    }

    public static class ValidationAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("openApiValidation");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#t") String type, @Advice.AllArguments Object[] args,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("openApiValidation");
            if (outermost) {
                Recorder.validatedOpenApi(type, args, result, thrown);
            }
        }
    }

    public static class ExpressionAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("runtimeExpression");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
            Recorder.exit("runtimeExpression");
            if (outermost) {
                Recorder.resolved(args, thrown);
            }
        }
    }

    public static class RenderAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("renderTemplate");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.AllArguments Object[] args,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("renderTemplate");
            if (outermost) {
                Recorder.rendered(self, args, result, thrown);
            }
        }
    }

    public static class HelperAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("templateHelper");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#t") String type, @Advice.Origin java.lang.reflect.Method method,
                                @Advice.AllArguments Object[] args, @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result,
                                @Advice.Thrown Throwable thrown) {
            Recorder.exit("templateHelper");
            if (outermost) {
                Recorder.helped(type, method, args, result, thrown);
            }
        }
    }

    public static class MatchAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("matches");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.Argument(1) Object actual,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("matches");
            if (outermost) {
                Recorder.matched(self, actual, result, thrown);
            }
        }
    }

    public static class BodyMatchAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("bodymatch");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.AllArguments Object[] args,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("bodymatch");
            if (outermost) {
                Recorder.bodyMatched(self, (String) args[args.length - 1], result, thrown);
            }
        }
    }

    // ---- B4 WASM, kind `wasm` ----

    private static ObjectNode wasmRequest(Object wasmRequest) {
        org.mockserver.wasm.WasmRequest r = (org.mockserver.wasm.WasmRequest) wasmRequest;
        ObjectNode n = JSON.createObjectNode();
        if (r == null) {
            return n;
        }
        n.put("method", r.getMethod());
        n.put("path", r.getPath());
        n.set("headers", JSON.valueToTree(r.getHeaders()));
        n.set("queryStringParameters", JSON.valueToTree(r.getQueryStringParameters()));
        n.set("cookies", JSON.valueToTree(r.getCookies()));
        n.put("body", r.getBody());
        return n;
    }

    private static ObjectNode wasmResponse(Integer status, Object headers, String body) {
        ObjectNode n = JSON.createObjectNode();
        if (status != null) {
            n.put("statusCode", status);
        }
        n.set("headers", JSON.valueToTree(headers));
        n.put("body", body);
        return n;
    }

    /** An {@code HttpResponse} as status, name -> values and body, before a shaper mutates it. */
    private static ObjectNode httpResponse(org.mockserver.model.HttpResponse response) {
        Map<String, java.util.List<String>> headers = new java.util.LinkedHashMap<>();
        if (response.getHeaderList() != null) {
            for (org.mockserver.model.Header header : response.getHeaderList()) {
                java.util.List<String> values = headers.computeIfAbsent(header.getName().getValue(), k -> new java.util.ArrayList<>());
                for (org.mockserver.model.NottableString v : header.getValues()) {
                    values.add(v.getValue());
                }
            }
        }
        return wasmResponse(response.getStatusCode(), headers, response.getBodyAsString());
    }

    private static void wasmModule(ObjectNode c, byte[] bytes) {
        if (bytes == null) {
            c.putNull("module");
        } else {
            c.put("module", java.util.Base64.getEncoder().encodeToString(bytes));
        }
    }

    private static boolean staticWasmEnabled(Object configuration) throws ReflectiveOperationException {
        if (configuration == null) {
            return org.mockserver.configuration.ConfigurationProperties.wasmEnabled();
        }
        return (Boolean) configuration.getClass().getMethod("wasmEnabled").invoke(configuration);
    }

    /** {@code WasmRuntime.callMatch(String|WasmRequest)} or {@code callShape(WasmRequest, WasmResponse)}. */
    public static void wasmRuntimeCalled(Object runtime, String method, Object[] args, Object result, Throwable thrown) {
        ObjectNode c = base("WasmRuntime." + method);
        enter("jackson");
        try {
            c.put("kind", "runtime");
            wasmModule(c, (byte[]) field(runtime, "wasmBytes"));
            c.put("maxMemoryPages", (Integer) field(runtime, "maxMemoryPages"));
            c.put("executionTimeoutMillis", (Long) field(runtime, "executionTimeoutMillis"));
            if (args[0] == null || args[0] instanceof String) {
                c.put("call", "callMatchBody");
                c.put("body", (String) args[0]);
            } else {
                c.put("call", method);
                c.set("request", wasmRequest(args[0]));
            }
            if (args.length > 1) {
                org.mockserver.wasm.WasmResponse r = (org.mockserver.wasm.WasmResponse) args[1];
                c.set("response", r == null ? null : wasmResponse(r.getStatusCode(), r.getHeaders(), r.getBody()));
            }
            if (thrown == null) {
                if (result instanceof org.mockserver.wasm.WasmResponse) {
                    org.mockserver.wasm.WasmResponse r = (org.mockserver.wasm.WasmResponse) result;
                    c.set("result", wasmResponse(r.getStatusCode(), r.getHeaders(), r.getBody()));
                } else {
                    c.set("result", JSON.valueToTree(result));
                }
            }
            c.put("interrupted", Thread.currentThread().isInterrupted());
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            exit("jackson");
        }
        outcome(c, thrown);
        write("wasm", c);
    }

    /** {@code WasmBodyMatcher.matches(MatchDifference, String)}: the module name, the store's bytes for it, the gate and
     * the request the matcher builds its envelope from. */
    public static void wasmMatcherCalled(Object matcher, Object context, String actual, Object result, Throwable thrown) {
        ObjectNode c = base("WasmBodyMatcher.matches");
        enter("jackson");
        try {
            c.put("kind", "matcher");
            String name = (String) field(matcher, "moduleName");
            c.put("moduleName", name);
            c.put("wasmEnabled", staticWasmEnabled(field(matcher, "configuration")));
            wasmModule(c, name == null ? null : org.mockserver.wasm.WasmStore.getInstance().get(name));
            Field not = org.mockserver.matchers.NotMatcher.class.getDeclaredField("not");
            not.setAccessible(true);
            c.put("not", not.getBoolean(matcher));
            Object request = context == null ? null : ((org.mockserver.matchers.MatchDifference) context).getHttpRequest();
            c.set("request", wasmRequest(request instanceof org.mockserver.model.HttpRequest
                ? org.mockserver.wasm.WasmRequest.fromHttpRequest((org.mockserver.model.HttpRequest) request, actual)
                : org.mockserver.wasm.WasmRequest.ofBody(actual)));
            if (thrown == null) {
                c.put("result", (Boolean) result);
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            exit("jackson");
        }
        outcome(c, thrown);
        write("wasm", c);
    }

    /** The response a shaper is about to mutate, taken on entry. */
    public static ObjectNode wasmShapeEntered(Object[] args) {
        enter("jackson");
        try {
            return httpResponse((org.mockserver.model.HttpResponse) args[0]);
        } catch (Throwable e) {
            ObjectNode n = JSON.createObjectNode();
            n.put("unserialisable", String.valueOf(e));
            return n;
        } finally {
            exit("jackson");
        }
    }

    /** {@code WasmResponseShaper.shape(response, request, moduleName, bytes)} or
     * {@code HttpResponseActionHandler.shapeResponseWithWasm(response, request, matchedRequest)}. */
    public static void wasmShaped(Object self, Object[] args, ObjectNode before, Throwable thrown) {
        boolean handler = args.length == 3;
        ObjectNode c = base(handler ? "HttpResponseActionHandler.shapeResponseWithWasm" : "WasmResponseShaper.shape");
        enter("jackson");
        try {
            if (before.has("unserialisable")) {
                c.put("unserialisable", before.get("unserialisable").asText());
            }
            c.put("kind", handler ? "handler" : "shaper");
            c.set("response", before);
            org.mockserver.model.HttpRequest request = (org.mockserver.model.HttpRequest) args[1];
            String body = request.getBody() == null ? null : request.getBodyAsString();
            c.set("request", wasmRequest(org.mockserver.wasm.WasmRequest.fromHttpRequest(request, body)));
            c.put("wasmEnabled", staticWasmEnabled(field(self, "configuration")));
            if (handler) {
                Object matched = args[2];
                Object matchedBody = matched instanceof org.mockserver.model.HttpRequest ? ((org.mockserver.model.HttpRequest) matched).getBody() : null;
                if (matchedBody instanceof org.mockserver.model.WasmBody) {
                    String name = ((org.mockserver.model.WasmBody) matchedBody).getModuleName();
                    c.put("moduleName", name);
                    wasmModule(c, org.mockserver.wasm.WasmStore.getInstance().get(name));
                } else {
                    c.put("matchedPath", matched instanceof org.mockserver.model.HttpRequest && ((org.mockserver.model.HttpRequest) matched).getPath() != null
                        ? ((org.mockserver.model.HttpRequest) matched).getPath().getValue() : null);
                    wasmModule(c, null);
                }
            } else {
                c.put("moduleName", (String) args[2]);
                wasmModule(c, (byte[]) args[3]);
            }
            c.set("result", httpResponse((org.mockserver.model.HttpResponse) args[0]));
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            exit("jackson");
        }
        outcome(c, thrown);
        write("wasm", c);
    }

    public static class WasmRuntimeAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("wasm");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.Origin("#m") String method,
                                @Advice.AllArguments Object[] args,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("wasm");
            if (outermost) {
                Recorder.wasmRuntimeCalled(self, method, args, result, thrown);
            }
        }
    }

    public static class WasmMatcherAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("wasm");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.AllArguments Object[] args,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("wasm");
            if (outermost) {
                Recorder.wasmMatcherCalled(self, args[0], (String) args[1], result, thrown);
            }
        }
    }

    public static class WasmShapeAdvice {
        @Advice.OnMethodEnter
        public static ObjectNode enter(@Advice.AllArguments Object[] args) {
            return Recorder.enter("wasm") ? Recorder.wasmShapeEntered(args) : null;
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter ObjectNode before, @Advice.This Object self, @Advice.AllArguments Object[] args,
                                @Advice.Thrown Throwable thrown) {
            Recorder.exit("wasm");
            if (before != null) {
                Recorder.wasmShaped(self, args, before, thrown);
            }
        }
    }

    // ---- B4 LLM, kinds `llmcodec`, `llmhandler`, `llmmatch` ----

    private static Object anyField(Object target, String name) throws ReflectiveOperationException {
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

    /** An {@code HttpLlmResponse} as the {@code httpLlmResponse} of an expectation, in the oracle's own JSON. */
    private static com.fasterxml.jackson.databind.JsonNode llmJson(org.mockserver.model.HttpLlmResponse llm) throws Exception {
        String json = new org.mockserver.serialization.ExpectationSerializer(new MockServerLogger())
            .serialize(new org.mockserver.mock.Expectation(org.mockserver.model.HttpRequest.request()).thenRespondWithLlm(llm));
        return JSON.readTree(json).get("httpLlmResponse");
    }

    private static String llmRequest(Object request) {
        return request == null ? null : new org.mockserver.serialization.HttpRequestSerializer(new MockServerLogger())
            .serialize((org.mockserver.model.HttpRequest) request);
    }

    /** The configuration values that differ from the run's startup values: {@code configuration}, or the static store. */
    private static void llmConfiguration(ObjectNode c, Object configuration) {
        ObjectNode differences = c.putObject("configuration");
        Object effective = configuration != null ? configuration : org.mockserver.configuration.Configuration.configuration();
        configurationValues(effective).forEach((name, value) -> {
            if (!value.equals(CONFIGURATION_DEFAULTS.get(name))) {
                differences.put(name, value);
            }
        });
    }

    /** A {@code ProviderCodec} call: what it encodes, as the {@code httpLlmResponse} that makes the handler call it. */
    @SuppressWarnings("unchecked")
    public static void llmCodecCalled(Object codec, String method, Object[] args, Throwable thrown) {
        ObjectNode c = base(codec.getClass().getSimpleName() + "." + method);
        enter("jackson");
        try {
            org.mockserver.model.Provider provider = ((org.mockserver.llm.ProviderCodec) codec).provider();
            c.put("call", method);
            c.put("provider", provider == null ? null : provider.name());
            org.mockserver.model.HttpLlmResponse llm = org.mockserver.model.HttpLlmResponse.llmResponse().withProvider(provider);
            switch (method) {
                case "encode":
                    llm.withModel((String) args[1]).withCompletion((org.mockserver.model.Completion) args[0]);
                    break;
                case "encodeStreaming":
                    llm.withModel((String) args[1]).withCompletion((org.mockserver.model.Completion) args[0]);
                    c.set("physics", args[2] == null ? null : llmJson(org.mockserver.model.HttpLlmResponse.llmResponse()
                        .withCompletion(org.mockserver.model.Completion.completion()
                            .withStreamingPhysics((org.mockserver.model.StreamingPhysics) args[2]))).get("completion").get("streamingPhysics"));
                    break;
                case "encodeEmbedding":
                    llm.withEmbedding((org.mockserver.model.EmbeddingResponse) args[0]);
                    if (args.length > 2) {
                        llm.withModel((String) args[2]);
                    }
                    c.put("input", (String) args[1]);
                    break;
                case "encodeRerank":
                    llm.withRerank((org.mockserver.model.RerankResponse) args[0]);
                    c.set("documents", JSON.valueToTree(args[1]));
                    break;
                case "decode":
                    c.put("request", llmRequest(args[0]));
                    break;
                default:
                    throw new IllegalArgumentException(method);
            }
            c.set("llm", llmJson(llm));
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            exit("jackson");
        }
        outcome(c, thrown);
        write("llmcodec", c);
    }

    /** An {@code HttpLlmResponseActionHandler} call: the action, the request and the handler's configuration. */
    public static void llmHandlerCalled(Object handler, String method, Object[] args, Throwable thrown) {
        ObjectNode c = base("HttpLlmResponseActionHandler." + method);
        enter("jackson");
        try {
            c.put("call", method);
            if (method.equals("withInferredUsageIfEnabled")) {
                org.mockserver.model.Provider provider = args[1] == null ? null : ((org.mockserver.llm.ProviderCodec) args[1]).provider();
                c.set("llm", llmJson(org.mockserver.model.HttpLlmResponse.llmResponse().withProvider(provider)
                    .withCompletion((org.mockserver.model.Completion) args[0])));
                c.put("request", llmRequest(args[2]));
            } else {
                c.set("llm", args[0] == null ? null : llmJson((org.mockserver.model.HttpLlmResponse) args[0]));
                c.put("request", args.length > 1 ? llmRequest(args[1]) : null);
            }
            llmConfiguration(c, anyField(handler, "configuration"));
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            exit("jackson");
        }
        outcome(c, thrown);
        write("llmhandler", c);
    }

    /** {@code LlmConversationMatcher.matches(request, configuration)}: the matcher as conversation predicates. */
    public static void llmMatcherCalled(Object matcher, Object[] args, Object result, Throwable thrown) {
        ObjectNode c = base("LlmConversationMatcher.matches");
        enter("jackson");
        try {
            org.mockserver.model.ConversationPredicates predicates = org.mockserver.model.ConversationPredicates.conversationPredicates()
                .withTurnIndex((Integer) anyField(matcher, "turnIndex"))
                .withLatestMessageContains((String) anyField(matcher, "latestMessageContains"))
                .withLatestMessageMatches((String) anyField(matcher, "latestMessageMatchesSource"))
                .withLatestMessageRole((org.mockserver.llm.ParsedMessage.Role) anyField(matcher, "latestMessageRole"))
                .withContainsToolResultFor((String) anyField(matcher, "containsToolResultFor"))
                .withSemanticMatchAgainst((String) anyField(matcher, "semanticMatchAgainst"))
                .withNormalization((org.mockserver.model.NormalizationOptions) anyField(matcher, "normalization"));
            c.set("llm", llmJson(org.mockserver.model.HttpLlmResponse.llmResponse()
                .withProvider((org.mockserver.model.Provider) anyField(matcher, "provider"))
                .withConversationPredicates(predicates)));
            c.put("request", llmRequest(args[0]));
            llmConfiguration(c, args[1]);
            if (thrown == null) {
                c.put("result", (Boolean) result);
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            exit("jackson");
        }
        outcome(c, thrown);
        write("llmmatch", c);
    }

    public static class LlmCodecAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("llm");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.Origin("#m") String method,
                                @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
            Recorder.exit("llm");
            if (outermost) {
                Recorder.llmCodecCalled(self, method, args, thrown);
            }
        }
    }

    public static class LlmHandlerAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("llm");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.Origin("#m") String method,
                                @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
            Recorder.exit("llm");
            if (outermost) {
                Recorder.llmHandlerCalled(self, method, args, thrown);
            }
        }
    }

    public static class LlmMatcherAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("llm");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.AllArguments Object[] args,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("llm");
            if (outermost) {
                Recorder.llmMatcherCalled(self, args, result, thrown);
            }
        }
    }
}
