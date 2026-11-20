package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code schemavalidator} (B2): the schema-carrying validators {@code JsonSchemaValidator(logger,
 * String schema)} and {@code XmlSchemaValidator(logger, schema, sourceUri)}. The family-wide {@code ValidateAdvice}
 * records only {@code isValid}'s input, never the schema the validator was built from, and {@code XmlSchemaValidator}
 * is not a {@code JsonSchemaValidator} at all, so neither class's tests recorded a replayable case. This boundary keeps
 * the schema from the constructor (per thread: the tests build a validator and call it at once) and writes one line to
 * schemavalidator.jsonl for each outermost {@code isValid} call on those two exact classes
 * ({@code type: json|xml, schema, input, result}), and {@code new}/{@code built} lines around each constructor
 * (a {@code new} with no {@code built} is an invalid schema rejected at build time).
 */
public class SchemaValidatorAdvice implements Boundary {

    /** The schema (and for XML the source URI) the current thread's last validator was built from. */
    public static final ThreadLocal<String[]> JSON_LAST = new ThreadLocal<>();
    public static final ThreadLocal<String[]> XML_LAST = new ThreadLocal<>();

    private static final String JSON = "org.mockserver.validator.jsonschema.JsonSchemaValidator";
    private static final String XML = "org.mockserver.validator.xmlschema.XmlSchemaValidator";

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named(JSON))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(JsonConstructed.class).on(isConstructor().and(takesArguments(2)).and(
                    net.bytebuddy.matcher.ElementMatchers.takesArgument(1, String.class))))
                .visit(Advice.to(JsonValid.class).on(named("isValid").and(takesArguments(String.class, boolean.class)))))
            .type(named(XML))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(XmlConstructed.class).on(isConstructor().and(takesArguments(3))))
                .visit(Advice.to(XmlValid.class).on(named("isValid").and(takesArguments(String.class)))));
    }

    // Byte Buddy cannot catch an exception thrown by a constructor, so a constructor writes a `new` line on entry and a
    // `built` line on normal exit; a `new` with no `built` after it is a schema the constructor rejected.
    public static class JsonConstructed {
        @Advice.OnMethodEnter
        public static void enter(@Advice.Argument(1) String schema) {
            SchemaValidatorAdvice.constructing("json", schema, null);
        }

        @Advice.OnMethodExit
        public static void exit(@Advice.Argument(1) String schema) {
            SchemaValidatorAdvice.constructed("json", schema, null);
        }
    }

    public static class XmlConstructed {
        @Advice.OnMethodEnter
        public static void enter(@Advice.Argument(1) String schema, @Advice.Argument(2) String sourceUri) {
            SchemaValidatorAdvice.constructing("xml", schema, sourceUri);
        }

        @Advice.OnMethodExit
        public static void exit(@Advice.Argument(1) String schema, @Advice.Argument(2) String sourceUri) {
            SchemaValidatorAdvice.constructed("xml", schema, sourceUri);
        }
    }

    public static class JsonValid {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("schemavalidator.json");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.Argument(0) String input,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("schemavalidator.json");
            if (outermost && self.getClass().getName().equals(JSON)) {
                SchemaValidatorAdvice.validated("json", JSON_LAST.get(), input, result, thrown);
            }
        }
    }

    public static class XmlValid {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("schemavalidator.xml");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.Argument(0) String input,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit("schemavalidator.xml");
            if (outermost) {
                SchemaValidatorAdvice.validated("xml", XML_LAST.get(), input, result, thrown);
            }
        }
    }

    private static void line(String event, String type, String schema, String sourceUri) {
        ObjectNode c = Recorder.base("SchemaValidator.new");
        c.put("event", event);
        c.put("type", type);
        if (schema == null) {
            c.putNull("schema");
        } else {
            c.put("schema", schema);
        }
        if (sourceUri != null) {
            c.put("sourceUri", sourceUri);
        }
        Recorder.write("schemavalidator", c);
    }

    public static void constructing(String type, String schema, String sourceUri) {
        line("new", type, schema, sourceUri);
    }

    public static void constructed(String type, String schema, String sourceUri) {
        (type.equals("json") ? JSON_LAST : XML_LAST).set(new String[]{schema, sourceUri});
        line("built", type, schema, sourceUri);
    }

    public static void validated(String type, String[] built, String input, Object result, Throwable thrown) {
        if (built == null) {
            return;
        }
        ObjectNode c = Recorder.base("SchemaValidator.isValid");
        c.put("event", "valid");
        c.put("type", type);
        c.put("schema", built[0]);
        if (built[1] != null) {
            c.put("sourceUri", built[1]);
        }
        if (input == null) {
            c.putNull("input");
        } else {
            c.put("input", input);
        }
        if (thrown == null) {
            c.put("result", result == null ? "" : result.toString());
        }
        Recorder.outcome(c, thrown);
        Recorder.write("schemavalidator", c);
    }
}
