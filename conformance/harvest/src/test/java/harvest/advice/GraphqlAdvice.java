package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Map;

import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code graphql} (B4), one depth key, outermost call only:
 * {@code GraphQLExpectationGenerator.generate(schema[, path])} and {@code GraphQLResponseSynthesizer.synthesizeResponse(body)} with the schema the
 * instance was built from. Replayed through {@code PUT /mockserver/graphql} (and the GraphQL request it serves).
 */
public class GraphqlAdvice implements Boundary {

    /** Each synthesizer's schema text, by instance. */
    public static final Map<Object, String> SCHEMAS = Collections.synchronizedMap(new IdentityHashMap<>());

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.graphql.GraphQLExpectationGenerator"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Generate.class)
                .on(named("generate"))))
            .type(named("org.mockserver.graphql.GraphQLResponseSynthesizer"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(Construct.class).on(isConstructor().and(takesArguments(String.class))))
                .visit(Advice.to(Synthesize.class).on(named("synthesizeResponse").and(takesArguments(String.class)))));
    }

    public static class Generate {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("graphql");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
            Recorder.exit("graphql");
            if (outermost) {
                ObjectNode c = Recorder.base("GraphQLExpectationGenerator.generate");
                c.put("call", "generate");
                c.put("schema", (String) args[0]);
                if (args.length > 1) {
                    c.put("path", (String) args[1]);
                }
                Recorder.outcome(c, thrown);
                Recorder.write("graphql", c);
            }
        }
    }

    /** Byte Buddy cannot catch a constructor's exception, so only the schema of a built instance is kept. */
    public static class Construct {
        @Advice.OnMethodExit
        public static void exit(@Advice.This Object self, @Advice.Argument(0) String schema) {
            SCHEMAS.put(self, schema);
        }
    }

    public static class Synthesize {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter("graphql");
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.Argument(0) String body, @Advice.Thrown Throwable thrown) {
            Recorder.exit("graphql");
            if (outermost) {
                ObjectNode c = Recorder.base("GraphQLResponseSynthesizer.synthesizeResponse");
                c.put("call", "synthesize");
                c.put("schema", SCHEMAS.get(self));
                c.put("body", body);
                Recorder.outcome(c, thrown);
                Recorder.write("graphql", c);
            }
        }
    }
}
