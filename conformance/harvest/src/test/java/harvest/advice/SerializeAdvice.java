package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import org.mockserver.configuration.Configuration;
import org.mockserver.load.LoadScenario;
import org.mockserver.logging.MockServerLogger;
import org.mockserver.mock.Expectation;
import org.mockserver.mock.OpenAPIExpectation;
import org.mockserver.model.HttpRequestAndHttpResponse;
import org.mockserver.model.PortBinding;
import org.mockserver.slo.SloCriteria;
import org.mockserver.verify.Verification;
import org.mockserver.verify.VerificationSequence;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code serialize} (B2): {@code ExpectationSerializer.serialize},
 * {@code HttpRequestAndHttpResponseSerializer.serialize}, and {@code ConfigurationSerializer},
 * {@code PortBindingSerializer}, {@code LoadScenarioSerializer}, {@code VerificationSerializer},
 * {@code VerificationSequenceSerializer}, {@code SloCriteriaSerializer.serialize(SloCriteria)} (not its
 * {@code serialize(SloVerdict)} overload — no endpoint accepts a verdict as input) and the top-level
 * {@code OpenAPIExpectationSerializer}, single-object and array overloads where they exist, each outermost call one
 * line of serialize.jsonl. Several of these classes' test suites exercise `serialize` through a Mockito
 * {@code @InjectMocks} subject whose internal {@code ObjectMapper}/{@code ObjectWriter} fields are mocks (only
 * {@code verify()}d, never producing real JSON) — this advice ignores that and re-serialises the real domain-object
 * argument with a fresh, unmocked serializer of its own, the same way {@code HarAdvice} re-serialises
 * {@code HarConverter.serialize}'s argument.
 */
public class SerializeAdvice implements Boundary {

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.serialization.ExpectationSerializer"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(SerializeAdvice.class).on(named("serialize").and(takesArgument(0, Expectation.class))))
                .visit(Advice.to(SerializeAdvice.class).on(named("serialize").and(takesArguments(1)).and(takesArgument(0, Expectation[].class)))))
            .type(named("org.mockserver.serialization.HttpRequestAndHttpResponseSerializer"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(SerializeAdvice.class).on(named("serialize").and(takesArgument(0, HttpRequestAndHttpResponse.class))))
                .visit(Advice.to(SerializeAdvice.class).on(named("serialize").and(takesArguments(1)).and(takesArgument(0, HttpRequestAndHttpResponse[].class)))))
            .type(named("org.mockserver.serialization.ConfigurationSerializer"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(SerializeAdvice.class).on(named("serialize").and(takesArgument(0, Configuration.class)))))
            .type(named("org.mockserver.serialization.PortBindingSerializer"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(SerializeAdvice.class).on(named("serialize").and(takesArgument(0, PortBinding.class)))))
            .type(named("org.mockserver.serialization.LoadScenarioSerializer"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(SerializeAdvice.class).on(named("serialize").and(takesArgument(0, LoadScenario.class)))))
            .type(named("org.mockserver.serialization.VerificationSerializer"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(SerializeAdvice.class).on(named("serialize").and(takesArgument(0, Verification.class)))))
            .type(named("org.mockserver.serialization.VerificationSequenceSerializer"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(SerializeAdvice.class).on(named("serialize").and(takesArgument(0, VerificationSequence.class)))))
            .type(named("org.mockserver.serialization.SloCriteriaSerializer"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(SerializeAdvice.class).on(named("serialize").and(takesArgument(0, SloCriteria.class)))))
            .type(named("org.mockserver.serialization.OpenAPIExpectationSerializer"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(SerializeAdvice.class).on(named("serialize").and(takesArguments(1)).and(takesArgument(0, OpenAPIExpectation.class))))
                .visit(Advice.to(SerializeAdvice.class).on(named("serialize").and(takesArguments(1)).and(takesArgument(0, OpenAPIExpectation[].class)))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter("serialize");
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#t") String type, @Advice.AllArguments Object[] args,
                            @Advice.Thrown Throwable thrown) {
        Recorder.exit("serialize");
        if (outermost) {
            SerializeAdvice.record(type, args, thrown);
        }
    }

    public static void record(String type, Object[] args, Throwable thrown) {
        // `thrown` is whatever the ORIGINAL call raised, which in several calling tests is a Mockito-mocked
        // exception on the internal ObjectWriter (not a real serialisation failure) — irrelevant here, since this
        // advice re-serialises with a fresh, unmocked serializer of its own and never fails the same way.
        String simple = type.substring(type.lastIndexOf('.') + 1);
        ObjectNode c = Recorder.base(simple + ".serialize");
        // The fresh serializer below calls the very method this advice is on (Byte Buddy instruments the class, not
        // this one instance) — re-enter the SAME depth key so that recursive call is never "outermost" and record()
        // never re-invokes itself (a `serialize` call with un-mocked internals would otherwise stack-overflow).
        Recorder.enter("serialize");
        Recorder.enter("jackson");
        try {
            MockServerLogger logger = new MockServerLogger();
            Object arg = args[0];
            if (arg instanceof Expectation) {
                c.put("class", "Expectation");
                c.put("input", new org.mockserver.serialization.ExpectationSerializer(logger).serialize((Expectation) arg));
            } else if (arg instanceof Expectation[]) {
                c.put("class", "Expectation[]");
                c.put("input", new org.mockserver.serialization.ExpectationSerializer(logger).serialize((Expectation[]) arg));
            } else if (arg instanceof HttpRequestAndHttpResponse) {
                c.put("class", "HttpRequestAndHttpResponse");
                c.put("input", new org.mockserver.serialization.HttpRequestAndHttpResponseSerializer(logger).serialize((HttpRequestAndHttpResponse) arg));
            } else if (arg instanceof HttpRequestAndHttpResponse[]) {
                c.put("class", "HttpRequestAndHttpResponse[]");
                c.put("input", new org.mockserver.serialization.HttpRequestAndHttpResponseSerializer(logger).serialize((HttpRequestAndHttpResponse[]) arg));
            } else if (arg instanceof Configuration) {
                c.put("class", "Configuration");
                c.put("input", new org.mockserver.serialization.ConfigurationSerializer(logger).serialize((Configuration) arg));
            } else if (arg instanceof PortBinding) {
                c.put("class", "PortBinding");
                c.put("input", new org.mockserver.serialization.PortBindingSerializer(logger).serialize((PortBinding) arg));
            } else if (arg instanceof LoadScenario) {
                c.put("class", "LoadScenario");
                c.put("input", new org.mockserver.serialization.LoadScenarioSerializer(logger).serialize((LoadScenario) arg));
            } else if (arg instanceof Verification) {
                c.put("class", "Verification");
                c.put("input", new org.mockserver.serialization.VerificationSerializer(logger).serialize((Verification) arg));
            } else if (arg instanceof VerificationSequence) {
                c.put("class", "VerificationSequence");
                c.put("input", new org.mockserver.serialization.VerificationSequenceSerializer(logger).serialize((VerificationSequence) arg));
            } else if (arg instanceof SloCriteria) {
                c.put("class", "SloCriteria");
                c.put("input", new org.mockserver.serialization.SloCriteriaSerializer(logger).serialize((SloCriteria) arg));
            } else if (arg instanceof OpenAPIExpectation) {
                c.put("class", "OpenAPIExpectation");
                c.put("input", new org.mockserver.serialization.OpenAPIExpectationSerializer(logger).serialize((OpenAPIExpectation) arg));
            } else if (arg instanceof OpenAPIExpectation[]) {
                c.put("class", "OpenAPIExpectation[]");
                c.put("input", new org.mockserver.serialization.OpenAPIExpectationSerializer(logger).serialize((OpenAPIExpectation[]) arg));
            } else {
                c.put("unserialisable", "unrecognised argument " + (arg == null ? "null" : arg.getClass().getName()));
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
            Recorder.exit("serialize");
        }
        Recorder.write("serialize", c);
    }
}
