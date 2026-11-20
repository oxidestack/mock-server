package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code wsdl} (B4): {@code WsdlExpectationGenerator.generate(String)}, each outermost call one line
 * of wsdl.jsonl with the WSDL text and whether it threw. Replayed as {@code PUT /mockserver/wsdl} plus a retrieve of
 * the active expectations.
 */
public class WsdlAdvice implements Boundary {

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.mock.wsdl.WsdlExpectationGenerator"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(WsdlAdvice.class)
                .on(named("generate").and(takesArguments(String.class)))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter("wsdl");
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.Argument(0) String wsdl, @Advice.Thrown Throwable thrown) {
        Recorder.exit("wsdl");
        if (outermost) {
            ObjectNode c = Recorder.base("WsdlExpectationGenerator.generate");
            c.put("wsdl", wsdl);
            Recorder.outcome(c, thrown);
            Recorder.write("wsdl", c);
        }
    }
}
