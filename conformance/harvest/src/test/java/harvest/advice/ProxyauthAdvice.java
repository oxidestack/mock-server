package harvest.advice;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code proxyauth} (B4): {@code ProxyAuthenticationValidator.isAuthenticated(request, username,
 * password)}, each outermost call one line of proxyauth.jsonl with the request's {@code Proxy-Authorization} values,
 * the configured username and password and the answer. Replayed as a {@code CONNECT} on a server started with
 * {@code proxyAuthenticationUsername}/{@code proxyAuthenticationPassword}.
 */
public class ProxyauthAdvice implements Boundary {

    private static final String KEY = "proxyauth";

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.authentication.ProxyAuthenticationValidator"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ProxyauthAdvice.class)
                .on(named("isAuthenticated").and(takesArguments(3)))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter(KEY);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.AllArguments Object[] args,
                            @Advice.Return boolean authenticated, @Advice.Thrown Throwable thrown) {
        Recorder.exit(KEY);
        if (outermost) {
            ProxyauthAdvice.called(args, authenticated, thrown);
        }
    }

    public static void called(Object[] args, boolean authenticated, Throwable thrown) {
        ObjectNode c = Recorder.base("ProxyAuthenticationValidator.isAuthenticated");
        org.mockserver.model.HttpRequest request = (org.mockserver.model.HttpRequest) args[0];
        if (request == null) {
            c.putNull("headers");
        } else {
            ArrayNode values = c.putArray("headers");
            for (String value : request.getHeader("Proxy-Authorization")) {
                values.add(value);
            }
        }
        c.put("username", (String) args[1]);
        c.put("password", (String) args[2]);
        c.put("authenticated", authenticated);
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }
}
