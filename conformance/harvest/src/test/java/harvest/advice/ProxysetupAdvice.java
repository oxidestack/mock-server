package harvest.advice;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code proxysetup} (B4): {@code new ProxySetupInfo(caCertificatePath, ports, configuration, osName)},
 * what {@code GET /mockserver/proxyConfiguration} renders, one line of proxysetup.jsonl per construction with the ports,
 * the OS name and the three configuration values it reads ({@code dynamicallyCreateCertificateAuthorityCertificate},
 * {@code proxySetup}, {@code certificateAuthorityCertificate}). Replayed as that request, JSON and text, on a server
 * started with those values.
 */
public class ProxysetupAdvice implements Boundary {

    private static final String KEY = "proxysetup";

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.socket.tls.ProxySetupInfo"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ProxysetupAdvice.class)
                .on(isConstructor().and(takesArguments(4)))));
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.AllArguments Object[] args) {
        ProxysetupAdvice.called(args);
    }

    public static void called(Object[] args) {
        ObjectNode c = Recorder.base("ProxySetupInfo.<init>");
        c.put("caCertificatePath", (String) args[0]);
        ArrayNode ports = c.putArray("ports");
        if (args[1] instanceof java.util.List) {
            for (Object port : (java.util.List<?>) args[1]) {
                ports.add(String.valueOf(port));
            }
        }
        org.mockserver.configuration.Configuration configuration = (org.mockserver.configuration.Configuration) args[2];
        c.put("dynamicallyCreateCertificateAuthorityCertificate", String.valueOf(configuration.dynamicallyCreateCertificateAuthorityCertificate()));
        c.put("proxySetup", String.valueOf(configuration.proxySetup()));
        c.put("certificateAuthorityCertificate", configuration.certificateAuthorityCertificate());
        c.put("defaultCertificateAuthorityCertificate",
            org.mockserver.configuration.ConfigurationProperties.DEFAULT_CERTIFICATE_AUTHORITY_X509_CERTIFICATE);
        c.put("osName", (String) args[3]);
        Recorder.write(KEY, c);
    }
}
