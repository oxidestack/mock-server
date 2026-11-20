package harvest.advice;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import org.mockserver.logging.MockServerLogger;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Objects;

import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.isPublic;
import static net.bytebuddy.matcher.ElementMatchers.isStatic;
import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;
import static net.bytebuddy.matcher.ElementMatchers.not;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code idp} (B4): the identity providers' OIDC, SCIM and SAML surface, under one depth key, outermost
 * call only, in order, one line of idp.jsonl each:
 * <ul>
 *   <li>{@code *ProviderGenerator.generate(config)}: the configuration's fields that differ from a fresh instance's (the
 *   {@code PUT /mockserver/oidc|scim|saml} body);</li>
 *   <li>the class callbacks' {@code handle(HttpRequest)}: the request and the response (for values later requests
 *   reuse);</li>
 *   <li>{@code OidcAuthorizationStore.registerProvider(provider)}: the provider's configuration and endpoint paths;</li>
 *   <li>every other method of the stores, minter, key provider, SCIM filter/sort/patch/shaper and SAML builders a test
 *   calls directly, by name only (in-process calls, which a converter keeps out of the wire form).</li>
 * </ul>
 * Each line carries the calling thread, for the tests that call from a pool.
 */
public class IdpAdvice implements Boundary {

    private static final String KEY = "idp";

    private static final String[] GENERATORS = {"org.mockserver.oidc.OidcProviderGenerator", "org.mockserver.scim.ScimProviderGenerator",
        "org.mockserver.saml.SamlProviderGenerator"};

    private static final String[] CALLBACKS = {"org.mockserver.oidc.OidcAuthorizationCodeCallback", "org.mockserver.oidc.OidcDeviceAuthorizationCallback",
        "org.mockserver.oidc.OidcDiscoveryCallback", "org.mockserver.oidc.OidcIntrospectionCallback", "org.mockserver.oidc.OidcLogoutCallback",
        "org.mockserver.oidc.OidcRevocationCallback", "org.mockserver.oidc.OidcTokenCallback", "org.mockserver.oidc.OidcUserinfoCallback",
        "org.mockserver.scim.ScimCollectionCallback", "org.mockserver.scim.ScimResourceCallback", "org.mockserver.saml.SamlSsoCallback",
        "org.mockserver.saml.SamlSloCallback"};

    private static final String[] IN_PROCESS = {"org.mockserver.oidc.OidcAuthorizationStore", "org.mockserver.oidc.OidcTokenMinter",
        "org.mockserver.oidc.OidcKeyProvider", "org.mockserver.oidc.OidcIssuerResolver", "org.mockserver.scim.ScimResourceStore",
        "org.mockserver.scim.ScimPatchApplier", "org.mockserver.scim.ScimFilter", "org.mockserver.scim.ScimSort", "org.mockserver.scim.ScimShaper",
        "org.mockserver.scim.ScimCallbackSupport", "org.mockserver.saml.SamlAssertionStore", "org.mockserver.saml.SamlResponseBuilder",
        "org.mockserver.saml.SamlLogoutResponseBuilder", "org.mockserver.saml.SamlSigningCredential"};

    private static final ObjectMapper JSON = new ObjectMapper();

    @Override
    public String[] preload() {
        String[] all = new String[GENERATORS.length + CALLBACKS.length + IN_PROCESS.length];
        System.arraycopy(GENERATORS, 0, all, 0, GENERATORS.length);
        System.arraycopy(CALLBACKS, 0, all, GENERATORS.length, CALLBACKS.length);
        System.arraycopy(IN_PROCESS, 0, all, GENERATORS.length + CALLBACKS.length, IN_PROCESS.length);
        return all;
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(namedOneOf(GENERATORS))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(CallAdvice.class)
                .on(named("generate").and(takesArguments(1)))))
            .type(namedOneOf(CALLBACKS))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(CallbackAdvice.class)
                .on(named("handle").and(takesArguments(org.mockserver.model.HttpRequest.class)))))
            .type(named("org.mockserver.oidc.OidcTokenMinter"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(MintAdvice.class)
                .on(named("mintTokenResponse"))))
            .type(namedOneOf(IN_PROCESS))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(CallAdvice.class)
                .on(isMethod().and(not(isAbstract())).and(not(isConstructor()))
                    .and(not(isStatic().and(named("getInstance"))))
                    .and(not(named("mintTokenResponse")))
                    .and(not(namedOneOf("toString", "equals", "hashCode"))))));
    }

    public static class CallbackAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter(KEY);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#t") String type, @Advice.Argument(0) Object request,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object response, @Advice.Thrown Throwable thrown) {
            Recorder.exit(KEY);
            if (outermost) {
                IdpAdvice.callback(type, request, response, thrown);
            }
        }
    }

    /** {@code OidcTokenMinter.mintTokenResponse(scope, nonce, includeRefresh[, issuer])}: a token response minted
     * in-process, with its arguments and the response (whose tokens later requests present). */
    public static class MintAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter(KEY);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object minter, @Advice.AllArguments Object[] args,
                                @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
            Recorder.exit(KEY);
            if (outermost) {
                IdpAdvice.minted(minter, args, result, thrown);
            }
        }
    }

    public static void minted(Object minter, Object[] args, Object result, Throwable thrown) {
        ObjectNode c = base("OidcTokenMinter.mintTokenResponse");
        Recorder.enter("jackson");
        try {
            c.put("call", "mint");
            c.put("scope", (String) args[0]);
            c.put("nonce", (String) args[1]);
            c.put("includeRefresh", (Boolean) args[2]);
            c.put("issuer", args.length > 3 ? (String) args[3] : null);
            c.set("configuration", differences(Recorder.field(minter, "config")));
            c.put("result", (String) result);
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }

    public static class CallAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter(KEY);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#t") String type, @Advice.Origin("#m") String method,
                                @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
            Recorder.exit(KEY);
            if (outermost) {
                IdpAdvice.called(type, method, args, thrown);
            }
        }
    }

    private static ObjectNode base(String boundary) {
        ObjectNode c = Recorder.base(boundary);
        c.put("thread", Thread.currentThread().getName());
        return c;
    }

    public static void callback(String type, Object request, Object response, Throwable thrown) {
        ObjectNode c = base(simple(type) + ".handle");
        Recorder.enter("jackson");
        try {
            c.put("call", "callback");
            c.put("callback", type);
            MockServerLogger logger = new MockServerLogger();
            c.put("request", new org.mockserver.serialization.HttpRequestSerializer(logger).serialize((org.mockserver.model.HttpRequest) request));
            if (response != null) {
                c.put("response", new org.mockserver.serialization.HttpResponseSerializer(logger).serialize((org.mockserver.model.HttpResponse) response));
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }

    public static void called(String type, String method, Object[] args, Throwable thrown) {
        ObjectNode c = base(simple(type) + "." + method);
        Recorder.enter("jackson");
        try {
            if (method.equals("generate")) {
                c.put("call", "generate");
                c.put("provider", simple(type).replace("ProviderGenerator", "").toLowerCase());
                c.set("configuration", differences(args[0]));
            } else if (type.equals("org.mockserver.oidc.OidcAuthorizationStore") && method.equals("registerProvider")) {
                c.put("call", "registerProvider");
                c.put("provider", "oidc");
                Object provider = args[0];
                c.set("configuration", differences(Recorder.field(provider, "config")));
                c.put("authorizePath", (String) Recorder.field(provider, "authorizePath"));
                c.put("tokenPath", (String) Recorder.field(provider, "tokenPath"));
                c.put("deviceAuthorizationPath", (String) Recorder.field(provider, "deviceAuthorizationPath"));
            } else if (type.equals("org.mockserver.oidc.OidcKeyProvider") && method.equals("resolveKeyPair")) {
                // reached on the wire by PUT /mockserver/oidc (the generator resolves the key the same way)
                c.put("call", "resolveKeyPair");
                c.set("configuration", differences(args[0]));
            } else if (type.equals("org.mockserver.oidc.OidcKeyProvider") && method.equals("parseAlgorithm")) {
                c.put("call", "parseAlgorithm");
                c.put("algorithm", (String) args[0]);
            } else if (type.equals("org.mockserver.scim.ScimCallbackSupport") && method.equals("bearerGate")) {
                // the gate every SCIM callback applies first: the request against that provider
                c.put("call", "bearerGate");
                c.put("request", new org.mockserver.serialization.HttpRequestSerializer(new MockServerLogger())
                    .serialize((org.mockserver.model.HttpRequest) args[0]));
                if (args[1] != null) {
                    scimProvider(c, args[1]);
                }
            } else if (type.equals("org.mockserver.scim.ScimResourceStore") && method.equals("registerProvider")) {
                // a provider built by hand: the generator's configuration fields it carries
                c.put("call", "registerProvider");
                scimProvider(c, args[0]);
            } else if (type.equals("org.mockserver.oidc.OidcAuthorizationStore") && method.equals("putCode")) {
                c.put("call", "putCode");
                c.put("code", (String) args[0]);
                for (String name : new String[]{"redirectUri", "codeChallenge", "codeChallengeMethod", "scope", "nonce"}) {
                    c.put(name, (String) Recorder.field(args[1], name));
                }
            } else if (type.equals("org.mockserver.oidc.OidcAuthorizationStore") && method.equals("putDeviceCode")) {
                c.put("call", "putDeviceCode");
                c.put("deviceCode", (String) args[0]);
                c.put("userCode", (String) Recorder.field(args[1], "userCode"));
                c.put("scope", (String) Recorder.field(args[1], "scope"));
                c.put("pendingPolls", String.valueOf(Recorder.field(args[1], "pendingPolls")));
            } else if (type.equals("org.mockserver.scim.ScimPatchApplier") && method.equals("apply")) {
                // reached on the wire as a PATCH of a seeded resource
                c.put("call", "scimPatch");
                c.set("resource", JSON.valueToTree(args[0]));
                c.set("patch", JSON.valueToTree(args[1]));
            } else if (type.equals("org.mockserver.scim.ScimFilter") && method.equals("parse")) {
                c.put("call", "scimFilter");
                c.put("filter", (String) args[0]);
            } else if (type.equals("org.mockserver.scim.ScimSort") && method.equals("parse")) {
                c.put("call", "scimSort");
                c.put("sortBy", (String) args[0]);
                c.put("sortOrder", (String) args[1]);
            } else if ((type.equals("org.mockserver.scim.ScimFilter") || type.equals("org.mockserver.scim.ScimSort")) && method.equals("apply")) {
                // the resources a parsed filter or sort is applied to: a list query over them seeded
                c.put("call", "scimApply");
                c.set("resources", JSON.valueToTree(args[0]));
            } else {
                c.put("call", "inProcess");
                c.put("method", simple(type) + "." + method);
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }

    /** A hand-built {@code ScimResourceStore.Provider}'s configuration fields, and how many resources it was seeded with. */
    private static void scimProvider(ObjectNode c, Object provider) throws ReflectiveOperationException {
        c.put("provider", "scim");
        ObjectNode config = c.putObject("configuration");
        config.put("basePath", (String) Recorder.field(provider, "basePath"));
        config.put("idStrategy", String.valueOf(Recorder.field(Recorder.field(provider, "users"), "idStrategy")));
        config.put("requireBearerToken", (Boolean) Recorder.field(provider, "requireBearerToken"));
        config.put("expectedBearerToken", (String) Recorder.field(provider, "expectedBearerToken"));
        config.put("enforceFilter", (Boolean) Recorder.field(provider, "enforceFilter"));
        config.put("enforcePatch", (Boolean) Recorder.field(provider, "enforcePatch"));
        c.put("seeded", ((java.util.Map<?, ?>) Recorder.field(Recorder.field(provider, "users"), "items")).size()
            + ((java.util.Map<?, ?>) Recorder.field(Recorder.field(provider, "groups"), "items")).size());
    }


    /** The configuration's fields whose values differ from a fresh instance's, by field name (the JSON property). */
    private static ObjectNode differences(Object configuration) throws ReflectiveOperationException {
        ObjectNode out = JSON.createObjectNode();
        if (configuration == null) {
            return null;
        }
        Object defaults = configuration.getClass().getDeclaredConstructor().newInstance();
        for (Field f : configuration.getClass().getDeclaredFields()) {
            if (Modifier.isStatic(f.getModifiers())) {
                continue;
            }
            f.setAccessible(true);
            Object value = f.get(configuration);
            if (!Objects.equals(value, f.get(defaults))) {
                out.set(f.getName(), JSON.valueToTree(value));
            }
        }
        return out;
    }

    private static String simple(String type) {
        return type.substring(type.lastIndexOf('.') + 1);
    }
}
