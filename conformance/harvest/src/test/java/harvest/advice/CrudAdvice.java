package harvest.advice;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import org.mockserver.logging.MockServerLogger;

import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.isPublic;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;

/**
 * Kind {@code crud} (B4): the CRUD data store, its action handler and dispatcher, under one depth key,
 * outermost call only, in order, one line of crud.jsonl each:
 * <ul>
 *   <li>{@code new CrudDataStore(…)}: the store's identity, id field and strategy, item cap and items after
 *   construction (the initial data it kept);</li>
 *   <li>{@code new CrudActionHandler(store, basePath)}: the handler's identity, its store's and its base path;</li>
 *   <li>the handler's {@code handle*(request)}: the request and the response;</li>
 *   <li>the store's {@code getAll/getById/create/update/patch/delete/clear/size} called directly: the arguments and,
 *   for {@code create}, the created item;</li>
 *   <li>{@code CrudDispatcher.register/unregister/dispatch/reset}.</li>
 * </ul>
 * Each line carries the calling thread (the concurrency tests call from a pool).
 */
public class CrudAdvice implements Boundary {

    private static final String KEY = "crud";
    private static final ObjectMapper JSON = new ObjectMapper();

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.mock.crud.CrudDataStore", "org.mockserver.mock.crud.CrudActionHandler",
            "org.mockserver.mock.crud.CrudDispatcher"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(namedOneOf("org.mockserver.mock.crud.CrudDataStore", "org.mockserver.mock.crud.CrudActionHandler"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ConstructAdvice.class)
                .on(isConstructor())))
            .type(named("org.mockserver.mock.crud.CrudActionHandler"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(CallAdvice.class)
                .on(nameStartsWith("handle").and(isPublic()))))
            .type(named("org.mockserver.mock.crud.CrudDataStore"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(CallAdvice.class)
                .on(namedOneOf("getAll", "getById", "create", "update", "patch", "delete", "clear", "size"))))
            .type(named("org.mockserver.mock.crud.CrudDispatcher"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(CallAdvice.class)
                .on(namedOneOf("register", "unregister", "dispatch", "reset"))));
    }

    public static class ConstructAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter(KEY);
        }

        @Advice.OnMethodExit
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self) {
            if (outermost) {
                CrudAdvice.constructed(self);
            }
            Recorder.exit(KEY);
        }
    }

    public static class CallAdvice {
        @Advice.OnMethodEnter
        public static boolean enter() {
            return Recorder.enter(KEY);
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.Origin("#m") String method,
                                @Advice.AllArguments Object[] args, @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result,
                                @Advice.Thrown Throwable thrown) {
            if (outermost) {
                CrudAdvice.called(self, method, args, result, thrown);
            }
            Recorder.exit(KEY);
        }
    }

    private static ObjectNode base(String boundary) {
        ObjectNode c = Recorder.base(boundary);
        c.put("thread", Thread.currentThread().getName());
        return c;
    }

    public static void constructed(Object self) {
        String type = self.getClass().getSimpleName();
        ObjectNode c = base(type + ".<init>");
        Recorder.enter("jackson");
        try {
            if (self instanceof org.mockserver.mock.crud.CrudDataStore) {
                org.mockserver.mock.crud.CrudDataStore store = (org.mockserver.mock.crud.CrudDataStore) self;
                c.put("call", "newStore");
                c.put("store", System.identityHashCode(store));
                c.put("idField", store.getIdField());
                c.put("idStrategy", String.valueOf(store.getIdStrategy()));
                c.put("maxItems", store.getMaxItems());
                ArrayNode items = c.putArray("items");
                store.getAll().forEach(items::add);
            } else {
                c.put("call", "newHandler");
                c.put("handler", System.identityHashCode(self));
                c.put("store", System.identityHashCode(Recorder.field(self, "store")));
                c.put("basePath", (String) Recorder.field(self, "basePath"));
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.write(KEY, c);
    }

    public static void called(Object self, String method, Object[] args, Object result, Throwable thrown) {
        String type = self.getClass().getSimpleName();
        ObjectNode c = base(type + "." + method);
        Recorder.enter("jackson");
        try {
            MockServerLogger logger = new MockServerLogger();
            c.put("method", method);
            if (self instanceof org.mockserver.mock.crud.CrudActionHandler) {
                c.put("call", "handle");
                c.put("handler", System.identityHashCode(self));
                c.put("request", new org.mockserver.serialization.HttpRequestSerializer(logger).serialize((org.mockserver.model.HttpRequest) args[0]));
                if (result != null) {
                    c.put("response", new org.mockserver.serialization.HttpResponseSerializer(logger).serialize((org.mockserver.model.HttpResponse) result));
                }
            } else if (self instanceof org.mockserver.mock.crud.CrudDataStore) {
                c.put("call", "store");
                c.put("store", System.identityHashCode(self));
                ArrayNode values = c.putArray("args");
                for (Object arg : args) {
                    if (arg instanceof com.fasterxml.jackson.databind.JsonNode) {
                        values.add((com.fasterxml.jackson.databind.JsonNode) arg);
                    } else if (arg == null) {
                        values.addNull();
                    } else {
                        values.add(String.valueOf(arg));
                    }
                }
                if (result instanceof com.fasterxml.jackson.databind.JsonNode) {
                    c.set("result", (com.fasterxml.jackson.databind.JsonNode) result);
                }
            } else {
                c.put("call", "dispatcher");
                c.put("dispatcher", System.identityHashCode(self));
                if (method.equals("register")) {
                    c.put("basePath", (String) args[0]);
                    c.put("handler", System.identityHashCode(args[1]));
                } else if (method.equals("unregister")) {
                    c.put("basePath", (String) args[0]);
                } else if (method.equals("dispatch")) {
                    c.put("request", new org.mockserver.serialization.HttpRequestSerializer(logger).serialize((org.mockserver.model.HttpRequest) args[0]));
                    if (result != null) {
                        c.put("response", new org.mockserver.serialization.HttpResponseSerializer(logger).serialize((org.mockserver.model.HttpResponse) result));
                    }
                }
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        } finally {
            Recorder.exit("jackson");
        }
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }
}
