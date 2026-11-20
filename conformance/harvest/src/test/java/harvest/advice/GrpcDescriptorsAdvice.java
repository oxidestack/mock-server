package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import java.util.Base64;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code grpcdescriptors} (B4): {@code GrpcProtoDescriptorStore.loadDescriptorSet(byte[])} and
 * {@code loadDescriptorSetFromPath(Path)}, each outermost call one line of grpcdescriptors.jsonl with the descriptor set
 * the store already held (rebuilt as in {@link GrpcReflectAdvice#descriptorSet}) and the bytes it loaded (the file's
 * bytes for a path; absent when the file cannot be read). Replayed as the earlier set and the new one sent to
 * {@code PUT /mockserver/grpc/descriptors}, then {@code PUT /mockserver/grpc/services}.
 */
public class GrpcDescriptorsAdvice implements Boundary {

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.grpc.GrpcProtoDescriptorStore"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.grpc.GrpcProtoDescriptorStore"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(GrpcDescriptorsAdvice.class)
                .on(namedOneOf("loadDescriptorSet", "loadDescriptorSetFromPath").and(takesArguments(1)))));
    }

    /** The store's descriptor set before the load for the outermost call, null for a nested one. */
    @Advice.OnMethodEnter
    public static String enter(@Advice.This Object self) {
        return GrpcDescriptorsAdvice.before(self);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter String before, @Advice.Origin("#m") String method, @Advice.Argument(0) Object input,
                            @Advice.Thrown Throwable thrown) {
        Recorder.exit("grpcdescriptors");
        if (before != null) {
            GrpcDescriptorsAdvice.record(before, method, input, thrown);
        }
    }

    public static String before(Object self) {
        if (!Recorder.enter("grpcdescriptors")) {
            return null;
        }
        try {
            return GrpcReflectAdvice.descriptorSet(self);
        } catch (Throwable e) {
            return "unserialisable: " + e;
        }
    }

    public static void record(String before, String method, Object input, Throwable thrown) {
        ObjectNode c = Recorder.base("GrpcProtoDescriptorStore." + method);
        c.put("before", before);
        try {
            byte[] bytes = input instanceof byte[] ? (byte[]) input
                : input instanceof java.nio.file.Path ? java.nio.file.Files.readAllBytes((java.nio.file.Path) input) : null;
            if (bytes != null) {
                c.put("body", Base64.getEncoder().encodeToString(bytes));
            }
        } catch (Throwable e) {
            c.put("unreadable", String.valueOf(input));
        }
        if (input instanceof java.nio.file.Path) {
            c.put("path", String.valueOf(input));
        }
        Recorder.outcome(c, thrown);
        Recorder.write("grpcdescriptors", c);
    }
}
