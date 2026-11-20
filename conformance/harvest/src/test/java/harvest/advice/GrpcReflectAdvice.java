package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code grpcreflect} (B4): {@code GrpcServerReflectionHandler.handleReflectionRequest(byte[])}, each
 * outermost call one line of grpcreflect.jsonl with the gRPC-framed request body (base64, absent for null) and the
 * descriptor set its store held, rebuilt from the store's file descriptors (dependencies first). Replayed as
 * {@code PUT /mockserver/grpc/descriptors} plus the native gRPC reflection call over h2c.
 */
public class GrpcReflectAdvice implements Boundary {

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.grpc.GrpcServerReflectionHandler"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.grpc.GrpcServerReflectionHandler"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(GrpcReflectAdvice.class)
                .on(named("handleReflectionRequest").and(takesArguments(byte[].class)))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter("grpcreflect");
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.Argument(0) byte[] body,
                            @Advice.Thrown Throwable thrown) {
        Recorder.exit("grpcreflect");
        if (outermost) {
            GrpcReflectAdvice.record(self, body, thrown);
        }
    }

    public static void record(Object self, byte[] body, Throwable thrown) {
        ObjectNode c = Recorder.base("GrpcServerReflectionHandler.handleReflectionRequest");
        try {
            c.put("descriptorSet", descriptorSet(Recorder.field(self, "descriptorStore")));
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        }
        if (body != null) {
            c.put("body", Base64.getEncoder().encodeToString(body));
        }
        Recorder.outcome(c, thrown);
        Recorder.write("grpcreflect", c);
    }

    /**
     * The FileDescriptorSet a {@code GrpcProtoDescriptorStore} holds, base64, each file after its dependencies (the
     * order {@code PUT /mockserver/grpc/descriptors} resolves them in); an empty string for an empty store. Shared by
     * the other grpc kinds.
     */
    public static String descriptorSet(Object store) throws ReflectiveOperationException {
        if (store == null) {
            return "";
        }
        @SuppressWarnings("unchecked")
        Map<String, com.google.protobuf.Descriptors.FileDescriptor> files =
            (Map<String, com.google.protobuf.Descriptors.FileDescriptor>) Recorder.field(store, "fileDescriptors");
        Map<String, com.google.protobuf.DescriptorProtos.FileDescriptorProto> ordered = new LinkedHashMap<>();
        for (com.google.protobuf.Descriptors.FileDescriptor file : new java.util.TreeMap<>(files).values()) {
            add(file, files, ordered);
        }
        if (ordered.isEmpty()) {
            return "";
        }
        com.google.protobuf.DescriptorProtos.FileDescriptorSet.Builder set = com.google.protobuf.DescriptorProtos.FileDescriptorSet.newBuilder();
        ordered.values().forEach(set::addFile);
        return Base64.getEncoder().encodeToString(set.build().toByteArray());
    }

    private static void add(com.google.protobuf.Descriptors.FileDescriptor file,
                            Map<String, com.google.protobuf.Descriptors.FileDescriptor> files,
                            Map<String, com.google.protobuf.DescriptorProtos.FileDescriptorProto> ordered) {
        if (ordered.containsKey(file.getName()) || !files.containsKey(file.getName())) {
            return;
        }
        for (com.google.protobuf.Descriptors.FileDescriptor dependency : file.getDependencies()) {
            add(dependency, files, ordered);
        }
        ordered.put(file.getName(), file.toProto());
    }
}
