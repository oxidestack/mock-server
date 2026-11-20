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
 * Kind {@code grpcsynth} (B4): {@code GrpcExampleSynthesizer.synthesizeJson(Descriptor, converter)}, each
 * outermost call one line of grpcsynth.jsonl with the message's full name and a descriptor set of its file (and the
 * files it imports) in which that file also declares {@code service HarvestSynth { rpc Get(<message>) returns
 * (<message>); }}. On the wire the synthesizer answers a matched gRPC expectation without a body, so this is replayed
 * as that descriptor set, an expectation on {@code /<package.>HarvestSynth/Get} with an empty response, and the call.
 */
public class GrpcSynthAdvice implements Boundary {

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.grpc.GrpcExampleSynthesizer"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.grpc.GrpcExampleSynthesizer"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(GrpcSynthAdvice.class)
                .on(named("synthesizeJson").and(takesArguments(2)))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter("grpcsynth");
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.Argument(0) Object descriptor, @Advice.Thrown Throwable thrown) {
        Recorder.exit("grpcsynth");
        if (outermost) {
            GrpcSynthAdvice.record(descriptor, thrown);
        }
    }

    public static void record(Object descriptor, Throwable thrown) {
        ObjectNode c = Recorder.base("GrpcExampleSynthesizer.synthesizeJson");
        if (descriptor != null) {
            try {
                com.google.protobuf.Descriptors.Descriptor message = (com.google.protobuf.Descriptors.Descriptor) descriptor;
                com.google.protobuf.Descriptors.FileDescriptor file = message.getFile();
                c.put("message", message.getFullName());
                c.put("package", file.getPackage());
                Map<String, com.google.protobuf.DescriptorProtos.FileDescriptorProto> ordered = new LinkedHashMap<>();
                add(file, ordered);
                String type = "." + message.getFullName();
                com.google.protobuf.DescriptorProtos.FileDescriptorProto own = ordered.get(file.getName()).toBuilder()
                    .addService(com.google.protobuf.DescriptorProtos.ServiceDescriptorProto.newBuilder()
                        .setName("HarvestSynth")
                        .addMethod(com.google.protobuf.DescriptorProtos.MethodDescriptorProto.newBuilder()
                            .setName("Get").setInputType(type).setOutputType(type)))
                    .build();
                ordered.put(file.getName(), own);
                com.google.protobuf.DescriptorProtos.FileDescriptorSet.Builder set = com.google.protobuf.DescriptorProtos.FileDescriptorSet.newBuilder();
                ordered.values().forEach(set::addFile);
                c.put("descriptorSet", Base64.getEncoder().encodeToString(set.build().toByteArray()));
            } catch (Throwable e) {
                c.put("unserialisable", String.valueOf(e));
            }
        }
        Recorder.outcome(c, thrown);
        Recorder.write("grpcsynth", c);
    }

    private static void add(com.google.protobuf.Descriptors.FileDescriptor file,
                            Map<String, com.google.protobuf.DescriptorProtos.FileDescriptorProto> ordered) {
        if (ordered.containsKey(file.getName())) {
            return;
        }
        for (com.google.protobuf.Descriptors.FileDescriptor dependency : file.getDependencies()) {
            add(dependency, ordered);
        }
        ordered.put(file.getName(), file.toProto());
    }
}
