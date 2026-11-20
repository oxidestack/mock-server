package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import java.lang.reflect.Field;
import java.util.Base64;
import java.util.List;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code grpcfeed} (B4): {@code IncrementalGrpcFrameDecoder.feed(byte[])}, one line of grpcfeed.jsonl
 * per call with the chunk, the decoder it was fed to (identity hash, its buffer cap and the {@code maxGrpcMessageSize}
 * it reads: its configuration's, or the static store's without one) and the outcome. Grouped per decoder and replayed
 * as one bidi-streaming call whose DATA frames are the chunks in order: {@code GrpcBidiStreamHandler} feeds each DATA
 * frame of a stream to one such decoder.
 */
public class GrpcFeedAdvice implements Boundary {

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.grpc.IncrementalGrpcFrameDecoder"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.grpc.IncrementalGrpcFrameDecoder"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(GrpcFeedAdvice.class)
                .on(named("feed").and(takesArguments(1)))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter("grpcfeed");
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.This Object self, @Advice.AllArguments Object[] args,
                            @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result, @Advice.Thrown Throwable thrown) {
        Recorder.exit("grpcfeed");
        if (outermost) {
            GrpcFeedAdvice.record(self, args, result, thrown);
        }
    }

    public static void record(Object self, Object[] args, Object result, Throwable thrown) {
        ObjectNode c = Recorder.base("IncrementalGrpcFrameDecoder.feed");
        c.put("decoder", System.identityHashCode(self));
        if (args[0] != null) {
            c.put("chunk", Base64.getEncoder().encodeToString((byte[]) args[0]));
        }
        c.put("maxBufferSize", (Integer) field(self, "maxBufferSize"));
        org.mockserver.configuration.Configuration configuration = (org.mockserver.configuration.Configuration) field(self, "configuration");
        c.put("maxGrpcMessageSize", configuration != null ? configuration.maxGrpcMessageSize()
            : org.mockserver.configuration.ConfigurationProperties.maxGrpcMessageSize());
        if (result instanceof List) {
            c.put("messages", ((List<?>) result).size());
        }
        Recorder.outcome(c, thrown);
        Recorder.write("grpcfeed", c);
    }

    private static Object field(Object self, String name) {
        try {
            Field f = self.getClass().getDeclaredField(name);
            f.setAccessible(true);
            return f.get(self);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }
}
