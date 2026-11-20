package harvest.advice;

import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import java.util.Base64;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

/**
 * Kind {@code grpcframe} (B4): {@code GrpcFrameCodec.decode(byte[], String, Configuration)}, which every
 * {@code decode}/{@code decodeSingle} overload ends in, each outermost call one line of grpcframe.jsonl with the
 * framed bytes, the {@code grpc-encoding} and the configured {@code maxGrpcMessageSize} (the instance's, or the static
 * store's without one). Replayed as the body of a native gRPC unary call on the greeting descriptor, with that
 * {@code grpc-encoding} header, on a server started with that limit.
 */
public class GrpcFrameAdvice implements Boundary {

    @Override
    public String[] preload() {
        return new String[]{"org.mockserver.grpc.GrpcFrameCodec"};
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(named("org.mockserver.grpc.GrpcFrameCodec"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(GrpcFrameAdvice.class)
                .on(named("decode").and(takesArguments(3)))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter("grpcframe");
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.AllArguments Object[] args, @Advice.Thrown Throwable thrown) {
        Recorder.exit("grpcframe");
        if (outermost) {
            GrpcFrameAdvice.record(args, thrown);
        }
    }

    public static void record(Object[] args, Throwable thrown) {
        ObjectNode c = Recorder.base("GrpcFrameCodec.decode");
        if (args[0] != null) {
            c.put("body", Base64.getEncoder().encodeToString((byte[]) args[0]));
        }
        if (args[1] != null) {
            c.put("encoding", (String) args[1]);
        }
        org.mockserver.configuration.Configuration configuration = (org.mockserver.configuration.Configuration) args[2];
        c.put("maxGrpcMessageSize", configuration != null ? configuration.maxGrpcMessageSize()
            : org.mockserver.configuration.ConfigurationProperties.maxGrpcMessageSize());
        Recorder.outcome(c, thrown);
        Recorder.write("grpcframe", c);
    }
}
