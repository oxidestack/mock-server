package harvest.advice;

import net.bytebuddy.agent.builder.AgentBuilder;

/**
 * One harvested boundary (a kind), in a class of its own in this package: {@code harvest.Recorder} finds every
 * concrete {@code Boundary} here by its class file and lets it add its advice, so that a new kind edits no shared list
 * (a kind is found by its class name). The advice classes stay static nested or top-level classes whose methods call the
 * recorder's public helpers ({@code Recorder.enter/exit/base/outcome/write/field}); name the class {@code <Kind>Advice}.
 */
public interface Boundary {

    /** Classes to load before the agent is installed (a class first loaded during another's retransformation is never
     * transformed). */
    default String[] preload() {
        return new String[0];
    }

    /** {@code agent} with this boundary's {@code .type(…).transform(…)} added. */
    AgentBuilder install(AgentBuilder agent);
}
