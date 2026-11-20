package conformance.upstream;

import org.junit.AssumptionViolatedException;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.Statement;
import org.junit.runner.notification.RunNotifier;

/**
 * Runs one upstream test class, unmodified, against the target: upstream's {@code new MockServer(...)} and
 * {@code ClientAndServer} resolve to the process-backed stand-ins in this module, the class's {@link SkipList}
 * entries are reported as skipped, and whatever server processes the class leaves running are stopped after it.
 */
public final class UpstreamRunner extends BlockJUnit4ClassRunner {

    private final SkipList skips;

    public UpstreamRunner(Class<?> testClass) throws InitializationError {
        super(testClass);
        this.skips = new SkipList(testClass);
        // -Dmethods=a,b runs only those test methods (for investigating one failure)
        String methods = System.getProperty("methods", "");
        if (!methods.isBlank()) {
            java.util.Set<String> wanted = java.util.Set.of(methods.split("\\s*,\\s*"));
            try {
                filter(new org.junit.runner.manipulation.Filter() {
                    @Override
                    public boolean shouldRun(org.junit.runner.Description d) {
                        return d.getMethodName() == null || wanted.contains(d.getMethodName());
                    }

                    @Override
                    public String describe() {
                        return "methods " + methods;
                    }
                });
            } catch (org.junit.runner.manipulation.NoTestsRemainException e) {
                throw new InitializationError("no method of " + testClass.getName() + " in -Dmethods=" + methods);
            }
        }
    }

    @Override
    public void run(RunNotifier notifier) {
        ServerProcess.owner(getTestClass().getJavaClass().getSimpleName());
        try {
            super.run(notifier);
        } finally {
            ServerProcess.stopAll();
        }
    }

    @Override
    protected Statement classBlock(RunNotifier notifier) {
        if (skips.reason("*") != null) {
            // the whole class is skipped: do not start its servers at all
            return childrenInvoker(notifier);
        }
        return super.classBlock(notifier);
    }

    @Override
    protected Statement methodBlock(FrameworkMethod method) {
        String reason = skips.reason(method.getName());
        if (reason != null) {
            return new Statement() {
                @Override
                public void evaluate() {
                    throw new AssumptionViolatedException(reason);
                }
            };
        }
        return super.methodBlock(method);
    }
}
