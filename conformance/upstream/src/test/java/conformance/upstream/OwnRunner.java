package conformance.upstream;

import org.junit.AssumptionViolatedException;
import org.junit.internal.builders.AllDefaultPossibilitiesBuilder;
import org.junit.runner.Description;
import org.junit.runner.Runner;
import org.junit.runner.manipulation.Filter;
import org.junit.runner.manipulation.Filterable;
import org.junit.runner.manipulation.NoTestsRemainException;
import org.junit.runner.notification.Failure;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.model.InitializationError;

import java.util.ArrayList;
import java.util.List;

/**
 * Runs one upstream test class that names its own runner ({@code @RunWith}, e.g. examples/java's
 * {@code SpringJUnit4ClassRunner}) with that runner, unmodified, instead of {@link UpstreamRunner}: its
 * {@link SkipList} entries are filtered out and reported as skipped, and the server processes it leaves running are
 * stopped after it, as {@link UpstreamRunner} does.
 */
final class OwnRunner extends Runner implements Filterable {

    private final Class<?> testClass;
    private final Runner delegate;
    private final SkipList skips;
    private final List<Description> skipped = new ArrayList<>();

    OwnRunner(Class<?> testClass) throws InitializationError {
        this.testClass = testClass;
        this.skips = new SkipList(testClass);
        try {
            this.delegate = new AllDefaultPossibilitiesBuilder().runnerForClass(testClass);
        } catch (Throwable t) {
            throw new InitializationError(t);
        }
        String methods = System.getProperty("methods", "");
        java.util.Set<String> wanted = methods.isBlank() ? null : java.util.Set.of(methods.split("\\s*,\\s*"));
        try {
            filter(new Filter() {
                @Override
                public boolean shouldRun(Description d) {
                    if (d.getMethodName() == null) {
                        return true;
                    }
                    if (wanted != null && !wanted.contains(d.getMethodName())) {
                        return false;
                    }
                    if (skips.reason(d.getMethodName()) != null) {
                        skipped.add(d);
                        return false;
                    }
                    return true;
                }

                @Override
                public String describe() {
                    return "skip lists";
                }
            });
        } catch (NoTestsRemainException e) {
            // every method skipped: reported in run
        }
    }

    @Override
    public Description getDescription() {
        Description description = delegate.getDescription().childlessCopy();
        delegate.getDescription().getChildren().forEach(description::addChild);
        skipped.forEach(description::addChild);
        return description;
    }

    @Override
    public void filter(Filter filter) throws NoTestsRemainException {
        if (delegate instanceof Filterable) {
            ((Filterable) delegate).filter(filter);
        }
    }

    @Override
    public void run(RunNotifier notifier) {
        for (Description d : skipped) {
            notifier.fireTestStarted(d);
            notifier.fireTestAssumptionFailed(new Failure(d, new AssumptionViolatedException(skips.reason(d.getMethodName()))));
            notifier.fireTestFinished(d);
        }
        if (skipped.size() == delegate.testCount() + skipped.size() && delegate.testCount() == 0) {
            return;
        }
        ServerProcess.owner(testClass.getSimpleName());
        try {
            delegate.run(notifier);
        } finally {
            ServerProcess.stopAll();
        }
    }
}
