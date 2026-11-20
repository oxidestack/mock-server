package conformance.upstream;

import org.junit.AssumptionViolatedException;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Skips listed upstream tests, reported as skipped with their reason. Two lists per test class, one line per
 * method ({@code methodName  # reason}):
 * <ul>
 *   <li>{@code skips/in-jvm/<Class>.txt}: fails on the oracle as a separate process too (needs the test JVM);
 *       applies to every process target;</li>
 *   <li>{@code skips/not-applicable/<Class>.txt}: cannot run unmodified against mock-server's process; the
 *       reason names the Rust port that checks the same behaviour ({@code tests/upstream/<file>.rs::<fn>}).
 *       Applies to rs-process, where it takes precedence over an {@code in-jvm} entry for the same method;</li>
 *   <li>{@code skips/rs/<Class>.txt}: not yet passing on mock-server; the reason says what is missing.</li>
 * </ul>
 * A line {@code *  # reason} skips every method of the class. The lists are read from {@code -DskipsDir}
 * (the source tree), so a deleted skip file never survives as a stale copy under {@code target/}.
 * {@code -DrunSkipped=in-jvm} (or {@code not-applicable}, {@code rs}) ignores a list, to confirm that its entries still fail.
 */
public final class SkipList implements TestRule {

    private final Map<String, String> skips = new HashMap<>();

    public SkipList(Class<?> testClass) {
        String target = TargetServer.target();
        if (!target.equals("oracle-jvm")) {
            load("in-jvm/" + testClass.getSimpleName() + ".txt", "in-JVM");
        }
        if (target.equals("rs-process")) {
            load("not-applicable/" + testClass.getSimpleName() + ".txt", "not-applicable");
            load("rs/" + testClass.getSimpleName() + ".txt", "mock-server");
        }
    }

    /** The reason {@code method} is skipped, or null. */
    public String reason(String method) {
        String reason = skips.get(method);
        return reason != null ? reason : skips.get("*");
    }

    private void load(String name, String kind) {
        // -DrunSkipped=in-jvm (or rs) runs a list's tests anyway, to confirm they still fail
        if (System.getProperty("runSkipped", "").contains(name.substring(0, name.indexOf('/')))) {
            return;
        }
        File file = new File(System.getProperty("skipsDir", "src/test/resources/skips"), name);
        if (!file.isFile()) {
            return;
        }
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                String[] parts = trimmed.split("#", 2);
                skips.put(parts[0].trim(), kind + ": " + (parts.length > 1 ? parts[1].trim() : "no reason given"));
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public Statement apply(Statement base, Description description) {
        String reason = reason(description.getMethodName());
        if (reason == null) {
            return base;
        }
        return new Statement() {
            @Override
            public void evaluate() {
                throw new AssumptionViolatedException(reason);
            }
        };
    }
}
