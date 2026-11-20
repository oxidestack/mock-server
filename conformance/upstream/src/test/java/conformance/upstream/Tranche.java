package conformance.upstream;

import org.junit.runner.Runner;
import org.junit.runners.Suite;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.RunnerBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A tranche of the inventory (§7): the upstream test classes listed, one fully qualified name per line, in
 * {@code tranches/<name>.txt}, each run by {@link UpstreamRunner} (or, when it names its own, by {@link OwnRunner}). {@code -Dclasses=A,B} (simple names) narrows a
 * run to those classes.
 */
public final class Tranche extends Suite {

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.TYPE)
    public @interface Name {
        String value();
    }

    public Tranche(Class<?> suite, RunnerBuilder builder) throws InitializationError {
        super(suite, runners(suite));
    }

    private static List<Runner> runners(Class<?> suite) throws InitializationError {
        Name name = suite.getAnnotation(Name.class);
        if (name == null) {
            throw new InitializationError(suite.getName() + " needs @Tranche.Name");
        }
        String only = System.getProperty("classes", "");
        Set<String> selected = only.isBlank() ? null : new HashSet<>(Arrays.asList(only.split("\\s*,\\s*")));
        List<Runner> runners = new ArrayList<>();
        for (String className : classNames("tranches/" + name.value() + ".txt")) {
            String simpleName = className.substring(className.lastIndexOf('.') + 1);
            if (selected != null && !selected.contains(simpleName)) {
                continue;
            }
            try {
                Class<?> testClass = Class.forName(className);
                // a class with its own runner (examples/java's Spring ones) keeps it
                runners.add(testClass.isAnnotationPresent(org.junit.runner.RunWith.class) ? new OwnRunner(testClass) : new UpstreamRunner(testClass));
            } catch (ClassNotFoundException e) {
                throw new InitializationError(e);
            }
        }
        return runners;
    }

    private static List<String> classNames(String resource) throws InitializationError {
        try (InputStream in = Tranche.class.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) {
                throw new InitializationError("missing " + resource);
            }
            List<String> names = new ArrayList<>();
            for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                String trimmed = line.replaceAll("#.*", "").trim();
                if (!trimmed.isEmpty()) {
                    names.add(trimmed);
                }
            }
            return names;
        } catch (IOException e) {
            throw new InitializationError(e);
        }
    }
}
