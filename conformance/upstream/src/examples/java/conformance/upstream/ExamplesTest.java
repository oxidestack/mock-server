package conformance.upstream;

import org.junit.runner.RunWith;

/**
 * Tranche {@code examples}: upstream's examples/java classes in {@code tranches/examples.txt} (counted with T5,
 * inventory §7). Compiled only under the {@code examples} Maven profile, which carries their dependencies.
 */
@RunWith(Tranche.class)
@Tranche.Name("examples")
public class ExamplesTest {
}
