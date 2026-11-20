package conformance;

import org.junit.jupiter.api.BeforeAll;
import org.testcontainers.mockserver.MockServerContainer;

/** The suite against real MockServer 9.2.0: proves the tests encode MockServer's behaviour. */
class OracleTest extends MockingSuite {
    @BeforeAll
    static void startOracle() {
        start(new MockServerContainer(Images.ORACLE));
    }
}
