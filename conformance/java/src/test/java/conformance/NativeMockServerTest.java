package conformance;

import org.junit.jupiter.api.BeforeAll;
import org.testcontainers.mockserver.MockServerContainer;

/** The same suite against mock-server. */
class NativeMockServerTest extends MockingSuite {
    @BeforeAll
    static void startNativeMockServer() {
        start(new MockServerContainer(Images.MOCK_SERVER));
    }
}
