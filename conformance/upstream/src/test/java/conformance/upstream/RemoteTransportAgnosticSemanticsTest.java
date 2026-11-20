package conformance.upstream;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.mockserver.testing.integration.mock.AbstractTransportAgnosticSemanticsIntegrationTest;

/** Upstream's {@code AbstractTransportAgnosticSemanticsIntegrationTest}, unmodified, against the target server. */
public class RemoteTransportAgnosticSemanticsTest extends AbstractTransportAgnosticSemanticsIntegrationTest {

    @ClassRule
    public static final TargetServer target = TargetServer.forClass(RemoteTransportAgnosticSemanticsTest.class);

    @Rule
    public final SkipList skips = new SkipList(RemoteTransportAgnosticSemanticsTest.class);

    @BeforeClass
    public static void connect() {
        mockServerClient = target.client();
    }

    @Override
    public int getServerPort() {
        return target.port();
    }
}
