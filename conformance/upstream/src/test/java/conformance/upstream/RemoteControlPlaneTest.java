package conformance.upstream;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.mockserver.testing.integration.mock.AbstractControlPlaneIntegrationTest;

/** Upstream's {@code AbstractControlPlaneIntegrationTest}, unmodified, against the target server. */
public class RemoteControlPlaneTest extends AbstractControlPlaneIntegrationTest {

    @ClassRule
    public static final TargetServer target = TargetServer.forClass(RemoteControlPlaneTest.class);

    @Rule
    public final SkipList skips = new SkipList(RemoteControlPlaneTest.class);

    @BeforeClass
    public static void connect() {
        mockServerClient = target.client();
    }

    @Override
    public int getServerPort() {
        return target.port();
    }
}
