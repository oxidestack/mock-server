package conformance.upstream;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.mockserver.testing.integration.mock.AbstractPackagingSmokeTest;

/** Upstream's {@code AbstractPackagingSmokeTest}, unmodified, against the target server. */
public class RemotePackagingSmokeTest extends AbstractPackagingSmokeTest {

    @ClassRule
    public static final TargetServer target = TargetServer.forClass(RemotePackagingSmokeTest.class);

    @Rule
    public final SkipList skips = new SkipList(RemotePackagingSmokeTest.class);

    @BeforeClass
    public static void connect() {
        mockServerClient = target.client();
    }

    /** Same decision as upstream's packaging subclasses. */
    @Override
    protected boolean supportsHTTP2() {
        return io.netty.handler.ssl.SslProvider.isAlpnSupported(io.netty.handler.ssl.SslContext.defaultServerProvider())
            || io.netty.handler.ssl.SslProvider.isAlpnSupported(io.netty.handler.ssl.SslProvider.JDK)
            || io.netty.handler.ssl.SslProvider.isAlpnSupported(io.netty.handler.ssl.SslProvider.OPENSSL);
    }

    @Override
    public int getServerPort() {
        return target.port();
    }
}
