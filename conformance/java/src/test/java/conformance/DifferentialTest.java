package conformance;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockserver.client.MockServerClient;
import org.mockserver.verify.VerificationTimes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

/**
 * Both servers side by side, started the way MockServer's own Testcontainers module does it (env
 * SERVER_PORT, readiness = PUT /mockserver/status), comparing the text users see in AssertionErrors.
 */
class DifferentialTest {

    static GenericContainer<?> oracle;
    static GenericContainer<?> rs;

    static GenericContainer<?> start(org.testcontainers.utility.DockerImageName image) {
        GenericContainer<?> c = new GenericContainer<>(image)
            .withEnv("SERVER_PORT", "1080")
            .withExposedPorts(1080)
            .waitingFor(Wait.forHttp("/mockserver/status").withMethod("PUT").forStatusCode(200));
        c.start();
        return c;
    }

    @BeforeAll
    static void startBoth() {
        oracle = start(Images.ORACLE);
        rs = start(Images.MOCK_SERVER);
    }

    @AfterAll
    static void stopBoth() {
        oracle.stop();
        rs.stop();
    }

    static String onBoth(Function<MockServerClient, String> scenario, GenericContainer<?> c) {
        try (MockServerClient client = new MockServerClient(c.getHost(), c.getMappedPort(1080))) {
            client.reset();
            return scenario.apply(client).replaceAll("(?i)\"host\" : \\[ \"[^\"]+\" \\]", "\"host\" : [ \"<host>\" ]");
        }
    }

    static String verificationFailure(MockServerClient client) {
        client.when(request().withPath("/x")).respond(response().withBody("x"));
        try {
            new java.net.URL("http://" + client.remoteAddress().getHostString() + ":" + client.getPort() + "/x").openStream().close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        try {
            client.verify(request().withPath("/missing"), VerificationTimes.exactly(1));
            return "passed";
        } catch (AssertionError e) {
            return e.getMessage();
        }
    }

    @Test
    void verificationFailureMessagesAreIdentical() {
        assertEquals(onBoth(DifferentialTest::verificationFailure, oracle), onBoth(DifferentialTest::verificationFailure, rs));
    }
}
