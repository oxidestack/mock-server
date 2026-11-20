package conformance;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockserver.client.MockServerClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Expectations preloaded from a JSON file via MOCKSERVER_INITIALIZATION_JSON_PATH. */
class InitializationTest {

    static Stream<DockerImageName> images() {
        return Stream.of(Images.ORACLE, Images.MOCK_SERVER);
    }

    @ParameterizedTest
    @MethodSource("images")
    void loadsExpectationsFromFile(DockerImageName image) throws Exception {
        try (GenericContainer<?> c = new GenericContainer<>(image)
            .withCopyFileToContainer(MountableFile.forClasspathResource("initializerJson.json", 0644), "/config/initializerJson.json")
            .withEnv("MOCKSERVER_INITIALIZATION_JSON_PATH", "/config/initializerJson.json")
            .withExposedPorts(1080)
            .waitingFor(Wait.forHttp("/mockserver/status").withMethod("PUT").forStatusCode(200))) {
            c.start();
            var response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://" + c.getHost() + ":" + c.getMappedPort(1080) + "/preloaded")).build(),
                HttpResponse.BodyHandlers.ofString());
            assertEquals("from file", response.body());
            try (MockServerClient client = new MockServerClient(c.getHost(), c.getMappedPort(1080))) {
                assertEquals(2, client.retrieveActiveExpectations(null).length);
            }
        }
    }
}
