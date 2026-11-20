package conformance;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.testcontainers.utility.DockerImageName;

/** The two servers every suite runs against. */
final class Images {
    /** The oracle pinned in the repository's {@code oracle.env}; Maven runs the suite from conformance/java. */
    static final DockerImageName ORACLE = DockerImageName.parse(oraclePin("ORACLE_IMAGE")).asCompatibleSubstituteFor("mockserver/mockserver");
    static final DockerImageName MOCK_SERVER =
        DockerImageName.parse(System.getProperty("mockServerImage", "mock-server:latest"))
            .asCompatibleSubstituteFor("mockserver/mockserver");

    private Images() {
    }

    private static String oraclePin(String key) {
        try {
            return Files.readAllLines(Path.of("../../oracle.env")).stream()
                .filter(line -> line.startsWith(key + "="))
                .map(line -> line.substring(key.length() + 1))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("oracle.env has no " + key));
        } catch (IOException e) {
            throw new IllegalStateException("reading oracle.env", e);
        }
    }
}
