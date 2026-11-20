import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * Differential vectors for Jackson's syntax-error wording: each input of
 * `tests/files/jackson-syntax/inputs.txt` (`<name> <hex bytes>` per line) read the two ways MockServer reads a JSON file
 * whose failure text it prints:
 * <ul>
 *   <li>`map`: `ObjectMapperFactory.createObjectMapper().readValue(InputStream, Map.class)`, as
 *   `ConfigurationProperties.readJsonPropertyFile` reads a JSON property file (`UTF8StreamJsonParser`); the exception's
 *   `toString()`, or null when the input reads;</li>
 *   <li>`tree`: `JsonArraySerializer.splitJSONArrayToJSONNodes(new String(bytes, UTF_8))`, as `mockserver import`
 *   (`MockServerClient.importExpectations`) reads the file (`ReaderBasedJsonParser`); the `IllegalArgumentException`'s
 *   message, or null when the input reads.</li>
 * </ul>
 * Compile it against the oracle image's jars and run it inside the image, with the inputs and the output path as
 * arguments:
 * <pre>
 * docker create --name jars $ORACLE_IMAGE; docker cp jars:/mockserver.jar .; docker cp jars:/mockserver-deps.jar .; docker rm jars
 * javac --release 21 -cp mockserver.jar:mockserver-deps.jar -d out JacksonSyntaxVectors.java
 * docker run --rm -v $PWD/out:/probe:ro -v $REPO/tests/files/jackson-syntax:/v --entrypoint /usr/lib/jvm/temurin25-trimmed/bin/java \
 *   $ORACLE_IMAGE -cp /probe:/mockserver.jar:/mockserver-deps.jar JacksonSyntaxVectors /v/inputs.txt /v/vectors.json
 * </pre>
 */
public class JacksonSyntaxVectors {
    public static void main(String[] args) throws Exception {
        Object mapper = Class.forName("org.mockserver.serialization.ObjectMapperFactory").getMethod("createObjectMapper").invoke(null);
        Object splitter = Class.forName("org.mockserver.serialization.JsonArraySerializer").getConstructor().newInstance();
        StringBuilder out = new StringBuilder("[");
        String sep = "\n ";
        for (String line : Files.readAllLines(Paths.get(args[0]), StandardCharsets.UTF_8)) {
            if (line.isBlank()) continue;
            String[] parts = line.split(" ", 2);
            byte[] bytes = unhex(parts.length > 1 ? parts[1] : "");
            String map;
            try {
                mapper.getClass().getMethod("readValue", InputStream.class, Class.class).invoke(mapper, new ByteArrayInputStream(bytes), Map.class);
                map = null;
            } catch (java.lang.reflect.InvocationTargetException e) {
                map = e.getCause().toString();
            }
            String tree;
            try {
                splitter.getClass().getMethod("splitJSONArrayToJSONNodes", String.class).invoke(splitter, new String(bytes, StandardCharsets.UTF_8));
                tree = null;
            } catch (java.lang.reflect.InvocationTargetException e) {
                tree = e.getCause().getMessage();
            }
            out.append(sep).append("{\"name\": ").append(quote(parts[0])).append(", \"map\": ").append(quote(map)).append(", \"tree\": ").append(quote(tree)).append("}");
            sep = ",\n ";
        }
        out.append("\n]\n");
        Files.write(Paths.get(args[1]), out.toString().getBytes(StandardCharsets.UTF_8));
    }

    static byte[] unhex(String hex) {
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    static String quote(String s) {
        if (s == null) return "null";
        StringBuilder q = new StringBuilder("\"");
        char[] cs = s.toCharArray();
        for (int i = 0; i < cs.length; i++) {
            char c = cs[i];
            // a lone surrogate is written as '?', as the oracle's UTF-8 console writes it
            boolean paired = Character.isHighSurrogate(c) ? i + 1 < cs.length && Character.isLowSurrogate(cs[i + 1])
                : Character.isLowSurrogate(c) && i > 0 && Character.isHighSurrogate(cs[i - 1]);
            if (Character.isSurrogate(c) && !paired) q.append('?');
            else if (c == '"' || c == '\\') q.append('\\').append(c);
            else if (c < 0x20 || c > 0x7e) q.append(String.format("\\u%04x", (int) c));
            else q.append(c);
        }
        return q.append('"').toString();
    }
}
