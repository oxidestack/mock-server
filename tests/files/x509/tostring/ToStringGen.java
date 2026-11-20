import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.Provider;
import java.security.Security;
import java.security.cert.*;
import java.util.*;

/**
 * Differential vectors for `X509Certificate.toString` (Sun's `X509CertImpl` layout), as MockServer's DEBUG
 * `loaded CA X509 from path{}containing PEM{}as{}` entry prints it: for every `*.pem` and `*.der` certificate in the
 * directory, writes `<name>.txt` with the certificate's `toString`, or `<name>.err` with the exception for one the
 * factory refuses.
 * MockServer registers BouncyCastle as a security provider, so a key of an algorithm the JDK does not implement (GOST,
 * DSTU 4145, ElGamal) is read by BouncyCastle's key factory and printed by its class: put the BC jars on
 * the class path and this adds the provider the way MockServer does (after the JDK's).
 * Usage (OpenJDK 25, the oracle's zone): java -Duser.timezone=GMT -cp bcprov-jdk18on-1.85.jar ToStringGen.java <dir>
 */
public class ToStringGen {
    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider((Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").getDeclaredConstructor().newInstance());
        } catch (ReflectiveOperationException e) {
            // no BouncyCastle on the class path: the JDK's providers only
        }
        Path dir = Paths.get(args[0]);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<Path> files = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
            for (Path file : stream) {
                String name = file.getFileName().toString();
                if (name.endsWith(".pem") || name.endsWith(".der")) files.add(file);
            }
        }
        Collections.sort(files);
        for (Path file : files) {
            String name = file.getFileName().toString();
            String base = name.substring(0, name.length() - 4);
            try (InputStream in = Files.newInputStream(file)) {
                Certificate certificate = factory.generateCertificate(in);
                Files.write(dir.resolve(base + ".txt"), certificate.toString().getBytes(StandardCharsets.UTF_8));
            } catch (CertificateException e) {
                // no toString: a certificate the factory refuses (a critical extension its class rejects)
                Files.write(dir.resolve(base + ".err"), e.toString().getBytes(StandardCharsets.UTF_8));
            }
        }
    }
}
