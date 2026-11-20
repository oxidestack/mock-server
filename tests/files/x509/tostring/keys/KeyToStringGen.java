import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 * Differential vectors for a CA private key's `toString` as MockServer's TRACE `loaded CA private key from
 * path{}containing PEM{}` entry prints it: each `*.pem` read as `PEMToFile.privateKeyFromPEM` reads it (BouncyCastle
 * 1.85), its `toString` written to `<name>.txt`.
 * Usage: java -cp bcprov-jdk18on-1.85.jar:bcpkix-jdk18on-1.85.jar:bcutil-jdk18on-1.85.jar KeyToStringGen.java <dir>
 */
public class KeyToStringGen {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Path dir = Paths.get(args[0]);
        List<Path> files = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.pem")) {
            stream.forEach(files::add);
        }
        Collections.sort(files);
        for (Path file : files) {
            PEMParser parser = new PEMParser(new StringReader(Files.readString(file)));
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            Object read = parser.readObject();
            PrivateKey key = read instanceof PEMKeyPair
                ? converter.getKeyPair((PEMKeyPair) read).getPrivate()
                : converter.getPrivateKey(PrivateKeyInfo.getInstance(read));
            String name = file.getFileName().toString();
            Files.write(dir.resolve(name.substring(0, name.length() - 4) + ".txt"), key.toString().getBytes(StandardCharsets.UTF_8));
        }
    }
}
