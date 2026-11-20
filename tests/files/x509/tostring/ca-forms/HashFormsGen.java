import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * HashML-DSA (2.16.840.1.101.3.4.3.32-34) and HashSLH-DSA (.35-46) keys and certificates, one per
 * parameter set. Usage (OpenJDK 25): java -Duser.timezone=GMT -cp bcprov:bcpkix:bcutil HashFormsGen.java <out dir>
 * Keys: <name>-key.pem and <name>-key.txt (toString as PEMToFile.privateKeyFromPEM reads it) or <name>-key.err.
 * Certificates (RSA-signed, carrying the form's public key): <name>.pem and <name>.txt (toString as the JDK's
 * CertificateFactory reads it with BouncyCastle registered after the JDK's providers) or <name>.err.
 */
public class HashFormsGen {
    static Path out;
    static KeyPair signer;

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        out = Paths.get(args[0]);
        Files.createDirectories(out);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(936L);
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA", "BC");
        rsa.initialize(2048, random);
        signer = rsa.generateKeyPair();
        forms(MLDSAParameterSpec.class, "ML-DSA", random);
        forms(SLHDSAParameterSpec.class, "SLH-DSA", random);
    }

    /** Each pre-hash parameter set (a `*_with_*` constant) of the spec class, in name order. */
    static void forms(Class<?> spec, String algorithm, SecureRandom random) throws Exception {
        Field[] fields = spec.getFields();
        Arrays.sort(fields, Comparator.comparing(Field::getName));
        for (Field field : fields) {
            if (!Modifier.isStatic(field.getModifiers()) || !field.getName().contains("_with_")) {
                continue;
            }
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, "BC");
            generator.initialize((AlgorithmParameterSpec) field.get(null), random);
            KeyPair pair = generator.generateKeyPair();
            String name = "hash-" + field.getName().replace('_', '-');
            System.out.println(name + " " + SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()).getAlgorithm().getAlgorithm());
            key(name, pair.getPrivate().getEncoded());
            certificate(name, SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()));
        }
    }

    static void key(String file, byte[] der) throws Exception {
        String pem = pem("PRIVATE KEY", der);
        Files.writeString(out.resolve(file + "-key.pem"), pem);
        try {
            PEMParser parser = new PEMParser(new StringReader(pem));
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            Object read = parser.readObject();
            PrivateKey key = read instanceof PEMKeyPair
                ? converter.getKeyPair((PEMKeyPair) read).getPrivate()
                : converter.getPrivateKey(PrivateKeyInfo.getInstance(read));
            Files.writeString(out.resolve(file + "-key.txt"), key.toString());
            System.out.println("KEY READ " + file + " " + key.getClass().getName());
        } catch (Exception e) {
            Files.writeString(out.resolve(file + "-key.err"), e.toString());
            System.out.println("KEY REFUSED " + file + " " + e);
        }
    }

    static void certificate(String file, SubjectPublicKeyInfo info) throws Exception {
        X500Name name = new X500Name("CN=MockServer Hash CA, O=Example");
        Date from = new Date(1767225600000L), to = new Date(2082758400000L);
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(name, BigInteger.valueOf(0x936), from, to, name, info);
        byte[] der = builder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(signer.getPrivate())).getEncoded();
        String pem = pem("CERTIFICATE", der);
        Files.writeString(out.resolve(file + ".pem"), pem);
        try {
            java.security.cert.Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
            Files.writeString(out.resolve(file + ".txt"), certificate.toString());
            System.out.println("CERT READ " + file + " " + ((X509Certificate) certificate).getPublicKey().getClass().getName());
        } catch (CertificateException e) {
            Files.writeString(out.resolve(file + ".err"), e.toString());
            System.out.println("CERT REFUSED " + file + " " + e);
        }
    }

    static String pem(String type, byte[] der) throws Exception {
        StringWriter s = new StringWriter();
        try (PemWriter w = new PemWriter(s)) {
            w.writeObject(new PemObject(type, der));
        }
        return s.toString();
    }
}
