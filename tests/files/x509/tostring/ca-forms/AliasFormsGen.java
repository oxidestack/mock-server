import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * RSA, DSA and EC keys and certificates under the alternative algorithm OIDs BouncyCastle and the JDK
 * alias. Usage (OpenJDK 25): java -Duser.timezone=GMT -cp bcprov:bcpkix:bcutil AliasFormsGen.java <out dir>
 * Keys: <name>-key.pem and <name>-key.txt (toString as PEMToFile.privateKeyFromPEM reads it) or <name>-key.err.
 * Certificates (RSA-signed, carrying the form's public key): <name>.pem and <name>.txt (toString as the JDK's
 * CertificateFactory reads it with BouncyCastle registered after the JDK's providers) or <name>.err.
 */
public class AliasFormsGen {
    static Path out;
    static KeyPair signer;

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        out = Paths.get(args[0]);
        Files.createDirectories(out);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(935L);
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA", "BC");
        rsa.initialize(2048, random);
        signer = rsa.generateKeyPair();
        KeyPair rsaPair = rsa.generateKeyPair();
        KeyPairGenerator dsa = KeyPairGenerator.getInstance("DSA", "BC");
        dsa.initialize(2048, random);
        KeyPair dsaPair = dsa.generateKeyPair();
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC", "BC");
        ec.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"), random);
        KeyPair ecPair = ec.generateKeyPair();

        // RSA keys and certificates under OAEP and X.509's `2.5.8.1.1`
        PrivateKeyInfo rsaKey = PrivateKeyInfo.getInstance(rsaPair.getPrivate().getEncoded());
        SubjectPublicKeyInfo rsaPub = SubjectPublicKeyInfo.getInstance(rsaPair.getPublic().getEncoded());
        for (String[] form : new String[][] {{"rsa-oaep", "1.2.840.113549.1.1.7", "null"}, {"rsa-oaep-default", "1.2.840.113549.1.1.7", "sequence"},
                {"rsa-oaep-absent", "1.2.840.113549.1.1.7", "absent"}, {"rsa-x509", "2.5.8.1.1", "null"}, {"rsa-x509-absent", "2.5.8.1.1", "absent"}}) {
            AlgorithmIdentifier alg = algorithm(form[1], form[2], null);
            key(form[0], new PrivateKeyInfo(alg, rsaKey.parsePrivateKey()).getEncoded());
            certificate(form[0], new SubjectPublicKeyInfo(alg, rsaPub.getPublicKeyData().getBytes()));
        }
        // DSA keys and certificates under dsa-with-sha1 and the two OIW OIDs
        PrivateKeyInfo dsaKey = PrivateKeyInfo.getInstance(dsaPair.getPrivate().getEncoded());
        SubjectPublicKeyInfo dsaPub = SubjectPublicKeyInfo.getInstance(dsaPair.getPublic().getEncoded());
        ASN1Encodable dsaParams = dsaKey.getPrivateKeyAlgorithm().getParameters();
        for (String[] form : new String[][] {{"dsa-sha1", "1.2.840.10040.4.3"}, {"dsa-oiw27", "1.3.14.3.2.27"}, {"dsa-oiw12", "1.3.14.3.2.12"}}) {
            AlgorithmIdentifier alg = algorithm(form[1], "params", dsaParams);
            key(form[0], new PrivateKeyInfo(alg, dsaKey.parsePrivateKey()).getEncoded());
            certificate(form[0], new SubjectPublicKeyInfo(alg, dsaPub.getPublicKeyData().getBytes()));
        }
        // EC keys and certificates on P-256 under the SEC 1 and X9.63 ECDH and ECMQV scheme OIDs
        PrivateKeyInfo ecKey = PrivateKeyInfo.getInstance(ecPair.getPrivate().getEncoded());
        SubjectPublicKeyInfo ecPub = SubjectPublicKeyInfo.getInstance(ecPair.getPublic().getEncoded());
        ASN1Encodable curve = ecKey.getPrivateKeyAlgorithm().getParameters();
        String[] ecOids = {"1.3.132.1.11.0", "1.3.132.1.11.1", "1.3.132.1.11.2", "1.3.132.1.11.3", "1.3.132.1.12", "1.3.132.1.13",
            "1.3.132.1.14.0", "1.3.132.1.14.1", "1.3.132.1.14.2", "1.3.132.1.14.3", "1.3.132.1.15.0", "1.3.132.1.15.1",
            "1.3.132.1.15.2", "1.3.132.1.15.3", "1.3.133.16.840.63.0.2", "1.3.133.16.840.63.0.3", "1.3.133.16.840.63.0.16"};
        for (String id : ecOids) {
            String name = "ec-alias-" + id.replace("1.3.132.1.", "sec-").replace("1.3.133.16.840.63.0.", "x963-").replace('.', '-');
            AlgorithmIdentifier alg = algorithm(id, "params", curve);
            key(name, new PrivateKeyInfo(alg, ecKey.parsePrivateKey()).getEncoded());
            certificate(name, new SubjectPublicKeyInfo(alg, ecPub.getPublicKeyData().getBytes()));
        }
        // a curve outside the JDK's CurveDB (BouncyCastle names it) and explicit parameters, under an alias the JDK reads
        KeyPairGenerator bp = KeyPairGenerator.getInstance("EC", "BC");
        bp.initialize(new java.security.spec.ECGenParameterSpec("brainpoolP256t1"), random);
        SubjectPublicKeyInfo bpPub = SubjectPublicKeyInfo.getInstance(bp.generateKeyPair().getPublic().getEncoded());
        certificate("ec-alias-sec-11-1-bp256t1", new SubjectPublicKeyInfo(algorithm("1.3.132.1.11.1", "params", bpPub.getAlgorithm().getParameters()), bpPub.getPublicKeyData().getBytes()));
        org.bouncycastle.asn1.x9.X9ECParameters p256 = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("prime256v1");
        certificate("ec-alias-sec-11-1-explicit", new SubjectPublicKeyInfo(algorithm("1.3.132.1.11.1", "params", new org.bouncycastle.asn1.x9.X962Parameters(p256)), ecPub.getPublicKeyData().getBytes()));
        // the plain keys the certificate-only forms pair with
        key("alias-dsa", dsaPair.getPrivate().getEncoded());
        key("alias-ec", ecPair.getPrivate().getEncoded());
    }

    static AlgorithmIdentifier algorithm(String id, String parameters, ASN1Encodable value) {
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(id);
        switch (parameters) {
            case "null": return new AlgorithmIdentifier(oid, DERNull.INSTANCE);
            case "sequence": return new AlgorithmIdentifier(oid, new DERSequence());
            case "absent": return new AlgorithmIdentifier(oid);
            default: return new AlgorithmIdentifier(oid, value);
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
        X500Name name = new X500Name("CN=MockServer Alias CA, O=Example");
        Date from = new Date(1767225600000L), to = new Date(2082758400000L);
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(name, BigInteger.valueOf(0x935), from, to, name, info);
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
