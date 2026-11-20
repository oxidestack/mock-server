import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.*;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * EC keys on the BouncyCastle-named curves outside the JDK's CurveDB, on explicit and on implicit
 * parameters. Usage: java -cp bcprov:bcpkix:bcutil EcFormsGen.java <out dir> <curve name>...
 * Writes <name>-key.pem and <name>-key.txt (toString as PEMToFile.privateKeyFromPEM reads it) or <name>-key.err,
 * and prints each curve's domain parameters.
 */
public class EcFormsGen {
    static Path out;

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        out = Paths.get(args[0]);
        Files.createDirectories(out);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(934L);
        for (int i = 1; i < args.length; i++) {
            String name = args[i];
            ASN1ObjectIdentifier oid = org.bouncycastle.asn1.x9.ECNamedCurveTable.getOID(name);
            X9ECParameters x9 = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName(name);
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
            g.initialize(new ECNamedCurveGenParameterSpec(name), random);
            KeyPair pair = g.generateKeyPair();
            byte[] der = pair.getPrivate().getEncoded();
            PrivateKeyInfo info = PrivateKeyInfo.getInstance(der);
            String file = "ec-" + name.toLowerCase(Locale.ROOT).replace("gostr3410-2001-cryptopro-", "cryptopro-").replace("tc26-gost-3410-12-", "tc26-");
            write(file, der);
            ECCurve curve = x9.getCurve();
            ECPoint gp = x9.getG().normalize();
            StringBuilder field = new StringBuilder();
            if (curve instanceof ECCurve.AbstractFp) {
                field.append("p=").append(curve.getField().getCharacteristic().toString(16));
            } else {
                int[] e = ((org.bouncycastle.math.field.PolynomialExtensionField) curve.getField()).getMinimalPolynomial().getExponentsPresent();
                field.append("m=").append(curve.getFieldSize()).append(" exps=").append(Arrays.toString(e));
            }
            System.out.println("CURVE " + name + " " + oid + " " + file + " params=" + info.getPrivateKeyAlgorithm().getParameters().getClass().getSimpleName()
                + " size=" + curve.getFieldSize() + " " + field + " a=" + curve.getA().toBigInteger().toString(16) + " b=" + curve.getB().toBigInteger().toString(16)
                + " gx=" + gp.getAffineXCoord().toBigInteger().toString(16) + " gy=" + gp.getAffineYCoord().toBigInteger().toString(16));
        }
        // a P-256 key: its ECPrivateKey with and without the curve, under NULL, absent, explicit parameters
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(new ECNamedCurveGenParameterSpec("prime256v1"), random);
        KeyPair pair = g.generateKeyPair();
        PrivateKeyInfo info = PrivateKeyInfo.getInstance(pair.getPrivate().getEncoded());
        ECPrivateKey inner = ECPrivateKey.getInstance(info.parsePrivateKey());
        BigInteger d = inner.getKey();
        X9ECParameters p256 = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("prime256v1");
        ASN1ObjectIdentifier p256oid = X9ObjectIdentifiers.prime256v1;
        AlgorithmIdentifier nullAlg = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, DERNull.INSTANCE);
        AlgorithmIdentifier absentAlg = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey);
        ECPrivateKey withCurve = new ECPrivateKey(256, d, inner.getPublicKey(), new X962Parameters(p256oid));
        ECPrivateKey bare = new ECPrivateKey(256, d, inner.getPublicKey(), null);
        write("ec-implicit", new PrivateKeyInfo(nullAlg, withCurve).getEncoded());
        write("ec-implicit-bare", new PrivateKeyInfo(nullAlg, bare).getEncoded());
        write("ec-absent", new PrivateKeyInfo(absentAlg, withCurve).getEncoded());
        writeSec1("ec-implicit-sec1", new ECPrivateKey(256, d, inner.getPublicKey(), new X962Parameters(DERNull.INSTANCE)).getEncoded());
        // explicit parameters (uncompressed and compressed base point) on a prime and on binary curves
        explicit("ec-explicit-p256", "prime256v1", random, false);
        explicit("ec-explicit-p256c", "prime256v1", random, true);
        explicit("ec-explicit-c2pnb163v1", "c2pnb163v1", random, false);
        explicit("ec-explicit-c2pnb163v1c", "c2pnb163v1", random, true);
        explicit("ec-explicit-sect163k1", "sect163k1", random, false);
        explicit("ec-explicit-sect233k1c", "sect233k1", random, true);
        explicit("ec-explicit-frp256v1", "FRP256v1", random, false);
        explicit("ec-explicit-sm2c", "sm2p256v1", random, true);
    }

    static void explicit(String file, String name, SecureRandom random, boolean compressed) throws Exception {
        X9ECParameters x9 = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName(name);
        X9ECParameters spec = new X9ECParameters(x9.getCurve(), new X9ECPoint(x9.getG(), compressed), x9.getN(), x9.getH(), x9.getSeed());
        BigInteger d = new BigInteger(x9.getN().bitLength() - 1, random);
        ECPoint q = x9.getG().multiply(d).normalize();
        ECPrivateKey key = new ECPrivateKey(x9.getN().bitLength(), d, new DERBitString(q.getEncoded(false)), new X962Parameters(spec));
        AlgorithmIdentifier alg = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, new X962Parameters(spec));
        write(file, new PrivateKeyInfo(alg, key).getEncoded());
    }

    static void write(String file, byte[] der) throws Exception {
        pem(file, "PRIVATE KEY", der);
    }

    static void writeSec1(String file, byte[] der) throws Exception {
        pem(file, "EC PRIVATE KEY", der);
    }

    static void pem(String file, String type, byte[] der) throws Exception {
        StringWriter s = new StringWriter();
        try (PemWriter w = new PemWriter(s)) {
            w.writeObject(new PemObject(type, der));
        }
        Files.writeString(out.resolve(file + "-key.pem"), s.toString());
        try {
            PEMParser parser = new PEMParser(new StringReader(s.toString()));
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            Object read = parser.readObject();
            PrivateKey key = read instanceof PEMKeyPair
                ? converter.getKeyPair((PEMKeyPair) read).getPrivate()
                : converter.getPrivateKey(PrivateKeyInfo.getInstance(read));
            Files.writeString(out.resolve(file + "-key.txt"), key.toString());
            System.out.println("READ " + file + " " + key.getClass().getName());
        } catch (Exception e) {
            Files.writeString(out.resolve(file + "-key.err"), e.toString());
            System.out.println("REFUSED " + file + " " + e);
        }
    }
}
