import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;

/**
 * More differential vectors for X.509 parsing, past what Gen.java's bases reach: rsa_v3 with each extension
 * class OIDMap names that rsa_v3 lacks (critical, so a malformed one fails), with public keys of other algorithms, and
 * PKCS#7 bundles with signer attributes and CRLs. Each base is written to more/<base>.der; only its new part is
 * mutated (with Gen's mutation rules), then hand-written cases follow. The output has Gen's columns, and one
 * "@<base>\t<JWK members>" line per base: the key members its x5c column uses (its own RSA or P-256 key, else rsa_v3's).
 * Usage: javac -cp <jar> -d <classes> Gen.java More.java; java -cp <classes>:<jar> More <x509 dir> <out tsv>, run on
 * the oracle image's JVM with its jar-with-dependencies (nimbus-jose-jwt, BouncyCastle and bcpkix).
 */
public class More {
    // ---- DER building ----
    static byte[] der(int tag, byte[]... parts) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] p : parts) body.writeBytes(p);
        Gen.Node n = new Gen.Node();
        n.tag = tag; n.raw = body.toByteArray();
        return Gen.encode(n);
    }

    static byte[] h(String hex) { return Gen.hex(hex); }
    static byte[] seq(byte[]... parts) { return der(0x30, parts); }
    static byte[] oid(String hex) { return der(0x06, h(hex)); }
    static byte[] ia5(int tag, String s) { return der(tag, s.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)); }

    /** A critical extension. */
    static byte[] ext(String oidHex, byte[] value) { return seq(oid(oidHex), h("0101ff"), der(0x04, value)); }

    static Gen.Node node(byte[] der) {
        Gen.Node n = Gen.parseAll(der, 0, der.length).get(0);
        Gen.encapsulate(n);
        if (!Arrays.equals(Gen.encode(n), der)) throw new IllegalStateException("round trip");
        return n;
    }

    static Gen.Node withExtension(Gen.Node rsa, byte[] extension) {
        Gen.Node n = rsa.copy();
        Gen.at(n, new int[]{0, 7, 0}).kids.add(node(extension));
        return node(Gen.encode(n));
    }

    static Gen.Node withKey(Gen.Node rsa, byte[] spki) {
        Gen.Node n = rsa.copy();
        n.kids.get(0).kids.set(6, node(spki));
        return node(Gen.encode(n));
    }

    static String jwk(PublicKey key, String fallback) {
        if (key instanceof RSAPublicKey r) return "\"kty\":\"RSA\",\"n\":\"" + Gen.b64url(r.getModulus()) + "\",\"e\":\"" + Gen.b64url(r.getPublicExponent()) + "\"";
        if (key instanceof ECPublicKey e && e.getParams().getCurve().getField().getFieldSize() == 256 && e.getParams().getOrder().equals(P256_ORDER)) {
            return "\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + Gen.b64url(e.getW().getAffineX()) + "\",\"y\":\"" + Gen.b64url(e.getW().getAffineY()) + "\"";
        }
        return fallback;
    }

    static final BigInteger P256_ORDER = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);

    /** A compressed point in place of the uncompressed one of an EC SubjectPublicKeyInfo. */
    static byte[] compressed(ECPublicKey key) {
        Gen.Node spki = node(key.getEncoded());
        int size = (key.getParams().getCurve().getField().getFieldSize() + 7) / 8;
        byte[] x = key.getW().getAffineX().toByteArray();
        byte[] point = new byte[1 + size];
        point[0] = (byte) (key.getW().getAffineY().testBit(0) ? 3 : 2);
        System.arraycopy(x, Math.max(0, x.length - size), point, 1 + Math.max(0, size - x.length), Math.min(size, x.length));
        byte[] bits = new byte[point.length + 1];
        System.arraycopy(point, 0, bits, 1, point.length);
        spki.kids.set(1, node(der(0x03, bits)));
        return Gen.encode(spki);
    }

    record Base(String name, Gen.Node node, String scope, String jwk) {}

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Path dir = Paths.get(args[0]);
        Path more = dir.resolve("more");
        Files.createDirectories(more);
        Gen.Node rsa = node(Files.readAllBytes(dir.resolve("rsa_v3.der")));
        PublicKey rsaKey = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Gen.encode(rsa))).getPublicKey();
        String rsaJwk = jwk(rsaKey, null);
        List<Base> bases = new ArrayList<>();
        String extScope = "0.7.0.5";

        // ---- the extension classes rsa_v3 lacks ----
        byte[] gt1 = "20250101000000Z".getBytes(), gt2 = "20300101000000Z".getBytes();
        byte[] dirName = seq(der(0x31, seq(oid("550403"), der(0x0c, "ca".getBytes()))));
        Object[][] exts = {
            {"ext_private_key_usage", "551d10", seq(der(0x80, gt1), der(0x81, gt2))},
            {"ext_crl_number", "551d14", der(0x02, h("05"))},
            {"ext_reason_code", "551d15", der(0x0a, h("01"))},
            {"ext_name_constraints", "551d1e", seq(
                der(0xa0, seq(ia5(0x82, "example.com")), seq(der(0x87, h("0a000000ff000000"))), seq(ia5(0x86, ".example.com"), der(0x80, h("00")), der(0x81, h("05")))),
                der(0xa1, seq(ia5(0x81, "a@b.example")), seq(der(0xa4, dirName))))},
            {"ext_policy_mappings", "551d21", seq(seq(oid("2a0304"), oid("2a0305")))},
            {"ext_policy_constraints", "551d24", seq(der(0x80, h("01")), der(0x81, h("02")))},
            {"ext_netscape_cert_type", "6086480186f8420101", der(0x03, h("0780"))},
            {"ext_inhibit_any_policy", "551d36", der(0x02, h("00"))},
            {"ext_certificate_issuer", "551d1d", seq(ia5(0x82, "ca.example.com"), der(0xa4, dirName))},
            {"ext_issuing_distribution_point", "551d1c", seq(
                der(0xa0, der(0xa0, ia5(0x86, "http://crl.example.com/a.crl"))), der(0x81, h("ff")), der(0x83, h("0560")), der(0x84, h("00")))},
            {"ext_delta_crl_indicator", "551d1b", der(0x02, h("03"))},
            {"ext_ocsp_no_check", "2b0601050507300105", der(0x05)},
            // the URI name of an IssuerAlternativeName: hand-written hosts follow
            {"ext_uri_name", "551d12", seq(ia5(0x86, "http://example.com/"))},
        };
        for (Object[] e : exts) bases.add(new Base((String) e[0], withExtension(rsa, ext((String) e[1], (byte[]) e[2])), extScope, rsaJwk));

        // ---- keys of other algorithms ----
        Map<String, KeyPair> pairs = new LinkedHashMap<>();
        KeyPairGenerator g;
        g = KeyPairGenerator.getInstance("DSA"); g.initialize(2048); pairs.put("key_dsa", g.generateKeyPair());
        for (String alg : new String[]{"Ed25519", "Ed448", "X25519", "X448", "RSASSA-PSS"}) {
            g = KeyPairGenerator.getInstance(alg);
            if (alg.equals("RSASSA-PSS")) g.initialize(2048);
            pairs.put("key_" + alg.toLowerCase().replace("-", "_"), g.generateKeyPair());
        }
        g = KeyPairGenerator.getInstance("RSASSA-PSS");
        g.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4, new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)));
        pairs.put("key_rsassa_pss_params", g.generateKeyPair());
        g = KeyPairGenerator.getInstance("DH"); g.initialize(2048); pairs.put("key_dh", g.generateKeyPair());
        g = KeyPairGenerator.getInstance("ML-DSA"); pairs.put("key_ml_dsa", g.generateKeyPair());
        g = KeyPairGenerator.getInstance("ML-KEM"); pairs.put("key_ml_kem", g.generateKeyPair());
        g = KeyPairGenerator.getInstance("EC", "BC"); g.initialize(new ECGenParameterSpec("secp256k1")); pairs.put("key_ec_secp256k1", g.generateKeyPair());
        g = KeyPairGenerator.getInstance("EC", "BC"); g.initialize(new ECGenParameterSpec("brainpoolP256r1")); pairs.put("key_ec_brainpool", g.generateKeyPair());
        for (var e : pairs.entrySet()) bases.add(new Base(e.getKey(), withKey(rsa, e.getValue().getPublic().getEncoded()), "0.6", jwk(e.getValue().getPublic(), rsaJwk)));
        g = KeyPairGenerator.getInstance("EC"); g.initialize(new ECGenParameterSpec("secp256r1"));
        ECPublicKey p256 = (ECPublicKey) g.generateKeyPair().getPublic();
        bases.add(new Base("key_ec_compressed", withKey(rsa, compressed(p256)), "0.6", jwk(p256, rsaJwk)));
        g = KeyPairGenerator.getInstance("EC"); g.initialize(new ECGenParameterSpec("secp384r1"));
        ECPublicKey p384 = (ECPublicKey) g.generateKeyPair().getPublic();
        bases.add(new Base("key_ec_compressed_p384", withKey(rsa, compressed(p384)), "0.6", rsaJwk));
        // explicit EC parameters (BouncyCastle encodes them when the curve is not named)
        ECParameterSpec named = p256.getParams();
        ECParameterSpec explicit = new ECParameterSpec(named.getCurve(), named.getGenerator(), named.getOrder(), named.getCofactor());
        PublicKey explicitKey = KeyFactory.getInstance("EC", "BC").generatePublic(new ECPublicKeySpec(p256.getW(), explicit));
        bases.add(new Base("key_ec_explicit", withKey(rsa, explicitKey.getEncoded()), "0.6", jwk(p256, rsaJwk)));

        // ---- PKCS#7 with signer attributes and a CRL ----
        {
            KeyPairGenerator rg = KeyPairGenerator.getInstance("RSA"); rg.initialize(2048);
            KeyPair signer = rg.generateKeyPair();
            org.bouncycastle.cert.X509CertificateHolder holder = new org.bouncycastle.cert.X509CertificateHolder(Gen.encode(rsa));
            java.util.Date now = new java.util.Date(1767225600000L);
            org.bouncycastle.cert.X509v2CRLBuilder crl = new org.bouncycastle.cert.X509v2CRLBuilder(holder.getSubject(), now);
            crl.setNextUpdate(new java.util.Date(now.getTime() + 86400000L));
            org.bouncycastle.asn1.x509.ExtensionsGenerator entry = new org.bouncycastle.asn1.x509.ExtensionsGenerator();
            entry.addExtension(org.bouncycastle.asn1.x509.Extension.reasonCode, false, org.bouncycastle.asn1.x509.CRLReason.lookup(1));
            entry.addExtension(org.bouncycastle.asn1.x509.Extension.invalidityDate, false, new org.bouncycastle.asn1.ASN1GeneralizedTime(now));
            crl.addCRLEntry(BigInteger.valueOf(7), now, entry.generate());
            crl.addCRLEntry(BigInteger.valueOf(8), now, 0);
            crl.addExtension(org.bouncycastle.asn1.x509.Extension.cRLNumber, false, new org.bouncycastle.asn1.ASN1Integer(3));
            org.bouncycastle.operator.ContentSigner cs = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(signer.getPrivate());
            org.bouncycastle.cert.X509CRLHolder crlHolder = crl.build(cs);
            org.bouncycastle.cms.CMSSignedDataGenerator gen = new org.bouncycastle.cms.CMSSignedDataGenerator();
            gen.addSignerInfoGenerator(new org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder(
                new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().build()).build(
                    new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(signer.getPrivate()), holder));
            gen.addCertificate(holder);
            gen.addCRL(crlHolder);
            byte[] signed = gen.generate(new org.bouncycastle.cms.CMSProcessableByteArray("data".getBytes()), false).getEncoded("DER");
            Gen.Node p7 = node(signed);
            bases.add(new Base("p7_signer", p7, "1.0.5", rsaJwk));
            bases.add(new Base("p7_crl", p7, "1.0.4", rsaJwk));
        }

        // ---- write ----
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(Paths.get(args[1])))) {
            out.println("# base\tops\tgenerateCertificates (CA chain file)\tJWKSet.parse with the mutated certificate as x5c[0] (the @ line's key members); ~ is Invalid X.509 certificate at position 0: ");
            Set<String> written = new HashSet<>();
            for (Base b : bases) {
                if (written.add(b.name())) {
                    Files.write(more.resolve(b.name() + ".der"), Gen.encode(b.node()));
                    out.println("@" + b.name() + "\t" + b.jwk());
                }
            }
            Set<String> done = new HashSet<>();
            for (Base b : bases) {
                List<String> cases = new ArrayList<>();
                cases.add("");
                List<String[]> all = new ArrayList<>();
                Gen.walk(b.node(), "r", all);
                for (String[] w : all) {
                    if (!(w[0].equals(b.scope()) || w[0].startsWith(b.scope() + "."))) continue;
                    if (b.name().startsWith("p7") && w[0].split("\\.").length > 9) continue;
                    for (String op : Gen.opsFor(w[0], Integer.parseInt(w[1], 16), w[2].equals("p"), false)) cases.add(w[0] + ":" + op);
                }
                cases.addAll(extra(b.name()));
                for (String ops : cases) {
                    if (!done.add(b.name() + "|" + ops)) continue;
                    byte[] data;
                    try { data = Gen.apply(b.node(), ops); } catch (RuntimeException e) { continue; }
                    String ca = Gen.ca(data);
                    String jwk = Gen.x5c(b.jwk(), Base64.getEncoder().encodeToString(data));
                    String prefix = "java.text.ParseException: Invalid JWK at position 0: Invalid X.509 certificate chain \"x5c\": Invalid X.509 certificate at position 0: ";
                    if (jwk.startsWith(prefix)) jwk = "~" + jwk.substring(prefix.length());
                    out.println(b.name() + "\t" + ops + "\t" + Gen.esc(ca) + "\t" + Gen.esc(jwk));
                }
            }
        }
    }

    static String hexOf(String s) { return Gen.hex(s.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)); }

    /** Hand-written cases per base. */
    static List<String> extra(String base) {
        List<String> out = new ArrayList<>();
        switch (base) {
            case "ext_uri_name" -> {
                for (String uri : new String[]{"http://localhost./", "http://nonexistent.invalid./", "http://a.invalid./x", "http://1.2.3.4./",
                        "http://foo_bar.example/", "http://-a.example/", "http://a-.example/", "http://[::1]/", "http://[::1/", "http://[1::2::3]/",
                        "http://127.0.0.1/", "http://999.1.1.1/", "http://1.2.3/", "http://a..b/", "http://./", "http://x./", "urn:x", "http:///p",
                        "http://user@host.example:80/", "http://h%41.example/", "http://é.example/", "mailto:a@b", "http://a.b.c.d.e.f./",
                        "http://0x7f.0.0.1/", "http://localhost/", "http://LOCALHOST./", "http://a.123/", "http://123.a/"}) {
                    out.add("0.7.0.5.2.0.0:set=" + hexOf(uri));
                }
            }
            case "ext_name_constraints" -> {
                // the URI constraint is 0.7.0.5.2.0.0.2.0, the IP one 0.7.0.5.2.0.0.1.0
                for (String c : new String[]{"example.com", ".example.com", "http://example.com", "", ".", "-a.com", "a..b", "a b", "*.example.com",
                        "example.com:80", "//example.com", "a_b.com", "[::1]", "1.2.3.4", "example.com/path"}) {
                    out.add("0.7.0.5.2.0.0.2.0:set=" + hexOf(c));
                }
                for (String ip : new String[]{"0a000000", "0a000000ff00", "00000000000000000000000000000001", "0000000000000000000000000000000100000000000000000000000000000000", ""}) {
                    out.add("0.7.0.5.2.0.0.1.0:set=" + ip);
                }
                out.add("0.7.0.5.2.0.0.2.1:set=7fffffff");
                out.add("0.7.0.5.2.0.0.2.2:set=ff");
                out.add("0.7.0.5.2.0.0.2.1:tag=82");
                out.add("0.7.0.5.2.0.0.2.0:tag=86 0.7.0.5.2.0.0.2.0:set=" + hexOf("http://x/"));
                out.add("0.7.0.5.2.0.1:tag=a0");
                out.add("0.7.0.5.2.0.0:tag=a1");
                out.add("0.7.0.5.2.0.0:empty");
            }
            case "ext_inhibit_any_policy" -> {
                for (String v : new String[]{"ff", "fe", "7fffffff", "80000000", "0100000000", "00ff"}) out.add("0.7.0.5.2.0:set=" + v);
                out.add("0.7.0.5.1:set=00");
                out.add("0.7.0.5.1:del");
            }
            case "ext_private_key_usage" -> {
                out.add("0.7.0.5.2.0.1:tag=80");
                out.add("0.7.0.5.2.0.0:tag=81");
                out.add("0.7.0.5.2.0.0:del 0.7.0.5.2.0.0:del");
            }
            case "ext_policy_constraints" -> {
                out.add("0.7.0.5.2.0.1:tag=80");
                out.add("0.7.0.5.2.0.0:tag=81");
                out.add("0.7.0.5.2.0.0:set=7fffffffff");
            }
            case "ext_reason_code" -> {
                for (String v : new String[]{"00", "0a", "ff", "7fffffff", "0100000000"}) out.add("0.7.0.5.2.0:set=" + v);
            }
            case "ext_netscape_cert_type" -> {
                for (String v : new String[]{"00", "0000", "00ff", "08ff", "07ffff"}) out.add("0.7.0.5.2.0:set=" + v);
            }
            case "ext_ocsp_no_check" -> {
                out.add("0.7.0.5.2:set=");
                out.add("0.7.0.5.2:set=ff");
            }
            case "ext_issuing_distribution_point" -> {
                out.add("0.7.0.5.2.0.0:dup");
                out.add("0.7.0.5.2.0.1:tag=82");
                out.add("0.7.0.5.2.0.1:tag=85");
                out.add("0.7.0.5.2.0.1:tag=86");
                out.add("0.7.0.5.2.0.3:tag=81");
                out.add("0.7.0.5.2.0.0.0:tag=a1");
            }
            case "key_ec_compressed" -> {
                out.add("0.6.1:set=000200");
                out.add("0.6.1:set=0002" + "00".repeat(32));
                out.add("0.6.1:set=0003" + "ff".repeat(32));
                out.add("0.6.1:set=0005" + "00".repeat(32));
                out.add("0.6.1:set=0000");
                out.add("0.6.1:set=00");
            }
            default -> {}
        }
        return out;
    }
}
