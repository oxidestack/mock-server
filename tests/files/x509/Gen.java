import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.util.*;

/**
 * Differential vectors for X.509 parsing: base certificates mutated on their DER tree, each run through
 * CertificateFactory.generateCertificates (a CA chain file) and nimbus JWKSet.parse (an x5c entry).
 * Usage: java -cp nimbus.jar:bcprov.jar Gen.java <bases dir> <out tsv>
 */
public class Gen {
    static final class Node {
        int tag;
        List<Node> kids;     // constructed (or encapsulated: one kid)
        byte[] raw;          // primitive / raw content
        int encap;           // 0 none, 1 OCTET STRING, 2 BIT STRING (00 + inner)
        boolean indef;

        Node copy() {
            Node n = new Node();
            n.tag = tag; n.encap = encap; n.indef = indef;
            n.raw = raw == null ? null : raw.clone();
            if (kids != null) { n.kids = new ArrayList<>(); for (Node k : kids) n.kids.add(k.copy()); }
            return n;
        }
    }

    // ---- parse ----
    static int[] readTL(byte[] b, int at) {
        if (at + 2 > b.length) return null;
        int tag = b[at] & 0xff;
        if ((tag & 0x1f) == 0x1f) return null;
        int l = b[at + 1] & 0xff, p = at + 2, len;
        if (l < 0x80) len = l;
        else {
            int c = l & 0x7f;
            if (c == 0 || c > 3 || p + c > b.length) return null;
            len = 0;
            for (int i = 0; i < c; i++) len = len << 8 | (b[p + i] & 0xff);
            p += c;
        }
        if (p + len > b.length) return null;
        return new int[]{tag, p, len};
    }

    static List<Node> parseAll(byte[] b, int from, int to) {
        List<Node> out = new ArrayList<>();
        int at = from;
        while (at < to) {
            int[] tl = readTL(Arrays.copyOf(b, to), at);
            if (tl == null) return null;
            Node n = parseNode(b, tl);
            if (n == null) return null;
            out.add(n);
            at = tl[1] + tl[2];
        }
        return out;
    }

    static Node parseNode(byte[] b, int[] tl) {
        Node n = new Node();
        n.tag = tl[0];
        if ((n.tag & 0x20) != 0) {
            n.kids = parseAll(b, tl[1], tl[1] + tl[2]);
            if (n.kids == null) return null;
        } else {
            n.raw = Arrays.copyOfRange(b, tl[1], tl[1] + tl[2]);
        }
        return n;
    }

    /** Encapsulation rules, applied after the plain parse. */
    static void encapsulate(Node n) {
        if (n.kids == null) return;
        for (Node k : n.kids) encapsulate(k);
        int size = n.kids.size();
        if (n.tag == 0x30 && (size == 2 || size == 3) && n.kids.get(0).tag == 0x06) {
            Node last = n.kids.get(size - 1);
            if (last.tag == 0x04 && last.raw != null) {
                List<Node> inner = parseAll(last.raw, 0, last.raw.length);
                if (inner != null && inner.size() == 1) {
                    encapsulate(inner.get(0));
                    last.kids = inner; last.raw = null; last.encap = 1;
                }
            }
        }
        if (n.tag == 0x30 && size == 2 && n.kids.get(0).tag == 0x30) {
            Node bits = n.kids.get(1);
            if (bits.tag == 0x03 && bits.raw != null && bits.raw.length > 1 && bits.raw[0] == 0) {
                List<Node> inner = parseAll(bits.raw, 1, bits.raw.length);
                if (inner != null && inner.size() == 1 && inner.get(0).tag == 0x30) {
                    encapsulate(inner.get(0));
                    bits.kids = inner; bits.raw = null; bits.encap = 2;
                }
            }
        }
    }

    // ---- encode ----
    static void encode(Node n, ByteArrayOutputStream out) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        if (n.raw != null) body.writeBytes(n.raw);
        else {
            if (n.encap == 2) body.write(0);
            for (Node k : n.kids) encode(k, body);
        }
        out.write(n.tag);
        if (n.indef && n.raw == null) {
            out.write(0x80);
            out.writeBytes(body.toByteArray());
            out.write(0); out.write(0);
            return;
        }
        int len = body.size();
        if (len < 0x80) out.write(len);
        else if (len < 0x100) { out.write(0x81); out.write(len); }
        else if (len < 0x10000) { out.write(0x82); out.write(len >> 8); out.write(len & 0xff); }
        else { out.write(0x83); out.write(len >> 16); out.write(len >> 8 & 0xff); out.write(len & 0xff); }
        out.writeBytes(body.toByteArray());
    }

    static byte[] encode(Node n) { ByteArrayOutputStream o = new ByteArrayOutputStream(); encode(n, o); return o.toByteArray(); }

    static byte[] content(Node n) {
        if (n.raw != null) return n.raw;
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        if (n.encap == 2) body.write(0);
        for (Node k : n.kids) encode(k, body);
        return body.toByteArray();
    }

    // ---- ops ----
    static Node at(Node root, int[] path) {
        Node n = root;
        for (int i : path) n = n.kids.get(i);
        return n;
    }

    static byte[] hex(String h) {
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x)); return s.toString(); }

    /** ops: "<path>:<op>" separated by spaces; path "r" is the root, else dot-joined indices. */
    static byte[] apply(Node base, String ops) {
        Node root = base.copy();
        byte[] whole = null;
        for (String op : ops.split(" ")) {
            if (op.isEmpty()) continue;
            int c = op.indexOf(':');
            String p = op.substring(0, c), what = op.substring(c + 1);
            if (p.equals("file")) {
                if (whole == null) whole = encode(root);
                if (what.startsWith("trunc=")) whole = Arrays.copyOf(whole, Integer.parseInt(what.substring(6)));
                else if (what.startsWith("append=")) { byte[] a = hex(what.substring(7)); byte[] w = Arrays.copyOf(whole, whole.length + a.length); System.arraycopy(a, 0, w, whole.length, a.length); whole = w; }
                else throw new IllegalArgumentException(op);
                continue;
            }
            int[] path = p.equals("r") ? new int[0] : Arrays.stream(p.split("\\.")).mapToInt(Integer::parseInt).toArray();
            Node n = at(root, path);
            if (what.startsWith("tag=")) {
                byte[] c2 = content(n);
                n.tag = Integer.parseInt(what.substring(4), 16); n.raw = c2; n.kids = null; n.encap = 0;
            } else if (what.equals("empty")) { n.raw = new byte[0]; n.kids = null; n.encap = 0; }
            else if (what.equals("del") || what.equals("dup")) {
                Node parent = at(root, Arrays.copyOf(path, path.length - 1));
                int i = path[path.length - 1];
                if (what.equals("del")) parent.kids.remove(i); else parent.kids.add(i + 1, n.copy());
            } else if (what.equals("shrink")) { n.raw = Arrays.copyOf(n.raw, n.raw.length - 1); }
            else if (what.equals("grow")) { n.raw = Arrays.copyOf(n.raw, n.raw.length + 1); }
            else if (what.startsWith("set=")) { n.raw = hex(what.substring(4)); n.kids = null; n.encap = 0; }
            else if (what.equals("indef")) n.indef = true;
            else throw new IllegalArgumentException(op);
        }
        return whole != null ? whole : encode(root);
    }

    // ---- enumeration ----
    static void walk(Node n, String path, List<String[]> out) {
        out.add(new String[]{path, Integer.toHexString(n.tag), n.raw == null ? "c" : "p"});
        if (n.kids != null) for (int i = 0; i < n.kids.size(); i++) walk(n.kids.get(i), path.equals("r") ? "" + i : path + "." + i, out);
    }

    static List<String> opsFor(String path, int tag, boolean prim, boolean isRoot) {
        List<String> ops = new ArrayList<>();
        ops.add(tag == 0x04 ? "tag=02" : "tag=04");
        ops.add(tag == 0x30 ? "tag=31" : "tag=30");
        ops.add("empty");
        if (!isRoot) { ops.add("del"); ops.add("dup"); }
        if (prim) {
            ops.add("grow");
            ops.add("shrink");
            switch (tag) {
                case 0x02 -> { ops.add("set=00"); ops.add("set=ff"); ops.add("set=0001"); ops.add("set=03"); ops.add("set=7fffffffffffffffffff"); }
                case 0x06 -> { ops.add("set=80"); ops.add("set=2a"); ops.add("set=2a8648"); ops.add("set=8001"); ops.add("set=2a864886f70d01010b"); ops.add("set=2a8648ce3d0201"); ops.add("set=551d13"); ops.add("set=551d0f"); ops.add("set=551d11"); ops.add("set=2b0601"); }
                case 0x01 -> { ops.add("set=01"); ops.add("set=00"); ops.add("set=ff"); ops.add("set=0000"); }
                case 0x03 -> { ops.add("set=00"); ops.add("set=08"); ops.add("set=0800"); ops.add("set=07ff"); ops.add("set=0180"); }
                case 0x17 -> { for (String t : new String[]{"991301000000Z", "2501010000Z", "250101000000+0100", "25010100000Z", "250101000000", "2501010000+0130", "49123123595 9Z"}) ops.add("set=" + hex(t.getBytes())); }
                case 0x18 -> { for (String t : new String[]{"20251301000000Z", "20250101000000.5Z", "202501010000Z", "20250101000000", "20250101000000+0100", "20250101000000.Z"}) ops.add("set=" + hex(t.getBytes())); }
                case 0x13, 0x0c, 0x16 -> { ops.add("set=ff"); ops.add("set=c3"); ops.add("set=e282ac"); ops.add("set=00"); }
                case 0x05 -> ops.add("set=00");
                default -> {}
            }
        } else {
            ops.add("indef");
        }
        return ops;
    }

    // ---- probes ----
    static String chain(Throwable t) {
        StringBuilder s = new StringBuilder(t.toString());
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        seen.add(t);
        for (Throwable c = t.getCause(); c != null && seen.add(c); c = c.getCause()) s.append("\nCaused by: ").append(c);
        return s.toString();
    }

    static String esc(String s) {
        StringBuilder o = new StringBuilder();
        for (char ch : s.toCharArray()) {
            if (ch == '\\') o.append("\\\\");
            else if (ch == '\n') o.append("\\n");
            else if (ch < 0x20 || ch > 0x7e) o.append(String.format("\\u%04x", (int) ch));
            else o.append(ch);
        }
        return o.toString();
    }

    static String ca(byte[] data) {
        try {
            Collection<? extends java.security.cert.Certificate> certs = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(data));
            return "OK " + certs.size();
        } catch (Throwable t) {
            return chain(t);
        }
    }

    static String b64url(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    static String b64url(java.math.BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length > 1 && b[0] == 0) b = Arrays.copyOfRange(b, 1, b.length);
        return b64url(b);
    }

    static String jwkFor(PublicKey key) {
        if (key instanceof RSAPublicKey r) return "\"kty\":\"RSA\",\"n\":\"" + b64url(r.getModulus()) + "\",\"e\":\"" + b64url(r.getPublicExponent()) + "\"";
        ECPublicKey e = (ECPublicKey) key;
        return "\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + b64url(e.getW().getAffineX()) + "\",\"y\":\"" + b64url(e.getW().getAffineY()) + "\"";
    }

    static String x5c(String keyMembers, String... certs) {
        StringBuilder s = new StringBuilder("{\"keys\":[{" + keyMembers + ",\"x5c\":[");
        for (int i = 0; i < certs.length; i++) s.append(i > 0 ? "," : "").append('"').append(certs[i]).append('"');
        String json = s.append("]}]}").toString();
        try {
            com.nimbusds.jose.jwk.JWKSet.parse(json);
            return "OK";
        } catch (Throwable t) {
            return t.toString();
        }
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Path dir = Paths.get(args[0]);
        String[] bases = {"rsa_v3", "ec_v3", "rsa_v1", "p7b"};
        Map<String, Node> nodes = new LinkedHashMap<>();
        Map<String, String> keys = new HashMap<>();
        {
            byte[] v3 = Files.readAllBytes(dir.resolve("rsa_v3.der"));
            Node n = parseAll(v3, 0, v3.length).get(0);
            n.kids.get(0).kids.remove(7);
            n.kids.get(0).kids.remove(0);
            Files.write(dir.resolve("rsa_v1.der"), encode(n));
        }
        for (String b : bases) {
            byte[] der = Files.readAllBytes(dir.resolve(b + ".der"));
            Node n = parseAll(der, 0, der.length).get(0);
            encapsulate(n);
            if (!Arrays.equals(encode(n), der)) throw new IllegalStateException("round trip " + b);
            nodes.put(b, n);
        }
        PublicKey rsaKey = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(encode(nodes.get("rsa_v3")))).getPublicKey();
        PublicKey ecKey = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(encode(nodes.get("ec_v3")))).getPublicKey();
        keys.put("rsa_v3", jwkFor(rsaKey)); keys.put("rsa_v1", jwkFor(rsaKey)); keys.put("p7b", jwkFor(rsaKey)); keys.put("ec_v3", jwkFor(ecKey));

        List<String[]> cases = new ArrayList<>();
        for (String b : bases) {
            Node base = nodes.get(b);
            cases.add(new String[]{b, ""});
            List<String[]> all = new ArrayList<>();
            walk(base, "r", all);
            for (String[] w : all) if (!b.equals("p7b") || w[0].split("\\.").length <= 4) for (String op : opsFor(w[0], Integer.parseInt(w[1], 16), w[2].equals("p"), w[0].equals("r"))) cases.add(new String[]{b, w[0] + ":" + op});
            int len = encode(base).length;
            for (int t = 1; t < len; t += Math.max(1, len / 40)) cases.add(new String[]{b, "file:trunc=" + t});
            cases.add(new String[]{b, "file:trunc=" + (len - 1)});
            for (String a : new String[]{"00", "30", "3000", "0a", "2d2d2d2d2d"}) cases.add(new String[]{b, "file:append=" + a});
        }
        // hand-written combinations
        String[][] extra = {
            {"rsa_v3", "r:indef 0:indef"}, {"rsa_v3", "0:indef 0.6:indef 0.6.1:indef"}, {"rsa_v3", "r:indef file:append=30"},
            {"ec_v3", "r:indef file:append=0000"}, {"p7b", "r:indef 1:indef 1.0:indef"},
            {"rsa_v3", "0.0:del 0.7:del"}, {"rsa_v3", "0.0.0:set=00 0.7:del"}, {"rsa_v3", "0.0.0:set=01 0.7:del"},
            {"rsa_v3", "0.0.0:set=05"}, {"rsa_v3", "0.0.0:set=ff"}, {"rsa_v3", "0.5:set= 0.7.0.5.1:set=00"},
        };
        for (String[] e : extra) cases.add(e);
        // RSA key values around SunRsaSign's checks, where BouncyCastle's key factory is tried next
        java.math.BigInteger two = java.math.BigInteger.TWO;
        java.math.BigInteger p40 = two.pow(40).nextProbablePrime(), q40 = p40.add(two.pow(20)).nextProbablePrime();
        java.math.BigInteger p2047 = two.pow(2047).nextProbablePrime(), q2047 = two.pow(2047).add(two.pow(100)).nextProbablePrime();
        java.math.BigInteger[] moduli = {
            java.math.BigInteger.valueOf(251), p40.multiply(q40), two.pow(100).nextProbablePrime(), two.pow(599).nextProbablePrime(),
            two.pow(16400).subtract(java.math.BigInteger.ONE), p2047.multiply(q2047), p40.multiply(java.math.BigInteger.valueOf(743)),
            p40.multiply(q40).multiply(two),
        };
        for (java.math.BigInteger m : moduli) {
            cases.add(new String[]{"rsa_v3", "0.6.1.0.0:set=" + hex(m.toByteArray())});
            cases.add(new String[]{"rsa_v3", "0.6.1.0.0:set=" + hex(m.toByteArray()) + " 0.6.1.0.1:set=" + hex(two.pow(64).add(java.math.BigInteger.ONE).toByteArray())});
        }
        java.math.BigInteger n = ((RSAPublicKey) rsaKey).getModulus();
        for (java.math.BigInteger e : new java.math.BigInteger[]{java.math.BigInteger.ONE, two, java.math.BigInteger.valueOf(3), n, n.add(two), n.add(java.math.BigInteger.ONE)}) {
            cases.add(new String[]{"rsa_v3", "0.6.1.0.1:set=" + hex(e.toByteArray())});
        }
        cases.add(new String[]{"rsa_v3", "0.6.1.0.0:set=" + hex(moduli[1].toByteArray()) + " 0.6.1.0.1:set=000003"});
        cases.add(new String[]{"rsa_v3", "0.6.1.0.0:set=" + hex(moduli[1].toByteArray()) + " 0.6.1.0.1:set=01 0.6.1:set=01" + hex(encode(at(nodes.get("rsa_v3"), new int[]{0, 6, 1, 0})))});

        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(Paths.get(args[1])))) {
            out.println("# base\tops\tgenerateCertificates (CA chain file)\tJWKSet.parse with the mutated certificate as x5c[0] (base's own key); ~ is " + "Invalid X.509 certificate at position 0: ");
            Set<String> done = new HashSet<>();
            for (String[] c : cases) {
                if (!done.add(c[0] + "|" + c[1])) continue;
                byte[] data;
                try { data = apply(nodes.get(c[0]), c[1]); } catch (RuntimeException e) { continue; }
                String caResult = ca(data);
                String jwk = x5c(keys.get(c[0]), Base64.getEncoder().encodeToString(data));
                String prefix = "java.text.ParseException: Invalid JWK at position 0: Invalid X.509 certificate chain \"x5c\": Invalid X.509 certificate at position 0: ";
                if (jwk.startsWith(prefix)) jwk = "~" + jwk.substring(prefix.length());
                out.println(c[0] + "\t" + c[1] + "\t" + esc(caResult) + "\t" + esc(jwk));
            }
        }
        // PEM framing (JDK 26 `Pem.readPEM`) and JWK chains, with placeholders the replay fills in the same way
        String rsaB64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encode(nodes.get("rsa_v3")));
        String ecB64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encode(nodes.get("ec_v3")));
        String std = "-----BEGIN CERTIFICATE-----\n{C}\n-----END CERTIFICATE-----\n";
        String[] pems = {
            std, std.replace("\n", "\r\n"), std.replace("\n", "\r"), "junk\n" + std, "x" + std, std + "\nfoo\n", std + std.replace("{C}", "{E}"),
            "-----BEGIN CERTIFICATE-----{C}\n-----END CERTIFICATE-----\n", "-----BEGIN CERTIFICATE----- \n{C}\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE----- \n{C}\n-----END CERTIFICATE----- ", "-----BEGIN CERTIFICATE-----\n{C}\n-----END X509 CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\n{C}\n-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n{C}\n-----END CERTIFICATE-----x\n",
            "-----BEGIN CERT\nIFICATE-----\n{C}\n-----END CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\n{C}\n", "-----BEGIN CERTIFICATE-----\n{C}",
            "-----BEGIN X-----\n{C}\n-----END X-----\n", "-----BEGIN BEGIN X-----\n{C}\n-----END BEGIN X-----\n", "-----BEGIN END X-----\n{C}\n-----END END X-----\n",
            "-----BEGIN CERTIFICATE----\n{C}\n-----END CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\n{C}\n----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\n{C}\n-----END CERTIFICATE----\n", "------BEGIN CERTIFICATE-----\n{C}\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\n{C}!\n-----END CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\n{C}\u000b\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", "-----begin certificate-----\n{C}\n-----end certificate-----\n",
            "-----BEGIN X509 CERTIFICATE-----\n{C}\n-----END X509 CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\n{C}=\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\n{C}\n-----END CERTIFICATE-----\r\r\n", "-----BEGIN CERTIFICATE-----\r\r{C}\n-----END CERTIFICATE-----\r\r",
            "-----BEGIN CERTIFICATE-----\n{C}\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n" + std, "-----BEGIN \u00e9CERTIFICATE-----\n{C}\n-----END \u00e9CERTIFICATE-----\n",
            "\n\n-----BEGIN CERTIFICATE-----\n{C}\n-----END CERTIFICATE-----\n-----BEGIN", "-----BEGIN CERTIFICATE-----\n{C}\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n{E}",
        };
        String rsaMembers = keys.get("rsa_v3"), ecMembers = keys.get("ec_v3");
        String rsaDer = Base64.getEncoder().encodeToString(encode(nodes.get("rsa_v3"))), ecDer = Base64.getEncoder().encodeToString(encode(nodes.get("ec_v3")));
        String rsaPem = Base64.getEncoder().encodeToString(std.replace("{C}", rsaB64).getBytes());
        String[] jwks = {
            "{\"keys\":[{{RSA_KEY},\"x5c\":[\"{RSA}\",\"{EC}\"]}]}", "{\"keys\":[{{RSA_KEY},\"x5c\":[\"{RSA}\",\"AAAA\"]}]}",
            "{\"keys\":[{{RSA_KEY},\"x5c\":[\"\"]}]}", "{\"keys\":[{{RSA_KEY},\"x5c\":[]}]}", "{\"keys\":[{{RSA_KEY},\"x5c\":[\"{EC}\"]}]}",
            "{\"keys\":[{{EC_KEY},\"x5c\":[\"{RSA}\"]}]}", "{\"keys\":[{{EC_KEY},\"x5c\":[\"\"]}]}", "{\"keys\":[{{EC_KEY},\"x5c\":[\"{EC}\",\"\"]}]}",
            "{\"keys\":[{\"kty\":\"oct\",\"k\":\"AAAA\",\"x5c\":[\"{RSA}\"]}]}", "{\"keys\":[{\"kty\":\"oct\",\"k\":\"AAAA\",\"x5c\":[\"MAA=\"]}]}",
            "{\"keys\":[{\"kty\":\"oct\",\"k\":\"AAAA\",\"x5c\":[\"\"]}]}", "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"AAAA\",\"x5c\":[\"{RSA}\"]}]}",
            "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\",\"x5c\":[\"{RSA}\"]}]}", "{\"keys\":[{{RSA_KEY},\"use\":\"sig\",\"key_ops\":[\"encrypt\"],\"x5c\":[\"AAAA\"]}]}",
            "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"x5c\":[\"AAAA\"]}]}", "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"x5c\":[\"{RSA}\"]}]}",
            "{\"keys\":[{{RSA_KEY},\"x5c\":[\"{RSA_PEM}\"]}]}", "{\"keys\":[{{RSA_KEY},\"x5c\":[\"!!!!\"]}]}", "{\"keys\":[{\"kty\":\"XYZ\",\"x5c\":[\"AAAA\"]}]}",
            "{\"keys\":[{{EC_KEY},\"x5c\":[\"{EC}\"]},{{RSA_KEY},\"x5c\":[\"{EC}\"]}]}", "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x5c\":[\"AAAA\"]}]}",
            "{\"keys\":[{{RSA_KEY},\"x5c\":[\"{RSA}\"],\"p\":\"AQAB\"}]}", "{\"keys\":[{{RSA_KEY},\"x5c\":[\"{RSA}AAAA\"]}]}",
        };
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(Paths.get(args[1]), java.nio.file.StandardOpenOption.APPEND))) {
            for (String t : pems) {
                byte[] data = t.replace("{C}", rsaB64).replace("{E}", ecB64).getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
                String jwk = x5c(rsaMembers, Base64.getEncoder().encodeToString(data));
                String prefix = "java.text.ParseException: Invalid JWK at position 0: Invalid X.509 certificate chain \"x5c\": Invalid X.509 certificate at position 0: ";
                if (jwk.startsWith(prefix)) jwk = "~" + jwk.substring(prefix.length());
                out.println("pem\t" + esc(t) + "\t" + esc(ca(data)) + "\t" + esc(jwk));
            }
            for (String t : jwks) {
                String json = t.replace("{RSA_KEY}", rsaMembers).replace("{EC_KEY}", ecMembers).replace("{RSA_PEM}", rsaPem).replace("{RSA}", rsaDer).replace("{EC}", ecDer);
                String result;
                try { com.nimbusds.jose.jwk.JWKSet.parse(json); result = "OK"; } catch (Throwable e) { result = e.toString(); }
                out.println("jwk\t" + esc(t) + "\t-\t" + esc(result));
            }
        }
        // the derived v1 base for Rust: written by a separate call
    }
}
