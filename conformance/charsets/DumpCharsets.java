import java.io.*;
import java.nio.*;
import java.nio.charset.*;
import java.util.*;
import java.util.zip.GZIPOutputStream;

/**
 * Dumps the charsets of the oracle's JVM into the table `src/media_type.rs` reads
 * (`src/java_charsets.bin.gz`). Run it inside the oracle image, whose trimmed JRE has no jdk.charsets module:
 *
 *   javac --release 25 -d target/charsets conformance/charsets/DumpCharsets.java
 *   docker run --rm -v "$PWD:/w" --entrypoint /usr/lib/jvm/temurin25-trimmed/bin/java mockserver/mockserver:8.0.0 \
 *     -cp /w/target/charsets DumpCharsets /w/src/java_charsets.bin.gz
 *
 * Format (big-endian, gzipped): "JCS1", u16 charset count, then per charset: name and aliases (u8 count) as
 * u8-length UTF-8 strings, u8 kind (1: the Unicode encodings `media_type.rs` computes, 0: a table). A table has
 * the encoder's replacement bytes (u8 length), then groups of byte sequences, each a u32 count and varint deltas
 * from the previous sequence's big-endian value: for lengths 1-4 the sequences the decoder turns into one code
 * point (each followed by the zigzag varint delta of that code point), for lengths 1-4 those it rejects as a
 * whole (one U+FFFD), for lengths 1-4 those it waits on for more input; then its encode differences (u32 count;
 * varint code point delta, u8 length, bytes; length 0 for unmappable) wherever the encoder differs from the first
 * sequence decoding to that code point. GB18030's four-byte sequences beyond the BMP are linear, and its
 * four-byte errors uniform, so `media_type.rs` computes them.
 */
public class DumpCharsets {
    static final Set<String> UNICODE = Set.of("UTF-8", "CESU-8", "UTF-16", "UTF-16BE", "UTF-16LE", "x-UTF-16LE-BOM",
            "UTF-32", "UTF-32BE", "UTF-32LE", "X-UTF-32BE-BOM", "X-UTF-32LE-BOM");

    public static void main(String[] args) throws Exception {
        Collection<Charset> charsets = Charset.availableCharsets().values();
        try (DataOutputStream out = new DataOutputStream(new BufferedOutputStream(new GZIPOutputStream(new FileOutputStream(args[0]))))) {
            out.writeBytes("JCS1");
            out.writeShort(charsets.size());
            for (Charset cs : charsets) {
                str(out, cs.name());
                List<String> aliases = new ArrayList<>(cs.aliases());
                Collections.sort(aliases);
                out.writeByte(aliases.size());
                for (String a : aliases) str(out, a);
                if (UNICODE.contains(cs.name())) { out.writeByte(1); continue; }
                out.writeByte(0);
                table(out, cs);
            }
        }
    }

    static void str(DataOutputStream out, String s) throws IOException {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        out.writeByte(b.length);
        out.write(b);
    }

    static final int ERROR = -2, INCOMPLETE = -1;
    /** Keeps a sequence the decoder waits on apart from the same sequence rejected once more bytes follow. */
    static final long WAITING = 1L << 40;

    /** GB18030's four-byte sequences (a lead, then 0x30-0x39), whose errors `media_type.rs` computes. */
    static boolean gb18030FourByte(Charset cs, byte[] seq) {
        return cs.name().equals("GB18030") && seq.length >= 2 && (seq[1] & 0xff) >= 0x30 && (seq[1] & 0xff) <= 0x39;
    }

    static boolean gb18030Supplementary(Charset cs, byte[] seq) {
        return cs.name().equals("GB18030") && seq.length >= 2 && (seq[0] & 0xff) >= 0x90 && (seq[1] & 0xff) >= 0x30 && (seq[1] & 0xff) <= 0x39;
    }

    static void table(DataOutputStream out, Charset cs) throws IOException {
        CharsetEncoder enc = cs.newEncoder();
        byte[] repl = enc.replacement();
        out.writeByte(repl.length);
        out.write(repl);
        TreeMap<Long, Integer> decode = new TreeMap<>();
        CharsetDecoder dec = cs.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT);
        for (int b = 0; b < 256; b++) walk(cs, dec, new byte[] {(byte) b}, decode);
        Map<Integer, Long> inverse = new HashMap<>();
        int total = 0;
        for (int len = 1; len <= 4; len++) {
            List<long[]> entries = new ArrayList<>();
            for (Map.Entry<Long, Integer> e : decode.entrySet()) {
                if (e.getKey() >>> 32 == len && e.getValue() >= 0) entries.add(new long[] {e.getKey() & 0xffffffffL, e.getValue()});
            }
            out.writeInt(entries.size());
            long seq = 0, cp = 0;
            for (long[] e : entries) {
                varint(out, e[0] - seq);
                varint(out, zigzag(e[1] - cp));
                seq = e[0];
                cp = e[1];
                inverse.putIfAbsent((int) e[1], ((long) len << 32) | e[0]);
            }
            total += entries.size();
        }
        int errors = 0;
        for (int marker : new int[] {ERROR, INCOMPLETE}) {
            for (int len = 1; len <= 4; len++) {
                List<Long> seqs = new ArrayList<>();
                for (Map.Entry<Long, Integer> e : decode.entrySet()) {
                    if ((e.getKey() >>> 32 & 0xff) == len && e.getValue() == marker) seqs.add(e.getKey() & 0xffffffffL);
                }
                out.writeInt(seqs.size());
                long prev = 0;
                for (long u : seqs) { varint(out, u - prev); prev = u; }
                if (marker == ERROR) errors += seqs.size();
            }
        }
        enc.onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT);
        ByteArrayOutputStream diffs = new ByteArrayOutputStream();
        DataOutputStream d = new DataOutputStream(diffs);
        int count = 0, prevCp = 0;
        for (int cp = 0; cp <= 0x10ffff; cp++) {
            if (cp >= 0xd800 && cp <= 0xdfff) continue;
            if (cp >= 0x10000 && cs.name().equals("GB18030")) break;
            byte[] actual = new byte[0];
            ByteBuffer bb = ByteBuffer.allocate(16);
            CoderResult r = enc.reset().encode(CharBuffer.wrap(Character.toChars(cp)), bb, true);
            if (!r.isError() && !enc.flush(bb).isError()) actual = Arrays.copyOf(bb.array(), bb.position());
            Long key = inverse.get(cp);
            byte[] expected = new byte[0];
            if (key != null) {
                int len = (int) (key >>> 32);
                expected = new byte[len];
                for (int i = 0; i < len; i++) expected[i] = (byte) (key >>> (8 * (len - 1 - i)));
            }
            if (!Arrays.equals(actual, expected)) {
                varint(d, cp - prevCp);
                prevCp = cp;
                d.writeByte(actual.length);
                d.write(actual);
                count++;
            }
        }
        out.writeInt(count);
        out.write(diffs.toByteArray());
        System.err.println(cs.name() + ": " + total + " decode, " + errors + " errors, " + count + " encode differences");
    }

    static long zigzag(long v) {
        return (v << 1) ^ (v >> 63);
    }

    static void varint(DataOutputStream out, long v) throws IOException {
        while ((v & ~0x7fL) != 0) {
            out.writeByte((int) ((v & 0x7f) | 0x80));
            v >>>= 7;
        }
        out.writeByte((int) v);
    }

    /** Records `seq` if it decodes completely; extends it while the decoder waits for more input. */
    static void walk(Charset cs, CharsetDecoder dec, byte[] seq, Map<Long, Integer> decode) {
        if (gb18030Supplementary(cs, seq)) return;
        boolean gbFour = gb18030FourByte(cs, seq);
        ByteBuffer in = ByteBuffer.wrap(seq);
        CharBuffer chars = CharBuffer.allocate(8);
        CoderResult r = dec.reset().decode(in, chars, false);
        long key = prefix(seq, seq.length);
        if (r.isError()) {
            // A rejected prefix of two or more bytes is one malformed sequence, whatever follows it.
            if (r.length() >= 2 && !gbFour) decode.put(prefix(seq, r.length()), ERROR);
            return;
        }
        if (!in.hasRemaining()) {
            // A decoder may hold bytes back until the end of input; flush asks for the rest.
            CoderResult end = dec.decode(in, chars, true);
            if (end.isError()) return;
            dec.flush(chars);
            chars.flip();
            if (chars.length() == 0) {
                if (!gbFour) decode.put(key | WAITING, INCOMPLETE);
                if (seq.length < 4) for (int b = 0; b < 256; b++) walk(cs, dec, append(seq, b), decode);
                return;
            }
            int[] cps = chars.toString().codePoints().toArray();
            if (cps.length == 1) decode.put(key, cps[0]);
            return;
        }
        chars.flip();
        if (chars.length() == 0 && in.position() == 0 && seq.length < 4) {
            if (!gbFour) decode.put(key | WAITING, INCOMPLETE);
            for (int b = 0; b < 256; b++) walk(cs, dec, append(seq, b), decode);
        }
    }

    static long prefix(byte[] seq, int len) {
        long key = 0;
        for (int i = 0; i < len; i++) key = key << 8 | (seq[i] & 0xff);
        return (long) len << 32 | key;
    }

    static byte[] append(byte[] seq, int b) {
        byte[] n = Arrays.copyOf(seq, seq.length + 1);
        n[seq.length] = (byte) b;
        return n;
    }
}
