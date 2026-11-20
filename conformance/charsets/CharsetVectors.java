import java.io.*;
import java.nio.charset.*;
import java.util.*;

/**
 * Differential vectors for `src/media_type.rs`'s charset codec: `text.getBytes(cs)` and
 * `new String(bytes, cs)` for every charset of the oracle's JVM, written as JSON. Run it in the oracle image as
 * DumpCharsets is run, with `tests/files/charsets/vectors.json` as the argument.
 */
public class CharsetVectors {
    static final String[] TEXTS = {
        "plain ascii 0123 {\"a\":1}",
        "café üß € šž ąę ¤¦¨",
        "Жизнь Ґґ αβγ אב ال กข",
        "あアｱ 日本語 中文 繁體 한국어 ①Ⅰ～〜‖−¢£¬",
        "😀 𠀋 \u0081­﻿￿ 龥龦€　",
    };

    public static void main(String[] args) throws Exception {
        StringBuilder out = new StringBuilder("{\n \"encode\": [");
        String sep = "\n  ";
        for (Charset cs : Charset.availableCharsets().values()) {
            if (!cs.canEncode()) continue;
            for (String t : TEXTS) {
                out.append(sep).append("{\"charset\": \"").append(cs.name()).append("\", \"text\": ").append(cps(t))
                    .append(", \"bytes\": \"").append(hex(t.getBytes(cs))).append("\"}");
                sep = ",\n  ";
            }
        }
        out.append("\n ],\n \"decode\": [");
        sep = "\n  ";
        Random random = new Random(271);
        for (Charset cs : Charset.availableCharsets().values()) {
            List<byte[]> samples = new ArrayList<>();
            if (cs.canEncode()) for (String t : TEXTS) samples.add(t.getBytes(cs));
            for (int i = 0; i < 40; i++) {
                byte[] b = new byte[1 + random.nextInt(12)];
                random.nextBytes(b);
                samples.add(b);
            }
            // Byte-order marks, truncated and malformed sequences, and leads followed by ASCII.
            String[] fixed = {"feff0041", "fffe4100", "0000feff00000041", "fffe000041000000", "41", "4142c3", "e282", "ed a080", "eda080edb080",
                "f09f9880", "c0af", "ff", "8141", "8140", "81", "a1", "a1a1", "8f", "8fa2af", "8ea1", "8ea2a1a1", "81308130", "8130", "84318730",
                "8431a439", "90308130", "e3329a35", "e3329a36", "fe39fe39", "00110000", "0000d800", "d800dc00", "dc00", "d800", "0041d800"};
            for (String f : fixed) samples.add(unhex(f.replace(" ", "")));
            for (byte[] b : samples) {
                out.append(sep).append("{\"charset\": \"").append(cs.name()).append("\", \"bytes\": \"").append(hex(b))
                    .append("\", \"text\": ").append(cps(new String(b, cs))).append("}");
                sep = ",\n  ";
            }
        }
        out.append("\n ]\n}\n");
        try (Writer w = new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8)) {
            w.write(out.toString());
        }
    }

    static String cps(String s) {
        StringJoiner j = new StringJoiner(",", "[", "]");
        s.codePoints().forEach(c -> j.add(Integer.toString(c)));
        return j.toString();
    }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }

    static byte[] unhex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }
}
