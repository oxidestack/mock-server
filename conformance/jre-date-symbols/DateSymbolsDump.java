import java.text.*;
import java.util.*;

/**
 * Generates src/matcher/body/simple_date_format_data.rs (without its `use super::Symbols;` line) from the JRE it runs
 * on, which must be the oracle image's: the image has no JDK, so compile here and run the class there:
 * <pre>
 * javac --release 25 -d target/jre-date-symbols conformance/jre-date-symbols/DateSymbolsDump.java
 * docker run --rm --entrypoint /usr/lib/jvm/temurin25-trimmed/bin/java -v "$PWD/target/jre-date-symbols:/w:ro" \
 *   "$ORACLE_IMAGE" --add-exports java.base/sun.util.locale.provider=ALL-UNNAMED \
 *   --add-exports java.base/sun.util.resources=ALL-UNNAMED --add-opens java.base/java.text=ALL-UNNAMED \
 *   -cp /w DateSymbolsDump
 * </pre>
 * The internal packages are read only to list the numbering systems (`-u-nu-*`) the locale data has, and the minus
 * sign text an exponent takes.
 */
public class DateSymbolsDump {
    static final int[] REST = {Calendar.SHORT_STANDALONE, Calendar.LONG_FORMAT, Calendar.LONG_STANDALONE};

    static Set<String> names(Calendar cal, int field, Locale l, int... styles) {
        Set<String> out = new TreeSet<>();
        for (int s : styles) {
            Map<String, Integer> m = cal.getDisplayNames(field, s, l);
            if (m != null) out.addAll(m.keySet());
        }
        return out;
    }

    static String lit(String s) {
        StringBuilder b = new StringBuilder("\"");
        s.codePoints().forEach(c -> {
            if (c == '"' || c == '\\') b.append('\\').append((char) c);
            else if (c < 0x20 || c > 0x7e) b.append(String.format("\\u{%x}", c));
            else b.append((char) c);
        });
        return b.append('"').toString();
    }

    /** The calendar types `Calendar.getInstance` makes, in the order of `Symbols.calendars`. */
    static final String[] CALENDARS = {"gregory", "buddhist", "japanese"};

    /** A `Numbers`: what `NumberFormat.getIntegerInstance(l)` reads when SimpleDateFormat parses a number. */
    static String numbers(Locale l) throws Exception {
        DecimalFormat f = (DecimalFormat) NumberFormat.getIntegerInstance(l);
        DecimalFormatSymbols s = f.getDecimalFormatSymbols();
        java.lang.reflect.Method m = DecimalFormatSymbols.class.getDeclaredMethod("getMinusSignText");
        m.setAccessible(true);
        String minus = (String) m.invoke(s);
        if (!f.getPositivePrefix().isEmpty() || !f.getPositiveSuffix().isEmpty() || !f.getNegativeSuffix().isEmpty()
            || !f.getNegativePrefix().equals(minus)) {
            throw new IllegalStateException("affixes " + l);
        }
        return String.format("Numbers { zero: 0x%04X, minus: %s, decimal: 0x%04X, exponent: %s, infinity: %s, nan: %s }",
            (int) s.getZeroDigit(), lit(minus), (int) s.getDecimalSeparator(), lit(s.getExponentSeparator()),
            lit(s.getInfinity()), lit(s.getNaN()));
    }

    /** The numbering systems the locale data of `l`'s provider has number symbols for. */
    static Set<String> numberingSystems(Locale l) throws Exception {
        Class<?> lpa = Class.forName("sun.util.locale.provider.LocaleProviderAdapter");
        Object adapter = lpa.getMethod("getAdapter", Class.class, Locale.class)
            .invoke(null, java.text.spi.DecimalFormatSymbolsProvider.class, l);
        Object data = adapter.getClass().getMethod("getLocaleData").invoke(adapter);
        ResourceBundle rb = (ResourceBundle) data.getClass().getMethod("getNumberFormatData", Locale.class).invoke(data, l);
        Set<String> out = new TreeSet<>();
        for (String k : rb.keySet()) if (k.endsWith(".NumberElements")) out.add(k.substring(0, k.indexOf('.')));
        return out;
    }

    static void list(StringBuilder b, String indent, String name, Collection<String> xs) {
        b.append(indent).append(name).append(": &[");
        int n = 0;
        for (String x : xs) {
            if (n++ % 8 == 0) b.append('\n').append(indent).append("    ");
            else b.append(' ');
            b.append(lit(x)).append(',');
        }
        b.append('\n').append(indent).append("],\n");
    }

    public static void main(String[] a) throws Exception {
        StringBuilder b = new StringBuilder();
        b.append("// Generated from the oracle image's JRE (").append(System.getProperty("java.runtime.version"))
            .append(", default locale ").append(Locale.getDefault()).append(", time zone ").append(TimeZone.getDefault().getID())
            .append(") by\n// conformance/jre-date-symbols/DateSymbolsDump.java: the display names SimpleDateFormat matches when it parses, per\n")
            .append("// locale-data class and calendar, the zone names in the order subParseZoneString tries them, and the symbols its\n")
            .append("// integer parser reads, per numbering system (`-u-nu-*`) where they differ from the class's. Do not edit by hand.\n\n");
        b.append("// SHORT date: ").append(lit(((SimpleDateFormat) DateFormat.getDateInstance(DateFormat.SHORT)).toPattern()))
            .append(", SHORT date-time: ").append(lit(((SimpleDateFormat) DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)).toPattern())).append("\n");
        b.append("pub(super) const SHORT_DATE: &str = ").append(lit(((SimpleDateFormat) DateFormat.getDateInstance(DateFormat.SHORT)).toPattern())).append(";\n");
        b.append("pub(super) const SHORT_DATE_TIME: &str = ").append(lit(((SimpleDateFormat) DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)).toPattern())).append(";\n\n");
        // Each class: its name, a tag of it, and a tag of it that takes a -u- extension.
        String[][] classes = {{"EN", "en-US", "en-US"}, {"ROOT", "und", "de"}, {"FALLBACK", "x-foo", "und"}};
        Set<String> systems = new TreeSet<>();
        for (String[] c : classes) systems.addAll(numberingSystems(Locale.forLanguageTag(c[1])));
        for (String[] c : classes) {
            Locale l = Locale.forLanguageTag(c[1]);
            SimpleDateFormat f = new SimpleDateFormat("z", l);
            Calendar cal = f.getCalendar();
            b.append("pub(super) const ").append(c[0]).append(": Symbols = Symbols {\n");
            b.append("    calendars: [\n");
            for (String type : CALENDARS) {
                Locale lc = type.equals("gregory") ? l : Locale.forLanguageTag(c[2] + "-u-ca-" + type);
                SimpleDateFormat fc = new SimpleDateFormat("z", lc);
                Calendar cc = fc.getCalendar();
                if (!cc.getCalendarType().equals(type)
                    || !Arrays.deepEquals(fc.getDateFormatSymbols().getZoneStrings(), f.getDateFormatSymbols().getZoneStrings())
                    // The port reads a non-Gregorian `y` as a number or nothing: no year names.
                    || cc.getDisplayNames(Calendar.YEAR, Calendar.ALL_STYLES, lc) != null) {
                    throw new IllegalStateException(c[0] + " " + type);
                }
                b.append("        // ").append(type).append("\n        Names {\n");
                list(b, "            ", "eras", names(cc, Calendar.ERA, lc, Calendar.SHORT_FORMAT, REST[0], REST[1], REST[2]));
                list(b, "            ", "am_pm", names(cc, Calendar.AM_PM, lc, Calendar.SHORT_FORMAT, REST[0], REST[1], REST[2]));
                list(b, "            ", "months_format", names(cc, Calendar.MONTH, lc, Calendar.SHORT_FORMAT, Calendar.LONG_FORMAT));
                list(b, "            ", "months_standalone", names(cc, Calendar.MONTH, lc, Calendar.SHORT_STANDALONE, Calendar.LONG_STANDALONE));
                list(b, "            ", "months_all", names(cc, Calendar.MONTH, lc, Calendar.SHORT_FORMAT, REST[0], REST[1], REST[2]));
                list(b, "            ", "weekdays_long", names(cc, Calendar.DAY_OF_WEEK, lc, Calendar.LONG));
                list(b, "            ", "weekdays_short", names(cc, Calendar.DAY_OF_WEEK, lc, Calendar.SHORT));
                b.append("        },\n");
            }
            b.append("    ],\n");
            String[][] z = f.getDateFormatSymbols().getZoneStrings();
            LinkedHashSet<String> zones = new LinkedHashSet<>();
            for (String id : new String[]{f.getTimeZone().getID(), TimeZone.getDefault().getID()}) {
                for (String[] row : z) if (row[0].equals(id)) for (int i = 1; i <= 4; i++) zones.add(row[i]);
            }
            for (String[] row : z) for (int i = 1; i <= 4; i++) zones.add(row[i]);
            list(b, "    ", "zones", zones);
            String standard = numbers(l);
            if (!numbers(Locale.forLanguageTag(c[2] + "-u-ca-gregory")).equals(standard)) throw new IllegalStateException(c[0]);
            b.append("    numbers: ").append(standard).append(",\n");
            b.append("    numbering: &[\n");
            for (String nu : systems) {
                String n = numbers(Locale.forLanguageTag(c[2] + "-u-nu-" + nu));
                if (!n.equals(standard)) b.append("        (").append(lit(nu)).append(", ").append(n).append("),\n");
            }
            b.append("    ],\n");
            b.append("};\n\n");
        }
        StringBuilder zeros = new StringBuilder();
        List<String> zs = new ArrayList<>();
        for (int ch = 0; ch < 0x10000; ch++) {
            if (Character.digit((char) ch, 10) == 0) {
                for (int k = 0; k < 10; k++) if (Character.digit((char) (ch + k), 10) != k) throw new IllegalStateException("run " + ch);
                zs.add(String.format("0x%04X", ch));
            }
            int d = Character.digit((char) ch, 10);
            if (d >= 0 && Character.digit((char) (ch - d), 10) != 0) throw new IllegalStateException("orphan " + ch);
        }
        b.append("/// The UTF-16 units `Character.digit(ch, 10)` reads as 0; each starts a run of ten.\n");
        b.append("pub(super) const DIGIT_ZEROS: &[u16] = &[");
        for (int i = 0; i < zs.size(); i++) b.append(i % 12 == 0 ? "\n    " : " ").append(zs.get(i)).append(',');
        b.append("\n];\n");
        System.out.print(b);
    }
}
