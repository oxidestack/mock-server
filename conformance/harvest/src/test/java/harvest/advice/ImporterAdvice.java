package harvest.advice;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import harvest.Recorder;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import java.util.Collection;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;

/**
 * Kind {@code importer} (B4), outermost call only: the importers {@code HttpState} runs for
 * {@code PUT /mockserver/import}, {@code importExpectations(document[, options])} of {@code HarImporter},
 * {@code PostmanCollectionImporter}, {@code WireMockImporter}, {@code MountebankImporter}, {@code MockoonImporter} and
 * {@code PactImporter}, and {@code RecordedTrafficImporter.importRecordedTraffic(ndjson[, options])}. Each call is one
 * line of importer.jsonl: the importer, the document, and the redaction options (the one-argument overloads use
 * {@code Options.enabled()}). Replayed as {@code PUT /mockserver/import?format=…} with the options as its query
 * parameters (kinds/importer.py).
 */
public class ImporterAdvice implements Boundary {

    private static final String KEY = "importer";

    private static final String[] IMPORTERS = {
        "org.mockserver.imports.HarImporter",
        "org.mockserver.imports.PostmanCollectionImporter",
        "org.mockserver.imports.WireMockImporter",
        "org.mockserver.imports.MountebankImporter",
        "org.mockserver.imports.MockoonImporter",
        "org.mockserver.imports.RecordedTrafficImporter",
        "org.mockserver.mock.pact.PactImporter",
    };

    @Override
    public String[] preload() {
        return IMPORTERS;
    }

    @Override
    public AgentBuilder install(AgentBuilder agent) {
        return agent
            .type(namedOneOf(IMPORTERS))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ImporterAdvice.class)
                .on(namedOneOf("importExpectations", "importRecordedTraffic"))));
    }

    @Advice.OnMethodEnter
    public static boolean enter() {
        return Recorder.enter(KEY);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost, @Advice.Origin("#t") String type, @Advice.AllArguments Object[] args,
                            @Advice.Thrown Throwable thrown) {
        Recorder.exit(KEY);
        if (outermost) {
            ImporterAdvice.imported(type, args, thrown);
        }
    }

    public static void imported(String type, Object[] args, Throwable thrown) {
        ObjectNode c = Recorder.base(type.substring(type.lastIndexOf('.') + 1) + ".import");
        c.put("importer", type.substring(type.lastIndexOf('.') + 1));
        try {
            if (args[0] == null) {
                c.putNull("document");
            } else {
                c.put("document", (String) args[0]);
            }
            if (args.length < 2) {
                c.put("enabled", true);
                c.putArray("additionalSensitiveHeaders");
                c.putArray("additionalSensitiveBodyFields");
            } else if (args[1] == null) {
                c.put("nullOptions", true);
            } else {
                c.put("enabled", (Boolean) Recorder.field(args[1], "enabled"));
                strings(c.putArray("additionalSensitiveHeaders"), Recorder.field(args[1], "additionalSensitiveHeaders"));
                strings(c.putArray("additionalSensitiveBodyFields"), Recorder.field(args[1], "additionalSensitiveBodyFields"));
            }
        } catch (Throwable e) {
            c.put("unserialisable", String.valueOf(e));
        }
        Recorder.outcome(c, thrown);
        Recorder.write(KEY, c);
    }

    private static void strings(ArrayNode array, Object values) {
        if (values != null) {
            for (Object v : (Collection<?>) values) {
                array.add(String.valueOf(v));
            }
        }
    }
}
