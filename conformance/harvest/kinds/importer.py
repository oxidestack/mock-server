"""Kind `importer` (B4): the importers of `PUT /mockserver/import` (HAR, Postman, WireMock, Mountebank,
Mockoon, Pact, recorded-traffic NDJSON), each call replayed through the endpoint that runs it."""
from urllib.parse import quote

from harvest import Kind, control

FORMATS = {
    "HarImporter": "har",
    "PostmanCollectionImporter": "postman",
    "WireMockImporter": "wiremock",
    "MountebankImporter": "mountebank",
    "MockoonImporter": "mockoon",
    "PactImporter": "pact",
    "RecordedTrafficImporter": "recording",
}


def listed(values):
    """`splitCommaSeparated`'s inverse, or None when a value cannot survive the split (a comma, edge blanks, empty)."""
    if any("," in v or v != v.strip() or not v for v in values):
        return None
    return ",".join(values)


def convert_importer(case):
    """`PUT /mockserver/import?format=<the importer's>` with the document as the body and the redaction options as
    `redactSensitiveData=false`, `additionalRedactedHeaders`, `additionalRedactedBodyFields` (`buildImportRedactionOptions`).
    The answer is the upserted expectations (with the migration importers' warnings), or the recorded pairs and the
    skipped-lines header; a failure is the 400 `writeEndpointFailure` writes."""
    if "unserialisable" in case:
        return None, "unserialisable"
    document = case["document"]
    if document is None:
        return None, "null document (no wire form: a request body is never null)"
    if case.get("nullOptions"):
        return None, "null redaction options (no wire form)"
    fmt = FORMATS[case["importer"]]
    if fmt == "recording" and not document.strip():
        # HttpState reads the disk archive for a blank body: tests/upstream/recorded_traffic_reimport.rs
        return None, "blank recording archive (the endpoint reads the disk archive instead)"
    query = ["format=" + fmt]
    if not case["enabled"]:
        query.append("redactSensitiveData=false")
    for name, key in (("additionalRedactedHeaders", "additionalSensitiveHeaders"), ("additionalRedactedBodyFields", "additionalSensitiveBodyFields")):
        if case[key]:
            value = listed(case[key])
            if value is None:
                return None, "a sensitive name the comma-separated parameter cannot carry"
            query.append(name + "=" + quote(value, safe=","))
    return [control("/mockserver/import?" + "&".join(query), document, case["importer"] + " " + fmt)], None


KINDS = [Kind("importer", "B4", convert_importer)]
