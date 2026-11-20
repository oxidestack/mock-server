"""Kinds `nottable`, `validator` and `schemaval` (B2 package 7).

Each is harvested by a run of its own into target/harvest-b4/<dir>/ (the defaults of `harvest.py --kinds`), written
only to DIR/B4-<kind>-<TestClass>.json: harvest.py knows no tranche called B2, so these files carry the B4 prefix.

  mvn -q test -Dharvest.tests='org/mockserver/serialization/serializers/string/NottableStringSerializerTest.java' -Dharvest.dir=target/harvest-b4/nottable
  mvn -q test -Dharvest.tests='org/mockserver/validator/jsonschema/JsonSchemaHttpResponseValidatorTest.java,org/mockserver/validator/jsonschema/JsonSchemaHttpRequestAndHttpResponseValidatorTest.java' -Dharvest.dir=target/harvest-b4/validator
  mvn -q test -Dharvest.tests='org/mockserver/validator/jsonschema/JsonSchemaValidatorTest.java,org/mockserver/validator/xmlschema/XmlSchemaValidatorTest.java' -Dharvest.dir=target/harvest-b4/schemaval
  python3 harvest.py --kinds nottable,validator,schemaval
"""
import json

from harvest import Kind, combined_steps, control, RETRIEVE_ACTIVE

TIMESTAMP = "\\d{4}-\\d{2}-\\d{2}T[0-9:.]+Z"
LOG_TIMESTAMP = "\\d{4}-\\d\\d-\\d\\d \\d\\d:\\d\\d:\\d\\d\\.\\d{3}"
PATH = "/harvested"


# --- nottable: NottableStringSerializerTest ------------------------------------------------------------------------

def convert_nottable(case):
    """What `ObjectMapper.writeValueAsString` produced for a NottableString (alone, or as the `value` of a one-property
    bean) is the form the server echoes a string matcher in. It reaches the wire as a query parameter value, which
    takes every form (plain, `!`, `?`, object with `not`/`optional`/`parameterStyle`/`schema`): the same value goes in
    through `PUT /mockserver/expectation` and comes back out of `retrieve?type=ACTIVE_EXPECTATIONS`."""
    kind = case.get("type", "")
    if "WrapperForSerializer" in kind:
        return None, "the schema node inside a schema string, not a NottableString"
    try:
        value = json.loads(case["input"])
    except ValueError:
        return None, "not JSON"
    if "$" in kind.rsplit(".", 1)[-1]:
        # an anonymous bean `{ getValue() }`: the value is the property
        value = value["value"]
    expectation = {"httpRequest": {"path": PATH, "queryStringParameters": {"p": [value]}}, "httpResponse": {"body": "x"}}
    return [control("/mockserver/expectation", expectation, "input"), control(RETRIEVE_ACTIVE, "", "echo")], None


# --- validator: the httpResponse and request-and-response validators -------------------------------------------------

def convert_validator(case):
    boundary = case["boundary"].rsplit(".", 1)[-1]
    text = case.get("input")
    if text is None:
        return None, "null input"
    if boundary == "JsonSchemaHttpRequestAndHttpResponseValidator":
        # the only wire path of the combined format is the recorded-traffic import (RecordedTrafficImporter parses each
        # line with HttpRequestAndHttpResponseSerializer, whose validator this is); a rejected line is a generic 400
        return combined_steps(text)
    if boundary == "JsonSchemaHttpResponseValidator":
        # the wire path of HttpResponseSerializer's validator is a template's generated output
        # (HttpTemplateOutputDeserializer): a valid response is served, an invalid one logs the validator's text
        # ("template generated output that failed httpResponseDTO validation") and the request gets a 404
        if "{{" in text:
            return None, "contains a Mustache tag"
        expectation = {"httpRequest": {"path": PATH}, "httpResponseTemplate": {"templateType": "MUSTACHE", "template": text}}
        return [control("/mockserver/expectation", expectation, "input"),
                {"method": "GET", "path": PATH, "note": "response"},
                {"method": "PUT", "path": "/mockserver/retrieve?type=LOGS", "body": {"path": PATH}, "note": "logs",
                 "mask": [LOG_TIMESTAMP]}], None
    return None, "no wire form for " + boundary


# --- schemaval: JsonSchemaValidator and XmlSchemaValidator -------------------------------------------------------

def group_schemaval(lines):
    """One case per validator the test builds: its `new`, then `built` and each `valid` (isValid) call that followed.
    A `new` with no `built` after it is a schema the constructor rejected."""
    cases = []
    for line in lines:
        event = line["event"]
        if event == "new":
            cases.append({"boundary": "SchemaValidator", "test": line["test"], "type": line["type"], "schema": line["schema"],
                          "sourceUri": line.get("sourceUri"), "built": False, "probes": []})
        elif event == "built":
            cases[-1]["built"] = True
        elif event == "valid":
            cases[-1]["probes"].append(line)
    return cases


def convert_schemaval(case):
    """The validator's constructor is the body matcher's compile and `isValid` its `matches` (JsonSchemaMatcher,
    XmlSchemaMatcher); the matcher's `failed because:` text is what `PUT /mockserver/debugMismatch` returns for a probe
    request, and an expectation whose schema the constructor rejects is rejected at creation."""
    if case.get("sourceUri"):
        return None, "schema imports a class path resource (xs:import resolved against a source URI)"
    schema = case["schema"]
    if schema is None:
        return None, "null schema"
    if case["type"] == "json":
        try:
            schema = json.loads(schema)
        except ValueError:
            pass
        body = {"type": "JSON_SCHEMA", "jsonSchema": schema}
    else:
        body = {"type": "XML_SCHEMA", "xmlSchema": schema}
    expectation = {"httpRequest": {"path": PATH, "body": body}, "httpResponse": {"statusCode": 200}}
    steps = [control("/mockserver/expectation", expectation, "input")]
    if not case["built"]:
        steps.append(control(RETRIEVE_ACTIVE, "", "echo"))
        return steps, None
    for probe in case["probes"]:
        request = {"path": PATH}
        # a blank instance is a request without a body on the wire (a zero-length body), which the matchers report
        # as absent; `"body": ""` in a probe definition would be a different, empty string body
        if probe["input"]:
            request["body"] = probe["input"]
        steps.append({"method": "PUT", "path": "/mockserver/debugMismatch", "body": request, "note": "probe",
                      "compare": "json", "mask": [TIMESTAMP]})
    if not case["probes"]:
        return None, "no isValid call"
    return steps, None


KINDS = [
    Kind("nottable", "B4", convert_nottable, source=("nottable", "jackson")),
    Kind("validator", "B4", convert_validator, source=("validator", "validate"), per_test=True),
    Kind("schemaval", "B4", convert_schemaval, source=("schemaval", "schemavalidator"), group=group_schemaval, per_test=True),
]
