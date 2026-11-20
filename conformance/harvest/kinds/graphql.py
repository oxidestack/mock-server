"""Kind `graphql` (B4): `GraphQLExpectationGenerator.generate` and
`GraphQLResponseSynthesizer.synthesizeResponse`, through `PUT /mockserver/graphql`."""
import json
import urllib.parse

from harvest import Kind, RETRIEVE_ACTIVE, control


def generate(schema, path=None):
    target = "/mockserver/graphql" + ("?" + urllib.parse.urlencode({"path": path}) if path is not None else "")
    step = control(target, schema, "GraphQLExpectationGenerator.generate")
    step["headers"] = {"Content-Type": "text/plain"}
    return step


def convert_graphql(case):
    """`generate(schema[, path])`: the schema sent to `PUT /mockserver/graphql` (the path as its `path` query
    parameter), then the active expectations. `synthesizeResponse(body)` on a synthesizer built from a schema: the
    schema imported the same way, then the body posted to `/graphql`, where the generated expectation of the
    operation's kind matches and its response is synthesized from the query. A raw GraphQL document is sent as
    `{"query": …}` (the GraphQL matcher reads GraphQL-over-HTTP bodies; the synthesizer reads both forms alike)."""
    call = case["call"]
    if case.get("schema") is None:
        return None, "null schema"
    if call == "generate":
        return [generate(case["schema"], case.get("path")), control(RETRIEVE_ACTIVE, "", "active expectations")], None
    if call == "synthesize":
        body = case.get("body")
        if body is None or not body.strip():
            return None, "blank request body (synthesis is skipped before the synthesizer is called)"
        trimmed = body.strip()
        if not (trimmed.startswith("{") and '"query"' in trimmed):
            body = json.dumps({"query": trimmed})
        request = {"method": "POST", "path": "/graphql", "headers": {"Content-Type": "application/json"}, "body": body,
                   "note": "GraphQLResponseSynthesizer.synthesizeResponse"}
        return [generate(case["schema"]), request], None
    return None, "unknown call " + call


KINDS = [Kind("graphql", "B4", convert_graphql)]
