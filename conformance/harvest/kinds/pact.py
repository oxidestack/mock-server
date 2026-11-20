"""Kind `pact` (B4): `PactExporter.export` and `PactProviderStates.namesOf`/`gatingStateOf`."""
import json
import urllib.parse

from harvest import Kind, RETRIEVE_ACTIVE, control


def convert_pact(case):
    """`export(expectations, consumer, provider)`: the expectations upserted in the order given, then
    `PUT /mockserver/pact` with the names as query parameters (a null name is an absent parameter), which exports the
    active expectations. `namesOf`/`gatingStateOf(interaction)`: a pact with that one interaction imported through
    `PUT /mockserver/pact/import` (a minimal request and response added where the interaction has none), then the
    active expectations, whose scenario state is the gating state. `activate`/`clear` on a `ScenarioManager` the test
    builds has no wire form (the server's scenario manager is only driven by `PUT /mockserver/pact/verify`)."""
    if "unserialisable" in case:
        return None, "unserialisable"
    call = case["call"]
    if call == "export":
        steps = []
        if case["expectations"]:
            expectations = [json.loads(e) for e in case["expectations"]]
            steps.append(control("/mockserver/expectation", expectations, "expectations to export"))
        query = {k: case[k] for k in ("consumer", "provider") if case.get(k) is not None}
        path = "/mockserver/pact" + ("?" + urllib.parse.urlencode(query) if query else "")
        steps.append(control(path, "", "PactExporter.export"))
        return steps, None
    if call in ("namesOf", "gatingStateOf"):
        if case.get("interaction") is None:
            return None, "null interaction (no wire form)"
        interaction = json.loads(case["interaction"])
        interaction.setdefault("request", {"method": "GET", "path": "/"})
        interaction.setdefault("response", {"status": 200})
        pact = {"consumer": {"name": "c"}, "provider": {"name": "p"}, "interactions": [interaction],
                "metadata": {"pactSpecification": {"version": "3.0.0"}}}
        return [control("/mockserver/pact/import", pact, "PactProviderStates." + call),
                control(RETRIEVE_ACTIVE, "", "active expectations")], None
    return None, "ScenarioManager built by the test (no wire form)"


KINDS = [Kind("pact", "B4", convert_pact)]
