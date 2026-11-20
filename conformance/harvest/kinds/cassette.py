"""Kind `cassette` (B4): `CassetteRegistry` register/remove/list/reset, through the cassette endpoints."""
import os
import urllib.parse

from harvest import HERE, Kind, reset

# the tests spell a cassette file relative to the harvest's working directory and hand the registry its absolute
# form; the harvested case names a fixed directory instead of the machine that ran the harvest
LOCAL_DIRECTORY = os.path.join(HERE, ".tmp") + os.sep
PLACEHOLDER_DIRECTORY = "/tmp/harvest/"


def portable(path):
    """`path` with the harvest's own `.tmp` directory replaced by the placeholder directory."""
    if path is not None and path.startswith(LOCAL_DIRECTORY):
        return PLACEHOLDER_DIRECTORY + path[len(LOCAL_DIRECTORY):]
    return path

# a cassette's last use, epoch millis (the tests inject their own clocks; the server stamps the time it has)
LAST_USED = {"regex": "\"lastUsed\" : \\d+", "replace": "\"lastUsed\" : <millis>"}


def group_cassette(lines):
    """The calls of one test method, in order, as one case."""
    cases = []
    for call in lines:
        if cases and cases[-1]["test"] == call["test"]:
            cases[-1]["calls"].append(call)
        else:
            cases.append({"boundary": "CassetteRegistry", "test": call["test"], "calls": [call]})
    return cases


def convert_cassette(case):
    """Each test builds registries of its own; the server has one, so a case may use one registry only (a reset
    between them would be a different sequence). `register` is `PUT /mockserver/cassettes` with its fields, `remove`
    `DELETE /mockserver/cassettes?path=`, `list` `GET /mockserver/cassettes`, `reset` `PUT /mockserver/reset`.
    Registrations are spaced by a few milliseconds so that most-recently-used order is the order they were made in
    (the tests' clocks either advance or stand still, which the server's clock cannot reproduce)."""
    registries = {c["registry"] for c in case["calls"]}
    if len(registries) > 1:
        return None, "several registries in one test"
    steps = []
    for call in case["calls"]:
        if "unserialisable" in call:
            return None, "unserialisable"
        kind = call["call"]
        if kind == "register":
            body = {"path": portable(call["path"])}
            if call.get("filename") is not None:
                body["filename"] = call["filename"]
            body["expectationCount"] = call["expectationCount"]
            if call.get("origin") is not None:
                body["origin"] = call["origin"]
            steps.append({"method": "PUT", "path": "/mockserver/cassettes", "body": body, "sleepMillis": 5,
                          "note": "CassetteRegistry.register", "mask": [LAST_USED]})
        elif kind == "remove":
            if call.get("path") is None:
                steps.append({"method": "DELETE", "path": "/mockserver/cassettes", "note": "CassetteRegistry.remove(null)"})
            else:
                steps.append({"method": "DELETE", "path": "/mockserver/cassettes?" + urllib.parse.urlencode({"path": portable(call["path"])}),
                              "note": "CassetteRegistry.remove"})
        elif kind == "list":
            steps.append({"method": "GET", "path": "/mockserver/cassettes", "note": "CassetteRegistry.list", "mask": [LAST_USED]})
        elif kind == "reset":
            steps.append(dict(reset(), note="CassetteRegistry.reset"))
        else:
            return None, "unknown call " + kind
    return steps, None


KINDS = [Kind("cassette", "B4", convert_cassette, group=group_cassette, per_test=True)]
