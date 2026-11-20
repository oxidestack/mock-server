"""Kind `confput` (B4): the fluent setters of a `Configuration` instance that the tests of mockserver-core's
`configuration` package call, `configuration.<name>(value)`, one case per distinct call: `PUT /mockserver/configuration`
with `{<name>: value}`, whose answer is the configuration as the server now reads it (`GET /mockserver/configuration`'s
body), compared on the `<name>` line only. A running server's `Configuration` is the instance those setters act on,
so the PUT shows what the getter reads back: clamps (`maxRequestBodySize(0)` reads 1), refusals
(`binaryMessageLengthPrefixBytes(16)` throws, the PUT answers 400), masks of credentials, and nulls falling back to the
static store.

A value that stops the server answering the harness's next request (a body or header limit below what the next PUT
sends, control-plane authentication switched on) would leave every later case of a shared file unanswered, so such a
case runs on a server of its own, started with that value as a property: its PUT and a GET of the configuration then
show the startup read as well as the refusal. Values that keep such a server from starting at all, control-plane
mutual TLS and writers of files at the test's paths are left out (`convert_confput`)."""
import json
import re

from harvest import Kind

# the whole configuration as one pretty-printed Jackson object: keep the `"<name>" : value` member only (a nested
# object spans lines up to its closing `  }`); the other members hold heap-sized defaults (maxExpectations, …) and
# values earlier cases of the same file set, neither of which the case is about
MEMBER = "(?s)\\A\\{\\n(?:.*?\\n)?  \"<name>\" : (\\{\\n.*?\\n  \\}|[^\\n]*?),?\\n.*\\z"
# the configuration without the member (a setter with no field of that name): the case is the status
WHOLE = {"regex": "(?s)\\A\\{\\n.*\\z", "replace": "<the configuration, which has no <name> member>"}
LENGTH = {"regex": "^content-length: \\d+$", "replace": "content-length: <the whole configuration>"}

# below these the next request the harness sends is refused (413, 431, 400 for the initial line)
LIMITS = {"maxRequestBodySize": 65536, "maxHeaderSize": 16384, "maxInitialLineLength": 8192}
# switched on, the control plane answers the harness 401 or wants a client certificate
AUTHENTICATION = ("controlPlaneJWTAuthenticationRequired", "controlPlaneOidcAuthenticationRequired",
                  "controlPlaneAuthorizationEnabled")
# so low that a server started with it refuses the readiness probe (its request line or headers are longer)
UNSTARTABLE = {"maxInitialLineLength": 8192, "maxHeaderSize": 64}
# switched on, the control plane takes only TLS connections with a client certificate (the auth_mtls scenarios)
MUTUAL_TLS = "controlPlaneTLSMutualAuthenticationRequired"
# set, these change every later answer of the server (headers stamped on each response): their cases get a file and
# server of their own, so that the rest of a test class's cases do not depend on them
OWN_SERVER = ("defaultResponseHeaders",)
# switched on, the server writes files at paths the test chose (relative to the replaying process)
WRITERS = ("persistExpectations", "persistRecordedExpectations", "persistRecordedRequestsToDisk", "outputMemoryUsageCsv",
           "watchInitializationJson")


# a file the test created in the harvesting JVM's temporary directory (`File.createTempFile`): the oracle never sees
# it, so the case is replayed with a path that exists nowhere, the same on every harvest
TEMPORARY = re.compile(r"^(?:/var/folders/|/tmp/|/private/var/folders/).*/(?:prefix\d+suffix|mockserver-[\w-]+?\d+\.\w+)$")


def portable(name, value):
    return "/does/not/exist/confput/" + name if isinstance(value, str) and TEMPORARY.match(value) else value


def locks(case):
    """Whether the case's value stops the server answering the harness's next request."""
    name, value = case["name"], case.get("value")
    if name in LIMITS:
        return isinstance(value, int) and not isinstance(value, bool) and value < LIMITS[name]
    return name in AUTHENTICATION and value is True


def property_value(value):
    return "true" if value is True else "false" if value is False else str(value)


def member_mask(name):
    return [{"regex": MEMBER.replace("<name>", name), "replace": '"' + name + '" : ${1}'},
            {"regex": WHOLE["regex"], "replace": WHOLE["replace"].replace("<name>", name)}, LENGTH]


def convert_confput(case):
    if "unserialisable" in case:
        return None, "unserialisable: " + case["unserialisable"]
    name, value = case["name"], portable(case["name"], case.get("value"))
    if name in WRITERS and value is True:
        return None, "switches on writing files at a path the test chose"
    if name in UNSTARTABLE and isinstance(value, int) and value < UNSTARTABLE[name]:
        return None, "a server with it refuses the harness's readiness probe, and every request after the PUT"
    if name == MUTUAL_TLS and value is True:
        return None, "switches on control-plane mutual TLS, which the harness's plain HTTP cannot reach"
    note = "configuration.{}({})".format(name, json.dumps(value))
    if "thrown" in case:
        note += ": throws {} in Java".format(case["thrown"])
    elif not case.get("noGetter") and case.get("read") != value:
        note += ": read back as {} in Java".format(json.dumps(case.get("read")))
    steps = [{"method": "PUT", "path": "/mockserver/configuration", "body": {name: value}, "note": note,
              "mask": member_mask(name)}]
    if locks(case):
        steps.append({"method": "GET", "path": "/mockserver/configuration", "note": "the value as read at startup",
                      "mask": member_mask(name)})
    return steps, None


def confput_properties(case):
    """A locking value starts a server of its own with it; every other case shares a server of its own per test class
    (`logLevel` at its default): the configuration a case puts survives `reset`, and a file recorded twice on the
    shared oracle would start its second recording with the first one's last values (a `defaultResponseHeaders` or
    CORS setting then changes every later answer)."""
    if locks(case):
        return {case["name"]: property_value(case.get("value"))}
    if case["name"] in OWN_SERVER:
        # its default, as a property: a file of its own, whose later cases a set value would otherwise reach
        return {"logLevel": "INFO", case["name"]: ""}
    return {"logLevel": "INFO"}


KINDS = [Kind("confput", "B4", convert_confput, source=("config", "confput"),
              properties=confput_properties)]
