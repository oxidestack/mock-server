"""Kind `ssrf` (B4): `InetAddressValidator.validateForwardTarget(Configuration, String host)`."""
from harvest import Kind, control

PATH = "/harvested-ssrf"
# the forwarded request's own headers, whose order the oracle does not keep stable (as in w2_forward_ssrf)
HEADERS_MASK = {"regex": "\"[Hh]ost\" : \\[ \"[^\"]*\" \\],\\s*\"content-length\" : \\[ \"0\" \\]"
                         "|\"content-length\" : \\[ \"0\" \\],\\s*\"[Hh]ost\" : \\[ \"[^\"]*\" \\]",
                "replace": "<received request headers>", "reason": "header order of the received request"}

# The oracle logs the request matching the expectation once or twice, the second entry anywhere after the refusal
# (seen in about half the runs of a case): every `request: … matched expectation: …` entry is dropped.
_SEPARATOR = "------------------------------------"
_IN_ENTRY = "(?:(?!" + _SEPARATOR + ")[\\s\\S])*?"  # never across an entry separator
_MATCH_ENTRY = "[^\\n]* - request:\\n" + _IN_ENTRY + "\\n matched expectation:\\n\\n  \\{" + _IN_ENTRY + "\\n  \\}\\n"
MATCH_ENTRIES_MASK = {"regex": _SEPARATOR + "\\n" + _MATCH_ENTRY + "\\s*$|" + _MATCH_ENTRY + "(?:\\n" + _SEPARATOR + "\\n)?",
                      "replace": "", "reason": "the oracle logs a second match of the request only now and then"}


def convert_ssrf(case):
    """An `httpForward` to the host on a server started with `forwardProxyBlockPrivateNetworks`, the request it
    answers, then the log of that request (the refusal names the host and the blocked range). Only refused calls are
    replayed: an allowed host would really be connected to."""
    if "unserialisable" in case:
        return None, "unserialisable: " + case["unserialisable"]
    if not case.get("enabled"):
        return None, "forwardProxyBlockPrivateNetworks off: the forward would connect to the host"
    if case.get("testLookup"):
        return None, "the test replaced the host lookup (lookupOnThisThread)"
    if not case.get("thrown"):
        return None, "allowed: the forward would connect to the host"
    host = case.get("host")
    if not host or not host.strip():
        return None, "blank host"
    expectation = {"httpRequest": {"path": PATH}, "httpForward": {"host": host, "port": 8080}}
    request = {"method": "GET", "path": PATH, "note": "validateForwardTarget: " + case["thrown"].rsplit(".", 1)[-1]}
    log = control("/mockserver/retrieve?type=LOGS", {"path": PATH}, "log")
    log["mask"] = ["^content-length: \\d+$", HEADERS_MASK, MATCH_ENTRIES_MASK]
    put = control("/mockserver/expectation", expectation, "httpForward")
    put["maxMillis"] = 30000  # the first expectation on a freshly started property-scoped oracle can take over 10 s
    return [put, request, log], None


def ssrf_properties(case):
    return {"forwardProxyBlockPrivateNetworks": "true"}


KINDS = [Kind("ssrf", "B4", convert_ssrf, properties=ssrf_properties)]
