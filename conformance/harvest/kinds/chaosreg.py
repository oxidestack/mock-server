"""Kind `chaosreg` (B4): `ServiceChaosRegistry` and `TcpChaosRegistry` calls of the registry tests
(ServiceChaosRegistryTest, ServiceChaosRegistryPatchTest, TcpChaosRegistryTest), one case per test method, through
`/mockserver/serviceChaos` and `/mockserver/tcpChaos`."""
from harvest import Kind

ENDPOINT = {"service": "/mockserver/serviceChaos", "tcp": "/mockserver/tcpChaos"}
# a TTL's remaining milliseconds count down between the PUT and the GET
TTL_REMAINING = {"regex": "(\"ttlRemainingMillis\" : \\{[^}]*?\" : )\\d+", "replace": "$1<millis>"}
# `activeCountByFaultType` of the service registry is the `mock_server_active_service_chaos` gauge; every other line
# of the exposition (timings, JVM-free process figures, other gauges) is dropped
GAUGE_ONLY = {"regex": "(?m)^(?:# (?:HELP|TYPE) )?(?!mock_server_active_service_chaos\\b)[a-zA-Z_][a-zA-Z0-9_]*(?:\\{[^\\n]*\\})?(?: [^\\n]*)?\\n",
              "replace": ""}
EXPOSITION_LENGTH = {"regex": "^content-length: \\d+$", "replace": "content-length: <the whole exposition>"}
METRICS = {"metricsEnabled": "true"}


def group_chaosreg(lines):
    """The recorded calls of one test method, in order, as one case."""
    cases = []
    for call in lines:
        if cases and cases[-1]["test"] == call["test"]:
            cases[-1]["calls"].append(call)
        else:
            cases.append({"boundary": "ChaosRegistry", "test": call["test"], "calls": [call]})
    return cases


def convert_chaosreg(case):
    """The server has one registry of each kind, so a test may use one registry of each kind only (its own instance or
    the process-wide one: without a TTL a test's own clock is never read). `put(host, profile[, ttl])` is `PUT` with
    `host`, `chaos` (the profile's DTO) and `ttlMillis` when positive, `remove(host)` `PUT` with the host alone,
    `reset` `PUT {"clear": true}` (but not the @After reset of the process-wide registry in a test that uses its own),
    `patch` `PATCH`; `get`, `entries` and `ttlRemainingMillis` read the registry back
    with `GET` (the endpoint lists every live registration under its normalised host, which is what a lookup
    resolves against). The service registry's `activeCountByFaultType` is its Prometheus gauge (`GET
    /mockserver/metrics`, the file's server started with `metricsEnabled`). Calls the registries ignore (a null host
    or profile) have no step. A TTL on a test's own registry runs on the test's clock, which the server cannot
    follow."""
    calls = case["calls"]
    # the test classes' @After resets the process-wide registry, which a test using its own never touched otherwise
    own = {c["registry"] for c in calls if not c["shared"]}
    calls = [c for c in calls if not (c["shared"] and c["call"] == "reset" and c["registry"] in own)]
    for kind in ENDPOINT:
        if len({c["identity"] for c in calls if c["registry"] == kind}) > 1:
            return None, "several {} chaos registries in one test".format(kind)
    steps = []
    for call in calls:
        if "unserialisable" in call:
            return None, "unserialisable: " + call["unserialisable"]
        kind, method, args = call["registry"], call["call"], call["args"]
        path = ENDPOINT[kind]
        note = ("ServiceChaosRegistry." if kind == "service" else "TcpChaosRegistry.") + method
        if method == "put":
            host, profile = args[0], args[1]
            ttl = args[2] if len(args) > 2 else 0
            if host is None or profile is None:
                continue
            if ttl and not call["shared"]:
                return None, "TTL on a test's own registry (its injected clock)"
            body = {"host": host, "chaos": profile}
            if ttl and ttl > 0:
                body["ttlMillis"] = ttl
            steps.append({"method": "PUT", "path": path, "body": body, "note": note})
        elif method == "remove":
            if args[0] is None:
                continue
            steps.append({"method": "PUT", "path": path, "body": {"host": args[0]}, "note": note})
        elif method == "reset":
            steps.append({"method": "PUT", "path": path, "body": {"clear": True}, "note": note})
        elif method == "patch":
            if args[0] is None or args[1] is None:
                continue
            steps.append({"method": "PATCH", "path": path, "body": {"host": args[0], "chaos": args[1]}, "note": note})
        elif method in ("get", "entries", "ttlRemainingMillis"):
            if method == "get" and args[0] is None:
                continue
            steps.append({"method": "GET", "path": path, "note": note, "mask": [TTL_REMAINING]})
        elif method == "activeCountByFaultType" and kind == "service":
            steps.append({"method": "GET", "path": "/mockserver/metrics", "note": note + " (the mock_server_active_service_chaos gauge)",
                          "mask": [GAUGE_ONLY, EXPOSITION_LENGTH]})
        elif method in ("activeCountByFaultType", "activeCount"):
            return None, "TcpChaosRegistry.{}: no endpoint or gauge reports it".format(method)
        else:
            return None, "unknown call " + method
    if not any(s["method"] != "PUT" or "clear" not in s.get("body", {}) for s in steps):
        return None, "no call with a wire form"
    return steps, None


def chaosreg_properties(case):
    """`metricsEnabled` for a case that reads the active-chaos gauge."""
    if any(c["call"] == "activeCountByFaultType" and c["registry"] == "service" for c in case["calls"]):
        return dict(METRICS)
    return None


KINDS = [Kind("chaosreg", "B4", convert_chaosreg, group=group_chaosreg, properties=chaosreg_properties,
              per_test=True, own_file="-default")]
