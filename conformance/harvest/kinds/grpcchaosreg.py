"""Kind `grpcchaosreg` (B4): `GrpcChaosRegistry` calls of GrpcChaosRegistryTest, one case per test method,
through `/mockserver/grpcChaos`."""
from harvest import Kind

PATH = "/mockserver/grpcChaos"
# a TTL's remaining milliseconds count down between the PUT and the GET
TTL_REMAINING = {"regex": "(\"ttlRemainingMillis\" : \\{[^}]*?\" : )\\d+", "replace": "$1<millis>"}


def group_grpcchaosreg(lines):
    """The recorded calls of one test method, in order, as one case."""
    cases = []
    for call in lines:
        if cases and cases[-1]["test"] == call["test"]:
            cases[-1]["calls"].append(call)
        else:
            cases.append({"boundary": "GrpcChaosRegistry", "test": call["test"], "calls": [call]})
    return cases


def convert_grpcchaosreg(case):
    """The server has one gRPC chaos registry, so a test may use one registry only (its own instance or the
    process-wide one: without a TTL a test's own clock is never read). `put(service, profile[, ttl])` is `PUT` with
    `service`, `chaos` (the profile's DTO) and `ttlMillis` when positive, `remove(service)` `PUT` with the service
    alone, `reset` `PUT {"clear": true}` (but not the @After reset of the process-wide registry in a test that uses its
    own), `patch` `PATCH`; `get`, `entries`, `ttlRemainingMillis` and `activeCount` read the registry back with `GET`
    (the endpoint lists every live registration under its normalised service name, which is what a lookup resolves
    against, and their number is `activeCount`). Calls the registry ignores (a null service or profile) have no step.
    A TTL on a test's own registry runs on the test's clock, which the server cannot follow. `incrementMatchCount` is
    counted by gRPC calls to a service with a count-window profile only, and `activeCountByFaultType` has no endpoint
    or gauge."""
    calls = case["calls"]
    # the test class's @After resets the process-wide registry, which a test using its own never touched otherwise
    own = any(not c["shared"] for c in calls)
    calls = [c for c in calls if not (c["shared"] and c["call"] == "reset" and own)]
    if len({c["identity"] for c in calls}) > 1:
        return None, "several gRPC chaos registries in one test"
    steps = []
    for call in calls:
        if "unserialisable" in call:
            return None, "unserialisable: " + call["unserialisable"]
        method, args = call["call"], call["args"]
        note = "GrpcChaosRegistry." + method
        if method == "put":
            service, profile = args[0], args[1]
            ttl = args[2] if len(args) > 2 else 0
            if service is None or profile is None:
                continue
            if ttl and not call["shared"]:
                return None, "TTL on a test's own registry (its injected clock)"
            body = {"service": service, "chaos": profile}
            if ttl and ttl > 0:
                body["ttlMillis"] = ttl
            steps.append({"method": "PUT", "path": PATH, "body": body, "note": note})
        elif method == "remove":
            if args[0] is None:
                continue
            steps.append({"method": "PUT", "path": PATH, "body": {"service": args[0]}, "note": note})
        elif method == "reset":
            steps.append({"method": "PUT", "path": PATH, "body": {"clear": True}, "note": note})
        elif method == "patch":
            if args[0] is None or args[1] is None:
                continue
            steps.append({"method": "PATCH", "path": PATH, "body": {"service": args[0], "chaos": args[1]}, "note": note})
        elif method in ("get", "entries", "ttlRemainingMillis", "activeCount"):
            if method == "get" and args[0] is None:
                continue
            steps.append({"method": "GET", "path": PATH, "note": note, "mask": [TTL_REMAINING]})
        elif method == "incrementMatchCount":
            return None, "GrpcChaosRegistry.incrementMatchCount: counted only by gRPC calls under a count-window profile"
        elif method == "activeCountByFaultType":
            return None, "GrpcChaosRegistry.activeCountByFaultType: no endpoint or gauge reports it"
        else:
            return None, "unknown call " + method
    if not any(s["method"] != "PUT" or "clear" not in s.get("body", {}) for s in steps):
        return None, "no call with a wire form"
    return steps, None


KINDS = [Kind("grpcchaosreg", "B4", convert_grpcchaosreg, group=group_grpcchaosreg, per_test=True,
              own_file="-default")]
