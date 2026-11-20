"""Kinds `ratelimit`, `loadreg`, `loadorch`, `loadgen`, `loadfeeder` and `slo` (B4 row 10): the load, SLO and rate-limit
classes of mockserver-core, recorded by `LoadAdvice` in one run (`target/harvest-b4/load`), one case per test method."""
import json
import urllib.parse

from harvest import Kind, control, request_steps, reset

SOURCE_DIR = "load"
# the epoch second a window or bucket resets, and a 60 s window's seconds left
RATE_LIMIT_MASK = [{"regex": "x-ratelimit-reset: \\d+", "replace": "x-ratelimit-reset: <epoch seconds>"},
                   {"regex": "^retry-after: (59|60)$", "replace": "retry-after: <seconds left in the window>"}]
# a clock advance of a test's own clock that a pause can stand for
MAX_PAUSE_MILLIS = 2000
DEFAULTS = {"rateLimitMaxNamedQuotas": 10000, "loadGenerationEnabled": "false", "loadGenerationMaxVirtualUsers": "50",
            "loadGenerationMaxInFlightRequests": "200", "loadGenerationMaxRequestsPerSecond": "500",
            "loadGenerationMaxDurationMillis": "3600000", "loadGenerationMaxSteps": "50", "loadGenerationMaxRate": "5000.0",
            "loadGenerationMaxStages": "20", "loadGenerationMaxConcurrentScenarios": "10",
            "loadGenerationSuppressEventLog": "true", "sloTrackingEnabled": "false"}


def group_per_test(lines):
    """The recorded calls of one test method, in order, as one case."""
    cases = []
    for call in lines:
        if cases and cases[-1]["test"] == call["test"]:
            cases[-1]["calls"].append(call)
        else:
            cases.append({"boundary": call["boundary"], "test": call["test"], "calls": [call]})
    return cases


def unserialisable(case):
    for call in case["calls"]:
        if "unserialisable" in call:
            return "unserialisable: " + call["unserialisable"]
    return None


# --- ratelimit ---

def convert_ratelimit(case):
    """`RateLimitRegistry.tryAcquire(rateLimit, fallbackKey)` is a request to an expectation whose `rateLimit` is that
    rate limit and whose id is the fallback key (the key HttpActionHandler passes): `harvested-rl-<key>` on
    `/harvested/<key>`, a null rate limit an expectation without one. A named rate limit counts under its name, so it
    gets an expectation of its own, `harvested-rl-<key>-<name>` (upstream keeps an expectation's first rate limit when
    the expectation is updated by id, the oracle confirms). An allowed acquisition answers 200, a refused one 429 with
    the X-RateLimit headers. `reset()` is `PUT
    /mockserver/reset` (which upstream's `HttpState.reset` passes on to the registry), after which the expectations are
    upserted again. The test's own clock moving forward by up to 2 s is a pause; a longer advance, or a null
    fallback key (an expectation always has an id), has no wire form."""
    reason = unserialisable(case)
    if reason:
        return None, reason
    calls = case["calls"]
    if len({c["identity"] for c in calls}) > 1:
        return None, "several rate-limit registries in one test"
    steps = []
    upserted = {}
    now = calls[0]["now"]
    for call in calls:
        pause = call["now"] - now
        now = call["now"]
        if pause > MAX_PAUSE_MILLIS:
            return None, "the test's clock advances {} ms (no pause stands for it)".format(pause)
        if call["call"] == "reset":
            steps.append(dict(reset(), note="RateLimitRegistry.reset()"))
            upserted = {}
            continue
        key, limit = call["key"], call["rateLimit"]
        if key is None:
            return None, "a null fallback key (an expectation always has an id)"
        name = key + ("-" + limit["name"] if limit and limit.get("name") is not None else "")
        if upserted.get(name, "absent") != limit:
            expectation = {"id": "harvested-rl-" + name, "httpRequest": {"path": "/harvested/" + name},
                           "httpResponse": {"statusCode": 200}}
            if limit is not None:
                expectation["rateLimit"] = limit
            steps.append(control("/mockserver/expectation", expectation, "the rate-limited expectation"))
            upserted[name] = limit
        if pause > 0:
            steps.append({"sleepMillis": pause, "note": "the test's clock advances {} ms".format(pause)})
        steps.append({"method": "GET", "path": "/harvested/" + name, "note": "RateLimitRegistry.tryAcquire", "mask": RATE_LIMIT_MASK})
    return pipelined(steps), None


def pipelined(steps):
    """Acquisitions the test makes at one instant of its clock (no pause or upsert between them) are pipelined on one
    connection (`"pipeline": n` on the first), so the real time between them is the server's own handling only: a
    token bucket must not refill between them, however loaded the machine."""
    out, run = [], []
    def flush():
        if len(run) > 1:
            run[0] = dict(run[0], pipeline=len(run))
        out.extend(run)
        run.clear()
    for step in steps:
        if step.get("note") == "RateLimitRegistry.tryAcquire":
            run.append(step)
        else:
            flush()
            out.append(step)
    flush()
    return out


def ratelimit_properties(case):
    """The named-counter cap a test set (`rateLimitMaxNamedQuotas`)."""
    caps = {c["rateLimitMaxNamedQuotas"] for c in case["calls"]} - {DEFAULTS["rateLimitMaxNamedQuotas"]}
    return {"rateLimitMaxNamedQuotas": str(caps.pop())} if caps else None


# --- loadreg ---

LOAD_SCENARIO = "/mockserver/loadScenario"
# a run's live measurements and times (as kind `handle` masks them)
_RUN_FIELDS = ("elapsedMillis|currentVus|requestsSent|succeeded|failed|droppedIterations|errorRate|startedAt|endedAt"
               "|startedAtEpochMillis|endedAtEpochMillis|durationMillis|p50|p95|p99|p999|p50Millis|p95Millis|p99Millis|p999Millis")
LOAD_RUN = [{"regex": '"(' + _RUN_FIELDS + ')" : -?[0-9][0-9.E-]*', "replace": '"$1" : <run>'}]
# a step and a profile for a registry definition that has none: the endpoint validates before it registers
LOADABLE_STEPS = [{"request": {"path": "/harvested"}}]
LOADABLE_PROFILE = {"stages": [{"type": "VU", "vus": 1, "durationMillis": 1000}]}


def scenario_path(name):
    return LOAD_SCENARIO + "/" + urllib.parse.quote(name, safe="")


def convert_loadreg(case):
    """`LoadScenarioRegistry` is the store behind the loadScenario endpoints: `load(name, definition)` is `PUT
    /mockserver/loadScenario` (the endpoint registers a definition under its own `name`, so the body's name is the
    key; a definition without steps or profile, which the endpoint's validation refuses before it registers, gets a
    minimal step and profile), `get` and `contains` `GET /mockserver/loadScenario/<name>` (404 when absent), `list`
    `GET /mockserver/loadScenario`, `delete` `DELETE /mockserver/loadScenario/<name>`, `clear` `DELETE
    /mockserver/loadScenario`."""
    reason = unserialisable(case)
    if reason:
        return None, reason
    if len({c["identity"] for c in case["calls"]}) > 1:
        return None, "several load scenario registries in one test"
    # each test builds a fresh registry; the server's survives `PUT /mockserver/reset` (the oracle confirms)
    steps = [{"method": "DELETE", "path": LOAD_SCENARIO, "note": "a fresh registry"}]
    for call in case["calls"]:
        method, args = call["call"], call["args"]
        note = "LoadScenarioRegistry." + method
        if method == "load":
            definition = dict(args[1]) if isinstance(args[1], dict) else None
            if definition is None or args[0] is None:
                return None, "load without a definition object"
            definition["name"] = args[0]
            if not definition.get("steps"):
                definition["steps"] = LOADABLE_STEPS
            if not definition.get("profile"):
                definition["profile"] = LOADABLE_PROFILE
            steps.append(control(LOAD_SCENARIO, definition, note))
        elif method in ("get", "contains"):
            steps.append({"method": "GET", "path": scenario_path(args[0]), "note": note, "mask": LOAD_RUN})
        elif method == "list":
            steps.append({"method": "GET", "path": LOAD_SCENARIO, "note": note, "mask": LOAD_RUN})
        elif method == "delete":
            steps.append({"method": "DELETE", "path": scenario_path(args[0]), "note": note})
        elif method == "clear":
            steps.append({"method": "DELETE", "path": LOAD_SCENARIO, "note": note})
        else:
            return None, "unknown call " + method
    return steps, None


# --- loadorch ---

def configuration_properties(configuration):
    """The load-generation and SLO values of a recorded configuration that differ from the startup defaults."""
    return {name: value for name, value in (configuration or {}).items() if DEFAULTS.get(name) != value} or None


def convert_loadorch(case):
    """`LoadScenarioOrchestrator.validate(scenario)` and `start(scenario, sender)` with the test's sender: the
    validation the loadScenario endpoint runs before it registers, so each is `PUT /mockserver/loadScenario` with
    the scenario (`LoadScenarioSerializer`): 400 with the error, or the scenario loaded, read back with `GET
    /mockserver/loadScenario/<name>`. A start refused by the concurrent-scenario cap (an error `start` adds after
    validating) needs real runs: every start of that test is the load and `PUT /mockserver/loadScenario/start`, on a
    server with load generation enabled. What a run then does (the traffic the test's own sender sees, its clock,
    VU counts, checks, captures, feeders, pacing, thresholds and metrics) is not replayed."""
    reason = unserialisable(case)
    if reason:
        return None, reason
    calls = case["calls"]
    runs = any(c["call"] == "start" and "concurrently active" in (c.get("error") or "") for c in calls)
    steps = []
    for call in calls:
        note = "LoadScenarioOrchestrator." + call["call"]
        if call.get("scenario") is None:
            return None, "a null scenario (the endpoint needs a body)"
        scenario = json.loads(call["scenario"])
        name = scenario.get("name")
        validation = call.get("error") and "concurrently active" not in call["error"]
        steps.append(control(LOAD_SCENARIO, call["scenario"], note + " (validation)"))
        if runs and call["call"] == "start" and not validation:
            steps.append(control(LOAD_SCENARIO + "/start", {"name": name}, note))
        elif not call.get("error") and isinstance(name, str) and name.strip():
            steps.append({"method": "GET", "path": scenario_path(name), "note": note + " (the definition loaded)", "mask": LOAD_RUN})
    return steps, None


def loadorch_properties(case):
    """The caps a test set (the orchestrator's configuration), and load generation for a case that starts runs."""
    props = {}
    for call in case["calls"]:
        for name, value in (configuration_properties(call.get("configuration")) or {}).items():
            props.setdefault(name, value)
    if any(c["call"] == "start" and "concurrently active" in (c.get("error") or "") for c in case["calls"]):
        props["loadGenerationEnabled"] = "true"
    return props or None


# --- loadgen ---

# a target on port 1080 is the oracle's own container port, which the harness turns into `<port>` in the oracle's
# answers only; another port checks the same override (as kind `handle` does)
ORACLE_PORT = 1080
RECORDED_LENGTH = {"regex": "^content-length: \\d+$", "replace": "content-length: <varies with the socket addresses>"}


def convert_loadgen(case):
    """`LoadScenarioFromRecording.generate(name, recorded, mode, maxSteps, target, profile)`: the recorded requests
    sent to the data plane (the event log's RECEIVED_REQUEST entries are what the endpoint converts), then `PUT
    /mockserver/loadScenario/generateFromRecording` with the other arguments. `LoadScenarioFromOpenAPI.generate(name,
    spec, target, profile)`: `PUT /mockserver/loadScenario/generateFromOpenAPI`. A null recorded list has no wire form
    (the endpoint always converts a list). Only the first generation of a test (each is a load under the same name)
    is kept when one test generates several."""
    reason = unserialisable(case)
    if reason:
        return None, reason
    steps = []
    for call in case["calls"]:
        body = {"name": call["name"]}
        target = call.get("target")
        if target is not None:
            target = dict(target)
            if target.get("port") == ORACLE_PORT:
                target["port"] = ORACLE_PORT + 1
            body["target"] = target
        if call.get("profile") is not None:
            body["profile"] = call["profile"]
        if call["generator"] == "LoadScenarioFromRecording":
            if call.get("recorded") is None:
                return None, "a null recorded list (the endpoint always converts a list)"
            for request in call["recorded"]:
                step, why = request_steps(request)
                if step is None:
                    return None, why
                step["note"] = "a recorded request"
                steps.append(step)
            if call.get("mode") is not None:
                body["mode"] = call["mode"]
            if call.get("maxSteps") is not None:
                body["maxSteps"] = call["maxSteps"]
            steps.append(dict(control(LOAD_SCENARIO + "/generateFromRecording", body, "LoadScenarioFromRecording.generate"),
                              mask=[RECORDED_LENGTH]))
            # the next generation of the same test converts its own recording only
            steps.append(dict(reset(), note="the next generation's recording starts empty"))
        else:
            if call.get("specUrlOrPayload") is None:
                return None, "a null spec"
            body["specUrlOrPayload"] = call["specUrlOrPayload"]
            steps.append(control(LOAD_SCENARIO + "/generateFromOpenAPI", body, "LoadScenarioFromOpenAPI.generate"))
    if steps and steps[-1].get("path") == "/mockserver/reset":
        steps.pop()
    return steps, None


# --- loadfeeder ---

def convert_loadfeeder(case):
    """`LoadFeeder.resolvedRows()` called by a test directly (outermost: the orchestrator's own calls belong to its
    `validate`/`start`). The loadScenario endpoint's validation resolves a scenario's feeder, so a feeder whose
    dataset fails to resolve is `PUT /mockserver/loadScenario` with a scenario carrying that feeder (and a minimal
    step and profile): 400 with the feeder's error. Rows that do resolve are seen only in the requests of a run."""
    reason = unserialisable(case)
    if reason:
        return None, reason
    steps = []
    for call in case["calls"]:
        if "thrown" not in call:
            return None, "resolved feeder rows (seen only in a run's requests)"
        scenario = json.loads(call["scenario"])
        scenario["steps"] = LOADABLE_STEPS
        scenario["profile"] = LOADABLE_PROFILE
        steps.append(control(LOAD_SCENARIO, scenario, "LoadFeeder.resolvedRows (through the scenario's validation)"))
    return steps, None


# --- slo ---

def convert_slo(case):
    """`SloEvaluator.evaluate(criteria)` is `PUT /mockserver/verifySLO` with the criteria (`SloCriteriaSerializer`) on
    a server with SLO tracking enabled, when the sample store is empty. Samples the test placed in the store itself
    (`SloSampleStore.record` with a hand-chosen timestamp and latency) have no wire form: the server records the
    arrival time and the measured latency of real forwarded traffic."""
    reason = unserialisable(case)
    if reason:
        return None, reason
    steps = []
    for call in case["calls"]:
        if call["storeSize"]:
            return None, "samples recorded by the test at hand-chosen timestamps and latencies"
        if not call.get("sharedStore"):
            return None, "an evaluator over a test's own sample store"
        steps.append(control("/mockserver/verifySLO", call["criteria"], "SloEvaluator.evaluate"))
    return steps, None


def slo_properties(case):
    tracking = {c.get("sloTrackingEnabled") for c in case["calls"]}
    return {"sloTrackingEnabled": "true"} if "true" in tracking else None


KINDS = [
    Kind("ratelimit", "B4", convert_ratelimit, source=(SOURCE_DIR, "ratelimit"), group=group_per_test,
         properties=ratelimit_properties, per_test=True, own_file="-default"),
    Kind("loadreg", "B4", convert_loadreg, source=(SOURCE_DIR, "loadreg"), group=group_per_test,
         per_test=True, own_file="-default"),
    Kind("loadorch", "B4", convert_loadorch, source=(SOURCE_DIR, "loadorch"), group=group_per_test,
         properties=loadorch_properties, per_test=True, own_file="-default"),
    Kind("loadgen", "B4", convert_loadgen, source=(SOURCE_DIR, "loadgen"), group=group_per_test,
         per_test=True, own_file="-default"),
    Kind("loadfeeder", "B4", convert_loadfeeder, source=(SOURCE_DIR, "loadfeeder"), group=group_per_test,
         per_test=True, own_file="-default"),
    Kind("slo", "B4", convert_slo, source=(SOURCE_DIR, "slo"), group=group_per_test,
         properties=slo_properties, per_test=True, own_file="-default"),
]
