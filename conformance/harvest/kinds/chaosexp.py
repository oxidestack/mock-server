"""Kinds `chaosexp`, `autohalt` and `chaosprofile` (B4 row 4): ChaosExperimentOrchestratorTest,
ChaosAutoHaltMonitorTest and ChaosProfileLibraryTest, recorded by `ChaosexpAdvice` in one run
(`target/harvest-b4/chaosexp`), one case per test method, through the `/mockserver/chaosExperiment…` endpoints, the
service/TCP chaos endpoints and requests to expectations whose `chaos` injects the fault a test records."""
import json
import urllib.parse

from harvest import Kind, control, reset

SOURCE = ("chaosexp", "chaosexp")
REGISTRY = {"ServiceChaosRegistry": "/mockserver/serviceChaos", "TcpChaosRegistry": "/mockserver/tcpChaos"}
EXPERIMENT = "/mockserver/chaosExperiment"
PROFILES = "/mockserver/chaosExperiment/profiles/"
# a clock advance of a test's own clock that a pause can stand for, and the most a case may pause in all
MAX_PAUSE_MILLIS = 5500
MAX_CASE_PAUSE_MILLIS = 6000
# how far behind a stage boundary of the server's own scheduler a pause lands
STAGE_MARGIN_MILLIS = 300
TTL_REMAINING = {"regex": "(\"ttlRemainingMillis\" : \\{[^}]*?\" : )\\d+", "replace": "$1<millis>"}
# the experiment status and history read the server's clock
EXPERIMENT_TIMES = {"regex": "(\"(?:stageElapsedMillis|stageRemainingMillis|totalElapsedMillis|startRemainingMillis|"
                             "terminatedAtMillis|windowFromEpochMillis|windowToEpochMillis)\" : )\\d+",
                    "replace": "$1<millis>"}
# the auto-halt counter only; every other line of the exposition is dropped
HALTS_ONLY = {"regex": "(?m)^(?:# (?:HELP|TYPE) )?(?!mock_server_chaos_auto_halt)[a-zA-Z_][a-zA-Z0-9_]*(?:\\{[^\\n]*\\})?(?: [^\\n]*)?\\n",
              "replace": ""}
EXPOSITION_LENGTH = {"regex": "^content-length: \\d+$", "replace": "content-length: <the whole exposition>"}
# the expectation `ChaosAutoHaltMonitor.recordError(type)` stands for: one whose chaos injects that fault (the
# action handler records each injected fault with the monitor)
FAULTS = {
    "error": {"errorStatus": 503, "errorProbability": 1.0},
    "drop": {"dropConnectionProbability": 1.0},
    "quota": {"quotaName": "harvested-autohalt-quota", "quotaLimit": 1, "quotaWindowMillis": 600000},
    "latency": {"latency": {"timeUnit": "MILLISECONDS", "value": 1}},
    "slow": {"slowResponseChunkSize": 4, "slowResponseChunkDelay": {"timeUnit": "MILLISECONDS", "value": 1}},
    "truncate": {"truncateBodyAtFraction": 0.5},
    "malformed": {"malformedBody": True},
    "graphql": {"graphqlErrors": True},
}
# a definition the profile library test's `isValidName` probes save under the name
PROBE_DEFINITION = {"name": "probe", "stages": [{"durationMillis": 1000, "profiles": {"probe.svc": {"errorStatus": 503}}}]}


def group_per_test(test_class):
    def group(lines):
        cases = []
        for call in lines:
            if call["test"].split("#")[0].rsplit(".", 1)[-1] != test_class:
                continue
            if cases and cases[-1]["test"] == call["test"]:
                cases[-1]["calls"].append(call)
            else:
                cases.append({"boundary": test_class, "test": call["test"], "calls": [call]})
        return cases
    return group


def is_fixture_reset(call):
    """A reset the test classes' @Before/@After make: of the registries, the process-wide monitor, the test's own
    orchestrator (its @After)."""
    return call["call"] == "reset" and (call["owner"] in REGISTRY or call["owner"] == "ChaosExperimentOrchestrator"
                                        or (call["owner"] == "ChaosAutoHaltMonitor" and call["shared"]))


def body_calls(case):
    """The calls of the test body: the fixture resets before the first other call and after the last are dropped."""
    calls = case["calls"]
    start, end = 0, len(calls)
    while start < end and is_fixture_reset(calls[start]):
        start += 1
    while end > start and is_fixture_reset(calls[end - 1]):
        end -= 1
    return calls[start:end]


def unserialisable(calls):
    if len({c.get("thread") for c in calls}) > 1:
        return "calls from several threads"
    for call in calls:
        if "unserialisable" in call:
            return "unserialisable: " + call["unserialisable"]
    return None


def registry_step(call):
    """A service/TCP chaos registry call as its endpoint (as kind `chaosreg`), or (None, reason); a call the registry
    ignores is (None, None)."""
    owner, method, args = call["owner"], call["call"], call["args"]
    path = REGISTRY[owner]
    note = owner + "." + method
    if not call["shared"]:
        return None, "a test's own " + owner
    if method == "put":
        if args[0] is None or args[1] is None:
            return None, None
        body = {"host": args[0], "chaos": args[1]}
        if len(args) > 2 and args[2] and args[2] > 0:
            body["ttlMillis"] = args[2]
        return {"method": "PUT", "path": path, "body": body, "note": note}, None
    if method == "remove":
        return ({"method": "PUT", "path": path, "body": {"host": args[0]}, "note": note}, None) if args[0] is not None else (None, None)
    if method == "reset":
        return {"method": "PUT", "path": path, "body": {"clear": True}, "note": note}, None
    if method == "patch":
        if args[0] is None or args[1] is None:
            return None, None
        return {"method": "PATCH", "path": path, "body": {"host": args[0], "chaos": args[1]}, "note": note}, None
    if method in ("get", "entries", "ttlRemainingMillis", "activeCount"):
        # the listing shows every live registration, which a lookup or a count reads
        return {"method": "GET", "path": path, "note": note, "mask": [TTL_REMAINING]}, None
    return None, owner + "." + method + " has no wire form"


class Faults:
    """The expectations of the faults a case injects, upserted on first use."""

    def __init__(self):
        self.upserted = set()

    def steps(self, fault):
        steps = []
        path = "/harvested/autohalt/" + fault
        if fault not in self.upserted:
            self.upserted.add(fault)
            steps.append(control("/mockserver/expectation", {"id": "harvested-autohalt-" + fault,
                                                              "httpRequest": {"path": path},
                                                              "httpResponse": {"statusCode": 200, "body": "harvested chaos response"},
                                                              "chaos": FAULTS[fault]},
                                 "the expectation whose chaos injects a {} fault".format(fault)))
            if fault == "quota":
                steps.append({"method": "GET", "path": path, "note": "the request the quota allows (no fault)"})
        steps.append({"method": "GET", "path": path, "note": "ChaosAutoHaltMonitor.recordError(\"{}\")".format(fault)})
        return steps


def monitor_settings(calls):
    """The auto-halt settings every monitor call of a case saw, or None when they differ."""
    seen = {(c["enabled"], c["threshold"], c["window"]) for c in calls
            if c["owner"] == "ChaosAutoHaltMonitor" and c["call"] in ("recordError", "getHaltCount", "currentWindowSize")}
    return seen.pop() if len(seen) == 1 else None if seen else ()


def halt_count_step():
    return {"method": "GET", "path": "/mockserver/metrics", "note": "ChaosAutoHaltMonitor.getHaltCount (the mock_server_chaos_auto_halt counter)",
            "mask": [HALTS_ONLY, EXPOSITION_LENGTH]}


def monitor_step(call, faults, monitors):
    """A ChaosAutoHaltMonitor call as steps, or (None, reason)."""
    monitors.add(call["identity"])
    if len(monitors) > 1:
        return None, "several auto-halt monitors in one test"
    method = call["call"]
    if method == "recordError":
        fault = call["args"][0]
        if fault is None or fault not in FAULTS:
            # ignored by the monitor, and not a fault the action handler injects
            return [], None
        return faults.steps(fault), None
    if method == "getHaltCount":
        return [halt_count_step()], None
    if method == "reset":
        # the server resets its monitor with everything else (the fault expectations are upserted again)
        faults.upserted.clear()
        return [dict(reset(), note="ChaosAutoHaltMonitor.reset (with the rest of the server)")], None
    if method in ("currentWindowSize", "setConfiguration"):
        # the window's size has no endpoint or gauge; a configuration is the file's properties
        return [], None
    return None, "ChaosAutoHaltMonitor." + method + " has no wire form"


def pause_step(millis, note):
    return {"sleepMillis": millis, "note": note}


# --- chaosprofile ---

def convert_chaosprofile(case):
    """`ChaosProfileLibrary` calls through the profile endpoints: `save(name, definition)` is `PUT
    …/chaosExperiment/profiles/<name>` (the name URL-encoded; a null definition no body), `list` `GET …/profiles`,
    `get` and `delete` `GET`/`DELETE …/profiles/<name>`. `isValidName(name)` saves a probe definition under the name
    and deletes it (a null name, which no path names, has no step). The server's library is not cleared by a reset, so a case ends deleting every name it saved."""
    calls = case["calls"]
    reason = unserialisable(calls)
    if reason:
        return None, reason
    steps = []
    saved = []
    for call in calls:
        method, args = call["call"], call["args"]
        note = "ChaosProfileLibrary." + method
        if method == "list":
            steps.append({"method": "GET", "path": PROFILES.rstrip("/"), "note": note})
            continue
        name = args[0]
        if name is None and method == "isValidName":
            # no path names a null name: the call has no step
            continue
        if name is None:
            return None, "a null profile name (no path names it)"
        path = PROFILES + urllib.parse.quote(name, safe="")
        if method == "save":
            step = {"method": "PUT", "path": path, "note": note}
            if args[1] is not None:
                step["body"] = args[1]
            steps.append(step)
            saved.append(path)
        elif method == "get":
            steps.append({"method": "GET", "path": path, "note": note})
        elif method == "delete":
            steps.append({"method": "DELETE", "path": path, "note": note})
        elif method == "isValidName":
            steps.append({"method": "PUT", "path": path, "body": PROBE_DEFINITION, "note": note + " (a save under the name)"})
            saved.append(path)
        else:
            return None, "unknown call " + method
    for path in dict.fromkeys(saved):
        steps.append({"method": "DELETE", "path": path, "note": "the library outlives a reset: remove what the case saved"})
    return steps, None


# --- autohalt ---

def convert_autohalt(case):
    """The monitor a test builds is the server's own (one per case): `recordError(type)` is a request to an
    expectation whose `chaos` injects that fault (`error` 503, `drop`, `quota` past a one-request quota, `latency`,
    `slow`, `truncate`, `malformed`, `graphql`; a null or unknown type, which the monitor ignores, no request);
    `getHaltCount` is the `mock_server_chaos_auto_halt` counter (`GET /mockserver/metrics`, the file's server started
    with `metricsEnabled`); the enabled flag, threshold and window the monitor read (static or from an installed
    configuration) are the file's properties. The registries are their endpoints. The test's clock moving forward by up
    to 5.5 s is a pause. The monitor's own `reset` is `PUT /mockserver/reset` (the server resets it only with everything
    else; the auto-halt counter is process-wide and keeps its count). No wire form: calls from several threads (their
    clock readings are not in order) and a second monitor. `currentWindowSize` (no endpoint or gauge) is not read
    back.

    Adapted by hand after recording: a long file (over 20 steps) none of whose cases advances the test's
    clock, with a 10 s window, has `chaosAutoHaltWindowMillis` 600000 in its properties (the file keeps its name).
    Upstream makes all of a case's calls at one instant of its clock, so no fault leaves the window there; replayed
    in real time on a loaded machine, a hundred requests can outlast 10 s and the earlier faults would leave it. Its
    halts and counts are unchanged. Pipelining the requests instead is no fix: the oracle drops requests pipelined
    behind a slow-response fault's answer. Re-apply it after a re-harvest."""
    calls = body_calls(case)
    reason = unserialisable(calls)
    if reason:
        return None, reason
    if monitor_settings(calls) is None:
        return None, "the auto-halt settings change within the test"
    steps = []
    faults = Faults()
    monitors = set()
    now = None
    paused = 0
    for call in calls:
        if call["owner"] in REGISTRY:
            step, why = registry_step(call)
            if why:
                return None, why
            if step:
                steps.append(step)
            continue
        if call["owner"] != "ChaosAutoHaltMonitor":
            return None, "unexpected call " + call["boundary"]
        if call["shared"] and call["call"] != "recordError":
            return None, "the process-wide monitor read back"
        if now is not None and call["now"] > now:
            pause = call["now"] - now
            if pause > MAX_PAUSE_MILLIS or paused + pause > MAX_CASE_PAUSE_MILLIS:
                return None, "the test's clock advances {} ms (no pause stands for it)".format(pause)
            paused += pause
            steps.append(pause_step(pause, "the test's clock advances {} ms".format(pause)))
        if not call["shared"]:
            now = call["now"]
        more, why = monitor_step(call, faults, monitors)
        if more is None:
            return None, why
        steps.extend(more)
    if not steps:
        return None, "no call with a wire form"
    return steps, None


def autohalt_properties(case):
    settings = monitor_settings(body_calls(case))
    props = {"metricsEnabled": "true"}
    if settings:
        enabled, threshold, window = settings
        props.update({"chaosAutoHaltEnabled": str(enabled).lower(), "chaosAutoHaltErrorThreshold": str(threshold),
                      "chaosAutoHaltWindowMillis": str(window)})
    return props


# --- chaosexp ---

class Model:
    """What the server's orchestrator is doing, as far as the converter needs to know: none, scheduled or running,
    the current stage and the test-clock time the stage (or the scheduled start) is due."""

    def __init__(self):
        self.state, self.definition, self.stage, self.due, self.started_at = "none", None, 0, None, None


def convert_chaosexp(case):
    """The test's orchestrator is the server's: `start(definition)` is `PUT /mockserver/chaosExperiment` with the
    definition's JSON (a null definition no body), `getStatus` `GET …/chaosExperiment` and `getHistory` `GET
    …/chaosExperiment/history` (the server's clock readings masked), `stop` `DELETE …/chaosExperiment`, `reset` `PUT
    /mockserver/reset`. `ExperimentDefinition.fromJson(json)` is that JSON started, read back and stopped. A stage
    advance (`advanceNow`) or deferred start (`triggerScheduledStartNow`) is a pause until the server's own scheduler
    has made it, when the test's clock moved to the stage's end (or the start time) by at most 5.5 s; on an
    orchestrator with nothing scheduled or running both are no-ops, without a step. Registry calls are their
    endpoints, the process-wide auto-halt monitor's `recordError` the injected fault (as kind `autohalt`). Every file's
    server runs with `sloTrackingEnabled`, as the test class sets. No wire form: SLO samples a test records at
    hand-chosen times (`SloSampleStore.record`) and `checkSloNow` (which only such samples make interesting), an
    advance before the stage's end or past the pause limit."""
    calls = body_calls(case)
    reason = unserialisable(calls)
    if reason:
        return None, reason
    if monitor_settings(calls) is None:
        return None, "the auto-halt settings change within the test"
    if len({c["identity"] for c in calls if c["owner"] == "ChaosExperimentOrchestrator"}) > 1:
        return None, "several orchestrators in one test"
    steps = []
    faults = Faults()
    model = Model()
    lag = None
    paused = 0

    def pause_until(now, note):
        nonlocal lag, paused
        pause = now - (lag if lag is not None else model.started_at)
        if lag is None:
            pause += STAGE_MARGIN_MILLIS
        if pause > MAX_PAUSE_MILLIS or paused + pause > MAX_CASE_PAUSE_MILLIS:
            return "the test's clock advances {} ms (no pause stands for it)".format(pause)
        paused += pause
        lag = now
        steps.append(pause_step(pause, note))
        return None

    for call in calls:
        owner, method, args = call["owner"], call["call"], call["args"]
        if owner in REGISTRY:
            step, why = registry_step(call)
            if why:
                return None, why
            if step:
                steps.append(step)
            continue
        if owner == "SloSampleStore":
            return None, "SLO samples recorded at hand-chosen times"
        if owner == "ChaosAutoHaltMonitor":
            if not call["shared"] or method != "recordError":
                return None, "ChaosAutoHaltMonitor." + method + " in an orchestrator test"
            more, why = monitor_step(call, faults, set())
            if more is None:
                return None, why
            steps.extend(more)
            continue
        note = owner + "." + method
        if owner == "ExperimentDefinition":
            if model.state != "none":
                return None, "fromJson while an experiment runs"
            steps.append({"method": "PUT", "path": EXPERIMENT, "body": args[0], "note": note + " (the definition started)"})
            steps.append({"method": "GET", "path": EXPERIMENT, "note": note + " (read back)", "mask": [EXPERIMENT_TIMES]})
            steps.append({"method": "DELETE", "path": EXPERIMENT, "note": note + " (stopped)"})
            continue
        if method == "start":
            definition = args[0]
            step = {"method": "PUT", "path": EXPERIMENT, "note": note}
            if definition is not None:
                definition = dict(definition)
                if definition.get("name") is None:
                    definition.pop("name", None)
                step["body"] = definition
            steps.append(step)
            if call.get("result") is None and definition is not None:
                model.definition = definition
                model.started_at = call["now"]
                lag = None
                if definition.get("startDelayMillis", 0) > 0 or definition.get("cronSchedule"):
                    if definition.get("cronSchedule"):
                        model.state, model.due = "scheduled", None
                    else:
                        model.state, model.due = "scheduled", call["now"] + definition["startDelayMillis"]
                else:
                    model.state, model.stage = "running", 0
                    model.due = call["now"] + definition["stages"][0]["durationMillis"]
        elif method == "getStatus":
            steps.append({"method": "GET", "path": EXPERIMENT, "note": note, "mask": [EXPERIMENT_TIMES]})
        elif method == "getHistory":
            steps.append({"method": "GET", "path": EXPERIMENT + "/history", "note": note + " (the endpoint lists up to 50)",
                          "mask": [EXPERIMENT_TIMES]})
        elif method == "stop":
            steps.append({"method": "DELETE", "path": EXPERIMENT, "note": note})
            model.state = "none"
        elif method == "reset":
            steps.append(dict(reset(), note=note))
            model.state = "none"
        elif method == "checkSloNow":
            return None, "checkSloNow (SLO samples at hand-chosen times)"
        elif method == "triggerScheduledStartNow":
            if model.state != "scheduled":
                continue
            if model.due is None:
                return None, "a cron start (the server's wall clock decides when)"
            if call["now"] < model.due:
                return None, "a deferred start forced before its time"
            why = pause_until(call["now"], note + " (the server's scheduler starts it)")
            if why:
                return None, why
            model.state, model.stage = "running", 0
            model.due = call["now"] + model.definition["stages"][0]["durationMillis"]
        elif method == "advanceNow":
            if model.state == "none":
                continue
            if model.state != "running" or call["now"] < model.due:
                return None, "a stage advanced before its end"
            why = pause_until(call["now"], note + " (the server's scheduler ends the stage)")
            if why:
                return None, why
            stages = model.definition["stages"]
            if model.stage + 1 < len(stages):
                model.stage += 1
            elif model.definition.get("loop"):
                model.stage = 0
            else:
                model.state = "none"
                continue
            model.due = call["now"] + stages[model.stage]["durationMillis"]
        else:
            return None, "unknown call " + note
    if not steps:
        return None, "no call with a wire form"
    return steps, None


def chaosexp_properties(case):
    props = {"sloTrackingEnabled": "true"}
    settings = monitor_settings(body_calls(case))
    if settings and any(c["owner"] == "ChaosAutoHaltMonitor" for c in body_calls(case)):
        enabled, threshold, window = settings
        props.update({"chaosAutoHaltEnabled": str(enabled).lower(), "chaosAutoHaltErrorThreshold": str(threshold),
                      "chaosAutoHaltWindowMillis": str(window)})
    return props


KINDS = [
    Kind("chaosprofile", "B4", convert_chaosprofile, source=SOURCE, group=group_per_test("ChaosProfileLibraryTest"),
         per_test=True, own_file="-default"),
    Kind("autohalt", "B4", convert_autohalt, source=SOURCE, group=group_per_test("ChaosAutoHaltMonitorTest"),
         properties=autohalt_properties, per_test=True, own_file="-default"),
    Kind("chaosexp", "B4", convert_chaosexp, source=SOURCE, group=group_per_test("ChaosExperimentOrchestratorTest"),
         properties=chaosexp_properties, per_test=True, own_file="-default"),
]
