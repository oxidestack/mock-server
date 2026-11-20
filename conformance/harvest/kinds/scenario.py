"""Kind `scenario` (B4): `ScenarioManager` calls of the scenario manager tests (ScenarioManagerTest,
ScenarioManagerCompositeKeyTest, ScenarioTimedTransitionTest), one case per test method, through the scenario
endpoints and probe expectations."""
import urllib.parse

from harvest import Kind, reset

# a test's isolation value travels in this header; a scenario name used with an isolation value carries the
# `LlmScenarioNames` marker naming it, so that `RequestMatchers.extractIsolationKey` reads it
ISOLATION_HEADER = "x-harvest-isolation"
ISOLATION_MARKER = "__iso=header:" + ISOLATION_HEADER
PROBE_ID = "harvested-scenario-probe"
PROBE_PATH = "/harvested-scenario"
ANCHOR_ID = "harvested-scenario-anchor"
ANCHOR_PATH = "/harvested-scenario-anchor"
# a timed transition fires `transitionAfterMs` after the PUT; the next step waits this much longer
TRANSITION_MARGIN_MILLIS = 400
# the concurrency stress tests make thousands of racing calls; their wire form would be as many requests
MAX_CALLS = 100
# calls that change nothing when an argument is null (ScenarioManager's own guards)
NAME_AND_VALUE = {"setState", "transitionState"}


def group_scenario(lines):
    """The recorded calls of one test method, in order, as one case."""
    cases = []
    for call in lines:
        if cases and cases[-1]["test"] == call["test"]:
            cases[-1]["calls"].append(call)
        else:
            cases.append({"boundary": "ScenarioManager", "test": call["test"], "calls": [call]})
    return cases


def split(call):
    """(name, isolation, rest) of a call's arguments: the single-argument overloads have no isolation."""
    args = call["args"]
    composite = {"getState": 2, "setState": 3, "matchesState": 3, "matchesAndTransition": 4, "transitionState": 3}
    if call["call"] in composite:
        if len(args) == composite[call["call"]]:
            return args[0], args[1], args[2:]
        return args[0], None, args[1:]
    return (args[0] if args else None), None, args[1:]


def scenario_path(name):
    """The scenario endpoints take the name from the raw path, undecoded (`%3D` stays in the name): characters a
    request line carries as they are stay unescaped, so that the endpoint names the scenario an expectation names."""
    return "/mockserver/scenario/" + urllib.parse.quote(name, safe=":@!$&'()*+,;=-._~[]")


def convert_scenario(case):
    """A test's one ScenarioManager is the server's. `setState` without isolation is `PUT /mockserver/scenario/<name>`,
    `getState` without isolation `GET /mockserver/scenario/<name>`, with isolation (and `getAllStates`, structured or
    not) the listing `GET /mockserver/scenario`, whose `name[isolation]` keys show every isolated state. Matching is a
    probe expectation (upserted under one id when it changes) and a request to it, answered 200 when the gate passes:
    `matchesState` is `scenarioName`+`scenarioState`, `matchesAndTransition` adds `newScenarioState`, and
    `transitionState`/`setState` with isolation is `scenarioName`+`newScenarioState` (`RequestMatchers`' unconditional
    entry-state transition). A name used with an isolation value anywhere in the test carries the isolation marker
    everywhere; the isolation value is a header of the probe request. `clear(name)` is removing the scenario's last
    expectation (`RequestMatchers.clearOrphanedScenarioState`): the probe when it names the scenario, else an anchor
    expectation added and cleared by id. `reset` is `PUT /mockserver/reset`. A timed
    transition whose guard holds is `PUT /mockserver/scenario/<name>` with its `nextState` and `transitionAfterMs`
    (setting the state it already has), followed by a pause; one whose guard fails changes nothing. Calls that
    ScenarioManager ignores (a null name or value; `matchesAndTransition` with a name and a new state but no required
    state, true without a transition; cancelling transitions a synchronous scheduler already ran) have no step; a
    null-guarded match is a probe with the fields that are not null, which passes the gate the same way."""
    calls = case["calls"]
    if len({c["manager"] for c in calls}) > 1:
        return None, "several ScenarioManager instances in one test"
    if len(calls) > MAX_CALLS:
        return None, "concurrency stress test ({} calls on {} threads)".format(len(calls), len({c["thread"] for c in calls}))
    isolated = set()
    for call in calls:
        if "unserialisable" in call:
            return None, "unserialisable: " + call["unserialisable"]
        name, isolation, _ = split(call)
        if isolation is not None and name is not None:
            isolated.add(name)

    def wire(name):
        return name + ISOLATION_MARKER if name in isolated else name

    steps = []
    probe = None
    pause = 0

    def add(step):
        nonlocal pause
        if pause:
            steps.append({"sleepMillis": pause})
            pause = 0
        steps.append(step)

    def probe_request(expectation, isolation, note):
        nonlocal probe
        if expectation != probe:
            probe = expectation
            add({"method": "PUT", "path": "/mockserver/expectation", "body": dict(expectation), "note": note + " (probe expectation)"})
        step = {"method": "GET", "path": PROBE_PATH, "note": note}
        if isolation is not None:
            step["headers"] = {ISOLATION_HEADER: isolation}
        add(step)

    def expectation(**fields):
        e = {"id": PROBE_ID, "httpRequest": {"path": PROBE_PATH}}
        e.update({k: v for k, v in fields.items() if v is not None})
        e["httpResponse"] = {"statusCode": 200, "body": "probe matched"}
        return e

    for call in calls:
        kind = call["call"]
        name, isolation, rest = split(call)
        note = "ScenarioManager." + kind
        if kind in NAME_AND_VALUE:
            if name is None or rest[0] is None:
                continue
            if kind == "setState" and isolation is None:
                add({"method": "PUT", "path": scenario_path(wire(name)), "body": {"state": rest[0]}, "note": note})
            else:
                probe_request(expectation(scenarioName=wire(name), newScenarioState=rest[0]), isolation, note)
        elif kind == "getState":
            if name is None:
                continue
            if isolation is None:
                add({"method": "GET", "path": scenario_path(wire(name)), "note": note})
            else:
                add({"method": "GET", "path": "/mockserver/scenario", "note": note + " (with isolation: the listing)"})
        elif kind in ("getAllStates", "getAllStatesStructured"):
            add({"method": "GET", "path": "/mockserver/scenario", "note": note})
        elif kind in ("matchesState", "matchesAndTransition"):
            new_state = rest[1] if kind == "matchesAndTransition" else None
            if name is not None and rest[0] is None and new_state is not None:
                # true without a transition, where an expectation would transition unconditionally
                continue
            if name is None:
                # an expectation without a scenario name neither gates nor transitions; neither does the manager
                probe_request(expectation(scenarioState=rest[0], newScenarioState=new_state), isolation, note)
                continue
            probe_request(expectation(scenarioName=wire(name), scenarioState=rest[0], newScenarioState=new_state), isolation, note)
        elif kind == "reset":
            add(dict(reset(), note=note))
            probe = None
        elif kind == "clear":
            if name is None:
                continue
            if probe is not None and probe.get("scenarioName") == wire(name):
                add({"method": "PUT", "path": "/mockserver/clear", "body": {"id": PROBE_ID}, "note": note + " (the probe, the last expectation of the scenario)"})
                probe = None
            else:
                add({"method": "PUT", "path": "/mockserver/expectation", "body": dict(expectation(scenarioName=wire(name)), id=ANCHOR_ID, httpRequest={"path": ANCHOR_PATH}),
                     "note": note + " (an expectation of the scenario)"})
                add({"method": "PUT", "path": "/mockserver/clear", "body": {"id": ANCHOR_ID}, "note": note + " (removing it)"})
        elif kind == "scheduleTransition":
            transition = call["args"][0]
            if not str(call["args"][1]).endswith(":true"):
                return None, "scheduleTransition on an asynchronous scheduler"
            if transition.get("scenarioName") is None or call.get("stateBefore") != transition.get("currentState"):
                continue
            body = {"state": transition["currentState"], "nextState": transition["nextState"],
                    "transitionAfterMs": transition["transitionAfterMs"]}
            add({"method": "PUT", "path": scenario_path(wire(transition["scenarioName"])), "body": body, "note": note})
            pause = transition["transitionAfterMs"] + TRANSITION_MARGIN_MILLIS
        elif kind in ("cancelPendingTransition", "cancelAllPendingTransitions"):
            continue
        else:
            return None, "unknown call " + kind
    if not any("method" in s for s in steps):
        return None, "no call with a wire form"
    return steps, None


KINDS = [Kind("scenario", "B4", convert_scenario, group=group_scenario, per_test=True)]
