"""Kind `vtimes`: `VerificationTimes` (`verify/VerificationTimesTest`), harvested by a run of its own:

  mvn -q test -Dharvest.tests='org/mockserver/verify/**/*Test.java' -Dharvest.dir=target/harvest-b4/vtimes

A `matches(count)` call is `count` requests to one path and `PUT /mockserver/verify` with the instance's bounds as
VerificationTimesDTOSerializer writes them (an unbounded -1 omitted): 202 when it matches, else 406 with the
`toString()` wording. A `toString()` call is the same with a count the bounds refuse (when there is one), so the 406
shows the text. A factory that threw is the verify body whose DTO builds `between(atLeast, atMost)`; `exactly`,
`atLeast` and `atMost` of a negative count have no JSON form (-1 is the form's unbounded sentinel, and the client
writes no other negative number for them)."""
from harvest import Kind, control

PATH = "/verificationTimes"


def _times(at_least, at_most):
    times = {}
    if at_least != -1:
        times["atLeast"] = at_least
    if at_most != -1:
        times["atMost"] = at_most
    return times


def _steps(at_least, at_most, count, note):
    steps = [{"method": "GET", "path": PATH, "note": f"request {i + 1} of {count}"} for i in range(count)]
    steps.append(control("/mockserver/verify", {"httpRequest": {"path": PATH}, "times": _times(at_least, at_most)}, note))
    return steps


def _refused_count(at_least, at_most):
    """A request count the bounds refuse, or the lowest count when every count matches."""
    if at_least > 0:
        return at_least - 1
    if at_most != -1:
        return at_most + 1
    return 0


def convert_vtimes(case):
    call = case["call"]
    if call == "matches":
        if case["count"] < 0 or case["count"] > 20:
            return None, "request count outside 0..20"
        return _steps(case["atLeast"], case["atMost"], case["count"], f"matches({case['count']}) of {case['result']}"), None
    if call == "toString":
        count = _refused_count(case["atLeast"], case["atMost"])
        if count > 20:
            return None, "request count outside 0..20"
        return _steps(case["atLeast"], case["atMost"], count, f"toString() \"{case['result']}\""), None
    if call == "factory":
        if case["method"] != "between":
            return None, "negative count of exactly/atLeast/atMost (no JSON form)"
        at_least, at_most = case["arg0"], case["arg1"]
        body = {"httpRequest": {"path": PATH}, "times": {"atLeast": at_least, "atMost": at_most}}
        return [control("/mockserver/verify", body, f"between({at_least}, {at_most}) threw {case.get('message')}")], None
    return None, "unknown call " + call


KINDS = [Kind("vtimes", "B4", convert_vtimes)]
