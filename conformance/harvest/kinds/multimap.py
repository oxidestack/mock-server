"""Kind `multimap`: the contain-all algorithm of the `collections` tests (`SubSetMatcherTest`,
`NottableString{MultiMap,HashMap}ContainAllTest`), harvested by a run of its own:

  mvn -q test -Dharvest.tests='org/mockserver/collections/**/*Test.java' -Dharvest.dir=target/harvest-b4/multimap

`MultimapAdvice` lifts each outermost call to a request matcher and the request it is looked for in, written by
`HttpRequestSerializer`: multi-valued maps (and `containsSubset`'s entries) as `queryStringParameters`, with the
matcher's key match style, single-valued ones as `cookies`. Converted like the default `match` kind: an expectation
with the matcher and the actual request on the data plane, or, when the maps were built for the control plane, the
actual stored as an expectation and the matcher used as a retrieve filter. A side holding a schema cannot be sent
as a request and stays unconvertible ("matcher-shaped query/cookie")."""
from harvest import Kind, convert_match


def convert_multimap(case):
    steps, reason = convert_match(case)
    if steps is not None:
        expected = "contains" if case.get("result") else "does not contain"
        steps[-1]["note"] = f"{steps[-1].get('note', '')} ({case['boundary']}: actual {expected} matcher)"
    return steps, reason


KINDS = [Kind("multimap", "B4", convert_multimap)]
