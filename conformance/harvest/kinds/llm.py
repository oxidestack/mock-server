"""Kinds `llmcodec`, `llmhandler`, `llmmatch` (B4): the LLM provider codecs, the action handler and the
conversation matcher, all from one harvest run (`<in>/llm/`)."""
import json

from harvest import Kind, RETRIEVE_ACTIVE, control, request_steps


# The generated parts of LLM answers (ids, creation times, Ollama durations), masked as the hand-written llm_*
# scenarios mask them; the content length follows the ids' and timestamps' lengths.
LLM_MASKS = [
    {"regex": "\"(msg|toolu|chatcmpl|call|resp|fc|rs|item|msg_bdrk|modr)_?-?[A-Za-z0-9]{8,}\"", "replace": "\"<id>\""},
    {"regex": "\"created\":\\d+", "replace": "\"created\":<time>"},
    {"regex": "\"created_at\":\\d+", "replace": "\"created_at\":<time>"},
    {"regex": "\"created_at\":\"[^\"]+\"", "replace": "\"created_at\":\"<time>\""},
    # master's Responses objects carry the completion time too
    {"regex": "\"completed_at\":\\d+", "replace": "\"completed_at\":<time>"},
    # the oracle listens on 1080, so the harness normalises an embedding's `"index":1080` (a request of over 1080
    # inputs) to `<port>` in its answers only
    {"regex": "\"index\":<port>", "replace": "\"index\":1080"},
    {"regex": "\"(total|load|prompt_eval|eval)_duration\":\\d+", "replace": "\"d\":0"},
    {"regex": "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z", "replace": "<ts>"},
    {"regex": "content-length: \\d+", "replace": "content-length: <n>"},
]
LLM_EXPECTATION_ID = "harvested-llm"
LLM_STRESS_CALLS = 50


def llm_expectation(llm, http_request, note):
    """The action as the only expectation (a fixed id, so the next call of a sequence replaces it) and its echo."""
    return [control("/mockserver/expectation", {"id": LLM_EXPECTATION_ID, "httpRequest": http_request, "httpLlmResponse": llm}, note),
            control(RETRIEVE_ACTIVE, "", "echo")]


def llm_request(request_json, body=None):
    """The data-plane request that reaches the action: the recorded request (path `/harvested` when it has none), or
    `POST /harvested` with `body`. Returns (expectation matcher, step) or (None, reason)."""
    if request_json is None:
        step = {"method": "POST", "path": "/harvested"}
        if body is not None:
            step["body"] = body
    else:
        actual = json.loads(request_json)
        if "path" not in actual:
            actual["path"] = "/harvested"
        if "method" not in actual:
            actual["method"] = "POST"
        step, reason = request_steps(actual)
        if step is None:
            return None, reason
    step["note"] = "request"
    step["mask"] = LLM_MASKS
    return {"path": step["path"].split("?", 1)[0]}, step


def convert_llmcodec(case):
    """A provider codec call: `encode(completion, model)`, `encodeStreaming(completion, model, physics)` (the completion
    with `streaming` and the physics given), `encodeEmbedding(embedding, input[, model])` (a request whose `input` is
    the text) and `encodeRerank(rerank, documents)` (a request carrying the `documents`) become the `httpLlmResponse`
    that makes the action handler call the codec the same way, and a request that reaches it."""
    if "unserialisable" in case:
        return None, "unserialisable"
    call = case["call"]
    if call == "decode":
        return None, "decode (ParsedConversation has no wire form of its own)"
    llm = case["llm"]
    body = None
    if call == "encodeStreaming":
        if llm.get("completion") is None:
            return None, "streaming encode of a null completion"
        completion = dict(llm["completion"], streaming=True)
        completion.pop("streamingPhysics", None)
        if case.get("physics") is not None:
            completion["streamingPhysics"] = case["physics"]
        llm = dict(llm, completion=completion)
    elif call == "encode":
        if llm.get("completion") is None:
            return None, "encode of a null completion"
        if llm["completion"].get("streaming"):
            # the handler would stream it; the codec's non-streaming encode has no other wire form
            llm = dict(llm, completion={k: v for k, v in llm["completion"].items() if k not in ("streaming", "streamingPhysics")})
    elif call == "encodeEmbedding":
        if llm.get("embedding") is None:
            return None, "null embedding"
        body = json.dumps({"input": case["input"]}) if case.get("input") is not None else None
    elif call == "encodeRerank":
        if llm.get("rerank") is None:
            return None, "null rerank"
        if case.get("documents") is not None:
            if any(not isinstance(d, str) for d in case["documents"]):
                return None, "null document"
            body = json.dumps({"documents": case["documents"]})
    matcher, step = llm_request(None, body)
    return llm_expectation(llm, matcher, case["call"]) + [step], None


def group_llmhandler(lines):
    """Kind `llmhandler`: one test method's handler calls, in order, as one case (quotas, seeded chaos and the
    Responses store carry state from one call to the next)."""
    cases = []
    for call in lines:
        if cases and cases[-1]["test"] == call["test"]:
            cases[-1]["calls"].append(call)
        else:
            cases.append({"boundary": "HttpLlmResponseActionHandler", "test": call["test"], "calls": [call]})
    for case in cases:
        if len(case["calls"]) > LLM_STRESS_CALLS:
            # a concurrency loop: its distinct calls, in a stable order (the threads interleave differently each run)
            distinct = {json.dumps(c, sort_keys=True): c for c in case["calls"]}
            case["calls"] = [distinct[k] for k in sorted(distinct)]
    return cases


def convert_llmhandler(case):
    """Each handler call is its `httpLlmResponse` as the only expectation, then its request (`POST /harvested` when
    the call has none: `chaosErrorResponseOrNull`)."""
    steps = []
    for call in case["calls"]:
        if "unserialisable" in call:
            return None, "unserialisable"
        if call.get("llm") is None:
            return None, "null action"
        matcher, step = llm_request(call.get("request"))
        if matcher is None:
            return None, step
        steps += llm_expectation(call["llm"], matcher, call["call"]) + [step]
    return steps, None


def convert_llmmatch(case):
    """`LlmConversationMatcher.matches(request)`: the matcher as the `conversationPredicates` of an expectation that
    answers a fixed completion, then the request (404 when it does not match)."""
    if "unserialisable" in case:
        return None, "unserialisable"
    llm = dict(case["llm"], completion={"text": "matched"})
    matcher, step = llm_request(case.get("request"))
    if matcher is None:
        return None, step
    return llm_expectation(llm, matcher, "conversation predicates") + [step], None


def llm_properties(case):
    """The server an LLM case runs on: the configuration differences recorded with its call(s)."""
    props = {}
    for call in case.get("calls", [case]):
        for name, value in (call.get("configuration") or {}).items():
            props.setdefault(name, value)
    return props or None


KINDS = [
    Kind("llmcodec", "B4", convert_llmcodec, source=("llm", "llmcodec"), properties=llm_properties, own_file="-default"),
    Kind("llmhandler", "B4", convert_llmhandler, source=("llm", "llmhandler"), group=group_llmhandler,
         properties=llm_properties, per_test=True, own_file="-default"),
    Kind("llmmatch", "B4", convert_llmmatch, source=("llm", "llmmatch"), properties=llm_properties, own_file="-default"),
]
