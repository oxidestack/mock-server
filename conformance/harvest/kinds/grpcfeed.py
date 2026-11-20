"""gRPC kind `grpcfeed` (B4): `IncrementalGrpcFrameDecoder.feed`, harvested by a run of its own into
target/harvest-b4/grpcfeed/ (the classes that construct the decoder, with `-Dharvest.workdir` as for the other gRPC
kinds, see pom.xml):

    mvn -q test -Dharvest.tests='org/mockserver/grpc/IncrementalGrpcFrameDecoderTest.java,org/mockserver/grpc/GrpcMessageSizeConfigurationTest.java' \
        -Dharvest.workdir=<core> -Dharvest.dir=<abs>/target/harvest-b4/grpcfeed

The data plane's decoder is `GrpcBidiStreamHandler`'s, one per bidi-streaming call, fed one HTTP/2 DATA frame at a
time. So one case is one decoder's feeds in order, replayed as a bidi call on the greeting service's `Chat` method
whose DATA frames (the `dataFrames` step option) are those chunks, on a server with grpcBidiStreamingEnabled and the
decoder's maxGrpcMessageSize. The expectation answers each decoded message with one fixed message, so the answer shows
how many messages were reassembled, and the trailers show a decoder failure (or a message that is no `ChatRequest`).
"""
import base64
import importlib.util
import os

from harvest import Kind, control

# kinds/grpc.py's step helpers (a kind module is loaded by path, not as a package member).
_spec = importlib.util.spec_from_file_location("harvest_kinds.grpc_helpers", os.path.join(os.path.dirname(__file__), "grpc.py"))
_grpc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_grpc)
clear, greeting, call = _grpc.clear, _grpc.greeting, _grpc.call

CHAT = "/com.example.grpc.GreetingService/Chat"
DEFAULT_MAX_MESSAGE_SIZE = 4 * 1024 * 1024


def data_plane_cap(max_message_size):
    """`IncrementalGrpcFrameDecoder.defaultMaxBufferSize`: the cap of every decoder the data plane builds."""
    return max(8 * 1024 * 1024, max_message_size * 2)


def group(lines):
    """One case per decoder (test method and identity), its feeds in call order."""
    cases = {}
    for line in lines:
        key = (line["test"], line["decoder"])
        case = cases.setdefault(key, {"boundary": line["boundary"], "test": line["test"], "maxBufferSize": line["maxBufferSize"],
                                      "maxGrpcMessageSize": line["maxGrpcMessageSize"], "chunks": [], "outcomes": []})
        case["chunks"].append(line.get("chunk"))
        case["outcomes"].append(line.get("message") if "thrown" in line else line.get("messages"))
    for case in cases.values():
        case["input"] = repr(case["chunks"])
    return list(cases.values())


def convert(case):
    """A decoder's feeds -> the bidi call whose DATA frames are its chunks (a null chunk is an empty DATA frame)."""
    fed = sum(len(base64.b64decode(c or "")) for c in case["chunks"])
    if case["maxBufferSize"] != data_plane_cap(case["maxGrpcMessageSize"]) and fed > min(case["maxBufferSize"], 8 * 1024 * 1024):
        return None, "a buffer cap the data plane never builds (max(8 MiB, 2 x maxGrpcMessageSize)), reached by the fed bytes"
    expectation = control("/mockserver/expectation", {
        "httpRequest": {"path": CHAT},
        "grpcBidiResponse": {"statusName": "OK", "rules": [
            {"matchJson": ".*", "responses": [{"json": "{\"greeting\": \"decoded\"}"}]}]}},
        "expectation: one answer per decoded message")
    step = call(CHAT, None, "IncrementalGrpcFrameDecoder.feed: one DATA frame per fed chunk")
    step["dataFrames"] = [c or "" for c in case["chunks"]]
    return [clear(), greeting(), expectation, step], None


def properties(case):
    props = {"grpcBidiStreamingEnabled": "true"}
    if case["maxGrpcMessageSize"] != DEFAULT_MAX_MESSAGE_SIZE:
        props["maxGrpcMessageSize"] = str(case["maxGrpcMessageSize"])
    return props


KINDS = [Kind("grpcfeed", "B4", convert, group=group, properties=properties, per_test=True)]
