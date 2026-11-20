"""gRPC kinds (B4): mockserver-core's `org.mockserver.grpc` boundaries, all harvested by one run into
target/harvest-b4/grpc/ (see the `harvest.workdir` comment in pom.xml), each converted into the gRPC call that reaches
the boundary on the wire: native gRPC as cleartext HTTP/2 steps (`"h2": true`), gRPC-Web over HTTP/1.1.

Every case starts from `PUT /mockserver/grpc/clear` (a reset keeps the descriptor store) and uploads the descriptor
set it needs: the one the store held (rebuilt by the advice), or upstream's greeting.dsc (`tests/files/grpc/`) for
the kinds that need any gRPC method to call.
"""
from harvest import Kind, control

SOURCE = "grpc"
GREETING = "/com.example.grpc.GreetingService/Greeting"
EMPTY_FRAME = "AAAAAAA="  # a gRPC frame holding an empty message
REFLECTION = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"


def clear():
    return {"method": "PUT", "path": "/mockserver/grpc/clear", "note": "no descriptors"}


def descriptors(base64, note="descriptor set"):
    return {"method": "PUT", "path": "/mockserver/grpc/descriptors", "bodyBase64": base64, "note": note}


def greeting():
    return {"method": "PUT", "path": "/mockserver/grpc/descriptors", "bodyFile": "grpc/greeting.dsc",
            "note": "greeting descriptor"}


def call(path, body=EMPTY_FRAME, note="gRPC call", content_type="application/grpc", headers=None):
    """A native gRPC call over h2c; `content_type` None sends none."""
    h = {"content-type": content_type} if content_type is not None else {}
    h["te"] = "trailers"
    h.update(headers or {})
    step = {"h2": True, "method": "POST", "path": path, "headers": h, "trailers": True, "binaryBody": True, "note": note}
    if body is not None:
        step["bodyBase64"] = body
    return step


def web_call(path, note="gRPC-Web call"):
    return {"method": "POST", "path": path, "headers": {"content-type": "application/grpc-web"}, "bodyBase64": EMPTY_FRAME,
            "binaryBody": True, "note": note}


def expectation(response, path=GREETING, note="expectation"):
    return control("/mockserver/expectation", {"httpRequest": {"path": path}, "httpResponse": response}, note)


def convert_reflect(case):
    """`handleReflectionRequest(body)` -> the store's descriptor set, then the body sent to the v1 reflection method."""
    if "unserialisable" in case:
        return None, "descriptor store not serialisable"
    if not case.get("descriptorSet"):
        return None, "empty descriptor store (the reflection handler is installed only while descriptors are loaded)"
    return [clear(), descriptors(case["descriptorSet"]),
            call(REFLECTION, case.get("body"), "GrpcServerReflectionHandler.handleReflectionRequest")], None


STATUS_NO_CALLER = {
    "fromCode": "GrpcStatusMapper.fromCode has no data-plane caller in 8.0.0",
    "fromHttpStatus": "GrpcStatusMapper.fromHttpStatus has no data-plane caller in 8.0.0",
    "stripControlCharacters": "GrpcStatusMapper.stripControlCharacters is reached only from a gRPC forward's upstream grpc-message",
}


def convert_status(case):
    """Each `GrpcStatusMapper` static -> the gRPC answer that applies it to the argument."""
    method = case["method"]
    if method in STATUS_NO_CALLER:
        return None, STATUS_NO_CALLER[method]
    value = case.get("value")
    note = "GrpcStatusMapper." + method
    if method in ("percentEncodeMessage", "percentDecodeMessage"):
        headers = {"grpc-status": ["2"]}
        if value is not None:
            headers["grpc-message"] = [value]
        steps = [clear(), greeting(), expectation({"headers": headers}, note="expectation: grpc-message is the argument")]
        if method == "percentEncodeMessage":
            return steps + [call(GREETING, note=note + ": the grpc-message trailer")], None
        return steps + [web_call(GREETING, note=note + ": the gRPC-Web trailer frame")], None
    if method == "fromName":
        headers = {"grpc-status-name": [value]} if value is not None else {}
        return [clear(), greeting(), expectation({"headers": headers}, note="expectation: grpc-status-name is the argument"),
                call(GREETING, note=note + ": the grpc-status trailer")], None
    if method == "fromHttpTransportStatus":
        return [clear(), greeting(), expectation({"statusCode": case["code"]}, note="expectation: the HTTP status is the argument"),
                call(GREETING, note=note + ": the grpc-status trailer")], None
    if method == "isGrpcContentType":
        return [clear(), greeting(),
                expectation({"headers": {"grpc-status": ["0"]}, "body": {"greeting": "hello"}}, note="expectation: a gRPC answer"),
                call(GREETING, note=note + ": the request content-type is the argument", content_type=value)], None
    return None, "GrpcStatusMapper." + method + " not converted"


def convert_timeout(case):
    """`parseNanos(value)` -> a call with `grpc-timeout: value` to an expectation delayed past the parsed deadline (by
    700 ms) or by 300 ms when upstream reads the value as absent or as longer than 5 s."""
    value = case.get("value")
    if value is None:
        return None, "no grpc-timeout header (a null value)"
    nanos = case.get("nanos")
    millis = 300 if nanos is None or nanos >= 5_000_000_000 else nanos // 1_000_000 + 700
    response = {"headers": {"grpc-status": ["0"]}, "body": {"greeting": "hello"},
                "delay": {"timeUnit": "MILLISECONDS", "value": millis}}
    return [clear(), greeting(), expectation(response, note=f"expectation delayed {millis} ms"),
            call(GREETING, note="GrpcTimeout.parseNanos: grpc-timeout is the argument", headers={"grpc-timeout": value})], None


def convert_descriptors(case):
    """`loadDescriptorSet(bytes)` / `loadDescriptorSetFromPath(path)` -> the earlier set and the new one uploaded, then
    the services listing."""
    before = case.get("before") or ""
    if before.startswith("unserialisable"):
        return None, "descriptor store not serialisable"
    if "body" not in case:
        return None, "descriptor file not readable (a missing path has no request body)"
    steps = [clear()]
    if before:
        steps.append(descriptors(before, "descriptors loaded before"))
    steps.append(descriptors(case["body"], case["boundary"]))
    steps.append({"method": "PUT", "path": "/mockserver/grpc/services", "note": "services"})
    return steps, None


def convert_synth(case):
    """`synthesizeJson(message)` -> a bodiless expectation on a method returning that message, and the call."""
    if "message" not in case:
        return None, "null descriptor"
    if "unserialisable" in case:
        return None, "descriptor not serialisable"
    package = case.get("package")
    path = "/" + (package + "." if package else "") + "HarvestSynth/Get"
    return [clear(), descriptors(case["descriptorSet"], "the message's file with service HarvestSynth"),
            expectation({}, path, "expectation without a body"),
            call(path, note="GrpcExampleSynthesizer.synthesizeJson: " + case["message"])], None


def web_request(content_type, body_base64=None, text=None, note="gRPC-Web call"):
    """A gRPC-Web call over HTTP/1.1 with `content_type` (None sends none) and either raw bytes or a text body."""
    step = {"method": "POST", "path": GREETING, "headers": {}, "binaryBody": True, "note": note}
    if content_type is not None:
        step["headers"]["content-type"] = content_type
    if body_base64 is not None:
        step["bodyBase64"] = body_base64
    if text is not None:
        step["body"] = text
    return step


def empty_frame_for(content_type):
    """An empty-message frame as the content-type carries it: base64 text for a -text type, bytes otherwise."""
    if "text" in (content_type or "").lower():
        return {"text": EMPTY_FRAME}
    return {"body_base64": EMPTY_FRAME}


WEB_ANSWER = {"headers": {"grpc-status": ["0"]}, "body": {"greeting": "hello"}}


def convert_web(case):
    """Each `GrpcWebTranslator` static -> the gRPC-Web call that applies it to the arguments."""
    method, args = case["method"], case["args"]
    note = "GrpcWebTranslator." + method
    if method == "parseTrailerFrame":
        return None, "GrpcWebTranslator.parseTrailerFrame has no data-plane caller in 8.0.0"
    if method == "decodeRequestBody":
        body, content_type = args
        if body is None:
            return None, "no request body (a null body)"
        call_step = web_request(content_type, body["bytes"], note=note + ": the request body and content-type")
        return [clear(), greeting(), expectation(WEB_ANSWER, note="expectation: a gRPC answer"), call_step], None
    if method in ("isGrpcWebContentType", "isGrpcWebTextContentType", "responseContentType"):
        content_type = args[0]
        call_step = web_request(content_type, note=note + ": the request content-type", **empty_frame_for(content_type))
        return [clear(), greeting(), expectation(WEB_ANSWER, note="expectation: a gRPC answer"), call_step], None
    if method in ("buildTrailerFrame", "encodeResponseBody"):
        if method == "encodeResponseBody":
            frames, rest, text = args[0], args[1:-1], args[-1]
            if frames is not None and frames.get("bytes"):
                return None, "encodeResponseBody with message frames (the frames come from the response conversion)"
        else:
            rest, text = args, False
        status, message = rest[0], rest[1]
        custom = rest[2]["map"] if len(rest) > 2 and rest[2] is not None else None
        response = {"headers": {}}
        if status is not None:
            response["headers"]["grpc-status"] = [status]
        if message is not None:
            response["headers"]["grpc-message"] = [message]
        if custom:
            response["trailers"] = {name: [value if value is not None else ""] for name, value in custom.items()}
        content_type = "application/grpc-web-text" if text else "application/grpc-web"
        call_step = web_request(content_type, note=note + ": the trailer frame", **empty_frame_for(content_type))
        return [clear(), greeting(), expectation(response, note="expectation: the status, message and trailers"), call_step], None
    return None, note + " not converted"


DEFAULT_MAX_MESSAGE_SIZE = 4 * 1024 * 1024


def convert_frame(case):
    """`decode(bytes, encoding, configuration)` -> the bytes as the body of a unary call with that `grpc-encoding`."""
    headers = {"grpc-encoding": case["encoding"]} if "encoding" in case else {}
    return [clear(), greeting(),
            expectation({"headers": {"grpc-status": ["0"]}, "body": {"greeting": "hello"}}, note="expectation: a gRPC answer"),
            call(GREETING, case.get("body"), "GrpcFrameCodec.decode: the request body", headers=headers)], None


def frame_properties(case):
    size = case.get("maxGrpcMessageSize", DEFAULT_MAX_MESSAGE_SIZE)
    return {"maxGrpcMessageSize": str(size)} if size != DEFAULT_MAX_MESSAGE_SIZE else None


KINDS = [
    Kind("grpcreflect", "B4", convert_reflect, source=(SOURCE, "grpcreflect")),
    Kind("grpcstatus", "B4", convert_status, source=(SOURCE, "grpcstatus")),
    Kind("grpctimeout", "B4", convert_timeout, source=(SOURCE, "grpctimeout")),
    Kind("grpcdescriptors", "B4", convert_descriptors, source=(SOURCE, "grpcdescriptors")),
    Kind("grpcsynth", "B4", convert_synth, source=(SOURCE, "grpcsynth")),
    Kind("grpcweb", "B4", convert_web, source=(SOURCE, "grpcweb")),
    Kind("grpcframe", "B4", convert_frame, source=(SOURCE, "grpcframe"), properties=frame_properties,
         own_file="-default"),
]
