#!/usr/bin/env bash
# Decodes an OTLP trace export of ours with the reference protobuf classes (opentelemetry-proto, in a venv under
# target/) and checks its shape: telemetry::tests::exports_spans_as_otlp_protobuf captures the export.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${REPO}/target/otlp-venv"
DUMP="${REPO}/target/otlp-trace.bin"
if [[ ! -x "${VENV}/bin/python" ]]; then
  python3 -m venv "${VENV}"
  "${VENV}/bin/pip" install -q opentelemetry-proto
fi
rm -f "${DUMP}"
(cd "${REPO}" && MOCK_SERVER_OTLP_TRACE_DUMP="${DUMP}" cargo test -q --lib telemetry::tests::exports_spans_as_otlp_protobuf)
"${VENV}/bin/python" - "${DUMP}" <<'PY'
import sys
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

request = ExportTraceServiceRequest()
request.ParseFromString(open(sys.argv[1], "rb").read())
assert len(request.resource_spans) == 1, request
rs = request.resource_spans[0]
resource = {a.key: a.value.string_value for a in rs.resource.attributes}
assert resource["service.name"] == "mockserver", resource
scope = rs.scope_spans[0]
assert scope.scope.name == "org.mockserver", scope.scope
spans = list(scope.spans)
assert len(spans) >= 1, "at least one span (the GET /hit request span)"


def attrs(s):
    out = {}
    for a in s.attributes:
        v = a.value
        kind = v.WhichOneof("value")
        out[a.key] = getattr(v, kind) if kind else None
    return out


request_span = next((s for s in spans if s.name == "GET /hit"), None)
assert request_span is not None, [s.name for s in spans]
# SPAN_KIND_SERVER == 2 (opentelemetry.proto.trace.v1.Span.SpanKind)
assert request_span.kind == 2, request_span.kind
a = attrs(request_span)
assert a["http.request.method"] == "GET", a
assert a["http.route"] == "/hit", a
assert a["http.response.status_code"] == 200, a
assert "mockserver.expectation_id" in a, a
for s in spans:
    assert len(s.trace_id) == 16 and len(s.span_id) == 8, s.name  # 16/8 raw bytes = 32/16 hex chars
    assert s.end_time_unix_nano >= s.start_time_unix_nano > 0, s.name
print(f"decoded {len(spans)} span(s): ok")
PY
