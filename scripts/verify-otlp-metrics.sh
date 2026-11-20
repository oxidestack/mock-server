#!/usr/bin/env bash
# Decodes an OTLP metrics export of ours with the reference protobuf classes (opentelemetry-proto, in a venv under
# target/) and checks its shape: telemetry::tests::exports_metrics_as_otlp_protobuf captures the export.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${REPO}/target/otlp-venv"
DUMP="${REPO}/target/otlp-metrics.bin"
if [[ ! -x "${VENV}/bin/python" ]]; then
  python3 -m venv "${VENV}"
  "${VENV}/bin/pip" install -q opentelemetry-proto
fi
rm -f "${DUMP}"
(cd "${REPO}" && MOCK_SERVER_OTLP_DUMP="${DUMP}" cargo test -q --lib telemetry::tests::exports_metrics_as_otlp_protobuf)
"${VENV}/bin/python" - "${DUMP}" <<'PY'
import sys
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest

request = ExportMetricsServiceRequest()
request.ParseFromString(open(sys.argv[1], "rb").read())
assert len(request.resource_metrics) == 1, request
rm = request.resource_metrics[0]
resource = {a.key: a.value.string_value for a in rm.resource.attributes}
assert resource["service.name"] == "mockserver", resource
scope = rm.scope_metrics[0]
assert scope.scope.name == "org.mockserver", scope.scope
metrics = {m.name: m for m in scope.metrics}
assert len(metrics) == len(scope.metrics), "one Metric per instrument name"


def points(name, kind):
    m = metrics[name]
    assert m.WhichOneof("data") == kind, (name, m.WhichOneof("data"))
    return list(getattr(m, kind).data_points)


def attrs(p):
    return {a.key: a.value.string_value for a in p.attributes}


assert points("requests_received_count", "gauge")[0].as_int > 0
total = metrics["mock_server_requests_received_total"].sum
assert total.is_monotonic and total.aggregation_temporality == 2, total
assert {attrs(p)["fault_type"] for p in points("mock_server_http_chaos_injected_total", "sum")} >= {"latency", "error"}
assert len(points("mock_server_active_service_chaos", "gauge")) == 8
requests = points("mock_server_load_requests", "sum")
assert sum(p.as_int for p in requests) == 3, requests
a = attrs(requests[0])
assert a["scenario"] == "otlp" and a["method"] == "GET" and a["status_class"] == "2xx" and a["team"] == "a" and a["route"] == "/load/x", a
assert points("mock_server_load_iterations", "sum")[0].as_int >= 1
assert {attrs(p)["outcome"] for p in points("mock_server_load_checks", "sum")} == {"pass"}
assert points("mock_server_load_response_bytes", "sum")[0].as_int == 6
assert points("mock_server_llm_cache_hit_ratio", "gauge")[0].WhichOneof("value") == "as_double"
assert resource["service.version"], resource
build = points("mock_server_native_build_info", "gauge")
assert build[0].as_int == 1 and attrs(build[0])["mockserver_version"] == "9.2.0", build
assert set(attrs(build[0])) == {"git_hash", "mockserver_version", "rustc", "target", "version"}, build
# The process set under the OTel process semconv names and units.
cpu = metrics["process.cpu.time"]
assert cpu.unit == "s" and cpu.sum.is_monotonic and cpu.sum.aggregation_temporality == 2, cpu
assert {attrs(p)["cpu.mode"] for p in cpu.sum.data_points} == {"user", "system"}, cpu
assert all(p.WhichOneof("value") == "as_double" for p in cpu.sum.data_points), cpu
assert metrics["process.uptime"].unit == "s" and points("process.uptime", "gauge")[0].as_double > 0
for name, unit in [("process.memory.usage", "By"), ("process.memory.virtual", "By"),
                   ("process.unix.file_descriptor.count", "{file_descriptor}"), ("process.thread.count", "{thread}")]:
    m = metrics[name]
    assert m.unit == unit and not m.sum.is_monotonic and m.sum.aggregation_temporality == 2, m
    assert points(name, "sum")[0].as_int > 0, m
assert not any(name.startswith("jvm") for name in metrics), "no JVM gauges"
for m in scope.metrics:
    data = getattr(m, m.WhichOneof("data")).data_points
    for p in data:
        assert p.time_unix_nano >= p.start_time_unix_nano > 0, m.name
print(f"decoded {len(scope.metrics)} metrics, {sum(len(getattr(m, m.WhichOneof('data')).data_points) for m in scope.metrics)} data points: ok")
PY
