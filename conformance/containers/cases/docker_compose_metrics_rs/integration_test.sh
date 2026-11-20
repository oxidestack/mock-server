#!/usr/bin/env bash
# Counterpart of upstream's docker_compose_metrics/integration_test.sh, in its shape and with its assertions 1 and 3
# unchanged. Assertion 2 checks the JVM gauges (JvmMetricsCollector); mock-server has no JVM and does not imitate
# `jvm_*` series, so it checks the standard process set that stands in for them (the OTel process semantic conventions:
# src/metrics.rs, src/metrics/process.rs; the image is Linux, so every one of them is there), the build info and the
# tokio runtime set, and the connection and forward-pool set.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
# the MockServer version both build infos name (conformance/containers/run.sh exports MOCK_SERVER_REPO)
# shellcheck source=/dev/null
ORACLE_VERSION="$(. "${MOCK_SERVER_REPO:?}/oracle.env" && echo "${ORACLE_VERSION}")"
source "${SCRIPT_DIR}/../docker-compose.sh"
source "${SCRIPT_DIR}/../logging.sh"

printMessage "Start: \"${SCRIPT_DIR/\//}\""

function cleanup() {
  tear-down 2>/dev/null || true
}

# wait_ready is now provided by the shared docker-compose.sh harness.

# Retry a client-side check until it passes or attempts run out — absorbs the
# Prometheus scrape interval and the OTLP export interval on a cold runner
# without a brittle fixed sleep. Sets TEST_EXIT_CODE=1 on exhaustion.
function assert_eventually() {
  local desc="${1}" check="${2}" attempts="${3:-12}"
  for _ in $(seq 1 "${attempts}"); do
    if docker-exec-client "${check}"; then
      printMessage "PASS: ${desc}"
      return 0
    fi
    sleep 2
  done
  printMessage "FAIL: ${desc}"
  TEST_EXIT_CODE=1
  return 1
}

function integration_test() {
  trap cleanup EXIT
  start-up
  TEST_EXIT_CODE=0

  # both the server under test and the MockServer acting as the OTLP sink
  wait_ready "mockserver" || { TEST_EXIT_CODE=1; logTestResult "${TEST_EXIT_CODE}" "${TEST_CASE}"; return ${TEST_EXIT_CODE}; }
  wait_ready "otlp-receiver" || { TEST_EXIT_CODE=1; logTestResult "${TEST_EXIT_CODE}" "${TEST_CASE}"; return ${TEST_EXIT_CODE}; }

  # Tell the OTLP receiver to accept the exporter's metric POSTs with 200 so the
  # export succeeds cleanly (an unmatched request would 404 and make the OTel SDK
  # log errors and back off). The request is still recorded either way.
  docker-exec-client "curl -sf -o /dev/null -X PUT 'http://otlp-receiver:1080/mockserver/expectation' -d \\\"{
                        'httpRequest' : { 'method' : 'POST', 'path' : '/v1/metrics' },
                        'httpResponse' : { 'statusCode' : 200 }
                      }\\\"" || true

  # Drive some traffic. requests_received_count increments on ANY request, so
  # no expectation is needed (the unmatched requests return 404 but still count).
  for _ in $(seq 1 5); do
    docker-exec-client "curl -s -o /dev/null http://mockserver:1080/anything" || true
  done
  # One TLS connection on the unified port (a TLS handshake), and one forward through the pooled client
  docker-exec-client "curl -sk -o /dev/null https://mockserver:1080/anything" || true
  docker-exec-client "curl -sf -o /dev/null -X PUT 'http://mockserver:1080/mockserver/expectation' -d \\\"{
                        'httpRequest' : { 'path' : '/forwarded' },
                        'httpForward' : { 'host' : 'otlp-receiver', 'port' : 1080 }
                      }\\\"" || true
  docker-exec-client "curl -s -o /dev/null http://mockserver:1080/forwarded" || true

  # Assert each metric path, retrying to absorb the scrape + OTLP-export
  # intervals rather than relying on a single brittle sleep.

  # 1 — Prometheus scraped MockServer's request counter (the scrape path)
  assert_eventually "Prometheus scraped requests_received_count" \
    "curl -sf 'http://prometheus:9090/api/v1/query?query=requests_received_count' | jq -e '.data.result[0].value[1] | tonumber > 0' >/dev/null" || true

  # 2 — process gauges present on the scrape path (upstream: the JVM gauges of JvmMetricsCollector)
  assert_eventually "Process metrics present in Prometheus" \
    "curl -sf 'http://prometheus:9090/api/v1/query?query=process_max_resident_memory_bytes' | jq -e '.data.result[0].value[1] | tonumber > 0' >/dev/null" || true
  assert_eventually "Process CPU counter present in Prometheus" \
    "curl -sf 'http://prometheus:9090/api/v1/query?query=process_cpu_seconds_total' | jq -e '.data.result | length > 0' >/dev/null" || true
  for gauge in process_resident_memory_bytes process_virtual_memory_bytes process_virtual_memory_max_bytes \
               process_open_fds process_max_fds process_start_time_seconds process_threads; do
    assert_eventually "${gauge} present in Prometheus" \
      "curl -sf 'http://prometheus:9090/api/v1/query?query=${gauge}' | jq -e '.data.result[0].value[1] | tonumber > 0' >/dev/null" || true
  done
  assert_eventually "Open fds within the fd limit" \
    "curl -sf 'http://prometheus:9090/api/v1/query?query=process_open_fds%20%3C%3D%20process_max_fds' | jq -e '.data.result | length > 0' >/dev/null" || true
  # the tokio runtime set: the gauges, and the per-worker counters
  assert_eventually "tokio_workers_count present in Prometheus" \
    "curl -sf 'http://prometheus:9090/api/v1/query?query=tokio_workers_count' | jq -e '.data.result[0].value[1] | tonumber > 0' >/dev/null" || true
  assert_eventually "tokio_live_tasks_count present in Prometheus" \
    "curl -sf 'http://prometheus:9090/api/v1/query?query=tokio_live_tasks_count' | jq -e '.data.result[0].value[1] | tonumber > 0' >/dev/null" || true
  assert_eventually "tokio_global_queue_depth present in Prometheus" \
    "curl -sf 'http://prometheus:9090/api/v1/query?query=tokio_global_queue_depth' | jq -e '.data.result | length > 0' >/dev/null" || true
  for counter in tokio_worker_park_total tokio_worker_busy_seconds_total; do
    assert_eventually "${counter} present per worker in Prometheus" \
      "curl -sf 'http://prometheus:9090/api/v1/query?query=count(${counter}%7Bworker%3D~%22%5B0-9%5D%2B%22%7D)%20%3D%3D%20on()%20max(tokio_workers_count)' | jq -e '.data.result | length > 0' >/dev/null" || true
  done
  # the connection set and the forward pool
  assert_eventually "mock_server_active_connections present for TCP in Prometheus" \
    "curl -sf 'http://prometheus:9090/api/v1/query?query=mock_server_active_connections%7Bnetwork_transport%3D%22tcp%22%2Ctls%3D~%22true%7Cfalse%22%7D' | jq -e '.data.result | length > 0' >/dev/null" || true
  assert_eventually "mock_server_connection_duration_seconds counted closed connections" \
    "curl -sf 'http://prometheus:9090/api/v1/query?query=sum(mock_server_connection_duration_seconds_count%7Bnetwork_transport%3D%22tcp%22%7D)' | jq -e '.data.result[0].value[1] | tonumber > 0' >/dev/null" || true
  assert_eventually "mock_server_tls_handshake_duration_seconds counted the HTTPS handshake" \
    "curl -sf 'http://prometheus:9090/api/v1/query?query=sum(mock_server_tls_handshake_duration_seconds_count%7Btls_protocol_version%3D~%221%5C%5C.%5B23%5D%22%7D)' | jq -e '.data.result[0].value[1] | tonumber > 0' >/dev/null" || true
  assert_eventually "http_client_open_connections present for the forward target" \
    "curl -sf 'http://prometheus:9090/api/v1/query?query=http_client_open_connections%7Bserver_address%3D%22otlp-receiver%22%2Cserver_port%3D%221080%22%7D' | jq -e '.data.result | length > 0' >/dev/null" || true
  assert_eventually "mock_server_native_build_info present beside mock_server_build_info" \
    "curl -sf 'http://prometheus:9090/api/v1/query?query=mock_server_native_build_info%7Bmockserver_version%3D%22${ORACLE_VERSION}%22%2Crustc%21%3D%22%22%2Ctarget%21%3D%22%22%2Cgit_hash%21%3D%22unknown%22%2Cgit_hash%21%3D%22%22%2Cversion%21%3D%22%22%7D' | jq -e '.data.result | length > 0' >/dev/null && curl -sf 'http://prometheus:9090/api/v1/query?query=mock_server_build_info%7Bversion%3D%22${ORACLE_VERSION}%22%7D' | jq -e '.data.result | length > 0' >/dev/null" || true

  # 3 — MockServer actually pushed OTLP metric exports over the wire: the OTLP
  # receiver verifies it got at least one POST /v1/metrics (verify returns 202
  # on success, 406 otherwise, so curl -sf passes only when it has arrived).
  assert_eventually "MockServer exported metrics via OTLP (POST /v1/metrics received)" \
    "curl -sf -o /dev/null -X PUT 'http://otlp-receiver:1080/mockserver/verify' -d \\\"{
       'httpRequest' : { 'method' : 'POST', 'path' : '/v1/metrics' },
       'times' : { 'atLeast' : 1, 'atMost' : -1 }
     }\\\"" || true

  if [[ "${TEST_EXIT_CODE}" != "0" ]]; then
    container-logs || true
  fi
  logTestResult "${TEST_EXIT_CODE}" "${TEST_CASE}"
  return "${TEST_EXIT_CODE}"
}

integration_test
