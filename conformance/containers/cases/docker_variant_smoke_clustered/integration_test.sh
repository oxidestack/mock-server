#!/usr/bin/env bash
# Counterpart of upstream's docker_variant_smoke_clustered (container_integration_tests/integration_tests.sh,
# smoke_test_clustered): boots with MOCKSERVER_STATE_BACKEND=infinispan and no MOCKSERVER_CLUSTER_ENABLED (LOCAL
# mode) and checks PUT /mockserver/status answers 200 — upstream's own smoke check, "Infinispan boots
# in LOCAL mode when MOCKSERVER_CLUSTER_ENABLED is not set". Run it with `make container-tests`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
source "${SCRIPT_DIR}/../docker-compose.sh"
source "${SCRIPT_DIR}/../logging.sh"

printMessage "Start: \"${SCRIPT_DIR/\//}\""

function cleanup() {
  tear-down 2>/dev/null || true
}

function integration_test() {
  trap cleanup EXIT
  start-up
  TEST_EXIT_CODE=0
  wait_ready "mockserver" || TEST_EXIT_CODE=1
  logTestResult "${TEST_EXIT_CODE}" "${TEST_CASE}"
  return ${TEST_EXIT_CODE}
}

integration_test
