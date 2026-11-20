#!/usr/bin/env bash
# Counterpart of upstream's docker_arm64_build_gate (integration_tests.sh test_arm64_build_gate), which cross-builds
# upstream's docker/Dockerfile for linux/arm64 with buildx: the same build gate for our Dockerfile. A successful
# build is the gate, as upstream's; nothing boots. The repository root comes from MOCK_SERVER_REPO (run.sh).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
source "${SCRIPT_DIR}/../logging.sh"

printMessage "Start: \"${SCRIPT_DIR/\//}\""

function integration_test() {
  local tag="mock-server-arm64-gate:${TEST_CASE}"
  TEST_EXIT_CODE=0
  runCommand "docker buildx build --platform linux/arm64 -t ${tag} ${MOCK_SERVER_REPO}" || TEST_EXIT_CODE=1
  docker rmi "${tag}" >/dev/null 2>&1 || true
  logTestResult "${TEST_EXIT_CODE}" "${TEST_CASE}"
  return ${TEST_EXIT_CODE}
}

integration_test
