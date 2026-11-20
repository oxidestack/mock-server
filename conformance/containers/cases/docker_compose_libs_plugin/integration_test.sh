#!/usr/bin/env bash
# Counterpart of upstream's docker_compose_libs_classpath/integration_test.sh, in its shape: the initializer comes
# from a WASM callback plugin on /libs (MOCK_SERVER_PLUGIN_WASM, built by conformance/containers/run.sh) instead
# of a Java jar compiled against the fat jar.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
source "${SCRIPT_DIR}/../docker-compose.sh"
source "${SCRIPT_DIR}/../logging.sh"

printMessage "Start: \"${SCRIPT_DIR/\//}\""

function cleanup() {
  tear-down 2>/dev/null || true
  rm -rf "${SCRIPT_DIR}/libs"
}

function integration_test() {
  trap cleanup EXIT
  runCommand "rm -rf ${SCRIPT_DIR}/libs && mkdir -p ${SCRIPT_DIR}/libs"
  runCommand "cp ${MOCK_SERVER_PLUGIN_WASM} ${SCRIPT_DIR}/libs/"
  runCommand "chmod -R a+rX ${SCRIPT_DIR}/libs"

  start-up
  TEST_EXIT_CODE=0
  wait_ready "mockserver" || { TEST_EXIT_CODE=1; logTestResult "${TEST_EXIT_CODE}" "${TEST_CASE}"; return ${TEST_EXIT_CODE}; }

  # Verify the initialiser ran by hitting the expectation it registered
  RESPONSE_BODY=$(docker-exec-client "curl -v -s -X PUT 'http://mockserver:1080/libs-test-path'")

  if [[ "${RESPONSE_BODY}" != "libs_classpath_response" ]]; then
    printFailureMessage "Failed to retrieve response body from libs plugin initialiser, found: \"${RESPONSE_BODY}\""
    TEST_EXIT_CODE=1
  fi

  logTestResult "${TEST_EXIT_CODE}" "${TEST_CASE}"
  return ${TEST_EXIT_CODE}
}

integration_test
