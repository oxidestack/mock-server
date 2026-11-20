#!/usr/bin/env bash
# Upstream's container integration tests (upstream/mockserver/container_integration_tests), unmodified, against an
# image tagged mockserver/mockserver:integration_testing.
#
#   conformance/containers/run.sh [rs|oracle]           default rs
#
#   rs      builds our image (`make image IMAGE=$IMAGE`, skipped with SKIP_IMAGE_BUILD=true) and tags it, and for
#           helm_sidecar_injection our admission webhook image (`make webhook-image WEBHOOK_IMAGE=$WEBHOOK_IMAGE`, default
#           $IMAGE-webhook) as mockserver/mockserver-webhook:integration_testing
#   oracle  tags the oracle image pinned in oracle.env
#
# as mockserver/mockserver:integration_testing (and as mockserver/mockserver:mockserver-7.6.0, the image the chart's
# default values and MockServerContainerIntegrationTest pin, so helm_default_config deploys it too).
#
# Environment: CONTAINER_GROUPS=docker,helm (default both), CASES=a,b (only these case names), DELETE_CLUSTER=false keeps a
# k3d cluster this run created (one that existed before is never deleted), K3D_IGNORE_DISK_PRESSURE=true creates the
# cluster with the kubelet's disk eviction thresholds at 1% and image garbage collection off (a nearly full Docker disk
# otherwise taints the node, or collects the imported images, and no pod starts).
#
# Sharing one Docker daemon with other checkouts: the two tags are held only while the run lasts
# (scripts/with-image-tags.sh puts back whatever they named before), each docker-compose case runs as its own copy
# `<case>__<suffix>` (so its compose project, containers and networks carry this checkout's suffix), and the
# healthcheck/nonroot containers get the suffix too. The helm cases share upstream's fixed k3d cluster `mockserver`.
#
# The case scripts and upstream's harness functions (`test`, `test_healthcheck`, `test_nonroot_user`, the
# k3d/helm plumbing, logTestResult) run unmodified from a copy of the upstream tree under target/, so generated
# certificates and persisted files never land in the submodule. What this script adds: which cases run (cases
# upstream's harness runs that test MockServer's JVM packaging are listed in not-applicable.txt with the reason and
# their Rust counterpart), counterpart cases of our own (cases/), and a per-case result file,
# target/results-<target>.tsv (case, group, status, detail), read by conformance/upstream/results.py and coverage.py.
set -euo pipefail

TARGET="${1:-rs}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
IMAGE="${IMAGE:-mock-server}"
WANTED_GROUPS="${CONTAINER_GROUPS:-docker,helm}"
ONLY="${CASES:-}"
WORK="${HERE}/target"
COPY="${WORK}/upstream"
# a narrowed run (CASES, CONTAINER_GROUPS) updates only the cases it ran
RESULTS="${WORK}/results-${TARGET}.tsv"
SUT="mockserver/mockserver:integration_testing"
CHART_DEFAULT_IMAGE="mockserver/mockserver:mockserver-7.6.0"
# upstream's -clustered image variant: mock-server has one image, so on rs this tag names the SUT as well
CLUSTERED_IMAGE="mockserver/mockserver:integration_testing_clustered"

# our admission webhook image (k8s-webhook/), for helm_sidecar_injection on rs; upstream's run reads the webhook image
# from mockserver/mockserver-webhook, which names ours (WEBHOOK_SUT) while the run lasts
WEBHOOK_IMAGE_NAME="${WEBHOOK_IMAGE:-${IMAGE}-webhook}"
WEBHOOK_SUT="mockserver/mockserver-webhook:integration_testing"
webhook_wanted() {
  [[ ",${WANTED_GROUPS}," == *",helm,"* ]] && [[ -z "${ONLY}" || ",${ONLY}," == *",helm_sidecar_injection,"* ]]
}

case "${TARGET}" in
  rs)
    if [[ "${SKIP_IMAGE_BUILD:-}" != "true" ]]; then
      make -C "${REPO}" image IMAGE="${IMAGE}"
      if webhook_wanted; then make -C "${REPO}" webhook-image WEBHOOK_IMAGE="${WEBHOOK_IMAGE_NAME}"; fi
    fi
    SOURCE_IMAGE="${IMAGE}:latest"
    export SKIP_IMAGE_BUILD=true  # built once, before the re-exec below
    ;;
  oracle) SOURCE_IMAGE="$(. "${REPO}/oracle.env" && echo "${ORACLE_IMAGE}")" ;;
  *) echo "usage: $0 [rs|oracle]" >&2; exit 2 ;;
esac
# Hold the two tags for the rest of the run, then put them back (this script again, under scripts/with-image-tags.sh).
if [[ -z "${CONTAINER_TAGS_HELD:-}" ]]; then
  held=("${SUT}" "${CHART_DEFAULT_IMAGE}")
  if [[ "${TARGET}" == "rs" ]]; then held+=("${CLUSTERED_IMAGE}"); fi
  webhook_hold=()
  if [[ "${TARGET}" == "rs" ]] && webhook_wanted && docker image inspect "${WEBHOOK_IMAGE_NAME}:latest" >/dev/null 2>&1; then
    webhook_hold=("${REPO}/scripts/with-image-tags.sh" "${WEBHOOK_IMAGE_NAME}:latest" "${WEBHOOK_SUT}" --)
  fi
  CONTAINER_TAGS_HELD=1 exec "${REPO}/scripts/with-image-tags.sh" "${SOURCE_IMAGE}" "${held[@]}" -- \
    ${webhook_hold[@]+"${webhook_hold[@]}"} "$0" "$@"
fi
# This checkout's suffix for everything named on the shared daemon.
SUFFIX="$(basename "${REPO}" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9\n' '-' | cut -c1-24)-$(printf '%s' "${REPO}" | cksum | cut -c1-6)"
FULL_RUN=true
if [[ -n "${ONLY}" || ",${WANTED_GROUPS}," != *",docker,"* || ",${WANTED_GROUPS}," != *",helm,"* ]]; then FULL_RUN=false; fi

# A fresh copy of the three upstream directories the scripts reach through relative paths.
mkdir -p "${COPY}/examples"
for dir in container_integration_tests helm examples/docker-compose; do
  rm -rf "${COPY:?}/${dir}"
  cp -R "${REPO}/upstream/mockserver/${dir}" "${COPY}/${dir}"
done
# Our counterpart cases sit next to upstream's, so upstream's `test` runs them the same way.
if [[ -d "${HERE}/cases" ]]; then cp -R "${HERE}/cases/." "${COPY}/container_integration_tests/"; fi

wanted() {  # wanted <group> <case>
  [[ ",${WANTED_GROUPS}," == *",$1,"* ]] || return 1
  [[ -z "${ONLY}" || ",${ONLY}," == *",$2,"* ]]
}

# Upstream's harness, sourced: it defines its functions without running anything.
# shellcheck source=/dev/null
source "${COPY}/container_integration_tests/integration_tests.sh"
UPSTREAM_DIR="${SCRIPT_DIR}"
# test_healthcheck and test_nonroot_user name their containers with fixed local names: the same functions, with this
# checkout's suffix on those names.
eval "$(declare -f test_healthcheck | sed "s/\"healthcheck-test\"/\"healthcheck-test-${SUFFIX}\"/")"
eval "$(declare -f test_nonroot_user | sed "s/\"nonroot-test\"/\"nonroot-test-${SUFFIX}\"/")"

# run_compose_case <case>: upstream's `test` on a copy of the case (and its example) named `<case>__<suffix>`, since
# the harness names the compose project after the case directory.
run_compose_case() {
  local c="$1" copy="$1__${SUFFIX}"
  rm -rf "${UPSTREAM_DIR:?}/${copy}" "${COPY}/examples/docker-compose/${copy}"
  cp -R "${UPSTREAM_DIR}/${c}" "${UPSTREAM_DIR}/${copy}"
  if [[ -d "${COPY}/examples/docker-compose/${c}" ]]; then cp -R "${COPY}/examples/docker-compose/${c}" "${COPY}/examples/docker-compose/${copy}"; fi
  test "${copy}"
  # several upstream scripts leave their project running (tear-down commented out); upstream's run_all_tests
  # stops them at the end, which would also leave the networks behind
  (cd "${UPSTREAM_DIR}/${copy}" && TEST_CASE="${copy}" tear-down) >/dev/null 2>&1
}

export PASS_LOG_FILE FAIL_LOG_FILE WARN_LOG_FILE SKIP_LOG_FILE
PASS_LOG_FILE=$(mktemp); FAIL_LOG_FILE=$(mktemp); WARN_LOG_FILE=$(mktemp); SKIP_LOG_FILE=$(mktemp)

# Only the curl/nghttp client image: SKIP_DOCKER_BUILD_MOCKSERVER leaves the image under test alone.
SKIP_JAVA_BUILD=true SKIP_DOCKER_BUILD_MOCKSERVER=true build_docker

DOCKER_CASES=(
  docker_compose_forward_with_override
  docker_compose_remote_host_and_port_by_environment_variable
  docker_compose_server_port_by_command
  docker_compose_server_port_by_environment_variable_long_name
  docker_compose_server_port_by_environment_variable_short_name
  docker_compose_without_server_port
  docker_compose_with_expectation_initialiser
  docker_compose_with_persisted_expectations
  docker_compose_with_server_port_from_default_properties_file
  docker_compose_with_server_port_from_custom_properties_file
  docker_compose_with_mtls
  docker_compose_graceful_shutdown
  docker_compose_metrics
)
HELM_CASES=(
  helm_default_config
  helm_local_docker_container
  helm_custom_server_port
  helm_remote_host_and_port
  helm_inline_config
  helm_configmap_injection
  helm_mockserver_config_chart
)
# Counterparts (cases/): run on rs only, recorded under their own names.
RS_CASES=()
if [[ "${TARGET}" == "rs" ]]; then
  for dir in "${HERE}"/cases/*/; do [[ -d "${dir}" ]] && RS_CASES+=("$(basename "${dir}")"); done
  export MOCK_SERVER_REPO="${REPO}"
  # the integration-testing callback classes as a WASM plugin, for docker_compose_libs_plugin
  if wanted docker docker_compose_libs_plugin; then
    make -C "${REPO}" plugins
    export MOCK_SERVER_PLUGIN_WASM="${REPO}/target/wasm/wasm32-unknown-unknown/release/mock_server_integration_testing_callbacks.wasm"
  fi
fi

# not_applicable <case>: listed in not-applicable.txt, so not run on rs (the oracle target runs every case)
not_applicable() {
  [[ "${TARGET}" == "rs" ]] && cut -f1 "${HERE}/not-applicable.txt" | grep -qx "$1"
}

set +euo pipefail
for c in "${DOCKER_CASES[@]}" "${RS_CASES[@]}"; do
  if wanted docker "${c}" && ! not_applicable "${c}"; then
    run_compose_case "${c}"
  fi
done
if wanted docker docker_healthcheck; then test_healthcheck; fi
if wanted docker docker_nonroot_user; then test_nonroot_user; fi

if [[ ",${WANTED_GROUPS}," == *",helm,"* ]]; then
  helm_selected=false
  for c in "${HELM_CASES[@]}" helm_sidecar_injection helm_clustered_convergence helm_jgroups_dns_ping; do wanted helm "${c}" && helm_selected=true; done
  if [[ "${helm_selected}" == "true" ]]; then
    # Upstream's start-up-k8s reuses any cluster whose name matches `grep -w mockserver`; this run creates the
    # cluster itself when no cluster has exactly that name, and deletes only a cluster it created.
    created_cluster=false
    if k3d cluster get "${CLUSTER_NAME}" >/dev/null 2>&1; then
      printMessage "Using the existing k3d cluster ${CLUSTER_NAME}; it is left in place"
    else
      extra=()
      if [[ "${K3D_IGNORE_DISK_PRESSURE:-}" == "true" ]]; then
        extra=(--k3s-arg "--kubelet-arg=eviction-hard=imagefs.available<1%,nodefs.available<1%@server:*"
          --k3s-arg "--kubelet-arg=eviction-minimum-reclaim=imagefs.available=1%,nodefs.available=1%@server:*"
          --k3s-arg "--kubelet-arg=image-gc-high-threshold=100@server:*"
          --k3s-arg "--kubelet-arg=image-gc-low-threshold=99@server:*")
      fi
      # upstream's k3d-config.yaml (as start-up-k8s would create it), plus the optional kubelet thresholds
      k3d cluster create --config "${UPSTREAM_DIR}/k3d-config.yaml" ${extra[@]+"${extra[@]}"} && created_cluster=true
    fi
    start-up-k8s
    import_image_into_k3d "${CHART_DEFAULT_IMAGE}"
    # `k3d image import` skips a name whose image the node already holds under another name (two tags of one image,
    # as on the oracle target), and the pod then fails to pull it: load any missing name straight into containerd.
    images=("${SUT}" "${CHART_DEFAULT_IMAGE}")
    if [[ "${TARGET}" == "rs" ]]; then images+=("${CLUSTERED_IMAGE}"); fi
    for image in "${images[@]}"; do
      if ! docker exec "k3d-${CLUSTER_NAME}-server-0" ctr -n k8s.io images ls -q 2>/dev/null | grep -qx "docker.io/${image}"; then
        docker save "${image}" | docker exec -i "k3d-${CLUSTER_NAME}-server-0" ctr -n k8s.io images import - >/dev/null
      fi
    done
    clustered_ready=false
    if [[ "${TARGET}" == "rs" ]] && import_image_into_k3d "${CLUSTERED_IMAGE}"; then clustered_ready=true; fi
    for c in "${HELM_CASES[@]}"; do
      if wanted helm "${c}"; then test "${c}"; fi
    done
    # upstream's own branch of run_all_tests: both cases deploy the -clustered image (here: our image under that tag)
    for c in helm_clustered_convergence helm_jgroups_dns_ping; do
      if wanted helm "${c}" && [[ "${TARGET}" == "rs" ]]; then
        if [[ "${clustered_ready}" == "true" ]]; then test "${c}"; else logTestResult "1" "${c}"; fi
      fi
    done
    if wanted helm helm_sidecar_injection; then
      # upstream's own branch of run_all_tests: needs the admission-webhook image and records an honest skip without
      # it. On rs that is our k8s-webhook image under WEBHOOK_SUT (held above); upstream's webhook_image_ref would
      # take whichever mockserver/mockserver-webhook tag the daemon lists first. On oracle, upstream's own image
      # (mockserver/mockserver-webhook:9.2.0, the tag of ORACLE_WEBHOOK_IMAGE, pulled beforehand) is found the upstream way.
      webhook_ref=""
      if [[ "${TARGET}" == "rs" ]]; then
        if docker image inspect "${WEBHOOK_SUT}" >/dev/null 2>&1; then webhook_ref="${WEBHOOK_SUT}"; fi
      elif webhook_image_available; then
        webhook_ref="$(webhook_image_ref)"
      fi
      if [[ -n "${webhook_ref}" ]]; then
        if import_image_into_k3d "${webhook_ref}"; then
          export MOCKSERVER_WEBHOOK_IMAGE="${webhook_ref}" MOCKSERVER_SIDECAR_IMAGE="${SUT}"
          test "helm_sidecar_injection"
          unset MOCKSERVER_WEBHOOK_IMAGE MOCKSERVER_SIDECAR_IMAGE
        else
          logTestResult "1" "helm_sidecar_injection"
        fi
      else
        logTestSkip "helm_sidecar_injection" "webhook handler image absent (rs: make webhook-image; oracle: docker pull mockserver/mockserver-webhook:9.2.0)"
      fi
    fi
    if [[ "${created_cluster}" == "true" && "${DELETE_CLUSTER:-true}" != "false" ]]; then
      DELETE_CLUSTER=true tear-down-k8s
    fi
  fi
fi
# Not upstream's clean-up-docker-containers, which stops every container of the image: each case's compose project
# was torn down above, and the healthcheck/nonroot containers remove themselves.
set -euo pipefail

# Results: one row per case of upstream's manifest (plus our counterparts).
RESULTS_SUFFIX="${SUFFIX}" RESULTS_FULL_RUN="${FULL_RUN}" \
  python3 "${HERE}/results.py" "${UPSTREAM_DIR}/expected_tests.manifest" "${HERE}/not-applicable.txt" "${RESULTS}" \
  "${PASS_LOG_FILE}" "${FAIL_LOG_FILE}" "${WARN_LOG_FILE}" "${SKIP_LOG_FILE}" ${RS_CASES[@]+"${RS_CASES[@]}"} > "${RESULTS}.new"
mv "${RESULTS}.new" "${RESULTS}"
rm -f "${PASS_LOG_FILE}" "${FAIL_LOG_FILE}" "${WARN_LOG_FILE}" "${SKIP_LOG_FILE}"

echo
column -t -s $'\t' "${RESULTS}"
! grep -q $'\tfail\t' "${RESULTS}"
