#!/usr/bin/env bash
# End-to-end proof, in a privileged Linux container under a Docker VM, of the three
# original-destination resolvers (SO_ORIGINAL_DST, TPROXY, eBPF map lookup) — `make proxy-resolver-e2e`.
# Mirrors upstream's Docker-gated SoOriginalDstEndToEndIntegrationTest / TproxyEndToEndIntegrationTest /
# EbpfOriginalDestinationEndToEndIntegrationTest almost verbatim (same iptables/TPROXY/bpftool commands, same
# dummy IP:port, same expectation body), swapping `java -jar mockserver.jar` for our own static release binary.
#
# Usage: scripts/proxy-resolver-e2e.sh [so-original-dst|tproxy|ebpf|all]  (default: all)
#
# Each case is a `--rm` container named mock-server-126-<case>. A case whose underlying kernel feature is
# unsupported (no xt_TPROXY module, no BPF, or the daemon refuses --privileged/--cap-add=NET_ADMIN, e.g. a
# user-namespace-remapped Docker VM) SKIPs — printed, not fatal — exactly as the upstream JUnit `Assume`s do; a
# wrong HTTP code or exit status is a hard FAIL.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

IMAGE=${IMAGE:-mock-server-126-e2e}
DOCKER_HOST=${DOCKER_HOST:-$(docker context inspect --format '{{.Endpoints.docker.Host}}')}
export DOCKER_HOST

CASE=${1:-all}
FAILED=0

log() { echo "[proxy-resolver-e2e] $*"; }

build_image() {
  log "building $IMAGE from scripts/proxy-resolver-e2e.Dockerfile"
  docker build -f scripts/proxy-resolver-e2e.Dockerfile -t "$IMAGE" .
}

# Runs $2 (a bash -c script) in a --rm container named mock-server-126-$1, with the extra docker-run flags in
# $3 (word-split intentionally). Prints the container's combined output and returns its exit code.
run_case() {
  local name=$1 script=$2 extra_flags=$3
  local container="mock-server-126-${name}"
  docker rm -f "$container" >/dev/null 2>&1 || true
  # shellcheck disable=SC2086
  docker run --rm --name "$container" $extra_flags "$IMAGE" bash -c "$script"
}

# --- Case 1: SO_ORIGINAL_DST via iptables REDIRECT (SoOriginalDstEndToEndIntegrationTest) ---
case_so_original_dst() {
  local script='
set -e
/mock-server -Dmockserver.transparentProxyEnabled=true -Dmockserver.logLevel=INFO -serverPort 1080 &
MOCKSERVER_PID=$!
for i in $(seq 1 30); do curl -s http://localhost:1080/mockserver/status && break; sleep 1; done
curl -s -X PUT http://localhost:1080/mockserver/expectation -d "{\"httpRequest\":{\"path\":\"/.*\"},\"httpResponse\":{\"statusCode\":200,\"body\":\"original-dst-ok\"}}"
iptables -t nat -A OUTPUT -d 192.0.2.1 -p tcp --dport 8080 -j REDIRECT --to-port 1080
ip addr add 192.0.2.1/32 dev lo
HTTP_CODE=$(curl -s -o /tmp/body.txt -w "%{http_code}" http://192.0.2.1:8080/test-original-dst)
BODY=$(cat /tmp/body.txt)
echo "HTTP_CODE=$HTTP_CODE"
echo "BODY=$BODY"
kill $MOCKSERVER_PID 2>/dev/null || true
'
  local out
  out=$(run_case so-original-dst "$script" "--cap-add=NET_ADMIN")
  local rc=$?
  echo "$out"
  evaluate so-original-dst "$rc" "$out" "original-dst-ok" ""
}

# --- Case 2: TPROXY (TproxyEndToEndIntegrationTest) ---
case_tproxy() {
  local script='
set -e
/mock-server -Dmockserver.transparentProxyEnabled=true -Dmockserver.transparentProxyTproxy=true -Dmockserver.logLevel=INFO -serverPort 1080 &
MOCKSERVER_PID=$!
for i in $(seq 1 30); do curl -s http://localhost:1080/mockserver/status && break; sleep 1; done
curl -s -X PUT http://localhost:1080/mockserver/expectation -d "{\"httpRequest\":{\"path\":\"/.*\"},\"httpResponse\":{\"statusCode\":200,\"body\":\"tproxy-ok\"}}"
ip route add local 0.0.0.0/0 dev lo table 100
ip rule add fwmark 1 lookup 100
if ! iptables -t mangle -A PREROUTING -d 192.0.2.2 -p tcp --dport 9090 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 1080 2>&1; then
  echo "TPROXY_UNSUPPORTED=true"
  kill $MOCKSERVER_PID 2>/dev/null || true
  exit 0
fi
ip addr add 192.0.2.2/32 dev lo
HTTP_CODE=$(curl -s -o /tmp/body.txt -w "%{http_code}" http://192.0.2.2:9090/test-tproxy)
BODY=$(cat /tmp/body.txt)
echo "HTTP_CODE=$HTTP_CODE"
echo "BODY=$BODY"
kill $MOCKSERVER_PID 2>/dev/null || true
'
  local out
  out=$(run_case tproxy "$script" "--cap-add=NET_ADMIN")
  local rc=$?
  echo "$out"
  evaluate tproxy "$rc" "$out" "tproxy-ok" "TPROXY_UNSUPPORTED=true"
}

# --- Case 3: eBPF map lookup, falling through to SO_ORIGINAL_DST for the actual traffic (same limitation upstream's
# EbpfOriginalDestinationEndToEndIntegrationTest documents: without a real cgroup/connect4 BPF program the accepted
# socket's cookie never matches the map's pre-populated key, so this proves the BPF map read path — bpf(BPF_OBJ_GET)
# + bpf(BPF_MAP_LOOKUP_ELEM) via the raw syscall — and the chain's fallthrough, not a full traffic-steered lookup) ---
case_ebpf() {
  local script='
set -e
if ! bpftool version >/dev/null 2>&1; then
  echo "BPF_UNSUPPORTED=true"
  exit 0
fi
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
if ! bpftool map create /sys/fs/bpf/mockserver_orig_dst type hash key 8 value 6 entries 4096 name ms_orig_dst 2>&1; then
  echo "BPF_MAP_CREATE_FAILED=true"
  exit 0
fi
echo "BPF map created successfully"
bpftool map update pinned /sys/fs/bpf/mockserver_orig_dst key hex 01 00 00 00 00 00 00 00 value hex 0a 63 63 01 1f 90
echo "BPF map populated"
bpftool map dump pinned /sys/fs/bpf/mockserver_orig_dst
ls -la /sys/fs/bpf/mockserver_orig_dst
echo "BPF_MAP_READY=true"
/mock-server -Dmockserver.transparentProxyEnabled=true -Dmockserver.transparentProxyEbpf=true -Dmockserver.transparentProxyEbpfMapPath=/sys/fs/bpf/mockserver_orig_dst -Dmockserver.logLevel=INFO -serverPort 1080 &
MOCKSERVER_PID=$!
for i in $(seq 1 30); do curl -s http://localhost:1080/mockserver/status && break; sleep 1; done
curl -s -X PUT http://localhost:1080/mockserver/expectation -d "{\"httpRequest\":{\"path\":\"/.*\"},\"httpResponse\":{\"statusCode\":200,\"body\":\"ebpf-ok\"}}"
iptables -t nat -A OUTPUT -d 192.0.2.3 -p tcp --dport 8080 -j REDIRECT --to-port 1080
ip addr add 192.0.2.3/32 dev lo
HTTP_CODE=$(curl -s -o /tmp/body.txt -w "%{http_code}" http://192.0.2.3:8080/test-ebpf)
BODY=$(cat /tmp/body.txt)
echo "HTTP_CODE=$HTTP_CODE"
echo "BODY=$BODY"
kill $MOCKSERVER_PID 2>/dev/null || true
rm -f /sys/fs/bpf/mockserver_orig_dst
'
  local out
  out=$(run_case ebpf "$script" "--privileged")
  local rc=$?
  echo "$out"
  evaluate ebpf "$rc" "$out" "ebpf-ok" "BPF_UNSUPPORTED=true BPF_MAP_CREATE_FAILED=true"
}

# evaluate <name> <exit-code> <output> <expected-body-marker> <skip-markers...>
evaluate() {
  local name=$1 rc=$2 out=$3 marker=$4 skip_markers=$5
  for skip in $skip_markers; do
    if [[ "$out" == *"$skip"* ]]; then
      log "$name: SKIP ($skip)"
      return 0
    fi
  done
  if [[ "$out" == *"container not running in privileged mode"* || "$out" == *"could not select device driver"* || "$out" == *"operation not permitted"* ]]; then
    log "$name: SKIP (daemon refused the requested capability/privilege)"
    return 0
  fi
  if [[ $rc -ne 0 ]]; then
    log "$name: FAIL (container exited $rc)"
    FAILED=1
    return 1
  fi
  if [[ "$out" == *"HTTP_CODE=200"* && "$out" == *"$marker"* ]]; then
    log "$name: PASS"
    return 0
  fi
  log "$name: FAIL (expected HTTP_CODE=200 and body '$marker')"
  FAILED=1
  return 1
}

build_image

case "$CASE" in
  so-original-dst) case_so_original_dst ;;
  tproxy) case_tproxy ;;
  ebpf) case_ebpf ;;
  all)
    case_so_original_dst
    case_tproxy
    case_ebpf
    ;;
  *)
    echo "usage: $0 [so-original-dst|tproxy|ebpf|all]" >&2
    exit 2
    ;;
esac

exit $FAILED
