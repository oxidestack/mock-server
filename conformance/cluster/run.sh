#!/usr/bin/env bash
# Mixed-cluster conformance harness: our node and the oracle's clustered image (oracle.env) in one JGroups
# cluster (TCP + TCPPING, stack.xml), exercised in both directions and in both join orders.
#
#   conformance/cluster/run.sh [rs-first|java-first|all]      default all
#
# Environment: IMAGE (our image, default mock-server:latest; `make image IMAGE=...` builds it),
# JAVA_IMAGE (default ORACLE_CLUSTERED_IMAGE of oracle.env), SUFFIX (name suffix for containers and network,
# default 158), TAP=false (skip the frame tap), KEEP=true (leave containers up for inspection), PERSIST=false (no
# expectation persistence; the late joiner then restores nothing), RUN (name of this run's log directory, default a
# timestamp).
#
# Every run keeps its node logs (docker logs -t) under target/runs/<RUN>/: both nodes after the merge checks, each node
# when it is killed, the survivor at the end, and both live nodes with their GET /mockserver/cluster on every failing
# check (`<order>-<node>-fail<n>.log`).
#
# Per join order, with F the node started first (the coordinator) and S the second:
#   1. F alone: view size 1. S joins: both views size 2.
#   2. F -> S and S -> F: expectation, scenario state, service chaos profile, saved chaos-experiment profile and load
#      scenario (ChaosProfileLibrary / LoadScenarioRegistry: the `chaos-profiles` / `load-scenarios` CRUD caches),
#      clear, each created on one side and observed on the other; Times.exactly(1) and Times.exactly(3) are served that
#      often across both nodes. The running chaos experiment and quota windows are per JVM upstream
#      (ChaosExperimentOrchestrator, HttpQuotaRegistry are static singletons): the other node sees no experiment and a
#      fresh quota, on both implementations alike.
#  2b. Partition and merge: S is frozen (docker pause) past failure detection, F drops to a view of 1 and keeps
#      serving; S is thawed, MERGE3 finds the two subgroups and GMS merges them (MERGE_REQ / MERGE_RSP /
#      INSTALL_MERGE_VIEW between a Rust and a Java coordinator, whichever leads), both nodes log ISPN000093 for the
#      merged view, agree on view and coordinator, replicate again in both directions, and both serve the expectation
#      F made alone during the partition.
#   3. Kill S: F's view drops to 1 inside the failure-detection window. An expectation made on F while alone, then a
#      fresh S joins late: it gets the scenario state by state transfer, and (persistExpectations on both nodes, the
#      default here) it serves the pre-join expectation restored from the persisted document F wrote to `blobs`.
#   4. Kill F (the coordinator): S's view drops to 1 and S still serves what it had.
# Views are read from GET /mockserver/cluster (memberCount; shape and coordinator parity between the two nodes).
# Every JGroups TCP segment of the Java node is recorded by tap.py into target/frames/<order>-*.pcap; afterwards
# pcap_extract.py asserts the Cache.compute lambda each side sent equals the recorded Java vector, and dumps golden
# candidates (lambda, handshakes, first frames) to target/frames/vectors/<order>/.
#
# Exit code: 0 when every check passed; 1 otherwise. A failing check prints FAIL with the evidence and the run goes on.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
SUFFIX="${SUFFIX:-158}"
IMAGE="${IMAGE:-mock-server:latest}"
JAVA_IMAGE="${JAVA_IMAGE:-$(. "$(dirname "$0")/../../oracle.env" && echo "${ORACLE_CLUSTERED_IMAGE}")}"
TAP_IMAGE="${TAP_IMAGE:-python:3-alpine}"
NET="ms-cluster-${SUFFIX}"
CLUSTER="ms-cluster-name-${SUFFIX}"
OUT="${HERE}/target"
FRAMES="${OUT}/frames"
RUN="${RUN:-$(date +%Y%m%d-%H%M%S)}"
LOGS="${OUT}/runs/${RUN}"
ORDER="${1:-all}"
mkdir -p "${FRAMES}" "${LOGS}"

PASS=0
FAILS=0
ok() { PASS=$((PASS + 1)); echo "  ok   $*"; }
bad() { FAILS=$((FAILS + 1)); echo "  FAIL $*"; [[ -n "${TAG:-}" ]] && save_logs "${TAG}" "fail${FAILS}"; }

# save_logs <order tag> <label>: every live node's log and cluster view into this run's directory
save_logs() {
  local who n
  for who in rs java; do
    n="$(cname "${who}")"
    docker inspect "${n}" >/dev/null 2>&1 || continue
    { docker logs -t "${n}" 2>&1
      echo "--- GET /mockserver/cluster at $(date -u +%FT%TZ)"
      curl -s -m 5 "http://127.0.0.1:$(port_of "${who}")/mockserver/cluster" 2>&1
    } > "${LOGS}/$1-${who}-$2.log"
  done
}

# arrived_late <seconds> <command...>: after a failed `eventually`, whether the command is satisfied later, and when
# (a window too short under load, or never)
arrived_late() {
  local n="$1" i; shift
  for i in $(seq 1 "${n}"); do
    if "$@" >/dev/null 2>&1; then echo "       ... satisfied ${i}s after the window closed"; return 0; fi
    sleep 1
  done
  echo "       ... still not satisfied ${n}s after the window closed"; return 1
}

cname() { echo "ms-$1-${SUFFIX}"; }          # cname rs|java
IMG() { if [[ "$1" == rs ]]; then echo "${IMAGE}"; else echo "${JAVA_IMAGE}"; fi; }

port_of() {  # host port of a node's 1080
  docker port "$(cname "$1")" 1080/tcp 2>/dev/null | head -1 | sed 's/.*://'
}

start_node() {  # start_node <rs|java> <tag>
  local who="$1" tag="$2" name
  name="$(cname "${who}")"
  # persistExpectations: a clustered node writes the document to the replicated `blobs` cache under the file name
  # (same name on both nodes, so both use one key) and restores from it at start. The directory is one the image's
  # user can write to.
  local persist=()
  if [[ "${PERSIST:-true}" != false ]]; then
    local dir=/config; [[ "$(IMG "${who}")" == "${JAVA_IMAGE}" ]] && dir=/tmp
    persist=(-e MOCKSERVER_PERSIST_EXPECTATIONS=true -e "MOCKSERVER_PERSISTED_EXPECTATIONS_PATH=${dir}/cluster-persisted-${SUFFIX}.json")
  fi
  docker rm -f "${name}" >/dev/null 2>&1
  docker run -d --name "${name}" --network "${NET}" -p 127.0.0.1::1080 \
    -v "${HERE}/stack.xml:/stack.xml:ro" \
    -e INITIAL_HOSTS="$(cname java)[7800],$(cname rs)[7800]" \
    -e MOCKSERVER_STATE_BACKEND=infinispan \
    -e MOCKSERVER_CLUSTER_ENABLED=true \
    -e MOCKSERVER_CLUSTER_NAME="${CLUSTER}" \
    -e MOCKSERVER_CLUSTER_TRANSPORT_CONFIG=/stack.xml \
    -e MOCKSERVER_LOG_LEVEL=INFO \
    ${persist[@]+"${persist[@]}"} \
    "$(IMG "${who}")" >/dev/null || return 1
  if [[ "${who}" == java && "${TAP:-true}" != false ]]; then
    docker rm -f "ms-tap-${SUFFIX}" >/dev/null 2>&1
    docker inspect -f '{{(index .NetworkSettings.Networks "'"${NET}"'").IPAddress}}' "${name}" > "${FRAMES}/${tag}-java.ip"
    docker run -d --name "ms-tap-${SUFFIX}" --network "container:${name}" --cap-add NET_RAW \
      -v "${HERE}:/h:ro" -v "${FRAMES}:/out" "${TAP_IMAGE}" python3 /h/tap.py "/out/${tag}-java.pcap" 7800 >/dev/null
  fi
  wait_ready "${who}"
}

wait_ready() {  # wait_ready <rs|java>: the control plane answers
  local p i
  for i in $(seq 1 90); do
    p="$(port_of "$1")"
    if [[ -n "${p}" ]] && [[ "$(curl -s -o /dev/null -w '%{http_code}' -X PUT "http://127.0.0.1:${p}/mockserver/status" 2>/dev/null)" == 200 ]]; then return 0; fi
    sleep 1
  done
  bad "$1 did not become ready"; docker logs "$(cname "$1")" 2>&1 | tail -20; return 1
}

kill_node() {  # SIGKILL: no leave message, the survivor must detect it
  docker kill "$(cname "$1")" >/dev/null 2>&1
  docker rm -f "ms-tap-${SUFFIX}" >/dev/null 2>&1
  docker logs -t "$(cname "$1")" > "${LOGS}/$2-$1-killed.log" 2>&1
  docker rm -f "$(cname "$1")" >/dev/null 2>&1
}

# The size of the node's current cluster view, read from GET /mockserver/cluster (ClusterInfo.memberCount).
view_size() {
  local p; p="$(port_of "$1")"
  [[ -n "${p}" ]] || return 0
  curl -s "http://127.0.0.1:${p}/mockserver/cluster" 2>/dev/null | jq -r '.memberCount // empty' 2>/dev/null
}

# cluster_shape <node>: what both implementations must report alike, member ids masked (they differ by design).
cluster_shape() {
  curl -s "http://127.0.0.1:$(port_of "$1")/mockserver/cluster" 2>/dev/null | jq -c '. as $r | {
    clustered, memberCount,
    keys: (keys | sort), memberKeys: (($r.members[0] // {}) | keys | sort),
    nodeIsMember: ([$r.members[].id] | index($r.nodeId) != null),
    coordinatorIsMember: ([$r.members[] | select(.id == $r.coordinator and .coordinator)] | length == 1),
    localIsNode: ([$r.members[] | select(.local) | .id] == [$r.nodeId])
  }' 2>/dev/null
}

wait_view() {  # wait_view <node> <size> <seconds> <what>
  local i n
  for i in $(seq 1 "$3"); do
    n="$(view_size "$1")"
    if [[ "${n}" == "$2" ]]; then ok "$4 (view size $2 after ${i}s)"; return 0; fi
    sleep 1
  done
  bad "$4: view size '${n:-none}' after $3s, wanted $2"
  docker logs "$(cname "$1")" 2>&1 | grep -E 'ISPN0000(93|94)|WARN|ERROR' | tail -8
  body "$1" /mockserver/cluster
  return 1
}

# curl against a node's control plane or data plane: api <node> <METHOD> <path> [body]
api() {
  local p; p="$(port_of "$1")"
  if [[ -n "${4:-}" ]]; then curl -s -X "$2" "http://127.0.0.1:${p}$3" -d "$4"; else curl -s -X "$2" "http://127.0.0.1:${p}$3"; fi
}
code() { curl -s -o /dev/null -w '%{http_code}' -X "${3:-GET}" "http://127.0.0.1:$(port_of "$1")$2"; }
body() { curl -s "http://127.0.0.1:$(port_of "$1")$2"; }

# eventually <seconds> <what> <command...>: poll until the command succeeds (replication is asynchronous to the caller)
eventually() {
  local n="$1" what="$2" i; shift 2
  for i in $(seq 1 $((n * 2))); do
    if "$@" >/dev/null 2>&1; then ok "${what}"; return 0; fi
    sleep 0.5
  done
  bad "${what} (not satisfied in ${n}s)"; return 1
}

has_body() { [[ "$(body "$1" "$2")" == *"$3"* ]]; }
# an unmatched request is 404, or 502 when the Host header is not the node's own (MockServer's exploratory proxy)
not_served() { [[ "$(code "$1" "$2")" != 200 ]]; }
listed() { [[ "$(api "$1" PUT '/mockserver/retrieve?type=ACTIVE_EXPECTATIONS')" == *"$2"* ]]; }
chaos_listed() { [[ "$(api "$1" GET /mockserver/serviceChaos)" == *"$2"* ]]; }
chaos_absent() { [[ "$(api "$1" GET /mockserver/serviceChaos)" != *"$2"* ]]; }
profile_absent() { [[ "$(body "$1" /mockserver/chaosExperiment/profiles)" != *"\"$2\""* ]]; }
load_absent() { [[ "$(body "$1" /mockserver/loadScenario)" != *"\"$2\""* ]]; }

# ops <writer> <reader> <tag>: everything created on the writer is observed on the reader
ops() {
  local w="$1" r="$2" t="$3"
  echo " ${w} -> ${r}"
  api "${w}" PUT /mockserver/reset >/dev/null
  # expectation
  api "${w}" PUT /mockserver/expectation "{\"id\":\"e-${t}\",\"httpRequest\":{\"path\":\"/e-${t}\"},\"httpResponse\":{\"body\":\"from-${w}\"}}" >/dev/null
  eventually 10 "expectation from ${w} is served by ${r}" has_body "${r}" "/e-${t}" "from-${w}"
  # scenario state: the transition happens on the reader, the writer sees it
  api "${w}" PUT /mockserver/expectation "[{\"httpRequest\":{\"path\":\"/c-${t}\"},\"httpResponse\":{\"body\":\"empty\"},\"scenarioName\":\"s-${t}\",\"scenarioState\":\"Started\",\"newScenarioState\":\"Filled\"},{\"httpRequest\":{\"path\":\"/c-${t}\"},\"httpResponse\":{\"body\":\"filled\"},\"scenarioName\":\"s-${t}\",\"scenarioState\":\"Filled\"}]" >/dev/null
  eventually 10 "scenario expectations from ${w} reached ${r}" has_body "${r}" "/c-${t}" "empty"
  eventually 10 "scenario state set on ${r} is seen on ${w}" has_body "${w}" "/mockserver/scenario/s-${t}" "Filled"
  eventually 10 "scenario step 2 served by ${w}" has_body "${w}" "/c-${t}" "filled"
  # service chaos profile
  api "${w}" PUT /mockserver/serviceChaos "{\"host\":\"svc-${t}.test\",\"chaos\":{\"errorStatus\":503}}" >/dev/null
  eventually 10 "service chaos profile from ${w} listed on ${r}" chaos_listed "${r}" "svc-${t}.test"
  api "${w}" PUT /mockserver/serviceChaos '{"clear":true}' >/dev/null
  eventually 10 "service chaos clear from ${w} reached ${r}" chaos_absent "${r}" "svc-${t}.test"
  # saved chaos-experiment profile (ChaosProfileLibrary, crudEntities("chaos-profiles"))
  api "${w}" PUT "/mockserver/chaosExperiment/profiles/p-${t}" '{"stages":[{"durationMillis":600000,"profiles":{"p.svc":{"errorStatus":502}}}]}' >/dev/null
  eventually 10 "saved chaos profile from ${w} listed on ${r}" has_body "${r}" /mockserver/chaosExperiment/profiles "\"p-${t}\""
  eventually 10 "saved chaos profile from ${w} readable on ${r}" has_body "${r}" "/mockserver/chaosExperiment/profiles/p-${t}" '"errorStatus" : 502'
  api "${w}" DELETE "/mockserver/chaosExperiment/profiles/p-${t}" >/dev/null
  eventually 10 "saved chaos profile delete from ${w} reached ${r}" profile_absent "${r}" "p-${t}"
  # load scenario definition (LoadScenarioRegistry, crudEntities("load-scenarios")), stored, not started
  api "${w}" PUT /mockserver/loadScenario "{\"name\":\"ls-${t}\",\"steps\":[{\"request\":{\"method\":\"GET\",\"path\":\"/ls-${t}\"}}],\"profile\":{\"stages\":[{\"vus\":1,\"durationMillis\":1000}]}}" >/dev/null
  eventually 10 "load scenario from ${w} listed on ${r}" has_body "${r}" /mockserver/loadScenario "\"ls-${t}\""
  api "${w}" DELETE "/mockserver/loadScenario/ls-${t}" >/dev/null
  eventually 10 "load scenario delete from ${w} reached ${r}" load_absent "${r}" "ls-${t}"
  # a running chaos experiment is the writer's own (a static ChaosExperimentOrchestrator per JVM)
  api "${w}" PUT /mockserver/chaosExperiment "{\"name\":\"x-${t}\",\"stages\":[{\"durationMillis\":600000,\"profiles\":{\"x-${t}.test\":{\"errorStatus\":503}}}]}" >/dev/null
  if has_body "${w}" /mockserver/chaosExperiment "x-${t}"; then ok "chaos experiment runs on ${w}"; else bad "chaos experiment did not start on ${w}: $(body "${w}" /mockserver/chaosExperiment | tr -d '\n ')"; fi
  sleep 2
  if has_body "${r}" /mockserver/chaosExperiment '"status" : "none"'; then ok "chaos experiment from ${w} is not running on ${r} (per JVM)"; else bad "chaos experiment from ${w} seen on ${r}: $(body "${r}" /mockserver/chaosExperiment | tr -d '\n ')"; fi
  api "${w}" DELETE /mockserver/chaosExperiment >/dev/null
  api "${w}" PUT /mockserver/serviceChaos '{"clear":true}' >/dev/null
  # quota windows are the node's own (a static HttpQuotaRegistry per JVM): limit 1 is spent on the writer only
  api "${w}" PUT /mockserver/expectation "{\"httpRequest\":{\"path\":\"/quota-${t}\"},\"httpResponse\":{\"body\":\"q\"},\"chaos\":{\"quotaName\":\"q-${t}\",\"quotaLimit\":1,\"quotaWindowMillis\":600000}}" >/dev/null
  eventually 10 "quota expectation from ${w} reached ${r}" listed "${r}" "/quota-${t}"
  local q1 q2 q3
  q1="$(code "${w}" "/quota-${t}")"; q2="$(code "${w}" "/quota-${t}")"; q3="$(code "${r}" "/quota-${t}")"
  if [[ "${q1}" == 200 && "${q2}" == 429 && "${q3}" == 200 ]]; then ok "quota q-${t} is per node (${w}: ${q1} ${q2}, ${r}: ${q3})"; else bad "quota q-${t}: ${w}=${q1} ${q2} ${r}=${q3}, wanted 200 429 then 200 on the other node"; fi
  # Times.exactly(1): one answer in total across both nodes
  api "${w}" PUT /mockserver/expectation "{\"httpRequest\":{\"path\":\"/once-${t}\"},\"httpResponse\":{\"body\":\"once\"},\"times\":{\"remainingTimes\":1,\"unlimited\":false}}" >/dev/null
  eventually 10 "Times(1) expectation from ${w} reached ${r}" listed "${r}" "/once-${t}"
  local c1 c2 c3
  c1="$(code "${w}" "/once-${t}")"; c2="$(code "${r}" "/once-${t}")"; c3="$(code "${w}" "/once-${t}")"
  if [[ "${c1}" == 200 && "${c2}" != 200 && "${c3}" != 200 ]]; then ok "Times(1) from ${w} served once fleet-wide (${c1} ${c2} ${c3})"; else bad "Times(1) from ${w}: ${w}=${c1} ${r}=${c2} ${w}=${c3}, wanted 200 then not served"; fi
  # Times.exactly(3): three answers in total, alternating nodes
  api "${w}" PUT /mockserver/expectation "{\"httpRequest\":{\"path\":\"/thrice-${t}\"},\"httpResponse\":{\"body\":\"t\"},\"times\":{\"remainingTimes\":3,\"unlimited\":false}}" >/dev/null
  eventually 10 "Times(3) expectation from ${w} reached ${r}" listed "${r}" "/thrice-${t}"
  local got="" n
  for n in "${w}" "${r}" "${w}" "${r}" "${w}"; do
    if [[ "$(code "${n}" "/thrice-${t}")" == 200 ]]; then got="${got}Y"; else got="${got}n"; fi
  done
  if [[ "${got}" == YYYnn ]]; then ok "Times(3) from ${w} served 3 times fleet-wide (${got})"; else bad "Times(3) from ${w}: ${got} (Y served, n not), wanted YYYnn"; fi
  # clear (by path) on the writer reaches the reader
  api "${w}" PUT "/mockserver/clear?type=EXPECTATIONS" "{\"path\":\"/e-${t}\"}" >/dev/null
  eventually 10 "clear on ${w} reached ${r}" not_served "${r}" "/e-${t}"
  api "${w}" PUT /mockserver/reset >/dev/null
  eventually 10 "reset on ${w} emptied ${r}" not_served "${r}" "/c-${t}"
}

# wire_checks <order tag>: assertions on the pcaps of the Java node (the tap sees both directions of its port 7800).
# The Cache.compute lambda each side sends must be the descriptor recorded from the real class.
wire_checks() {
  [[ "${TAP:-true}" != false ]] || return 0
  echo " wire assertions on the ${1} frames"
  local out who
  out="$(python3 "${HERE}/pcap_extract.py" --vectors "${HERE}/../../tests/files/cluster/write_commands.hex" --dump "${FRAMES}/vectors/${1}" --gms "${FRAMES}/${1}"-*-java.pcap 2>&1)"
  echo "${out}" | sed 's/^/    /'
  for who in java rs; do
    if grep -q "ok .* ${who} node put [1-9][0-9]* compute lambda" <<<"${out}"; then ok "${who} node put the compute lambda on the wire (${1})"; else bad "${who} node put no compute lambda on the wire (${1})"; fi
    if grep -q "FAIL ${who} descriptor differs" <<<"${out}"; then bad "${who} compute lambda differs from the golden vector (${1})"; elif grep -q "ok .* ${who} descriptor equals the golden" <<<"${out}"; then ok "${who} compute lambda equals the golden vector (${1})"; fi
  done
  # the merge of step 2b on the wire: one coordinator leads (MERGE_REQ, INSTALL_MERGE_VIEW), the other answers
  # (MERGE_RSP); which one leads depends on the random UUIDs
  local n leader=""
  n() { grep -E "gms $1 $2 " <<<"${out}" | awk '{print $4}'; }
  for who in java rs; do
    if [[ -n "$(n "${who}" MERGE_REQ)" && -n "$(n "${who}" INSTALL_MERGE_VIEW)" ]]; then leader="${who}"; fi
  done
  if [[ -n "${leader}" ]]; then
    local other=rs; [[ "${leader}" == rs ]] && other=java
    ok "${leader} led the merge: MERGE_REQ x$(n "${leader}" MERGE_REQ), INSTALL_MERGE_VIEW x$(n "${leader}" INSTALL_MERGE_VIEW) (${1})"
    if [[ -n "$(n "${other}" MERGE_RSP)" ]]; then ok "${other} answered the merge with MERGE_RSP x$(n "${other}" MERGE_RSP) (${1})"; else bad "${other} sent no MERGE_RSP (${1})"; fi
  else
    bad "no node sent MERGE_REQ and INSTALL_MERGE_VIEW (${1})"
  fi
  # A coordinator's VIEW (and a merge's GET_DIGEST_REQ) is one multicast through NAKACK2 on both
  # implementations (GMS.castViewChangeAndSendJoinRsps, Merger.fetchDigestsFromAllMembersInSubPartition): every such
  # frame with a NAKACK2 MSG header has TP's MULTICAST flag, and none carries a UNICAST3 header. A frame with a NAKACK2
  # XMIT_RSP header is a retransmission answering the peer's XMIT_REQ, sent to the requester alone with
  # use_mcast_xmit="false" (stack.xml; NAKACK2.sendXmitRsp): it must be a unicast. The first node coordinates the
  # join, so it always casts a VIEW; the second casts one only when it coordinates a subgroup or the merged view
  # (it may merge before installing a view of its own, and the merged coordinator is the lowest address), so its
  # frames are checked when there are any, as are GET_DIGEST_REQ frames.
  local line kind
  for who in java rs; do
    for kind in VIEW GET_DIGEST_REQ; do
      line="$(grep -E "gmscast ${who} ${kind} " <<<"${out}")"
      [[ -n "${line}" ]] || { [[ "${kind}" == VIEW && "${who}" == "${1%-first}" ]] && bad "${who} sent no VIEW frame (${1})"; continue; }
      if [[ "${line}" =~ msg_mcast=[1-9][0-9]*\ msg_ucast=0\ xmit_mcast=0\ xmit_ucast=[0-9]+\ unicast3=0\ bare=0$ ]]; then
        ok "${who} ${kind}: every NAKACK2 MSG frame a multicast, retransmissions unicast (${line#*${kind} }) (${1})"
      else
        bad "${who} ${kind}: not every NAKACK2 MSG frame a multicast (${line#*${kind} }) (${1})"
      fi
    done
  done
}

run_order() {  # run_order <first> <second>
  local F="$1" S="$2" tag="$1-first"
  TAG="${tag}"
  echo "== join order ${tag}: ${F} coordinates"
  docker network rm "${NET}" >/dev/null 2>&1
  docker network create "${NET}" >/dev/null || { bad "network"; return; }
  start_node "${F}" "${tag}-1" || return
  wait_view "${F}" 1 30 "${F} alone forms a view of 1"
  start_node "${S}" "${tag}-2" || return
  wait_view "${F}" 2 40 "${F} sees ${S} join"
  wait_view "${S}" 2 40 "${S} joined ${F}'s view"
  local fs ss
  fs="$(cluster_shape "${F}")"; ss="$(cluster_shape "${S}")"
  if [[ -n "${fs}" && "${fs}" == "${ss}" ]]; then ok "GET /mockserver/cluster has the same shape on both nodes: ${fs}"; else bad "GET /mockserver/cluster shapes differ: ${F}=${fs} ${S}=${ss}"; fi
  # Every member id on both nodes is a JGroups logical name, `<host>-<n>`, never a bare UUID.
  local who ids
  for who in "${F}" "${S}"; do
    ids="$(body "${who}" /mockserver/cluster | jq -r '[.nodeId, .coordinator, (.members[] | .id)] | .[]' 2>/dev/null)"
    if [[ -n "${ids}" ]] && ! grep -Evq '^.+-[0-9]+$' <<<"${ids}" && ! grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' <<<"${ids}"; then ok "${who} reports logical-name member ids ($(tr '\n' ' ' <<<"${ids}" | cut -c1-80))"; else bad "${who} reports ids that are not <host>-<n> names: ${ids}"; fi
  done
  same_coordinator() { [[ "$(body "${F}" /mockserver/cluster | jq -r .coordinator)" == "$(body "${S}" /mockserver/cluster | jq -r .coordinator)" ]]; }
  eventually 10 "both nodes name the same coordinator" same_coordinator || echo "       ${F} says $(body "${F}" /mockserver/cluster | jq -c '[.nodeId,.coordinator]'), ${S} says $(body "${S}" /mockserver/cluster | jq -c '[.nodeId,.coordinator]')"
  if [[ "$(body "${F}" /mockserver/cluster | jq -r '.members[] | select(.local) | .coordinator')" == true ]]; then ok "${F} flags itself coordinator"; else bad "${F} is not coordinator in its own view"; fi
  if [[ "$(body "${S}" /mockserver/cluster | jq -r '.members[] | select(.local) | .coordinator')" == false ]]; then ok "${S} is not flagged coordinator"; else bad "${S} is flagged coordinator"; fi
  ops "${F}" "${S}" "${F}a"
  ops "${S}" "${F}" "${S}b"

  echo " partition ${S} (frozen past failure detection), then merge"
  docker pause "$(cname "${S}")" >/dev/null
  wait_view "${F}" 1 40 "${F} drops to view 1 while ${S} is partitioned"
  api "${F}" PUT /mockserver/expectation '{"id":"split","httpRequest":{"path":"/split"},"httpResponse":{"body":"made-while-split"}}' >/dev/null
  has_body "${F}" /split made-while-split && ok "${F} serves alone during the partition" || bad "${F} does not serve during the partition"
  # a second local add reconciles F against its own replica: /split still listed means its backend put landed
  api "${F}" PUT /mockserver/expectation '{"id":"split-2","httpRequest":{"path":"/split-2"},"httpResponse":{"body":"made-while-split"}}' >/dev/null
  eventually 5 "${F} keeps /split in its replica during the partition (listed after a second local add)" listed "${F}" '"id" : "split-2"'
  listed "${F}" '"id" : "split"' && ok "${F} still lists /split after reconciling with its replica" || bad "${F} dropped /split from its replica during the partition"
  docker unpause "$(cname "${S}")" >/dev/null
  local i alone=""
  for i in $(seq 1 40); do
    [[ "$(view_size "${S}")" == 1 ]] && { alone="after ${i}s"; break; }
    [[ "$(view_size "${F}")" == 2 ]] && break
    sleep 1
  done
  echo "       ${S} alone in its own view: ${alone:-not observed (merged first)}"
  wait_view "${F}" 2 60 "${F} merged with ${S}"
  wait_view "${S}" 2 60 "${S} merged with ${F}"
  eventually 15 "both nodes name the same coordinator after the merge" same_coordinator
  # GET /mockserver/cluster reads the JGroups view, which can be installed before Infinispan's view listener logs it.
  # Not `grep -q`: it exits at the match, and docker logs, still writing, dies of SIGPIPE, which pipefail reports as a
  # failure (seen 3 times in 20 merges, with the line already in the log).
  logged_merge() { docker logs "$(cname "$1")" 2>&1 | grep 'ISPN000093: Received new, MERGED cluster view' >/dev/null; }
  for who in "${F}" "${S}"; do
    eventually 15 "${who} logged ISPN000093 for the merged view" logged_merge "${who}"
  done
  # A write F makes before it installs the merge's rebalance topology (S not yet an owner) reaches S only
  # by state transfer, which fires no cache event (CacheNotifierImpl skips PUT_FOR_STATE_TRANSFER), so S's
  # RequestMatchers does not serve it until its next reconcile (a local add), on a Java reader too. Under load the
  # coordinator's rebalance can lag the merged view by seconds, so the replication checks start once a probe written on
  # F is served by S.
  local k settled=""
  for k in $(seq 1 20); do
    api "${F}" PUT /mockserver/expectation "{\"id\":\"settle-${k}\",\"httpRequest\":{\"path\":\"/settle-${k}\"},\"httpResponse\":{\"body\":\"settled\"}}" >/dev/null
    for i in 1 2 3 4 5 6; do has_body "${S}" "/settle-${k}" settled && { settled="${k}"; break 2; }; sleep 0.5; done
  done
  if [[ -n "${settled}" ]]; then ok "merge rebalance settled: probe ${settled} from ${F} served by ${S}"; else bad "no probe from ${F} served by ${S} after the merge (20 probes, 3 s each)"; fi
  api "${F}" PUT /mockserver/expectation '{"id":"m-f","httpRequest":{"path":"/merged-f"},"httpResponse":{"body":"from-f"}}' >/dev/null
  eventually 15 "after the merge ${F} -> ${S} replicates" has_body "${S}" /merged-f from-f || arrived_late 60 has_body "${S}" /merged-f from-f
  api "${S}" PUT /mockserver/expectation '{"id":"m-s","httpRequest":{"path":"/merged-s"},"httpResponse":{"body":"from-s"}}' >/dev/null
  eventually 15 "after the merge ${S} -> ${F} replicates" has_body "${F}" /merged-s from-s || arrived_late 60 has_body "${F}" /merged-s from-s
  save_logs "${tag}" merged
  # What F made alone survives the merge on both nodes (java+java: 5 of 5 runs); S reconciled with its
  # replica on the m-s add above. A woken S that still multicasts in the old view must not get its history replayed on
  # F (NAKACK2 discards a sender outside the view): a replay re-applied S's last reset and emptied F's caches.
  for who in "${F}" "${S}"; do
    eventually 15 "/split (made on ${F} during the partition) is served by ${who} after the merge" has_body "${who}" /split made-while-split
  done

  echo " kill ${S} (non-coordinator)"
  kill_node "${S}" "${tag}-1"
  wait_view "${F}" 1 40 "${F} drops to view 1 after ${S} is killed"
  api "${F}" PUT /mockserver/reset >/dev/null
  api "${F}" PUT /mockserver/expectation '{"id":"late","httpRequest":{"path":"/late"},"httpResponse":{"body":"made-alone"}}' >/dev/null
  api "${F}" PUT /mockserver/expectation '[{"httpRequest":{"path":"/lc"},"httpResponse":{"body":"x"},"scenarioName":"late-s","scenarioState":"Started","newScenarioState":"Moved"}]' >/dev/null
  code "${F}" /lc >/dev/null
  echo " late join of ${S}"
  start_node "${S}" "${tag}-3" || return
  wait_view "${S}" 2 40 "late ${S} joined ${F}"
  eventually 15 "late ${S} received the scenario state by state transfer" has_body "${S}" /mockserver/scenario/late-s Moved
  if [[ "${PERSIST:-true}" != false ]]; then
    # The joiner restores the persisted document F wrote to `blobs` while alone (ExpectationFileSystemPersistence's
    # blob-store restore at start, cause blobstore:<file name>).
    eventually 20 "late ${S} serves the pre-join expectation restored from blobs" has_body "${S}" /late made-alone
    eventually 10 "late ${S} lists the restored expectation under its id" listed "${S}" '"id" : "late"'
  else
    # Without persistence (java+java likewise): a joiner's request matchers are rebuilt only from cache events and
    # from the persistence reload, not from state transfer, so an expectation made before the join is not served.
    sleep 3
    if not_served "${S}" /late; then ok "late ${S} does not serve the pre-join expectation (same as java+java)"; else bad "late ${S} serves the pre-join expectation (java+java does not)"; fi
  fi
  api "${F}" PUT /mockserver/expectation '{"id":"post","httpRequest":{"path":"/post"},"httpResponse":{"body":"after-join"}}' >/dev/null
  eventually 10 "expectation made after the late join is served by ${S}" has_body "${S}" /post after-join

  echo " kill ${F} (coordinator)"
  kill_node "${F}" "${tag}-2"
  wait_view "${S}" 1 40 "${S} drops to view 1 after the coordinator ${F} is killed"
  has_body "${S}" /post after-join && ok "${S} still serves the replicated expectation as the new coordinator" || bad "${S} lost the expectation"
  docker logs -t "$(cname "${S}")" > "${LOGS}/${tag}-${S}-final.log" 2>&1
  wire_checks "${tag}"
  [[ "${KEEP:-}" == true ]] || cleanup_nodes
}

cleanup_nodes() {
  docker rm -f "$(cname rs)" "$(cname java)" "ms-tap-${SUFFIX}" >/dev/null 2>&1
  docker network rm "${NET}" >/dev/null 2>&1
}
trap '[[ "${KEEP:-}" == true ]] || cleanup_nodes' EXIT

cleanup_nodes
case "${ORDER}" in
  rs-first) run_order rs java ;;
  java-first) run_order java rs ;;
  all) run_order rs java; run_order java rs ;;
  *) echo "usage: $0 [rs-first|java-first|all]" >&2; exit 2 ;;
esac
echo
TAG=""
echo "passed=${PASS} failed=${FAILS}; frames in ${FRAMES}, logs in ${LOGS}"
[[ "${FAILS}" -eq 0 ]]
