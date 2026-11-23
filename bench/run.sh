#!/usr/bin/env bash
# The same load against MockServer (the image oracle.env pins) and mock-server, written down as measured.
# bench/README.md says what it measures and how; every parameter below is an environment variable.
#
# Every measurement starts a fresh container of one server, alone on a user-defined bridge network with `--cpus $CPUS`,
# loads its expectations, warms it up for $WARMUP s, waits for its console to settle, and runs `oha` (in a container
# on the same network) for $DURATION s with $CONNECTIONS connections. Around that window it reads the container's
# cgroup (cpu.stat, memory.peak), the server's VmHWM and its console log. $ROUNDS rounds, the servers' order
# alternating between rounds. Everything read goes into $RUN_DIR; results.json there is assembled from it.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../oracle.env
. "$here/../oracle.env"

IMAGE=${IMAGE:-mock-server:latest}               # ours
CPUS=${CPUS:-2}                                  # each server's --cpus
CONNECTIONS=${CONNECTIONS:-64}                   # oha -c
WARMUP=${WARMUP:-20}                             # seconds of load before the window (the JVM's JIT needs 10-20 s)
DURATION=${DURATION:-15}                         # seconds of the measured window
ROUNDS=${ROUNDS:-3}
LEVELS=${LEVELS:-INFO WARN}                      # MOCKSERVER_LOG_LEVEL, both servers
EXPECTATIONS=${EXPECTATIONS:-1 1000}             # GET /e0 .. /e<n-1>, each answered with its name
REQUESTS=${REQUESTS:-matched unmatched}          # matched: GET /e<n-1>; unmatched: GET /none, answered 404
SERVERS=${SERVERS:-oracle ours}
# Configurations, `;`-separated; each is `default` or space-separated NAME=VALUE environment variables.
OURS_CONFIGS=${OURS_CONFIGS:-default;MOCKSERVER_MAX_LOG_ENTRIES=100000}
ORACLE_CONFIGS=${ORACLE_CONFIGS:-default}
METRICS=${METRICS:-false}                        # MOCKSERVER_METRICS_ENABLED, both servers
SETTLE_MAX=${SETTLE_MAX:-60}                     # longest wait, in seconds, for a console to stop growing
# ALLOC_IMAGE: an image of ours built with the alloc-count feature; when set, one more pass per case of ours counts
# allocator calls per request with it (`docker build --build-arg CARGO_FEATURES=alloc-count -t <tag> .`).
ALLOC_IMAGE=${ALLOC_IMAGE:-}
MACHINE_KIND=${MACHINE_KIND:-Docker host}        # how results.json names the machine (a cloud VM, a laptop's VM)
NOTE=${NOTE:-}                                   # a sentence results.json and the page carry
RUN_DIR=${RUN_DIR:-$here/runs/$(date -u +%Y%m%dT%H%M%SZ)}
# RESULTS=<file>: also copy results.json there and pack the run directory beside it as <file without .json>-raw.tar.gz
RESULTS=${RESULTS:-}

OHA_IMAGE=ghcr.io/hatoo/oha:1.17.0@sha256:9e8cd7468794d692acda410de42738aa1d2fa0268a5c56d1d58581874ee2b0eb
CURL_IMAGE=curlimages/curl:8.16.0@sha256:463eaf6072688fe96ac64fa623fe73e1dbe25d8ad6c34404a669ad3ce1f104b6
NET=mock-server-bench
PROBE=mock-server-bench-probe
SUT=mock-server-bench-server
# The Host header every request carries: a name both servers take as their own, so an unmatched request is answered
# 404 instead of proxied (attemptToProxyIfNoMatchingExpectation, on by default, forwards a request naming another host).
HOST_HEADER=localhost:1080

mkdir -p "$RUN_DIR/raw"
RUN_DIR=$(cd "$RUN_DIR" && pwd)
LOG="$RUN_DIR/run.log"
say() { printf '%s\n' "$*" | tee -a "$LOG"; }

cleanup() {
  docker rm -f -v "$SUT" "$PROBE" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create "$NET" >/dev/null

# The probe: on the network (curl), in the host's PID namespace (/proc/<pid>/status), with the host's cgroup tree and
# container logs read-only (cpu.stat, memory.peak, the json-file console log).
DOCKER_ROOT=$(docker info -f '{{.DockerRootDir}}')
LOG_DRIVER=$(docker info -f '{{.LoggingDriver}}')
[ "$LOG_DRIVER" = json-file ] || { echo "bench/run.sh reads the console from the json-file log driver; Docker's default is $LOG_DRIVER" >&2; exit 1; }
docker run -d --name "$PROBE" --network "$NET" --pid host --user 0 \
  -v /sys/fs/cgroup:/cg:ro -v "$DOCKER_ROOT/containers:/dc:ro" --entrypoint sleep "$CURL_IMAGE" infinity >/dev/null
probe() { docker exec "$PROBE" sh -c "$1"; }
probe 'test -f /cg/cgroup.controllers' || { echo "bench/run.sh needs cgroup v2 on the Docker host" >&2; exit 1; }

image_ref() {  # name, then the image's id and repository digests, as one JSON object
  docker image inspect -f '{"name":"'"$1"'","id":"{{.Id}}","digests":[{{range $i, $d := .RepoDigests}}{{if $i}},{{end}}"{{$d}}"{{end}}]}' "$1"
}
for image in "$IMAGE" "$ORACLE_IMAGE" "$OHA_IMAGE" ${ALLOC_IMAGE:+"$ALLOC_IMAGE"}; do
  docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null
done

# The run's environment, before the load.
# Docker's own description of the host, read for meta.json and not kept: it also names the host and its registries.
docker info --format '{{json .}}' >"$RUN_DIR/docker-info.json"
{
  printf '{"ours":%s,"oracle":%s,"oha":%s,"alloc_count":%s}' "$(image_ref "$IMAGE")" "$(image_ref "$ORACLE_IMAGE")" \
    "$(image_ref "$OHA_IMAGE")" "$(if [ -n "$ALLOC_IMAGE" ]; then image_ref "$ALLOC_IMAGE"; else echo null; fi)"
} >"$RUN_DIR/images.json"
# the CPU's name: lscpu on a Linux host, the Mac's own name under a Docker VM on macOS, else the Docker host's cpuinfo
cpu_model=$( (lscpu 2>/dev/null | sed -n 's/^Model name:[[:space:]]*//p' | head -1) || true)
[ -n "$cpu_model" ] || cpu_model=$( (sysctl -n machdep.cpu.brand_string 2>/dev/null) || true)
[ -n "$cpu_model" ] || cpu_model=$(probe "sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1")
[ -n "$cpu_model" ] || cpu_model=$(probe "awk -F': ' '/^CPU implementer/{i=\$2} /^CPU part/{p=\$2} END{if (i) print \"implementer \" i \", part \" p}' /proc/cpuinfo")
commit=$(git -C "$here" rev-parse HEAD 2>/dev/null || echo unknown)
dirty=false
git -C "$here" diff --quiet HEAD 2>/dev/null || dirty=true
COMMIT=$commit DIRTY=$dirty CPU_MODEL=$cpu_model LOAD_START=$(probe 'cut -d" " -f1-3 /proc/loadavg') \
  IMAGE=$IMAGE CPUS=$CPUS CONNECTIONS=$CONNECTIONS WARMUP=$WARMUP DURATION=$DURATION ROUNDS=$ROUNDS LEVELS=$LEVELS \
  EXPECTATIONS=$EXPECTATIONS REQUESTS=$REQUESTS SERVERS=$SERVERS OURS_CONFIGS=$OURS_CONFIGS \
  ORACLE_CONFIGS=$ORACLE_CONFIGS METRICS=$METRICS SETTLE_MAX=$SETTLE_MAX HOST_HEADER=$HOST_HEADER \
  MACHINE_KIND=$MACHINE_KIND NOTE=$NOTE ORACLE_VERSION=$ORACLE_VERSION \
  python3 - "$RUN_DIR" <<'PY'
import json, os, sys, datetime
e = os.environ
run = sys.argv[1]
info = json.load(open(f"{run}/docker-info.json"))
meta = {
  "started": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
  "command": "bench/run.sh",
  "commit": e["COMMIT"], "uncommitted_changes": e["DIRTY"] == "true",
  "note": e["NOTE"] or None,
  "oracle_version": e["ORACLE_VERSION"],
  "images": json.load(open(f"{run}/images.json")),
  "machine": {"kind": e["MACHINE_KIND"], "arch": info.get("Architecture"), "cpu_model": e["CPU_MODEL"] or None,
              "vcpus": info.get("NCPU"), "memory_gib": round(info.get("MemTotal", 0) / 2**30, 1),
              "os": info.get("OperatingSystem"), "kernel": info.get("KernelVersion"), "docker": info.get("ServerVersion"),
              "cgroup": f"v{info.get('CgroupVersion')}, {info.get('CgroupDriver')}", "log_driver": info.get("LoggingDriver")},
  "load_average_start": [float(x) for x in e["LOAD_START"].split()],
  "params": {"cpus": float(e["CPUS"]), "connections": int(e["CONNECTIONS"]), "warmup_s": int(e["WARMUP"]),
             "duration_s": int(e["DURATION"]), "rounds": int(e["ROUNDS"]), "levels": e["LEVELS"].split(),
             "expectations": [int(n) for n in e["EXPECTATIONS"].split()], "requests": e["REQUESTS"].split(),
             "servers": e["SERVERS"].split(), "ours_configs": e["OURS_CONFIGS"].split(";"),
             "oracle_configs": e["ORACLE_CONFIGS"].split(";"), "metrics": e["METRICS"] == "true",
             "settle_max_s": int(e["SETTLE_MAX"]), "host_header": e["HOST_HEADER"], "memory_limit": None},
}
json.dump(meta, open(f"{run}/meta.json", "w"), indent=1)
PY
rm -f "$RUN_DIR/docker-info.json"

server_name() { if [ "$1" = oracle ]; then echo "MockServer $ORACLE_VERSION"; else echo mock-server; fi; }
slug() { printf '%s' "$1" | tr -c 'A-Za-z0-9' '-' | tr -s '-' | sed 's/-$//'; }

# The console log's file in the probe and its line count, and the cgroup's directory.
log_file() { echo "/dc/$1/$1-json.log"; }
lines() { probe "wc -l < $(log_file "$1")" | tr -d ' '; }
# Waits until the console log stops growing (1 s without a new line), at most $SETTLE_MAX s; prints the line count and
# whether it settled.
settle() {
  local id=$1 a b waited=0
  a=$(lines "$id")
  while :; do
    sleep 1
    b=$(lines "$id")
    if [ "$a" = "$b" ]; then echo "$b true"; return; fi
    a=$b
    waited=$((waited + 1))
    if [ "$waited" -ge "$SETTLE_MAX" ]; then echo "$b false"; return; fi
  done
}
cpu_usec() { probe "sed -n 's/^usage_usec //p' $1/cpu.stat"; }

measure() {  # round server config level n request [alloc]
  local round=$1 server=$2 config=$3 level=$4 n=$5 request=$6 alloc=${7:-}
  local image path id cg body i envs=()
  if [ "$server" = oracle ]; then image=$ORACLE_IMAGE; else image=${alloc:+$ALLOC_IMAGE}; image=${image:-$IMAGE}; fi
  if [ "$request" = matched ]; then path=/e$((n - 1)); else path=/none; fi
  [ "$config" = default ] || for kv in $config; do envs+=(-e "$kv"); done
  local tag
  tag=$(slug "r$round-$server-$config-$level-$n-$request${alloc:+-alloc}")
  local raw="$RUN_DIR/raw/$tag"

  docker run -d --name "$SUT" --network "$NET" --cpus "$CPUS" -e MOCKSERVER_LOG_LEVEL="$level" \
    -e MOCKSERVER_METRICS_ENABLED="$METRICS" ${envs[@]+"${envs[@]}"} "$image" >/dev/null
  id=$(docker inspect -f '{{.Id}}' "$SUT")
  cg=$(probe "find /cg -maxdepth 4 -type d -name '*$id*' | head -1")
  [ -n "$cg" ] || { echo "no cgroup for container $id" >&2; exit 1; }
  for ((i = 0; i < 600; i++)); do
    probe "curl -sf -o /dev/null -X PUT http://$SUT:1080/mockserver/status" && break
    sleep 0.2
  done
  body="["
  for ((i = 0; i < n; i++)); do body+="{\"httpRequest\":{\"method\":\"GET\",\"path\":\"/e$i\"},\"httpResponse\":{\"body\":\"e$i\"}},"; done
  printf '%s]' "${body%,}" | docker exec -i "$PROBE" curl -sf -o /dev/null -X PUT --data-binary @- "http://$SUT:1080/mockserver/expectation"

  docker run --rm --name mock-server-bench-oha --network "$NET" "$OHA_IMAGE" -z "${WARMUP}s" -c "$CONNECTIONS" \
    --host "$HOST_HEADER" --no-tui --output-format quiet "http://$SUT:1080$path" >/dev/null
  local before settled_before
  read -r before settled_before < <(settle "$id")
  local alloc_before=""
  if [ -n "$alloc" ]; then
    docker kill -s USR1 "$SUT" >/dev/null
    read -r before _ < <(settle "$id")
    alloc_before=$(probe "grep 'alloc-count ' $(log_file "$id") | tail -1")
  fi
  local load_before cpu0 t0 cpu1 t1
  load_before=$(probe 'cut -d" " -f1-3 /proc/loadavg')
  cpu0=$(cpu_usec "$cg")
  t0=$(date +%s)
  docker run --rm --name mock-server-bench-oha --network "$NET" "$OHA_IMAGE" -z "${DURATION}s" -c "$CONNECTIONS" \
    --host "$HOST_HEADER" --no-tui --output-format json "http://$SUT:1080$path" >"$raw.oha.json"
  t1=$(date +%s)
  cpu1=$(cpu_usec "$cg")
  local after settled_after cpu2
  read -r after settled_after < <(settle "$id")
  cpu2=$(cpu_usec "$cg")
  local alloc_after=""
  if [ -n "$alloc" ]; then
    docker kill -s USR1 "$SUT" >/dev/null
    settle "$id" >/dev/null
    alloc_after=$(probe "grep 'alloc-count ' $(log_file "$id") | tail -1")
  fi
  # The window's console lines that log a received request, and MockServer's warnings, since the start, that it drops
  # log events (each is printed once per process, most often during the warm-up).
  local counts
  counts="$(probe "tail -n +$((before + 1)) $(log_file "$id") | head -n $((after - before)) | grep -c 'received request' || true")"
  counts+=" $(probe "grep -c 'ring buffer full' $(log_file "$id") || true")"
  counts+=" $(probe "grep -c 'in-flight byte budget reached' $(log_file "$id") || true")"
  local vmhwm peak
  vmhwm=$(probe "for p in \$(cat $cg/cgroup.procs); do sed -n 's/^VmHWM:[[:space:]]*\([0-9]*\) kB/\1/p' /proc/\$p/status; done | sort -n | tail -1")
  peak=$(probe "cat $cg/memory.peak 2>/dev/null || true")
  docker rm -f -v "$SUT" >/dev/null

  ROUND=$round SERVER_KEY=$server SERVER_NAME=$(server_name "$server") CONFIG=$config LEVEL=$level N=$n REQUEST=$request \
    URL_PATH=$path ALLOC=$alloc SUT_IMAGE=$image CONTAINER_ID=$id OHA=raw/$tag.oha.json T0=$t0 T1=$t1 \
    LOAD_BEFORE=$load_before CPU0=$cpu0 CPU1=$cpu1 CPU2=$cpu2 BEFORE=$before AFTER=$after \
    SETTLED_BEFORE=$settled_before SETTLED_AFTER=$settled_after COUNTS=$counts VMHWM=$vmhwm PEAK=$peak \
    ALLOC_BEFORE=$alloc_before ALLOC_AFTER=$alloc_after python3 - "$raw.readings.json" <<'PY'
import json, os, sys
e = os.environ
received, ring_full, budget = (int(x) for x in e["COUNTS"].split())
def alloc(line):  # a json-file log line holding `alloc-count allocs=<n> ...`
    return {k: int(v) for k, v in (kv.split("=") for kv in json.loads(line)["log"].split()[1:])} if line else None
json.dump({
  "round": int(e["ROUND"]), "server": e["SERVER_NAME"], "server_key": e["SERVER_KEY"], "config": e["CONFIG"],
  "log_level": e["LEVEL"], "expectations": int(e["N"]), "request": e["REQUEST"], "path": e["URL_PATH"],
  "alloc_count": bool(e["ALLOC"]), "image": e["SUT_IMAGE"], "container_id": e["CONTAINER_ID"], "oha": e["OHA"],
  "window": {"start_epoch_s": int(e["T0"]), "end_epoch_s": int(e["T1"])},
  "load_average_before": [float(x) for x in e["LOAD_BEFORE"].split()],
  "cpu_usage_usec": {"before": int(e["CPU0"]), "window_end": int(e["CPU1"]), "settled": int(e["CPU2"])},
  "console": {"lines_before": int(e["BEFORE"]), "lines_after": int(e["AFTER"]),
              "settled_before": e["SETTLED_BEFORE"] == "true", "settled_after": e["SETTLED_AFTER"] == "true",
              "received_request_lines": received, "ring_full_warnings": ring_full, "in_flight_budget_warnings": budget},
  "vmhwm_kib": int(e["VMHWM"]) if e["VMHWM"] else None,
  "memory_peak_bytes": int(e["PEAK"]) if e["PEAK"] else None,
  "alloc_before": alloc(e["ALLOC_BEFORE"]), "alloc_after": alloc(e["ALLOC_AFTER"]),
}, open(sys.argv[1], "w"), indent=1)
PY
  python3 - "$raw.readings.json" "$RUN_DIR" <<'PY' | tee -a "$LOG"
import json, sys
r = json.load(open(sys.argv[1]))
o = json.load(open(sys.argv[2] + "/" + r["oha"]))
done = sum(o.get("statusCodeDistribution", {}).values())
cpu = r["cpu_usage_usec"]["settled"] - r["cpu_usage_usec"]["before"]
p = o["latencyPercentiles"]
print(f"| {r['round']} | {r['server']} | {r['config']} | {r['log_level']} | {r['expectations']} | {r['request']}"
      f"{' (alloc-count)' if r['alloc_count'] else ''} | {o['summary']['requestsPerSec']:.0f} | {cpu / max(done, 1):.1f}"
      f" | {p['p50'] * 1000:.2f} / {p['p99'] * 1000:.2f} / {p['p99.9'] * 1000:.2f} | {(r['vmhwm_kib'] or 0) / 1024:.0f}"
      f" | {r['console']['lines_after'] - r['console']['lines_before']} / {r['console']['received_request_lines']} of {done}"
      f" | {dict(o.get('statusCodeDistribution', {}))} |")
PY
}

echo "# readings in $RUN_DIR"  # on the terminal only: run.log is published with the run
say "# $IMAGE and $ORACLE_IMAGE; --cpus $CPUS, $CONNECTIONS connections, ${WARMUP}s warm-up, ${DURATION}s window, $ROUNDS rounds; Host: $HOST_HEADER"
say "| round | server | config | level | expectations | request | req/s | CPU µs/req | p50 / p99 / p99.9 ms | VmHWM MiB | console lines / received of requests | status codes |"
say "|---|---|---|---|---|---|---|---|---|---|---|---|"
read -r -a servers <<<"$SERVERS"
for ((round = 1; round <= ROUNDS; round++)); do
  order=("${servers[@]}")
  if [ $((round % 2)) -eq 0 ] && [ "${#servers[@]}" -eq 2 ]; then order=("${servers[1]}" "${servers[0]}"); fi
  for level in $LEVELS; do
    for n in $EXPECTATIONS; do
      for request in $REQUESTS; do
        for server in "${order[@]}"; do
          if [ "$server" = oracle ]; then configs=$ORACLE_CONFIGS; else configs=$OURS_CONFIGS; fi
          IFS=';' read -r -a list <<<"$configs"
          for config in "${list[@]}"; do measure "$round" "$server" "$config" "$level" "$n" "$request"; done
        done
      done
    done
  done
done
if [ -n "$ALLOC_IMAGE" ] && [[ " $SERVERS " == *" ours "* ]]; then
  for level in $LEVELS; do
    for n in $EXPECTATIONS; do
      for request in $REQUESTS; do
        IFS=';' read -r -a list <<<"$OURS_CONFIGS"
        for config in "${list[@]}"; do measure 1 ours "$config" "$level" "$n" "$request" alloc; done
      done
    done
  done
fi

LOAD_END=$(probe 'cut -d" " -f1-3 /proc/loadavg') python3 - "$RUN_DIR/meta.json" <<'PY'
import datetime, json, os, sys
meta = json.load(open(sys.argv[1]))
meta["finished"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
meta["load_average_end"] = [float(x) for x in os.environ["LOAD_END"].split()]
json.dump(meta, open(sys.argv[1], "w"), indent=1)
PY
python3 "$here/results.py" "$RUN_DIR"
echo "# results: $RUN_DIR/results.json"
if [ -n "$RESULTS" ]; then
  archive="${RESULTS%.json}-raw.tar.gz"
  python3 - "$RUN_DIR/results.json" "$RESULTS" "$(basename "$archive")" <<'PY'
import json, sys
results = json.load(open(sys.argv[1]))
results["meta"]["raw"] = sys.argv[3]
with open(sys.argv[2], "w") as f:
    json.dump(results, f, indent=1, ensure_ascii=False)
    f.write("\n")
PY
  tar -czf "$archive" -C "$(dirname "$RUN_DIR")" "$(basename "$RUN_DIR")"
  say "# results: $RESULTS, raw: $archive"
fi
