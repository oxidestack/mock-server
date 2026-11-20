#!/usr/bin/env bash
# The same load against the oracle and mock-server, each limited to the same CPUs, on one Docker
# network so the load generator (oha, in a container) never crosses the host/VM boundary.
# CPUS (2), DURATION (15s) and CONNECTIONS (64) set the load; ORACLE_LOG_LEVEL and RS_LOG_LEVEL (INFO) each server's
# log level; IMAGE, METRICS, RS_DOCKER_ARGS and RESULTS are described below.
set -euo pipefail
CPUS=${CPUS:-2}
DURATION=${DURATION:-15s}
CONNECTIONS=${CONNECTIONS:-64}
NET=msrs-bench
# shellcheck source=../oracle.env
. "$(dirname "$0")/../oracle.env"
OHA=ghcr.io/hatoo/oha:latest
IMAGE=${IMAGE:-mock-server:latest}
# METRICS=true turns metricsEnabled on in both servers (the metrics overhead).
METRICS=${METRICS:-false}
# RESULTS=<file> also writes the run as JSON in the format of site/public/benchmarks/results.json, which the site's
# Benchmarks page is generated from (site/README.md, "The Benchmarks page"): every row, the commit, the machine Docker
# runs on and the load.
RESULTS=${RESULTS:-}
ROWS=$(mktemp)

docker network create $NET >/dev/null 2>&1 || true
cleanup() { docker rm -f bench-oracle bench-rs >/dev/null 2>&1 || true; }
trap 'cleanup; rm -f "$ROWS"' EXIT
cleanup

docker run -d --name bench-oracle --network $NET --cpus "$CPUS" -e MOCKSERVER_LOG_LEVEL="${ORACLE_LOG_LEVEL:-INFO}" -e MOCKSERVER_METRICS_ENABLED="$METRICS" "$ORACLE_IMAGE" >/dev/null
# RS_DOCKER_ARGS: extra `docker run` arguments for mock-server only, e.g. `-e MOCKSERVER_MAX_LOG_ENTRIES=100000`.
# shellcheck disable=SC2086
docker run -d --name bench-rs --network $NET --cpus "$CPUS" -e MOCKSERVER_LOG_LEVEL="${RS_LOG_LEVEL:-INFO}" -e MOCKSERVER_METRICS_ENABLED="$METRICS" ${RS_DOCKER_ARGS:-} "$IMAGE" >/dev/null

load() {  # host, N expectations
  local host=$1 n=$2 body="["
  for ((i = 0; i < n; i++)); do body+="{\"httpRequest\":{\"method\":\"GET\",\"path\":\"/e$i\"},\"httpResponse\":{\"body\":\"e$i\"}},"; done
  body="${body%,}]"
  docker run --rm --network $NET curlimages/curl -s -o /dev/null -w '%{http_code}' -X PUT "http://$host:1080/mockserver/reset" >/dev/null
  printf '%s' "$body" | docker run --rm -i --network $NET curlimages/curl -s -o /dev/null -X PUT --data-binary @- "http://$host:1080/mockserver/expectation"
}

wait_up() { until docker run --rm --network $NET curlimages/curl -sf -o /dev/null -X PUT "http://$1:1080/mockserver/status"; do sleep 0.5; done; }
wait_up bench-oracle
wait_up bench-rs

run() {  # label host path; $n is the number of expectations loaded
  local out
  out=$(docker run --rm --network $NET $OHA -z "$DURATION" -c "$CONNECTIONS" --no-tui --output-format json "http://$2:1080$3")
  local mem
  mem=$(docker stats --no-stream --format '{{.MemUsage}}' "bench-${2#bench-}" | cut -d/ -f1)
  echo "$out" | python3 -c "
import json,sys
d=json.load(sys.stdin); s=d['summary']; p=d['latencyPercentiles']
codes=d.get('statusCodeDistribution',{})
print(f\"| $1 | {s['requestsPerSec']:.0f} | {p['p50']*1000:.2f} | {p['p99']*1000:.2f} | {p['p99.9']*1000:.2f} | $mem | {codes} |\")
# The same row for RESULTS, the memory in MiB (docker stats writes 171.5MiB, 1.2GiB).
import re
m=re.match(r'([0-9.]+)\s*([KMG]i?B|kB|B)','$mem'.strip())
scale={'B':1/2**20,'kB':1/1024,'KiB':1/1024,'MB':1,'MiB':1,'GB':1024,'GiB':1024}
mib=round(float(m.group(1))*scale[m.group(2)]) if m else None
oracle='$2'=='bench-oracle'
row=dict(server='MockServer $ORACLE_VERSION' if oracle else 'mock-server',
  config=('default' if oracle else ('${RS_DOCKER_ARGS:-}'.strip() or 'default'))+(', metricsEnabled' if '$METRICS'=='true' else ''),
  expectations=$n, request='unmatched' if '$3'=='/none' else 'matched',
  log_level='${ORACLE_LOG_LEVEL:-INFO}' if oracle else '${RS_LOG_LEVEL:-INFO}',
  req_per_sec=round(s['requestsPerSec']), rss_mib=None if mib is None else [mib,mib],
  p50_ms=round(p['p50']*1000,2), p99_ms=round(p['p99']*1000,2), p999_ms=round(p['p99.9']*1000,2))
open('$ROWS','a').write(json.dumps(row)+'\n')"
}

echo "# image $IMAGE${RS_DOCKER_ARGS:+ with $RS_DOCKER_ARGS}; log level: MockServer ${ORACLE_LOG_LEVEL:-INFO}, mock-server ${RS_LOG_LEVEL:-INFO} (both print to stdout, Docker json-file driver); metricsEnabled $METRICS; $DURATION, $CONNECTIONS connections, --cpus $CPUS"
echo "# load before: $(uptime | sed 's/.*load averages*: //'); containers: $(docker ps -q | wc -l | tr -d ' ')"
echo "| scenario | req/s | p50 ms | p99 ms | p99.9 ms | RSS after | status codes |"
echo "|---|---|---|---|---|---|---|"
for n in 1 1000; do
  load bench-oracle $n; load bench-rs $n
  last=$((n - 1))
  # warm-up (JIT for the oracle)
  docker run --rm --network $NET $OHA -z 5s -c "$CONNECTIONS" --no-tui "http://bench-oracle:1080/e$last" >/dev/null
  docker run --rm --network $NET $OHA -z 2s -c "$CONNECTIONS" --no-tui "http://bench-rs:1080/e$last" >/dev/null
  run "MockServer $ORACLE_VERSION, $n expectations, match last" bench-oracle "/e$last"
  run "mock-server, $n expectations, match last" bench-rs "/e$last"
  # unmatched: a path no expectation matches, answered 404. From 64 expectations on both servers narrow literal
  # paths through a path index (MockServer's candidateIndexThreshold), so at 1,000 this is an index miss, not a scan.
  docker run --rm --network $NET $OHA -z 5s -c "$CONNECTIONS" --no-tui "http://bench-oracle:1080/none" >/dev/null
  docker run --rm --network $NET $OHA -z 2s -c "$CONNECTIONS" --no-tui "http://bench-rs:1080/none" >/dev/null
  run "MockServer $ORACLE_VERSION, $n expectations, unmatched" bench-oracle "/none"
  run "mock-server, $n expectations, unmatched" bench-rs "/none"
  echo "# load after $n: $(uptime | sed 's/.*load averages*: //'); containers: $(docker ps -q | wc -l | tr -d ' ')"
done

# The results file: the rows above, and what they were measured on.
if [ -n "$RESULTS" ]; then
  here=$(dirname "$0")
  commit=$(git -C "$here" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
  git -C "$here" diff --quiet HEAD 2>/dev/null || commit="$commit with uncommitted changes"
  cpu=$(docker run --rm --entrypoint sh curlimages/curl -c "sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1")
  docker info --format '{{json .}}' | ROWS=$ROWS RESULTS=$RESULTS COMMIT=$commit CPU_MODEL=${cpu:-unknown} \
    IMAGE_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE") python3 -c "
import json, os, sys, datetime
info = json.load(sys.stdin)
dur = '$DURATION'
results = {
  'schema': 1,
  'meta': {
    'date': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d'),
    'command': 'bench/run.sh',
    'commit': os.environ['COMMIT'],
    'image': '$IMAGE, ' + os.environ['IMAGE_ID'][:19],
    'oracle_image': '$ORACLE_IMAGE',
    'machine': {'kind': 'Docker host', 'arch': info.get('Architecture'), 'cpu_model': os.environ['CPU_MODEL'],
                'vcpus': info.get('NCPU'), 'memory_gib': round(info.get('MemTotal', 0) / 2**30),
                'os': info.get('OperatingSystem'), 'kernel': info.get('KernelVersion'), 'docker': info.get('ServerVersion')},
    'load': {'cpus': '$CPUS', 'connections': $CONNECTIONS, 'warmup_s': {'MockServer $ORACLE_VERSION': 5, 'mock-server': 2},
             'duration_s': int(dur[:-1]) if dur.endswith('s') and dur[:-1].isdigit() else dur, 'memory_limit': None, 'rounds': 1},
    'memory': 'the container\'s memory use as docker stats reports it, read after the load',
  },
  'rows': [json.loads(line) for line in open(os.environ['ROWS'])],
}
with open(os.environ['RESULTS'], 'w') as f:
    json.dump(results, f, indent=1, ensure_ascii=False)
    f.write('\n')
print('# results: ' + os.environ['RESULTS'])"
fi
