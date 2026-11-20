#!/usr/bin/env bash
# Container start -> `started on port` for an image, from Docker's own timestamps (all on the VM clock):
# created = `.Created`, started = `.State.StartedAt` (the runtime has exec'd the entrypoint), ready = the daemon's
# receive timestamp on the first log line containing `started on port`. No host port is published.
# Usage: bench/startup.sh <image> [runs]   (CPUS=2 by default, as bench/run.sh)
set -euo pipefail
IMAGE=${1:?image}
RUNS=${2:-11}
CPUS=${CPUS:-2}
NAME=bench-startup-$$
ROWS=$(mktemp)
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap 'cleanup; rm -f "$ROWS"' EXIT

echo "# $IMAGE, $RUNS runs, --cpus $CPUS; load: $(uptime | sed 's/.*load averages*: //'); containers: $(docker ps -q | wc -l | tr -d ' ')"
echo "run start_to_ready_ms create_to_start_ms docker_run_to_ready_ms"
for ((i = 1; i <= RUNS; i++)); do
  cleanup
  t0=$(python3 -c 'import time; print(time.time())')
  docker run -d --name "$NAME" --cpus "$CPUS" "$IMAGE" >/dev/null
  line=""
  for ((w = 0; w < 1200; w++)); do
    line=$(docker logs --timestamps "$NAME" 2>&1 | grep -m1 'started on port' || true)
    [ -n "$line" ] && break
    sleep 0.05
  done
  [ -n "$line" ] || { echo "run $i: no 'started on port' line within 60 s" >&2; exit 1; }
  times=$(docker inspect --format '{{.Created}} {{.State.StartedAt}}' "$NAME")
  python3 - "$t0" "$times" "${line%% *}" "$i" <<'PY'
import sys
from datetime import datetime, timezone
def ts(s):  # RFC 3339 with nanoseconds -> seconds since epoch (microsecond precision)
    s = s.rstrip('Z')
    base, _, frac = s.partition('.')
    return datetime.fromisoformat(base).replace(tzinfo=timezone.utc).timestamp() + float('0.' + (frac or '0')[:6])
t0 = float(sys.argv[1]); created, started = sys.argv[2].split(); ready = ts(sys.argv[3])
print(sys.argv[4], f"{(ready - ts(started)) * 1000:.1f}", f"{(ts(started) - ts(created)) * 1000:.1f}", f"{(ready - t0) * 1000:.1f}")
PY
done | tee "$ROWS"
# docker_run_to_ready mixes the host clock (t0) with the VM clock (ready); the other two columns use the VM clock only.
python3 - "$ROWS" <<'PY'
import statistics, sys
rows = [l.split()[1:] for l in open(sys.argv[1]) if l.strip()]
cols = list(zip(*[[float(v) for v in r] for r in rows]))
print("median", *(f"{statistics.median(c):.1f}" for c in cols))
PY
