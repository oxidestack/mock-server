#!/usr/bin/env bash
# Records exchanges.golden.json from upstream's own webhook image (the oracle for the webhook), one container per
# configuration of cases.json, each on an ephemeral host port with a fresh self-signed P-256 certificate. The
# containers' stderr (java.util.logging) lands in target/webhook-oracle/<config>.log for comparison with ours.
#
#   k8s-webhook/oracle/record.sh            WEBHOOK_ORACLE_IMAGE / WEBHOOK_ORACLE_NAME override the defaults
#
# The default image is ORACLE_WEBHOOK_IMAGE of oracle.env, pinned with the other oracle images.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
IMAGE="${WEBHOOK_ORACLE_IMAGE:-$(. "${REPO}/oracle.env" && echo "${ORACLE_WEBHOOK_IMAGE}")}"
NAME="${WEBHOOK_ORACLE_NAME:-mock-server-webhook-oracle}"
WORK="${REPO}/target/webhook-oracle"
mkdir -p "${WORK}/tls"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj /CN=localhost \
  -keyout "${WORK}/tls/tls.key" -out "${WORK}/tls/tls.crt" 2>/dev/null
chmod 644 "${WORK}/tls/tls.key" "${WORK}/tls/tls.crt"

configs=$(python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["configs"]))' "${HERE}/cases.json")
parts=()
for config in ${configs}; do
  envs=()
  while IFS= read -r line; do envs+=(-e "${line}"); done < <(python3 -c '
import json, sys
for k, v in json.load(open(sys.argv[1]))["configs"][sys.argv[2]].items():
    print(f"{k}={v}")' "${HERE}/cases.json" "${config}")
  docker rm -f "${NAME}-${config}" >/dev/null 2>&1 || true
  docker run -d --name "${NAME}-${config}" -p 127.0.0.1::8443 \
    --mount "type=bind,source=${WORK}/tls,target=/etc/webhook/tls,readonly" ${envs[@]+"${envs[@]}"} "${IMAGE}" >/dev/null
  port=$(docker port "${NAME}-${config}" 8443/tcp | head -1 | sed 's/.*://')
  for _ in $(seq 1 60); do
    curl -ksf "https://127.0.0.1:${port}/healthz" >/dev/null 2>&1 && break
    sleep 1
  done
  python3 "${HERE}/record.py" "${HERE}/cases.json" "${config}" "${port}" > "${WORK}/${config}.json"
  docker logs "${NAME}-${config}" > "${WORK}/${config}.log" 2>&1
  docker rm -f "${NAME}-${config}" >/dev/null
  parts+=("${WORK}/${config}.json")
done
python3 -c '
import json, sys
out = []
for f in sys.argv[2:]:
    out += json.load(open(f))
open(sys.argv[1], "w").write(json.dumps(out, indent=2, ensure_ascii=False) + "\n")' "${HERE}/exchanges.golden.json" "${parts[@]}"
echo "wrote ${HERE}/exchanges.golden.json"
