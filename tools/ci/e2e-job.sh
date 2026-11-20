#!/usr/bin/env bash
# The image's end-to-end suites, the second half of .github/workflows/ci.yml's image job: after tools/ci/image-job.sh
# on the same runner, with the image it built and kept (IMAGE_KEEP=1).
#
# 1. builds what the suites need besides that image: its clustered variant (the Dockerfile's `clustered` target, from
#    the same build cache) and the admission webhook's image (k8s-webhook/Dockerfile);
# 2. the mixed cluster (`make cluster-tests`, conformance/cluster/run.sh): the clustered variant and the oracle's
#    clustered image (oracle.env) in one JGroups cluster, both join orders;
# 3. upstream's container integration tests (`make container-tests`, conformance/containers/run.sh): the
#    docker-compose cases and the helm cases on k3d. A case skipped or not run fails the job as a failed one does; a
#    case listed in conformance/containers/not-applicable.txt is not run, with its reason in the results table.
#
#   bash tools/ci/e2e-job.sh
#
# Needs Docker with the compose plugin, rustup (the callback plugin of docker_compose_libs_plugin, built by
# `make plugins`), python3, and the upstream/mockserver submodule checked out. k3d, helm and kubectl are installed at
# the versions pinned here, each checked against its SHA-256, into a directory of their own under target/; the
# upstream harness's `docker-compose` is the compose plugin.
#
# Environment: IMAGE, the image image-job.sh kept (default mock-server-ci:<arch>, its own default).
# Exit 0: every suite passed; 1: one failed.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

case "$(uname -m)" in
aarch64 | arm64) arch=arm64 ;;
x86_64 | amd64) arch=amd64 ;;
*)
	echo "e2e-job: no tools for $(uname -m)" >&2
	exit 1
	;;
esac
IMAGE=${IMAGE:-mock-server-ci:$arch}
# The names the harnesses take: `<name>:latest` for the image, `<name>-webhook:latest` for the webhook's.
E2E=mock-server-e2e
RUST_TOOLCHAIN=1.98.0

K3D_VERSION=v5.8.3
HELM_VERSION=v3.17.3
KUBECTL_VERSION=v1.32.4
# The SHA-256 of each one's linux-<arch> download, as its release publishes it.
case "$arch" in
amd64)
	K3D_SHA256=dbaa79a76ace7f4ca230a1ff41dc7d8a5036a8ad0309e9c54f9bf3836dbe853e
	HELM_SHA256=ee88b3c851ae6466a3de507f7be73fe94d54cbf2987cbaa3d1a3832ea331f2cd
	KUBECTL_SHA256=10d739e9af8a59c9e7a730a2445916e04bc9cbb44bc79d22ce460cd329fa076c
	;;
arm64)
	K3D_SHA256=0b8110f2229631af7402fb828259330985918b08fefd38b7f1b788a1c8687216
	HELM_SHA256=7944e3defd386c76fd92d9e6fec5c2d65a323f6fadc19bfb5e704e3eee10348e
	KUBECTL_SHA256=c6f96d0468d6976224f5f0d81b65e1a63b47195022646be83e49d38389d572c2
	;;
esac

say() { echo "e2e-job: $*" >&2; }

cleanup() {
	docker rmi "$E2E:latest" "$E2E:clustered-latest" "$E2E-webhook:latest" > /dev/null 2>&1 || true
}
trap cleanup EXIT

# fetch <url> <sha256> <file>
fetch() {
	curl -fsSL --retry 3 -o "$3" "$1"
	echo "$2  $3" | sha256sum -c --quiet -
}

say "1. the tools and the images"
tools="$ROOT/target/e2e-tools"
mkdir -p "$tools"
fetch "https://github.com/k3d-io/k3d/releases/download/$K3D_VERSION/k3d-linux-$arch" "$K3D_SHA256" "$tools/k3d"
fetch "https://get.helm.sh/helm-$HELM_VERSION-linux-$arch.tar.gz" "$HELM_SHA256" "$tools/helm.tar.gz"
tar -xzf "$tools/helm.tar.gz" -C "$tools" --strip-components=1 "linux-$arch/helm"
rm -f "$tools/helm.tar.gz"
fetch "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/$arch/kubectl" "$KUBECTL_SHA256" "$tools/kubectl"
printf '#!/bin/sh\nexec docker compose "$@"\n' > "$tools/docker-compose"
chmod +x "$tools/k3d" "$tools/helm" "$tools/kubectl" "$tools/docker-compose"
export PATH="$tools:$PATH"
k3d version
helm version --short
kubectl version --client
docker-compose version --short

rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal --target wasm32-unknown-unknown
export RUSTUP_TOOLCHAIN=$RUST_TOOLCHAIN MOCK_SERVER_WASM_TOOLCHAIN=$RUST_TOOLCHAIN

docker tag "$IMAGE" "$E2E:latest"
docker build --build-arg "MOCK_SERVER_GIT_HASH=$(git rev-parse --short=8 HEAD)" --target clustered -t "$E2E:clustered-latest" .
docker build -f k8s-webhook/Dockerfile -t "$E2E-webhook:latest" .

failed=0

say "2. the mixed cluster"
IMAGE="$E2E:clustered-latest" conformance/cluster/run.sh all || failed=1

say "3. upstream's container integration tests"
results=conformance/containers/target/results-rs.tsv
rm -f "$results"
IMAGE="$E2E" WEBHOOK_IMAGE="$E2E-webhook" SKIP_IMAGE_BUILD=true K3D_IGNORE_DISK_PRESSURE=true \
	conformance/containers/run.sh rs || failed=1
# run.sh fails on a failed case only; here a case its harness skipped, or never reached, fails too.
if awk -F '\t' 'NR > 1 && ($3 == "skip:absent" || $3 == "not-run") { print; bad = 1 } END { exit !bad }' "$results"; then
	say "the cases above were skipped or not run"
	failed=1
fi

[ "$failed" = 0 ] || exit 1
say "passed"
