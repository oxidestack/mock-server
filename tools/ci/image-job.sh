#!/bin/sh
# The image job of .github/workflows/ci.yml and release.yml, on a GitHub-hosted runner of the architecture it builds
# for (amd64 on ubuntu-24.04, arm64 on ubuntu-24.04-arm: each image is built natively, never emulated):
#
# 1. builds the image from the Dockerfile, with the OCI labels and the commit `mock_server_native_build_info` reports;
# 2. starts it as a user would (`docker run -p 1080:1080`), waits for its health check, creates an expectation through
#    the control plane and gets its answer back from the data plane;
# 3. runs MockServer's own Testcontainers module tests against it (conformance/java, `make conformance` without its
#    rebuild): the image under the MockServer tag those tests pin, so a test written for MockServer's image passes
#    unchanged with this one;
# 4. writes the image's SBOMs (syft: SPDX and CycloneDX JSON) to target/sbom/mock-server-<arch>.{spdx,cdx}.json and
#    checks they list the crates the binary was built from (the Dockerfile builds it with cargo-auditable, which
#    embeds that list);
# 5. saves the tested image with `docker save` when IMAGE_SAVE names a file, for the release to push.
#
#   sh tools/ci/image-job.sh
#
# Needs Docker, git, curl, a JDK 21 and Maven (the runner's), and the upstream/mockserver submodule checked out.
# Everything it starts is named after the job and removed at exit, the image too unless it was saved.
#
# Environment: IMAGE, the tag to build (default mock-server-ci:<arch>); IMAGE_VERSION and IMAGE_SOURCE, the OCI
# version and source labels (default the commit, and nothing); IMAGE_SAVE, the file `docker save` writes; SKIP_JAVA=1
# leaves out step 3 (a quick local run).
# Exit 0: every step passed; 1: one failed.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

# syft v1.42.0, by the digest of its multi-architecture index.
SYFT=anchore/syft:v1.42.0@sha256:19ed45c8f4bf846390b072966a2fec52279d09f9e47650830ffabec7eebaf0fe

case "$(uname -m)" in
aarch64 | arm64) arch=arm64 ;;
x86_64 | amd64) arch=amd64 ;;
*)
	echo "image-job: no image for $(uname -m)" >&2
	exit 1
	;;
esac
IMAGE=${IMAGE:-mock-server-ci:$arch}
commit=$(git rev-parse HEAD)
name="mock-server-image-job-$$"

say() { echo "image-job: $*" >&2; }

cleanup() {
	docker rm -f -v "$name" > /dev/null 2>&1 || true
	[ -n "${IMAGE_SAVE:-}" ] || docker rmi "$IMAGE" > /dev/null 2>&1 || true
}
trap cleanup EXIT

say "1. build $IMAGE ($arch)"
# shellcheck disable=SC2046 # the source label is one flag or none
docker build \
	--build-arg "MOCK_SERVER_GIT_HASH=$(git rev-parse --short=8 HEAD)" \
	--label "org.opencontainers.image.title=mock-server" \
	--label "org.opencontainers.image.description=A drop-in replacement for the MockServer image, in Rust" \
	--label "org.opencontainers.image.licenses=Apache-2.0" \
	--label "org.opencontainers.image.revision=$commit" \
	--label "org.opencontainers.image.version=${IMAGE_VERSION:-$commit}" \
	$([ -z "${IMAGE_SOURCE:-}" ] || echo "--label org.opencontainers.image.source=$IMAGE_SOURCE") \
	-t "$IMAGE" .

say "2. the image answers an expectation"
docker run -d --name "$name" -p 127.0.0.1::1080 "$IMAGE" > /dev/null
port=$(docker port "$name" 1080/tcp | head -n 1 | sed 's/.*://')
i=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$name")" = healthy ]; do
	i=$((i + 1))
	[ "$i" -lt 60 ] || {
		docker logs "$name" >&2
		say "the container is not healthy after 60 s"
		exit 1
	}
	sleep 1
done
curl -fsS -X PUT "http://127.0.0.1:$port/mockserver/expectation" -H 'Content-Type: application/json' -d '{
	"httpRequest": {"method": "GET", "path": "/hello"},
	"httpResponse": {"statusCode": 200, "body": "hello from the image"}
}' > /dev/null
got=$(curl -fsS "http://127.0.0.1:$port/hello")
[ "$got" = "hello from the image" ] || {
	docker logs "$name" >&2
	say "GET /hello answered '$got'"
	exit 1
}
docker rm -f -v "$name" > /dev/null

if [ "${SKIP_JAVA:-}" = 1 ]; then
	say "3. skipped (SKIP_JAVA=1)"
else
	say "3. MockServer's Testcontainers tests against the image"
	pinned=$(sed -n 's/.*PINNED_MOCKSERVER_IMAGE = "\([^"]*\)".*/\1/p' \
		upstream/mockserver/mockserver/mockserver-testcontainers/src/test/java/org/mockserver/testcontainers/TestcontainersImages.java)
	[ -n "$pinned" ] || {
		say "no PINNED_MOCKSERVER_IMAGE in upstream/mockserver (is the submodule checked out?)"
		exit 1
	}
	# mockServerImage names the image to the suites that start it by name (the pom's default is mock-server:latest).
	(cd conformance/java && ../../scripts/with-image-tags.sh "$IMAGE" "$pinned" -- mvn -B -q test -DmockServerImage="$IMAGE")
fi

say "4. the SBOMs"
out="$ROOT/target/sbom"
mkdir -p "$out"
tar="$out/mock-server-$arch.tar"
docker save -o "$tar" "$IMAGE"
docker run --rm --name "$name-syft" --user "$(id -u):$(id -g)" -v "$out:/sbom" "$SYFT" \
	scan "docker-archive:/sbom/mock-server-$arch.tar" --source-name mock-server -q \
	-o "spdx-json=/sbom/mock-server-$arch.spdx.json" -o "cyclonedx-json=/sbom/mock-server-$arch.cdx.json"
rm -f "$tar"
# An SBOM is only worth shipping if it sees the binary's crates; without cargo-auditable's list it sees none.
for f in "$out/mock-server-$arch.spdx.json" "$out/mock-server-$arch.cdx.json"; do
	for crate in tokio hyper; do
		grep -q "\"$crate\"" "$f" || {
			say "$f lists no $crate"
			exit 1
		}
	done
done

if [ -n "${IMAGE_SAVE:-}" ]; then
	say "5. save to $IMAGE_SAVE"
	docker save -o "$IMAGE_SAVE" "$IMAGE"
fi
say "passed"
