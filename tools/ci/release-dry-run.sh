#!/bin/sh
# The release's publication against a scratch registry: what the `publish` and `mirror` jobs of
# .github/workflows/release.yml do to quay.io and ghcr.io, done to a throwaway registry container on this machine, with
# a throwaway signing key, so nothing reaches a real registry or Sigstore's public log. The manual run of release.yml
# (its dry run) runs it on the images both architectures' jobs built and tested; locally it runs on any two image
# tarballs.
#
#   sh tools/ci/release-dry-run.sh <version> <image.tar>... [-- <file>...]
#
# 1. starts `registry` on 127.0.0.1 (the first free port from 35000), on the host's network as crane's and oras' own;
# 2. pushes the tarballs by digest into one manifest list tagged as the version publishes (publish-image.sh push);
# 3. signs the list with the throwaway key and verifies the signature (release.sh sign, verify);
# 4. lists the list's platforms (release.sh platforms) and checks there is one per tarball;
# 5. copies it with its referrers to a second repository, the mirror, and checks the digest and the signature there
#    (release.sh mirror, verify);
# 6. signs each <file> after `--` as the GitHub release's files are signed and verifies them (release.sh sign-blob,
#    verify-blob), and prints the release notes (release.sh notes).
#
# Needs Docker, and Linux for cosign and oras (tools/lint/fetch-tool.sh): a runner, or a container that reaches the
# Docker socket and the host's network. The tarballs and files must lie where the Docker daemon sees the same path
# (crane's container mounts them). The registry container and the key are removed at exit.
# Exit 0: every step passed; 1: one failed; 2: usage.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)

# registry 3.0.0, by the digest of its multi-architecture index.
REGISTRY=registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e

[ $# -ge 2 ] || {
	sed -n '7,8p' "$0" >&2
	exit 2
}
version=$1
shift
tars="" count=0
while [ $# -gt 0 ] && [ "$1" != -- ]; do
	tars="$tars $1" count=$((count + 1))
	shift
done
[ $# -eq 0 ] || shift
[ "$count" -gt 0 ] || {
	echo "release-dry-run: no image tarball" >&2
	exit 2
}

say() { echo "release-dry-run: $*" >&2; }

# Under the repository, where the daemon sees the same path: crane's container mounts the credentials' directory.
work="$ROOT/target/release-dry-run.$$"
mkdir -p "$work"
name="mock-server-dry-run-registry-$$"
cleanup() {
	docker rm -f -v "$name" > /dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

say "1. a scratch registry"
# On the host's network, where crane's container and oras are: the first port of a few that the registry can bind.
port=""
for p in 35000 35001 35002 35003 35004 35005 35006 35007 35008 35009; do
	docker run -d --rm --name "$name" --network host -e "REGISTRY_HTTP_ADDR=127.0.0.1:$p" "$REGISTRY" > /dev/null
	i=0
	while [ "$i" -lt 20 ] && docker inspect "$name" > /dev/null 2>&1; do
		if curl -fsS "http://127.0.0.1:$p/v2/" > /dev/null 2>&1; then
			port=$p
			break 2
		fi
		i=$((i + 1))
		sleep 1
	done
	docker rm -f -v "$name" > /dev/null 2>&1 || true
done
[ -n "$port" ] || {
	say "no scratch registry answered on 127.0.0.1:35000-35009"
	exit 1
}
registry=127.0.0.1:$port
repository=$registry/oxidestack/mock-server
mirror=$registry/mirror/mock-server

export DOCKER_CONFIG="$work/docker" CRANE_CONFIG="$work/docker" CRANE_FLAGS=--insecure REGISTRY_PLAIN_HTTP=1
mkdir -p "$DOCKER_CONFIG"
printf '{}\n' > "$DOCKER_CONFIG/config.json"

say "2. push $repository:$version"
# shellcheck disable=SC2086 # the tarballs are words
digest=$(sh "$ROOT/tools/ci/publish-image.sh" push "$repository" "$version" $tars | tail -n 1)
case $digest in
sha256:*) ;;
*)
	say "publish-image.sh printed no digest: $digest"
	exit 1
	;;
esac

say "3. sign and verify $repository@$digest"
export COSIGN_PASSWORD="" COSIGN_KEY="$work/throwaway.key" COSIGN_PUB="$work/throwaway.pub"
(cd "$work" && "$(sh "$ROOT/tools/lint/fetch-tool.sh" cosign)" generate-key-pair --output-key-prefix throwaway) > /dev/null 2>&1
sh "$ROOT/tools/ci/release.sh" sign "$repository@$digest"
sh "$ROOT/tools/ci/release.sh" verify "$repository:$version" "v$version"

say "4. the platforms"
platforms=$(sh "$ROOT/tools/ci/release.sh" platforms "$repository@$digest")
printf '%s\n' "$platforms" >&2
got=$(printf '%s\n' "$platforms" | grep -c '^linux/')
[ "$got" -eq "$count" ] || {
	say "the list has $got platforms, $count tarballs were pushed"
	exit 1
}

say "5. mirror to $mirror"
# shellcheck disable=SC2046 # the tags are words
copied=$(sh "$ROOT/tools/ci/release.sh" mirror "$repository" "$mirror" $(sh "$ROOT/tools/ci/publish-image.sh" tags "$version"))
[ "$copied" = "$digest" ] || {
	say "the mirror's digest is $copied, the source's $digest"
	exit 1
}
sh "$ROOT/tools/ci/release.sh" verify "$mirror:$version" "v$version"

if [ $# -gt 0 ]; then
	say "6. sign and verify the release's files"
	for f in "$@"; do cp "$f" "$work/"; done
	files=""
	for f in "$@"; do files="$files $work/$(basename "$f")"; done
	# shellcheck disable=SC2086 # the files are words
	sh "$ROOT/tools/ci/release.sh" sign-blob $files
	# shellcheck disable=SC2086 # the files are words
	sh "$ROOT/tools/ci/release.sh" verify-blob "v$version" $files
fi

say "the notes"
sh "$ROOT/tools/ci/release.sh" notes "$version" "$digest"
say "passed: $repository:$version is $digest, signed, mirrored with its signature"
