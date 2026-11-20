#!/bin/sh
# The release's steps around the image's push (tools/ci/publish-image.sh): what .github/workflows/release.yml checks
# before it builds, the signatures it makes and checks, the copy to the mirror and the notes of the GitHub release.
# cosign and oras are the binaries pinned in tools/lint/tools.txt, fetched by tools/lint/fetch-tool.sh, so this runs on
# Linux (a runner, or a container); gh and jq are the runner's.
#
#   sh tools/ci/release.sh check <tag>
#       The tag's version (publish-image.sh's rule) on stdout. For a release (no `-`) the tree must already say it:
#       Cargo.toml's version, and scripts/release-check.sh's rule: a `## [<version>]` section in CHANGELOG.md and, when
#       that section has Action required, a `## Upgrading to <version>` section in docs/guide/upgrading.md. A
#       pre-release needs none of them.
#   sh tools/ci/release.sh on-main <owner/repo> <sha>
#       Exit 0 when <sha> is on the default branch (`main` contains it), so a tag on a side branch publishes nothing.
#   sh tools/ci/release.sh wait-ci <owner/repo> <sha> [<minutes>]
#       Waits (default 180 minutes) until a run of ci.yml on <sha> has passed; exit 1 when every run on it failed or
#       the time is up.
#   sh tools/ci/release.sh notes <version> [<image digest>]
#       The GitHub release's body on stdout: CHANGELOG.md's `## [<version>]` section, from the line after the heading
#       to the next `## `, without its trailing link. A pre-release without a section of its own says what it is and
#       carries the Unreleased section instead. Then how to run and verify the image, naming quay.io (and the digest,
#       when given).
#   sh tools/ci/release.sh quay-login <robot>
#       Exchanges this GitHub Actions job's OIDC token at quay.io for the robot's one-hour token (quay.io's robot
#       federation: no stored secret) and logs in to quay.io. Both tokens are masked in the log, neither is an argument.
#   sh tools/ci/release.sh login <registry> <username>
#       Logs in to <registry> with the password on stdin.
#   sh tools/ci/release.sh sign <reference@digest>
#       Signs with cosign: keyless in CI (the job's OIDC identity, Fulcio and Rekor), or with $COSIGN_KEY.
#   sh tools/ci/release.sh verify <reference> <tag>
#       Checks the cosign signature: made by .github/workflows/release.yml of $GITHUB_REPOSITORY (default
#       oxidestack/mock-server) at refs/tags/<tag>, issued by GitHub Actions' OIDC; or by $COSIGN_PUB.
#   sh tools/ci/release.sh sign-blob <file>...
#       Signs each file of the GitHub release with cosign as `sign` does, into <file>.sigstore.json beside it: one
#       Sigstore bundle holding the signature, Fulcio's certificate and Rekor's entry.
#   sh tools/ci/release.sh verify-blob <tag> <file>...
#       Checks each file against its <file>.sigstore.json, the identity `verify`'s; or by $COSIGN_PUB.
#   sh tools/ci/release.sh mirror <source repository> <mirror repository> <tag> [<tag>...]
#       Copies <source>:<tag> to the mirror with every referrer it has (cosign's signatures, the SBOM and provenance
#       attestations), so the mirror carries the same digest and the same signed statements; adds the other tags;
#       checks the digests agree; prints the digest.
#   sh tools/ci/release.sh platforms <reference>
#       `<os>/<architecture> <digest>` for each image of the manifest list at <reference>.
#
# Every registry call is tried three times, 10 s then 30 s apart (RETRY_DELAYS); what fails all three exits 1, and
# whether that fails the release is the workflow's decision (quay.io's does, the mirror's does not).
#
# Environment: DOCKER_CONFIG, the registry credentials every tool here reads (default ~/.docker; crane's CRANE_CONFIG
# should name the same directory); REGISTRY_PLAIN_HTTP=1 for a plain-HTTP test registry; COSIGN_KEY/COSIGN_PUB (and
# COSIGN_PASSWORD) to sign and verify with a key pair instead of keyless; CHANGELOG another changelog and UPGRADING
# another upgrade guide (the local tests); QUAY_AUDIENCE, the audience quay-login asks GitHub's OIDC token for (default
# `quay`, the one quay.io's federation form proposes).
# Exit 0: done; 1: a step failed; 2: usage.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE_REPOSITORY=quay.io/oxidestack/mock-server
RETRY_DELAYS=${RETRY_DELAYS:-10 30}
AUTH=${DOCKER_CONFIG:-$HOME/.docker}/config.json
CHANGELOG=${CHANGELOG:-$ROOT/CHANGELOG.md}
export CHANGELOG

usage() {
	sed -n '7,43p' "$0" >&2
	exit 2
}

say() { echo "release: $*" >&2; }

# tool <name>: the pinned binary's path.
tool() { sh "$ROOT/tools/lint/fetch-tool.sh" "$1"; }

# retry <what> <command>...: the command up to three times.
retry() {
	what=$1
	shift
	for delay in $RETRY_DELAYS 0; do
		"$@" && return 0
		[ "$delay" = 0 ] && break
		say "$what failed; again in ${delay}s"
		sleep "$delay"
	done
	say "$what failed three times"
	return 1
}

# oras_ <command> <args>: oras with the credentials (and plain HTTP for a test registry); `cp` names both ends.
oras_() {
	if [ "$1" = cp ]; then
		set -- "$@" --from-registry-config "$AUTH" --to-registry-config "$AUTH"
		[ "${REGISTRY_PLAIN_HTTP:-}" != 1 ] || set -- "$@" --from-plain-http --to-plain-http
	else
		set -- "$@" --registry-config "$AUTH"
		[ "${REGISTRY_PLAIN_HTTP:-}" != 1 ] || set -- "$@" --plain-http
	fi
	"$ORAS" "$@"
}

cosign_() {
	# The plain-HTTP flag names cosign's own spelling.
	# shellcheck disable=SC2046 # the flag is one word or none
	DOCKER_CONFIG=$(dirname "$AUTH") "$COSIGN" "$@" $([ "${REGISTRY_PLAIN_HTTP:-}" = 1 ] && echo --allow-http-registry)
}

# section <heading>: CHANGELOG.md's section under `## <heading>` (`[9.2.0]`, `Unreleased`), without the heading and
# the link at its end.
section() {
	awk -v want="## $1" '
		index($0, want) == 1 && (length($0) == length(want) || substr($0, length(want) + 1, 1) == " ") { on = 1; next }
		on && /^## / { exit }
		on { print }
	' "$CHANGELOG" | awk -v v="$1" '
		{ lines[NR] = $0 }
		END {
			n = NR
			# A released section ends with its compare link, `[<version>]: https://…`, and blank lines.
			while (n > 0 && (lines[n] ~ /^[ \t]*$/ || index(lines[n], v ": ") == 1)) n--
			s = 1
			while (s <= n && lines[s] ~ /^[ \t]*$/) s++
			for (i = s; i <= n; i++) print lines[i]
		}
	'
}

[ $# -ge 1 ] || usage
cmd=$1
shift
case $cmd in
check)
	[ $# -eq 1 ] || usage
	version=$(sh "$ROOT/tools/ci/publish-image.sh" version "$1")
	case $version in
	*-*) ;;
	*)
		rc=0
		got=$(sed -n '/^\[package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -n 1)
		[ "$got" = "$version" ] || {
			say "Cargo.toml's version is $got, the tag says $version"
			rc=1
		}
		sh "$ROOT/scripts/release-check.sh" "$1" > /dev/null || rc=1
		[ $rc -eq 0 ] || exit 1
		;;
	esac
	echo "$version"
	;;
on-main)
	[ $# -eq 2 ] || usage
	status=$(gh api "repos/$1/compare/main...$2" --jq .status)
	case $status in
	identical | behind) ;;
	*)
		say "$2 is not on main (main...$2 is $status): a release is tagged on main"
		exit 1
		;;
	esac
	;;
wait-ci)
	[ $# -ge 2 ] && [ $# -le 3 ] || usage
	repo=$1 sha=$2 minutes=${3:-180}
	deadline=$(($(date +%s) + minutes * 60))
	while :; do
		# Every run of ci.yml on the commit: a push's, a manual one's.
		runs=$(gh api "repos/$repo/actions/workflows/ci.yml/runs?head_sha=$sha&per_page=100" \
			--jq '.workflow_runs[] | "\(.status) \(.conclusion // "-") \(.html_url)"')
		if printf '%s\n' "$runs" | grep -q '^completed success '; then
			say "CI passed on $sha: $(printf '%s\n' "$runs" | grep '^completed success ' | head -n 1 | cut -d' ' -f3)"
			exit 0
		fi
		if [ -n "$runs" ] && ! printf '%s\n' "$runs" | grep -qv '^completed '; then
			say "every CI run on $sha has failed or was cancelled:"
			printf '%s\n' "$runs" >&2
			exit 1
		fi
		[ "$(date +%s)" -lt "$deadline" ] || {
			say "no passed CI run on $sha after $minutes minutes"
			exit 1
		}
		sleep 60
	done
	;;
notes)
	[ $# -ge 1 ] && [ $# -le 2 ] || usage
	version=$1 digest=${2:-}
	body=$(section "[$version]")
	if [ -z "$body" ]; then
		case $version in
		*-*)
			body="A pre-release of ${version%%-*}, for testing. \`latest\` and the \`mockserver-<version>\` tags stay on the last release."
			unreleased=$(section Unreleased)
			[ -z "$unreleased" ] || body=$(printf '%s\n\n%s' "$body" "$unreleased")
			;;
		*)
			say "CHANGELOG.md has no section ## [$version]"
			exit 1
			;;
		esac
	fi
	repo=${GITHUB_REPOSITORY:-oxidestack/mock-server}
	ref="$IMAGE_REPOSITORY:$version"
	identity="https://github.com/$repo/.github/workflows/release.yml@refs/tags/v$version"
	at=""
	[ -z "$digest" ] || at=" (\`$digest\`)"
	printf '%s\n\n' "$body"
	cat << EOF
## Run

\`\`\`sh
docker run --rm -p 1080:1080 $ref
\`\`\`

The image$at is published to quay.io for linux/amd64 and linux/arm64 and mirrored, with the same digest, signature and attestations, to \`ghcr.io/oxidestack/mock-server\`. The SBOMs (SPDX and CycloneDX, one per architecture) are attached below.

## Verify

\`\`\`sh
cosign verify $ref --certificate-identity $identity --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://$ref --repo $repo
\`\`\`

Each file below is signed the same way, its Sigstore bundle beside it (\`<file>.sigstore.json\`), and \`mock-server-$version.intoto.jsonl\` is the build provenance of them all. The bundles are in Sigstore's current bundle format: \`cosign verify-blob\` needs cosign 3 or later (cosign 2 needs \`--new-bundle-format\` added, or it answers \`bundle does not contain cert for verification\`). For the amd64 SBOM, as for any other file:

\`\`\`sh
cosign verify-blob mock-server-amd64.spdx.json --bundle mock-server-amd64.spdx.json.sigstore.json --certificate-identity $identity --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify mock-server-amd64.spdx.json --repo $repo
\`\`\`
EOF
	;;
quay-login)
	[ $# -eq 1 ] || usage
	robot=$1
	QUAY_AUDIENCE=${QUAY_AUDIENCE:-quay}
	[ -n "$robot" ] || {
		echo "::error title=quay.io::no repository variable QUAY_ROBOT (the robot account, oxidestack+<name>)"
		exit 1
	}
	[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || {
		say "no OIDC token in this job (it needs id-token: write)"
		exit 1
	}
	# The token is asked for quay.io's audience, which the robot's federation names: a token for quay.io cannot be
	# replayed at another service that trusts GitHub's issuer.
	oidc=$(curl -fsS --retry 3 -G -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
		--data-urlencode "audience=$QUAY_AUDIENCE" "$ACTIONS_ID_TOKEN_REQUEST_URL" | jq -r .value)
	echo "::add-mask::$oidc"
	# curl reads the robot's credentials from its config on stdin, never from an argument.
	answer=$(mktemp)
	status=$(printf 'user = "%s:%s"\n' "$robot" "$oidc" |
		curl -sS --retry 3 -o "$answer" -w '%{http_code}' -K - https://quay.io/oauth2/federation/robot/token) || status=000
	token=$(jq -r '.token // empty' "$answer" 2> /dev/null || true)
	[ "$status" = 200 ] && [ -n "$token" ] || {
		# What quay.io said, and the claims it matched against the robot's federation: the issuer, the subject and the
		# audience are not secret, the token's signature is never printed.
		claims=$(printf '%s' "$oidc" | cut -d. -f2 | tr '_-' '/+' | awk '{ while (length($0) % 4) $0 = $0 "="; print }' |
			base64 -d 2> /dev/null | jq -c '{iss, sub, aud}' 2> /dev/null || echo '?')
		echo "::error title=quay.io::the robot token exchange answered HTTP $status: $(head -c 500 "$answer")"
		echo "::error title=quay.io::the job's OIDC claims: $claims"
		rm -f "$answer"
		exit 1
	}
	rm -f "$answer"
	echo "::add-mask::$token"
	printf '%s' "$token" | sh "$0" login quay.io "$robot"
	;;
login)
	[ $# -eq 2 ] || usage
	ORAS=$(tool oras)
	mkdir -p "$(dirname "$AUTH")"
	# The password is read from stdin. oras writes a Docker config.json, which cosign, crane and the attestation
	# action read too.
	oras_ login "$1" -u "$2" --password-stdin > /dev/null
	;;
sign)
	[ $# -eq 1 ] || usage
	case $1 in
	*@sha256:*) ;;
	*)
		say "sign a digest, not a tag: $1"
		exit 2
		;;
	esac
	COSIGN=$(tool cosign)
	if [ -n "${COSIGN_KEY:-}" ]; then
		retry "signature of $1" cosign_ sign --yes --key "$COSIGN_KEY" --use-signing-config=false --tlog-upload=false "$1"
	else
		retry "signature of $1" cosign_ sign --yes "$1"
	fi
	;;
verify)
	[ $# -eq 2 ] || usage
	COSIGN=$(tool cosign)
	if [ -n "${COSIGN_PUB:-}" ]; then
		retry "verification of $1" cosign_ verify --key "$COSIGN_PUB" --insecure-ignore-tlog=true "$1" > /dev/null
	else
		repo=${GITHUB_REPOSITORY:-oxidestack/mock-server}
		retry "verification of $1" cosign_ verify "$1" \
			--certificate-identity "https://github.com/$repo/.github/workflows/release.yml@refs/tags/$2" \
			--certificate-oidc-issuer https://token.actions.githubusercontent.com > /dev/null
	fi
	say "$1: the signature verifies"
	;;
sign-blob)
	[ $# -ge 1 ] || usage
	COSIGN=$(tool cosign)
	for file in "$@"; do
		[ -f "$file" ] || {
			say "no file $file"
			exit 1
		}
		if [ -n "${COSIGN_KEY:-}" ]; then
			retry "signature of $file" "$COSIGN" sign-blob --yes --key "$COSIGN_KEY" --use-signing-config=false \
				--tlog-upload=false --bundle "$file.sigstore.json" "$file" > /dev/null
		else
			retry "signature of $file" "$COSIGN" sign-blob --yes --bundle "$file.sigstore.json" "$file" > /dev/null
		fi
	done
	;;
verify-blob)
	[ $# -ge 2 ] || usage
	tag=$1
	shift
	COSIGN=$(tool cosign)
	repo=${GITHUB_REPOSITORY:-oxidestack/mock-server}
	for file in "$@"; do
		if [ -n "${COSIGN_PUB:-}" ]; then
			retry "verification of $file" "$COSIGN" verify-blob --key "$COSIGN_PUB" --insecure-ignore-tlog=true \
				--bundle "$file.sigstore.json" "$file" > /dev/null
		else
			retry "verification of $file" "$COSIGN" verify-blob --bundle "$file.sigstore.json" \
				--certificate-identity "https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag" \
				--certificate-oidc-issuer https://token.actions.githubusercontent.com "$file" > /dev/null
		fi
		say "$file: the signature verifies"
	done
	;;
mirror)
	[ $# -ge 3 ] || usage
	src=$1 dst=$2 first=$3
	shift 3
	ORAS=$(tool oras)
	# -r: the referrers too, through the OCI referrers API or its tag-schema fallback, whichever each registry has.
	retry "copy to $dst:$first" oras_ cp -r "$src:$first" "$dst:$first" > /dev/null
	for tag in "$@"; do
		retry "tag $dst:$tag" oras_ tag "$dst:$first" "$tag" > /dev/null
	done
	want=$(retry "digest of $src:$first" oras_ resolve "$src:$first")
	got=$(retry "digest of $dst:$first" oras_ resolve "$dst:$first")
	[ "$want" = "$got" ] || {
		say "$dst:$first is $got, $src:$first is $want"
		exit 1
	}
	echo "$got"
	;;
platforms)
	[ $# -eq 1 ] || usage
	ORAS=$(tool oras)
	retry "manifest of $1" oras_ manifest fetch "$1" |
		jq -r '.manifests[] | select(.platform.os != "unknown") | "\(.platform.os)/\(.platform.architecture) \(.digest)"'
	;;
*) usage ;;
esac
