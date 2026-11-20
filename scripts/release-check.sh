#!/bin/sh
# The release gate for the upgrade guide (the twin of docx-to-pdf's `tools/ci/release.sh check`).
#
#   sh scripts/release-check.sh <tag>
#       <tag> is vX.Y.Z (or X.Y.Z). A release (no `-` in the version) whose CHANGELOG.md section `## [X.Y.Z]` has a
#       `### Action required` heading must have `## Upgrading to X.Y.Z` in docs/guide/upgrading.md, else exit 1. A
#       release without a section of its own is refused too. A pre-release (`-rc.N`) needs nothing. The version
#       is printed on stdout.
#   sh scripts/release-check.sh
#       No release yet: the `## Unreleased` section of CHANGELOG.md, when it has Action required, needs some
#       `## Upgrading to ` section in the guide (the placeholder `X.Y.Z` of the first release is one). This is the
#       form `main`'s pipeline runs.
#
# CHANGELOG and UPGRADING in the environment name other files (the tests use it). Needs only sh and awk.
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CHANGELOG=${CHANGELOG:-$ROOT/CHANGELOG.md}
UPGRADING=${UPGRADING:-$ROOT/docs/guide/upgrading.md}

say() { echo "release-check: $*" >&2; }

# section <heading prefix>: the lines of the CHANGELOG section whose `## ` heading starts with the prefix, up to the next `## `.
section() {
	awk -v p="## $1" '
		/^## / { on = (index($0, p) == 1); next }
		on { print }
	' "$CHANGELOG"
}

case $# in
0)
	if section "Unreleased" | grep -q '^### Action required'; then
		grep -q '^## Upgrading to ' "$UPGRADING" || {
			say "CHANGELOG.md's Unreleased section asks for action, and docs/guide/upgrading.md has no ## Upgrading to section"
			exit 1
		}
	fi
	echo Unreleased
	;;
1)
	version=${1#v}
	case $version in
	*-*) echo "$version"; exit 0 ;; # a pre-release: its notes live on its GitHub release
	[0-9]*.[0-9]*.[0-9]*) ;;
	*) say "$1 is not a version tag (vX.Y.Z)"; exit 1 ;;
	esac
	if [ -z "$(section "[$version]")" ]; then
		say "CHANGELOG.md has no section ## [$version]"
		exit 1
	fi
	if section "[$version]" | grep -q '^### Action required'; then
		grep -qx "## Upgrading to $version" "$UPGRADING" || {
			say "CHANGELOG.md's $version asks for action, and docs/guide/upgrading.md has no ## Upgrading to $version"
			exit 1
		}
	fi
	echo "$version"
	;;
*)
	say "usage: release-check.sh [<tag>]"
	exit 2
	;;
esac
