#!/bin/sh
# The workflows' gate (the `lint-actions` job of .github/workflows/ci.yml): actionlint on .github/workflows/ (syntax,
# expressions, the `run:` scripts through shellcheck), then zizmor on .github/ (template injection, over-broad
# `permissions`, unpinned actions and images, persisted credentials), offline, so a push never waits on GitHub's API.
# The binaries are the ones pinned in tools/lint/tools.txt, so this runs on Linux: a runner, or a container of the rust
# image (`docker run --rm -v "$PWD:/src" -w /src rust:1.98.0-bookworm sh tools/ci/lint-actions.sh`).
# Exit 0: clean; 1: findings.
set -eu
cd "$(dirname "$0")/../.."
PATH="$(dirname "$(sh tools/lint/fetch-tool.sh shellcheck)"):$PATH"
rc=0
"$(sh tools/lint/fetch-tool.sh actionlint)" -no-color || rc=1
"$(sh tools/lint/fetch-tool.sh zizmor)" --offline --no-progress --format plain .github || rc=1
exit $rc
