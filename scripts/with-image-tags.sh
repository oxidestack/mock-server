#!/usr/bin/env bash
# Runs a command with an image temporarily under other names, then puts every name back as it was:
#
#   scripts/with-image-tags.sh SOURCE_IMAGE TAG [TAG...] -- COMMAND [ARG...]
#
# Before tagging, each TAG's current image id is saved; on exit (normal, error or signal) the tag is pointed back at
# that id, or removed when it did not exist. A pulled image (the real mockserver/mockserver:mockserver-7.6.0, say)
# keeps its tag. Exits with COMMAND's status.
set -uo pipefail
source_image="$1"
shift
tags=()
while [[ $# -gt 0 && "$1" != "--" ]]; do tags+=("$1"); shift; done
[[ "${1:-}" == "--" && ${#tags[@]} -gt 0 ]] || { echo "usage: $0 SOURCE_IMAGE TAG... -- COMMAND..." >&2; exit 2; }
shift

saved=()
for tag in "${tags[@]}"; do
  saved+=("$(docker image inspect --format '{{.Id}}' "${tag}" 2>/dev/null || true)")
done

restore() {
  local i
  for i in "${!tags[@]}"; do
    if [[ -n "${saved[$i]}" ]]; then
      docker tag "${saved[$i]}" "${tags[$i]}" >/dev/null 2>&1 || echo "could not restore ${tags[$i]} to ${saved[$i]}" >&2
    else
      docker rmi --no-prune "${tags[$i]}" >/dev/null 2>&1 || true
    fi
  done
}
trap restore EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for tag in "${tags[@]}"; do
  docker tag "${source_image}" "${tag}" || exit 1
done
"$@"
