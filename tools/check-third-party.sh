#!/bin/sh
# Checks that third_party/ holds exactly the files third_party/MANIFEST lists, each unmodified (its recorded upstream
# sha256), and that each file's licence is on deny.toml's allowlist or names an exception. Run from the
# repository root (the `licenses` CI job, `make licenses`). POSIX sh, so it runs in the CI image and on macOS.
#
# Exit 0: all good. Exit 1: findings, one line each. Exit 2: the manifest or deny.toml cannot be read.

set -u

dir=third_party
manifest=$dir/MANIFEST
deny=deny.toml

[ -r "$manifest" ] || { echo "check-third-party: cannot read $manifest" >&2; exit 2; }
[ -r "$deny" ] || { echo "check-third-party: cannot read $deny" >&2; exit 2; }

if command -v sha256sum >/dev/null 2>&1; then
  sha() { sha256sum "$1" | cut -d' ' -f1; }
else
  sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

# deny.toml's top-level `[licenses] allow = [` list, one licence per line (the exceptions' one-line lists are not it).
allowed=$(awk '
  /^\[/ { section = $0 }
  section == "[licenses]" && /^allow = \[[ \t]*$/ { inlist = 1; next }
  inlist && /^\]/ { exit }
  inlist { while (match($0, /"[^"]+"/)) { print substr($0, RSTART + 1, RLENGTH - 2); $0 = substr($0, RSTART + RLENGTH) } }
' "$deny")
[ -n "$allowed" ] || { echo "check-third-party: no [licenses] allow list in $deny" >&2; exit 2; }

findings=0
fail() { echo "third_party: $*"; findings=$((findings + 1)); }

listed=$(mktemp)
trap 'rm -f "$listed"' EXIT

lineno=0
while IFS= read -r line || [ -n "$line" ]; do
  lineno=$((lineno + 1))
  case "$line" in ''|'#'*) continue ;; esac
  # shellcheck disable=SC2086
  set -- $line
  if [ "$#" -ne 5 ]; then
    fail "$manifest:$lineno: expected 5 fields (path sha256 licence source exception), found $#"
    continue
  fi
  path=$1 hash=$2 licence=$3 source=$4 exception=$5
  echo "$path" >> "$listed"
  file=$dir/$path
  if [ ! -f "$file" ]; then
    fail "$path: listed in $manifest but missing"
  else
    actual=$(sha "$file")
    [ "$actual" = "$hash" ] || fail "$path: sha256 $actual, recorded $hash (modified; upstream is $source)"
  fi
  if [ "$exception" = "-" ]; then
    printf '%s\n' "$allowed" | grep -qxF "$licence" \
      || fail "$path: licence $licence is not on $deny's allowlist and $manifest names no exception for it"
  fi
done < "$manifest"

# Every file in the folder is listed (the manifest itself excepted).
find "$dir" -type f ! -path "$manifest" | sed "s|^$dir/||" | sort | while IFS= read -r path; do
  grep -qxF "$path" "$listed" || echo "third_party: $path: not listed in $manifest (record its upstream source, sha256 and licence)"
done > "$listed.unlisted"
if [ -s "$listed.unlisted" ]; then
  cat "$listed.unlisted"
  findings=$((findings + $(wc -l < "$listed.unlisted")))
fi
rm -f "$listed.unlisted"

if [ "$findings" -gt 0 ]; then
  echo "check-third-party: $findings finding(s)"
  exit 1
fi
echo "check-third-party: ok ($(wc -l < "$listed" | tr -d ' ') file(s))"
