#!/usr/bin/env bash
# Builds MockServer's dashboard UI (upstream/mockserver/mockserver-ui) the way upstream's `build-ui` Maven profile
# does (`npm ci`, then `npm run build` = `tsc -b && vite build`) into dashboard/, which build.rs embeds into the
# binary. The build runs in a copy under target/dashboard-ui/ so the submodule stays clean, with
# scripts/dashboard-vite.config.ts (mockserver-ui's config plus a module list) so that DASHBOARD-THIRD-PARTY-NOTICES.txt
# is regenerated from what the bundle contains.
# Skips the build when the output was built from the same mockserver-ui tree and scripts (its `.stamp`); FORCE=1
# rebuilds. Needs node 22, npm, tar, git, shasum and python3 on PATH.
#
# build.rs runs it too, when no bundle is in dashboard/, with:
#   DASHBOARD_OUT=<dir>      the bundle's directory instead of dashboard/
#   DASHBOARD_NOTICES=<file> where the notices go instead of DASHBOARD-THIRD-PARTY-NOTICES.txt
#   DASHBOARD_WORK=<dir>     the working copy instead of target/dashboard-ui
#                            It keeps upstream's sibling layout: <work>/mockserver-ui/ next to
#                            <work>/mockserver-client-rust/Cargo.toml, whose version mockserver-ui/build-constants.ts
#                            reads through ../mockserver-client-rust.
#   DASHBOARD_AUTO=1         a node other than 22 counts as missing rather than a warning
#   DASHBOARD_NODE=download  installs node (mockserver-ui/.nvmrc's version) from nodejs.org under the working copy's
#                            parent, `frontend/`, as frontend-maven-plugin does; checked against SHASUMS256.txt
# A missing prerequisite exits 2 with a `missing: …` line on stderr; build.rs reports it as a warning.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source_dir="$root/upstream/mockserver/mockserver-ui"
# Files outside mockserver-ui that its build reads, relative to upstream/mockserver; .dockerignore and the
# Dockerfile's `ui` stage list the same.
siblings=(mockserver-client-rust/Cargo.toml)
work="${DASHBOARD_WORK:-${CARGO_TARGET_DIR:-$root/target}/dashboard-ui}"
out="${DASHBOARD_OUT:-$root/dashboard}"
notices="${DASHBOARD_NOTICES:-$root/DASHBOARD-THIRD-PARTY-NOTICES.txt}"
# The same list as .dockerignore's: installed or generated, never sources.
excludes=(node_modules build test-results playwright-report)

missing() { echo "missing: $*" >&2; exit 2; }

[ -f "$source_dir/package.json" ] || missing "$source_dir (run: git submodule update --init upstream/mockserver)"
for tool in git shasum tar python3; do
    command -v "$tool" > /dev/null || missing "$tool on PATH"
done

# What the bundle is built from: the submodule's mockserver-ui tree and siblings (plus any uncommitted change) and
# these scripts.
stamp=$( {
    git -C "$root/upstream/mockserver" rev-parse HEAD:mockserver-ui "${siblings[@]/#/HEAD:}"
    git -C "$root/upstream/mockserver" status --porcelain -- mockserver-ui "${siblings[@]}"
    cat "$0" "$root/scripts/dashboard-vite.config.ts" "$root/scripts/dashboard-notices.py"
} | shasum | cut -d' ' -f1)
if [ -z "${FORCE:-}" ] && [ -f "$out/index.html" ] && [ "$(cat "$out/.stamp" 2>/dev/null)" = "$stamp" ]; then
    echo "dashboard bundle up to date: $out"
    exit 0
fi

node_version=$(cat "$source_dir/.nvmrc")
if [ "${DASHBOARD_NODE:-}" = download ]; then
    case "$(uname -s)" in Darwin) os=darwin ;; Linux) os=linux ;; *) missing "a nodejs.org build for $(uname -s)" ;; esac
    case "$(uname -m)" in x86_64|amd64) arch=x64 ;; arm64|aarch64) arch=arm64 ;; *) missing "a nodejs.org build for $(uname -m)" ;; esac
    command -v curl > /dev/null || missing "curl on PATH (to download node)"
    name="node-v$node_version-$os-$arch"
    install="$(dirname "$work")/frontend"
    if [ ! -x "$install/$name/bin/node" ]; then
        mkdir -p "$install"
        echo "downloading $name from nodejs.org into $install"
        curl -fsSL -o "$install/$name.tar.gz" "https://nodejs.org/dist/v$node_version/$name.tar.gz"
        expected=$(curl -fsSL "https://nodejs.org/dist/v$node_version/SHASUMS256.txt" | awk -v f="$name.tar.gz" '$2 == f {print $1}')
        actual=$(shasum -a 256 "$install/$name.tar.gz" | cut -d' ' -f1)
        [ -n "$expected" ] && [ "$expected" = "$actual" ] || { echo "checksum mismatch for $name.tar.gz" >&2; exit 1; }
        tar -C "$install" -xzf "$install/$name.tar.gz"
        rm "$install/$name.tar.gz"
    fi
    export PATH="$install/$name/bin:$PATH"
fi
command -v node > /dev/null || missing "node $node_version on PATH (or MOCK_SERVER_DASHBOARD_NODE=download)"
command -v npm > /dev/null || missing "npm on PATH"
node_major=$(node --version | sed 's/^v\([0-9]*\).*/\1/')
if [ "$node_major" != "${node_version%%.*}" ]; then
    [ -n "${DASHBOARD_AUTO:-}" ] && missing "node ${node_version%%.*} on PATH (found $(node --version))"
    echo "warning: node $(node --version); upstream builds with v$node_version" >&2
fi

# A fresh copy of the sources; node_modules survives between runs (npm ci replaces it anyway).
ui="$work/mockserver-ui"
mkdir -p "$ui"
find "$work" -mindepth 1 -maxdepth 1 ! -name mockserver-ui -exec rm -rf {} +
find "$ui" -mindepth 1 -maxdepth 1 ! -name node_modules -exec rm -rf {} +
tar -C "$source_dir" "${excludes[@]/#/--exclude=./}" -cf - . | tar -C "$ui" -xf -
for sibling in "${siblings[@]}"; do
    mkdir -p "$(dirname "$work/$sibling")"
    cp "$root/upstream/mockserver/$sibling" "$work/$sibling"
done
cp "$root/scripts/dashboard-vite.config.ts" "$ui/vite.msrs.config.ts"
cd "$ui"
npm ci --no-audit --no-fund
npx tsc -b
npx vite build --config vite.msrs.config.ts

# Through a temporary file, so a failure leaves the previous notices in place rather than an empty file.
"$root/scripts/dashboard-notices.py" "$ui" > "$notices.tmp" || { rm -f "$notices.tmp"; exit 1; }
mv "$notices.tmp" "$notices"
# Replace the bundle but keep dashboard/.gitignore, which keeps the directory tracked.
mkdir -p "$out"
find "$out" -mindepth 1 -maxdepth 1 ! -name .gitignore -exec rm -rf {} +
cp -R build/. "$out/"
echo "$stamp" > "$out/.stamp"
echo "dashboard bundle: $out ($(du -sh "$out" | cut -f1))"
