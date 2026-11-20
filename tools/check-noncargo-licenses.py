#!/usr/bin/env python3
"""The CNCF third-party licence policy over the non-Cargo dependencies of what is distributed.

deny.toml and tools/check-third-party.sh cover the Cargo graph and third_party/. This covers:
  npm    the packages bundled into the embedded dashboard, as DASHBOARD-THIRD-PARTY-NOTICES.txt lists them (generated
         from the bundle's module graph by scripts/dashboard-notices.py; the dashboard CI job fails when it is stale)
  maven  the compile and runtime dependencies (transitive too) of java-launcher/, the one Maven artifact built for
         distribution; test-scope dependencies are not distributed and are not read

Both are checked against the allowlist in deny.toml's `[licenses] allow` (the same one) and against the named
exceptions in tools/noncargo-licence-exceptions.txt, one `<ecosystem> <name>@<version> <licence> <CNCF status>` per
line (the licence expression with spaces written as `_`), exact versions: a version bump of an excepted package fails until its entry is reviewed and moved. An entry that
matches no package is stale and fails too.

    tools/check-noncargo-licenses.py npm [--notices FILE]
    tools/check-noncargo-licenses.py maven --list FILE [--repo DIR]
        FILE is `mvn -f java-launcher/pom.xml dependency:list -DincludeScope=runtime -DoutputFile=FILE`; DIR is the
        local Maven repository the list was resolved into (default ~/.m2/repository).

Exit 0: all good. Exit 1: findings, one line each. Exit 2: an input cannot be read.
"""
import argparse
import os
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Licence names as POMs write them -> SPDX ids. Matched on the lowercased name with punctuation collapsed; a name that
# is not here is a finding (add it here only after reading what the licence is).
POM_NAMES = {
    "apache license version 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "the apache software license version 2.0": "Apache-2.0",
    "the apache license version 2.0": "Apache-2.0",
    "apache software license version 2.0": "Apache-2.0",
    "mit license": "MIT",
    "mit": "MIT",
    "the mit license": "MIT",
    "bsd license": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "the 3-clause bsd license": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "eclipse distribution license v. 1.0": "BSD-3-Clause",
    "eclipse distribution license - v 1.0": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "the bsd 2-clause license": "BSD-2-Clause",
    "eclipse public license v2.0": "EPL-2.0",
    "eclipse public license 2.0": "EPL-2.0",
    "eclipse public license - v 2.0": "EPL-2.0",
    "eclipse public license 1.0": "EPL-1.0",
    "gnu lesser general public license": "LGPL-2.1-only",
    "gnu general public license version 2 with the classpath exception": "GPL-2.0-only WITH Classpath-exception-2.0",
    "gnu general public license v2.0 w/classpath exception": "GPL-2.0-only WITH Classpath-exception-2.0",
    "public domain": "Public-Domain",
    "cc0": "CC0-1.0",
    "creative commons zero": "CC0-1.0",
    "mozilla public license 2.0": "MPL-2.0",
    # Read from the licence texts the POMs point at, not guessed:
    "bsd": "BSD-3-Clause",  # com.jcraft:jzlib, http://www.jcraft.com/jzlib/LICENSE.txt: the 3-clause text
    "the mit license mit": "MIT",  # classgraph, "The MIT License (MIT)"
    "edl 1.0": "BSD-3-Clause",  # Eclipse Distribution License 1.0 is the 3-clause BSD text
    "epl 2.0": "EPL-2.0",
    "gpl2 w/ cpe": "GPL-2.0-only WITH Classpath-exception-2.0",
    "bouncy castle licence": "MIT",  # bouncycastle.org/licence.html is the MIT (X11) text
    "mit-0": "MIT-0",
}


def allowlist(deny=ROOT / "deny.toml"):
    """deny.toml's top-level `[licenses] allow = [...]`, the way tools/check-third-party.sh reads it."""
    try:
        text = deny.read_text()
    except OSError as e:
        die(f"cannot read {deny}: {e}")
    allowed, section, inlist = set(), "", False
    for line in text.splitlines():
        if line.startswith("["):
            section = line.strip()
        if section == "[licenses]" and re.match(r"allow = \[\s*$", line):
            inlist = True
            continue
        if inlist and line.startswith("]"):
            break
        if inlist:
            allowed.update(re.findall(r'"([^"]+)"', line))
    if not allowed:
        die(f"no [licenses] allow list in {deny}")
    return allowed


def exceptions(path=ROOT / "tools" / "noncargo-licence-exceptions.txt"):
    """{(ecosystem, name@version): licence}; one line each, `#` comments."""
    out = {}
    try:
        lines = path.read_text().splitlines()
    except OSError as e:
        die(f"cannot read {path}: {e}")
    for n, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split(None, 3)
        if len(parts) < 4:
            die(f"{path}:{n}: expected `<ecosystem> <name>@<version> <licence> <CNCF status>`")
        out[(parts[0], parts[1])] = parts[2]
    return out


def die(msg):
    print(f"check-noncargo-licenses: {msg}", file=sys.stderr)
    sys.exit(2)


def tokens(expr):
    return re.findall(r"\(|\)|[^\s()]+", expr)


def satisfied(expr, allowed):
    """Whether an SPDX expression (AND, OR, WITH, parentheses) is licensable under the allowlist alone: an OR needs one
    allowed side, an AND all of them; `X WITH exception` is X's own id, which is how the allowlist names it."""
    toks = tokens(expr)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def atom():
        t = take()
        if t == "(":
            v = disj()
            if peek() == ")":
                take()
            return v
        ident = t
        if peek() == "WITH":
            take()
            take()
            return False  # a licence exception is never on the allowlist
        return ident in allowed

    def conj():
        v = atom()
        while peek() == "AND":
            take()
            v = atom() and v
        return v

    def disj():
        v = conj()
        while peek() == "OR":
            take()
            v = conj() or v
        return v

    try:
        return disj()
    except IndexError:
        return False


def report(kind, found, allowed, excepted):
    """found: [(name@version, licence expression)]. Prints the findings; returns the exit code."""
    findings, used = [], set()
    for ident, expr in found:
        if satisfied(expr, allowed):
            continue
        key = (kind, ident)
        if key in excepted and excepted[key] == expr.replace(" ", "_"):
            used.add(key)
            continue
        if key in excepted:
            findings.append(f"{kind}: {ident}: licence {expr!r}, but its exception records {excepted[key]!r} (spaces as _); review it")
            used.add(key)
        else:
            findings.append(
                f"{kind}: {ident}: licence {expr!r} is not on deny.toml's allowlist and "
                "tools/noncargo-licence-exceptions.txt names no exception for it"
            )
    for key in sorted(k for k in excepted if k[0] == kind and k not in used):
        findings.append(f"{kind}: {key[1]}: exception is stale (no such package, or its licence is allowlisted now); delete it")
    for f in findings:
        print(f)
    if findings:
        print(f"check-noncargo-licenses: {kind}: {len(findings)} finding(s)")
        return 1
    print(f"check-noncargo-licenses: {kind}: ok ({len(found)} package(s))")
    return 0


def npm(notices):
    try:
        text = notices.read_text()
    except OSError as e:
        die(f"cannot read {notices}: {e}")
    m = re.search(r"^(\d+) packages:\n\n(.*?)\n\n", text, re.S | re.M)
    if not m:
        die(f"{notices}: no `N packages:` summary")
    found = []
    for line in m.group(2).splitlines():
        ident, _, expr = line.partition("  ")
        expr = expr.strip()
        if not ident or not expr:
            die(f"{notices}: unreadable summary line {line!r}")
        # `unspecified in package.json` is not a licence: it is a finding until the package is settled.
        found.append((ident, expr))
    if len(found) != int(m.group(1)):
        die(f"{notices}: summary says {m.group(1)} packages, lists {len(found)}")
    return found


def norm(name):
    return re.sub(r"\s+", " ", re.sub(r"[,()]", " ", name.lower())).strip()


def pom_root(repo, g, a, v):
    p = repo / g.replace(".", "/") / a / v / f"{a}-{v}.pom"
    if not p.is_file():
        return None
    root = ET.parse(p).getroot()
    return root


def local(tag):
    return tag.rsplit("}", 1)[-1]


def child(el, name):
    for c in el:
        if local(c.tag) == name:
            return c
    return None


def text_of(el, name):
    c = child(el, name)
    return (c.text or "").strip() if c is not None else ""


def pom_licences(repo, g, a, v, depth=0):
    """Licence names a POM declares, else its parent's (Maven inherits <licenses>)."""
    root = pom_root(repo, g, a, v)
    if root is None:
        return None
    lic = child(root, "licenses")
    if lic is not None:
        names = [text_of(l, "name") or text_of(l, "url") for l in lic if local(l.tag) == "license"]
        if names:
            return names
    parent = child(root, "parent")
    if parent is not None and depth < 8:
        return pom_licences(repo, text_of(parent, "groupId"), text_of(parent, "artifactId"), text_of(parent, "version"), depth + 1)
    return []


def maven(listing, repo):
    try:
        lines = listing.read_text().splitlines()
    except OSError as e:
        die(f"cannot read {listing}: {e}")
    gavs = {}
    for line in lines:
        m = re.match(r"\s+([^:\s]+):([^:\s]+):[^:\s]+:(?:[^:\s]+:)?([^:\s]+):(compile|runtime)\b", line)
        if m:
            gavs[(m.group(1), m.group(2), m.group(3))] = None  # classifier variants share a POM
    if not gavs:
        die(f"{listing}: no resolved compile/runtime artifacts (is it `dependency:list` output?)")
    found = []
    for g, a, v in sorted(gavs):
        names = pom_licences(repo, g, a, v)
        ident = f"{g}:{a}@{v}"
        if names is None:
            die(f"{ident}: no POM in {repo} (resolve the list into this repository first)")
        if not names:
            found.append((ident, "unspecified-in-pom"))
            continue
        spdx = [POM_NAMES.get(norm(n), f"unmapped:{n.replace(' ', '_')}") for n in names]
        # A POM listing several licences offers them as alternatives (Maven's own reading: the user may choose).
        found.append((ident, " OR ".join(spdx)))
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="kind", required=True)
    n = sub.add_parser("npm")
    n.add_argument("--notices", type=pathlib.Path, default=ROOT / "DASHBOARD-THIRD-PARTY-NOTICES.txt")
    m = sub.add_parser("maven")
    m.add_argument("--list", type=pathlib.Path, required=True)
    m.add_argument("--repo", type=pathlib.Path, default=pathlib.Path(os.path.expanduser("~/.m2/repository")))
    ap.add_argument("--exceptions", type=pathlib.Path, default=ROOT / "tools" / "noncargo-licence-exceptions.txt")
    ap.add_argument("--deny", type=pathlib.Path, default=ROOT / "deny.toml")
    args = ap.parse_args()
    allowed, excepted = allowlist(args.deny), exceptions(args.exceptions)
    found = npm(args.notices) if args.kind == "npm" else maven(args.list, args.repo)
    sys.exit(report(args.kind, found, allowed, excepted))


if __name__ == "__main__":
    main()
