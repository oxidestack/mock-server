#!/usr/bin/env python3
"""Writes docs/coverage.md: how much of MockServer 8.0.0's own test suite runs against mock-server.

  python3 conformance/coverage.py > docs/coverage.md

Inputs, all produced by earlier runs:
- conformance/upstream/target/surefire-reports/{oracle-process,rs-process}/TEST-conformance.upstream.*.xml  (make upstream-tests;
  results.suite_reports, which ignores a -Dtest=<Class> rerun's stray TEST-<fqcn>.xml)
- conformance/upstream/src/test/resources/tranches/T*.txt                             (wired classes)
- target/upstream-scenario-results.tsv                          (cargo test --test oracle, harvested B cases)
- target/upstream-scenario-diffs.txt                            (the same run's first differences)
- docs/divergences.md                                           (its main table's rows, by kind)

Exits non-zero, writing nothing, unless the last two come from one unfiltered replay.
"""
import collections
import csv
import datetime
import glob
import os
import re
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
UPSTREAM = os.path.join(ROOT, "conformance", "upstream")
sys.path.insert(0, UPSTREAM)
import results  # noqa: E402

T1_SUITES = ("RemoteControlPlaneTest", "RemoteTransportAgnosticSemanticsTest", "RemotePackagingSmokeTest")

# Upstream's container cases (conformance/containers, expected_tests.manifest) and mockserver-testcontainers'
# MockServerContainerIntegrationTest, by the tranche the inventory (§7) gives them.
CONTAINER_TRANCHES = {
    "T1": ["MockServerContainerIntegrationTest", "docker_compose_server_port_by_command",
           "docker_compose_server_port_by_environment_variable_long_name",
           "docker_compose_server_port_by_environment_variable_short_name", "docker_compose_without_server_port",
           "docker_compose_with_expectation_initialiser", "docker_compose_with_server_port_from_default_properties_file",
           "docker_compose_with_server_port_from_custom_properties_file", "docker_healthcheck", "docker_nonroot_user",
           "docker_compose_jvm_options", "docker_compose_libs_classpath", "docker_compose_war_tomcat",
           "docker_variant_smoke_clustered", "docker_arm64_build_gate", "docker_variant_smoke_root",
           "docker_variant_smoke_snapshot", "docker_variant_smoke_local", "docker_variant_smoke_graaljs",
           "docker_variant_smoke_root-snapshot"],
    "T3": ["docker_compose_forward_with_override", "docker_compose_remote_host_and_port_by_environment_variable",
           "docker_compose_with_mtls"],
    "T4": ["docker_compose_with_persisted_expectations", "docker_compose_graceful_shutdown", "docker_compose_metrics"],
    "T5": ["helm_default_config", "helm_local_docker_container", "helm_custom_server_port", "helm_remote_host_and_port",
           "helm_inline_config", "helm_configmap_injection", "helm_mockserver_config_chart", "helm_sidecar_injection",
           "helm_clustered_convergence", "helm_jgroups_dns_ping"],
}
# Suites counted in each row of the category-A table besides the tranche's own (examples/java joins T5).
EXTRA_SUITES = {"T5": ("ExamplesTest",)}
EXAMPLES_TESTS = 44

# Inventory §4.1: @Test methods per B tranche, and the packages the harvester runs.
B_TESTS = {"B1": 2003, "B2": 1133, "B3": 853, "B4": 3521}


CATEGORY_C = os.path.join(ROOT, "conformance", "category-c")


def category_c_counts():
    """Per area and class of `conformance/category-c/<area>/<Class>.txt`: the tests, by what covers them.

    A test with any `process:` reference counts as process; else `rust:`, else `http:`; `n/a` and `gap` as written.
    tests/process_scenarios.rs (`category_c_inventories_cover_every_upstream_test`) checks the files are complete."""
    rows = []
    for path in sorted(glob.glob(os.path.join(CATEGORY_C, "*", "*.txt"))):
        area = os.path.basename(os.path.dirname(path))
        c = collections.Counter()
        with open(path) as f:
            for line in f:
                entry = line.split("#", 1)[0].split()
                if not entry:
                    continue
                refs = " ".join(entry[1:])
                kind = next((k for k in ("process", "rust", "http") if f"{k}:" in refs), refs)
                c[kind] += 1
        rows.append((area, os.path.basename(path)[:-4], c))
    return rows


INVENTORY = os.path.join(ROOT, "docs", "research", "mockserver-test-inventory.md")


def classified_classes():
    """Test classes a classification table of the inventory settles without a harvested file of their own (covered
    elsewhere, or category C): the second cell (the class) of each row whose third does not start with "harvested", between `<!-- coverage:classified -->` and
    `<!-- /coverage:classified -->` (a table per harvest kind family), and rows
    `| `<package>` | `<Class>` (<n>) | covered … |` or `| … | C … |` anywhere."""
    found, inside = set(), False
    if not os.path.exists(INVENTORY):
        return found
    with open(INVENTORY, encoding="utf-8") as f:
        for line in f:
            if "<!-- coverage:classified -->" in line:
                inside = True
            elif "<!-- /coverage:classified -->" in line:
                inside = False
            elif inside and line.startswith("|"):
                cells = [c.strip().strip("`") for c in line.strip().strip("|").split("|")]
                # a row saying "harvested" counts only through its harvested file
                if len(cells) > 2 and re.fullmatch(r"\w+Test", cells[1]) and not cells[2].startswith("harvested"):
                    found.add(cells[1])
            m = re.match(r"\|\s*`[\w/]+`\s*\|\s*`(\w+Test)`(?:\s*\(\d+\))?\s*\|\s*(covered|C)\b", line)
            if m:
                found.add(m.group(1))
    return found


def harvested_packages(files):
    """mockserver-core's test packages (the first segment under `org/mockserver`) that hold a harvested class, and the
    test classes of every package not harvested yet, read from the upstream submodule against the harvested stems.
    A class with a `conformance/category-c/<area>/<Class>.txt` is accounted for too: a package whose
    every class is harvested or listed there is not "not yet"."""
    tree = os.path.join(ROOT, "upstream", "mockserver", "mockserver", "mockserver-core", "src", "test", "java", "org",
                        "mockserver")
    if not os.path.isdir(tree):
        return [], []
    package_of = {}
    for path in glob.glob(os.path.join(tree, "**", "*Test.java"), recursive=True):
        package_of.setdefault(os.path.basename(path)[:-len(".java")], os.path.relpath(path, tree).split(os.sep)[0])
    stems = {stem for tranche in files.values() for stem in tranche}
    classes = set()
    for stem in stems:
        for part in stem.split("-")[1:]:
            if part in package_of:
                classes.add(part)
    harvested = sorted({package_of[c] for c in classes})
    classes |= {os.path.basename(p)[:-len(".txt")] for p in glob.glob(os.path.join(CATEGORY_C, "*", "*.txt"))}
    classified = classified_classes()
    remaining = collections.Counter(package_of[c] for c in package_of if c not in classes and c not in classified)
    unharvested = sorted(((p, n) for p, n in remaining.items() if p not in harvested or p == "matchers"),
                         key=lambda item: (-item[1], item[0]))
    return harvested, unharvested


def tranche_classes(name):
    path = os.path.join(UPSTREAM, "src", "test", "resources", "tranches", name + ".txt")
    classes = []
    for line in open(path, encoding="utf-8"):
        m = re.match(r"\s*([\w.]+)\s*#\s*(\d+)", line)
        if m:
            classes.append((m.group(1), int(m.group(2))))
    return classes


def a_counts(rows, suites):
    c = collections.Counter()
    for (suite, _, _), status in rows.items():
        if suite in suites:
            c[status] += 1
            c["total"] += 1
    return c


def rs_results():
    """rs-process results: the newest of a normal run and a -DrunSkipped=rs run (`rs-process-all`), whose failures
    count as skipped rs when a skips/rs entry lists them."""
    newest = lambda t: max((os.path.getmtime(p) for p in results.suite_reports(t)), default=0)  # noqa: E731
    if newest("rs-process-all") <= newest("rs-process"):
        return results.results("rs-process")
    listed = set()
    for path in glob.glob(os.path.join(UPSTREAM, "src", "test", "resources", "skips", "rs", "*.txt")):
        cls = os.path.basename(path)[:-len(".txt")]
        for line in open(path, encoding="utf-8"):
            if line.strip() and not line.startswith("#"):
                listed.add((cls, line.split("#")[0].strip()))
    rows = results.results("rs-process-all")
    for key, status in rows.items():
        cls = key[1].rsplit(".", 1)[-1]
        if status == "fail" and ((cls, key[2]) in listed or (cls, "*") in listed):
            rows[key] = "skip:rs"
    return rows


SCENARIO_RESULTS = os.path.join(ROOT, "target", "upstream-scenario-results.tsv")
SCENARIO_DIFFS = os.path.join(ROOT, "target", "upstream-scenario-diffs.txt")
DIVERGENCES = os.path.join(ROOT, "docs", "divergences.md")
DIVERGENCE_HEADER = "| Area | Oracle | mock-server | Why |"


UNREPRODUCIBLE = "unreproducible:"


def divergence_rows(path=DIVERGENCES):
    """(kind, row) for each row of docs/divergences.md's main table: an adopted post-8.0.0 fix (its "Why"
    cites the upstream fix or the adoption), a deliberate runtime difference (its "Why" begins `deliberate (`), an
    unreproducible one (its "Why" begins `unreproducible:`: no user who swaps the oracle's image for ours can observe
    it), or a to-do (every other row)."""
    lines = open(path, encoding="utf-8").read().split("\n")
    start = lines.index(DIVERGENCE_HEADER) + 2
    for line in lines[start:]:
        if not line.startswith("|"):
            break
        why = line.rstrip().rstrip("|").rsplit(" | ", 1)[1].strip()
        if why.startswith("deliberate ("):
            yield "deliberate", line
        elif why.startswith(("upstream fix ", "adopted by ")):
            yield "adopted", line
        elif why.startswith(UNREPRODUCIBLE):
            yield "unreproducible", line
        else:
            yield "todo", line


def divergence_counts(path=DIVERGENCES):
    return collections.Counter(kind for kind, _ in divergence_rows(path))


def unfiltered_scenario_replay():
    """The harvested-case tally and its diff file must both come from one unfiltered replay. Their first
    line is `# replay full <ts>`, or `# replay filtered <ts> MOCK_SERVER_SCENARIO=… files=<n> base=…` when a
    filtered replay merged its files' rows into them (tests/scenarios/README.md). Anything else is refused: a filtered
    tally once read as the whole of category B."""
    rerun = "run `cargo test --test oracle` with no MOCK_SERVER_SCENARIO first"
    firsts = []
    for path in (SCENARIO_RESULTS, SCENARIO_DIFFS):
        if not os.path.exists(path):
            return f"{os.path.relpath(path, ROOT)} is missing; {rerun}"
        with open(path, encoding="utf-8", errors="replace") as f:
            first = f.readline().rstrip("\n")
        if not first.startswith("# replay "):
            return f"{os.path.relpath(path, ROOT)} has no `# replay` provenance line (written before the tally carried provenance); {rerun}"
        if not first.startswith("# replay full "):
            return f"{os.path.relpath(path, ROOT)} comes from a filtered replay ({first[2:]}); {rerun}"
        firsts.append(first)
    if firsts[0] != firsts[1]:
        return f"the tally ({firsts[0][2:]}) and the diff file ({firsts[1][2:]}) come from different replays; {rerun}"
    return None


def main():
    refusal = unfiltered_scenario_replay()
    if refusal:
        sys.exit(f"coverage.py: refusing to write category B: {refusal}. "
                 "(If stdout was redirected to docs/coverage.md, restore it: `git checkout docs/coverage.md`.)")
    oracle = results.results("oracle-process")
    rs = rs_results()
    out = []
    w = out.append
    w("# Upstream test coverage")
    w("")
    w(f"Generated by `python3 conformance/coverage.py > docs/coverage.md` on {datetime.date.today().isoformat()}; "
      "numbers come from the last full run of each suite on each target. The goal is that mock-server "
      "passes every applicable MockServer 8.0.0 test; the tranches are those of the MockServer test inventory.")
    w("")
    w("## Category A: upstream's black-box classes, unmodified")
    w("")
    w("`make upstream-tests TARGET=oracle-process|rs-process [TEST=T2Test] [CLASSES=…]`. T1 runs upstream's abstract "
      "suites through `Remote*Test` subclasses; T2–T5 run mockserver-netty's own concrete classes, whose "
      "`new MockServer(…)`/`ClientAndServer` resolve to process-backed stand-ins. *Skipped in-JVM*: fails on "
      "oracle-process too (`skips/in-jvm/`). *Not applicable*: cannot run unmodified against mock-server; "
      "skipped on rs-process only and checked by the Rust port its `skips/not-applicable/` entry names (`tests/upstream/`). *Skipped rs*: a to-do entry giving the reason (`skips/rs/`). "
      "*Upstream @Ignore*: ignored in upstream's own sources.")
    w("")
    w("| Tranche | classes | executions | oracle-process passing | rs-process run | rs-process passing | rs failing | skipped in-JVM | not applicable (Rust port) | skipped rs | upstream @Ignore | not yet wired |")
    w("|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|")
    totals = collections.Counter()
    for t in ("T1", "T2", "T3", "T4", "T5"):
        suites = (T1_SUITES if t == "T1" else (t + "Test",)) + EXTRA_SUITES.get(t, ())
        classes = (3 if t == "T1" else len(tranche_classes(t))) + (len(tranche_classes("examples")) if t == "T5" else 0)
        o, r = a_counts(oracle, suites), a_counts(rs, suites)
        executions = max(o["total"], r["total"])
        rs_run = r["pass"] + r["fail"]
        not_wired = (EXAMPLES_TESTS if t == "T5" and not any(k[0] == "ExamplesTest" for k in rs) else 0)
        row = {
            "classes": classes, "executions": executions, "oracle": o["pass"], "run": rs_run, "pass": r["pass"],
            "fail": r["fail"], "jvm": o["skip:in-jvm"] or r["skip:in-jvm"], "na": r["skip:na"], "rs": r["skip:rs"],
            "ignore": r["skip:upstream"] or o["skip:upstream"], "nw": not_wired,
        }
        totals.update(row)
        rs_cell = lambda v: str(v) if r["total"] else "not run"  # noqa: E731
        w(f"| {t} | {classes} | {executions} | {o['pass'] if o['total'] else 'not run'} | {rs_cell(rs_run)} | "
          f"{rs_cell(r['pass'])} | {rs_cell(r['fail'])} | {row['jvm']} | {row['na']} | {rs_cell(r['skip:rs'])} | {row['ignore']} | {not_wired} |")
    w(f"| **total** | {totals['classes']} | {totals['executions']} | {totals['oracle']} | {totals['run']} | "
      f"{totals['pass']} | {totals['fail']} | {totals['jvm']} | {totals['na']} | {totals['rs']} | {totals['ignore']} | {totals['nw']} |")
    w("")
    w("*Not yet wired*: upstream tests no run has reached (examples/java counts here until its first rs-process run).")
    w("")
    w("### Container suites")
    w("")
    w("`make container-tests [CONTAINER_TARGET=oracle]` runs upstream's `container_integration_tests` cases unmodified "
      "(docker-compose, and helm on k3d) against an image tagged `mockserver/mockserver:integration_testing`; "
      "`make conformance` runs mockserver-testcontainers' `MockServerContainerIntegrationTest` on our image. "
      "*Not applicable*: tests MockServer's JVM packaging (`conformance/containers/not-applicable.txt`, each with its "
      "reason and counterpart). *Not run*: skipped by upstream's harness (an image it needs is absent) or not yet run.")
    w("")
    w("| Tranche | cases | oracle passing | rs run | rs passing | rs failing | not applicable | not run |")
    w("|---|--:|--:|--:|--:|--:|--:|--:|")
    rs_cases, oracle_cases = results.containers("rs"), results.containers("oracle")
    rs_cases["MockServerContainerIntegrationTest"] = ("testcontainers", results.testcontainers() or "not-run", "", "", "full")
    ctotal = collections.Counter()
    failing = []
    for t, cases in CONTAINER_TRANCHES.items():
        c = collections.Counter()
        for case in cases:
            status = rs_cases.get(case, ("", "not-run", ""))[1]
            c["cases"] += 1
            c["oracle"] += oracle_cases.get(case, ("", ""))[1] == "pass"
            c["run"] += status in ("pass", "fail")
            c["pass"] += status == "pass"
            c["fail"] += status == "fail"
            c["na"] += status == "skip:na"
            c["notrun"] += status in ("not-run", "skip:absent")
            if status == "fail":
                failing.append(case)
        ctotal.update(c)
        w(f"| {t} | {c['cases']} | {c['oracle'] if oracle_cases else 'not run'} | {c['run']} | {c['pass']} | {c['fail']} | {c['na']} | {c['notrun']} |")
    w(f"| **total** | {ctotal['cases']} | {ctotal['oracle'] if oracle_cases else 'not run'} | {ctotal['run']} | {ctotal['pass']} | "
      f"{ctotal['fail']} | {ctotal['na']} | {ctotal['notrun']} |")
    w("")
    counterparts = [case for case, row in rs_cases.items() if row[0] == "counterpart"]
    if counterparts:
        w("Counterpart cases of ours (`conformance/containers/cases/`): " + ", ".join(
            f"`{case}` {rs_cases[case][1]}" for case in counterparts) + ".")
        w("")
    for label, cases in (("rs", rs_cases), ("oracle", oracle_cases)):
        partial = sorted({row[3] or "undated" for row in cases.values() if row[4] == "partial" and row[1] in ("pass", "fail")})
        if partial:
            w(f"The {label} counts include results of narrowed runs (`CASES`/`CONTAINER_GROUPS`) from: {', '.join(partial)}.")
            w("")
    if failing:
        w("Failing: " + "; ".join(f"`{case}`" for case in failing) + ".")
        w("")
    w("## Category B: mockserver-core's unit tests, harvested")
    w("")
    w("`conformance/harvest` runs mockserver-core's tests with a recorder on the boundaries where a test hands a request or a document to the code under test; "
      "`harvest.py` turns each distinct call into a case in `tests/scenarios/upstream/`, recorded from the oracle "
      "(`make record`) and replayed by `cargo test --test oracle`. *Listed*: in `skips-rs.txt` with its reason. "
      "*Oracle-unstable*: answered differently by two oracle recordings, not compared.")
    w("")
    w("| Tranche | upstream @Test | classes harvested | cases | matching | listed (to do) | oracle-unstable |")
    w("|---|--:|--:|--:|--:|--:|--:|")
    cases = collections.defaultdict(collections.Counter)
    files = collections.defaultdict(set)
    if os.path.exists(SCENARIO_RESULTS):
        for row in list(csv.reader(open(SCENARIO_RESULTS, encoding="utf-8"), delimiter="\t"))[2:]:
            stem, _, result = row
            tranche = stem.split("-")[0]
            cases[tranche][result] += 1
            files[tranche].add(stem)
    for t, tests in B_TESTS.items():
        c = cases[t]
        w(f"| {t} | {tests} | {len(files[t])} | {sum(c.values())} | {c['pass']} | {c['skip-rs']} | {c['unstable']} |")
    w("")
    w("Harvested boundaries: control-plane deserialisers, JSON-schema validators, `HttpRequestPropertiesMatcher.matches`, "
      "the Jackson round-trips of the (de)serialiser tests, control-plane request sequences through `HttpState.handle` "
      "and `MockServerEventLog` verification (B1, B2, B4 kind `handle`); template engines and helpers, OpenAPI "
      "conversion, example generation, validation and runtime expressions, and the retrieve formats (code, curl, HAR) "
      "(B3); the body matchers, schema validators, the LLM provider codecs, action handler and conversation matcher, WASM rules, "
      "and the OIDC, SCIM and SAML providers (B4).")
    w("")
    harvested, unharvested = harvested_packages(files)
    if harvested:
        w("Packages with a harvested class: " + ", ".join(f"`{p}`" for p in harvested) + ". Not yet: "
          + ", ".join((f"the field matchers in `matchers`" if p == "matchers" else f"`{p}`")
                      + f" ({n} {'class' if n == 1 else 'classes'})" for p, n in unharvested) + ".")
    w("")
    w("## Divergences")
    w("")
    d = divergence_counts()
    w("Rows of `docs/divergences.md`'s main table. *To do*: a difference still to remove. *Adopted*: an "
      "upstream fix after 8.0.0 that mock-server adopted; the row goes when the oracle moves to the release that carries it. *Deliberate*: a "
      "difference the runtime causes. *Unreproducible*: no user can observe it (the oracle varies "
      "run to run and ours is one of its outcomes, or nothing can read it back); its \"Why\" begins `unreproducible:`.")
    w("")
    w("| rows | to do | adopted | deliberate | unreproducible |")
    w("|--:|--:|--:|--:|--:|")
    w(f"| {sum(d.values())} | {d['todo']} | {d['adopted']} | {d['deliberate']} | {d['unreproducible']} |")
    w("")
    w("## Known flakiness")
    w("")
    w("Under heavy concurrent load (builds or recordings next to a run), a server process occasionally misses the 60 s "
      "readiness probe (seen once each for oracle-process and rs-process); the class passes when rerun alone. Runs are "
      "made one at a time.")
    w("")
    w("The HTTP/3 classes that send a request body (`Http3McpIntegrationTest`, `Http3MockingMatrixIntegrationTest`) "
      "race in their own client, on the oracle as on mock-server: `requestStream.write(headers).sync()` is an "
      "unflushed write from the test thread, which Netty queues with `lazyExecute` "
      "(`AbstractChannelHandlerContext.java:832`, 4.2.17) without waking the event loop, so it waits for the next "
      "datagram or timer. When the server has sent its last packet before that, the next timer is the client's 30 s "
      "idle timeout: the test then fails after about 50 s (matrix) or 74 s (MCP) with no answer. Measured on Linux "
      "arm64 (2026-09-28) with that client: 10 of 300 requests stalled against the 8.0.0 jar, 9 of 300 against "
      "mock-server; unmodified `Http3McpIntegrationTest` failed this way on oracle-process too (1 run in 5). "
      "macOS does not show it. Not a server divergence; nothing in the server changes it without diverging on the "
      "wire.")
    w("")
    w("## Category C")
    w("")
    w("Not applicable (JVM-only behaviour), except CLI parsing and configuration plumbing, covered by process-level scenarios "
      "(`tests/process_scenarios/`). `conformance/category-c/<area>/<Class>.txt` names what covers each upstream test: "
      "*process* a process scenario (with the oracle's output), *Rust* only a Rust test, *n/a* nothing can (a JVM "
      "internal), *gap* a to-do.")
    w("")
    c_rows = category_c_counts()
    w("| area | class | tests | process | Rust | HTTP | n/a | gap |")
    w("|---|---|--:|--:|--:|--:|--:|--:|")
    for area, cls, c in c_rows:
        w(f"| {area} | `{cls}` | {sum(c.values())} | {c['process']} | {c['rust']} | {c['http']} | {c['n/a']} | {c['gap']} |")
    for area in sorted({a for a, _, _ in c_rows}):
        t = sum((c for a, _, c in c_rows if a == area), collections.Counter())
        w(f"| {area} | **total** | {sum(t.values())} | {t['process']} | {t['rust']} | {t['http']} | {t['n/a']} | {t['gap']} |")
    w("")
    import config_properties  # noqa: E402 (conformance/)
    total, exercised, reasoned, missing = config_properties.tally(quiet=True)
    w(f"Configuration plumbing (`conformance/config_properties.py`): of {total} `ConfigurationProperties` "
      f"properties, {exercised} are set by a process scenario (`tests/process_scenarios/`; the `config_tier_*` and "
      f"`config_values_*` scenarios compare `GET /mockserver/config` with the oracle's), {reasoned} are listed with a "
      f"reason in `tests/process_scenarios/config_properties.txt`, {missing} are neither.")
    print("\n".join(out))


if __name__ == "__main__":
    main()
