#!/usr/bin/env python3
"""Per-test results of conformance/upstream runs, for comparing targets and for docs/coverage.md.

  results.py list TARGET              one line per test: suite, class, method, status (pass/fail/skip:<kind>)
  results.py diff TARGET_A TARGET_B   tests whose status differs between two targets
  results.py tally TARGET             counts per suite: run, passing, failing, skipped in-jvm, skipped rs
  results.py prune TARGET [LIST]      removes entries of skips/LIST (default rs) that passed in TARGET's reports
                                      (a -DrunSkipped=LIST run; in-jvm entries are pruned from an oracle-process run)
  results.py ports                    checks that every skips/not-applicable entry names an existing Rust port
  results.py containers TARGET        upstream's container cases (conformance/containers, TARGET rs|oracle) and
                                      MockServerContainerIntegrationTest (conformance/java): case, group, status,
                                      detail, when it ran, and whether that run was full or partial

Reads target/surefire-reports/<TARGET>/TEST-conformance.upstream.*.xml; the suite is the surefire test set (a
Remote*Test for T1, T2Test..T5Test for the tranches, ExamplesTest). Any other TEST-*.xml there is a stray report of a
single upstream class run with -Dtest=<Class> (`make upstream-tests TEST=<Class>`) and is ignored, so such a rerun never
adds a suite to the full-run tallies.
"""
import glob
import os
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
SUITE_PREFIX = "TEST-conformance.upstream."


def suite_reports(target):
    """The suite reports of TARGET, sorted; a -Dtest=<Class> run's TEST-<fqcn>.xml is not one."""
    return sorted(glob.glob(os.path.join(HERE, "target", "surefire-reports", target, SUITE_PREFIX + "*.xml")))


def results(target):
    rows = {}
    for path in suite_reports(target):
        suite = os.path.basename(path)[len(SUITE_PREFIX):-len(".xml")]
        for case in ET.parse(path).getroot().iter("testcase"):
            status = "pass"
            skipped = case.find("skipped")
            if skipped is not None:
                message = skipped.get("message", "")
                status = ("skip:in-jvm" if message.startswith("in-JVM") else "skip:na" if message.startswith("not-applicable")
                          else "skip:rs" if message.startswith("mock-server") else "skip:upstream")
            elif case.find("failure") is not None or case.find("error") is not None:
                status = "fail"
            rows[(suite, case.get("classname"), case.get("name"))] = status
    return rows


REPO = os.path.dirname(os.path.dirname(HERE))


def not_applicable():
    """(class, method, port) for every skips/not-applicable entry; port is `tests/upstream/<file>.rs::<fn>`."""
    out = []
    for path in sorted(glob.glob(os.path.join(HERE, "src", "test", "resources", "skips", "not-applicable", "*.txt"))):
        cls = os.path.basename(path)[:-len(".txt")]
        for line in open(path, encoding="utf-8"):
            if line.strip() and not line.startswith("#"):
                method, _, reason = line.partition("#")
                port = reason.split()[0] if reason.split() else ""
                out.append((cls, method.strip(), port))
    return out


def check_ports():
    """Entries whose port is not `tests/upstream/<file>.rs::<fn>` with such a function in that file."""
    bad = []
    for cls, method, port in not_applicable():
        file, _, fn = port.partition("::")
        path = os.path.join(REPO, file)
        if not (file.startswith("tests/upstream/") and fn and os.path.isfile(path)):
            bad.append((f"{cls}#{method}", f"no port file: {port or '(none)'}"))
        elif f"fn {fn}(" not in open(path, encoding="utf-8").read():
            bad.append((f"{cls}#{method}", f"no fn {fn} in {file}"))
    return bad


CONTAINER_RESULTS = os.path.join(REPO, "conformance", "containers", "target")
TESTCONTAINERS_REPORT = os.path.join(REPO, "conformance", "java", "target", "surefire-reports",
                                     "TEST-org.mockserver.testcontainers.MockServerContainerIntegrationTest.xml")


def containers(target):
    """{case: (group, status, detail, ran_at, scope)} of conformance/containers/run.sh's results on TARGET (rs|oracle):
    status pass | fail | skip:na | skip:absent | not-run; scope full or partial (a narrowed run, see
    conformance/containers/results.py). Empty when it has not run."""
    rows = {}
    path = os.path.join(CONTAINER_RESULTS, f"results-{target}.tsv")
    if os.path.exists(path):
        for line in open(path, encoding="utf-8").read().splitlines()[1:]:
            case, group, status, detail, ran_at, scope = (line.split("\t") + [""] * 5)[:6]
            rows[case] = (group, status, detail, ran_at, scope or "partial")
    return rows


def testcontainers():
    """MockServerContainerIntegrationTest's status on our image (`make conformance`), or None when it has not run."""
    if not os.path.exists(TESTCONTAINERS_REPORT):
        return None
    for case in ET.parse(TESTCONTAINERS_REPORT).getroot().iter("testcase"):
        if case.find("skipped") is not None:
            return "skip:upstream"
        return "fail" if case.find("failure") is not None or case.find("error") is not None else "pass"
    return None


def main(argv):
    if len(argv) >= 2 and argv[0] == "list":
        for (suite, cls, method), status in sorted(results(argv[1]).items()):
            print(f"{suite}\t{cls}\t{method}\t{status}")
    elif len(argv) >= 3 and argv[0] == "diff":
        a, b = results(argv[1]), results(argv[2])
        for key in sorted(set(a) | set(b)):
            if a.get(key) != b.get(key):
                print(f"{key[1]}#{key[2]}\t{argv[1]}={a.get(key, '-')}\t{argv[2]}={b.get(key, '-')}")
    elif len(argv) >= 2 and argv[0] == "tally":
        counts = {}
        for (suite, _, _), status in results(argv[1]).items():
            c = counts.setdefault(suite, {"run": 0, "pass": 0, "fail": 0, "skip:in-jvm": 0, "skip:na": 0, "skip:rs": 0, "skip:upstream": 0})
            c[status] += 1
            if not status.startswith("skip"):
                c["run"] += 1
        print("suite\trun\tpass\tfail\tskip in-jvm\tnot applicable\tskip rs\tskip upstream @Ignore")
        for suite, c in sorted(counts.items()):
            print(f"{suite}\t{c['run']}\t{c['pass']}\t{c['fail']}\t{c['skip:in-jvm']}\t{c['skip:na']}\t{c['skip:rs']}\t{c['skip:upstream']}")
    elif len(argv) >= 2 and argv[0] == "prune":
        passed = {(cls.rsplit(".", 1)[-1], method) for (_, cls, method), status in results(argv[1]).items() if status == "pass"}
        kind = argv[2] if len(argv) >= 3 else "rs"
        removed = 0
        for path in sorted(glob.glob(os.path.join(HERE, "src", "test", "resources", "skips", kind, "*.txt"))):
            cls = os.path.basename(path)[:-len(".txt")]
            lines = open(path, encoding="utf-8").read().splitlines(keepends=True)
            kept = [l for l in lines if l.startswith("#") or not l.strip() or (cls, l.split("#")[0].strip()) not in passed]
            removed += len(lines) - len(kept)
            if len(kept) != len(lines):
                if all(l.startswith("#") or not l.strip() for l in kept):
                    os.remove(path)
                else:
                    open(path, "w", encoding="utf-8").writelines(kept)
        print(f"removed {removed} entries")
    elif argv and argv[0] == "ports":
        missing = [f"{entry}\t{why}" for entry, why in check_ports()]
        print("\n".join(missing) if missing else "every not-applicable entry names an existing port")
        return 1 if missing else 0
    elif len(argv) >= 2 and argv[0] == "containers":
        for case, (group, status, detail, ran_at, scope) in containers(argv[1]).items():
            print(f"{case}\t{group}\t{status}\t{detail}\t{ran_at}\t{scope}")
        if argv[1] == "rs":
            print(f"MockServerContainerIntegrationTest\ttestcontainers\t{testcontainers() or 'not-run'}\t\t\t")
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
