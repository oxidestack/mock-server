#!/usr/bin/env python3
"""Per-case results of a run.sh run, from upstream's result logs (logTestResult & co.):

  results.py MANIFEST NOT_APPLICABLE PREVIOUS PASS_LOG FAIL_LOG WARN_LOG SKIP_LOG [COUNTERPART_CASE...]  > results.tsv

One row per case of upstream's expected_tests.manifest, then one per counterpart case of ours, with the columns
case, group, status (pass | fail | skip:na | skip:absent | not-run), detail, ran_at (when the run that produced the
status finished, UTC) and scope: `full` (a run of every group and case) or `partial` (narrowed by CASES or
CONTAINER_GROUPS). A case this run did not reach keeps its row from PREVIOUS, with that row's own ran_at and scope, so
narrowed runs add up and a tally can tell which rows came from which kind of run. The file is written only when a run
finishes, so an interrupted run leaves the previous file as it was.

Environment: RESULTS_SUFFIX, the suffix run.sh gave the compose cases' copies (`<case>__<suffix>`), stripped here;
RESULTS_FULL_RUN=true|false.
"""
import datetime
import os
import re
import sys

ANSI = re.compile(r"\x1b\[[0-9;]*m")
ENTRY = re.compile(r"^\s*- ([A-Za-z0-9_-]+)(.*)$")
COLUMNS = ["case", "group", "status", "detail", "ran_at", "scope"]


def logged(path, suffix):
    out = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        m = ENTRY.match(ANSI.sub("", line))
        if m:
            case = m.group(1)
            if suffix and case.endswith("__" + suffix):
                case = case[:-len("__" + suffix)]
            out[case] = m.group(2).lstrip(": ").strip()
    return out


def read(path):
    """{case: row dict} of a results file; rows of the older four-column format count as partial and undated."""
    rows = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8").read().splitlines()[1:]:
            parts = (line.split("\t") + [""] * len(COLUMNS))[:len(COLUMNS)]
            row = dict(zip(COLUMNS, parts))
            row["scope"] = row["scope"] or "partial"
            rows[row["case"]] = row
    return rows


def main(argv):
    manifest, not_applicable, previous_path, pass_log, fail_log, warn_log, skip_log = argv[:7]
    counterparts = argv[7:]
    suffix = os.environ.get("RESULTS_SUFFIX", "")
    scope = "full" if os.environ.get("RESULTS_FULL_RUN") == "true" else "partial"
    ran_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    previous = read(previous_path)
    status = {}
    for path, kind in ((pass_log, "pass"), (warn_log, "fail"), (fail_log, "fail"), (skip_log, "skip:absent")):
        for case, detail in logged(path, suffix).items():
            if status.get(case, ("",))[0] != "fail":  # a failure anywhere wins
                status[case] = (kind, detail)
    reasons = {}
    for line in open(not_applicable, encoding="utf-8"):
        if line.strip() and not line.startswith("#"):
            case, _, why = line.rstrip("\n").partition("\t")
            reasons[case.strip()] = why.strip()

    def row(case, group):
        if case in status:
            return [case, group, *status[case], ran_at, scope]
        if case in reasons:
            return [case, group, "skip:na", reasons[case], ran_at, scope]
        if case in previous and previous[case]["status"] != "skip:na":
            p = previous[case]
            return [case, group, p["status"], p["detail"], p["ran_at"], p["scope"]]
        return [case, group, "not-run", "", ran_at, scope]

    print("\t".join(COLUMNS))
    for line in open(manifest, encoding="utf-8"):
        parts = line.split()
        if len(parts) == 2 and not parts[0].startswith("#"):
            print("\t".join(row(parts[1], parts[0])))
    for case in counterparts:
        print("\t".join(row(case, "counterpart")))


if __name__ == "__main__":
    main(sys.argv[1:])
