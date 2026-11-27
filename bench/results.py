#!/usr/bin/env python3
"""bench/run.sh's results.json, assembled from what the run directory holds: meta.json and every measurement's
raw/<tag>.readings.json and raw/<tag>.oha.json. Nothing else goes in, so the file can be rebuilt from the directory.

    python3 bench/results.py <run directory>

A row is one case (server, configuration, log level, expectations, request): its figures are the median
over the rounds, and `rounds` keeps every round's own. The allocation pass (ALLOC_IMAGE), when there was one, adds its
per-request allocator calls to the row of ours it measured.
"""
import glob
import json
import os
import statistics
import sys

SCHEMA = 2


def median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def rounded(x, digits):
    return None if x is None else round(x, digits)


def per_request(a, b, key, requests):
    if not a or not b or not requests:
        return None
    return (b[key] - a[key]) / requests


def kib_mib(x):
    return None if x is None else rounded(x / 1024, 1)


def bytes_mib(x):
    return None if x is None else rounded(x / 2**20, 1)


def measurement(run, readings):
    oha = json.load(open(os.path.join(run, readings["oha"])))
    codes = oha.get("statusCodeDistribution") or {}
    requests = sum(codes.values())
    cpu = readings["cpu_usage_usec"]
    p = oha["latencyPercentiles"]
    console = readings["console"]
    lines = console["lines_after"] - console["lines_before"]
    out = {
        "round": readings["round"],
        "readings": os.path.relpath(readings["_path"], run),
        "oha": readings["oha"],
        "req_per_sec": rounded(oha["summary"]["requestsPerSec"], 1),
        "requests": requests,
        "status_codes": codes,
        "errors": oha.get("errorDistribution") or {},
        # the server's CPU from the window's start until its console settled (the logging it deferred included)
        "cpu_us_per_req": rounded((cpu["settled"] - cpu["before"]) / requests, 2) if requests else None,
        "cpu_us_per_req_window": rounded((cpu["window_end"] - cpu["before"]) / requests, 2) if requests else None,
        "p50_ms": rounded(p["p50"] * 1000, 3) if p.get("p50") is not None else None,
        "p99_ms": rounded(p["p99"] * 1000, 3) if p.get("p99") is not None else None,
        "p999_ms": rounded(p["p99.9"] * 1000, 3) if p.get("p99.9") is not None else None,
        "rss_mib": rounded(readings["vmhwm_kib"] / 1024, 1) if readings["vmhwm_kib"] is not None else None,
        "memory_peak_mib": rounded(readings["memory_peak_bytes"] / 2**20, 1) if readings["memory_peak_bytes"] is not None else None,
        "rss_window_end_mib": kib_mib(readings.get("vmrss_window_end_kib")),
        "memory_current_window_end_mib": bytes_mib(readings.get("memory_current_window_end_bytes")),
        "retained_fill_requests": readings.get("retained_fill_requests"),
        "warmup_status_codes": (readings.get("warmup") or {}).get("status_codes"),
        "fills": readings.get("fills") or [],
        "console_lines": lines,
        "received_request_lines": console["received_request_lines"],
        "console_settled": console["settled_before"] and console["settled_after"],
        "drop_warnings": console["ring_full_warnings"] + console["in_flight_budget_warnings"],
        "load_average_before": readings["load_average_before"],
    }
    # Requests the window answered that no `received request` line logs: at INFO, the event log entries lost.
    out["unlogged_requests"] = max(0, requests - console["received_request_lines"]) if readings["log_level"] == "INFO" else None
    a, b = readings.get("alloc_before"), readings.get("alloc_after")
    out["allocs_per_req"] = rounded(per_request(a, b, "allocs", requests), 2)
    out["reallocs_per_req"] = rounded(per_request(a, b, "reallocs", requests), 2)
    out["alloc_bytes_per_req"] = rounded(per_request(a, b, "bytes", requests), 0)
    return out


MEDIANS = ["req_per_sec", "cpu_us_per_req", "p50_ms", "p99_ms", "p999_ms", "rss_mib", "memory_peak_mib",
           "rss_window_end_mib", "memory_current_window_end_mib", "retained_fill_requests",
           "console_lines", "received_request_lines", "unlogged_requests", "requests"]


def assemble(run):
    meta = json.load(open(os.path.join(run, "meta.json")))
    measured, allocs = {}, {}
    for path in sorted(glob.glob(os.path.join(run, "raw", "*.readings.json"))):
        readings = json.load(open(path))
        readings["_path"] = path
        key = (readings["server"], readings["config"], readings["log_level"], readings["expectations"], readings["request"])
        (allocs if readings["alloc_count"] else measured).setdefault(key, []).append(measurement(run, readings))
    rows = []
    for key, rounds in measured.items():
        server, config, level, n, request = key
        rounds.sort(key=lambda r: r["round"])
        row = {"server": server, "config": config, "expectations": n, "request": request, "log_level": level,
               "cpus": meta["params"]["cpus"], "memory_limit": meta["params"].get("memory_limit")}
        for field in MEDIANS:
            m = median([r[field] for r in rounds])
            row[field] = None if m is None else round(m, 3)
        row["drop_warnings"] = max(r["drop_warnings"] for r in rounds)
        row["console_settled"] = all(r["console_settled"] for r in rounds)
        alloc = allocs.get(key)
        for field in ("allocs_per_req", "reallocs_per_req", "alloc_bytes_per_req"):
            m = median([r[field] for r in alloc]) if alloc else None
            row[field] = None if m is None else round(m, 2)
        row["rounds"] = rounds
        if alloc:
            row["alloc_rounds"] = alloc
        rows.append(row)
    meta["date"] = meta["started"][:10]
    meta["raw"] = None
    meta["metrics"] = {
        "req_per_sec": "oha's requests a second over the window",
        "cpu_us_per_req": "the container cgroup's cpu.stat usage_usec from the window's start until its console stopped growing, divided by the requests oha completed",
        "latency": "oha's p50, p99 and p99.9 over the window",
        "rss_mib": "VmHWM, the server process's peak resident memory since its container started, read after the window",
        "memory_peak_mib": "the container cgroup's memory.peak, read after the window",
        "rss_window_end_mib": "VmRSS, the server process's resident memory at the window's end: the steady state, with the event log as full as the load left it",
        "memory_current_window_end_mib": "the container cgroup's memory.current at the window's end",
        "retained_fill_requests": "verify and retrieve: the fill's requests the event log still held after the window",
        "load": "verify and retrieve run a number of calls (control_warmup_calls, control_calls) after filling the event log with `fill` orders; the other rows run for warmup_s and duration_s",
        "console_lines": "lines the server wrote to its console during the window (Docker json-file log)",
        "unlogged_requests": "at INFO, requests completed in the window minus the window's `received request` console lines: MockServer drops event log entries when its ring buffer is full",
        "allocs_per_req": "allocator calls (alloc and alloc_zeroed) per request, from the alloc-count build of ours",
        "median": "each row's figures are the median over its rounds; `rounds` holds every round's",
    }
    return {"schema": SCHEMA, "meta": meta, "rows": rows}


def main():
    run = sys.argv[1]
    results = assemble(run)
    with open(os.path.join(run, "results.json"), "w") as f:
        json.dump(results, f, indent=1, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    main()
