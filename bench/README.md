# Benchmarks

`bench/run.sh` puts the same HTTP load on mock-server and on the MockServer image `oracle.env` pins, and writes down
what it measured. `bench/startup.sh` times a container's start to its `started on port` line.

## Running it

Docker (cgroup v2, the default `json-file` log driver), bash, Python 3 and git; nothing else on the host. It runs on a
plain Ubuntu 24.04 VM, amd64 or arm64, and on a Docker VM on macOS for a smoke test. Run the real benchmark on a VM of
its own: on a shared machine, CPU time a request is the figure to trust, not requests a second.

```sh
make image                                               # ours, as mock-server:latest
RESULTS=site/public/benchmarks/results.json bench/run.sh # the full run: about an hour
```

A smoke test, to see it work end to end in a few minutes:

```sh
IMAGE=mock-server:latest WARMUP=3 DURATION=3 ROUNDS=1 LEVELS=INFO EXPECTATIONS=1 OURS_CONFIGS=default bench/run.sh
```

| Variable | Default | |
| --- | --- | --- |
| `IMAGE` | `mock-server:latest` | our image |
| `CPUS` | `2` | each server's `--cpus` |
| `MEMORY` | `2g` | each server's `--memory`: a Testcontainers host shares its memory with the tests, so neither server gets all of it; the JVM sizes its heap from this limit |
| `CONNECTIONS` | `64` | `oha -c` |
| `WARMUP` | `20` | seconds of the same load before the window; the JVM needs 10-20 s to reach its speed |
| `DURATION` | `15` | seconds of the measured window |
| `ROUNDS` | `3` | rounds; the servers' order alternates between them |
| `LEVELS` | `INFO WARN` | `MOCKSERVER_LOG_LEVEL` of both servers |
| `EXPECTATIONS` | `1 1000` | expectations created before the load |
| `REQUESTS` | `matched unmatched` | the request: the last expectation's path, or a path none matches |
| `SERVERS` | `oracle ours` | which servers to run |
| `OURS_CONFIGS` | `default;MOCKSERVER_MAX_LOG_ENTRIES=100000` | our configurations, `;`-separated; each `default` or `NAME=VALUE ...` |
| `ORACLE_CONFIGS` | `default` | MockServer's, the same way |
| `METRICS` | `false` | `MOCKSERVER_METRICS_ENABLED` of both servers |
| `SETTLE_MAX` | `60` | the longest wait, in seconds, for a console to stop growing |
| `ALLOC_IMAGE` | | an image built with `alloc-count`; adds the allocations a request |
| `MACHINE_KIND` | `Docker host` | how `results.json` names the machine: `cloud VM`, ... |
| `NOTE` | | a sentence `results.json` and the Benchmarks page carry |
| `RUN_DIR` | `bench/runs/<UTC time>` | where the readings go |
| `RESULTS` | | also copy `results.json` there, with the run directory packed beside it as `<name>-raw.tar.gz` |

## What one measurement is

For every round, log level, number of expectations and request, each server (in that round's order) and each of its
configurations:

1. A fresh container of the server, alone on the user-defined bridge network `mock-server-bench` with `--cpus $CPUS`
   and `--memory $MEMORY`, so memory and the event log start empty for every measurement.
2. The expectations, `GET /e<n>` answered with `e<n>`, created in one `PUT /mockserver/expectation`.
3. `WARMUP` seconds of the load, then a wait until the console stops growing (a server may still be printing the
   warm-up's requests).
4. The cgroup's `cpu.stat` `usage_usec`, then `DURATION` seconds of `oha` (in a container on the same network,
   pinned by digest) with `CONNECTIONS` connections, its JSON kept.
5. A wait until the console stops growing again, `usage_usec` again, the server's `VmHWM` (the largest of the
   cgroup's processes) and the cgroup's `memory.peak`, and the window's console lines counted. The container is
   removed.

Every request carries `Host: localhost:1080`. Both servers take that name as their own; a name they do not (the
container's name) makes an unmatched request a proxied one under `attemptToProxyIfNoMatchingExpectation`, which is on
by default: a DNS lookup, a connection to itself and a second pass, measured instead of the 404.

The readings come from a probe container (`mock-server-bench-probe`) in the Docker host's PID namespace with the host's
cgroup tree and container logs mounted read-only, so they are the same on a Linux host and under a Docker VM.

## What it writes

`$RUN_DIR` holds `meta.json` (the commit, the images' ids and digests, the machine: CPU model, vCPUs, memory, arch,
kernel, Docker, cgroup, log driver; the load average at the start, every parameter), `run.log` (the table it prints),
and in `raw/` each measurement's `<tag>.oha.json` and `<tag>.readings.json` (cgroup CPU before, at the window's end and
once settled; console line counts; VmHWM; memory.peak; the load average before the window).
[`results.py`](results.py) assembles `results.json` from those files alone, so it can be rebuilt
(`python3 bench/results.py <run dir>`):

- `req_per_sec`: `oha`'s requests a second over the window.
- `cpu_us_per_req`: the cgroup's CPU time from the window's start until the console settled after it (the logging a
  server defers is included), over the requests `oha` completed. `cpu_us_per_req_window` in each round stops at the
  window's end instead.
- `p50_ms`, `p99_ms`, `p999_ms`: `oha`'s latency percentiles.
- `rss_mib`: VmHWM, the peak resident memory since the container started. `memory_peak_mib`: the cgroup's
  `memory.peak`.
- `console_lines`: lines the server printed during the window.
- `unlogged_requests` (at `INFO`): requests completed in the window minus its `received request` lines. MockServer
  records its event log on one thread behind a ring buffer and drops entries when it is full (`Log event ring buffer
  full — dropping`, printed once; `drop_warnings` counts those warnings): those requests are neither printed nor kept
  for verification. Requests still in flight when the window ends are logged but not completed, so a server that
  drops nothing shows zero.
- `allocs_per_req`, `reallocs_per_req`, `alloc_bytes_per_req`: see below.

Each row is the median over its rounds; `rounds` keeps every round's figures and the files they came from.

## Allocations a request

The `alloc-count` Cargo feature (`src/alloc_count.rs`) wraps the binary's allocator in a counter and prints the counts
on `SIGUSR1`. No published image enables it, and a build without it compiles none of it. With `ALLOC_IMAGE` set, the
script runs one more measurement per case of ours with that image, signals it before and after the window and divides
the difference by the requests. The counters are shared atomics, so that image's own throughput is not ours: only its
counts go into `results.json`.

```sh
docker build --build-arg CARGO_FEATURES=alloc-count -t mock-server:alloc-count .
ALLOC_IMAGE=mock-server:alloc-count RESULTS=site/public/benchmarks/results.json bench/run.sh
```

The image profile's fat LTO needs several GiB to link; a Docker VM with too little memory kills the link. The counts
do not depend on it, so such a machine can build the counting image from a copy of the `Dockerfile` with
`ENV CARGO_PROFILE_IMAGE_LTO=thin` before the `cargo auditable build` step.

## Publishing a run

The Benchmarks page of the site is generated from `site/public/benchmarks/results.json`, and links the
`results-raw.tar.gz` beside it (`site/README.md`, "The Benchmarks page"). Run with
`RESULTS=site/public/benchmarks/results.json`, commit both files, and build the site.
