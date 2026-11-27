# Benchmarks

`bench/run.sh` puts the same HTTP load on mock-server and on the MockServer image `oracle.env` pins, and writes down
what it measured. `bench/startup.sh` times a container's start to its `started on port` line.

## Running it

Docker (cgroup v2, the default `json-file` log driver), bash, Python 3 and git; nothing else on the host. It runs on a
plain Ubuntu 24.04 VM, amd64 or arm64, and on a Docker VM on macOS for a smoke test. Run the real benchmark on a VM of
its own: on a shared machine, CPU time a request is the figure to trust, not requests a second.

```sh
make image                                               # ours, as mock-server:latest
RESULTS=site/public/benchmarks/results.json bench/run.sh # the full run: about three hours
```

A smoke test, to see it work end to end in a few minutes:

```sh
IMAGE=mock-server:latest WARMUP=3 DURATION=3 ROUNDS=1 LEVELS=INFO EXPECTATIONS=1 OURS_CONFIGS=default \
  CONTROL_WARMUP=500 CONTROL_CALLS=500 bench/run.sh
```

| Variable | Default | |
| --- | --- | --- |
| `IMAGE` | `mock-server:latest` | our image |
| `CPUS` | `2` | each server's `--cpus` |
| `MEMORY` | `1g` | each server's `--memory`: a Testcontainers host shares its memory with the tests, so neither server gets all of it; the JVM sizes its heap from this limit |
| `CONNECTIONS` | `64` | `oha -c` |
| `WARMUP` | `20` | seconds of the same load before the window; the JVM needs 10-20 s to reach its speed |
| `DURATION` | `15` | seconds of the measured window |
| `ROUNDS` | `3` | rounds; the servers' order alternates between them |
| `LEVELS` | `INFO WARN` | `MOCKSERVER_LOG_LEVEL` of both servers |
| `EXPECTATIONS` | `1 1000` | expectations created before the load |
| `REQUESTS` | `matched unmatched json headers verify retrieve` | the rows: see [The rows](#the-rows) |
| `FILL` | `10000` | `verify`, `retrieve`: orders sent to fill the event log, before the warm-up and again before the window |
| `CONTROL_WARMUP` | `5000` | `verify`, `retrieve`: calls of the warm-up |
| `CONTROL_CALLS` | `5000` | `verify`, `retrieve`: calls of the window |
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

## The rows

Each row is one kind of request, among `EXPECTATIONS` expectations of its kind; the request matches the last one
created, so a server that tries expectations in order tries them all. Together they cover what an integration test
does with a mock: answer its calls, match what it posts, and tell it afterwards what it received.

| `REQUESTS` | The request | What it models |
| --- | --- | --- |
| `matched` | `GET /e<n-1>`; expectations `GET /e<i>` answered `e<i>` | the floor: the cheapest call a server answers, mostly the kernel's and HTTP's cost |
| `unmatched` | `GET /none`, answered 404 | a call the test did not expect: the server logs it with its closest expectation |
| `json` | `POST /orders` with a ~4 KiB JSON order whose `order.id` is `e<n-1>`; expectations `POST /orders` with a JSON body matcher `{"order":{"id":"e<i>"}}`, `ONLY_MATCHING_FIELDS`, answered 201 | a service posting a document, told apart from the others by one field of it, as `json(..., ONLY_MATCHING_FIELDS)` expectations do; at 1,000 every request is compared with every expectation's JSON |
| `headers` | `GET /e<n-1>`; each expectation answered 200 with 8 headers (`Content-Type`, `Cache-Control`, `ETag`, request and correlation ids, rate-limit headers, `Vary`) and a ~2 KiB JSON body | a realistic response a client parses: the cost of writing headers and a JSON body instead of two bytes |
| `verify` | `PUT /mockserver/verify`: `POST /orders/00000` at least 3 times | a test's check at its end that a call was made, against an event log a data-plane load filled: every call searches the log |
| `retrieve` | `PUT /mockserver/retrieve?type=REQUESTS` for `POST /orders/00000`: 3 requests of ~4 KiB back | a test reading back what it sent, against the same log |

`verify` and `retrieve` add expectation `POST /orders/[0-9]+`, answered 201, after their `EXPECTATIONS`. Before their
warm-up, and again before their window, `oha` sends `FILL` orders (the `json` row's body) to random paths
`/orders/<4 digits>` and then 3 to `/orders/00000`: more than either server keeps under 1 GiB (both bound the log by
`maxEventLogSizeInBytes` as well as `maxLogEntries`), so each window starts from a full log of orders with the three
the matcher selects among the newest. At `INFO` every verify or retrieve call adds an entry to the log, which pushes
the oldest orders out; a run for a time would leave a fast server searching its own verification records instead of
orders, and in the end losing the three it looks for. So these rows run `CONTROL_WARMUP` and `CONTROL_CALLS` calls,
the same work for both servers, and `retained_fill_requests` records how many orders were still in the log after the
window. Their `req_per_sec` is over a window as long as the server needs for those calls.

A verify that fails is a different and far heavier call (both servers list the log's requests in the failure), so
the matcher's three requests are always there: every `verify` call is answered 202 and every `retrieve` 200.

## What one measurement is

For every round, log level, number of expectations and request, each server (in that round's order) and each of its
configurations:

1. A fresh container of the server, alone on the user-defined bridge network `mock-server-bench` with `--cpus $CPUS`
   and `--memory $MEMORY`, so memory and the event log start empty for every measurement.
2. The row's expectations, created in one `PUT /mockserver/expectation`.
3. `WARMUP` seconds of the load (`verify`, `retrieve`: a fill, `CONTROL_WARMUP` calls and a second fill), then a
   wait until the console stops growing (a server may still be printing the warm-up's requests).
4. The cgroup's `cpu.stat` `usage_usec`, then `DURATION` seconds (`verify`, `retrieve`: `CONTROL_CALLS` calls) of
   `oha` (in a container on the same network, pinned by digest) with `CONNECTIONS` connections, its JSON kept.
5. At the window's end, the server's `VmRSS` and the cgroup's `memory.current`: the steady state.
6. A wait until the console stops growing again, `usage_usec` again, the server's `VmHWM` (the largest of the
   cgroup's processes) and the cgroup's `memory.peak`, and the window's console lines counted. The container is
   removed.

Every request carries `Host: localhost:1080`. Both servers take that name as their own; a name they do not (the
container's name) makes an unmatched request a proxied one under `attemptToProxyIfNoMatchingExpectation`, which is on
by default: a DNS lookup, a connection to itself and a second pass, measured instead of the 404.

The readings come from a probe container (`mock-server-bench-probe`) in the Docker host's PID namespace with the host's
cgroup tree and container logs mounted read-only, so they are the same on a Linux host and under a Docker VM.

## What it writes

Every row runs under the same `--cpus` and `--memory`; each row of `results.json` carries them (`cpus`,
`memory_limit`), as `meta.params` does.

`$RUN_DIR` holds `meta.json` (the commit, the images' ids and digests, the machine: CPU model, vCPUs, memory, arch,
kernel, Docker, cgroup, log driver; the load average at the start, every parameter), `run.log` (the table it prints),
and in `raw/` each measurement's `<tag>.oha.json`, `<tag>.warmup.oha.json` (and the fills') and `<tag>.readings.json`
(cgroup CPU before, at the window's end and once settled; console line counts; VmHWM, memory.peak, VmRSS and
memory.current; the load average before the window).
[`results.py`](results.py) assembles `results.json` from those files alone, so it can be rebuilt
(`python3 bench/results.py <run dir>`):

- `req_per_sec`: `oha`'s requests a second over the window.
- `cpu_us_per_req`: the cgroup's CPU time from the window's start until the console settled after it (the logging a
  server defers is included), over the requests `oha` completed. `cpu_us_per_req_window` in each round stops at the
  window's end instead.
- `p50_ms`, `p99_ms`, `p999_ms`: `oha`'s latency percentiles.
- `rss_mib`: VmHWM, the peak resident memory since the container started. `memory_peak_mib`: the cgroup's
  `memory.peak`.
- `rss_window_end_mib`: VmRSS at the window's end, the steady state with the event log as full as the load left it
  (after 15 s of load every row's log is at its bound). A peak can be a moment; what a test host must keep free for
  a server through a suite is its plateau. `memory_current_window_end_mib`: the cgroup's `memory.current` then.
- `status_codes` (per round), `warmup_status_codes` and, for `verify` and `retrieve`, each fill's: what the server
  answered, to compare between the servers.
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
