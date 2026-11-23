# Benchmarks

> **A log of earlier measurements.** Today's harness and what it records are in
> [`bench/README.md`](../bench/README.md), and its newest published run is the site's Benchmarks page. The sections
> below were measured with earlier versions of `bench/run.sh`, which sent `Host: <container name>` (so every
> unmatched row of both servers measured a proxied request to the server itself, not the 404), warmed MockServer up
> for 3-5 s (its JIT needs 10-20 s), reused one container per server across rows and kept no raw output. Compare
> their figures with each other, not with a run of the current script.

The first measurement, with an early `bench/run.sh`: both images on one Docker network, each limited to **2 CPUs**, load from `oha` in a
container (64 connections, 15 s, after a warm-up — 5 s for the JVM). Expectations are `GET /e<n>` → `e<n>`; the
request targets the last one created. Host: Apple Silicon, a Linux VM (8 vCPU, 24 GiB). Both servers in their default
configuration: MockServer logs every request at `INFO`; mock-server keeps a 100 000-entry request log and does
not print requests. Run on 2026-09-25 on the first measured tree.

> **These Mac rows predate the 9.x event-log work** (per-request event-log entries) and were not re-measured on later
> code. The same recipe on an amd64 VM runs that first tree at 72 500-77 600 req/s and a later one at 5 600-6 100 req/s
> under `--cpus 2`. Read the rows below as the old code's figures, not the current image's; the sections from "The
> console on `tracing`" on are the current ones.

| scenario | req/s | p50 ms | p99 ms | p99.9 ms | RSS after |
|---|---|---|---|---|---|
| MockServer 8.0.0, 1 expectation | 22 342 | 0.66 | 59.76 | 92.90 | 4.17 GiB |
| mock-server, 1 expectation | 96 502 | 0.62 | 1.45 | 2.86 | 177 MiB |
| MockServer 8.0.0, 1 000 expectations | 27 962 | 0.56 | 46.03 | 111.76 | 7.77 GiB |
| mock-server, 1 000 expectations | 72 683 | 0.67 | 4.51 | 10.21 | 181 MiB |

Other measurements:

| | MockServer 8.0.0 | mock-server |
|---|---|---|
| Image size | ≈ 411 MB | 17 MB |
| `docker run` → first `PUT /mockserver/status` 200 | 566–855 ms (upstream figures) | ≈ 250 ms (incl. `docker run`) |
| RSS idle | 392 MiB | 0.8 MiB |
| Java conformance suite, 22 tests incl. container start | 2.5–2.7 s | 1.2 s |

Throughput numbers move ±30 % run to run on this laptop (MockServer's 1-expectation figure was 32 025 req/s in an
earlier run); the p99 and memory gaps are stable. The JVM's RSS reflects its heap sizing (`MaxRAMPercentage=75`), not
necessarily live data.

### Unmatched requests with 1,000 expectations

Server CPU time per request (`ps` cputime delta over 4,000 keep-alive `GET /none`, 4 client threads), release
binary run natively, 1,000 `GET /e<n>` expectations, default configuration (closest-match hint on). CPU time rather
than req/s because the machine was shared (load average 60-106 during the runs). Each unmatched request scans every
expectation for the closest match twice, as upstream does: once for the `closest expectation` log entry (INFO only)
and once for the `x-mockserver-closest-match-hint` header. The hint now reuses the log's scan when it would be the
same evaluation, and an expectation that fails at the method or path is counted as one difference without
building it once the closest has at most one.

| | before | after |
|---|---|---|
| unmatched, INFO | 625-717 µs | 272 µs |
| unmatched, WARN | 332-368 µs | 212-215 µs |
| matched last (`/e999`), INFO, for scale | 60 µs | 73 µs |

What is left per scan (~140 µs) is the data-plane match of each expectation (`RequestMatcher::matches`) and cloning
and dropping the 1,000 candidate `Arc`s (contended refcounts under concurrent requests).

### Unmatched requests, concurrent clients

The same harness as the previous section (server CPU per request, release binary run natively, 1,000 `GET /e<n>`
expectations, 4,000 keep-alive `GET /none` after 2,000 for warm-up), with `ab -k -c 16`. Load average 155-194
during the runs, so the figures are indicative; each row is two alternating runs. Each unmatched request's two
closest-match scans no longer clone (and drop) every live expectation's `Arc`: the store's list is copy-on-write
and a scan iterates a shared snapshot of it (one reference count), still holding no lock of the store while the
matchers run.

| | before | after |
|---|---|---|
| unmatched, INFO, 16 clients | 350-422 µs (5,800-8,700 req/s) | 135-150 µs (20,400-25,000 req/s) |
| unmatched, WARN, 16 clients | 272-282 µs (10,900-16,700 req/s) | 112-117 µs (23,300-25,600 req/s) |
| unmatched, INFO, 1 client | 152 µs | 162 µs (noise: nothing to contend) |
| matched last (`/e999`), INFO, 16 clients, for scale | 61 µs | 60 µs |

The cost was the contended refcounts: with one client the clones were cheap, with sixteen every request's 2,000
atomic increments and decrements on shared cache lines dominated the scan.

### Matched requests at INFO

Server CPU time per request (`ps` cputime delta over 100,000 keep-alive `GET /e0`, `ab -k -c 16`, after 60,000 for
warm-up), release binary run natively, one expectation, stdout piped to a reader. Medians of six alternating runs at
INFO and three at WARN; the machine was shared (load average 55-110), so the figures are indicative and move about
±10 % run to run. "Before" is the tree with the console writer thread and the closest-match changes above already in.

| | before | after |
|---|---|---|
| matched, INFO | 73 µs | 62 µs |
| matched, WARN, for scale | 46 µs | 51 µs (noise: the WARN path did not change) |

What changed, output unchanged: the matching entries share one printed expectation per expectation and `times`
(it was rebuilt, compared with the previous copy and dropped on every request), the console line is built without
`format!` and its timestamp formatted once a second, and `format_log_message` scans bytes. What is left at INFO is
mostly building and dropping the extra entries themselves (each request evicts three entries from a full
100,000-entry log) and the event log's mutex, whose `lock_slow` share grew with the host's load (2 % of samples at
load ~60, 7 % at ~115), which points at lock holders being descheduled rather than a long critical section.

### The console on `tracing`

`bench/run.sh` as above (both servers `--cpus 2`, 64 connections, 15 s), on an **amd64 VM, not the Mac**: one
Ubuntu 24.04 VM of 10 vCPU (Intel Xeon Gold 6248R) and 48 GiB, Docker 28 with buildx, load average below 2 before
each run (2026-11-02). These rows are not comparable with the Mac rows above. "Before" is the tree just before the
console moved to `tracing`, "after" is the tree with that change, and "later" is a later tree; all three are built by
the same recipe, the project's static musl `--profile image` build without the dashboard stage. Two alternating
rounds at INFO, one at WARN; mock-server's req/s, with MockServer 9.2.0 from the same runs for scale:

| scenario | before (INFO) | after (INFO) | later (INFO) | before (WARN) | later (WARN) | MockServer 9.2.0 (INFO) |
|---|---|---|---|---|---|---|
| 1 expectation, match last | 5 528 / 6 005 | 5 886 / 6 194 | 3 774 / 5 382 | 6 173 | 5 681 | 8 825-14 576 |
| 1 expectation, unmatched | 1 726 / 1 695 | 1 728 / 1 709 | 1 682 / 1 764 | 2 277 | 2 143 | 1 563-1 938 |
| 1 000 expectations, match last | 6 045 / 5 623 | 5 641 / 5 249 | 4 834 / 4 566 | 7 130 | 6 021 | 35 633-47 387 |
| 1 000 expectations, unmatched | 1 675 / 1 769 | 1 648 / 1 876 | **74 / 76** | 2 678 | 1 558 | 380-485 |
| RSS after the runs | 489-833 MiB | 488-849 MiB | 1.1-1.4 GiB | 244-263 MiB | 1.0-1.2 GiB | 2.5-15 GiB |

- The move to `tracing` itself costs nothing measurable: before and after are within the run-to-run spread (±7 %).
- The later tree is slower at INFO, and 1,000 expectations unmatched collapses to ~75 req/s (p50 ~850 ms), 23 times
  slower than the tree after the move; at WARN the same case is 1,558 req/s. Its RSS is about twice as high at every
  level. Both come from changes after the move.
- On this VM mock-server is flat at about 6,000 req/s matched (p50 ~11 ms) at INFO and WARN alike, where the Mac
  gave 72,000-96,000 with the same `--cpus 2`. Something machine-dependent bounds it here (CFS quota throttling, the
  musl allocator under contention, or the VM's network path are candidates). A later diagnosis found the VM is not the
  bound: the Mac rows are old code (the first measured tree runs 72 500-77 600 req/s on this kind of VM); the cause is
  per-request allocations since the event-log work plus musl's allocator, and at INFO Docker's log driver (see "Log
  level and the Docker log driver" below).

### Metrics overhead

`bench/run.sh` as above with `METRICS=true`, which passes `MOCKSERVER_METRICS_ENABLED=true` to both servers, against
`METRICS` unset, on an **amd64 VM, not the Mac**: one Ubuntu 24.04 VM of 8 vCPU (Intel Xeon Gold 6248R) and 32 GiB,
Docker 29, load average 0.7-6.4 before each run (2026-11-03). The image is the later tree with the bench knob, built by
the recipe of the previous section. Four rounds, off then on in rounds 1-2 and on then off in rounds 3-4; req/s of each round, mean in brackets:

| scenario | mock-server, metrics off | mock-server, metrics on | MockServer 9.2.0, off | MockServer 9.2.0, on |
|---|---|---|---|---|
| 1 expectation, match last | 5 032 / 5 918 / 5 950 / 5 403 (5 576) | 4 960 / 4 918 / 5 375 / 5 510 (5 191) | 17 335-27 651 | 11 508-15 873 |
| 1 expectation, unmatched | 1 765 / 1 810 / 1 900 / 1 775 (1 813) | 1 704 / 1 900 / 1 839 / 1 717 (1 790) | 1 872-2 212 | 1 691-2 050 |
| 1 000 expectations, match last | 5 605 / 5 094 / 5 695 / 4 807 (5 300) | 4 851 / 5 311 / 5 383 / 5 176 (5 180) | 33 402-44 772 | 33 317-40 408 |
| 1 000 expectations, unmatched | 72 / 74 / 95 / 95 (84) | 84 / 78 / 91 / 77 (83) | 644-1 009 | 606-807 |
| RSS after the runs | 1.13-1.50 GiB | 1.14-1.50 GiB | 2.7-14.1 GiB | 2.2-14.2 GiB |

- Metrics cost mock-server nothing above the run-to-run spread: the means differ by 1-2 % except 1 expectation
  matched (-7 %), whose on and off ranges overlap (the off runs alone spread 5,032-5,950, ±8 %). RSS is unchanged.
- The same switch costs MockServer 9.2.0 about 45 % on 1 expectation matched.
- This VM bounds mock-server at about 6,000 req/s matched (the image's allocations and musl's allocator, see "Log
  level and the Docker log driver" below), so a CPU-bound host could show a larger share; 1,000 expectations unmatched
  is the slow path of the `tracing` section.

### The unmatched INFO path and RSS since the `tracing` console

The same recipe as above, on another amd64 stand (one Ubuntu 24.04 VM of 16 vCPU Xeon Gold 6248R and 64 GiB, load
below 2 before each run, 2026-11-03): the tree after the `tracing` console change ("tracing"), the later tree ("HEAD") and HEAD with the unmatched-path change
("fix"), each built by the recipe above, two alternating rounds at INFO and WARN; mock-server's req/s:

| scenario | tracing (INFO) | HEAD (INFO) | fix (INFO) | tracing (WARN) | HEAD (WARN) | fix (WARN) |
|---|---|---|---|---|---|---|
| 1 expectation, match last | 5 846 / 5 816 | 5 536 / 5 834 | 5 363 / 5 588 | 6 869 / 6 466 | 5 983 / 6 751 | 6 203 / 6 388 |
| 1 expectation, unmatched | 1 790 / 1 827 | 1 922 / 1 974 | 1 865 / 1 854 | 2 474 / 2 443 | 2 368 / 2 788 | 2 418 / 2 654 |
| 1 000 expectations, match last | 5 784 / 5 580 | 5 425 / 5 695 | 5 205 / 5 499 | 7 417 / 7 462 | 6 043 / 6 513 | 5 859 / 6 391 |
| 1 000 expectations, unmatched | 1 806 / 1 786 | **71 / 82** | **221 / 211** | 2 646 / 2 853 | 1 514 / 1 799 | 1 493 / 1 666 |
| RSS after the runs | 470-836 MiB | 1.1-1.5 GiB | 1.0-1.5 GiB | 244-263 MiB | 1.1-1.2 GiB | 1.1-1.2 GiB |

MockServer 9.2.0 in the same runs, 1 000 expectations unmatched at INFO: 552-599 req/s (RSS 12.8-15.4 GiB).

- **1 000 unmatched at INFO** is 9.1.0's closest-match walk (upstream `fullScanClosestMatchAndLazyRemoval`):
  with the candidate index missing, every one of the 1,000 expectations is evaluated per request and the first 50
  (`maxLoggedMatchFailures`) are logged as did-not-match entries, where tracing logged one closest-match line. The oracle
  does the same, so tracing's figure is out of reach without changing the event log. Most of HEAD's cost was a copy of each
  walked expectation's canonical form (`Expectation::current`) that only the 50 logged entries need; the fix takes none
  and skips the second match of the entries past the budget: 3x at the image, 4x native (245 -> 950 req/s on 2 pinned
  CPUs, glibc). What is left is building, storing and printing the 50 entries, which the musl allocator makes about 2.5
  times dearer than glibc here.
- **RSS** follows 9.1.0's heap-derived defaults: `maxLogEntries` is `heap / 8 KB` up to 250,000 where
  tracing had 100,000, and the log keeps that many entries. With `MOCKSERVER_MAX_LOG_ENTRIES=100000` the fix is back at
  tracing's RSS (INFO 430-743 MiB, WARN 394-579 MiB).
- **WARN with 1 000 expectations** stays 12-43 % below tracing in the image only. The same sources built natively
  (glibc release, musl release, and musl with the image profile's fat LTO)
  measure the fix at or above tracing on 2 pinned CPUs, and the LTO musl binaries run in a container are within 10 %;
  not diagnosed further.

### Log level and the Docker log driver

The image prints one console line per request at `INFO`, as MockServer does, and a container's stdout goes through
Docker's log driver. On an amd64 stand (Ubuntu 24.04 VM, Xeon Gold 6248R, `--cpus 2`, bridge network,
glibc build of the image, the later tree), mock-server req/s, two rounds:

| setting | req/s |
|---|---|
| `INFO`, default `json-file` log driver | 6 931 / 6 919 (0.87 of 2 cores: the server waits on the log pipe) |
| `INFO`, `--log-driver none` | 14 539 / 12 397 |
| `WARN` | 20 794 / 19 023 |

Practical reading: at the default `INFO` the `json-file` driver caps the image at about 7,000 req/s however many CPUs
it gets; `MOCKSERVER_LOG_LEVEL=WARN` or `--log-driver none` (or a driver that does not block on the pipe) lifts the
cap. MockServer prints at `INFO` too, so the comparison with it holds at the default. The static musl image is
below this cap already (about 6,000 req/s at any level, musl's allocator). Not measured on the Mac.

### The allocator of the static image

One amd64 stand (Ubuntu 24.04, 16 vCPU Xeon Gold 6248R, 31 GiB, Docker 29.1.3, load below 2 before
the runs, 2026-11-16), HEAD plus the allocator change, four images built from the same sources with the
project's recipe (static musl `--profile image`, fat LTO, `FROM scratch`; the glibc one distroless/cc): `musl` is the image as shipped before, `mimalloc` and `jemalloc` the
same binary with that `#[global_allocator]`. `--cpus 2`, user-defined bridge, `oha` 64 connections in a container,
15 s after a 3 s warm-up, three alternating rounds, mean req/s. This is the amd64 side of
`bench/run.sh`'s rows for the server alone (the oracle is not run: its figures are in the sections above).

| case | musl (shipped before) | musl + mimalloc | musl + jemalloc | glibc (distroless) |
|---|---|---|---|---|
| 1 expectation, matched, INFO | 6,010 | 6,897 | 6,907 | 6,920 |
| 1 expectation, matched, WARN | 6,952 | **25,751** | 27,078 | 20,575 |
| 1 expectation, unmatched, INFO | 1,385 | 2,634 | 2,627 | 2,650 |
| 1 expectation, unmatched, WARN | 2,046 | **5,520** | 5,578 | 5,049 |
| 1,000 expectations, matched, INFO | 5,716 | 6,910 | 6,932 | 6,933 |
| 1,000 expectations, matched, WARN | 6,835 | **25,861** | 26,559 | 20,655 |
| 1,000 expectations, unmatched, INFO | 120 | 118 | 121 | 119 |
| 1,000 expectations, unmatched, WARN | 1,443 | **4,058** | 3,867 | 3,302 |
| image size (docker, bytes) | 33,521,062 | 33,735,603 | 33,830,227 | 42,493,620 |
| RSS (VmHWM, MiB, range over the rows) | 103-1,405 | 206-1,669 | 182-1,638 | 176-1,738 |

- **At WARN the allocator is a 3.7x change** (matched 6,8-7,0k to 25.8k; 1,000 unmatched 1.4k to 4.1k). mimalloc and
  jemalloc agree within 5 % on every row (jemalloc ahead on matched WARN by 3-4 %, mimalloc ahead on 1,000 unmatched
  WARN by 5 %); glibc is 20 % behind both on matched WARN and the biggest image.
- **At INFO** the Docker `json-file` pipe is the cap (about 6,900 req/s, see the previous section); the allocator moves the musl
  image from 5.7-6.0k to that cap, and the unmatched 1-expectation row from 1.4k to 2.6k. 1,000 unmatched at INFO
  (about 120 req/s) is 9.1.0's closest-match walk and logging, not the allocator: all four agree.
- **RSS** (VmHWM per row): matched rows are 5-6 % lower with mimalloc (INFO 1,166-1,170
  against 1,232 MiB; WARN 1,275 against 1,365-1,391); the unmatched rows are higher, because musl returns freed groups
  to the kernel at once and mimalloc keeps them: 1 expectation INFO 1,669 against 1,150-1,165 MiB, WARN 251-263
  against 111-117; 1,000 expectations WARN 206-216 against 103-106 (jemalloc: 231-243 and 182-186). The large figures
  are the retained event log (`maxLogEntries` is heap-derived since 9.1.0), not the allocator: tracing's
  470-836 MiB at INFO (the rows above) is not restored by either allocator, and HEAD with musl is already at 1.1-1.5 GiB.
  Against HEAD's own musl image RSS is higher on four rows by up to 0.5 GiB and lower on four; against tracing it is
  no better and no worse than HEAD was before the allocator change on the matched rows, which is what the allocator can change.
- **Binary and image size**: mimalloc adds 0.2 MB (0.6 %), jemalloc 0.3 MB, glibc +9 MB.
