# Writing an oracle scenario

A scenario is a `tests/scenarios/<name>.json` file: a list of HTTP (and other) steps that is sent to the real
MockServer, the oracle, once (`make record`, which writes `<name>.golden.json` beside it) and then replayed against
mock-server by `cargo test --test oracle`, which compares the two answers. This guide lists what a scenario file may
contain. The testing workflow is in the root `CONTRIBUTING.md`; this is its first step.

Never use a literal port 1-5, 1090, 18999 or 3111x in a scenario: the `scenarios_name_no_fixed_listening_port` test
fails on one. Use the placeholders below.

## Placeholders

| Placeholder | Meaning |
|---|---|
| `{{host}}` | the server's own address (the default `Host`) |
| `{{port}}` | the server's own port, for self-forwarding |
| `{{deadhost}}` | an address that is foreign and unreachable, like a Testcontainers-mapped port seen from inside the container |
| `{{deadport}}` | just its port, for a `host` and `port` given separately; in a JSON body write `"port": "{{deadport}}"` |
| `{{bindport:N}}` | a port to bind in place of the fixed `N`, for a `PUT /mockserver/bind` port; quoted in a JSON body the same way |
| `{{base64:<file>}}` | the base64 of a file under `tests/files` |
| `{{repeat:N:text}}` | `text` N times, for a large file or body |
| `{{peerhost}}`, `{{peerport}}`, `{{peeraddress}}` | the second node of a `"peer": true` scenario; `{{peerhost}}`/`{{peerport}}` split `{{peeraddress}}`, e.g. `"port": {{peerport}}` inside a string body |
| `{{deadporthex}}` | the dead port as four hex digits, in a `tcp` chunk |
| `{{capture:<key>}}` | a value saved by an earlier step's `capture` |
| `{{scratch}}` | a scratch directory; name `{{scratch}}` and `/tmp` files after the scenario |

## Step options

### The request

- `method`, `path`, `headers`, `body` (a string or JSON), `bodyBase64`, `bodyFile` (a file under `tests/files`).
- `note`: free text that is kept in the golden and shown in a failure.
- `sleepMillis`: wait before the next step.
- `"async": key`: an HTTP step sent without waiting, with a later `{"await": key}` step recording its answer.
- `"pipelinePut": true`: sends this step and the next on one connection in one write, for timed transitions a fresh
  connection could miss.
- `maxMillis`: raises the per-step response timeout above the 10 s default, for a step whose handler itself reaches the
  network (an OpenAPI `specUrlOrPayload` fetch) or one moving a 10 MiB body.
- `minMillis`: the answer must take at least that long.

### Reading the answer

- `capture`: a response header or the body, reused as `{{capture:<key>}}`.
- `decodeBase64`: a regex whose first capture group, base64 of UTF-8 text, is decoded in place before normalising and
  masking.
- `mask`: regexes replaced before comparing, each a string or `{"regex", "replace", "reason"}`. `reason` says why the
  value cannot match and is not read. Also valid on a `readFile` step, applied to its file content. A streamed
  forward's logged `x-mockserver-chunk-delays-ms` is measured (`System.nanoTime()` gaps between chunk arrivals, floored
  to ms), and the oracle itself reads `0,1,0,0` now and then for an undelayed upstream, more under load. The harness
  does not normalise it, because harvested fixture cases carry the same header as input data they echo; a step that
  logs a measured one masks the gaps with a `mask` that keeps the leading `0` and the chunk count (see
  `forward_streaming_intent`, step "exchanges").
- `"trailers": true`: also records the response's HTTP/1.1 chunked trailer fields, in order.
- `"binaryBody": true`: records the response body as base64, e.g. protobuf reflection answers.
- `"unzip": true`: a ZIP body is compared by its entries, names and contents in order, not by its bytes.
- `pollUntil`: a regex. The step is sent again every 200 ms, up to 30 s, until its body matches, and the last answer
  compares whole; for an event nothing else shows, such as an in-flight request being counted. On a `readFile` step it
  re-reads the file until its content matches, which sends the server nothing and so logs nothing, e.g. a watcher's
  reload awaited through the persisted expectations file.
- `awaitClose: true`: after the answer, waits up to 10 s for the server to close the connection, for a close the server
  logs just before closing, e.g. `disconnected and closed socket` read back later.

### How the answer is compared

- `"compare": "json"`: the body is compared as JSON, for object key order the oracle does not keep stable, e.g.
  `debugMismatch` differences reached directly or nested as a JSON-encoded string inside the body, such as an MCP
  `tools/call` response's `"text"` field (re-parsed recursively, see `deep_parse_embedded_json` in `tests/oracle.rs`).
- `"compare": "unordered"`: a log's entries as a multiset, for entries racing threads write in either order.
- `"compare": "status"`: only for recorded divergences.
- `"diverge": {"row": …, "status": n, "contains": […], "lacks": […]}`: an answer an adopted upstream fix after 8.0.0
  changes. The golden keeps the oracle's answer; replay checks ours against this status and these body texts, and
  `row` must name a `docs/divergences.md` row. Also `"headers"` / `"lacksHeaders"` (whole header lines ours must and
  must not have) and, on a `tcp` step, whose answer counts as its body, `"closed"`.

### Waiting

- `awaitIdle: true` on a `sleepMillis` step: replay waits, up to 30 s, until the server has no request in flight
  instead of sleeping. Recording sleeps. For an answer a step gave up on, e.g. a forward's read timeout against a
  slower upstream on the same server, whose log entries must land before the next step's.
- `awaitCounts: {name: n, …}` on a `sleepMillis` step: replay waits, up to 30 s, until each of the server's scheduler
  counts is `n`: `delayedResponses`, `sideActions`, `pendingDelayed`, `schedulerQueued`, `templateQueued`,
  `templateRunning`, `templateDryRuns` (see `Server::scheduler_count`). Recording sleeps. For a sleep that stands for
  "the request sent before it has been admitted", e.g. a delayed response holding the only slot before the one that
  must be refused.

### Files

- `readFile`, `writeFile` and the steps around them work on the server's file system. `"replace": true` inside a
  `writeFile` writes the file beside its path and renames it over it, so a watcher never reads it half written;
  without it the file is rewritten in place, as one the server holds open needs.
- `deleteFile`: a path, removed if present; an empty directory too; a `*` in the file name removes every match.
- `listFiles`: a path whose file name may hold `*`: the matching names, sorted, as `{"files": […]}`, `mask` applied to
  each.

### Other transports

- `"h2": true`: sends the step as cleartext HTTP/2 with prior knowledge through the `h2` crate, headers exactly as
  written, no automatic `content-length`; trailers are the HTTP/2 ones. With `"dataFrames": [base64, …]` (an entry may
  be `{"base64": …, "repeat": n}`, n frames) the body is one DATA frame per entry, the last ending the stream, for a
  gRPC message split across frames, e.g. inside its 5-byte prefix.
- `"udp": base64`: a datagram to the DNS listener. Recording sends it from a `python:3-alpine` sidecar in the oracle's
  network namespace (override with `MOCK_SERVER_UDP_IMAGE`), because Docker on macOS forwards no UDP.
- `"wsOpen"` / `"wsRead"` / `"wsSend"` / `"wsClose": name`: a WebSocket kept by name, by default the callback
  WebSocket: breakpoint holds and their decisions (see `Session` in `tests/oracle.rs`). `"wsDrain": name` discards what
  arrives within `waitMillis` uncounted, or up to a message matching `until`. `"countSkipped": false` on a `wsRead`
  drops its skipped count, for the dashboard's racy pushes. `"repeat": n` on a `wsSend` sends its message n times in
  one write.

#### `"h3": true`: HTTP/3

The step's `method`, `path`, `headers` and body go out as one HTTP/3 request on a fresh QUIC connection to the
server's `http3Port` (`:authority` `localhost:<port>`, or the step's `authority`, e.g. a CONNECT-UDP target; a
`":protocol"` header is a pseudo-header after `:path`). Its request stream is read as raw frames:
`{"frames": ["HEADERS", "DATA", …], "status", "headers", "body", "trailers", "end"}`, consecutive DATA frames counted as
one, `end` one of `fin`, `reset <code>`, `connection closed` or `timeout` after `maxMillis`.

- `stallMillis: n` grants the stream 64 KiB and no more for n ms, then reads as usual, and leaves `body` out.
- `trailers` (an object like `headers`) sends a trailer section after the body; `repeatHeader: [name, value, count]`
  adds that field count times; `closeError: true` waits up to 2 s after the stream ended and keeps how the server closed
  the connection as `closed` (`{application, code, reason}` or null); `settings: [id, …]` keeps those entries of the
  server's SETTINGS frame. Both clients encode a field section the same way (static-table lines for exact matches,
  literals without Huffman coding), so a section is as long on the wire when recorded as when replayed.
- `"streams": [{method, path, headers, body}, …]` in place of the step's own request sends each on one connection, the
  next 50 ms after the first bytes of the one before, and answers `{"streams": [<result>, …]}`, `body` kept only for a
  stream that ended `fin`. With it `stallMillis: n` grants the connection 96 KiB and each stream 1 MiB and no more for
  n ms from the first request.
- It needs the scenario option `"quic": true` and an `http3Port` in `"properties"`. Recording sends it from an aioquic
  sidecar, image `mock-server-h3client` built on first use or `MOCK_SERVER_H3_IMAGE`, in the oracle's network
  namespace. `tests/support/h3_step.rs` and `.py` are the two clients.

#### `"tcp": [base64, …]`: raw bytes

Raw bytes to the server's port, e.g. a SOCKS handshake.

- A chunk may instead be `{"text": …}` or `{"hex": …}` with placeholders substituted. `chunkMillis` sets the pause
  between chunks, default 200.
- `"tls": true` sends the chunks through a TLS client trusting any certificate, ALPN `http/1.1`, server name
  `localhost` or the step's `sni`, e.g. a CONNECT sent over TLS. `signatureSchemes: [rustls name, …]` sets its
  `signature_algorithms` (e.g. `ED448`), `"tls12": true` offers TLS 1.2 only, `"negotiated": true` adds
  `{"negotiated": {version, cipherSuite, signatureScheme}}` to a `"text": true` answer, and `cipherSuites: [rustls
  name, …]` is the client's offer in that order. A refused handshake is the answer `{"tlsHandshakeFailed": <how it
  ended>}`, e.g. `tls handshake eof` for a close without an alert.
- A chunk `{"starttls": n}` reads the answer's next n bytes in the clear and then starts TLS on the same connection (no
  ALPN, no server name; `"tls12": true` offers TLS 1.2 only), for a protocol that upgrades part way, e.g. PostgreSQL's
  SSLRequest.
- Chunks `{"await": n}` (read, up to 10 s, until the answer has n bytes, then read no more until the step's end) and
  `{"raw": hex}` (bytes written on the socket itself, under a `"tls"` step's TLS session, e.g. a corrupt record while a
  response is being written).
- `tlsEnd: true` adds how the TLS connection ended: `close_notify`, `eof` (a FIN without one) or `open`.
- `awaitBytes: n` first waits up to 10 s for the answer's first n bytes before the usual two-second read, for an answer
  that is only late under load, such as the first TLS flight after minting the leaf key, or one that waits out a
  server-side timer (an LLM verdict's timeout: under a loaded full run that timer was seen to fire 1.5 s late).
- `stallMillis: n` reads nothing for n ms after the last chunk, as a client that stopped reading, then up to 10 s, and
  records `{"tcpHead": status line, "complete": whether the content-length body all arrived, "closed"}` of the last
  response read; past a complete one more bytes follow, e.g. a CONNECT's `200`.
- An `"h2raw"` step has `readMillis` (how long it reads, default 2000; it never returns window), `dataLengths: true`
  (DATA frames by length, not payload), `openWindows: true` (SETTINGS_INITIAL_WINDOW_SIZE and the connection window at
  2^31-1, so only the socket holds a response back), `stallMillis: n` (reads nothing for n ms, then up to
  `readMillis`, default 10 s; records `{"frames": the frames but DATA, "complete": whether a DATA frame ended the
  stream, "closed"}`) and `streams: [{"method", "path"}, …]` (more bodiless requests on the same connection, streams
  3, 5, …). A whole `h2raw` step has a deadline of its stall and read times plus 30 s, `marginMillis` replacing the
  30 s, and panics past it, so a stuck file is listed as failed and never hangs the recorder.

## Scenario options

- `"properties": {…}` runs the scenario against a server started with those `mockserver.*` properties (recorded from
  an oracle container of its own; values are passed single-quoted through `JDK_JAVA_OPTIONS`, so inline JSON
  survives).
- `"jvmOptions": ["-Dio.netty.maxDirectMemory=8388608"]`: JVM options appended to the oracle's `JDK_JAVA_OPTIONS`,
  after its pinned processors and heap, and on replay to the same variable of our `Config`, which reads
  `io.netty.maxDirectMemory` and `-XX:MaxDirectMemorySize` from it. The heap flags are not replayed; the heap stays
  the recording VM's.
- `"env": {"MOCKSERVER_X": "value"}`: environment variables of that server (`docker run -e` for the oracle).
- `"propertiesFile": [lines]` (or one string): the file the server reads, mounted at the image's
  `/config/mockserver.properties` for the oracle, handed to `Config::with_property_file_text` on replay. Either of
  `env` and `propertiesFile` alone also gives the scenario a server of its own, and together with `"properties"` they
  cover all four tiers of `GET /mockserver/config`.
- `"quic": true`: the oracle serves `http3Port`. Recorded on the standard image since 9.2.0, which serves HTTP/3
  itself; before, on the `http3` variant `ORACLE_HTTP3_IMAGE`, which `make oracle ORACLE_QUIC=1` still starts.
- `"peerNetwork": "shared"`: the peer in the first node's network namespace, reached as `localhost`.
  `"peerImage": "<image>"`: a `"peer": true` node recorded on that image (default the oracle's); the golden names it
  `peerRecordedFrom`.
- `"warmEventLoops": true` (with `"properties"`): replay on a server whose worker event loops have each handled an HTTP
  request, as the oracle container's are after its readiness polls. A `gRPC request error` WARN logged outside any
  request carries the port there; one on a loop that served none does not.
- `"isolated": true`: for state `reset` does not clear. Bound ports and configuration (a `PUT` of
  `/mockserver/configuration` or `/mockserver/mode` needs it) are such state. So are:
  - the forward connection pool: a golden that logs a forward's `timing` needs `"properties"` too, because an
    `"isolated"` file without them is recorded on the shared oracle, whose pool already holds a connection to its own
    port, and a forward on a pooled connection logs no `timeToFirstByteInMillis`;
  - the TLS contexts' CA loads, logged once per server on its first inbound TLS connection and its first TLS forward:
    a golden that logs TLS traffic needs it;
  - the client addresses whose TLS handshake failed, logged at WARN only the first time per server: every shared
    server has seen the harness's address fail (`warm_tls_contexts`), so a golden with that WARN needs `"properties"`.

  This holds in harvested files too.
- `"settleMillis": n`: see "Replay" below.
- `"socketConnectionTimeoutInMillis": "120000"`: see "Recording" below.

## Replay

Replay runs scenarios concurrently: `MOCK_SERVER_REPLAY_WORKERS` servers (default the available parallelism, at
most 8; `1` is one-at-a-time replay) each take the next file, starting from a reset, next to the harvested files' 8
servers. A worker hands its server to the next file only once the requests the last one left in flight have been
answered (a step that gives up on a delayed answer would otherwise see the server log its `returning response` and
exchange into the next file's log, after that file's reset). The oracle reports no requests in progress, so such a
scenario declares `"settleMillis": n`: recording waits `n` ms after its last step before the next file on the shared
oracle (an `"isolated"` file without `"properties"` is recorded there too), and replay fails a file that keeps its
shared server busy for over 500 ms past its last step without a `settleMillis` covering it.

A scenario may not depend on anything outside its own server and its own named files. One that touches process-wide
state (gRPC health, the LLM Responses store, `{{bindport:N}}`, a shared `directoryToSaveDynamicSSLCertificate`) or a
`stallMillis` step's tens of MB, which starve timed steps beside it, replays alone. A 10 MiB body does not: the server
works on bodies of 256 KiB or more off its runtime workers. A new kind of shared state needs a group in `process_wide`
in `tests/oracle.rs`, with its reason. Name `{{scratch}}` and `/tmp` files after the scenario.

Other worktrees replay the same scenarios on one machine: each fixed `/tmp` name a scenario spells out is a
machine-wide lock while it replays (`tmp_name_locks`), and a fixed `http3Port`/`dnsPort` is moved to a free port, the
server started again while the listener is absent (`tests/support/udp_port.rs`). A `{{bindport:N}}` port is probed and
released too: a bind that fails (`Exception while binding MockServer to port N`) for an `N` no earlier step bound
replays the scenario again with fresh ports (`lost_bind_ports`; `tests/support/tcp_port.rs`), so a scenario that
expects that answer binds `N` successfully first.

### What the harness normalises

UUIDs, timestamps, ports, socket addresses and `x-mockserver-response-time-ms` are normalised, and `date` is ignored.
Anything else that differs is a bug or a `docs/divergences.md` entry. Two more rewrites:

- An OpenAPI expectation's id (`openapi:<title>_<hash>:<operation>`) hashes its spec location, so a spec named by a
  file path gets a different id in each checkout. The harness writes `<location hash>` for it in any text that also
  names the checkout path (`{{root}}`), and, in a text that does not (a closest-match hint header), for exactly the
  hashes of the absolute paths of the files under `tests/files`; an inline spec's hash is compared as is.
- Every forward carries the forward loop guard's `x-mockserver-forwarded-by: MockServer_<hex>` (9.1.0), an id random
  per server: the harness writes `MockServer_<instance id>` for it, in goldens as they are loaded too, so goldens
  recorded before the guard keep the ids the oracle sent. A self-forward ends in `508 Loop Detected` after
  `forwardLoopMaxHops` hops (`forward_loop_guard`); a fresh oracle takes about 15 s to create its first forward
  expectation, so such a first step needs `maxMillis`.

### The skip list

`skips-rs.txt` here lists top-level steps that do not match the oracle yet: `<scenario> <step>  # <cause>` (the step
index failures print, counting only compared steps) or `<scenario> *  # <cause>` for a scenario not replayed at all.
It is a to-do list, never accepted state. Replay fails on a listed step that matches, so a fix removes its line. The
harvested cases in `upstream/` have their own `skips-rs.txt`, `<case id>  # <reason>`.

### The harvested replay's results

The harvested replay writes `target/upstream-scenario-results.tsv` (one row per case) and
`target/upstream-scenario-diffs.txt` (the first difference of each non-matching case), both under a first line naming
the replay. An unfiltered replay replaces both: `# replay full <ts>`. A `MOCK_SERVER_SCENARIO` replay merges into
them by file, its files' rows replacing theirs and the rest kept: `# replay filtered <ts>
MOCK_SERVER_SCENARIO=<f> files=<n> base=full <ts0>` (`base=none`, rows not kept, when the two files do not name one
full run). `conformance/coverage.py` refuses anything but two `# replay full` lines with the same timestamp, so
regenerate `docs/coverage.md` only after an unfiltered `cargo test --test oracle`.

## Recording

`make record` writes the goldens from the oracle; record one scenario at a time with
`MOCK_SERVER_SCENARIO=<name> make record`, never the whole set.

- `MOCK_SERVER_SCENARIO=<name>$` names one file exactly (without the `$` it is a substring).
- `MOCK_SERVER_RECORD_RESUME=1` skips files whose golden the current oracle image already recorded (mark a golden's
  `recordedFrom` as anything else to re-record it). A file that cannot be recorded is listed at the end instead of
  ending the pass.
- `MOCK_SERVER_RECORD_TO=<dir>` writes the goldens under `<dir>` (same paths relative to `tests/scenarios`) instead
  of over the tree's, to compare a pass with them.
- After every file on the shared oracle the recorder checks that `reset` leaves it answering the control plane and an
  unmatched request with 404, and fails a file that leaves it otherwise (it needs `"properties"` of its own).
- Configuration survives `reset`, so a file whose steps change it (`changes_configuration`: a `PUT` of
  `/configuration` or `/mode`, or a CORS preflight, which turns `enableCORSForAPI` on for good; such files are
  `"isolated"`) is recorded on an oracle container of its own, as one with `"properties"` is, harvested files too. The
  recorder also fails a shared-oracle file that leaves `GET /mockserver/configuration` other than the pass found it
  (the subject alternative names an expectation's `Host` header adds excepted). Without this rule, isolated files
  without `"properties"` left their configuration to every file after them: on 9.2.0 one such file left
  `maxExpectations: 7`, so a later `PUT /mockserver/oidc` kept only the last 7 of its 9 expectations (no discovery, no
  JWKS), and a preflight left `enableCORSForAPI` on.
- A property-scoped oracle answers the readiness probe before its start-up is done (the CA load and `MockServer proxy
  setup` banner under `proxySetupLogging`, then the `startupWarmup` request), so the recorder waits for the banner on
  the container's console and, under `metricsEnabled`, for the warm-up to be counted, before the scenario's first step.
- The recorder ends the MCP sessions each file opened on the shared oracle (`DELETE /mockserver/mcp`), which keeps at
  most 100 and logs a WARN into the file that evicts one.
- A fresh oracle's first inbound TLS connection waits for its server certificate, generated off the event loop (an
  RSA-2048 key pair in a cold JVM, then the CA load and the leaf), and `SniHandler` closes the connection without a log
  entry once `socketConnectionTimeoutInMillis` (default 20 s) passes; on a loaded machine that generation took longer,
  so the step recorded `tls handshake eof` and the event log lacked the CA entries in some recordings. A scenario whose
  first TLS connection makes a property-scoped oracle generate a certificate sets
  `"socketConnectionTimeoutInMillis": "120000"` (the `log_ca_form_*` files and, since then, every other one; a fixed
  server certificate that `CertificateConfigurationValidator` refuses generates nothing and needs none). Its request
  then must not be forwarded: `Host: localhost` over TLS makes an unmatched request a forward to `localhost:443`, whose
  client TLS context mints a leaf of its own first (another 10 s or more there), past `awaitBytes`' 10 s wait; a
  request without a `Host` header is answered with 404 instead.
