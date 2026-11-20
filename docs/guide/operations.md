# Operations

<!-- languages:begin -->
**English** · [Русский](../i18n/ru/guide/operations.md) · [中文](../i18n/zh/guide/operations.md) · [Español](../i18n/es/guide/operations.md)
<!-- languages:end -->

Running mock-server: the container, health, memory, logs, metrics, TLS and plugins. Facts come from the
`Dockerfile`, the code and the measurements named in each section.

## The container

The image (`make image`, see [Installation](installation.md)) is `FROM scratch`: one static binary, no shell and no
package manager, so `docker exec <name> sh` does not work; `docker exec <name> /mock-server healthcheck` does. It
runs as the user `65532:65532` and listens on `SERVER_PORT=1080`. `/config` is writable by that user, and is where the
entry point looks for `mockserver.properties`.

Mount a properties file or expectation JSON read-only and name it:

```sh
docker run --rm -p 1080:1080 -v "$PWD/init:/init:ro" \
  -e MOCKSERVER_INITIALIZATION_JSON_PATH=/init/expectations.json quay.io/oxidestack/mock-server:9.2.0-rc.1
```

## Health checks

- Liveness and the image's `HEALTHCHECK`: `PUT /mockserver/status` (200 with the ports). The `healthcheck`
  subcommand sends it to `localhost` on the first port of `MOCKSERVER_SERVER_PORT`, else `SERVER_PORT`, else 1080,
  and exits 0 on a 200 (`src/main.rs`).
- Readiness: `GET /mockserver/ready` answers `{"status":"READY"}` (`src/control.rs`).
- A client that waits for a log line can wait for `started on port: 1080`: it is still printed, which is what Testcontainers' wait strategy reads.

## Memory

Resident memory is bound by `MOCKSERVER_MAX_LOG_ENTRIES` (`maxLogEntries`): it grows by about 4.6 KiB per retained log
entry. The default is derived from the available heap, like MockServer's, with a ceiling of 250,000 entries.
`maxEventLogSizeInBytes` is not a memory bound here. Set `MOCKSERVER_MAX_LOG_ENTRIES` to what the container's memory
limit allows. The [Benchmarks](https://oxidestack.github.io/mock-server/benchmarks/) page has the measurements, with
their machine and load.

The image allocates with mimalloc (`src/main.rs`), because the static musl build's default allocator takes one
global lock.

## Logging

`logLevel` (`MOCKSERVER_LOG_LEVEL`, `-l`, `-logLevel`) and `logLevelOverrides` decide which events are logged, as in
upstream. The console is Rust-native: a line reads
`<UTC timestamp>  INFO mock_server::server: port=1080 started on port: 1080`. `RUST_LOG` filters by target, e.g.
`RUST_LOG=mock_server=info,mock_server::matching=off`. Logging configuration files are not read. The event log
that `PUT /mockserver/retrieve?type=logs` returns is the oracle's, not the console's.

## Metrics and dashboards

Set `MOCKSERVER_METRICS_ENABLED=true` and scrape `GET /mockserver/metrics`; `MOCKSERVER_OTEL_METRICS_ENABLED=true` exports
OTLP. The series are process, build, tokio runtime, HTTP server, connections, forward
pool, plus upstream's own families. The two Grafana dashboards in `grafana/`, the server's and the load injection's,
are over them. `scripts/verify-otlp-metrics.sh` decodes an OTLP export for checking.

## TLS

HTTPS and TLS-to-the-server leaves are minted from MockServer's bundled CA (`src/tls/`), so a client that trusts it
for MockServer trusts it here. `--proxy-setup` (or `MOCKSERVER_PROXY_SETUP=true`) generates a private CA instead and
prints a copy-paste block for the client side. The properties for your own certificates (`privateKeyPath`,
`x509CertificatePath`, `certificateAuthorityCertificate`, the control-plane TLS ones) are upstream's:
`spec/mockserver/manual/mock_server/HTTPS_TLS.html`.

## Callback plugins

Class callbacks load through plugins listed in `MOCKSERVER_CALLBACK_PLUGINS` (`/libs:/extensions` in the image).
The static image cannot load native plugins (`.so`, `.dylib`, `.dll`); WASM plugins (`.wasm`) work. Mount them at
`/libs` or `/extensions`. Each plugin is reported on stderr when loaded and one that fails to load is reported and
skipped (`docs/callback-plugins.md`).

## Clustering

Clustering (`clusterEnabled`) is in every image and speaks the JGroups and Infinispan wire protocols MockServer uses. The container cases of `make container-tests` run upstream's docker-compose and Helm cases against it.

## Stopping

`PUT /mockserver/stop` stops the listeners and lets in-flight requests drain for up to `stopDrainMillis`. `SIGTERM` (`docker stop`) ends the process as its default action does, after the queued
console lines are written (`src/main.rs`); it does not drain.

## Upgrading

Each release's steps are in [Upgrading](upgrading.md).
