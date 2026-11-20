# API reference

<!-- languages:begin -->
**English** · [Русский](../i18n/ru/guide/api.md) · [中文](../i18n/zh/guide/api.md) · [Español](../i18n/es/guide/api.md)
<!-- languages:end -->

The API is MockServer's: the control plane under `/mockserver/*`, and the data plane, which answers every other
request from the expectations you created. The contract is upstream's OpenAPI document, vendored verbatim at
`spec/mockserver/mockserver-openapi.yaml`, and the server serves it at `GET /mockserver/openapi.yaml`. Control-plane
input is validated against upstream's schemas in `spec/mockserver/schema/`, with the oracle's error text. This page
lists the common operations; the document is the complete reference, and where the oracle behaves differently from it,
the oracle wins.

Clients in any language that talk to MockServer's control plane work unchanged. The same operations are
also answered at the bare legacy paths (`PUT /expectation`, `PUT /reset`, ...) (`src/control.rs`).

## Create expectations

```sh
curl -X PUT localhost:1080/mockserver/expectation -d '{
  "httpRequest":  {"method": "GET", "path": "/hello"},
  "httpResponse": {"statusCode": 200, "body": "world"}
}'
curl -i localhost:1080/hello
```

`PUT /mockserver/expectation` takes one expectation or an array and answers 201 with the expectations in the
oracle's canonical form. Matching, actions (response, forward, callback, error), times, priority and the other fields
are those of upstream's `expectation` schema (`spec/mockserver/schema/expectation.json`).

Other ways to create them: `PUT /mockserver/openapi` (from an OpenAPI or Swagger spec), `PUT /mockserver/import` (HAR,
Postman, WireMock, Mountebank, Mockoon, recorded traffic), the `--init` and `--openapi` command-line options, and the
initialization properties (`initializationJsonPath`, `initializationOpenAPIPath`).

## Inspect, verify, clear

| Operation | Path | Notes |
|---|---|---|
| Retrieve | `PUT /mockserver/retrieve?type=` | `requests` (default), `request_responses`, `recorded_expectations`, `active_expectations`, `logs`, `metrics`; `format=` `json` (default), `log_entries`, `har`, code generators, exports |
| Verify a request count | `PUT /mockserver/verify` | 202 when satisfied, 406 with the mismatch otherwise |
| Verify an order | `PUT /mockserver/verifySequence` | |
| Clear | `PUT /mockserver/clear?type=` | `all` (default), `log`, `expectations`; the body is a request matcher |
| Reset | `PUT /mockserver/reset` | clears every expectation and recorded request |
| Ports | `PUT /mockserver/status` | JSON of the listening ports |
| More ports | `PUT /mockserver/bind` | |
| Stop | `PUT /mockserver/stop` | stops the server; in-flight requests drain for up to `stopDrainMillis` |
| Lint | `PUT /mockserver/lint` | reports expectations that can never match; the same report as `mock-server lint` |
| Configuration | `GET`/`PUT /mockserver/configuration` | read, or change, the configuration at run time |

Source for each row: `spec/mockserver/mockserver-openapi.yaml`, and `src/control.rs` for the stop and drain behaviour.
The manual pages `clearing_and_resetting.html`, `debugging_issues.html` and `importing_expectations.html` under
`spec/mockserver/manual/mock_server/` describe the semantics.

## Health and readiness

- `PUT /mockserver/status` answers 200 with the listening ports once the server is up. The image's `HEALTHCHECK`
  (`mock-server healthcheck`) sends it to the first port of `MOCKSERVER_SERVER_PORT`, else `SERVER_PORT`, else 1080.
- `GET /mockserver/ready` answers 200 with `{"status":"READY"}` (`src/control.rs`).

## Metrics

With `metricsEnabled=true` the server answers `GET /mockserver/metrics` in the Prometheus text format and
`PUT /mockserver/retrieve?type=METRICS` with the same counts. The families are upstream's, except that the JVM ones
(`jvm_*`) are replaced by process, tokio runtime, HTTP server and connection series. With `otelMetricsEnabled` the same data is exported over OTLP. Two Grafana dashboards are in
`grafana/`.

## Dashboard

`GET /mockserver/dashboard` serves MockServer's UI, embedded in the binary.

## Protocols and further operations

Beyond HTTP/1.1, the server speaks HTTP/2, HTTP/3 (`http3Port`), TLS with certificates minted from MockServer's CA,
gRPC (`/mockserver/grpc/*`), DNS (`dnsEnabled`, `dnsPort`), AsyncAPI brokers (`/mockserver/asyncapi`) and binary
protocols. The control plane also has chaos (`serviceChaos`, `tcpChaos`, `grpcChaos`), CRUD stores (`crud`), file
storage (`files/*`), clock control (`clock`), drift (`drift`), scenarios (`scenario`) and an MCP endpoint (`mcp`).
Each is in the OpenAPI document or upstream's manual (`spec/mockserver/manual/`); `src/control.rs` (`OPERATIONS`) is
the list the server answers. `docs/coverage.md` and `docs/divergences.md` say where behaviour is not yet identical to
the oracle's.

## Callback plugins

A class callback (`httpResponseClassCallback`, `httpForwardClassCallback`) names a class that mock-server resolves
through callback providers instead of a JVM class path: see `docs/callback-plugins.md`.
