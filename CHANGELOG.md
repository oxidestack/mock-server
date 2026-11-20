# Changelog

<!-- markdownlint-configure-file { "MD013": false, "MD024": { "siblings_only": true } } -->

All notable changes to mock-server, newest release first. The layout is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/)'s, with sections for the people who run the service: Action
required, Features, Bug fixes, Performance and Other changes. The versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

The changes since the last release are the release notes of the commits after its tag; a release gathers them into
its section below.

The first release, version and date not yet set: a drop-in replacement for the MockServer 9.2.0 image, as Rust. Its
differences from that image are in [`docs/divergences.md`](docs/divergences.md); what a deployment has to change is
in [Upgrading](docs/guide/upgrading.md).

### Action required

- `JAVASCRIPT` response templates fail, as on the stock MockServer image (no GraalJS); rewrite them in Velocity or
  Mustache. There is no `graaljs` image variant.
- Callback classes, `initializationClass` and server extensions do not load from a class path (`/libs`,
  `/extensions`): a jar there is named in a warning and ignored; provide them as callback plugins.
- JVM settings (`JAVA_TOOL_OPTIONS`, `MOCKSERVER_JAVA_OPTS`, thread-pool counts, `javascript*`) have no effect and
  are named in one start-up WARN line; `mock-server migrate` rewrites `-Dmockserver.*` settings to
  `MOCKSERVER_*`.
- `/mockserver/metrics` has the `process_*` series and `mock_server_native_build_info` instead of `jvm_*` series.

### Features

- Wire-compatible with MockServer 9.2.0 (control plane, data plane, HTTP/1.1, HTTP/2, TLS, the `version` header and
  the Java, Node, Python, Ruby and REST clients), checked against the 9.2.0 image as oracle and against MockServer's
  own test suites.
- A static `FROM scratch` image with MockServer's port, environment and `/config` layout, a `clustered` variant, and a
  Kubernetes admission webhook image.
- `mock-server migrate` reports and rewrites the configuration, compose files, Helm values and test sources that
  a move from the MockServer image changes.

### Other changes

- Console output is Rust-native; the event log and the lines Testcontainers waits for are unchanged.
- Dashboard analytics are off unless `MOCKSERVER_DASHBOARD_ANALYTICS_ENDPOINT` and `..._KEY` are set.
