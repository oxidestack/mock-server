# Upgrading

<!-- languages:begin -->
**English** · [Русский](../i18n/ru/guide/upgrading.md) · [中文](../i18n/zh/guide/upgrading.md) ·
[Español](../i18n/es/guide/upgrading.md)
<!-- languages:end -->

How to move a deployment from the release it runs to a newer one, or from the MockServer image to mock-server.
Find the section of every release newer than yours, and apply them oldest first: going from 9.2.0 to a later
release means the section of each release in between, then the one of the release you want. A release with nothing
to change says so. Then [upgrade](#how-to-upgrade) to the newest release in one step: a release never needs an
intermediate one installed first.

Each section lists what the release asks of a deployment or of a client: under **Action required**, a change to make
before or with the upgrade; under **Deprecated**, something that still works and will stop in a later release; under
**Removed**, something that has stopped. The
[changelog](https://github.com/oxidestack/mock-server/blob/main/CHANGELOG.md) says everything else each release
changed. Only releases have a section: a release candidate (`-rc.N`) is described on its GitHub release, and what it
changes is written here under the release that ships it.

The documentation of the release you run is on this site too: the version picker at the top of each page switches
between releases, and a page of an older release links the same page in the latest.

## How to upgrade

mock-server keeps expectations and the event log in memory, as MockServer does, and writes no files of its own
unless you configure persistence or recording. An upgrade replaces the container (or the binary) and nothing else,
and a rollback is the same step with the older version. Expectations that are not loaded again at start-up
(`initializationJsonPath`, a client's `ClientAndServer` set-up) are gone after a restart, as they are in MockServer.

1. Read the sections below for every release newer than yours, and make their changes to your configuration,
   environment, chart values or clients.
2. Replace the container:
   - `docker run` or Docker Compose: change the image's tag (`quay.io/oxidestack/mock-server:<version>`) and start it
     again (`docker compose up -d`). The port (`1080`), the environment variables, the command-line arguments and the
     `/config` layout are the MockServer image's.
   - Testcontainers: change the image name given to `MockServerContainer` (declare it compatible with
     `mockserver/mockserver` through `asCompatibleSubstituteFor`).
   - Helm: use upstream's MockServer chart with `image.repositoryNameAndTag` set to the new image and your own values
     file; there is no separate chart.
3. Watch the first minutes: the container's health check, the status of your first requests and, if you scrape it,
   `/mockserver/metrics`. To roll back, run step 2 with the version you had.

Coming from the Java MockServer image, run `mock-server migrate` over your configuration, compose files, Helm
values and test sources first: it reports each setting or build file that needs a change, and `--write` applies the
mechanical ones.

## Upgrading to X.Y.Z (first release, version and date not yet set)

<!-- Placeholder: replace "X.Y.Z" in this heading and the Unreleased heading of CHANGELOG.md with the first release's
     number when it is cut (tags follow upstream; the first is expected to be 9.2.0). Every later release gets its
     own section above this one. -->

The first release of mock-server: a drop-in for the MockServer 9.2.0 image. The control plane, the data plane and
the clients (Java, Node, Python, Ruby, raw REST) behave as the 9.2.0 image does on the wire, including the `version`
header, so a client built for MockServer 9.2.0 needs no change. Differences from the image are listed in
[`docs/divergences.md`](https://github.com/oxidestack/mock-server/blob/main/docs/divergences.md), which is the
authoritative list; the ones below are those a deployment has to act on.

### Action required

- **JavaScript templates.** A `JAVASCRIPT` response template fails, as it does on the stock MockServer image, which has
  no GraalJS. mock-server never ships a JavaScript engine; rewrite such templates in Velocity or Mustache. Deployments
  that ran the `graaljs` image variant must do this, as there is no such variant.
- **Java classes loaded from the class path.** Callback classes (`httpResponseClassCallback`, `httpForwardClassCallback`),
  `initializationClass` and server extensions come from jars in `/libs` or `/extensions` on the MockServer image. Here
  there is no class path: a jar there is named in a warning and ignored, and a callback or initializer is provided by a
  callback plugin (native or WASM; `MOCKSERVER_CALLBACK_PLUGINS`). A deployment that depends on such classes needs a
  plugin before it moves.
- **JVM settings.** `JAVA_TOOL_OPTIONS`, `JAVA_OPTS`, `MOCKSERVER_JAVA_OPTS`, the thread-pool counts and the
  `javascript*` keys have no effect; the server writes one WARN line naming them at start-up. Memory is bounded by the
  container's limit and by `maxExpectations` and `maxLogEntries` (about 4.6 KiB of resident memory per retained log
  entry): move any `-Dmockserver.<key>=<value>` inside those variables to `MOCKSERVER_<KEY>` or the properties file.
  `mock-server migrate` does this rewrite.
- **Dashboards and alerts built on JVM metrics.** `/mockserver/metrics` has the `process_*` series of Prometheus's
  standard process collector and a `*_build_info` series in place of `jvm_gc_*`, `jvm_memory_*` and
  `jvm_threads_*`; the `mock_server_*` request and chaos series are upstream's. Change any panel or alert that reads a
  `jvm_*` series.

### Deprecated

Nothing.

### Removed

- The image variants `graaljs`, `snapshot`, `root`, `root-snapshot`, `local`, `aot` and `clustered`: one image is
  published per version, for both platforms. Clustering is in it; MockServer's `clustered` image differs from its
  plain one only in the value of `MOCKSERVER_DASHBOARD_ANALYTICS_DISTRIBUTION`.
- The `mockserver-war` and `mockserver-proxy-war` Tomcat packages: run the container beside the servlet container.
- Dashboard analytics to upstream's PostHog project: the image's `MOCKSERVER_DASHBOARD_ANALYTICS_ENDPOINT` and
  `MOCKSERVER_DASHBOARD_ANALYTICS_KEY` are empty, so no analytics are sent unless you set both.
- The JVM's console log layout: console lines are Rust-native (`tracing`), but the lines a Testcontainers wait strategy
  reads (`started on port: 1080`) are kept. The event log (`retrieve?type=LOGS`, `LOG_ENTRIES`, the dashboard) is
  unchanged. A pipeline that parses the other console lines needs a new pattern.
