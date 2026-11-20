# Troubleshooting

<!-- languages:begin -->
**English** · [Русский](../i18n/ru/guide/troubleshooting.md) · [中文](../i18n/zh/guide/troubleshooting.md) · [Español](../i18n/es/guide/troubleshooting.md)
<!-- languages:end -->

Each entry is a symptom this repository can account for. When the behaviour you see differs from MockServer's, that is
a bug or a listed divergence: check `docs/divergences.md`, and compare against the oracle (the image pinned in
`oracle.env`), which is right when the two disagree.

## The server does not start

**`-p` or the port is required.** `mock-server run` needs a port from `-p`, `MOCKSERVER_SERVER_PORT`,
`mockserver.serverPort` or the properties file (`src/cli_usage/run.txt`). The image sets `SERVER_PORT=1080`.

**A properties file is named but cannot be read.** A file named by `mockserver.propertyFile` or
`MOCKSERVER_PROPERTY_FILE` that cannot be read is reported at start; the default `mockserver.properties` is read only
when present (`src/config.rs`, `load_property_file`).

**A start-up notice about unknown keys or JVM-only settings.** An unknown `mockserver.*` or `MOCKSERVER_*` key is
reported as upstream reports it. `JVM-only settings have no effect in mock-server: [...]` names the JVM flags
(`-Xmx`, `JAVA_TOOL_OPTIONS`, ...) that are accepted and ignored: memory is bound by the container limit and
`maxLogEntries`.

## The health check fails

`mock-server healthcheck` connects to `localhost` on the first port of `MOCKSERVER_SERVER_PORT`, else `SERVER_PORT`,
else 1080. A server on another port than that one fails the check: set `SERVER_PORT` (or `MOCKSERVER_SERVER_PORT`) to
the port the server listens on (`src/main.rs`).

## Memory grows

Resident memory grows by about 4.6 KiB per retained log entry until `maxLogEntries` is reached. Set
`MOCKSERVER_MAX_LOG_ENTRIES` lower ([Operations](operations.md#memory)). `maxEventLogSizeInBytes` does not bound it.

## `/mockserver/dashboard` answers 404

The binary was built without the UI bundle. `make dashboard` (node 22, the `upstream/mockserver` submodule) builds it
into `dashboard/`, and the next build embeds it; the image builds it in its own stage (`Makefile`, `Dockerfile`).

## A class callback fails

mock-server loads no Java classes. A class callback name is resolved through callback plugins
(`MOCKSERVER_CALLBACK_PLUGINS`): an in-process registration, a native plugin, or a WASM plugin. The static image cannot
load native plugins, and a `.jar` named in a plugin directory is reported on stderr and not loaded
(`Dockerfile`, `docs/callback-plugins.md`). `initializationClass` is a Java class and cannot be loaded either.
JavaScript templates fail exactly as they do in the oracle, which has no GraalJS.

## A forward to the server itself never returns

A forward whose target is its own path loops inside MockServer, and the oracle does too; it keeps writing to its log
after `reset`. Restart the server and point the forward at another host or path.

## From Java tests

- **The launcher cannot find the binary.** The start fails with a message naming the three places it looked: the
  `mockServer.binary` system property, `MOCK_SERVER_BINARY`, `mock-server` on `PATH`
  (`docs/java-launcher.md`).
- **A `mockserver-netty-no-dependencies` jar still starts an in-JVM server.** Those shaded jars bundle upstream's
  `ClientAndServer`; use the unshaded module and exclude `mockserver-netty` (`docs/java-launcher.md`).
- **A process is left running after the JVM died.** A JVM killed with `SIGKILL` runs no shutdown hook, so the
  launched process stays (`docs/java-launcher.md`).
- **`UnsupportedOperationException: in-JVM: ...`.** The method reads an in-JVM server's internals, which a process
  does not have (`registerListener`, `setLogEventListener`, `getScheduler` and the others in `docs/java-launcher.md`).
- **Testcontainers does not accept the image.** Declare it a substitute:
  `DockerImageName.parse(...).asCompatibleSubstituteFor("mockserver/mockserver")` (`conformance/java/.../Images.java`).

## Behaviour differs from MockServer

1. Reproduce it against the oracle with the same request. If the oracle answers the same, it is not a divergence.
2. Check `docs/divergences.md` and `docs/coverage.md` for a known row.
3. Otherwise it is a bug: the project's tests record the oracle's answer as a golden scenario
   (`tests/scenarios/`), and a bug report with the request and both answers becomes one.

Questions go to [DeepWiki](https://deepwiki.com/oxidestack/mock-server) first, which answers from the code and
documentation (where the two disagree, the documentation is right), then to
[Discussions](https://github.com/oxidestack/mock-server/discussions); bugs go to
[issues](https://github.com/oxidestack/mock-server/issues).
