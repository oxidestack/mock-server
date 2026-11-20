# Configuration

<!-- languages:begin -->
**English** · [Русский](../i18n/ru/guide/configuration.md) · [中文](../i18n/zh/guide/configuration.md) · [Español](../i18n/es/guide/configuration.md)
<!-- languages:end -->

mock-server reads MockServer's configuration: the same property names, environment variables, command line and
properties file. Where this page and the oracle (the MockServer image pinned in `oracle.env`) disagree, the oracle is
right. The property reference is upstream's: `spec/mockserver/manual/mock_server/configuration_properties.html`
(Apache-2.0, upstream's own page).

## How a value is read

A property `mockserver.fooBarBaz` is also the environment variable `MOCKSERVER_FOO_BAR_BAZ` (`env_name` in
`src/config.rs`; a few names are exceptions, and `src/effective_config_properties.txt` lists every property with its
environment variable). A value can come from these sources (the precedence among them for an ordinary property is upstream's, in the manual page
above; the four settings below are resolved as stated):

1. the command line (`-p`, `-serverPort`, `-D<key>=<value>` ...);
2. a `-Dmockserver.<name>=<value>` system-property option;
3. the environment variable `MOCKSERVER_<NAME>`;
4. the properties file (below).

For the settings the launcher itself resolves, `serverPort`, `proxyRemoteHost`, `proxyRemotePort` and `logLevel`, the
order in `src/config.rs` (`cli_owned`) is: the command-line option, the system property, `MOCKSERVER_<NAME>`, the
short environment name (`SERVER_PORT`, `PROXY_REMOTE_HOST`, `PROXY_REMOTE_PORT`, `LOG_LEVEL`), then the properties
file. A blank value counts as unset. The image sets `SERVER_PORT=1080`, which gives way to a `mockserver.serverPort`
in the properties file.

To see what a given command line and environment resolve to, run it with `--print-config`: the server prints the
effective configuration, one `name = value   [source]` line per property, and exits without listening.

```sh
MOCKSERVER_MAX_LOG_ENTRIES=100000 mock-server --print-config
```

Keys the server does not know are reported as upstream reports them (`findUnknownConfigurationKeys`).

## Command line

The binary has MockServer's picocli command tree (`src/cli_usage/`). The usage text below is the oracle's:

| Command | What it does |
|---|---|
| `run` (default) | start the server: `-p/--port`, `-l/--log-level`, `--init`, `--openapi`, `--persist`, `--proxy-to`, `--validate-openapi`, `--validate-enforce`, `--watch`, `--dev`, `--proxy-setup`, `-D<key>=<value>` |
| `ui` | start and open the dashboard in a browser |
| `proxy --to <host[:port]>` | start in port-forwarding mode |
| `openapi <spec>` | start with expectations from an OpenAPI spec |
| `import <file> -p <port>` | load expectations from a JSON file into a running server (`-H` for the host) |
| `lint <file>...` | check expectation JSON for expectations that can never match; `--json`, `--strict`; needs no server |
| `demo` | start with a few example expectations |
| `version`, `help` | |

The legacy flags `-serverPort`, `-proxyRemotePort`, `-proxyRemoteHost` and `-logLevel` still work. Two commands are
ours and outside that tree: `mock-server healthcheck` (the image's health check) and `mock-server migrate`
(finds what in a repository relies on MockServer's JVM packaging, and applies mechanical rewrites;
`src/migrate/`).

## Properties file

The file named by `mockserver.propertyFile` or `MOCKSERVER_PROPERTY_FILE` is read at start (default
`mockserver.properties` in the working directory; the image points it at `/config/mockserver.properties`, a directory
the image creates and the server's user owns). A file name ending in `.json` is read as JSON. An unreadable file the
operator named is reported at start (`src/config.rs`, `load_property_file`). A properties file never supplies
`logLevel`; a JSON one can.

## Memory-bounding properties

`maxLogEntries` and `maxExpectations` (`MOCKSERVER_MAX_LOG_ENTRIES`, `MOCKSERVER_MAX_EXPECTATIONS`) bound the event
log and the expectations kept. Their defaults are derived from the available heap, as upstream derives them, with a
ceiling (250,000 log entries; `default_max_log_entries` in `src/config.rs`). `--dev` lowers both to 1,000.
[Operations](operations.md#memory) gives the consequence for resident memory.

## Settings that are Rust-native

The server sorts every JVM-only input into support, map, warn and reject:

- `-Dmockserver.<key>` inside `JAVA_TOOL_OPTIONS` is not read by the server (`migrate` rewrites it to the environment
  variable). `-Xmx`, `-Xms`, `-XX:*RAMPercentage` and other JVM flags have no effect; when such settings are present the
  server prints one WARN line at start naming them.
- `nioEventLoopThreadCount` sets the number of worker threads; unset, it is the number of available cores.
- `useNativeTransport` and `javascript*` settings are accepted and have no effect (the divergence is in
  `docs/divergences.md`).
- Logging configuration files (`logback.xml`, `logging.properties`) have no counterpart; levels come from `logLevel`
  and `logLevelOverrides`. The console is Rust-native: `RUST_LOG` filters events (`src/log.rs`).

## Plugins

`mockserver.callbackPlugins` (`MOCKSERVER_CALLBACK_PLUGINS`) lists the plugin files and directories that provide class
callbacks, separated like a class path (`docs/callback-plugins.md`). The Docker image sets it to `/libs:/extensions`.

## Dashboard analytics

Dashboard analytics are off by default: `MOCKSERVER_DASHBOARD_ANALYTICS_ENDPOINT` and
`MOCKSERVER_DASHBOARD_ANALYTICS_KEY` are empty in the image, and the project never sends to upstream's account.
