# mock-server

<!-- languages:begin -->
**English** · [Русский](README.ru.md) · [中文](README.zh-CN.md) · [Español](README.es.md)
<!-- languages:end -->

A drop-in for [MockServer](https://www.mock-server.com), written in Rust. It answers MockServer's REST API and takes
its command line, environment variables and properties as the MockServer 9.2.0 image does, so the clients (Java,
Node, Python, Ruby, raw REST), the Testcontainers modules and the Helm chart that drive MockServer drive it with only
the image's name changed: one static binary, no JVM.

> **Not published yet.** The image and the documentation site are named here as they will be from the first release,
> `v9.2.0-rc.1`. Until it is out, build the image from source ([Building and testing](#building-and-testing)).

**Documentation: [oxidestack.github.io/mock-server](https://oxidestack.github.io/mock-server/)**

## Quick start

```sh
docker run --rm -p 1080:1080 quay.io/oxidestack/mock-server:9.2.0-rc.1
```

In another terminal, once it has started:

```sh
curl -X PUT localhost:1080/mockserver/expectation -d '{
  "httpRequest":  {"method": "GET", "path": "/hello"},
  "httpResponse": {"statusCode": 200, "body": "world"}
}'
curl -i localhost:1080/hello                              # 200, world
```

The dashboard is at `http://localhost:1080/mockserver/dashboard`. Every release is signed and carries its SBOMs and
build provenance; [Verifying an image](docs/guide/installation.md#verifying-an-image) checks one with `cosign` and
`gh attestation verify`.

## What it gives

- **A drop-in.** A client that talks to MockServer's `/mockserver/*` control plane works unchanged, with MockServer's
  command line, environment variables, properties and `/config` layout. The MockServer image pinned in `oracle.env`
  is the reference: where it and any document here disagree, it is right, and where the behaviour is not yet
  identical, [`docs/divergences.md`](docs/divergences.md) says so.
- **One static binary.** No JVM and no garbage collector; the container image is `FROM scratch`, for `linux/amd64`
  and `linux/arm64`, and runs as a non-root user. Memory is bounded by `MOCKSERVER_MAX_LOG_ENTRIES`
  ([Operations](docs/guide/operations.md#memory)), and the
  [Benchmarks](https://oxidestack.github.io/mock-server/benchmarks/) page compares it with MockServer's image under
  the same load.
- **Beyond HTTP/1.1.** HTTP/2, HTTP/3, TLS, gRPC, DNS, AsyncAPI brokers, proxying, chaos, clustering and
  MockServer's dashboard ([API reference](docs/guide/api.md)).
- **For Java test suites.** Testcontainers with the image, or `java-launcher/`, a drop-in for `mockserver-netty` that
  starts the binary behind `ClientAndServer` and the JUnit and Spring integrations
  ([Installation](docs/guide/installation.md#from-java-tests)).

## Documentation

The guide is published at [oxidestack.github.io/mock-server](https://oxidestack.github.io/mock-server/), the latest
release's at the root and every release's under its version; the same pages, as they are on `main`, are in
`docs/guide/`:

- [Installation](docs/guide/installation.md) — `docker run`, Docker Compose, Kubernetes, from source, and from Java
  tests
- [Upgrading](docs/guide/upgrading.md) — what each release asks of a deployment, and moving from MockServer's image
- [Configuration](docs/guide/configuration.md) — how settings are read, the command line, the properties file
- [API reference](docs/guide/api.md) — the control plane, health, metrics, the dashboard and the other protocols
- [Operations](docs/guide/operations.md) — the container, health checks, memory, logging, metrics, TLS, plugins
- [Troubleshooting](docs/guide/troubleshooting.md) — symptoms, what each means and what to do
- [Benchmarks](https://oxidestack.github.io/mock-server/benchmarks/) — requests a second and memory against
  MockServer's image, from the committed results of `bench/run.sh`
- [Changelog](CHANGELOG.md) — what each release changed

## Building and testing

The repository carries MockServer's monorepo as a git submodule, which the tests and the dashboard build read (the
project's own Rust libraries are crates.io dependencies), so clone it with its submodule:

```sh
git clone --recursive https://github.com/oxidestack/mock-server.git
```

In a clone made without `--recursive`, run `git submodule update --init` once.

- `cargo build --release` builds the server, `target/release/mock-server`.
- `make image` builds the container image for your machine's architecture as `mock-server:latest`; it needs Docker.
- `cargo test` runs the unit tests, the Rust ports of MockServer's own tests and every recorded scenario; it needs no
  MockServer container. [CONTRIBUTING.md](CONTRIBUTING.md) lists the slower suites and the checks every pull request
  runs.

## Getting help

A question about how the server works can go to [DeepWiki](https://deepwiki.com/oxidestack/mock-server) first: it
answers from this repository's code and documentation, and where it disagrees with the documentation, the
documentation is right. Questions it does not settle go to
[Discussions](https://github.com/oxidestack/mock-server/discussions), bugs to
[issues](https://github.com/oxidestack/mock-server/issues), vulnerabilities to a private report
([SECURITY.md](SECURITY.md)). [CONTRIBUTING.md](CONTRIBUTING.md) says how to build, test and send a change.

## Licence

The code is licensed under the [Apache License, Version 2.0](LICENSE) (`Apache-2.0`). The documentation — this README
and the guides under `docs/` — is licensed under
[Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/) (`CC-BY-4.0`); its
legal text is in [`LICENSE-docs`](LICENSE-docs). `spec/mockserver/` holds MockServer's own schemas, OpenAPI document
and manual pages: they are upstream's, not this project's documentation, and stay Apache-2.0. Material taken from
elsewhere keeps its own licence, attributed in [`NOTICE`](NOTICE).
