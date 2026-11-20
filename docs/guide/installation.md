# Installation

<!-- languages:begin -->
**English** · [Русский](../i18n/ru/guide/installation.md) · [中文](../i18n/zh/guide/installation.md) · [Español](../i18n/es/guide/installation.md)
<!-- languages:end -->

mock-server is one static executable, `mock-server`, that behaves as MockServer does on the wire. This page runs its
image, builds it from source, and says how a Java test suite reaches it. Every command here is one the repository
defines (`Makefile`, `Dockerfile`, `Cargo.toml`) or one its release publishes.

> **Not published yet.** The image below is named as it will be from the first release, `v9.2.0-rc.1`. Until it is
> out, [build the image](#build-the-container-image) and use `mock-server:latest` wherever this page names
> `quay.io/oxidestack/mock-server`.

## Run the image

```sh
docker run --rm -p 1080:1080 quay.io/oxidestack/mock-server:9.2.0-rc.1
```

The image is published to quay.io for `linux/amd64` and `linux/arm64` under one tag, and mirrored, with the same
digest, signature and attestations, to `ghcr.io/oxidestack/mock-server`. A version follows the MockServer release it
matches: `9.2.0` is a drop-in for MockServer 9.2.0's image. A release is tagged `<version>`, `mockserver-<version>`
(the tag MockServer's own image carries) and `latest`; a release candidate, `9.2.0-rc.1`, is tagged only with its
version.

Arguments after the image name are the server's, as with MockServer's image:
`docker run --rm -p 1081:1081 quay.io/oxidestack/mock-server:9.2.0-rc.1 -serverPort 1081`.

What the image sets (`Dockerfile`):

| | |
|---|---|
| Port | `SERVER_PORT=1080`, `EXPOSE 1080` |
| Entry point | `/mock-server -Dmockserver.propertyFile=/config/mockserver.properties` |
| User | `65532:65532`, which owns `/config` |
| Callback plugins | `MOCKSERVER_CALLBACK_PLUGINS=/libs:/extensions` (see [Operations](operations.md)) |
| Health check | `/mock-server healthcheck` every 5 s, 3 s timeout |
| Licences | `/licenses/` (`LICENSE`, `NOTICE`, `DASHBOARD-THIRD-PARTY-NOTICES.txt`) |

## Verifying an image

Every released image is signed with cosign, keyless, by the release workflow of `oxidestack/mock-server`, and carries
its SLSA build provenance and an SPDX SBOM per architecture as attestations. With
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) and the [GitHub CLI](https://cli.github.com/):

```sh
cosign verify quay.io/oxidestack/mock-server:9.2.0-rc.1 \
  --certificate-identity https://github.com/oxidestack/mock-server/.github/workflows/release.yml@refs/tags/v9.2.0-rc.1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://quay.io/oxidestack/mock-server:9.2.0-rc.1 --repo oxidestack/mock-server
```

Each release's GitHub page carries the same commands for its version, and its SBOMs as files.

## Docker Compose

```yaml
services:
  mockserver:
    image: quay.io/oxidestack/mock-server:9.2.0-rc.1
    ports:
      - "1080:1080"
    environment:
      MOCKSERVER_LOG_LEVEL: INFO
```

Any `mockserver.*` property is the environment variable `MOCKSERVER_<NAME>` ([Configuration](configuration.md)).

## Kubernetes

The project ships no Helm chart of its own: MockServer's chart is the one users have, run with this image through
`image.repositoryNameAndTag`, and the container cases (`make container-tests`) run it that way:

```sh
helm repo add mockserver https://www.mock-server.com
helm upgrade --install --namespace mockserver --create-namespace \
  --set image.repositoryNameAndTag=quay.io/oxidestack/mock-server:9.2.0-rc.1 \
  mockserver mockserver/mockserver
```

The admission webhook has its own crate and image, built by `make webhook-image` (`k8s-webhook/`); it is not
published yet.

## Build the binary

You need a Rust toolchain (the dependency versions are locked in `Cargo.lock`) and the git submodules:

```sh
git clone --recursive https://github.com/oxidestack/mock-server.git
cd mock-server
cargo build --release
```

In a clone made without `--recursive`, run `git submodule update --init` once. The executable is
`target/release/mock-server`. The MockServer dashboard (`/mockserver/dashboard`) is embedded into the binary by
`build.rs`; without the UI bundle the binary answers that path with 404. `make dashboard` builds the bundle (node 22
and the `upstream/mockserver` submodule). When the submodule and node 22 are there, `build.rs` builds it by itself;
otherwise it warns and embeds none (`Makefile`, target `dashboard`).

Start it:

```sh
target/release/mock-server -serverPort 1080
```

The command line is MockServer's (`mock-server run -p 1080` and the legacy `-serverPort 1080` are the same). See
[Configuration](configuration.md).

## Build the container image

`make image` builds the `Dockerfile` for your machine's architecture. The image is `FROM scratch`, holds the one
binary, runs as user 65532, and builds the dashboard in its own stage:

```sh
make image                 # tags mock-server:latest, :<MockServer version>, :mockserver-<MockServer version>
make image IMAGE=mine/mock-server
docker run --rm -p 1080:1080 mock-server:latest
```

`make image` also builds the `clustered` target as `clustered-latest` and `clustered-<version>`: the same image whose
only difference is the value of `MOCKSERVER_DASHBOARD_ANALYTICS_DISTRIBUTION` (`Dockerfile`; clustering itself is in
every image). The release publishes the plain image only.

## From Java tests

Two routes, both without changing test code (`docs/java-launcher.md`):

- **Testcontainers.** Use `MockServerContainer` with the image, declared as a substitute for MockServer's:
  `DockerImageName.parse("quay.io/oxidestack/mock-server:9.2.0-rc.1").asCompatibleSubstituteFor("mockserver/mockserver")`.
  `make conformance` runs MockServer's Java client suite this way.
- **In the JVM.** `java-launcher/` is a drop-in for `org.mock-server:mockserver-netty`: `ClientAndServer`, the JUnit 4
  rule, the JUnit 5 extension and the Spring listener start the binary as a process behind the same API. Exclude
  `mockserver-netty` and add the launcher; the lookup of the binary is the `mockServer.binary` system property, the
  `MOCK_SERVER_BINARY` environment variable, then `mock-server` on `PATH`. `make java-launcher` runs its tests and
  installs it into the local Maven repository; the artifact is not published yet. The limits are listed in
  `docs/java-launcher.md`.

## Verify

```sh
curl -s -X PUT localhost:1080/mockserver/status
```

answers a JSON body naming the listening ports. In a container, `docker exec <name> /mock-server healthcheck` exits 0
when that request answers 200 (`src/main.rs`, `healthcheck`).

Next: [Configuration](configuration.md), [API](api.md), [Operations](operations.md), [Troubleshooting](troubleshooting.md).
