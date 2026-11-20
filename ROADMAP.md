# Roadmap

Where mock-server is and where it is going. mock-server is a Rust reimplementation of
[MockServer](https://www.mock-server.com) that behaves the same on the wire, so that a client, a test suite or a
deployment that works with the MockServer image moves to it without a change. The stages below run in order; a
finished stage carries the month it was finished.

To suggest something for the roadmap, start a discussion in
[Ideas](https://github.com/oxidestack/mock-server/discussions/categories/ideas). [GOVERNANCE.md](GOVERNANCE.md) says
how a larger change is decided.

## Done

### The reference, recorded — 2026

MockServer 9.2.0's own image as the reference: the project's behaviour is recorded from it as scenarios that every
build replays, and MockServer's own test suites run against the server.

### The server — 2026

The control plane and data plane of MockServer: expectations, matching, verification, forwarding, proxying, response
templates, callbacks, OpenAPI matching, HTTP/1.1, HTTP/2, HTTP/3, TLS, gRPC, DNS, AsyncAPI brokers, chaos, SCIM and
SAML mocks, imports from HAR, Postman, WireMock, Mountebank and Mockoon, and the dashboard.

### The image and the Java launcher — 2026

A container image built `FROM scratch`, and a launcher that starts the binary behind `ClientAndServer` and the JUnit
and Spring integrations, as a drop-in for `mockserver-netty`.

## Now: publication

- The repository public on GitHub under Apache-2.0, with the documentation under CC-BY-4.0, a documentation site, and
  user guides to install, configure, operate, troubleshoot and upgrade.
- GitHub Actions on every push and pull request: every quality gate, every test, and the image built and tested
  natively on amd64 and arm64.
- Repository security: code scanning, OpenSSF Scorecard, dependency review, actions pinned by commit, branch
  protection that requires every check, and a sign-off (DCO) check on every pull request.
- The remaining differences from MockServer closed, each listed in [`docs/divergences.md`](docs/divergences.md)
  until it is.

## Next: the first release

- The first release candidate, `v9.2.0-rc.1`, matching MockServer 9.2.0: the image on `quay.io/oxidestack/mock-server`
  for both architectures, mirrored to ghcr.io under the same digests and signed the same way, and a GitHub release
  with its notes, SBOMs, signatures and provenance. A release stands on quay.io.
- The release `v9.2.0` after the candidate, and a documentation site with a version for every minor.
- The licence exceptions the CNCF needs for the components the allowlist does not name settled
  ([GOVERNANCE.md](GOVERNANCE.md)), then an application to the CNCF Sandbox, with the project's entry in the Cloud
  Native Landscape.

## Later

- An OpenSSF Best Practices badge.
- The Kubernetes admission webhook and the Java launcher's artifacts published on their own.
- Following MockServer's releases: each new one re-pins the reference and brings the project up to it.
- More maintainers, from more than one organisation ([GOVERNANCE.md](GOVERNANCE.md)).
- What adopters ask for: a difference from MockServer is the most useful report there is.
