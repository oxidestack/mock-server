# Contributing to mock-server

Thank you for helping. This page says where to ask, how to build and test the server, how its behaviour is
held to MockServer's, and how to write the commits of a pull request.

## Where to go

- **A question** (how to deploy it, why a request does not match, whether it fits your case):
  [DeepWiki](https://deepwiki.com/oxidestack/mock-server) answers from the code and the documentation, which win where
  the two disagree; what it does not settle, start a
  [discussion in Q&A](https://github.com/oxidestack/mock-server/discussions/categories/q-a).
- **An idea** you would like to talk through before it becomes a request:
  [Ideas](https://github.com/oxidestack/mock-server/discussions/categories/ideas).
- **A bug**: [open an issue](https://github.com/oxidestack/mock-server/issues/new/choose) with the expectation, the
  request and the answer, and what MockServer answers to the same. A difference from MockServer is the most useful
  bug report there is.
- **A vulnerability**: never in a public issue. [`SECURITY.md`](SECURITY.md) says how to report it privately.

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## What the project promises

mock-server is a drop-in replacement for [MockServer](https://www.mock-server.com): a client, a test suite or a
deployment that works with the MockServer image works with this one. The MockServer image the project is pinned to
(`oracle.env`) is the reference: where it, MockServer's documentation and this project's documentation disagree, the
image wins. Every change in behaviour starts by asking that image what it does. Where mock-server still answers
differently, [`docs/divergences.md`](docs/divergences.md) says so; a row there is work to do, never an accepted
difference.

## Building

The repository carries MockServer's monorepo as a git submodule, which the tests and the dashboard build read (the
project's own Rust libraries are crates.io dependencies), so clone it with its submodule:

```sh
git clone --recursive https://github.com/oxidestack/mock-server.git
```

In a clone made without `--recursive`, run `git submodule update --init` once.

- `cargo build` builds the server; the Rust version it needs is `rust-version` in `Cargo.toml`.
- `make image` builds the container image for your machine's architecture; it needs Docker.
- `make dashboard` builds MockServer's dashboard bundle into the binary (Node 22); without it the build embeds none
  unless it can build one itself.

## Testing

- `cargo test` runs the unit tests, the Rust ports of MockServer's own tests (`tests/upstream/`) and every recorded
  scenario, replayed against the server. It needs no MockServer container.
- A scenario is a sequence of requests in `tests/scenarios/<name>.json` with the answers MockServer gave, recorded as
  `<name>.golden.json`. New behaviour goes in as a scenario first, failing; then the code makes it pass.
  `make oracle` starts the pinned MockServer image and `make record` records a scenario from it; the scenario
  directory's `README.md` says how a scenario is written, how one is recorded and how the harness normalises ids,
  timestamps and ports. Record one scenario at a time, and do not change an existing golden unless the change is the
  point of your pull request.
- `make conformance`, `make upstream-tests`, `make java-launcher`, `make container-tests` and `make cluster-tests` run
  MockServer's own Java and container test suites against the server, and `make broker-tests`, `make blob-tests` and
  `make proxy-resolver-e2e` the tests against live brokers, blob store emulators and privileged containers. They are
  slow and need Docker (and a JDK for the Java suites); CI runs every one of them on each push.
- The tests sit at a few seams only: the scenarios, the Java suites, the ports of MockServer's tests, the matcher's
  interface and the JSON printer. Add a test at one of them, not next to a private function.

## The checks

Every pull request runs formatting, clippy with warnings as errors, every test of the repository (the unit tests, the
scenarios, the ports of MockServer's tests, the Java and container suites above, the site build and the tools'
tests), the licence gate (`make licenses`: `cargo deny` against the CNCF allowlist, and the files under
`third_party/`) and the container image build. A test that needs Docker fails where Docker is missing rather than
skipping (`MOCK_SERVER_REQUIRE_DOCKER=1`). A red check names the gate and why.

The code is formatted by hand in the style of the file around it. Do not run `cargo fmt` over the repository: it
rewrites files you did not change.

## Commit messages

Every commit follows [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/) and is signed off
([DCO](https://developercertificate.org/)). The release notes are drafted from the commits' release-note blocks.

````text
<type>(<scope>)!: <description>

<body>

```release-note
<what changes for users and operators, and what they have to do>
```

BREAKING-CHANGE: <what changes and what to do>
Closes: #<issue>
Signed-off-by: Your Name <you@example.org>
````

- **Type**: `feat` (something new a client or operator can use), `fix` (what ships behaved wrongly), `perf`,
  `refactor`, `test`, `docs`, `build`, `ci`, `chore`, `revert`.
- **Scope**, optional, the part changed: `matcher`, `control`, `dataplane`, `http1`, `h2`, `http3`, `tls`, `grpc`,
  `dns`, `chaos`, `templates`, `openapi`, `asyncapi`, `import`, `forward`, `callbacks`, `auth`, `mcp`, `state`,
  `config`, `telemetry`, `migrate`, `dashboard`, `image`, `java-launcher`, `k8s-webhook`, `conformance`, `bench`,
  `crates`, `deps`, `release`. Leave it out when the change spans several.
- **Description**: imperative, lower-case, no full stop; the whole first line at most 72 characters.
- **Body**: what changed and why, wrapped at 72 columns. A line that cannot be wrapped is exempt: one without a space
  (a URL, a path), one indented by four spaces or more, and a `Signed-off-by:` or `Co-authored-by:` trailer.
- **Release note**: a `release-note` block, the body's last paragraph, written for the people who run the server,
  not for its developers. Required on `feat`, `fix`, `perf` and breaking commits, optional on the others. Write
  `NONE` in it when no released version is affected. No line in it starts with `#`: git drops such lines when the
  message goes through the editor.
- **Breaking**: a client or a deployment must change to keep working (an endpoint, an answer MockServer gives, a
  property, the image's user or paths, a metric's name; matching MockServer where we differed is a `fix`): `!` before
  the colon, a `BREAKING-CHANGE:` footer, and a release note saying what to do.
- **Footers**: the message's last paragraph, one block, in this order: `BREAKING-CHANGE:`, `Refs:`, `Closes:`,
  `Co-authored-by:`, `Signed-off-by:`. Never put a paragraph opening with `Word:` or `Word #` before the release
  note: the release notes are drafted with a parser that reads the footers from such a paragraph on.
- **Reverts**: `revert: <the reverted commit's first line>`, the reason, and `Refs: <hash>`.

Pull requests are merged with "Rebase and merge", so each commit lands as written: squash your fixups
(`git commit --fixup`, `git rebase -i --autosquash`) before asking for a merge.

### Signing off

The sign-off is your statement, under the [Developer Certificate of Origin](https://developercertificate.org/), that
you wrote the change or otherwise have the right to submit it under the project's licences. There is no contributor
licence agreement. Sign off with the name and address your commits are authored with:

```sh
git config user.name "Your Name"
git config user.email you@example.org
git commit -s
```

A check on every pull request fails a commit whose last footer is not its author's `Signed-off-by:`. A commit you
forgot to sign off is signed off again with `git commit --amend -s --no-edit`, or, for every commit of a branch,
`git rebase --signoff main`; then push the branch with `--force-with-lease`.

## Pull requests

- One change per pull request, with the tests that show it: a bug fix comes with the scenario that failed before it.
- A change to what a client sends or gets back, a property, an environment variable or a flag updates the guide that
  documents it (`docs/guide/`) in the same pull request, and its translations or says which it leaves behind.
- A new difference from MockServer is never merged as accepted: it is a row in `docs/divergences.md` with the reason
  it is not yet matched.
- For a larger change, start with an issue or a discussion, so that the approach is agreed before the code is written.

## Translating the documentation

The documentation is in English, Russian, Chinese and Spanish, and a reader who speaks one of them natively is the
best reviewer its translation can have. English is the original: a change starts there, and a translation follows
it. A translation of the README sits beside it (`README.ru.md`, `README.zh-CN.md`, `README.es.md`), a translation of
a guide page in `docs/i18n/<language>/guide/` (`ru`, `zh`, `es`). Fixing a translation, translating a page that has
none yet, or bringing an outdated one up to date are all welcome pull requests.

- A translation keeps the original's structure: its headings in the same order, its code, commands, property names
  and values exactly as they are, and links that resolve from its own file.
- It opens with the languages line every version of the page shares.

## Licences

By contributing you agree that your code is licensed under the [Apache License, Version 2.0](LICENSE) and your
documentation under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/),
as the rest of the repository. A document, a data file or code taken from elsewhere keeps its own licence: say where
it comes from and under which licence in the pull request, and it is attributed in [`NOTICE`](NOTICE). Third-party
files are stored unmodified under `third_party/`, and a dependency must be under one of the
[CNCF's allowed licences](https://github.com/cncf/foundation/blob/main/policies-guidance/allowed-third-party-license-policy.md).
