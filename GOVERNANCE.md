# Governance

This page says who decides what in mock-server, how decisions are made, and how that changes as the project grows.
mock-server follows the [CNCF Code of Conduct](CODE_OF_CONDUCT.md) in all of it.

## Today: one maintainer

mock-server has a single maintainer, listed in [MAINTAINERS.md](MAINTAINERS.md). Until a second maintainer joins, the
maintainer decides, and decides in the open: a change is proposed, discussed and merged as a pull request, a larger
question is settled in an issue or a discussion first, and the reasoning is written down there. No decision about the
project is made in a private channel, apart from the handling of a vulnerability ([SECURITY.md](SECURITY.md)) or a
code-of-conduct report ([CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)), which stay private until they are resolved.

The project means to have maintainers from more than one organisation. Everything below is written for that.

## Roles

- **Users** run the server. They help most by asking in
  [Discussions](https://github.com/oxidestack/mock-server/discussions), reporting a difference from MockServer,
  and adding themselves to [ADOPTERS.md](ADOPTERS.md).
- **Contributors** send issues, pull requests, reviews, documentation and answers. Anyone can be one;
  [CONTRIBUTING.md](CONTRIBUTING.md) says how. Every commit is signed off under the
  [Developer Certificate of Origin](https://developercertificate.org/).
- **Maintainers** review and merge pull requests, triage issues, answer security reports, cut releases, and hold the
  project's accounts and settings. They are listed in [MAINTAINERS.md](MAINTAINERS.md).

## How decisions are made

- **Day to day — lazy consensus.** A pull request merges once a maintainer other than its author approves it and its
  checks pass, and no maintainer has objected. While there is a single maintainer, the maintainer's own changes go
  through the same pull requests and checks, without a second approval.
- **Larger changes** — the control plane, a property, the image's user or paths, a new
  dependency outside the licence allowlist, a release's scope: proposed in an issue or a discussion and open for at
  least a week before the pull request merges, so that users and contributors can say what it costs them.
- **When consensus fails**, the maintainers vote. A decision needs a simple majority of all maintainers; a change to
  this page, adding or removing a maintainer, and a change to the licence need two thirds of them. A vote is held in a
  public issue and stays open for at least a week, or until every maintainer has voted.
- **A maintainer with a conflict of interest** in a decision, or one a code-of-conduct report concerns, says so and
  takes no part in it. While there is a single maintainer, nobody else in the project can decide a report about
  them; who decides one is settled when there are more maintainers ([CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)).

## Becoming a maintainer

A contributor who has made sustained contributions — reviewed and merged changes, triaged issues, answered users —
and who knows the code, the image and the release process well enough to own them can be nominated by any maintainer
or nominate themselves in an issue. The maintainers decide by the two-thirds vote above. The new maintainer is added
to [MAINTAINERS.md](MAINTAINERS.md) in a pull request, and to the project's accounts.

## Stepping down

A maintainer can step down at any time by saying so in an issue; they are thanked and listed as an emeritus maintainer
in [MAINTAINERS.md](MAINTAINERS.md). A maintainer who has taken no part in the project for six months is asked
whether they want to continue; with no answer within a month, the other maintainers may move them to emeritus by the
two-thirds vote. A maintainer who breaks the code of conduct can be removed the same way.

## Dependencies

mock-server takes on a dependency only when it earns its place, and keeps every one current:

- **Licences.** A Rust dependency is licensed under one of the
  [CNCF's allowed third-party licences](https://github.com/cncf/foundation/blob/main/policies-guidance/allowed-third-party-license-policy.md);
  `cargo deny` holds every crate in the dependency graph to that list (`deny.toml`), and anything outside it needs an
  exception from the CNCF before it can be added. Data files outside Cargo are stored unmodified under
  `third_party/` with their licence and source recorded, the dashboard's npm packages and the Java launcher's Maven
  dependencies are checked the same way, and a component taken from elsewhere is attributed in [`NOTICE`](NOTICE).
- **Exceptions still pending.** Some components are under licences the allowlist does not name, and the project has
  not yet asked the CNCF for exceptions for them: the Public Suffix List (MPL-2.0), a few Rust crates under
  Unicode-3.0, Unlicense or CDLA-Permissive-2.0, and the dashboard's layout engine elkjs (EPL-2.0) and the Java
  launcher's `jakarta.servlet-api` (EPL-2.0 or GPL-2.0 with the Classpath Exception). Each is listed by exact version
  in `deny.toml`, `third_party/MANIFEST` or `tools/noncargo-licence-exceptions.txt` with its status. These are known
  gaps, not approvals: each is settled by an exception or a different dependency before the project applies to the
  CNCF.
- **Sources and versions.** `Cargo.lock` is committed, and two versions of one crate in the graph are refused unless
  `deny.toml` says why. The project's own libraries are crates.io packages built from public repositories, locked by
  version and checksum in `Cargo.lock` like any other crate. Container images and CI tools are pinned by digest.
- **Advisories.** `cargo deny` fails a pull request on a known advisory, a yanked crate or an unmaintained one. A fix
  for a vulnerable dependency goes into the next release ([SECURITY.md](SECURITY.md)).
- **Updates.** Pins are kept current by pull requests that go through the same checks as any other change; a
  dependency's breaking change is a larger change, as above. The MockServer image the project is held to, and the
  MockServer sources it is built from, move only by a maintainer's decision: a new MockServer release is a re-pin
  that the whole test suite has to survive.

## Changing this page

This page changes by pull request, under the two-thirds vote above once there is more than one maintainer.
