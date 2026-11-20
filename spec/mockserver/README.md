# Upstream MockServer reference material (the oracle's revision)

Verbatim copies from `mock-server/mockserver-monorepo` at tag `mockserver-9.2.0` (commit `789142c14`, the oracle's
pinned revision), earlier at tag `mockserver-9.1.0` (commit `e4d4986ce`), at master commit
`b765b8271` (8.0.1-SNAPSHOT) and first at tag `mockserver-8.0.0` (commit `a9db199`), Apache License 2.0 —
see `LICENSE.md` in this directory.

| Path | Upstream source |
|---|---|
| `schema/*.json` | `mockserver/mockserver-core/src/main/resources/org/mockserver/model/schema/` |
| `mockserver-openapi.yaml` | `jekyll-www.mock-server.com/mockserver-openapi.yaml` (control-plane OpenAPI spec) |
| `llms.txt`, `llms-full.txt` | `jekyll-www.mock-server.com/` (plain-text manual digest) |
| `manual/` | `jekyll-www.mock-server.com/{mock_server,proxy,where}/*.html` (the product manual) |

Do not edit these files; they are the compatibility reference. The scenarios under `tests/scenarios/` and the
divergence list in `docs/divergences.md` record how mock-server-rs compares with it.
