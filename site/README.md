# The documentation site

[Astro Starlight](https://starlight.astro.build) over the documentation this repository already has: the
[README](../README.md) and the guides in [`docs/guide/`](../docs/guide/). It is served as a project page at
<https://oxidestack.github.io/mock-server/> once the repository is public and Pages is on.

```sh
make site    # site/dist/, built in the pinned node image; a broken internal link or anchor fails it
```

Node runs only in a container: `make site` runs [`build.sh`](build.sh) in the node 22 image that the Makefile pins by
digest (`SITE_NODE_IMAGE`), and `npm ci` installs exactly [`package-lock.json`](package-lock.json)'s tree, every
package pinned by version and integrity hash. npm's cache is `target/site/npm-cache`. To look at the pages while
editing them, run the dev server in that image, from the repository root:

```sh
docker run --rm -it -p 4321:4321 --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD:/src" -w /src/site \
  "$(sed -n 's/^SITE_NODE_IMAGE ?= //p' Makefile)" sh -c 'sh build.sh && npm run dev'
```

and open <http://localhost:4321/mock-server/>.

## A page has one home, and it is not here

Nothing is copied into this directory by hand. Every build runs [`scripts/stage.mjs`](scripts/stage.mjs), which reads
`README.md`, `docs/guide/*.md` and their translations ([Languages](#languages)) and writes them into
`src/content/docs/` with these changes and no others:

| Change | Why |
| --- | --- |
| The first `#` heading becomes the page's title | Starlight takes the title from frontmatter |
| `[Configuration](configuration.md#server)` becomes `/mock-server/configuration/#server`; a link to any other file of the repository becomes a link to it on GitHub | right on GitHub, a 404 on the site, which carries only the documentation |
| `<name>` outside code becomes `&lt;name>` | a renderer reads it as an HTML tag and drops it |
| An image, `![…](site/src/assets/…)`, is linked relative to the staged page; an image of another file of the repository fails the staging | a GitHub page is no image, and a file under `src/` is bundled by the build |

`src/content/docs/`, `dist/`, `.astro/` and `node_modules/` are build output, ignored by git: edit `README.md` or
`docs/guide/…`, never a staged page. A new guide page is staged by being there; it appears in the navigation once
[`astro.config.mjs`](astro.config.mjs)'s `sidebar` names it.

## Versions

The site serves releases, never `main`: the latest release at the root, `/mock-server/`, and every minor under
`/mock-server/<x.y>/`, each built by its own tag's `site/` (its own lockfile and pages), with a version picker in
the header and, on an older release, a banner that points at the same page in the latest and at its upgrade guide.
Only stable tags `vX.Y.Z` count; a release candidate's notes live on its GitHub release. A minor is built from its
latest patch tag (`1.1` is `v1.1.3` once that is out).

```sh
make site-versions    # into target/site/pages/, as GitHub Pages serves it
```

[`versions/extract.sh`](versions/extract.sh) (on the host, it needs git) unpacks each release tag with `git archive`;
[`versions/build.sh`](versions/build.sh) (in the node image) builds each with `SITE_BASE` (its base path) and
`SITE_REF` (the tag, which the links to repository files name), and the latest once more at the root;
[`versions/inject.mjs`](versions/inject.mjs) then gives every page a `docs-version` meta tag and
[`versions/versions.js`](versions/versions.js), which draws the picker and the banner from `versions.json` at run time
(so a release built long ago lists the ones after it), and marks every `/<x.y>/` copy `noindex`. Its tests:
`node --test site/versions/inject.test.mjs`. A tag older than the site, or whose `astro.config.mjs` does not read
`SITE_BASE`, fails the build with a message naming it.

**No release tag yet.** `make site-versions` still succeeds: it builds the working tree once, at the root, with no
picker and no `versions.json`, and says so. The first stable tag changes that with no other edit. The deployment that
publishes `target/site/pages/` is not wired up yet.

## Languages

English is the original, at the site's root. The README is translated into Russian, Chinese and Spanish beside it:
`README.ru.md`, `README.zh-CN.md`, `README.es.md`. A guide page is translated as a file of `docs/i18n/` at the page's
own path under its language: `docs/i18n/zh/guide/upgrading.md` translates `docs/guide/upgrading.md`. The languages and
their READMEs are [`locales.mjs`](locales.mjs)'s, each labelled with its code and its own name, `RU (Русский)`;
adding one is a line there, a README and a directory. The translations themselves are written separately: until they
exist, the other languages show the English page, with Starlight's note that it is not translated yet.

On GitHub, an original and its translations link each other in a languages line at their head, between
`<!-- languages:begin -->` and `<!-- languages:end -->`. On the site the language picker does that, so the staging
takes the line out. The staging fails when an original's line misses a translation that exists; a link to a
translation not written yet is allowed for now (`scripts/stage.mjs`, `languages()`), until every translation is written and the check is made strict again.
A translated page is served under its language, `/mock-server/ru/upgrading/`.

A translation records which version of its original it translates: `<!-- translation of README.md: 1a2b3c4d5e6f -->`,
the first 12 hex digits of the original's SHA-256 (`sha256sum README.md | cut -c1-12`). The staging fails on a
translation without one; when the original's digest is another, the staging logs the translation as possibly out of
date and the page carries Starlight's banner saying so, in its language, with a link to the original.

## The Benchmarks page

[`public/benchmarks/results.json`](public/benchmarks/results.json) holds the results of the newest run of
[`bench/run.sh`](../bench/run.sh) on record, committed as the script wrote them and served beside the page for
download. [`scripts/benchmarks.mjs`](scripts/benchmarks.mjs) reads it on every build and writes the Benchmarks page:
the run (date, commit, machine, load, both images) and, for each log level, the requests a second and the memory of
each server and setting. Nothing on the page is typed by hand: every figure goes through the generator's `v()`, and
the build fails on a digit of the page that is not a value of the results. Its tests:
`node --test site/scripts/benchmarks.test.mjs`, which `build.sh` runs. The page is in English only; the other
languages show it with Starlight's note that it is not translated.

A new run is published by running the script with `RESULTS`, then replacing the file and building:

```sh
make image
RESULTS=site/public/benchmarks/results.json bench/run.sh
make site
```

The file committed today was not written by the script: its run kept only a summary, so it was converted from that
by hand, and its `meta.converted` says what the run measured and what it did not record. The next run replaces it.

## The checks

[starlight-links-validator](https://github.com/HiDeoo/starlight-links-validator) fails the build on an internal link
to a page that does not exist or to an anchor that is not a heading of its page, and the staging fails on a link to a
file that is not in the repository. Before `npm ci` fetches anything, [`scripts/licences.mjs`](scripts/licences.mjs)
holds every package of the lockfile to `deny.toml`'s licence allowlist (the CNCF's allowed third-party licences); the
few build tools outside it (libvips, lightningcss, three BlueOak-licensed helpers, CSS syntax data) are listed there
by name with the licence they were reviewed under: each runs only during the build, and nothing of theirs is in
`dist/`, which the CNCF policy treats as internal tooling needing no exception.

## Where it is served from

`oxidestack.github.io` is shared by every project of the organisation, so this site is a project page under
`/mock-server/`: that is `base` in `astro.config.mjs`, and every internal link carries it. The deployment
(GitHub Pages, a CI job) is not wired up yet.

## The logo

None yet: `astro.config.mjs` marks where `logo` and `favicon` go.
