# Translating the documentation

The documentation is in English, Russian, Chinese and Spanish, and a reader who speaks one of them natively is the
best reviewer its translation can have. English is the original: a change starts there, and a translation follows
it. A translation of the README sits beside it (`README.ru.md`, `README.zh-CN.md`, `README.es.md`), a translation of
a guide page is in `docs/i18n/<language>/guide/` (`ru`, `zh`, `es`) under the page's own name. Fixing a translation,
translating a page that has none yet, or bringing an outdated one up to date are all welcome pull requests.

- A translation keeps the original's structure: its headings in the same order, its code, commands, setting names,
  environment variables and values exactly as they are, and links that resolve from its own file (a translation links
  the translated page of its own language). Product and legal names stay untranslated. HTML-comment placeholders stay
  as they are.
- It opens, after its title, with the languages line every version of the page shares, and a record of the original
  it translates, `<!-- translation of docs/guide/upgrading.md: 1a2b3c4d5e6f -->`: the first 12 hex digits of the
  original's SHA-256 (`sha256sum docs/guide/upgrading.md | cut -c1-12`, on macOS `shasum -a 256 …`). When the original
  changes and the record does not, the site marks the translation as possibly out of date and links the original;
  bringing it up to date means translating what changed, then writing the original's new digest.
- A new translated page is listed in the original's languages line, and `make site` checks that it is, and that
  the line links no translation that does not exist.
- A change to an original updates its translations and their records in the same commit, or the commit names the
  ones it leaves behind.

`site/README.md` ("Languages") says how the site serves the translations.
