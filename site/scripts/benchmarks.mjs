// The Benchmarks page, generated from the committed results of a bench/run.sh run (public/benchmarks/results.json),
// which the site also serves beside the page for download. Nothing on the page is typed by hand: every value read from
// the results goes through `v()`, which marks it, and the check strips the marked spans, the markup and the link
// targets from the page and fails on any digit left over, so a figure written into a template below fails the build.
// The few labels that hold a digit and are not figures (p50, x86_64, 2>&1) are listed in LABELS.
//
//   node scripts/benchmarks.mjs    the page into src/content/docs/benchmarks.md, after the check
//
// package.json's prebuild runs it after scripts/stage.mjs, which empties src/content/docs/; exit 1 on a finding.
// A new run is published by replacing public/benchmarks/results.json with the file `RESULTS=<file> bench/run.sh`
// writes (site/README.md, "The Benchmarks page").

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
export const RESULTS = join(here, '..', 'public', 'benchmarks', 'results.json')
const PAGE = join(here, '..', 'src', 'content', 'docs', 'benchmarks.md')

/** The site's base path (astro.config.mjs `base`), which a release's documentation sets to its version's. */
const BASE = process.env.SITE_BASE || '/mock-server'
const GITHUB = 'https://github.com/oxidestack/mock-server'
const REF = process.env.SITE_REF || 'main'

const OPEN = '\u0001'
const CLOSE = '\u0002'

/** A value read from the results, marked so the check knows it was not typed here. */
export const v = (x) => `${OPEN}${x}${CLOSE}`

/** Labels with a digit that are names, not figures. */
const LABELS = [/\bp(50|99)\b/g, /\bx86_64\b/g, /\bamd64\b/g, /\barm64\b/g, /\b404\b/g]

/** The digits of `text` that no value of the results accounts for, each with its context. */
export function strays(text) {
  let rest = text
    .replace(new RegExp(`${OPEN}[^${CLOSE}]*${CLOSE}`, 'g'), '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<[^>]*>/g, ' ')
    .replace(/\]\([^)]*\)/g, ']')
  for (const label of LABELS) rest = rest.replace(label, '')
  const out = []
  for (const m of rest.matchAll(/\d/g)) out.push(rest.slice(Math.max(0, m.index - 30), m.index + 30).replace(/\s+/g, ' '))
  return out
}

/** The text a reader sees: the marks removed. */
export const plain = (text) => text.replaceAll(OPEN, '').replaceAll(CLOSE, '')

/** A count with thousands separated by a thin space, as the rest of the documentation writes them. */
const count = (n) => v(Math.round(n).toLocaleString('en-US').replace(/,/g, ' '))

/** A memory range in MiB, `[low, high]`, as one figure when both rounds agree. */
const mib = (range) => {
  if (!range) return '—'
  const [lo, hi] = range
  return lo === hi ? `${count(lo)} MiB` : `${count(lo)}–${count(hi)} MiB`
}

const reqs = (n) => (n === null || n === undefined ? '—' : count(n))

/** The rows' cases in a fixed order: log level, then expectations, then matched before unmatched. */
function cases(rows) {
  const seen = new Map()
  for (const r of rows) seen.set(`${r.log_level}|${r.expectations}|${r.request}`, r)
  const rank = (r) => [r.log_level === 'INFO' ? 0 : 1, r.expectations, r.request === 'matched' ? 0 : 1]
  return [...seen.values()].sort((a, b) => {
    const x = rank(a)
    const y = rank(b)
    return x[0] - y[0] || x[1] - y[1] || x[2] - y[2]
  })
}

const sameCase = (a, b) => a.log_level === b.log_level && a.expectations === b.expectations && a.request === b.request

/** One case in words: "1 expectation, matched". */
const label = (r) =>
  `${count(r.expectations)} ${r.expectations === 1 ? 'expectation' : 'expectations'}, ${r.request === 'matched' ? 'matched' : 'unmatched'}`

/** The columns: every (server, configuration) pair of the results, ours first, its default first. */
function columns(rows) {
  const out = []
  for (const r of rows) if (!out.some((c) => c.server === r.server && c.config === r.config)) out.push({ server: r.server, config: r.config })
  const ours = (c) => (c.server === 'mock-server' ? 0 : 1)
  return out.sort((a, b) => ours(a) - ours(b) || (a.config === 'default' ? 0 : 1) - (b.config === 'default' ? 0 : 1))
}

const columnName = (c) => (c.config === 'default' ? v(c.server) : `${v(c.server)}, \`${v(c.config)}\``)

function machine(meta) {
  const m = meta.machine
  const parts = [
    `${v(m.kind)}, ${v(m.arch)}`,
    `${v(m.cpu_model)}`,
    `${v(m.vcpus)} vCPUs and ${v(m.memory_gib)} GiB`,
    `${v(m.os)}, kernel ${v(m.kernel)}, Docker ${v(m.docker)}`,
  ]
  return parts.join('; ')
}

/** The warm-up: one length for both servers, or each server's. */
const warmup = (w) =>
  typeof w === 'object'
    ? `warm-ups of ${Object.entries(w).map(([server, s]) => `${v(s)} s for ${v(server)}`).join(' and ')}`
    : `a ${v(w)} s warm-up`

/** The page, its values marked (`plain()` removes the marks). */
export function page(results) {
  const { meta, rows } = results
  const load = meta.load
  const cols = columns(rows)
  const withReqs = cols.filter((c) => rows.some((r) => r.server === c.server && r.config === c.config && r.req_per_sec != null))
  const levels = [...new Set(rows.map((r) => r.log_level))]
  const L = []
  L.push(
    '---',
    'title: Benchmarks',
    'description: "mock-server and the MockServer image under the same load: requests a second and memory, from the committed results of bench/run.sh."',
    '---',
    '',
    `Every number on this page is read from one file, the [results](${BASE}/benchmarks/results.json) of the newest`,
    `run of [\`bench/run.sh\`](${GITHUB}/blob/${REF}/bench/run.sh) on record. The site's build generates the page from`,
    'it and fails on a number that is not read from it. Both servers run in their default configuration unless a column',
    'names a setting, each alone in its container under the same CPU limit, and the load generator runs in a container on',
    'the same Docker network.',
    '',
    '## The run',
    '',
    '| | |',
    '| --- | --- |',
    `| When | ${v(meta.date)} |`,
    `| Code | commit \`${v(meta.commit)}\`${meta.commit_note ? ` (${v(meta.commit_note)})` : ''}; the image ${v(meta.image)} |`,
    `| MockServer | \`${v(meta.oracle_image)}\` |`,
    `| Machine | ${machine(meta)} |`,
    `| Load | \`oha\`, ${v(load.connections)} connections for ${v(load.duration_s)} s after ${warmup(load.warmup_s)}; each server limited to ${v(load.cpus)} CPUs, ${load.memory_limit ? `${v(load.memory_limit)} of memory` : 'no memory limit'}; ${v(load.rounds)} ${load.rounds === 1 ? 'round' : 'rounds'} a row |`,
    `| Memory | ${v(meta.memory)} |`,
  )
  if (meta.converted) L.push(`| Note | ${v(meta.converted)} |`)
  L.push(
    '',
    'An expectation is `GET /e<n>` answered with `e<n>`; a matched request asks for the last one created, an unmatched',
    'one for a path none matches, which is answered 404 and, as in MockServer, logged with the closest expectation.',
    '',
  )
  for (const level of levels) {
    const here = cases(rows.filter((r) => r.log_level === level))
    L.push(`## At ${v(level)}`, '', 'Requests a second:', '')
    L.push(`| | ${withReqs.map(columnName).join(' | ')} |`, `| --- |${withReqs.map(() => ' ---: |').join('')}`)
    for (const c of here) {
      const cell = (col) => reqs(rows.find((r) => sameCase(r, c) && r.server === col.server && r.config === col.config)?.req_per_sec)
      L.push(`| ${label(c)} | ${withReqs.map(cell).join(' | ')} |`)
    }
    L.push('', 'Memory after the load:', '')
    L.push(`| | ${cols.map(columnName).join(' | ')} |`, `| --- |${cols.map(() => ' ---: |').join('')}`)
    for (const c of here) {
      const cell = (col) => mib(rows.find((r) => sameCase(r, c) && r.server === col.server && r.config === col.config)?.rss_mib)
      L.push(`| ${label(c)} | ${cols.map(cell).join(' | ')} |`)
    }
    L.push('')
  }
  L.push(
    '## Reading the figures',
    '',
    '- At `INFO` both servers print a console line for every request through Docker\'s `json-file` log driver, and',
    '  mock-server waits on that pipe: its `INFO` throughput is the pipe\'s, and `WARN` (or a log driver that does not',
    '  block) shows the server without it.',
    '- Memory is mostly the retained event log. Its size is `maxLogEntries` (`MOCKSERVER_MAX_LOG_ENTRIES`), derived from',
    '  the available memory as MockServer derives it; a column with a smaller value shows what lowering it does',
    `  ([Configuration](${BASE}/configuration/#memory-bounding-properties)).`,
    '- One run on one machine: another machine, another CPU limit or another load gives other figures. The',
    '  comparison between the two servers in the same run holds better than either absolute figure.',
    '',
    '## Run it yourself',
    '',
    'Docker is all it needs. Build the image, then run the same load against it and the MockServer image pinned in',
    `[\`oracle.env\`](${GITHUB}/blob/${REF}/oracle.env):`,
    '',
    '```sh',
    'make image',
    'RESULTS=results.json bench/run.sh',
    '```',
    '',
    'It prints a table as it goes and writes a `results.json` like [this one](' + BASE + '/benchmarks/results.json).',
    '`CPUS`, `DURATION`, `CONNECTIONS`, `RS_LOG_LEVEL`, `ORACLE_LOG_LEVEL` and `RS_DOCKER_ARGS` change the load and the',
    'settings (the script\'s header says each).',
  )
  return `${L.join('\n')}\n`
}

/** Every finding of the check: a digit on the page not read from the results, a row the page cannot place. */
export function check(results) {
  const findings = []
  if (results.schema !== 1) findings.push(`results.json has schema ${results.schema}, this script reads 1`)
  for (const r of results.rows ?? []) {
    for (const key of ['server', 'config', 'expectations', 'request', 'log_level']) {
      if (r[key] === undefined || r[key] === null) findings.push(`a row has no ${key}: ${JSON.stringify(r)}`)
    }
    if (!['matched', 'unmatched'].includes(r.request)) findings.push(`a row's request is neither matched nor unmatched: ${r.request}`)
  }
  if (findings.length) return findings
  for (const s of strays(page(results))) findings.push(`the Benchmarks page has a number not read from the results: …${s}…`)
  return findings
}

function main() {
  if (!existsSync(RESULTS)) throw new Error(`no results at ${RESULTS}`)
  const results = JSON.parse(readFileSync(RESULTS, 'utf8'))
  const findings = check(results)
  if (findings.length) {
    for (const f of findings) console.error(`benchmarks: ${f}`)
    process.exit(1)
  }
  mkdirSync(dirname(PAGE), { recursive: true })
  writeFileSync(PAGE, plain(page(results)))
  console.log(`benchmarks: the Benchmarks page from results.json (${results.meta.date}, commit ${results.meta.commit}, ${results.rows.length} rows)`)
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main()
