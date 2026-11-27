// The Benchmarks page, generated from the committed results of a bench/run.sh run (public/benchmarks/results.json),
// which the site also serves beside the page for download. Nothing on the page is typed by hand: every value read from
// the results goes through `v()`, which marks it, and the check strips the marked spans, the markup and the link
// targets from the page and fails on any digit left over, so a figure written into a template below fails the build.
// The few labels that hold a digit and are not figures (p50, p99.9, x86_64, 404) are listed in LABELS.
//
//   node scripts/benchmarks.mjs    the page into src/content/docs/benchmarks.md, after the check
//
// package.json's prebuild runs it after scripts/stage.mjs, which empties src/content/docs/; exit 1 on a finding.
// A new run is published by replacing public/benchmarks/results.json and results-raw.tar.gz with the files
// `RESULTS=<file> bench/run.sh` writes (site/README.md, "The Benchmarks page").

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
const LABELS = [/\bp99\.9\b/g, /\bp(50|99)\b/g, /\bx86_64\b/g, /\bamd64\b/g, /\barm64\b/g, /\b404\b/g]

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

/** A decimal figure with `digits` decimals, or a dash where the run has none. */
const dec = (x, digits) => (x === null || x === undefined ? '—' : v(Number(x).toFixed(digits)))

const reqs = (n) => (n === null || n === undefined ? '—' : count(n))

/** Memory in MiB, or a dash. */
const mib = (x) => (x === null || x === undefined ? '—' : `${count(x)} MiB`)

/** bench/run.sh's requests, in the page's order, each with how a row names it. */
export const REQUESTS = {
  matched: 'matched',
  unmatched: 'unmatched',
  json: 'JSON body matched',
  headers: 'headers and a JSON body',
  verify: 'verify',
  retrieve: 'retrieve',
}
const KINDS = Object.keys(REQUESTS)

/** The rows' cases in a fixed order: log level, then expectations, then the request (REQUESTS' order). */
function cases(rows) {
  const seen = new Map()
  for (const r of rows) seen.set(`${r.log_level}|${r.expectations}|${r.request}`, r)
  const rank = (r) => [r.log_level === 'INFO' ? 0 : 1, r.expectations, KINDS.indexOf(r.request)]
  return [...seen.values()].sort((a, b) => {
    const x = rank(a)
    const y = rank(b)
    return x[0] - y[0] || x[1] - y[1] || x[2] - y[2]
  })
}

const sameCase = (a, b) => a.log_level === b.log_level && a.expectations === b.expectations && a.request === b.request

/** One case in words: "1 expectation, matched". */
const label = (r) => `${count(r.expectations)} ${r.expectations === 1 ? 'expectation' : 'expectations'}, ${REQUESTS[r.request]}`

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
    `${v(m.cpu_model ?? 'CPU not named')}`,
    `${v(m.vcpus)} vCPUs and ${v(m.memory_gib)} GiB`,
    `${v(m.os)}, kernel ${v(m.kernel)}, Docker ${v(m.docker)}, cgroup ${v(m.cgroup)}, log driver \`${v(m.log_driver)}\``,
  ]
  return parts.join('; ')
}

const image = (i) => (i ? `\`${v(i.name)}\` (\`${v(i.id.replace(/^sha256:/, '').slice(0, 12))}\`)` : '—')

const loadAverage = (l) => (l ? l.map((x) => v(x)).join(' / ') : '—')

/** A table of one figure: a row per case of this level, a column per server and configuration. */
function table(L, title, here, rows, cols, cell) {
  L.push(title, '')
  L.push(`| | ${cols.map(columnName).join(' | ')} |`, `| --- |${cols.map(() => ' ---: |').join('')}`)
  for (const c of here) {
    const at = (col) => rows.find((r) => sameCase(r, c) && r.server === col.server && r.config === col.config)
    L.push(`| ${label(c)} | ${cols.map((col) => (at(col) ? cell(at(col)) : '—')).join(' | ')} |`)
  }
  L.push('')
}

/** The page, its values marked (`plain()` removes the marks). */
export function page(results) {
  const { meta, rows } = results
  const p = meta.params
  const cols = columns(rows)
  const levels = [...new Set(rows.map((r) => r.log_level))]
  const range = (r, field, fmt) => {
    const xs = (r.rounds ?? []).map((x) => x[field]).filter((x) => x !== null && x !== undefined)
    if (xs.length < 2) return fmt(r[field])
    return `${fmt(r[field])} (${fmt(Math.min(...xs))}–${fmt(Math.max(...xs))})`
  }
  const L = []
  L.push(
    '---',
    'title: Benchmarks',
    'description: "mock-server and the MockServer image under the same load: requests a second, CPU time a request, latency and memory, from the committed results of bench/run.sh."',
    '---',
    '',
    `Every number on this page is read from one file, the [results](${BASE}/benchmarks/results.json) of the newest`,
    `run of [\`bench/run.sh\`](${GITHUB}/blob/${REF}/bench/run.sh) on record, as the script wrote it. The site's build`,
    'generates the page from it and fails on a number that is not read from it. Both servers run in their default',
    'configuration unless a column names a setting, each alone in a fresh container under the same CPU limit, and the',
    'load generator runs in a container on the same Docker network.',
    '',
    '## The run',
    '',
    '| | |',
    '| --- | --- |',
    `| When | ${v(meta.started)} to ${v(meta.finished)} |`,
    `| Code | commit \`${v(meta.commit.slice(0, 12))}\`${meta.uncommitted_changes ? ' with uncommitted changes' : ''} |`,
    `| mock-server | ${image(meta.images.ours)} |`,
    `| MockServer | ${image(meta.images.oracle)} |`,
    `| Machine | ${machine(meta)} |`,
    `| Load | \`oha\` ${v(meta.images.oha.name.split('@')[0].split(':').pop())}, ${v(p.connections)} connections for ${v(p.duration_s)} s after a ${v(p.warmup_s)} s warm-up, \`Host: ${v(p.host_header)}\`; each server limited to ${v(p.cpus)} CPUs, ${p.memory_limit ? `${v(p.memory_limit)} of memory` : 'no memory limit'}; ${v(p.rounds)} ${p.rounds === 1 ? 'round' : 'rounds'}, the servers' order alternating |`,
    `| Load average | ${loadAverage(meta.load_average_start)} at the start, ${loadAverage(meta.load_average_end)} at the end |`,
  )
  if (meta.note) L.push(`| Note | ${v(meta.note)} |`)
  if (meta.raw) L.push(`| Raw data | [every round's \`oha\` output and readings](${BASE}/benchmarks/${meta.raw}) |`)
  L.push(
    '',
    'An expectation is `GET /e<n>` answered with `e<n>`; a matched request asks for the last one created, an unmatched',
    'one for a path none matches, which is answered 404 and, as in MockServer, logged with the closest expectation.',
    'The other rows model an integration test: a JSON body matched among expectations told apart by one field, a',
    'response with headers and a JSON body, and `verify` and `retrieve` calls against an event log filled with posted',
    `orders, which count calls instead of seconds ([the rows](${GITHUB}/blob/${REF}/bench/README.md#the-rows)).`,
    'Each figure is the median over the rounds; where there were several, the lowest and highest follow in brackets.',
    '',
  )
  const withAllocs = rows.some((r) => r.allocs_per_req != null)
  for (const level of levels) {
    const atLevel = rows.filter((r) => r.log_level === level)
    const here = cases(atLevel)
    L.push(`## At ${v(level)}`, '')
    table(L, 'Requests a second:', here, atLevel, cols, (r) => range(r, 'req_per_sec', reqs))
    table(L, 'CPU time a request, µs (the container\'s CPU time over the requests completed):', here, atLevel, cols, (r) =>
      range(r, 'cpu_us_per_req', (x) => dec(x, 1)),
    )
    table(L, 'Latency p50 / p99 / p99.9, ms:', here, atLevel, cols, (r) => `${dec(r.p50_ms, 2)} / ${dec(r.p99_ms, 2)} / ${dec(r.p999_ms, 2)}`)
    table(L, 'Peak memory (VmHWM) after the load:', here, atLevel, cols, (r) => mib(r.rss_mib))
    if (atLevel.some((r) => r.rss_window_end_mib != null)) {
      table(L, 'Resident memory (VmRSS) at the end of the window, the event log full:', here, atLevel, cols, (r) => mib(r.rss_window_end_mib))
    }
    table(L, level === 'INFO' ? 'Console lines written during the window; requests no `received request` line logs:' : 'Console lines written during the window:', here, atLevel, cols, (r) =>
      r.unlogged_requests == null ? reqs(r.console_lines) : `${reqs(r.console_lines)}; ${reqs(r.unlogged_requests)} unlogged`,
    )
    if (withAllocs) {
      table(L, 'Allocator calls a request (allocations, reallocations), from the counting build:', here, atLevel, cols, (r) =>
        r.allocs_per_req == null ? '—' : `${dec(r.allocs_per_req, 1)}, ${dec(r.reallocs_per_req, 1)}`,
      )
    }
  }
  L.push(
    '## Reading the figures',
    '',
    '- CPU time a request holds up better than requests a second on a shared or noisy machine: it is the',
    '  container\'s own CPU time (its cgroup\'s `cpu.stat`) from the window\'s start until its console stops growing,',
    '  so the logging a server defers is counted too, divided by the requests `oha` completed.',
    '- At `INFO` both servers print every request through Docker\'s `json-file` log driver. MockServer records its',
    '  event log on one thread behind a ring buffer and drops entries when the buffer is full (it warns once): the',
    '  unlogged requests are the requests completed in the window minus its `received request` lines, so they are',
    '  requests the server neither printed nor kept for verification. The few requests still in flight when the',
    '  window ends are logged without being counted as completed, so a server that drops none shows none.',
    '- Memory is mostly the retained event log. Its size is `maxLogEntries` (`MOCKSERVER_MAX_LOG_ENTRIES`), derived from',
    '  the available memory as MockServer derives it; a column with a smaller value shows what lowering it does',
    `  ([Configuration](${BASE}/configuration/#memory-bounding-properties)).`,
    '- One run on one machine: another machine, another CPU limit or another load gives other figures. The',
    '  comparison between the two servers in the same run holds better than either absolute figure.',
    '',
    '## Run it yourself',
    '',
    'Docker and Python are all it needs. Build the image, then run the same load against it and the MockServer image',
    `pinned in [\`oracle.env\`](${GITHUB}/blob/${REF}/oracle.env):`,
    '',
    '```sh',
    'make image',
    'RESULTS=results.json bench/run.sh',
    '```',
    '',
    'It prints a line per measurement as it goes, keeps every reading in a run directory and writes a `results.json`',
    'like [this one](' + BASE + '/benchmarks/results.json) with the run directory packed beside it.',
    `[\`bench/README.md\`](${GITHUB}/blob/${REF}/bench/README.md) lists the settings and what each reading is.`,
  )
  return `${L.join('\n')}\n`
}

/** Every finding of the check: a digit on the page not read from the results, a row the page cannot place. */
export function check(results) {
  const findings = []
  if (results.schema !== 2) findings.push(`results.json has schema ${results.schema}, this script reads 2`)
  for (const r of results.rows ?? []) {
    for (const key of ['server', 'config', 'expectations', 'request', 'log_level']) {
      if (r[key] === undefined || r[key] === null) findings.push(`a row has no ${key}: ${JSON.stringify(r)}`)
    }
    if (!KINDS.includes(r.request)) findings.push(`a row's request is not one of ${KINDS.join(', ')}: ${r.request}`)
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
  console.log(`benchmarks: the Benchmarks page from results.json (${results.meta.date}, commit ${results.meta.commit.slice(0, 12)}, ${results.rows.length} rows)`)
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main()
