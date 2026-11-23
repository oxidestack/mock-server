// The Benchmarks page generator's tests: `node --test site/scripts/benchmarks.test.mjs` (site/build.sh runs them).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { RESULTS, check, page, plain, strays, v } from './benchmarks.mjs'

const committed = () => JSON.parse(readFileSync(RESULTS, 'utf8'))

const round = (n, extra) => ({ round: n, req_per_sec: 1000, cpu_us_per_req: 50, ...extra })

const tiny = () => ({
  schema: 2,
  meta: {
    started: '2030-01-02T03:04:05+00:00',
    finished: '2030-01-02T04:05:06+00:00',
    date: '2030-01-02',
    commit: 'abcdef0123456789abcdef0123456789abcdef01',
    uncommitted_changes: false,
    note: null,
    images: {
      ours: { name: 'mock-server:latest', id: 'sha256:1111111111111111', digests: [] },
      oracle: { name: 'mockserver/mockserver@sha256:00', id: 'sha256:2222222222222222', digests: [] },
      oha: { name: 'ghcr.io/hatoo/oha:1.17.0@sha256:33', id: 'sha256:33', digests: [] },
      alloc_count: null,
    },
    machine: { kind: 'laptop', arch: 'arm64', cpu_model: 'M9', vcpus: 8, memory_gib: 16, os: 'macOS', kernel: '25', docker: '29', cgroup: 'v2, systemd', log_driver: 'json-file' },
    load_average_start: [0.5, 0.4, 0.3],
    load_average_end: [1.5, 1.4, 1.3],
    params: { cpus: 2, connections: 64, warmup_s: 20, duration_s: 15, rounds: 3, host_header: 'localhost:1080', memory_limit: null },
    raw: 'results-raw.tar.gz',
  },
  rows: [
    {
      server: 'mock-server', config: 'default', expectations: 1, request: 'matched', log_level: 'INFO',
      req_per_sec: 1234.4, cpu_us_per_req: 41.26, p50_ms: 0.5, p99_ms: 2.25, p999_ms: 7, rss_mib: 12, console_lines: 5000, unlogged_requests: 0,
      allocs_per_req: 31.04, reallocs_per_req: 2,
      rounds: [round(1, { req_per_sec: 1200 }), round(2, { req_per_sec: 1234.4 }), round(3, { req_per_sec: 1300 })],
    },
    {
      server: 'MockServer 9.2.0', config: 'default', expectations: 1, request: 'matched', log_level: 'INFO',
      req_per_sec: 999, cpu_us_per_req: 120, p50_ms: 1, p99_ms: 30, p999_ms: 60, rss_mib: 400, console_lines: 7000, unlogged_requests: 900,
      allocs_per_req: null, reallocs_per_req: null,
      rounds: [round(1, { req_per_sec: 999 })],
    },
  ],
})

test('the committed results pass the check', () => {
  assert.deepEqual(check(committed()), [])
})

test('every figure of the committed results is on the page', () => {
  const results = committed()
  const text = plain(page(results))
  const n = (x) => Math.round(x).toLocaleString('en-US').replace(/,/g, ' ')
  for (const r of results.rows) {
    if (r.req_per_sec != null) assert.ok(text.includes(n(r.req_per_sec)), `${r.server} ${r.req_per_sec}`)
    if (r.cpu_us_per_req != null) assert.ok(text.includes(r.cpu_us_per_req.toFixed(1)), `${r.server} ${r.cpu_us_per_req}`)
    if (r.p99_ms != null) assert.ok(text.includes(r.p99_ms.toFixed(2)), `${r.server} ${r.p99_ms}`)
  }
  assert.ok(text.includes(results.meta.commit.slice(0, 12)))
  assert.ok(text.includes(results.meta.machine.arch))
})

test('the page shows the run, the machine and both servers', () => {
  const text = plain(page(tiny()))
  assert.match(text, /\| When \| 2030-01-02T03:04:05\+00:00 to 2030-01-02T04:05:06\+00:00 \|/)
  assert.match(text, /commit `abcdef012345`/)
  assert.match(text, /laptop, arm64; M9; 8 vCPUs and 16 GiB/)
  assert.match(text, /`oha` 1\.17\.0, 64 connections for 15 s after a 20 s warm-up, `Host: localhost:1080`/)
  assert.match(text, /\| Load average \| 0\.5 \/ 0\.4 \/ 0\.3 at the start, 1\.5 \/ 1\.4 \/ 1\.3 at the end \|/)
  assert.match(text, /\[every round's `oha` output and readings\]\(\/mock-server\/benchmarks\/results-raw\.tar\.gz\)/)
})

test('each figure has its table: median and range, CPU, latency, memory, console, allocations', () => {
  const text = plain(page(tiny()))
  assert.match(text, /\| 1 expectation, matched \| 1 234 \(1 200–1 300\) \| 999 \|/)
  assert.match(text, /\| 1 expectation, matched \| 41\.3 \(50\.0–50\.0\) \| 120\.0 \|/)
  assert.match(text, /\| 1 expectation, matched \| 0\.50 \/ 2\.25 \/ 7\.00 \| 1\.00 \/ 30\.00 \/ 60\.00 \|/)
  assert.match(text, /\| 1 expectation, matched \| 12 MiB \| 400 MiB \|/)
  assert.match(text, /\| 1 expectation, matched \| 5 000; 0 unlogged \| 7 000; 900 unlogged \|/)
  assert.match(text, /\| 1 expectation, matched \| 31\.0, 2\.0 \| — \|/)
})

test('a digit typed into the page, not read from the results, is a finding', () => {
  assert.deepEqual(strays(`${v(42)} requests`), [])
  assert.equal(strays('about 7 000 requests').length, 4)
  assert.deepEqual(strays('p50, p99 and p99.9 of x86_64, a 404'), [])
})

test('a row without its case is a finding, not a page', () => {
  const results = tiny()
  delete results.rows[0].request
  assert.match(check(results).join('\n'), /a row has no request/)
})
