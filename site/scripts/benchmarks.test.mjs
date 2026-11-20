// The Benchmarks page generator's tests: `node --test site/scripts/benchmarks.test.mjs` (site/build.sh runs them).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { RESULTS, check, page, plain, strays, v } from './benchmarks.mjs'

const committed = () => JSON.parse(readFileSync(RESULTS, 'utf8'))

const tiny = () => ({
  schema: 1,
  meta: {
    date: '2030-01-02',
    commit: 'abcdef012345',
    image: 'built from that commit',
    oracle_image: 'mockserver/mockserver@sha256:00',
    machine: { kind: 'laptop', arch: 'arm64', cpu_model: 'M9', vcpus: 8, memory_gib: 16, os: 'macOS', kernel: '25', docker: '29' },
    load: { cpus: 2, connections: 64, warmup_s: 3, duration_s: 15, memory_limit: null, rounds: 1 },
    memory: 'docker stats',
  },
  rows: [
    { server: 'mock-server', config: 'default', expectations: 1, request: 'matched', log_level: 'INFO', req_per_sec: 1234.4, rss_mib: [10, 12] },
    { server: 'MockServer 9.2.0', config: 'default', expectations: 1, request: 'matched', log_level: 'INFO', req_per_sec: 999, rss_mib: [400, 400] },
  ],
})

test('the committed results pass the check', () => {
  assert.deepEqual(check(committed()), [])
})

test('every figure of the committed results is on the page', () => {
  const results = committed()
  const text = plain(page(results))
  for (const r of results.rows) {
    if (r.req_per_sec != null) assert.ok(text.includes(Math.round(r.req_per_sec).toLocaleString('en-US').replace(/,/g, ' ')), `${r.server} ${r.req_per_sec}`)
  }
  assert.ok(text.includes(results.meta.commit))
  assert.ok(text.includes(results.meta.machine.cpu_model))
})

test('the page shows the run, the machine and both servers', () => {
  const text = plain(page(tiny()))
  assert.match(text, /\| When \| 2030-01-02 \|/)
  assert.match(text, /commit `abcdef012345`/)
  assert.match(text, /laptop, arm64; M9; 8 vCPUs and 16 GiB/)
  assert.match(text, /\| 1 expectation, matched \| 1 234 \| 999 \|/)
  assert.match(text, /\| 1 expectation, matched \| 10–12 MiB \| 400 MiB \|/)
})

test('a digit typed into the page, not read from the results, is a finding', () => {
  assert.deepEqual(strays(`${v(42)} requests`), [])
  assert.equal(strays('about 7 000 requests').length, 4)
  assert.deepEqual(strays('p50 and p99 of x86_64, a 404'), [])
})

test('a row without its case is a finding, not a page', () => {
  const results = tiny()
  delete results.rows[0].request
  assert.match(check(results).join('\n'), /a row has no request/)
})
