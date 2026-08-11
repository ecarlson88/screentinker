'use strict';

/*
 * The boot-time dependency check.
 *
 * It exists for the moments nobody is at their best: a rollback that restores an older
 * package.json but not its packages, and a Node upgrade that leaves the native database module
 * compiled against the wrong ABI. Both present as "server will not start", with an error naming a
 * file rather than the action needed.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const preflight = require('../lib/preflight-deps');

test('a healthy install reports nothing missing and nothing broken', () => {
  assert.deepEqual(preflight.missingDeps(), [], 'this tree should be complete');
  assert.equal(preflight.nativeModuleBroken(), null, 'and the native module should load');
});

test('THE NATIVE CHECK CONSTRUCTS A DATABASE, it does not merely require the module', () => {
  /*
   * better-sqlite3's entry point is plain JavaScript that loads the compiled binding lazily, so
   * `require()` SUCCEEDS under a Node whose ABI the binary was never built for. The first version
   * of this check stopped at require and therefore reported a genuinely broken install — verified
   * against a real Node 18 / Node 20 mismatch — as healthy.
   *
   * Pinned as source because the failure is invisible: the check keeps passing, on every machine
   * where nothing is wrong, right up until the one where something is.
   */
  const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'preflight-deps.js'), 'utf8');
  const fn = src.slice(src.indexOf('function nativeModuleBroken'), src.indexOf('function run('));
  assert.match(fn, /new Database\(':memory:'\)/,
    'nativeModuleBroken must open a database, or an ABI mismatch goes undetected');
  assert.ok(!/^\s*require\('better-sqlite3'\);\s*$/m.test(fn), 'a bare require is not a load test');
});

test('missingDeps agrees with what is actually on disk', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  const declared = Object.keys(pkg.dependencies || {});
  assert.ok(declared.length > 0, 'the server declares dependencies');
  const reported = preflight.missingDeps();
  for (const name of declared) {
    const present = fs.existsSync(path.join(__dirname, '..', 'node_modules', name, 'package.json'));
    assert.equal(present, !reported.includes(name), `${name}: presence and report disagree`);
  }
});

test('the preflight uses only Node builtins', () => {
  /*
   * It runs BEFORE dependencies are installed, so anything it imported could be the very thing
   * that is missing — and the failure would be the one it exists to prevent, with an extra layer
   * of confusion on top.
   */
  const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'preflight-deps.js'), 'utf8');
  const requires = [...src.matchAll(/require\('([^']+)'\)/g)].map((m) => m[1]);
  const builtins = new Set(['fs', 'path', 'child_process', 'os', 'crypto', 'util']);
  for (const r of requires) {
    // better-sqlite3 is the thing being TESTED for loadability, not a dependency of this file.
    if (r === 'better-sqlite3') continue;
    assert.ok(builtins.has(r) || r.startsWith('.'), `preflight must not depend on ${r}`);
  }
});

test('it can be turned off for an air-gapped host', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'preflight-deps.js'), 'utf8');
  assert.match(src, /ST_SKIP_DEP_PREFLIGHT/, 'an operator who manages node_modules must be able to opt out');
  const saved = process.env.ST_SKIP_DEP_PREFLIGHT;
  process.env.ST_SKIP_DEP_PREFLIGHT = '1';
  try { assert.doesNotThrow(() => preflight.preflight(), 'opting out must be a clean no-op'); }
  finally { if (saved === undefined) delete process.env.ST_SKIP_DEP_PREFLIGHT; else process.env.ST_SKIP_DEP_PREFLIGHT = saved; }
});

test('server.js runs the preflight BEFORE requiring anything', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const preflightAt = src.indexOf("require('./lib/preflight-deps')");
  const firstDep = src.indexOf("require('express')");
  assert.ok(preflightAt > -1, 'server.js must run the preflight');
  assert.ok(preflightAt < firstDep, 'it must come before the first dependency, or it cannot help');
});
