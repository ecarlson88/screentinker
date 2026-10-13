'use strict';

/*
 * The web player follows white-label branding (tab title + favicon), against a real server.
 *
 *   - /player and /player/legacy are served titled "<brand> Player", with a favicon link when one is
 *     set, from the domain / platform-default branding (an unpaired screen knows no workspace);
 *   - admin-supplied values are escaped, and an unsafe favicon URL is never emitted (and is refused
 *     at save time);
 *   - a paired screen is told its OWN workspace's brand in device:paired, and a save on the
 *     dashboard reaches it live as device:branding;
 *   - a view-only link carries the viewed screen's workspace brand.
 */

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
const crypto = require('node:crypto');
const ioClient = require('socket.io-client');
const { safeFaviconUrl, playerBrand } = require('../lib/branding');

const { freePort } = require('./helpers/free-port');
let PORT, BASE, proc, db, JWT, WS;
const DATA_DIR = path.join(os.tmpdir(), 'st-brand-int-' + crypto.randomBytes(4).toString('hex'));
const LOG = path.join(os.tmpdir(), 'st-brand-int-' + crypto.randomBytes(4).toString('hex') + '.log');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

before(async () => {
  PORT = await freePort();
  BASE = `http://127.0.0.1:${PORT}`;
  const logFd = fs.openSync(LOG, 'w');
  const env = { ...process.env, DATA_DIR, SELF_HOSTED: 'true', PORT: String(PORT), NODE_ENV: 'test' };
  delete env.VIEW_ONLY_ENABLED; delete env.VIEW_TRUSTED_PROXIES;
  proc = spawn('node', ['server.js'], { cwd: path.join(__dirname, '..'), env, stdio: ['ignore', logFd, logFd] });
  let up = false;
  for (let i = 0; i < 80; i++) { try { const r = await fetch(BASE + '/api/status'); if (r.ok) { up = true; break; } } catch { /* */ } await sleep(250); }
  if (!up) throw new Error('server did not boot:\n' + fs.readFileSync(LOG, 'utf8').slice(-2000));
  const r = await fetch(BASE + '/api/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'admin@test.local', password: 'test12345', name: 'Admin' }) });
  JWT = (await r.json()).token;
  const { Database } = require('../db/sqlite-driver');
  db = new Database(path.join(DATA_DIR, 'db', 'remote_display.db'));
  WS = db.prepare('SELECT id FROM workspaces LIMIT 1').get().id;
});
after(() => { try { proc.kill('SIGKILL'); } catch { /* */ } });

const as = (method, url, body) => fetch(BASE + url, {
  method, headers: { Authorization: 'Bearer ' + JWT, 'Content-Type': 'application/json', 'X-Workspace-Id': WS },
  body: body === undefined ? undefined : JSON.stringify(body),
});
const page = async (url) => (await fetch(BASE + url)).text();
const titleOf = (html) => (html.match(/<title>([^<]*)<\/title>/) || [])[1];
const iconOf = (html) => (html.match(/<link rel="icon" href="([^"]*)">/) || [])[1];
const setPlatformDefault = (brand, favicon) => {
  db.prepare("DELETE FROM white_labels WHERE id = 'platform-default'").run();
  db.prepare("INSERT INTO white_labels (id, user_id, workspace_id, brand_name, favicon_url) VALUES ('platform-default', (SELECT id FROM users LIMIT 1), NULL, ?, ?)").run(brand, favicon);
};
const setWorkspaceBrand = (wsId, brand, favicon) => {
  db.prepare('DELETE FROM white_labels WHERE workspace_id = ?').run(wsId);
  db.prepare("INSERT INTO white_labels (id, user_id, workspace_id, brand_name, favicon_url) VALUES (?, (SELECT id FROM users LIMIT 1), ?, ?, ?)")
    .run('wl-' + crypto.randomBytes(4).toString('hex'), wsId, brand, favicon);
};

// A screen that stays connected, recording every event it is sent.
function liveScreen(payload) {
  const sock = ioClient(`${BASE}/device`, { transports: ['websocket'], reconnection: false, forceNew: true });
  const events = [];
  sock.onAny((name, data) => events.push({ name, data }));
  sock.on('connect', () => sock.emit('device:register', { ...payload, device_info: { app_version: 'test' } }));
  const waitFor = async (name, pred = () => true) => {
    for (let i = 0; i < 100; i++) {
      const e = events.find((x) => x.name === name && pred(x.data));
      if (e) return e.data;
      await sleep(50);
    }
    throw new Error('no ' + name + ' arrived; saw: ' + events.map((x) => x.name).join(', '));
  };
  return { sock, events, waitFor, close: () => { try { sock.close(); } catch { /* */ } } };
}

test('favicon URL rule: http(s) or a same-origin path, nothing else', () => {
  for (const ok of ['https://cdn.example.com/i.png', 'http://x.example/f.ico', '/uploads/brand/f.png']) {
    assert.equal(safeFaviconUrl(ok), ok, ok);
  }
  for (const bad of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'data:image/png;base64,AAAA', '//evil.example/f.png',
    '/\\evil.example', 'https://x.example/a b.png', 'ftp://x.example/f.ico', 'f.png', '', null, 42]) {
    assert.equal(safeFaviconUrl(bad), null, String(bad));
  }
  assert.deepEqual(playerBrand(null), { brand_name: 'ScreenTinker', favicon_url: null }, 'hardcoded fallback');
  assert.deepEqual(playerBrand({ brand_name: '  ', favicon_url: 'javascript:x' }), { brand_name: 'ScreenTinker', favicon_url: null });
});

test('with no branding at all, the player keeps a sane title and no favicon link', async () => {
  db.prepare('DELETE FROM white_labels').run();
  for (const url of ['/player', '/player/legacy']) {
    const html = await page(url);
    assert.equal(titleOf(html), 'ScreenTinker Player', url);
    assert.match(html, /<h1 data-brand-name>ScreenTinker<\/h1>/, url);
    assert.equal(iconOf(html), undefined, url);
  }
});

test('the platform default brands /player and /player/legacy, escaped', async () => {
  setPlatformDefault('Acme <b>&"Co"', '/brand/icon.png?a=1&b="2"');
  for (const url of ['/player', '/player/legacy']) {
    const html = await page(url);
    assert.equal(titleOf(html), 'Acme &lt;b&gt;&amp;&quot;Co&quot; Player', url);
    assert.equal(iconOf(html), '/brand/icon.png?a=1&amp;b=&quot;2&quot;', url);
    assert.match(html, /<h1 data-brand-name>Acme &lt;b&gt;&amp;&quot;Co&quot;<\/h1>/, url + ' pairing heading');
    assert.match(html, /<h2 data-brand-name>Acme &lt;b&gt;&amp;&quot;Co&quot;<\/h2>/, url + ' status heading');
    assert.doesNotMatch(html, /<b>&"Co"/, 'the raw name never reaches the markup');
    // The client's starting point, with `<` escaped so it cannot close the inline script.
    assert.match(html, /window\.__playerConfig\.brand = \{"brand_name":"Acme \\u003cb>&\\"Co\\"","favicon_url":"\/brand\/icon\.png\?a=1&b=\\"2\\""\};/, url);
  }
});

test('a line separator in the brand name cannot break the inline script on old engines', async () => {
  setPlatformDefault('Acme\u2028Co', null);
  const html = await page('/player/legacy');
  assert.match(html, /"brand_name":"Acme\\u2028Co"/);
  const script = html.slice(html.indexOf('window.__playerConfig.brand'), html.indexOf('</script>', html.indexOf('window.__playerConfig.brand')));
  assert.equal(script.includes('\u2028'), false, 'no raw U+2028 inside the inline script');
});

test("a '$' pattern in the brand name is literal, not a replacement pattern", async () => {
  setPlatformDefault("Acme $& $' Co", null);
  const html = await page('/player');
  assert.equal(titleOf(html), "Acme $&amp; $' Co Player");
  assert.match(html, /window\.__playerConfig\.brand = \{"brand_name":"Acme \$& \$' Co","favicon_url":null\};<\/script>/);
});

test('an unsafe favicon already in the DB is never emitted; saving one is refused', async () => {
  setPlatformDefault('Acme', 'javascript:alert(1)');
  const html = await page('/player');
  assert.equal(titleOf(html), 'Acme Player');
  assert.equal(iconOf(html), undefined);
  assert.doesNotMatch(html, /javascript:alert/);

  const admin = await as('PUT', '/api/admin/branding', { brand_name: 'Acme', favicon_url: 'javascript:alert(1)' });
  assert.equal(admin.status, 400, 'platform default');
  const ws = await as('POST', '/api/white-label', { brand_name: 'Acme', favicon_url: 'data:image/png;base64,AA' });
  assert.equal(ws.status, 400, 'workspace');
  const okSave = await as('POST', '/api/white-label', { brand_name: 'Acme', favicon_url: 'https://cdn.example.com/f.png' });
  assert.equal(okSave.status, 200, 'a safe URL still saves');
});

test('a paired screen gets its own workspace brand, and a dashboard save reaches it live', async () => {
  setPlatformDefault('Instance Brand', null);
  setWorkspaceBrand(WS, 'Mine', '/mine.png');
  db.prepare("INSERT OR IGNORE INTO workspaces (id, organization_id, name) SELECT 'ws-someone-else', organization_id, 'Other' FROM workspaces WHERE id = ?").run(WS);
  setWorkspaceBrand('ws-someone-else', 'Not Mine', '/other.png');

  const code = String(crypto.randomInt(100000, 1000000));
  const screen = liveScreen({ pairing_code: code });
  try {
    const reg = await screen.waitFor('device:registered');
    const pair = await as('POST', '/api/provision/pair', { pairing_code: code, name: 'Lobby' });
    assert.equal(pair.status, 200);
    const paired = await screen.waitFor('device:paired');
    assert.deepEqual(paired.brand, { brand_name: 'Mine', favicon_url: '/mine.png' }, 'pair time: this workspace, not another');

    // Reconnect with the issued identity: the re-sent device:paired carries the brand too.
    screen.close();
    const again = liveScreen({ device_id: reg.device_id, device_token: reg.device_token });
    try {
      const re = await again.waitFor('device:paired');
      assert.deepEqual(re.brand, { brand_name: 'Mine', favicon_url: '/mine.png' }, 'reconnect');

      const save = await as('POST', '/api/white-label', { brand_name: 'Mine Renamed', favicon_url: '' });
      assert.equal(save.status, 200);
      const live = await again.waitFor('device:branding');
      assert.deepEqual(live.brand, { brand_name: 'Mine Renamed', favicon_url: null }, 'pushed on save');

      // A view-only link of this screen shows the same workspace brand.
      const v = await (await as('PUT', `/api/devices/${reg.device_id}/view`, { enabled: true })).json();
      const viewHtml = await page('/view/' + v.share_url.split('/view/')[1]);
      assert.equal(titleOf(viewHtml), 'Mine Renamed Player', 'view link');
    } finally { again.close(); }
  } finally { screen.close(); }
});
