'use strict';

// The widget iframe's origin, and what it costs.
//
// The player mounts a widget in an iframe sandboxed to `allow-scripts` with NO allow-same-origin,
// which gives it an OPAQUE origin: widget scripts cannot read the player's window, its localStorage,
// or its device token. That is deliberate and worth keeping — widget HTML is operator-authored and
//, for the webpage widget, third-party.
//
// It has a consequence that is easy to forget and was in fact forgotten: a service worker does not
// control opaque-origin clients, so the widget frame's navigation NEVER reaches sw.js. The
// cache-first widget branch there is real code that this player's own widgets do not use — measured
// in Chrome, a clock widget mounted five times over 25 seconds while the shell cache held zero
// widget entries, and a plain fetch() of the same URL from the controlled page was cached
// immediately. Widgets survive an outage today on the HTTP cache and the server's immutable
// Cache-Control, not on the worker.
//
// So this test pins the security property, and pins the fact that the offline story for widgets
// rests on the HTTP header. Someone who "fixes" offline widgets by adding allow-same-origin trades
// the isolation for a cache — the wrong direction, and the reason this is asserted rather than left
// as a comment.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const HTML = fs.readFileSync(path.join(__dirname, '..', 'player', 'index.html'), 'utf8');
const SW = fs.readFileSync(path.join(__dirname, '..', 'player', 'sw.js'), 'utf8');
const WIDGETS = fs.readFileSync(path.join(__dirname, '..', 'routes', 'widgets.js'), 'utf8');

test('the widget iframe stays null-origin by default, with explicit per-item opt-in only', () => {
  assert.match(HTML, /function widgetSandboxAttr\(item\)/, 'widget sandbox policy should be centralized');
  assert.match(HTML, /item && item\.widget_allow_same_origin/, 'opt-in must be keyed by item/org setting');
  assert.match(HTML, /allow-scripts allow-same-origin/, 'explicit opt-in token must exist');
  assert.match(HTML, /: 'allow-scripts'/, 'safe default remains allow-scripts only');
});

test('the offline guarantee for widgets is the HTTP header, and the server still sets it', () => {
  // If this regresses to no-store, widgets stop surviving an outage everywhere — and the service
  // worker will NOT quietly cover for it, because it never sees the request.
  assert.match(WIDGETS, /max-age=31536000, immutable/,
    'a rev-pinned render must stay hard-cacheable: it is the only thing holding widgets offline');
  assert.match(WIDGETS, /no-store/, 'a render with no rev must stay uncacheable — nothing distinguishes one from the next');
});

test('the worker does not claim to be what keeps widgets offline', () => {
  // The comment above that branch used to say it was. A worker cannot control an opaque-origin
  // client, so the claim was false in exactly the deployment it was written for.
  const branch = SW.slice(0, SW.indexOf("url.pathname.startsWith('/api/widgets/')"));
  assert.match(branch, /opaque-origin|opaque origin/i,
    'sw.js must record that the widget frame is opaque-origin and bypasses it');
});
