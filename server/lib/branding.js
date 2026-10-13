'use strict';

// Issue #15: instance-level default white-label branding.
//
// Branding is stored per-workspace in white_labels (keyed by workspace_id). This
// adds a single "platform default" row that every workspace inherits unless it
// has set its own. Resolution order:
//   1. the current workspace's row        (per-workspace override; unchanged)
//   2. a custom-domain match              (public/pre-login white-label hosts)
//   3. the platform-default row           (instance default, #15)
//   4. hardcoded ScreenTinker fallback
//
// The platform-default row is identified by a FIXED id (not "workspace_id IS
// NULL"): legacy pre-multitenancy white_labels rows can also have a null
// workspace_id, so a null-scope sentinel would be ambiguous. A fixed id is not.
//
// Override is ROW-LEVEL: a workspace that has any row uses it wholesale; only
// workspaces with NO row fall through to the platform default. No row-copying at
// creation, so editing the platform default propagates everywhere instantly.

const PLATFORM_DEFAULT_ID = 'platform-default';

const HARDCODED_BRANDING = {
  brand_name: 'ScreenTinker',
  logo_url: null,
  favicon_url: null,
  primary_color: '#3B82F6',
  secondary_color: '#1E293B',
  bg_color: '#111827',
  custom_css: null,
  hide_branding: 0,
};

// The single platform-default row (fixed id), or null if none has been set.
function platformDefaultRow(db) {
  return db.prepare('SELECT * FROM white_labels WHERE id = ?').get(PLATFORM_DEFAULT_ID) || null;
}

// Resolve effective branding for a context. Pass whichever you have:
//   { workspaceId } for the authed app, { domain } for the public/login path.
function resolveBranding(db, { workspaceId = null, domain = null } = {}) {
  if (workspaceId) {
    const wl = db.prepare('SELECT * FROM white_labels WHERE workspace_id = ?').get(workspaceId);
    if (wl) return wl;
  }
  if (domain) {
    const wl = db.prepare('SELECT * FROM white_labels WHERE custom_domain = ?').get(domain);
    if (wl) return wl;
  }
  return platformDefaultRow(db) || { ...HARDCODED_BRANDING };
}

// Presentational fields only. The PUBLIC resolver (GET /api/branding) and the
// by-domain lookup must not leak internal columns (id, user_id, workspace_id,
// custom_domain, timestamps) to unauthenticated / cross-tenant callers.
const PUBLIC_BRANDING_FIELDS = ['brand_name', 'logo_url', 'favicon_url', 'primary_color', 'secondary_color', 'bg_color', 'custom_css', 'hide_branding'];
function publicBranding(row) {
  const out = {};
  for (const f of PUBLIC_BRANDING_FIELDS) out[f] = row ? (row[f] ?? null) : null;
  return out;
}

// A favicon URL the player may emit: http(s), or a same-origin absolute path.
// Everything else - javascript:, data:, protocol-relative //host, backslash tricks - is null.
// Used both to reject a bad value at save time and to drop one already stored at render time.
function safeFaviconUrl(url) {
  if (typeof url !== 'string') return null;
  const u = url.trim();
  if (!u || u.length > 2048 || /[\s\\]/.test(u)) return null;
  if (/^\/(?!\/)/.test(u)) return u;
  if (!/^https?:\/\//i.test(u)) return null;
  try { new URL(u); return u; } catch (e) { return null; }
}

// True when a save-time favicon_url is acceptable: absent/empty (clears it) or a safe URL.
function isAcceptableFaviconUrl(url) {
  if (url === undefined || url === null || url === '') return true;
  return safeFaviconUrl(url) !== null;
}

// The two fields the web player shows (tab title + favicon), already sanitized. Never custom_css:
// that is platform-admin-only and has no business on a screen.
function playerBrand(row) {
  const name = row && typeof row.brand_name === 'string' ? row.brand_name.trim().slice(0, 200) : '';
  return {
    brand_name: name || HARDCODED_BRANDING.brand_name,
    favicon_url: safeFaviconUrl(row && row.favicon_url),
  };
}

// The player brand for a device: its workspace's branding, else the platform default (the same
// order the authed dashboard uses). Null when the row is missing or the lookup fails, so callers
// can omit the field and the player keeps what it already shows.
function playerBrandForDevice(db, deviceId) {
  try {
    const d = db.prepare('SELECT workspace_id FROM devices WHERE id = ?').get(deviceId);
    if (!d) return null;
    return playerBrand(resolveBranding(db, { workspaceId: d.workspace_id || null }));
  } catch (e) { return null; }
}

// Push the current brand to these devices' live sockets (or the replica holding them). Offline
// screens are skipped: they get it in device:paired on their next register. Never throws.
function pushPlayerBrand(io, db, deviceIds) {
  if (!io || !deviceIds || !deviceIds.length) return;
  try {
    const deviceNs = io.of('/device');
    const relay = require('./mesh/command-relay');
    for (const id of deviceIds) {
      const brand = playerBrandForDevice(db, id);
      if (!brand) continue;
      const room = deviceNs.adapter.rooms.get(id);
      if (room && room.size > 0) deviceNs.to(id).emit('device:branding', { brand });
      else { try { relay.relayToAttached(db, id, 'device:branding', { brand }); } catch (e) { /* offline */ } }
    }
  } catch (e) { /* best effort: the next register carries it */ }
}

// After a workspace's branding is saved: every screen in that workspace.
function pushPlayerBrandToWorkspace(io, db, workspaceId) {
  if (!io || !workspaceId) return;
  try {
    pushPlayerBrand(io, db, db.prepare('SELECT id FROM devices WHERE workspace_id = ?').all(workspaceId).map(d => d.id));
  } catch (e) { /* best effort */ }
}

// After the platform default is saved: the screens that inherit it (workspace with no row of its own).
function pushPlayerBrandToInheritors(io, db) {
  if (!io) return;
  try {
    pushPlayerBrand(io, db, db.prepare(`SELECT id FROM devices WHERE workspace_id IS NOT NULL
      AND workspace_id NOT IN (SELECT workspace_id FROM white_labels WHERE workspace_id IS NOT NULL)`).all().map(d => d.id));
  } catch (e) { /* best effort */ }
}

module.exports = {
  resolveBranding, platformDefaultRow, publicBranding, HARDCODED_BRANDING, PLATFORM_DEFAULT_ID,
  safeFaviconUrl, isAcceptableFaviconUrl, playerBrand, playerBrandForDevice, pushPlayerBrand,
  pushPlayerBrandToWorkspace, pushPlayerBrandToInheritors,
};
