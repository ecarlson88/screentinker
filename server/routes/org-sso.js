'use strict';

/*
 * Per-organization SSO — the customer-facing half of single sign-on.
 *
 * Instance-wide providers live in the environment and belong to whoever runs the server. These
 * belong to a CUSTOMER: an organization points ScreenTinker at its own identity provider, and its
 * people sign in with it without the operator editing a config file.
 *
 * The login flow is unchanged. A provider configured here is resolved by exactly the same
 * oidc-providers.get(slug) the environment ones go through, so there is one authorization request
 * builder, one token exchange and one verifier — not a second, less-tested path for tenants.
 */

const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const { db } = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const { resolveTenancy } = require('../lib/tenancy');
const secretbox = require('../lib/secretbox');
const oidc = require('../lib/oidc');
const { logActivity, getClientIp } = require('../services/activity');

/*
 * Only an org owner/admin may configure how their people sign in — it is the most security-relevant
 * setting a tenant has. Platform staff are deliberately NOT given a bypass here: this is customer
 * configuration, and an operator who needs to change it can do so as a member of that organization.
 */
function requireOrgAdmin(req, res, next) {
  const orgId = req.params.orgId;
  if (!orgId) return res.status(400).json({ error: 'organization required' });
  const row = db.prepare(
    'SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?'
  ).get(orgId, req.user.id);
  if (!row || (row.role !== 'org_owner' && row.role !== 'org_admin')) {
    // 404 rather than 403: an outsider should not learn that an organization id exists.
    return res.status(404).json({ error: 'Not found' });
  }
  req.orgId = orgId;
  next();
}

/*
 * The slug is a URL path segment and is generated, never chosen.
 *
 * Two customers both wanting "okta" must not collide, and one must not be able to guess or squat
 * another's. It is random and globally unique; the admin only ever sees the display name.
 */
const newSlug = () => `org${crypto.randomBytes(6).toString('hex')}`;

/** Never let a secret out of the API, in either direction of a round trip. */
function toPublic(row) {
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    issuer: row.issuer,
    client_id: row.client_id,
    has_client_secret: !!row.client_secret_enc,
    scopes: row.scopes,
    email_domains: row.email_domains,
    enabled: !!row.enabled,
    login_url: `/api/auth/oidc/${row.slug}/start`,
    callback_url: `/api/auth/oidc/${row.slug}/callback`,
  };
}

/*
 * Domains are the routing key, so they are normalised hard: lowercased, de-duplicated, stripped of
 * a leading @ or scheme someone pasted, and validated as something that can actually be the right
 * hand side of an address. A wildcard is refused — "*" would route every unrecognised address at
 * one customer's IdP.
 */
function normaliseDomains(raw) {
  const seen = new Set();
  for (const part of String(raw || '').split(/[,\s]+/)) {
    let d = part.trim().toLowerCase().replace(/^@/, '').replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!d) continue;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(d)) {
      throw new Error(`"${part.trim()}" is not a valid email domain`);
    }
    seen.add(d);
  }
  return [...seen].join(',');
}

/**
 * A domain may belong to ONE organization.
 *
 * Without this, a second tenant could claim a domain already routed elsewhere and quietly capture
 * that company's logins — the worst failure this feature could have. First claim wins; the loser is
 * told which domain clashed and nothing about who holds it.
 */
function assertDomainsFree(domains, orgId, excludeId) {
  if (!domains) return;
  const wanted = domains.split(',');
  const rows = db.prepare("SELECT id, organization_id, email_domains FROM org_sso_providers WHERE email_domains != ''").all();
  for (const row of rows) {
    if (row.id === excludeId) continue;
    const held = String(row.email_domains).split(',');
    for (const d of wanted) {
      if (held.includes(d) && row.organization_id !== orgId) {
        const e = new Error(`the domain ${d} is already used for sign-in by another organization`);
        e.status = 409;
        throw e;
      }
    }
  }
}

router.use(requireAuth, resolveTenancy);

// List an organization's providers.
router.get('/:orgId/sso', requireOrgAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM org_sso_providers WHERE organization_id = ? ORDER BY created_at').all(req.orgId);
  res.json({ providers: rows.map(toPublic) });
});

router.post('/:orgId/sso', requireOrgAdmin, async (req, res) => {
  const { name, issuer, client_id: clientId, client_secret: clientSecret, scopes, email_domains: domains } = req.body || {};
  if (!name || !issuer || !clientId) {
    return res.status(400).json({ error: 'name, issuer and client_id are required' });
  }

  let cleanDomains;
  try {
    cleanDomains = normaliseDomains(domains);
    assertDomainsFree(cleanDomains, req.orgId, null);
  } catch (e) {
    return res.status(e.status || 400).json({ error: e.message });
  }

  /*
   * The issuer is checked against the live provider BEFORE anything is stored. A typo here would
   * otherwise be discovered by a user staring at a failed login, and the error they would see says
   * nothing useful. Discovery also proves the URL is an OIDC issuer at all rather than a company
   * home page someone pasted.
   */
  try {
    await oidc.discover(String(issuer).trim().replace(/\/+$/, ''));
  } catch (e) {
    return res.status(400).json({ error: `Could not read OpenID configuration from that issuer: ${e.message}` });
  }

  const id = crypto.randomUUID();
  const slug = newSlug();
  db.prepare(`
    INSERT INTO org_sso_providers (id, organization_id, slug, name, issuer, client_id, client_secret_enc, scopes, email_domains, enabled)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
  `).run(id, req.orgId, slug, String(name).trim(), String(issuer).trim().replace(/\/+$/, ''), String(clientId).trim(),
    clientSecret ? secretbox.encrypt(String(clientSecret)) : null,
    String(scopes || 'openid email profile').trim(), cleanDomains);

  logActivity(req.user.id, 'org_sso_created', `${name} (${slug})`, req.orgId, getClientIp(req));
  res.status(201).json(toPublic(db.prepare('SELECT * FROM org_sso_providers WHERE id = ?').get(id)));
});

router.put('/:orgId/sso/:id', requireOrgAdmin, async (req, res) => {
  const existing = db.prepare('SELECT * FROM org_sso_providers WHERE id = ? AND organization_id = ?').get(req.params.id, req.orgId);
  if (!existing) return res.status(404).json({ error: 'Not found' });

  const { name, issuer, client_id: clientId, client_secret: clientSecret, scopes, email_domains: domains, enabled } = req.body || {};

  let cleanDomains = existing.email_domains;
  if (domains !== undefined) {
    try {
      cleanDomains = normaliseDomains(domains);
      assertDomainsFree(cleanDomains, req.orgId, existing.id);
    } catch (e) {
      return res.status(e.status || 400).json({ error: e.message });
    }
  }

  const nextIssuer = issuer !== undefined ? String(issuer).trim().replace(/\/+$/, '') : existing.issuer;
  if (nextIssuer !== existing.issuer) {
    try { await oidc.discover(nextIssuer); }
    catch (e) { return res.status(400).json({ error: `Could not read OpenID configuration from that issuer: ${e.message}` }); }
  }

  /*
   * An absent client_secret LEAVES THE STORED ONE ALONE; an empty string clears it. The API never
   * returns the secret, so a UI that round-trips a form would otherwise blank it on every save —
   * the classic way a settings page silently breaks the thing it is editing.
   */
  const secretEnc = clientSecret === undefined ? existing.client_secret_enc
    : (clientSecret === '' ? null : secretbox.encrypt(String(clientSecret)));

  db.prepare(`
    UPDATE org_sso_providers
       SET name = ?, issuer = ?, client_id = ?, client_secret_enc = ?, scopes = ?, email_domains = ?, enabled = ?,
           updated_at = strftime('%s','now')
     WHERE id = ?
  `).run(
    name !== undefined ? String(name).trim() : existing.name,
    nextIssuer,
    clientId !== undefined ? String(clientId).trim() : existing.client_id,
    secretEnc,
    scopes !== undefined ? String(scopes).trim() : existing.scopes,
    cleanDomains,
    enabled === undefined ? existing.enabled : (enabled ? 1 : 0),
    existing.id,
  );

  logActivity(req.user.id, 'org_sso_updated', `${existing.name} (${existing.slug})`, req.orgId, getClientIp(req));
  res.json(toPublic(db.prepare('SELECT * FROM org_sso_providers WHERE id = ?').get(existing.id)));
});

router.delete('/:orgId/sso/:id', requireOrgAdmin, (req, res) => {
  const existing = db.prepare('SELECT * FROM org_sso_providers WHERE id = ? AND organization_id = ?').get(req.params.id, req.orgId);
  if (!existing) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM org_sso_providers WHERE id = ?').run(existing.id);
  logActivity(req.user.id, 'org_sso_deleted', `${existing.name} (${existing.slug})`, req.orgId, getClientIp(req));
  res.json({ success: true });
});

module.exports = router;
