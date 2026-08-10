'use strict';

/*
 * Which identity providers this instance offers.
 *
 * Providers are resolved through ONE function on purpose. Instance-wide providers come from the
 * environment today; per-organization SSO will come from the database later, and when it does it
 * plugs in here rather than growing a second login path. The rest of the app only ever asks
 * "give me the provider called X" and never learns where the answer came from.
 *
 * ── Configuration ────────────────────────────────────────────────────────────────────────────
 *
 *   OIDC_PROVIDERS=okta,authentik            comma-separated slugs to enable
 *   OIDC_OKTA_ISSUER=https://example.okta.com
 *   OIDC_OKTA_CLIENT_ID=...
 *   OIDC_OKTA_CLIENT_SECRET=...              optional — PKCE means a public client works
 *   OIDC_OKTA_NAME=Okta                      optional button label
 *   OIDC_OKTA_SCOPES=openid email profile    optional
 *
 * Google and Microsoft are ordinary OIDC providers and are registered automatically from the
 * variables the README has always documented (GOOGLE_CLIENT_ID, MICROSOFT_CLIENT_ID +
 * MICROSOFT_TENANT_ID), so an existing deployment keeps working without editing anything. They get
 * no special code path — the only difference is that their issuer is filled in for you.
 */

const GOOGLE_ISSUER = 'https://accounts.google.com';
const DEFAULT_SCOPES = 'openid email profile';

/** A slug has to be safe in a URL path and in an env var name. */
const SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,30}$/;

function envKey(slug, suffix) {
  return `OIDC_${slug.toUpperCase().replace(/-/g, '_')}_${suffix}`;
}

function fromEnv(env, slug) {
  const issuer = (env[envKey(slug, 'ISSUER')] || '').trim().replace(/\/+$/, '');
  const clientId = (env[envKey(slug, 'CLIENT_ID')] || '').trim();
  if (!issuer || !clientId) return null;
  return {
    slug,
    name: (env[envKey(slug, 'NAME')] || '').trim() || slug.replace(/[-_]/g, ' '),
    issuer,
    clientId,
    clientSecret: (env[envKey(slug, 'CLIENT_SECRET')] || '').trim() || null,
    scopes: (env[envKey(slug, 'SCOPES')] || '').trim() || DEFAULT_SCOPES,
    source: 'env',
  };
}

/**
 * Every provider this instance offers, in a stable order.
 *
 * ⚠️ Never returns clientSecret to a caller that only wants to draw buttons — see publicList().
 */
function list(env = process.env) {
  const out = [];
  const seen = new Set();

  // Back-compat: the two providers the README documented before generic OIDC existed.
  const googleId = (env.GOOGLE_CLIENT_ID || '').trim();
  if (googleId) {
    out.push({
      slug: 'google',
      name: 'Google',
      issuer: GOOGLE_ISSUER,
      clientId: googleId,
      clientSecret: (env.GOOGLE_CLIENT_SECRET || '').trim() || null,
      scopes: DEFAULT_SCOPES,
      source: 'env',
    });
    seen.add('google');
  }

  const msId = (env.MICROSOFT_CLIENT_ID || '').trim();
  if (msId) {
    // `common` lets any Microsoft account in, which is what multi-tenant means and is the documented
    // default. A single-tenant deployment sets the tenant GUID and the issuer narrows with it, so a
    // token from another tenant then fails the iss check rather than being silently accepted.
    const tenant = (env.MICROSOFT_TENANT_ID || 'common').trim() || 'common';
    out.push({
      slug: 'microsoft',
      name: 'Microsoft',
      issuer: `https://login.microsoftonline.com/${tenant}/v2.0`,
      clientId: msId,
      clientSecret: (env.MICROSOFT_CLIENT_SECRET || '').trim() || null,
      scopes: DEFAULT_SCOPES,
      source: 'env',
    });
    seen.add('microsoft');
  }

  for (const raw of String(env.OIDC_PROVIDERS || '').split(',')) {
    const slug = raw.trim().toLowerCase();
    if (!slug || seen.has(slug)) continue;
    if (!SLUG_RE.test(slug)) continue;   // ignore rather than crash a boot over a typo
    const p = fromEnv(env, slug);
    if (p) { out.push(p); seen.add(slug); }
  }

  return out;
}

/** One provider by slug, or null. This is the seam per-org SSO will extend. */
function get(slug, env = process.env) {
  if (!slug || !SLUG_RE.test(String(slug))) return null;
  return list(env).find((p) => p.slug === slug) || null;
}

/**
 * What the login page is allowed to know: enough to draw a button and nothing else.
 * No client ids, because the browser never talks to the provider directly any more — the redirect
 * is built server-side, so there is nothing for the page to do with one.
 */
function publicList(env = process.env) {
  return list(env).map((p) => ({ slug: p.slug, name: p.name }));
}

module.exports = { list, get, publicList, DEFAULT_SCOPES, SLUG_RE };
