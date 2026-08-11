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

/*
 * `local` is what users.auth_provider says for a password account, so a provider by that name would
 * make every federated login look like a password login to the linking rules — and would put a NULL
 * password_hash on rows that POST /login then feeds straight to bcrypt.compareSync. Reserved rather
 * than merely discouraged.
 */
const RESERVED_SLUGS = new Set(['local', 'recovery']);

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
    /*
     * ⚠️ A TENANT GUID IS REQUIRED. `common` and `organizations` are refused, for two reasons that
     * point the same way.
     *
     * It does not work: Microsoft's multi-tenant metadata advertises
     * `https://login.microsoftonline.com/{tenantid}/v2.0` — a literal template — so the issuer can
     * never equal the configured URL and every login fails at /start regardless.
     *
     * And the obvious patch is dangerous: loosening the `iss` comparison to accept the template
     * means accepting tokens from EVERY Azure tenant, which is nOAuth — an admin of any tenant can
     * set an arbitrary, unverified `email` on one of their own users and be issued a session as that
     * address here. Doing multi-tenant Microsoft safely needs per-tenant pinning (validate `tid`
     * against an allowlist and key the account on `oid`+`tid`, not on email), which is a feature,
     * not a relaxed regex.
     *
     * So: refuse loudly at boot rather than ship a login that either never works or works too well.
     */
    const rawTenant = (env.MICROSOFT_TENANT_ID || '').trim().toLowerCase();
    if (!rawTenant || ['common', 'organizations', 'consumers'].includes(rawTenant)) {
      if (!list._warned) {
        console.warn('[sso] MICROSOFT_CLIENT_ID is set but MICROSOFT_TENANT_ID is missing or multi-tenant '
          + `(${rawTenant || 'unset'}). Microsoft sign-in is DISABLED: set your tenant GUID. See README.`);
        list._warned = true;
      }
      seen.add('microsoft');
    } else {
      out.push({
        slug: 'microsoft',
        name: 'Microsoft',
        // A tenant GUID narrows the issuer to that tenant, so a token from any other tenant fails
        // the `iss` check instead of being quietly accepted.
        issuer: `https://login.microsoftonline.com/${rawTenant}/v2.0`,
        clientId: msId,
        clientSecret: (env.MICROSOFT_CLIENT_SECRET || '').trim() || null,
        scopes: DEFAULT_SCOPES,
        source: 'env',
      });
      seen.add('microsoft');
    }
  }

  for (const raw of String(env.OIDC_PROVIDERS || '').split(',')) {
    const slug = raw.trim().toLowerCase();
    if (!slug || seen.has(slug)) continue;
    if (!SLUG_RE.test(slug) || RESERVED_SLUGS.has(slug)) continue;   // ignore rather than crash a boot over a typo
    const p = fromEnv(env, slug);
    if (p) { out.push(p); seen.add(slug); }
  }

  return out;
}

/** One provider by slug, or null. This is the seam per-org SSO will extend. */
function get(slug, env = process.env) {
  if (!slug || !SLUG_RE.test(String(slug))) return null;
  const fromEnvList = list(env).find((p) => p.slug === slug);
  if (fromEnvList) return fromEnvList;
  // Instance providers win a name clash, which cannot happen in practice (org slugs are random)
  // but decides it deterministically if it ever did.
  return getOrgProvider(slug);
}

/**
 * What the login page is allowed to know: enough to draw a button and nothing else.
 * No client ids, because the browser never talks to the provider directly any more — the redirect
 * is built server-side, so there is nothing for the page to do with one.
 */
function publicList(env = process.env) {
  return list(env).map((p) => ({ slug: p.slug, name: p.name }));
}


/* ────────────────────────────────────────────────────────────────────────────────────────────
 * Per-organization providers.
 *
 * Loaded lazily so this module stays usable (and testable) without a database — the env-only paths
 * above never touch it. An org provider is an ordinary provider once loaded: the login flow cannot
 * tell the difference, which is the whole point of resolving everything through get().
 */

let _db = null;
function db() {
  if (_db === null) {
    try { _db = require('../db/database').db; } catch { _db = false; }
  }
  return _db || null;
}

function rowToProvider(row, secretbox) {
  return {
    slug: row.slug,
    name: row.name,
    issuer: String(row.issuer).replace(/\/+$/, ''),
    clientId: row.client_id,
    /*
     * Fail CLOSED. secretbox.decrypt returns null when the key has rotated, which silently turned a
     * confidential client into a public one — the login then fails at the provider with an error
     * nobody can act on, while the admin screen still says "a secret is set".
     */
    clientSecret: row.client_secret_enc
      ? (secretbox.decrypt(row.client_secret_enc) ?? (() => { throw new Error('client secret could not be decrypted — re-enter it'); })())
      : null,
    scopes: row.scopes || DEFAULT_SCOPES,
    source: 'org',
    organizationId: row.organization_id,
    /*
     * ⚠️ VERIFIED domains only — never org_sso_providers.email_domains.
     *
     * That column is what an admin typed. This is what they PROVED, by publishing a record in the
     * domain's own DNS, and it is the only thing the login callback may confine an assertion to.
     * Reading the typed column here would reduce the whole verification feature to a decoration:
     * a tenant could type any company's domain and immediately assert addresses in it.
     */
    emailDomains: verifiedDomainsFor(row.id).join(','),
  };
}

/** The domains a provider has actually proved it controls. */
function verifiedDomainsFor(providerId) {
  const conn = db();
  if (!conn) return [];
  try {
    return conn.prepare('SELECT domain FROM org_sso_domains WHERE provider_id = ? AND verified_at IS NOT NULL')
      .all(providerId).map((r) => r.domain);
  } catch (e) {
    if (/no such table/i.test(e.message)) return [];
    throw e;
  }
}

/** One org provider by its (globally unique) slug, or null. */
function getOrgProvider(slug) {
  const conn = db();
  if (!conn || !slug || !SLUG_RE.test(String(slug))) return null;
  try {
    const row = conn.prepare('SELECT * FROM org_sso_providers WHERE slug = ? AND enabled = 1').get(String(slug));
    if (!row) return null;
    return rowToProvider(row, require('./secretbox'));
  } catch (e) {
    /*
     * Only "the table is not there yet" is a null. This catch used to swallow EVERYTHING, which
     * turned a secret that could not be decrypted back into a silent success — the exact failure the
     * fail-closed check above exists to prevent. Anything else propagates so it is logged and the
     * login fails loudly.
     */
    if (/no such table/i.test(e.message)) return null;
    throw e;
  }
}

/**
 * Who owns a provider slug — without decrypting anything, and regardless of whether it is enabled.
 *
 * The linking rules need to know which ORGANIZATION established an account, not how to talk to its
 * provider, and asking get() for that has two problems: it fails closed on an undecryptable secret
 * (right for a login, wrong for an ownership question) and it hides disabled rows, which still own
 * the accounts they created.
 *
 * null means "nothing here owns that slug" — either it never existed or the provider has since been
 * deleted, and those are deliberately the same answer.
 */
function ownerOf(slug) {
  if (!slug || !SLUG_RE.test(String(slug))) return null;
  if (list().some((p) => p.slug === slug)) return { source: 'env', organizationId: null };
  const conn = db();
  if (!conn) return null;
  try {
    const row = conn.prepare('SELECT organization_id FROM org_sso_providers WHERE slug = ?').get(String(slug));
    return row ? { source: 'org', organizationId: row.organization_id } : null;
  } catch (e) {
    if (/no such table/i.test(e.message)) return null;
    throw e;
  }
}

/**
 * Which provider, if any, owns an email address.
 *
 * Domain routing is what makes per-org SSO usable: a customer's staff type their work address and
 * are sent to their own identity provider rather than being asked for a password they do not have.
 *
 * ⚠️ Matched on the domain ONLY, never on whether the address exists. Answering "yes, that domain
 * uses SSO" tells an attacker nothing they could not learn from the customer's website; answering
 * "yes, that USER exists" would be an account-enumeration oracle on the login page.
 */
function forEmail(email) {
  const conn = db();
  if (!conn) return null;
  const at = String(email || '').lastIndexOf('@');
  if (at === -1) return null;
  const domain = String(email).slice(at + 1).toLowerCase().trim();
  if (!domain) return null;
  try {
    /*
     * Routing is driven by the VERIFIED domain table, not by the text an admin typed, and the JOIN
     * is what enforces it — an unverified claim cannot send anyone anywhere.
     *
     * No ORDER BY: `domain` is UNIQUE, so at most one row can match and there is no tie to break.
     * An earlier version ordered here and the comment claimed it decided a race; it decided
     * nothing, and saying so invited someone to rely on it.
     */
    const row = conn.prepare(`
      SELECT p.* FROM org_sso_domains d
      JOIN org_sso_providers p ON p.id = d.provider_id
      WHERE d.domain = ? AND d.verified_at IS NOT NULL AND p.enabled = 1
    `).get(domain);
    if (row) return rowToProvider(row, require('./secretbox'));
  } catch (e) {
    // Only a missing table is a null — anything else (a secret that will not decrypt, a schema
    // drift) must surface rather than silently answering "this domain has no SSO", which is how a
    // fail-closed guarantee turns back into a fail-open one.
    if (!/no such table/i.test(e.message)) throw e;
  }
  return null;
}

/**
 * Is this address inside an organization that REQUIRES its identity provider?
 *
 * Only a VERIFIED domain can compel anyone: an org must not be able to switch off password login
 * for a domain it merely typed, which would be a denial-of-service against a company it has nothing
 * to do with. Enabled providers only, for the same reason a disabled provider routes nobody.
 */
function ssoOnlyForEmail(email) {
  const conn = db();
  if (!conn) return null;
  const at = String(email || '').lastIndexOf('@');
  if (at === -1) return null;
  const domain = String(email).slice(at + 1).toLowerCase().trim();
  if (!domain) return null;
  try {
    return conn.prepare(`
      SELECT o.id AS organization_id, o.name AS organization_name, p.slug
        FROM org_sso_domains d
        JOIN org_sso_providers p ON p.id = d.provider_id
        JOIN organizations o ON o.id = d.organization_id
       WHERE d.domain = ? AND d.verified_at IS NOT NULL AND p.enabled = 1 AND o.sso_only = 1
    `).get(domain) || null;
  } catch (e) {
    if (/no such table|no such column/i.test(e.message)) return null;
    throw e;
  }
}

module.exports = {
  list, get, publicList, getOrgProvider, ownerOf, forEmail, ssoOnlyForEmail, DEFAULT_SCOPES, SLUG_RE,
};
