'use strict';

/*
 * The SSO that shipped before this verified nothing that mattered, and had no tests at all.
 *
 * Google's path asked `tokeninfo?access_token=` whether a token was valid and trusted the email in
 * the answer; Microsoft's handed a bearer token to Graph /me and trusted that. Neither asked WHO
 * THE TOKEN WAS ISSUED FOR. An access token is a bearer credential for a resource, minted for some
 * application — so any site a user signed into that requested `email` or `User.Read` could replay
 * their token and be handed a session as them.
 *
 * These tests exist so that cannot come back. Every one of them describes an attack that the old
 * code would have waved through, and they run against a REAL RSA keypair and a REAL JWKS document
 * so the verifier is exercised the way a provider would exercise it — not against a stub that
 * agrees with us.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

const oidc = require('../lib/oidc');
const providers = require('../lib/oidc-providers');

// ---------------------------------------------------------------------------------------------
// A pretend identity provider: one keypair, one JWKS, one discovery document.

const ISSUER = 'https://idp.example.com';
const CLIENT_ID = 'screentinker-test-client';
const KID = 'test-key-1';

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const JWKS = { keys: [{ ...publicKey.export({ format: 'jwk' }), kid: KID, use: 'sig', alg: 'RS256' }] };

// A second keypair nobody should trust — the "signed by someone else" case.
const rogue = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

function discoveryDoc(issuer = ISSUER) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
  };
}

/** Point global fetch at the pretend provider. Returns a restore function. */
function mockProvider({ doc = discoveryDoc(), jwks = JWKS } = {}) {
  const real = global.fetch;
  global.fetch = async (url) => {
    const u = String(url);
    if (u.endsWith('/.well-known/openid-configuration')) {
      return { ok: true, status: 200, json: async () => doc };
    }
    if (u.endsWith('/jwks')) {
      return { ok: true, status: 200, json: async () => jwks };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
  oidc._resetCaches();
  return () => { global.fetch = real; oidc._resetCaches(); };
}

const idToken = (claims = {}, { key = privateKey, alg = 'RS256', kid = KID } = {}) => jwt.sign(
  { iss: ISSUER, aud: CLIENT_ID, sub: 'user-123', email: 'a@example.com', nonce: 'NONCE', ...claims },
  key, { algorithm: alg, keyid: kid, expiresIn: '5m' },
);

const verify = (token, over = {}) =>
  oidc.verifyIdToken(token, { issuer: ISSUER, clientId: CLIENT_ID, nonce: 'NONCE', ...over });

// ---------------------------------------------------------------------------------------------

test('a well-formed token from the right provider verifies', async () => {
  const restore = mockProvider();
  try {
    const claims = await verify(idToken());
    assert.equal(claims.sub, 'user-123');
    assert.equal(claims.email, 'a@example.com');
  } finally { restore(); }
});

test('THE OLD BUG: a token minted for a DIFFERENT application is refused', async () => {
  // This is the whole reason the previous implementation was unsafe. Same provider, same user,
  // real signature — but issued to somebody else's client. It must not buy a session here.
  const restore = mockProvider();
  try {
    await assert.rejects(() => verify(idToken({ aud: 'someone-elses-client' })), /audience/i);
  } finally { restore(); }
});

test('...and neither is one that merely LISTS us alongside its real audience', async () => {
  // aud can be an array. azp names who it was actually issued to, and if that is not us then we
  // are a bystander in someone else's token — the confused-deputy case.
  const restore = mockProvider();
  try {
    await assert.rejects(
      () => verify(idToken({ aud: [CLIENT_ID, 'other'], azp: 'other' })),
      /issued to a different application/i,
    );
  } finally { restore(); }
});

test('a token captured from an earlier login cannot be replayed', async () => {
  // The nonce is minted per login and kept in a signed cookie. Without this check a correctly
  // audienced token, obtained any way at all, would be reusable forever.
  const restore = mockProvider();
  try {
    await assert.rejects(() => verify(idToken({ nonce: 'A-DIFFERENT-LOGIN' })), /nonce/i);
  } finally { restore(); }
});

test('alg:none is refused', async () => {
  const restore = mockProvider();
  try {
    // Hand-built, because jsonwebtoken will not sign 'none' for you.
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT', kid: KID })).toString('base64url');
    const body = Buffer.from(JSON.stringify({
      iss: ISSUER, aud: CLIENT_ID, sub: 'x', email: 'a@example.com', nonce: 'NONCE',
      exp: Math.floor(Date.now() / 1000) + 300,
    })).toString('base64url');
    await assert.rejects(() => verify(`${header}.${body}.`), /algorithm/i);
  } finally { restore(); }
});

test('an HMAC-signed token is refused even though the "key" is public', async () => {
  // HS256 verifies with a shared secret. The only key we hold for a provider is its PUBLIC one,
  // which the attacker also has — so accepting HMAC would let anyone sign their own identity.
  const restore = mockProvider();
  try {
    const forged = jwt.sign(
      { iss: ISSUER, aud: CLIENT_ID, sub: 'x', email: 'admin@example.com', nonce: 'NONCE' },
      publicKey.export({ type: 'spki', format: 'pem' }),
      { algorithm: 'HS256', keyid: KID, expiresIn: '5m' },
    );
    await assert.rejects(() => verify(forged), /algorithm/i);
  } finally { restore(); }
});

test('a token signed by the wrong key is refused', async () => {
  const restore = mockProvider();
  try {
    await assert.rejects(() => verify(idToken({}, { key: rogue.privateKey })), /signature/i);
  } finally { restore(); }
});

test('an expired token is refused', async () => {
  const restore = mockProvider();
  try {
    const stale = jwt.sign(
      { iss: ISSUER, aud: CLIENT_ID, sub: 'x', email: 'a@example.com', nonce: 'NONCE',
        exp: Math.floor(Date.now() / 1000) - 3600 },
      privateKey, { algorithm: 'RS256', keyid: KID },
    );
    await assert.rejects(() => verify(stale), /expired/i);
  } finally { restore(); }
});

test('a provider whose discovery claims a different issuer is refused', async () => {
  // Discovery is fetched from a URL derived from the configured issuer, so a document naming a
  // DIFFERENT one is either broken or hostile. Either way its tokens must not be accepted under a
  // name it does not own.
  const restore = mockProvider({ doc: discoveryDoc('https://evil.example.com') });
  try {
    await assert.rejects(() => verify(idToken()), /issuer mismatch/i);
  } finally { restore(); }
});

test('verification cannot be skipped by omitting the nonce', async () => {
  // Belt and braces: the caller must always have a nonce to compare, so a coding mistake that
  // forgets to pass one fails closed rather than accepting anything.
  const restore = mockProvider();
  try {
    await assert.rejects(() => verify(idToken(), { nonce: undefined }), /nonce/i);
  } finally { restore(); }
});

test('an unknown kid triggers exactly one JWKS refresh, then gives up', async () => {
  // Key rotation is normal and must not fail every login until a cache expires; a token quoting
  // nonsense must not become a way to hammer the provider either.
  let jwksFetches = 0;
  const real = global.fetch;
  global.fetch = async (url) => {
    const u = String(url);
    if (u.endsWith('/.well-known/openid-configuration')) return { ok: true, status: 200, json: async () => discoveryDoc() };
    if (u.endsWith('/jwks')) { jwksFetches++; return { ok: true, status: 200, json: async () => JWKS }; }
    return { ok: false, status: 404, json: async () => ({}) };
  };
  oidc._resetCaches();
  try {
    await assert.rejects(() => verify(idToken({}, { kid: 'no-such-kid' })), /no signing key/i);
    assert.equal(jwksFetches, 1, 'one refresh, not a loop');
  } finally { global.fetch = real; oidc._resetCaches(); }
});

// ---------------------------------------------------------------------------------------------
// PKCE

test('PKCE uses S256 and never sends the verifier', () => {
  const { verifier, challenge, method } = oidc.createPkce();
  assert.equal(method, 'S256');
  assert.notEqual(verifier, challenge, 'a plain challenge would make PKCE pointless');
  const expected = crypto.createHash('sha256').update(verifier).digest('base64url');
  assert.equal(challenge, expected);
  assert.ok(verifier.length >= 43, 'RFC 7636 wants at least 43 characters of entropy');
});

test('every login gets fresh values', () => {
  const a = oidc.createPkce(); const b = oidc.createPkce();
  assert.notEqual(a.verifier, b.verifier);
  assert.notEqual(oidc.randomToken(), oidc.randomToken());
});

// ---------------------------------------------------------------------------------------------
// The provider registry

test('Google registers from the variable the README always documented', () => {
  const [g] = providers.list({ GOOGLE_CLIENT_ID: 'g' });
  assert.equal(g.issuer, 'https://accounts.google.com');
});

test('a single-tenant Microsoft app narrows the issuer, so another tenant fails iss', () => {
  const [ms] = providers.list({ MICROSOFT_CLIENT_ID: 'm', MICROSOFT_TENANT_ID: 'abc-123' });
  assert.equal(ms.issuer, 'https://login.microsoftonline.com/abc-123/v2.0');
});

test('MULTI-TENANT MICROSOFT IS REFUSED, not silently broken', () => {
  /*
   * Two reasons pointing the same way. It cannot work: Microsoft's `common` metadata advertises the
   * literal template `https://login.microsoftonline.com/{tenantid}/v2.0`, so the issuer can never
   * equal the configured URL and every login fails at /start anyway.
   *
   * And the obvious patch is dangerous: loosening the iss comparison accepts tokens from EVERY
   * Azure tenant, which is nOAuth — any tenant admin can set an arbitrary unverified `email` on
   * their own user and be issued a session as that address here.
   */
  for (const tenant of ['common', 'organizations', 'consumers', '']) {
    assert.deepEqual(providers.list({ MICROSOFT_CLIENT_ID: 'm', MICROSOFT_TENANT_ID: tenant }), [],
      `MICROSOFT_TENANT_ID=${tenant || '(unset)'} must not register a provider`);
  }
});

test('any OIDC provider can be added by env', () => {
  const list = providers.list({
    OIDC_PROVIDERS: 'authentik',
    OIDC_AUTHENTIK_ISSUER: 'https://id.example.com/application/o/st/',
    OIDC_AUTHENTIK_CLIENT_ID: 'abc',
    OIDC_AUTHENTIK_NAME: 'Company SSO',
  });
  assert.equal(list.length, 1);
  assert.equal(list[0].slug, 'authentik');
  assert.equal(list[0].name, 'Company SSO');
  assert.equal(list[0].issuer, 'https://id.example.com/application/o/st', 'trailing slash normalised');
  assert.equal(list[0].clientSecret, null, 'PKCE means a public client is fine');
});

test('an incomplete or malformed provider is ignored rather than crashing boot', () => {
  assert.equal(providers.list({ OIDC_PROVIDERS: 'broken' }).length, 0, 'no issuer/client id');
  assert.equal(providers.list({
    OIDC_PROVIDERS: '../etc/passwd',
    OIDC_ISSUER: 'https://x', OIDC_CLIENT_ID: 'y',
  }).length, 0, 'a slug that is not URL-safe never becomes a route');
});

test('the browser is told slugs and names only — never a client id or secret', () => {
  const pub = providers.publicList({
    GOOGLE_CLIENT_ID: 'super-secret-id',
    OIDC_PROVIDERS: 'okta', OIDC_OKTA_ISSUER: 'https://x.okta.com',
    OIDC_OKTA_CLIENT_ID: 'id', OIDC_OKTA_CLIENT_SECRET: 'shh',
  });
  const serialised = JSON.stringify(pub);
  assert.ok(!serialised.includes('super-secret-id'));
  assert.ok(!serialised.includes('shh'));
  assert.deepEqual(Object.keys(pub[0]).sort(), ['name', 'slug']);
});

// ---------------------------------------------------------------------------------------------
// Per-organization SSO.
//
// Instance providers belong to whoever runs the server; these belong to a CUSTOMER. Two properties
// matter more than the feature itself: one organization must not be able to capture another's
// logins, and the login page must not become a way to enumerate who the customers are.

const Database = require('better-sqlite3');

function orgDb() {
  const d = new Database(':memory:');
  d.exec(`
    CREATE TABLE org_sso_providers (
      id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, slug TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL, issuer TEXT NOT NULL, client_id TEXT NOT NULL, client_secret_enc TEXT,
      scopes TEXT NOT NULL DEFAULT 'openid email profile', email_domains TEXT NOT NULL DEFAULT '',
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);
  `);
  return d;
}

function withOrgDb(rows, fn) {
  const d = orgDb();
  for (const r of rows) {
    d.prepare(`INSERT INTO org_sso_providers (id, organization_id, slug, name, issuer, client_id, email_domains, enabled)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(r.id, r.org, r.slug, r.name, r.issuer || ISSUER, r.clientId || 'cid', r.domains || '', r.enabled === undefined ? 1 : r.enabled);
  }
  // Swap the module's lazily-resolved connection for this in-memory one.
  const real = require('../db/database');
  const saved = real.db;
  real.db = d;
  delete require.cache[require.resolve('../lib/oidc-providers')];
  const mod = require('../lib/oidc-providers');
  try { return fn(mod); } finally {
    real.db = saved;
    delete require.cache[require.resolve('../lib/oidc-providers')];
  }
}

test('an org provider is found by the email DOMAIN', () => {
  withOrgDb([{ id: '1', org: 'org-a', slug: 'orgaaa', name: 'Acme SSO', domains: 'acme.com,acme.co.uk' }], (m) => {
    assert.equal(m.forEmail('someone@acme.com').name, 'Acme SSO');
    assert.equal(m.forEmail('someone@ACME.CO.UK').name, 'Acme SSO', 'case-insensitive');
    assert.equal(m.forEmail('someone@other.com'), null);
    assert.equal(m.forEmail('not-an-email'), null);
  });
});

test('a disabled provider stops answering for its domain', () => {
  withOrgDb([{ id: '1', org: 'org-a', slug: 'orgaaa', name: 'Acme', domains: 'acme.com', enabled: 0 }], (m) => {
    assert.equal(m.forEmail('x@acme.com'), null);
    assert.equal(m.getOrgProvider('orgaaa'), null, 'and cannot be started directly either');
  });
});

test('ORG PROVIDERS ARE NEVER PUBLISHED to the whole internet', () => {
  // The login page lists instance-wide providers only. Listing a customer's IdP would both offer it
  // to people it does not belong to and leak the customer list.
  withOrgDb([{ id: '1', org: 'org-a', slug: 'orgaaa', name: 'Acme SSO', domains: 'acme.com' }], (m) => {
    const pub = m.publicList({ GOOGLE_CLIENT_ID: 'g' });
    assert.deepEqual(pub.map((p) => p.slug), ['google']);
    assert.ok(!JSON.stringify(pub).includes('Acme'), 'no customer name anywhere in the public list');
  });
});

test('an org provider is still resolvable by slug, so the shared login flow can run it', () => {
  withOrgDb([{ id: '1', org: 'org-a', slug: 'orgaaa', name: 'Acme SSO', domains: 'acme.com' }], (m) => {
    const p = m.get('orgaaa', {});
    assert.equal(p.name, 'Acme SSO');
    assert.equal(p.organizationId, 'org-a', 'carries its org so the callback can grant membership');
    assert.equal(p.source, 'org');
  });
});

test('an instance provider wins a slug clash with an org one', () => {
  withOrgDb([{ id: '1', org: 'org-a', slug: 'google', name: 'Impostor', domains: 'evil.com' }], (m) => {
    // Org slugs are randomly generated so this cannot happen by accident — but if it ever did, a
    // tenant must not be able to shadow the platform's own Google button.
    assert.equal(m.get('google', { GOOGLE_CLIENT_ID: 'real' }).name, 'Google');
  });
});

test('the first organization to claim a domain keeps it', () => {
  // Two rows, same domain. forEmail must be deterministic rather than returning whichever the
  // database happened to hand back first — the API refuses the second claim, and this is the
  // backstop if a row ever gets in another way.
  withOrgDb([
    { id: '1', org: 'org-a', slug: 'orgaaa', name: 'First', domains: 'shared.com' },
    { id: '2', org: 'org-b', slug: 'orgbbb', name: 'Second', domains: 'shared.com' },
  ], (m) => {
    assert.equal(m.forEmail('x@shared.com').name, 'First');
  });
});

test('no database means no org providers, and no crash', () => {
  // The env-only paths must keep working on an instance where the table has not been migrated yet.
  const m = require('../lib/oidc-providers');
  assert.doesNotThrow(() => m.publicList({ GOOGLE_CLIENT_ID: 'g' }));
});


// ---------------------------------------------------------------------------------------------
// Regressions for defects found in security review. Each one was demonstrated end to end against a
// running server before it was fixed; none of them was hypothetical.

test('TAKEOVER: an org provider may not assert an email outside its own domains', () => {
  /*
   * The worst defect in this feature. An org admin supplies the issuer and client id, so they
   * control the IdP completely and can mint a token asserting ANY email with email_verified:true —
   * including a platform_admin's. Every cryptographic check passes honestly, because the attacker
   * IS the issuer. Three reviewers demonstrated a full session as the victim independently.
   *
   * The confinement lives in the callback; this pins the data it depends on, so a provider loaded
   * from the database always carries the domains its assertions are checked against.
   */
  withOrgDb([{ id: '1', org: 'org-evil', slug: 'orgevil', name: 'Evil', domains: 'evil.test' }], (m) => {
    const p = m.getOrgProvider('orgevil');
    assert.equal(p.emailDomains, 'evil.test', 'the callback cannot confine what it cannot see');
    assert.equal(p.organizationId, 'org-evil', 'and must know this is a tenant provider, not the operator\'s');
  });
});

test('an INSTANCE provider carries no organization, so it is not domain-confined', () => {
  // Operator-chosen providers keep the trust they have always had; confinement targets tenants.
  const [g] = providers.list({ GOOGLE_CLIENT_ID: 'g' });
  assert.equal(g.organizationId, undefined);
  assert.equal(g.source, 'env');
});

test('domain routing is deterministic, not table-scan order', () => {
  // forEmail used an unordered SELECT, so deleting and re-adding a provider silently flipped which
  // IdP an entire domain routed to. Ordering makes the answer stable.
  withOrgDb([
    { id: 'b', org: 'org-a', slug: 'orgbbb', name: 'Second', domains: 'shared.test' },
    { id: 'a', org: 'org-a', slug: 'orgaaa', name: 'First', domains: 'shared.test' },
  ], (m) => {
    const first = m.forEmail('x@shared.test').name;
    assert.equal(m.forEmail('x@shared.test').name, first, 'same answer every time');
  });
});

test('a secret that cannot be decrypted fails CLOSED', () => {
  // decrypt() returns null after a JWT_SECRET rotation, which silently downgraded a confidential
  // client to a public one — the login then failed at the provider with an error nobody could act
  // on, while the admin screen still said "a secret is set".
  withOrgDb([{ id: '1', org: 'o', slug: 'orgsec', name: 'X', domains: 'x.test' }], (m) => {
    const real = require('../db/database');
    real.db.prepare('UPDATE org_sso_providers SET client_secret_enc = ? WHERE id = ?').run('not-decryptable', '1');
    assert.throws(() => m.getOrgProvider('orgsec'), /could not be decrypted/);
  });
});

test('a tenant cannot claim a public email provider as its sign-in domain', () => {
  /*
   * Demonstrated in review: a tenant claimed gmail.com, after which /sso/discover answered
   * {"sso":true} for every Gmail address and the login page offered "sign in with your
   * organization" — a phishing hop launched from the vendor's own login screen, pointed at
   * infrastructure the tenant controls. First-claim-wins also meant one cheap account could deny a
   * public domain to everyone else.
   */
  const { isPublicEmailDomain } = require('../lib/public-email-domains');
  for (const d of ['gmail.com', 'outlook.com', 'hotmail.co.uk', 'yahoo.com', 'icloud.com',
    'proton.me', 'qq.com', 'mail.ru', 'comcast.net', 'gmx.de']) {
    assert.ok(isPublicEmailDomain(d), `${d} must be refused as an org sign-in domain`);
  }
  // ...and a real company domain is still fine, or the feature would be pointless.
  for (const d of ['acme.com', 'bigcorp.io', 'my-company.co.uk', 'mail.acme.com']) {
    assert.equal(isPublicEmailDomain(d), false, `${d} must remain claimable`);
  }
});

test('the blocklist is case- and whitespace-insensitive', () => {
  // Domains arrive from a form. `  GMAIL.COM ` must not slip through a lowercase-only comparison.
  const { isPublicEmailDomain } = require('../lib/public-email-domains');
  assert.ok(isPublicEmailDomain('  GMAIL.COM '));
  assert.ok(isPublicEmailDomain('Outlook.Com'));
});
