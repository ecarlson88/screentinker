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

test('Google and Microsoft register from the variables the README always documented', () => {
  const list = providers.list({ GOOGLE_CLIENT_ID: 'g', MICROSOFT_CLIENT_ID: 'm', MICROSOFT_TENANT_ID: 'common' });
  const byslug = Object.fromEntries(list.map((p) => [p.slug, p]));
  assert.equal(byslug.google.issuer, 'https://accounts.google.com');
  assert.equal(byslug.microsoft.issuer, 'https://login.microsoftonline.com/common/v2.0');
});

test('a single-tenant Microsoft app narrows the issuer, so another tenant fails iss', () => {
  const [ms] = providers.list({ MICROSOFT_CLIENT_ID: 'm', MICROSOFT_TENANT_ID: 'abc-123' });
  assert.equal(ms.issuer, 'https://login.microsoftonline.com/abc-123/v2.0');
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
