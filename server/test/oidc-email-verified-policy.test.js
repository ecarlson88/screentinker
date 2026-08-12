'use strict';

/*
 * Who may be believed about an email address.
 *
 * Regression: requiring `claims.email_verified === true` made Microsoft sign-in impossible, because
 * Entra ID v2 does not send the claim. Every Entra login authenticated and was then refused with
 * `email_unverified`. The previous test suite asserted how the Microsoft ISSUER string is built but
 * never pushed a Microsoft-shaped token through the policy, so nothing failed.
 *
 * The rule these tests pin down:
 *   - `email_verified: true`            -> believed, always
 *   - claim ABSENT + operator-chosen    -> believed (Microsoft, or an opted-in generic provider)
 *   - claim ABSENT + org-configured     -> refused
 *   - `email_verified: false`           -> refused, whoever asked
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { emailIsVerified, list } = require('../lib/oidc-providers');

const MS_ENV = { MICROSOFT_CLIENT_ID: 'client-abc', MICROSOFT_TENANT_ID: 'ffffffff-1111-2222-3333-444444444444' };
const microsoft = () => list(MS_ENV).find((p) => p.slug === 'microsoft');
const google = () => list({ GOOGLE_CLIENT_ID: 'g-abc' }).find((p) => p.slug === 'google');
const orgProvider = { slug: 'acme7f3', source: 'org', organizationId: 'org-1', assumeEmailVerified: false };

test('an explicit true is believed from any provider', () => {
  for (const p of [microsoft(), google(), orgProvider]) {
    assert.equal(emailIsVerified({ email_verified: true }, p), true, `${p.slug} should accept an explicit true`);
  }
});

test('Microsoft omits the claim and is still believed (the regression)', () => {
  const ms = microsoft();
  assert.equal(ms.assumeEmailVerified, true, 'the tenant-pinned Microsoft entry must assume verification');
  assert.equal(emailIsVerified({ email: 'someone@example.com' }, ms), true);
});

test('Google stays strict — it does send the claim, so there is nothing to assume', () => {
  const g = google();
  assert.equal(g.assumeEmailVerified, false);
  assert.equal(emailIsVerified({ email: 'someone@example.com' }, g), false);
});

test('an ORG-configured provider may never assume, even if the object claims it can', () => {
  assert.equal(emailIsVerified({ email: 'a@b.c' }, orgProvider), false);
  // Belt and braces: a tampered/hand-built org object must not be able to opt itself in through
  // the database, which is why rowToProvider pins the field rather than reading a column.
  const src = require('fs').readFileSync(require.resolve('../lib/oidc-providers'), 'utf8');
  assert.match(src, /assumeEmailVerified: false,\s*\n\s*source: 'org'/,
    'rowToProvider must hard-code assumeEmailVerified:false next to source:org');
  assert.doesNotMatch(src, /assumeEmailVerified: *row\./, 'must never be read from the org row');
});

test('an EXPLICIT false is refused even where absence would be assumed', () => {
  assert.equal(emailIsVerified({ email_verified: false }, microsoft()), false);
  assert.equal(emailIsVerified({ email_verified: 'false' }, microsoft()), false, 'a string is not a true');
  assert.equal(emailIsVerified({ email_verified: 0 }, microsoft()), false);
});

test('a generic provider can opt in by env, and is strict without it', () => {
  const base = { OIDC_PROVIDERS: 'keycloak', OIDC_KEYCLOAK_ISSUER: 'https://kc.example.com', OIDC_KEYCLOAK_CLIENT_ID: 'kc' };
  const strict = list(base).find((p) => p.slug === 'keycloak');
  assert.equal(strict.assumeEmailVerified, false);
  assert.equal(emailIsVerified({}, strict), false);

  const opted = list({ ...base, OIDC_KEYCLOAK_ASSUME_EMAIL_VERIFIED: 'true' }).find((p) => p.slug === 'keycloak');
  assert.equal(opted.assumeEmailVerified, true);
  assert.equal(emailIsVerified({}, opted), true);
  assert.equal(emailIsVerified({ email_verified: false }, opted), false, 'opting in never overrides an explicit false');
});

test('missing claims object or provider does not throw and does not pass', () => {
  assert.equal(emailIsVerified(null, microsoft()), true, 'no claims at all still consults the provider policy');
  assert.equal(emailIsVerified({}, null), false);
  assert.equal(emailIsVerified({}, undefined), false);
});
