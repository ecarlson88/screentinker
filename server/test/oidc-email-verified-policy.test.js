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
 *   - `email_verified: true`                       -> believed, always
 *   - claim ABSENT + operator-chosen               -> believed (Microsoft, or an opted-in provider)
 *   - claim ABSENT + org with a VERIFIED domain    -> believed (it proved DNS control)
 *   - claim ABSENT + org with NO verified domain   -> refused (it has proven nothing)
 *   - `email_verified: false`                      -> refused, whoever asked
 *
 * The org case is a consequence of DNS proof, never a setting: an organization must not be able to
 * turn it on for itself, so it is derived and never read from a column.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { emailIsVerified, list } = require('../lib/oidc-providers');

const MS_ENV = { MICROSOFT_CLIENT_ID: 'client-abc', MICROSOFT_TENANT_ID: 'ffffffff-1111-2222-3333-444444444444' };
const microsoft = () => list(MS_ENV).find((p) => p.slug === 'microsoft');
const google = () => list({ GOOGLE_CLIENT_ID: 'g-abc' }).find((p) => p.slug === 'google');
// An org provider as rowToProvider builds it: `assumeEmailVerified` follows from whether any domain
// has actually been DNS-verified.
const orgProvider = (verifiedDomains = []) => ({
  slug: 'acme7f3', source: 'org', organizationId: 'org-1',
  emailDomains: verifiedDomains.join(','),
  assumeEmailVerified: verifiedDomains.length > 0,
});
const orgUnproven = orgProvider();                     // configured, nothing verified yet
const orgProven = orgProvider(['bytetinker.net']);     // TXT published, domain green

test('an explicit true is believed from any provider', () => {
  for (const p of [microsoft(), google(), orgUnproven, orgProven]) {
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

test('an org provider that has proven a domain may assume — the customer-Entra case', () => {
  // Entra sends no email_verified. Before this, the domain went green and the login still failed.
  assert.equal(emailIsVerified({ email: 'dan@bytetinker.net' }, orgProven), true);
});

test('an org provider that has proven NOTHING assumes nothing', () => {
  assert.equal(emailIsVerified({ email: 'dan@bytetinker.net' }, orgUnproven), false);
});

test('the org assumption is DERIVED from proof, never readable from the row', () => {
  const src = require('fs').readFileSync(require.resolve('../lib/oidc-providers'), 'utf8');
  assert.match(src, /assumeEmailVerified: verified\.length > 0,\s*\n\s*source: 'org'/,
    'rowToProvider must derive it from the verified-domain list, next to source:org');
  // The whole point: an organization must not be able to switch this on for itself.
  assert.doesNotMatch(src, /assumeEmailVerified: *row\./, 'must never be read from the org row');
  // ...and there must be no column for it to be read FROM. Checked against the schema rather than
  // this file, where `OIDC_<SLUG>_ASSUME_EMAIL_VERIFIED` is a legitimate operator-set env var.
  const schema = require('fs').readFileSync(require.resolve('../db/database'), 'utf8');
  assert.doesNotMatch(schema, /assume_email_verified/i,
    'org_sso_providers must have no assume_email_verified column');
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
