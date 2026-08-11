'use strict';

/*
 * Proving that a tenant controls a sign-in domain.
 *
 * Per-organization SSO routes everyone at a domain to that organization's identity provider. That
 * is exactly right when the organization owns the domain and an account-takeover primitive when it
 * does not — and typing a domain into a form is not ownership. A review demonstrated the whole
 * chain: claim a company's domain, sign in as a named address there, and the real owner is left
 * unable to reach an account bearing their own address.
 *
 * DNS is the check, because control of a domain's DNS is what "owning a domain" means in the only
 * sense that matters here. It is also the mechanism every other vendor uses, so the instructions
 * are already familiar to the person who has to follow them.
 *
 * TWO RECORD FORMS, both at the same name, because organizations differ in what their DNS lets
 * them add — some providers refuse TXT at a subdomain, some refuse CNAME anywhere useful:
 *
 *   _screentinker-verify.example.com.  IN  TXT    "st-verify=<token>"
 *   _screentinker-verify.example.com.  IN  CNAME  <token>.verify.screentinker.com.
 *
 * A dedicated `_`-prefixed name is used rather than the apex on purpose: an apex TXT record sits
 * alongside SPF and DMARC, where a careless edit breaks mail, and it is the one record set an
 * administrator is most reluctant to touch.
 */

const dns = require('dns').promises;
const crypto = require('crypto');

const RECORD_PREFIX = '_screentinker-verify';
const TXT_PREFIX = 'st-verify=';
const CNAME_SUFFIX = '.verify.screentinker.com';

// A DNS answer that never arrives must not hold an HTTP request open. The resolver's own retries
// sit under this, so it is a ceiling on the whole lookup rather than on one query.
const LOOKUP_TIMEOUT_MS = 5000;

/*
 * How long an UNVERIFIED claim is worth anything.
 *
 * A claim reserves the domain so two tenants cannot race it — but a reservation that never lapses
 * is squatting with extra steps: type a company's domain, prove nothing, and hold it against its
 * real owner forever. Eight hours is comfortably longer than a DNS change takes to publish and
 * propagate, and short enough that an unprovable claim is gone by the next working day.
 *
 * The token dies with the claim. Trying again mints a NEW token, so an old record left in DNS from
 * a lapsed attempt proves nothing, and a domain that changed hands cannot be verified with the
 * previous holder's value.
 *
 * A VERIFIED domain is not affected — proof already happened, and re-proving on a timer would log
 * out a customer over a DNS edit made months later.
 */
const CLAIM_TTL_S = 8 * 60 * 60;

/** True when an unverified claim has run out of time and no longer reserves anything. */
function isClaimExpired(row, nowS = Math.floor(Date.now() / 1000)) {
  if (!row || row.verified_at) return false;
  return (Number(row.token_issued_at) || 0) + CLAIM_TTL_S <= nowS;
}

/** Tokens are compared, so they are random and long enough that guessing is not a strategy. */
const newToken = () => crypto.randomBytes(16).toString('hex');

const recordName = (domain) => `${RECORD_PREFIX}.${domain}`;

/** Exactly what the admin has to publish — shown in the UI, so it is built in one place. */
function instructions(domain, token) {
  return {
    record_name: recordName(domain),
    txt_value: `${TXT_PREFIX}${token}`,
    cname_value: `${token}${CNAME_SUFFIX}`,
  };
}

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('DNS lookup timed out')), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/*
 * Look for the proof.
 *
 * Both record types are queried together and either one is enough. NXDOMAIN and "no such record"
 * are ordinary answers here — the overwhelmingly common case is an admin checking before the record
 * has propagated — so they are reported as "not found yet", never as an error to be alarmed by.
 *
 * ⚠️ Resolution uses the system resolver, which is the same view of DNS the operator already
 * trusts. A tenant that can poison that resolver can forge a proof, but a tenant that can do that
 * has already won something larger.
 */
async function check(domain, token) {
  const name = recordName(domain);
  const wantTxt = `${TXT_PREFIX}${token}`;
  const wantCname = `${token}${CNAME_SUFFIX}`;

  const results = await Promise.allSettled([
    withTimeout(dns.resolveTxt(name), LOOKUP_TIMEOUT_MS),
    withTimeout(dns.resolveCname(name), LOOKUP_TIMEOUT_MS),
  ]);

  const [txtRes, cnameRes] = results;

  if (txtRes.status === 'fulfilled') {
    // resolveTxt returns arrays of string chunks — a long value is split, so join before comparing.
    for (const chunks of txtRes.value) {
      if (chunks.join('').trim() === wantTxt) return { ok: true, via: 'TXT' };
    }
  }
  if (cnameRes.status === 'fulfilled') {
    for (const target of cnameRes.value) {
      // DNS names are case-insensitive and may or may not carry the root dot.
      if (target.replace(/\.$/, '').toLowerCase() === wantCname.toLowerCase()) return { ok: true, via: 'CNAME' };
    }
  }

  // Nothing matched. Say which of the two failure shapes it is, because the fixes differ: a record
  // that is absent needs publishing, a record that is present but wrong needs correcting.
  const found = [];
  if (txtRes.status === 'fulfilled') found.push(...txtRes.value.map((c) => `TXT ${c.join('')}`));
  if (cnameRes.status === 'fulfilled') found.push(...cnameRes.value.map((c) => `CNAME ${c}`));

  if (found.length) {
    return { ok: false, error: `${name} exists but does not match. Found: ${found.join('; ')}` };
  }

  const timedOut = results.some((r) => r.status === 'rejected' && /timed out/i.test(r.reason && r.reason.message));
  if (timedOut) return { ok: false, error: 'the DNS lookup timed out — try again shortly' };

  return { ok: false, error: `no ${RECORD_PREFIX} record found for ${domain} yet (DNS can take a few minutes)` };
}

module.exports = {
  check, instructions, newToken, recordName, isClaimExpired,
  CLAIM_TTL_S, RECORD_PREFIX, TXT_PREFIX, CNAME_SUFFIX,
};
