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
 * ONE RECORD FORM — a TXT record at a dedicated name:
 *
 *   _screentinker-verify.example.com.  IN  TXT  "st-verify=<token>"
 *
 * A CNAME alternative was drafted and dropped. It would have pointed at
 * `<token>.verify.screentinker.com`, which requires operating a wildcard DNS zone that answers for
 * every token ever issued — infrastructure this project does not have, so the instructions would
 * have described a check that could never pass. TXT needs nothing but the customer's own zone.
 *
 * A dedicated `_`-prefixed name is used rather than the apex on purpose: an apex TXT record sits
 * alongside SPF and DMARC, where a careless edit breaks mail, and it is the one record set an
 * administrator is most reluctant to touch.
 *
 * ⚠️ THE PROOF NAME MUST NOT BE A CNAME. A TXT lookup follows CNAMEs transparently, and RFC 4592
 * means a wildcard `*.example.com` synthesizes `_screentinker-verify.example.com` too — so a
 * wildcard CNAME pointing anywhere the attacker controls would let them prove a domain they do not
 * own. That turns an ordinary subdomain takeover into an apex takeover, and from there into every
 * `@example.com` login. ACME's dns-01 permits this delegation deliberately; here the thing being
 * delegated is the whole company's sign-in, so it is refused instead.
 */

const dns = require('dns').promises;
const crypto = require('crypto');

const RECORD_PREFIX = '_screentinker-verify';
const TXT_PREFIX = 'st-verify=';

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
  if (!row) return false;
  // `verified_at` is compared to null, NOT tested for truthiness: SQL asks `IS NOT NULL` and a
  // stored 0 would otherwise be "verified" to the router and "unverified" here — two definitions of
  // the same word, which is how a domain ends up routing while the code believes it cannot.
  if (row.verified_at !== null && row.verified_at !== undefined) return false;
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

  /*
   * Refuse before looking at the TXT at all if the name is delegated. Checking afterwards would
   * still be safe, but doing it first means the answer never depends on what the delegation target
   * happens to say.
   */
  try {
    const cnames = await withTimeout(dns.resolveCname(name), LOOKUP_TIMEOUT_MS);
    if (cnames && cnames.length) {
      return {
        ok: false,
        error: `${name} is a CNAME (to ${cnames[0]}). The record must be a TXT record in this `
          + 'domain\u2019s own zone — a delegated name would let whoever controls the target prove this domain.',
      };
    }
  } catch { /* no CNAME is the normal and wanted case */ }

  let records;
  try {
    records = await withTimeout(dns.resolveTxt(name), LOOKUP_TIMEOUT_MS);
  } catch (e) {
    // NXDOMAIN and "no such record" are the ORDINARY answers here — an admin checking before the
    // record has propagated — so they are "not found yet", not an error to be alarmed by.
    if (/timed out/i.test(e.message)) return { ok: false, error: 'the DNS lookup timed out — try again shortly' };
    return { ok: false, error: `no ${RECORD_PREFIX} record found for ${domain} yet (DNS can take a few minutes)` };
  }

  // resolveTxt returns arrays of string chunks — a value over 255 bytes is split, so join first.
  for (const chunks of records) {
    if (chunks.join('').trim() === wantTxt) return { ok: true, via: 'TXT' };
  }

  // Present but wrong is a different problem from absent, and the fixes differ: one needs
  // correcting, the other needs publishing. A wildcard TXT lands here, which is right — it answers
  // with its own value, and that is not a proof of anything. (A wildcard CNAME is refused above.)
  if (records.length) {
    const found = records.map((c) => c.join('')).join('; ');
    return { ok: false, error: `${name} exists but does not match. Found: ${found}` };
  }
  return { ok: false, error: `no ${RECORD_PREFIX} record found for ${domain} yet (DNS can take a few minutes)` };
}

module.exports = {
  check, instructions, newToken, recordName, isClaimExpired,
  CLAIM_TTL_S, RECORD_PREFIX, TXT_PREFIX,
};
