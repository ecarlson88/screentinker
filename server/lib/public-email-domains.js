'use strict';

/*
 * Email domains nobody may claim for organization SSO.
 *
 * Per-org SSO routes everyone at a domain to that organization's identity provider. Applied to a
 * company domain that is the point. Applied to a CONSUMER domain it is an attack: one tenant claims
 * `gmail.com`, and from then on every Gmail user who types their address into this product's login
 * page is offered a "sign in with your organization" button that sends them to infrastructure the
 * tenant controls — phishing launched from the vendor's own trusted login screen. First-claim-wins
 * also lets one cheap account deny a public domain to everyone else, permanently.
 *
 * ⚠️ This is a floor, not a ceiling. It stops the mass-abuse case; it does NOT stop a tenant
 * claiming a domain that belongs to some specific other company. Only proof of control — a DNS TXT
 * record, or a challenge to postmaster@ — settles that, and until it exists a claimed domain means
 * "nobody else had claimed it", not "they own it".
 *
 * Kept as data, in one file, because it is a list that will need adding to and that is the cheapest
 * possible edit. Matching is exact on the registrable domain, so `mail.google.com` is not blocked by
 * `gmail.com` — subdomains of consumer providers are not a realistic sign-in domain anyway.
 */

const PUBLIC_EMAIL_DOMAINS = new Set([
  // Google
  'gmail.com', 'googlemail.com',
  // Microsoft
  'outlook.com', 'outlook.co.uk', 'hotmail.com', 'hotmail.co.uk', 'hotmail.fr', 'hotmail.it',
  'live.com', 'live.co.uk', 'msn.com', 'passport.com',
  // Yahoo and friends
  'yahoo.com', 'yahoo.co.uk', 'yahoo.co.jp', 'yahoo.fr', 'yahoo.de', 'yahoo.ca', 'yahoo.com.au',
  'ymail.com', 'rocketmail.com', 'aol.com', 'aim.com',
  // Apple
  'icloud.com', 'me.com', 'mac.com',
  // Privacy-focused
  'proton.me', 'protonmail.com', 'pm.me', 'tutanota.com', 'tutanota.de', 'tuta.io', 'tuta.com',
  'duck.com', 'hey.com', 'fastmail.com', 'fastmail.fm',
  // Other large consumer providers
  'gmx.com', 'gmx.de', 'gmx.net', 'gmx.at', 'gmx.ch', 'web.de', 'mail.com', 'email.com',
  'zoho.com', 'zohomail.com', 'yandex.com', 'yandex.ru', 'ya.ru', 'mail.ru', 'bk.ru', 'inbox.ru',
  'list.ru', 'rambler.ru',
  'qq.com', 'foxmail.com', '163.com', '126.com', 'sina.com', 'sina.cn', 'naver.com', 'daum.net',
  'hanmail.net', 'rediffmail.com',
  // ISP-style mailboxes, where the domain belongs to the ISP and not to any customer
  'comcast.net', 'verizon.net', 'att.net', 'sbcglobal.net', 'bellsouth.net', 'cox.net',
  'charter.net', 'earthlink.net', 'juno.com', 'optonline.net', 'roadrunner.com',
  'btinternet.com', 'sky.com', 'virginmedia.com', 'talktalk.net', 'orange.fr', 'wanadoo.fr',
  'free.fr', 'laposte.net', 'libero.it', 'virgilio.it', 'tiscali.it', 'terra.com.br', 'uol.com.br',
  'bol.com.br', 'telus.net', 'shaw.ca', 'rogers.com', 'sympatico.ca', 'bigpond.com', 'optusnet.com.au',
  't-online.de', 'freenet.de', 'arcor.de',
]);

/** True when this domain is a consumer mailbox provider rather than an organization's own domain. */
function isPublicEmailDomain(domain) {
  return PUBLIC_EMAIL_DOMAINS.has(String(domain || '').trim().toLowerCase());
}

module.exports = { PUBLIC_EMAIL_DOMAINS, isPublicEmailDomain };
