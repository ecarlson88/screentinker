const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const https = require('https');
const { v4: uuidv4 } = require('uuid');
const { db } = require('../db/database');
const { generateToken, generateMfaPendingToken, verifyMfaPendingToken, requireAuth, requireAdmin, requireSuperAdmin, isPlatformRole, isPlatformStaff, PLATFORM_ROLES } = require('../middleware/auth');
const { resolveTenancy } = require('../lib/tenancy');
const { logActivity, getClientIp } = require('../services/activity');
const totp = require('../lib/totp');
const totpLockout = require('../lib/totp-lockout');
const loginLockout = require('../lib/login-lockout');
const QRCode = require('qrcode');
const { sendSignupEmails, sendVerificationEmail, sendPasswordResetEmail } = require('../services/signupEmails');
const passwordReset = require('../lib/passwordReset');
const emailVerify = require('../lib/emailVerify');
const emailSvc = require('../services/email');
const { deleteUserCascade, OrgHasOtherMembersError } = require('../lib/user-deletion');
const config = require('../config');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const oidc = require('../lib/oidc');
const oidcProviders = require('../lib/oidc-providers');

// Phase 2.1: find or create the user's default org+workspace. Returns the
// workspace_id to embed in the JWT. Idempotent: if the user already has
// memberships (e.g. migrated from Phase 1), returns the first one without
// creating anything.
// #12: allowCreate gates the MINT path only. An existing membership is always
// returned (idempotent). When allowCreate is false and the user has no
// membership, returns null - the caller is created org-less and an admin /
// operator assigns them to a workspace afterward.
function ensureDefaultOrgForUser(user, { allowCreate = true } = {}) {
  const existing = db.prepare(`
    SELECT w.id FROM workspaces w
    JOIN workspace_members wm ON wm.workspace_id = w.id
    WHERE wm.user_id = ?
    ORDER BY wm.joined_at ASC LIMIT 1
  `).get(user.id);
  if (existing) return existing.id;
  if (!allowCreate) return null;

  // No memberships -> mint a fresh org and Default workspace owned by user.
  const orgId = uuidv4();
  const wsId  = uuidv4();
  const orgName = (user.name && user.name.trim())
    ? `${user.name}'s organization`
    : `${user.email}'s organization`;
  const tx = db.transaction(() => {
    db.prepare(`INSERT INTO organizations (
      id, name, owner_user_id, plan_id,
      stripe_customer_id, stripe_subscription_id,
      subscription_status, subscription_ends
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
      orgId, orgName, user.id, user.plan_id || 'free',
      user.stripe_customer_id || null, user.stripe_subscription_id || null,
      user.subscription_status || 'active', user.subscription_ends || null
    );
    db.prepare(`INSERT INTO organization_members (organization_id, user_id, role) VALUES (?, ?, 'org_owner')`).run(orgId, user.id);
    db.prepare(`INSERT INTO workspaces (id, organization_id, name, created_by) VALUES (?, ?, 'Default', ?)`).run(wsId, orgId, user.id);
    db.prepare(`INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?, ?, 'workspace_admin')`).run(wsId, user.id);
  });
  tx();
  return wsId;
}

function logFailedLogin(email, ip, reason) {
  try {
    db.prepare('INSERT INTO activity_log (user_id, action, details, ip_address) VALUES (NULL, ?, ?, ?)')
      .run('auth:login_failed', `${email} - ${reason}`, ip);
  } catch {}
}

function logSuccessfulLogin(userId, email, ip) {
  try {
    // Phase 2.2 writer-leak fix: stamp the user's oldest workspace so this
    // login event is queryable in tenant-scoped activity views. Multi-workspace
    // users still land on one row; the activity dashboard already shows
    // per-user context separately from per-workspace context.
    const ws = db.prepare(
      'SELECT workspace_id FROM workspace_members WHERE user_id = ? ORDER BY joined_at ASC LIMIT 1'
    ).get(userId);
    db.prepare('INSERT INTO activity_log (user_id, action, details, ip_address, workspace_id) VALUES (?, ?, ?, ?, ?)')
      .run(userId, 'auth:login_success', email, ip, ws?.workspace_id || null);
    db.prepare("UPDATE users SET last_login = strftime('%s','now') WHERE id = ?").run(userId);
  } catch {}
}

// ==================== Local Auth ====================

// Returns true if new account creation is allowed at this moment.
// First-user setup (empty DB) is always allowed so a fresh install can be initialized.
function canRegister() {
  if (!config.disableRegistration) return true;
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  return userCount === 0;
}

// Register
router.post('/register', (req, res) => {
  if (!canRegister()) {
    return res.status(403).json({ error: 'Public registration is disabled. Contact your administrator.' });
  }
  const { email, password, name, createOrg } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (existing) return res.status(409).json({ error: 'Email already registered' });

  const id = uuidv4();
  const passwordHash = bcrypt.hashSync(password, 10);

  // First user becomes platform_admin with enterprise plan (self-hosted) or free plan with Pro trial.
  // Phase 1 renamed the legacy 'superadmin' role to 'platform_admin'; new bootstrap users get the new name directly.
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  const role = userCount === 0 ? 'platform_admin' : 'user';
  const isFirstUser = userCount === 0;
  const plan = (isFirstUser && config.selfHosted) ? 'enterprise' : 'pro'; // Start on Pro trial
  const trialStarted = isFirstUser && config.selfHosted ? null : Math.floor(Date.now() / 1000);

  // Email verification: require it for a normal local signup only when we can actually send
  // the mail. The bootstrap (first) user is never gated — a fresh install must not lock out
  // its own admin — and neither is an instance with no email transport configured (a self-host
  // that can't send would otherwise strand every signup). email_verified column DEFAULTs to 1,
  // so we only ever write 0 here on the require-verification path.
  const requireVerify = !isFirstUser && emailSvc.isConfigured();
  const emailVerified = requireVerify ? 0 : 1;

  db.prepare(`
    INSERT INTO users (id, email, name, password_hash, auth_provider, role, plan_id, trial_started, trial_plan, email_verified)
    VALUES (?, ?, ?, ?, 'local', ?, ?, ?, ?, ?)
  `).run(id, email.toLowerCase(), name || email.split('@')[0], passwordHash, role, plan, trialStarted, trialStarted ? 'pro' : null, emailVerified);

  const user = db.prepare('SELECT id, email, name, role, auth_provider, avatar_url, plan_id, stripe_customer_id, stripe_subscription_id, subscription_status, subscription_ends, email_verified FROM users WHERE id = ?').get(id);
  // #12: org-on-create. Per-request createOrg overrides the deployment default
  // (config.autoCreateOrgOnSignup). The first user is always given an org so a
  // fresh install is never left headless. When neither applies, the user is
  // created org-less and lands on the "no workspaces yet" state until an admin
  // assigns them.
  const createOrgForUser = isFirstUser
    || (createOrg !== undefined ? !!createOrg : config.autoCreateOrgOnSignup);
  const workspaceId = ensureDefaultOrgForUser(user, { allowCreate: createOrgForUser });

  // Welcome + admin-notify emails (hosted instance only, idempotent, async).
  sendSignupEmails(user, req);

  // Verification email (issue a token first) whenever this signup needs to confirm its address.
  if (requireVerify) {
    const vtoken = emailVerify.issue(user.id);
    sendVerificationEmail(user, vtoken, req);
  }

  // Hosted (SELF_HOSTED unset) HARD-BLOCKS an unverified local signup: no session until they
  // click the link. Self-host is a soft nudge — fall through and issue the session; the client
  // shows a "verify your email" banner (user.email_verified === 0) with a resend button.
  if (requireVerify && !config.selfHosted) {
    return res.status(201).json({ verification_required: true, email: user.email });
  }

  const token = generateToken(user, workspaceId);
  res.status(201).json({ token, user, current_workspace_id: workspaceId });
});

// Login
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = db.prepare('SELECT * FROM users WHERE email = ? AND auth_provider = ?').get(email.toLowerCase(), 'local');
  if (!user) {
    logFailedLogin(email, getClientIp(req), 'User not found');
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // Per-ACCOUNT brute-force lockout (lib/login-lockout), on top of the per-IP limiter in
  // server.js. Checked BEFORE bcrypt so a locked account costs no hashing work.
  //
  // The response is deliberately IDENTICAL to a wrong password: a distinct 429 would tell
  // an attacker "this account exists and is under attack", turning the endpoint into an
  // account-existence oracle. The trade is that a locked-out legitimate user sees the
  // generic message, so the trip is written to activity_log for the operator instead.
  if (loginLockout.isLocked(user.id)) {
    logFailedLogin(email, getClientIp(req), 'Locked out (too many failed passwords)');
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  if (!bcrypt.compareSync(password, user.password_hash)) {
    const rec = loginLockout.recordFailure(user.id);
    if (rec.lockedUntil) logActivity(null, 'auth:login_locked', `${email} - locked after repeated failures`, null, getClientIp(req));
    logFailedLogin(email, getClientIp(req), 'Wrong password');
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // Password proven. Clear the counter HERE rather than in issueSession: the TOTP and
  // email-verification branches below return before issueSession is ever reached, so a
  // reset placed there would never fire for those accounts.
  loginLockout.reset(user.id);

  // Email verification gate. Unverified LOCAL accounts are asked to confirm on login — this
  // covers both new signups AND existing users who predate the feature (grandfathered locals are
  // email_verified=0). Gated ONLY where we can actually send the mail (isConfigured), so an
  // instance with no email transport never locks anyone out. Existing users never received a
  // signup email, so (re)send one here (guarded against re-mailing a still-valid token). HOSTED
  // hard-blocks — no session, no MFA step; self-host is a soft nudge (login proceeds, client
  // shows a banner). SSO + platform admins are grandfathered to 1, so this never trips for them.
  if (!user.email_verified && emailSvc.isConfigured()) {
    ensureVerificationEmail(user, req);
    if (!config.selfHosted) {
      return res.json({ verification_required: true, email: user.email });
    }
  }

  // #100: password OK. If TOTP is enabled, DON'T issue a session yet - return an
  // mfa_pending token; the client completes via POST /api/auth/totp/verify. This is
  // the ONLY place TOTP gates (interactive password login). The SSO routes and the
  // API-token path never reach here, so both bypass TOTP by construction.
  if (user.totp_enabled) {
    return res.json({ mfa_required: true, mfa_token: generateMfaPendingToken(user) });
  }
  issueSession(req, res, user);
});

// #100: finish an interactive login - shared by /login (no TOTP) and /totp/verify
// (after TOTP). Logs the successful login + issues the full session JWT.
function issueSession(req, res, user, extra = {}) {
  logSuccessfulLogin(user.id, user.email, getClientIp(req));
  const workspaceId = ensureDefaultOrgForUser(user, { allowCreate: config.autoCreateOrgOnSignup });
  const token = generateToken(user, workspaceId);
  // #100: callers pass a SELECT * row. Strip password_hash AND the TOTP internals
  // (the encrypted secret + the replay counter) so no secret/internal rides in the
  // response body - "secrets never in responses", same as the API token work.
  const { password_hash, totp_secret_enc, totp_last_step, ...safeUser } = user;
  res.json({ token, user: safeUser, current_workspace_id: workspaceId, ...extra });
}

// ==================== Email verification (signup) ====================
// (Re)send a verification email for an unverified user, UNLESS a still-valid token is already
// pending — so a login-gated user isn't re-mailed on every attempt. Callers have already checked
// emailSvc.isConfigured(). `user` is a SELECT * row (carries email_verify_expires).
function ensureVerificationEmail(user, req) {
  const now = Math.floor(Date.now() / 1000);
  if (user.email_verify_expires && user.email_verify_expires > now) return; // valid token still out
  const token = emailVerify.issue(user.id);
  sendVerificationEmail(user, token, req);
}

// The emailed link lands here (GET, unauthenticated — the user isn't logged in yet). We flip
// the flag and redirect into the app with a flash flag, so there's no separate frontend route.
router.get('/verify-email', (req, res) => {
  const ok = emailVerify.consume(req.query.token);
  return res.redirect(ok ? '/app#/login?verified=1' : '/app#/login?verify_error=1');
});

// Resend the verification email. Unauthenticated (the hosted gate blocks the session, so the
// user has no token) and rate-limited in server.js. Always returns a generic success so it
// never reveals whether an address exists or is already verified.
router.post('/resend-verification', (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  if (email) {
    const user = db.prepare("SELECT * FROM users WHERE email = ? AND auth_provider = 'local'").get(email);
    if (user && !user.email_verified) {
      const token = emailVerify.issue(user.id);
      sendVerificationEmail(user, token, req);
    }
  }
  res.json({ ok: true });
});

// ==================== Self-service password reset ====================
// Two endpoints, both unauthenticated by necessity (the user cannot log in).
//
// The request endpoint ALWAYS answers the same way — same status, same body — whether the
// address exists, is an SSO identity with no local password, or is malformed. Anything
// else turns it into an account-existence oracle, which is the classic mistake here.
//
// Completing a reset deliberately does NOT return a session. The user logs in afterwards,
// so a TOTP-enabled account still has to clear its second factor; issuing a token here
// would turn "read one email" into a full session and quietly bypass MFA.
const RESET_GENERIC_OK = { ok: true, message: 'If that address has an account, a reset link is on its way.' };

router.post('/forgot-password', (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  // Respond identically no matter what happens below.
  try {
    if (email) {
      const user = db.prepare("SELECT * FROM users WHERE email = ? AND auth_provider = 'local'").get(email);
      if (user) {
        if (!emailSvc.isConfigured()) {
          // Loud, because the user will wait for an email that can never arrive and the
          // generic response cannot tell them.
          console.error(`[password-reset] NO EMAIL TRANSPORT CONFIGURED — reset requested for ${email} cannot be delivered.`);
        } else {
          const token = passwordReset.issue(user.id);
          sendPasswordResetEmail(user, token, req).catch(e =>
            console.error('[password-reset] send failed:', e && e.message));
          logActivity(user.id, 'auth:password_reset_requested', null, null, getClientIp(req));
        }
      }
    }
  } catch (e) {
    console.error('[password-reset] request error:', e && e.message);
  }
  return res.json(RESET_GENERIC_OK);
});

router.post('/reset-password', (req, res) => {
  const { token, password } = req.body || {};
  if (!password || String(password).length < passwordReset.MIN_PASSWORD_LENGTH) {
    return res.status(400).json({ error: `Password must be at least ${passwordReset.MIN_PASSWORD_LENGTH} characters` });
  }
  const userId = passwordReset.consume(token, String(password));
  if (!userId) return res.status(400).json({ error: 'This reset link is invalid or has expired. Request a new one.' });
  // Someone who locked themselves out guessing must not stay locked out after proving
  // control of the mailbox and choosing a new password.
  loginLockout.reset(userId);
  const u = db.prepare('SELECT email FROM users WHERE id = ?').get(userId);
  logActivity(userId, 'auth:password_reset_completed', null, null, getClientIp(req));
  console.log(`[password-reset] password changed for ${u ? u.email : userId}`);
  // No session on purpose — see above.
  return res.json({ ok: true, message: 'Password updated. You can now sign in.' });
});

// ==================== TOTP MFA (#100) ====================
// Opt-in per-user, LOCAL accounts only (SSO IdPs own MFA). Enrollment is a two-step
// confirm (setup -> enable) so a mistyped secret can't lock anyone out. Recovery
// codes are shown ONCE at enable, stored SHA-256-hashed, single-use.

const RECOVERY_CODE_COUNT = 10;

function recoveryCodesRemaining(userId) {
  return db.prepare('SELECT COUNT(*) AS n FROM totp_recovery_codes WHERE user_id = ? AND used_at IS NULL').get(userId).n;
}

// Atomically replace a user's recovery codes - no window where old + new both verify
// (tightening #3). Returns the plaintext set (shown ONCE).
function resetRecoveryCodes(userId) {
  const { plain, hashes } = totp.generateRecoveryCodes(RECOVERY_CODE_COUNT);
  db.transaction(() => {
    db.prepare('DELETE FROM totp_recovery_codes WHERE user_id = ?').run(userId);
    const ins = db.prepare('INSERT INTO totp_recovery_codes (id, user_id, code_hash) VALUES (?, ?, ?)');
    for (const h of hashes) ins.run(uuidv4(), userId, h);
  })();
  return plain;
}

// Consume one single-use recovery code (mark used). True if a fresh code matched.
function consumeRecoveryCode(userId, input) {
  if (!input) return false;
  const row = db.prepare('SELECT id FROM totp_recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL')
    .get(userId, totp.hashRecoveryCode(input));
  if (!row) return false;
  db.prepare("UPDATE totp_recovery_codes SET used_at = strftime('%s','now') WHERE id = ?").run(row.id);
  return true;
}

router.get('/totp/status', requireAuth, (req, res) => {
  const u = db.prepare('SELECT totp_enabled, auth_provider FROM users WHERE id = ?').get(req.user.id);
  res.json({
    enabled: !!u.totp_enabled,
    eligible: u.auth_provider === 'local',
    recovery_codes_remaining: u.totp_enabled ? recoveryCodesRemaining(req.user.id) : 0,
  });
});

// Step 1: mint a pending secret + return the otpauth:// URI + a ready-to-render QR
// data URL (drawn server-side with the already-bundled `qrcode` lib, same as the
// device-owner provisioning QR). The raw secret is also returned for manual entry.
router.post('/totp/setup', requireAuth, async (req, res) => {
  const u = db.prepare('SELECT auth_provider, totp_enabled, email FROM users WHERE id = ?').get(req.user.id);
  if (u.auth_provider !== 'local') return res.status(400).json({ error: 'TOTP is only for password accounts; your identity provider manages MFA.' });
  if (u.totp_enabled) return res.status(409).json({ error: 'TOTP already enabled. Disable it first to re-enroll.' });
  const secret = totp.generateSecret();
  db.prepare("UPDATE users SET totp_secret_enc = ?, totp_enabled = 0, updated_at = strftime('%s','now') WHERE id = ?")
    .run(totp.encryptSecret(secret), req.user.id);
  // Fold the instance host into the QR label so users with accounts on more than one
  // ScreenTinker can tell them apart in their authenticator app (#100). trust-proxy is set,
  // so req.get('host') is the public host even behind Cloudflare/nginx.
  const host = (req.get('host') || '').replace(/[^A-Za-z0-9.:-]/g, '').slice(0, 60);
  const otpauth_uri = totp.keyuri(u.email, secret, host || undefined);
  let qr_data_url = null;
  // QR is a convenience — if it fails, the client still has otpauth_uri + secret for manual entry.
  try { qr_data_url = await QRCode.toDataURL(otpauth_uri, { errorCorrectionLevel: 'M', margin: 1, width: 240 }); }
  catch (e) { /* fall through with qr_data_url = null */ }
  res.json({ otpauth_uri, secret, qr_data_url });
});

// Step 2: confirm a code from the user's app, THEN enable + issue recovery codes (once).
router.post('/totp/enable', requireAuth, (req, res) => {
  const u = db.prepare('SELECT totp_secret_enc, totp_enabled, totp_last_step, auth_provider FROM users WHERE id = ?').get(req.user.id);
  if (u.auth_provider !== 'local') return res.status(400).json({ error: 'TOTP unavailable for SSO accounts.' });
  if (u.totp_enabled) return res.status(409).json({ error: 'TOTP already enabled.' });
  if (!u.totp_secret_enc) return res.status(400).json({ error: 'Start with POST /api/auth/totp/setup.' });
  const step = totp.verifyCode(req.body.code, totp.decryptSecret(u.totp_secret_enc), u.totp_last_step);
  if (!step) return res.status(400).json({ error: 'Invalid code' });
  db.prepare("UPDATE users SET totp_enabled = 1, totp_last_step = ?, updated_at = strftime('%s','now') WHERE id = ?")
    .run(step, req.user.id);
  res.json({ enabled: true, recovery_codes: resetRecoveryCodes(req.user.id) }); // shown ONCE
});

// Disable: re-auth with a current code (or a recovery code) so a hijacked session
// can't silently strip MFA. Clears the secret + all recovery codes.
router.post('/totp/disable', requireAuth, (req, res) => {
  const u = db.prepare('SELECT totp_secret_enc, totp_enabled, totp_last_step FROM users WHERE id = ?').get(req.user.id);
  if (!u.totp_enabled) return res.status(400).json({ error: 'TOTP is not enabled.' });
  const ok = !!totp.verifyCode(req.body.code, totp.decryptSecret(u.totp_secret_enc), u.totp_last_step)
    || consumeRecoveryCode(req.user.id, req.body.code);
  if (!ok) return res.status(400).json({ error: 'Invalid code' });
  db.transaction(() => {
    db.prepare("UPDATE users SET totp_enabled = 0, totp_secret_enc = NULL, totp_last_step = 0, updated_at = strftime('%s','now') WHERE id = ?").run(req.user.id);
    db.prepare('DELETE FROM totp_recovery_codes WHERE user_id = ?').run(req.user.id);
  })();
  res.json({ enabled: false });
});

// Regenerate recovery codes: re-auth (current code) + ATOMIC replace (tightening #3).
router.post('/totp/recovery-codes/regenerate', requireAuth, (req, res) => {
  const u = db.prepare('SELECT totp_secret_enc, totp_enabled, totp_last_step FROM users WHERE id = ?').get(req.user.id);
  if (!u.totp_enabled) return res.status(400).json({ error: 'TOTP is not enabled.' });
  const step = totp.verifyCode(req.body.code, totp.decryptSecret(u.totp_secret_enc), u.totp_last_step);
  if (!step) return res.status(400).json({ error: 'Invalid code' });
  db.prepare('UPDATE users SET totp_last_step = ? WHERE id = ?').run(step, req.user.id);
  res.json({ recovery_codes: resetRecoveryCodes(req.user.id) });
});

// Second login step: exchange an mfa_pending token + a code (TOTP or recovery) for a
// full session. Per-route 10/min rate-limit (server.js) + per-user lockout (#87 model).
router.post('/totp/verify', (req, res) => {
  const { mfa_token, code } = req.body;
  if (!mfa_token || !code) return res.status(400).json({ error: 'mfa_token and code required' });
  let decoded;
  // verifyMfaPendingToken is the ONLY accessor that accepts the pre-TOTP audience; a full
  // session token presented here is rejected by it (audience mismatch).
  try { decoded = verifyMfaPendingToken(mfa_token); } catch { return res.status(401).json({ error: 'mfa session expired' }); }
  if (!decoded.mfa_pending || !decoded.id) return res.status(401).json({ error: 'invalid mfa token' });
  if (totpLockout.isLocked(decoded.id)) return res.status(429).json({ error: 'Too many invalid codes. Try again later.' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(decoded.id);
  if (!user || !user.totp_enabled) return res.status(401).json({ error: 'invalid mfa token' });

  // TOTP first (with intra-window replay block via totp_last_step), then a recovery code.
  const step = totp.verifyCode(code, totp.decryptSecret(user.totp_secret_enc), user.totp_last_step);
  let viaRecovery = false;
  if (step) {
    db.prepare('UPDATE users SET totp_last_step = ? WHERE id = ?').run(step, user.id);
  } else if (consumeRecoveryCode(user.id, code)) {
    viaRecovery = true;
  } else {
    totpLockout.recordFailure(decoded.id);
    logFailedLogin(user.email, getClientIp(req), 'Bad TOTP/recovery code');
    return res.status(401).json({ error: 'Invalid code' });
  }
  totpLockout.reset(decoded.id);
  issueSession(req, res, user, {
    via_recovery: viaRecovery,
    recovery_codes_remaining: recoveryCodesRemaining(user.id),
  });
});

// ==================== Google OAuth ====================

/*
 * REMOVED 2026-08-10: POST /api/auth/google and POST /api/auth/microsoft.
 *
 * Both authenticated with an ACCESS token and neither checked who it was issued for. Google's path
 * fell back to `tokeninfo?access_token=` and read the email out of the reply; Microsoft's handed the
 * bearer token to Graph /me and trusted that. Graph — and tokeninfo — will describe the user behind
 * a token minted for SOMEBODY ELSE'S application, so any site a user signed into that requested
 * `email` or `User.Read` could replay their token here and be handed a session as them.
 *
 * Nothing is lost by deleting them: the login page called `google.accounts.oauth2` and
 * `new msal.PublicClientApplication`, and neither SDK was ever loaded by any page in this app, so
 * both buttons threw ReferenceError on click. The feature had never worked.
 *
 * Replaced by the OIDC routes at the bottom of this file, which verify an ID token's signature,
 * issuer, audience and our own nonce, and which cover Google, Microsoft and any other provider
 * through one code path. See lib/oidc.js.
 */


// ==================== User Management ====================

// Get current user + tenancy context.
// Phase 2.1: response shape extended with current_workspace, current_organization,
// roles, and the list of accessible workspaces. Legacy fields (user object at
// the top level) are preserved so existing frontend code continues to work.
router.get('/me', requireAuth, resolveTenancy, (req, res) => {
  // Platform admins see every workspace in the system (via the LEFT JOIN they
  // still get their own workspace_role for direct memberships; NULL elsewhere,
  // matching accessContext's actingAs semantics). Regular users see every
  // workspace they can reach via either path: direct workspace_members row, OR
  // org_owner / org_admin on the parent organization. Mirrors the access
  // logic in accessibleWorkspaceIds() (lib/tenancy.js); kept as a separate
  // query rather than reusing it because /me needs full row shape, not just
  // IDs. Role is read from the signed JWT (not user-supplied), so non-admins
  // cannot reach the admin branch. No cap on the admin list yet - revisit at
  // 50+ workspaces when dropdown UX without search starts to degrade.
  //
  // Each accessible_workspaces entry also carries `can_admin: bool` so the
  // UI can render admin affordances (rename pencil etc.) only where the
  // caller has permission. The server still enforces permission on the
  // actual mutation routes regardless of this advisory flag.
  // device_count: correlated subquery on workspaces.id. Equality fails on NULL
  // so unclaimed pair-pool devices (workspace_id IS NULL) are correctly excluded.
  // Microseconds per row at current scale (~37 rows worst case for platform_admin);
  // not optimizing - revisit if the admin list grows past a few hundred workspaces.
  // #13: platform staff (admin OR operator) SEE every workspace (visibility).
  // can_admin below is computed separately from isPlatformRole (owner only), so
  // operators see all workspaces but get can_admin:false on each.
  const isPlatformStaffUser = isPlatformStaff(req.user.role);
  const isPlatformAdmin = isPlatformRole(req.user.role);
  const accessible = isPlatformStaffUser
    ? db.prepare(`
        SELECT w.id, w.name, w.organization_id, o.name AS organization_name,
               wm.role AS workspace_role, om.role AS org_role,
               (SELECT COUNT(*) FROM devices WHERE workspace_id = w.id) AS device_count
        FROM workspaces w
        JOIN organizations o ON o.id = w.organization_id
        LEFT JOIN workspace_members wm ON wm.workspace_id = w.id AND wm.user_id = ?
        LEFT JOIN organization_members om ON om.organization_id = w.organization_id AND om.user_id = ?
        ORDER BY o.name, w.name
      `).all(req.user.id, req.user.id)
    : db.prepare(`
        SELECT w.id, w.name, w.organization_id, o.name AS organization_name,
               wm.role AS workspace_role, om.role AS org_role,
               (SELECT COUNT(*) FROM devices WHERE workspace_id = w.id) AS device_count
        FROM workspaces w
        JOIN organizations o ON o.id = w.organization_id
        LEFT JOIN workspace_members wm ON wm.workspace_id = w.id AND wm.user_id = ?
        LEFT JOIN organization_members om ON om.organization_id = w.organization_id AND om.user_id = ?
        WHERE wm.user_id IS NOT NULL
           OR (om.user_id IS NOT NULL AND om.role IN ('org_owner', 'org_admin'))
        ORDER BY o.name, w.name
      `).all(req.user.id, req.user.id);

  // Compute can_admin per workspace. Mirrors canAdminWorkspace() in lib/permissions.js
  // but uses already-joined org_role to avoid another N+1 query per workspace.
  for (const w of accessible) {
    w.can_admin = isPlatformAdmin
      || w.org_role === 'org_owner' || w.org_role === 'org_admin'
      || w.workspace_role === 'workspace_admin';
    delete w.org_role; // internal-only; don't leak to client
  }

  const currentOrg = req.organizationId
    ? db.prepare('SELECT id, name FROM organizations WHERE id = ?').get(req.organizationId)
    : null;

  res.json({
    ...req.user,
    // Read straight from the row (the JWT predates this field) so the client's verify banner
    // reflects live state after reload. Fail-open to verified if somehow absent.
    email_verified: db.prepare('SELECT email_verified FROM users WHERE id = ?').get(req.user.id)?.email_verified ?? 1,
    hide_billing: config.hideBilling, // #116: client hides the Subscription nav + guards #/billing
    current_workspace_id: req.workspaceId,
    current_workspace: req.workspace ? { id: req.workspace.id, name: req.workspace.name, organization_id: req.workspace.organization_id } : null,
    current_organization: currentOrg,
    current_workspace_role: req.workspaceRole,
    current_org_role: req.orgRole,
    is_platform_admin: req.isPlatformAdmin,
    acting_as: req.actingAs,
    accessible_workspaces: accessible,
  });
});

// Switch the active workspace. Validates the user has access (direct
// workspace_member, org-level admin in the parent org, or platform_admin),
// then mints a fresh JWT with the new current_workspace_id.
router.post('/switch-workspace', requireAuth, (req, res) => {
  const { workspace_id } = req.body || {};
  if (!workspace_id) return res.status(400).json({ error: 'workspace_id required' });

  const ws = db.prepare('SELECT * FROM workspaces WHERE id = ?').get(workspace_id);
  if (!ws) return res.status(404).json({ error: 'Workspace not found' });

  // #13: platform staff (admin OR operator) can switch into any workspace.
  const isPlatformStaffUser = isPlatformStaff(req.user.role);
  const wsMember = db.prepare('SELECT 1 FROM workspace_members WHERE workspace_id = ? AND user_id = ?').get(ws.id, req.user.id);
  const orgMember = db.prepare(`
    SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?
  `).get(ws.organization_id, req.user.id);
  const canAct = isPlatformStaffUser
    || !!wsMember
    || (orgMember && (orgMember.role === 'org_owner' || orgMember.role === 'org_admin'));

  if (!canAct) return res.status(403).json({ error: 'Access denied to that workspace' });

  const token = generateToken(req.user, ws.id);
  res.json({ token, current_workspace_id: ws.id });
});

// Update current user
router.put('/me', requireAuth, (req, res) => {
  const { name, password, current_password, email_alerts } = req.body;
  if (name) {
    db.prepare('UPDATE users SET name = ?, updated_at = strftime(\'%s\',\'now\') WHERE id = ?')
      .run(name, req.user.id);
  }
  if (email_alerts !== undefined) {
    db.prepare('UPDATE users SET email_alerts = ?, updated_at = strftime(\'%s\',\'now\') WHERE id = ?')
      .run(email_alerts ? 1 : 0, req.user.id);
  }
  if (password) {
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const row = db.prepare('SELECT password_hash, auth_provider FROM users WHERE id = ?').get(req.user.id);
    if (!row) return res.status(404).json({ error: 'User not found' });
    if (row.auth_provider !== 'local') {
      return res.status(400).json({ error: `Your account signs in via ${row.auth_provider}. Manage your password there.` });
    }
    if (row.password_hash) {
      if (!current_password || !bcrypt.compareSync(current_password, row.password_hash)) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }
    }
    const hash = bcrypt.hashSync(password, 10);
    // #10: a successful password change clears must_change_password, releasing
    // the first-login change-password gate.
    db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = strftime(\'%s\',\'now\') WHERE id = ?')
      .run(hash, req.user.id);
  }
  const user = db.prepare('SELECT id, email, name, role, auth_provider, avatar_url, plan_id, email_alerts, must_change_password FROM users WHERE id = ?').get(req.user.id);
  res.json(user);
});

// List users - platform admins see all, admins see team members only
router.get('/users', requireAuth, requireAdmin, (req, res) => {
  if (PLATFORM_ROLES.includes(req.user.role)) {
    // One aggregate query (no N+1): each user carries workspace_count, and for
    // an exactly-one membership the single workspace id/name + org name (used by
    // the admin Users page Workspace column). MAX() over a single grouped row
    // yields that row's values; the CASE blanks them when count != 1 so we never
    // surface a single workspace name for a multi-membership user.
    const users = db.prepare(`
      SELECT u.id, u.email, u.name, u.role, u.auth_provider, u.avatar_url, u.plan_id, u.created_at, u.last_login,
             COUNT(wm.workspace_id) AS workspace_count,
             CASE WHEN COUNT(wm.workspace_id) = 1 THEN MAX(w.id)   END AS workspace_id,
             CASE WHEN COUNT(wm.workspace_id) = 1 THEN MAX(w.name) END AS workspace_name,
             CASE WHEN COUNT(wm.workspace_id) = 1 THEN MAX(o.name) END AS organization_name
      FROM users u
      LEFT JOIN workspace_members wm ON wm.user_id = u.id
      LEFT JOIN workspaces w ON w.id = wm.workspace_id
      LEFT JOIN organizations o ON o.id = w.organization_id
      GROUP BY u.id
      ORDER BY u.created_at ASC
    `).all();
    res.json(users);
  } else {
    // Admin sees themselves + users in their teams
    const users = db.prepare(`
      SELECT DISTINCT u.id, u.email, u.name, u.role, u.auth_provider, u.avatar_url, u.plan_id, u.created_at
      FROM users u
      LEFT JOIN team_members tm ON u.id = tm.user_id
      WHERE u.id = ? OR tm.team_id IN (SELECT team_id FROM team_members WHERE user_id = ?)
      ORDER BY u.created_at ASC
    `).all(req.user.id, req.user.id);
    res.json(users);
  }
});

// Delete user (superadmin only)
router.delete('/users/:id', requireAuth, requireSuperAdmin, (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  const target = db.prepare('SELECT id, email FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  // #18: a bare DELETE FROM users fails the FK constraints (23 uncascaded refs).
  // deleteUserCascade resolves every reference in one transaction: hard-deletes
  // orgs the user solely owns, preserves (unlinks/reassigns) resources in orgs
  // they don't own, and refuses if they own a shared org.
  try {
    deleteUserCascade(db, { targetId: target.id, actingAdminId: req.user.id });
  } catch (e) {
    if (e instanceof OrgHasOtherMembersError) return res.status(409).json({ error: e.message });
    throw e;
  }
  logActivity(req.user.id, 'delete_user', `target: ${target.email}`, null, getClientIp(req));
  res.json({ success: true });
});

// Update user platform role (platform admin only).
// #14: this manages users.role (the PLATFORM-level role) only - workspace and
// org roles are managed in the members views. Whitelist is the current model:
// 'user' and 'platform_admin' (the legacy 'admin'/'superadmin' strings are gone
// after normalization and are no longer accepted here).
const ASSIGNABLE_PLATFORM_ROLES = ['user', 'platform_operator', 'platform_admin'];
router.put('/users/:id/role', requireAuth, requireSuperAdmin, (req, res) => {
  const { role } = req.body;
  if (!ASSIGNABLE_PLATFORM_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
  // Self-demotion guard: a platform admin can't strip their own platform role
  // (would lock themselves out of platform admin actions).
  if (req.params.id === req.user.id && !isPlatformRole(role)) return res.status(400).json({ error: 'Cannot demote yourself' });
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, req.params.id);
  res.json({ success: true });
});

// Admin password reset for another user.
// Superadmins: can reset any local user. Admins: can reset members of teams
// they own (and never a superadmin). Self-reset routes through PUT /me with
// current_password — this endpoint is the override path.
router.put('/users/:id/password', requireAuth, requireAdmin, (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'Use Settings > Change Password for your own account' });
  }
  const target = db.prepare('SELECT id, email, role, auth_provider FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.auth_provider !== 'local') {
    return res.status(400).json({ error: `User signs in via ${target.auth_provider} — password reset does not apply` });
  }

  if (!PLATFORM_ROLES.includes(req.user.role)) {
    // Admin path: must own a team that includes the target, and target must
    // be a regular user (cannot reset another admin's or a platform_admin's
    // password — that would be a lateral-takeover vector).
    if (target.role !== 'user') {
      return res.status(403).json({ error: 'Admins can only reset passwords for regular users' });
    }
    const sharedOwnedTeam = db.prepare(`
      SELECT 1 FROM team_members tm_admin
      JOIN team_members tm_target ON tm_admin.team_id = tm_target.team_id
      WHERE tm_admin.user_id = ? AND tm_admin.role = 'owner'
        AND tm_target.user_id = ?
      LIMIT 1
    `).get(req.user.id, req.params.id);
    if (!sharedOwnedTeam) {
      return res.status(403).json({ error: 'You can only reset passwords for members of teams you own' });
    }
  }

  const hash = bcrypt.hashSync(password, 10);
  db.prepare("UPDATE users SET password_hash = ?, updated_at = strftime('%s','now') WHERE id = ?")
    .run(hash, req.params.id);

  // Explicit audit entry — the generic activity logger captures the route
  // and target id, but a labeled detail string makes the audit log readable.
  // Never include the password; just who reset whose password.
  logActivity(req.user.id, 'password_reset_for_user', `target: ${target.email}`, null, getClientIp(req));
  res.json({ success: true });
});

// Get auth config (public - tells frontend which providers are available)
router.get('/config', (req, res) => {
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  /*
   * `providers` is the whole SSO surface now: slug + display name, nothing else. The browser no
   * longer needs a client id, because it never talks to a provider itself — it follows a link to
   * /api/auth/oidc/<slug>/start and the server builds the authorization request. That is what
   * removed the need for a provider SDK on this page, and with it the CSP exception one would need.
   */
  const providers = oidcProviders.publicList();
  res.json({
    providers,
    // Kept so a cached older login page hides its buttons rather than drawing dead ones. The client
    // ids are deliberately no longer echoed — nothing in the browser has any use for them.
    googleEnabled: providers.some((p) => p.slug === 'google'),
    microsoftEnabled: providers.some((p) => p.slug === 'microsoft'),
    localEnabled: true,
    needsSetup: userCount === 0,
    registration_enabled: !config.disableRegistration || userCount === 0,
  });
});

// Accept a workspace invite. Mounted here (under /api/auth) rather than in
// routes/workspaces.js because the invite id is the only thing the caller
// has - they don't necessarily know which workspace it targets yet, so
// /api/workspaces/:id/... wouldn't fit. requireAuth gates access; the
// invite's email is matched against the authenticated user's email
// case-insensitively, so a logged-in account can only accept invites
// addressed to its own email.
router.post('/accept-invite/:inviteId', requireAuth, (req, res) => {
  const invite = db.prepare('SELECT * FROM workspace_invites WHERE id = ?').get(req.params.inviteId);
  if (!invite) return res.status(404).json({ error: 'Invite not found' });

  const now = Math.floor(Date.now() / 1000);
  if (invite.expires_at <= now) {
    db.prepare('DELETE FROM workspace_invites WHERE id = ?').run(invite.id);
    return res.status(410).json({ error: 'Invite has expired' });
  }

  if (String(invite.email).toLowerCase() !== String(req.user.email).toLowerCase()) {
    return res.status(403).json({ error: 'This invite is for a different email address' });
  }

  const ws = db.prepare('SELECT id, name, organization_id FROM workspaces WHERE id = ?').get(invite.workspace_id);
  if (!ws) {
    // Workspace was deleted between invite creation and accept. Clean up.
    db.prepare('DELETE FROM workspace_invites WHERE id = ?').run(invite.id);
    return res.status(410).json({ error: 'Workspace no longer exists' });
  }

  const org = db.prepare('SELECT name FROM organizations WHERE id = ?').get(ws.organization_id);

  // Idempotent: if the user already has a workspace_members row, return
  // success without changing the role (don't silently demote/upgrade), and
  // still consume the invite. The invitee's intent ("I want access") is
  // already satisfied either way.
  const existing = db.prepare('SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?')
    .get(ws.id, req.user.id);

  const txn = db.transaction(() => {
    if (!existing) {
      db.prepare(`
        INSERT INTO workspace_members (workspace_id, user_id, role, invited_by)
        VALUES (?, ?, ?, ?)
      `).run(ws.id, req.user.id, invite.role, invite.invited_by);
    }
    db.prepare('DELETE FROM workspace_invites WHERE id = ?').run(invite.id);
  });
  txn();

  // Stamp workspaceId so activityLogger captures tenant attribution.
  req.workspaceId = ws.id;

  res.json({
    workspace_id: ws.id,
    workspace_name: ws.name,
    organization_name: org?.name || null,
    role: existing ? existing.role : invite.role,
    already_member: !!existing,
  });
});


// ==================== OpenID Connect (generic SSO) ====================
/*
 * ONE flow for every provider — Google, Microsoft, Okta, Keycloak, Authentik, anything that speaks
 * OIDC. Authorization Code + PKCE, run server-side, which is why there is no provider SDK on the
 * login page and no third-party script origin in the CSP.
 *
 * It replaces two endpoints that could not tell WHO a token was minted for. Detail in lib/oidc.js;
 * the short version is that identity now comes from an ID token whose signature, issuer, audience
 * and OUR nonce are all checked, instead of from an access token handed to a userinfo endpoint.
 *
 * ⚠️ TOTP: an SSO login does not prompt for it, matching the existing documented behaviour at the
 * password-login branch above ("The SSO routes and the API-token path never reach here"). The
 * second factor is the identity provider's job in this flow. Changing that is a product decision,
 * not something this refactor should do silently.
 */

// The transaction is held in a short-lived signed cookie rather than server memory so that a
// restart mid-login, or a second server process, does not strand the user on a dead state.
const OIDC_TX_COOKIE = 'st_oidc_tx';
const OIDC_TX_TTL_S = 600;

function readCookie(req, name) {
  const raw = req.headers.cookie;
  if (!raw) return null;
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return null;
}

/*
 * The origin the provider will redirect back to. APP_URL pins it, exactly as the signup and invite
 * mails do, because the redirect_uri must match what is registered with the provider CHARACTER FOR
 * CHARACTER — deriving it from the request Host would break the moment someone reaches the box by
 * a second name, and would be attacker-controlled input in the bargain.
 */
function publicOrigin(req) {
  const configured = (process.env.APP_URL || '').trim().replace(/\/+$/, '');
  if (configured) return configured;
  return `${req.protocol}://${req.get('host')}`;
}

const redirectUriFor = (req, slug) => `${publicOrigin(req)}/api/auth/oidc/${slug}/callback`;

// Send the browser back to the SPA. Errors travel as a code the login page can translate; the
// token travels in the FRAGMENT, which browsers do not send to servers and proxies do not log.
function backToApp(res, params) {
  const qs = new URLSearchParams(params).toString();
  res.redirect(`/app#/login?${qs}`);
}

// Which providers this instance offers. Public: it is what draws the login buttons.
router.get('/providers', (req, res) => {
  res.json({ providers: oidcProviders.publicList() });
});

router.get('/oidc/:slug/start', async (req, res) => {
  const provider = oidcProviders.get(req.params.slug);
  if (!provider) return backToApp(res, { sso_error: 'unknown_provider' });

  try {
    const doc = await oidc.discover(provider.issuer);
    const pkce = oidc.createPkce();
    const nonce = oidc.randomToken();
    const state = oidc.randomToken();

    const tx = jwt.sign(
      { slug: provider.slug, nonce, verifier: pkce.verifier, state },
      config.jwtSecret,
      { expiresIn: OIDC_TX_TTL_S },
    );
    res.cookie(OIDC_TX_COOKIE, tx, {
      httpOnly: true,
      sameSite: 'lax',            // the provider returns via a top-level GET, which Lax allows
      secure: req.protocol === 'https',
      maxAge: OIDC_TX_TTL_S * 1000,
      path: '/api/auth',
    });

    const url = new URL(doc.authorization_endpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', provider.clientId);
    url.searchParams.set('redirect_uri', redirectUriFor(req, provider.slug));
    url.searchParams.set('scope', provider.scopes);
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', pkce.challenge);
    url.searchParams.set('code_challenge_method', pkce.method);
    res.redirect(url.toString());
  } catch (err) {
    console.error(`[oidc] ${req.params.slug} start failed:`, err.message);
    backToApp(res, { sso_error: 'provider_unavailable' });
  }
});

router.get('/oidc/:slug/callback', async (req, res) => {
  const provider = oidcProviders.get(req.params.slug);
  if (!provider) return backToApp(res, { sso_error: 'unknown_provider' });

  // The provider itself can refuse (consent declined, admin policy). That is not an error here.
  if (req.query.error) {
    console.warn(`[oidc] ${provider.slug} returned ${req.query.error}`);
    return backToApp(res, { sso_error: 'provider_refused' });
  }

  const raw = readCookie(req, OIDC_TX_COOKIE);
  res.clearCookie(OIDC_TX_COOKIE, { path: '/api/auth' });
  if (!raw) return backToApp(res, { sso_error: 'expired' });

  let tx;
  try {
    tx = jwt.verify(raw, config.jwtSecret);
  } catch {
    return backToApp(res, { sso_error: 'expired' });
  }

  // CSRF: the state we minted, in the cookie only we could set, must match the one coming back.
  // Compared in constant time so a wrong state cannot be discovered a character at a time.
  const got = String(req.query.state || '');
  const want = String(tx.state || '');
  const sameLength = got.length === want.length;
  if (!sameLength || !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(want))) {
    return backToApp(res, { sso_error: 'bad_state' });
  }
  if (tx.slug !== provider.slug) return backToApp(res, { sso_error: 'bad_state' });
  if (!req.query.code) return backToApp(res, { sso_error: 'no_code' });

  let claims;
  try {
    const tokens = await oidc.exchangeCode({
      issuer: provider.issuer,
      clientId: provider.clientId,
      clientSecret: provider.clientSecret,
      code: String(req.query.code),
      redirectUri: redirectUriFor(req, provider.slug),
      verifier: tx.verifier,
    });
    claims = await oidc.verifyIdToken(tokens.id_token, {
      issuer: provider.issuer,
      clientId: provider.clientId,
      nonce: tx.nonce,
    });
  } catch (err) {
    console.error(`[oidc] ${provider.slug} verification failed:`, err.message);
    return backToApp(res, { sso_error: 'verification_failed' });
  }

  const email = String(claims.email || '').toLowerCase().trim();
  if (!email) return backToApp(res, { sso_error: 'no_email' });
  /*
   * An unverified email is refused. The whole account model keys on email — linking, invites,
   * password reset — so accepting an address the provider itself will not vouch for would let
   * anyone who can type an address into a sloppy IdP arrive as its owner. Providers that omit the
   * claim entirely are treated as "not asserted", which is the same answer.
   */
  if (claims.email_verified === false) return backToApp(res, { sso_error: 'email_unverified' });

  try {
    const result = upsertFederatedUser({ claims, email, provider, req });
    if (result.error) return backToApp(res, { sso_error: result.error });
    const { user, isNew } = result;

    logSuccessfulLogin(user.id, user.email, getClientIp(req));
    const workspaceId = ensureDefaultOrgForUser(user, { allowCreate: config.autoCreateOrgOnSignup });
    const token = generateToken(user, workspaceId);
    if (isNew) sendSignupEmails(user, req);
    backToApp(res, { sso_token: token });
  } catch (err) {
    console.error(`[oidc] ${provider.slug} sign-in failed:`, err.message);
    backToApp(res, { sso_error: 'server_error' });
  }
});

/*
 * Find or create the account behind a verified set of claims.
 *
 * The linking rule is the one the Google path already used, kept deliberately: an existing account
 * WITH a password is never taken over by an SSO login — the owner proves control by logging in
 * locally and linking from Settings. An account with no password (already federated) is re-pointed
 * at whichever provider just authenticated it.
 */
function upsertFederatedUser({ claims, email, provider, req }) {
  const existing = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!existing) {
    if (!canRegister()) return { error: 'registration_disabled' };
    const id = uuidv4();
    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
    const isFirst = userCount === 0;
    const role = isFirst ? 'platform_admin' : 'user';
    const plan = (isFirst && config.selfHosted) ? 'enterprise' : 'pro';
    const trialStarted = isFirst && config.selfHosted ? null : Math.floor(Date.now() / 1000);
    db.prepare(`
      INSERT INTO users (id, email, name, auth_provider, provider_id, avatar_url, role, plan_id, trial_started, trial_plan, email_verified)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    `).run(id, email, claims.name || '', provider.slug, String(claims.sub), claims.picture || '',
      role, plan, trialStarted, trialStarted ? 'pro' : null);
    return { user: db.prepare('SELECT * FROM users WHERE id = ?').get(id), isNew: true };
  }

  if (existing.auth_provider !== provider.slug) {
    if (existing.password_hash) return { error: 'account_exists_local' };
    db.prepare('UPDATE users SET auth_provider = ?, provider_id = ?, avatar_url = ? WHERE id = ?')
      .run(provider.slug, String(claims.sub), claims.picture || existing.avatar_url, existing.id);
    return { user: db.prepare('SELECT * FROM users WHERE id = ?').get(existing.id), isNew: false };
  }

  /*
   * Same provider, but a DIFFERENT subject. `sub` is the provider's stable id and the email is not:
   * addresses get reassigned, especially inside companies. Refusing here is what stops a recycled
   * address inheriting the previous holder's account.
   */
  if (existing.provider_id && String(existing.provider_id) !== String(claims.sub)) {
    return { error: 'subject_mismatch' };
  }
  if (!existing.provider_id) {
    db.prepare('UPDATE users SET provider_id = ? WHERE id = ?').run(String(claims.sub), existing.id);
  }
  return { user: db.prepare('SELECT * FROM users WHERE id = ?').get(existing.id), isNew: false };
}


module.exports = router;
