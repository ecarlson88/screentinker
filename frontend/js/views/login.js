import { showToast } from '../components/toast.js';
import { t } from '../i18n.js';
import { esc } from '../utils.js';


/*
 * A recognisable mark for the providers people expect to see, and an honest generic one for
 * everything else. Inline SVG rather than a remote image: an <img> to a provider CDN would put a
 * third-party origin back into the CSP, which is precisely what moving the flow server-side removed.
 */
const PROVIDER_ICONS = {
  google: `<svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true">
    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/>
    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
  </svg>`,
  microsoft: `<svg width="18" height="18" viewBox="0 0 21 21" aria-hidden="true">
    <rect x="1" y="1" width="9" height="9" fill="#f25022"/>
    <rect x="11" y="1" width="9" height="9" fill="#7fba00"/>
    <rect x="1" y="11" width="9" height="9" fill="#00a4ef"/>
    <rect x="11" y="11" width="9" height="9" fill="#ffb900"/>
  </svg>`,
};

const GENERIC_ICON = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
  <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
</svg>`;

const providerIcon = (slug) => PROVIDER_ICONS[slug] || GENERIC_ICON;

let authConfig = null;

async function loadAuthConfig() {
  if (authConfig) return authConfig;
  const res = await fetch('/api/auth/config');
  authConfig = await res.json();
  return authConfig;
}

// #15: resolve instance/default branding for the (pre-login) login page.
// Public endpoint: custom-domain match -> platform default -> ScreenTinker.
async function loadLoginBranding() {
  try {
    const res = await fetch('/api/branding?domain=' + encodeURIComponent(location.hostname));
    if (!res.ok) return {};
    return await res.json();
  } catch { return {}; }
}

function brandEsc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}

// Apply document-level branding (colors, favicon, title, custom CSS) for login.
function applyLoginBrandingDoc(b) {
  const root = document.documentElement;
  if (b.primary_color) root.style.setProperty('--accent', b.primary_color);
  if (b.bg_color) root.style.setProperty('--bg-primary', b.bg_color);
  if (b.brand_name) document.title = b.brand_name;
  if (b.favicon_url) {
    document.querySelectorAll('link[rel="icon"], link[rel="apple-touch-icon"]').forEach(l => l.setAttribute('href', b.favicon_url));
  }
  if (b.custom_css) {
    let style = document.getElementById('wl-custom-css');
    if (!style) { style = document.createElement('style'); style.id = 'wl-custom-css'; document.head.appendChild(style); }
    style.textContent = b.custom_css;
  }
}

export async function render(container) {
  const [config, branding] = await Promise.all([loadAuthConfig(), loadLoginBranding()]);
  const isSetup = config.needsSetup;
  // registration_enabled may be absent on older servers — treat as enabled for back-compat
  const canRegister = config.registration_enabled !== false;

  applyLoginBrandingDoc(branding);
  const brandName = branding.brand_name || 'ScreenTinker';
  // Branded logo if set, else the default ScreenTinker glyph.
  const logoHtml = branding.logo_url
    ? `<img src="${brandEsc(branding.logo_url)}" alt="${brandEsc(brandName)}" style="max-height:48px;max-width:200px;margin:0 auto 12px;display:block">`
    : `<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" style="margin:0 auto 12px">
            <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
            <line x1="8" y1="21" x2="16" y2="21"/>
            <line x1="12" y1="17" x2="12" y2="21"/>
          </svg>`;

  container.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:center;min-height:100vh;padding:16px">
      <div style="width:400px;max-width:100%">
        <div style="text-align:center;margin-bottom:32px">
          ${logoHtml}
          <h1 style="font-size:24px;font-weight:700;color:var(--accent)">${brandEsc(brandName)}</h1>
          <p style="color:var(--text-secondary);font-size:13px;margin-top:4px">
            ${isSetup ? t('auth.subtitle_setup') : t('auth.subtitle_signin')}
          </p>
          ${!isSetup && canRegister ? `<p style="color:var(--warning);font-size:12px;margin-top:8px">${t('auth.trial_notice')}</p>` : ''}
        </div>

        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:24px">
          <!-- Local Auth Form -->
          <div id="localAuthForm">
            <div class="form-group">
              <label>${t('auth.email')}</label>
              <input type="email" id="loginEmail" class="input" placeholder="${t('auth.placeholder_email')}" autocomplete="email">
            </div>
            <div class="form-group">
              <label id="loginPasswordLabel">${t('auth.password')}</label>
            <!-- Filled in only when the typed email belongs to an organization that has configured
                 its own identity provider. A customer's IdP is never listed to everyone: the button
                 appears for the people it belongs to and nobody else, which also keeps the customer
                 list off the login page. -->
            <div id="orgSsoSlot" style="display:none;margin-bottom:12px"></div>
              <input type="password" id="loginPassword" class="input" placeholder="${t('auth.placeholder_password')}" autocomplete="current-password">
            </div>
            ${isSetup ? `
            <div class="form-group">
              <label>${t('auth.name')}</label>
              <input type="text" id="loginName" class="input" placeholder="${t('auth.placeholder_name')}">
            </div>
            ` : ''}
            <button class="btn btn-primary" id="loginBtn" style="width:100%;justify-content:center;padding:10px">
              ${isSetup ? t('auth.create_admin_account') : t('auth.sign_in')}
            </button>
            ${!isSetup ? `
            <p style="text-align:center;margin-top:10px">
              <a href="#" id="forgotLink" style="color:var(--text-secondary);font-size:12px;text-decoration:none">${t('auth.forgot_password')}</a>
            </p>
            ` : ''}
            ${!isSetup && canRegister ? `
            <button class="btn btn-secondary" id="showRegisterBtn" style="width:100%;justify-content:center;padding:10px;margin-top:8px">
              ${t('auth.create_account')}
            </button>
            ` : ''}
          </div>

          <!-- Register form (hidden by default) -->
          <div id="registerForm" style="display:none">
            <div class="form-group">
              <label>${t('auth.name')}</label>
              <input type="text" id="regName" class="input" placeholder="${t('auth.placeholder_name')}">
            </div>
            <div class="form-group">
              <label>${t('auth.email')}</label>
              <input type="email" id="regEmail" class="input" placeholder="${t('auth.placeholder_email')}">
            </div>
            <div class="form-group">
              <label>${t('auth.password')}</label>
              <input type="password" id="regPassword" class="input" placeholder="${t('auth.placeholder_register_password')}">
            </div>
            <button class="btn btn-primary" id="registerBtn" style="width:100%;justify-content:center;padding:10px">
              ${t('auth.create_account')}
            </button>
            <button class="btn btn-secondary" id="showLoginBtn" style="width:100%;justify-content:center;padding:10px;margin-top:8px">
              ${t('auth.back_to_signin')}
            </button>
          </div>

          <!-- TOTP 2FA challenge (hidden until /login returns mfa_required) -->
          <div id="mfaForm" style="display:none">
            <h2 style="font-size:16px;font-weight:600;margin-bottom:6px">${t('auth.mfa_title')}</h2>
            <p style="color:var(--text-secondary);font-size:13px;margin-bottom:14px">${t('auth.mfa_prompt')}</p>
            <div class="form-group">
              <label>${t('auth.mfa_code_label')}</label>
              <input type="text" id="mfaCode" class="input" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false"
                     placeholder="123456" maxlength="12" style="letter-spacing:6px;text-align:center;font-family:monospace;font-size:18px">
            </div>
            <button class="btn btn-primary" id="mfaVerifyBtn" style="width:100%;justify-content:center;padding:10px">${t('auth.mfa_verify')}</button>
            <button class="btn btn-secondary" id="mfaBackBtn" style="width:100%;justify-content:center;padding:10px;margin-top:8px">${t('auth.back_to_signin')}</button>
            <p style="color:var(--text-muted);font-size:11px;text-align:center;margin-top:12px">${t('auth.mfa_recovery_hint')}</p>
          </div>

          <!-- Email-verification notice (hidden until a verification_required response) -->
          <div id="verifyNotice" style="display:none;text-align:center">
            <div style="font-size:42px;line-height:1;margin-bottom:10px">✉️</div>
            <h2 style="font-size:18px;font-weight:600;margin-bottom:8px">${t('auth.verify_title')}</h2>
            <p style="color:var(--text-secondary);font-size:13px;margin-bottom:6px">${t('auth.verify_body')}</p>
            <p style="font-weight:600;font-size:14px;margin-bottom:16px"><span id="verifyEmail"></span></p>
            <button class="btn btn-secondary" id="verifyResendBtn" style="width:100%;justify-content:center;padding:10px">${t('auth.verify_resend')}</button>
            <button class="btn btn-secondary" id="verifyBackBtn" style="width:100%;justify-content:center;padding:10px;margin-top:8px">${t('auth.back_to_signin')}</button>
          </div>

          <div id="ssoBlock">
          ${(config.providers || []).length ? `
          <div style="display:flex;align-items:center;gap:12px;margin:20px 0">
            <hr style="flex:1;border-color:var(--border)">
            <span style="color:var(--text-muted);font-size:12px">${t('auth.divider_or')}</span>
            <hr style="flex:1;border-color:var(--border)">
          </div>
          ` : ''}

          <!-- One button per configured provider, and each is a plain LINK to a server endpoint.
               There is no provider SDK on this page: the browser never speaks to the identity
               provider directly, so nothing here needs a client id and the CSP needs no
               third-party script origin. Google and Microsoft are ordinary entries in this list.
               The icon is chosen by slug where we have one and falls back to a generic mark, so a
               self-hoster's Keycloak or Authentik still gets a real-looking button. -->
          <!-- Wrapped so the whole set can be hidden at once: an organization that REQUIRES its own
               identity provider must not be shown the operator's, which are not domain-confined. -->
          <div id="instanceProviders">
          ${(config.providers || []).map((p) => `
          <a class="btn btn-secondary" href="/api/auth/oidc/${encodeURIComponent(p.slug)}/start"
             id="sso-${esc(p.slug)}"
             style="width:100%;justify-content:center;padding:10px;gap:8px;margin-top:8px;text-decoration:none">
            ${providerIcon(p.slug)}
            ${esc(t('auth.signin_with', { provider: p.name }))}
          </a>
          `).join('')}
          </div>
          </div>
        </div>

        <!-- Support Access (collapsible) -->
        <details id="supportDetails" style="margin-top:16px">
          <summary style="font-size:11px;color:var(--text-muted);cursor:pointer;text-align:center">${t('auth.support_access')}</summary>
          <div style="margin-top:8px">
            <input type="text" id="supportToken" class="input" placeholder="${t('auth.support_token_placeholder')}" style="font-family:monospace">
            <button class="btn btn-secondary" id="supportLoginBtn" style="width:100%;justify-content:center;padding:8px;margin-top:6px;font-size:12px">${t('auth.support_authenticate')}</button>
          </div>
        </details>

        <div id="forgotForm" style="display:none">
          <div class="form-group">
            <label>${t('auth.email')}</label>
            <input type="email" id="forgotEmail" class="input" placeholder="${t('auth.placeholder_email')}" autocomplete="email">
          </div>
          <button class="btn btn-primary" id="forgotSendBtn" style="width:100%;justify-content:center;padding:10px">${t('auth.forgot_send')}</button>
          <button class="btn btn-secondary" id="forgotBackBtn" style="width:100%;justify-content:center;padding:10px;margin-top:8px">${t('auth.back_to_signin')}</button>
          <p id="forgotNotice" style="color:var(--text-secondary);font-size:12px;text-align:center;margin-top:12px;display:none">${t('auth.forgot_sent')}</p>
        </div>
        <div id="resetForm" style="display:none">
          <div class="form-group">
            <label>${t('auth.new_password')}</label>
            <input type="password" id="resetPassword" class="input" placeholder="${t('auth.placeholder_register_password')}" autocomplete="new-password">
          </div>
          <button class="btn btn-primary" id="resetSubmitBtn" style="width:100%;justify-content:center;padding:10px">${t('auth.reset_submit')}</button>
          <button class="btn btn-secondary" id="resetBackBtn" style="width:100%;justify-content:center;padding:10px;margin-top:8px">${t('auth.back_to_signin')}</button>
        </div>
        <p id="loginError" style="color:var(--danger);font-size:12px;text-align:center;margin-top:12px;display:none"></p>
        <p style="text-align:center;margin-top:16px;font-size:11px;color:var(--text-muted)">
          <a href="/legal/terms.html" target="_blank" style="color:var(--text-muted);text-decoration:underline">${t('auth.terms')}</a>
          &nbsp;&middot;&nbsp;
          <a href="/legal/privacy.html" target="_blank" style="color:var(--text-muted);text-decoration:underline">${t('auth.privacy')}</a>
        </p>
      </div>
    </div>
  `;

  setupHandlers(config, isSetup);
}

function setupHandlers(config, isSetup) {
  const showError = (msg) => {
    const el = document.getElementById('loginError');
    el.textContent = msg;
    el.style.display = 'block';
  };

  // Outcome of clicking the email-verification link (server GET /verify-email redirects here).
  const hashQuery = new URLSearchParams((location.hash.split('?')[1]) || '');
  if (hashQuery.get('verified') === '1') showToast(t('auth.verify_ok'), 'success');
  else if (hashQuery.get('verify_error') === '1') showToast(t('auth.verify_failed'), 'error');

  // Support token login
  document.getElementById('supportLoginBtn')?.addEventListener('click', async () => {
    const token = document.getElementById('supportToken')?.value.trim();
    if (!token) { showError(t('auth.error_paste_support_token')); return; }
    try {
      const res = await fetch('/api/auth/support', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });
      const data = await res.json();
      if (!res.ok) { showError(data.error); return; }
      onAuthSuccess(data);
    } catch (err) { showError(t('auth.error_support_failed')); }
  });

  // Local login/register
  if (isSetup) {
    document.getElementById('loginBtn')?.addEventListener('click', () => doRegister(true));
  } else {
    document.getElementById('loginBtn')?.addEventListener('click', doLogin);
    document.getElementById('showRegisterBtn')?.addEventListener('click', () => {
      document.getElementById('localAuthForm').style.display = 'none';
      document.getElementById('registerForm').style.display = 'block';
    });
    document.getElementById('showLoginBtn')?.addEventListener('click', () => {
      document.getElementById('localAuthForm').style.display = 'block';
      document.getElementById('registerForm').style.display = 'none';
    });
    document.getElementById('registerBtn')?.addEventListener('click', () => doRegister(false));
  }

  // Enter key on password field
  document.getElementById('loginPassword')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') isSetup ? doRegister(true) : doLogin();
  });

  async function doLogin() {
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    if (!email || !password) { showError(t('auth.error_email_password_required')); return; }

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      /*
       * The organization requires its identity provider, so this is not a credential failure and
       * must not read like one — "invalid password" sends the user to reset a password that will
       * never work again. Point them at the control that does work.
       */
      if (!res.ok && data.code === 'sso_required') { showError(t('auth.sso_required')); return; }
      if (!res.ok) { showError(data.error); return; }
      // Unverified account (hosted hard-gate): no session — prompt to check email.
      if (data.verification_required) { showVerifyNotice(data.email || email); return; }
      // #100: TOTP-enabled accounts get no session yet — a second step verifies a code.
      if (data.mfa_required) { showMfaChallenge(data.mfa_token); return; }
      onAuthSuccess(data);
    } catch (err) {
      showError(t('auth.error_login_failed'));
    }
  }

  // "Check your email" panel shown when signup/login returns verification_required (hosted).
  // ---- Self-service password reset -------------------------------------------------
  // Two cards swapped into the same login shell. The request step ALWAYS shows the same
  // confirmation regardless of the server's answer, matching the server's deliberate
  // refusal to reveal whether an address exists.
  function showCard(id) {
    ['localAuthForm', 'registerForm', 'mfaForm', 'ssoBlock', 'forgotForm', 'resetForm'].forEach((x) => {
      const el = document.getElementById(x); if (el) el.style.display = (x === id ? 'block' : 'none');
    });
    const errEl = document.getElementById('loginError'); if (errEl) errEl.style.display = 'none';
  }

  const forgotLink = document.getElementById('forgotLink');
  if (forgotLink) forgotLink.addEventListener('click', (e) => {
    e.preventDefault();
    showCard('forgotForm');
    const src = document.getElementById('loginEmail');
    const dst = document.getElementById('forgotEmail');
    if (src && dst) dst.value = src.value; // carry over whatever they already typed
  });

  const forgotBackBtn = document.getElementById('forgotBackBtn');
  if (forgotBackBtn) forgotBackBtn.addEventListener('click', () => showCard('localAuthForm'));

  const forgotSendBtn = document.getElementById('forgotSendBtn');
  if (forgotSendBtn) forgotSendBtn.addEventListener('click', async () => {
    const email = (document.getElementById('forgotEmail').value || '').trim();
    forgotSendBtn.disabled = true;
    try {
      await fetch('/api/auth/forgot-password', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }),
      });
    } catch (e) { /* deliberately ignored — see below */ }
    // Same confirmation either way. Surfacing a network/server error here would leak
    // whether the address matched, undoing the server-side enumeration resistance.
    document.getElementById('forgotNotice').style.display = 'block';
    forgotSendBtn.disabled = false;
  });

  // A link from the reset email: #/reset-password?token=...
  function resetTokenFromHash() {
    const h = window.location.hash || '';
    const q = h.indexOf('?');
    if (!h.startsWith('#/reset-password') || q < 0) return null;
    return new URLSearchParams(h.slice(q + 1)).get('token');
  }

  const pendingResetToken = resetTokenFromHash();
  if (pendingResetToken) showCard('resetForm');

  const resetBackBtn = document.getElementById('resetBackBtn');
  if (resetBackBtn) resetBackBtn.addEventListener('click', () => { window.location.hash = '#/login'; window.location.reload(); });

  const resetSubmitBtn = document.getElementById('resetSubmitBtn');
  if (resetSubmitBtn) resetSubmitBtn.addEventListener('click', async () => {
    const password = document.getElementById('resetPassword').value || '';
    resetSubmitBtn.disabled = true;
    try {
      const res = await fetch('/api/auth/reset-password', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: pendingResetToken, password }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { showError(data.error || t('auth.reset_failed')); resetSubmitBtn.disabled = false; return; }
      // No session is issued by design, so send them through a normal sign-in — which is
      // what keeps TOTP in the loop for accounts that have it.
      showToast(t('auth.reset_done'), 'success');
      window.location.hash = '#/login';
      window.location.reload();
    } catch (e) {
      showError(t('auth.reset_failed'));
      resetSubmitBtn.disabled = false;
    }
  });

  function showVerifyNotice(email) {
    // The server refused a session — make sure no stale token from a prior login lingers,
    // else the router would treat this browser as authenticated and bounce it into the app.
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    ['localAuthForm', 'registerForm', 'mfaForm', 'ssoBlock', 'supportDetails'].forEach((id) => {
      const el = document.getElementById(id); if (el) el.style.display = 'none';
    });
    document.getElementById('verifyNotice').style.display = 'block';
    document.getElementById('verifyEmail').textContent = email || '';
    const errEl = document.getElementById('loginError'); if (errEl) errEl.style.display = 'none';
    document.getElementById('verifyBackBtn').addEventListener('click', () => window.location.reload());
    document.getElementById('verifyResendBtn').addEventListener('click', async () => {
      try {
        await fetch('/api/auth/resend-verification', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email }),
        });
        showToast(t('auth.verify_resent'), 'success'); // always generic (server never leaks existence)
      } catch (e) {
        showToast(t('auth.verify_resend_failed'), 'error');
      }
    });
  }

  // Swap the card to the 6-digit challenge and exchange mfa_token + code for a session.
  function showMfaChallenge(mfaToken) {
    ['localAuthForm', 'registerForm', 'ssoBlock', 'supportDetails'].forEach((id) => {
      const el = document.getElementById(id); if (el) el.style.display = 'none';
    });
    const form = document.getElementById('mfaForm');
    form.style.display = 'block';
    const errEl = document.getElementById('loginError'); if (errEl) errEl.style.display = 'none';
    const codeEl = document.getElementById('mfaCode');
    codeEl.value = '';
    codeEl.focus();

    const verify = async () => {
      const code = codeEl.value.trim();
      if (!code) { showError(t('auth.mfa_code_required')); return; }
      try {
        const res = await fetch('/api/auth/totp/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mfa_token: mfaToken, code })
        });
        const data = await res.json();
        if (!res.ok) { showError(data.error || t('auth.mfa_invalid')); codeEl.select(); return; }
        onAuthSuccess(data);
      } catch (err) {
        showError(t('auth.error_login_failed'));
      }
    };
    document.getElementById('mfaVerifyBtn').addEventListener('click', verify);
    codeEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') verify(); });
    document.getElementById('mfaBackBtn').addEventListener('click', () => { window.location.reload(); });
  }

  async function doRegister(isFirstUser) {
    const email = document.getElementById(isFirstUser ? 'loginEmail' : 'regEmail').value.trim();
    const password = document.getElementById(isFirstUser ? 'loginPassword' : 'regPassword').value;
    const name = document.getElementById(isFirstUser ? 'loginName' : 'regName')?.value.trim() || '';
    if (!email || !password) { showError(t('auth.error_email_password_required')); return; }
    if (password.length < 6) { showError(t('auth.error_password_min_6')); return; }

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, name })
      });
      const data = await res.json();
      if (!res.ok) { showError(data.error); return; }
      // Hosted signup requires confirming the email before a session is issued.
      if (data.verification_required) { showVerifyNotice(data.email || email); return; }
      onAuthSuccess(data);
    } catch (err) {
      showError(t('auth.error_registration_failed'));
    }
  }

  /*
   * SSO is a link, not a script.
   *
   * The buttons above are anchors to /api/auth/oidc/<slug>/start, so there is nothing to bind here
   * and no SDK to wait for. What DOES need handling is the trip back: the callback redirects to
   * #/login carrying either a session token or an error code.
   *
   * The token rides in the URL FRAGMENT, which browsers never send to servers and proxies never
   * log — and it is stripped from the address bar before anything else happens, so a shared screen
   * or a copied URL does not carry a live session.
   */
  /*
   * Email-first SSO for organizations.
   *
   * Instance-wide providers are always on the page. An ORG provider is different — it belongs to
   * one customer — so it is fetched by domain once the address looks complete, and only then.
   *
   * Debounced because this fires while someone types, and the endpoint is rate limited; asking on
   * every keystroke would spend a user's whole budget before they finished their own address.
   */
  let ssoLookupTimer = null;
  let lastDomainAsked = '';
  const orgSlot = () => document.getElementById('orgSsoSlot');

  /*
   * Show or hide the password half of the sign-in form.
   *
   * Presentation only — the server refuses a password for these accounts regardless. Restoring it
   * on every negative answer matters as much as hiding it: someone who types an SSO-only address,
   * then corrects it to their own, must get the password box back.
   */
  function setPasswordVisible(visible) {
    /*
     * ⚠️ Hide the password FIELD, never its .form-group — the organization SSO slot lives inside
     * that same group, so hiding the container took the single sign-on button down with it and left
     * a login page whose only action was "Create Account". Found by looking at a screenshot.
     */
    const show = visible ? '' : 'none';
    for (const id of ['loginPassword', 'loginPasswordLabel', 'loginBtn']) {
      const el = document.getElementById(id);
      if (el) el.style.display = show;
    }
    /*
     * The instance's own providers go too. They are the operator's, not this organization's, and
     * they are not domain-confined — so offering "Continue with Google" to someone whose company
     * requires its own identity provider is offering them the bypass. The server refuses it either
     * way; this stops the page inviting it.
     */
    const instance = document.getElementById('instanceProviders');
    if (instance) instance.style.display = show;
    // "Forgot your password?" sits in its own <p>; hide the wrapper so no empty gap is left.
    const forgot = document.getElementById('forgotLink');
    if (forgot) {
      const wrap = forgot.parentElement && forgot.parentElement.tagName === 'P' ? forgot.parentElement : forgot;
      wrap.style.display = show;
    }
  }

  async function lookupOrgSso(email) {
    const at = String(email || '').lastIndexOf('@');
    const domain = at === -1 ? '' : email.slice(at + 1).trim().toLowerCase();
    const slot = orgSlot();
    if (!slot) return;
    // Nothing to ask about until there is a domain with a dot in it.
    if (!domain || !domain.includes('.')) {
      slot.style.display = 'none'; slot.innerHTML = ''; lastDomainAsked = ''; setPasswordVisible(true); return;
    }
    if (domain === lastDomainAsked) return;
    try {
      const res = await fetch(`/api/auth/sso/discover?email=${encodeURIComponent(email)}`);
      const data = await res.json();
      // Remembered only after a SUCCESSFUL answer. Recording it before the fetch meant a 5xx or a
      // tripped rate limit poisoned that domain for the rest of the page's life.
      lastDomainAsked = domain;
      if (!data.sso) { slot.style.display = 'none'; slot.innerHTML = ''; setPasswordVisible(true); return; }
      /*
       * When the organization REQUIRES its identity provider, the password box is not merely going
       * to fail — it is the wrong thing to offer. Showing it invites someone to type a password,
       * be refused, and go and reset a password that will never work again. Hidden, not disabled,
       * so there is one obvious way forward.
       */
      setPasswordVisible(!data.required);
      /*
       * A FORM, not a link, and a deliberately generic label.
       *
       * The lookup tells us only that this domain uses SSO — never which provider or whose it is,
       * because that would identify a customer to anyone who guessed a domain. The server does the
       * mapping again on submit, so the slug is never published to the page. POST keeps the address
       * out of the URL, browser history and any Referer the provider's page would send.
       */
      slot.innerHTML = `
        <form method="POST" action="/api/auth/sso/start">
          <input type="hidden" name="email" value="${esc(email)}">
          <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center;padding:10px">
            ${t('auth.signin_sso')}
          </button>
        </form>
        <div style="font-size:11px;color:var(--text-muted);margin-top:6px;text-align:center">
          ${t('auth.sso_org_hint')}
        </div>`;
      slot.style.display = '';
    } catch {
      // A failed lookup must never block a password login — the form still works, and the password
      // box comes back rather than leaving someone staring at a form with no way to submit it.
      slot.style.display = 'none';
      slot.innerHTML = '';
      setPasswordVisible(true);
    }
  }

  document.getElementById('loginEmail')?.addEventListener('input', (e) => {
    clearTimeout(ssoLookupTimer);
    const value = e.target.value;
    ssoLookupTimer = setTimeout(() => lookupOrgSso(value), 400);
  });

  /*
   * Completing an SSO login.
   *
   * The callback no longer hands the session token back in the URL — that was a login-CSRF hole,
   * because a crafted link could install an ATTACKER'S token and quietly sign the victim into their
   * account. The server now leaves it in a one-shot httpOnly cookie and we exchange it here, which
   * a link cannot forge.
   *
   * Wrapped in an async IIFE because setupHandlers() is not async; `await` at this level is a
   * SyntaxError that takes the whole module graph down with it, since app.js imports this file
   * statically and there is no bundler to catch it first.
   */
  const ssoParams = new URLSearchParams((window.location.hash.split('?')[1] || ''));
  const ssoReturning = ssoParams.get('sso') === '1';
  const ssoError = ssoParams.get('sso_error');

  if (ssoReturning || ssoError) {
    // Keep any real query string; only the hash carried the SSO markers.
    history.replaceState(null, '', window.location.pathname + window.location.search + '#/login');
  }

  if (ssoReturning) {
    (async () => {
      try {
        const res = await fetch('/api/auth/sso/claim', { method: 'POST' });
        if (!res.ok) throw new Error('claim rejected');
        const data = await res.json();
        onAuthSuccess(data);
      } catch {
        showToast(t('auth.sso_failed'), 'error');
      }
    })();
  } else if (ssoError) {
    // Every code the callback can emit has a message; an unknown one still says something true
    // rather than failing silently, which is how the previous implementation behaved on every click.
    const known = ['expired', 'bad_state', 'no_code', 'no_email', 'email_unverified',
      'verification_failed', 'provider_refused', 'provider_unavailable', 'unknown_provider',
      'registration_disabled', 'account_exists_local', 'subject_mismatch', 'server_error',
      'domain_not_allowed', 'account_exists_other_provider'];
    const key = known.includes(ssoError) ? `auth.sso_err_${ssoError}` : 'auth.sso_failed';
    showToast(t(key), 'error');
  }
}

function onAuthSuccess(data) {
  // Defensive: only a response that actually carries a session token logs the user in. A
  // tokenless response (e.g. verification_required / mfa_required) must never be stored as a
  // session — otherwise isAuthenticated() would pass on the string "undefined" and the router
  // would bounce an un-authenticated browser into the app / setup wizard.
  if (!data || !data.token) return;
  localStorage.setItem('token', data.token);
  localStorage.setItem('user', JSON.stringify(data.user));
  window.location.hash = '#/';
  window.location.reload();
}

export function cleanup() {}
