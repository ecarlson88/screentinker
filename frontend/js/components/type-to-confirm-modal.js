import { t } from '../i18n.js';

// Reusable destructive-confirmation modal (#36). The primary (danger) button stays
// disabled until the user types `expected` exactly — guards irreversible deletes
// (delete org / workspace). opts:
//   title, body (HTML allowed - caller escapes), expected (string to type),
//   confirmLabel, onConfirm: async () => any  (throw to show an inline error)
export function openTypeToConfirmModal(opts = {}) {
  const { title, body = '', expected, confirmLabel, onConfirm } = opts;
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal">
      <div class="modal-header">
        <h3>${esc(title || '')}</h3>
        <button class="btn-icon" type="button" data-ttc-close aria-label="${t('common.close')}">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>
      <div class="modal-body">
        <div style="font-size:13px;line-height:1.5;margin-bottom:12px">${body}</div>
        <div class="form-group">
          <label for="ttcInput">${t('confirm_delete.type_label', { name: esc(expected) })}</label>
          <input id="ttcInput" type="text" class="input" autocomplete="off" style="width:100%">
        </div>
        <div id="ttcError" style="display:none;color:var(--danger);font-size:13px;margin-top:8px"></div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" type="button" data-ttc-close>${t('common.cancel')}</button>
        <button class="btn btn-danger" type="button" id="ttcConfirm" disabled>${esc(confirmLabel || t('common.delete'))}</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  const input = overlay.querySelector('#ttcInput');
  const confirmBtn = overlay.querySelector('#ttcConfirm');
  const errorEl = overlay.querySelector('#ttcError');

  const matches = () => input.value.trim() === String(expected);
  input.addEventListener('input', () => { confirmBtn.disabled = !matches(); });

  function close() { overlay.remove(); document.removeEventListener('keydown', onKey); }
  function onKey(e) {
    if (e.key === 'Escape') close();
    else if (e.key === 'Enter' && matches()) confirm();
  }
  document.addEventListener('keydown', onKey);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
  overlay.querySelectorAll('[data-ttc-close]').forEach(b => b.addEventListener('click', close));

  async function confirm() {
    if (!matches()) return;
    errorEl.style.display = 'none';
    confirmBtn.disabled = true;
    confirmBtn.textContent = t('common.deleting');
    try {
      await onConfirm?.();
      close();
    } catch (err) {
      confirmBtn.disabled = false;
      confirmBtn.textContent = confirmLabel || t('common.delete');
      errorEl.textContent = err?.message || t('confirm_delete.failed');
      errorEl.style.display = 'block';
    }
  }
  confirmBtn.addEventListener('click', confirm);
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}
