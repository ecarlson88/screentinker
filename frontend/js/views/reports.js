import { api } from '../api.js';
import { showToast } from '../components/toast.js';
import { esc } from '../utils.js';
import { t } from '../i18n.js';

// A refused request must reject, not resolve.
//
// This helper used to end in `.then(r => r.json())`, so a 403/404/500 body resolved as an ordinary
// value and the surrounding try/catch was unreachable — every handler took the failure for success.
// Concretely: deleting a built-in layout template showed "Layout deleted" while the server had
// returned 403 and the template was still there, and a rejected platform-role change showed "Role
// updated" while the dropdown kept displaying a value the server refused (its revert lives only in
// the dead catch). The shared client in api.js has always thrown on !res.ok; these local copies did
// not. Same contract now, including the 401 session-expiry reload.
const API = (url, opts = {}) => fetch('/api' + url, { headers: { Authorization: `Bearer ${localStorage.getItem('token')}`, ...opts.headers }, ...opts }).then(async (r) => {
  if (r.status === 401) { localStorage.removeItem('token'); window.location.reload(); throw new Error('Session expired'); }
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.error || `Request failed (${r.status})`); }
  return r.json();
});

export async function render(container) {
  const devices = await api.getDevices();
  const today = new Date();
  const thirtyDaysAgo = new Date(today);
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  container.innerHTML = `
    <div class="page-header">
      <div><h1>${t('report.title')} <span class="help-tip" data-tip="${t('report.help_tip')}">?</span></h1><div class="subtitle">${t('report.subtitle')}</div></div>
      <a class="btn btn-secondary" id="exportBtn">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
        </svg>
        ${t('report.export_csv')}
      </a>
    </div>

    <div style="display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap;align-items:flex-end">
      <div class="form-group" style="margin:0"><label>${t('report.device')}</label>
        <select id="reportDevice" class="input" style="width:200px;background:var(--bg-input)">
          <option value="">${t('report.all_devices')}</option>
          ${devices.map(d => `<option value="${d.id}">${esc(d.name)}</option>`).join('')}
        </select>
      </div>
      <div class="form-group" style="margin:0"><label>${t('report.start_date')}</label>
        <input type="date" id="reportStart" class="input" value="${thirtyDaysAgo.toISOString().split('T')[0]}">
      </div>
      <div class="form-group" style="margin:0"><label>${t('report.end_date')}</label>
        <input type="date" id="reportEnd" class="input" value="${today.toISOString().split('T')[0]}">
      </div>
      <button class="btn btn-primary btn-sm" id="loadReportBtn">${t('report.load_report')}</button>
    </div>

    <div id="reportContent"><div class="empty-state"><h3>${t('report.select_range')}</h3></div></div>
  `;

  document.getElementById('loadReportBtn').onclick = loadReport;
  loadReport();
  document.getElementById('exportBtn').onclick = () => {
    const deviceId = document.getElementById('reportDevice').value;
    const start = document.getElementById('reportStart').value;
    const end = document.getElementById('reportEnd').value;
    const token = localStorage.getItem('token');
    window.open(`/api/reports/export?device_id=${deviceId}&start=${start}&end=${end}&token=${token}`, '_blank');
  };

  async function loadReport() {
    const deviceId = document.getElementById('reportDevice').value;
    const start = document.getElementById('reportStart').value;
    const end = document.getElementById('reportEnd').value;
    const content = document.getElementById('reportContent');

    content.innerHTML = `<div class="empty-state"><h3>${t('common.loading')}</h3></div>`;

    try {
      const summary = await API(`/reports/summary?device_id=${deviceId}&start=${start}&end=${end}`);

      content.innerHTML = `
        <div class="info-grid" style="margin-bottom:24px">
          <div class="info-card">
            <div class="info-card-label">${t('report.total_plays')}</div>
            <div class="info-card-value">${summary.overall.total_plays.toLocaleString()}</div>
          </div>
          <div class="info-card">
            <div class="info-card-label">${t('report.total_hours')}</div>
            <div class="info-card-value">${summary.overall.total_hours}</div>
          </div>
          <div class="info-card">
            <div class="info-card-label">${t('report.unique_content')}</div>
            <div class="info-card-value">${summary.overall.unique_content}</div>
          </div>
          <div class="info-card">
            <div class="info-card-label">${t('report.active_devices')}</div>
            <div class="info-card-value">${summary.overall.unique_devices}</div>
          </div>
          <div class="info-card">
            <div class="info-card-label">${t('report.avg_duration')}</div>
            <div class="info-card-value small">${formatDuration(summary.overall.avg_duration_sec)}</div>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px">
          <div class="settings-section" style="margin:0">
            <h3 style="font-size:14px;margin-bottom:12px">${t('report.plays_per_day')}</h3>
            <div id="dailyChart" style="height:200px;display:flex;align-items:flex-end;gap:2px"></div>
          </div>

          <div class="settings-section" style="margin:0">
            <h3 style="font-size:14px;margin-bottom:12px">${t('report.plays_by_hour')}</h3>
            <div id="hourlyChart" style="height:200px;display:flex;align-items:flex-end;gap:1px"></div>
          </div>
        </div>

        <div class="settings-section" style="margin-bottom:20px">
          <h3 style="font-size:14px;margin-bottom:12px">${t('report.top_content')}</h3>
          <div class="table-wrap">
          <table style="width:100%;border-collapse:collapse;font-size:13px;min-width:460px">
            <thead><tr style="border-bottom:1px solid var(--border)">
              <th style="padding:8px;text-align:left;color:var(--text-muted)">${t('report.col.content')}</th>
              <th style="padding:8px;text-align:right;color:var(--text-muted)">${t('report.col.plays')}</th>
              <th style="padding:8px;text-align:right;color:var(--text-muted)">${t('report.col.total_hours')}</th>
              <th style="padding:8px;text-align:right;color:var(--text-muted)">${t('report.col.completion')}</th>
            </tr></thead>
            <tbody>
              ${summary.by_content.map(c => `
                <tr style="border-bottom:1px solid var(--border)">
                  <td style="padding:8px">${c.content_name || t('common.unknown')}</td>
                  <td style="padding:8px;text-align:right">${c.plays}</td>
                  <td style="padding:8px;text-align:right">${(c.total_seconds / 3600).toFixed(1)}</td>
                  <td style="padding:8px;text-align:right">${c.plays > 0 ? Math.round((c.completed_plays / c.plays) * 100) : 0}%</td>
                </tr>
              `).join('') || `<tr><td colspan="4" style="padding:16px;text-align:center;color:var(--text-muted)">${t('report.no_data')}</td></tr>`}
            </tbody>
          </table>
          </div>
        </div>

        <div class="settings-section">
          <h3 style="font-size:14px;margin-bottom:12px">${t('report.by_device')}</h3>
          <div class="table-wrap">
          <table style="width:100%;border-collapse:collapse;font-size:13px;min-width:400px">
            <thead><tr style="border-bottom:1px solid var(--border)">
              <th style="padding:8px;text-align:left;color:var(--text-muted)">${t('report.col.device')}</th>
              <th style="padding:8px;text-align:right;color:var(--text-muted)">${t('report.col.plays')}</th>
              <th style="padding:8px;text-align:right;color:var(--text-muted)">${t('report.col.total_hours')}</th>
            </tr></thead>
            <tbody>
              ${summary.by_device.map(d => `
                <tr style="border-bottom:1px solid var(--border)">
                  <td style="padding:8px">${d.device_name}</td>
                  <td style="padding:8px;text-align:right">${d.plays}</td>
                  <td style="padding:8px;text-align:right">${(d.total_seconds / 3600).toFixed(1)}</td>
                </tr>
              `).join('') || `<tr><td colspan="3" style="padding:16px;text-align:center;color:var(--text-muted)">${t('report.no_data')}</td></tr>`}
            </tbody>
          </table>
          </div>
        </div>
      `;

      renderBarChart('dailyChart', summary.by_day.map(d => ({
        label: new Date(d.day).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
        value: d.plays
      })));

      const hourData = Array.from({ length: 24 }, (_, i) => {
        const found = summary.by_hour.find(h => h.hour === i);
        return { label: i === 0 ? '12a' : i < 12 ? i + 'a' : i === 12 ? '12p' : (i - 12) + 'p', value: found?.plays || 0 };
      });
      renderBarChart('hourlyChart', hourData);

    } catch (err) {
      content.innerHTML = `<div class="empty-state"><h3>${t('report.error')}</h3><p>${esc(err.message)}</p></div>`;
    }
  }
}

function renderBarChart(containerId, data) {
  const container = document.getElementById(containerId);
  if (!container || !data.length) return;

  const maxVal = Math.max(...data.map(d => d.value), 1);

  container.innerHTML = data.map(d => `
    <div style="flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;min-width:0" title="${esc(d.label)}: ${esc(d.value)}">
      <div style="font-size:9px;color:var(--text-muted);margin-bottom:2px;display:${d.value > 0 ? 'block' : 'none'}">${d.value}</div>
      <div style="width:100%;max-width:20px;height:${Math.max(2, (d.value / maxVal) * 160)}px;background:var(--accent);border-radius:2px 2px 0 0;min-height:2px"></div>
      <div style="font-size:8px;color:var(--text-muted);margin-top:4px;transform:rotate(-45deg);white-space:nowrap">${esc(d.label)}</div>
    </div>
  `).join('');
}

function formatDuration(seconds) {
  if (!seconds) return '0s';
  if (seconds < 60) return Math.round(seconds) + 's';
  if (seconds < 3600) return Math.round(seconds / 60) + 'm';
  return (seconds / 3600).toFixed(1) + 'h';
}

export function cleanup() {}
