/**
 * auth.js - Frontend authentication logic
 * Handles: register, login, 2FA, password tools, API calls
 */

const API = '/api/auth';

// ─── Storage Helpers ──────────────────────────────────────────

const Storage = {
  setToken:       (t) => { sessionStorage.setItem('auth_token', t); localStorage.setItem('auth_token', t); },
  getToken:       ()  => sessionStorage.getItem('auth_token') || localStorage.getItem('auth_token'),
  setRefreshToken:(r) => localStorage.setItem('refresh_token', r),
  getRefreshToken:()  => localStorage.getItem('refresh_token'),
  clearTokens:    ()  => { sessionStorage.removeItem('auth_token'); localStorage.removeItem('auth_token'); localStorage.removeItem('refresh_token'); },
  setUser:        (u) => { sessionStorage.setItem('auth_user', JSON.stringify(u)); localStorage.setItem('auth_user', JSON.stringify(u)); },
  getUser:        ()  => { try { return JSON.parse(sessionStorage.getItem('auth_user') || localStorage.getItem('auth_user')); } catch { return null; } },
  clearUser:      ()  => { sessionStorage.removeItem('auth_user'); localStorage.removeItem('auth_user'); },
  setPending2FA:  (t) => sessionStorage.setItem('pending_2fa', t),
  getPending2FA:  ()  => sessionStorage.getItem('pending_2fa'),
  clearPending:   ()  => sessionStorage.removeItem('pending_2fa'),
  clear:          ()  => { Storage.clearTokens(); Storage.clearUser(); Storage.clearPending(); },
};

// ─── API Helpers ──────────────────────────────────────────────

async function apiCall(method, endpoint, body = null) {
  const headers = { 'Content-Type': 'application/json' };
  const token = Storage.getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;

  // Fix: Handle admin routes separately from auth routes
  const baseUrl = endpoint.startsWith('/admin') ? '/api' : API;
  let res = await fetch(`${baseUrl}${endpoint}`, { method, headers, body: body ? JSON.stringify(body) : null });
  let data = await res.json().catch(() => null);

  // Auto-refresh token logic (Tương tự MS365)
  if (res.status === 401 && data?.message === 'Invalid or expired token') {
    const rfToken = Storage.getRefreshToken();
    if (rfToken) {
      const rfRes = await fetch(`${API}/refresh-token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: rfToken })
      });
      const rfData = await rfRes.json().catch(()=>null);
      if (rfRes.ok && rfData.token) {
        Storage.setToken(rfData.token);
        headers['Authorization'] = `Bearer ${rfData.token}`;
        res = await fetch(`${API}${endpoint}`, { method, headers, body: body ? JSON.stringify(body) : null });
        data = await res.json().catch(()=>null);
      } else {
        Storage.clear();
        window.location.href = '/';
      }
    }
  } else if (res.status === 403 && data?.locked && !endpoint.includes('/login')) {
    // Force logout for locked accounts
    Storage.clear();
    window.location.href = '/login?error=locked';
  } else if (res.status === 401 && (data?.requireRelogin || data?.message?.includes('Revoked') || data?.message?.includes('hết hạn') || data?.message === 'User no longer exists')) {
    // Session invalidated globally (revoked by attack, admin, deleted user, or force logout)
    Storage.clear();
    showToast('warning', '⚠️ Phiên hết hạn', 'Tài khoản của bạn đã bị đăng xuất hoặc không tồn tại. Vui lòng đăng nhập lại.');
    setTimeout(() => { window.location.href = '/'; }, 2000);
  }

  return { ok: res.ok, status: res.status, data };
}

// ─── Toast Notifications ──────────────────────────────────────

function showToast(type, title, message, duration = 3000) {
  const icons = { success: '✅', error: '❌', info: 'ℹ️', warning: '⚠️' };
  const container = document.getElementById('toast-container') || createToastContainer();

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${icons[type] || 'ℹ️'}</span>
    <div class="toast-text">
      <div class="toast-title">${title}</div>
      ${message ? `<div class="toast-msg">${message}</div>` : ''}
    </div>
  `;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), duration + 300);
}

function createToastContainer() {
  const c = document.createElement('div');
  c.id = 'toast-container';
  c.className = 'toast-container';
  document.body.appendChild(c);
  return c;
}

// ─── Alert Messages ───────────────────────────────────────────

function showAlert(containerId, type, icon, message) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = `
    <div class="alert alert-${type}">
      <span class="alert-icon">${icon}</span>
      <span>${message}</span>
    </div>
  `;
}

function clearAlert(containerId) {
  const el = document.getElementById(containerId);
  if (el) el.innerHTML = '';
}

// ─── Button Loading State ─────────────────────────────────────

function setButtonLoading(btnId, loading) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  btn.disabled = loading;
  btn.classList.toggle('btn-loading', loading);
  const text = btn.querySelector('.btn-text');
  const loader = btn.querySelector('.btn-loader');
  if (text) text.style.display = loading ? 'none' : '';
  if (loader) loader.innerHTML = loading ? '<span class="spinner">⏳</span>' : '';
  if (loader) loader.style.display = loading ? '' : 'none';
}

// ─── Password Strength Meter ──────────────────────────────────

let strengthDebounce;
async function updateStrengthMeter(password, containerId = 'strength-container') {
  clearTimeout(strengthDebounce);
  const container = document.getElementById(containerId);
  if (!container) return;

  if (!password) {
    container.style.display = 'none';
    return;
  }
  container.style.display = 'block';

  strengthDebounce = setTimeout(async () => {
    try {
      const { ok, data } = await apiCall('POST', '/tools/analyze', { password });
      if (!ok) return;

      const { analysis, bruteForce } = data;
      const pct = [0, 25, 50, 75, 100][analysis.score];

      const barFill = container.querySelector('.strength-bar-fill');
      const label   = container.querySelector('.strength-label');

      if (barFill) {
        barFill.style.width = pct + '%';
        barFill.style.background = `linear-gradient(90deg, ${analysis.color}, ${analysis.color}dd)`;
      }
      if (label) {
        // FR2: show enterprise badge if all checks pass
        const badge = analysis.meetsEnterprise
          ? '<span style="color:var(--accent-green);font-size:0.7rem;margin-left:8px;">✅ Đủ chuẩn enterprise</span>'
          : '<span style="color:var(--accent-orange);font-size:0.7rem;margin-left:8px;">⚠️ Chưa đạt FR2</span>';
        label.innerHTML = `
          <span style="color:${analysis.color}">${analysis.label}</span>
          <span style="color:var(--text-muted);font-weight:400;font-size:0.7rem;margin-left:8px;">
            Crack time: ${analysis.crackTimeDisplay}
          </span>${badge}
        `;
      }

      // Update FR2 entropy check (chk-entropy) if present
      const chkEntropy = document.getElementById('chk-entropy');
      if (chkEntropy) {
        const ok = analysis.score >= 3;
        chkEntropy.classList.toggle('ok', ok);
        chkEntropy.classList.toggle('fail', !ok);
        chkEntropy.querySelector('.check-icon').textContent = ok ? '✓' : '○';
      }

      // Checks
      const checks = container.querySelectorAll('.strength-check');
      const checkMap = [
        { key: 'uppercase',   label: 'Uppercase', ok: analysis.hasUppercase },
        { key: 'lowercase',   label: 'Lowercase', ok: analysis.hasLowercase },
        { key: 'numbers',     label: 'Numbers',   ok: analysis.hasNumbers   },
        { key: 'symbols',     label: 'Symbols',   ok: analysis.hasSymbols   },
        { key: 'length',      label: '12+ chars', ok: analysis.length >= 12 },
        { key: 'notCommon',   label: 'Not common', ok: !analysis.isCommon   },
      ];

      checks.forEach((el, i) => {
        if (checkMap[i]) {
          el.classList.toggle('ok', checkMap[i].ok);
          el.classList.toggle('fail', !checkMap[i].ok);
          el.querySelector('.check-icon').textContent = checkMap[i].ok ? '✓' : '○';
        }
      });

      // Feedback
      const feedbackEl = container.querySelector('.strength-feedback');
      if (feedbackEl && analysis.feedback.warning) {
        feedbackEl.textContent = '⚠️ ' + analysis.feedback.warning;
        feedbackEl.style.display = 'block';
      } else if (feedbackEl) {
        feedbackEl.style.display = 'none';
      }

    } catch (e) {
      console.error('Strength check failed:', e);
    }
  }, 300);
}

// ─── OTP Input Handler ────────────────────────────────────────

function initOTPInputs(containerId, callback) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const inputs = container.querySelectorAll('.otp-digit');

  inputs.forEach((input, idx) => {
    input.addEventListener('input', (e) => {
      const val = e.target.value.replace(/\D/g, '').slice(-1);
      input.value = val;
      if (val && idx < inputs.length - 1) inputs[idx + 1].focus();

      const code = Array.from(inputs).map(i => i.value).join('');
      if (code.length === 6 && callback) callback(code);
    });

    input.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !input.value && idx > 0) {
        inputs[idx - 1].focus();
      }
    });

    input.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
      pasted.split('').forEach((c, i) => { if (inputs[i]) inputs[i].value = c; });
      if (pasted.length === 6 && callback) callback(pasted);
      const nextIdx = Math.min(pasted.length, inputs.length - 1);
      inputs[nextIdx].focus();
    });
  });
}

function getOTPValue(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return '';
  return Array.from(container.querySelectorAll('.otp-digit')).map(i => i.value).join('');
}

function clearOTPInputs(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.querySelectorAll('.otp-digit').forEach(i => { i.value = ''; });
  container.querySelectorAll('.otp-digit')[0]?.focus();
}

// ─── Tab System ───────────────────────────────────────────────

function initTabs(tabsId) {
  const container = document.getElementById(tabsId);
  if (!container) return;
  const btns = container.querySelectorAll('.tab-btn');
  btns.forEach(btn => {
    btn.addEventListener('click', () => {
      btns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const target = btn.dataset.tab;
      document.querySelectorAll('.tab-content').forEach(tc => {
        tc.classList.toggle('active', tc.id === target);
      });
    });
  });
}

// ─── Copy to Clipboard ────────────────────────────────────────

async function copyToClipboard(text, label = 'Copied!') {
  try {
    await navigator.clipboard.writeText(text);
    showToast('success', label, 'Copied to clipboard');
  } catch {
    showToast('error', 'Copy failed', 'Please copy manually');
  }
}

// ─── Auth Guards ──────────────────────────────────────────────

function requireLogin() {
  if (!Storage.getToken()) {
    window.location.href = '/';
    return false;
  }
  return true;
}

function redirectIfLoggedIn() {
  const token = Storage.getToken();
  const user = Storage.getUser();
  if (token && user) {
    const redirectUrl = user.role === 'admin' ? '/admin' : '/dashboard';
    window.location.href = redirectUrl;
  }
}

async function logout() {
  const refreshToken = Storage.getRefreshToken();
  if (refreshToken) {
    await fetch(`${API}/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${Storage.getToken()}`
      },
      body: JSON.stringify({ refreshToken })
    }).catch(() => null);
  }
  Storage.clear();
  showToast('info', 'Logged out', 'Đăng xuất thiết bị hiện tại thành công!');
  setTimeout(() => { window.location.href = '/'; }, 800);
}

async function logoutAll() {
  if (!confirm('Bạn có muốn đăng xuất khỏi TẤT CẢ các thiết bị đang đăng nhập không?')) return;
  await fetch(`${API}/logout-all`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${Storage.getToken()}`
    }
  }).catch(() => null);
  Storage.clear();
  alert('Đã thu hồi toàn bộ phiên đăng nhập (Logout MS365 Style). Vui lòng đăng nhập lại.');
  window.location.href = '/';
}

// ─── Expose globally ──────────────────────────────────────────

window.Auth   = { Storage, apiCall, showToast, showAlert, clearAlert, setButtonLoading };
window.UI     = { updateStrengthMeter, initOTPInputs, getOTPValue, clearOTPInputs, initTabs, copyToClipboard };
window.Guards = { requireLogin, redirectIfLoggedIn, logout, logoutAll };
