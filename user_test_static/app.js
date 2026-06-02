// AuthGlow Test Playground - Client Logic
// All API calls go through the local playground proxy to avoid CORS issues.

const SESSION_KEYS = {
  accessToken: 'ag_access_token',
  refreshToken: 'ag_refresh_token',
  userId: 'ag_user_id',
  userEmail: 'ag_user_email',
  mfaSecret: 'ag_mfa_secret',
  mfaSessionToken: 'ag_mfa_session_token',
  oauthCode: 'ag_oauth_code',
  oauthAccessToken: 'ag_oauth_access_token',
  oauthCodeVerifier: 'ag_oauth_code_verifier',
};

// ---- PKCE Helpers ----
function generateCodeVerifier() {
  var array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64urlEncode(array);
}

function base64urlEncode(buffer) {
  var binary = '';
  var bytes = new Uint8Array(buffer);
  for (var i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function computeCodeChallenge(verifier) {
  var encoder = new TextEncoder();
  var data = encoder.encode(verifier);
  var hash = await crypto.subtle.digest('SHA-256', data);
  return base64urlEncode(hash);
}

// ---- Session Management ----
function getSession() {
  const s = {};
  for (const [k, v] of Object.entries(SESSION_KEYS)) {
    s[k] = localStorage.getItem(v) || '';
  }
  return s;
}

function setSession(data) {
  for (const [k, v] of Object.entries(data)) {
    if (v !== undefined && v !== null) {
      localStorage.setItem(SESSION_KEYS[k], String(v));
    }
  }
  updateSessionUI();
}

function clearSession() {
  for (const k of Object.values(SESSION_KEYS)) {
    localStorage.removeItem(k);
  }
  updateSessionUI();
  showToast('Session cleared', 'info');
}

function updateSessionUI() {
  const s = getSession();
  const dot = document.getElementById('conn-dot');
  const info = document.getElementById('session-info');
  if (!dot || !info) return;
  if (s.accessToken) {
    dot.className = 'status-dot connected';
    info.textContent = s.userEmail || s.userId || 'Logged in';
    var oauthEmail = document.getElementById('oauth-email');
    if (oauthEmail && !oauthEmail.value && s.userEmail) {
      oauthEmail.value = s.userEmail;
    }
  } else if (s.mfaSessionToken) {
    dot.className = 'status-dot';
    dot.style.background = 'var(--warning)';
    info.textContent = 'MFA pending...';
  } else {
    dot.className = 'status-dot disconnected';
    info.textContent = 'Not logged in';
  }
}

// ---- Navigation ----
function showSection(name) {
  document.querySelectorAll('.section').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  const section = document.getElementById('section-' + name);
  if (section) section.classList.add('active');
  const navItem = document.querySelector(`.nav-item[data-section="${name}"]`);
  if (navItem) navItem.classList.add('active');
}

// ---- Toast ----
function showToast(msg, type) {
  type = type || 'info';
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.style.cssText = 'position:fixed;top:16px;right:16px;z-index:9999;display:flex;flex-direction:column;gap:8px;';
    document.body.appendChild(container);
  }
  const toast = document.createElement('div');
  const colors = { info: 'var(--primary-bg)', success: 'var(--success-bg)', error: 'var(--error-bg)', warning: 'var(--warning-bg)' };
  const textColors = { info: 'var(--primary)', success: 'var(--success)', error: 'var(--error)', warning: 'var(--warning)' };
  toast.style.cssText = 'padding:10px 18px;border-radius:6px;font-size:13px;font-weight:600;background:' + (colors[type] || colors.info) + ';color:' + (textColors[type] || textColors.info) + ';border:1px solid ' + (textColors[type] || textColors.info) + '30;animation:fadeIn .2s;';
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(function() { toast.style.opacity = '0'; toast.style.transition = 'opacity .3s'; setTimeout(function() { toast.remove(); }, 300); }, 3000);
}

// ---- JSON Syntax Highlighting ----
function syntaxHighlight(json) {
  if (typeof json !== 'string') json = JSON.stringify(json, null, 2);
  json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return json.replace(/(^\s*".*?")(\s*:)/gm, '<span class="key">$1</span>$2')
    .replace(/:\s*(".*?")/g, ': <span class="string">$1</span>')
    .replace(/:\s*(\d+\.?\d*)/g, ': <span class="number">$1</span>')
    .replace(/:\s*(true|false)/g, ': <span class="bool">$1</span>')
    .replace(/:\s*(null)/g, ': <span class="null">$1</span>');
}

// ---- Render Response ----
function showResponse(containerId, status, data, timeMs) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.classList.add('visible');
  const statusClass = status >= 200 && status < 300 ? 'success' : status >= 400 ? 'error' : 'warning';
  let formatted;
  if (typeof data === 'object') {
    formatted = syntaxHighlight(data);
  } else {
    const div = document.createElement('div');
    div.textContent = String(data);
    formatted = div.innerHTML;
  }

  container.innerHTML =
    '<div class="response-header">' +
      '<span class="status-badge ' + statusClass + '">' + status + '</span>' +
      '<span class="time">' + timeMs + 'ms</span>' +
      '<button class="copy-btn" onclick="copyResponse(this)">Copy</button>' +
    '</div>' +
    '<div class="response-body">' + formatted + '</div>';
}

function copyResponse(btn) {
  const body = btn.parentElement.nextElementSibling;
  navigator.clipboard.writeText(body.textContent).then(function() {
    btn.textContent = 'Copied!';
    setTimeout(function() { btn.textContent = 'Copy'; }, 1500);
  });
}

// ---- Core API Call via Proxy ----
async function apiCall(method, path, body, extraHeaders, auth) {
  var s = getSession();
  if (auth && !s.accessToken) {
    showToast('Login required — authenticate first or complete MFA verification', 'error');
    return { status: 401, data: { detail: 'No access token. Please login first.' }, time: 0 };
  }
  var proxyPath = '/proxy' + path;
  var headers = { 'Content-Type': 'application/json' };
  if (extraHeaders) Object.assign(headers, extraHeaders);
  if (auth) {
    headers['Authorization'] = 'Bearer ' + s.accessToken;
  }

  const start = performance.now();
  try {
    const opts = { method: method, headers: headers };
    if (body && method !== 'GET') {
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(proxyPath, opts);
    const elapsed = Math.round(performance.now() - start);
    let data;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      data = await res.json();
    } else {
      data = await res.text();
    }
    return { status: res.status, data: data, time: elapsed };
  } catch (err) {
    const elapsed = Math.round(performance.now() - start);
    return { status: 0, data: { error: err.message }, time: elapsed };
  }
}

async function apiCallAndShow(method, path, containerId, body, auth, extraHeaders) {
  const btn = event.target.closest('button');
  const origText = btn.textContent;
  btn.disabled = true;
  btn.innerHTML = '<span class="loading-spinner"></span> Loading...';
  const res = await apiCall(method, path, body, extraHeaders, auth);
  btn.disabled = false;
  btn.textContent = origText;
  showResponse(containerId, res.status, res.data, res.time);
  return res;
}

// ---- Health Check ----
async function checkHealth() {
  const res = await apiCall('GET', '/health');
  if (res.status === 200 && res.data.authglow === 'reachable') {
    showToast('AuthGlow server is reachable!', 'success');
  } else if (res.status === 502) {
    showToast('AuthGlow server unreachable - make sure it is running on :8001', 'error');
  } else {
    showToast('AuthGlow health check: status ' + res.status, 'warning');
  }
  return res;
}

// ---- Setup ----
async function createAdmin() {
  const body = {
    email: document.getElementById('setup-email').value,
    password: document.getElementById('setup-password').value,
    first_name: document.getElementById('setup-first').value || null,
    last_name: document.getElementById('setup-last').value || null,
  };
  const res = await apiCallAndShow('POST', '/api/setup/create-admin', 'res-setup-create', body);
  if (res.status >= 200 && res.status < 300 && res.data.user_id) {
    showToast('Admin created! You can now login.', 'success');
  }
}

// ---- Auth ----
async function registerUser() {
  const body = {
    email: document.getElementById('reg-email').value,
    password: document.getElementById('reg-password').value,
    first_name: document.getElementById('reg-first').value || null,
    last_name: document.getElementById('reg-last').value || null,
  };
  const res = await apiCallAndShow('POST', '/api/users', 'res-auth-register', body);
  if (res.status >= 200 && res.status < 300) {
    showToast('User registered!', 'success');
  }
}

async function inviteUser() {
  const body = {
    email: document.getElementById('reg-email').value,
    scopes: ['read'],
  };
  const res = await apiCallAndShow('POST', '/api/users/invite', 'res-auth-register', body, true);
  if (res.status >= 200 && res.status < 300) {
    showToast('Invitation sent!', 'success');
  }
}

async function loginUser() {
  const formData = new URLSearchParams();
  formData.append('username', document.getElementById('login-email').value);
  formData.append('password', document.getElementById('login-password').value);

  const btn = event.target.closest('button');
  btn.disabled = true;
  btn.innerHTML = '<span class="loading-spinner"></span> Logging in...';
  const start = performance.now();

  try {
    const res = await fetch('/proxy/api/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString(),
    });
    const elapsed = Math.round(performance.now() - start);
    let data;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      data = await res.json();
    } else {
      const text = await res.text();
      try { data = JSON.parse(text); } catch(e) { data = { raw: text }; }
    }

    showResponse('res-auth-login', res.status, data, elapsed);
    btn.disabled = false;
    btn.textContent = 'Login';

    if (data.access_token) {
      setSession({ accessToken: data.access_token, refreshToken: data.refresh_token || '' });
      showToast('Logged in successfully!', 'success');
      const meRes = await apiCall('GET', '/api/users/me', null, null, true);
      if (meRes.status === 200 && meRes.data) {
        const d = meRes.data;
        setSession({ userId: d.id || d.user_id || '', userEmail: d.email || '' });
      }
    } else if (data.mfa_required) {
      const token = data.session_token || data.mfa_session_token || '';
      if (token) {
        localStorage.removeItem(SESSION_KEYS.accessToken);
        localStorage.removeItem(SESSION_KEYS.refreshToken);
        setSession({ mfaSessionToken: token, accessToken: '', refreshToken: '' });
        showMfaModal();
      } else {
        showToast('MFA required but no session token received', 'error');
      }
    } else {
      showToast('Login failed (status ' + res.status + ')', 'error');
    }
    return { status: res.status, data: data, time: elapsed };
  } catch (err) {
    btn.disabled = false;
    btn.textContent = 'Login';
    const elapsed = Math.round(performance.now() - start);
    showResponse('res-auth-login', 0, { error: err.message }, elapsed);
  }
}

// ---- MFA ----
async function mfaEnrollIntercept() {
  const res = await apiCall('POST', '/api/mfa/enroll', null, null, true);
  showResponse('res-mfa-enroll', res.status, res.data, res.time);
  if (res.status === 200 && res.data) {
    if (res.data.secret) {
      setSession({ mfaSecret: res.data.secret });
      const secretEl = document.getElementById('mfa-secret-display');
      if (secretEl) secretEl.textContent = res.data.secret;
    }
    if (res.data.qr_code || res.data.qr_code_base64 || res.data.image) {
      const qrData = res.data.qr_code || res.data.qr_code_base64 || res.data.image;
      const img = document.getElementById('mfa-qr-img');
      if (qrData.startsWith('data:')) {
        img.src = qrData;
      } else if (qrData.startsWith('http')) {
        img.src = qrData;
      } else {
        img.src = 'data:image/png;base64,' + qrData;
      }
      document.getElementById('mfa-qr-container').style.display = 'block';
    }
    showToast('MFA enrolled! Scan QR code and verify with a TOTP code.', 'success');
  }
  return res;
}

async function verifyMFA() {
  const code = document.getElementById('mfa-verify-code').value;
  const body = { code: code };
  return await apiCallAndShow('POST', '/api/mfa/verify', 'res-mfa-verify', body, true);
}

async function loginWithMFA() {
  var code = document.getElementById('mfa-login-code').value;
  var s = getSession();
  var sessionToken = s.mfaSessionToken;
  if (!sessionToken) {
    showToast('No MFA session token found. Login first to get one.', 'error');
    return { status: 0, data: { error: 'No MFA session token' }, time: 0 };
  }
  var body = { code: code };
  var extraHeaders = { 'Authorization': 'Bearer ' + sessionToken };
  var res = await apiCallAndShow('POST', '/api/mfa/verify-login', 'res-mfa-login', body, false, extraHeaders);
  if (res.status === 200 && res.data.access_token) {
    setSession({ accessToken: res.data.access_token, refreshToken: res.data.refresh_token || '' });
    var meRes = await apiCall('GET', '/api/users/me', null, null, true);
    if (meRes.status === 200 && meRes.data) {
      setSession({ userId: meRes.data.id || meRes.data.user_id || '', userEmail: meRes.data.email || '' });
    }
    showToast('MFA login successful!', 'success');
  }
  return res;
}

// ---- Profile ----
async function updateProfile() {
  const body = {};
  const fn = document.getElementById('prof-first').value;
  const ln = document.getElementById('prof-last').value;
  if (fn) body.first_name = fn;
  if (ln) body.last_name = ln;
  return await apiCallAndShow('PATCH', '/api/profile/me', 'res-profile-update', body, true);
}

async function changePassword() {
  const body = {
    current_password: document.getElementById('prof-oldpw').value,
    new_password: document.getElementById('prof-newpw').value,
  };
  return await apiCallAndShow('POST', '/api/profile/me/change-password', 'res-profile-chpw', body, true);
}

// ---- Password Reset ----
async function requestPasswordReset() {
  const body = { email: document.getElementById('pwreset-email').value };
  const res = await apiCallAndShow('POST', '/api/password/reset/request', 'res-pwreset-request', body);
  if (res.status >= 200 && res.status < 300 && res.data.token) {
    document.getElementById('pwreset-token').value = res.data.token;
  }
  return res;
}

async function confirmPasswordReset() {
  const body = {
    token: document.getElementById('pwreset-token').value,
    new_password: document.getElementById('pwreset-newpw').value,
  };
  return await apiCallAndShow('POST', '/api/password/reset/confirm', 'res-pwreset-confirm', body);
}

// ---- Email ----
async function verifyEmail() {
  const body = { token: document.getElementById('email-token').value };
  return await apiCallAndShow('POST', '/api/email/verify', 'res-email-verify', body);
}

// ---- API Keys ----
async function createApiKey() {
  const body = {
    name: document.getElementById('apikey-name').value,
    scopes: document.getElementById('apikey-scopes').value.split(',').map(function(s) { return s.trim(); }),
  };
  const res = await apiCallAndShow('POST', '/api/keys', 'res-apikey-create', body, true);
  if (res.status >= 200 && res.status < 300 && res.data) {
    const key = res.data.key || res.data.raw_key || res.data.api_key || '';
    if (key) document.getElementById('apikey-test-key').value = key;
  }
  return res;
}

async function testApiKey() {
  const key = document.getElementById('apikey-test-key').value;
  return await apiCallAndShow('POST', '/api/token/api-key', 'res-apikey-test', null, false, { Authorization: 'Bearer ' + key });
}

// ---- OAuth2 Flow ----
async function oauthAuthorize() {
  const s = getSession();
  const email = document.getElementById('oauth-email').value || s.email || '';
  const password = document.getElementById('oauth-password').value;

  if (!email || !password) {
    showToast('Email and password are required for OAuth2 authorize', 'error');
    return;
  }

  const usePKCE = document.getElementById('oauth-use-pkce').checked;
  let codeVerifier = '';
  let codeChallenge = '';
  let codeChallengeMethod = '';

  if (usePKCE) {
    codeVerifier = generateCodeVerifier();
    codeChallenge = await computeCodeChallenge(codeVerifier);
    codeChallengeMethod = 'S256';
    document.getElementById('oauth-code-verifier').value = codeVerifier;
    setSession({ oauthCodeVerifier: codeVerifier });
  }

  const body = {
    email: email,
    password: password,
    client_id: document.getElementById('oauth-client-id').value,
    redirect_uri: document.getElementById('oauth-redirect').value,
    scope: document.getElementById('oauth-scope').value,
  };

  if (usePKCE) {
    body.code_challenge = codeChallenge;
    body.code_challenge_method = codeChallengeMethod;
  }

  const btn = event.target.closest('button');
  btn.disabled = true;
  btn.innerHTML = '<span class="loading-spinner"></span> Authorizing...';
  const start = performance.now();

  try {
    const headers = { 'Content-Type': 'application/json' };
    const res = await fetch('/auto-oauth2-authorize', {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(body),
    });
    const elapsed = Math.round(performance.now() - start);
    let data;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      data = await res.json();
    } else {
      data = await res.text();
    }

    showResponse('res-oauth-authorize', res.status, data, elapsed);
    btn.disabled = false;
    btn.textContent = 'Authorize';

    if (data.authorization_code) {
      document.getElementById('oauth-code').value = data.authorization_code;
      setSession({ oauthCode: data.authorization_code });
      showToast('Authorization code received! Proceed to token exchange.', 'success');
    } else if (data.mfa_required) {
      showToast('MFA is required for this account — complete MFA verification first.', 'warning');
    } else if (data.error) {
      showToast('OAuth2 error: ' + (data.error_description || data.error), 'error');
    }
  } catch (err) {
    btn.disabled = false;
    btn.textContent = 'Authorize';
    showResponse('res-oauth-authorize', 0, { error: err.message }, Math.round(performance.now() - start));
  }
}

async function oauthToken() {
  const s = getSession();
  const code = document.getElementById('oauth-code').value || s.oauthCode;
  const client_id = document.getElementById('oauth-client-id').value;
  const client_secret = document.getElementById('oauth-client-secret').value;
  const redirect_uri = document.getElementById('oauth-redirect').value;
  const code_verifier = document.getElementById('oauth-code-verifier').value || s.oauthCodeVerifier || '';

  const formData = new URLSearchParams();
  formData.append('grant_type', 'authorization_code');
  formData.append('code', code);
  formData.append('client_id', client_id);
  formData.append('client_secret', client_secret);
  formData.append('redirect_uri', redirect_uri);
  if (code_verifier) {
    formData.append('code_verifier', code_verifier);
  }

  const btn = event.target.closest('button');
  btn.disabled = true;
  btn.innerHTML = '<span class="loading-spinner"></span> Exchanging...';
  const start = performance.now();

  try {
    const creds = btoa(client_id + ':' + client_secret);
    const res = await fetch('/proxy/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + creds,
      },
      body: formData.toString(),
    });
    const elapsed = Math.round(performance.now() - start);
    let data;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      data = await res.json();
    } else {
      data = await res.text();
    }

    showResponse('res-oauth-token', res.status, data, elapsed);
    btn.disabled = false;
    btn.textContent = 'Get Token';

    if (res.status === 200 && data.access_token) {
      setSession({ oauthAccessToken: data.access_token });
      showToast('OAuth2 token obtained! Now fetch user info.', 'success');
    }
  } catch (err) {
    btn.disabled = false;
    btn.textContent = 'Get Token';
    showResponse('res-oauth-token', 0, { error: err.message }, Math.round(performance.now() - start));
  }
}

async function oauthUserInfo() {
  const s = getSession();
  const token = s.oauthAccessToken;
  if (!token) {
    showToast('No OAuth2 access token — complete the token exchange first.', 'error');
    return { status: 0, data: { error: 'No OAuth2 access token' }, time: 0 };
  }
  return await apiCallAndShow('GET', '/oauth2/userinfo', 'res-oauth-userinfo', null, false, { Authorization: 'Bearer ' + token });
}

// ---- OAuth2 Clients ----
async function createOAuthClient() {
  var rawScopes = document.getElementById('oclient-scopes').value.trim();
  var allowedScopes = rawScopes ? rawScopes.split(/\s+/).filter(Boolean) : ['read'];
  var isConfidential = document.getElementById('oclient-confidential').checked;

  const body = {
    client_name: document.getElementById('oclient-name').value,
    redirect_uris: document.getElementById('oclient-redirects').value.split(',').map(function(s) { return s.trim(); }).filter(Boolean),
    allowed_scopes: allowedScopes,
    is_confidential: isConfidential,
  };

  if (!isConfidential) {
    body.require_pkce = true;
    body.require_consent = true;
  }

  const res = await apiCallAndShow('POST', '/api/oauth-clients', 'res-oclient-create', body, true);
  if (res.status >= 200 && res.status < 300 && res.data.client_id) {
    document.getElementById('oauth-client-id').value = res.data.client_id;
    document.getElementById('oclient-mgr-id').value = res.data.client_id;
    if (res.data.client_secret) {
      document.getElementById('oauth-client-secret').value = res.data.client_secret;
    }
    showToast('OAuth2 client created! Client ID auto-filled.', 'success');
  }
  return res;
}

async function deactivateOAuthClient() {
  var cid = document.getElementById('oclient-mgr-id').value.trim();
  if (!cid) { showToast('Enter a Client ID', 'error'); return; }
  if (!confirm('Deactivate client ' + cid + '?')) return;
  return await apiCallAndShow('POST', '/api/oauth-clients/' + cid + '/deactivate', 'res-oclient-manage', null, true);
}

async function activateOAuthClient() {
  var cid = document.getElementById('oclient-mgr-id').value.trim();
  if (!cid) { showToast('Enter a Client ID', 'error'); return; }
  return await apiCallAndShow('POST', '/api/oauth-clients/' + cid + '/activate', 'res-oclient-manage', null, true);
}

async function deleteOAuthClient() {
  var cid = document.getElementById('oclient-mgr-id').value.trim();
  if (!cid) { showToast('Enter a Client ID', 'error'); return; }
  if (!confirm('PERMANENTLY delete client ' + cid + '? This cannot be undone.')) return;
  var res = await apiCallAndShow('DELETE', '/api/oauth-clients/' + cid, 'res-oclient-manage', null, true);
  if (res.status >= 200 && res.status < 300) {
    document.getElementById('oclient-mgr-id').value = '';
    showToast('Client deleted.', 'success');
  }
  return res;
}

// ---- Admin ----
async function adminSearchUsers() {
  const q = document.getElementById('admin-search').value;
  const path = q ? '/api/admin/users/search?search=' + encodeURIComponent(q) : '/api/admin/users/search';
  return await apiCallAndShow('GET', path, 'res-admin-users', null, true);
}

async function adminGetUser() {
  const uid = document.getElementById('admin-userid').value;
  if (!uid) { showToast('Enter a user ID', 'error'); return; }
  return await apiCallAndShow('GET', '/api/admin/users/' + uid, 'res-admin-detail', null, true);
}

// ---- RBAC ----
async function createPermission() {
  const body = {
    name: document.getElementById('rbac-perm-name').value,
    resource: document.getElementById('rbac-perm-resource').value,
    action: document.getElementById('rbac-perm-action').value,
    description: document.getElementById('rbac-perm-desc').value,
  };
  return await apiCallAndShow('POST', '/api/rbac/permissions', 'res-rbac-perm-create', body, true);
}

async function createRole() {
  const body = {
    name: document.getElementById('rbac-role-name').value,
    description: document.getElementById('rbac-role-desc').value,
  };
  const res = await apiCallAndShow('POST', '/api/rbac/roles', 'res-rbac-role-create', body, true);
  if (res.status >= 200 && res.status < 300 && res.data.id) {
    showToast('Role created! Copy the ID for assignment.', 'success');
  }
  return res;
}

async function assignRole() {
  const body = {
    user_id: document.getElementById('rbac-assign-uid').value,
    role_id: document.getElementById('rbac-assign-rid').value,
  };
  return await apiCallAndShow('POST', '/api/rbac/user-roles', 'res-rbac-assign', body, true);
}

async function getUserPermissions() {
  const uid = document.getElementById('rbac-userperms-uid').value;
  if (!uid) { showToast('Enter a user ID', 'error'); return; }
  return await apiCallAndShow('GET', '/api/rbac/users/' + uid + '/permissions', 'res-rbac-userperms', null, true);
}

// ---- Passkeys (WebAuthn) ----
function arrayBufferToBase64url(buffer) {
  var bytes = new Uint8Array(buffer);
  var binary = '';
  for (var i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlToArrayBuffer(base64url) {
  var base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  var binary = atob(base64);
  var bytes = new Uint8Array(binary.length);
  for (var i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

var pendingPasskeyRegistration = null;

async function passkeyRegister() {
  var btn = event.target.closest('button');
  btn.disabled = true;
  btn.innerHTML = '<span class="loading-spinner"></span> Starting...';

  var res = await apiCall('POST', '/api/passkey/register/begin', null, null, true);
  btn.disabled = false;
  btn.textContent = 'Start Registration';
  showResponse('res-pk-reg-begin', res.status, res.data, res.time);

  if (res.status !== 200) {
    showToast('Failed to start passkey registration', 'error');
    return;
  }

  var options = res.data;

  if (!navigator.credentials || !navigator.credentials.create) {
    showToast('WebAuthn not supported in this browser/context. Requires HTTPS or localhost.', 'error');
    return;
  }

  try {
    var publicKeyCredentialCreationOptions = {
      publicKey: {
        rp: options.rp,
        user: {
          id: base64urlToArrayBuffer(options.user.id),
          name: options.user.name,
          displayName: options.user.displayName,
        },
        challenge: base64urlToArrayBuffer(options.challenge),
        pubKeyCredParams: options.pubKeyCredParams,
        timeout: options.timeout || 60000,
        excludeCredentials: (options.excludeCredentials || []).map(function(c) {
          return {
            id: base64urlToArrayBuffer(c.id),
            type: c.type,
            transports: c.transports,
          };
        }),
        authenticatorSelection: options.authenticatorSelection,
        attestation: options.attestation || 'none',
      }
    };

    showToast('Browser will prompt for authenticator...', 'info');
    var credential = await navigator.credentials.create(publicKeyCredentialCreationOptions);

    pendingPasskeyRegistration = {
      credential_id: arrayBufferToBase64url(credential.rawId),
      client_data_json: arrayBufferToBase64url(credential.response.clientDataJSON),
      attestation_object: arrayBufferToBase64url(credential.response.attestationObject),
      transports: credential.response.getTransports ? credential.response.getTransports() : ['internal'],
      name: document.getElementById('pk-name').value || 'My Passkey',
    };

    document.getElementById('pk-complete-btn').style.display = 'inline-block';
    showToast('Passkey created! Click "Complete Registration" to save it.', 'success');

  } catch (err) {
    if (err.name === 'NotAllowedError') {
      showToast('Passkey registration cancelled or not allowed', 'warning');
    } else {
      showToast('Passkey error: ' + err.message, 'error');
    }
  }
}

async function passkeyCompleteRegistration() {
  if (!pendingPasskeyRegistration) {
    showToast('No pending passkey registration. Start a new one first.', 'error');
    return;
  }

  var res = await apiCallAndShow('POST', '/api/passkey/register/complete', 'res-pk-reg-begin', pendingPasskeyRegistration, true);
  if (res.status === 200) {
    showToast('Passkey registered successfully!', 'success');
    pendingPasskeyRegistration = null;
    document.getElementById('pk-complete-btn').style.display = 'none';
  }
}

async function passkeyAuthenticate() {
  var email = document.getElementById('pk-auth-email').value;
  if (!email) { showToast('Enter an email address', 'error'); return; }

  var btn = event.target.closest('button');
  btn.disabled = true;
  btn.innerHTML = '<span class="loading-spinner"></span> Starting...';

  var beginRes = await apiCall('POST', '/api/passkey/auth/begin', { email: email }, null, false);
  btn.disabled = false;
  btn.textContent = 'Authenticate';

  if (beginRes.status !== 200) {
    showResponse('res-pk-auth', beginRes.status, beginRes.data, beginRes.time);
    showToast('Failed to start passkey authentication', 'error');
    return;
  }

  var options = beginRes.data;

  try {
    var allowCredentials = (options.allowCredentials || []).map(function(c) {
      return {
        id: base64urlToArrayBuffer(c.id),
        type: c.type,
        transports: c.transports || ['internal'],
      };
    });

    var publicKeyCredentialRequestOptions = {
      publicKey: {
        challenge: base64urlToArrayBuffer(options.challenge),
        rpId: options.rpId,
        allowCredentials: allowCredentials,
        timeout: options.timeout || 60000,
        userVerification: options.userVerification || 'preferred',
      }
    };

    showToast('Browser will prompt for authenticator...', 'info');
    var assertion = await navigator.credentials.get(publicKeyCredentialRequestOptions);

    var verifyBody = {
      credential_id: arrayBufferToBase64url(assertion.rawId),
      client_data_json: arrayBufferToBase64url(assertion.response.clientDataJSON),
      authenticator_data: arrayBufferToBase64url(assertion.response.authenticatorData),
      signature: arrayBufferToBase64url(assertion.response.signature),
      user_handle: assertion.response.userHandle ? arrayBufferToBase64url(assertion.response.userHandle) : null,
    };

    var verifyRes = await apiCall('POST', '/api/passkey/auth/complete', verifyBody, null, false);
    showResponse('res-pk-auth', verifyRes.status, verifyRes.data, verifyRes.time);

    if (verifyRes.status === 200 && verifyRes.data.access_token) {
      setSession({ accessToken: verifyRes.data.access_token });
      showToast('Passkey authentication successful!', 'success');
      var meRes = await apiCall('GET', '/api/users/me', null, null, true);
      if (meRes.status === 200 && meRes.data) {
        setSession({ userId: meRes.data.id || '', userEmail: meRes.data.email || '' });
      }
    }

  } catch (err) {
    if (err.name === 'NotAllowedError') {
      showToast('Passkey authentication cancelled', 'warning');
    } else {
      showToast('Passkey error: ' + err.message, 'error');
    }
  }
}

async function deletePasskey() {
  var credId = document.getElementById('pk-del-id').value;
  if (!credId) { showToast('Enter a credential ID from the list', 'error'); return; }
  return await apiCallAndShow('DELETE', '/api/passkey/' + encodeURIComponent(credId), 'res-pk-delete', null, true);
}

// ---- MFA Modal ----
function showMfaModal() {
  var modal = document.getElementById('mfa-modal');
  modal.style.display = 'flex';
  document.getElementById('mfa-modal-code').value = '';
  document.getElementById('mfa-modal-error').style.display = 'none';
  setTimeout(function() { document.getElementById('mfa-modal-code').focus(); }, 100);
}

function closeMfaModal() {
  document.getElementById('mfa-modal').style.display = 'none';
}

async function submitMfaModal() {
  var code = document.getElementById('mfa-modal-code').value.trim();
  if (!code) return;
  var s = getSession();
  var sessionToken = s.mfaSessionToken;
  if (!sessionToken) {
    showToast('No MFA session token. Please login again.', 'error');
    closeMfaModal();
    return;
  }
  var body = { code: code };
  var extraHeaders = { 'Authorization': 'Bearer ' + sessionToken };
  var res = await apiCall('POST', '/api/mfa/verify-login', body, extraHeaders, false);
  if (res.status === 200 && res.data.access_token) {
    setSession({ accessToken: res.data.access_token, refreshToken: res.data.refresh_token || '', mfaSessionToken: '' });
    var meRes = await apiCall('GET', '/api/users/me', null, null, true);
    if (meRes.status === 200 && meRes.data) {
      setSession({ userId: meRes.data.id || meRes.data.user_id || '', userEmail: meRes.data.email || '' });
    }
    closeMfaModal();
    showToast('MFA verified! Logged in successfully.', 'success');
  } else {
    var errEl = document.getElementById('mfa-modal-error');
    errEl.textContent = res.data.detail || res.data.error || 'Invalid code, try again';
    errEl.style.display = 'block';
  }
}

// Handle Enter key in modal
document.addEventListener('keydown', function(e) {
  var modal = document.getElementById('mfa-modal');
  if (modal.style.display === 'flex' && e.key === 'Enter') {
    submitMfaModal();
  }
});

// ---- Init ----
updateSessionUI();