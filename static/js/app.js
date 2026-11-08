/**
 * SYSAD Centralized Portal Client Application
 * Implements Login Gateway & Role-Based Dashboards for:
 *  - Student
 *  - IT Staff
 *  - Administrator
 */

let authToken = localStorage.getItem('sysad_token') || null;
let currentUser = null;
let telemetryInterval = null;

// Initialize on DOM Ready
document.addEventListener('DOMContentLoaded', async () => {
  if (authToken) {
    await verifySession();
  } else {
    showLoginView();
  }
});

// Toast Notification
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerText = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// REST Helper
async function apiCall(endpoint, method = 'GET', body = null, showErrorToast = true) {
  const headers = { 'Content-Type': 'application/json' };
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  try {
    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);

    const response = await fetch(endpoint, options);
    let data;
    try {
      data = await response.json();
    } catch (parseErr) {
      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }
      throw new Error('Invalid response from server');
    }

    if (!response.ok) {
      throw new Error(data.error || 'Request failed');
    }
    return data;
  } catch (err) {
    if (showErrorToast) {
      showToast(err.message, 'error');
    }
    throw err;
  }
}

// -------------------------------------------------------------
// Authentication & Session Management (Process 1.0)
// -------------------------------------------------------------
async function verifySession() {
  try {
    const res = await apiCall('/api/auth/session', 'GET');
    if (res.authenticated && res.user) {
      currentUser = res.user;
      if (currentUser && currentUser.full_name) {
        currentUser.full_name = currentUser.full_name.replace(/\s*\(SysAdmin\)/gi, '').trim();
      }
      renderRoleDashboard();
    } else {
      showLoginView();
    }
  } catch (err) {
    showLoginView();
  }
}

async function handleManualLogin(e) {
  e.preventDefault();
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value.trim();
  await performLogin(username, password);
}

function toggleLoginRegister(view) {
  const loginCard = document.getElementById('card-login-view');
  const regCard = document.getElementById('card-register-view');
  if (view === 'register') {
    if (loginCard) loginCard.style.display = 'none';
    if (regCard) regCard.style.display = 'block';
  } else {
    if (regCard) regCard.style.display = 'none';
    if (loginCard) loginCard.style.display = 'block';
  }
}

async function handleStudentRegistration(e) {
  e.preventDefault();
  const fullName = document.getElementById('reg-fullname').value.trim();
  const username = document.getElementById('reg-username').value.trim().toLowerCase();
  const department = document.getElementById('reg-department').value;
  const password = document.getElementById('reg-password').value;
  const confirmPassword = document.getElementById('reg-password-confirm').value;

  if (password !== confirmPassword) {
    showToast('Passwords do not match. Please verify and retry.', 'error');
    return;
  }

  if (password.length < 6) {
    showToast('Password must be at least 6 characters long.', 'warning');
    return;
  }

  try {
    const res = await apiCall('/api/auth/register-student', 'POST', {
      full_name: fullName,
      username,
      department,
      password
    });

    showToast(res.message, 'success');

    // Switch back to login view with registered username prefilled
    toggleLoginRegister('login');
    const loginUserEl = document.getElementById('login-username');
    if (loginUserEl) loginUserEl.value = username;
    const loginPassEl = document.getElementById('login-password');
    if (loginPassEl) {
      loginPassEl.value = '';
      loginPassEl.focus();
    }
  } catch (err) {
    // Handled in apiCall
  }
}

async function performLogin(username, password) {
  try {
    const res = await apiCall('/api/auth/login', 'POST', { username, password });
    authToken = res.token;
    currentUser = res.user;
    if (currentUser && currentUser.full_name) {
      currentUser.full_name = currentUser.full_name.replace(/\s*\(SysAdmin\)/gi, '').trim();
    }
    localStorage.setItem('sysad_token', authToken);
    showToast(`Welcome, ${currentUser.full_name}! Authenticated as ${currentUser.role}`, 'success');
    renderRoleDashboard();
  } catch (err) {
    // Handled in apiCall
  }
}

async function handleLogout() {
  try {
    if (authToken) {
      await apiCall('/api/auth/logout', 'POST');
    }
  } catch (e) {}

  authToken = null;
  currentUser = null;
  localStorage.removeItem('sysad_token');
  showToast('You have been signed out from the Centralized Portal.', 'info');
  showLoginView();
}

function showLoginView() {
  if (telemetryInterval) {
    clearInterval(telemetryInterval);
    telemetryInterval = null;
  }

  // Hide all dashboards
  document.getElementById('dashboard-student').style.display = 'none';
  document.getElementById('dashboard-itstaff').style.display = 'none';
  document.getElementById('dashboard-admin').style.display = 'none';

  // Hide header user controls
  document.getElementById('header-user-controls').style.display = 'none';

  // Show login screen
  document.getElementById('view-login').style.display = 'block';
  toggleLoginRegister('login');
}

// -------------------------------------------------------------
// Role-Based Dashboard Dispatcher
// -------------------------------------------------------------
function renderRoleDashboard() {
  if (!currentUser) {
    showLoginView();
    return;
  }

  // Hide Login View
  document.getElementById('view-login').style.display = 'none';

  // Show Header User Badge and Logout button
  const headerControls = document.getElementById('header-user-controls');
  headerControls.style.display = 'flex';
  const roleClean = currentUser.role.replace(/\s+/g, '-');
  const cleanDisplayName = (currentUser.full_name || '').replace(/\s*\(SysAdmin\)/gi, '').trim();
  currentUser.full_name = cleanDisplayName;
  document.getElementById('user-profile-badge').innerHTML = `
    <span class="role-badge ${roleClean}">${currentUser.role}</span>
    <span style="font-size:0.85rem; font-weight:600;">${cleanDisplayName}</span>
  `;

  // Hide all dashboards first
  document.getElementById('dashboard-student').style.display = 'none';
  document.getElementById('dashboard-itstaff').style.display = 'none';
  document.getElementById('dashboard-admin').style.display = 'none';

  // Switch to the respective dashboard
  switch (currentUser.role) {
    case 'Student':
      document.getElementById('dashboard-student').style.display = 'block';
      loadStudentData();
      break;

    case 'IT Staff':
      document.getElementById('dashboard-itstaff').style.display = 'block';
      loadITStaffData();
      break;

    case 'Administrator':
      document.getElementById('dashboard-admin').style.display = 'block';
      loadAdminData();
      break;

    default:
      showToast(`Unknown role '${currentUser.role}'`, 'error');
      showLoginView();
      break;
  }
}

// -------------------------------------------------------------
// 1. STUDENT DASHBOARD LOGIC
// -------------------------------------------------------------
async function loadStudentData() {
  if (!currentUser) return;

  // Welcome banner & account status
  document.getElementById('student-welcome-msg').innerText =
    `Logged in as ${currentUser.full_name} • Department: ${currentUser.department || 'Information Technology'}`;
  document.getElementById('student-lifecycle-status').innerText = currentUser.status.toUpperCase();
  const tokenDisplay = document.getElementById('student-token-display');
  if (tokenDisplay) tokenDisplay.innerText = authToken;

  // Load student tickets
  try {
    const res = await apiCall('/api/tickets');
    const tbody = document.querySelector('#student-tickets-table tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    const countEl = document.getElementById('student-ticket-count');
    if (countEl) countEl.innerText = res.tickets.length;

    if (res.tickets.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:1.5rem;">No tickets submitted yet. Use the form above to report a problem.</td></tr>`;
      return;
    }

    res.tickets.forEach(t => {
      const tr = document.createElement('tr');
      const priBadge = getPriorityBadge(t.priority);
      tr.innerHTML = `
        <td style="font-family:monospace; font-weight:700; color:var(--accent-cyan);">${t.ticket_code}</td>
        <td><strong>${escapeHtml(t.title)}</strong><div style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(t.description)}</div></td>
        <td>${t.category}</td>
        <td><span class="badge ${priBadge}">${t.priority}</span></td>
        <td><span class="badge" style="background:#243452;">${t.status}</span></td>
        <td>${t.assigned_to || 'Pending Triage'}</td>
        <td style="font-size:0.78rem; color:${t.resolution_notes ? 'var(--accent-green)' : 'var(--text-muted)'};">${t.resolution_notes ? escapeHtml(t.resolution_notes) : 'In Queue / Investigation'}</td>
        <td style="font-size:0.75rem; color:var(--text-muted);">${formatDateTime(t.updated_at)}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {}

  // Load workstation telemetry
  try {
    await loadStudentWorkstations();
  } catch (e) {}

  // Check and display security violation notices for this student
  try {
    await loadStudentViolations();
  } catch (e) {}
}

async function loadStudentViolations() {
  try {
    const res = await apiCall('/api/network/user-violations');
    const banner = document.getElementById('student-violation-banner');
    if (!banner) return;

    if (res && res.count > 0) {
      banner.style.display = 'block';
      const countBadge = document.getElementById('student-violation-count');
      if (countBadge) countBadge.innerText = `${res.count} Incident(s) Logged`;
      const detailsEl = document.getElementById('student-violation-details');
      if (detailsEl && res.violations[0]) {
        const latest = res.violations[0];
        detailsEl.innerHTML = `
          <strong>Latest Incident:</strong> Access to <code>${escapeHtml(latest.target)}</code> was blocked (Category: ${escapeHtml(latest.category)}). Policy Rule ${escapeHtml(latest.policy_rule || 'FW-RULE-06')} enforced. (Incident Time: ${formatDateTime(latest.timestamp)})
        `;
      }
    } else {
      banner.style.display = 'none';
    }
  } catch (err) {}
}

async function openStudentIncidentsModal() {
  const modal = document.getElementById('modal-student-incidents');
  if (!modal) return;

  const tbody = document.getElementById('student-incidents-tbody');
  const footerEl = document.getElementById('student-incidents-count-footer');
  if (tbody) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:1.5rem; color:var(--text-muted);">Loading incidents from security audit database...</td></tr>';
  }

  modal.classList.add('open');

  try {
    const res = await apiCall('/api/network/user-violations');
    if (!tbody) return;

    if (!res || !res.violations || res.violations.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:2rem; color:var(--accent-green);">No security policy violations recorded for this account. Keep up the good academic conduct!</td></tr>';
      if (footerEl) footerEl.innerText = '0 incidents recorded';
      return;
    }

    tbody.innerHTML = '';
    res.violations.forEach((v) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family:monospace; color:var(--text-muted); font-size:0.75rem;">#${v.id}</td>
        <td style="font-size:0.75rem; color:var(--text-muted); white-space:nowrap;">${formatDateTime(v.timestamp)}</td>
        <td>
          <code style="color:var(--accent-cyan); font-weight:600; word-break:break-all;">${escapeHtml(v.target)}</code>
        </td>
        <td>
          <span style="color:var(--accent-rose); font-weight:600; font-size:0.78rem;">${escapeHtml(v.category)}</span>
        </td>
        <td>
          <span style="font-family:monospace; font-size:0.75rem; color:var(--text-muted);">${escapeHtml(v.policy_rule || 'FW-RULE-06')}</span>
        </td>
        <td>
          <span class="badge badge-critical" style="font-size:0.68rem; padding:0.2rem 0.45rem;">DROPPED</span>
        </td>
      `;
      tbody.appendChild(tr);
    });

    if (footerEl) {
      footerEl.innerText = `Total: ${res.count} security violation incident(s) logged under ${currentUser.username}`;
    }
  } catch (err) {
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--accent-rose); padding:1rem;">Failed to load incident ledger: ${escapeHtml(err.message)}</td></tr>`;
    }
  }
}

// -------------------------------------------------------------
// 2. IT STAFF DASHBOARD LOGIC
// -------------------------------------------------------------
function switchITView(viewId) {
  document.querySelectorAll('#dashboard-itstaff .tab-btn').forEach(b => b.classList.remove('active'));
  const btn = document.getElementById(`it-tab-${viewId}`);
  if (btn) btn.classList.add('active');

  document.getElementById('it-view-ledger').style.display = viewId === 'ledger' ? 'block' : 'none';
  document.getElementById('it-view-directory').style.display = viewId === 'directory' ? 'block' : 'none';
  document.getElementById('it-view-telemetry').style.display = viewId === 'telemetry' ? 'block' : 'none';
  const opsView = document.getElementById('it-view-operations');
  if (opsView) opsView.style.display = viewId === 'operations' ? 'block' : 'none';

  if (viewId === 'ledger') loadTickets();
  else if (viewId === 'directory') loadUsers();
  else if (viewId === 'telemetry') { loadAlerts(); fetchTelemetry(); }
  else if (viewId === 'operations') { loadFirewallRules(); loadServerConfig(); }
}

async function loadITStaffData() {
  if (!currentUser) return;
  document.getElementById('itstaff-welcome-msg').innerText =
    `Operator: ${currentUser.full_name} (${currentUser.username}) • Department: ${currentUser.department}`;

  await loadTickets();
  await loadUsers();
  await loadAlerts();
  await fetchTelemetry();
  await loadFirewallRules();
  await loadServerConfig();
  startTelemetryPolling();
}

// -------------------------------------------------------------
// 4. ADMINISTRATOR DASHBOARD LOGIC
// -------------------------------------------------------------
function switchAdminView(viewId) {
  document.querySelectorAll('#dashboard-admin .tab-btn').forEach(b => b.classList.remove('active'));
  const btn = document.getElementById(`admin-tab-${viewId}`);
  if (btn) btn.classList.add('active');

  document.getElementById('admin-view-rbac').style.display = viewId === 'rbac' ? 'block' : 'none';
  document.getElementById('admin-view-monitoring').style.display = viewId === 'monitoring' ? 'block' : 'none';
  document.getElementById('admin-view-directory').style.display = viewId === 'directory' ? 'block' : 'none';
  document.getElementById('admin-view-ledger').style.display = viewId === 'ledger' ? 'block' : 'none';
  const opsView = document.getElementById('admin-view-operations');
  if (opsView) opsView.style.display = viewId === 'operations' ? 'block' : 'none';
  document.getElementById('admin-view-audit').style.display = viewId === 'audit' ? 'block' : 'none';

  if (viewId === 'rbac') loadRbacMatrix();
  else if (viewId === 'monitoring') { loadAlerts(); loadMaintenance(); fetchTelemetry(); }
  else if (viewId === 'directory') loadUsers();
  else if (viewId === 'ledger') loadTickets();
  else if (viewId === 'operations') { loadFirewallRules(); loadServerConfig(); loadForbiddenUrls(); }
  else if (viewId === 'audit') loadAuditLogs();
}

async function loadAdminData() {
  if (!currentUser) return;
  const cleanAdminName = (currentUser.full_name || '').replace(/\s*\(SysAdmin\)/gi, '').trim();
  document.getElementById('admin-welcome-msg').innerText =
    `Logged in as ${cleanAdminName}`;

  await loadRbacMatrix();
  await loadTickets();
  await loadUsers();
  await loadAlerts();
  await loadMaintenance();
  await loadFirewallRules();
  await loadServerConfig();
  await loadForbiddenUrls();
  await loadAuditLogs();
  startTelemetryPolling();
}

// -------------------------------------------------------------
// Common DFD Process Handlers
// -------------------------------------------------------------

// Problem Reporting (Process 3.0)
async function handleProblemReport(e, role = 'student') {
  e.preventDefault();
  const prefix = 'student-prob';
  const body = {
    title: document.getElementById(`${prefix}-title`).value.trim(),
    category: document.getElementById(`${prefix}-category`).value,
    priority: document.getElementById(`${prefix}-urgency`).value,
    description: document.getElementById(`${prefix}-desc`).value.trim()
  };

  try {
    const res = await apiCall('/api/tickets/create', 'POST', body);
    showToast(`Trouble ticket ${res.ticket_code} submitted to ledger!`, 'success');
    const form = document.getElementById(`${role}-report-form`);
    if (form) form.reset();
    loadStudentData();
  } catch (err) {}
}

// Password Updates (Process 1.0)
async function handlePasswordUpdate(e, role = 'student') {
  e.preventDefault();
  const prefix = 'student-pw';
  const old_password = document.getElementById(`${prefix}-old`).value;
  const new_password = document.getElementById(`${prefix}-new`).value;

  try {
    const res = await apiCall('/api/auth/password-update', 'POST', { old_password, new_password });
    showToast(res.message, 'success');
    document.getElementById(`${prefix}-old`).value = '';
    document.getElementById(`${prefix}-new`).value = '';
  } catch (err) {}
}

// Load Tickets (Process 3.0)
async function loadTickets() {
  try {
    const res = await apiCall('/api/tickets');
    const isIT = currentUser && currentUser.role === 'IT Staff';
    const isAdmin = currentUser && currentUser.role === 'Administrator';

    if (isIT) {
      const tbody = document.querySelector('#itstaff-tickets-table tbody');
      if (tbody) renderPrioritizedQueue(tbody, res.tickets);
      
      const countEl = document.getElementById('it-stat-queue-count');
      if (countEl) {
        const pending = res.tickets.filter(t => t.priority === 'Critical' || t.priority === 'High').length;
        countEl.innerText = pending;
      }
    } else if (isAdmin) {
      const tbody = document.querySelector('#admin-tickets-table tbody');
      if (tbody) renderPrioritizedQueue(tbody, res.tickets);
    }
  } catch (err) {}
}

function renderPrioritizedQueue(tbody, tickets) {
  tbody.innerHTML = '';
  if (tickets.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; color:var(--text-muted); padding:1.5rem;">Ticket queue is empty. All incidents resolved!</td></tr>`;
    return;
  }

  tickets.forEach(t => {
    const tr = document.createElement('tr');
    const priBadge = getPriorityBadge(t.priority);
    const isResolved = (t.status === 'Resolved' || t.status === 'Closed');
    tr.innerHTML = `
      <td><span class="badge ${priBadge}">${t.priority}</span></td>
      <td style="font-family:monospace; font-weight:700; color:var(--accent-cyan);">${t.ticket_code}</td>
      <td>
        <div style="font-weight:600;">${escapeHtml(t.title)}</div>
        <div style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(t.description)}</div>
      </td>
      <td>${t.category}</td>
      <td>${escapeHtml(t.submitted_by_name)}</td>
      <td><span class="badge" style="background:#243452;">${t.status}</span></td>
      <td><strong>${t.assigned_to}</strong></td>
      <td style="font-size:0.78rem; max-width:200px;">${t.resolution_notes ? escapeHtml(t.resolution_notes) : '<em style="color:var(--text-muted);">None</em>'}</td>
      <td>
        ${isResolved 
          ? `<button class="btn btn-primary btn-sm btn-ticket-action" onclick='openTriageModal(${JSON.stringify(t)})' style="width:90px; min-height:42px; display:inline-flex; align-items:center; justify-content:center; text-align:center; line-height:1.25;" title="Resolved tickets cannot be edited">View</button>`
          : `<button class="btn btn-primary btn-sm btn-ticket-action" onclick='openTriageModal(${JSON.stringify(t)})' style="width:90px; min-height:42px; display:inline-flex; align-items:center; justify-content:center; text-align:center; line-height:1.25;">Triage /<br>Resolve</button>`
        }
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function openTriageModal(ticket) {
  const isResolved = (ticket.status === 'Resolved' || ticket.status === 'Closed');

  document.getElementById('triage-ticket-id').value = ticket.id;
  document.getElementById('triage-ticket-code').innerText = `${ticket.ticket_code} [${ticket.category}]`;
  document.getElementById('triage-ticket-title').innerText = ticket.title;
  document.getElementById('triage-ticket-desc').innerText = ticket.description;
  document.getElementById('triage-status').value = ticket.status;
  document.getElementById('triage-priority').value = ticket.priority;
  document.getElementById('triage-assignee').value = (ticket.assigned_to !== 'Unassigned') ? ticket.assigned_to : (currentUser ? currentUser.username : '');
  document.getElementById('triage-notes').value = ticket.resolution_notes || '';

  // Enforce read-only state when ticket is resolved
  document.getElementById('triage-status').disabled = isResolved;
  document.getElementById('triage-priority').disabled = isResolved;
  document.getElementById('triage-assignee').disabled = isResolved;
  document.getElementById('triage-notes').disabled = isResolved;

  const lockedBanner = document.getElementById('triage-locked-banner');
  if (lockedBanner) lockedBanner.style.display = isResolved ? 'block' : 'none';

  const submitBtn = document.getElementById('triage-submit-btn');
  if (submitBtn) submitBtn.style.display = isResolved ? 'none' : 'inline-block';

  document.getElementById('modal-triage').classList.add('open');
}

async function handleTicketTriageSubmit(e) {
  e.preventDefault();
  const ticketId = document.getElementById('triage-ticket-id').value;
  const body = {
    ticket_id: parseInt(ticketId),
    status: document.getElementById('triage-status').value,
    priority: document.getElementById('triage-priority').value,
    assigned_to: document.getElementById('triage-assignee').value,
    resolution_notes: document.getElementById('triage-notes').value
  };

  try {
    const res = await apiCall('/api/tickets/triage', 'POST', body);
    showToast(res.message, 'success');
    closeModal('modal-triage');
    loadTickets();
  } catch (err) {}
}

// Load Users & Directory (Process 2.0)
async function loadUsers() {
  try {
    const isIT = currentUser && currentUser.role === 'IT Staff';
    const status = isIT
      ? (document.getElementById('it-user-filter-status')?.value || 'All')
      : (document.getElementById('admin-user-filter-status')?.value || 'All');
    const role = isIT
      ? (document.getElementById('it-user-filter-role')?.value || 'All')
      : (document.getElementById('admin-user-filter-role')?.value || 'All');
    const search = isIT
      ? (document.getElementById('it-user-filter-search')?.value || '')
      : (document.getElementById('admin-user-filter-search')?.value || '');

    const query = new URLSearchParams({ status, role, search }).toString();
    const res = await apiCall(`/api/directory/users?${query}`);

    // Update pending approvals banner
    const pendingUsers = (res.users || []).filter(u => u.status === 'Pending Approval');
    const itPendingBar = document.getElementById('it-pending-approvals-bar');
    const adminPendingBar = document.getElementById('admin-pending-approvals-bar');
    if (itPendingBar) {
      itPendingBar.style.display = pendingUsers.length > 0 ? 'flex' : 'none';
      const txt = itPendingBar.querySelector('.pending-count-text');
      if (txt) txt.innerText = `${pendingUsers.length} student registration(s) awaiting approval`;
    }
    if (adminPendingBar) {
      adminPendingBar.style.display = pendingUsers.length > 0 ? 'flex' : 'none';
      const txt = adminPendingBar.querySelector('.pending-count-text');
      if (txt) txt.innerText = `${pendingUsers.length} student registration(s) awaiting approval`;
    }

    if (isIT) {
      const tbody = document.querySelector('#itstaff-users-table tbody');
      if (tbody) renderUsersTable(tbody, res.users, false);
      const countEl = document.getElementById('it-stat-users-count');
      if (countEl) countEl.innerText = res.users.length;
    } else {
      const tbody = document.querySelector('#admin-users-table tbody');
      if (tbody) renderUsersTable(tbody, res.users, true);
    }
  } catch (err) {}
}

function renderUsersTable(tbody, users, canDelete) {
  tbody.innerHTML = '';
  if (users.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:1.5rem;">No user accounts found.</td></tr>`;
    return;
  }

  // Sort so Pending Approval registrations appear at the top
  const sortedUsers = [...users].sort((a, b) => {
    if (a.status === 'Pending Approval' && b.status !== 'Pending Approval') return -1;
    if (b.status === 'Pending Approval' && a.status !== 'Pending Approval') return 1;
    return 0;
  });

  sortedUsers.forEach(u => {
    const tr = document.createElement('tr');
    const isPending = (u.status === 'Pending Approval');
    if (isPending) {
      tr.style.background = 'rgba(245, 158, 11, 0.08)';
    }

    const statusBadge = u.status === 'Active' ? 'badge-active' :
                        u.status === 'Aging' ? 'badge-aging' : 'badge-suspended';
    const roleClean = u.role.replace(/\s+/g, '-');
    const cleanUserFullName = (u.full_name || '').replace(/\s*\(SysAdmin\)/gi, '').trim();

    tr.innerHTML = `
      <td>#${u.id}</td>
      <td>
        <div style="font-weight:600;">${escapeHtml(cleanUserFullName)}</div>
        <div style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(u.username)} • ${escapeHtml(u.email)}</div>
      </td>
      <td><span class="role-badge ${roleClean}">${u.role}</span></td>
      <td>${escapeHtml(u.department || 'General')}</td>
      <td>
        ${isPending
          ? `<span class="badge" style="background:rgba(245, 158, 11, 0.2); color:#fbbf24; border:1px solid #f59e0b; font-weight:600;">Pending Approval</span>`
          : `<span class="badge ${statusBadge}">${u.status}</span>`
        }
      </td>
      <td style="font-size:0.75rem; color:var(--text-muted);">${formatDateTime(u.last_login)}</td>
      <td>
        ${isPending ? `
          <div style="display:flex; gap:0.35rem; align-items:center;">
            <button class="btn btn-primary btn-sm" onclick="approveStudentRegistration(${u.id}, '${escapeHtml(u.username)}')" style="background:#10b981; border-color:#10b981; padding:0.25rem 0.55rem; font-size:0.75rem; font-weight:600;" title="Approve Student Account">✓ Approve</button>
            <button class="btn btn-danger btn-sm" onclick="rejectStudentRegistration(${u.id}, '${escapeHtml(u.username)}')" style="padding:0.25rem 0.55rem; font-size:0.75rem;" title="Reject Registration">✕ Reject</button>
          </div>
        ` : `
          <div style="display:flex; gap:0.35rem; align-items:center;">
            <select style="width:115px; padding:0.25rem 0.4rem; font-size:0.75rem;" onchange="updateUserLifecycle(${u.id}, this.value)">
              <option value="Active" ${u.status === 'Active' ? 'selected' : ''}>Active</option>
              <option value="Aging" ${u.status === 'Aging' ? 'selected' : ''}>Aging</option>
              <option value="Suspended" ${u.status === 'Suspended' ? 'selected' : ''}>Suspended</option>
              <option value="Pending Approval" ${u.status === 'Pending Approval' ? 'selected' : ''}>Pending</option>
            </select>
            ${canDelete ? `<button class="btn btn-danger btn-sm" onclick="deleteUserAccount(${u.id}, '${u.username}')" title="Delete Account">🗑️</button>` : ''}
          </div>
        `}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function approveStudentRegistration(userId, username) {
  if (!confirm(`Confirm approval for student '${username}'? This will activate their account and permit them to sign in.`)) return;
  try {
    const res = await apiCall('/api/directory/approve-student', 'POST', { user_id: userId });
    showToast(res.message, 'success');
    loadUsers();
    loadAlerts();
  } catch (err) {}
}

async function rejectStudentRegistration(userId, username) {
  if (!confirm(`Are you sure you want to reject the registration for student '${username}'? The registration request will be removed.`)) return;
  try {
    const res = await apiCall('/api/directory/reject-student', 'POST', { user_id: userId });
    showToast(res.message, 'info');
    loadUsers();
    loadAlerts();
  } catch (err) {}
}

async function updateUserLifecycle(userId, newStatus) {
  try {
    const res = await apiCall('/api/directory/lifecycle-status', 'POST', {
      user_id: userId,
      status: newStatus
    });
    showToast(res.message, 'success');
    loadUsers();
    loadAlerts();
  } catch (err) {}
}

async function deleteUserAccount(userId, username) {
  if (!confirm(`Are you sure you want to permanently delete account '${username}'?`)) return;
  try {
    const res = await apiCall('/api/directory/delete-user', 'POST', { user_id: userId });
    showToast(res.message, 'success');
    loadUsers();
  } catch (err) {}
}

function openProvisionModal() {
  document.getElementById('modal-provision').classList.add('open');
}

async function handleAccountProvision(e) {
  e.preventDefault();
  const body = {
    username: document.getElementById('prov-username').value.trim(),
    full_name: document.getElementById('prov-fullname').value.trim(),
    email: document.getElementById('prov-email').value.trim(),
    department: document.getElementById('prov-dept').value.trim(),
    role: document.getElementById('prov-role').value,
    password: document.getElementById('prov-password').value
  };

  try {
    const res = await apiCall('/api/directory/provision', 'POST', body);
    showToast(res.message, 'success');
    closeModal('modal-provision');
    document.getElementById('provision-form').reset();
    loadUsers();
  } catch (err) {}
}

// -------------------------------------------------------------
// Security & Telemetry (Process 4.0)
// -------------------------------------------------------------
function startTelemetryPolling() {
  if (telemetryInterval) clearInterval(telemetryInterval);
  if (!currentUser || (currentUser.role !== 'IT Staff' && currentUser.role !== 'Administrator')) {
    return;
  }
  fetchTelemetry();
  telemetryInterval = setInterval(fetchTelemetry, 4000);
}

async function fetchTelemetry() {
  if (!currentUser || (currentUser.role !== 'IT Staff' && currentUser.role !== 'Administrator')) {
    if (telemetryInterval) {
      clearInterval(telemetryInterval);
      telemetryInterval = null;
    }
    return;
  }
  try {
    const res = await apiCall('/api/monitoring/telemetry', 'GET', null, false);
    const tel = res.telemetry;

    // IT Staff dashboard telemetry updates
    const itCpu = document.getElementById('it-stat-cpu');
    if (itCpu) itCpu.innerText = `${tel.cpu_percent}%`;
    const itDisk = document.getElementById('it-stat-disk');
    if (itDisk) itDisk.innerText = `${tel.disk_percent}%`;
    const itLiveCpu = document.getElementById('it-live-cpu-val');
    if (itLiveCpu) {
      itLiveCpu.innerText = `${tel.cpu_percent}%`;
      document.getElementById('it-live-cpu-bar').style.width = `${tel.cpu_percent}%`;
    }
    const itLiveRam = document.getElementById('it-live-ram-val');
    if (itLiveRam) {
      itLiveRam.innerText = `${tel.ram_percent}%`;
      document.getElementById('it-live-ram-bar').style.width = `${tel.ram_percent}%`;
    }
    const itLiveDisk = document.getElementById('it-live-disk-val');
    if (itLiveDisk) {
      itLiveDisk.innerText = `${tel.disk_percent}%`;
      document.getElementById('it-live-disk-bar').style.width = `${tel.disk_percent}%`;
    }

    // Admin dashboard telemetry updates
    const admCpu = document.getElementById('admin-tel-cpu');
    if (admCpu) {
      admCpu.innerText = `${tel.cpu_percent}%`;
      document.getElementById('admin-tel-cpu-bar').style.width = `${tel.cpu_percent}%`;
    }
    const admRam = document.getElementById('admin-tel-ram');
    if (admRam) {
      admRam.innerText = `${tel.ram_percent}%`;
      document.getElementById('admin-tel-ram-bar').style.width = `${tel.ram_percent}%`;
    }
    const admDisk = document.getElementById('admin-tel-disk');
    if (admDisk) {
      admDisk.innerText = `${tel.disk_percent}%`;
      document.getElementById('admin-tel-disk-bar').style.width = `${tel.disk_percent}%`;
    }
    const admConns = document.getElementById('admin-tel-conns');
    if (admConns) {
      admConns.innerText = `${tel.active_connections} active`;
      document.getElementById('admin-tel-status').innerText = `Status: ${tel.system_status}`;
    }

    // Refresh client-side telemetry workstations
    await loadStudentWorkstations();
  } catch (err) {}
}

let cachedWorkstations = [];
let currentWorkstationPage = 0;
const WORKSTATIONS_PER_PAGE = 10;

async function loadStudentWorkstations() {
  try {
    const res = await apiCall('/api/telemetry/student-workstations');
    if (!res || !res.workstations) return;
    cachedWorkstations = res.workstations || [];

    const totalPages = Math.ceil(cachedWorkstations.length / WORKSTATIONS_PER_PAGE) || 1;
    if (currentWorkstationPage >= totalPages) currentWorkstationPage = 0;

    renderWorkstationsView();
    renderStudentWorkstationWidget(cachedWorkstations);
  } catch (err) {
    console.error('Failed to load workstation telemetry:', err);
  }
}

function renderWorkstationsView() {
  renderWorkstationsTable('it-workstations-body', 'agent-fleet-count', 'it-workstations-pagination', cachedWorkstations);
  renderWorkstationsTable('admin-workstations-body', 'admin-fleet-count', 'admin-workstations-pagination', cachedWorkstations);
}

function renderWorkstationsTable(tbodyId, badgeId, paginationId, workstations) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;

  const countBadge = document.getElementById(badgeId);
  const onlineCount = workstations.filter(w => w.status === 'ONLINE').length;
  if (countBadge) {
    countBadge.innerText = `${onlineCount} Online / ${workstations.length} Total`;
    countBadge.className = onlineCount > 0 ? 'badge badge-active' : 'badge badge-low';
  }

  const pag = document.getElementById(paginationId);

  if (workstations.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:1.25rem;">No client-side agents registered yet. Run <code>run_agent.bat</code> on student PCs.</td></tr>`;
    if (pag) pag.innerHTML = '';
    return;
  }

  const totalPages = Math.ceil(workstations.length / WORKSTATIONS_PER_PAGE) || 1;
  if (currentWorkstationPage >= totalPages) currentWorkstationPage = totalPages - 1;
  if (currentWorkstationPage < 0) currentWorkstationPage = 0;

  const startIdx = currentWorkstationPage * WORKSTATIONS_PER_PAGE;
  const pageItems = workstations.slice(startIdx, startIdx + WORKSTATIONS_PER_PAGE);

  tbody.innerHTML = '';
  pageItems.forEach(ws => {
    const tr = document.createElement('tr');
    const isOnline = ws.status === 'ONLINE';
    const cpuColor = ws.cpu_load > 85 ? 'var(--accent-rose)' : ws.cpu_load > 60 ? 'var(--accent-amber)' : 'var(--accent-cyan)';
    const ramColor = ws.ram_usage_pct > 85 ? 'var(--accent-rose)' : ws.ram_usage_pct > 60 ? 'var(--accent-amber)' : 'var(--accent-purple)';

    tr.innerHTML = `
      <td>
        <strong style="color:var(--accent-cyan); font-family:monospace;">${escapeHtml(ws.hostname)}</strong>
      </td>
      <td><strong>${escapeHtml(ws.student_username || 'Student')}</strong></td>
      <td style="font-size:0.75rem;">${escapeHtml(ws.os_platform || 'Windows')}</td>
      <td>
        <div style="font-size:0.8rem; font-weight:700; color:${cpuColor};">${ws.cpu_load.toFixed(1)}%</div>
        <div class="progress-bar-bg" style="height:4px;"><div class="progress-bar-fill" style="width:${Math.min(100, ws.cpu_load)}%; background:${cpuColor};"></div></div>
      </td>
      <td>
        <div style="font-size:0.8rem;">${ws.ram_used_mb.toFixed(0)} / ${ws.ram_total_mb.toFixed(0)} MB <span style="color:${ramColor}; font-weight:700;">(${ws.ram_usage_pct.toFixed(1)}%)</span></div>
        <div class="progress-bar-bg" style="height:4px;"><div class="progress-bar-fill" style="width:${Math.min(100, ws.ram_usage_pct)}%; background:${ramColor};"></div></div>
      </td>
      <td>
        <div style="font-size:0.8rem;">${ws.disk_used_gb.toFixed(1)} / ${ws.disk_total_gb.toFixed(1)} GB <span style="font-weight:700; color:var(--accent-amber);">(${ws.disk_usage_pct.toFixed(1)}%)</span></div>
        <div class="progress-bar-bg" style="height:4px;"><div class="progress-bar-fill" style="width:${Math.min(100, ws.disk_usage_pct)}%; background:var(--accent-amber);"></div></div>
      </td>
      <td>
        ${isOnline 
          ? `<span class="badge badge-active">ONLINE</span>` 
          : `<span class="badge" style="background:#243452; color:#94a3b8;">OFFLINE</span>`}
      </td>
      <td style="font-size:0.75rem; color:var(--text-muted);">${ws.seconds_ago !== undefined ? `${ws.seconds_ago}s ago` : 'Recent'}</td>
    `;
    tbody.appendChild(tr);
  });

  if (pag) {
    pag.innerHTML = '';
    pag.style.display = 'flex';
    pag.style.justifyContent = 'space-between';
    pag.style.alignItems = 'center';
    pag.style.marginTop = '0.75rem';
    pag.style.paddingTop = '0.6rem';
    pag.style.borderTop = '1px solid rgba(255,255,255,0.08)';
    pag.style.fontSize = '0.78rem';
    pag.style.color = 'var(--text-muted)';

    const countInfo = document.createElement('span');
    countInfo.innerHTML = `Showing <strong>${startIdx + 1}–${Math.min(startIdx + WORKSTATIONS_PER_PAGE, workstations.length)}</strong> of <strong>${workstations.length}</strong> workstations (Page ${currentWorkstationPage + 1}/${totalPages})`;

    const btnGroup = document.createElement('div');
    btnGroup.style.display = 'flex';
    btnGroup.style.gap = '0.4rem';

    const prevBtn = document.createElement('button');
    prevBtn.className = 'btn btn-secondary btn-sm';
    prevBtn.innerText = '← Previous';
    prevBtn.disabled = (currentWorkstationPage === 0);
    prevBtn.style.opacity = (currentWorkstationPage === 0) ? '0.45' : '1';
    prevBtn.style.cursor = (currentWorkstationPage === 0) ? 'default' : 'pointer';
    prevBtn.onclick = () => {
      if (currentWorkstationPage > 0) {
        currentWorkstationPage--;
        renderWorkstationsView();
      }
    };

    const nextBtn = document.createElement('button');
    nextBtn.className = 'btn btn-secondary btn-sm';
    nextBtn.innerText = 'Next →';
    nextBtn.disabled = (currentWorkstationPage >= totalPages - 1);
    nextBtn.style.opacity = (currentWorkstationPage >= totalPages - 1) ? '0.45' : '1';
    nextBtn.style.cursor = (currentWorkstationPage >= totalPages - 1) ? 'default' : 'pointer';
    nextBtn.onclick = () => {
      if (currentWorkstationPage < totalPages - 1) {
        currentWorkstationPage++;
        renderWorkstationsView();
      }
    };

    btnGroup.appendChild(prevBtn);
    btnGroup.appendChild(nextBtn);

    pag.appendChild(countInfo);
    pag.appendChild(btnGroup);
  }
}

function renderStudentWorkstationWidget(workstations) {
  const badge = document.getElementById('student-agent-status-badge');
  const metricsView = document.getElementById('student-agent-metrics-view');
  const offlineView = document.getElementById('student-agent-offline-view');
  if (!badge) return;

  const myWs = workstations.find(w => currentUser && w.student_username === currentUser.username) || workstations[0];

  if (myWs && myWs.status === 'ONLINE') {
    badge.className = 'badge badge-active';
    badge.innerText = 'Agent Active';
    if (metricsView) metricsView.style.display = 'block';
    if (offlineView) offlineView.style.display = 'none';

    document.getElementById('student-agent-hostname').innerText = myWs.hostname;
    document.getElementById('student-agent-cpu').innerText = `${myWs.cpu_load.toFixed(1)}%`;
    document.getElementById('student-agent-cpu-bar').style.width = `${Math.min(100, myWs.cpu_load)}%`;
    
    document.getElementById('student-agent-ram').innerText = `${myWs.ram_usage_pct.toFixed(1)}% (${myWs.ram_used_mb.toFixed(0)} MB)`;
    document.getElementById('student-agent-ram-bar').style.width = `${Math.min(100, myWs.ram_usage_pct)}%`;
    
    document.getElementById('student-agent-disk').innerText = `${myWs.disk_usage_pct.toFixed(1)}% (${myWs.disk_used_gb.toFixed(1)} GB)`;
    document.getElementById('student-agent-disk-bar').style.width = `${Math.min(100, myWs.disk_usage_pct)}%`;
  } else {
    badge.className = 'badge';
    badge.style.background = '#243452';
    badge.style.color = '#94a3b8';
    badge.innerText = 'Agent Inactive / Offline';
    if (metricsView) metricsView.style.display = 'none';
    if (offlineView) offlineView.style.display = 'block';
  }
}

async function runAgingScan() {
  try {
    const res = await apiCall('/api/monitoring/scan-aging', 'POST');
    showToast(res.message, 'warning');
    loadUsers();
    loadAlerts();
    loadAuditLogs();
  } catch (err) {}
}

let cachedAlerts = [];
let currentAlertPage = 0;
const ALERTS_PER_PAGE = 4;

async function loadAlerts() {
  try {
    const res = await apiCall('/api/monitoring/alerts');
    cachedAlerts = res.alerts || [];
    renderAlertsPagination();
  } catch (err) {}
}

function renderAlertsPagination() {
  const itContainer = document.getElementById('it-alerts-container');
  const adminContainer = document.getElementById('admin-alerts-container');

  [itContainer, adminContainer].forEach(container => {
    if (!container) return;
    container.innerHTML = '';
    container.style.display = 'flex';
    container.style.flexDirection = 'column';
    container.style.minHeight = '320px';
    container.style.justifyContent = 'space-between';

    if (!cachedAlerts || cachedAlerts.length === 0) {
      container.innerHTML = `<div style="color:var(--accent-green); font-size:0.85rem; padding:0.5rem 0;">No active security alerts or threat detections recorded.</div>`;
      return;
    }

    const totalPages = Math.ceil(cachedAlerts.length / ALERTS_PER_PAGE);
    if (currentAlertPage >= totalPages) currentAlertPage = Math.max(0, totalPages - 1);
    if (currentAlertPage < 0) currentAlertPage = 0;

    const startIdx = currentAlertPage * ALERTS_PER_PAGE;
    const pageItems = cachedAlerts.slice(startIdx, startIdx + ALERTS_PER_PAGE);

    const itemsWrapper = document.createElement('div');
    itemsWrapper.style.display = 'flex';
    itemsWrapper.style.flexDirection = 'column';
    itemsWrapper.style.gap = '0.5rem';
    itemsWrapper.style.minHeight = '275px';

    pageItems.forEach(a => {
      const div = document.createElement('div');
      div.className = `alert-item ${a.severity}`;
      div.innerHTML = `
        <div style="flex:1;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong style="${a.severity === 'Critical' ? 'color:var(--accent-rose);' : 'color:var(--accent-amber);'}">${escapeHtml(a.title)}</strong>
            <span style="font-size:0.7rem; color:var(--text-muted);">${a.timestamp}</span>
          </div>
          <div style="font-size:0.78rem; margin-top:2px; color:var(--text-main); line-height:1.35;">${escapeHtml(a.message)}</div>
        </div>
      `;
      itemsWrapper.appendChild(div);
    });
    container.appendChild(itemsWrapper);

    // If there are more than 4 alerts, render Next / Previous pagination controls
    if (cachedAlerts.length > ALERTS_PER_PAGE) {
      const pagEl = document.createElement('div');
      pagEl.style.display = 'flex';
      pagEl.style.justifyContent = 'space-between';
      pagEl.style.alignItems = 'center';
      pagEl.style.marginTop = 'auto';
      pagEl.style.paddingTop = '0.6rem';
      pagEl.style.borderTop = '1px solid rgba(255,255,255,0.08)';
      pagEl.style.fontSize = '0.78rem';
      pagEl.style.color = 'var(--text-muted)';

      const countInfo = document.createElement('span');
      countInfo.innerHTML = `Showing <strong>${startIdx + 1}–${Math.min(startIdx + ALERTS_PER_PAGE, cachedAlerts.length)}</strong> of <strong>${cachedAlerts.length}</strong> detections (Page ${currentAlertPage + 1}/${totalPages})`;

      const btnGroup = document.createElement('div');
      btnGroup.style.display = 'flex';
      btnGroup.style.gap = '0.4rem';

      const prevBtn = document.createElement('button');
      prevBtn.className = 'btn btn-secondary btn-sm';
      prevBtn.innerText = '← Previous';
      prevBtn.disabled = (currentAlertPage === 0);
      prevBtn.style.opacity = (currentAlertPage === 0) ? '0.45' : '1';
      prevBtn.style.cursor = (currentAlertPage === 0) ? 'default' : 'pointer';
      prevBtn.onclick = () => {
        if (currentAlertPage > 0) {
          currentAlertPage--;
          renderAlertsPagination();
        }
      };

      const nextBtn = document.createElement('button');
      nextBtn.className = 'btn btn-secondary btn-sm';
      nextBtn.innerText = 'Next →';
      nextBtn.disabled = (currentAlertPage >= totalPages - 1);
      nextBtn.style.opacity = (currentAlertPage >= totalPages - 1) ? '0.45' : '1';
      nextBtn.style.cursor = (currentAlertPage >= totalPages - 1) ? 'default' : 'pointer';
      nextBtn.onclick = () => {
        if (currentAlertPage < totalPages - 1) {
          currentAlertPage++;
          renderAlertsPagination();
        }
      };

      btnGroup.appendChild(prevBtn);
      btnGroup.appendChild(nextBtn);

      pagEl.appendChild(countInfo);
      pagEl.appendChild(btnGroup);
      container.appendChild(pagEl);
    }
  });
}

async function triggerBackup() {
  try {
    const res = await apiCall('/api/monitoring/backup', 'POST');
    showToast(`${res.message} [${res.backup_files.join(', ')}]`, 'success');
    loadMaintenance();
    loadAuditLogs();
  } catch (err) {}
}

function openPatchModal() {
  document.getElementById('modal-patch').classList.add('open');
}

async function handlePatchSubmit(e) {
  e.preventDefault();
  const body = {
    title: document.getElementById('patch-title').value.trim(),
    details: document.getElementById('patch-details').value.trim()
  };

  try {
    const res = await apiCall('/api/monitoring/patch', 'POST', body);
    showToast(res.message, 'success');
    closeModal('modal-patch');
    loadMaintenance();
    loadAuditLogs();
  } catch (err) {}
}

async function loadMaintenance() {
  try {
    const res = await apiCall('/api/monitoring/maintenance');
    const tbody = document.querySelector('#admin-maintenance-table tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    res.maintenance_tasks.forEach(m => {
      const tr = document.createElement('tr');
      const typeBadge = m.task_type === 'BACKUP' ? 'var(--accent-cyan)' : 'var(--accent-purple)';
      tr.innerHTML = `
        <td><span class="badge" style="background:${typeBadge}22; color:${typeBadge}; border:1px solid ${typeBadge};">${m.task_type}</span></td>
        <td>
          <div style="font-weight:600;">${escapeHtml(m.title)}</div>
          <div style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(m.details || '')}</div>
        </td>
        <td><span class="badge badge-active">${m.status}</span></td>
        <td>${m.created_by}</td>
        <td style="font-size:0.75rem; color:var(--text-muted);">${formatDateTime(m.executed_at || m.scheduled_at)}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {}
}

// -------------------------------------------------------------
// RBAC Matrix (Process 1.0)
// -------------------------------------------------------------
async function loadRbacMatrix() {
  try {
    const res = await apiCall('/api/rbac/roles');
    const tbody = document.querySelector('#admin-rbac-table tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    res.roles.forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${r.role_name}</strong><div style="font-size:0.72rem; color:var(--text-muted);">${escapeHtml(r.description || '')}</div></td>
        <td><input type="checkbox" id="perm-submit-${r.role_name}" ${r.can_submit_tickets ? 'checked' : ''}></td>
        <td><input type="checkbox" id="perm-viewown-${r.role_name}" ${r.can_view_own_tickets ? 'checked' : ''}></td>
        <td><input type="checkbox" id="perm-users-${r.role_name}" ${r.can_manage_users ? 'checked' : ''}></td>
        <td><input type="checkbox" id="perm-triage-${r.role_name}" ${r.can_triage_tickets ? 'checked' : ''}></td>
        <td><input type="checkbox" id="perm-telemetry-${r.role_name}" ${r.can_view_telemetry ? 'checked' : ''}></td>
        <td><input type="checkbox" id="perm-backup-${r.role_name}" ${r.can_manage_backups ? 'checked' : ''}></td>
        <td><input type="checkbox" id="perm-patch-${r.role_name}" ${r.can_manage_patches ? 'checked' : ''}></td>
        <td><input type="checkbox" id="perm-audit-${r.role_name}" ${r.can_view_audit_logs ? 'checked' : ''}></td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="saveRbacRole('${r.role_name}')">Save</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {}
}

async function saveRbacRole(roleName) {
  const body = {
    role_name: roleName,
    can_submit_tickets: document.getElementById(`perm-submit-${roleName}`).checked,
    can_view_own_tickets: document.getElementById(`perm-viewown-${roleName}`).checked,
    can_manage_users: document.getElementById(`perm-users-${roleName}`).checked,
    can_triage_tickets: document.getElementById(`perm-triage-${roleName}`).checked,
    can_view_telemetry: document.getElementById(`perm-telemetry-${roleName}`).checked,
    can_manage_backups: document.getElementById(`perm-backup-${roleName}`).checked,
    can_manage_patches: document.getElementById(`perm-patch-${roleName}`).checked,
    can_view_audit_logs: document.getElementById(`perm-audit-${roleName}`).checked
  };

  try {
    const res = await apiCall('/api/rbac/roles/update', 'POST', body);
    showToast(res.message, 'success');
    loadAuditLogs();
  } catch (err) {}
}

// -------------------------------------------------------------
// Audit Logs (Audit & Ticket Logs DB)
// -------------------------------------------------------------
async function loadAuditLogs() {
  try {
    const res = await apiCall('/api/monitoring/audit-logs?limit=40');
    const tbody = document.querySelector('#admin-audit-table tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    res.audit_logs.forEach(log => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family:monospace; color:var(--text-muted);">#${log.id}</td>
        <td><span class="badge" style="background:#0a0f1d; border:1px solid var(--accent-cyan); color:var(--accent-cyan);">${log.event_type}</span></td>
        <td><strong>${escapeHtml(log.actor_username)}</strong></td>
        <td><span class="role-badge ${log.actor_role.replace(/\s+/g, '-')}">${log.actor_role}</span></td>
        <td style="font-size:0.8rem;">${escapeHtml(log.details)}</td>
        <td style="font-family:monospace; font-size:0.75rem; color:var(--text-muted);">${log.ip_address}</td>
        <td style="font-size:0.75rem; color:var(--text-muted);">${formatDateTime(log.timestamp)}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {}
}

// -------------------------------------------------------------
// Functions for the 6 Expected Outcomes
// -------------------------------------------------------------

// Outcome 1: Automated Account Management
async function triggerBatchOnboard() {
  const cohort = prompt("Enter cohort identifier for batch account creation:", "CS2026_Lab_Cohort");
  if (!cohort) return;
  try {
    const res = await apiCall('/api/directory/batch-onboard', 'POST', { cohort: cohort, count: 5 });
    showToast(res.message, 'success');
    loadUsers();
    loadAuditLogs();
  } catch (err) {}
}

async function triggerAutoCleanup() {
  if (!confirm("Run Automated Orphan Cleanup? Stale profiles inactive for >120 days will be auto-suspended.")) return;
  try {
    const res = await apiCall('/api/directory/auto-cleanup', 'POST');
    showToast(res.message, 'warning');
    loadUsers();
    loadAlerts();
    loadAuditLogs();
  } catch (err) {}
}

// Outcome 3: Proactive Threat Prevention
async function triggerEnforceRotation() {
  try {
    const res = await apiCall('/api/security/enforce-credential-rotation', 'POST');
    showToast(res.message, 'warning');
    loadUsers();
    loadAlerts();
    loadAuditLogs();
  } catch (err) {}
}

// Outcome 4: Accelerated Incident Resolution & Permission Audits
async function togglePermissionAuditCard() {
  const card = document.getElementById('permission-change-audit-card');
  if (!card) return;
  if (card.style.display === 'none' || card.style.display === '') {
    card.style.display = 'block';
    await loadPermissionAudits();
  } else {
    card.style.display = 'none';
  }
}

async function loadPermissionAudits() {
  try {
    const res = await apiCall('/api/monitoring/permission-audit-trail');
    const tbody = document.querySelector('#permission-audit-table tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (res.permission_audits.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:1rem;">No recent permission changes found.</td></tr>`;
      return;
    }

    res.permission_audits.forEach(p => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family:monospace; color:var(--text-muted);">#${p.id}</td>
        <td><span class="badge" style="background:#0a0f1d; border:1px solid var(--accent-purple); color:#c084fc;">${p.event_type}</span></td>
        <td><strong>${escapeHtml(p.actor_username)}</strong></td>
        <td>${p.actor_role}</td>
        <td style="font-size:0.8rem; color:var(--text-main);">${escapeHtml(p.details)}</td>
        <td style="font-size:0.75rem; color:var(--text-muted);">${formatDateTime(p.timestamp)}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {}
}

// Outcome 5: High Infrastructure Reliability & Rapid Recovery
async function triggerRapidRecovery() {
  if (!confirm("Execute Rapid Recovery? This restores the primary Identity Database from the latest snapshot archive.")) return;
  try {
    const res = await apiCall('/api/monitoring/restore-backup', 'POST');
    showToast(res.message, 'success');
    loadUsers();
    loadMaintenance();
    loadAuditLogs();
  } catch (err) {}
}

// Outcome 6: Optimized IT Operations (Firewall & Server Config)
async function loadFirewallRules() {
  try {
    const res = await apiCall('/api/operations/firewall');
    ['#it-firewall-table tbody', '#admin-firewall-table tbody'].forEach(selector => {
      const tbody = document.querySelector(selector);
      if (!tbody) return;
      tbody.innerHTML = '';

      res.firewall_rules.forEach(r => {
        const tr = document.createElement('tr');
        const actionBadge = r.action === 'ALLOW' ? 'badge-active' : 'badge-critical';
        const statusBadge = r.status === 'ACTIVE' ? 'badge-active' : 'badge-suspended';
        tr.innerHTML = `
          <td><strong>${escapeHtml(r.rule_name)}</strong><div style="font-size:0.72rem; color:var(--text-muted);">${r.direction}</div></td>
          <td style="font-family:monospace; font-size:0.75rem;">${r.source_subnet} : ${r.port}</td>
          <td><span class="badge ${actionBadge}">${r.action}</span></td>
          <td><span class="badge ${statusBadge}">${r.status}</span></td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="toggleFirewallRule(${r.id})">
              ${r.status === 'ACTIVE' ? 'Disable' : 'Enable'}
            </button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    });
  } catch (err) {}
}

async function toggleFirewallRule(ruleId) {
  try {
    const res = await apiCall('/api/operations/firewall/toggle', 'POST', { rule_id: ruleId });
    showToast(res.message, 'info');
    loadFirewallRules();
    loadAuditLogs();
  } catch (err) {}
}

async function loadServerConfig() {
  try {
    const res = await apiCall('/api/operations/server-config');
    ['#it-config-table tbody', '#admin-config-table tbody'].forEach(selector => {
      const tbody = document.querySelector(selector);
      if (!tbody) return;
      tbody.innerHTML = '';

      const prefix = selector.startsWith('#it') ? 'it' : 'admin';
      res.server_configs.forEach(c => {
        const tr = document.createElement('tr');
        const inputId = `${prefix}-cfg-${c.key}`;
        tr.innerHTML = `
          <td style="font-family:monospace; font-weight:600; color:var(--accent-cyan);">${escapeHtml(c.key)}</td>
          <td><input type="text" id="${inputId}" value="${escapeHtml(c.value)}" style="padding:0.25rem 0.5rem; width:130px;" onkeydown="if(event.key==='Enter') saveServerConfig('${c.key}', '${inputId}')"></td>
          <td><span class="badge" style="background:#243452;">${c.category}</span></td>
          <td style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(c.description)}</td>
          <td>
            <button class="btn btn-primary btn-sm" onclick="saveServerConfig('${c.key}', '${inputId}')" style="min-width:60px;">Save</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    });
  } catch (err) {}
}

async function saveServerConfig(key, inputId = null) {
  let value = null;
  if (inputId) {
    const el = document.getElementById(inputId);
    if (el) value = el.value.trim();
  }
  if (value === null) {
    const itEl = document.getElementById(`it-cfg-${key}`);
    const adminEl = document.getElementById(`admin-cfg-${key}`);
    value = (adminEl ? adminEl.value : (itEl ? itEl.value : '')).trim();
  }

  try {
    const res = await apiCall('/api/operations/server-config/update', 'POST', { key, value });
    showToast(res.message, 'success');
    loadAuditLogs();
  } catch (err) {}
}

async function saveAllServerConfigs() {
  const isIT = currentUser && currentUser.role === 'IT Staff';
  const prefix = isIT ? 'it' : 'admin';
  let inputs = document.querySelectorAll(`input[id^="${prefix}-cfg-"]`);
  if (!inputs.length) {
    const itTable = document.querySelector('#it-dashboard:not([style*="display: none"]) #it-config-table');
    const adminTable = document.querySelector('#admin-dashboard:not([style*="display: none"]) #admin-config-table');
    const targetTable = itTable || adminTable || document;
    inputs = targetTable.querySelectorAll('input[id*="-cfg-"]');
  }

  if (!inputs.length) {
    showToast('No configuration parameters found to save.', 'warning');
    return;
  }

  const configs = [];
  inputs.forEach(input => {
    const key = input.id.replace(/^(it|admin)-cfg-/, '');
    const value = input.value.trim();
    if (key) configs.push({ key, value });
  });

  if (configs.length === 0) {
    showToast('No configuration parameters to save.', 'warning');
    return;
  }

  try {
    // Attempt batch update
    const res = await apiCall('/api/operations/server-config/update', 'POST', { configs }, false);
    showToast(res.message || `Successfully saved ${configs.length} server configuration parameter(s)!`, 'success');
    loadAuditLogs();
  } catch (batchErr) {
    // Fallback: row-by-row update if running server has not yet applied batch updates
    let savedCount = 0;
    let lastError = batchErr.message;
    for (const c of configs) {
      try {
        await apiCall('/api/operations/server-config/update', 'POST', { key: c.key, value: c.value }, false);
        savedCount++;
      } catch (indErr) {
        lastError = indErr.message;
      }
    }

    if (savedCount > 0) {
      showToast(`Successfully saved ${savedCount} server configuration parameter(s)!`, 'success');
      loadAuditLogs();
    } else {
      showToast(`Failed to save configurations: ${lastError}. Please restart the server via start_system.bat.`, 'error');
    }
  }
}

// -------------------------------------------------------------
// Admin Forbidden Websites Management (Add, Suspend, Delete)
// -------------------------------------------------------------
async function loadForbiddenUrls() {
  try {
    const res = await apiCall('/api/network/forbidden-urls');
    const tbody = document.getElementById('admin-forbidden-urls-body');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!res.rules || res.rules.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:1rem;">No prohibited URL rules registered.</td></tr>`;
      return;
    }

    res.rules.forEach(r => {
      const tr = document.createElement('tr');
      const isActive = r.status === 'ACTIVE';
      const statusBadge = isActive ? 'badge-critical' : 'badge-suspended';
      const statusText = isActive ? 'ACTIVE (BLOCKED)' : 'SUSPENDED (PERMITTED)';
      const toggleAction = isActive ? 'SUSPENDED' : 'ACTIVE';
      const toggleBtnText = isActive ? 'Suspend Rule' : 'Activate Rule';
      const toggleBtnClass = isActive ? 'btn-warning' : 'btn-primary';

      tr.innerHTML = `
        <td><code style="color:var(--accent-cyan); font-weight:700;">${escapeHtml(r.domain_pattern)}</code></td>
        <td>${escapeHtml(r.category)}</td>
        <td style="font-size:0.78rem; color:var(--text-muted);">${escapeHtml(r.reason || 'Restricted')}</td>
        <td><span class="badge ${statusBadge}">${statusText}</span></td>
        <td style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(r.added_by)} (${formatDateTime(r.created_at)})</td>
        <td>
          <div style="display:flex; gap:0.35rem;">
            <button class="btn ${toggleBtnClass} btn-sm" onclick="toggleForbiddenUrlStatus(${r.id}, '${toggleAction}')">
              ${toggleBtnText}
            </button>
            <button class="btn btn-danger btn-sm" onclick="deleteForbiddenUrl(${r.id}, '${escapeHtml(r.domain_pattern)}')">
              Delete
            </button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {}
}

function openAddForbiddenUrlModal() {
  document.getElementById('forbid-domain').value = '';
  document.getElementById('forbid-reason').value = '';
  document.getElementById('modal-add-forbidden-url').classList.add('open');
}

async function handleAddForbiddenUrlSubmit(e) {
  e.preventDefault();
  const domain = document.getElementById('forbid-domain').value.trim();
  const category = document.getElementById('forbid-category').value;
  const reason = document.getElementById('forbid-reason').value.trim();

  if (!domain) {
    showToast('Please enter a domain or URL pattern', 'warning');
    return;
  }

  try {
    const res = await apiCall('/api/network/forbidden-urls/create', 'POST', {
      domain_pattern: domain,
      category,
      reason
    });
    showToast(res.message, 'success');
    closeModal('modal-add-forbidden-url');
    loadForbiddenUrls();
    loadAuditLogs();
  } catch (err) {}
}

async function toggleForbiddenUrlStatus(id, newStatus) {
  try {
    const res = await apiCall('/api/network/forbidden-urls/toggle-status', 'POST', {
      id,
      status: newStatus
    });
    showToast(res.message, 'success');
    loadForbiddenUrls();
    loadAuditLogs();
  } catch (err) {}
}

async function deleteForbiddenUrl(id, domain) {
  if (!confirm(`Are you sure you want to remove '${domain}' from the prohibited web filter?`)) return;
  try {
    const res = await apiCall('/api/network/forbidden-urls/delete', 'POST', { id });
    showToast(res.message, 'success');
    loadForbiddenUrls();
    loadAuditLogs();
  } catch (err) {}
}

// Campus Web Filter & Security Inspector
function openInExternalBrowser(customUrl) {
  const input = document.getElementById('web-filter-input');
  let url = customUrl || (input ? input.value.trim() : '');
  if (!url) url = 'https://torrent-tracker.org';
  const target = `http://127.0.0.1:8000/gateway?url=${encodeURIComponent(url)}`;
  window.open(target, '_blank');
}

async function testWebFilterAccess() {
  const input = document.getElementById('web-filter-input');
  const resultDiv = document.getElementById('web-filter-result');
  if (!input || !resultDiv) return;

  const url = input.value.trim();
  if (!url) {
    showToast('Please enter a website URL or domain to test', 'warning');
    return;
  }

  try {
    const res = await apiCall('/api/network/web-filter-check', 'POST', { url });
    resultDiv.style.display = 'block';

    if (res.blocked) {
      resultDiv.innerHTML = `
        <div style="background: rgba(244, 63, 94, 0.12); border: 1px solid var(--accent-rose); border-radius: var(--radius-sm); padding: 1rem;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong style="color:var(--accent-rose); font-size:0.95rem;">403 Forbidden: Access Blocked by Campus Network Gateway</strong>
            <span class="badge badge-critical">PACKET DROPPED</span>
          </div>
          <div style="font-size:0.85rem; margin-top:0.4rem; color:var(--text-main);">${escapeHtml(res.message)}</div>
          <div style="font-size:0.75rem; color:var(--text-muted); margin-top:0.5rem; display:flex; gap:1.25rem; flex-wrap:wrap;">
            <span><strong>Target:</strong> ${escapeHtml(res.url)}</span>
            <span><strong>Violation:</strong> ${escapeHtml(res.category)}</span>
            <span><strong>Enforced Rule:</strong> ${escapeHtml(res.policy_rule)}</span>
            <span><strong>Audit Status:</strong> Logged to Security DB</span>
          </div>
        </div>
      `;

      // Automatically trigger High-Priority Security Violation Modal Dialog
      const secMsg = document.getElementById('modal-sec-message');
      const secUrl = document.getElementById('modal-sec-url');
      const secCat = document.getElementById('modal-sec-category');
      const secRule = document.getElementById('modal-sec-rule');
      const secModal = document.getElementById('modal-security-block');

      if (secMsg) secMsg.innerText = res.message;
      if (secUrl) secUrl.innerText = res.url;
      if (secCat) secCat.innerText = res.category;
      if (secRule) secRule.innerText = res.policy_rule;
      if (secModal) secModal.classList.add('open');

      showToast(`Access Denied (403): '${url}' is blocked by campus firewall!`, 'error');
      await loadStudentViolations();
    } else {
      resultDiv.innerHTML = `
        <div style="background: rgba(16, 185, 129, 0.12); border: 1px solid var(--accent-green); border-radius: var(--radius-sm); padding: 1rem;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong style="color:var(--accent-green); font-size:0.95rem;">200 OK: Destination Permitted</strong>
            <span class="badge badge-active">ALLOWED</span>
          </div>
          <div style="font-size:0.85rem; margin-top:0.4rem; color:var(--text-main);">${escapeHtml(res.message)}</div>
          <div style="font-size:0.75rem; color:var(--text-muted); margin-top:0.5rem;">
            <span><strong>Category:</strong> ${escapeHtml(res.category)}</span> • <span><strong>Rule:</strong> ${escapeHtml(res.policy_rule)}</span>
          </div>
        </div>
      `;
      showToast(`Connection permitted to '${url}'`, 'success');
    }
  } catch (err) {}
}

// -------------------------------------------------------------
// Helper Utilities
// -------------------------------------------------------------
function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove('open');
}

function getPriorityBadge(priority) {
  switch (priority) {
    case 'Critical': return 'badge-critical';
    case 'High': return 'badge-high';
    case 'Medium': return 'badge-medium';
    default: return 'badge-low';
  }
}

function formatDateTime(isoString) {
  if (!isoString) return 'Never';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch (e) {
    return isoString;
  }
}

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.innerText = text;
  return div.innerHTML;
}

// Enter-key trigger for Web Filter Inspector
document.addEventListener('DOMContentLoaded', () => {
  const filterInput = document.getElementById('web-filter-input');
  if (filterInput) {
    filterInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        testWebFilterAccess();
      }
    });
  }
});

// -------------------------------------------------------------
// ACTIVE SESSIONS & TOKEN GOVERNANCE (OUTCOME 3)
// -------------------------------------------------------------
function openActiveSessionsModal() {
  const modal = document.getElementById('modal-active-sessions');
  if (modal) {
    modal.classList.add('open');
    loadActiveSessions();
  }
}

async function loadActiveSessions() {
  const tbody = document.getElementById('active-sessions-tbody');
  const summaryEl = document.getElementById('active-sessions-stat-summary');
  if (tbody) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:1.5rem; color:var(--text-muted);">Loading active sessions from user_roles.db...</td></tr>';
  }

  try {
    const res = await apiCall('/api/auth/active-sessions');
    if (!tbody) return;

    if (!res || !res.sessions || res.sessions.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:1.5rem; color:var(--text-muted);">No active sessions found.</td></tr>';
      if (summaryEl) summaryEl.innerText = '0 total sessions recorded';
      return;
    }

    const activeCount = res.sessions.filter(s => s.is_active).length;
    if (summaryEl) {
      summaryEl.innerHTML = `<strong>${activeCount} active / unexpired</strong> session(s) (${res.sessions.length} total recorded)`;
    }

    tbody.innerHTML = '';
    res.sessions.forEach(s => {
      const tr = document.createElement('tr');
      const statusBadge = s.is_active 
        ? `<span class="badge badge-active" style="font-size:0.7rem;">Active</span>` 
        : `<span class="badge" style="background:#243452; color:#94a3b8; font-size:0.7rem;">Expired</span>`;
      
      const roleBadge = s.role === 'Administrator' ? 'badge-critical' : (s.role === 'IT Staff' ? 'badge-high' : 'badge-low');
      const isCurrent = (s.token === authToken);

      tr.innerHTML = `
        <td>
          <div style="font-weight:600; color:var(--text-main);">${escapeHtml(s.username)} ${isCurrent ? '<span style="font-size:0.7rem; color:var(--accent-cyan);">(You)</span>' : ''}</div>
          <div style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(s.full_name || '--')} • ${escapeHtml(s.department || '--')}</div>
        </td>
        <td><span class="badge ${roleBadge}">${escapeHtml(s.role)}</span></td>
        <td>
          <code style="font-family:monospace; font-size:0.72rem; color:var(--accent-cyan);">${escapeHtml(s.token_masked || s.token)}</code>
        </td>
        <td style="font-size:0.78rem; color:var(--text-muted);">${formatDateTime(s.created_at)}</td>
        <td>${statusBadge}</td>
        <td>
          ${isCurrent 
            ? '<span style="font-size:0.75rem; color:var(--text-muted);">Current Session</span>' 
            : `<button class="btn btn-danger btn-sm" onclick="revokeActiveSession('${escapeHtml(s.token)}', '${escapeHtml(s.username)}')">Revoke</button>`
          }
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:1.5rem; color:var(--accent-rose);">Failed to load sessions: ${escapeHtml(err.message)}</td></tr>`;
    }
  }
}

async function revokeActiveSession(token, username) {
  if (!confirm(`Are you sure you want to revoke the session token for '${username}'? They will be logged out immediately.`)) {
    return;
  }
  try {
    const res = await apiCall('/api/auth/revoke-session', 'POST', { token });
    showToast(res.message || `Session for ${username} revoked.`, 'success');
    loadActiveSessions();
    if (typeof loadAdminTelemetry === 'function') loadAdminTelemetry();
  } catch (err) {
    showToast(`Failed to revoke session: ${err.message}`, 'error');
  }
}
