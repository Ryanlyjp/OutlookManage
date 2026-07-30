const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));
let accounts = [];
const selected = new Set();
let currentJob = null;
let jobTimer = null;

async function api(path, options = {}) {
  const opts = { headers: {}, ...options };
  if (opts.body && !(opts.body instanceof FormData)) opts.headers['Content-Type'] = 'application/json';
  const response = await fetch(path, opts);
  if (response.status === 401) {
    window.location.href = '/login';
    throw new Error('登录已失效');
  }
  const contentType = response.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await response.json() : await response.text();
  if (!response.ok) throw new Error(data.detail || data.reason || `HTTP ${response.status}`);
  return data;
}

function toast(message, delay = 3000) {
  const element = $('#toast');
  element.textContent = message;
  element.classList.remove('hidden');
  clearTimeout(element.timer);
  element.timer = setTimeout(() => element.classList.add('hidden'), delay);
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

function statusLabel(status) {
  return ({ normal: '正常', banned: 'ABUSE', token_invalid: 'Token 无效', other_error: '其他错误' })[status] || '未测试';
}

function statusChip(status) {
  return `<span class="chip ${escapeHtml(status || 'untested')}">${statusLabel(status)}</span>`;
}

function formatTime(value) {
  if (!value) return '-';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', { hour12: false });
}

function showPage(id) {
  $$('.page').forEach((page) => page.classList.toggle('active', page.id === id));
  $$('[data-page]').forEach((link) => link.classList.toggle('active', link.dataset.page === id));
  if (id === 'logs') loadLogs().catch((error) => toast(error.message));
}

function route() {
  const id = window.location.hash.slice(1) || 'overview';
  showPage(document.getElementById(id) ? id : 'overview');
}

async function refreshStatus() {
  const data = await api('/api/status');
  const summary = data.summary;
  $('#stat-total').textContent = summary.total;
  $('#stat-normal').textContent = summary.normal;
  $('#stat-banned').textContent = summary.banned;
  $('#stat-token-invalid').textContent = summary.token_invalid;
  $('#stat-other-error').textContent = summary.other_error;
  $('#stat-untested').textContent = summary.untested;
}

async function refreshAccounts() {
  const data = await api('/api/accounts');
  accounts = data.accounts;
  const existing = new Set(accounts.map((account) => account.id));
  Array.from(selected).forEach((id) => { if (!existing.has(id)) selected.delete(id); });
  renderAccounts();
}

async function refreshAll() {
  await Promise.all([refreshStatus(), refreshAccounts()]);
}

function filteredAccounts() {
  const query = $('#search').value.trim().toLowerCase();
  const filter = $('#status-filter').value;
  return accounts.filter((account) => {
    const matchesQuery = !query || `${account.email} ${account.client_id}`.toLowerCase().includes(query);
    const matchesStatus = filter === 'all' || (filter === 'untested' ? !account.health_status : account.health_status === filter);
    return matchesQuery && matchesStatus;
  });
}

function renderAccounts() {
  const rows = filteredAccounts();
  $('#empty-state').classList.toggle('hidden', rows.length > 0);
  $('#account-body').innerHTML = rows.map((account) => {
    const reason = account.ban_reason || account.error_detail || (account.health_status === 'normal' ? 'Graph 邮件读取正常' : '-');
    return `<tr class="${selected.has(account.id) ? 'selected-row' : ''}">
      <td class="select-cell"><input class="row-select" type="checkbox" data-id="${account.id}" ${selected.has(account.id) ? 'checked' : ''} aria-label="选择 ${escapeHtml(account.email)}"></td>
      <td><div class="account-main"><strong>${escapeHtml(account.email)}</strong><small>${escapeHtml(account.client_id)}</small></div></td>
      <td>${statusChip(account.health_status)}</td>
      <td class="nowrap">${escapeHtml(formatTime(account.last_protocol_test_at))}</td>
      <td><div class="reason" title="${escapeHtml(reason)}">${escapeHtml(reason)}</div></td>
      <td><div class="row-actions">
        <button class="btn sm primary" data-action="test" data-id="${account.id}">测试</button>
        <button class="btn sm ghost" data-action="edit" data-id="${account.id}">编辑</button>
        <button class="btn sm danger" data-action="delete" data-id="${account.id}">删除</button>
      </div></td>
    </tr>`;
  }).join('');
  updateSelectionControls(rows);
}

function updateSelectionControls(visibleRows = filteredAccounts()) {
  const visibleIds = visibleRows.map((account) => account.id);
  const selectedVisible = visibleIds.filter((id) => selected.has(id)).length;
  const selectAll = $('#select-all');
  selectAll.checked = visibleIds.length > 0 && selectedVisible === visibleIds.length;
  selectAll.indeterminate = selectedVisible > 0 && selectedVisible < visibleIds.length;
  $('#selected-count').textContent = selected.size;
  $('#test-selected-btn').disabled = selected.size === 0;
  $('#clear-selection-btn').disabled = selected.size === 0;
}

async function previewImport() {
  const data = await api('/api/accounts/import-preview', { method: 'POST', body: JSON.stringify({ text: $('#import-text').value }) });
  $('#import-result').textContent = `有效 ${data.valid} 行，错误 ${data.errors.length} 行${data.errors.length ? `\n${JSON.stringify(data.errors, null, 2)}` : ''}`;
}

async function importAccounts() {
  const data = await api('/api/accounts/import', { method: 'POST', body: JSON.stringify({ text: $('#import-text').value }) });
  $('#import-result').textContent = `新增 ${data.inserted}，更新 ${data.updated}，错误 ${data.errors.length}`;
  toast('导入完成');
  await refreshAll();
}

async function startUntested() {
  const concurrency = parseInt($('#run-concurrency').value, 10) || 5;
  const data = await api('/api/accounts/batch/test-untested', { method: 'POST', body: JSON.stringify({ concurrency }) });
  watchJob(data.job_id);
}

async function startSelected() {
  if (!selected.size) throw new Error('请先选择账号');
  const concurrency = parseInt($('#run-concurrency').value, 10) || parseInt($('#cfg-concurrency').value, 10) || 5;
  const data = await api('/api/accounts/test-selected', { method: 'POST', body: JSON.stringify({ ids: Array.from(selected), concurrency }) });
  watchJob(data.job_id);
}

function watchJob(jobId) {
  currentJob = jobId;
  $('#job-panel').classList.remove('hidden');
  clearInterval(jobTimer);
  pollJob();
  jobTimer = setInterval(pollJob, 1500);
}

async function pollJob() {
  if (!currentJob) return;
  try {
    const data = await api(`/api/jobs/${currentJob}`);
    const job = data.job;
    const percent = job.total ? Math.round(job.processed / job.total * 100) : 0;
    $('#job-progress').style.width = `${percent}%`;
    $('#job-state').textContent = job.state === 'running' ? '运行中' : job.state;
    $('#job-detail').textContent = `处理 ${job.processed}/${job.total} · 正常 ${job.succeeded} · 异常 ${job.failed} · 跳过 ${job.skipped}`;
    if (['done', 'failed', 'cancelled'].includes(job.state)) {
      clearInterval(jobTimer);
      currentJob = null;
      selected.clear();
      await refreshAll();
      toast('测活任务已完成');
    }
  } catch (error) {
    clearInterval(jobTimer);
    toast(error.message);
  }
}

async function testOne(id) {
  toast('正在测试账号…');
  const data = await api(`/api/accounts/${id}/test`, { method: 'POST' });
  toast(`${data.email}：${statusLabel(data.health_status)}`);
  await refreshAll();
}

async function openEdit(id) {
  const data = await api(`/api/accounts/${id}`);
  const account = data.account;
  $('#edit-id').value = account.id;
  $('#edit-email').value = account.email;
  $('#edit-client-id').value = account.client_id;
  $('#edit-refresh-token').value = account.refresh_token;
  $('#edit-remark').value = account.remark || '';
  $('#modal').classList.remove('hidden');
}

function closeEdit() { $('#modal').classList.add('hidden'); }

async function saveAccount() {
  const id = $('#edit-id').value;
  await api(`/api/accounts/${id}`, { method: 'PUT', body: JSON.stringify({
    email: $('#edit-email').value,
    client_id: $('#edit-client-id').value,
    refresh_token: $('#edit-refresh-token').value,
    remark: $('#edit-remark').value,
  }) });
  closeEdit();
  toast('账号已保存，状态已重置为未测试');
  await refreshAll();
}

async function deleteAccount(id) {
  const account = accounts.find((item) => item.id === id);
  if (!window.confirm(`确认删除 ${account?.email || id}？`)) return;
  await api(`/api/accounts/${id}`, { method: 'DELETE' });
  toast('账号已删除');
  await refreshAll();
}

async function loadSettings() {
  const data = await api('/api/config');
  $('#cfg-proxy').value = data.config.proxy_url || '';
  $('#cfg-concurrency').value = data.config.default_concurrency || 5;
  $('#run-concurrency').value = data.config.default_concurrency || 5;
}

async function saveSettings() {
  const concurrency = parseInt($('#cfg-concurrency').value, 10) || 5;
  await api('/api/config', { method: 'PUT', body: JSON.stringify({ proxy_url: $('#cfg-proxy').value, default_concurrency: concurrency }) });
  $('#run-concurrency').value = concurrency;
  toast('设置已保存');
}

async function changePassword() {
  const next = $('#new-password').value;
  if (next.length < 12) throw new Error('新密码至少需要 12 位');
  if (next !== $('#confirm-password').value) throw new Error('两次输入的新密码不一致');
  await api('/api/auth/password', { method: 'PUT', body: JSON.stringify({ current_password: $('#current-password').value, new_password: next }) });
  window.location.href = '/login';
}

async function loadLogs() { $('#log-output').textContent = await api('/api/logs'); }

window.addEventListener('hashchange', route);
$('#refresh-btn').onclick = () => refreshAll().catch((error) => toast(error.message));
$('#preview-btn').onclick = () => previewImport().catch((error) => toast(error.message));
$('#import-btn').onclick = () => importAccounts().catch((error) => toast(error.message));
$('#clear-import-btn').onclick = () => { $('#import-text').value = ''; $('#import-result').textContent = ''; };
$('#test-untested-btn').onclick = () => startUntested().catch((error) => toast(error.message));
$('#test-selected-btn').onclick = () => startSelected().catch((error) => toast(error.message));
$('#clear-selection-btn').onclick = () => { selected.clear(); renderAccounts(); };
$('#select-all').onchange = (event) => {
  filteredAccounts().forEach((account) => event.target.checked ? selected.add(account.id) : selected.delete(account.id));
  renderAccounts();
};
$('#search').oninput = renderAccounts;
$('#status-filter').onchange = renderAccounts;
$('#account-body').onclick = (event) => {
  const checkbox = event.target.closest('.row-select');
  if (checkbox) {
    const id = Number(checkbox.dataset.id);
    checkbox.checked ? selected.add(id) : selected.delete(id);
    renderAccounts();
    return;
  }
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const id = Number(button.dataset.id);
  if (button.dataset.action === 'test') testOne(id).catch((error) => toast(error.message, 5000));
  if (button.dataset.action === 'edit') openEdit(id).catch((error) => toast(error.message));
  if (button.dataset.action === 'delete') deleteAccount(id).catch((error) => toast(error.message));
};
$('#close-modal-btn').onclick = closeEdit;
$('#cancel-edit-btn').onclick = closeEdit;
$('#save-account-btn').onclick = () => saveAccount().catch((error) => toast(error.message));
$('#save-settings-btn').onclick = () => saveSettings().catch((error) => toast(error.message));
$('#change-password-btn').onclick = () => changePassword().catch((error) => toast(error.message));
$('#clear-logs-btn').onclick = () => api('/api/logs/clear', { method: 'POST' }).then(loadLogs).catch((error) => toast(error.message));
$('#cancel-job-btn').onclick = () => currentJob && api(`/api/jobs/${currentJob}/cancel`, { method: 'POST' }).catch((error) => toast(error.message));
$('#logout-btn').onclick = () => api('/api/auth/logout', { method: 'POST' }).finally(() => { window.location.href = '/login'; });
$$('.stat').forEach((card) => { card.onclick = () => { $('#status-filter').value = card.dataset.filter; window.location.hash = 'accounts'; renderAccounts(); }; });

route();
Promise.all([refreshAll(), loadSettings()]).catch((error) => toast(error.message, 5000));
