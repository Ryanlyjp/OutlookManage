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
  if (id === 'settings') loadShares().catch((error) => toast(error.message));
  if (id === 'scheduled') loadScheduledTasks().catch((error) => toast(error.message));
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
  refreshScheduleAccountOptions();
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
  $('#delete-selected-btn').disabled = selected.size === 0;
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

async function deleteSelected() {
  if (!selected.size) throw new Error('请先选择账号');
  const count = selected.size;
  if (!window.confirm(`确认永久删除已选的 ${count} 个账号及其测试历史？`)) return;
  const data = await api('/api/accounts/delete-selected', {
    method: 'POST',
    body: JSON.stringify({ ids: Array.from(selected) }),
  });
  selected.clear();
  toast(`已删除 ${data.deleted} 个账号`);
  await refreshAll();
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
  $('#api-key-state').textContent = data.config.api_key_configured ? '已配置全局 API Key' : '尚未配置全局 API Key';
  $('#cfg-api-key').value = data.config.api_key || '';
  $('#cfg-tg-bot').value = data.config.telegram_bot_token || '';
  $('#cfg-tg-chat').value = data.config.telegram_chat_id || '';
}

async function saveSettings() {
  const concurrency = parseInt($('#cfg-concurrency').value, 10) || 5;
  await api('/api/config', { method: 'PUT', body: JSON.stringify({ proxy_url: $('#cfg-proxy').value, default_concurrency: concurrency }) });
  $('#run-concurrency').value = concurrency;
  toast('设置已保存');
}

async function saveApiKey() {
  const key = $('#cfg-api-key').value.trim();
  if (key.length < 24) throw new Error('API Key 至少需要 24 位');
  await api('/api/config', { method: 'PUT', body: JSON.stringify({ api_key: key, telegram_bot_token: $('#cfg-tg-bot').value, telegram_chat_id: $('#cfg-tg-chat').value }) });
  $('#api-key-state').textContent = '已配置全局 API Key';
  toast('全局 API 与 TG 设置已保存');
}

async function copyApiKey() {
  const key = $('#cfg-api-key').value;
  if (!key) throw new Error('当前没有可复制的 API Key');
  await navigator.clipboard.writeText(key);
  toast('全局 API Key 已复制');
}

function currentMailAccount() {
  const value = $('#mail-account').value.trim();
  if (!value) throw new Error('请输入邮箱或完整四段账号信息');
  return value;
}

function renderOtp(target, otp) {
  target.innerHTML = `<strong>${escapeHtml(otp.code)}</strong><span>${escapeHtml(otp.subject || '')}</span>`;
  target.classList.remove('hidden');
}

function renderMailItems(target, emails, openHandler) {
  target.innerHTML = emails.length ? emails.map((email) => `<button class="mail-item" data-id="${escapeHtml(email.id)}"><strong>${escapeHtml(email.subject)}</strong><span>${escapeHtml(email.sender)}</span><time>${escapeHtml(formatTime(email.received_at))}</time></button>`).join('') : '<p class="muted">没有邮件</p>';
  target.querySelectorAll('.mail-item').forEach((button) => { button.onclick = () => openHandler(button.dataset.id); });
}

function renderMailDetail(target, email, otpHandler, attachmentHandler) {
  const attachments = (email.attachments || []).filter((item) => !item.inline).map((item) => `<button class="btn ghost sm attachment-btn" data-id="${escapeHtml(item.id)}">下载 ${escapeHtml(item.filename)} (${item.size_bytes || 0} B)</button>`).join('');
  target.innerHTML = `<div class="mail-detail-head"><h2>${escapeHtml(email.subject)}</h2><p>${escapeHtml(email.sender)} · ${escapeHtml(formatTime(email.received_at))}</p><button class="btn primary sm otp-single">提取 OTP</button></div><div class="mail-body"></div>${attachments ? `<div class="attachments"><h3>附件</h3>${attachments}</div>` : ''}`;
  const body = target.querySelector('.mail-body');
  if (email.body_html) {
    const frame = document.createElement('iframe');
    frame.setAttribute('sandbox', '');
    frame.srcdoc = email.body_html;
    body.appendChild(frame);
  } else body.innerHTML = `<pre>${escapeHtml(email.body_text || '(无正文)')}</pre>`;
  target.querySelector('.otp-single').onclick = otpHandler;
  target.querySelectorAll('.attachment-btn').forEach((button) => { button.onclick = () => attachmentHandler(button.dataset.id); });
}

async function mailLatestOtp() {
  const data = await api('/api/mail/otp', { method: 'POST', body: JSON.stringify({ account: currentMailAccount() }) });
  renderOtp($('#mail-otp-result'), data.otp);
}

async function readMail() {
  const account = currentMailAccount();
  const data = await api('/api/mail/messages', { method: 'POST', body: JSON.stringify({ account }) });
  renderMailItems($('#mail-list'), data.emails, (id) => openMailDetail(id).catch((error) => toast(error.message)));
}

async function openMailDetail(id) {
  const account = currentMailAccount();
  const data = await api(`/api/mail/messages/${encodeURIComponent(id)}/detail`, { method: 'POST', body: JSON.stringify({ account }) });
  renderMailDetail($('#mail-detail'), data.email,
    () => api(`/api/mail/messages/${encodeURIComponent(id)}/otp`, { method: 'POST', body: JSON.stringify({ account }) }).then((item) => renderOtp($('#mail-otp-result'), item.otp)).catch((error) => toast(error.message)),
    (attachmentId) => downloadAdminAttachment(id, attachmentId, account).catch((error) => toast(error.message)));
}

async function downloadAdminAttachment(messageId, attachmentId, account) {
  const response = await fetch(`/api/mail/messages/${encodeURIComponent(messageId)}/attachments/${encodeURIComponent(attachmentId)}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ account }) });
  if (!response.ok) throw new Error((await response.json()).detail || '附件下载失败');
  const blob = await response.blob();
  const link = document.createElement('a'); link.href = URL.createObjectURL(blob);
  const disposition = response.headers.get('content-disposition') || '';
  link.download = disposition.match(/filename="([^"]+)"/)?.[1] || 'attachment'; link.click(); URL.revokeObjectURL(link.href);
}

function refreshShareAccountOptions() {
  $('#share-account').innerHTML = accounts.map((account) => `<option value="${account.id}">${escapeHtml(account.email)}</option>`).join('');
}

function refreshScheduleAccountOptions() {
  const options = accounts.map((account) => `<option value="${escapeHtml(account.email)}"></option>`).join('');
  const datalist = $('#schedule-email-options');
  if (datalist) datalist.innerHTML = options;
  const select = $('#schedule-edit-account');
  if (select) select.innerHTML = accounts.map((account) => `<option value="${account.id}">${escapeHtml(account.email)}</option>`).join('');
}

function findScheduleAccount(email) {
  const normalized = email.trim().toLowerCase();
  return accounts.find((account) => account.email.toLowerCase() === normalized);
}

function scheduleStatus(status) {
  if (status === 'ok') return '<span class="chip normal">正常</span>';
  if (status === 'fail') return '<span class="chip other_error">异常</span>';
  return '<span class="chip untested">待执行</span>';
}

async function loadScheduledTasks() {
  refreshScheduleAccountOptions();
  const data = await api('/api/scheduled-tasks');
  $('#schedule-list').innerHTML = data.tasks.length ? data.tasks.map((task) => `<div class="schedule-row" data-id="${task.id}">
    <div class="schedule-main"><strong>${escapeHtml(task.email)}</strong><span>${task.enabled ? `每 ${Number(task.interval_minutes).toLocaleString('zh-CN')} 分钟 · 下次 ${escapeHtml(formatTime(task.next_run_at))}` : '已停止'} · TG ${task.notify_telegram ? '开启' : '关闭'}</span><span>最近 ${escapeHtml(formatTime(task.last_run_at))} · ${scheduleStatus(task.last_status)} ${escapeHtml(task.last_message || '')}</span></div>
    <div class="schedule-runs">${task.runs.length ? task.runs.map((run) => `<p><time>${escapeHtml(formatTime(run.created_at))}</time> ${run.status === 'ok' ? '正常' : '异常'} · ${escapeHtml(run.message)}</p>`).join('') : '<p class="muted">暂无执行记录</p>'}</div>
    <div class="schedule-actions"><button class="btn ghost sm" data-action="edit">编辑</button><button class="btn danger sm" data-action="delete">删除</button></div>
  </div>`).join('') : '<p class="muted">暂无定时任务</p>';
  $('#schedule-list').querySelectorAll('.schedule-row').forEach((row) => {
    const task = data.tasks.find((item) => item.id === Number(row.dataset.id));
    row.querySelector('[data-action="edit"]').onclick = () => openScheduleEdit(task);
    row.querySelector('[data-action="delete"]').onclick = () => deleteScheduledTask(task.id);
  });
}

async function createScheduledTask() {
  const account = findScheduleAccount($('#schedule-email').value);
  if (!account) throw new Error('请从账号池提示中选择完整邮箱');
  const interval = Number($('#schedule-minutes').value);
  if (!Number.isFinite(interval) || interval < 1) throw new Error('定时间隔最短为 1 分钟');
  await api('/api/scheduled-tasks', { method: 'POST', body: JSON.stringify({ account_id: account.id, interval_minutes: interval, enabled: true, notify_telegram: $('#schedule-notify').checked }) });
  $('#schedule-email').value = '';
  toast('定时任务已创建');
  await loadScheduledTasks();
}

function openScheduleEdit(task) {
  refreshScheduleAccountOptions();
  $('#schedule-edit-id').value = task.id;
  $('#schedule-edit-account').value = task.account_id;
  $('#schedule-edit-minutes').value = task.interval_minutes;
  $('#schedule-edit-notify').checked = Boolean(task.notify_telegram);
  $('#schedule-edit-enabled').checked = Boolean(task.enabled);
  $('#schedule-modal').classList.remove('hidden');
}

function closeScheduleEdit() { $('#schedule-modal').classList.add('hidden'); }

async function saveScheduleEdit() {
  const id = Number($('#schedule-edit-id').value);
  const interval = Number($('#schedule-edit-minutes').value);
  if (!Number.isFinite(interval) || interval < 1) throw new Error('定时间隔最短为 1 分钟');
  await api(`/api/scheduled-tasks/${id}`, { method: 'PUT', body: JSON.stringify({ account_id: Number($('#schedule-edit-account').value), interval_minutes: interval, enabled: $('#schedule-edit-enabled').checked, notify_telegram: $('#schedule-edit-notify').checked }) });
  closeScheduleEdit(); toast('定时任务已保存'); await loadScheduledTasks();
}

async function deleteScheduledTask(id) {
  if (!window.confirm('确认删除该定时任务及其执行记录？')) return;
  await api(`/api/scheduled-tasks/${id}`, { method: 'DELETE' });
  toast('定时任务已删除'); await loadScheduledTasks();
}

async function loadShares() {
  refreshShareAccountOptions();
  const data = await api('/api/shares');
  $('#share-list').innerHTML = data.shares.length ? data.shares.map((share) => `<div class="share-row" data-id="${share.id}"><div><strong>${escapeHtml(share.email)}</strong><p>${share.enabled ? '启用' : '已停用'} · ${share.expires_at ? `到期 ${escapeHtml(formatTime(share.expires_at))}` : '永久'}</p><code>页面：${escapeHtml(location.origin + share.page_url)}</code><code>最新 OTP：${escapeHtml(location.origin + share.otp_api)}</code><code>邮件列表：${escapeHtml(location.origin + share.emails_api)}</code><code>邮件详情：${escapeHtml(location.origin + share.detail_api)}</code><code>单封 OTP：${escapeHtml(location.origin + share.email_otp_api)}</code><code>附件：${escapeHtml(location.origin + share.attachment_api)}</code></div><div class="share-actions"><button class="btn ghost sm" data-action="copy">复制页面链接</button><button class="btn ghost sm" data-action="toggle">${share.enabled ? '停用' : '启用'}</button><button class="btn ghost sm" data-action="regenerate">重生成链接/密钥</button><button class="btn danger sm" data-action="delete">删除</button></div></div>`).join('') : '<p class="muted">尚未设置分享</p>';
  $('#share-list').querySelectorAll('.share-row').forEach((row) => {
    const share = data.shares.find((item) => item.id === Number(row.dataset.id));
    row.querySelector('[data-action="copy"]').onclick = () => navigator.clipboard.writeText(location.origin + share.page_url).then(() => toast('页面链接已复制'));
    row.querySelector('[data-action="toggle"]').onclick = () => updateShare(share.id, { enabled: !share.enabled });
    row.querySelector('[data-action="regenerate"]').onclick = () => updateShare(share.id, { regenerate_page_token: true, api_key: '' }, true);
    row.querySelector('[data-action="delete"]').onclick = () => deleteShare(share.id);
  });
}

async function createShare() {
  const data = await api('/api/shares', { method: 'POST', body: JSON.stringify({ account_id: Number($('#share-account').value), expires_days: Number($('#share-expires').value) || 0, api_key: $('#share-api-key').value.trim() || null }) });
  $('#share-created').textContent = `页面：${location.origin + data.page_url}\n分享 API Key（仅显示本次）：${data.api_key}`;
  $('#share-api-key').value = '';
  await loadShares();
}

async function updateShare(id, payload, showSecret = false) {
  const data = await api(`/api/shares/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
  if (showSecret) $('#share-created').textContent = `新页面：${location.origin + data.page_url}\n新 API Key（仅显示本次）：${data.api_key}`;
  await loadShares(); toast('分享已更新');
}

async function deleteShare(id) {
  if (!window.confirm('确认删除该分享？链接和 API Key 将立即失效。')) return;
  await api(`/api/shares/${id}`, { method: 'DELETE' }); await loadShares(); toast('分享已删除');
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
$('#delete-selected-btn').onclick = () => deleteSelected().catch((error) => toast(error.message));
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
$('#save-api-key-btn').onclick = () => saveApiKey().catch((error) => toast(error.message));
$('#copy-api-key-btn').onclick = () => copyApiKey().catch((error) => toast(error.message));
$('#mail-otp-btn').onclick = () => mailLatestOtp().catch((error) => toast(error.message, 5000));
$('#mail-read-btn').onclick = () => readMail().catch((error) => toast(error.message, 5000));
$('#create-share-btn').onclick = () => createShare().catch((error) => toast(error.message, 5000));
$('#create-schedule-btn').onclick = () => createScheduledTask().catch((error) => toast(error.message, 5000));
$('#close-schedule-modal-btn').onclick = closeScheduleEdit;
$('#cancel-schedule-edit-btn').onclick = closeScheduleEdit;
$('#save-schedule-edit-btn').onclick = () => saveScheduleEdit().catch((error) => toast(error.message, 5000));
$('#change-password-btn').onclick = () => changePassword().catch((error) => toast(error.message));
$('#clear-logs-btn').onclick = () => api('/api/logs/clear', { method: 'POST' }).then(loadLogs).catch((error) => toast(error.message));
$('#cancel-job-btn').onclick = () => currentJob && api(`/api/jobs/${currentJob}/cancel`, { method: 'POST' }).catch((error) => toast(error.message));
$('#logout-btn').onclick = () => api('/api/auth/logout', { method: 'POST' }).finally(() => { window.location.href = '/login'; });
$$('.stat').forEach((card) => { card.onclick = () => { $('#status-filter').value = card.dataset.filter; window.location.hash = 'accounts'; renderAccounts(); }; });

route();
Promise.all([refreshAll(), loadSettings()]).then(refreshShareAccountOptions).catch((error) => toast(error.message, 5000));
