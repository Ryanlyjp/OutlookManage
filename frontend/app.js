const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));

let ALL_ACCOUNTS = [];
let SELECTED = new Set();
let logTimer = null;
let jobTimer = null;
let SORT = { key: 'id', dir: 'desc' };
let PAGE = { page: 1, size: 50 };
let CURRENT_JOB_ID = null;
const LAST_RECOVER_DEBUG = new Map();
const REMOTE_READY = ['synced', 'imported', 'exists'];
let APPLIED_ALIVE_THRESHOLD = { years: 0, months: 0, days: 7 };

async function api(path, options = {}) {
  const opts = { headers: {}, ...options };
  if (opts.body && !(opts.body instanceof FormData)) {
    opts.headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.detail || data.reason || data.error || `HTTP ${res.status}`);
    err.payload = data;
    err.status = res.status;
    throw err;
  }
  return data;
}

function toast(msg, ms = 2800) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.remove('hidden');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.add('hidden'), ms);
}

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

function chip(value) {
  const raw = value || '-';
  const lower = String(raw).toLowerCase();
  let cls = '';
  if (lower === 'ok' || lower === 'all' || lower === 'healthy' || lower === 'imported' || lower === 'synced' || lower === 'exists' || lower === 'refresh_ok') cls = 'ok';
  else if (lower === 'banned' || lower === 'fail' || lower === 'token_invalid' || lower === 'other_error' || lower === 'refresh_fail' || lower === 'proto_error') cls = 'fail';
  else if (lower === '-' || lower === '' || lower === 'new' || raw === '未测试') cls = 'muted';
  else cls = 'warn';
  return `<span class="chip ${cls}">${esc(raw)}</span>`;
}

function isBannedAccount(item) {
  // 与后端 is_banned_row 一致：health_status 或 health_severity 任一为 banned
  return item.health_status === 'banned' || item.health_severity === 'banned';
}

function abuseCandidate(item) {
  return isBannedAccount(item);
}

function canShowRecoverAbuse(item) {
  return isBannedAccount(item);
}

function sevClass(sev) {
  if (sev === 'banned' || sev === 'fail') return 'fail';
  if (sev === 'warn') return 'warn';
  if (sev === 'ok') return 'ok';
  return 'muted';
}

function isNormalAccount(item) {
  return item.graph_status === 'ok' || item.imap_status === 'ok' || item.pop_status === 'ok';
}

function isRemoteSynced(item) {
  return isNormalAccount(item) && REMOTE_READY.includes(item.remote_sync_status);
}

function isNeverSynced(item) {
  return isNormalAccount(item) && !REMOTE_READY.includes(item.remote_sync_status);
}

function isUntestedAccount(item) {
  return !item.health_status && !item.last_protocol_test_at && !item.error_detail;
}

function isOtherErrorAccount(item) {
  if (isNormalAccount(item) || isBannedAccount(item) || isUntestedAccount(item)) return false;
  return item.health_status === 'other_error'
    || item.health_status === 'token_invalid'
    || item.status === 'proto_error'
    || !!item.error_detail;
}

function formatDateTime(value) {
  if (!value) return '-';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString('zh-CN', { hour12: false });
}

function getAliveDurationMs(item) {
  if (!item?.registered_at) return null;
  const start = new Date(item.registered_at);
  if (Number.isNaN(start.getTime())) return null;
  const endBase = isNormalAccount(item) ? new Date() : (item.last_alive_at ? new Date(item.last_alive_at) : null);
  if (!endBase || Number.isNaN(endBase.getTime()) || endBase <= start) return null;
  return endBase.getTime() - start.getTime();
}

function formatAliveDuration(item) {
  const durationMs = getAliveDurationMs(item);
  if (durationMs == null) return '-';
  let seconds = Math.floor(durationMs / 1000);
  const days = Math.floor(seconds / 86400);
  seconds -= days * 86400;
  const hours = Math.floor(seconds / 3600);
  seconds -= hours * 3600;
  const minutes = Math.floor(seconds / 60);
  const parts = [];
  if (days) parts.push(`${days}天`);
  if (hours || days) parts.push(`${hours}小时`);
  parts.push(`${minutes}分钟`);
  return parts.join('');
}

function getAliveThresholdInputs() {
  const years = Math.max(0, parseInt($('#alive-years')?.value || '0', 10) || 0);
  const months = Math.max(0, parseInt($('#alive-months')?.value || '0', 10) || 0);
  const days = Math.max(0, parseInt($('#alive-days')?.value || '0', 10) || 0);
  return { years, months, days };
}

function getAliveThresholdMs() {
  const { years, months, days } = APPLIED_ALIVE_THRESHOLD;
  const totalDays = years * 365 + months * 30 + days;
  return totalDays * 86400 * 1000;
}

function isAliveOverThreshold(item) {
  const durationMs = getAliveDurationMs(item);
  return durationMs != null && durationMs > getAliveThresholdMs();
}

function syncAliveThresholdInputs() {
  $('#alive-years').value = String(APPLIED_ALIVE_THRESHOLD.years);
  $('#alive-months').value = String(APPLIED_ALIVE_THRESHOLD.months);
  $('#alive-days').value = String(APPLIED_ALIVE_THRESHOLD.days);
}

function updateAliveThresholdSummary() {
  const el = $('#alive-threshold-count');
  const current = $('#alive-threshold-current');
  if (!el || !current) return;
  const matched = ALL_ACCOUNTS.filter(isAliveOverThreshold).length;
  el.textContent = String(matched);
  current.textContent = `当前阈值：${APPLIED_ALIVE_THRESHOLD.years}年${APPLIED_ALIVE_THRESHOLD.months}月${APPLIED_ALIVE_THRESHOLD.days}天`;
}

function applyAliveThreshold(showToast = true) {
  APPLIED_ALIVE_THRESHOLD = getAliveThresholdInputs();
  PAGE.page = 1;
  updateAliveThresholdSummary();
  renderTable();
  if (showToast) toast('存活时间阈值已应用');
}

function resetAliveThreshold() {
  APPLIED_ALIVE_THRESHOLD = { years: 0, months: 0, days: 7 };
  syncAliveThresholdInputs();
  updateAliveThresholdSummary();
  PAGE.page = 1;
  renderTable();
  toast('已重置为 7 天');
}

// 统计卡片：直接由账号列表(含全部字段)在前端计算，无需后端
function computeStats() {
  const a = ALL_ACCOUNTS;
  const set = (id, v) => { const el = $(id); if (el) el.textContent = v; };
  const stats = {
    total: a.length,
    normal: a.filter(isNormalAccount).length,
    banned: a.filter(isBannedAccount).length,
    otherError: a.filter(isOtherErrorAccount).length,
    synced: a.filter(isRemoteSynced).length,
    untested: a.filter(isUntestedAccount).length,
    graph: a.filter((x) => x.graph_status === 'ok').length,
    imapPop: a.filter((x) => x.imap_status === 'ok' || x.pop_status === 'ok').length,
    neverSynced: a.filter(isNeverSynced).length,
  };
  set('#stat-total', stats.total);
  set('#stat-normal', stats.normal);
  set('#stat-banned', stats.banned);
  set('#stat-other-error', stats.otherError);
  set('#stat-synced', stats.synced);
  set('#stat-untested', stats.untested);
  set('#stat-graph', stats.graph);
  set('#stat-imap-pop', stats.imapPop);
  renderWorkflow(stats);
}

function renderWorkflow(stats) {
  const set = (id, v) => { const el = $(id); if (el) el.textContent = v; };
  set('#flow-total', `${stats.total} 个账号`);
  set('#flow-untested', `${stats.untested} 个未测试`);
  set('#flow-unsynced', `${stats.neverSynced} 个未上传`);
  set('#flow-maintain', `${stats.banned + stats.otherError} 个需关注`);
  const desc = $('#next-action-desc');
  const btn = $('#next-action-btn');
  if (!desc || !btn) return;
  if (stats.total === 0) {
    desc.textContent = '当前没有账号，先导入账号或加载注册产出 oauth2.txt。';
    btn.textContent = '去导入账号';
    btn.dataset.target = '#import';
    btn.dataset.action = '';
  } else if (stats.untested > 0) {
    desc.textContent = `还有 ${stats.untested} 个账号未测试，建议先完成协议测试再同步远程。`;
    btn.textContent = '测试未测试';
    btn.dataset.target = '#tasks';
    btn.dataset.action = 'test-untested';
  } else if (stats.neverSynced > 0) {
    desc.textContent = `有 ${stats.neverSynced} 个可用账号尚未上传远程，建议执行一键同步未上传。`;
    btn.textContent = '同步未上传';
    btn.dataset.target = '#tasks';
    btn.dataset.action = 'sync-never-synced';
  } else {
    desc.textContent = '当前没有明显待办，可在账号池筛选异常账号或执行日常维护。';
    btn.textContent = '查看账号池';
    btn.dataset.target = '#accounts';
    btn.dataset.action = '';
  }
}

function matchFilter(item, kw, filter, domain) {
  if (kw && !item.email.toLowerCase().includes(kw)) return false;
  if (domain) {
    const d = (item.email.split('@')[1] || '').toLowerCase();
    if (domain === '__other__') { if (d === 'outlook.com' || d === 'hotmail.com') return false; }
    else if (d !== domain) return false;
  }
  if (filter) {
    if (filter === 'all') { /* 显示全部 */ }
    else if (filter === 'normal') { if (!isNormalAccount(item)) return false; }
    else if (filter === 'synced') { if (!isRemoteSynced(item)) return false; }
    else if (filter === 'graph') { if (item.graph_status !== 'ok') return false; }
    else if (filter === 'imap_pop') { if (item.imap_status !== 'ok' && item.pop_status !== 'ok') return false; }
    else if (filter === 'banned') { if (!isBannedAccount(item)) return false; }
    else if (filter === 'other_error') { if (!isOtherErrorAccount(item)) return false; }
    else if (filter === 'untested') { if (!isUntestedAccount(item)) return false; }
    else if (filter === 'alive_over_threshold') { if (!isAliveOverThreshold(item)) return false; }
    else if (filter === 'never_synced') {
      if (!isNeverSynced(item)) return false;
    }
  }
  return true;
}

function getFiltered() {
  const kw = $('#search-input').value.trim().toLowerCase();
  const filter = $('#filter-select').value;
  const domain = $('#domain-select').value;
  const rows = ALL_ACCOUNTS.filter((it) => matchFilter(it, kw, filter, domain));
  const { key, dir } = SORT;
  rows.sort((a, b) => {
    let va = a[key], vb = b[key];
    if (key === 'id') { va = +va; vb = +vb; } else { va = String(va || '').toLowerCase(); vb = String(vb || '').toLowerCase(); }
    if (va < vb) return dir === 'asc' ? -1 : 1;
    if (va > vb) return dir === 'asc' ? 1 : -1;
    return 0;
  });
  return rows;
}

function renderProtocolStatus(it) {
  return `<div class="protocol-stack">
    <span>Graph ${chip(it.graph_status)}</span>
    <span>IMAP ${chip(it.imap_status)}</span>
    <span>POP ${chip(it.pop_status)}</span>
    <span>SMTP ${chip(it.smtp_status)}</span>
  </div>`;
}

function renderHealthStatus(it, reasonHtml) {
  return `<div class="status-stack">
    ${chip(it.health_status || '未测试')}
    <div class="reason-cell">${reasonHtml}</div>
  </div>`;
}

function renderRegisteredAlive(it) {
  return `<div class="status-stack">
    <span class="nowrap">${esc(formatDateTime(it.registered_at))}</span>
    <small class="muted">${esc(formatAliveDuration(it))}</small>
  </div>`;
}

function renderTable() {
  const rows = getFiltered();
  const total = rows.length;
  const pages = Math.max(1, Math.ceil(total / PAGE.size));
  if (PAGE.page > pages) PAGE.page = pages;
  if (PAGE.page < 1) PAGE.page = 1;
  const start = (PAGE.page - 1) * PAGE.size;
  const pageRows = rows.slice(start, start + PAGE.size);
  $('#account-table').innerHTML = pageRows.length ? pageRows.map((it) => {
    const reason = it.ban_reason || it.error_detail || '';
    const reasonHtml = reason ? `<span class="reason ${sevClass(it.health_severity)}">${esc(reason)}</span>` : '<span class="muted">-</span>';
    const checked = SELECTED.has(it.id) ? 'checked' : '';
    const recoverBtn = canShowRecoverAbuse(it)
      ? `<button class="action-link" data-act="recover" data-id="${it.id}">恢复ABUSE</button>`
      : '';
    return `<tr data-id="${it.id}">
      <td><input type="checkbox" class="row-check" data-id="${it.id}" ${checked}></td>
      <td>${it.id}</td>
      <td class="email-cell" data-id="${it.id}">${esc(it.email)}</td>
      <td>${renderHealthStatus(it, reasonHtml)}</td>
      <td>${renderProtocolStatus(it)}</td>
      <td>${renderRegisteredAlive(it)}</td>
      <td class="nowrap">${esc(it.last_protocol_test_at || '-')}</td>
      <td>${chip(it.remote_sync_status)}</td>
      <td>
        <div class="action-group">
          <button class="action-link" data-act="refresh" data-id="${it.id}">刷新</button>
          <button class="action-link" data-act="protocol" data-id="${it.id}">测试</button>
          ${recoverBtn}
          <button class="action-link" data-act="copy2" data-id="${it.id}">复制账密</button>
          <button class="action-link" data-act="copy4" data-id="${it.id}">复制全部</button>
        </div>
      </td>
    </tr>`;
  }).join('') : '<tr><td colspan="9" class="empty-state"><b>暂无账号</b><span>下一步：导入账号或加载注册产出 oauth2.txt。</span><button class="btn sm primary" data-empty-jump="#import">去导入</button></td></tr>';
  $('#page-info').textContent = `${PAGE.page} / ${pages}`;
  $('#table-summary').textContent = `筛选结果 ${total} 个 · 本页 ${pageRows.length} · 已选 ${SELECTED.size}`;
  $('#selected-count').textContent = `已选 ${SELECTED.size}`;
  updateAliveThresholdSummary();
  document.querySelectorAll('th.sortable').forEach((th) => {
    th.querySelector('.sort-ind').textContent = th.dataset.sort === SORT.key ? (SORT.dir === 'asc' ? '↑' : '↓') : '↕';
  });
  $('#select-all').checked = pageRows.length > 0 && pageRows.every((it) => SELECTED.has(it.id));
}

async function loadAccounts() {
  const d = await api('/api/accounts');
  ALL_ACCOUNTS = d.items;
  SELECTED.forEach((id) => { if (!ALL_ACCOUNTS.find((a) => a.id === id)) SELECTED.delete(id); });
  computeStats();
  updateAliveThresholdSummary();
  renderTable();
}

async function loadLogs() {
  const d = await api('/api/logs');
  const el = $('#log-output');
  el.innerHTML = d.lines.length ? d.lines.map((l) => {
    let cls = 'log-info';
    if (/\[FAIL\]|失败|错误/.test(l)) cls = 'log-fail';
    else if (/\[WARN\]/.test(l)) cls = 'log-warn';
    else if (/\[OK\]|成功|完成/.test(l)) cls = 'log-ok';
    return `<span class="${cls}">${esc(l)}</span>`;
  }).join('\n') : '暂无日志';
  el.scrollTop = el.scrollHeight;
}

async function refreshAll() {
  await Promise.all([loadAccounts(), loadLogs()]);
}

// ---------- 导入 ----------
async function doPreview() {
  const text = $('#account-input').value.trim();
  if (!text) return toast('请输入账号');
  const d = await api('/api/accounts/import-preview', { method: 'POST', body: JSON.stringify({ text }) });
  $('#import-result').innerHTML = `预览：有效 <b>${d.valid}</b> 行 · 新增 <b>${d.new}</b> · 覆盖 <b>${d.overwrite}</b> · 输入内重复 ${d.dup_in_input} · <span class="${d.error_count ? 'fail' : ''}">错误 ${d.error_count}</span>`
    + (d.errors.length ? `<div class="err-list">${d.errors.map((e) => `第${e.line_no}行: ${esc(e.error)}`).join('<br>')}</div>` : '');
}

function importErrorBreakdown(errors, errorCount) {
  if (!errorCount) return '';
  const counts = {};
  (errors || []).forEach((e) => { counts[e.error] = (counts[e.error] || 0) + 1; });
  const lines = Object.entries(counts).sort((a, b) => b[1] - a[1])
    .map(([r, c]) => `<div class="reason-line"><span>${esc(r)}</span><em class="fail">${c}</em></div>`).join('');
  return `<div class="reason-break"><b class="fail">错误明细（共 ${errorCount}）</b>${lines}</div>`;
}

async function doImport() {
  const text = $('#account-input').value.trim();
  if (!text) return toast('请输入账号');
  const d = await api('/api/accounts/import-text', { method: 'POST', body: JSON.stringify({ text }) });
  $('#import-result').innerHTML = `导入完成：<b>新增 ${d.inserted}</b> · 覆盖 ${d.updated} · 总有效 ${d.inserted + d.updated} · 错误 ${d.error_count}`
    + importErrorBreakdown(d.errors, d.error_count);
  toast('导入完成，建议执行一键测试未测试');
  await refreshAll();
}

async function uploadFile(file) {
  const fd = new FormData();
  fd.append('file', file);
  const d = await api('/api/accounts/import-file', { method: 'POST', body: fd });
  $('#import-result').innerHTML = `文件导入：<b>新增 ${d.inserted}</b> · 覆盖 ${d.updated} · 总有效 ${d.inserted + d.updated} · 错误 ${d.error_count}`
    + importErrorBreakdown(d.errors, d.error_count);
  toast('文件导入完成，建议执行一键测试未测试');
  await refreshAll();
}

// ---------- 单账号操作 ----------
function copyText(text) {
  const done = () => toast('已复制到剪贴板');
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
  } else {
    fallbackCopy(text, done);
  }
}
function fallbackCopy(text, done) {
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); done(); } catch (e) { toast('复制失败'); }
  ta.remove();
}
async function copyAccount(id, full) {
  // 列表不再带 password/refresh_token，复制完整行时走详情接口
  try {
    if (!full) {
      const a = ALL_ACCOUNTS.find((x) => x.id === id);
      if (!a) return;
      // 仅邮箱+密码也需详情（列表无 password）
      const d = await api(`/api/accounts/${id}/detail`);
      const acc = d.account || {};
      copyText(`${acc.email}----${acc.password || ''}`);
      return;
    }
    const d = await api(`/api/accounts/${id}/detail`);
    const acc = d.account || {};
    copyText(`${acc.email}----${acc.password || ''}----${acc.client_id || ''}----${acc.refresh_token || ''}`);
  } catch (e) {
    toast(e.message || '复制失败', 4200);
  }
}

async function rowAction(act, id) {
  if (act === 'detail') return openDrawer(id);
  if (act === 'copy2') return void copyAccount(id, false);
  if (act === 'copy4') return void copyAccount(id, true);
  const actionLabel = act === 'refresh' ? '刷新中' : act === 'protocol' ? '测试中' : '恢复中';
  toast(`账号 #${id} ${actionLabel}…`, 4000);
  try {
    const path = act === 'refresh'
      ? `/api/accounts/${id}/refresh`
      : act === 'protocol'
        ? `/api/accounts/${id}/protocol-test`
        : `/api/accounts/${id}/recover-abuse`;
    const d = await api(path, { method: 'POST' });
    if (act === 'recover') {
      if (d.debug_log) LAST_RECOVER_DEBUG.set(id, d.debug_log);
      else LAST_RECOVER_DEBUG.delete(id);
    }
    const msg = d.success
      ? (d.reason || d.health || '完成')
      : `失败：${d.reason || ''}${d.debug_log ? ` | 日志：${d.debug_log}` : ''}`;
    toast(msg, 5200);
    if (act === 'recover') {
      await refreshAll();
      await openDrawer(id);
      return;
    }
  } catch (e) {
    const debugLog = e?.payload?.debug_log || '';
    if (act === 'recover') {
      if (debugLog) LAST_RECOVER_DEBUG.set(id, debugLog);
      else LAST_RECOVER_DEBUG.delete(id);
    }
    toast(`失败：${e.message}${debugLog ? ` | 日志：${debugLog}` : ''}`, 7000);
    if (act === 'recover') {
      await refreshAll();
      await openDrawer(id);
      return;
    }
  }
  await refreshAll();
}

// ---------- 批量 ----------
const BATCH_API = {
  refresh: '/api/accounts/batch/refresh',
  protocol: '/api/accounts/batch/protocol',
  'recover-abuse': '/api/accounts/batch/recover-abuse',
  'remote-import': '/api/remote/import',
};
const BATCH_NAME = { refresh: '批量刷新', protocol: '批量协议测试', 'recover-abuse': '批量恢复 ABUSE', 'remote-import': '同步到远程' };
const JOB_NAME = {
  refresh: '批量刷新',
  protocol: '批量协议测试',
  'recover-abuse': '批量恢复 ABUSE',
  'remote-import': '远程同步',
  delete: '批量删除',
};

function scrollToSection(target) {
  const el = document.querySelector(target);
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function runWorkflowAction(action) {
  if (action === 'test-untested') return $('#test-untested-btn')?.click();
  if (action === 'sync-never-synced') return $('#sync-never-synced-btn')?.click();
  return null;
}

async function startBatch(type, all) {
  const ids = all ? null : Array.from(SELECTED);
  if (!all && ids.length === 0) return toast('请先勾选账号');
  const concurrency = parseInt($('#concurrency').value, 10) || 8;
  try {
    const d = await api(BATCH_API[type], { method: 'POST', body: JSON.stringify({ ids, concurrency }) });
    toast(`${BATCH_NAME[type]} 已启动，共 ${d.total} 个，并发 ${d.concurrency}`);
    pollJob(d.job_id, BATCH_NAME[type]);
  } catch (e) {
    toast(`启动失败：${e.message}`, 4200);
  }
}

function renderReasons(reasons) {
  if (!reasons) return '';
  const blocks = [];
  const labels = { ok: ['成功明细', 'ok'], skip: ['跳过明细', 'warn'], fail: ['失败原因', 'fail'] };
  for (const st of ['fail', 'skip', 'ok']) {
    const m = reasons[st];
    if (!m || Object.keys(m).length === 0) continue;
    const [label, cls] = labels[st];
    const entries = Object.entries(m).sort((a, b) => b[1] - a[1]);
    blocks.push(`<div class="reason-break"><b class="${cls}">${label}</b>` +
      entries.map(([r, c]) => `<div class="reason-line"><span>${esc(r)}</span><em class="${cls}">${c}</em></div>`).join('') +
      `</div>`);
  }
  return blocks.join('');
}

function pollJob(jobId, title) {
  const panel = $('#job-panel');
  panel.classList.remove('hidden');
  $('#job-title').textContent = title;
  $('#job-state').textContent = '已启动';
  $('#job-bar').style.width = '0%';
  $('#job-stats').innerHTML = '<div class="job-counts">任务已启动，等待首批结果…</div>';
  CURRENT_JOB_ID = jobId;
  clearInterval(jobTimer);
  const tick = async () => {
    try {
      const d = await api(`/api/jobs/${jobId}`);
      const j = d.job;
      const pct = j.total ? Math.round((j.processed / j.total) * 100) : 0;
      $('#job-bar').style.width = pct + '%';
      const stateText = j.state === 'done'
        ? '已完成'
        : (j.state === 'cancelled' ? '已取消' : (j.state === 'failed' ? '失败' : `${pct}%`));
      $('#job-state').textContent = stateText;
      $('#job-stats').innerHTML =
        `<div class="job-counts">总数 ${j.total} · 处理 ${j.processed} · <span class="ok">成功 ${j.succeeded}</span> · <span class="fail">失败 ${j.failed}</span> · <span class="warn">跳过 ${j.skipped}</span></div>`
        + (j.error ? `<div class="reason-break"><b class="fail">任务错误</b><div class="reason-line"><span>${esc(j.error)}</span></div></div>` : '')
        + renderReasons(j.reasons);
      if (j.state === 'done' || j.state === 'cancelled' || j.state === 'failed') {
        clearInterval(jobTimer);
        CURRENT_JOB_ID = null;
        const msg = j.state === 'cancelled'
          ? `${title} 已取消：已处理 ${j.processed}，成功 ${j.succeeded}，失败 ${j.failed}，跳过 ${j.skipped}`
          : (j.state === 'failed'
            ? `${title} 失败：${j.error || '未知错误'}`
            : `${title} 完成：成功 ${j.succeeded}，失败 ${j.failed}，跳过 ${j.skipped}`);
        toast(msg, 5000);
        await refreshAll();
      } else {
        await loadAccounts();
      }
    } catch (e) {
      clearInterval(jobTimer);
      CURRENT_JOB_ID = null;
      $('#job-state').textContent = '轮询失败';
      $('#job-stats').innerHTML = `<div class="reason-break"><b class="fail">任务轮询失败</b><div class="reason-line"><span>${esc(e.message || '未知错误')}</span></div></div>`;
      toast(`任务轮询失败：${e.message || '未知错误'}`, 5000);
    }
  };
  tick();
  jobTimer = setInterval(tick, 2000);
}

async function restoreRunningJob() {
  if (CURRENT_JOB_ID) return;
  const d = await api('/api/jobs');
  const running = (d.jobs || []).find((j) => j.state === 'running');
  if (!running) return;
  const title = JOB_NAME[running.type] || running.type || '当前任务';
  pollJob(running.id, `恢复任务：${title}`);
}

// ---------- 详情抽屉 ----------
async function openDrawer(id) {
  try {
    const d = await api(`/api/accounts/${id}/detail`);
    const a = d.account;
    const lastRecoverDebug = LAST_RECOVER_DEBUG.get(id) || '';
    $('#drawer-title').textContent = a.email;
    const reason = a.ban_reason || a.error_detail;
    const recoverBtn = canShowRecoverAbuse(a)
      ? `<button class="btn sm" data-dact="recover" data-id="${id}">恢复 ABUSE</button>`
      : '';
    const histRows = d.history.length ? d.history.map((h) =>
      `<tr><td class="nowrap">${esc(h.created_at)}</td><td>${esc(h.action)}</td><td>${chip(h.status)}</td><td>${esc(h.detail)}</td></tr>`
    ).join('') : '<tr><td colspan="4" class="muted">暂无历史</td></tr>';
    $('#drawer-content').innerHTML = `
      ${reason ? `<div class="reason-box ${sevClass(a.health_severity)}">${esc(reason)}</div>` : ''}
      <div class="kv-grid">
        <div><span>Health</span>${chip(a.health_status || '未测试')}</div>
        <div><span>Graph</span>${chip(a.graph_status)}</div>
        <div><span>IMAP</span>${chip(a.imap_status)}</div>
        <div><span>POP</span>${chip(a.pop_status)}</div>
        <div><span>SMTP</span>${chip(a.smtp_status)}</div>
        <div><span>Remote</span>${chip(a.remote_sync_status || '未同步')}</div>
        <div><span>注册时间</span>${esc(formatDateTime(a.registered_at))}</div>
        <div><span>存活时间</span><small>${esc(formatAliveDuration(a))}</small></div>
        <div><span>最近刷新</span>${esc(a.last_refresh_at || '-')}</div>
        <div><span>最近测试</span>${esc(a.last_protocol_test_at || '-')}</div>
        <div><span>恢复状态</span>${chip(a.recovery_status || '-')}</div>
        ${lastRecoverDebug ? `<div class="kv-full"><span>本次恢复日志</span><small>${esc(lastRecoverDebug)}</small></div>` : ''}
        <div><span>刷新错误</span><small>${esc(a.last_refresh_error || '-')}</small></div>
        <div><span>远程错误</span><small>${esc(a.remote_sync_error || '-')}</small></div>
        <div class="kv-full"><span>密码（可编辑）</span><input class="edit-field" id="edit-password" value="${esc(a.password)}"></div>
        <div class="kv-full"><span>client_id（可编辑）</span><input class="edit-field" id="edit-client_id" value="${esc(a.client_id)}"></div>
        <div class="kv-full"><span>Refresh Token / 授权令牌（可编辑）</span><textarea class="edit-field" id="edit-refresh_token" rows="3">${esc(a.refresh_token)}</textarea></div>
        <div class="kv-full"><span>备注（可编辑）</span><input class="edit-field" id="edit-remark" value="${esc(a.remark || '')}"></div>
      </div>
      <div class="drawer-actions">
        <button class="btn sm primary" data-dact="save" data-id="${id}">保存修改到本地库</button>
        <button class="btn sm" data-dact="refresh" data-id="${id}">刷新 token</button>
        <button class="btn sm" data-dact="protocol" data-id="${id}">协议测试</button>
        ${recoverBtn}
        <button class="btn sm danger" data-dact="remote-remove" data-id="${id}">从远程移除(留本地)</button>
        <button class="btn sm danger" data-dact="purge" data-id="${id}">彻底删除(本地+远程)</button>
      </div>
      <h4>历史记录</h4>
      <div class="table-wrap"><table class="mini"><thead><tr><th>时间</th><th>动作</th><th>状态</th><th>详情</th></tr></thead><tbody>${histRows}</tbody></table></div>
    `;
    $('#drawer').classList.remove('hidden');
  } catch (e) { toast(`加载详情失败：${e.message}`); }
}

function closeDrawer() { $('#drawer').classList.add('hidden'); }

async function drawerAction(act, id) {
  if (act === 'save') {
    await api(`/api/accounts/${id}`, { method: 'PUT', body: JSON.stringify({
      password: $('#edit-password').value,
      client_id: $('#edit-client_id').value,
      refresh_token: $('#edit-refresh_token').value,
      remark: $('#edit-remark').value,
    }) });
    toast('已保存到本地数据库');
    await refreshAll();
    return openDrawer(id);
  }
  if (act === 'remote-remove') {
    if (!confirm('从远程移除该账号？本地记录保留。')) return;
    await api(`/api/accounts/${id}/remote-remove`, { method: 'POST' });
    toast('已从远程移除（本地保留）'); closeDrawer(); return refreshAll();
  }
  if (act === 'purge') {
    if (!confirm('彻底删除该账号（本地+远程）？不可恢复！')) return;
    await api(`/api/accounts/${id}?remote=true`, { method: 'DELETE' });
    toast('已彻底删除（本地+远程）'); closeDrawer(); return refreshAll();
  }
  await rowAction(act, id);
  await openDrawer(id);
}

// ---------- 配置 ----------
function addMapRow(domain = '', gid = '') {
  const row = document.createElement('div');
  row.className = 'map-row';
  row.innerHTML = `<input class="map-domain" placeholder="outlook.com" value="${esc(domain)}">
    <span>→</span>
    <input class="map-gid" type="number" placeholder="分组ID" value="${gid ?? ''}">
    <button class="btn sm ghost map-del" type="button">删除</button>`;
  row.querySelector('.map-del').onclick = () => row.remove();
  $('#map-rows').appendChild(row);
}

async function loadConfig() {
  const d = await api('/api/config');
  const c = d.config;
  $('#cfg-proxy').value = c.proxy_url || '';
  $('#cfg-remote-url').value = c.remote_base_url || '';
  $('#cfg-remote-pass').value = c.remote_password || '';
  $('#cfg-recipient').value = c.external_recipient || '';
  $('#cfg-skip-unmapped').checked = c.skip_unmapped !== false;
  $('#concurrency').value = c.default_concurrency || 100;
  $('#map-rows').innerHTML = '';
  const map = c.group_map || {};
  const keys = Object.keys(map);
  if (keys.length === 0) addMapRow();
  else keys.forEach((k) => addMapRow(k, map[k]));
}

async function saveConfig() {
  const group_map = {};
  $$('#map-rows .map-row').forEach((row) => {
    const domain = row.querySelector('.map-domain').value.trim().toLowerCase();
    const gid = parseInt(row.querySelector('.map-gid').value, 10);
    if (domain && Number.isInteger(gid)) group_map[domain] = gid;
  });
  await api('/api/config', { method: 'PUT', body: JSON.stringify({
    proxy_url: $('#cfg-proxy').value,
    remote_base_url: $('#cfg-remote-url').value,
    remote_password: $('#cfg-remote-pass').value,
    group_map,
    skip_unmapped: $('#cfg-skip-unmapped').checked,
    external_recipient: $('#cfg-recipient').value,
  }) });
  toast('配置已保存');
}

// ---------- 事件绑定 ----------
// 统计卡片点击筛选
$$('.stat-card[data-filter]').forEach((card) => {
  card.style.cursor = 'pointer';
  card.onclick = () => {
    const filterValue = card.dataset.filter;
    $('#filter-select').value = filterValue;
    PAGE.page = 1;
    renderTable();
    document.getElementById('accounts').scrollIntoView({ behavior: 'smooth' });
  };
});

$('#next-action-btn').onclick = () => {
  const btn = $('#next-action-btn');
  scrollToSection(btn.dataset.target || '#accounts');
  if (btn.dataset.action) setTimeout(() => runWorkflowAction(btn.dataset.action), 350);
};
$$('.workflow-step[data-jump]').forEach((step) => {
  step.onclick = () => scrollToSection(step.dataset.jump);
});

$('#preview-btn').onclick = () => doPreview().catch((e) => toast(e.message, 4200));
$('#import-btn').onclick = () => doImport().catch((e) => toast(e.message, 4200));
$('#clear-btn').onclick = () => { $('#account-input').value = ''; $('#import-result').textContent = ''; };
$('#load-default-btn').onclick = () => api('/api/accounts/load-default-file').then((d) => { refreshAll(); toast(`已导入 oauth2.txt（新增 ${d.inserted}/覆盖 ${d.updated}），建议执行一键测试未测试`); }).catch((e) => toast(e.message, 4200));
$('#file-input').onchange = (e) => { if (e.target.files[0]) uploadFile(e.target.files[0]).catch((err) => toast(err.message, 4200)); };
$('#refresh-view-btn').onclick = () => refreshAll().catch((e) => toast(e.message, 4200));
$('#save-config-btn').onclick = () => saveConfig().catch((e) => toast(e.message, 4200));
$('#add-map-row').onclick = () => addMapRow();
$('#search-input').oninput = () => { PAGE.page = 1; renderTable(); };
$('#filter-select').onchange = () => { PAGE.page = 1; renderTable(); };
$('#domain-select').onchange = () => { PAGE.page = 1; renderTable(); };
$('#apply-alive-threshold-btn').onclick = () => applyAliveThreshold(true);
$('#reset-alive-threshold-btn').onclick = () => resetAliveThreshold();
$('#page-size').onchange = (e) => { PAGE.size = parseInt(e.target.value, 10) || 50; PAGE.page = 1; renderTable(); };
$('#page-prev').onclick = () => { if (PAGE.page > 1) { PAGE.page--; renderTable(); } };
$('#page-next').onclick = () => { PAGE.page++; renderTable(); };
document.querySelectorAll('th.sortable').forEach((th) => {
  th.onclick = () => {
    const key = th.dataset.sort;
    if (SORT.key === key) SORT.dir = SORT.dir === 'asc' ? 'desc' : 'asc';
    else { SORT.key = key; SORT.dir = 'asc'; }
    renderTable();
  };
});
$('#drawer-close').onclick = closeDrawer;
$('#drawer-mask').onclick = closeDrawer;

$('#select-all').onchange = (e) => {
  // 全选/取消：仅作用于当前页（符合“控制当前页全部数据选中”语义）
  const rows = getFiltered();
  const start = (PAGE.page - 1) * PAGE.size;
  rows.slice(start, start + PAGE.size).forEach((it) => {
    if (e.target.checked) SELECTED.add(it.id); else SELECTED.delete(it.id);
  });
  renderTable();
};

document.querySelectorAll('[data-batch]').forEach((btn) => {
  btn.onclick = () => startBatch(btn.dataset.batch, btn.dataset.all === '1');
});

async function deleteBatch(mode) {
  // mode: 'remote' = 从远程移除(留本地)  |  'both' = 本地+远程彻底删除
  const ids = Array.from(SELECTED);
  if (!ids.length) return toast('请先勾选账号');
  const both = mode === 'both';
  const label = both ? '彻底删除(本地+远程)' : '从远程移除(本地保留)';
  if (!confirm(`确认对 ${ids.length} 个账号执行「${label}」？${both ? '本地记录也会删除，不可恢复！' : '本地记录保留。'}`)) return;
  try {
    const concurrency = parseInt($('#concurrency').value, 10) || 8;
    const path = both ? '/api/accounts/batch/delete' : '/api/accounts/batch/remote-remove';
    const body = both ? { ids, remote: true, concurrency } : { ids, concurrency };
    const d = await api(path, { method: 'POST', body: JSON.stringify(body) });
    if (d.job_id) { toast(`${label} 已启动，共 ${d.total} 个`); pollJob(d.job_id, label); }
    else { toast(`完成，共 ${d.deleted} 个`); SELECTED.clear(); await refreshAll(); }
  } catch (e) { toast(`操作失败：${e.message}`, 4200); }
}
document.querySelectorAll('[data-del]').forEach((btn) => {
  btn.onclick = () => deleteBatch(btn.dataset.del);
});

document.querySelectorAll('[data-export]').forEach((btn) => {
  btn.onclick = () => {
    const cat = btn.dataset.export;
    window.open(`/api/accounts/export?category=${cat}&with_reason=true`, '_blank');
    toast(`正在导出「${btn.textContent}」并下载`);
  };
});

$('#account-table').onclick = (e) => {
  const emptyJump = e.target.closest('[data-empty-jump]');
  if (emptyJump) return scrollToSection(emptyJump.dataset.emptyJump);
  const checkEl = e.target.closest('.row-check');
  if (checkEl) {
    const id = +checkEl.dataset.id;
    if (checkEl.checked) SELECTED.add(id); else SELECTED.delete(id);
    $('#selected-count').textContent = `已选 ${SELECTED.size}`;
    return;
  }
  const actBtn = e.target.closest('[data-act]');
  if (actBtn) return rowAction(actBtn.dataset.act, +actBtn.dataset.id);
  const emailCell = e.target.closest('.email-cell');
  if (emailCell) return openDrawer(+emailCell.dataset.id);
  const row = e.target.closest('tr[data-id]');
  if (row) return openDrawer(+row.dataset.id);
};

$('#drawer-content').onclick = (e) => {
  const btn = e.target.closest('[data-dact]');
  if (btn) drawerAction(btn.dataset.dact, +btn.dataset.id).catch((err) => toast(err.message, 4200));
};

$('#auto-log').onchange = (e) => {
  clearInterval(logTimer);
  if (e.target.checked) logTimer = setInterval(loadLogs, 4000);
};
logTimer = setInterval(loadLogs, 4000);

$('#clear-logs-btn').onclick = async () => {
  if (!confirm('确认清空运行日志（包括 logs/app.log 文件内容）？')) return;
  try { await api('/api/logs/clear', { method: 'POST' }); await loadLogs(); toast('日志已清空'); }
  catch (e) { toast(`清空失败：${e.message}`, 4200); }
};
$('#select-filtered-btn').onclick = () => {
  getFiltered().forEach((it) => SELECTED.add(it.id));
  renderTable();
  toast(`已选中筛选结果 ${SELECTED.size} 个`);
};
$('#clear-selected-btn').onclick = () => { SELECTED.clear(); renderTable(); };

$('#job-cancel-btn').onclick = async () => {
  if (!CURRENT_JOB_ID) return toast('没有正在运行的任务');
  if (!confirm('确认立即终止所有任务？在途测试会立刻中断，已处理结果保留，未处理记为跳过。')) return;
  const jobId = CURRENT_JOB_ID;
  const btn = $('#job-cancel-btn');
  btn.disabled = true;
  // 乐观 UI：点取消立刻显示已取消，不等下一次轮询
  $('#job-state').textContent = '已取消';
  try {
    await api(`/api/jobs/${jobId}/cancel`, { method: 'POST' });
    toast('任务已立即终止', 3500);
    try {
      const d = await api(`/api/jobs/${jobId}`);
      const j = d.job;
      if (j) {
        const pct = j.total ? Math.round((j.processed / j.total) * 100) : 0;
        $('#job-bar').style.width = pct + '%';
        $('#job-state').textContent = '已取消';
        $('#job-stats').innerHTML =
          `<div class="job-counts">总数 ${j.total} · 处理 ${j.processed} · <span class="ok">成功 ${j.succeeded}</span> · <span class="fail">失败 ${j.failed}</span> · <span class="warn">跳过 ${j.skipped}</span></div>`
          + renderReasons(j.reasons || {});
        clearInterval(jobTimer);
        CURRENT_JOB_ID = null;
        toast(`已取消：已处理 ${j.processed}，成功 ${j.succeeded}，失败 ${j.failed}，跳过 ${j.skipped}`, 5000);
        await refreshAll();
      }
    } catch (_) { /* 轮询失败不影响取消结果 */ }
  } catch (e) {
    toast(`终止失败：${e.message}`, 4200);
    $('#job-state').textContent = '运行中';
  } finally {
    btn.disabled = false;
  }
};

$('#concurrency').onchange = async () => {
  const val = parseInt($('#concurrency').value, 10);
  if (!val || val < 1 || val > 100) { toast('并发数必须在 1-100 之间', 3000); return; }
  try {
    await api('/api/config', { method: 'PUT', body: JSON.stringify({ default_concurrency: val }) });
    toast('并发数已保存');
  } catch (e) { toast(`保存失败：${e.message}`, 4200); }
};

$('#test-untested-btn').onclick = async () => {
  const concurrency = parseInt($('#concurrency').value, 10) || 24;
  try {
    const d = await api('/api/accounts/batch/test-untested', { method: 'POST', body: JSON.stringify({ concurrency }) });
    toast(`一键测试未测试 已启动，共 ${d.total} 个，并发 ${d.concurrency}`);
    pollJob(d.job_id, '一键测试未测试');
  } catch (e) { toast(`启动失败：${e.message}`, 4200); }
};

$('#test-missing-registration-btn').onclick = async () => {
  const concurrency = parseInt($('#concurrency').value, 10) || 24;
  try {
    const d = await api('/api/accounts/batch/test-missing-registration', { method: 'POST', body: JSON.stringify({ concurrency }) });
    toast(`补测注册/存活时间 已启动，共 ${d.total} 个，并发 ${d.concurrency}`);
    pollJob(d.job_id, '补测注册/存活时间');
  } catch (e) { toast(`启动失败：${e.message}`, 4200); }
};

$('#sync-never-synced-btn').onclick = async () => {
  const concurrency = parseInt($('#concurrency').value, 10) || 24;
  try {
    const d = await api('/api/accounts/batch/sync-never-synced', { method: 'POST', body: JSON.stringify({ concurrency }) });
    toast(`一键同步未上传 已启动，共 ${d.total} 个，并发 ${d.concurrency}`);
    pollJob(d.job_id, '一键同步未上传');
  } catch (e) { toast(`启动失败：${e.message}`, 4200); }
};

$('#reconcile-remote-btn').onclick = async () => {
  if (!confirm('开始校准？将上传正常账号，并从远程批量分组移除本地封禁或已不存在的账号。')) return;
  const concurrency = parseInt($('#concurrency').value, 10) || 24;
  try {
    const d = await api('/api/remote/reconcile', { method: 'POST', body: JSON.stringify({ concurrency }) });
    toast(`远程校准已启动，正常 ${d.normal} 个，封禁 ${d.banned} 个`);
    pollJob(d.job_id, '校准本地与远程');
  } catch (e) { toast(`启动失败：${e.message}`, 4200); }
};

// 侧栏导航高亮：点击即时高亮 + 滚动时按当前区块自动高亮
const navLinks = Array.from(document.querySelectorAll('.nav a'));
function setActive(hash) {
  navLinks.forEach((a) => a.classList.toggle('active', a.getAttribute('href') === hash));
}
navLinks.forEach((a) => a.addEventListener('click', () => setActive(a.getAttribute('href'))));
const spySections = ['overview', 'import', 'tasks', 'accounts', 'config', 'logs']
  .map((id) => document.getElementById(id)).filter(Boolean);
if ('IntersectionObserver' in window) {
  const spy = new IntersectionObserver((entries) => {
    const visible = entries.filter((e) => e.isIntersecting)
      .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
    if (visible[0]) setActive('#' + visible[0].target.id);
  }, { rootMargin: '-45% 0px -50% 0px', threshold: [0, 0.1, 0.5, 1] });
  spySections.forEach((s) => spy.observe(s));
}

loadConfig().catch(() => {});
syncAliveThresholdInputs();
updateAliveThresholdSummary();
refreshAll().catch((e) => toast(e.message, 4200));
restoreRunningJob().catch(() => {});
