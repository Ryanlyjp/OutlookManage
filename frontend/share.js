const $ = (selector) => document.querySelector(selector);
const token = location.pathname.split('/').filter(Boolean).pop();
const base = `/api/otp-share/page/${encodeURIComponent(token)}`;
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
const formatTime = (value) => value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '-';
function toast(message) { const el = $('#toast'); el.textContent = message; el.classList.remove('hidden'); setTimeout(() => el.classList.add('hidden'), 4000); }
async function api(path) { const response = await fetch(path); const data = await response.json(); if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`); return data; }
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const input = document.createElement('textarea');
    input.value = text; input.style.position = 'fixed'; input.style.opacity = '0';
    document.body.appendChild(input); input.select();
    try { if (!document.execCommand('copy')) throw new Error('复制失败，请手动复制'); }
    finally { input.remove(); }
  }
}
async function otp(data) {
  const target = $('#share-otp-result');
  target.innerHTML = `<strong>${escapeHtml(data.code)}</strong><span>${escapeHtml(data.subject || '')}</span>`;
  target.classList.remove('hidden');
  try { await copyText(String(data.code)); toast('OTP 已复制'); }
  catch { toast('OTP 已提取，自动复制失败，请手动复制'); }
}
async function withLoading(button, action) {
  if (button.disabled) return;
  const original = button.innerHTML;
  button.disabled = true; button.setAttribute('aria-busy', 'true');
  button.innerHTML = '<span class="share-spinner" aria-hidden="true"></span>正在读取…';
  try { await action(); } catch (error) { toast(error.message); }
  finally { button.innerHTML = original; button.disabled = false; button.removeAttribute('aria-busy'); }
}
function renderList(emails) { const target = $('#share-mail-list'); target.innerHTML = emails.map((email) => `<button class="mail-item" data-id="${escapeHtml(email.id)}"><strong>${escapeHtml(email.subject)}</strong><span>${escapeHtml(email.sender)}</span><time>${escapeHtml(formatTime(email.received_at))}</time></button>`).join('') || '<p class="muted">没有邮件</p>'; target.querySelectorAll('button').forEach((button) => button.onclick = () => detail(button.dataset.id).catch((error) => toast(error.message))); }
async function detail(id) { const data = await api(`${base}/emails/${encodeURIComponent(id)}`); const email = data.email; const target = $('#share-mail-detail'); const attachments = (email.attachments || []).filter((item) => !item.inline).map((item) => `<a class="btn ghost sm" href="${base}/emails/${encodeURIComponent(id)}/attachments/${encodeURIComponent(item.id)}">下载 ${escapeHtml(item.filename)}</a>`).join(''); target.innerHTML = `<div class="mail-detail-head"><h2>${escapeHtml(email.subject)}</h2><p>${escapeHtml(email.sender)} · ${escapeHtml(formatTime(email.received_at))}</p><button class="btn primary sm" id="detail-otp">提取 OTP</button></div><div class="mail-body"></div>${attachments ? `<div class="attachments"><h3>附件</h3>${attachments}</div>` : ''}`; const body = target.querySelector('.mail-body'); if (email.body_html) { const frame = document.createElement('iframe'); frame.setAttribute('sandbox', ''); frame.srcdoc = email.body_html; body.appendChild(frame); } else body.innerHTML = `<pre>${escapeHtml(email.body_text || '(无正文)')}</pre>`; $('#detail-otp').onclick = () => withLoading($('#detail-otp'), async () => { $('#share-otp-result').classList.add('hidden'); const data = await api(`${base}/emails/${encodeURIComponent(id)}/otp`); await otp(data.otp); }); }
$('#share-otp-btn').onclick = () => withLoading($('#share-otp-btn'), async () => {
  $('#share-otp-result').classList.add('hidden');
  const data = await api(`${base}/latest`); await otp(data.otp);
});
$('#share-read-btn').onclick = () => withLoading($('#share-read-btn'), async () => {
  const data = await api(`${base}/emails`); renderList(data.emails);
});
api(`${base}/mailbox`).then((data) => {
  const address = data.mailbox.full_address;
  const button = $('#share-mailbox');
  button.textContent = `${address} (可点击复制)`; button.disabled = false;
  button.onclick = () => copyText(address).then(() => toast('邮箱已复制')).catch((error) => toast(error.message));
  $('#share-expiry').textContent = data.expires_at ? `有效至 ${formatTime(data.expires_at)}` : '永久有效';
}).catch((error) => { $('#share-mailbox').textContent = error.message; });
