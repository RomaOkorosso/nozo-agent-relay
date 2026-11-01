/* Nozo Relay panel script. Vanilla JS, no framework, no inline handlers (CSP: default-src 'self').
 *
 * Security notes:
 *  - Authority is the HttpOnly session cookie. The only secret readable here is the CSRF double-submit
 *    cookie, sent as a header on mutations. Nothing is persisted in any browser storage API.
 *  - Server HTML fragments are produced by Jinja2 with autoescape; user text is only ever inserted
 *    with textContent or via those escaped fragments.
 *  - WebSocket auth is the same-origin session cookie; no credential is placed in the URL.
 *  - Offline: commands are NOT queued; a failed/blocked send must be repeated by the user.
 */
(() => {
  'use strict';

  const body = document.body;
  const page = body.dataset.page || '';
  const CSRF_COOKIE = body.dataset.csrfCookie || 'nozo_csrf';
  const CSRF_HEADER = body.dataset.csrfHeader || 'X-CSRF-Token';
  const projectId = body.dataset.projectId || '';
  const taskId = body.dataset.taskId || '';

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  // ------------------------------------------------------------------ helpers
  function readCookie(name) {
    const m = document.cookie.split('; ').find((c) => c.startsWith(name + '='));
    return m ? decodeURIComponent(m.slice(name.length + 1)) : '';
  }

  function uuid() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    const b = crypto.getRandomValues(new Uint8Array(16));
    b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
    const h = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }

  let toastTimer = null;
  function toast(text, kind) {
    const el = $('#toast');
    if (!el) return;
    el.textContent = text;
    el.classList.toggle('toast-error', kind === 'error');
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, kind === 'error' ? 9000 : 5000);
  }

  const timeFmt = (() => {
    try {
      return new Intl.DateTimeFormat('ru-RU', { dateStyle: 'short', timeStyle: 'medium', timeZoneName: 'short' });
    } catch (_e) { return null; }
  })();

  function localizeTimes(root) {
    if (!timeFmt) return;
    $$('time.t[datetime]', root).forEach((el) => {
      const d = new Date(el.getAttribute('datetime'));
      if (Number.isNaN(d.getTime())) return;
      if (!el.title.startsWith('UTC')) el.title = 'UTC: ' + el.textContent.trim();
      el.textContent = timeFmt.format(d);
    });
  }

  const online = () => navigator.onLine !== false;

  class ApiError extends Error {
    constructor(status, payload) {
      const err = (payload && payload.error) || {};
      super(err.message || ('HTTP ' + status));
      this.status = status; this.code = err.code || ''; this.payload = payload;
    }
  }

  async function api(method, url, opts = {}) {
    if (!online()) {
      throw new ApiError(0, { error: { message: 'Нет сети: команда не отправлена. Повторите, когда связь появится.' } });
    }
    const headers = { Accept: 'application/json' };
    if (method !== 'GET') {
      headers[CSRF_HEADER] = readCookie(CSRF_COOKIE);
      if (opts.idem !== false) headers['Idempotency-Key'] = opts.idem || uuid();
    }
    if (opts.json !== undefined) headers['Content-Type'] = 'application/json';
    if (opts.ifMatch !== undefined) headers['If-Match'] = `"${opts.ifMatch}"`;
    let res;
    try {
      res = await fetch(url, {
        method, headers, credentials: 'same-origin', cache: 'no-store',
        body: opts.json !== undefined ? JSON.stringify(opts.json) : undefined,
      });
    } catch (_e) {
      throw new ApiError(0, { error: { message: 'Не удалось отправить: нет связи с сервером. Команда НЕ поставлена в очередь, повторите вручную.' } });
    }
    let data = null;
    try { data = await res.json(); } catch (_e) { data = null; }
    if (res.status === 401) { window.location.assign('/login'); throw new ApiError(401, data); }
    if (!res.ok) throw new ApiError(res.status, data);
    return { status: res.status, data };
  }

  function explain(e) {
    if (!(e instanceof ApiError)) return 'Ошибка: ' + (e && e.message ? e.message : e);
    if (e.status === 412) return 'Данные устарели — состояние обновлено, повторите действие.';
    if (e.status === 429) return 'Слишком много попыток. Подождите и повторите.';
    return e.message;
  }

  // ------------------------------------------------------------------ connection indicator
  const conn = {
    state: 'connecting', lastSynced: null,
    labels: {
      connecting: 'Подключение…', connected: 'Онлайн (WebSocket)', reconnecting: 'Переподключение…',
      polling: 'Опрос каждые 10 с (WebSocket недоступен)', offline: 'Нет сети',
    },
  };
  function renderConn() {
    const bar = $('#connbar');
    if (!bar) return;
    bar.dataset.state = conn.state;
    $('#conn-label').textContent = conn.labels[conn.state] || conn.state;
    const t = $('#conn-sync');
    t.textContent = conn.lastSynced ? conn.lastSynced.toLocaleTimeString('ru-RU') : '—';
  }
  function setConn(state) { conn.state = state; renderConn(); }
  function markSynced() { conn.lastSynced = new Date(); renderConn(); }

  // ------------------------------------------------------------------ live regions
  const regionHw = new Map();
  let refreshTimer = null; let refreshing = false; let again = false;

  function busy(el) {
    return el.dataset.skipBusy === '1' && (el.matches(':focus-within') || el.querySelector('details[open]'));
  }
  function swap(el, html) {
    const tpl = document.createElement('template');
    tpl.innerHTML = html;
    const root = tpl.content.firstElementChild;
    const hw = root && Number(root.dataset.hw);
    if (hw) regionHw.set(el.dataset.region, hw);
    localizeTimes(tpl.content);
    el.replaceChildren(tpl.content);
  }

  async function fetchText(url) {
    const res = await fetch(url, { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'text/html' } });
    if (res.status === 401) { window.location.assign('/login'); throw new Error('unauthenticated'); }
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return res.text();
  }

  async function refreshRegions() {
    const els = $$('[data-region]');
    await Promise.all(els.map(async (el) => {
      if (busy(el)) { setTimeout(scheduleRefresh, 1500); return; }
      swap(el, await fetchText(el.dataset.url));
    }));
    const chat = $('[data-chat]');
    if (chat) await refreshChat(chat);
  }

  function scheduleRefresh(delay = 200) {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(runRefresh, delay);
  }
  async function runRefresh() {
    if (!online()) return;
    if (refreshing) { again = true; return; }
    refreshing = true;
    try {
      await refreshRegions();
      markSynced();
    } catch (_e) { /* next event / poll retries; indicator shows connectivity */ }
    refreshing = false;
    if (again) { again = false; scheduleRefresh(100); }
  }
  const refreshNow = () => { clearTimeout(refreshTimer); return runRefresh(); };

  // ------------------------------------------------------------------ chat
  function nearBottom(sc) { return sc.scrollHeight - sc.scrollTop - sc.clientHeight < 80; }

  function mergeMessages(list, fragRoot) {
    let added = 0;
    const existing = new Map($$('[data-msg-id]', list).map((li) => [li.dataset.msgId, li]));
    $$('li[data-msg-id]', fragRoot).forEach((li) => {
      if (existing.has(li.dataset.msgId)) return; // dedup by message id
      const node = document.importNode(li, true);
      const key = node.dataset.key;
      const next = $$('[data-msg-id]', list).find((x) => x.dataset.key > key);
      if (next) list.insertBefore(node, next); else list.appendChild(node);
      existing.set(node.dataset.msgId, node);
      added += 1;
    });
    return added;
  }

  function chatQuery(section, extra) {
    const p = new URLSearchParams();
    const scoped = section.dataset.taskId;
    if (scoped) p.set('task_id', scoped);
    $$('[data-chat-filter]', section).forEach((s) => { if (s.value) p.set(s.dataset.chatFilter, s.value); });
    Object.entries(extra || {}).forEach(([k, v]) => { if (v) p.set(k, v); });
    const q = p.toString();
    return section.dataset.url + (q ? '?' + q : '');
  }

  function parseFrag(html) {
    const tpl = document.createElement('template');
    tpl.innerHTML = html;
    localizeTimes(tpl.content);
    return tpl.content.querySelector('.chat-frag');
  }

  function syncChatChrome(section) {
    const list = $('[data-live-list]', section);
    const empty = $('[data-chat-empty]', section);
    if (empty) empty.hidden = list.children.length > 0;
    const older = $('[data-act="older"]', section);
    if (older) older.hidden = !section.dataset.older;
  }

  async function refreshChat(section, reset = false) {
    const list = $('[data-live-list]', section);
    const sc = $('[data-chat-scroll]', section);
    const stick = nearBottom(sc);
    const frag = parseFrag(await fetchText(chatQuery(section)));
    if (!frag) return;
    if (reset) {
      list.replaceChildren();
      section.dataset.older = frag.dataset.older || '';
    }
    mergeMessages(list, frag);
    syncChatChrome(section);
    if (stick || reset) sc.scrollTop = sc.scrollHeight;
  }

  async function loadOlder(section) {
    const cursor = section.dataset.older;
    if (!cursor) return;
    const list = $('[data-live-list]', section);
    const sc = $('[data-chat-scroll]', section);
    const prevH = sc.scrollHeight;
    const frag = parseFrag(await fetchText(chatQuery(section, { before: cursor })));
    if (!frag) return;
    mergeMessages(list, frag);
    section.dataset.older = frag.dataset.older || '';
    syncChatChrome(section);
    sc.scrollTop = sc.scrollHeight - prevH; // keep the viewport anchored
  }

  function initChat() {
    const section = $('[data-chat]');
    if (!section) return;
    const sc = $('[data-chat-scroll]', section);
    sc.scrollTop = sc.scrollHeight;
    syncChatChrome(section);
    localizeTimes(section);
    $$('[data-chat-filter]', section).forEach((s) => s.addEventListener('change', () => {
      refreshChat(section, true).catch((e) => toast(explain(e), 'error'));
    }));
    const form = $('form.composer', section);
    if (!form) return;
    const bar = $('[data-reply-bar]', form);
    const setReply = (id, author, snippet) => {
      form.dataset.replyTo = id || '';
      bar.hidden = !id;
      $('[data-reply-author]', bar).textContent = author || '';
      $('[data-reply-snippet]', bar).textContent = snippet || '';
    };
    section.addEventListener('click', (ev) => {
      const t = ev.target.closest('[data-act]');
      if (!t) return;
      if (t.dataset.act === 'reply') {
        setReply(t.dataset.replyId, t.dataset.replyAuthor, t.dataset.replySnippet);
        $('textarea', form).focus();
      } else if (t.dataset.act === 'cancel-reply') {
        setReply('', '', '');
      } else if (t.dataset.act === 'older') {
        loadOlder(section).catch((e) => toast(explain(e), 'error'));
      }
    });
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const text = form.elements.body.value.trim();
      if (!text) return;
      const payload = {
        kind: form.elements.kind.value, body: text,
        task_id: form.dataset.task || (form.elements.task_id ? form.elements.task_id.value : '') || null,
        reply_to: form.dataset.replyTo || null,
      };
      // Same content => same ids, so a retry after a network error cannot post twice.
      const sig = JSON.stringify(payload);
      if (form._sig !== sig) { form._sig = sig; form._cmid = uuid(); form._idem = uuid(); }
      const btn = $('button[type=submit]', form);
      btn.disabled = true;
      try {
        await api('POST', `/api/v1/projects/${form.dataset.project}/messages`,
          { json: { client_message_id: form._cmid, ...payload }, idem: form._idem });
        form.elements.body.value = '';
        form._sig = null; setReply('', '', '');
        await refreshChat(section);
        $('[data-chat-scroll]', section).scrollTop = 1e9;
        markSynced();
      } catch (e) { toast(explain(e), 'error'); } finally { btn.disabled = false; }
    });
  }

  // ------------------------------------------------------------------ commands
  const reasonText = (fallback) => {
    const el = $('#reason');
    const v = el && el.value.trim();
    return v || fallback;
  };

  async function currentTask() {
    const r = await api('GET', `/api/v1/projects/${projectId}/tasks/${taskId}`);
    return r.data;
  }

  function describeControl(res, verb) {
    const ctl = (res.data && res.data.control) || {};
    if (res.status === 202 || ctl.status === 'requested' || ctl.status === 'stopping') {
      return `${verb}: ЗАПРОШЕНО. Остановка не подтверждена, пока runner не пришлёт квитанцию.`;
    }
    if (ctl.status === 'unknown') return `${verb}: остановка НЕ подтверждена.`;
    return `${verb}: выполнено.`;
  }

  async function taskControl(btn) {
    const command = btn.dataset.command;
    const verbs = { pause: 'Пауза', resume: 'Продолжить', cancel: 'Отмена', complete: 'Завершение', reassign: 'Переназначение' };
    const payload = { command, reason: reasonText('Из панели владельца: ' + (verbs[command] || command)) };
    if (command === 'reassign') {
      const scope = btn.closest('.fold-body') || document;
      $$('[data-reassign]', scope).forEach((s) => { if (s.value) payload[s.name] = s.value; });
      if (!payload.implementer_id && !payload.auditor_id) { toast('Выберите нового исполнителя или аудитора.', 'error'); return; }
    }
    const task = await currentTask();
    const res = await api('POST', `/api/v1/projects/${projectId}/tasks/${taskId}/controls`, { json: payload, ifMatch: task.version });
    toast(describeControl(res, verbs[command] || command));
  }

  async function enqueue() {
    const task = await currentTask();
    await api('POST', `/api/v1/projects/${projectId}/tasks/${taskId}/enqueue`, { ifMatch: task.version });
    toast('Задача поставлена в очередь.');
  }

  async function projectControl(btn) {
    const command = btn.dataset.command;
    const res = await api('POST', `/api/v1/projects/${btn.dataset.project}/controls`,
      { json: { command, reason: reasonText(command === 'pause' ? 'Пауза проекта из панели' : 'Продолжение из панели') } });
    toast(describeControl(res, command === 'pause' ? 'Пауза проекта' : 'Продолжение проекта'));
    if (res.status < 300) setTimeout(() => window.location.reload(), 600);
  }

  async function emergencyStop() {
    const res = await api('POST', '/api/v1/controls/emergency-stop', { json: { reason: reasonText('Аварийная остановка из панели') } });
    toast(describeControl(res, 'Аварийная остановка'), 'error');
    setTimeout(() => window.location.reload(), 900);
  }

  async function logout() {
    try { await api('POST', '/api/v1/auth/logout'); } catch (_e) { /* cookie cleared server-side or already invalid */ }
    window.location.assign('/login');
  }

  async function guarded(btn, fn) {
    btn.disabled = true;
    try { await fn(); await refreshNow(); } catch (e) {
      toast(explain(e), 'error');
      if (e instanceof ApiError && (e.status === 412 || e.status === 409)) scheduleRefresh(50);
    } finally { btn.disabled = false; }
  }

  function initCommands() {
    document.addEventListener('click', (ev) => {
      const btn = ev.target.closest('button[data-act]');
      if (!btn) return;
      const act = btn.dataset.act;
      if (act === 'logout') { ev.preventDefault(); logout(); }
      else if (act === 'control') guarded(btn, () => taskControl(btn));
      else if (act === 'enqueue') guarded(btn, enqueue);
      else if (act === 'project-control') guarded(btn, () => projectControl(btn));
      else if (act === 'emergency-stop') guarded(btn, emergencyStop);
    });
  }

  function lines(v) { return v.split('\n').map((s) => s.trim()).filter(Boolean); }

  function initTaskCreate() {
    const form = $('form[data-kind="task-create"]');
    if (!form) return;
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const f = form.elements;
      const payload = {
        title: f.title.value.trim(), requirements: f.requirements.value.trim(),
        acceptance: lines(f.acceptance.value), implementer_id: f.implementer_id.value, auditor_id: f.auditor_id.value,
        mode: f.mode.value, autonomous: f.autonomous.checked, urgency: f.urgency.value,
        scope: {
          allowed_paths: lines(f.allowed_paths.value), denied_paths: lines(f.denied_paths.value),
          max_changed_files: Number(f.max_changed_files.value), max_diff_lines: Number(f.max_diff_lines.value),
          allow_new_dependencies: false,
        },
      };
      if (form.dataset.delegationId) payload.delegation_id = form.dataset.delegationId;
      const sig = JSON.stringify(payload);
      if (form._sig !== sig) { form._sig = sig; form._idem = uuid(); }
      const btn = $('button[type=submit]', form);
      btn.disabled = true;
      try {
        const res = await api('POST', `/api/v1/projects/${form.dataset.project}/tasks`, { json: payload, idem: form._idem });
        const created = res.data;
        if (f.enqueue.checked) {
          await api('POST', `/api/v1/projects/${form.dataset.project}/tasks/${created.id}/enqueue`, { ifMatch: created.version });
        }
        window.location.assign(`/projects/${form.dataset.project}/tasks/${created.id}`);
      } catch (e) { toast(explain(e), 'error'); btn.disabled = false; }
    });
  }

  function initLogin() {
    // HTML form posts to /login (no fetch). Free tunnels + remote browsers drop/break JSON login.
  }

  // ------------------------------------------------------------------ tabs
  function activateTab(name) {
    const panels = $$('[data-tab-panel]');
    if (!panels.some((p) => p.dataset.tabPanel === name)) return;
    panels.forEach((p) => p.classList.toggle('is-active', p.dataset.tabPanel === name));
    $$('[data-tab]').forEach((t) => t.classList.toggle('is-active', t.dataset.tab === name));
    if (name === 'chat') { const sc = $('[data-chat-scroll]'); if (sc) sc.scrollTop = sc.scrollHeight; }
  }
  function initTabs() {
    $$('[data-tab]').forEach((t) => t.addEventListener('click', () => {
      activateTab(t.dataset.tab);
      history.replaceState(null, '', '#' + t.dataset.tab);
    }));
    const fromHash = () => {
      const h = location.hash.slice(1);
      if (h.startsWith('report-')) {
        activateTab('reports');
        const d = document.getElementById(h); if (d) { d.open = true; d.scrollIntoView(); }
      } else if (h) activateTab(h);
    };
    window.addEventListener('hashchange', fromHash);
    fromHash();
  }

  // ------------------------------------------------------------------ WebSocket (durable events)
  const ws = {
    sock: null, lastSeq: Number(body.dataset.hw) || 0, seen: new Set(), attempts: 0, retry: null,
    watchdog: null, poll: null, everReady: false, wantResync: false,
  };
  const BACKOFF = [1000, 2000, 4000, 8000, 15000, 30000];

  function minHw() {
    const v = Array.from(regionHw.values()).filter(Boolean);
    return v.length ? Math.min(...v) : ws.lastSeq;
  }
  function clearWatchdog() { clearTimeout(ws.watchdog); }
  function armWatchdog() {
    clearWatchdog();
    ws.watchdog = setTimeout(() => { if (ws.sock) ws.sock.close(); }, 50000); // > 2 heartbeats of 20 s
  }
  function startPolling() {
    if (ws.poll) return;
    ws.poll = setInterval(() => { if (online()) refreshNow(); }, 10000);
  }
  function stopPolling() { clearInterval(ws.poll); ws.poll = null; }

  function scheduleReconnect(immediate) {
    clearTimeout(ws.retry);
    if (!online()) { setConn('offline'); return; }
    ws.attempts += 1;
    if (ws.attempts >= 3) { setConn('polling'); startPolling(); } else setConn('reconnecting');
    const delay = immediate ? 200 : BACKOFF[Math.min(ws.attempts - 1, BACKOFF.length - 1)] * (0.75 + Math.random() * 0.5);
    ws.retry = setTimeout(connectWs, delay);
  }

  function handleFrame(frame) {
    armWatchdog();
    if (frame.type === 'heartbeat') { markSynced(); return; }
    if (frame.type === 'ready') {
      const reconnect = ws.everReady;
      ws.everReady = true; ws.attempts = 0; stopPolling(); setConn('connected'); markSynced();
      if (reconnect || ws.wantResync) { ws.wantResync = false; refreshNow(); }
      return;
    }
    if (frame.type === 'resync_required') { ws.wantResync = true; return; }
    if (frame.event_id === undefined || frame.seq === undefined) return;
    // At-least-once on the wire, exactly-once in the UI: dedupe by seq and event_id.
    if (frame.seq <= ws.lastSeq || ws.seen.has(frame.event_id)) return;
    ws.lastSeq = frame.seq;
    ws.seen.add(frame.event_id);
    if (ws.seen.size > 1000) ws.seen.delete(ws.seen.values().next().value);
    markSynced();
    scheduleRefresh(150);
  }

  function connectWs() {
    clearTimeout(ws.retry);
    if (ws.sock) { try { ws.sock.close(); } catch (_e) { /* ignore */ } }
    if (!online()) { setConn('offline'); return; }
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    let sock;
    try {
      sock = new WebSocket(`${proto}//${location.host}${body.dataset.wsPath}?after_seq=${ws.lastSeq}`);
    } catch (_e) { scheduleReconnect(false); return; }
    ws.sock = sock;
    sock.onopen = () => armWatchdog();
    sock.onmessage = (m) => { try { handleFrame(JSON.parse(m.data)); } catch (_e) { /* ignore malformed */ } };
    sock.onclose = async (ev) => {
      if (ws.sock !== sock) return;
      ws.sock = null; clearWatchdog();
      if (ev.code === 4401) { window.location.assign('/login'); return; }
      if (ev.code === 4410 || ev.code === 4411 || ws.wantResync) {
        // Fresh snapshot first, then resume from the oldest watermark of what was just rendered.
        ws.wantResync = false; regionHw.clear();
        try { await refreshNow(); ws.lastSeq = minHw(); ws.seen.clear(); } catch (_e) { /* retry below */ }
      }
      scheduleReconnect(false);
    };
    sock.onerror = () => { /* onclose follows */ };
  }

  function initLive() {
    if (!body.dataset.wsPath) return;
    renderConn();
    window.addEventListener('offline', () => { setConn('offline'); stopPolling(); if (ws.sock) ws.sock.close(); });
    window.addEventListener('online', () => { ws.attempts = 0; connectWs(); refreshNow(); });
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible' && conn.state !== 'connected') { ws.attempts = 0; connectWs(); }
      if (document.visibilityState === 'visible') scheduleRefresh(50);
    });
    if (!online()) setConn('offline'); else connectWs();
  }

  // ------------------------------------------------------------------ boot
  localizeTimes(document);
  initLogin();
  initTabs();
  initChat();
  initCommands();
  initTaskCreate();
  initLive();
  document.addEventListener('DOMContentLoaded', () => localizeTimes(document));
})();
