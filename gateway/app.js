(() => {
  const STORE_BASE = "nozo_gw_base";
  const STORE_KEY = "nozo_gw_key";
  const STORE_IMPL = "nozo_gw_impl";
  const STORE_AUD = "nozo_gw_aud";
  const STORE_DEL = "nozo_gw_delegation";
  const STORE_PENDING_TASK = "nozo_gw_pending_task";
  const STORE_PENDING_MSG = "nozo_gw_pending_msg";
  const STORE_DRAFT_MSG = "nozo_gw_draft_msg";
  const STORE_DRAFT_TASK = "nozo_gw_draft_task";
  const MAX_ACCEPTANCE = 30;
  const MAX_PATHS = 100;
  const LIST_PAGE_LIMIT = 50;
  const MAX_LIST_PAGES = 40;
  const POINTER_URL = new URL("pointer.json", location.href).href;
  const POLL_MS = 15000;

  const $ = (sel, el = document) => el.querySelector(sel);
  const connectPanel = $("#connect-panel");
  const appPanel = $("#app-panel");
  const connChip = $("#conn-chip");
  const connectErr = $("#connect-error");
  const msgErr = $("#msg-error");
  const msgOk = $("#msg-ok");
  const taskErr = $("#task-error");
  const taskOk = $("#task-ok");
  const projectSelect = $("#project-select");
  const taskList = $("#task-list");
  const messagesEl = $("#messages");
  const whoami = $("#whoami");
  const taskForm = $("#task-form");
  const msgForm = $("#msg-form");
  const btnCreate = $("#btn-create-task");
  const btnSend = $("#btn-send-msg");

  let state = { base: "", key: "", projectId: null, me: null, selectedTaskId: null };
  /** @type {{ idempotencyKey: string, projectId: string, payload: object } | null} */
  let pendingTask = null;
  /** @type {{ idempotencyKey: string, clientMessageId: string, projectId: string, body: string, taskId: string|null } | null} */
  let pendingMsg = null;
  let pollTimer = null;
  let recovering = false;
  /** @type {object[]} */
  let cachedTasks = [];
  /** @type {object|null} */
  let selectedTask = null;

  const STATE_LABEL = {
    idle: "не подключено",
    connecting: "подключение…",
    connected: "подключено",
    lost: "связь потеряна",
    recovering: "восстановление…",
    auth: "требуется вход",
  };

  function setConnState(s, detail) {
    connChip.dataset.state = s;
    connChip.textContent = detail || STATE_LABEL[s] || s;
  }

  function uuid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    const b = crypto.getRandomValues(new Uint8Array(16));
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }

  function normalizeBase(url) {
    return String(url || "").trim().replace(/\/+$/, "");
  }

  function isUuid(v) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(v || "").trim());
  }

  function stableJson(obj) {
    return JSON.stringify(obj);
  }

  function classifyFetchFailure(err, res, text) {
    if (res && (res.status === 401 || res.status === 403)) {
      const code = (() => {
        try { return JSON.parse(text || "{}").error?.code; } catch { return null; }
      })();
      if (res.status === 401 || code === "unauthenticated" || code === "credential_revoked") {
        return { kind: "auth", message: "Ключ отклонён или истёк. Введите coordinator Bearer заново." };
      }
      return { kind: "http", message: (JSON.parse(text || "{}").error?.message) || `HTTP ${res.status}` };
    }
    if (!res) {
      const msg = err && err.message ? err.message : String(err || "NetworkError");
      if (/Failed to fetch|NetworkError|network/i.test(msg)) {
        return { kind: "network", message: "Сеть/туннель недоступны (Failed to fetch). Проверьте, что ноутбук онлайн и Funnel жив." };
      }
      return { kind: "network", message: msg };
    }
    const looksHtml = /^\s*</.test(text || "");
    if (looksHtml) {
      return { kind: "html", message: "Вместо JSON пришёл HTML (заглушка провайдера/прокси). Relay URL неверный или туннель не тот." };
    }
    try {
      const data = text ? JSON.parse(text) : null;
      const msg = (data && data.error && data.error.message) || `HTTP ${res.status}`;
      return { kind: "http", message: msg, status: res.status, data };
    } catch {
      return { kind: "http", message: `Не JSON от Relay (HTTP ${res.status}).` };
    }
  }

  function loadJson(key) {
    try {
      const raw = sessionStorage.getItem(key);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  function saveJson(key, val) {
    if (val == null) sessionStorage.removeItem(key);
    else sessionStorage.setItem(key, JSON.stringify(val));
  }

  function loadPending() {
    const parsed = loadJson(STORE_PENDING_TASK);
    if (!parsed || !parsed.idempotencyKey || !parsed.payload || !parsed.projectId) return null;
    return parsed;
  }

  function savePending(p) {
    pendingTask = p;
    saveJson(STORE_PENDING_TASK, p);
    updatePendingUi();
  }

  function clearPending() {
    savePending(null);
  }

  function loadPendingMsg() {
    const p = loadJson(STORE_PENDING_MSG);
    if (!p || !p.idempotencyKey || !p.clientMessageId || !p.projectId || !p.body) return null;
    return p;
  }

  function savePendingMsg(p) {
    pendingMsg = p;
    saveJson(STORE_PENDING_MSG, p);
    updatePendingMsgUi();
  }

  function clearPendingMsg() {
    savePendingMsg(null);
  }

  function updatePendingUi() {
    if (!btnCreate || !taskForm) return;
    let discard = $("#btn-discard-pending");
    if (pendingTask) {
      if (!discard) {
        discard = document.createElement("button");
        discard.type = "button";
        discard.id = "btn-discard-pending";
        discard.className = "btn";
        discard.textContent = "Сбросить незавершённую отправку";
        discard.addEventListener("click", () => {
          clearPending();
          taskErr.hidden = true;
          taskOk.hidden = false;
          taskOk.textContent = "Незавершённая отправка сброшена. Можно создать новую задачу.";
        });
        btnCreate.insertAdjacentElement("afterend", discard);
      }
      discard.hidden = false;
      btnCreate.textContent = "Повторить создание (тот же запрос)";
    } else {
      if (discard) discard.hidden = true;
      btnCreate.textContent = "Создать задачу";
    }
  }

  function updatePendingMsgUi() {
    if (!btnSend || !msgForm) return;
    let discard = $("#btn-discard-pending-msg");
    if (pendingMsg) {
      if (!discard) {
        discard = document.createElement("button");
        discard.type = "button";
        discard.id = "btn-discard-pending-msg";
        discard.className = "btn";
        discard.textContent = "Сбросить сообщение";
        discard.addEventListener("click", () => {
          clearPendingMsg();
          msgErr.hidden = true;
          msgOk.hidden = false;
          msgOk.textContent = "Черновик сброса. Можно отправить новый текст.";
        });
        btnSend.insertAdjacentElement("afterend", discard);
      }
      discard.hidden = false;
      btnSend.textContent = pendingMsg.outcome === "final" ? "Отправка отклонена — сбросьте" : "Повторить отправку";
    } else {
      if (discard) discard.hidden = true;
      btnSend.textContent = "Отправить";
    }
  }

  /**
   * Trust model (SA-05): Bearer is sent only to https URLs without userinfo.
   * Values from same-origin pointer.json are trusted (Pages is the trust root).
   * Manual/?relay= URLs must match known transport host suffixes.
   */
  function isTrustedRelayBase(url, { fromPointer = false } = {}) {
    try {
      const u = new URL(normalizeBase(url));
      if (u.protocol !== "https:") return false;
      if (u.username || u.password) return false;
      if (!u.hostname || u.hostname.includes("..")) return false;
      if (fromPointer) return true;
      if (u.hostname.endsWith(".ts.net")) return true;
      const suffixes = [
        ".lhr.life",
        ".localhost.run",
        ".trycloudflare.com",
        ".pinggy.link",
        ".pinggy.net",
        ".tunnl.gg",
        ".bore.pub",
      ];
      return suffixes.some((s) => u.hostname.endsWith(s));
    } catch {
      return false;
    }
  }

  function applyPayloadToForm(payload) {
    if (!taskForm || !payload) return;
    taskForm.elements.title.value = payload.title || "";
    taskForm.elements.requirements.value = payload.requirements || "";
    taskForm.elements.acceptance.value = (payload.acceptance || []).join("\n");
    taskForm.elements.implementer_id.value = payload.implementer_id || "";
    taskForm.elements.auditor_id.value = payload.auditor_id || "";
    taskForm.elements.delegation_id.value = payload.delegation_id || "";
    taskForm.elements.paths.value = ((payload.scope && payload.scope.allowed_paths) || []).join("\n");
    taskForm.elements.mode.value = payload.mode || "surgical";
    taskForm.elements.autonomous.checked = !!payload.autonomous;
  }

  function persistDrafts() {
    if (msgForm) saveJson(STORE_DRAFT_MSG, { body: msgForm.elements.body.value || "" });
    if (taskForm) {
      saveJson(STORE_DRAFT_TASK, {
        title: taskForm.elements.title.value,
        requirements: taskForm.elements.requirements.value,
        acceptance: taskForm.elements.acceptance.value,
        implementer_id: taskForm.elements.implementer_id.value,
        auditor_id: taskForm.elements.auditor_id.value,
        delegation_id: taskForm.elements.delegation_id.value,
        paths: taskForm.elements.paths.value,
        mode: taskForm.elements.mode.value,
        autonomous: !!taskForm.elements.autonomous.checked,
      });
    }
  }

  function restoreDrafts() {
    const md = loadJson(STORE_DRAFT_MSG);
    if (md && msgForm && !msgForm.elements.body.value) msgForm.elements.body.value = md.body || "";
    const td = loadJson(STORE_DRAFT_TASK);
    if (td && taskForm && !taskForm.elements.title.value) {
      taskForm.elements.title.value = td.title || "";
      taskForm.elements.requirements.value = td.requirements || "";
      taskForm.elements.acceptance.value = td.acceptance || "";
      if (td.implementer_id) taskForm.elements.implementer_id.value = td.implementer_id;
      if (td.auditor_id) taskForm.elements.auditor_id.value = td.auditor_id;
      if (td.delegation_id) taskForm.elements.delegation_id.value = td.delegation_id;
      if (td.paths) taskForm.elements.paths.value = td.paths;
      if (td.mode) taskForm.elements.mode.value = td.mode;
      taskForm.elements.autonomous.checked = !!td.autonomous;
    }
  }

  async function api(path, { method = "GET", body = null, idempotencyKey = null, ifMatch = null } = {}) {
    const headers = {
      Authorization: `Bearer ${state.key}`,
      Accept: "application/json",
    };
    if (body != null) headers["Content-Type"] = "application/json";
    if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
    if (ifMatch != null && ifMatch !== "") headers["If-Match"] = `"${ifMatch}"`;
    let res;
    try {
      res = await fetch(`${state.base}${path}`, {
        method,
        headers,
        body: body != null ? JSON.stringify(body) : undefined,
        credentials: "omit",
        redirect: "error",
      });
    } catch (e) {
      const c = classifyFetchFailure(e, null, null);
      const err = new Error(c.message);
      err.kind = c.kind;
      throw err;
    }
    const text = await res.text();
    if (!res.ok) {
      const c = classifyFetchFailure(null, res, text);
      const err = new Error(c.message);
      err.kind = c.kind;
      err.status = res.status;
      err.data = c.data;
      if (c.kind === "auth") {
        setConnState("auth");
        sessionStorage.removeItem(STORE_KEY);
        showConnect(c.message);
      }
      throw err;
    }
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      const c = classifyFetchFailure(null, res, text);
      const err = new Error(c.message);
      err.kind = c.kind;
      throw err;
    }
    const etag = res.headers.get("ETag");
    if (data && typeof data === "object" && etag && data.version == null) {
      const n = Number(String(etag).replace(/W\//i, "").replace(/"/g, ""));
      if (Number.isFinite(n)) data.version = n;
    }
    return data;
  }

  function showConnect(errText) {
    stopPoll();
    connectPanel.hidden = false;
    appPanel.hidden = true;
    $("#btn-disconnect").hidden = true;
    if (!errText || connChip.dataset.state !== "auth") setConnState("idle");
    if (errText) {
      connectErr.hidden = false;
      connectErr.textContent = errText;
    } else {
      connectErr.hidden = true;
    }
  }

  function showApp() {
    connectPanel.hidden = true;
    appPanel.hidden = false;
    $("#btn-disconnect").hidden = false;
    setConnState("connected", state.base.replace(/^https?:\/\//, ""));
  }

  function fillTaskDefaults() {
    if (!taskForm) return;
    const impl = sessionStorage.getItem(STORE_IMPL);
    const aud = sessionStorage.getItem(STORE_AUD);
    const del = sessionStorage.getItem(STORE_DEL);
    if (impl && !taskForm.elements.implementer_id.value) taskForm.elements.implementer_id.value = impl;
    if (aud && !taskForm.elements.auditor_id.value) taskForm.elements.auditor_id.value = aud;
    if (del && !taskForm.elements.delegation_id.value) taskForm.elements.delegation_id.value = del;
  }

  function restorePendingAfterConnect() {
    pendingTask = loadPending();
    updatePendingUi();
    pendingMsg = loadPendingMsg();
    updatePendingMsgUi();
    if (pendingMsg && msgForm) msgForm.elements.body.value = pendingMsg.body;
    if (!pendingTask) return;
    if (pendingTask.projectId && state.projectId && pendingTask.projectId !== state.projectId) {
      taskErr.hidden = false;
      taskErr.textContent = "Есть незавершённая отправка для другого проекта. Сбросьте её или переключите проект.";
      return;
    }
    applyPayloadToForm(pendingTask.payload);
    taskOk.hidden = false;
    taskOk.textContent = "Найдена незавершённая отправка (ответ мог потеряться). Нажмите «Повторить» с тем же телом — дубль не создастся. Или сбросьте.";
  }

  /** @type {string[]} */
  let pointerCandidates = [];

  async function fetchPointerDoc() {
    try {
      const res = await fetch(POINTER_URL, {
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  }

  function candidatesFromPointer(data) {
    if (!data) return [];
    const out = [];
    const push = (u) => {
      const b = normalizeBase(u);
      if (b && isTrustedRelayBase(b, { fromPointer: true }) && !out.includes(b)) out.push(b);
    };
    push(data.relay_base);
    const fb = data.relay_fallbacks;
    if (Array.isArray(fb)) fb.forEach(push);
    return out;
  }

  async function fetchPointerBase() {
    const data = await fetchPointerDoc();
    pointerCandidates = candidatesFromPointer(data);
    return pointerCandidates[0] || null;
  }

  async function connectWithFailover(bases, key) {
    const list = (bases || []).filter(Boolean);
    let lastErr = null;
    for (const base of list) {
      try {
        await connect(base, key);
        return;
      } catch (e) {
        lastErr = e;
        if (e.kind === "auth") throw e;
        // network/html → try next trusted candidate
      }
    }
    throw lastErr || new Error("Нет доступного Relay URL");
  }

  async function connect(base, key) {
    setConnState("connecting");
    state.base = normalizeBase(base);
    state.key = String(key || "").trim();
    if (!state.base || !state.key) throw new Error("Нужны URL и ключ");
    if (/\?/.test(state.key) || state.key.includes("http")) {
      throw new Error("В поле ключа нужен Bearer nzr_…, не URL и не пароль логина");
    }
    const me = await api("/api/v1/me");
    state.me = me;
    sessionStorage.setItem(STORE_BASE, state.base);
    sessionStorage.setItem(STORE_KEY, state.key);
    whoami.textContent = `${me.principal.display_name} (${me.principal.kind})`;
    const memberships = me.memberships || [];
    projectSelect.innerHTML = "";
    for (const m of memberships) {
      const opt = document.createElement("option");
      opt.value = m.project_id;
      opt.textContent = `${m.name || m.slug} (${m.role})`;
      projectSelect.appendChild(opt);
    }
    if (!memberships.length) throw new Error("Нет проектов у этого ключа");
    state.projectId = memberships[0].project_id;
    projectSelect.value = state.projectId;
    fillTaskDefaults();
    restoreDrafts();
    showApp();
    restorePendingAfterConnect();
    await refresh();
    startPoll();
  }

  async function fetchAllPages(pathBase) {
    const items = [];
    let cursor = null;
    for (let page = 0; page < MAX_LIST_PAGES; page++) {
      const qs = new URLSearchParams({ limit: String(LIST_PAGE_LIMIT) });
      if (cursor) qs.set("cursor", cursor);
      const data = await api(`${pathBase}?${qs}`);
      const batch = data.items || [];
      items.push(...batch);
      cursor = data.next_cursor || null;
      if (!cursor || !batch.length) break;
    }
    return items;
  }

  async function refresh() {
    if (!state.projectId) return;
    msgErr.hidden = true;
    const base = `/api/v1/projects/${state.projectId}`;
    const [tasks, msgs] = await Promise.all([
      fetchAllPages(`${base}/tasks`),
      fetchAllPages(`${base}/messages`),
    ]);
    renderTasks([...tasks].reverse());
    renderMessages(msgs);
    if (state.selectedTaskId && !cachedTasks.some((t) => t.id === state.selectedTaskId)) {
      state.selectedTaskId = null;
      renderTaskDetail(null);
    }
    if (connChip.dataset.state === "lost" || connChip.dataset.state === "recovering") {
      setConnState("connected", state.base.replace(/^https?:\/\//, ""));
    }
  }

  function statusFilterValue() {
    const el = $("#task-status-filter");
    return el ? String(el.value || "") : "";
  }

  function renderTasks(items) {
    cachedTasks = items || [];
    const filter = statusFilterValue();
    const shown = filter ? cachedTasks.filter((t) => t.status === filter) : cachedTasks;
    taskList.innerHTML = "";
    if (!shown.length) {
      taskList.innerHTML = '<li class="muted">Нет задач</li>';
      return;
    }
    for (const t of shown) {
      const li = document.createElement("li");
      li.className = "task-item" + (t.id === state.selectedTaskId ? " selected" : "");
      li.dataset.taskId = t.id;
      const title = t.title || t.summary || t.id;
      li.innerHTML = `<span class="task-status">${t.status || "?"}</span> <span class="task-title"></span>`;
      li.querySelector(".task-title").textContent = title;
      li.title = t.id || "";
      li.tabIndex = 0;
      li.addEventListener("click", () => selectTask(t.id));
      li.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          selectTask(t.id);
        }
      });
      taskList.appendChild(li);
    }
  }

  function renderMessages(items) {
    messagesEl.innerHTML = "";
    for (const m of items) {
      const div = document.createElement("div");
      div.className = "bubble";
      const meta = document.createElement("div");
      meta.className = "meta";
      const taskBit = m.task_id ? ` · task ${String(m.task_id).slice(0, 8)}` : "";
      meta.textContent = `${m.kind || "note"} · ${m.created_at || ""}${taskBit}`;
      const body = document.createElement("div");
      body.textContent = m.body || "";
      div.append(meta, body);
      messagesEl.appendChild(div);
    }
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function setActionFeedback(okText, errText) {
    const ok = $("#task-action-ok");
    const err = $("#task-action-error");
    if (ok) {
      ok.hidden = !okText;
      ok.textContent = okText || "";
    }
    if (err) {
      err.hidden = !errText;
      err.textContent = errText || "";
    }
  }

  function updateTaskActionButtons(task) {
    const st = task && task.status;
    const btnEnq = $("#btn-enqueue");
    const btnPause = $("#btn-pause");
    const btnResume = $("#btn-resume");
    const btnComplete = $("#btn-complete");
    const btnCancel = $("#btn-cancel");
    const terminal = ["cancelled", "completed"].includes(st);
    const idleCompletable = ["draft", "queued", "changes_requested", "awaiting_review", "paused", "blocked"].includes(st);
    if (btnEnq) btnEnq.hidden = st !== "draft";
    if (btnPause) btnPause.hidden = !["queued", "claimed", "running", "awaiting_review", "reviewing", "changes_requested"].includes(st);
    if (btnResume) btnResume.hidden = !["paused", "blocked"].includes(st);
    if (btnComplete) btnComplete.hidden = !idleCompletable;
    if (btnCancel) btnCancel.hidden = terminal || !st;
  }

  function renderTaskDetail(task) {
    const panel = $("#task-detail");
    if (!panel) return;
    if (!task) {
      panel.hidden = true;
      selectedTask = null;
      return;
    }
    selectedTask = task;
    panel.hidden = false;
    const rev = task.current_revision || {};
    const req = rev.requirements || task.requirements || "";
    $("#task-detail-meta").textContent =
      `${task.status || "?"} · v${task.version ?? "?"} · ${task.id || ""}`;
    const body = $("#task-detail-body");
    body.textContent = [
      task.title || "",
      "",
      String(req).slice(0, 1200),
      rev.acceptance && rev.acceptance.length ? "\nAcceptance:\n- " + rev.acceptance.join("\n- ") : "",
    ]
      .filter(Boolean)
      .join("\n");
    updateTaskActionButtons(task);
    setActionFeedback("", "");
  }

  async function selectTask(taskId) {
    if (!taskId || !state.projectId) return;
    state.selectedTaskId = taskId;
    renderTasks(cachedTasks);
    try {
      const detail = await api(`/api/v1/projects/${state.projectId}/tasks/${taskId}`);
      renderTaskDetail(detail);
    } catch (e) {
      const cached = cachedTasks.find((t) => t.id === taskId) || null;
      renderTaskDetail(cached);
      setActionFeedback("", e.message || String(e));
    }
  }

  async function enqueueTask(task) {
    if (!task || !state.projectId) throw new Error("Нет задачи");
    const version = task.version;
    if (version == null) throw new Error("Нет version для If-Match — обновите задачу");
    return api(`/api/v1/projects/${state.projectId}/tasks/${task.id}/enqueue`, {
      method: "POST",
      idempotencyKey: uuid(),
      ifMatch: version,
    });
  }

  async function controlTask(task, command, reason) {
    if (!task || !state.projectId) throw new Error("Нет задачи");
    const version = task.version;
    if (version == null) throw new Error("Нет version для If-Match");
    return api(`/api/v1/projects/${state.projectId}/tasks/${task.id}/controls`, {
      method: "POST",
      idempotencyKey: uuid(),
      ifMatch: version,
      body: { command, reason: reason || `${command} via Pages gateway` },
    });
  }

  function parseLines(raw) {
    return String(raw || "")
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function validateTaskForm(fd) {
    const title = String(fd.get("title") || "").trim();
    const requirements = String(fd.get("requirements") || "").trim();
    const acceptance = parseLines(fd.get("acceptance"));
    const implementer_id = String(fd.get("implementer_id") || "").trim();
    const auditor_id = String(fd.get("auditor_id") || "").trim();
    const delegation_id = String(fd.get("delegation_id") || "").trim();
    const paths = parseLines(fd.get("paths"));
    const mode = String(fd.get("mode") || "surgical");
    const autonomous = !!taskForm.elements.autonomous.checked;

    if (!title) throw new Error("Укажите заголовок");
    if (!requirements) throw new Error("Укажите требования");
    if (!acceptance.length) throw new Error("Нужен хотя бы один acceptance-критерий");
    if (acceptance.length > MAX_ACCEPTANCE) {
      throw new Error(`Слишком много acceptance-строк: ${acceptance.length} (макс. ${MAX_ACCEPTANCE}). Уберите лишние — критерии не обрезаются молча.`);
    }
    if (!isUuid(implementer_id)) throw new Error("implementer_id должен быть UUID");
    if (!isUuid(auditor_id)) throw new Error("auditor_id должен быть UUID");
    if (!isUuid(delegation_id)) throw new Error("delegation_id должен быть UUID");
    if (implementer_id === auditor_id) throw new Error("Implementer и auditor должны отличаться");
    if (!paths.length) throw new Error("Нужен хотя бы один allowed path");
    if (paths.length > MAX_PATHS) {
      throw new Error(`Слишком много paths: ${paths.length} (макс. ${MAX_PATHS}). Лишние не обрезаются молча.`);
    }
    for (const p of paths) {
      if (p.startsWith("/") || p.includes("..")) throw new Error(`Некорректный path: ${p}`);
    }
    if (mode !== "surgical" && mode !== "creative") throw new Error("mode: surgical|creative");

    return {
      title,
      requirements,
      acceptance,
      implementer_id,
      auditor_id,
      delegation_id,
      mode,
      autonomous,
      urgency: "normal",
      max_failed_reviews: 3,
      scope: {
        allowed_paths: paths,
        denied_paths: [],
        max_changed_files: 50,
        max_diff_lines: 2000,
        allow_new_dependencies: false,
      },
    };
  }

  function startPoll() {
    stopPoll();
    pollTimer = setInterval(() => {
      if (!state.projectId || document.hidden) return;
      softRefresh();
    }, POLL_MS);
  }

  function stopPoll() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
  }

  async function softRefresh() {
    if (recovering) return;
    try {
      await refresh();
    } catch (e) {
      if (e.kind === "auth") return;
      setConnState("lost");
      recovering = true;
      setConnState("recovering");
      try {
        const pointed = await fetchPointerBase();
        const tryBases = [
          state.base,
          ...pointerCandidates.filter((b) => b !== state.base),
        ].filter(Boolean);
        let ok = false;
        let last = null;
        for (const b of tryBases) {
          try {
            state.base = b;
            await refresh();
            sessionStorage.setItem(STORE_BASE, state.base);
            setConnState("connected", state.base.replace(/^https?:\/\//, ""));
            ok = true;
            break;
          } catch (err) {
            last = err;
            if (err.kind === "auth") throw err;
          }
        }
        if (!ok) {
          if (pointed) state.base = pointed;
          if (last && last.kind !== "auth") setConnState("lost");
        }
      } catch (e2) {
        if (e2.kind !== "auth") setConnState("lost");
      } finally {
        recovering = false;
      }
    }
  }

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && state.projectId) softRefresh();
    persistDrafts();
  });
  window.addEventListener("pagehide", persistDrafts);
  if (msgForm) {
    msgForm.elements.body.addEventListener("input", () => {
      saveJson(STORE_DRAFT_MSG, { body: msgForm.elements.body.value || "" });
    });
  }

  $("#connect-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    connectErr.hidden = true;
    const fd = new FormData(ev.target);
    const typed = normalizeBase(fd.get("base"));
    const key = fd.get("key");
    try {
      await fetchPointerBase();
      const bases = [typed, ...pointerCandidates.filter((b) => b !== typed)];
      await connectWithFailover(bases, key);
    } catch (e) {
      showConnect(e.message || String(e));
    }
  });

  $("#btn-disconnect").addEventListener("click", () => {
    sessionStorage.removeItem(STORE_BASE);
    sessionStorage.removeItem(STORE_KEY);
    state = { base: "", key: "", projectId: null, me: null };
    pendingTask = loadPending();
    pendingMsg = loadPendingMsg();
    // SA-06: final server rejection is discarded on disconnect; unknown-outcome kept for retry.
    if (pendingMsg && pendingMsg.outcome === "final") {
      clearPendingMsg();
      pendingMsg = null;
    }
    showConnect();
  });

  $("#btn-refresh").addEventListener("click", () => refresh().catch((e) => {
    msgErr.hidden = false;
    msgErr.textContent = e.message || String(e);
  }));

  projectSelect.addEventListener("change", () => {
    state.projectId = projectSelect.value;
    refresh().catch((e) => {
      msgErr.hidden = false;
      msgErr.textContent = e.message || String(e);
    });
  });

  msgForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    msgErr.hidden = true;
    msgOk.hidden = true;
    const body = ev.target.elements.body.value.trim();
    if (!body && !pendingMsg) return;

    pendingMsg = loadPendingMsg();
    if (pendingMsg) {
      if (pendingMsg.projectId !== state.projectId) {
        msgErr.hidden = false;
        msgErr.textContent = "Незавершённое сообщение относится к другому проекту. Сбросьте его.";
        updatePendingMsgUi();
        return;
      }
      if (pendingMsg.outcome === "final" && body && body !== pendingMsg.body) {
        msgErr.hidden = false;
        msgErr.textContent =
          "Сервер окончательно отклонил предыдущее сообщение. Нажмите «Сбросить сообщение» или очистите поле и отключитесь/подключитесь — затем отправьте новый текст.";
        updatePendingMsgUi();
        return;
      }
      if (pendingMsg.outcome !== "final" && body && body !== pendingMsg.body) {
        msgErr.hidden = false;
        msgErr.textContent =
          "Текст изменён при неизвестном исходе. Верните прежний текст и повторите (тот же ключ) или сбросьте сообщение.";
        ev.target.elements.body.value = pendingMsg.body;
        updatePendingMsgUi();
        return;
      }
    } else {
      const attach = !!(msgForm.elements.attach_task && msgForm.elements.attach_task.checked);
      savePendingMsg({
        idempotencyKey: uuid(),
        clientMessageId: uuid(),
        projectId: state.projectId,
        body,
        taskId: attach && state.selectedTaskId ? state.selectedTaskId : null,
        outcome: "unknown",
      });
    }

    btnSend.disabled = true;
    try {
      const msgBody = {
        client_message_id: pendingMsg.clientMessageId,
        kind: "note",
        body: pendingMsg.body,
      };
      if (pendingMsg.taskId) msgBody.task_id = pendingMsg.taskId;
      await api(`/api/v1/projects/${state.projectId}/messages`, {
        method: "POST",
        idempotencyKey: pendingMsg.idempotencyKey,
        body: msgBody,
      });
      clearPendingMsg();
      saveJson(STORE_DRAFT_MSG, null);
      ev.target.elements.body.value = "";
      msgOk.hidden = false;
      msgOk.textContent = "Отправлено (подтверждено сервером).";
      await refresh();
    } catch (e) {
      const finalHttp =
        e.kind === "http" &&
        e.status >= 400 &&
        e.status < 500 &&
        e.status !== 408 &&
        e.status !== 429;
      if (finalHttp) {
        pendingMsg = { ...pendingMsg, outcome: "final" };
        savePendingMsg(pendingMsg);
        msgErr.hidden = false;
        msgErr.textContent =
          (e.message || String(e)) +
          " — окончательный отказ сервера. Сбросьте сообщение (кнопка) или очистите поле и отключитесь/подключитесь, затем отправьте исправленный текст.";
      } else {
        pendingMsg = { ...pendingMsg, outcome: "unknown" };
        savePendingMsg(pendingMsg);
        msgErr.hidden = false;
        msgErr.textContent =
          (e.message || String(e)) +
          " — исход неизвестен; повтор с тем же ключом безопасен (дубль не создастся).";
        if (e.kind === "network" || e.kind === "html") setConnState("lost");
      }
    } finally {
      btnSend.disabled = false;
      updatePendingMsgUi();
    }
  });

  taskForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    taskErr.hidden = true;
    taskOk.hidden = true;
    let payload;
    try {
      payload = validateTaskForm(new FormData(taskForm));
    } catch (e) {
      taskErr.hidden = false;
      taskErr.textContent = e.message || String(e);
      return;
    }

    sessionStorage.setItem(STORE_IMPL, payload.implementer_id);
    sessionStorage.setItem(STORE_AUD, payload.auditor_id);
    sessionStorage.setItem(STORE_DEL, payload.delegation_id);

    pendingTask = loadPending();
    if (pendingTask) {
      if (pendingTask.projectId !== state.projectId) {
        taskErr.hidden = false;
        taskErr.textContent = "Незавершённая отправка относится к другому проекту. Сбросьте её или переключите проект.";
        updatePendingUi();
        return;
      }
      if (stableJson(pendingTask.payload) !== stableJson(payload)) {
        taskErr.hidden = false;
        taskErr.textContent =
          "Форма изменена, а Idempotency-Key уже занят прежним телом (иначе 409). Сбросьте незавершённую отправку или верните прежние поля и повторите.";
        applyPayloadToForm(pendingTask.payload);
        updatePendingUi();
        return;
      }
    } else {
      savePending({
        idempotencyKey: uuid(),
        projectId: state.projectId,
        payload,
      });
    }

    const enqueueAfter = !!(taskForm.elements.enqueue_after_create && taskForm.elements.enqueue_after_create.checked);

    btnCreate.disabled = true;
    try {
      const created = await api(`/api/v1/projects/${state.projectId}/tasks`, {
        method: "POST",
        idempotencyKey: pendingTask.idempotencyKey,
        body: pendingTask.payload,
      });
      clearPending();
      saveJson(STORE_DRAFT_TASK, null);
      taskForm.elements.title.value = "";
      taskForm.elements.requirements.value = "";
      taskForm.elements.acceptance.value = "";
      let statusNote = created.status || "draft";
      if (enqueueAfter && created.id) {
        try {
          const enq = await enqueueTask(created);
          statusNote = (enq && enq.status) || "queued";
        } catch (enqErr) {
          taskOk.hidden = false;
          taskOk.textContent = `Создано draft ${created.id}; enqueue не удался: ${enqErr.message || enqErr}`;
          await refresh();
          if (created.id) await selectTask(created.id);
          return;
        }
      }
      taskOk.hidden = false;
      taskOk.textContent = `Создано: ${created.id || created.title || "ok"} (${statusNote})`;
      await refresh();
      if (created.id) await selectTask(created.id);
    } catch (e) {
      savePending(pendingTask);
      taskErr.hidden = false;
      const code = e.data && e.data.error && e.data.error.code;
      if (e.status === 409 && code === "idempotency_conflict") {
        taskErr.textContent =
          "idempotency_conflict: этот ключ уже использован с другим телом. Сбросьте незавершённую отправку и создайте заново.";
      } else {
        taskErr.textContent = (e.message || String(e)) + " — можно безопасно повторить тот же запрос.";
      }
      if (e.kind === "network" || e.kind === "html") setConnState("lost");
    } finally {
      btnCreate.disabled = false;
      updatePendingUi();
    }
  });

  pendingTask = loadPending();
  updatePendingUi();
  pendingMsg = loadPendingMsg();
  updatePendingMsgUi();

  const statusFilter = $("#task-status-filter");
  if (statusFilter) {
    statusFilter.addEventListener("change", () => renderTasks(cachedTasks));
  }

  async function runSelectedAction(fn, okLabel) {
    if (!selectedTask && state.selectedTaskId) {
      await selectTask(state.selectedTaskId);
    }
    if (!selectedTask) {
      setActionFeedback("", "Сначала выберите задачу");
      return;
    }
    setActionFeedback("", "");
    try {
      await fn(selectedTask);
      setActionFeedback(okLabel, "");
      await refresh();
      if (state.selectedTaskId) await selectTask(state.selectedTaskId);
    } catch (e) {
      setActionFeedback("", e.message || String(e));
    }
  }

  const btnEnqueue = $("#btn-enqueue");
  if (btnEnqueue) {
    btnEnqueue.addEventListener("click", () =>
      runSelectedAction((t) => enqueueTask(t), "Задача поставлена в очередь")
    );
  }
  const btnPause = $("#btn-pause");
  if (btnPause) {
    btnPause.addEventListener("click", () =>
      runSelectedAction((t) => controlTask(t, "pause"), "Pause отправлен")
    );
  }
  const btnResume = $("#btn-resume");
  if (btnResume) {
    btnResume.addEventListener("click", () =>
      runSelectedAction((t) => controlTask(t, "resume"), "Resume отправлен")
    );
  }
  const btnComplete = $("#btn-complete");
  if (btnComplete) {
    btnComplete.addEventListener("click", () => {
      const reason = window.prompt("Причина завершения?", "completed via Pages gateway");
      if (!reason) return;
      runSelectedAction((t) => controlTask(t, "complete", reason), "Задача отмечена выполненной");
    });
  }
  const btnCancel = $("#btn-cancel");
  if (btnCancel) {
    btnCancel.addEventListener("click", () => {
      const reason = window.prompt("Причина cancel?", "cancelled via Pages gateway");
      if (!reason) return;
      runSelectedAction((t) => controlTask(t, "cancel", reason), "Cancel отправлен");
    });
  }

  (async () => {
    const form = $("#connect-form");
    const params = new URLSearchParams(location.search);
    const relayParam = params.get("relay");
    const pointed = await fetchPointerBase();
    const savedBase = sessionStorage.getItem(STORE_BASE);
    const savedKey = sessionStorage.getItem(STORE_KEY);

    if (relayParam && isTrustedRelayBase(relayParam)) form.elements.base.value = relayParam;
    else if (pointed) form.elements.base.value = pointed;
    else if (savedBase) form.elements.base.value = savedBase;

    if (savedBase && savedKey) {
      try {
        const bases = [
          savedBase,
          ...pointerCandidates.filter((b) => b !== savedBase),
        ];
        await connectWithFailover(bases, savedKey);
        form.elements.base.value = state.base;
      } catch (e) {
        showConnect(
          (e.message || String(e)) +
            (pointed ? " — попробуйте URL из pointer или IPv4-fallback." : "")
        );
        if (pointed) form.elements.base.value = pointed;
      }
    } else {
      setConnState("idle");
    }
  })();
})();
