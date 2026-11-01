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

  let state = { base: "", key: "", projectId: null, me: null };
  /** @type {{ idempotencyKey: string, projectId: string, payload: object } | null} */
  let pendingTask = null;
  /** @type {{ idempotencyKey: string, clientMessageId: string, projectId: string, body: string } | null} */
  let pendingMsg = null;
  let pollTimer = null;
  let recovering = false;

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
    if (!btnSend) return;
    btnSend.textContent = pendingMsg ? "Повторить отправку" : "Отправить";
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

  async function api(path, { method = "GET", body = null, idempotencyKey = null } = {}) {
    const headers = {
      Authorization: `Bearer ${state.key}`,
      Accept: "application/json",
    };
    if (body != null) headers["Content-Type"] = "application/json";
    if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
    let res;
    try {
      res = await fetch(`${state.base}${path}`, {
        method,
        headers,
        body: body != null ? JSON.stringify(body) : undefined,
        credentials: "omit",
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
    try {
      return text ? JSON.parse(text) : null;
    } catch {
      const c = classifyFetchFailure(null, res, text);
      const err = new Error(c.message);
      err.kind = c.kind;
      throw err;
    }
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

  async function fetchPointerBase() {
    try {
      const res = await fetch(POINTER_URL, { cache: "no-store", credentials: "omit" });
      if (!res.ok) return null;
      const data = await res.json();
      const base = normalizeBase(data && data.relay_base);
      return base || null;
    } catch {
      return null;
    }
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
    if (connChip.dataset.state === "lost" || connChip.dataset.state === "recovering") {
      setConnState("connected", state.base.replace(/^https?:\/\//, ""));
    }
  }

  function renderTasks(items) {
    taskList.innerHTML = "";
    if (!items.length) {
      taskList.innerHTML = '<li class="muted">Нет задач</li>';
      return;
    }
    for (const t of items) {
      const li = document.createElement("li");
      const title = t.title || t.summary || t.id;
      li.textContent = `${t.status || "?"} — ${title}`;
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
      meta.textContent = `${m.kind || "note"} · ${m.created_at || ""} · ${m.sender_id || ""}`;
      const body = document.createElement("div");
      body.textContent = m.body || "";
      div.append(meta, body);
      messagesEl.appendChild(div);
    }
    messagesEl.scrollTop = messagesEl.scrollHeight;
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
        // Re-read pointer in case transport URL changed (rare for Funnel; useful for fallback tunnels).
        const pointed = await fetchPointerBase();
        if (pointed && pointed !== state.base) {
          state.base = pointed;
          sessionStorage.setItem(STORE_BASE, state.base);
        }
        await refresh();
        setConnState("connected", state.base.replace(/^https?:\/\//, ""));
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
    try {
      await connect(fd.get("base"), fd.get("key"));
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
        msgErr.textContent = "Незавершённое сообщение относится к другому проекту.";
        return;
      }
      if (body && body !== pendingMsg.body) {
        msgErr.hidden = false;
        msgErr.textContent = "Текст изменён при незавершённой отправке. Верните текст или сбросьте (очистите поле и отключитесь/подключитесь).";
        ev.target.elements.body.value = pendingMsg.body;
        return;
      }
    } else {
      savePendingMsg({
        idempotencyKey: uuid(),
        clientMessageId: uuid(),
        projectId: state.projectId,
        body,
      });
    }

    btnSend.disabled = true;
    try {
      await api(`/api/v1/projects/${state.projectId}/messages`, {
        method: "POST",
        idempotencyKey: pendingMsg.idempotencyKey,
        body: {
          client_message_id: pendingMsg.clientMessageId,
          kind: "note",
          body: pendingMsg.body,
        },
      });
      clearPendingMsg();
      saveJson(STORE_DRAFT_MSG, null);
      ev.target.elements.body.value = "";
      msgOk.hidden = false;
      msgOk.textContent = "Отправлено (подтверждено сервером).";
      await refresh();
    } catch (e) {
      savePendingMsg(pendingMsg);
      msgErr.hidden = false;
      msgErr.textContent = (e.message || String(e)) + " — статус неизвестен до подтверждения; повтор безопасен.";
      if (e.kind === "network" || e.kind === "html") setConnState("lost");
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
      taskOk.hidden = false;
      taskOk.textContent = `Создано: ${created.id || created.title || "ok"} (${created.status || "draft"})`;
      await refresh();
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

  (async () => {
    const form = $("#connect-form");
    const params = new URLSearchParams(location.search);
    const relayParam = params.get("relay");
    const pointed = await fetchPointerBase();
    const savedBase = sessionStorage.getItem(STORE_BASE);
    const savedKey = sessionStorage.getItem(STORE_KEY);

    if (relayParam) form.elements.base.value = relayParam;
    else if (savedBase) form.elements.base.value = savedBase;
    else if (pointed) form.elements.base.value = pointed;

    if (savedBase && savedKey) {
      connect(savedBase, savedKey).catch((e) => showConnect(e.message || String(e)));
    } else {
      setConnState("idle");
    }
  })();
})();
