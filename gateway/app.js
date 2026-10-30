(() => {
  const STORE_BASE = "nozo_gw_base";
  const STORE_KEY = "nozo_gw_key";
  const STORE_IMPL = "nozo_gw_impl";
  const STORE_AUD = "nozo_gw_aud";
  const STORE_DEL = "nozo_gw_delegation";
  const STORE_PENDING_TASK = "nozo_gw_pending_task";
  const MAX_ACCEPTANCE = 30;
  const MAX_PATHS = 100;
  const LIST_PAGE_LIMIT = 50;
  /** Cap pages so a huge project cannot hang the SPA (50×40 = 2000 items). */
  const MAX_LIST_PAGES = 40;

  const $ = (sel, el = document) => el.querySelector(sel);
  const connectPanel = $("#connect-panel");
  const appPanel = $("#app-panel");
  const connLabel = $("#conn-label");
  const connectErr = $("#connect-error");
  const msgErr = $("#msg-error");
  const taskErr = $("#task-error");
  const taskOk = $("#task-ok");
  const projectSelect = $("#project-select");
  const taskList = $("#task-list");
  const messagesEl = $("#messages");
  const whoami = $("#whoami");
  const taskForm = $("#task-form");
  const btnCreate = $("#btn-create-task");

  let state = { base: "", key: "", projectId: null, me: null };
  /** @type {{ idempotencyKey: string, projectId: string, payload: object } | null} */
  let pendingTask = null;

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

  function loadPending() {
    try {
      const raw = sessionStorage.getItem(STORE_PENDING_TASK);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || !parsed.idempotencyKey || !parsed.payload || !parsed.projectId) return null;
      return parsed;
    } catch {
      return null;
    }
  }

  function savePending(p) {
    pendingTask = p;
    if (p) sessionStorage.setItem(STORE_PENDING_TASK, JSON.stringify(p));
    else sessionStorage.removeItem(STORE_PENDING_TASK);
    updatePendingUi();
  }

  function clearPending() {
    savePending(null);
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
      throw new Error(e && e.message ? e.message : "NetworkError (туннель/CORS/сеть)");
    }
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch {
      const looksHtml = /^\s*</.test(text || "");
      throw new Error(
        looksHtml
          ? "Туннель вернул HTML вместо API (часто free Pinggy/заглушка). Нужен другой публичный URL Relay."
          : `Не JSON от Relay (HTTP ${res.status}).`
      );
    }
    if (!res.ok) {
      const msg = (data && data.error && data.error.message) || `HTTP ${res.status}`;
      const err = new Error(msg);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  function showConnect(errText) {
    connectPanel.hidden = false;
    appPanel.hidden = true;
    $("#btn-disconnect").hidden = true;
    connLabel.textContent = "не подключено";
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
    connLabel.textContent = state.base.replace(/^https?:\/\//, "");
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

  async function connect(base, key) {
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
    showApp();
    restorePendingAfterConnect();
    await refresh();
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
    // API returns ASC; show newest tasks first so creates past page 1 stay obvious.
    renderTasks([...tasks].reverse());
    renderMessages(msgs);
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
    // Keep pendingTask in sessionStorage so reload/reconnect can resume safely.
    pendingTask = loadPending();
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

  $("#msg-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    msgErr.hidden = true;
    const body = ev.target.elements.body.value.trim();
    if (!body) return;
    try {
      await api(`/api/v1/projects/${state.projectId}/messages`, {
        method: "POST",
        idempotencyKey: uuid(),
        body: {
          client_message_id: uuid(),
          kind: "note",
          body,
        },
      });
      ev.target.elements.body.value = "";
      await refresh();
    } catch (e) {
      msgErr.hidden = false;
      msgErr.textContent = e.message || String(e);
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
      taskForm.elements.title.value = "";
      taskForm.elements.requirements.value = "";
      taskForm.elements.acceptance.value = "";
      taskOk.hidden = false;
      taskOk.textContent = `Создано: ${created.id || created.title || "ok"} (${created.status || "draft"})`;
      await refresh();
    } catch (e) {
      // Keep immutable pending in sessionStorage for reload/retry.
      savePending(pendingTask);
      taskErr.hidden = false;
      const code = e.data && e.data.error && e.data.error.code;
      if (e.status === 409 && code === "idempotency_conflict") {
        taskErr.textContent =
          "idempotency_conflict: этот ключ уже использован с другим телом. Сбросьте незавершённую отправку и создайте заново.";
      } else {
        taskErr.textContent = (e.message || String(e)) + " — можно безопасно повторить тот же запрос.";
      }
    } finally {
      btnCreate.disabled = false;
      updatePendingUi();
    }
  });

  pendingTask = loadPending();
  updatePendingUi();

  const savedBase = sessionStorage.getItem(STORE_BASE);
  const savedKey = sessionStorage.getItem(STORE_KEY);
  if (savedBase && savedKey) {
    connect(savedBase, savedKey).catch((e) => showConnect(e.message || String(e)));
  } else {
    const params = new URLSearchParams(location.search);
    const relay = params.get("relay");
    if (relay) {
      const form = $("#connect-form");
      form.elements.base.value = relay;
    }
  }
})();
