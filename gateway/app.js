(() => {
  const STORE_BASE = "nozo_gw_base";
  const STORE_KEY = "nozo_gw_key";

  const $ = (sel, el = document) => el.querySelector(sel);
  const connectPanel = $("#connect-panel");
  const appPanel = $("#app-panel");
  const connLabel = $("#conn-label");
  const connectErr = $("#connect-error");
  const msgErr = $("#msg-error");
  const projectSelect = $("#project-select");
  const taskList = $("#task-list");
  const messagesEl = $("#messages");
  const whoami = $("#whoami");

  let state = { base: "", key: "", projectId: null, me: null };

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

  async function api(path, { method = "GET", body = null, idempotency = false } = {}) {
    const headers = {
      Authorization: `Bearer ${state.key}`,
      Accept: "application/json",
    };
    if (body != null) headers["Content-Type"] = "application/json";
    if (idempotency) headers["Idempotency-Key"] = uuid();
    const res = await fetch(`${state.base}${path}`, {
      method,
      headers,
      body: body != null ? JSON.stringify(body) : undefined,
      credentials: "omit",
    });
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
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

  async function connect(base, key) {
    state.base = normalizeBase(base);
    state.key = String(key || "").trim();
    if (!state.base || !state.key) throw new Error("Нужны URL и ключ");
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
    showApp();
    await refresh();
  }

  async function refresh() {
    if (!state.projectId) return;
    msgErr.hidden = true;
    const [tasks, msgs] = await Promise.all([
      api(`/api/v1/projects/${state.projectId}/tasks?limit=50`),
      api(`/api/v1/projects/${state.projectId}/messages?limit=50`),
    ]);
    renderTasks(tasks.items || tasks.tasks || []);
    renderMessages(msgs.items || msgs.messages || []);
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
        idempotency: true,
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
