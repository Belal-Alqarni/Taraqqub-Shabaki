const state = {
  devices: [],
  alerts: [],
  topology: null,
  session: null,
  publicConfig: null,
  users: [],
  agents: [],
};

async function api(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (method !== "GET" && state.session?.csrf_token) {
    headers["X-CSRF-Token"] = state.session.csrf_token;
  }
  const response = await fetch(path, {
    ...options,
    headers,
  });
  if (response.status === 401) {
    window.location.replace("/login");
    throw new Error("Authentication required.");
  }
  if (!response.ok) {
    const result = await response.json().catch(() => ({}));
    throw new Error(result.detail || `Request failed: ${response.status}`);
  }
  return response.json();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function fmt(value, suffix = "") {
  if (value === null || value === undefined) return "n/a";
  return `${Number(value).toFixed(1)}${suffix}`;
}

function sourceLabel(source) {
  if (source === "agent") return "agent";
  if (source === "discovered") return "live";
  if (source === "manual") return "manual";
  return "demo";
}

function renderKpis() {
  const total = state.devices.length;
  const online = state.devices.filter((item) => item.status === "online").length;
  const degraded = state.devices.filter((item) => item.status === "degraded").length;
  const open = state.alerts.filter((item) => item.status === "open").length;

  document.querySelector("#totalDevices").textContent = total;
  document.querySelector("#onlineDevices").textContent = online;
  document.querySelector("#degradedDevices").textContent = degraded;
  document.querySelector("#openAlerts").textContent = open;
}

function renderDevices() {
  const rows = state.devices.map((device) => `
    <tr>
      <td>${escapeHtml(device.name)}</td>
      <td>${escapeHtml(device.ip_address)}</td>
      <td>${escapeHtml(device.role)}</td>
      <td>${sourceLabel(device.source)}</td>
      <td><span class="status ${escapeHtml(device.status)}"><span class="dot"></span>${escapeHtml(device.status)}</span></td>
      <td>${fmt(device.latency_ms, " ms")}</td>
      <td>${fmt(device.packet_loss, "%")}</td>
      <td>${fmt(device.cpu_usage, "%")}</td>
      <td>${fmt(device.memory_usage, "%")}</td>
    </tr>
  `).join("");

  document.querySelector("#deviceRows").innerHTML = rows || `
    <tr>
      <td class="empty-cell" colspan="9">
        No devices yet. Create a Network Agent token, run the agent inside your
        authorized network, then refresh this dashboard.
      </td>
    </tr>
  `;
  document.querySelector("#lastUpdated").textContent = `Updated ${new Date().toLocaleTimeString()}`;

  const options = [`<option value="">General incident</option>`].concat(
    state.devices.map((device) => `<option value="${device.id}">${escapeHtml(device.name)}</option>`)
  );
  document.querySelector("#deviceSelect").innerHTML = options.join("");
}

function renderAlerts() {
  const list = document.querySelector("#alertList");
  if (state.alerts.length === 0) {
    list.innerHTML = `<p>No alerts yet. The network is quiet.</p>`;
    return;
  }

  list.innerHTML = state.alerts.map((alert) => `
    <div class="alert ${alert.severity}">
      <strong>${escapeHtml(alert.title)}</strong>
      <p>${escapeHtml(alert.description)}</p>
      <small>${escapeHtml(alert.device_name || "Network")} · ${escapeHtml(alert.status)} · ${new Date(alert.created_at).toLocaleString()}</small>
    </div>
  `).join("");
}

function renderTopology() {
  const map = document.querySelector("#topologyMap");
  if (!state.topology) return;

  if (state.topology.nodes.length === 0) {
    map.innerHTML = `
      <div class="empty-state">
        <strong>No topology yet</strong>
        <small>Your private topology appears after an authorized agent reports devices.</small>
      </div>
    `;
    return;
  }

  map.innerHTML = state.topology.nodes.map((node) => {
    return `
      <div class="node ${node.status}">
        <strong>${escapeHtml(node.name)}</strong>
        <small>${escapeHtml(node.ip_address)} · ${sourceLabel(node.source)}</small>
      </div>
    `;
  }).join("");
}

function renderUsers() {
  const rows = state.users.map((user) => `
    <tr>
      <td>${escapeHtml(user.username)}</td>
      <td>${escapeHtml(user.role)}</td>
      <td>${user.is_active ? "active" : "disabled"}</td>
      <td>${user.must_change_password ? "temporary" : "changed"}</td>
    </tr>
  `).join("");
  document.querySelector("#userRows").innerHTML = rows || `
    <tr><td class="empty-cell" colspan="4">No workspace users yet.</td></tr>
  `;
}

function renderAgents() {
  const rows = state.agents.map((agent) => `
    <tr>
      <td>${escapeHtml(agent.name)}</td>
      <td>${agent.is_active ? "active" : "revoked"}</td>
      <td>${agent.last_seen ? new Date(agent.last_seen).toLocaleString() : "never"}</td>
      <td>
        ${agent.is_active ? `<button class="secondary-button revoke-agent" data-agent-id="${agent.id}" type="button">Revoke</button>` : ""}
      </td>
    </tr>
  `).join("");
  document.querySelector("#agentRows").innerHTML = rows || `
    <tr>
      <td class="empty-cell" colspan="4">
        No agents yet. Create a token when you are ready to connect your network.
      </td>
    </tr>
  `;
}

async function refresh() {
  const [devices, alerts, topology] = await Promise.all([
    api("/api/devices"),
    api("/api/alerts"),
    api("/api/topology"),
  ]);
  state.devices = devices;
  state.alerts = alerts;
  state.topology = topology;
  renderKpis();
  renderDevices();
  renderAlerts();
  renderTopology();
}

async function safeRefresh() {
  try {
    await refresh();
  } catch {
    document.querySelector("#lastUpdated").textContent = "Connection unavailable";
  }
}

document.querySelector("#refreshBtn").addEventListener("click", safeRefresh);

document.querySelector("#logoutBtn").addEventListener("click", async () => {
  await api("/api/auth/logout", { method: "POST" });
  window.location.replace("/login");
});

document.querySelector("#userForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await api("/api/admin/users", {
    method: "POST",
    body: JSON.stringify({
      username: document.querySelector("#newUsername").value,
      role: document.querySelector("#newUserRole").value,
    }),
  });
  document.querySelector("#temporaryCredential").textContent =
    `Temporary login for ${result.username}: ${result.temporary_password}`;
  document.querySelector("#newUsername").value = "";
  state.users = await api("/api/admin/users");
  renderUsers();
});

document.querySelector("#agentForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const nameInput = document.querySelector("#agentName");
  const result = await api("/api/agents", {
    method: "POST",
    body: JSON.stringify({ name: nameInput.value }),
  });
  document.querySelector("#agentCredential").textContent =
    `Token (shown once): ${result.token}\n` +
    `Server: ${window.location.origin}\n` +
    "Set TARAQQUB_AGENT_NETWORK to your authorized private /24 subnet.";
  nameInput.value = "";
  state.agents = await api("/api/agents");
  renderAgents();
});

document.querySelector("#agentRows").addEventListener("click", async (event) => {
  const button = event.target.closest(".revoke-agent");
  if (!button) return;
  await api(`/api/agents/${button.dataset.agentId}/revoke`, { method: "POST" });
  state.agents = await api("/api/agents");
  renderAgents();
});

document.querySelector("#discoveryBtn").addEventListener("click", async () => {
  const button = document.querySelector("#discoveryBtn");
  const output = document.querySelector("#discoveryOutput");
  button.disabled = true;
  button.textContent = "Scanning...";
  output.textContent = "Discovering active devices on the local network...";
  try {
    const result = await api("/api/discovery/scan", { method: "POST" });
    output.textContent = `Network: ${result.network}\nFound: ${result.count} active device(s)\n\n${result.discovered
      .map((item) => `${item.ip_address}  ${item.name}  ${fmt(item.latency_ms, " ms")}`)
      .join("\n")}`;
    await refresh();
  } catch (error) {
    output.textContent = `Discovery failed: ${error.message}`;
  } finally {
    button.disabled = false;
    button.textContent = "Scan Local Network";
  }
});

document.querySelector("#assistantForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const deviceId = document.querySelector("#deviceSelect").value;
  const symptom = document.querySelector("#symptomInput").value;
  const result = await api("/api/advisor/analyze", {
    method: "POST",
    body: JSON.stringify({
      device_id: deviceId ? Number(deviceId) : null,
      symptom,
    }),
  });

  document.querySelector("#assistantOutput").innerHTML = `
    <div>
      <strong>Likely causes</strong>
      <ul>${result.likely_causes.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
    </div>
    <div>
      <strong>Recommended actions</strong>
      <ul>${result.recommended_actions.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
    </div>
    <div>Self-healing candidate: <strong>${result.self_healing_candidate ? "yes" : "no"}</strong></div>
  `;
});

async function bootstrap() {
  [state.session, state.publicConfig] = await Promise.all([
    api("/api/auth/session"),
    api("/api/public-config"),
  ]);
  if (state.session.must_change_password) {
    window.location.replace("/change-password");
    return;
  }
  document.querySelector("#sessionUser").textContent =
    `${state.session.username} · ${state.session.role}`;
  if (state.session.username === "demo") {
    document.querySelector("#demoNotice").classList.remove("hidden");
  }
  if (state.session.role === "admin") {
    document.querySelector("#users").classList.remove("hidden");
    document.querySelector("#usersNav").classList.remove("hidden");
    document.querySelector("#agents").classList.remove("hidden");
    document.querySelector("#agentsNav").classList.remove("hidden");
    state.users = await api("/api/admin/users");
    state.agents = await api("/api/agents");
    renderUsers();
    renderAgents();
  }
  if (state.session.role !== "admin" || state.publicConfig.public_demo) {
    document.querySelector("#discoveryBtn").classList.add("hidden");
  }
  await safeRefresh();
  setInterval(safeRefresh, 10000);
}

bootstrap();
