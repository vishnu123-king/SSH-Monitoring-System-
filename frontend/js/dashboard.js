/**
 * SSH Security Monitor - Dashboard JavaScript
 * Real-time WebSocket event ingestion, dynamic filtering, metrics rendering & auth.
 */

(function () {
  let authToken = localStorage.getItem("ssh_monitor_token") || "";
  let currentUser = null;
  let ws = null;
  let wsReconnectTimeout = null;

  // DOM Elements
  const wsStatusDot = document.getElementById("ws-status-dot");
  const wsStatusText = document.getElementById("ws-status-text");
  const hostNameEl = document.getElementById("host-name");

  const statTotalEvents = document.getElementById("stat-total-events");
  const statFailedAuths = document.getElementById("stat-failed-auths");
  const statSuccessAuths = document.getElementById("stat-success-auths");
  const statActiveAlerts = document.getElementById("stat-active-alerts");
  const statUniqueSources = document.getElementById("stat-unique-sources");

  const topSourcesList = document.getElementById("top-sources-list");
  const topUsernamesList = document.getElementById("top-usernames-list");

  const alertsTableBody = document.getElementById("alerts-table-body");
  const eventsTableBody = document.getElementById("events-table-body");

  const filterAlertSeverity = document.getElementById("filter-alert-severity");
  const filterAlertStatus = document.getElementById("filter-alert-status");
  const btnRefreshAlerts = document.getElementById("btn-refresh-alerts");

  const filterEventIp = document.getElementById("filter-event-ip");
  const filterEventType = document.getElementById("filter-event-type");
  const btnRefreshEvents = document.getElementById("btn-refresh-events");

  const modalLogin = document.getElementById("modal-login");
  const btnLogin = document.getElementById("btn-login");
  const btnLogout = document.getElementById("btn-logout");
  const btnCloseModal = document.getElementById("btn-close-modal");
  const loginForm = document.getElementById("login-form");
  const userDisplay = document.getElementById("user-display");
  const loginError = document.getElementById("login-error");

  // API Client with automatic auth header
  async function apiFetch(endpoint, options = {}) {
    const headers = options.headers || {};
    if (authToken) {
      headers["Authorization"] = `Bearer ${authToken}`;
    }
    const res = await fetch(endpoint, { credentials: "omit", ...options, headers });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(errData.detail || `Request failed with status ${res.status}`);
    }
    return res.json();
  }

  // Load Host / Config Info
  async function loadConfig() {
    try {
      const config = await apiFetch("/api/config");
      if (config.hostname) {
        hostNameEl.textContent = config.hostname;
      }
    } catch (e) {
      console.warn("Failed fetching config:", e);
    }
  }

  // Load Observability Stats
  async function loadStatistics() {
    try {
      const stats = await apiFetch("/api/statistics");
      statTotalEvents.textContent = Number(stats.total_events || 0).toLocaleString();
      statFailedAuths.textContent = Number(stats.failed_authentications || 0).toLocaleString();
      statSuccessAuths.textContent = Number(stats.successful_authentications || 0).toLocaleString();
      statActiveAlerts.textContent = Number(stats.active_alerts || 0).toLocaleString();
      statUniqueSources.textContent = Number(stats.unique_source_ips || 0).toLocaleString();

      // Top Sources
      if (stats.top_source_ips && stats.top_source_ips.length > 0) {
        topSourcesList.innerHTML = stats.top_source_ips
          .map(
            (s) =>
              `<div class="list-item"><span class="list-item-key">${s.ip}</span><span class="list-item-badge">${s.count} hits</span></div>`
          )
          .join("");
      } else {
        topSourcesList.innerHTML = '<div class="empty-state">No connection data yet</div>';
      }

      // Top Usernames
      if (stats.top_usernames && stats.top_usernames.length > 0) {
        topUsernamesList.innerHTML = stats.top_usernames
          .map(
            (u) =>
              `<div class="list-item"><span class="list-item-key">${u.username}</span><span class="list-item-badge">${u.count} attempts</span></div>`
          )
          .join("");
      } else {
        topUsernamesList.innerHTML = '<div class="empty-state">No targeted accounts yet</div>';
      }

      // Severity Distribution
      const sev = stats.severity_distribution || {};
      const maxCount = Math.max(sev.CRITICAL || 0, sev.HIGH || 0, sev.MEDIUM || 0, (sev.LOW || 0) + (sev.INFO || 0), 1);

      updateSeverityBar("CRITICAL", sev.CRITICAL || 0, maxCount);
      updateSeverityBar("HIGH", sev.HIGH || 0, maxCount);
      updateSeverityBar("MEDIUM", sev.MEDIUM || 0, maxCount);
      updateSeverityBar("LOW", (sev.LOW || 0) + (sev.INFO || 0), maxCount);
    } catch (e) {
      console.warn("Failed loading statistics:", e);
    }
  }

  function updateSeverityBar(sevKey, count, max) {
    const elCnt = document.getElementById(`cnt-${sevKey}`);
    const elBar = document.getElementById(`bar-${sevKey}`);
    if (elCnt) elCnt.textContent = count;
    if (elBar) {
      const pct = Math.round((count / max) * 100);
      elBar.style.width = `${pct}%`;
    }
  }

  // Load Security Alerts
  async function loadAlerts() {
    try {
      const params = new URLSearchParams({ page: "1", page_size: "30" });
      if (filterAlertSeverity.value) params.set("severity", filterAlertSeverity.value);
      if (filterAlertStatus.value) params.set("status", filterAlertStatus.value);

      const res = await apiFetch(`/api/alerts?${params.toString()}`);
      if (res.items.length === 0) {
        alertsTableBody.innerHTML = '<tr><td colspan="9" class="text-center" style="color:#6b7280;padding:2rem;">No security alerts matching criteria.</td></tr>';
        return;
      }

      alertsTableBody.innerHTML = res.items.map(renderAlertRow).join("");
      attachAlertActionListeners();
    } catch (e) {
      alertsTableBody.innerHTML = `<tr><td colspan="9" class="text-center error-text">${e.message}</td></tr>`;
    }
  }

  function renderAlertRow(a) {
    const timeFormatted = new Date(a.timestamp).toISOString().replace("T", " ").substring(0, 19);
    const canAck = a.status === "active";
    const actionBtn = canAck
      ? `<button class="btn-ack" data-alert-id="${a.id}">Acknowledge</button>`
      : `<span style="color:#6b7280;font-size:0.75rem;">Done</span>`;

    return `
      <tr id="alert-row-${a.id}">
        <td><code style="color:#9ca3af;">${timeFormatted}</code></td>
        <td><code>${a.rule_id}</code></td>
        <td><strong>${a.alert_type}</strong></td>
        <td><span class="tag tag-${a.severity}">${a.severity}</span></td>
        <td><code style="color:#38bdf8;">${a.source_ip || "-"}</code></td>
        <td>${a.username || "-"}</td>
        <td style="max-width:350px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${a.description}">${a.description}</td>
        <td><span class="tag tag-${a.status}">${a.status}</span></td>
        <td>${actionBtn}</td>
      </tr>
    `;
  }

  // Load Normalized Events
  async function loadEvents() {
    try {
      const params = new URLSearchParams({ page: "1", page_size: "40" });
      if (filterEventIp.value.trim()) params.set("source_ip", filterEventIp.value.trim());
      if (filterEventType.value) params.set("event_type", filterEventType.value);

      const res = await apiFetch(`/api/events?${params.toString()}`);
      if (res.items.length === 0) {
        eventsTableBody.innerHTML = '<tr><td colspan="7" class="text-center" style="color:#6b7280;padding:2rem;">No SSH events recorded yet.</td></tr>';
        return;
      }

      eventsTableBody.innerHTML = res.items.map(renderEventRow).join("");
    } catch (e) {
      eventsTableBody.innerHTML = `<tr><td colspan="7" class="text-center error-text">${e.message}</td></tr>`;
    }
  }

  function renderEventRow(e) {
    const timeFormatted = new Date(e.timestamp).toISOString().replace("T", " ").substring(0, 19);
    let typeClass = "tag-INFO";
    if (e.event_type === "AUTH_FAILURE" || e.event_type === "INVALID_USER") typeClass = "tag-CRITICAL";
    if (e.event_type.startsWith("AUTH_SUCCESS")) typeClass = "tag-resolved";

    return `
      <tr>
        <td><code style="color:#9ca3af;">${timeFormatted}</code></td>
        <td><span class="tag ${typeClass}">${e.event_type}</span></td>
        <td>${e.username ? `<strong style="color:#c084fc;">${e.username}</strong>` : "-"}</td>
        <td><code>${e.source_ip || "-"}</code></td>
        <td>${e.source_port || "-"}</td>
        <td><span style="font-size:0.7rem;color:#6b7280;">${e.parser_confidence}</span></td>
        <td style="font-family:monospace;font-size:0.75rem;color:#9ca3af;max-width:400px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${e.raw_message}">${e.raw_message}</td>
      </tr>
    `;
  }

  // Action listeners for acknowledging alerts
  function attachAlertActionListeners() {
    document.querySelectorAll(".btn-ack").forEach((btn) => {
      btn.onclick = async function () {
        const id = this.getAttribute("data-alert-id");
        if (!authToken) {
          modalLogin.classList.remove("hidden");
          return;
        }
        try {
          this.disabled = true;
          this.textContent = "...";
          await apiFetch(`/api/alerts/${id}/acknowledge`, { method: "POST" });
          loadAlerts();
          loadStatistics();
        } catch (err) {
          alert(`Failed to acknowledge alert: ${err.message}`);
          this.disabled = false;
          this.textContent = "Acknowledge";
        }
      };
    });
  }

  // WebSocket Connection
  function initWebSocket() {
    if (ws) {
      try { ws.close(); } catch (_) {}
    }

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${window.location.host}/ws/alerts`;

    wsStatusText.textContent = "CONNECTING...";
    wsStatusDot.className = "pulse-dot";

    ws = new WebSocket(wsUrl);

    ws.onopen = function () {
      wsStatusText.textContent = "LIVE MONITOR";
      wsStatusDot.className = "pulse-dot online";
    };

    ws.onmessage = function (event) {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === "alert.created") {
          handleIncomingAlert(msg.data);
        } else if (msg.type === "event.created") {
          handleIncomingEvent(msg.data);
        } else if (msg.type === "alert.updated") {
          loadAlerts();
          loadStatistics();
        }
      } catch (e) {
        console.debug("WS parse error:", e);
      }
    };

    ws.onclose = function () {
      wsStatusText.textContent = "RECONNECTING";
      wsStatusDot.className = "pulse-dot offline";
      clearTimeout(wsReconnectTimeout);
      wsReconnectTimeout = setTimeout(initWebSocket, 4000);
    };

    ws.onerror = function () {
      try { ws.close(); } catch (_) {}
    };
  }

  function handleIncomingAlert(alertData) {
    // Prepend to alerts table
    const emptyRow = alertsTableBody.querySelector(".text-center");
    if (emptyRow) emptyRow.remove();

    const tempDiv = document.createElement("tbody");
    tempDiv.innerHTML = renderAlertRow(alertData);
    if (alertsTableBody.firstChild) {
      alertsTableBody.insertBefore(tempDiv.firstElementChild, alertsTableBody.firstChild);
    } else {
      alertsTableBody.appendChild(tempDiv.firstElementChild);
    }
    attachAlertActionListeners();
    loadStatistics();
  }

  function handleIncomingEvent(eventData) {
    const emptyRow = eventsTableBody.querySelector(".text-center");
    if (emptyRow) emptyRow.remove();

    const tempDiv = document.createElement("tbody");
    tempDiv.innerHTML = renderEventRow(eventData);
    if (eventsTableBody.firstChild) {
      eventsTableBody.insertBefore(tempDiv.firstElementChild, eventsTableBody.firstChild);
    } else {
      eventsTableBody.appendChild(tempDiv.firstElementChild);
    }
    // Increment total event count in UI
    const curr = parseInt(statTotalEvents.textContent.replace(/,/g, "") || "0", 10);
    statTotalEvents.textContent = (curr + 1).toLocaleString();
  }

  // Auth Handling
  async function checkCurrentUser() {
    if (!authToken) {
      updateAuthUI(null);
      return;
    }
    try {
      const user = await apiFetch("/api/auth/me");
      currentUser = user;
      updateAuthUI(user);
    } catch (_) {
      authToken = "";
      localStorage.removeItem("ssh_monitor_token");
      updateAuthUI(null);
    }
  }

  function updateAuthUI(user) {
    if (user) {
      userDisplay.textContent = `👤 ${user.username}`;
      userDisplay.classList.remove("hidden");
      btnLogin.classList.add("hidden");
      btnLogout.classList.remove("hidden");
    } else {
      userDisplay.classList.add("hidden");
      btnLogin.classList.remove("hidden");
      btnLogout.classList.add("hidden");
    }
  }

  // Event Listeners
  btnLogin.onclick = () => {
    loginError.classList.add("hidden");
    modalLogin.classList.remove("hidden");
  };

  btnCloseModal.onclick = () => modalLogin.classList.add("hidden");

  btnLogout.onclick = () => {
    authToken = "";
    localStorage.removeItem("ssh_monitor_token");
    currentUser = null;
    updateAuthUI(null);
  };

  loginForm.onsubmit = async (e) => {
    e.preventDefault();
    loginError.classList.add("hidden");
    const u = document.getElementById("input-username").value;
    const p = document.getElementById("input-password").value;

    const body = new URLSearchParams({ username: u, password: p });
    try {
      const res = await fetch("/api/auth/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      });
      if (!res.ok) {
        throw new Error("Invalid username or password");
      }
      const data = await res.json();
      authToken = data.access_token;
      localStorage.setItem("ssh_monitor_token", authToken);
      modalLogin.classList.add("hidden");
      await checkCurrentUser();
      loadAlerts();
    } catch (err) {
      loginError.textContent = err.message;
      loginError.classList.remove("hidden");
    }
  };

  btnRefreshAlerts.onclick = loadAlerts;
  filterAlertSeverity.onchange = loadAlerts;
  filterAlertStatus.onchange = loadAlerts;

  btnRefreshEvents.onclick = loadEvents;
  filterEventType.onchange = loadEvents;
  filterEventIp.onkeydown = (e) => {
    if (e.key === "Enter") loadEvents();
  };

  // Initial Load
  loadConfig();
  checkCurrentUser();
  loadStatistics();
  loadAlerts();
  loadEvents();
  initWebSocket();

  // Periodic poll for stats
  setInterval(loadStatistics, 15000);
})();
