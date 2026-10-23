
/* =========================================================
   CYBERPULSE STAGE 7
   Live simulated dashboard + persistent browser storage
   ========================================================= */

"use strict";

const CP_STORE = {
  events: "cyberpulse_events_v6",
  notifications: "cyberpulse_notifications_v6",
  settings: "cyberpulse_settings_v6"
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

const SEVERITIES = ["Critical", "High", "Medium", "Low"];

const DEFAULT_EVENTS = [
  {
    id: "CP-1001",
    name: "Suspicious login pattern",
    severity: "Critical",
    source: "192.0.2.24",
    status: "Open",
    description: "Repeated simulated sign-in attempts triggered this sample alert.",
    recommendation: "Review authentication logs and verify whether the activity is expected.",
    timestamp: Date.now() - 120000
  },
  {
    id: "CP-1002",
    name: "Unusual port activity",
    severity: "High",
    source: "198.51.100.17",
    status: "Open",
    description: "An illustrative port activity pattern may warrant review.",
    recommendation: "Compare the activity with the approved asset inventory.",
    timestamp: Date.now() - 240000
  },
  {
    id: "CP-1003",
    name: "Repeated auth failures",
    severity: "Medium",
    source: "203.0.113.42",
    status: "Review",
    description: "Several failed authentication attempts are represented in this sample.",
    recommendation: "Inspect the authentication timeline and confirm the activity.",
    timestamp: Date.now() - 360000
  },
  {
    id: "CP-1004",
    name: "Configuration changed",
    severity: "Low",
    source: "192.0.2.81",
    status: "Resolved",
    description: "A sample configuration change event is included for demonstration.",
    recommendation: "Verify the change against an approved change request.",
    timestamp: Date.now() - 540000
  }
];

function readStorage(key, fallback) {
  try {
    const saved = localStorage.getItem(key);
    return saved === null ? fallback : JSON.parse(saved);
  } catch {
    return fallback;
  }
}

function writeStorage(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (error) {
    console.warn("CyberPulse storage error:", error);
  }
}

function makeId(prefix = "CP") {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

function normalizeEvent(event) {
  return {
    id: String(event.id || makeId()),
    name: String(event.name || "Unknown event"),
    severity: SEVERITIES.find(
      value => value.toLowerCase() === String(event.severity).toLowerCase()
    ) || "Medium",
    source: String(event.source || "198.51.100.25"),
    status: ["resolved", "closed"].includes(
      String(event.status || "").toLowerCase()
    ) ? "Resolved" : String(event.status || "Open"),
    description: String(event.description || "Simulated security event."),
    recommendation: String(event.recommendation || "Review and validate this event."),
    timestamp: Number(event.timestamp) || Date.now()
  };
}

let settings = {
  search: "",
  severity: "all",
  range: "12",
  paused: false,
  ...(readStorage(CP_STORE.settings, {}) || {})
};

let events = [];
let notifications = [];
let trafficChart = null;
let severityChart = null;
let trafficValues = Array.from({ length: 12 }, () => 30 + Math.random() * 70);
let simulationTimer = null;
let trafficTimer = null;
let selectedEventId = null;
let paused = Boolean(settings.paused);
let tick = 0;

/* ---------- Utilities ---------- */

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function relativeTime(timestamp) {
  const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hr ago`;
  return `${Math.floor(seconds / 86400)} day ago`;
}

function fullDate(timestamp) {
  return new Date(timestamp).toLocaleString();
}

function toast(message, type = "info") {
  let element = $("#toast");

  if (!element) {
    element = document.createElement("div");
    element.id = "toast";
    element.className = "toast";
    document.body.appendChild(element);
  }

  element.textContent = message;
  element.className = `toast show ${type}`;
  clearTimeout(element._timer);
  element._timer = setTimeout(() => element.classList.remove("show"), 3000);
}

function saveAll() {
  writeStorage(CP_STORE.events, events);
  writeStorage(CP_STORE.notifications, notifications);

  settings = {
    ...settings,
    search: $("#threatSearch")?.value || "",
    severity: $("#severityFilter")?.value || "all",
    range: $("#trafficRange")?.value || "12",
    paused
  };

  writeStorage(CP_STORE.settings, settings);
}

/* ---------- Load persistent data ---------- */

function loadEvents() {
  const saved = readStorage(CP_STORE.events, null);

  if (Array.isArray(saved) && saved.length) {
    events = saved.map(normalizeEvent);
    return;
  }

  const rows = $$("#threatTable tr").filter(row => row.querySelector("td"));

  events = rows.map((row, index) => {
    const cells = [...row.querySelectorAll("td")];
    const detected = cells[3]?.textContent || "";
    const age = detected.match(/(\d+)\s*min/i);

    return normalizeEvent({
      id: row.dataset.eventId || `CP-100${index + 1}`,
      name: row.dataset.eventName ||
        row.querySelector(".event-name")?.textContent.trim(),
      severity: row.dataset.severity || cells[1]?.textContent.trim(),
      source: cells[2]?.textContent.trim(),
      status: row.querySelector(".event-status")?.textContent.trim(),
      description: row.dataset.eventDescription,
      recommendation: row.dataset.recommendation,
      timestamp: Date.now() - (age ? Number(age[1]) : 2) * 60000
    });
  });

  if (!events.length) events = DEFAULT_EVENTS.map(normalizeEvent);
  writeStorage(CP_STORE.events, events);
}

function loadNotifications() {
  const saved = readStorage(CP_STORE.notifications, null);

  notifications = Array.isArray(saved) ? saved : [{
    id: makeId("NT"),
    title: "CyberPulse initialized",
    message: "Stage 7 simulated dashboard is ready.",
    timestamp: Date.now(),
    read: false
  }];

  writeStorage(CP_STORE.notifications, notifications);
}

/* ---------- Threat table ---------- */

function renderEvents() {
  const tbody = $("#threatTable");
  if (!tbody) return;

  const search = ($("#threatSearch")?.value || "").trim().toLowerCase();
  const filter = ($("#severityFilter")?.value || "all").toLowerCase();

  const visible = events.filter(event => {
    const matchesText = !search || [
      event.name, event.source, event.severity, event.status, event.id
    ].some(value => value.toLowerCase().includes(search));

    return matchesText &&
      (filter === "all" || event.severity.toLowerCase() === filter);
  });

  tbody.replaceChildren();

  visible.forEach(event => {
    const row = document.createElement("tr");
    row.dataset.eventId = event.id;
    row.dataset.severity = event.severity.toLowerCase();
    row.dataset.eventName = event.name;
    row.dataset.eventDescription = event.description;
    row.dataset.recommendation = event.recommendation;

    const nameCell = document.createElement("td");
    const detailButton = document.createElement("button");
    detailButton.type = "button";
    detailButton.className = "event-details-trigger";

    const nameSpan = document.createElement("span");
    nameSpan.className = "event-name";
    nameSpan.textContent = event.name;
    detailButton.appendChild(nameSpan);
    detailButton.addEventListener("click", () => openModal(event.id));
    nameCell.appendChild(detailButton);

    const severityCell = document.createElement("td");
    const severity = document.createElement("span");
    severity.className = `severity ${event.severity.toLowerCase()}`;
    severity.textContent = event.severity;
    severityCell.appendChild(severity);

    const sourceCell = document.createElement("td");
    sourceCell.textContent = event.source;

    const timeCell = document.createElement("td");
    timeCell.textContent = relativeTime(event.timestamp);
    timeCell.title = fullDate(event.timestamp);
    timeCell.dataset.eventTime = event.id;

    const statusCell = document.createElement("td");
    const status = document.createElement("span");
    status.className = `event-status ${event.status.toLowerCase()}`;
    status.textContent = event.status;
    statusCell.appendChild(status);

    const actionCell = document.createElement("td");
    const action = document.createElement("button");
    action.type = "button";
    action.className = "row-action";
    action.setAttribute(
      "aria-label",
      event.status === "Resolved" ? "Remove resolved event" : "Resolve alert"
    );
    action.textContent = event.status === "Resolved" ? "×" : "✓";
    action.addEventListener("click", () => {
      if (event.status === "Resolved") removeEvent(event.id);
      else resolveEvent(event.id);
    });
    actionCell.appendChild(action);

    row.append(nameCell, severityCell, sourceCell, timeCell, statusCell, actionCell);
    tbody.appendChild(row);
  });

  if ($("#emptyState")) $("#emptyState").hidden = visible.length > 0;

  if ($("#eventCount")) {
    $("#eventCount").textContent = `Showing ${visible.length} of ${events.length} events`;
  }

  if ($("#navThreatCount")) {
    $("#navThreatCount").textContent = events.filter(
      event => event.status !== "Resolved"
    ).length;
  }

  updateKPIs();
  updateSeverityChart();

  if (window.lucide) window.lucide.createIcons();
}

function updateKPIs() {
  const active = events.filter(event => event.status !== "Resolved");

  const count = severity =>
    active.filter(event => event.severity === severity).length;

  if ($("#openAlerts")) $("#openAlerts").textContent = active.length;
  if ($("#criticalCount")) $("#criticalCount").textContent = count("Critical");
  if ($("#highCount")) $("#highCount").textContent = count("High");
  if ($("#mediumCount")) $("#mediumCount").textContent = count("Medium");
  if ($("#lowCount")) $("#lowCount").textContent = count("Low");

  const score = Math.max(
    35,
    100 - count("Critical") * 15 - count("High") * 8 -
    count("Medium") * 4 - count("Low")
  );

  if ($("#securityScore")) $("#securityScore").textContent = score;
  if ($(".progress-fill")) $(".progress-fill").style.width = `${score}%`;

  if ($("#notificationDot")) {
    $("#notificationDot").hidden = notifications.every(item => item.read);
  }
}

/* ---------- Notifications ---------- */

function addNotification(title, message) {
  notifications.unshift({
    id: makeId("NT"),
    title,
    message,
    timestamp: Date.now(),
    read: false
  });

  notifications = notifications.slice(0, 80);
  writeStorage(CP_STORE.notifications, notifications);
  renderNotifications();
}

function renderNotifications() {
  const list = $("#notificationList");

  if (list) {
    list.replaceChildren();

    if (!notifications.length) {
      const empty = document.createElement("p");
      empty.className = "notification-empty";
      empty.textContent = "No new notifications.";
      list.appendChild(empty);
    } else {
      notifications.forEach(item => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = `notification-item${item.read ? "" : " unread"}`;

        const title = document.createElement("strong");
        title.textContent = item.title;

        const message = document.createElement("span");
        message.textContent = item.message;

        const time = document.createElement("small");
        time.textContent = relativeTime(item.timestamp);

        button.append(title, message, time);
        button.addEventListener("click", () => {
          item.read = true;
          writeStorage(CP_STORE.notifications, notifications);
          renderNotifications();
          updateKPIs();
        });

        list.appendChild(button);
      });
    }
  }

  if ($("#notificationDot")) {
    $("#notificationDot").hidden = notifications.every(item => item.read);
  }
}

function clearNotifications() {
  notifications = [];
  writeStorage(CP_STORE.notifications, notifications);
  renderNotifications();
  updateKPIs();
  toast("Notification history cleared.", "success");
}

/* ---------- Event actions ---------- */

function resolveEvent(id) {
  const event = events.find(item => item.id === id);
  if (!event || event.status === "Resolved") return;

  event.status = "Resolved";
  writeStorage(CP_STORE.events, events);
  renderEvents();
  addNotification("Threat resolved", `${event.name} was marked resolved.`);
  toast("Event marked as resolved.", "success");

  if (selectedEventId === id) openModal(id);
}

function removeEvent(id) {
  events = events.filter(event => event.id !== id);
  writeStorage(CP_STORE.events, events);
  renderEvents();
  toast("Event removed.", "success");
}

function resetEvents() {
  if (!confirm("Reset threat events? Notification history will be kept.")) return;

  events = DEFAULT_EVENTS.map(event => normalizeEvent({ ...event }));
  writeStorage(CP_STORE.events, events);
  renderEvents();
  closeModal();
  addNotification("Threat feed reset", "Sample events have been restored.");
  toast("Threat events reset.", "success");
}

/* ---------- Threat details modal ---------- */

function openModal(id) {
  const event = events.find(item => item.id === id);
  if (!event) return;

  selectedEventId = id;

  const setText = (selector, value) => {
    const element = $(selector);
    if (element) element.textContent = value;
  };

  setText("#modalTitle", event.name);
  setText("#modalDescription", event.description);
  setText("#modalSeverity", event.severity);
  setText("#modalStatus", event.status);
  setText("#modalSource", event.source);
  setText("#modalDetected", fullDate(event.timestamp));
  setText("#modalRecommendation", event.recommendation);

  if ($("#modalSeverity")) {
    $("#modalSeverity").className = `severity ${event.severity.toLowerCase()}`;
  }

  if ($("#resolveFromModal")) {
    $("#resolveFromModal").disabled = event.status === "Resolved";
  }

  const modal = $("#threatModal");
  if (modal) {
    modal.hidden = false;
    modal.classList.add("visible");
    document.body.classList.add("modal-open");
  }
}

function closeModal() {
  const modal = $("#threatModal");
  if (modal) {
    modal.hidden = true;
    modal.classList.remove("visible");
  }
  document.body.classList.remove("modal-open");
  selectedEventId = null;
}

/* ---------- Live simulated events ---------- */

function randomSourceIP() {
  const ranges = ["192.0.2", "198.51.100", "203.0.113"];
  return `${ranges[Math.floor(Math.random() * ranges.length)]}.${Math.floor(Math.random() * 254) + 1}`;
}

function createSimulatedEvent() {
  const templates = [
    ["Unusual DNS request pattern", "Medium", "A simulated device generated unusual DNS requests.", "Review the DNS query history."],
    ["Suspicious outbound connection", "High", "A simulated connection crossed a demo threshold.", "Review the destination and validate the activity."],
    ["Authentication spike detected", "Critical", "A burst of simulated authentication failures triggered an alert.", "Inspect the authentication timeline."],
    ["Configuration policy warning", "Low", "A sample configuration check produced a warning.", "Compare the setting with your approved baseline."],
    ["Port scan pattern", "High", "A simulated event resembles a scan across service ports.", "Confirm whether this activity is authorized."]
  ];

  const template = templates[Math.floor(Math.random() * templates.length)];

  const event = normalizeEvent({
    id: makeId(),
    name: template[0],
    severity: template[1],
    source: randomSourceIP(),
    status: "Open",
    description: template[2],
    recommendation: template[3],
    timestamp: Date.now()
  });

  events.unshift(event);
  events = events.slice(0, 100);

  writeStorage(CP_STORE.events, events);
  renderEvents();
  addNotification(`${event.severity} simulated event`, `${event.name} · ${event.source}`);

  if (event.severity === "Critical") {
    toast(`Critical demo event: ${event.name}`, "warning");
  }
}

function setPaused(value) {
  paused = Boolean(value);
  settings.paused = paused;

  if ($("#simulationToggle")) {
    $("#simulationToggle").innerHTML = paused
      ? '<i data-lucide="play"></i><span>Resume feed</span>'
      : '<i data-lucide="pause"></i><span>Pause feed</span>';
  }

  if (window.lucide) window.lucide.createIcons();

  clearInterval(simulationTimer);
  simulationTimer = null;

  if (!paused) {
    simulationTimer = setInterval(() => {
      if (!document.hidden && !paused) createSimulatedEvent();
    }, 8000);
  }

  saveAll();
}

/* ---------- Live traffic charts ---------- */

function updateTraffic() {
  const range = Math.max(
    3,
    Math.min(12, Number($("#trafficRange")?.value || 12))
  );

  const last = trafficValues[trafficValues.length - 1] || 50;
  trafficValues.push(Math.max(10, Math.min(160, last + (Math.random() - 0.45) * 35)));
  trafficValues = trafficValues.slice(-range);
  tick++;

  const activity = Math.round(trafficValues[trafficValues.length - 1] * 20 + 300);

  if ($("#networkActivity")) $("#networkActivity").textContent = activity.toLocaleString();

  if ($("#trafficSummary")) {
    $("#trafficSummary").textContent =
      `${activity.toLocaleString()} simulated requests/min · updated ${new Date().toLocaleTimeString()}`;
  }

  if (trafficChart) {
    trafficChart.data.labels = trafficValues.map(
      (_, index) => `${(tick - trafficValues.length + index + 1) * 3}s`
    );

    trafficChart.data.datasets[0].data = [...trafficValues];
    trafficChart.data.datasets[1].data = trafficValues.map(
      value => Math.max(5, value * (0.35 + Math.random() * 0.3))
    );

    trafficChart.update("none");
  }
}

function initializeCharts() {
  if (typeof Chart === "undefined") {
    console.warn("Chart.js did not load. Check your internet connection.");
    return;
  }

  if ($("#trafficChart")) {
    trafficChart = new Chart($("#trafficChart"), {
      type: "line",
      data: {
        labels: trafficValues.map((_, index) => `${index * 3}s`),
        datasets: [
          {
            label: "Inbound",
            data: [...trafficValues],
            borderColor: "#55e6ff",
            backgroundColor: "rgba(85,230,255,.10)",
            fill: true,
            tension: 0.38,
            pointRadius: 0,
            borderWidth: 2
          },
          {
            label: "Outbound",
            data: trafficValues.map(value => value * 0.55),
            borderColor: "#a58bfa",
            backgroundColor: "rgba(165,139,250,.06)",
            fill: true,
            tension: 0.38,
            pointRadius: 0,
            borderWidth: 2
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 350 },
        interaction: { intersect: false, mode: "index" },
        plugins: {
          legend: {
            labels: {
              color: "#91a1bd",
              usePointStyle: true,
              boxWidth: 8
            }
          }
        },
        scales: {
          x: {
            ticks: { color: "#91a1bd", maxTicksLimit: 6 },
            grid: { color: "rgba(145,161,189,.08)" }
          },
          y: {
            beginAtZero: true,
            ticks: { color: "#91a1bd" },
            grid: { color: "rgba(145,161,189,.08)" }
          }
        }
      }
    });
  }

  if ($("#severityChart")) {
    severityChart = new Chart($("#severityChart"), {
      type: "doughnut",
      data: {
        labels: SEVERITIES,
        datasets: [{
          data: [0, 0, 0, 0],
          backgroundColor: ["#ff6d91", "#ffb66d", "#e9d36f", "#55e6ff"],
          borderColor: "#111b2d",
          borderWidth: 3,
          hoverOffset: 5
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "68%",
        plugins: { legend: { display: false } }
      }
    });
  }

  updateSeverityChart();
}

function updateSeverityChart() {
  if (!severityChart) return;

  severityChart.data.datasets[0].data = SEVERITIES.map(severity =>
    events.filter(event =>
      event.severity === severity && event.status !== "Resolved"
    ).length
  );

  severityChart.update("none");
}

/* ---------- CSV export ---------- */

function exportCSV() {
  const search = ($("#threatSearch")?.value || "").trim().toLowerCase();
  const filter = ($("#severityFilter")?.value || "all").toLowerCase();

  const filtered = events.filter(event => {
    const matches = !search || [
      event.name, event.source, event.severity, event.status, event.id
    ].some(value => value.toLowerCase().includes(search));

    return matches &&
      (filter === "all" || event.severity.toLowerCase() === filter);
  });

  const headers = [
    "ID", "Event", "Severity", "Source", "Status",
    "Detected", "Description", "Recommendation"
  ];

  const csvCell = value =>
    `"${String(value ?? "").replace(/"/g, '""')}"`;

  const csv = [
    headers,
    ...filtered.map(event => [
      event.id,
      event.name,
      event.severity,
      event.source,
      event.status,
      fullDate(event.timestamp),
      event.description,
      event.recommendation
    ])
  ].map(row => row.map(csvCell).join(",")).join("\r\n");

  const url = URL.createObjectURL(
    new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8;" })
  );

  const link = document.createElement("a");
  link.href = url;
  link.download = `cyberpulse-events-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);

  toast(`${filtered.length} events exported to CSV.`, "success");
}

/* ---------- Controls and navigation ---------- */

function connectControls() {
  const search = $("#threatSearch");
  const severity = $("#severityFilter");
  const range = $("#trafficRange");

  if (search) search.value = settings.search || "";
  if (severity) severity.value = settings.severity || "all";
  if (range) range.value = settings.range || "12";

  search?.addEventListener("input", () => {
    settings.search = search.value;
    writeStorage(CP_STORE.settings, settings);
    renderEvents();
  });

  severity?.addEventListener("change", () => {
    settings.severity = severity.value;
    writeStorage(CP_STORE.settings, settings);
    renderEvents();
  });

  range?.addEventListener("change", () => {
    settings.range = range.value;
    trafficValues = trafficValues.slice(-Number(range.value || 12));
    writeStorage(CP_STORE.settings, settings);
    updateTraffic();
  });

  $("#simulationToggle")?.addEventListener("click", () => {
    setPaused(!paused);
    toast(paused ? "Threat feed paused." : "Threat feed resumed.");
  });

  $("#resetEvents")?.addEventListener("click", resetEvents);
  $("#exportEvents")?.addEventListener("click", exportCSV);
  $("#clearNotifications")?.addEventListener("click", clearNotifications);

  $("#resolveFromModal")?.addEventListener("click", () => {
    if (selectedEventId) resolveEvent(selectedEventId);
  });

  $("#closeThreatModal")?.addEventListener("click", closeModal);
  $("#closeModalSecondary")?.addEventListener("click", closeModal);

  $("#threatModal")?.addEventListener("click", event => {
    if (event.target.id === "threatModal") closeModal();
  });

  document.addEventListener("keydown", event => {
    if (event.key === "Escape") closeModal();
  });

  const notificationButton = $("#notificationButton");
  const notificationPanel = $("#notificationPanel");

  notificationButton?.addEventListener("click", event => {
    event.stopPropagation();
    const opening = notificationPanel.hidden;
    notificationPanel.hidden = !opening;
    notificationButton.setAttribute("aria-expanded", String(opening));

    if (opening) {
      notifications.forEach(item => item.read = true);
      writeStorage(CP_STORE.notifications, notifications);
      renderNotifications();
      updateKPIs();
    }
  });

  document.addEventListener("click", event => {
    if (
      notificationPanel &&
      !notificationPanel.contains(event.target) &&
      !notificationButton?.contains(event.target)
    ) {
      notificationPanel.hidden = true;
      notificationButton?.setAttribute("aria-expanded", "false");
    }
  });

  $("#menuToggle")?.addEventListener("click", () => {
    $("#sidebar")?.classList.toggle("sidebar-open");
  });

  $$(".sidebar-nav .nav-link").forEach(link => {
    link.addEventListener("click", () => {
      $$(".sidebar-nav .nav-link").forEach(item => item.classList.remove("active"));
      link.classList.add("active");
      $("#sidebar")?.classList.remove("sidebar-open");
    });
  });

  $("#viewDevices")?.addEventListener("click", () => {
    toast("Device inventory is illustrative demo data.");
  });
}

/* ---------- Start dashboard ---------- */

function initializeCyberPulse() {
  if ($("#currentDate")) {
    $("#currentDate").textContent = new Date().toLocaleDateString(undefined, {
      weekday: "long",
      year: "numeric",
      month: "long",
      day: "numeric"
    });
  }

  if ($("#year")) $("#year").textContent = new Date().getFullYear();

  loadEvents();
  loadNotifications();
  connectControls();
  initializeCharts();
  renderEvents();
  renderNotifications();
  updateKPIs();
  setPaused(paused);

  trafficTimer = setInterval(() => {
    if (!document.hidden) updateTraffic();
  }, 3000);

  setInterval(() => {
    $$("#threatTable tr").forEach(row => {
      const event = events.find(item => item.id === row.dataset.eventId);
      const timeCell = row.querySelector("[data-event-time]");
      if (event && timeCell) {
        timeCell.textContent = relativeTime(event.timestamp);
        timeCell.title = fullDate(event.timestamp);
      }
    });
  }, 15000);

  setInterval(saveAll, 30000);

  if (window.lucide) window.lucide.createIcons();

  console.info("CyberPulse Stage 7 initialized. All telemetry is simulated.");
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initializeCyberPulse);
} else {
  initializeCyberPulse();
}

/* ==========================================
   CYBERPULSE STAGE 8 — NETWORK MAP LOGIC
   Add this block at the bottom of script.js
   ========================================== */

(function initializeCyberPulseNetworkMap() {
    "use strict";

    const canvas = document.getElementById("cpNetworkCanvas");

    // Exit safely if the Stage 8 HTML has not been added.
    if (!canvas) return;

    const deviceData = {
        internet: {
            name: "Internet",
            ip: "External network",
            role: "External connectivity",
            description: "Represents simulated external network traffic entering and leaving the environment.",
            status: "CONNECTED"
        },
        gateway: {
            name: "Gateway Router",
            ip: "192.0.2.1",
            role: "Network gateway",
            description: "Represents the gateway that connects the simulated internal network to the external network.",
            status: "ONLINE"
        },
        workstation: {
            name: "Workstation 01",
            ip: "192.0.2.21",
            role: "Endpoint device",
            description: "Represents a user workstation that could generate simulated outbound traffic or security events.",
            status: "ONLINE"
        },
        server: {
            name: "Core Server",
            ip: "192.0.2.10",
            role: "Application server",
            description: "Represents a central server handling simulated application and network activity.",
            status: "ONLINE"
        },
        database: {
            name: "Database Node",
            ip: "192.0.2.30",
            role: "Data storage",
            description: "Represents a database server in the simulated network topology.",
            status: "ONLINE"
        }
    };

    const nodeElements = Array.from(
        canvas.querySelectorAll("[data-cp-device]")
    );

    const selectedName = document.getElementById("cpDeviceName");
    const selectedDescription = document.getElementById("cpDeviceDescription");
    const totalDevices = document.getElementById("cpTotalDevices");
    const totalConnections = document.getElementById("cpTotalConnections");
    const flaggedNodes = document.getElementById("cpFlaggedNodes");
    const simulateButton = document.getElementById("cpSimulateThreat");
    const resetButton = document.getElementById("cpResetNetwork");

    let selectedDevice = null;
    let flaggedDevice = null;

    function getNode(deviceId) {
        return nodeElements.find(function (node) {
            return node.dataset.cpDevice === deviceId;
        });
    }

    function updateMetrics() {
        if (totalDevices) {
            totalDevices.textContent = String(nodeElements.length);
        }

        if (totalConnections) {
            totalConnections.textContent = "7";
        }

        if (flaggedNodes) {
            flaggedNodes.textContent = flaggedDevice ? "1" : "0";
        }
    }

    function selectDevice(deviceId) {
        const device = deviceData[deviceId];
        if (!device) return;

        selectedDevice = deviceId;

        nodeElements.forEach(function (node) {
            node.classList.toggle(
                "cp-node-selected",
                node.dataset.cpDevice === deviceId
            );
        });

        if (selectedName) {
            selectedName.textContent = device.name;
        }

        if (selectedDescription) {
            const isFlagged = flaggedDevice === deviceId;

            selectedDescription.textContent =
                "IP: " + device.ip +
                " | Role: " + device.role +
                " | Status: " +
                (isFlagged ? "SUSPICIOUS — simulated threat indicator. " : device.status + ". ") +
                device.description;
        }
    }

    function simulateThreat() {
        // Choose an internal device for this demonstration.
        const candidates = ["gateway", "workstation", "server", "database"];

        const availableCandidates = candidates.filter(function (id) {
            return id !== flaggedDevice;
        });

        if (availableCandidates.length === 0) {
            resetThreat();
        }

        const pool = candidates.filter(function (id) {
            return id !== flaggedDevice;
        });

        const randomDevice =
            pool[Math.floor(Math.random() * pool.length)];

        flaggedDevice = randomDevice;

        nodeElements.forEach(function (node) {
            const isThreat =
                node.dataset.cpDevice === flaggedDevice;

            node.classList.toggle("cp-node-threat", isThreat);

            const statusLabel = node.querySelector(".cp-node-state");

            if (statusLabel) {
                const id = node.dataset.cpDevice;

                if (id === flaggedDevice) {
                    statusLabel.textContent = "SUSPICIOUS";
                } else {
                    statusLabel.textContent = deviceData[id].status;
                }
            }
        });

        selectDevice(randomDevice);
        updateMetrics();

        if (simulateButton) {
            simulateButton.innerHTML =
                '<i data-lucide="shield-check"></i> Threat Simulated';

            simulateButton.disabled = true;
            simulateButton.style.opacity = "0.75";

            window.setTimeout(function () {
                simulateButton.innerHTML =
                    '<i data-lucide="shield-alert"></i> Simulate Threat';

                simulateButton.disabled = false;
                simulateButton.style.opacity = "";

                if (window.lucide) {
                    window.lucide.createIcons();
                }
            }, 1200);
        }

        if (window.lucide) {
            window.lucide.createIcons();
        }
    }

    function resetThreat() {
        flaggedDevice = null;

        nodeElements.forEach(function (node) {
            node.classList.remove("cp-node-threat");

            const id = node.dataset.cpDevice;
            const statusLabel = node.querySelector(".cp-node-state");

            if (statusLabel && deviceData[id]) {
                statusLabel.textContent = deviceData[id].status;
            }
        });

        updateMetrics();

        if (selectedDevice) {
            selectDevice(selectedDevice);
        } else {
            if (selectedName) {
                selectedName.textContent = "Select a device";
            }

            if (selectedDescription) {
                selectedDescription.textContent =
                    "Click any node in the map to inspect its simulated status.";
            }
        }
    }

    function resetNetwork() {
        resetThreat();

        selectedDevice = null;

        nodeElements.forEach(function (node) {
            node.classList.remove("cp-node-selected");
        });

        if (selectedName) {
            selectedName.textContent = "Select a device";
        }

        if (selectedDescription) {
            selectedDescription.textContent =
                "Network map reset. Select a node to inspect its simulated details.";
        }

        updateMetrics();
    }

    nodeElements.forEach(function (node) {
        node.addEventListener("click", function () {
            selectDevice(node.dataset.cpDevice);
        });
    });

    if (simulateButton) {
        simulateButton.addEventListener("click", simulateThreat);
    }

    if (resetButton) {
        resetButton.addEventListener("click", resetNetwork);
    }

    updateMetrics();

    if (window.lucide) {
        window.lucide.createIcons();
    }

    console.log("CyberPulse Stage 8 network map initialized.");
})();

/* ==========================================
   CYBERPULSE STAGE 9 — ANALYTICS ENGINE
   Append below all existing script.js code
   ========================================== */

(function initializeCyberPulseStage9() {
    "use strict";

    const $ = function (id) {
        return document.getElementById(id);
    };

    const requiredElements = [
        "securityAnalytics",
        "cp9RiskScore",
        "cp9RiskLevel",
        "cp9RiskGauge",
        "cp9SeverityChart",
        "cp9TrendChart",
        "cp9InsightsList"
    ];

    if (!requiredElements.every(function (id) {
        return Boolean($(id));
    })) {
        return;
    }

    let severityChart = null;
    let trendChart = null;
    let lastSignature = "";
    let refreshQueued = false;

    const severityColors = {
        critical: "#fb7185",
        high: "#fb923c",
        medium: "#facc15",
        low: "#34d399"
    };

    function normalizeText(value) {
        return String(value || "").toLowerCase().trim();
    }

    function readThreatEvents() {
        const tableBody = $("threatTable");

        if (!tableBody) {
            return [];
        }

        const rows = Array.from(tableBody.querySelectorAll("tr"));

        return rows.map(function (row, index) {
            const text = normalizeText(row.innerText || row.textContent);

            if (!text || row.querySelector("#emptyState") ||
                row.classList.contains("empty-state")) {
                return null;
            }

            if (
                text.includes("no events found") ||
                text.includes("no threats found") ||
                text.includes("no events to display") ||
                text.includes("no threat events")
            ) {
                return null;
            }

            const severityMatch = text.match(
                /\b(critical|high|medium|low)\b/
            );

            const severity = severityMatch
                ? severityMatch[1]
                : "unknown";

            const resolved = /\b(resolved|mitigated|closed)\b/.test(text);
            const pending = /\b(open|unresolved|pending|investigating)\b/.test(text);

            return {
                id: row.dataset.eventId || row.id || "event-" + index,
                text: text,
                severity: severity,
                resolved: resolved,
                pending: pending,
                index: index
            };
        }).filter(Boolean);
    }

    function calculateAnalytics(events) {
        const counts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            unknown: 0
        };

        events.forEach(function (event) {
            counts[event.severity] =
                (counts[event.severity] || 0) + 1;
        });

        const unresolved = events.filter(function (event) {
            return !event.resolved;
        });

        const highPriority = events.filter(function (event) {
            return event.severity === "critical" ||
                   event.severity === "high";
        });

        // Transparent, illustrative risk heuristic.
        // Unresolved alerts contribute more than resolved alerts.
        let risk = 8;

        events.forEach(function (event) {
            const severityWeight = {
                critical: 26,
                high: 15,
                medium: 7,
                low: 2,
                unknown: 1
            }[event.severity] || 1;

            risk += event.resolved
                ? severityWeight * 0.2
                : severityWeight;
        });

        risk = Math.max(0, Math.min(100, Math.round(risk)));

        let level;
        let color;
        let explanation;

        if (risk >= 76) {
            level = "CRITICAL RISK";
            color = "#fb7185";
            explanation = "The illustrative risk heuristic is elevated. Review critical alerts and prioritize incident containment.";
        } else if (risk >= 51) {
            level = "HIGH RISK";
            color = "#fb923c";
            explanation = "The illustrative risk heuristic indicates significant outstanding risk. Investigate high-priority events.";
        } else if (risk >= 26) {
            level = "MODERATE RISK";
            color = "#facc15";
            explanation = "Some risk indicators are present. Review unresolved alerts and verify their status.";
        } else {
            level = "LOW RISK";
            color = "#34d399";
            explanation = events.length
                ? "The illustrative score is relatively low based on visible event rows. This does not prove the network is secure."
                : "No event rows were identified. This is not proof of a secure network or an absence of threats.";
        }

        return {
            counts: counts,
            total: events.length,
            unresolved: unresolved.length,
            highPriority: highPriority.length,
            risk: risk,
            level: level,
            color: color,
            explanation: explanation
        };
    }

    function updateText(analytics) {
        $("cp9RiskScore").textContent = String(analytics.risk);
        $("cp9RiskLevel").textContent = analytics.level;
        $("cp9RiskLevel").style.color = analytics.color;
        $("cp9RiskExplanation").textContent = analytics.explanation;

        $("cp9RiskGauge").style.background =
            "conic-gradient(" + analytics.color + " " +
            (analytics.risk * 3.6) + "deg, #263244 " +
            (analytics.risk * 3.6) + "deg 360deg)";

        $("cp9RiskGauge").setAttribute(
            "aria-label",
            "Illustrative security risk score: " + analytics.risk + " out of 100"
        );

        $("cp9TotalEvents").textContent = String(analytics.total);
        $("cp9UnresolvedEvents").textContent = String(analytics.unresolved);
        $("cp9HighPriorityEvents").textContent = String(analytics.highPriority);

        $("cp9CriticalCount").textContent = String(analytics.counts.critical);
        $("cp9HighCount").textContent = String(analytics.counts.high);
        $("cp9MediumCount").textContent = String(analytics.counts.medium);
        $("cp9LowCount").textContent = String(analytics.counts.low);

        $("cp9EventStatus").textContent = analytics.total
            ? "Visible events analyzed"
            : "No visible event rows";

        $("cp9UnresolvedStatus").textContent = analytics.unresolved
            ? "Review outstanding events"
            : "No unresolved rows identified";

        $("cp9PriorityStatus").textContent = analytics.highPriority
            ? "Priority review recommended"
            : "No high-priority rows identified";

        $("cp9RiskUpdated").textContent =
            "Rule-based estimate • Not a real audit";

        $("cp9LastAnalyzed").textContent =
            "Analyzed " + new Date().toLocaleTimeString();
    }

    function initializeSeverityChart(analytics) {
        const canvas = $("cp9SeverityChart");

        if (!canvas || typeof Chart === "undefined") {
            return;
        }

        const data = [
            analytics.counts.critical,
            analytics.counts.high,
            analytics.counts.medium,
            analytics.counts.low
        ];

        if (!severityChart) {
            severityChart = new Chart(canvas, {
                type: "doughnut",
                data: {
                    labels: ["Critical", "High", "Medium", "Low"],
                    datasets: [{
                        data: data,
                        backgroundColor: [
                            severityColors.critical,
                            severityColors.high,
                            severityColors.medium,
                            severityColors.low
                        ],
                        borderColor: "#0c1422",
                        borderWidth: 4,
                        hoverOffset: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: "70%",
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                label: function (context) {
                                    return context.label + ": " + context.raw;
                                }
                            }
                        }
                    }
                }
            });
        } else {
            severityChart.data.datasets[0].data = data;
            severityChart.update("none");
        }
    }

    function initializeTrendChart(events) {
        const canvas = $("cp9TrendChart");

        if (!canvas || typeof Chart === "undefined") {
            return;
        }

        // Divide visible table rows into up to seven ordered groups.
        // These are not clock-based intervals.
        const groupCount = 7;
        const labels = [];
        const critical = [];
        const high = [];
        const medium = [];
        const low = [];

        for (let group = 0; group < groupCount; group++) {
            labels.push("Group " + (group + 1));
            critical.push(0);
            high.push(0);
            medium.push(0);
            low.push(0);
        }

        events.forEach(function (event, index) {
            const group = Math.min(
                groupCount - 1,
                Math.floor(index * groupCount / Math.max(events.length, 1))
            );

            if (event.severity === "critical") critical[group]++;
            if (event.severity === "high") high[group]++;
            if (event.severity === "medium") medium[group]++;
            if (event.severity === "low") low[group]++;
        });

        const datasets = [
            { label: "Critical", data: critical, color: severityColors.critical },
            { label: "High", data: high, color: severityColors.high },
            { label: "Medium", data: medium, color: severityColors.medium },
            { label: "Low", data: low, color: severityColors.low }
        ].map(function (item) {
            return {
                label: item.label,
                data: item.data,
                borderColor: item.color,
                backgroundColor: item.color,
                borderWidth: 2,
                pointRadius: 3,
                pointHoverRadius: 5,
                tension: 0.35
            };
        });

        if (!trendChart) {
            trendChart = new Chart(canvas, {
                type: "line",
                data: {
                    labels: labels,
                    datasets: datasets
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {
                        intersect: false,
                        mode: "index"
                    },
                    plugins: {
                        legend: {
                            display: true,
                            position: "bottom",
                            labels: {
                                color: "#94a3b8",
                                usePointStyle: true,
                                boxWidth: 7,
                                padding: 14,
                                font: { size: 10 }
                            }
                        }
                    },
                    scales: {
                        x: {
                            grid: { color: "#64748b18" },
                            ticks: {
                                color: "#94a3b8",
                                font: { size: 10 }
                            },
                            border: { display: false }
                        },
                        y: {
                            beginAtZero: true,
                            ticks: {
                                precision: 0,
                                color: "#94a3b8",
                                font: { size: 10 }
                            },
                            grid: { color: "#64748b20" },
                            border: { display: false }
                        }
                    }
                }
            });
        } else {
            trendChart.data.labels = labels;
            trendChart.data.datasets.forEach(function (dataset, index) {
                dataset.data = datasets[index].data;
            });
            trendChart.update("none");
        }
    }

    function buildInsights(analytics, events) {
        const insights = [];

        const criticalUnresolved = events.filter(function (event) {
            return event.severity === "critical" && !event.resolved;
        }).length;

        const highUnresolved = events.filter(function (event) {
            return event.severity === "high" && !event.resolved;
        }).length;

        if (criticalUnresolved > 0) {
            insights.push({
                type: "danger",
                icon: "shield-alert",
                title: "Prioritize unresolved critical events",
                description: criticalUnresolved +
                    " visible critical event(s) are not marked resolved. Review the event details and follow your incident-response procedure."
            });
        }

        if (highUnresolved > 0) {
            insights.push({
                type: "warning",
                icon: "alert-triangle",
                title: "Investigate high-severity events",
                description: highUnresolved +
                    " visible high-severity event(s) are not marked resolved. Verify their context and determine appropriate next steps."
            });
        }

        if (analytics.counts.critical > 0 || analytics.counts.high > 0) {
            insights.push({
                type: "warning",
                icon: "chart-no-axes-combined",
                title: "High-severity events are present",
                description: "The visible history contains " +
                    (analytics.counts.critical + analytics.counts.high) +
                    " critical or high-severity event(s). Review timestamps, sources, and event details before drawing conclusions."
            });
        }

        if (analytics.unresolved > 0 && criticalUnresolved === 0 && highUnresolved === 0) {
            insights.push({
                type: "warning",
                icon: "clipboard-list",
                title: "Review unresolved events",
                description: analytics.unresolved +
                    " visible event(s) are not marked resolved. Confirm whether they require investigation or closure."
            });
        }

        if (analytics.total === 0) {
            insights.push({
                type: "positive",
                icon: "database",
                title: "No event rows detected",
                description: "The analytics panel could not identify event rows in the visible threat table. Generate simulated events or check the table structure. This does not mean the environment is threat-free."
            });
        } else if (insights.length === 0) {
            insights.push({
                type: "positive",
                icon: "shield-check",
                title: "No visible high-priority events identified",
                description: "No critical or high-severity event rows were identified in the visible history. Continue reviewing new events and verify the source data."
            });
        }

        insights.push({
            type: "normal",
            icon: "list-check",
            title: "Recommended review workflow",
            description: "Inspect the event details, validate the source and timestamp, prioritize by severity, record the response, and mark an event resolved only after verification."
        });

        return insights;
    }

    function renderInsights(analytics, events) {
        const container = $("cp9InsightsList");
        const insights = buildInsights(analytics, events);

        container.replaceChildren();

        insights.forEach(function (insight) {
            const article = document.createElement("div");
            article.className = "cp9-insight";

            if (insight.type === "warning") {
                article.classList.add("cp9-insight-warning");
            } else if (insight.type === "danger") {
                article.classList.add("cp9-insight-danger");
            } else if (insight.type === "positive") {
                article.classList.add("cp9-insight-positive");
            }

            const iconWrap = document.createElement("span");
            iconWrap.className = "cp9-insight-icon";

            const icon = document.createElement("i");
            icon.setAttribute("data-lucide", insight.icon);
            iconWrap.appendChild(icon);

            const content = document.createElement("div");
            const title = document.createElement("strong");
            const description = document.createElement("p");

            title.textContent = insight.title;
            description.textContent = insight.description;

            content.appendChild(title);
            content.appendChild(description);
            article.appendChild(iconWrap);
            article.appendChild(content);
            container.appendChild(article);
        });

        if (window.lucide) {
            window.lucide.createIcons();
        }
    }

    function refreshAnalytics(force) {
        const events = readThreatEvents();
        const analytics = calculateAnalytics(events);

        const signature = JSON.stringify({
            events: events.map(function (event) {
                return [
                    event.id,
                    event.severity,
                    event.resolved,
                    event.pending,
                    event.text
                ];
            })
        });

        updateText(analytics);
        initializeSeverityChart(analytics);
        initializeTrendChart(events);

        if (force || signature !== lastSignature) {
            renderInsights(analytics, events);
            lastSignature = signature;
        }
    }

    const refreshButton = $("cp9RefreshAnalytics");

    if (refreshButton) {
        refreshButton.addEventListener("click", function () {
            refreshAnalytics(true);

            refreshButton.innerHTML =
                '<i data-lucide="check-circle-2"></i> Analysis refreshed';

            if (window.lucide) {
                window.lucide.createIcons();
            }

            window.setTimeout(function () {
                refreshButton.innerHTML =
                    '<i data-lucide="refresh-cw"></i> Refresh analysis';

                if (window.lucide) {
                    window.lucide.createIcons();
                }
            }, 1200);
        });
    }

    // Watch for changes to the existing threat table.
    const tableBody = $("threatTable");

    if (tableBody && typeof MutationObserver !== "undefined") {
        const observer = new MutationObserver(function () {
            if (refreshQueued) return;

            refreshQueued = true;

            window.requestAnimationFrame(function () {
                refreshQueued = false;
                refreshAnalytics(false);
            });
        });

        observer.observe(tableBody, {
            childList: true,
            subtree: true,
            characterData: true,
            attributes: true
        });
    }

    // Also refresh periodically in case event status changes elsewhere.
    window.setInterval(function () {
        refreshAnalytics(false);
    }, 5000);

    // Initial calculation.
    refreshAnalytics(true);

    console.log("CyberPulse Stage 9 analytics initialized.");
})();

/* ==========================================
   WORKSPACE SCROLL NAVIGATION
   ========================================== */

(function initializeWorkspaceNavigation() {
    "use strict";

    const nav = document.getElementById("workspaceNav");

    if (!nav) return;

    const links = Array.from(nav.querySelectorAll(".nav-link"));

    const sections = links
        .map(function (link) {
            const id = link.dataset.section;
            return document.getElementById(id);
        })
        .filter(Boolean);

    function setActiveSection(sectionId) {
        links.forEach(function (link) {
            const isActive = link.dataset.section === sectionId;

            link.classList.toggle("active", isActive);

            if (isActive) {
                link.setAttribute("aria-current", "location");
            } else {
                link.removeAttribute("aria-current");
            }
        });
    }

    // Smoothly navigate to a section when a workspace link is clicked.
    links.forEach(function (link) {
        link.addEventListener("click", function (event) {
            const targetId = link.dataset.section;
            const target = document.getElementById(targetId);

            if (!target) return;

            event.preventDefault();

            target.scrollIntoView({
                behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches
                    ? "auto"
                    : "smooth",
                block: "start"
            });

            if (window.location.hash !== "#" + targetId) {
                window.history.replaceState(null, "", "#" + targetId);
            }

            setActiveSection(targetId);

            // Close the mobile sidebar if your existing CSS uses this class.
            const sidebar = document.getElementById("sidebar");

            if (sidebar && window.innerWidth <= 768) {
                sidebar.classList.remove("open");
            }
        });
    });

    // Update the selected workspace item while scrolling.
    if ("IntersectionObserver" in window) {
        const observer = new IntersectionObserver(function (entries) {
            const visibleSections = entries
                .filter(function (entry) {
                    return entry.isIntersecting;
                })
                .sort(function (a, b) {
                    return b.intersectionRatio - a.intersectionRatio;
                });

            if (visibleSections.length > 0) {
                setActiveSection(visibleSections[0].target.id);
            }
        }, {
            root: null,
            rootMargin: "-15% 0px -60% 0px",
            threshold: [0, 0.1, 0.25, 0.5]
        });

        sections.forEach(function (section) {
            observer.observe(section);
        });
    }

    // Support direct links such as #securityAnalytics.
    const initialId = window.location.hash.slice(1);

    if (initialId && sections.some(function (section) {
        return section.id === initialId;
    })) {
        setActiveSection(initialId);
    } else {
        setActiveSection("overview");
    }
})();


/* =========================================================
   CYBERPULSE REAL-TIME SECURITY API CONNECTOR
   Frontend polls the local backend; secrets stay server-side.
   ========================================================= */
(function initializeSecurityApiConnector() {
  "use strict";
  const status = document.getElementById("cpApiStatus");
  const POLL_INTERVAL_MS = 10000;
  let requestInProgress = false;
  let firstSuccessfulLoad = false;

  function setStatus(kind, label) {
    if (!status) return;
    status.classList.remove("connected", "error");
    if (kind) status.classList.add(kind);
    status.lastChild.textContent = " " + label;
  }

  async function pollSecurityApi() {
    if (requestInProgress || document.hidden) return;
    requestInProgress = true;
    try {
      const response = await fetch("/api/security/events", {
        method: "GET",
        headers: { "Accept": "application/json" },
        cache: "no-store"
      });
      if (!response.ok) throw new Error("API backend returned HTTP " + response.status);
      const payload = await response.json();
      if (!payload || !Array.isArray(payload.events)) {
        throw new Error("Expected { events: [...] } from the security API backend");
      }

      const apiEvents = payload.events.map((item, index) => normalizeEvent({
        id: item.id || item.event_id || item.uuid || "API-" + index,
        name: item.name || item.title || item.rule_name || item.description || "Security event",
        severity: item.severity || item.level || "Medium",
        source: item.source || item.source_ip || item.src_ip || item.agent_name || "Unknown source",
        status: item.status || "Open",
        description: item.description || item.message || "Imported from connected security API.",
        recommendation: item.recommendation || item.action || "Review this event in your security provider.",
        timestamp: item.timestamp ? (Number.isFinite(Number(item.timestamp)) ? Number(item.timestamp) : Date.parse(item.timestamp)) : Date.now()
      }));

      // In API mode, show provider events rather than creating misleading demo events.
      if (typeof setPaused === "function") setPaused(true);
      events = apiEvents.slice(0, 100);
      writeStorage(CP_STORE.events, events);
      renderEvents();

      setStatus("connected", "SECURITY API LIVE");
      firstSuccessfulLoad = true;
      if (payload.provider && status) status.title = "Connected provider: " + payload.provider;
    } catch (error) {
      setStatus("error", "API DISCONNECTED");
      if (!firstSuccessfulLoad) console.warn("CyberPulse security API connector:", error.message);
    } finally {
      requestInProgress = false;
    }
  }

  // Initial connection plus periodic polling. This is real API ingestion only
  // when the backend is configured with a real provider endpoint and credentials.
  pollSecurityApi();
  window.setInterval(pollSecurityApi, POLL_INTERVAL_MS);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) pollSecurityApi();
  });
})();
