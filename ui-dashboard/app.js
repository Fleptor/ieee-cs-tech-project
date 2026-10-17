"use strict";
const $ = (id) => document.getElementById(id);
const escapeHtml = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const state = {
  token: sessionStorage.getItem("cipher_token"),
  networks: [],
  network: null,
  data: null,
  username: "",
  generation: 0,
  loading: false,
  signup: false,
  action: null,
  stale: false,
  networksLoaded: false,
};
const views = {
  overview: [
    "Network overview",
    "A clear view of your network. Every signal grounded in live telemetry.",
  ],
  devices: [
    "Device inventory",
    "Find a device, inspect its state, and manage its access.",
  ],
  incidents: [
    "Security incidents",
    "Review the findings recorded by the CIPHER analysis engine.",
  ],
  intelligence: [
    "Threat intelligence",
    "Inspect the indicators configured for your edge sensors.",
  ],
  engine: [
    "Engine health",
    "Know which parts of your protection pipeline are reporting.",
  ],
};
const fmt = (n) => Number(n || 0).toLocaleString();
function bytes(n) {
  if (!n) return "0 B";
  const i = Math.min(4, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${["B", "KB", "MB", "GB", "TB"][i]}`;
}
function date(value) {
  if (!value) return "Unknown";
  const normalized =
    typeof value === "number"
      ? value * 1000
      : /^\d{4}-\d\d-\d\d \d/.test(value)
        ? value.replace(" ", "T") + "Z"
        : value;
  const d = new Date(normalized);
  return Number.isNaN(d.valueOf())
    ? "Unknown"
    : d.toLocaleString([], {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
}
function empty(title, text) {
  return `<div class="empty compact"><div><span class="empty-icon">◇</span><h3>${escapeHtml(title)}</h3><p>${escapeHtml(text)}</p></div></div>`;
}
function badge(label, kind = label) {
  return `<span class="badge ${escapeHtml(kind)}">${escapeHtml(label)}</span>`;
}
function toast(message) {
  $("toast").textContent = message;
  $("toast").hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => {
    $("toast").hidden = true;
  }, 5000);
}

async function api(path, method = "GET", body, token = state.token) {
  const response = await fetch(path, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(12000),
    cache: "no-store",
  });
  if (!response.ok) {
    const message =
      response.status === 401
        ? "Your session expired or access was denied. Sign in to continue."
        : response.status === 409
          ? "The request conflicts with existing data. Check the details and try again."
          : response.status === 404
            ? "This device or endpoint is no longer available."
            : `The server could not complete the request (${response.status}).`;
    if (response.status === 401 && token && token === state.token) signOut();
    throw new Error(message);
  }
  return response.headers.get("content-type")?.includes("application/json")
    ? response.json()
    : response.text();
}
function switchView() {
  const view =
    location.hash.slice(1) in views ? location.hash.slice(1) : "overview";
  document.querySelectorAll(".view").forEach((el) => {
    el.hidden = el.id !== `view-${view}`;
  });
  document.querySelectorAll("[data-view]").forEach((el) => {
    el.classList.toggle("selected", el.dataset.view === view);
    if (el.dataset.view === view) el.setAttribute("aria-current", "page");
    else el.removeAttribute("aria-current");
  });
  $("page-title").textContent = views[view][0];
  $("page-description").textContent = views[view][1];
  $("breadcrumb").textContent = {
    overview: "Overview",
    devices: "Devices",
    incidents: "Incidents",
    intelligence: "Threat intelligence",
    engine: "Engine health",
  }[view];
  $("sidebar").classList.remove("open");
  $("menu").setAttribute("aria-expanded", "false");
}
function notice(title, message, warning = false, auth = false) {
  $("notice").hidden = false;
  $("notice").className = `notice${warning ? " warning" : ""}`;
  $("notice").querySelector("strong").textContent = title;
  $("notice").querySelector("p").textContent = message;
  $("notice-auth").hidden = !auth;
}
function connection(text, online = false) {
  $("connection").innerHTML =
    `<i class="dot ${online ? "online" : ""}"></i>${escapeHtml(text)}`;
}
function signOut() {
  $("sidebar").classList.remove("open");
  $("menu").setAttribute("aria-expanded", "false");
  state.generation++;
  state.token = null;
  state.data = null;
  state.network = null;
  state.networks = [];
  state.networksLoaded = false;
  state.username = "";
  state.loading = false;
  state.stale = false;
  sessionStorage.removeItem("cipher_token");
  localStorage.removeItem("cipher_jwt");
  localStorage.removeItem("cipher_user");
  $("network").innerHTML = "<option>Sign in to select a network</option>";
  $("network").disabled = true;
  $("refresh").disabled = true;
  $("auth-open").hidden = false;
  $("logout").hidden = true;
  $("username").textContent = "Operator console";
  $("role").textContent = "Not signed in";
  $("avatar").textContent = "C";
  $("action-dialog").close();
  state.action = null;
  connection("Not connected");
  notice(
    "Connect to your network",
    "Sign in to see your devices, traffic, and security activity. New installation? Create the first operator account to connect your configured network.",
    false,
    true,
  );
  $("last-updated").textContent = "Awaiting authenticated connection";
  render();
}
async function loadNetworks() {
  const generation = ++state.generation;
  const result = await api("/api/networks");
  if (generation !== state.generation) return;
  state.username = result.username;
  state.networks = result.networks;
  state.networksLoaded = true;
  $("username").textContent = result.username;
  $("avatar").textContent = result.username.slice(0, 1).toUpperCase();
  $("auth-open").hidden = true;
  $("logout").hidden = false;
  $("network").innerHTML = state.networks.length
    ? state.networks
        .map(
          (n) =>
            `<option value="${escapeHtml(n.network_id)}">${escapeHtml(n.network_id)}</option>`,
        )
        .join("")
    : "<option>No assigned networks</option>";
  $("network").disabled = !state.networks.length;
  if (!state.networks.length) {
    notice(
      "No network assigned",
      "Your account is ready. Ask the installation owner to assign you to a network.",
    );
    connection("Signed in");
    render();
    return;
  }
  const saved = localStorage.getItem("cipher_network");
  state.network =
    state.networks.find((n) => n.network_id === saved)?.network_id ||
    state.networks[0].network_id;
  $("network").value = state.network;
  $("refresh").disabled = false;
  await refresh();
}
async function refresh() {
  if (!state.token || !state.network || state.loading) return;
  const generation = state.generation,
    network = state.network;
  state.loading = true;
  $("refresh").disabled = true;
  try {
    const encoded = state.token.split(".")[1].replaceAll("-", "+").replaceAll("_", "/");
    const expires = JSON.parse(atob(encoded)).exp;
    if (expires - Date.now() / 1000 < 900) {
      const token = await api("/api/session/refresh", "POST", {});
      if (generation !== state.generation) return;
      state.token = token; sessionStorage.setItem("cipher_token", token);
    }
    const data = await api(`/api/dashboard/${encodeURIComponent(network)}`);
    if (generation !== state.generation || network !== state.network) return;
    state.data = data;
    state.stale = false;
    $("role").textContent = state.networks.find((n) => n.network_id === network)
      ?.is_admin
      ? "Network administrator"
      : "Network member";
    connection("Control plane connected", true);
    if (!data.sensor_online)
      notice(
        "Edge sensor is offline",
        "The control plane is reachable, but no recent daemon heartbeat was received. Historical data is retained; new response requests will wait for the sensor.",
        true,
      );
    else if (!data.telemetry.length)
      notice(
        "Sensor connected · waiting for traffic",
        "Your edge daemon is reporting. Device activity will appear after the first telemetry report.",
      );
    else if (data.demo_mode || data.sensor?.simulated)
      notice("Booth simulation", "Scenario telemetry and sensor acknowledgments are simulated. Statistical analysis and configured supervisor calls run through the real server.");
    else $("notice").hidden = true;
    $("last-updated").textContent =
      `Updated ${date(data.server_time)} · refreshes every 3s`;
    render();
  } catch (error) {
    if (generation !== state.generation) return;
    state.stale = true;
    connection("Connection interrupted");
    notice(
      "Unable to refresh live data",
      `${error.message} Displayed data is from the last successful update. Retrying automatically.`,
      true,
    );
    renderHealth();
    renderDevices();
  } finally {
    if (generation === state.generation) {
      state.loading = false;
      $("refresh").disabled = !state.network;
    }
  }
}
function render() {
  const d = state.data,
    telemetry = d?.telemetry || [];
  $("metric-devices").textContent = d ? fmt(d.devices.length) : "—";
  $("nav-count").textContent = d ? fmt(d.devices.length) : "—";
  $("metric-traffic").textContent = telemetry.length
    ? bytes(telemetry.reduce((s, t) => s + t.bytes_in + t.bytes_out, 0))
    : "—";
  $("metric-drops").textContent = telemetry.length
    ? fmt(telemetry.reduce((s, t) => s + t.dropped_connections, 0))
    : "—";
  $("metric-blocked").textContent = d
    ? fmt(d.devices.filter((v) => v.state === "blocked").length)
    : "—";
  $("metric-active").textContent = d
    ? `${fmt(d.devices.filter((v) => new Date(v.last_seen).valueOf() > Date.now() - 60000).length)} seen in the last minute`
    : "Discovered by the edge sensor";
  renderChart();
  renderHealth();
  renderDevices();
  renderIncidents();
  renderCommands();
  renderIntel();
}
function renderChart() {
  const data = state.data?.telemetry || [],
    el = $("traffic-chart");
  if (!data.length) {
    el.className = "chart empty";
    el.innerHTML = empty(
      "Waiting for telemetry",
      "Traffic appears here when your edge sensor starts reporting.",
    );
    return;
  }
  el.className = "chart";
  const now = Math.floor(state.data.server_time / 60) * 60;
  const buckets = Array.from({ length: 60 }, (_, i) => ({
    time: now - (59 - i) * 60,
    in: 0,
    out: 0,
  }));
  for (const t of data) {
    const i = Math.floor((t.received_at - buckets[0].time) / 60);
    if (i >= 0 && i < 60) {
      buckets[i].in += t.bytes_in;
      buckets[i].out += t.bytes_out;
    }
  }
  const max = Math.max(1, ...buckets.flatMap((b) => [b.in, b.out]));
  const x = (i) => 58 + i * 9.55,
    y = (v) => 176 - (v / max) * 150;
  const path = (key) =>
    buckets
      .map(
        (b, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(b[key]).toFixed(1)}`,
      )
      .join(" ");
  const grid = [0, 0.5, 1]
    .map(
      (v) =>
        `<line x1="58" x2="622" y1="${y(max * v)}" y2="${y(max * v)}" stroke="#263745" stroke-dasharray="3 5"/><text x="0" y="${y(max * v) + 4}">${bytes(max * v)}</text>`,
    )
    .join("");
  const labels = [0, 15, 30, 45, 59]
    .map(
      (i) =>
        `<text x="${x(i)}" y="202" text-anchor="${i === 59 ? "end" : "start"}">${new Date(buckets[i].time * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</text>`,
    )
    .join("");
  el.innerHTML = `<svg viewBox="0 0 638 216" role="img" aria-label="Reported inbound and outbound payload bytes per minute for the last hour"><defs><linearGradient id="fill" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#8ce8c2" stop-opacity=".13"/><stop offset="1" stop-color="#8ce8c2" stop-opacity="0"/></linearGradient></defs>${grid}<path d="${path("in")} L622,176 L58,176 Z" fill="url(#fill)"/><path d="${path("in")}" fill="none" stroke="#8ce8c2" stroke-width="2"/><path d="${path("out")}" fill="none" stroke="#a59af5" stroke-width="2"/>${labels}${buckets.map((b, i) => `<rect x="${x(i) - 4}" y="20" width="9.5" height="158" fill="transparent"><title>${new Date(b.time * 1000).toLocaleTimeString()} · Inbound ${bytes(b.in)} · Outbound ${bytes(b.out)}</title></rect>`).join("")}</svg>`;
}
function renderHealth() {
  const d = state.data,
    online = !!d?.sensor_online && !state.stale;
  $("edge-dot").className = `dot${online ? " online" : ""}`;
  $("edge-summary").innerHTML =
    `${online ? "Edge sensor connected" : d ? "Edge sensor offline" : "Awaiting connection"}<small>${escapeHtml(online ? d.sensor?.interface || "Interface not reported" : "Live engine status")}</small>`;
  const pipeline = [
    [
      "01",
      "Packet sensor",
      d?.sensor?.interface || "eBPF / XDP",
      d?.sensor?.simulated ? "Simulated" : online && d?.sensor?.xdp_attached ? "Attached" : "Unknown",
    ],
    [
      "02",
      "Edge daemon",
      "Telemetry & enforcement",
      online ? "Online" : "Offline",
    ],
    [
      "03",
      "Control plane",
      "Statistical analysis",
      d && !state.stale ? "Connected" : "Unknown",
    ],
  ];
  $("pipeline").innerHTML = pipeline
    .map(
      ([n, title, sub, status]) =>
        `<div class="pipeline-row"><span class="pipeline-step">${n}</span><div><strong>${title}</strong><small>${escapeHtml(sub)}</small></div>${badge(status, ["Online", "Attached", "Connected"].includes(status) ? "online" : "unknown")}</div>`,
    )
    .join("");
  const last = d?.telemetry.at(-1),
    trained = (d?.baselines || []).filter(b => b.samples >= 50).length;
  const rows = [
    [
      "Control plane",
      d && !state.stale
        ? "Connected"
        : state.stale
          ? "Unavailable"
          : "Not connected",
    ],
    ["Network", state.network || "Not selected"],
    ["Edge daemon", online ? "Heartbeat received" : "No recent heartbeat"],
    [
      "XDP program",
      online && d?.sensor?.xdp_attached
        ? "Attached (daemon reported)"
        : "Not verified",
    ],
    ["Interface", d?.sensor?.interface || "Not reported"],
    ["Last sensor heartbeat", date(d?.sensor?.last_heartbeat)],
    ["Last received telemetry", date(last?.received_at)],
    [
      "Statistical baselines",
      d
        ? `${trained} devices ready · 50 reports required`
        : "Awaiting telemetry",
    ],
    [
      "LLM supervisor",
      d?.supervisor?.health?.last_error || d?.supervisor?.configuration_error ||
        (d?.supervisor?.health?.last_success ? `Last successful review ${date(d.supervisor.health.last_success)}` : d?.supervisor?.configured ? "Configured · not yet verified" : "Not configured"),
    ],
    [
      "Available telemetry",
      d
        ? `${fmt(d.telemetry.length)} reports · last hour · up to ${fmt(d.telemetry_limit)}`
        : "None",
    ],
    ["Supervisor provider", `${d?.supervisor?.provider || "—"} / ${d?.supervisor?.model || "Model not set"}`],
    ["Response policy", d?.policy?.mode === "enforce" ? "Automatic isolation enabled" : "Monitor and alert"],
    ["Policy delivery", !online ? "Sensor offline" : d?.sensor?.policy_revision === d?.policy?.revision ? "Acknowledged by sensor" : "Waiting for sensor acknowledgment"],
    ["Trusted devices", String(d?.devices?.filter(v => v.trusted).length || 0)],
    ["Alert cooldown", `${d?.supervisor?.cooldown_seconds || 120} seconds per device`],
    ["Intelligence delivery", "Sent on sensor connection"],
  ];
  $("engine-details").innerHTML = rows
    .map(
      ([k, v]) =>
        `<div class="engine-row"><span>${k}</span><strong>${escapeHtml(v)}</strong></div>`,
    )
    .join("");
  const admin = state.networks.find(n => n.network_id === state.network)?.is_admin;
  $("engine-actions").innerHTML = `<button class="button secondary" data-policy="${d?.policy?.mode === "enforce" ? "observe" : "enforce"}" ${!admin || state.stale ? "disabled" : ""}>${d?.policy?.mode === "enforce" ? "Switch to monitor and alert" : "Enable automatic isolation"}</button><button class="button secondary" data-check-llm ${!admin || state.stale ? "disabled" : ""}>Test LLM connection</button><button class="button secondary" data-export-telemetry ${!d ? "disabled" : ""}>Export telemetry</button>`;
  $("operator-activity").innerHTML = (d?.activity || []).slice(0, 15).map(a => `<div class="command-row"><div>${escapeHtml(a.actor)} · ${escapeHtml(a.action.replaceAll("_", " "))}<small>${escapeHtml(a.detail)} · ${escapeHtml(date(a.created_at))}</small></div></div>`).join("") || empty("No operator actions", "Policy changes and incident reviews will appear here.");
}
function renderDevices() {
  const devices = state.data?.devices || [],
    query = $("device-search").value.toLowerCase(),
    filter = $("device-filter").value;
  const filtered = devices.filter(
    (d) =>
      (filter === "all" || (filter === "trusted" ? d.trusted : d.state === filter)) &&
      [d.mac, d.ip, d.hostname, d.manufacturer].some((v) =>
        v?.toLowerCase().includes(query),
      ),
  );
  const admin = state.networks.find(
    (n) => n.network_id === state.network,
  )?.is_admin;
  $("export").disabled = !devices.length;
  $("device-result-count").textContent = state.data
    ? `${filtered.length} of ${devices.length} devices`
    : "";
  $("devices-body").innerHTML = filtered.length
    ? filtered
        .map((d) => {
          const command = state.data.commands.find((c) => c.mac === d.mac);
          const pending =
            command && ["pending", "sent"].includes(command.status);
          return `<tr><td><strong>${escapeHtml(d.hostname || "Unnamed device")}</strong><small class="mono">${escapeHtml(d.mac)}</small></td><td class="mono">${escapeHtml(d.ip || "Not reported")}</td><td>${badge(d.state)}${d.trusted ? badge("Trusted", "online") : ""}<small>Baseline: ${state.data.baselines?.find(b => b.mac === d.mac)?.samples || 0}/50</small>${command ? `<small>${escapeHtml(command.state === "blocked" ? "Isolate" : "Restore")}: ${escapeHtml(command.status)}</small>` : ""}</td><td>${escapeHtml(date(d.last_seen))}</td><td><button class="button small ${d.state === "blocked" ? "secondary" : "danger"}" data-mac="${escapeHtml(d.mac)}" data-state="${d.state === "blocked" ? "allowed" : "blocked"}" ${!admin || state.stale || pending ? "disabled" : ""}>${pending ? "Awaiting response" : d.state === "blocked" ? "Restore access" : "Isolate"}</button><button class="button small secondary" data-trust="${!d.trusted}" data-mac="${escapeHtml(d.mac)}" ${!admin || state.stale ? "disabled" : ""}>${d.trusted ? "Revoke trust" : "Trust & restore"}</button><button class="button small secondary" data-reset-baseline data-mac="${escapeHtml(d.mac)}" ${!admin || state.stale ? "disabled" : ""}>Relearn baseline</button></td></tr>`;
        })
        .join("")
    : `<tr><td colspan="5">${empty(devices.length ? "No matching devices" : "No devices observed", devices.length ? "Try a different search or state filter." : state.token ? "Devices appear after the sensor sends telemetry." : "Sign in to view your network inventory.")}</td></tr>`;
}
function incidentMarkup(log) {
  const admin = state.networks.find(n => n.network_id === state.network)?.is_admin;
  const reasons = log.evidence?.measurements?.reasons || [];
  return `<article class="incident"><div class="incident-top"><h3>${escapeHtml(log.threat_name)}</h3>${badge(log.disposition || "open", log.disposition === "open" ? "learning" : "online")}</div><p>${escapeHtml(log.explanation)}</p><p>Supervisor: ${escapeHtml(log.review_status || "not requested")} · Action: ${escapeHtml((log.action || "alert_only").replaceAll("_", " "))}${log.confidence ? ` · Model confidence: ${log.confidence}/100 (self-reported)` : ""}</p>${reasons.length ? `<details><summary>Detection evidence</summary><ul>${reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("")}</ul></details>` : ""}<div class="incident-meta"><span class="mono">${escapeHtml(log.mac)}</span><time>${escapeHtml(date(log.timestamp))}</time></div>${log.note ? `<p>Review note: ${escapeHtml(log.note)}</p>` : ""}<div class="incident-actions">${["resolved", "false_positive", "open"].filter(v => v !== log.disposition).map(v => `<button class="button small secondary" data-review-id="${log.id}" data-disposition="${v}" ${!admin || state.stale ? "disabled" : ""}>${v === "open" ? "Reopen" : v === "resolved" ? "Resolve" : "Mark false positive"}</button>`).join("")}</div></article>`;
}
function renderIncidents() {
  const logs = state.data?.incidents || [],
    q = $("incident-search").value.toLowerCase();
  const filtered = logs.filter((l) =>
    [l.mac, l.threat_name, l.explanation].some((v) =>
      v.toLowerCase().includes(q),
    ),
  );
  $("recent-incidents").className = "";
  $("recent-incidents").innerHTML = logs.length
    ? logs.slice(0, 2).map(incidentMarkup).join("")
    : empty(
        "No recorded incidents",
        "Findings appear here when the engine records an alert.",
      );
  $("incidents-list").innerHTML = filtered.length
    ? filtered.map(incidentMarkup).join("")
    : empty(
        logs.length ? "No matching findings" : "No recorded incidents",
        logs.length
          ? "Try a different search."
          : "An empty history does not verify that the network is threat-free.",
      );
}
function renderCommands() {
  const commands = state.data?.commands || [];
  $("recent-commands").className = "";
  $("recent-commands").innerHTML = commands.length
    ? commands
        .slice(0, 4)
        .map(
          (c) =>
            `<div class="command-row"><div>${c.state === "blocked" ? "Isolate" : "Restore"} <span class="mono">${escapeHtml(c.mac)}</span><small>${escapeHtml(date(c.created_at))}${c.detail ? " · " + escapeHtml(c.detail) : ""}</small></div>${badge(c.status)}</div>`,
        )
        .join("")
    : empty(
        "No actions requested",
        "Isolation and restoration requests appear here.",
      );
}
function renderIntel() {
  for (const [key, id, count] of [
    ["banned_ips", "intel-ips", "ip-count"],
    ["ad_domains", "intel-domains", "domain-count"],
  ]) {
    const list = state.data?.threat_intel?.[key] || [];
    $(count).textContent = list.length;
    $(id).innerHTML = list.length
      ? list.map((v) => `<li>${escapeHtml(v)}</li>`).join("")
      : `<li>No indicators configured</li>`;
  }
}
function openAuth() {
  $("auth-error").textContent = "";
  $("auth-dialog").showModal();
}
$("auth-open").onclick = openAuth;
$("notice-auth").onclick = openAuth;
$("auth-close").onclick = () => $("auth-dialog").close();
$("auth-toggle").onclick = () => {
  state.signup = !state.signup;
  $("auth-title").textContent = state.signup
    ? "Create an operator account"
    : "Welcome to CIPHER";
  $("auth-description").textContent = state.signup
    ? "Set up your access to the control plane."
    : "Sign in to your network workspace.";
  $("email-label").hidden = !state.signup;
  $("auth-email").required = state.signup;
  $("signup-note").hidden = !state.signup;
  $("auth-password").minLength = state.signup ? 8 : 1;
  $("auth-password").autocomplete = state.signup
    ? "new-password"
    : "current-password";
  $("auth-submit").textContent = state.signup
    ? "Create account →"
    : "Sign in →";
  $("auth-toggle").textContent = state.signup
    ? "Already have an account? Sign in"
    : "New installation? Create an account";
  $("auth-error").textContent = "";
};
$("auth-form").onsubmit = async (event) => {
  event.preventDefault();
  $("auth-submit").disabled = true;
  $("auth-error").textContent = "";
  try {
    const token = await api(
      `/api/Main/${state.signup ? "signup" : "login"}`,
      "POST",
      {
        username: $("auth-username").value.trim(),
        email: $("auth-email").value.trim(),
        password: $("auth-password").value,
      },
      null,
    );
    state.token = token;
    sessionStorage.setItem("cipher_token", token);
    $("auth-password").value = "";
    await loadNetworks();
    $("auth-dialog").close();
  } catch (error) {
    $("auth-error").textContent = error.message;
  } finally {
    $("auth-submit").disabled = false;
  }
};
$("logout").onclick = signOut;
$("sidebar-close").onclick = () => {
  $("sidebar").classList.remove("open");
  $("menu").setAttribute("aria-expanded", "false");
  $("menu").focus();
};
$("menu").onclick = () => {
  $("sidebar").classList.toggle("open");
  $("menu").setAttribute(
    "aria-expanded",
    String($("sidebar").classList.contains("open")),
  );
};
document.addEventListener("click", (event) => {
  if (
    window.innerWidth <= 650 &&
    !$("sidebar").contains(event.target) &&
    !$("menu").contains(event.target)
  ) {
    $("sidebar").classList.remove("open");
    $("menu").setAttribute("aria-expanded", "false");
  }
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    $("sidebar").classList.remove("open");
    $("menu").setAttribute("aria-expanded", "false");
  }
});
$("network").onchange = async () => {
  $("action-dialog").close();
  state.action = null;
  state.generation++;
  state.network = $("network").value;
  state.data = null;
  state.loading = false;
  state.stale = false;
  localStorage.setItem("cipher_network", state.network);
  render();
  await refresh();
};
$("refresh").onclick = refresh;
$("device-search").oninput = renderDevices;
$("device-filter").onchange = renderDevices;
$("incident-search").oninput = renderIncidents;
function openAction(path, payload, title, description) {
  state.action = {path, payload};
  $("action-title").textContent = title;
  $("action-description").textContent = description;
  $("action-submit").className = "button";
  $("action-error").textContent = "";
  $("action-dialog").showModal();
}
$("devices-body").onclick = event => {
  const button = event.target.closest("button[data-mac]");
  if (!button || button.disabled) return;
  const payload = {network_id: state.network, mac: button.dataset.mac};
  if (button.hasAttribute("data-trust")) {
    payload.trusted = button.dataset.trust === "true";
    openAction("/api/device/trust", payload, payload.trusted ? "Permanently trust and restore?" : "Revoke permanent trust?", payload.trusted ? "CIPHER will keep monitoring this device and raising alerts, but prevent automatic device isolation. Any existing MAC block will be removed after the sensor acknowledges. Manual isolation and packet-level filters remain available." : "This device becomes eligible for automatic isolation when enforcement is enabled. Monitoring continues.");
  } else if (button.hasAttribute("data-reset-baseline")) {
    openAction("/api/device/baseline/reset", payload, "Relearn this device’s baseline?", "Discard the saved statistical baseline and learn from the next 50 reports. Use representative normal traffic during this period.");
  } else {
    payload.state = button.dataset.state;
    openAction("/api/change_state", payload, payload.state === "blocked" ? "Isolate this device?" : "Restore network access?", `${payload.mac}: the state changes after the sensor acknowledges. ${state.data?.sensor_online ? "" : "The sensor is offline; this request will wait for reconnection."}`);
  }
};
document.addEventListener("click", async event => {
  const button = event.target.closest("button");
  if (!button || button.disabled) return;
  if (button.hasAttribute("data-policy")) {
    const mode = button.dataset.policy;
    openAction("/api/policy", {network_id: state.network, mode}, "Change automatic response policy?", mode === "enforce" ? "Enable automatic device isolation for untrusted devices. Cloud reviews require at least two statistical signals and model confidence of 85/100. Edge heuristics may also isolate devices. Trusted devices remain monitored and exempt." : "Keep alerts, but stop new automatic device isolation. Existing blocks and packet-level filters remain active; restore blocked devices individually.");
  } else if (button.hasAttribute("data-check-llm")) {
    button.disabled = true;
    toast("Checking the configured supervisor…");
    try {
      const result = await api("/api/supervisor/check", "POST", {network_id: state.network});
      toast(result.ok ? "Supervisor responded with a valid verdict." : result.supervisor.health.last_error || "Supervisor unavailable.");
      await refresh();
    } catch (error) { toast(error.message); }
    finally { button.disabled = false; }
  } else if (button.hasAttribute("data-export-telemetry")) {
    try {
      const result = await api(`/api/telemetry/${encodeURIComponent(state.network)}`);
      downloadJson(result, "cipher-telemetry.json");
    } catch (error) { toast(error.message); }
  } else if (button.hasAttribute("data-review-id")) {
    try {
      button.disabled = true;
      await api("/api/incidents/review", "POST", {network_id: state.network, id: Number(button.dataset.reviewId), disposition: button.dataset.disposition});
      await refresh();
    } catch (error) { toast(error.message); button.disabled = false; }
  }
});
function downloadJson(value, filename) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], {type: "application/json"}));
  const link = document.createElement("a"); link.href = url; link.download = filename; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$("action-close").onclick = $("action-cancel").onclick = () =>
  $("action-dialog").close();
$("action-form").onsubmit = async (event) => {
  event.preventDefault();
  if (!state.action) return;
  const generation = state.generation;
  $("action-submit").disabled = true;
  try {
    await api(state.action.path, "POST", state.action.payload);
    if (generation !== state.generation) return;
    $("action-dialog").close();
    toast("Request saved. Engine health shows sensor policy acknowledgment.");
    await refresh();
  } catch (error) {
    $("action-error").textContent = error.message;
  } finally {
    $("action-submit").disabled = false;
  }
};
$("export").onclick = () => {
  const rows = [
    ["Hostname", "MAC", "IP", "State", "Last seen"],
    ...(state.data?.devices || []).map((d) => [
      d.hostname,
      d.mac,
      d.ip,
      d.state,
      d.last_seen,
    ]),
  ];
  const csv = rows
    .map((row) =>
      row
        .map(
          (v) =>
            `"${String(v ?? "")
              .replace(/^[=+@\-\t\r]/, "'$&")
              .replace(/"/g, '""')}"`,
        )
        .join(","),
    )
    .join("\r\n");
  const url = URL.createObjectURL(
      new Blob([csv], { type: "text/csv;charset=utf-8" }),
    ),
    a = document.createElement("a");
  a.href = url;
  a.download = "cipher-devices.csv";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};
window.addEventListener("hashchange", switchView);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refresh();
});
switchView();
render();
if (state.token)
  loadNetworks().catch((error) => {
    notice("Unable to load your workspace", error.message, true, true);
    connection("Connection interrupted");
  });
setInterval(() => {
  if (document.hidden) return;
  if (state.token && !state.networksLoaded) {
    loadNetworks().catch(() => {});
  } else refresh();
}, 3000);
