/**
 * Project CIPHER - Next-Gen IPS Frontend Controller
 * Real-Time FlatBuffers WebSocket Pipeline & Axum Control Plane Client
 */

// ============================================================================
// 1. Zero-Dependency FlatBuffers Binary Deserializer Engine
// ============================================================================
class FBTable {
  constructor(view, pos) {
    this.view = view;
    this.pos = pos;
    this.vtableOffset = this.view.getInt32(this.pos, true);
    this.vtablePos = this.pos - this.vtableOffset;
    this.vtableLength = this.view.getUint16(this.vtablePos, true);
  }

  getOffset(vtableFieldOffset) {
    if (vtableFieldOffset >= this.vtableLength) return 0;
    return this.view.getUint16(this.vtablePos + vtableFieldOffset, true);
  }

  getUint8(vtableFieldOffset, defaultValue = 0) {
    const offset = this.getOffset(vtableFieldOffset);
    if (offset === 0) return defaultValue;
    return this.view.getUint8(this.pos + offset);
  }

  getUint16(vtableFieldOffset, defaultValue = 0) {
    const offset = this.getOffset(vtableFieldOffset);
    if (offset === 0) return defaultValue;
    return this.view.getUint16(this.pos + offset, true);
  }

  getUint32(vtableFieldOffset, defaultValue = 0) {
    const offset = this.getOffset(vtableFieldOffset);
    if (offset === 0) return defaultValue;
    return this.view.getUint32(this.pos + offset, true);
  }

  getInt32(vtableFieldOffset, defaultValue = 0) {
    const offset = this.getOffset(vtableFieldOffset);
    if (offset === 0) return defaultValue;
    return this.view.getInt32(this.pos + offset, true);
  }

  getUint64(vtableFieldOffset, defaultValue = 0) {
    const offset = this.getOffset(vtableFieldOffset);
    if (offset === 0) return defaultValue;
    const p = this.pos + offset;
    if (typeof this.view.getBigUint64 === 'function') {
      return Number(this.view.getBigUint64(p, true));
    }
    const low = this.view.getUint32(p, true);
    const high = this.view.getUint32(p + 4, true);
    return high * 4294967296 + low;
  }

  getFloat32(vtableFieldOffset, defaultValue = 0.0) {
    const offset = this.getOffset(vtableFieldOffset);
    if (offset === 0) return defaultValue;
    return this.view.getFloat32(this.pos + offset, true);
  }

  getString(vtableFieldOffset) {
    const offset = this.getOffset(vtableFieldOffset);
    if (offset === 0) return null;
    const strOffsetPos = this.pos + offset;
    const strPos = strOffsetPos + this.view.getUint32(strOffsetPos, true);
    const length = this.view.getUint32(strPos, true);
    const utf8Bytes = new Uint8Array(this.view.buffer, this.view.byteOffset + strPos + 4, length);
    return new TextDecoder().decode(utf8Bytes);
  }

  getTable(vtableFieldOffset) {
    const offset = this.getOffset(vtableFieldOffset);
    if (offset === 0) return null;
    const tableOffsetPos = this.pos + offset;
    const indirectPos = tableOffsetPos + this.view.getUint32(tableOffsetPos, true);
    return new FBTable(this.view, indirectPos);
  }

  getVectorOfStrings(vtableFieldOffset) {
    const offset = this.getOffset(vtableFieldOffset);
    if (offset === 0) return [];
    const vecOffsetPos = this.pos + offset;
    const vecPos = vecOffsetPos + this.view.getUint32(vecOffsetPos, true);
    const count = this.view.getUint32(vecPos, true);
    const result = [];
    for (let i = 0; i < count; i++) {
      const elemOffsetPos = vecPos + 4 + (i * 4);
      const strPos = elemOffsetPos + this.view.getUint32(elemOffsetPos, true);
      const len = this.view.getUint32(strPos, true);
      const utf8 = new Uint8Array(this.view.buffer, this.view.byteOffset + strPos + 4, len);
      result.push(new TextDecoder().decode(utf8));
    }
    return result;
  }
}

class FlatBuffersEnvelopeReader {
  constructor(buffer) {
    const ab = buffer instanceof ArrayBuffer ? buffer : buffer.buffer;
    const byteOffset = buffer.byteOffset || 0;
    const byteLength = buffer.byteLength || ab.byteLength;
    this.view = new DataView(ab, byteOffset, byteLength);
    this.rootPos = this.view.getUint32(0, true);
    this.rootTable = new FBTable(this.view, this.rootPos);
  }

  // IncomingPayload: 1 = RegisterRequest, 2 = ChangeStateRequest, 3 = TelemetryReport
  getPayloadType() {
    return this.rootTable.getUint8(4, 0);
  }

  getPayloadTable() {
    return this.rootTable.getTable(6);
  }

  // TelemetryReport (Payload Type 3)
  getTelemetryReport() {
    const tbl = this.getPayloadTable();
    if (!tbl) return null;
    return {
      networkId: tbl.getString(4) || '',
      mac: tbl.getString(6) || '',
      bytesIn: tbl.getUint64(8, 0),
      bytesOut: tbl.getUint64(10, 0),
      uniqueInternalIps: tbl.getUint32(12, 0),
      uniqueExternalIps: tbl.getUint32(14, 0),
      totalConnections: tbl.getUint32(16, 0),
      passedConnections: tbl.getUint32(18, 0),
      droppedConnections: tbl.getUint32(20, 0),
      anomalyFlagsCount: tbl.getUint32(22, 0),
      heuristicFlagsCount: tbl.getUint32(24, 0),
      infraAlertCount: tbl.getUint32(26, 0),
      portEntropyScore: tbl.getFloat32(28, 0.0)
    };
  }

  // RegisterRequest (Payload Type 1)
  getRegisterRequest() {
    const tbl = this.getPayloadTable();
    if (!tbl) return null;
    return {
      networkId: tbl.getString(4) || '',
      mac: tbl.getString(6) || '',
      hostname: tbl.getString(8) || 'Unknown Device',
      ip: tbl.getString(10) || '0.0.0.0',
      manufacturer: tbl.getString(12) || 'Generic NIC'
    };
  }

  // ChangeStateRequest (Payload Type 2)
  getChangeStateRequest() {
    const tbl = this.getPayloadTable();
    if (!tbl) return null;
    return {
      networkId: tbl.getString(4) || '',
      mac: tbl.getString(6) || '',
      state: tbl.getString(8) || 'allowed'
    };
  }

  // RouterResponse Envelope
  getRouterResponse() {
    const status = this.rootTable.getString(4);
    const mac = this.rootTable.getString(6);
    const threatIntelTable = this.rootTable.getTable(8);
    let threatIntel = null;

    if (threatIntelTable) {
      threatIntel = {
        adDomains: threatIntelTable.getVectorOfStrings(4),
        bannedIps: threatIntelTable.getVectorOfStrings(6)
      };
    }

    return { status, mac, threatIntel };
  }
}

// ============================================================================
// 2. Layer 1 Mathematical Z-Score Profiler (Rust Baseline Replication)
// ============================================================================
class TelemetryStatisticalProfiler {
  constructor(windowSize = 50) {
    this.windowSize = windowSize;
    this.baselines = new Map(); // MAC -> { buffer: Array<[bytesIn, bytesOut, drops, entropy]>, means, stdDevs }
  }

  process(mac, bytesIn, bytesOut, drops, entropy) {
    if (!this.baselines.has(mac)) {
      this.baselines.set(mac, {
        buffer: [],
        means: null,
        stdDevs: null
      });
    }

    const baseline = this.baselines.get(mac);
    const featureVector = [Number(bytesIn), Number(bytesOut), Number(drops), Number(entropy)];
    baseline.buffer.push(featureVector);

    if (baseline.buffer.length > this.windowSize) {
      baseline.buffer.shift();
    }

    // Baseline calculation when at least 8 samples are collected
    if (baseline.buffer.length >= 8) {
      const n = baseline.buffer.length;
      const means = [0, 0, 0, 0];
      for (let i = 0; i < n; i++) {
        for (let j = 0; j < 4; j++) {
          means[j] += baseline.buffer[i][j];
        }
      }
      for (let j = 0; j < 4; j++) {
        means[j] /= n;
      }

      const stdDevs = [0, 0, 0, 0];
      for (let i = 0; i < n; i++) {
        for (let j = 0; j < 4; j++) {
          const diff = baseline.buffer[i][j] - means[j];
          stdDevs[j] += diff * diff;
        }
      }
      for (let j = 0; j < 4; j++) {
        stdDevs[j] = Math.sqrt(stdDevs[j] / n);
      }

      baseline.means = means;
      baseline.stdDevs = stdDevs;

      const epsilon = 1e-8;
      const zScores = featureVector.map((val, idx) => {
        return Math.abs(val - means[idx]) / (stdDevs[idx] + epsilon);
      });

      const maxZScore = Math.max(...zScores);
      return {
        zScore: maxZScore,
        isAnomaly: maxZScore > 3.0,
        zScores
      };
    }

    return {
      zScore: 0.0,
      isAnomaly: false,
      zScores: [0, 0, 0, 0]
    };
  }
}

// ============================================================================
// 3. Application State & Global Singletons
// ============================================================================
const state = {
  token: localStorage.getItem('cipher_jwt') || null,
  user: JSON.parse(localStorage.getItem('cipher_user') || 'null'),
  networkId: localStorage.getItem('cipher_network_id') || 'network-alpha-01',
  devices: [],
  auditLogs: [],
  threatIntel: {
    bannedIps: ["185.15.59.224", "45.133.1.106"],
    adDomains: ["telemetry.malware.com", "trackers.ad-network.com"],
    lastUpdated: new Date()
  },
  activeTab: 'overview',
  bitmask: 0x07,
  wsConnected: false,
  kpis: {
    totalPackets: 0,
    droppedPackets: 0,
    elephantBypass: 99.98,
    activeDevices: 0
  }
};

const profiler = new TelemetryStatisticalProfiler(50);
let telemetryChart = null;
let wsClient = null;

// API Base URL
const API_BASE = '';

// ============================================================================
// 4. REST API Client with Zero-Trust JWT Header
// ============================================================================
async function apiRequest(endpoint, method = 'GET', body = null) {
  const headers = {
    'Content-Type': 'application/json'
  };

  if (state.token) {
    headers['Authorization'] = `Bearer ${state.token}`;
  }

  const options = { method, headers };
  if (body) {
    options.body = typeof body === 'string' ? body : JSON.stringify(body);
  }

  try {
    const response = await fetch(`${API_BASE}${endpoint}`, options);

    if (response.status === 401) {
      showToast('Session expired or unauthorized. Please authenticate.', 'error');
      logout();
      return null;
    }

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(errText || `HTTP Error ${response.status}`);
    }

    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return await response.json();
    }
    return await response.text();
  } catch (err) {
    console.error(`[API Error] ${endpoint}:`, err);
    throw err;
  }
}

// ============================================================================
// 5. Chart.js Initialization & High-Performance Telemetry Stream
// ============================================================================
async function ensureChartJsLoaded() {
  if (window.Chart) return window.Chart;
  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = 'https://cdn.jsdelivr.net/npm/chart.js';
    script.onload = () => resolve(window.Chart);
    script.onerror = () => reject(new Error('Failed to load Chart.js library'));
    document.head.appendChild(script);
  });
}

async function initTelemetryChart() {
  const canvas = document.getElementById('telemetry-chart');
  if (!canvas) return;

  await ensureChartJsLoaded();

  const ctx = canvas.getContext('2d');

  // Gradient fills for modern Quicken / Cyber-Slate visual style
  const gradientIn = ctx.createLinearGradient(0, 0, 0, 240);
  gradientIn.addColorStop(0, 'rgba(2, 132, 199, 0.22)');
  gradientIn.addColorStop(1, 'rgba(2, 132, 199, 0.00)');

  const gradientOut = ctx.createLinearGradient(0, 0, 0, 240);
  gradientOut.addColorStop(0, 'rgba(99, 102, 241, 0.18)');
  gradientOut.addColorStop(1, 'rgba(99, 102, 241, 0.00)');

  telemetryChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Inbound Traffic (Bytes/s)',
          data: [],
          borderColor: '#0284c7',
          backgroundColor: gradientIn,
          borderWidth: 2,
          pointRadius: 2,
          pointHoverRadius: 5,
          pointBackgroundColor: '#0284c7',
          pointBorderColor: '#ffffff',
          tension: 0.35,
          fill: true
        },
        {
          label: 'Outbound Traffic (Bytes/s)',
          data: [],
          borderColor: '#6366f1',
          backgroundColor: gradientOut,
          borderWidth: 2,
          pointRadius: 2,
          pointHoverRadius: 5,
          pointBackgroundColor: '#6366f1',
          pointBorderColor: '#ffffff',
          tension: 0.35,
          fill: true
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      interaction: {
        mode: 'index',
        intersect: false
      },
      plugins: {
        legend: {
          display: false
        },
        tooltip: {
          backgroundColor: 'rgba(15, 23, 42, 0.92)',
          titleFont: { family: 'JetBrains Mono', size: 11 },
          bodyFont: { family: 'Inter', size: 12 },
          borderColor: 'rgba(226, 232, 240, 0.2)',
          borderWidth: 1,
          padding: 10,
          callbacks: {
            label: (context) => {
              const val = context.parsed.y || 0;
              return ` ${context.dataset.label}: ${formatBytes(val)}/s`;
            }
          }
        }
      },
      scales: {
        x: {
          grid: {
            color: 'rgba(15, 23, 42, 0.04)',
            drawBorder: false
          },
          ticks: {
            color: '#94a3b8',
            font: { family: 'JetBrains Mono', size: 10 },
            maxRotation: 0,
            maxTicksLimit: 8
          }
        },
        y: {
          beginAtZero: true,
          grid: {
            color: 'rgba(15, 23, 42, 0.05)',
            drawBorder: false
          },
          ticks: {
            color: '#94a3b8',
            font: { family: 'JetBrains Mono', size: 10 },
            callback: (val) => formatBytes(val)
          }
        }
      }
    }
  });
}

function pushTelemetryToChart(bytesIn, bytesOut, timestampLabel) {
  if (!telemetryChart) return;

  const MAX_POINTS = 35;
  const labels = telemetryChart.data.labels;
  const dsIn = telemetryChart.data.datasets[0].data;
  const dsOut = telemetryChart.data.datasets[1].data;

  labels.push(timestampLabel);
  dsIn.push(bytesIn);
  dsOut.push(bytesOut);

  if (labels.length > MAX_POINTS) {
    labels.shift();
    dsIn.shift();
    dsOut.shift();
  }

  telemetryChart.update('none');
}

// ============================================================================
// 6. Persistent Zero-Trust FlatBuffers WebSocket Tunnel
// ============================================================================
class CipherPersistentWebSocket {
  constructor(path = null, tokenProvider = null) {
    this.customPath = path;
    this.tokenProvider = tokenProvider || (() => state.token);
    this.ws = null;
    this.reconnectTimer = null;
    this.reconnectAttempts = 0;
    this.baseDelay = 1000;
    this.maxDelay = 15000;
    this.isExplicitlyClosed = false;
  }

  getDynamicUrl() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host || 'localhost:3000';
    
    let path = this.customPath;
    if (!path) {
      path = `/api/router/ws/${encodeURIComponent(state.networkId)}`;
    } else if (path.includes(':network_id')) {
      path = path.replace(':network_id', encodeURIComponent(state.networkId));
    }
    
    if (!path.startsWith('/')) {
      path = `/${path}`;
    }

    return `${protocol}//${host}${path}`;
  }

  connect() {
    this.isExplicitlyClosed = false;
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    const token = typeof this.tokenProvider === 'function' ? this.tokenProvider() : this.tokenProvider;
    let wsUrl = this.getDynamicUrl();

    // Pass JWT via URL query parameter for browser compatibility
    if (token) {
      const sep = wsUrl.includes('?') ? '&' : '?';
      wsUrl = `${wsUrl}${sep}token=${encodeURIComponent(token)}`;
    }

    // Pass token as WebSocket subprotocol array as secondary extraction vector
    const subprotocols = token ? ['jwt', token] : [];

    try {
      console.log(`🔌 [WS] Connecting to dynamic WebSocket endpoint: ${wsUrl}`);
      this.ws = subprotocols.length > 0 ? new WebSocket(wsUrl, subprotocols) : new WebSocket(wsUrl);
      this.ws.binaryType = 'arraybuffer'; // Enable binary FlatBuffers decoding

      this.ws.onopen = () => {
        console.log('🟢 [WS] Axum Zero-Trust WebSocket connected.');
        this.reconnectAttempts = 0;
        setWebSocketStatus(true);
      };

      this.ws.onmessage = (event) => {
        handleIncomingWebSocketFrame(event.data);
      };

      this.ws.onerror = (err) => {
        console.warn('⚠️ [WS] WebSocket transport error encountered:', err);
      };

      this.ws.onclose = (event) => {
        console.warn(`🔴 [WS] Connection closed (code: ${event.code}, reason: "${event.reason || 'None'}").`);
        setWebSocketStatus(false);
        if (!this.isExplicitlyClosed) {
          this.scheduleReconnect();
        }
      };
    } catch (err) {
      console.error('🔴 [WS] Socket initialization error:', err);
      this.scheduleReconnect();
    }
  }

  scheduleReconnect() {
    if (this.isExplicitlyClosed) return;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);

    // Exponential backoff with random jitter: delay = min(base * 1.5^attempts + jitter, maxDelay)
    const jitter = Math.random() * 500;
    const exponential = this.baseDelay * Math.pow(1.5, this.reconnectAttempts);
    const delay = Math.min(exponential + jitter, this.maxDelay);

    this.reconnectAttempts++;
    console.log(`🔄 [WS] Reconnecting in ${(delay / 1000).toFixed(2)}s (attempt ${this.reconnectAttempts})...`);

    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay);
  }

  send(data) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(data);
    }
  }

  disconnect() {
    this.isExplicitlyClosed = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
    }
  }
}

function setWebSocketStatus(connected) {
  state.wsConnected = connected;
  const statusDots = document.querySelectorAll('.subsystem-item .status-dot');
  if (statusDots && statusDots.length > 2) {
    statusDots[2].className = connected ? 'status-dot active' : 'status-dot danger';
  }

  const livePill = document.querySelector('.topbar-right .live-pill span:last-child');
  if (livePill) {
    livePill.textContent = connected ? 'Zero-Cost Observability • Live FlatBuffers' : 'Tunnel Offline • Reconnecting...';
  }
}

// ============================================================================
// 7. Binary Frame Dispatcher & Pipeline Processing
// ============================================================================
function handleIncomingWebSocketFrame(rawData) {
  if (typeof rawData === 'string') {
    // Plaintext Welcome/Diagnostic Handshake
    console.log(`💬 [WS Handshake Text] ${rawData}`);
    return;
  }

  if (!(rawData instanceof ArrayBuffer)) {
    console.warn('⚠️ [WS] Non-ArrayBuffer frame received. Skipping.');
    return;
  }

  try {
    const reader = new FlatBuffersEnvelopeReader(rawData);
    const payloadType = reader.getPayloadType();

    if (payloadType === 3) {
      // IncomingPayload::TelemetryReport
      const report = reader.getTelemetryReport();
      if (report) {
        processTelemetryReport(report);
      }
    } else if (payloadType === 1) {
      // IncomingPayload::RegisterRequest
      const reg = reader.getRegisterRequest();
      if (reg) {
        processRegisterRequest(reg);
      }
    } else if (payloadType === 2) {
      // IncomingPayload::ChangeStateRequest
      const chg = reader.getChangeStateRequest();
      if (chg) {
        processStateChangeRequest(chg);
      }
    } else {
      // Check for RouterResponse (ThreatIntel or Kill Command execution)
      const res = reader.getRouterResponse();
      if (res && res.status) {
        processRouterResponse(res);
      }
    }
  } catch (err) {
    console.error('🔴 [FlatBuffers Error] Failed to decode binary envelope:', err);
  }
}

function processTelemetryReport(report) {
  const timestamp = new Date().toLocaleTimeString();

  // 1. Layer 1 Statistical Z-Score Profiling
  const profResult = profiler.process(
    report.mac,
    report.bytesIn,
    report.bytesOut,
    report.droppedConnections,
    report.portEntropyScore
  );

  const zScore = profResult.zScore;
  const isAnomaly = profResult.isAnomaly;

  // 2. Direct pipe to HTML5 Canvas via Chart.js
  pushTelemetryToChart(report.bytesIn, report.bytesOut, timestamp);

  // 3. Update DOM Real-Time Indicator Cards
  const zScoreEl = document.getElementById('metric-zscore');
  const entropyEl = document.getElementById('metric-entropy');
  const exfilEl = document.getElementById('metric-exfil');

  if (zScoreEl) {
    zScoreEl.textContent = zScore.toFixed(2);
    zScoreEl.style.color = zScore > 3.0 ? 'var(--accent-crimson)' : 'var(--accent-cyan)';
  }

  if (entropyEl) {
    entropyEl.textContent = report.portEntropyScore.toFixed(2);
  }

  if (exfilEl) {
    const ratio = (report.bytesOut / (report.bytesIn || 1)).toFixed(3);
    exfilEl.textContent = ratio;
  }

  // 4. Update KPI Aggregators
  state.kpis.totalPackets += report.totalConnections || 1;
  state.kpis.droppedPackets += report.droppedConnections || 0;
  updateKPIs();

  // 5. Audit Log Injection for Significant Mathematical Deviations
  if (isAnomaly || report.anomalyFlagsCount > 0) {
    addAuditLog({
      networkId: report.networkId || state.networkId,
      mac: report.mac,
      threatName: report.anomalyFlagsCount > 0 ? 'Protocol Violation Flagged' : 'Layer 1 Statistical Spike',
      confidence: Math.min(99, Math.round(zScore * 12 + 40)),
      explanation: `Z-Score: ${zScore.toFixed(2)} | Inbound: ${formatBytes(report.bytesIn)} | Outbound: ${formatBytes(report.bytesOut)} | Port Entropy: ${report.portEntropyScore.toFixed(2)}`,
      shouldBlock: zScore > 5.0,
      timestamp
    });
  }
}

function processRegisterRequest(reg) {
  const existingIndex = state.devices.findIndex(d => d.mac === reg.mac);
  const updatedDevice = {
    network_id: reg.networkId || state.networkId,
    mac: reg.mac,
    hostname: reg.hostname,
    ip: reg.ip,
    manufacturer: reg.manufacturer,
    state: 'allowed',
    last_seen: 'Active Now'
  };

  if (existingIndex >= 0) {
    state.devices[existingIndex] = updatedDevice;
  } else {
    state.devices.push(updatedDevice);
  }

  renderDevicesTable();
  updateKPIs();
  showToast(`🟢 Device Connected: ${reg.hostname} (${reg.mac})`, 'info');
}

function processStateChangeRequest(chg) {
  const dev = state.devices.find(d => d.mac === chg.mac);
  if (dev) {
    dev.state = chg.state;
    renderDevicesTable();
    showToast(`Device ${chg.mac} state updated to: ${chg.state}`, 'info');
  }
}

function processRouterResponse(res) {
  if (res.status === 'threat_intel' && res.threatIntel) {
    if (res.threatIntel.bannedIps && res.threatIntel.bannedIps.length > 0) {
      state.threatIntel.bannedIps = res.threatIntel.bannedIps;
    }
    if (res.threatIntel.adDomains && res.threatIntel.adDomains.length > 0) {
      state.threatIntel.adDomains = res.threatIntel.adDomains;
    }
    state.threatIntel.lastUpdated = new Date();
    renderThreatIntel();
  } else if (res.status.startsWith('command_')) {
    const action = res.status.replace('command_', '');
    showToast(`⚡ In-Kernel Hardware Command Applied: ${action} on ${res.mac}`, 'info');
  }
}

// ============================================================================
// 8. Device Fleet Table & Remote Hardware Actions
// ============================================================================
async function fetchDevices() {
  if (!state.token) return;
  try {
    const devices = await apiRequest('/api/get_devices', 'POST', state.networkId);
    if (Array.isArray(devices)) {
      state.devices = devices;
      renderDevicesTable();
      updateKPIs();
    }
  } catch (err) {
    console.warn('[Devices] Failed to fetch remote devices fleet:', err.message);
  }
}

function renderDevicesTable() {
  const tbody = document.getElementById('devices-table-body');
  if (!tbody) return;

  if (state.devices.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 24px;">No devices detected on network: ${state.networkId}</td></tr>`;
    return;
  }

  tbody.innerHTML = state.devices.map(device => `
    <tr data-mac="${device.mac}">
      <td>
        <div class="device-host-col">
          <span class="host-name">${escapeHtml(device.hostname || 'Unknown Device')}</span>
          <span class="host-vendor">${escapeHtml(device.manufacturer || 'Generic NIC')}</span>
        </div>
      </td>
      <td class="mono-cell">${escapeHtml(device.ip)}</td>
      <td class="mono-cell" style="color: var(--accent-cyan);">${escapeHtml(device.mac)}</td>
      <td>
        <span class="badge-state ${device.state.toLowerCase()}">
          <span class="status-dot ${device.state.toLowerCase() === 'allowed' ? 'active' : (device.state.toLowerCase() === 'blocked' ? 'danger' : 'warning')}"></span>
          ${device.state}
        </span>
      </td>
      <td style="color: var(--text-muted); font-size: 0.78rem;">${escapeHtml(device.last_seen || 'Active')}</td>
      <td>
        <div class="table-actions">
          ${device.state === 'allowed' 
            ? `<button class="btn btn-danger btn-sm" onclick="setDeviceState('${device.mac}', 'blocked')" title="Hardware Kill (eBPF MAC Map)">Isolate</button>`
            : `<button class="btn btn-primary btn-sm" onclick="setDeviceState('${device.mac}', 'allowed')" title="Restore Access">Allow</button>`
          }
          <button class="btn btn-secondary btn-sm" onclick="deleteDevice('${device.mac}')" title="Delete from Database">Remove</button>
        </div>
      </td>
    </tr>
  `).join('');
}

window.setDeviceState = async function(mac, newState) {
  try {
    const payload = {
      network_id: state.networkId,
      mac: mac,
      state: newState
    };

    let updatedDevices = null;
    if (state.token) {
      updatedDevices = await apiRequest('/api/change_state', 'POST', payload);
    }

    if (updatedDevices && Array.isArray(updatedDevices)) {
      state.devices = updatedDevices;
    } else {
      const dev = state.devices.find(d => d.mac === mac);
      if (dev) dev.state = newState;
    }

    renderDevicesTable();
    updateKPIs();

    if (newState === 'blocked') {
      showToast(`🚨 Hardware Kill Command executed for MAC: ${mac}`, 'error');
    } else {
      showToast(`Device ${mac} status updated to ${newState}`, 'success');
    }
  } catch (err) {
    showToast(`Failed to change device state: ${err.message}`, 'error');
  }
};

window.deleteDevice = async function(mac) {
  if (!confirm(`Confirm removal of device ${mac} from CIPHER control plane?`)) return;

  try {
    const payload = {
      network_id: state.networkId,
      mac: mac
    };

    let updatedDevices = null;
    if (state.token) {
      updatedDevices = await apiRequest('/api/delete_device', 'DELETE', payload);
    }

    if (updatedDevices && Array.isArray(updatedDevices)) {
      state.devices = updatedDevices;
    } else {
      state.devices = state.devices.filter(d => d.mac !== mac);
    }

    renderDevicesTable();
    updateKPIs();
    showToast(`Device ${mac} deleted`, 'info');
  } catch (err) {
    showToast(`Failed to delete device: ${err.message}`, 'error');
  }
};

function updateKPIs() {
  state.kpis.activeDevices = state.devices.length;
  const activeDevEl = document.getElementById('kpi-active-devices');
  const totalPktsEl = document.getElementById('kpi-total-packets');
  const droppedPktsEl = document.getElementById('kpi-dropped-packets');
  const elephantEl = document.getElementById('kpi-elephant-bypass');
  const navDeviceCount = document.getElementById('nav-device-count');

  if (activeDevEl) activeDevEl.textContent = state.kpis.activeDevices;
  if (navDeviceCount) navDeviceCount.textContent = state.kpis.activeDevices;
  if (totalPktsEl) totalPktsEl.textContent = state.kpis.totalPackets.toLocaleString();
  if (droppedPktsEl) droppedPktsEl.textContent = state.kpis.droppedPackets.toLocaleString();
  if (elephantEl) elephantEl.textContent = `${state.kpis.elephantBypass}%`;
}

// ============================================================================
// 9. Pillar 3: 8-Bit Threat Diagnostic Mask UI
// ============================================================================
function initBitmaskUI() {
  const flags = [
    { bit: 0, hex: 0x01, name: 'F_PASS', desc: 'Hardware Packet Forwarding Enforced' },
    { bit: 1, hex: 0x02, name: 'F_WAN_IN', desc: 'Inbound Direction Context (Internet -> LAN)' },
    { bit: 2, hex: 0x04, name: 'F_WAN_OUT', desc: 'Egress Context (LAN -> Internet Exfiltration)' },
    { bit: 3, hex: 0x08, name: 'F_ANOMALY', desc: 'RFC Protocol Violation (SYN-FIN/Bad Length)' },
    { bit: 4, hex: 0x10, name: 'F_LEGACY_DROP', desc: 'Insecure Protocol Blocked (Telnet/TFTP)' },
    { bit: 5, hex: 0x20, name: 'F_HEURISTIC', desc: 'Suspicious Discovery Protocol (UPnP/SSDP/mDNS)' },
    { bit: 6, hex: 0x40, name: 'F_INFRA_ALERT', desc: 'Rogue DHCP/DNS Spoofing Detected' },
    { bit: 7, hex: 0x80, name: 'F_AD_DROP', desc: 'DNS Sinkhole Match via Bloom Filter' }
  ];

  const container = document.getElementById('bitmask-grid');
  if (!container) return;

  container.innerHTML = flags.map(f => {
    const isActive = (state.bitmask & f.hex) !== 0;
    return `
      <div class="bit-box ${isActive ? 'active' : ''}" id="bit-box-${f.bit}" onclick="toggleBit(${f.hex})">
        <div class="bit-header">
          <span>Bit ${f.bit}</span>
          <span>0x${f.hex.toString(16).toUpperCase().padStart(2, '0')}</span>
        </div>
        <div class="bit-name">${f.name}</div>
        <div class="bit-desc">${f.desc}</div>
      </div>
    `;
  }).join('');

  updateBitmaskSummary();
}

window.toggleBit = function(hex) {
  state.bitmask ^= hex;
  initBitmaskUI();
};

function updateBitmaskSummary() {
  const valEl = document.getElementById('bitmask-raw-value');
  const binEl = document.getElementById('bitmask-binary-value');
  if (valEl) valEl.textContent = `0x${state.bitmask.toString(16).toUpperCase().padStart(2, '0')} (${state.bitmask})`;
  if (binEl) binEl.textContent = state.bitmask.toString(2).padStart(8, '0');
}

// ============================================================================
// 10. AI Audit Stream Ledger & Threat Intel
// ============================================================================
function addAuditLog(log) {
  state.auditLogs.unshift(log);
  if (state.auditLogs.length > 20) state.auditLogs.pop();
  renderAuditLogs();
}

function renderAuditLogs() {
  const container = document.getElementById('audit-stream-container');
  if (!container) return;

  if (state.auditLogs.length === 0) {
    container.innerHTML = `
      <div style="padding: 24px; text-align: center; color: var(--text-dim); font-size: 0.85rem;">
        No active anomalies flagged. Two-tier AI Engine standing by.
      </div>
    `;
    return;
  }

  container.innerHTML = state.auditLogs.map(log => `
    <div class="audit-card ${log.shouldBlock ? 'threat' : 'benign'}">
      <div class="audit-header">
        <span class="threat-tag">${escapeHtml(log.threatName)}</span>
        <span class="confidence-score">${log.confidence}% Confidence</span>
      </div>
      <div class="audit-body">${escapeHtml(log.explanation)}</div>
      <div class="audit-footer">
        <span>Target MAC: ${escapeHtml(log.mac)}</span>
        <span>${escapeHtml(log.timestamp)}</span>
      </div>
    </div>
  `).join('');
}

function renderThreatIntel() {
  const bannedIpsContainer = document.getElementById('threat-intel-ips');
  const adDomainsContainer = document.getElementById('threat-intel-domains');

  if (bannedIpsContainer) {
    bannedIpsContainer.innerHTML = state.threatIntel.bannedIps.map(ip => `
      <li style="padding: 6px 0; border-bottom: 1px solid var(--border-subtle); font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-crimson);">
        🛑 ${escapeHtml(ip)}
      </li>
    `).join('');
  }

  if (adDomainsContainer) {
    adDomainsContainer.innerHTML = state.threatIntel.adDomains.map(dom => `
      <li style="padding: 6px 0; border-bottom: 1px solid var(--border-subtle); font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-amber);">
        🛡️ ${escapeHtml(dom)}
      </li>
    `).join('');
  }
}

// ============================================================================
// 11. Authentication & Navigation Setup
// ============================================================================
function initNavigation() {
  const navItems = document.querySelectorAll('.nav-item[data-tab]');
  navItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      const tabId = item.getAttribute('data-tab');
      switchTab(tabId);
    });
  });

  const menuToggle = document.getElementById('menu-toggle');
  const sidebar = document.querySelector('.sidebar');
  if (menuToggle && sidebar) {
    menuToggle.addEventListener('click', () => {
      sidebar.classList.toggle('open');
    });
  }

  const netSelect = document.getElementById('network-select');
  if (netSelect) {
    netSelect.value = state.networkId;
    netSelect.addEventListener('change', (e) => {
      state.networkId = e.target.value;
      localStorage.setItem('cipher_network_id', state.networkId);
      showToast(`Switched active network context to: ${state.networkId}`, 'info');
      fetchDevices();
      if (wsClient) {
        wsClient.disconnect();
        wsClient.connect();
      }
    });
  }
}

function switchTab(tabId) {
  state.activeTab = tabId;
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));

  const activeNavItem = document.querySelector(`.nav-item[data-tab="${tabId}"]`);
  const activeSection = document.getElementById(`view-${tabId}`);

  if (activeNavItem) activeNavItem.classList.add('active');
  if (activeSection) activeSection.classList.add('active');

  const sidebar = document.querySelector('.sidebar');
  if (sidebar && window.innerWidth < 768) {
    sidebar.classList.remove('open');
  }
}

function initAuthUI() {
  const authModal = document.getElementById('auth-modal');
  const openAuthBtn = document.getElementById('btn-open-auth');
  const closeAuthBtn = document.getElementById('btn-close-auth');
  const authForm = document.getElementById('auth-form');
  const authToggleLink = document.getElementById('auth-toggle-mode');
  const logoutBtn = document.getElementById('btn-logout');

  let isSignup = false;

  if (openAuthBtn) {
    openAuthBtn.addEventListener('click', () => {
      authModal.classList.add('open');
    });
  }

  if (closeAuthBtn) {
    closeAuthBtn.addEventListener('click', () => {
      authModal.classList.remove('open');
    });
  }

  if (authToggleLink) {
    authToggleLink.addEventListener('click', (e) => {
      e.preventDefault();
      isSignup = !isSignup;
      document.getElementById('auth-modal-title').textContent = isSignup ? 'Create CIPHER Account' : 'Authenticate to CIPHER';
      document.getElementById('auth-submit-btn').textContent = isSignup ? 'Sign Up (Argon2id)' : 'Sign In';
      authToggleLink.textContent = isSignup ? 'Already have an account? Sign In' : 'Need an account? Sign Up';
    });
  }

  if (authForm) {
    authForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('auth-username').value.trim();
      const email = document.getElementById('auth-email').value.trim();
      const password = document.getElementById('auth-password').value;

      try {
        const endpoint = isSignup ? '/api/Main/signup' : '/api/Main/login';
        const payload = { username, email, password };
        const token = await apiRequest(endpoint, 'POST', payload);

        if (token) {
          state.token = typeof token === 'string' ? token.replace(/"/g, '') : token;
          state.user = { username, email };
          localStorage.setItem('cipher_jwt', state.token);
          localStorage.setItem('cipher_user', JSON.stringify(state.user));

          showToast(`Successfully authenticated as ${username}`, 'success');
          authModal.classList.remove('open');
          updateUserUI();
          fetchDevices();

          // Re-establish Zero-Trust WebSocket with authenticated JWT
          if (wsClient) {
            wsClient.disconnect();
            wsClient.connect();
          }
        }
      } catch (err) {
        showToast(`Authentication failed: ${err.message || 'Check credentials'}`, 'error');
      }
    });
  }

  if (logoutBtn) {
    logoutBtn.addEventListener('click', logout);
  }
}

function updateUserUI() {
  const userNameEl = document.getElementById('display-username');
  const userRoleEl = document.getElementById('display-user-role');
  const authActionBtn = document.getElementById('btn-open-auth');
  const logoutBtn = document.getElementById('btn-logout');

  if (state.user) {
    if (userNameEl) userNameEl.textContent = state.user.username;
    if (userRoleEl) userRoleEl.textContent = 'SOC Administrator';
    if (authActionBtn) authActionBtn.style.display = 'none';
    if (logoutBtn) logoutBtn.style.display = 'inline-flex';
  } else {
    if (userNameEl) userNameEl.textContent = 'Guest Operator';
    if (userRoleEl) userRoleEl.textContent = 'Read-Only Sandbox';
    if (authActionBtn) authActionBtn.style.display = 'inline-flex';
    if (logoutBtn) logoutBtn.style.display = 'none';
  }
}

function logout() {
  state.token = null;
  state.user = null;
  localStorage.removeItem('cipher_jwt');
  localStorage.removeItem('cipher_user');
  updateUserUI();
  showToast('Logged out of CIPHER Control Plane', 'info');
  if (wsClient) {
    wsClient.disconnect();
    wsClient.connect();
  }
}

// ============================================================================
// 12. Utilities & Helper Functions
// ============================================================================
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function formatBytes(bytes) {
  if (bytes === 0 || isNaN(bytes)) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i] || 'B'}`;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ============================================================================
// 13. Lifecycle Initialization
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initAuthUI();
  initBitmaskUI();
  initTelemetryChart();
  updateUserUI();
  renderAuditLogs();
  renderThreatIntel();

  if (state.token) {
    fetchDevices();
  }

  // Initialize Persistent Zero-Trust FlatBuffers WebSocket Client (Dynamic origin & path)
  wsClient = new CipherPersistentWebSocket('/api/router/ws/:network_id', () => state.token);
  wsClient.connect();
});
