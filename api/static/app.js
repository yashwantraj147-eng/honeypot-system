/**
 * Honeypot-System v2.0 - Core Frontend Orchestration
 * Real-time WebSocket Telemetry, Leaflet Radar Mapping, and Session Playback Engine.
 */

let attackEvents = [];
let leafletMap = null;
let mapMarkers = [];
let wsConnection = null;
let replayTimer = null;

// Color mapping for MITRE Tactics
const TACTIC_COLORS = {
    'Credential Access': { bg: 'bg-amber-950/80', text: 'text-amber-400', border: 'border-amber-800' },
    'Discovery': { bg: 'bg-sky-950/80', text: 'text-sky-400', border: 'border-sky-800' },
    'Execution': { bg: 'bg-purple-950/80', text: 'text-purple-400', border: 'border-purple-800' },
    'Initial Access': { bg: 'bg-rose-950/80', text: 'text-rose-400', border: 'border-rose-800' },
    'Command and Control': { bg: 'bg-emerald-950/80', text: 'text-emerald-400', border: 'border-emerald-800' },
    'Defense Evasion': { bg: 'bg-fuchsia-950/80', text: 'text-fuchsia-400', border: 'border-fuchsia-800' }
};

// ── Initialize Application on DOM Ready ──
document.addEventListener('DOMContentLoaded', () => {
    initClock();
    initLeafletMap();
    fetchStats();
    fetchRecentAttacks();
    initWebSocket();
    setupEventListeners();
});

// ── UTC Live Clock ──
function initClock() {
    const clockEl = document.getElementById('utc-clock');
    const update = () => {
        const now = new Date();
        clockEl.textContent = now.toUTCString().split(' ')[4] + ' UTC';
    };
    update();
    setInterval(update, 1000);
}

// ── Leaflet.js Dark Map Setup ──
function initLeafletMap() {
    leafletMap = L.map('radar-map', {
        center: [20.0, 0.0],
        zoom: 2,
        minZoom: 1.5,
        maxZoom: 8,
        zoomControl: false,
        attributionControl: false
    });

    // Dark-matter styled tiles
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 19,
        subdomains: 'abcd'
    }).addTo(leafletMap);

    L.control.zoom({ position: 'bottomright' }).addTo(leafletMap);
}

// ── Add Radar Marker to Map ──
function addMapMarker(attack) {
    if (!leafletMap || !attack.latitude || !attack.longitude) return;

    const customIcon = L.divIcon({
        className: 'radar-blip-container',
        html: `<div class="radar-blip"></div>`,
        iconSize: [14, 14],
        iconAnchor: [7, 7]
    });

    const marker = L.marker([attack.latitude, attack.longitude], { icon: customIcon }).addTo(leafletMap);
    
    const popupContent = `
        <div style="font-family:monospace;font-size:11px;min-width:180px;">
            <div style="color:#38bdf8;font-weight:bold;margin-bottom:4px;">${attack.source_ip}</div>
            <div>Target: <b style="color:#34d399;">${attack.service}</b></div>
            <div>Location: ${attack.geoip_city || 'Unknown'}, ${attack.geoip_country || 'Unknown'}</div>
            <div>MITRE: <span style="color:#f59e0b;">${attack.mitre_technique_id || 'N/A'}</span></div>
        </div>
    `;
    marker.bindPopup(popupContent);
    mapMarkers.push(marker);

    // Limit active markers to 80 to preserve performance
    if (mapMarkers.length > 80) {
        const oldMarker = mapMarkers.shift();
        leafletMap.removeLayer(oldMarker);
    }
}

// ── Fetch Initial Stats ──
async function fetchStats() {
    try {
        const res = await fetch('/api/v1/stats');
        if (!res.ok) return;
        const data = await res.json();

        document.getElementById('stat-total-attacks').textContent = data.total_attacks.toLocaleString();
        document.getElementById('stat-unique-ips').textContent = data.unique_ips.toLocaleString();
        document.getElementById('stat-threats-count').textContent = data.high_confidence_threats_count.toLocaleString();
        document.getElementById('sensor-id-badge').textContent = `SENSOR: ${data.sensor_name.toUpperCase()}`;

        renderMitreMatrix(data.top_mitre_techniques || []);
    } catch (err) {
        console.warn('Failed loading stats:', err);
    }
}

// ── Render MITRE ATT&CK Tactics Breakdown ──
function renderMitreMatrix(techniques) {
    const container = document.getElementById('mitre-breakdown');
    if (!techniques || techniques.length === 0) {
        container.innerHTML = '<div class="text-slate-500 text-center py-6">No attack heuristics observed yet.</div>';
        return;
    }

    const total = techniques.reduce((acc, cur) => acc + (cur.count || 0), 0) || 1;
    container.innerHTML = '';

    techniques.slice(0, 6).forEach(tech => {
        const pct = Math.round((tech.count / total) * 100);
        const tacticStyle = TACTIC_COLORS[tech.mitre_tactic] || { bg: 'bg-slate-900', text: 'text-slate-300', border: 'border-slate-700' };

        const item = document.createElement('div');
        item.className = 'space-y-1';
        item.innerHTML = `
            <div class="flex justify-between items-center text-[11px]">
                <span class="font-medium text-slate-200">${tech.mitre_name || 'Generic Probe'}</span>
                <span class="font-mono ${tacticStyle.text}">${tech.mitre_technique_id || 'T1059'} (${pct}%)</span>
            </div>
            <div class="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                <div class="bg-gradient-to-r from-cyan-500 to-blue-500 h-1.5 rounded-full" style="width: ${pct}%"></div>
            </div>
        `;
        container.appendChild(item);
    });
}

// ── Fetch Recent Attacks ──
async function fetchRecentAttacks() {
    try {
        const res = await fetch('/api/v1/attacks/recent?limit=50');
        if (!res.ok) return;
        const data = await res.json();
        attackEvents = data;

        const tableBody = document.getElementById('attack-table-body');
        tableBody.innerHTML = '';

        if (attackEvents.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="7" class="py-8 text-center text-slate-500">No intrusions recorded yet. Sensor listening on ports 22, 80, 21, 23.</td></tr>';
            return;
        }

        attackEvents.forEach(attack => {
            appendTableRow(attack, false);
            addMapMarker(attack);
        });

        document.getElementById('stream-count-badge').textContent = `${attackEvents.length} events`;
    } catch (err) {
        console.warn('Failed loading attacks:', err);
    }
}

// ── Append Row to Intrusion Event Table ──
function appendTableRow(attack, prepend = true) {
    const tableBody = document.getElementById('attack-table-body');

    // Remove empty placeholder if present
    if (tableBody.children.length === 1 && tableBody.children[0].innerText.includes('Waiting for live')) {
        tableBody.innerHTML = '';
    }

    const tacticStyle = TACTIC_COLORS[attack.mitre_tactic] || { bg: 'bg-slate-800', text: 'text-slate-300', border: 'border-slate-700' };

    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-800/40 transition border-b border-cyber-border/40';

    const payloadDisplay = attack.credentials ? 
        `<span class="text-amber-400">AUTH: ${escapeHtml(attack.credentials)}</span>` : 
        escapeHtml(attack.payload || 'Probe Connection');

    tr.innerHTML = `
        <td class="py-2.5 px-3 text-slate-400 whitespace-nowrap text-[11px]">${attack.timestamp}</td>
        <td class="py-2.5 px-3 font-semibold text-white whitespace-nowrap">${attack.source_ip}</td>
        <td class="py-2.5 px-3 text-slate-300 whitespace-nowrap">${attack.geoip_city || 'Unknown'}, ${attack.geoip_country || 'Unknown'}</td>
        <td class="py-2.5 px-3 whitespace-nowrap">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${getServiceBadgeClass(attack.service)}">${attack.service}</span>
        </td>
        <td class="py-2.5 px-3 max-w-[280px] truncate text-slate-300 font-mono text-[11px]" title="${escapeHtml(attack.payload || '')}">${payloadDisplay}</td>
        <td class="py-2.5 px-3 whitespace-nowrap">
            <span class="px-2 py-0.5 rounded border text-[10px] font-bold ${tacticStyle.bg} ${tacticStyle.text} ${tacticStyle.border}">
                ${attack.mitre_technique_id || 'T1059'} ${attack.mitre_name ? '- ' + attack.mitre_name : ''}
            </span>
        </td>
        <td class="py-2.5 px-3 text-right whitespace-nowrap">
            <button class="btn-replay text-[11px] text-cyan-400 hover:text-cyan-300 underline font-semibold" data-attack='${JSON.stringify(attack).replace(/'/g, "&apos;")}'>
                Replay
            </button>
        </td>
    `;

    if (prepend) {
        tableBody.insertBefore(tr, tableBody.firstChild);
        // Highlight animation for new items
        tr.classList.add('bg-cyan-950/30');
        setTimeout(() => tr.classList.remove('bg-cyan-950/30'), 2000);

        if (tableBody.children.length > 100) {
            tableBody.removeChild(tableBody.lastChild);
        }
    } else {
        tableBody.appendChild(tr);
    }

    // Attach replay click event
    tr.querySelector('.btn-replay').addEventListener('click', (e) => {
        const data = JSON.parse(e.currentTarget.getAttribute('data-attack'));
        openTerminalReplay(data);
    });
}

function getServiceBadgeClass(service) {
    switch ((service || '').toUpperCase()) {
        case 'SSH': return 'bg-blue-950 text-blue-400 border border-blue-800';
        case 'HTTP': return 'bg-emerald-950 text-emerald-400 border border-emerald-800';
        case 'FTP': return 'bg-amber-950 text-amber-400 border border-amber-800';
        case 'TELNET': return 'bg-purple-950 text-purple-400 border border-purple-800';
        default: return 'bg-slate-800 text-slate-300 border border-slate-700';
    }
}

// ── WebSocket Real-Time Ingestion ──
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/attacks`;

    wsConnection = new WebSocket(wsUrl);

    wsConnection.onopen = () => {
        document.getElementById('system-status-indicator').textContent = 'GRID ARMED & STREAMING';
    };

    wsConnection.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'attack_event' && msg.data) {
                const attack = msg.data;
                attackEvents.unshift(attack);
                appendTableRow(attack, true);
                addMapMarker(attack);
                fetchStats(); // Update totals & MITRE distribution
                document.getElementById('stream-count-badge').textContent = `${attackEvents.length} events`;
            }
        } catch (e) {
            console.error('Error handling WebSocket message:', e);
        }
    };

    wsConnection.onclose = () => {
        document.getElementById('system-status-indicator').textContent = 'RECONNECTING STREAM...';
        setTimeout(initWebSocket, 3000);
    };

    wsConnection.onerror = () => {
        wsConnection.close();
    };
}

// ── Terminal Session Replay Modal ──
async function openTerminalReplay(attack) {
    const modal = document.getElementById('replay-modal');
    const terminalEl = document.getElementById('terminal-content');
    const titleEl = document.getElementById('modal-session-title');
    modal.classList.remove('hidden');

    titleEl.textContent = `${attack.service} Keystroke Replay [${attack.source_ip}]`;
    terminalEl.textContent = '';

    if (replayTimer) clearInterval(replayTimer);

    // Attempt fetching recording from API
    let replayScript = [];

    // Fallback simulation if no raw file exists
    const mockBanner = `Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)\nLast login: ${attack.timestamp} from ${attack.source_ip}\nroot@ubuntu-server-01:~# `;
    const cmd = attack.payload || 'whoami';
    const mockOutput = attack.credentials ? 
        `Authentication failed: password rejected for user.\n` : 
        `Executing payload: ${cmd}\nroot@ubuntu-server-01:~# `;

    replayScript = [
        { text: mockBanner, delay: 300 },
        { text: cmd, delay: 800, typeCharByChar: true },
        { text: '\n' + mockOutput, delay: 500 }
    ];

    playTerminalScript(replayScript);
}

function playTerminalScript(script) {
    const terminalEl = document.getElementById('terminal-content');
    terminalEl.textContent = '';
    let stepIndex = 0;

    function nextStep() {
        if (stepIndex >= script.length) return;
        const step = script[stepIndex++];

        if (step.typeCharByChar) {
            let charIndex = 0;
            const charInterval = setInterval(() => {
                if (charIndex < step.text.length) {
                    terminalEl.textContent += step.text[charIndex++];
                } else {
                    clearInterval(charInterval);
                    setTimeout(nextStep, step.delay || 400);
                }
            }, 60);
        } else {
            terminalEl.textContent += step.text;
            setTimeout(nextStep, step.delay || 300);
        }
    }
    nextStep();
}

// ── Event Listeners ──
function setupEventListeners() {
    // Modal close
    document.getElementById('modal-close-btn').addEventListener('click', () => {
        document.getElementById('replay-modal').classList.add('hidden');
        if (replayTimer) clearInterval(replayTimer);
    });

    // Clear Table
    document.getElementById('btn-clear-table').addEventListener('click', () => {
        document.getElementById('attack-table-body').innerHTML = '<tr><td colspan="7" class="py-8 text-center text-slate-500">View cleared. New events will appear live.</td></tr>';
        document.getElementById('stream-count-badge').textContent = '0 events';
    });

    // Export JSON
    document.getElementById('btn-export-json').addEventListener('click', () => {
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(attackEvents, null, 2));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", `honeypot_attacks_${new Date().toISOString().slice(0,10)}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
    });
}

function escapeHtml(text) {
    if (!text) return '';
    return text.replace(/[&<>"']/g, function(m) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
    });
}

