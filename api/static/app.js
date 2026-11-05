/**
 * Honeypot-System v2.0 Enterprise - Frontend Orchestration Engine
 * WebSocket Real-Time Ingestion, Threat Dossiers, MITRE ATT&CK Navigator, and Keystroke Player.
 */

let attackEvents = [];
let leafletMap = null;
let mapMarkers = [];
let wsConnection = null;
let replayTimer = null;

// Tactic Badge Styling
const TACTIC_COLORS = {
    'Credential Access': { bg: 'bg-amber-950/80', text: 'text-amber-400', border: 'border-amber-800' },
    'Discovery': { bg: 'bg-sky-950/80', text: 'text-sky-400', border: 'border-sky-800' },
    'Execution': { bg: 'bg-purple-950/80', text: 'text-purple-400', border: 'border-purple-800' },
    'Initial Access': { bg: 'bg-rose-950/80', text: 'text-rose-400', border: 'border-rose-800' },
    'Command and Control': { bg: 'bg-emerald-950/80', text: 'text-emerald-400', border: 'border-emerald-800' },
    'Defense Evasion': { bg: 'bg-fuchsia-950/80', text: 'text-fuchsia-400', border: 'border-fuchsia-800' }
};

document.addEventListener('DOMContentLoaded', () => {
    initClock();
    initLeafletMap();
    fetchStats();
    fetchRecentAttacks();
    initWebSocket();
    setupEventListeners();
});

// ── Live UTC Clock ──
function initClock() {
    const clockEl = document.getElementById('utc-clock');
    const update = () => {
        const now = new Date();
        clockEl.textContent = now.toUTCString().split(' ')[4] + ' UTC';
    };
    update();
    setInterval(update, 1000);
}

// ── Leaflet Dark Map ──
function initLeafletMap() {
    leafletMap = L.map('radar-map', {
        center: [20.0, 0.0],
        zoom: 2,
        minZoom: 1.5,
        maxZoom: 8,
        zoomControl: false,
        attributionControl: false
    });

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 19,
        subdomains: 'abcd'
    }).addTo(leafletMap);

    L.control.zoom({ position: 'bottomright' }).addTo(leafletMap);
}

function addMapMarker(attack) {
    if (!leafletMap || !attack.latitude || !attack.longitude) return;

    let blipClass = 'blip-low';
    if (attack.severity === 'CRITICAL' || (attack.risk_score && attack.risk_score >= 80)) blipClass = 'blip-critical';
    else if (attack.severity === 'ELEVATED' || (attack.risk_score && attack.risk_score >= 60)) blipClass = 'blip-elevated';

    const customIcon = L.divIcon({
        className: 'radar-blip-container',
        html: `<div class="radar-blip ${blipClass}"></div>`,
        iconSize: [14, 14],
        iconAnchor: [7, 7]
    });

    const marker = L.marker([attack.latitude, attack.longitude], { icon: customIcon }).addTo(leafletMap);
    
    const popupContent = `
        <div style="font-family:monospace;font-size:11px;min-width:190px;">
            <div style="color:#38bdf8;font-weight:bold;margin-bottom:3px;">${attack.source_ip}</div>
            <div>Fingerprint: <b style="color:#f43f5e;">${escapeHtml(attack.fingerprint || 'Generic')}</b></div>
            <div>Target: <b style="color:#34d399;">${attack.service}</b></div>
            <div>Risk Score: <b>${attack.risk_score || 25}/100</b></div>
            <div>Location: ${escapeHtml(attack.geoip_city || 'Unknown')}, ${escapeHtml(attack.geoip_country || 'Unknown')}</div>
        </div>
    `;
    marker.bindPopup(popupContent);
    mapMarkers.push(marker);

    if (mapMarkers.length > 80) {
        const oldMarker = mapMarkers.shift();
        leafletMap.removeLayer(oldMarker);
    }
}

// ── Fetch Telemetry Stats ──
async function fetchStats() {
    try {
        const res = await fetch('/api/v1/stats');
        if (!res.ok) return;
        const data = await res.json();

        document.getElementById('stat-total-attacks').textContent = data.total_attacks.toLocaleString();
        document.getElementById('stat-unique-ips').textContent = data.unique_ips.toLocaleString();
        document.getElementById('stat-threats-count').textContent = data.high_confidence_threats_count.toLocaleString();
        document.getElementById('stat-threat-score').textContent = `${data.avg_risk_score} / 100`;
        document.getElementById('sensor-id-badge').textContent = `NODE: ${data.sensor_name.toUpperCase()}`;

        renderFingerprints(data.top_fingerprints || []);
        highlightMitreTechniques(data.top_mitre_techniques || []);
    } catch (err) {
        console.warn('Failed loading stats:', err);
    }
}

// ── Render Botnet & Tool Signatures ──
function renderFingerprints(fingerprints) {
    const container = document.getElementById('fingerprints-breakdown');
    if (!fingerprints || fingerprints.length === 0) {
        container.innerHTML = '<div class="text-slate-500 text-center py-6 font-mono">No botnet signatures tagged yet.</div>';
        return;
    }

    const total = fingerprints.reduce((acc, cur) => acc + (cur.count || 0), 0) || 1;
    container.innerHTML = '';

    fingerprints.forEach(fp => {
        const pct = Math.round((fp.count / total) * 100);
        const item = document.createElement('div');
        item.className = 'space-y-1 font-mono';
        item.innerHTML = `
            <div class="flex justify-between items-center text-[11px]">
                <span class="font-medium text-slate-200 truncate max-w-[190px]">${escapeHtml(fp.fingerprint)}</span>
                <span class="text-cyan-400 font-bold">${fp.count} (${pct}%)</span>
            </div>
            <div class="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                <div class="bg-gradient-to-r from-cyan-500 to-rose-500 h-1.5 rounded-full" style="width: ${pct}%"></div>
            </div>
        `;
        container.appendChild(item);
    });
}

// ── Highlight Active MITRE ATT&CK Matrix Cells ──
function highlightMitreTechniques(techniques) {
    if (!techniques) return;
    const activeTechs = new Set(techniques.map(t => t.mitre_technique_id));

    document.querySelectorAll('.mitre-cell').forEach(cell => {
        const techId = cell.getAttribute('data-tech');
        if (activeTechs.has(techId)) {
            cell.classList.add('active-hit');
        } else {
            cell.classList.remove('active-hit');
        }
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
            tableBody.innerHTML = '<tr><td colspan="9" class="py-8 text-center text-slate-500 font-mono">No intrusions recorded yet. Sensor listening on ports 22, 80, 21, 23.</td></tr>';
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

    if (tableBody.children.length === 1 && tableBody.children[0].innerText.includes('Waiting for live')) {
        tableBody.innerHTML = '';
    }

    const tacticStyle = TACTIC_COLORS[attack.mitre_tactic] || { bg: 'bg-slate-800', text: 'text-slate-300', border: 'border-slate-700' };

    let riskBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">LOW</span>';
    if (attack.severity === 'CRITICAL' || (attack.risk_score && attack.risk_score >= 80)) {
        riskBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800">${attack.risk_score || 85} CRIT</span>`;
    } else if (attack.severity === 'ELEVATED' || (attack.risk_score && attack.risk_score >= 60)) {
        riskBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-950 text-orange-300 border border-orange-800">${attack.risk_score || 65} ELEV</span>`;
    }

    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-800/40 transition border-b border-cyber-border/40';

    const payloadDisplay = attack.credentials ? 
        `<span class="text-amber-300 font-semibold">AUTH: ${escapeHtml(attack.credentials)}</span>` : 
        escapeHtml(attack.payload || 'Probe Connection');

    tr.innerHTML = `
        <td class="py-2.5 px-3 text-slate-400 whitespace-nowrap text-[11px]">${attack.timestamp}</td>
        <td class="py-2.5 px-3 whitespace-nowrap">
            <button class="btn-dossier text-cyan-400 hover:text-cyan-300 font-bold hover:underline" data-ip="${attack.source_ip}">
                ${attack.source_ip}
            </button>
        </td>
        <td class="py-2.5 px-3 text-slate-300 whitespace-nowrap">${escapeHtml(attack.geoip_city || 'Unknown')}, ${escapeHtml(attack.geoip_country || 'Unknown')}</td>
        <td class="py-2.5 px-3 whitespace-nowrap">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${getServiceBadgeClass(attack.service)}">${attack.service}</span>
        </td>
        <td class="py-2.5 px-3 whitespace-nowrap text-rose-300 font-medium text-[11px] truncate max-w-[150px]" title="${escapeHtml(attack.fingerprint || '')}">
            ${escapeHtml(attack.fingerprint || 'Generic Recon')}
        </td>
        <td class="py-2.5 px-3 max-w-[220px] truncate text-slate-300 font-mono text-[11px]" title="${escapeHtml(attack.payload || '')}">${payloadDisplay}</td>
        <td class="py-2.5 px-3 whitespace-nowrap">${riskBadge}</td>
        <td class="py-2.5 px-3 whitespace-nowrap">
            <span class="px-2 py-0.5 rounded border text-[10px] font-bold ${tacticStyle.bg} ${tacticStyle.text} ${tacticStyle.border}">
                ${attack.mitre_technique_id || 'T1059'}
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
        tr.classList.add('bg-cyan-950/40');
        setTimeout(() => tr.classList.remove('bg-cyan-950/40'), 2000);

        if (tableBody.children.length > 100) {
            tableBody.removeChild(tableBody.lastChild);
        }
    } else {
        tableBody.appendChild(tr);
    }

    tr.querySelector('.btn-replay').addEventListener('click', (e) => {
        const data = JSON.parse(e.currentTarget.getAttribute('data-attack'));
        openTerminalReplay(data);
    });

    tr.querySelector('.btn-dossier').addEventListener('click', (e) => {
        const ip = e.currentTarget.getAttribute('data-ip');
        openThreatDossier(ip);
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

// ── Threat Actor Dossier Modal ──
async function openThreatDossier(ip) {
    const modal = document.getElementById('dossier-modal');
    modal.classList.remove('hidden');

    document.getElementById('dossier-ip').textContent = ip;
    document.getElementById('dossier-score').textContent = 'Calculating...';
    document.getElementById('dossier-total-events').textContent = '...';

    try {
        const res = await fetch(`/api/v1/attacker/${encodeURIComponent(ip)}`);
        if (!res.ok) return;
        const data = await res.json();

        document.getElementById('dossier-score').textContent = `${data.max_risk_score} / 100 [${data.primary_severity}]`;
        document.getElementById('dossier-total-events').textContent = data.total_events;
        document.getElementById('dossier-location').textContent = `${data.geolocation.city || 'Unknown'}, ${data.geolocation.country || 'Unknown'}`;
        document.getElementById('dossier-services').textContent = data.services_targeted.join(', ');
        document.getElementById('dossier-fingerprint').textContent = data.primary_fingerprint;

        const credsEl = document.getElementById('dossier-credentials');
        if (data.credentials_attempted && data.credentials_attempted.length > 0) {
            credsEl.innerHTML = data.credentials_attempted.map(c => `<div>&bull; ${escapeHtml(c)}</div>`).join('');
        } else {
            credsEl.textContent = 'No authentication attempts captured.';
        }

        const timelineEl = document.getElementById('dossier-timeline');
        timelineEl.innerHTML = (data.timeline || []).slice(0, 5).map(t => `
            <div class="p-2 flex justify-between items-center text-[11px]">
                <span class="text-slate-400">${t.timestamp}</span>
                <span class="text-emerald-400 font-bold">${t.service}</span>
                <span class="text-slate-200 truncate max-w-[240px]">${escapeHtml(t.payload || 'Probe')}</span>
                <span class="text-amber-400 font-semibold">${t.mitre_technique_id || 'T1059'}</span>
            </div>
        `).join('');

    } catch (err) {
        console.error('Error fetching dossier:', err);
    }
}

// ── WebSocket Real-Time Channel ──
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
                fetchStats();
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

    titleEl.textContent = `${attack.service} Interactive Keystroke Replay [${attack.source_ip}]`;
    terminalEl.textContent = '';

    if (replayTimer) clearInterval(replayTimer);

    const mockBanner = `Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)\nLast login: ${attack.timestamp} from ${attack.source_ip}\nroot@ubuntu-server-01:~# `;
    const cmd = attack.payload || 'whoami';
    const mockOutput = attack.credentials ? 
        `Authentication failed: password rejected for user.\n` : 
        `Executing payload: ${cmd}\nroot@ubuntu-server-01:~# `;

    const replayScript = [
        { text: mockBanner, delay: 300 },
        { text: cmd, delay: 600, typeCharByChar: true },
        { text: '\n' + mockOutput, delay: 400 }
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
            }, 50);
        } else {
            terminalEl.textContent += step.text;
            setTimeout(nextStep, step.delay || 300);
        }
    }
    nextStep();
}

// ── Event Listeners ──
function setupEventListeners() {
    document.getElementById('modal-close-btn').addEventListener('click', () => {
        document.getElementById('replay-modal').classList.add('hidden');
        if (replayTimer) clearInterval(replayTimer);
    });

    document.getElementById('dossier-close-btn').addEventListener('click', () => {
        document.getElementById('dossier-modal').classList.add('hidden');
    });

    document.getElementById('dossier-dismiss-btn').addEventListener('click', () => {
        document.getElementById('dossier-modal').classList.add('hidden');
    });

    document.getElementById('btn-clear-table').addEventListener('click', () => {
        document.getElementById('attack-table-body').innerHTML = '<tr><td colspan="9" class="py-8 text-center text-slate-500 font-mono">View cleared. New events will appear live.</td></tr>';
        document.getElementById('stream-count-badge').textContent = '0 events';
    });

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
    return String(text).replace(/[&<>"']/g, function(m) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
    });
}
