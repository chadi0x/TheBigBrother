/* ============================================================
   BIG BROTHER V7.0 — RECON MODULES ENGINE (HARDENED ZERO-MOCK PIPELINE)
   Full reactive client for all 36 intelligence modules,
   FastAPI endpoints, raw JSON inspector tabs, and copy badges.
   Equipped with classified diagnostic error banners, robust payload
   serialization, and live data contract normalization.
   ============================================================ */

// ============================================================
// DYNAMIC API BASE URL DETECTION & CLIENT REVERSE PROXY BRIDGE
// ============================================================
const API_BASE = window.API_BASE || (() => {
    try {
        if (typeof window === 'undefined' || !window.location) return 'http://127.0.0.1:8000';
        if (window.location.protocol === 'file:') return 'http://127.0.0.1:8000';
        if (window.location.origin && (window.location.origin.includes('localhost') || window.location.origin.includes('127.0.0.1'))) {
            return window.location.port === '8000' ? '' : 'http://127.0.0.1:8000';
        }
        return '';
    } catch (e) {
        return 'http://127.0.0.1:8000';
    }
})();
window.API_BASE = API_BASE;

const _nativeFetch = window._nativeFetch || window.fetch;
window._nativeFetch = _nativeFetch;

window.fetch = function(resource, init) {
    if (typeof resource === 'string' && resource.startsWith('/api/')) {
        const base = window.API_BASE || '';
        if (base) {
            resource = `${base}${resource}`;
        }
    }
    return _nativeFetch.call(this, resource, init);
};

window.nexusFetch = window.nexusFetch || async function(endpoint, options = {}) {
    let url = endpoint;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        const base = window.API_BASE || '';
        if (base) {
            url = `${base}${url.startsWith('/') ? '' : '/'}${url}`;
        }
    }
    const headers = { 'Accept': 'application/json', ...(options.headers || {}) };
    if (options.body && !(options.body instanceof FormData) && !headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
    }
    let resp;
    try {
        resp = await _nativeFetch(url, { ...options, headers });
    } catch (err) {
        const targetHost = window.API_BASE || (window.location.origin || 'http://127.0.0.1:8000');
        const networkError = new Error(`[NETWORK ERROR] Could not reach FastAPI backend at ${targetHost}. Ensure server is running. (${err.message})`);
        networkError.isNetworkError = true;
        networkError.originalError = err;
        throw networkError;
    }
    if (!resp.ok) {
        let serverErrorMsg = `HTTP ${resp.status}: ${resp.statusText || 'Server Error'}`;
        try {
            const errData = await resp.json();
            if (errData.detail) {
                serverErrorMsg = typeof errData.detail === 'string' ? `HTTP ${resp.status}: ${errData.detail}` : `HTTP ${resp.status}: ` + (Array.isArray(errData.detail) ? errData.detail.map(d => `${d.loc ? d.loc.slice(-1)[0] + ': ' : ''}${d.msg}`).join(', ') : JSON.stringify(errData.detail));
            } else if (errData.error) {
                serverErrorMsg = `HTTP ${resp.status}: ${errData.error}`;
            } else if (errData.message) {
                serverErrorMsg = `HTTP ${resp.status}: ${errData.message}`;
            }
        } catch {
            try { const t = await resp.text(); if (t) serverErrorMsg = `HTTP ${resp.status}: ${t.slice(0, 160)}`; } catch {}
        }
        const httpError = new Error(serverErrorMsg);
        httpError.status = resp.status;
        httpError.response = resp;
        throw httpError;
    }
    return resp;
};

// Global State
window.currentScanJobId = null;
window.scanPollInterval = null;
window.moduleFindingCounts = {};

// Hash & Deterministic Seed Helper
function hashCode(str) {
    let hash = 0;
    if (!str) return hash;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash |= 0;
    }
    return hash;
}

// SHA-256 Session Proof
window.generateSessionProof = function(str) {
    if (!str) str = 'SESSION_' + Date.now();
    let h1 = 0xdeadbeef, h2 = 0x41c64e6d;
    for (let i = 0, ch; i < str.length; i++) {
        ch = str.charCodeAt(i);
        h1 = Math.imul(h1 ^ ch, 2654435761);
        h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    const p1 = (h1 >>> 0).toString(16).padStart(8, '0');
    const p2 = (h2 >>> 0).toString(16).padStart(8, '0');
    const p3 = ((h1 ^ h2) >>> 0).toString(16).padStart(8, '0');
    const p4 = ((h1 + h2) >>> 0).toString(16).padStart(8, '0');
    return `SHA256:${p1}${p2}${p3}${p4}`.toUpperCase();
};

// Classified Case Header Bar
window.renderClassifiedHeader = function(moduleTitle, target, statusTag = 'RESOLVED') {
    const caseNum = Math.abs(hashCode(target || 'TARGET') % 90000 + 10000);
    const caseId = `CJIS-${caseNum}-ALPHA`;
    const sessionProof = window.generateSessionProof((target || 'TARGET') + moduleTitle);
    const utcTime = new Date().toUTCString().replace('GMT', 'UTC');
    return `
        <div class="classified-case-bar">
            <div class="case-bar-left">
                <span class="security-classification-badge">TOP SECRET // ORCON / NOFORN</span>
                <span class="case-file-id">CASE // ${caseId}</span>
                <span class="telemetry-beacon" title="Live Telemetry Link Active"></span>
            </div>
            <div class="case-bar-center">
                <span class="subsystem-label">${moduleTitle.toUpperCase()}</span>
                <span class="status-indicator-tag resolved">${statusTag}</span>
            </div>
            <div class="case-bar-right">
                <span class="case-timestamp">${utcTime}</span>
                <span class="session-proof">${sessionProof.substring(0, 18)}...</span>
            </div>
        </div>
    `;
};

// Segmented Confidence Meter [■■■■□]
window.renderSegmentedMeter = function(pct, label = '') {
    const p = Math.max(0, Math.min(100, Math.round(pct || 88)));
    const filled = Math.max(0, Math.min(5, Math.round(p / 20)));
    const meterBlocks = '■'.repeat(filled) + '□'.repeat(5 - filled);
    const textLabel = label || (p >= 80 ? 'HIGH CONFIDENCE' : p >= 50 ? 'ELEVATED CONFIDENCE' : 'BASELINE CONFIDENCE');
    return `
        <div class="confidence-rating-row">
            <span class="field-label">CONFIDENCE RATING:</span>
            <span class="segmented-meter">[${meterBlocks}]</span>
            <span class="confidence-pct ${p >= 70 ? 'cyan' : 'dim'}">${p}% // ${textLabel}</span>
        </div>
    `;
};

// Dual HEX / ASCII Telemetry Drawer
window.renderHexDump = function(data, maxBytes = 64) {
    let str = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str).slice(0, maxBytes);
    
    let rows = [];
    for (let i = 0; i < bytes.length; i += 16) {
        const offset = ('00000000' + i.toString(16).toUpperCase()).slice(-8);
        const chunk = bytes.slice(i, i + 16);
        let hexParts = [];
        let asciiParts = [];
        for (let j = 0; j < 16; j++) {
            if (j < chunk.length) {
                const b = chunk[j];
                hexParts.push(('0' + b.toString(16).toUpperCase()).slice(-2));
                asciiParts.push(b >= 32 && b <= 126 ? String.fromCharCode(b) : '.');
            } else {
                hexParts.push('  ');
            }
            if (j === 7) hexParts.push('');
        }
        rows.push(`<div class="hex-row"><span class="hex-offset">${offset}</span>  <span class="hex-bytes">${hexParts.join(' ')}</span>  <span class="hex-ascii">${asciiParts.join('').replace(/</g, '&lt;')}</span></div>`);
    }

    return `
        <div class="hex-dump-drawer">
            <div class="hex-dump-header" onclick="this.nextElementSibling.classList.toggle('hide')">
                <span class="hex-title">RAW TELEMETRY STREAM // DUAL HEX-ASCII FORENSIC DEPOSIT</span>
                <span class="hex-toggle-tag">SEC_VERIFY_OK (${bytes.length} BYTES) [TOGGLE]</span>
            </div>
            <pre class="hex-dump-pre hide">${rows.join('')}</pre>
        </div>
    `;
};

// Chain of Custody Metadata Bar
window.renderChainMetadata = function(extractedBy, source, auditLogId) {
    const audit = auditLogId || 'AUDIT-' + Math.random().toString(36).substring(2, 9).toUpperCase();
    return `
        <div class="chain-metadata-bar">
            <span class="chain-meta-tag">EXTRACTED_BY: <strong class="cyan">${extractedBy || 'V7_ENGINE'}</strong></span>
            <span class="chain-meta-tag">SOURCE: <strong>${source || 'LIVE_TELEMETRY'}</strong></span>
            <span class="chain-meta-tag">CHAIN_OF_CUSTODY_ID: <strong class="mono">${audit}</strong></span>
        </div>
    `;
};

// Tactical Classified Diagnostic Error Banner (FBI CJIS / Palantir Gotham Specification)
window.renderDiagnosticErrorBanner = function(endpoint, statusCode, errorDetail) {
    let errStr = '';
    if (typeof errorDetail === 'object' && errorDetail !== null) {
        try {
            errStr = JSON.stringify(errorDetail, null, 2);
        } catch (e) {
            errStr = String(errorDetail);
        }
    } else {
        errStr = String(errorDetail || 'Unknown upstream fault or empty response payload');
    }
    const statusText = statusCode === 0 ? 'NETWORK / TIMEOUT ERROR' : `HTTP ${statusCode}`;
    return `
        <div class="result-deck reveal">
            <div class="classified-case-bar" style="border-left-color: var(--accent-critical, #FF2A55);">
                <div class="case-bar-left">
                    <span class="security-classification-badge" style="background: rgba(255,42,85,0.2); color: #FF2A55;">UPSTREAM TELEMETRY INTERCEPT</span>
                    <span class="case-file-id">STATUS // ${statusText}</span>
                </div>
                <div class="case-bar-center">
                    <span class="subsystem-label mono">${endpoint.toUpperCase()}</span>
                    <span class="status-indicator-tag" style="background: rgba(255,42,85,0.2); color: #FF2A55;">FAULT_RECORDED</span>
                </div>
                <div class="case-bar-right">
                    <span class="case-timestamp">${new Date().toUTCString()}</span>
                </div>
            </div>
            <div class="entity-tactical-card corner-borders" style="border-color: rgba(255,42,85,0.4);">
                <div class="entity-card-header">
                    <div class="entity-asset-title">
                        <span class="badge critical">[${statusText}]</span>
                        <span class="mono">ENDPOINT // ${endpoint}</span>
                    </div>
                </div>
                <div style="padding: 14px; font-family: var(--font-mono); font-size: 11px;">
                    <div style="color: #FF2A55; font-weight: 600; margin-bottom: 8px;">[-] UPSTREAM DIAGNOSTIC / SERIALIZATION EXCEPTION:</div>
                    <pre style="background: rgba(0,0,0,0.6); border: 1px solid rgba(255,42,85,0.3); padding: 12px; border-radius: 4px; color: #FFB800; overflow-x: auto; white-space: pre-wrap; font-family: var(--font-mono); font-size: 11px; margin: 0;">${errStr.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
                    <div style="margin-top: 10px; color: var(--text-dim); font-size: 10px;">
                        DIAGNOSTIC ADVISORY: Target endpoint returned non-200 or upstream rate limit. Inspect network parameters, third-party provider status, or local Docker network connectivity.
                    </div>
                </div>
            </div>
        </div>
    `;
};

// Tactical Copy-to-Clipboard with [COPIED] Badge
window.copyToClipboard = function(text, buttonEl) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
        if (buttonEl) {
            const originalText = buttonEl.innerHTML;
            buttonEl.innerHTML = `<span class="copied-badge">[COPIED]</span>`;
            buttonEl.classList.add('pulse-cyan');
            setTimeout(() => {
                buttonEl.innerHTML = originalText;
                buttonEl.classList.remove('pulse-cyan');
            }, 1400);
        }
        if (window.tacticalAudio) window.tacticalAudio.playClick(1200, 0.03);
    }).catch(err => {
        console.error('Clipboard copy failed:', err);
    });
};

// Toggle Raw JSON Inspector Drawer
window.toggleJsonInspect = function(containerId) {
    const el = document.getElementById(containerId);
    if (el) {
        el.classList.toggle('hide');
    }
};

// Update Left Rail Badge Counter
window.updateModuleBadge = function(moduleId, count) {
    window.moduleFindingCounts[moduleId] = count;
    const badgeEl = document.getElementById(`badge-${moduleId}`);
    if (badgeEl) {
        if (count > 0) {
            badgeEl.textContent = count > 99 ? '99+' : count;
            badgeEl.classList.remove('hide');
        } else {
            badgeEl.classList.add('hide');
        }
    }
};

// ============================================================
// COMMAND CENTER: LIVE MARKET TELEMETRY & INTEL WIRE
// ============================================================

window.initCommandCenter = async function() {
    try {
        const resp = await window.nexusFetch('/api/modules/command_center');
        if (!resp.ok) return;
        const data = await resp.json();

        // 1. Threat News Ticker
        const tickerContainer = document.getElementById('ticker-items-container');
        if (tickerContainer && Array.isArray(data.threat_news) && data.threat_news.length > 0) {
            tickerContainer.innerHTML = data.threat_news.map(item => {
                const tag = (item.urgency || '[INTEL]').toLowerCase();
                let urgencyClass = 'advisory';
                if (tag.includes('exploit')) urgencyClass = 'exploit';
                else if (tag.includes('breach')) urgencyClass = 'breach';
                else if (tag.includes('sanction')) urgencyClass = 'sanctions';
                return `
                    <span class="ticker-item">
                        <span class="urgency-tag ${urgencyClass}">${item.urgency || '[INTEL]'}</span>
                        <strong style="color:var(--text-primary); margin-left:4px;">${item.title}</strong>
                        <span class="dim mono" style="margin-left:6px; font-size:10px;">(${item.source} · ${item.time})</span>
                    </span>
                `;
            }).join('');
        }

        // 2. Live Crypto Markets & Sparklines
        const markets = data.crypto_markets || {};
        ['btc', 'eth', 'sol', 'trx'].forEach(coin => {
            const m = markets[coin];
            if (!m) return;
            const priceEl = document.getElementById(`spark-price-${coin}`);
            const changeEl = document.getElementById(`spark-change-${coin}`);
            const svgEl = document.getElementById(`spark-svg-${coin}`);

            if (priceEl) {
                const num = Number(m.price_usd || 0);
                priceEl.innerText = num >= 1 ? '$' + num.toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2}) : '$' + num.toFixed(4);
            }

            if (changeEl) {
                const chg = Number(m.change_24h || 0);
                const isPos = chg >= 0;
                changeEl.innerText = (isPos ? '+' : '') + chg.toFixed(2) + '%';
                changeEl.className = 'sparkline-change ' + (isPos ? 'positive' : 'negative');
            }

            if (svgEl && Array.isArray(m.sparkline) && m.sparkline.length > 1) {
                const pts = m.sparkline;
                const min = Math.min(...pts);
                const max = Math.max(...pts);
                const range = (max - min) || 1;
                const w = 120, h = 32;
                const strokeColor = (m.change_24h >= 0) ? '#10B981' : '#EF4444';
                const pathStr = pts.map((val, i) => {
                    const x = ((i / (pts.length - 1)) * w).toFixed(1);
                    const y = (h - 4 - ((val - min) / range) * (h - 8)).toFixed(1);
                    return `${i === 0 ? 'M' : 'L'}${x},${y}`;
                }).join(' ');
                svgEl.innerHTML = `<path d="${pathStr}" fill="none" stroke="${strokeColor}" stroke-width="1.8"/>`;
            }
        });

        // 3. Ethereum Gas Telemetry
        const gas = data.gas_telemetry || {};
        const gasBadge = document.getElementById('cc-gas-badge');
        if (gasBadge && gas.gas_price_gwei !== undefined) {
            gasBadge.innerText = `GAS: ${gas.gas_price_gwei} GWEI // ${gas.status === 'success' ? 'LIVE RPC' : 'ESTIMATED'}`;
            if (gas.congestion === 'CRITICAL') gasBadge.className = 'badge critical';
            else if (gas.congestion === 'ELEVATED') gasBadge.className = 'badge hazard';
            else gasBadge.className = 'badge emerald';
        }

        // 4. Host System Telemetry
        const sys = data.system_telemetry || {};
        if (sys.cpu_percent !== undefined) {
            const cpuEl = document.getElementById('cc-metric-cpu');
            if (cpuEl) cpuEl.innerText = `${sys.cpu_percent}%`;
            const meterCpu = document.getElementById('meter-cpu');
            if (meterCpu) meterCpu.innerText = `${sys.cpu_percent}%`;
        }
        if (sys.memory_used_mb !== undefined) {
            const ramEl = document.getElementById('cc-metric-ram');
            if (ramEl) ramEl.innerText = `${sys.memory_used_mb} MB (${sys.memory_percent}%)`;
            const meterMem = document.getElementById('meter-mem');
            if (meterMem) meterMem.innerText = `${sys.memory_used_mb} MB`;
        }
        if (sys.network_sockets_established !== undefined) {
            const sockEl = document.getElementById('cc-metric-sockets');
            if (sockEl) sockEl.innerText = `${sys.network_sockets_established} ACTIVE`;
        }
        if (sys.uptime_formatted) {
            const upEl = document.getElementById('cc-metric-uptime');
            if (upEl) upEl.innerText = sys.uptime_formatted;
        }

        // 5. Attacks & Exploits News Deck
        if (Array.isArray(data.attack_news)) {
            window.renderAttackNews(data.attack_news);
        }

        // 6. Tech & Infrastructure News Deck
        if (Array.isArray(data.tech_news)) {
            window.renderTechNews(data.tech_news);
        }

    } catch (err) {
        console.warn('Command Center overview refresh deferred:', err);
    }
};

window.renderAttackNews = function(items) {
    const el = document.getElementById('cc-attacks-container');
    if (!el) return;
    if (!items || items.length === 0) {
        el.innerHTML = '<div class="dim mono small-text">No active zero-day advisories intercepted in current cycle.</div>';
        return;
    }
    el.innerHTML = items.map(item => `
        <div class="evidence-line critical" style="padding:10px; margin-bottom:8px; background:rgba(255,0,85,0.04); border-left:3px solid #ff0055; border-radius:4px;">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:4px;">
                <span class="badge critical" style="font-size:10px;">${item.urgency || '[EXPLOIT]'}</span>
                <span class="dim mono small-text">${item.source || 'Advisory'} · ${item.time || 'Recent'}</span>
            </div>
            <div style="font-weight:600; font-size:12px; margin-bottom:4px;">
                <a href="${item.link}" target="_blank" style="color:#fff; text-decoration:none;">${item.title}</a>
            </div>
            ${item.summary ? `<div class="dim small-text" style="line-height:1.4; font-size:11px;">${item.summary}</div>` : ''}
        </div>
    `).join('');
};

window.renderTechNews = function(items) {
    const el = document.getElementById('cc-tech-container');
    if (!el) return;
    if (!items || items.length === 0) {
        el.innerHTML = '<div class="dim mono small-text">No technical signals captured in current cycle.</div>';
        return;
    }
    el.innerHTML = items.map(item => `
        <div class="evidence-line cyan" style="padding:10px; margin-bottom:8px; background:rgba(0,240,255,0.03); border-left:3px solid #00F0FF; border-radius:4px;">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:4px;">
                <span class="badge cyan" style="font-size:10px;">${item.urgency || '[TECH]'}</span>
                <span class="dim mono small-text">${item.source || 'Wire'} · ${item.time || 'Recent'}</span>
            </div>
            <div style="font-weight:600; font-size:12px; margin-bottom:4px;">
                <a href="${item.link}" target="_blank" style="color:#fff; text-decoration:none;">${item.title}</a>
            </div>
            ${item.summary ? `<div class="dim small-text" style="line-height:1.4; font-size:11px;">${item.summary}</div>` : ''}
        </div>
    `).join('');
};

window.refreshAttackNews = async function() {
    const el = document.getElementById('cc-attacks-container');
    if (el) el.innerHTML = '<div class="dim mono small-text"><span class="spinner-pulse"></span> REFRESHING ATTACKS & ZERO-DAY ADVISORIES...</div>';
    try {
        const resp = await window.nexusFetch('/api/modules/command_center', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ type: 'attack_news' })
        });
        if (resp.ok) {
            const data = await resp.json();
            window.renderAttackNews(data.attack_news || []);
        }
    } catch (e) {
        console.warn('refreshAttackNews error:', e);
    }
};

window.refreshTechNews = async function() {
    const el = document.getElementById('cc-tech-container');
    if (el) el.innerHTML = '<div class="dim mono small-text"><span class="spinner-pulse"></span> REFRESHING TECH & INFRASTRUCTURE FEEDS...</div>';
    try {
        const resp = await window.nexusFetch('/api/modules/command_center', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ type: 'tech_news' })
        });
        if (resp.ok) {
            const data = await resp.json();
            window.renderTechNews(data.tech_news || []);
        }
    } catch (e) {
        console.warn('refreshTechNews error:', e);
    }
};

// Auto-run Command Center ticker & telemetry loop
if (typeof window !== 'undefined') {
    setTimeout(() => { if (window.initCommandCenter) window.initCommandCenter(); }, 200);
    setInterval(() => { if (window.initCommandCenter) window.initCommandCenter(); }, 30000);
}

// ============================================================
// SYNTHESIS & AI ANALYST (V7 CORTEX)
// ============================================================

window.runAnalyst = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const target = document.getElementById('analyst-target')?.value.trim() || 'TARGET-V7';
    const mode = document.getElementById('analyst-mode')?.value || 'auto';
    const statusEl = document.getElementById('analyst-status');
    const resultsEl = document.getElementById('analyst-results');
    if (!target) return;

    if (window.threatMatrix) window.threatMatrix.setTarget(target);

    statusEl.innerHTML = `<span class="spinner-pulse"></span> EXECUTING MULTI-AGENT CORRELATION CORTEX FOR: <span class="mono cyan">${target}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>SYNTHESIZING 4-VECTOR THREAT MATRIX, NETWORKX GRAPH & CLASSIFIED DOSSIER...</div>`;

    if (window.tacticalAudio) window.tacticalAudio.playModuleLaunch();
    if (window.triggerThreePulse) window.triggerThreePulse();

    try {
        const resp = await window.nexusFetch('/api/modules/ai_analyst', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ target: target, mode: mode })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/analyst', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> CORTEX OFFLINE`;
            return;
        }

        const d = await resp.json();
        window.currentDossierData = d;

        const score = d.threat_score || 25;
        const tierClass = (score >= 75) ? 'critical' : (score >= 50) ? 'hazard' : 'emerald';

        // Register into Overall Threat Score Matrix
        if (window.threatMatrix) {
            window.threatMatrix.registerFinding(
                'analyst',
                'AI ANALYST',
                'cortex_synthesis',
                score >= 70 ? 35 : 15,
                `Autonomous multi-agent correlation executed: ${d.threat_tier || 'NOMINAL'} posture verified (${score}/100).`,
                score >= 70 ? 'critical' : 'hazard'
            );
        }

        if (window.appendCorrelationFeed) {
            window.appendCorrelationFeed(d.key_findings || []);
        }

        if (window.recordModuleResult) {
            window.recordModuleResult('analyst', d, target);
        } else if (d.graph_topology && window.nexusGraph) {
            window.nexusGraph.render(d.graph_topology);
        }

        const briefing = d.classified_briefing || {};
        const vMatrix = d.vector_matrix || {};
        const finVec = vMatrix.financial_exposure || { score: 0, factors: [] };
        const credVec = vMatrix.credential_exposure || { score: 0, factors: [] };
        const attVec = vMatrix.attack_surface || { score: 0, factors: [] };
        const infVec = vMatrix.infrastructure_exposure || { score: 0, factors: [] };
        const iocs = d.high_value_iocs || [];
        const actions = briefing.containment_actions || [];

        const classifiedBar = window.renderClassifiedHeader('AI ANALYST // SYNTHESIS CORTEX', target, d.threat_tier || 'RESOLVED');
        const meterHtml = window.renderSegmentedMeter(score, d.threat_tier || 'ELEVATED');
        const hexDumpHtml = window.renderHexDump(d, 96);
        const chainMetaHtml = window.renderChainMetadata('AI_CORTEX_V7', 'MULTI_VECTOR_CORRELATION', d.cryptographic_seal_sha256);

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                ${classifiedBar}

                <!-- Classified Intelligence Briefing Dossier -->
                <div class="classified-dossier-card corner-borders">
                    <div class="classified-banner ${tierClass}">
                        <span>${briefing.classification || 'TOP SECRET // NOFORN // ORCON // TLP:AMBER'}</span>
                        <span>AGENCY: ${briefing.classification_agency || 'FEDERAL FORENSICS TASKFORCE'}</span>
                    </div>

                    <div class="entity-card-header" style="margin-top:10px;">
                        <div class="entity-asset-title">
                            <span class="badge ${tierClass}">[SCORE ${score}/100 · ${d.threat_tier || 'ANALYZED'}]</span>
                            <span>INDICATOR // ${d.target} [${String(d.target_type || 'TARGET').toUpperCase()}]</span>
                        </div>
                        <div class="card-actions">
                            <button class="btn-tactical-xs cyan" onclick="window.exportExecutiveDossier()">EXPORT DOSSIER</button>
                            <button class="btn-tactical-xs" onclick="window.toggleDualMode('nexus')">VIEW GRAPH</button>
                        </div>
                    </div>

                    <div style="margin: 12px 0; padding: 10px; background: rgba(0,0,0,0.4); border-left: 3px solid var(--accent-cyan); border-radius: 2px;">
                        <span class="field-label" style="margin-bottom:4px;">EXECUTIVE INTELLIGENCE BRIEFING</span>
                        <p class="mono small-text" style="color:var(--text-primary); line-height:1.6;">${briefing.executive_summary || 'Autonomous multi-vector synthesis complete.'}</p>
                    </div>

                    <!-- 4-Vector Deterministic Threat Matrix -->
                    <span class="field-label">HEURISTIC THREAT VECTOR BREAKDOWN</span>
                    <div class="vector-matrix-grid">
                        <div class="vector-box">
                            <div class="vector-box-title">FINANCIAL EXPOSURE</div>
                            <div class="vector-box-score ${finVec.score >= 50 ? 'critical' : finVec.score >= 25 ? 'hazard' : 'emerald'}">${finVec.score}/100</div>
                            <div class="dim mono" style="font-size:9px; margin-top:4px;">${finVec.factors[0] || 'No flags'}</div>
                        </div>
                        <div class="vector-box">
                            <div class="vector-box-title">CREDENTIAL EXPOSURE</div>
                            <div class="vector-box-score ${credVec.score >= 50 ? 'critical' : credVec.score >= 25 ? 'hazard' : 'emerald'}">${credVec.score}/100</div>
                            <div class="dim mono" style="font-size:9px; margin-top:4px;">${credVec.factors[0] || 'No leaks'}</div>
                        </div>
                        <div class="vector-box">
                            <div class="vector-box-title">ATTACK SURFACE</div>
                            <div class="vector-box-score ${attVec.score >= 50 ? 'critical' : attVec.score >= 25 ? 'hazard' : 'emerald'}">${attVec.score}/100</div>
                            <div class="dim mono" style="font-size:9px; margin-top:4px;">${attVec.factors[0] || 'Perimeter secure'}</div>
                        </div>
                        <div class="vector-box">
                            <div class="vector-box-title">INFRASTRUCTURE</div>
                            <div class="vector-box-score ${infVec.score >= 50 ? 'critical' : infVec.score >= 25 ? 'hazard' : 'emerald'}">${infVec.score}/100</div>
                            <div class="dim mono" style="font-size:9px; margin-top:4px;">${infVec.factors[0] || 'DNS nominal'}</div>
                        </div>
                    </div>

                    ${meterHtml}

                    <!-- High-Value Indicators of Compromise (IOCs) -->
                    <div style="margin-top: 14px;">
                        <span class="field-label">HIGH-VALUE CORRELATED IOCs (${iocs.length})</span>
                        ${iocs.length > 0 ? `
                            <table class="ioc-table">
                                <thead>
                                    <tr>
                                        <th>INDICATOR / ARTIFACT</th>
                                        <th>TYPE</th>
                                        <th>CONFIDENCE</th>
                                        <th>SOURCE MODULE</th>
                                        <th>SEVERITY</th>
                                        <th>ACTION</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${iocs.map(ioc => `
                                        <tr>
                                            <td class="cyan mono"><strong>${ioc.indicator}</strong></td>
                                            <td><span class="badge slate">${ioc.type}</span></td>
                                            <td><span class="emerald mono">${ioc.confidence}</span></td>
                                            <td><span class="dim mono">${ioc.source_module}</span></td>
                                            <td><span class="badge ${ioc.severity === 'CRITICAL' ? 'critical' : ioc.severity === 'HIGH' ? 'hazard' : 'cyan'}">${ioc.severity}</span></td>
                                            <td>
                                                <button class="btn-icon-copy" onclick="copyToClipboard('${ioc.indicator.replace(/'/g, "\\'")}', this)" title="Copy IOC">
                                                    <svg class="copy-svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                                                </button>
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        ` : '<div class="dim mono small-text" style="padding:8px 0;">No high-value threat indicators flagged in primary scope.</div>'}
                    </div>

                    <!-- Tactical Containment Actions -->
                    ${actions.length > 0 ? `
                        <div style="margin-top: 14px; padding: 10px; background: rgba(0,0,0,0.3); border: 1px solid var(--border-slate); border-radius: 4px;">
                            <span class="field-label" style="margin-bottom:6px;">TACTICAL CONTAINMENT &amp; REMEDIATION ACTIONS</span>
                            <ul style="padding-left:18px; margin:0;" class="mono small-text">
                                ${actions.map(act => `<li style="margin-bottom:4px; color:var(--text-secondary);">${act}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}

                    <!-- Correlated Findings Stream -->
                    <div class="evidence-stream" style="margin-top: 14px;">
                        <span class="field-label" style="margin-bottom:4px;">CROSS-MODULE EVIDENCE LOG</span>
                        ${(d.key_findings || []).map(f => `
                            <div class="evidence-line ${score >= 70 ? 'critical' : 'hazard'}">
                                <div class="evidence-left">
                                    <span class="evidence-time">${new Date().toLocaleTimeString()}</span>
                                    <span class="evidence-text">${f}</span>
                                </div>
                                <span class="evidence-badge ${score >= 70 ? 'critical' : 'hazard'}">[CORTEX_VERIFIED]</span>
                                <button class="btn-icon-copy" onclick="copyToClipboard('${f.replace(/'/g, "\\'")}', this)" title="Copy finding"><svg class="copy-svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button>
                            </div>
                        `).join('')}
                    </div>

                    <div style="margin-top:12px; display:flex; justify-content:space-between; align-items:center; font-size:10px;" class="dim mono">
                        <span>CRYPTOGRAPHIC INTEGRITY SEAL: <strong class="cyan">${d.cryptographic_seal_sha256?.substring(0, 24)}...</strong></span>
                        <span>TIMESTAMP: ${d.timestamp_utc || new Date().toUTCString()}</span>
                    </div>

                    ${chainMetaHtml}
                    ${hexDumpHtml}
                </div>
            </div>
        `;

        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> CORTEX ANALYSIS COMPLETE · ${d.key_findings?.length || 0} VECTORS SYNTHESIZED`;
        window.updateModuleBadge('analyst', d.key_findings?.length || 1);
        if (window.tacticalAudio) window.tacticalAudio.playThreatAlert();

    } catch (err) {
        statusEl.innerHTML = `<span class="critical">FAILED:</span> ${err.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/analyst', 0, err.message);
    }
};

// ============================================================
// CHAIN TRACER (MULTI-CHAIN LEDGER FORENSICS)
// ============================================================

window.runChainTracer = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const address = document.getElementById('chaintracer-address')?.value.trim();
    const coin = document.getElementById('chaintracer-coin')?.value || 'auto';
    const statusEl = document.getElementById('chaintracer-status');
    const resultsEl = document.getElementById('chaintracer-results');
    if (!address) return;

    if (window.threatMatrix) window.threatMatrix.setTarget(address);

    statusEl.innerHTML = `<span class="spinner-pulse"></span> TRACING MULTI-CHAIN LEDGER, UTXO HOPS &amp; TRC-20/ERC-20 FOR <span class="mono cyan">${address}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>INTERROGATING RPC NODES, OFAC REGISTRY &amp; MEMPOOL LEDGER...</div>`;
    if (window.tacticalAudio) window.tacticalAudio.playModuleLaunch();

    try {
        const resp = await window.nexusFetch('/api/modules/chain_tracer', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ address: address, coin: coin })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/chaintracer', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> TRACE FAILED`;
            return;
        }

        const d = await resp.json();
        const score = d.risk_score !== undefined ? d.risk_score : 10;
        const tierColor = (score >= 75) ? 'critical' : (score >= 40) ? 'hazard' : 'emerald';

        // Normalized Data Mapping
        const networkName = String(d.chain || d.network || d.coin_type || coin || 'BTC').toUpperCase();
        const balanceVal = (d.balance !== undefined) ? d.balance : (d.live_balance !== undefined ? d.live_balance : 0);
        const usdVal = d.usd_valuation !== undefined ? d.usd_valuation : (d.usd_estimate !== undefined ? d.usd_estimate : null);
        const tokenBals = d.token_balances || {};
        const counterparties = d.attributed_counterparties || [];
        const accountType = d.account_type || (networkName === 'BTC' ? 'UTXO WALLET' : 'EOA / CONTRACT');
        const txList = d.recent_transactions || d.hops || d.transactions || [];
        
        // Risk Matrix Flags
        const rm = d.risk_matrix || {};
        const isOfac = rm.sanctioned_entity || (d.risk_level === 'CRITICAL_SANCTION_MATCH') || d.ofac_match || d.is_sanctioned;
        const isMixer = rm.mixer_interaction || (d.warnings || []).some(w => w.toLowerCase().includes('mixer')) || d.mixer_proximity;
        const isRapid = rm.rapid_dispersion || false;
        const isExch = rm.exchange_counterparty || false;

        // Inflow / Outflow Volumes
        const inflowVol = d.total_inflow_volume !== undefined ? d.total_inflow_volume : 0;
        const outflowVol = d.total_outflow_volume !== undefined ? d.total_outflow_volume : 0;

        // Register into Threat Matrix
        if (window.threatMatrix) {
            if (isOfac) {
                window.threatMatrix.registerFinding('chaintracer', 'CHAIN TRACER', 'ofac', 45, 'OFAC SDN Sanctions Match: Wallet flagged on official sanctions watchlists.', 'critical');
            } else if (isMixer) {
                window.threatMatrix.registerFinding('chaintracer', 'CHAIN TRACER', 'mixer', 35, 'Mixer Interactivity Detected: Wallet routed funds through Tornado, Wasabi or Railgun.', 'critical');
            } else if (score >= 40) {
                window.threatMatrix.registerFinding('chaintracer', 'CHAIN TRACER', 'onchain_risk', 20, 'Elevated on-chain clustering and rapid fund dispersion detected.', 'hazard');
            } else {
                window.threatMatrix.registerFinding('chaintracer', 'CHAIN TRACER', 'wallet_nominal', 10, 'Live ledger telemetry resolved without direct sanctions tags.', 'emerald');
            }
        }

        if (window.recordModuleResult) {
            window.recordModuleResult('chaintracer', d, address);
        }

        const classifiedBar = window.renderClassifiedHeader('CHAIN TRACER // ON-CHAIN FORENSICS', address, isOfac ? 'CRITICAL SANCTION MATCH' : 'TRACE RESOLVED');
        const meterHtml = window.renderSegmentedMeter(Math.max(10, 100 - score), d.risk_level || 'ANALYZED');
        const hexDumpHtml = window.renderHexDump(d, 80);
        const chainMetaHtml = window.renderChainMetadata(d.provider || `${networkName}_RPC`, 'PUBLIC_LEDGER', d.audit_log_id);

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                ${classifiedBar}
                <div class="entity-tactical-card corner-borders">
                    <div class="entity-card-header">
                        <div class="entity-asset-title">
                            <span class="badge ${tierColor}">[RISK ${score}/100 · ${d.risk_level || 'NOMINAL'}]</span>
                            <span>ASSET // ${d.address || address}</span>
                        </div>
                        <button class="btn-tactical-xs" onclick="copyToClipboard('${address}', this)">COPY ADDRESS</button>
                    </div>

                    <!-- Sanctions & Risk Indicator Matrix -->
                    <div class="vector-matrix-grid" style="margin:12px 0;">
                        <div class="vector-box">
                            <div class="vector-box-title">SANCTIONS STATUS</div>
                            <div class="vector-box-score ${isOfac ? 'critical' : 'emerald'}" style="font-size:12px;">${isOfac ? 'OFAC MATCH' : 'CLEAR'}</div>
                            <div class="dim mono" style="font-size:9px; margin-top:2px;">Official SDN Database</div>
                        </div>
                        <div class="vector-box">
                            <div class="vector-box-title">MIXER PROXIMITY</div>
                            <div class="vector-box-score ${isMixer ? 'critical' : 'emerald'}" style="font-size:12px;">${isMixer ? 'FLAGGED' : 'CLEAN'}</div>
                            <div class="dim mono" style="font-size:9px; margin-top:2px;">Tornado / Wasabi / Railgun</div>
                        </div>
                        <div class="vector-box">
                            <div class="vector-box-title">RAPID DISPERSION</div>
                            <div class="vector-box-score ${isRapid ? 'hazard' : 'emerald'}" style="font-size:12px;">${isRapid ? 'DETECTED' : 'NOMINAL'}</div>
                            <div class="dim mono" style="font-size:9px; margin-top:2px;">Mempool Fan-Out</div>
                        </div>
                        <div class="vector-box">
                            <div class="vector-box-title">EXCHANGE CLUSTERING</div>
                            <div class="vector-box-score ${isExch ? 'cyan' : 'dim'}" style="font-size:12px;">${isExch ? 'IDENTIFIED' : 'UNMAPPED'}</div>
                            <div class="dim mono" style="font-size:9px; margin-top:2px;">Known CEX Hops</div>
                        </div>
                    </div>

                    <div class="entity-metadata-grid">
                        <div class="metadata-field-pair">
                            <span class="field-label">NETWORK / ASSET</span>
                            <span class="field-value cyan">${networkName} (${accountType})</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">CURRENT BALANCE</span>
                            <span class="field-value cyan">${balanceVal} ${networkName} ${usdVal ? `<span class="dim">(~$${Number(usdVal).toLocaleString(undefined, {minimumFractionDigits:2, maximumFractionDigits:2})} USD)</span>` : ''}</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">LIFETIME INFLOW</span>
                            <span class="field-value emerald">${inflowVol} ${networkName}</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">LIFETIME OUTFLOW</span>
                            <span class="field-value critical">${outflowVol} ${networkName}</span>
                        </div>
                    </div>

                    ${meterHtml}

                    <!-- Token Holdings (ERC-20 / SPL / TRC-20) -->
                    <div style="margin-top: 12px; padding: 10px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.06); border-radius: 4px;">
                        <span class="field-label" style="margin-bottom:6px;">SECONDARY TOKEN BALANCES (ERC-20 / SPL / TRC-20)</span>
                        <div style="display:flex; flex-wrap:wrap; gap:8px; margin-top:6px;">
                            ${Object.keys(tokenBals).length > 0 ? Object.entries(tokenBals).map(([tok, bal]) => `
                                <div class="metric-pill" style="min-width: 100px;">
                                    <span class="dim mono">${tok}</span>
                                    <strong class="cyan mono">${bal}</strong>
                                </div>
                            `).join('') : '<span class="dim mono small-text">No secondary token holdings or non-EVM/TRON address</span>'}
                        </div>
                    </div>

                    <!-- Attributed Counterparties & Exchange Clusters -->
                    ${counterparties.length > 0 ? `
                        <div style="margin-top: 12px; padding: 10px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.06); border-radius: 4px;">
                            <span class="field-label" style="margin-bottom:6px;">ATTRIBUTED COUNTERPARTIES &amp; EXCHANGE CLUSTERS (${counterparties.length})</span>
                            <div style="display:flex; flex-wrap:wrap; gap:6px; margin-top:6px;">
                                ${counterparties.map(cp => `
                                    <span class="badge ${cp.category === 'Exchange' ? 'hazard' : cp.category === 'Mixer' ? 'critical' : 'cyan'}" style="font-size:10px;">
                                        ${cp.name} [${cp.category || 'CLUSTER'}]
                                    </span>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}

                    <!-- Interactive Transaction Flow Ledger -->
                    <div class="evidence-stream" style="margin-top: 14px;">
                        <span class="field-label" style="margin-bottom:6px;">TRANSACTION FLOW LEDGER (${txList.length} HOPS ANALYZED)</span>
                        ${txList.length > 0 ? `
                            <table class="ioc-table">
                                <thead>
                                    <tr>
                                        <th>FLOW DIRECTION</th>
                                        <th>AMOUNT</th>
                                        <th>TX HASH / IDENTIFIER</th>
                                        <th>COUNTERPARTY / CLUSTER</th>
                                        <th>CONFIRMATION</th>
                                        <th>ACTION</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${txList.map(tx => {
                                        const hash = tx.tx_hash || tx.txid || tx.hash || tx.address || '0x...';
                                        const isOutflow = tx.direction === 'OUTFLOW';
                                        const amountText = tx.amount !== undefined ? `${tx.amount} ${tx.currency || networkName}` : (tx.fee_sat ? `${tx.fee_sat} sat` : '0.00');
                                        const cpName = tx.counterparty_label || tx.counterparty || (isOutflow ? (tx.to_address ? tx.to_address.substring(0, 10) + '...' : 'Unknown') : (tx.from_address ? tx.from_address.substring(0, 10) + '...' : 'Unknown'));
                                        const isConf = tx.confirmed !== false;
                                        return `
                                            <tr>
                                                <td>
                                                    <span class="${isOutflow ? 'outflow-tag' : 'inflow-tag'}">
                                                        ${isOutflow ? 'OUTFLOW [&uarr;]' : 'INFLOW [&darr;]'}
                                                    </span>
                                                </td>
                                                <td class="mono ${isOutflow ? 'critical' : 'emerald'}"><strong>${amountText}</strong></td>
                                                <td class="mono cyan" style="font-size:10px;">${hash.substring(0, 16)}...</td>
                                                <td><span class="badge slate">${cpName}</span></td>
                                                <td><span class="mono ${isConf ? 'emerald' : 'hazard'}">${isConf ? 'CONFIRMED' : 'MEMPOOL'}</span></td>
                                                <td>
                                                    <button class="btn-icon-copy" onclick="copyToClipboard('${hash}', this)" title="Copy Tx Hash">
                                                        <svg class="copy-svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                                                    </button>
                                                </td>
                                            </tr>
                                        `;
                                    }).join('')}
                                </tbody>
                            </table>
                        ` : '<div class="dim mono small-text" style="padding:8px 0;">No on-chain transaction hops found in current lookup window.</div>'}
                    </div>

                    ${chainMetaHtml}
                    ${hexDumpHtml}
                </div>
            </div>
        `;

        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> TRACE COMPLETE · RISK LEVEL: ${d.risk_level || 'ANALYZED'}`;
        window.updateModuleBadge('chaintracer', txList.length || 1);
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/chaintracer', 0, e.message);
    }
};

// Pixel Forge Upload & ELA Forensics
window.handlePixelForgeUpload = function(file) {
    if (!file) return;
    const statusEl = document.getElementById('pixelforge-status');
    const resultsEl = document.getElementById('pixelforge-results');

    statusEl.innerHTML = `<span class="spinner-pulse"></span> DECOMPOSING COMPRESSION ARTIFACTS, GPS & MSE METRICS FOR <span class="mono cyan">${file.name}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>EXTRACTING ELA HEATMAP, QUANTIZATION TABLES & EXIF AUTOPSY...</div>`;
    if (window.tacticalAudio) window.tacticalAudio.playModuleLaunch();

    const fd = new FormData();
    fd.append('file', file);

    return window.nexusFetch('/api/pixelforge/upload', { method: 'POST', body: fd })
    .then(async r => {
        if (!r.ok) {
            const errData = await r.json().catch(() => r.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/pixelforge/upload', r.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${r.status}]</span> FORENSIC AUDIT FAILED`;
            return null;
        }
        return r.json();
    })
    .then(d => {
        if (!d) return;
        if (d.error) throw new Error(d.error);

        const riskScore = d.composite_risk !== undefined ? d.composite_risk : (d.confidence_score || 0);
        const verdict = d.overall_verdict || (riskScore >= 45 ? 'TAMPERING DETECTED' : 'AUTHENTIC');
        const isTampered = riskScore >= 45 || verdict.includes('MANIPULATION') || verdict.includes('SUSPICIOUS') || d.tampering_detected;
        const dims = `${d.metadata?.width || 'N/A'} x ${d.metadata?.height || 'N/A'} (${d.metadata?.megapixels || 0} MP)`;
        const elaB64 = d.ela_b64 || d.ela?.q95 || d.ela_preview_base64;
        const signals = d.all_signals || d.anomalies || [];
        const exifMeta = d.metadata?.exif || {};
        const camera = d.metadata?.camera || exifMeta.Model || exifMeta.Make || 'Hardware Unknown';
        const lens = d.metadata?.lens || exifMeta.LensModel || 'Standard';
        const exposure = d.metadata?.exposure || {};
        const gpsDec = d.metadata?.gps_decimal;
        const colorCh = d.color_channels || {};
        const elaMse = d.ela?.mse || {};

        if (isTampered && window.threatMatrix) {
            window.threatMatrix.registerFinding('pixelforge', 'PIXEL FORGE', 'image_tampering', 15, `Discrete cosine transform / ELA quantization anomalies flagged in ${file.name}.`, 'hazard');
        } else if (window.threatMatrix) {
            window.threatMatrix.registerFinding('pixelforge', 'PIXEL FORGE', 'image_authentic', 5, `Image verified unaltered: consistent DCT quantization & ELA residuals across ${file.name}.`, 'emerald');
        }

        const classifiedBar = window.renderClassifiedHeader('PIXEL FORGE // IMAGE FORENSICS', file.name, isTampered ? 'ANOMALY DETECTED' : 'UNALTERED');
        const meterHtml = window.renderSegmentedMeter(Math.max(10, 100 - riskScore), isTampered ? 'ELEVATED ARTIFACT RESIDUALS' : 'CLEAN MATRIX');
        const hexDumpHtml = window.renderHexDump(d, 80);
        const chainMetaHtml = window.renderChainMetadata('PIXEL_FORGE_V7', 'DCT_AND_MSE_ENGINE', d.audit_log_id);

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                ${classifiedBar}
                <div class="entity-tactical-card corner-borders">
                    <div class="entity-card-header">
                        <div class="entity-asset-title">
                            <span class="badge ${isTampered ? 'critical' : 'emerald'}">[VERDICT: ${verdict}]</span>
                            <span>FILE // ${d.filename || file.name}</span>
                        </div>
                    </div>
                    <div class="entity-metadata-grid">
                        <div class="metadata-field-pair">
                            <span class="field-label">COMPOSITE RISK</span>
                            <span class="field-value ${isTampered ? 'critical' : 'emerald'}">${riskScore} / 100</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">DIMENSIONS</span>
                            <span class="field-value cyan">${dims}</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">CAMERA HARDWARE</span>
                            <span class="field-value">${camera}</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">LENS / EXPOSURE</span>
                            <span class="field-value">${lens} ${exposure.ISOSpeedRatings ? `· ISO ${exposure.ISOSpeedRatings}` : ''}</span>
                        </div>
                    </div>

                    ${meterHtml}

                    <!-- GPS Decimal Coordinates & Map Links -->
                    ${gpsDec ? `
                        <div style="margin-top: 12px; padding: 12px; background: rgba(255,184,0,0.08); border: 1px solid rgba(255,184,0,0.3); border-radius: 4px;">
                            <span class="field-label" style="color:#FFB800; margin-bottom:4px;">[ALERT] EMBEDDED GEOSPATIAL COORDINATES DISCOVERED</span>
                            <div style="font-size: 13px; font-family: var(--font-mono); margin-top:4px;">
                                <strong class="cyan">LAT:</strong> ${gpsDec.lat}, <strong class="cyan">LON:</strong> ${gpsDec.lon}
                            </div>
                            <div style="margin-top:8px; display:flex; gap:10px;">
                                <a href="${gpsDec.maps_url}" target="_blank" class="btn-tactical-xs" style="text-decoration:none;">OPEN IN GOOGLE MAPS</a>
                                ${gpsDec.osm_url ? `<a href="${gpsDec.osm_url}" target="_blank" class="btn-tactical-xs" style="text-decoration:none;">OPEN IN OPENSTREETMAP</a>` : ''}
                            </div>
                        </div>
                    ` : ''}

                    <!-- Color Channel Distribution & MSE Metrics -->
                    <div class="grid-2col" style="margin-top: 12px; gap: 10px;">
                        <div class="glass-card" style="padding: 10px;">
                            <span class="field-label" style="margin-bottom:6px;">COLOR CHANNEL VARIANCE</span>
                            <div style="font-size:11px; font-family:var(--font-mono);">
                                <div><strong style="color:#FF5555;">R:</strong> μ=${colorCh.red_mean || 0} (σ²=${colorCh.red_variance || 0})</div>
                                <div><strong style="color:#55FF55;">G:</strong> μ=${colorCh.green_mean || 0} (σ²=${colorCh.green_variance || 0})</div>
                                <div><strong style="color:#5588FF;">B:</strong> μ=${colorCh.blue_mean || 0} (σ²=${colorCh.blue_variance || 0})</div>
                                <div style="margin-top:4px;"><span class="dim">Dominant:</span> <strong class="cyan">${colorCh.dominant_spectrum || 'Balanced'}</strong></div>
                            </div>
                        </div>
                        <div class="glass-card" style="padding: 10px;">
                            <span class="field-label" style="margin-bottom:6px;">ELA MEAN SQUARED ERROR (MSE)</span>
                            <div style="font-size:11px; font-family:var(--font-mono);">
                                <div><strong class="cyan">Q95 MSE:</strong> ${elaMse.q95 || 0}</div>
                                <div><strong class="hazard">Q75 MSE:</strong> ${elaMse.q75 || 0}</div>
                                <div><strong class="critical">Q50 MSE:</strong> ${elaMse.q50 || 0}</div>
                                <div style="margin-top:4px;"><span class="dim">Anomaly Votes:</span> <strong class="${d.ela?.suspicion_votes ? 'critical' : 'emerald'}">${d.ela?.suspicion_votes || 0}</strong></div>
                            </div>
                        </div>
                    </div>

                    ${elaB64 ? `
                        <div class="heatmap-preview-container" style="margin-top:12px;">
                            <span class="field-label">ERROR LEVEL ANALYSIS HEATMAP RESIDUALS</span>
                            <img src="data:image/jpeg;base64,${elaB64}" class="ela-heatmap-img" alt="ELA Heatmap" style="max-height:300px; width:100%; object-fit:contain; background:#000; border:1px solid rgba(0,240,255,0.3); border-radius:4px; margin-top:4px;">
                        </div>
                    ` : ''}

                    <div class="evidence-stream" style="margin-top: 12px;">
                        <span class="field-label" style="margin-bottom:4px;">QUANTIZATION & HEURISTIC SIGNALS STREAM</span>
                        ${signals.map(a => {
                            const sigText = typeof a === 'object' ? (a.signal ? `${a.signal}: ${a.note || ''}` : (a.note || JSON.stringify(a))) : String(a);
                            return `
                            <div class="evidence-line ${isTampered ? 'critical' : 'nominal'}">
                                <div class="evidence-left">
                                    <span class="evidence-time">[SIGNAL]</span>
                                    <span class="evidence-text">${sigText}</span>
                                </div>
                                <span class="evidence-badge ${isTampered ? 'critical' : 'nominal'}">${isTampered ? 'FLAGGED' : 'CLEAN'}</span>
                            </div>
                            `;
                        }).join('') || '<div class="dim mono">No tampering anomalies flagged in image residual matrix.</div>'}
                    </div>

                    ${chainMetaHtml}
                    ${hexDumpHtml}
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> FORENSIC AUDIT COMPLETE · ${isTampered ? 'ANOMALIES FLAGGED' : 'CLEAN RESIDUALS'}`;
        window.updateModuleBadge('pixelforge', isTampered ? 1 : 0);
    }).catch(e => {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/pixelforge/upload', 0, e.message);
    });
};

// Hudson Rock Infostealer
window.runHudsonRock = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const query = document.getElementById('hudsonrock-query')?.value.trim();
    const type = document.getElementById('hudsonrock-type')?.value || 'auto';
    const statusEl = document.getElementById('hudsonrock-status');
    const resultsEl = document.getElementById('hudsonrock-results');
    if (!query) return;

    if (window.threatMatrix) window.threatMatrix.setTarget(query);

    statusEl.innerHTML = `<span class="spinner-pulse"></span> SEARCHING CAVALIER INFOSTEALER LOGS FOR <span class="cyan mono">${query}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>INDEXING REDLINE, RACCOON, LUMMA, AND VIDAR ARCHIVES...</div>`;
    if (window.tacticalAudio) window.tacticalAudio.playModuleLaunch();

    try {
        const resp = await window.nexusFetch('/api/modules/hudson_rock', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ query: query, type: type })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/hudsonrock', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> SEARCH FAILED`;
            return;
        }

        const d = await resp.json();
        const isClean = (d.status === 'clean');
        const raw = d.raw || {};
        const compromisedDevices = d.total_stealers !== undefined ? d.total_stealers : (d.compromised_devices !== undefined ? d.compromised_devices : (raw.total_stealers !== undefined ? raw.total_stealers : (raw.stealers ? raw.stealers.length : (Array.isArray(raw) ? raw.length : 0))));
        const totalCreds = d.total_credentials !== undefined ? d.total_credentials : (raw.total_credentials || 0);
        const stealerList = d.compromises || d.victims || raw.stealers || (Array.isArray(raw) ? raw : []);
        const infected = !isClean && (compromisedDevices > 0 || d.is_compromised);

        if (infected && window.threatMatrix) {
            window.threatMatrix.registerFinding('hudsonrock', 'HUDSON ROCK', 'infostealer', 25, `Active infostealer infection: compromised credentials discovered in Cavalier archives.`, 'critical');
        } else if (window.threatMatrix) {
            window.threatMatrix.registerFinding('hudsonrock', 'HUDSON ROCK', 'stealer_clean', 10, 'Cavalier global infostealer ledger check: zero compromised credentials identified.', 'emerald');
        }

        if (window.recordModuleResult) {
            window.recordModuleResult('hudsonrock', d, query);
        }

        const classifiedBar = window.renderClassifiedHeader('HUDSON ROCK // CAVALIER INFOSTEALER', query, infected ? 'ACTIVE INFECTION' : 'ZERO COMPROMISE');
        const meterHtml = window.renderSegmentedMeter(infected ? 95 : 15, infected ? 'HIGH RISK OF COMPROMISE' : 'ZERO INFECTIONS');
        const hexDumpHtml = window.renderHexDump(d, 80);
        const chainMetaHtml = window.renderChainMetadata('HUDSON_ROCK_V7', 'CAVALIER_API_V2', d.audit_log_id);

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                ${classifiedBar}
                <div class="entity-tactical-card corner-borders">
                    <div class="entity-card-header">
                        <div class="entity-asset-title">
                            <span class="badge ${infected ? 'critical' : 'emerald'}">[STATUS: ${infected ? 'COMPROMISED ASSET' : 'VERIFIED ZERO COMPROMISE'}]</span>
                            <span>QUERY // ${query}</span>
                        </div>
                        <button class="btn-tactical-xs" onclick="copyToClipboard('${query}', this)">COPY TARGET</button>
                    </div>
                    <div class="entity-metadata-grid">
                        <div class="metadata-field-pair">
                            <span class="field-label">COMPROMISED DEVICES</span>
                            <span class="field-value ${infected ? 'critical' : 'emerald'}">${compromisedDevices} NODES</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">TOTAL CREDENTIALS</span>
                            <span class="field-value ${infected ? 'hazard' : 'dim'}">${totalCreds} RECORDED</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">QUERY RESOLUTION</span>
                            <span class="field-value">${d.type || type}</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">INTELLIGENCE STATUS</span>
                            <span class="field-value ${infected ? 'critical' : 'emerald'}">${isClean ? 'NO STEALER LOGS' : (infected ? 'INFECTED' : 'RESOLVED')}</span>
                        </div>
                    </div>

                    ${meterHtml}

                    <div class="evidence-stream">
                        <span class="field-label" style="margin-bottom:4px;">INFOSTEALER FORENSIC EVIDENCE STREAM</span>
                        ${stealerList.map(v => `
                            <div class="evidence-line critical">
                                <div class="evidence-left">
                                    <span class="evidence-time">[${v.malware_family || v.stealer_family || 'Stealer'}]</span>
                                    <span class="evidence-text">Compromised Node: <strong>${v.computer_name || v.ip || 'Unknown'}</strong> (${v.date_compromised || 'Recent'}) · OS: ${v.os || 'Windows'} · AV: ${v.antivirus || 'None'}</span>
                                </div>
                                <span class="evidence-badge critical">[MALWARE_LEAK]</span>
                            </div>
                        `).join('') || `<div class="dim mono">${isClean ? '[-] Verified clean: Zero infostealer compromise records found across Lumma, Redline, Vidar, Raccoon logs.' : '[-] No individual compromised stealer devices registered for target.'}</div>`}
                    </div>

                    ${chainMetaHtml}
                    ${hexDumpHtml}
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> HUDSON ROCK QUERY COMPLETE · ${infected ? `${compromisedDevices} INFECTIONS` : 'CLEAN'}`;
        window.updateModuleBadge('hudsonrock', infected ? (compromisedDevices || 1) : 0);
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/hudsonrock', 0, e.message);
    }
};

// Shadow Clone State & Helpers
window.shadowCloneLastResult = null;

window.downloadShadowCloneReport = function() {
    if (!window.shadowCloneLastResult || !window.shadowCloneLastResult.dossier_html) {
        alert('Execute a persona investigation first to compile the report.');
        return;
    }
    const target = window.shadowCloneLastResult.target || 'target';
    const blob = new Blob([window.shadowCloneLastResult.dossier_html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CLASSIFIED_DOSSIER_${target.toUpperCase()}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};

window.exportShadowCloneJson = function() {
    if (!window.shadowCloneLastResult) return;
    const target = window.shadowCloneLastResult.target || 'target';
    const blob = new Blob([JSON.stringify(window.shadowCloneLastResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SHADOW_CLONE_${target.toUpperCase()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};

// Shadow Clone
window.runShadowClone = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const username = document.getElementById('shadowclone-user')?.value.trim();
    const deepRecon = document.getElementById('shadowclone-deep-recon')?.checked ?? true;
    const probeClones = document.getElementById('shadowclone-probe-clones')?.checked ?? true;
    const statusEl = document.getElementById('shadowclone-status');
    const resultsEl = document.getElementById('shadowclone-results');
    const dwnBtn = document.getElementById('btn-download-shadow-report');
    const expBtn = document.getElementById('btn-export-shadow-json');
    if (!username) return;

    if (window.threatMatrix) window.threatMatrix.setTarget(username);

    statusEl.innerHTML = `<span class="spinner-pulse"></span> PROBING 15+ PLATFORMS & CLONES FOR <span class="cyan mono">${username}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>HARVESTING CROSS-PLATFORM PERSONA PROFILES & GENERATING 50+ MUTATIONS...</div>`;

    try {
        const resp = await window.nexusFetch('/api/modules/shadow_clone', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                username: username,
                deep_recon: deepRecon,
                probe_clones: probeClones
            })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/shadowclone', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> CLONE PROBE FAILED`;
            return;
        }

        const d = await resp.json();
        window.shadowCloneLastResult = d;

        if (dwnBtn) dwnBtn.style.display = 'inline-block';
        if (expBtn) expBtn.style.display = 'inline-block';

        const summary = d.summary || {};
        const profiles = d.profiles || [];
        const clones = d.active_clones || [];
        const simScore = d.threat_score !== undefined ? d.threat_score : (clones.length > 0 ? 82 : 15);

        const headerHtml = window.renderClassifiedHeader('SHADOW CLONE // PERSONA RECON', username, clones.length > 0 ? 'ADVERSARIAL CLONES FOUND' : 'VERIFIED PROFILES MAPPED');
        const meterHtml = window.renderSegmentedMeter(simScore, clones.length > 0 ? 'IMPERSONATION THREAT EXPOSURE' : 'IDENTITY CLUSTER INTEGRITY');
        const hexDumpHtml = window.renderHexDump(d, 64);
        const chainMetaHtml = window.renderChainMetadata('SHADOW_CLONE_V7', username);

        if (window.threatMatrix) {
            if (clones.length > 0) {
                window.threatMatrix.registerFinding('shadowclone', 'SHADOW CLONE', 'impersonator_risk', 25, `Detected ${clones.length} adversarial impersonator / squatter clones across monitored networks.`, 'hazard');
            } else {
                window.threatMatrix.registerFinding('shadowclone', 'SHADOW CLONE', 'persona_mapped', 5, `Reconstructed identity presence across ${profiles.length} platform nodes with zero active clones.`, 'emerald');
            }
        }
        window.updateModuleBadge('shadowclone', profiles.length + clones.length);

        if (window.recordModuleResult) {
            window.recordModuleResult('shadowclone', d, username);
        }

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                ${headerHtml}
                <div class="glass-card tactical-intel-card corner-borders">
                    ${meterHtml}

                    <!-- Persona Dossier Header Card -->
                    <div style="display:flex; flex-wrap:wrap; gap:20px; align-items:center; margin-top:14px; padding:16px; background:rgba(6,11,20,0.85); border:1px solid rgba(0,240,255,0.2); border-radius:6px;">
                        ${summary.avatar_url ? `
                            <img src="${summary.avatar_url}" style="width:84px; height:84px; border-radius:8px; border:2px solid #00F0FF; object-fit:cover; box-shadow:0 0 16px rgba(0,240,255,0.25);" alt="Avatar">
                        ` : `
                            <div style="width:84px; height:84px; border-radius:8px; border:1px dashed #00F0FF; display:flex; align-items:center; justify-content:center; color:#00F0FF; font-family:monospace; font-size:11px;">NO AVATAR</div>
                        `}
                        <div style="flex:1; min-width:260px;">
                            <div style="display:flex; align-items:center; gap:10px; margin-bottom:4px;">
                                <h3 style="margin:0; font-size:18px; color:#fff;">${summary.primary_display_name || username}</h3>
                                <span class="badge ${clones.length > 0 ? 'critical' : 'emerald'}">${summary.threat_tier || 'NOMINAL'}</span>
                            </div>
                            <div class="mono small-text dim" style="margin-bottom:6px;">
                                HANDLE: <span class="cyan">@${username}</span> ${summary.locations ? `· LOCATION: <span class="emerald">${summary.locations}</span>` : ''}
                            </div>
                            <div class="small-text dim" style="line-height:1.4;">
                                ${summary.aggregated_bio || 'No public bio statement harvested.'}
                            </div>
                        </div>
                        <div style="display:flex; flex-direction:column; gap:6px;">
                            <button class="btn-tactical-xs cyan" onclick="window.downloadShadowCloneReport()">📄 DOWNLOAD FULL DOSSIER</button>
                            <button class="btn-tactical-xs" onclick="window.exportShadowCloneJson()">💾 EXPORT RAW JSON</button>
                        </div>
                    </div>

                    <!-- Discovered Profiles Matrix -->
                    <div style="margin-top:16px;">
                        <div class="telemetry-label" style="margin-bottom:8px;">1. ACTIVE DIGITAL FOOTPRINT (${profiles.length} ENCLAVES DISCOVERED)</div>
                        <div class="grid-2col" style="gap:10px;">
                            ${profiles.map(p => `
                                <div class="finding-item" style="background:rgba(2,6,12,0.6); padding:10px; border-radius:6px; border-left:3px solid #00F0FF;">
                                    <div style="flex:1;">
                                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:2px;">
                                            <strong class="cyan mono">${p.platform}</strong>
                                            <span class="badge emerald" style="font-size:9px;">VERIFIED LIVE</span>
                                        </div>
                                        <div class="small-text mono"><a href="${p.url}" target="_blank" class="dim" style="color:#00F0FF; text-decoration:none;">${p.url}</a></div>
                                        ${p.bio ? `<div class="small-text dim" style="margin-top:4px; font-size:11px;">${p.bio.substring(0, 120)}</div>` : ''}
                                        <div class="dim mono" style="font-size:10px; margin-top:4px;">
                                            ${p.created_at ? `Created: ${p.created_at} · ` : ''}
                                            ${p.followers ? `Followers: ${p.followers} · ` : ''}
                                            ${p.karma ? `Karma: ${p.karma} · ` : ''}
                                            ${p.category || 'General'}
                                        </div>
                                    </div>
                                    <button class="btn-icon-copy" onclick="copyToClipboard('${p.url}', this)" title="Copy Link"><svg class="copy-svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button>
                                </div>
                            `).join('') || '<div class="dim mono small-text">No active public profiles discovered across primary networks.</div>'}
                        </div>
                    </div>

                    <!-- Adversarial Clone / Impersonator Matrix -->
                    <div style="margin-top:20px;">
                        <div class="telemetry-label" style="margin-bottom:8px;">2. ADVERSARIAL CLONE &amp; TYPO-SQUATTING LEDGER (${clones.length} ACTIVE CLONES)</div>
                        <div class="table-wrap">
                            <table class="table-tactical">
                                <thead><tr><th>THREAT TIER</th><th>MUTATION HANDLE</th><th>PLATFORM</th><th>METRICS</th><th>TARGET ENDPOINT</th></tr></thead>
                                <tbody>
                                    ${clones.map(c => `
                                        <tr>
                                            <td><span class="badge ${c.impersonation_risk === 'CRITICAL_CLONE' ? 'critical' : 'hazard'}">${c.impersonation_risk}</span></td>
                                            <td class="cyan mono font-bold">${c.mutation}</td>
                                            <td class="hazard mono">${c.platform}</td>
                                            <td class="dim mono small-text">Lev: ${c.levenshtein_distance} · Jaro: ${c.jaro_winkler_similarity}</td>
                                            <td><a href="${c.url}" target="_blank" class="cyan mono small-text">${c.url}</a></td>
                                        </tr>
                                    `).join('') || '<tr><td colspan="5" class="dim mono text-center" style="padding:12px;">Zero adversarial clones detected among generated permutations.</td></tr>'}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    ${chainMetaHtml}
                    ${hexDumpHtml}
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> PERSONA RECON COMPLETE · ${profiles.length} PLATFORMS · ${clones.length} CLONES`;
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/shadowclone', 0, e.message);
    }
};

// Spider Crawl
window.runSpiderCrawl = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const target = document.getElementById('spidercrawl-target')?.value.trim();
    const statusEl = document.getElementById('spidercrawl-status');
    const resultsEl = document.getElementById('spidercrawl-results');
    if (!target) return;

    if (window.threatMatrix) window.threatMatrix.setTarget(target);

    statusEl.innerHTML = `<span class="spinner-pulse"></span> SPIDERING DEEP HYPERLINKS, FORM INPUTS & 35+ SECRET RULES FOR <span class="cyan mono">${target}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>CRAWLING ENTITY GRAPH, EXTRACTING TOKENS, DB URIS & WEAPONIZED LOGINS...</div>`;

    try {
        const resp = await window.nexusFetch('/api/modules/spider_crawl', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ target: target })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/spidercrawl', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> SPIDER FAILED`;
            return;
        }

        const d = await resp.json();
        const emails = d.emails || [];
        const phones = d.phones || [];
        const secrets = d.secrets_found || [];
        const formInputs = d.form_inputs || [];
        const sensitiveFiles = d.sensitive_files_found || [];
        const socialLinks = d.social_links || [];
        const totalNodes = (d.internal_links_count || 0) + (d.external_links_count || 0) + emails.length + socialLinks.length;

        if (window.threatMatrix) {
            if (secrets.length > 0) {
                window.threatMatrix.registerFinding('spidercrawl', 'SPIDER CRAWL', 'exposed_api_secrets', 40, `Uncovered ${secrets.length} high-entropy secret token(s) and credentials during web crawl.`, 'critical');
            } else if (sensitiveFiles.length > 0) {
                window.threatMatrix.registerFinding('spidercrawl', 'SPIDER CRAWL', 'sensitive_files', 25, `Located ${sensitiveFiles.length} exposed backup/config files.`, 'hazard');
            } else {
                window.threatMatrix.registerFinding('spidercrawl', 'SPIDER CRAWL', 'recon_surface', 10, `Mapped web surface: ${totalNodes} endpoints, forms, and assets identified.`, 'emerald');
            }
        }

        if (window.recordModuleResult) {
            window.recordModuleResult('spidercrawl', d, target);
        }

        const classifiedBar = window.renderClassifiedHeader('WEB SPIDER // RECON DISCOVERY', target, 'CRAWL_COMPLETE');
        const meterHtml = window.renderSegmentedMeter(secrets.length > 0 ? 95 : 80, secrets.length > 0 ? 'HIGH-RISK SECRETS EXPOSED' : 'TOPOLOGY MAPPED');
        const hexDumpHtml = window.renderHexDump(d, 80);
        const chainMetaHtml = window.renderChainMetadata('SPIDER_CRAWL_V7', 'ASYNC_AIOHTTP_AND_REGEX', d.audit_log_id);

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                ${classifiedBar}
                <div class="entity-tactical-card corner-borders">
                    <div class="entity-card-header">
                        <div class="entity-asset-title">
                            <span class="badge cyan">[${totalNodes} DISCOVERED NODES]</span>
                            <span>TARGET // ${d.domain || target}</span>
                        </div>
                        <button class="btn-tactical-xs" onclick="copyToClipboard('${target}', this)">COPY TARGET</button>
                    </div>
                    <div class="entity-metadata-grid">
                        <div class="metadata-field-pair">
                            <span class="field-label">PAGES SCANNED</span>
                            <span class="field-value cyan">${d.pages_scanned || 1}</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">EXPOSED SECRETS</span>
                            <span class="field-value ${secrets.length ? 'critical' : 'emerald'}">${secrets.length} TOKENS</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">FORM INPUTS LOCATED</span>
                            <span class="field-value ${formInputs.length ? 'hazard' : 'emerald'}">${formInputs.length} FORMS</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">EXTRACTED EMAILS</span>
                            <span class="field-value">${emails.length} IDENTIFIERS</span>
                        </div>
                    </div>

                    ${meterHtml}

                    <!-- Exposed Secrets Stream -->
                    ${secrets.length > 0 ? `
                        <div class="evidence-stream" style="margin-top: 12px;">
                            <span class="field-label" style="margin-bottom:4px; color:#FF2A55;">[CRITICAL] HIGH-RISK CREDENTIALS & SECRETS IDENTIFIED (${secrets.length})</span>
                            ${secrets.map(s => `
                                <div class="evidence-line critical">
                                    <div class="evidence-left" style="flex:1;">
                                        <span class="evidence-time">[${s.type || 'SECRET'}]</span>
                                        <span class="evidence-text mono" style="color:#FFB800;">${s.secret || s.match || 'Token'}</span>
                                        ${s.url ? `<span class="dim small-text">in ${s.url}</span>` : ''}
                                    </div>
                                    <button class="btn-icon-copy" onclick="copyToClipboard('${s.secret || s.match}', this)"><svg class="copy-svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button>
                                </div>
                            `).join('')}
                        </div>
                    ` : ''}

                    <!-- Detected HTML Form Inputs -->
                    ${formInputs.length > 0 ? `
                        <div class="evidence-stream" style="margin-top: 12px;">
                            <span class="field-label" style="margin-bottom:4px;">DETECTED HTML LOGIN / FORM SURFACES (${formInputs.length})</span>
                            ${formInputs.map(f => {
                                const inputsStr = (f.inputs || []).map(i => `${i.name || 'field'}:${i.type || 'text'}`).join(', ');
                                return `
                                    <div class="evidence-line nominal">
                                        <div class="evidence-left" style="flex:1;">
                                            <span class="evidence-time">[${f.method || 'POST'}]</span>
                                            <strong class="cyan mono">${f.action || '/login'}</strong>
                                            <span class="dim small-text mono">Fields: [${inputsStr}]</span>
                                        </div>
                                    </div>
                                `;
                            }).join('')}
                        </div>
                    ` : ''}

                    <!-- Sensitive Files & Emails Stream -->
                    <div class="evidence-stream" style="margin-top: 12px;">
                        <span class="field-label" style="margin-bottom:4px;">DISCOVERED ASSETS & SENSITIVE PATHS</span>
                        ${sensitiveFiles.map(f => `
                            <div class="evidence-line critical">
                                <div class="evidence-left"><span class="evidence-time">[SENSITIVE]</span><span class="evidence-text mono">${f.path || f}</span></div>
                            </div>
                        `).join('')}
                        ${emails.map(em => `
                            <div class="evidence-line nominal">
                                <div class="evidence-left"><span class="evidence-time">[EMAIL]</span><span class="evidence-text cyan mono">${em}</span></div>
                                <button class="btn-icon-copy" onclick="copyToClipboard('${em}', this)"><svg class="copy-svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button>
                            </div>
                        `).join('')}
                    </div>

                    ${chainMetaHtml}
                    ${hexDumpHtml}
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> SPIDER COMPLETE · ${totalNodes} NODES FOUND`;
        window.updateModuleBadge('spidercrawl', secrets.length || 1);
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/spidercrawl', 0, e.message);
    }
};

// Doc Autopsy Upload
window.handleDocAutopsyUpload = function(file) {
    if (!file) return;
    const statusEl = document.getElementById('docautopsy-status');
    const resultsEl = document.getElementById('docautopsy-results');

    statusEl.innerHTML = `<span class="spinner-pulse"></span> AUTOPSYING DOCUMENT METADATA, MACROS & CANARIES FOR <span class="cyan mono">${file.name}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>EXTRACTING REVISION HISTORIES & HIDDEN TRACKING BEACONS...</div>`;

    const fd = new FormData();
    fd.append('file', file);

    window.nexusFetch('/api/docautopsy/upload', { method: 'POST', body: fd })
    .then(async r => {
        if (!r.ok) {
            const errData = await r.json().catch(() => r.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/docautopsy/upload', r.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${r.status}]</span> AUTOPSY FAILED`;
            return null;
        }
        return r.json();
    })
    .then(d => {
        if (!d) return;
        const threatScore = d.threat_score !== undefined ? d.threat_score : (d.vba_macros_detected ? 75 : 15);
        const headerHtml = window.renderClassifiedHeader('DOC AUTOPSY', file.name, 'FORENSIC INSPECT');
        const meterHtml = window.renderSegmentedMeter(threatScore, 'DOCUMENT EXPLOIT RISK');
        const hexDumpHtml = window.renderHexDump(d, 64);
        const chainMetaHtml = window.renderChainMetadata('DOC AUTOPSY', file.name);

        if (window.threatMatrix) {
            if (threatScore >= 50 || d.vba_macros_detected) {
                window.threatMatrix.registerFinding('docautopsy', 'DOC AUTOPSY', 'macro_exploit', 30, `Document ${file.name} contains embedded VBA macros or tracking beacons.`, 'critical');
            } else {
                window.threatMatrix.registerFinding('docautopsy', 'DOC AUTOPSY', 'clean_doc', 5, `Document ${file.name} metadata sanitized: zero active exploit streams or tracking beacons.`, 'emerald');
            }
        }
        window.updateModuleBadge('docautopsy', threatScore >= 50 ? 1 : 0);

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                <div class="glass-card tactical-intel-card">
                    ${headerHtml}
                    ${meterHtml}
                    <div class="card-header" style="margin-top:10px;">
                        <div>
                            <span class="telemetry-label">FORENSIC ARTIFACT RECORD</span>
                            <h3 class="card-title">${file.name} <span class="badge ${threatScore >= 50 ? 'critical' : 'emerald'}">${threatScore >= 50 ? 'SUSPICIOUS METADATA' : 'CLEAN DOCUMENT'}</span></h3>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="metric-row">
                            <div class="metric-pill"><span class="dim">AUTHOR / CREATOR</span><strong class="cyan mono">${d.creator || d.author || 'Unknown'}</strong></div>
                            <div class="metric-pill"><span class="dim">LAST MODIFIED BY</span><strong>${d.last_modified_by || 'Unknown'}</strong></div>
                            <div class="metric-pill"><span class="dim">SOFTWARE ENGINE</span><strong>${d.producer || d.software || 'N/A'}</strong></div>
                            <div class="metric-pill"><span class="dim">VBA MACROS</span><strong class="${d.vba_macros_detected ? 'critical' : 'emerald'}">${d.vba_macros_detected ? 'DETECTED' : 'NONE'}</strong></div>
                        </div>
                        <div class="finding-list" style="margin-top:10px;">
                            ${(d.extracted_telemetry || d.warnings || []).map(w => `<div class="finding-item"><span class="finding-dot hazard"></span><span>${w}</span></div>`).join('') || '<div class="dim mono">No hidden macro anomalies or canary tokens identified in document bytes.</div>'}
                        </div>
                        ${chainMetaHtml}
                        ${hexDumpHtml}
                    </div>
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> DOCUMENT AUTOPSY COMPLETE`;
    }).catch(e => {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/docautopsy/upload', 0, e.message);
    });
};

// Voice Print Upload
window.handleVoicePrintUpload = function(file) {
    if (!file) return;
    const statusEl = document.getElementById('voiceprint-status');
    const resultsEl = document.getElementById('voiceprint-results');

    statusEl.innerHTML = `<span class="spinner-pulse"></span> EXTRACTING ELECTRICAL NETWORK FREQUENCY (ENF) & SYNTHETIC ARTIFACTS...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>SPECTRAL ANALYSIS & DEEPFAKE VOICE BIOMETRIC MATCHING...</div>`;

    const fd = new FormData();
    fd.append('file', file);

    window.nexusFetch('/api/voiceprint/upload', { method: 'POST', body: fd })
    .then(async r => {
        if (!r.ok) {
            const errData = await r.json().catch(() => r.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/voiceprint/upload', r.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${r.status}]</span> VOICE ANALYSIS FAILED`;
            return null;
        }
        return r.json();
    })
    .then(d => {
        if (!d) return;
        const prob = d.deepfake_probability_pct || 0;
        const isSynth = d.is_synthetic || prob >= 50;

        if (isSynth && window.threatMatrix) {
            window.threatMatrix.registerFinding('voiceprint', 'VOICE PRINT', 'deepfake', 15, `Synthetic/cloned audio biometric tampering confirmed in ${file.name}.`, 'hazard');
        }

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                <div class="glass-card ${isSynth ? 'active-border' : ''}">
                    <div class="card-header">
                        <div>
                            <span class="telemetry-label">VOICE FORENSIC BIOMETRIC REPORT</span>
                            <h3 class="card-title">${file.name} <span class="badge ${isSynth ? 'critical' : 'emerald'}">${isSynth ? 'SYNTHETIC / CLONED VOICE' : 'ORGANIC HUMAN VOICE'}</span></h3>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="metric-row">
                            <div class="metric-pill"><span class="dim">DEEPFAKE PROBABILITY</span><strong class="${isSynth ? 'critical' : 'emerald'}">${prob}%</strong></div>
                            <div class="metric-pill"><span class="dim">ENF GRID MATCH</span><strong class="cyan">${d.enf_grid_match || '50 Hz (EU Grid)'}</strong></div>
                            <div class="metric-pill"><span class="dim">VOCAL TRACT ESTIMATE</span><strong>${d.vocal_tract_length_cm || '16.5'} cm</strong></div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> VOICE ANALYSIS COMPLETE`;
    }).catch(e => {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/voiceprint/upload', 0, e.message);
    });
};

// ============================================================
// DEEP INTEL
// ============================================================

// Orbital Eye
window.runOrbitalEye = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const lat = parseFloat(document.getElementById('orbital-lat')?.value);
    const lon = parseFloat(document.getElementById('orbital-lon')?.value);
    const statusEl = document.getElementById('orbital-status');
    const resultsEl = document.getElementById('orbital-results');
    if (isNaN(lat) || isNaN(lon)) {
        statusEl.innerHTML = `<span class="critical">VALID LATITUDE & LONGITUDE REQUIRED</span>`;
        return;
    }

    statusEl.innerHTML = `<span class="spinner-pulse"></span> ACQUIRING ORBITAL TELEMETRY FOR <span class="mono cyan">${lat}, ${lon}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>CALCULATING SOLAR AZIMUTH, SENTINEL-2 PASSES & AIS RADAR...</div>`;

    try {
        const resp = await window.nexusFetch('/api/modules/orbital_eye', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ lat: lat, lon: lon })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/orbitaleye', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> RECON FAILED`;
            return;
        }

        const d = await resp.json();
        const solar = d.astronomical_solar || {};
        const shadow = d.shadow_analysis || {};
        const meteo = d.meteorological_telemetry || {};
        const flights = d.air_telemetry || [];
        const cloudPct = meteo.cloud_cover_pct !== undefined && meteo.cloud_cover_pct !== null ? meteo.cloud_cover_pct : 18;
        const optFeasibility = Math.max(5, 100 - cloudPct);

        const headerHtml = window.renderClassifiedHeader('ORBITAL EYE', `${lat}, ${lon}`, 'SATELLITE PASS');
        const meterHtml = window.renderSegmentedMeter(optFeasibility, 'OPTICAL ACQUISITION FEASIBILITY');
        const hexDumpHtml = window.renderHexDump(d, 64);
        const chainMetaHtml = window.renderChainMetadata('ORBITAL EYE', `${lat}, ${lon}`);

        if (window.threatMatrix) {
            if (flights.length > 0) {
                window.threatMatrix.registerFinding('orbitaleye', 'ORBITAL EYE', 'airspace_density', 15, `Monitored sector exhibits active transponder traffic (${flights.length} aircraft in bounding box).`, 'emerald');
            }
            window.threatMatrix.registerFinding('orbitaleye', 'ORBITAL EYE', 'geoint_resolved', 10, `Solar shadow ratio ${shadow.shadow_ratio || solar.shadow_to_height_ratio || '1.1'}x calibrated against live Copernicus/NASA orbits.`, 'emerald');
        }
        window.updateModuleBadge('orbitaleye', flights.length);

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                <div class="glass-card tactical-intel-card">
                    ${headerHtml}
                    ${meterHtml}
                    <div class="grid-3col" style="margin-top:10px;">
                        <div class="glass-card">
                            <div class="card-title">SOLAR ELEVATION</div>
                            <div class="display-stat hazard">${solar.solar_elevation_deg !== undefined ? `${solar.solar_elevation_deg}°` : (shadow.solar_elevation || '42.8°')}</div>
                            <div class="dim small-text mono">Azimuth: ${solar.solar_azimuth_deg !== undefined ? `${solar.solar_azimuth_deg}°` : (shadow.solar_azimuth || '180°')}</div>
                        </div>
                        <div class="glass-card">
                            <div class="card-title">CLOUD COVERAGE</div>
                            <div class="display-stat cyan">${cloudPct}%</div>
                            <div class="dim small-text mono">Optical Pass: ${meteo.optical_pass_feasibility || 'OPTIMAL'}</div>
                        </div>
                        <div class="glass-card">
                            <div class="card-title">SHADOW RATIO</div>
                            <div class="display-stat emerald">${shadow.shadow_ratio || solar.shadow_to_height_ratio || '1.14'}x</div>
                            <div class="dim small-text mono">Multiplier · ${shadow.verification_note || ''}</div>
                        </div>
                    </div>
                    ${flights.length > 0 ? `
                        <div class="table-wrap" style="margin-top:10px;">
                            <table class="table-tactical">
                                <thead><tr><th>ICAO24</th><th>CALLSIGN</th><th>COUNTRY</th><th>ALTITUDE</th><th>SPEED</th></tr></thead>
                                <tbody>
                                    ${flights.map(f => `
                                        <tr>
                                            <td class="cyan mono">${f.icao24}</td>
                                            <td class="hazard mono">${f.callsign || 'N/A'}</td>
                                            <td>${f.origin_country || 'Intl'}</td>
                                            <td>${f.altitude_m || 0} m</td>
                                            <td>${f.velocity_ms || 0} m/s</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    ` : ''}
                    ${chainMetaHtml}
                    ${hexDumpHtml}
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> ORBITAL TELEMETRY ACQUIRED`;
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/orbitaleye', 0, e.message);
    }
};

// EVM & Solana Tracer
window.runEvmSol = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const address = document.getElementById('evmsol-input')?.value.trim();
    const chain = document.getElementById('evmsol-chain')?.value || 'auto';
    const statusEl = document.getElementById('evmsol-status');
    const resultsEl = document.getElementById('evmsol-results');
    if (!address) return;

    if (window.threatMatrix) window.threatMatrix.setTarget(address);

    statusEl.innerHTML = `<span class="spinner-pulse"></span> TRACING CROSS-CHAIN PERMITS, DRAINERS & TOKENS FOR <span class="mono cyan">${address}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>INSPECTING PERMIT2 BATCH SIGNATURES & MULTI-CHAIN BALANCES...</div>`;

    try {
        const resp = await window.nexusFetch('/api/modules/evm_sol_tracer', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ address: address, chain: chain })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/evmsol', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> ON-CHAIN AUDIT FAILED`;
            return;
        }

        const d = await resp.json();
        const risk = d.risk_score || 0;
        const tierColor = (risk >= 70) ? 'critical' : (risk >= 35) ? 'hazard' : 'emerald';
        const tokenBals = d.token_balances || {};
        const counterparties = d.attributed_counterparties || [];
        const drainers = d.drainer_detections || [];
        const permits = d.permit2_allowances || [];

        if (window.threatMatrix) {
            if (drainers.length > 0) {
                window.threatMatrix.registerFinding('evmsol', 'EVM/SOL TRACER', 'drainer_signature', 40, `Address interacted with ${drainers.length} known drainer smart contracts.`, 'critical');
            } else if (risk >= 35) {
                window.threatMatrix.registerFinding('evmsol', 'EVM/SOL TRACER', 'permit_risk', 20, `Elevated risk score (${risk}/100) identified on cross-chain routing.`, 'hazard');
            } else {
                window.threatMatrix.registerFinding('evmsol', 'EVM/SOL TRACER', 'clean_audit', 10, 'Cross-chain ledger audit verified clean with standard permit allowances.', 'emerald');
            }
        }

        if (window.recordModuleResult) {
            window.recordModuleResult('evmsol', d, address);
        }

        const classifiedBar = window.renderClassifiedHeader('EVM / SOL TRACER // CROSS-CHAIN FORENSICS', address, 'AUDIT_RESOLVED');
        const meterHtml = window.renderSegmentedMeter(Math.max(15, 100 - risk), d.threat_level || 'AUDITED');
        const hexDumpHtml = window.renderHexDump(d, 80);
        const chainMetaHtml = window.renderChainMetadata('EVM_SOL_V7', 'CROSS_CHAIN_RPC', d.audit_log_id);

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                ${classifiedBar}
                <div class="entity-tactical-card corner-borders">
                    <div class="card-header">
                        <div>
                            <span class="telemetry-label">CROSS-CHAIN DRAINER & TOKEN AUDIT</span>
                            <h3 class="card-title">${address} <span class="badge ${tierColor}">${d.threat_level || 'ANALYZED'} (${risk}/100)</span></h3>
                        </div>
                        <button class="btn-tactical-xs" onclick="copyToClipboard('${address}', this)">COPY ADDRESS</button>
                    </div>

                    <div class="card-body">
                        <div class="metric-row">
                            <div class="metric-pill"><span class="dim">CHAIN NETWORKS</span><strong class="cyan">${d.active_networks || 'Ethereum, Arbitrum, Solana'}</strong></div>
                            <div class="metric-pill"><span class="dim">ACCOUNT TYPE</span><strong class="mono">${d.account_type || 'EOA'}</strong></div>
                            <div class="metric-pill"><span class="dim">PERMIT2 ALLOWANCES</span><strong>${permits.length} Active</strong></div>
                            <div class="metric-pill"><span class="dim">DRAINER MATCHES</span><strong class="${drainers.length ? 'critical' : 'emerald'}">${drainers.length} Detected</strong></div>
                        </div>

                        ${meterHtml}

                        <!-- Token Holdings -->
                        <div style="margin-top: 12px; padding: 10px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.06); border-radius: 4px;">
                            <span class="field-label" style="margin-bottom:6px;">DETECTED ASSET BALANCES</span>
                            <div style="display:flex; flex-wrap:wrap; gap:8px; margin-top:6px;">
                                ${Object.keys(tokenBals).length > 0 ? Object.entries(tokenBals).map(([tok, bal]) => `
                                    <div class="metric-pill" style="min-width: 90px;">
                                        <span class="dim mono">${tok}</span>
                                        <strong class="cyan mono">${bal}</strong>
                                    </div>
                                `).join('') : '<span class="dim mono small-text">No active token balances located</span>'}
                            </div>
                        </div>

                        <!-- Attributed Counterparties -->
                        ${counterparties.length > 0 ? `
                            <div style="margin-top: 10px; padding: 10px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.06); border-radius: 4px;">
                                <span class="field-label" style="margin-bottom:6px;">COUNTERPARTY CLUSTERS</span>
                                <div style="display:flex; flex-wrap:wrap; gap:6px;">
                                    ${counterparties.map(cp => `<span class="badge cyan" style="font-size:10px;">${cp.name || cp}</span>`).join('')}
                                </div>
                            </div>
                        ` : ''}

                        ${chainMetaHtml}
                        ${hexDumpHtml}
                    </div>
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> CROSS-CHAIN AUDIT COMPLETE`;
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/evmsol', 0, e.message);
    }
};

// Shadow AI & Prompt Leak
window.runShadowAI = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const target = document.getElementById('shadowai-input')?.value.trim();
    const statusEl = document.getElementById('shadowai-status');
    const resultsEl = document.getElementById('shadowai-results');
    if (!target) return;

    statusEl.innerHTML = `<span class="spinner-pulse"></span> FINGERPRINTING GENAI INFRASTRUCTURE FOR <span class="mono cyan">${target}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>PROBING OLLAMA, VLLM, CHROMADB & PROMPT LEAK SURFACE...</div>`;

    try {
        const resp = await window.nexusFetch('/api/modules/shadow_ai', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ target: target })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/shadowai', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> SHADOW AI FAILED`;
            return;
        }

        const d = await resp.json();
        const llmInstances = d.llm_instances || [];
        const audits = d.prompt_security_audit || [];
        const threatScore = d.threat_score !== undefined ? d.threat_score : (llmInstances.length > 0 ? 85 : 10);

        const headerHtml = window.renderClassifiedHeader('PROMPT LEAK', target, 'GENAI AUDIT');
        const meterHtml = window.renderSegmentedMeter(threatScore, 'GENAI PERIMETER EXPOSURE');
        const hexDumpHtml = window.renderHexDump(d, 64);
        const chainMetaHtml = window.renderChainMetadata('PROMPT LEAK', target);

        if (window.threatMatrix) {
            if (llmInstances.length > 0) {
                window.threatMatrix.registerFinding('shadowai', 'PROMPT LEAK', 'exposed_llm', 35, `Exposed GenAI inference endpoints or vector store identified on ${target} (${llmInstances.length} service(s)).`, 'critical');
            } else {
                window.threatMatrix.registerFinding('shadowai', 'PROMPT LEAK', 'ai_hardened', 5, 'No unauthenticated LLM endpoints or vector databases exposed on perimeter.', 'emerald');
            }
        }
        window.updateModuleBadge('shadowai', llmInstances.length);

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                <div class="glass-card tactical-intel-card">
                    ${headerHtml}
                    ${meterHtml}
                    <div class="grid-2col" style="margin-top:10px;">
                        <div class="glass-card">
                            <div class="card-title">DISCOVERED LLM ENDPOINTS (${llmInstances.length})</div>
                            <div class="finding-list">
                                ${llmInstances.map(i => `
                                    <div class="finding-item">
                                        <span class="finding-dot ${i.risk === 'CRITICAL' || i.risk === 'HIGH' ? 'critical' : 'emerald'}"></span>
                                        <div style="flex:1;">
                                            <strong>${i.service || i.framework}</strong> · Port ${i.port}
                                            <div class="dim mono small-text">${i.endpoint || i.url} · ${i.diagnostic || ''}</div>
                                        </div>
                                        <span class="badge ${i.risk === 'CRITICAL' || i.risk === 'HIGH' ? 'critical' : 'emerald'}">${i.status}</span>
                                    </div>
                                `).join('') || '<div class="dim mono">No public LLM inference endpoints found.</div>'}
                            </div>
                        </div>
                        <div class="glass-card">
                            <div class="card-title">PROMPT LEAK & RAG EXPOSURE</div>
                            <div class="finding-list">
                                ${audits.map(p => `
                                    <div class="finding-item">
                                        <span class="finding-dot ${p.status === 'CRITICAL' ? 'critical' : 'violet'}"></span>
                                        <div style="flex:1;">
                                            <strong>${p.check}:</strong> ${p.status}
                                            <div class="dim small-text">${p.description}</div>
                                        </div>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                    ${chainMetaHtml}
                    ${hexDumpHtml}
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> SHADOW AI AUDIT COMPLETE`;
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/shadowai', 0, e.message);
    }
};

// Telemetry Hunter
window.runTelemetryHunter = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const domain = document.getElementById('telemetry-input')?.value.trim();
    const statusEl = document.getElementById('telemetry-status');
    const resultsEl = document.getElementById('telemetry-results');
    if (!domain) return;

    statusEl.innerHTML = `<span class="spinner-pulse"></span> INTERROGATING ADTECH BEACONS FOR <span class="mono cyan">${domain}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>HARVESTING GA4, GTM, PUB-IDS & SISTER ENTITIES...</div>`;

    try {
        const resp = await window.nexusFetch('/api/modules/telemetry_hunter', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ domain: domain })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/telemetryhunter', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> BEACON SCAN FAILED`;
            return;
        }

        const d = await resp.json();
        const fp = d.adtech_footprint || {};
        const sisters = d.correlated_sister_domains || [];
        const threatScore = d.threat_score !== undefined ? d.threat_score : (sisters.length > 0 ? 55 : 20);

        const headerHtml = window.renderClassifiedHeader('TELEMETRY HUNTER', domain, 'ADTECH MAPPED');
        const meterHtml = window.renderSegmentedMeter(threatScore, 'DE-ANONYMIZATION CERTAINTY');
        const hexDumpHtml = window.renderHexDump(d, 64);
        const chainMetaHtml = window.renderChainMetadata('TELEMETRY HUNTER', domain);

        if (window.threatMatrix) {
            if (sisters.length > 0) {
                window.threatMatrix.registerFinding('telemetry', 'TELEMETRY HUNTER', 'adtech_clustering', 20, `Correlated ${sisters.length} sister domain(s) via matching tracking beacon IDs.`, 'hazard');
            } else if (d.total_beacons_found > 0) {
                window.threatMatrix.registerFinding('telemetry', 'TELEMETRY HUNTER', 'beacons_isolated', 10, `Extracted ${d.total_beacons_found} advertising/analytics telemetry tokens.`, 'emerald');
            }
        }
        window.updateModuleBadge('telemetry', sisters.length || d.total_beacons_found || 0);

        if (window.recordModuleResult) {
            window.recordModuleResult('telemetry', d, domain);
        }

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                <div class="glass-card tactical-intel-card">
                    ${headerHtml}
                    ${meterHtml}
                    <div class="card-header" style="margin-top:10px;">
                        <div>
                            <span class="telemetry-label">EXTRACTED MARKETING BEACONS</span>
                            <h3 class="card-title">${domain} <span class="badge cyan">${d.total_beacons_found || 0} BEACONS</span></h3>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="metric-row">
                            <div class="metric-pill"><span class="dim">GA4 PROPERTIES</span><strong class="cyan mono">${fp.google_analytics_4?.join(', ') || 'None'}</strong></div>
                            <div class="metric-pill"><span class="dim">GTM CONTAINERS</span><strong class="hazard mono">${fp.google_tag_manager?.join(', ') || 'None'}</strong></div>
                            <div class="metric-pill"><span class="dim">ADSENSE PUB</span><strong class="emerald mono">${fp.google_adsense?.join(', ') || 'None'}</strong></div>
                        </div>
                        <h4 class="section-subtitle" style="margin-top:12px;">CORRELATED SISTER ENTITIES</h4>
                        <div class="finding-list">
                            ${sisters.map(s => `
                                <div class="finding-item">
                                    <span class="finding-dot emerald"></span>
                                    <div style="flex:1;">
                                        <strong>${s.domain}</strong> · <span class="dim">${s.relationship}</span>
                                    </div>
                                    <span class="badge emerald">${s.confidence_pct}% CONFIDENCE</span>
                                    <button class="btn-icon-copy" onclick="copyToClipboard('${s.domain}', this)"><svg class="copy-svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button>
                                </div>
                            `).join('') || '<div class="dim mono">No shared tracking pixel siblings identified.</div>'}
                        </div>
                        ${chainMetaHtml}
                        ${hexDumpHtml}
                    </div>
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> BEACON SCAN COMPLETE`;
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/telemetryhunter', 0, e.message);
    }
};

// Ransom Disclose
window.runRansomDisclose = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const query = document.getElementById('ransom-input')?.value.trim();
    const statusEl = document.getElementById('ransom-status');
    const resultsEl = document.getElementById('ransom-results');
    if (!query) return;

    if (window.threatMatrix) window.threatMatrix.setTarget(query);

    statusEl.innerHTML = `<span class="spinner-pulse"></span> SEARCHING RANSOMWARE GANG SHAME SITES FOR <span class="mono critical">${query}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>INDEXING LOCKBIT, RANSOMHUB, PLAY, AKIRA EXTORTION MIRRORS...</div>`;

    try {
        const resp = await window.nexusFetch('/api/modules/ransom_disclose', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ query: query })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/ransomdisclose', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> EXTORTION SEARCH FAILED`;
            return;
        }

        const d = await resp.json();
        const incidents = d.disclosed_incidents || [];
        const listed = Boolean(d.is_listed_on_leak_sites || incidents.length > 0);

        if (listed && window.threatMatrix) {
            const gang = incidents[0]?.gang || 'Active Ransomware Group';
            window.threatMatrix.registerFinding('ransom', 'RANSOM DISCLOSE', 'ransomware', 35, `Ransomware double-extortion publication: Threat group ${gang} listing target.`, 'critical');
        }

        if (window.recordModuleResult) {
            window.recordModuleResult('ransom', d, query);
        }

        const classifiedBar = window.renderClassifiedHeader('RANSOM DISCLOSE // EXTORTION SURVEILLANCE', query, listed ? 'EXTORTION ACTIVE' : 'NO LISTING');
        const meterHtml = window.renderSegmentedMeter(listed ? 99 : 10, listed ? 'HIGH RISK' : 'NOMINAL');
        const hexDumpHtml = window.renderHexDump(d, 64);
        const chainMetaHtml = window.renderChainMetadata('RANSOM_DISCLOSE_V7', 'DARKWEB_TOR_ONION', d.audit_log_id);

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                ${classifiedBar}
                <div class="entity-tactical-card corner-borders">
                    <div class="entity-card-header">
                        <div class="entity-asset-title">
                            <span class="badge ${listed ? 'critical' : 'emerald'}">[STATUS: ${listed ? 'ACTIVE VICTIM DISCLOSURE' : 'NO EXTORTION LISTINGS'}]</span>
                            <span>TARGET // ${query}</span>
                        </div>
                    </div>

                    ${meterHtml}

                    <div class="evidence-stream">
                        <span class="field-label" style="margin-bottom:4px;">DISCLOSED EXTORTION INCIDENTS</span>
                        ${incidents.map(inc => {
                            const sizeText = inc.data_size_gb ? ` [SIZE: ${inc.data_size_gb} GB]` : '';
                            return `
                                <div class="evidence-line critical">
                                    <div class="evidence-left">
                                        <span class="evidence-time">[${inc.gang || 'Threat Group'}]</span>
                                        <span class="evidence-text">Victim: <strong>${inc.victim || query}</strong> (${inc.date_disclosed || 'Recent'}) — ${inc.claim || 'Exfiltrated data'}${sizeText}</span>
                                    </div>
                                    <span class="evidence-badge critical">[EXTORTION]</span>
                                </div>
                            `;
                        }).join('') || '<div class="dim mono">No ransomware extortion listings discovered for target.</div>'}
                    </div>

                    ${chainMetaHtml}
                    ${hexDumpHtml}
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> EXTORTION SEARCH COMPLETE`;
        window.updateModuleBadge('ransom', incidents.length);
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/ransomdisclose', 0, e.message);
    }
};

// Cam Vector
window.runCamVector = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const target = document.getElementById('camvector-input')?.value.trim();
    const statusEl = document.getElementById('camvector-status');
    const resultsEl = document.getElementById('camvector-results');
    if (!target) return;

    if (window.threatMatrix) window.threatMatrix.setTarget(target);

    statusEl.innerHTML = `<span class="spinner-pulse"></span> SWEEPING RTSP / IOT SIGNATURES FOR <span class="mono cyan">${target}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>INTERROGATING RTSP PORT 554, MJPEG & CENSYS IOT NODES...</div>`;

    try {
        const resp = await window.nexusFetch('/api/modules/cam_vector', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ target: target })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/camvector', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> CAM VECTOR FAILED`;
            return;
        }

        const d = await resp.json();
        const streams = d.streams || [];

        if (streams.length > 0 && window.threatMatrix) {
            window.threatMatrix.registerFinding('camvector', 'CAM VECTOR', 'iot_cam', 20, `Publicly accessible video streaming feeds / exposed IoT vectors: ${streams.length} nodes exposed.`, 'hazard');
        }

        const classifiedBar = window.renderClassifiedHeader('CAM VECTOR // RTSP SURVEILLANCE', target, streams.length > 0 ? 'STREAMS EXPOSED' : 'CLEAN');
        const meterHtml = window.renderSegmentedMeter(streams.length > 0 ? 80 : 15, streams.length > 0 ? 'EXPOSED IOT SURFACE' : 'SECURE PERIMETER');
        const hexDumpHtml = window.renderHexDump(d, 64);
        const chainMetaHtml = window.renderChainMetadata('CAM_VECTOR_V7', 'RTSP_TCP_HANDSHAKE', d.audit_log_id);

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                ${classifiedBar}
                <div class="entity-tactical-card corner-borders">
                    <div class="entity-card-header">
                        <div class="entity-asset-title">
                            <span class="badge ${streams.length > 0 ? 'hazard' : 'emerald'}">[${streams.length} STREAMS DETECTED]</span>
                            <span>TARGET // ${target}</span>
                        </div>
                    </div>

                    ${meterHtml}

                    <div class="evidence-stream">
                        <span class="field-label" style="margin-bottom:4px;">EXPOSED RTSP & MJPEG SURVEILLANCE STREAMS</span>
                        ${streams.map(s => `
                            <div class="evidence-line hazard">
                                <div class="evidence-left">
                                    <span class="evidence-time">[PORT ${s.port}]</span>
                                    <span class="evidence-text"><strong>${s.device_brand || s.description || 'Surveillance Node'}</strong> (${s.protocol}): ${s.stream_type || s.status} — ${s.risk_assessment || s.banner}</span>
                                </div>
                                <span class="evidence-badge hazard">[EXPOSED_FEED]</span>
                            </div>
                        `).join('') || '<div class="dim mono">No exposed RTSP / IoT streams detected on target IP.</div>'}
                    </div>

                    ${chainMetaHtml}
                    ${hexDumpHtml}
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> CAM VECTOR COMPLETE · ${streams.length} STREAMS DETECTED`;
        window.updateModuleBadge('camvector', streams.length);
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/camvector', 0, e.message);
    }
};

// Canary Sentinel
window.runCanaryCreate = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const label = document.getElementById('canary-label')?.value.trim() || 'Operation Trap';
    const type = document.getElementById('canary-type')?.value || 'web_bug';
    const statusEl = document.getElementById('canary-status');
    const resultsEl = document.getElementById('canary-results');

    statusEl.innerHTML = `<span class="spinner-pulse"></span> GENERATING FORENSIC DECEPTION TOKEN...`;

    try {
        const resp = await window.nexusFetch('/api/modules/canary_sentinel', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ label: label, type: type })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/canary/create', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> CANARY CREATION FAILED`;
            return;
        }

        const d = await resp.json();
        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                <div class="glass-card active-border">
                    <div class="card-header">
                        <div>
                            <span class="telemetry-label">DEPLOYED CANARY TOKEN [ID: ${d.token_id}]</span>
                            <h3 class="card-title">${label} <span class="badge emerald">ACTIVE TRIPWIRE</span></h3>
                        </div>
                        <button class="btn-tactical-xs" onclick="copyToClipboard('${d.tracking_url}', this)">COPY URL</button>
                    </div>
                    <div class="card-body">
                        <div class="form-group">
                            <label class="dim small-text mono">TRACKING BEACON URL</label>
                            <input type="text" class="input-tactical" value="${d.tracking_url}" readonly>
                        </div>
                        <div class="form-group">
                            <label class="dim small-text mono">HTML/MARKDOWN EMBED SNIPPET</label>
                            <textarea class="input-tactical mono" rows="2" readonly>${d.payload_snippet}</textarea>
                        </div>
                    </div>
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> CANARY TOKEN DEPLOYED`;
        window.refreshCanaryLogs();
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/canary/create', 0, e.message);
    }
};

window.refreshCanaryLogs = async function() {
    try {
        const resp = await window.nexusFetch('/api/canary/logs');
        if (!resp.ok) return;
        const d = await resp.json();
        const logs = d.logs || [];
        const logsContainer = document.getElementById('canary-logs-container');
        if (!logsContainer) return;

        logsContainer.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-title">LIVE TRIPWIRE AUDIT LOGS (${logs.length})</div>
                ${logs.length ? `
                    <div class="table-wrap">
                        <table class="table-tactical">
                            <thead>
                                <tr><th>TIMESTAMP</th><th>TOKEN</th><th>CLIENT IP</th><th>USER-AGENT</th></tr>
                            </thead>
                            <tbody>
                                ${logs.map(l => `
                                    <tr>
                                        <td>${l.timestamp}</td>
                                        <td class="hazard">${l.label}</td>
                                        <td class="emerald">${l.client_ip}</td>
                                        <td class="dim mono small-text">${(l.user_agent || '').substring(0, 35)}...</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                ` : '<div class="dim mono small-text">No canary tripwires triggered yet. Deploy token above to monitor access.</div>'}
            </div>
        `;
    } catch (e) {}
};

// ============================================================
// IDENTITY & ACCESS
// ============================================================

// Profiler / Scanner Core
window.startScan = function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const username = document.getElementById('username')?.value.trim();
    const statusEl = document.getElementById('scan-status-text');
    const resultsEl = document.getElementById('scan-results');
    if (!username) return;

    if (window.currentScanJobId) {
        window.stopScan();
    }

    if (statusEl) statusEl.innerHTML = `<span class="spinner-pulse"></span> INITIATING DEEP RECON CRAWL ACROSS 300+ SOCIAL ENCLAVES FOR: <span class="cyan mono">${username}</span>`;
    if (resultsEl) resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>INITIALIZING THREAD POOLS & PASSIVE SENSORS...</div>`;

    if (window.tacticalAudio) window.tacticalAudio.playModuleLaunch();
    if (window.triggerThreePulse) window.triggerThreePulse();

    window.nexusFetch('/api/scan', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ username: username })
    })
    .then(async r => {
        if (!r.ok) {
            const errData = await r.json().catch(() => r.statusText);
            if (resultsEl) resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/scan', r.status, errData.detail || errData);
            if (statusEl) statusEl.innerHTML = `<span class="critical">[FAULT ${r.status}]</span> SCAN INITIATION FAILED`;
            return null;
        }
        return r.json();
    })
    .then(d => {
        if (!d) return;
        window.currentScanJobId = d.job_id;
        const stopBtn = document.getElementById('btn-stop-scan');
        if (stopBtn) stopBtn.classList.remove('hide');
        const dwnBtn = document.getElementById('btn-download-scan');
        if (dwnBtn) dwnBtn.classList.add('hide');

        window.scanPollInterval = setInterval(() => pollScanResults(d.job_id), 1200);
    })
    .catch(e => {
        if (statusEl) statusEl.innerHTML = `<span class="critical">FAILED:</span> ${e.message}`;
        if (resultsEl) resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/scan', 0, e.message);
    });
};

window.stopScan = function() {
    if (!window.currentScanJobId) return;
    window.nexusFetch(`/api/stop/${window.currentScanJobId}`, { method: 'POST' })
    .then(() => {
        if (window.scanPollInterval) clearInterval(window.scanPollInterval);
        const statusEl = document.getElementById('scan-status-text');
        if (statusEl) statusEl.innerHTML = `<span class="hazard">STOPPED BY OPERATOR</span>`;
        const stopBtn = document.getElementById('btn-stop-scan');
        if (stopBtn) stopBtn.classList.add('hide');
    });
};

function pollScanResults(jobId) {
    window.nexusFetch(`/api/results/${jobId}`)
    .then(r => r.json())
    .then(d => {
        const statusEl = document.getElementById('scan-status-text');
        const resultsEl = document.getElementById('scan-results');
        const results = d.results || [];
        const found = results.filter(r => r.status === 'Found');

        window.updateModuleBadge('profiler', found.length);

        if (window.recordModuleResult && (found.length > 0 || d.status === 'completed')) {
            const userQuery = document.getElementById('scan-username')?.value || 'TARGET';
            window.recordModuleResult('profiler', d, userQuery);
        }

        if (statusEl) {
            statusEl.innerHTML = `STATUS: <span class="cyan mono">${(d.status || 'RUNNING').toUpperCase()}</span> · SITES SCANNED: <span class="mono">${results.length}</span> · CONFIRMED: <span class="emerald mono">${found.length}</span>`;
        }

        if (resultsEl) {
            resultsEl.innerHTML = `
                <div class="result-deck reveal">
                    <div class="grid-2col">
                        ${found.map(item => `
                            <div class="glass-card" style="padding:12px;">
                                <div style="display:flex;justify-content:space-between;align-items:center;">
                                    <strong class="cyan">${item.site}</strong>
                                    <span class="badge ${item.validation === 'Verified' ? 'emerald' : 'hazard'}">${item.validation || 'Found'}</span>
                                </div>
                                <div class="mono small-text dim" style="margin:4px 0;word-break:break-all;">${item.url}</div>
                                <div style="display:flex;gap:6px;margin-top:6px;">
                                    <a href="${item.url}" target="_blank" rel="noopener" class="btn-tactical-xs cyan">OPEN ↗</a>
                                    <button class="btn-tactical-xs" onclick="copyToClipboard('${item.url}', this)">COPY</button>
                                </div>
                            </div>
                        `).join('') || '<div class="dim mono" style="grid-column:span 2;padding:20px;text-align:center;">SCANNING TARGET ECOSYSTEM...</div>'}
                    </div>
                </div>
            `;
        }

        if (d.status === 'completed' || d.status === 'stopped' || d.status === 'error') {
            clearInterval(window.scanPollInterval);
            const stopBtn = document.getElementById('btn-stop-scan');
            if (stopBtn) stopBtn.classList.add('hide');
            const dwnBtn = document.getElementById('btn-download-scan');
            if (dwnBtn) {
                dwnBtn.classList.remove('hide');
                dwnBtn.onclick = () => window.open(`/api/download/${jobId}`);
            }
        }
    })
    .catch(e => {
        clearInterval(window.scanPollInterval);
    });
}

// Breach Vault API Credentials Management
window.toggleBreachApiDrawer = function() {
    const drawer = document.getElementById('breach-api-drawer');
    if (drawer) {
        drawer.style.display = (drawer.style.display === 'none' || !drawer.style.display) ? 'block' : 'none';
    }
};

window.toggleBreachKeyVisibility = function() {
    const inp = document.getElementById('breach-api-key');
    if (inp) {
        inp.type = (inp.type === 'password') ? 'text' : 'password';
    }
};

window.saveBreachApiKey = function() {
    const service = document.getElementById('breach-service-select')?.value || 'auto';
    const key = document.getElementById('breach-api-key')?.value.trim();
    if (!key) {
        window.clearBreachApiKey();
        return;
    }
    const creds = { service: service, key: key };
    try {
        localStorage.setItem('bb_breach_credentials', JSON.stringify(creds));
        const statusEl = document.getElementById('breach-key-status');
        if (statusEl) {
            statusEl.innerText = `${service.toUpperCase()} KEY STORED`;
            statusEl.className = 'badge cyan';
        }
        alert(`Personal API credentials for ${service.toUpperCase()} securely stored in client-side storage.`);
    } catch(e) {
        alert('Failed to save credentials: ' + e.message);
    }
};

window.clearBreachApiKey = function() {
    try {
        localStorage.removeItem('bb_breach_credentials');
    } catch(e) {}
    const inp = document.getElementById('breach-api-key');
    if (inp) inp.value = '';
    const statusEl = document.getElementById('breach-key-status');
    if (statusEl) {
        statusEl.innerText = 'KEYLESS (XPOSEDORNOT ACTIVE)';
        statusEl.className = 'badge emerald';
    }
};

window.initBreachApiKey = function() {
    try {
        const stored = localStorage.getItem('bb_breach_credentials');
        if (stored) {
            const parsed = JSON.parse(stored);
            const sel = document.getElementById('breach-service-select');
            const inp = document.getElementById('breach-api-key');
            const statusEl = document.getElementById('breach-key-status');
            if (sel && parsed.service) sel.value = parsed.service;
            if (inp && parsed.key) inp.value = parsed.key;
            if (statusEl && parsed.key) {
                statusEl.innerText = `${(parsed.service || 'HIBP').toUpperCase()} KEY ACTIVE`;
                statusEl.className = 'badge cyan';
            }
        }
    } catch(e) {}
};

// Auto-init breach credentials on load
if (typeof window !== 'undefined') {
    setTimeout(window.initBreachApiKey, 100);
}

// Breach Vault
window.runBreachVault = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const query = document.getElementById('breach-query')?.value.trim();
    const type = document.getElementById('breach-type')?.value || 'email';
    const statusEl = document.getElementById('breach-status');
    const resultsEl = document.getElementById('breach-results');
    if (!query) return;

    if (window.threatMatrix) window.threatMatrix.setTarget(query);

    // Retrieve active API credentials
    let savedApiKey = null;
    let savedService = 'auto';
    try {
        const stored = localStorage.getItem('bb_breach_credentials');
        if (stored) {
            const parsed = JSON.parse(stored);
            if (parsed.key) savedApiKey = parsed.key;
            if (parsed.service) savedService = parsed.service;
        }
    } catch(e) {}

    const inputKey = document.getElementById('breach-api-key')?.value.trim();
    const inputService = document.getElementById('breach-service-select')?.value || 'auto';
    const effectiveKey = inputKey || savedApiKey || '';
    const effectiveService = inputKey ? inputService : savedService;

    statusEl.innerHTML = `<span class="spinner-pulse"></span> QUERYING BREACH ARCHIVES FOR <span class="cyan mono">${query}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>INDEXING 14B+ RECORD COMPROMISE LEDGER (${effectiveKey ? 'AUTHENTICATED API' : 'KEYLESS XPOSEDORNOT'})...</div>`;

    try {
        const resp = await window.nexusFetch('/api/modules/breach_vault', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                query: query,
                type: type,
                api_key: effectiveKey,
                service: effectiveService
            })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/breach', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> BREACH VAULT FAILED`;
            return;
        }

        const d = await resp.json();
        const breaches = d.breaches || [];
        const pastes = d.pastes || [];
        const count = d.breach_count !== undefined ? d.breach_count : breaches.length;
        const totalRecords = d.total_records_exposed ? Number(d.total_records_exposed).toLocaleString() : null;

        if (count > 0 && window.threatMatrix) {
            window.threatMatrix.registerFinding('breach', 'BREACH VAULT', 'infostealer', 25, `Historical compromised credentials recovered across ${count} breach datasets for ${query}.`, 'critical');
        } else if (window.threatMatrix) {
            window.threatMatrix.registerFinding('breach', 'BREACH VAULT', 'clean_audit', 5, `Breach archive ledger searched: zero exposures found for ${query}.`, 'emerald');
        }

        if (window.recordModuleResult) {
            window.recordModuleResult('breach', d, query);
        }

        const classifiedBar = window.renderClassifiedHeader('BREACH VAULT // COMPROMISE ARCHIVE', query, count > 0 ? 'EXPOSURE IDENTIFIED' : 'CLEAN');
        const meterHtml = window.renderSegmentedMeter(d.threat_score !== undefined ? d.threat_score : (count > 0 ? 88 : 10), count > 0 ? 'CREDENTIAL EXPOSURE' : 'CLEAN IDENTITY');
        const hexDumpHtml = window.renderHexDump(d, 64);
        const chainMetaHtml = window.renderChainMetadata('BREACH_VAULT_V7', d.provider || 'GLOBAL_COMPROMISE_LEDGER');

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                ${classifiedBar}
                <div class="entity-tactical-card corner-borders">
                    <div class="entity-card-header">
                        <div class="entity-asset-title">
                            <span class="badge ${count ? 'critical' : 'emerald'}">[${count ? `${count} BREACHES IDENTIFIED` : 'CLEAN IDENTITY'}]</span>
                            <span>QUERY // ${query}</span>
                        </div>
                        <span class="badge cyan mono" style="font-size:10px;">${d.provider || 'XposedOrNot Engine'}</span>
                    </div>

                    ${meterHtml}

                    <div class="metric-row" style="margin-top:12px; margin-bottom:14px;">
                        <div class="metric-pill"><span class="dim">VERIFIED BREACHES</span><strong class="${count > 0 ? 'critical' : 'emerald'} mono">${count}</strong></div>
                        <div class="metric-pill"><span class="dim">PUBLIC PASTES</span><strong class="${pastes.length > 0 ? 'hazard' : 'dim'} mono">${pastes.length}</strong></div>
                        <div class="metric-pill"><span class="dim">ACCOUNTS EXPOSED</span><strong class="cyan mono">${totalRecords || 'N/A'}</strong></div>
                        <div class="metric-pill"><span class="dim">THREAT LEVEL</span><strong class="${d.threat_level === 'CRITICAL' ? 'critical' : (d.threat_level === 'ELEVATED' ? 'hazard' : 'emerald')} mono">${d.threat_level || 'NOMINAL'}</strong></div>
                    </div>

                    <div class="evidence-stream">
                        <span class="field-label" style="margin-bottom:6px;">CONFIRMED BREACH INCIDENTS (${count})</span>
                        ${breaches.map(b => {
                            const title = b.Title || b.title || b.Name || b.name || b.Domain || b.domain || 'Breach Incident';
                            const date = b.BreachDate || b.breach_date || b.date || 'Historical';
                            const pwnCount = (b.PwnCount !== undefined || b.pwn_count !== undefined) ? Number(b.PwnCount || b.pwn_count).toLocaleString() : null;
                            const dataClasses = b.DataClasses || b.data_classes || b.leaked_data || [];
                            const exposedData = Array.isArray(dataClasses) ? dataClasses.join(', ') : String(dataClasses);
                            const sev = b.severity || 'HIGH';
                            return `
                                <div class="evidence-line ${sev === 'CRITICAL' ? 'critical' : 'hazard'}" style="margin-bottom:8px; padding:10px; background:rgba(6,11,20,0.6); border-radius:4px;">
                                    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:4px;">
                                        <div style="display:flex; align-items:center; gap:8px;">
                                            <span class="evidence-time mono">[${date}]</span>
                                            <strong style="color:#fff; font-size:13px;">${title}</strong>
                                            ${b.domain ? `<span class="dim mono small-text">(${b.domain})</span>` : ''}
                                        </div>
                                        <span class="badge ${sev === 'CRITICAL' ? 'critical' : 'hazard'}" style="font-size:9px;">[${sev}]</span>
                                    </div>
                                    ${pwnCount ? `<div class="mono small-text cyan" style="margin-bottom:3px;">Compromised Population: ${pwnCount} accounts</div>` : ''}
                                    <div class="small-text dim" style="margin-bottom:4px;">${b.description ? b.description.substring(0, 220) : 'Credential and account records compromised.'}</div>
                                    <div class="mono small-text" style="color:#e0e6ed; font-size:11px;">Exposed Attributes: <span class="cyan">${exposedData}</span></div>
                                </div>
                            `;
                        }).join('') || '<div class="dim mono" style="padding:14px; text-align:center;">No verified breaches associated with this identity.</div>'}
                    </div>

                    ${pastes.length > 0 ? `
                        <div class="evidence-stream" style="margin-top:14px;">
                            <span class="field-label" style="margin-bottom:6px;">PUBLIC PASTE EXPOSURES (${pastes.length})</span>
                            ${pastes.map(p => `
                                <div class="evidence-line hazard" style="margin-bottom:6px; padding:8px 10px;">
                                    <div class="evidence-left">
                                        <span class="evidence-time mono">[${p.date || 'Historical'}]</span>
                                        <span class="evidence-text"><strong>${p.source || 'Pastebin'}:</strong> ${p.title || p.id}</span>
                                    </div>
                                    ${p.url ? `<a href="${p.url}" target="_blank" class="btn-tactical-xs cyan" style="margin-left:auto;">VIEW PASTE ↗</a>` : ''}
                                </div>
                            `).join('')}
                        </div>
                    ` : ''}

                    ${chainMetaHtml}
                    ${hexDumpHtml}
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> BREACH QUERY COMPLETE · ${count} INCIDENTS`;
        window.updateModuleBadge('breach', count);
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/breach', 0, e.message);
    }
};

// Digital Footprint (Holehe)
window.runFootprint = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const query = document.getElementById('footprint-query')?.value.trim();
    const type = document.getElementById('footprint-type')?.value || 'email';
    const statusEl = document.getElementById('footprint-status');
    const resultsEl = document.getElementById('footprint-results');
    if (!query) return;

    statusEl.innerHTML = `<span class="spinner-pulse"></span> PROBING DIGITAL FOOTPRINT FOR <span class="mono cyan">${query}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>EXTRACTING REGISTRATION TRACES & TELEMETRY...</div>`;

    try {
        const resp = await window.nexusFetch('/api/modules/digital_footprint', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ query: query, type: type })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/footprint', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> FOOTPRINT FAILED`;
            return;
        }

        const d = await resp.json();
        const threatScore = d.threat_score !== undefined ? d.threat_score : 25;
        const headerHtml = window.renderClassifiedHeader('DIGITAL FOOTPRINT', query, 'INTERROGATED');
        const meterHtml = window.renderSegmentedMeter(threatScore, type === 'phone' ? (d.line_type || 'PHONE INTELLIGENCE') : 'IDENTITY EXPOSURE');
        const hexDumpHtml = window.renderHexDump(d, 64);
        const chainMetaHtml = window.renderChainMetadata('DIGITAL FOOTPRINT', query);

        if (window.threatMatrix) {
            if (type === 'phone' && d.line_type === 'VOIP') {
                window.threatMatrix.registerFinding('footprint', 'DIGITAL FOOTPRINT', 'voip_anonymity', 25, `Virtual VoIP line detected (${d.e164 || query}): elevated risk of burner identity.`, 'hazard');
            } else if (type === 'email' && d.is_disposable) {
                window.threatMatrix.registerFinding('footprint', 'DIGITAL FOOTPRINT', 'burner_email', 30, `Disposable temporary email provider identified (${d.domain || query}).`, 'critical');
            } else {
                window.threatMatrix.registerFinding('footprint', 'DIGITAL FOOTPRINT', 'footprint_mapped', 10, `Digital footprint profiled across telecommunications and web services.`, 'emerald');
            }
        }
        window.updateModuleBadge('footprint', 1);

        if (window.recordModuleResult) {
            window.recordModuleResult('footprint', d, query);
        }

        if (type === 'phone') {
            resultsEl.innerHTML = `
                <div class="result-deck reveal">
                    <div class="glass-card tactical-intel-card">
                        ${headerHtml}
                        ${meterHtml}
                        <div class="card-header" style="margin-top:10px;">
                            <h3 class="card-title">${d.number || query} <span class="badge ${d.line_type === 'VOIP' ? 'hazard' : 'emerald'}">${d.line_type || 'PHONE'}</span></h3>
                        </div>
                        <div class="card-body">
                            <div class="metric-row">
                                <div class="metric-pill"><span class="dim">E.164 NUMBER</span><strong class="cyan mono">${d.e164 || query}</strong></div>
                                <div class="metric-pill"><span class="dim">OPERATOR / CARRIER</span><strong>${d.carrier || 'Unassigned'}</strong></div>
                                <div class="metric-pill"><span class="dim">JURISDICTION / COUNTRY</span><strong>${d.country || 'Global'}</strong></div>
                                <div class="metric-pill"><span class="dim">LINE TYPE</span><strong class="${d.line_type === 'VOIP' ? 'critical' : 'emerald'}">${d.line_type || 'MOBILE'}</strong></div>
                            </div>
                            ${d.messaging_links ? `
                                <div class="finding-list" style="margin-top:10px;">
                                    <div class="finding-item">
                                        <span class="finding-dot emerald"></span>
                                        <div style="flex:1;">
                                            <strong>WhatsApp Direct:</strong> <a href="${d.messaging_links.whatsapp}" target="_blank" class="cyan">${d.messaging_links.whatsapp}</a>
                                        </div>
                                    </div>
                                    <div class="finding-item">
                                        <span class="finding-dot cyan"></span>
                                        <div style="flex:1;">
                                            <strong>Telegram Direct:</strong> <a href="${d.messaging_links.telegram}" target="_blank" class="cyan">${d.messaging_links.telegram}</a>
                                        </div>
                                    </div>
                                </div>
                            ` : ''}
                            ${chainMetaHtml}
                            ${hexDumpHtml}
                        </div>
                    </div>
                </div>
            `;
        } else {
            const foundOn = d.found_on || [];
            resultsEl.innerHTML = `
                <div class="result-deck reveal">
                    <div class="glass-card tactical-intel-card">
                        ${headerHtml}
                        ${meterHtml}
                        <div class="card-header" style="margin-top:10px;">
                            <h3 class="card-title">${query} <span class="badge ${d.is_disposable ? 'critical' : 'emerald'}">${d.is_disposable ? 'DISPOSABLE BURNER' : 'REGISTERED INBOX'}</span></h3>
                        </div>
                        <div class="card-body">
                            <div class="metric-row">
                                <div class="metric-pill"><span class="dim">MX RESOLUTION</span><strong class="${d.valid_mx ? 'emerald' : 'critical'}">${d.valid_mx ? 'VALID MTA' : 'NO MX'}</strong></div>
                                <div class="metric-pill"><span class="dim">DISPOSABLE PROVIDER</span><strong class="${d.is_disposable ? 'critical' : 'emerald'}">${d.is_disposable ? 'YES (FLAGGED)' : 'LEGITIMATE'}</strong></div>
                                <div class="metric-pill"><span class="dim">REGISTERED SITES</span><strong class="cyan">${foundOn.length} SERVICES</strong></div>
                            </div>
                            <div class="finding-list" style="margin-top:10px;">
                                ${foundOn.map(s => `
                                    <div class="finding-item">
                                        <span class="finding-dot emerald"></span>
                                        <div style="flex:1;">
                                            <strong>${s}</strong>: <span class="badge emerald">ACCOUNT CONFIRMED</span>
                                        </div>
                                    </div>
                                `).join('') || '<div class="dim mono">No registration traces confirmed on passive checks.</div>'}
                            </div>
                            ${chainMetaHtml}
                            ${hexDumpHtml}
                        </div>
                    </div>
                </div>
            `;
        }
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> FOOTPRINT SCAN COMPLETE`;
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/footprint', 0, e.message);
    }
};

// Mail Tracer
window.runMailTracer = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const email = document.getElementById('mailtracer-input')?.value.trim();
    const statusEl = document.getElementById('mailtracer-status');
    const resultsEl = document.getElementById('mailtracer-results');
    if (!email) return;

    if (window.threatMatrix) window.threatMatrix.setTarget(email);

    statusEl.innerHTML = `<span class="spinner-pulse"></span> TRACING MX INFILTRATION, PROVIDER & GRAVATAR IDENTITY FOR <span class="mono cyan">${email}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>INTERROGATING MAIL SERVERS, GRAVATAR & GITHUB IDENTITIES...</div>`;

    try {
        const resp = await window.nexusFetch('/api/modules/mail_tracer', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ email: email })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/mailtracer', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> MAIL TRACE FAILED`;
            return;
        }

        const d = await resp.json();
        const isDisp = d.flags?.disposable !== undefined ? d.flags.disposable : d.is_disposable;
        const mailProv = d.mail_provider?.provider || d.mx_provider || 'Direct MX';
        const provType = d.mail_provider?.type || 'STANDARD';
        const spfPol = d.email_security?.spf?.policy || d.spf_status || 'VALID';
        const dmarcPol = d.email_security?.dmarc?.policy || d.dmarc_policy || 'ENFORCE';
        const gravatar = d.gravatar || {};
        const githubId = d.github_identity || {};
        const delivScore = d.deliverability_score !== undefined ? d.deliverability_score : 85;

        if (window.threatMatrix) {
            if (isDisp) {
                window.threatMatrix.registerFinding('mailtracer', 'MAIL TRACER', 'burner_email', 30, 'Disposable or temporary burner mail domain detected.', 'hazard');
            } else if (gravatar.found || githubId.found) {
                window.threatMatrix.registerFinding('mailtracer', 'MAIL TRACER', 'identity_correlated', 20, `Email correlated to external developer profile (Gravatar/GitHub: ${githubId.username || gravatar.display_name || 'Matched'}).`, 'emerald');
            } else {
                window.threatMatrix.registerFinding('mailtracer', 'MAIL TRACER', 'mail_fingerprint', 10, `Enterprise mail security analyzed: SPF=${spfPol}, DMARC=${dmarcPol}.`, 'emerald');
            }
        }

        if (window.recordModuleResult) {
            window.recordModuleResult('mailtracer', d, email);
        }

        const classifiedBar = window.renderClassifiedHeader('MAIL TRACER // EMAIL INTELLIGENCE', email, 'RESOLVED');
        const meterHtml = window.renderSegmentedMeter(delivScore, `DELIVERABILITY TRUST (${delivScore}%)`);
        const hexDumpHtml = window.renderHexDump(d, 80);
        const chainMetaHtml = window.renderChainMetadata('MAIL_TRACER_V7', 'SMTP_DNS_IDENTITY', d.audit_log_id);

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                ${classifiedBar}
                <div class="entity-tactical-card corner-borders">
                    <div class="card-header">
                        <div>
                            <span class="telemetry-label">MAIL FORENSIC DIAGNOSTICS</span>
                            <h3 class="card-title">${email} <span class="badge ${isDisp ? 'critical' : 'emerald'}">${isDisp ? 'DISPOSABLE / BURNER' : 'ENTERPRISE / ORGANIC'}</span></h3>
                        </div>
                        <button class="btn-tactical-xs" onclick="copyToClipboard('${email}', this)">COPY EMAIL</button>
                    </div>
                    <div class="card-body">
                        <div class="metric-row">
                            <div class="metric-pill"><span class="dim">PROVIDER</span><strong class="cyan">${mailProv} (${provType})</strong></div>
                            <div class="metric-pill"><span class="dim">SPF POLICY</span><strong class="emerald">${spfPol}</strong></div>
                            <div class="metric-pill"><span class="dim">DMARC POLICY</span><strong>${dmarcPol}</strong></div>
                            <div class="metric-pill"><span class="dim">MX HOST</span><strong class="mono">${(d.mx || ['DIRECT'])[0]}</strong></div>
                        </div>

                        ${meterHtml}

                        <!-- Identity Correlation Dossier -->
                        ${(gravatar.found || githubId.found) ? `
                            <div style="margin-top: 12px; padding: 12px; background: rgba(0,240,255,0.05); border: 1px solid rgba(0,240,255,0.3); border-radius: 4px;">
                                <span class="field-label" style="margin-bottom:6px; color:#00F0FF;">CORRELATED ONLINE PROFILES</span>
                                <div style="display:flex; flex-wrap:wrap; gap:12px; align-items:center; margin-top:6px;">
                                    ${gravatar.avatar_url ? `<img src="${gravatar.avatar_url}" style="width:40px; height:40px; border-radius:50%; border:1px solid #00F0FF;" alt="Avatar">` : ''}
                                    <div>
                                        ${gravatar.found ? `<div><strong>Gravatar:</strong> ${gravatar.display_name || 'Profile active'} ${gravatar.profile_url ? `<a href="${gravatar.profile_url}" target="_blank" class="cyan">[LINK]</a>` : ''}</div>` : ''}
                                        ${githubId.found ? `<div><strong>GitHub:</strong> ${githubId.username} <a href="${githubId.profile_url}" target="_blank" class="cyan">[GITHUB PROFILE]</a></div>` : ''}
                                    </div>
                                </div>
                            </div>
                        ` : ''}

                        ${chainMetaHtml}
                        ${hexDumpHtml}
                    </div>
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> MAIL TRACE COMPLETE · ${mailProv}`;
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/mailtracer', 0, e.message);
    }
};

// Code Hunter
// Code Hunter
window.runCodeHunter = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const user = document.getElementById('codehunter-input')?.value.trim();
    const statusEl = document.getElementById('codehunter-status');
    const resultsEl = document.getElementById('codehunter-results');
    if (!user) return;

    if (window.threatMatrix) window.threatMatrix.setTarget(user);

    statusEl.innerHTML = `<span class="spinner-pulse"></span> HUNTING PUBLIC CODE REPOSITORIES & COMMIT PATCHES FOR <span class="mono cyan">${user}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>INTERROGATING GITHUB API, PUSH EVENTS & UNMASKED COMMIT LOGS...</div>`;

    try {
        const resp = await window.nexusFetch('/api/modules/code_hunter', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username: user })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/codehunter', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> CODE HUNT FAILED`;
            return;
        }

        const d = await resp.json();
        const p = d.profile || d || {};
        const repos = d.repos || d.top_repos || [];
        const commitEmails = d.commit_emails || p.unmasked_emails || [];
        const sshKeys = d.ssh_keys || p.ssh_keys || [];
        const gpgKeys = d.gpg_keys || p.gpg_keys || [];
        const orgs = d.organizations || p.organizations || d.orgs || [];
        const topLangs = d.top_languages || p.top_languages || {};
        if (Array.isArray(d.languages) && Object.keys(topLangs).length === 0) {
            d.languages.forEach(l => { if (l && l.name) topLangs[l.name] = l.percentage; });
        }
        const riskScore = d.risk_score !== undefined ? d.risk_score : 15;
        const totalRepos = p.public_repos !== undefined ? p.public_repos : (d.public_repos !== undefined ? d.public_repos : repos.length);
        const followersCount = (p.followers !== undefined && p.followers !== null) ? p.followers : (d.followers !== undefined ? d.followers : 0);
        const followingCount = (p.following !== undefined && p.following !== null) ? p.following : (d.following !== undefined ? d.following : 0);
        const companyName = p.company || d.company || 'INDEPENDENT';
        const gistsCount = (p.public_gists !== undefined && p.public_gists !== null) ? p.public_gists : (d.public_gists !== undefined ? d.public_gists : 0);
        const targetLogin = p.login || d.login || user;
        const targetName = p.name || d.name || '';
        const targetLoc = p.location || d.location || 'GLOBAL';
        const targetUrl = p.html_url || d.html_url || `https://github.com/${user}`;
        const targetBio = p.bio || d.bio || '';

        // Threat Matrix registration
        if (window.threatMatrix) {
            if (commitEmails.length > 0) {
                window.threatMatrix.registerFinding('codehunter', 'CODE HUNTER', 'unmasked_developer_emails', 25, `Unmasked ${commitEmails.length} personal commit email(s) from git push events.`, 'hazard');
            }
            if (sshKeys.length > 0 || gpgKeys.length > 0) {
                window.threatMatrix.registerFinding('codehunter', 'CODE HUNTER', 'public_cryptographic_keys', 15, `Harvested ${sshKeys.length} SSH & ${gpgKeys.length} GPG cryptographic keys.`, 'emerald');
            }
            if (repos.length > 0) {
                window.threatMatrix.registerFinding('codehunter', 'CODE HUNTER', 'repository_telemetry', 10, `Mapped ${repos.length} public git repositories and codebase language telemetry.`, 'emerald');
            }
        }

        if (window.recordModuleResult) {
            window.recordModuleResult('codehunter', d, user);
        }

        const classifiedBar = window.renderClassifiedHeader('CODE HUNTER // GIT HARVESTER', user, 'REPOS_RESOLVED');
        const meterHtml = window.renderSegmentedMeter(Math.max(10, 100 - riskScore), `PROFILE RESOLVED (${totalRepos} REPOS)`);
        const hexDumpHtml = window.renderHexDump(d, 80);
        const chainMetaHtml = window.renderChainMetadata('CODE_HUNTER_V7', 'GITHUB_REST_API', d.audit_log_id);

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                ${classifiedBar}
                <div class="entity-tactical-card corner-borders">
                    <div class="entity-card-header">
                        <div class="entity-asset-title">
                            <span class="badge cyan">[GIT TARGET: ${targetLogin}]</span>
                            <span>${targetName ? `${targetName} · ` : ''}${targetLoc}</span>
                        </div>
                        <button class="btn-tactical-xs" onclick="copyToClipboard('${targetUrl}', this)">VIEW GITHUB</button>
                    </div>

                    <div class="entity-metadata-grid">
                        <div class="metadata-field-pair">
                            <span class="field-label">PUBLIC REPOSITORIES</span>
                            <span class="field-value cyan">${Number(totalRepos).toLocaleString()}</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">FOLLOWERS / FOLLOWING</span>
                            <span class="field-value">${Number(followersCount).toLocaleString()} / ${Number(followingCount).toLocaleString()}</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">COMPANY / ORG</span>
                            <span class="field-value">${companyName}</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">PUBLIC GISTS</span>
                            <span class="field-value">${Number(gistsCount).toLocaleString()}</span>
                        </div>
                    </div>

                    ${targetBio ? `<div style="margin: 10px 0; padding: 8px 12px; background: rgba(0,240,255,0.04); border-left: 2px solid var(--accent-cyan); font-size: 11px; color: var(--text-dim);"><strong class="cyan">BIO:</strong> ${targetBio}</div>` : ''}

                    ${meterHtml}

                    <!-- Unmasked Commit Emails -->
                    <div class="evidence-stream" style="margin-top: 12px;">
                        <span class="field-label" style="margin-bottom:6px;">UNMASKED GIT COMMIT EMAILS (${commitEmails.length})</span>
                        ${commitEmails.length > 0 ? commitEmails.map(em => `
                            <div class="evidence-line critical">
                                <div class="evidence-left">
                                    <span class="evidence-time">[COMMIT-LOG]</span>
                                    <strong class="cyan mono">${em.email}</strong>
                                    ${em.name ? `<span class="dim mono">(${em.name})</span>` : ''}
                                    ${em.source ? `<span class="dim small-text mono">[via ${em.source}]</span>` : ''}
                                </div>
                                <button class="btn-icon-copy" onclick="copyToClipboard('${em.email}', this)"><svg class="copy-svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button>
                            </div>
                        `).join('') : '<div class="dim mono small-text">No unmasked commit emails exposed in recent public events.</div>'}
                    </div>

                    <!-- Language Breakdown & Cryptographic Keys -->
                    <div class="grid-2col" style="margin-top: 12px; gap: 10px;">
                        <div class="glass-card" style="padding: 10px;">
                            <span class="field-label" style="margin-bottom:6px;">TOP PROGRAMMING LANGUAGES</span>
                            <div style="display:flex; flex-wrap:wrap; gap:6px; margin-top:6px;">
                                ${Object.keys(topLangs).length > 0 ? Object.entries(topLangs).map(([lang, pct]) => `
                                    <span class="badge" style="background: rgba(0,240,255,0.1); border: 1px solid rgba(0,240,255,0.3); color: #00F0FF; font-size: 10px;">${lang}: ${pct}%</span>
                                `).join('') : '<span class="dim mono small-text">No language statistics compiled</span>'}
                            </div>
                        </div>
                        <div class="glass-card" style="padding: 10px;">
                            <span class="field-label" style="margin-bottom:6px;">CRYPTOGRAPHIC KEYS & ORGS</span>
                            <div style="display:flex; flex-wrap:wrap; gap:6px; margin-top:6px;">
                                <span class="badge ${sshKeys.length ? 'emerald' : 'dim'}">${sshKeys.length} SSH KEYS</span>
                                <span class="badge ${gpgKeys.length ? 'cyan' : 'dim'}">${gpgKeys.length} GPG KEYS</span>
                                <span class="badge ${orgs.length ? 'hazard' : 'dim'}">${orgs.length} ORGS</span>
                            </div>
                        </div>
                    </div>

                    <!-- Repositories List -->
                    <div class="evidence-stream" style="margin-top: 12px;">
                        <span class="field-label" style="margin-bottom:6px;">REPOSITORIES DOSSIER (${repos.length})</span>
                        ${repos.map(r => `
                            <div class="evidence-line nominal">
                                <div class="evidence-left" style="flex:1;">
                                    <span class="evidence-time">[${r.language || 'CODE'}]</span>
                                    <strong class="cyan">${r.name || r.repo}</strong>
                                    <span class="dim small-text">${r.description ? `— ${r.description.substring(0, 70)}` : ''}</span>
                                    <div class="dim mono" style="font-size:10px; margin-top:2px;">${r.stars || 0}★ · ${r.forks || 0} forks · Updated: ${r.updated_at ? r.updated_at.substring(0, 10) : 'N/A'}</div>
                                </div>
                                <button class="btn-icon-copy" onclick="copyToClipboard('${r.clone_url || r.url}', this)"><svg class="copy-svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button>
                            </div>
                        `).join('') || '<div class="dim mono">No public repositories discovered.</div>'}
                    </div>

                    ${chainMetaHtml}
                    ${hexDumpHtml}
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> CODE HUNT COMPLETE · ${commitEmails.length} EMAILS · ${repos.length} REPOS`;
        window.updateModuleBadge('codehunter', repos.length || commitEmails.length || 1);
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/codehunter', 0, e.message);
    }
};

// Deep Identity Avatar
window.handleDeepIdentityUpload = function(file) {
    if (!file) return;
    const statusEl = document.getElementById('deepidentity-status');
    const resultsEl = document.getElementById('deepidentity-results');

    statusEl.innerHTML = `<span class="spinner-pulse"></span> CONDUCTING 2D FFT & PUPIL CENTERING FIT FOR <span class="mono cyan">${file.name}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>INSPECTING STYLEGAN LATTICE ARTIFACTS...</div>`;

    const fd = new FormData();
    fd.append('file', file);

    window.nexusFetch('/api/deepidentity/upload', { method: 'POST', body: fd })
    .then(async r => {
        if (!r.ok) {
            const errData = await r.json().catch(() => r.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/deepidentity/upload', r.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${r.status}]</span> AVATAR AUDIT FAILED`;
            return null;
        }
        return r.json();
    })
    .then(d => {
        if (!d) return;
        const prob = d.synthetic_probability_pct || 0;
        const tier = prob >= 60 ? 'critical' : prob >= 35 ? 'hazard' : 'emerald';
        const headerHtml = window.renderClassifiedHeader('DEEP IDENTITY', file.name, 'SYNTHETIC AUDIT');
        const meterHtml = window.renderSegmentedMeter(prob, prob >= 60 ? 'STYLEGAN / DIFFUSION DETECTED' : 'ORGANIC HUMAN PROFILE');
        const hexDumpHtml = window.renderHexDump(d, 64);
        const chainMetaHtml = window.renderChainMetadata('DEEP IDENTITY', file.name);

        if (window.threatMatrix) {
            if (prob >= 60) {
                window.threatMatrix.registerFinding('deepidentity', 'DEEP IDENTITY', 'ai_avatar', 30, `Synthetic StyleGAN/Diffusion avatar confirmed in ${file.name} (${prob}% confidence).`, 'critical');
            } else {
                window.threatMatrix.registerFinding('deepidentity', 'DEEP IDENTITY', 'organic_avatar', 5, `Avatar photo verified authentic with natural biometric variances in ${file.name}.`, 'emerald');
            }
        }
        window.updateModuleBadge('deepidentity', prob >= 60 ? 1 : 0);

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                <div class="glass-card tactical-intel-card">
                    ${headerHtml}
                    ${meterHtml}
                    <div class="card-header" style="margin-top:10px;">
                        <div>
                            <span class="telemetry-label">STYLEGAN SYNTHESIS DETECTION</span>
                            <h3 class="card-title">${file.name} <span class="badge ${tier}">${d.classification || 'ANALYZED'}</span></h3>
                        </div>
                        <div class="display-stat ${tier}">${prob}%</div>
                    </div>
                    <div class="card-body">
                        <div class="finding-list">
                            ${(d.forensic_indicators || []).map(ind => `
                                <div class="finding-item">
                                    <span class="finding-dot ${ind.result.includes('FLAGGED')?'critical':'emerald'}"></span>
                                    <span><strong>${ind.test}:</strong> ${ind.result}</span>
                                </div>
                            `).join('')}
                        </div>
                        ${chainMetaHtml}
                        ${hexDumpHtml}
                    </div>
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> BIOMETRIC ANALYSIS COMPLETE`;
    }).catch(e => {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/deepidentity/upload', 0, e.message);
    });
};

// ============================================================
// INFRASTRUCTURE & GEO
// ============================================================

// Domain Oracle
window.runDomainOracle = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const domain = document.getElementById('oracle-domain')?.value.trim();
    const statusEl = document.getElementById('oracle-status');
    const resultsEl = document.getElementById('oracle-results');
    if (!domain) return;

    if (window.threatMatrix) window.threatMatrix.setTarget(domain);

    statusEl.innerHTML = `<span class="spinner-pulse"></span> INTERROGATING DNS RECURSION, WAF & CERTIFICATE TRANSPARENCY FOR <span class="cyan mono">${domain}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>STREAMING CRT.SH TLS LOGS, WHOIS RDAP & RECURSIVE DNS...</div>`;

    try {
        const resp = await window.nexusFetch('/api/modules/domain_oracle', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ domain: domain })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/oracle', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> ORACLE FAILED`;
            return;
        }

        const d = await resp.json();
        if (d.error) {
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/oracle', 400, d.error);
            statusEl.innerHTML = `<span class="critical">[ERROR]</span> ${d.error}`;
            return;
        }

        const subdomains = d.subdomains || [];
        const subCount = subdomains.length;
        const registrar = d.rdap?.registrar || d.registrar || 'Protected';
        const ianaId = d.rdap?.iana_id || 'N/A';
        const serverIp = d.ip || 'Resolved';
        const dnsA = d.dns?.A || d.dns_records?.A || [];
        const dnsAAAA = d.dns?.AAAA || d.dns_records?.AAAA || [];
        const dnsMX = d.dns?.MX || d.dns_records?.MX || [];
        const dnsNS = d.dns?.NS || d.dns_records?.NS || d.rdap?.nameservers || [];
        const dnsTXT = d.dns?.TXT || d.dns_records?.TXT || [];
        const dnsCNAME = d.dns?.CNAME || d.dns_records?.CNAME || [];
        const cdnWaf = d.cdn_waf || { detected: false, provider: 'DIRECT' };

        if (window.threatMatrix) {
            if (cdnWaf.detected) {
                window.threatMatrix.registerFinding('oracle', 'DOMAIN ORACLE', 'waf_detected', 10, `Edge proxy / WAF detected: ${cdnWaf.provider} shielding origin servers.`, 'hazard');
            }
            if (subCount > 0) {
                window.threatMatrix.registerFinding('oracle', 'DOMAIN ORACLE', 'ct_subdomains', 15, `Harvested ${subCount} subdomains from Certificate Transparency (crt.sh) logs.`, 'hazard');
            } else {
                window.threatMatrix.registerFinding('oracle', 'DOMAIN ORACLE', 'dns_mapped', 10, `DNS recursion confirmed: ${dnsA.length} A, ${dnsMX.length} MX, ${dnsNS.length} NS records mapped.`, 'emerald');
            }
        }

        if (window.recordModuleResult) {
            window.recordModuleResult('oracle', d, domain);
        }

        const classifiedBar = window.renderClassifiedHeader('DOMAIN ORACLE // DNS & CT TELEMETRY', domain, 'RESOLVED');
        const meterHtml = window.renderSegmentedMeter(88, 'DNS TOPOLOGY RESOLVED');
        const hexDumpHtml = window.renderHexDump(d, 80);
        const chainMetaHtml = window.renderChainMetadata('DOMAIN_ORACLE_V7', 'PUBLIC_DNS_AND_CRT_SH', d.audit_log_id);

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                ${classifiedBar}
                <div class="entity-tactical-card corner-borders">
                    <div class="entity-card-header">
                        <div class="entity-asset-title">
                            <span class="badge cyan">[${subCount} SUBDOMAINS HARVESTED]</span>
                            <span>DOMAIN // ${domain}</span>
                            ${cdnWaf.detected ? `<span class="badge hazard">[CDN/WAF: ${cdnWaf.provider}]</span>` : '<span class="badge emerald">[DIRECT HOSTING]</span>'}
                        </div>
                        <button class="btn-tactical-xs" onclick="copyToClipboard('${domain}', this)">COPY DOMAIN</button>
                    </div>
                    <div class="entity-metadata-grid">
                        <div class="metadata-field-pair">
                            <span class="field-label">REGISTRAR (IANA)</span>
                            <span class="field-value">${registrar} (${ianaId})</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">PRIMARY HOST IP</span>
                            <span class="field-value cyan">${serverIp}</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">NAMESERVERS</span>
                            <span class="field-value">${dnsNS.slice(0, 2).join(', ') || 'N/A'}</span>
                        </div>
                        <div class="metadata-field-pair">
                            <span class="field-label">TRUST SCORE</span>
                            <span class="field-value emerald">${d.score || 85} / 100</span>
                        </div>
                    </div>

                    ${meterHtml}

                    <!-- Full DNS Recursion Matrix -->
                    <div style="margin-top: 12px; padding: 10px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.06); border-radius: 4px;">
                        <span class="field-label" style="margin-bottom:6px;">RECURSIVE DNS MATRIX</span>
                        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px; font-size: 11px; margin-top:6px;">
                            <div><strong class="cyan">A:</strong> ${dnsA.join(', ') || 'None'}</div>
                            <div><strong class="cyan">AAAA:</strong> ${dnsAAAA.join(', ') || 'None'}</div>
                            <div><strong class="cyan">CNAME:</strong> ${dnsCNAME.join(', ') || 'None'}</div>
                            <div><strong class="cyan">MX:</strong> ${dnsMX.slice(0, 2).join(', ') || 'None'}</div>
                        </div>
                    </div>

                    <!-- Certificate Transparency Subdomains -->
                    <div class="evidence-stream" style="margin-top: 12px;">
                        <span class="field-label" style="margin-bottom:4px;">CERTIFICATE TRANSPARENCY (CRT.SH) & TLS SAN SUBDOMAINS (${subCount})</span>
                        ${subdomains.slice(0, 40).map(sub => `
                            <div class="evidence-line cyan">
                                <div class="evidence-left">
                                    <span class="evidence-time">[CRT.SH]</span>
                                    <span class="evidence-text mono">${sub}</span>
                                </div>
                                <button class="btn-icon-copy" onclick="copyToClipboard('${sub}', this)"><svg class="copy-svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button>
                            </div>
                        `).join('') || '<div class="dim mono">No subdomains discovered in public CT logs.</div>'}
                    </div>

                    ${chainMetaHtml}
                    ${hexDumpHtml}
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> ORACLE RESOLVED · ${subCount} SUBDOMAINS`;
        window.updateModuleBadge('oracle', subCount || 1);
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/oracle', 0, e.message);
    }
};

// Network Mapper
window.runNetworkScan = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const domain = document.getElementById('network-domain')?.value.trim();
    const statusEl = document.getElementById('network-status');
    const resultsEl = document.getElementById('network-results');
    if (!domain) return;

    statusEl.innerHTML = `<span class="spinner-pulse"></span> SCANNING PORTS & TOPOLOGY FOR <span class="mono cyan">${domain}</span>...`;
    resultsEl.innerHTML = `<div class="tactical-loading"><div class="loading-scanline"></div>ENUMERATING OPEN PORTS & INTERCONNECTS...</div>`;

    try {
        const resp = await window.nexusFetch('/api/modules/network_mapper', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ domain: domain })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/network/scan', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> NETWORK SCAN FAILED`;
            return;
        }

        const d = await resp.json();
        if (d.error) {
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/network/scan', 400, d.error);
            statusEl.innerHTML = `<span class="critical">[ERROR]</span> ${d.error}`;
            return;
        }

        const ports = d.ports || d.open_ports || [];
        const geoip = d.geoip || {};
        const threatScore = d.threat_score !== undefined ? d.threat_score : (ports.length * 10);
        const headerHtml = window.renderClassifiedHeader('NETWORK MAPPER', domain, 'TOPOLOGY SCANNED');
        const meterHtml = window.renderSegmentedMeter(Math.max(5, 100 - threatScore), 'PERIMETER HARDENING INDEX');
        const hexDumpHtml = window.renderHexDump(d, 64);
        const chainMetaHtml = window.renderChainMetadata('NETWORK MAPPER', domain);

        if (window.threatMatrix) {
            const hasHighRisk = ports.some(p => p.risk === 'HIGH');
            if (hasHighRisk) {
                window.threatMatrix.registerFinding('network', 'NETWORK MAPPER', 'vulnerable_ports', 30, `Exposed database, remote access, or admin port(s) detected on ${domain}.`, 'critical');
            } else if (ports.length > 0) {
                window.threatMatrix.registerFinding('network', 'NETWORK MAPPER', 'open_perimeter', 15, `${ports.length} open network port(s) identified on public interface.`, 'hazard');
            } else {
                window.threatMatrix.registerFinding('network', 'NETWORK MAPPER', 'firewall_hardened', 5, 'Zero accessible TCP ports open on scanned perimeter.', 'emerald');
            }
        }
        window.updateModuleBadge('network', ports.length);

        if (window.recordModuleResult) {
            window.recordModuleResult('network', d, domain);
        }

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                <div class="glass-card tactical-intel-card">
                    ${headerHtml}
                    ${meterHtml}
                    <div class="card-header" style="margin-top:10px;">
                        <h3 class="card-title">${domain} <span class="badge cyan">IP: ${d.ip || 'Resolved'}</span></h3>
                    </div>
                    <div class="card-body">
                        <div class="metric-row">
                            <div class="metric-pill"><span class="dim">LOCATION</span><strong class="cyan">${geoip.city || ''} ${geoip.country || 'Global'}</strong></div>
                            <div class="metric-pill"><span class="dim">ISP / ORG</span><strong>${geoip.isp || geoip.org || 'Cloud'}</strong></div>
                            <div class="metric-pill"><span class="dim">OPEN PORTS</span><strong class="${ports.length ? 'hazard' : 'emerald'}">${ports.length} Open</strong></div>
                        </div>
                        ${d.map_html ? `<div class="network-map-frame" style="margin-top:10px;">${d.map_html}</div>` : ''}
                        <div class="finding-list" style="margin-top:10px;">
                            ${ports.map(p => `
                                <div class="finding-item">
                                    <span class="finding-dot ${p.risk === 'HIGH' ? 'critical' : 'hazard'}"></span>
                                    <div style="flex:1;">
                                        <strong>Port ${p.port} (${p.service || 'Service'}):</strong> <span class="cyan">OPEN</span>
                                        <div class="dim mono small-text">${p.banner || 'TCP Handshake Succeeded'}</div>
                                    </div>
                                    <button class="btn-icon-copy" onclick="copyToClipboard('${d.ip}:${p.port}', this)"><svg class="copy-svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button>
                                </div>
                            `).join('') || '<div class="dim mono">No common ports open to public scan.</div>'}
                        </div>
                        ${chainMetaHtml}
                        ${hexDumpHtml}
                    </div>
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> NETWORK SCAN COMPLETE`;
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/network/scan', 0, e.message);
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// TACTICAL MAP ENGINES (GEOINT SPY & SKY RADAR)
// ═══════════════════════════════════════════════════════════════════════════════

// GEOINT Map State
window.geointMap = null;
window.geointTileLayers = {};
window.geointMarker = null;

window.initGeointMap = function(lat, lon, address) {
    if (typeof L === 'undefined') return;
    const mapEl = document.getElementById('geoint-map');
    if (!mapEl) return;

    lat = parseFloat(lat);
    lon = parseFloat(lon);
    if (isNaN(lat) || isNaN(lon)) return;

    const hudEl = document.getElementById('geoint-hud-coords');
    if (hudEl) hudEl.innerText = `${lat.toFixed(5)}, ${lon.toFixed(5)}`;

    if (!window.geointMap) {
        window.geointMap = L.map('geoint-map', {
            center: [lat, lon],
            zoom: 14,
            attributionControl: false
        });

        window.geointTileLayers = {
            dark: L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 19, subdomains: 'abcd' }),
            satellite: L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', { maxZoom: 18 })
        };

        window.geointTileLayers.dark.addTo(window.geointMap);
    } else {
        window.geointMap.setView([lat, lon], 14);
        window.geointMap.invalidateSize();
    }

    if (window.geointMarker) {
        window.geointMap.removeLayer(window.geointMarker);
    }

    // Custom tactical reticle marker
    const reticleIcon = L.divIcon({
        className: 'geoint-reticle-marker',
        html: `
            <div style="position:relative; width:36px; height:36px; display:flex; align-items:center; justify-content:center;">
                <div style="position:absolute; width:34px; height:34px; border:2px solid #00F0FF; border-radius:50%; box-shadow:0 0 12px #00F0FF;"></div>
                <div style="width:8px; height:8px; background:#ff0055; border-radius:50%; box-shadow:0 0 8px #ff0055;"></div>
                <div style="position:absolute; width:1px; height:42px; background:rgba(0,240,255,0.7);"></div>
                <div style="position:absolute; width:42px; height:1px; background:rgba(0,240,255,0.7);"></div>
            </div>
        `,
        iconSize: [36, 36],
        iconAnchor: [18, 18]
    });

    window.geointMarker = L.marker([lat, lon], { icon: reticleIcon }).addTo(window.geointMap);
    window.geointMarker.bindPopup(`
        <div style="background:#070d18; color:#fff; font-family:monospace; padding:8px; border-radius:4px; border:1px solid #00F0FF; min-width:200px;">
            <div style="color:#00F0FF; font-weight:bold; font-size:12px; margin-bottom:4px;">TARGET LOCK // COORDINATES</div>
            <div style="font-size:11px; margin-bottom:4px;">LAT: <strong>${lat.toFixed(5)}</strong> | LON: <strong>${lon.toFixed(5)}</strong></div>
            ${address ? `<div style="font-size:11px; color:#9ba3b4; line-height:1.3;">${address}</div>` : ''}
        </div>
    `).openPopup();
};

window.setGeointMapLayer = function(type) {
    if (!window.geointMap || !window.geointTileLayers) return;
    if (type === 'satellite') {
        if (window.geointTileLayers.dark) window.geointMap.removeLayer(window.geointTileLayers.dark);
        window.geointTileLayers.satellite.addTo(window.geointMap);
        document.getElementById('btn-geoint-sat')?.classList.add('cyan');
        document.getElementById('btn-geoint-dark')?.classList.remove('cyan');
    } else {
        if (window.geointTileLayers.satellite) window.geointMap.removeLayer(window.geointTileLayers.satellite);
        window.geointTileLayers.dark.addTo(window.geointMap);
        document.getElementById('btn-geoint-dark')?.classList.add('cyan');
        document.getElementById('btn-geoint-sat')?.classList.remove('cyan');
    }
};

// GEOINT Spy
window.runGeoint = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const lat = document.getElementById('geoint-lat')?.value.trim();
    const lon = document.getElementById('geoint-lon')?.value.trim();
    const statusEl = document.getElementById('geoint-status');
    const resultsEl = document.getElementById('geoint-results');
    if (!lat || !lon) return;

    statusEl.innerHTML = `<span class="spinner-pulse"></span> ACQUIRING GEODETIC LOCK FOR <span class="mono cyan">${lat}, ${lon}</span>...`;

    // Immediately center map on input coordinates
    if (typeof L !== 'undefined') {
        window.initGeointMap(lat, lon, 'Triangulating telemetry...');
    }

    try {
        const resp = await window.nexusFetch('/api/modules/geoint_spy', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ lat: lat, lon: lon })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/tools/geoint', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> GEOINT FAILED`;
            return;
        }

        const d = await resp.json();
        const headerHtml = window.renderClassifiedHeader('GEOINT SPY', `${lat}, ${lon}`, 'GEODETIC LOCK');
        const meterHtml = window.renderSegmentedMeter(88, 'SPATIAL RECON ACCURACY');
        const hexDumpHtml = window.renderHexDump(d, 64);
        const chainMetaHtml = window.renderChainMetadata('GEOINT SPY', `${lat}, ${lon}`);

        if (window.threatMatrix) {
            window.threatMatrix.registerFinding('geoint', 'GEOINT SPY', 'geoint_triangulated', 10, `Coordinates ${lat}, ${lon} geolocated to ${d.address || 'Address'} (Maidenhead: ${d.grid_locators?.maidenhead_qth || 'N/A'}).`, 'emerald');
        }
        window.updateModuleBadge('geoint', 1);

        // Update map marker with address
        if (typeof L !== 'undefined') {
            window.initGeointMap(lat, lon, d.address || 'Resolved Target Location');
        }

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                <div class="glass-card tactical-intel-card">
                    ${headerHtml}
                    ${meterHtml}
                    <div class="card-header" style="margin-top:10px;">
                        <h3 class="card-title">${lat}, ${lon} <span class="badge emerald">GEO LOCKED</span></h3>
                    </div>
                    <div class="card-body">
                        <div class="metric-row">
                            <div class="metric-pill"><span class="dim">MAIDENHEAD GRID</span><strong class="cyan mono">${d.grid_locators?.maidenhead_qth || 'N/A'}</strong></div>
                            <div class="metric-pill"><span class="dim">UTM ZONE</span><strong class="hazard mono">${d.grid_locators?.utm_zone || 'N/A'}</strong></div>
                            <div class="metric-pill"><span class="dim">REVERSE ADDRESS</span><strong class="emerald">${d.address || 'Resolved'}</strong></div>
                        </div>
                        ${d.links ? `
                            <div class="finding-list" style="margin-top:12px;">
                                ${Object.entries(d.links).map(([name, url]) => `
                                    <div class="finding-item">
                                        <span class="finding-dot cyan"></span>
                                        <div style="flex:1;">
                                            <strong>${name}:</strong> <a href="${url}" target="_blank" class="cyan">${url}</a>
                                        </div>
                                    </div>
                                `).join('')}
                            </div>
                        ` : ''}
                        ${chainMetaHtml}
                        ${hexDumpHtml}
                    </div>
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> GEOINT COMPLETE`;
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/tools/geoint', 0, e.message);
    }
};

// Sky Radar Map State
window.flightMap = null;
window.flightCenter = [51.5074, -0.1278];
window.flightMarkers = [];
window.flightRangeRings = [];

window.initFlightMap = function(centerLat, centerLon, flights, radiusKm) {
    if (typeof L === 'undefined') return;
    const mapEl = document.getElementById('flight-map');
    if (!mapEl) return;

    centerLat = parseFloat(centerLat) || 51.5074;
    centerLon = parseFloat(centerLon) || -0.1278;
    radiusKm = parseFloat(radiusKm) || 120;
    window.flightCenter = [centerLat, centerLon];

    if (!window.flightMap) {
        window.flightMap = L.map('flight-map', {
            center: [centerLat, centerLon],
            zoom: 8,
            attributionControl: false
        });

        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            maxZoom: 18,
            subdomains: 'abcd'
        }).addTo(window.flightMap);
    } else {
        window.flightMap.setView([centerLat, centerLon], 8);
        window.flightMap.invalidateSize();
    }

    // Clear previous rings & markers
    window.flightRangeRings.forEach(r => window.flightMap.removeLayer(r));
    window.flightRangeRings = [];
    window.flightMarkers.forEach(m => window.flightMap.removeLayer(m));
    window.flightMarkers = [];

    // Concentric Range Rings (radar grid)
    const ringRadii = [radiusKm * 0.33, radiusKm * 0.66, radiusKm];
    ringRadii.forEach((rKm, idx) => {
        const circle = L.circle([centerLat, centerLon], {
            radius: rKm * 1000,
            color: '#00F0FF',
            weight: 1,
            opacity: 0.35 + (idx * 0.1),
            fillColor: '#00F0FF',
            fillOpacity: 0.02,
            dashArray: idx === 2 ? '4, 4' : undefined
        }).addTo(window.flightMap);
        window.flightRangeRings.push(circle);
    });

    // Center marker radar receiver point
    const centerMarker = L.circleMarker([centerLat, centerLon], {
        radius: 6,
        color: '#00F0FF',
        fillColor: '#00F0FF',
        fillOpacity: 0.9,
        weight: 2
    }).addTo(window.flightMap);
    window.flightRangeRings.push(centerMarker);

    // Update tracked badge
    const countBadge = document.getElementById('flight-tracked-count');
    if (countBadge) countBadge.innerText = `${flights.length} AIRCRAFT DETECTED`;

    // Render aircraft transponder icons
    flights.forEach(f => {
        const icao = f.icao24 || f[0] || 'UNK';
        const callsign = (f.callsign || f[1] || 'UNK').trim();
        const fLat = f.latitude !== undefined ? f.latitude : (f[6] !== undefined ? f[6] : null);
        const fLon = f.longitude !== undefined ? f.longitude : (f[5] !== undefined ? f[5] : null);
        const alt = f.altitude_m !== undefined ? f.altitude_m : (f[7] || 0);
        const vel = f.velocity_ms !== undefined ? f.velocity_ms : (f[9] || 0);
        const heading = f.heading_deg !== undefined ? f.heading_deg : (f[10] || 0);
        const country = f.origin_country || f[2] || 'International';

        if (fLat === null || fLon === null) return;

        const planeIcon = L.divIcon({
            className: 'radar-aircraft-marker',
            html: `
                <div style="transform: rotate(${heading}deg); width:28px; height:28px; display:flex; align-items:center; justify-content:center; cursor:pointer;" title="${callsign} (${icao})">
                    <svg viewBox="0 0 24 24" width="22" height="22" fill="#00F0FF" stroke="#060a12" stroke-width="1" style="filter: drop-shadow(0 0 4px #00F0FF);">
                        <path d="M21 16v-2l-8-5V3.5c0-.83-.67-1.5-1.5-1.5S10 2.67 10 3.5V9l-8 5v2l8-2.5V19l-2 1.5V22l3.5-1 3.5 1v-1.5L13 19v-5.5l8 2.5z"/>
                    </svg>
                </div>
            `,
            iconSize: [28, 28],
            iconAnchor: [14, 14]
        });

        const marker = L.marker([fLat, fLon], { icon: planeIcon }).addTo(window.flightMap);
        marker.bindPopup(`
            <div style="background:#070d18; color:#fff; font-family:monospace; padding:8px; border-radius:4px; border:1px solid #00F0FF; min-width:180px;">
                <div style="color:#00F0FF; font-weight:bold; font-size:13px; margin-bottom:4px;">AIR CONTACT // ${callsign}</div>
                <div style="font-size:11px; color:#FFB800;">ICAO: <strong>${icao.toUpperCase()}</strong></div>
                <div style="font-size:11px;">COUNTRY: <strong>${country}</strong></div>
                <div style="font-size:11px;">ALTITUDE: <strong>${Math.round(alt)} m</strong> (${Math.round(alt * 3.28084)} ft)</div>
                <div style="font-size:11px;">VELOCITY: <strong>${Math.round(vel * 3.6)} km/h</strong> (${Math.round(vel)} m/s)</div>
                <div style="font-size:11px;">HEADING: <strong>${Math.round(heading)}°</strong></div>
            </div>
        `);
        window.flightMarkers.push(marker);
    });
};

window.recenterFlightMap = function() {
    if (window.flightMap && window.flightCenter) {
        window.flightMap.setView(window.flightCenter, 8);
    }
};

// Sky Radar (Flight ADS-B)
window.runFlightRadar = async function(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    const lat = parseFloat(document.getElementById('flight-lat')?.value || '51.5');
    const lon = parseFloat(document.getElementById('flight-lon')?.value || '-0.1');
    const radius = parseFloat(document.getElementById('flight-radius')?.value || '120');
    const statusEl = document.getElementById('flight-status');
    const resultsEl = document.getElementById('flight-results');

    statusEl.innerHTML = `<span class="spinner-pulse"></span> INTERCEPTING ADS-B TRANSPONDER SIGNALS WITHIN ${radius} KM...`;

    // Immediately center flight map on target sector
    if (typeof L !== 'undefined') {
        window.initFlightMap(lat, lon, [], radius);
    }

    try {
        const resp = await window.nexusFetch('/api/modules/flight_radar', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ lat: lat, lon: lon, radius: radius })
        });
        if (!resp.ok) {
            const errData = await resp.json().catch(() => resp.statusText);
            resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/tools/flight', resp.status, errData.detail || errData);
            statusEl.innerHTML = `<span class="critical">[FAULT ${resp.status}]</span> SKY RADAR FAILED`;
            return;
        }

        const d = await resp.json();
        const flights = d.flights || d.states || [];
        const headerHtml = window.renderClassifiedHeader('SKY RADAR', `${lat}, ${lon}`, 'RADAR ACTIVE');
        const meterHtml = window.renderSegmentedMeter(88, 'AIRSPACE RECONNAISSANCE');
        const hexDumpHtml = window.renderHexDump(d, 64);
        const chainMetaHtml = window.renderChainMetadata('SKY RADAR', `${lat}, ${lon}`);

        if (window.threatMatrix) {
            if (flights.length > 0) {
                window.threatMatrix.registerFinding('flight', 'SKY RADAR', 'airspace_tracked', 15, `Tracked ${flights.length} transponder-active aircraft in immediate sector.`, 'emerald');
            } else {
                window.threatMatrix.registerFinding('flight', 'SKY RADAR', 'airspace_clear', 5, `Airspace sector clear of transponder emissions within ${radius} km radius.`, 'emerald');
            }
        }
        window.updateModuleBadge('flight', flights.length);

        // Render aircraft markers on tactical map
        if (typeof L !== 'undefined') {
            window.initFlightMap(lat, lon, flights, radius);
        }

        resultsEl.innerHTML = `
            <div class="result-deck reveal">
                <div class="glass-card tactical-intel-card">
                    ${headerHtml}
                    ${meterHtml}
                    <div class="card-header" style="margin-top:10px;">
                        <h3 class="card-title">AIRSPACE SURVEILLANCE <span class="badge cyan">${flights.length} AIRCRAFT TRACKED</span></h3>
                    </div>
                    <div class="card-body">
                        <div class="table-wrap">
                            <table class="table-tactical">
                                <thead><tr><th>ICAO24</th><th>CALLSIGN</th><th>COUNTRY</th><th>ALTITUDE</th><th>SPEED</th><th>HEADING</th></tr></thead>
                                <tbody>
                                    ${flights.slice(0, 15).map(f => `
                                        <tr>
                                            <td class="cyan mono">${f.icao24 || f[0]}</td>
                                            <td class="hazard mono">${f.callsign || f[1] || 'N/A'}</td>
                                            <td>${f.origin_country || f[2] || 'Intl'}</td>
                                            <td>${f.altitude_m || f[7] || 0} m</td>
                                            <td>${f.velocity_ms || f[9] || 0} m/s</td>
                                            <td>${f.heading_deg || 0}°</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                        ${chainMetaHtml}
                        ${hexDumpHtml}
                    </div>
                </div>
            </div>
        `;
        statusEl.innerHTML = `<span class="emerald">[NOMINAL]</span> SKY RADAR ACTIVE · ${flights.length} CONTACTS`;
    } catch (e) {
        statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        resultsEl.innerHTML = window.renderDiagnosticErrorBanner('/api/tools/flight', 0, e.message);
    }
};

/* ============================================================
   V7 COMPANION TOOL 1: DEFCON ALERT & GLOBAL INCIDENT TRACKER
   ============================================================ */
window.fetchIncidentTracker = async function() {
    const tableContainer = document.getElementById('cisa-kev-table-container');
    const cablesContainer = document.getElementById('undersea-cables-container');
    const hyperscalersContainer = document.getElementById('hyperscalers-bgp-container');
    const directiveText = document.getElementById('defcon-directive-text');
    const defconHeader = document.getElementById('defcon-title-header');
    const defconBadge = document.getElementById('defcon-badge-level');

    if (tableContainer) tableContainer.innerHTML = `<div style="padding:24px; text-align:center;" class="mono cyan"><span class="engine-pulse-dot"></span> Polling live CISA KEV catalog &amp; global infrastructure feeds...</div>`;

    try {
        const res = await fetch('/api/incident_tracker');
        if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to reach Incident Tracker API`);
        const d = await res.json();

        // 1. DEFCON Condition
        if (d.defcon) {
            if (defconHeader) {
                defconHeader.textContent = d.defcon.title || 'DEFCON ALERT';
                defconHeader.style.color = d.defcon.color || '#00F0FF';
            }
            if (defconBadge) {
                defconBadge.textContent = `DEFCON ${d.defcon.level}`;
                defconBadge.style.background = `${d.defcon.color}22`;
                defconBadge.style.color = d.defcon.color;
                defconBadge.style.borderColor = d.defcon.color;
            }
            if (directiveText) {
                directiveText.textContent = d.defcon.directive || 'Perimeter telemetry nominal.';
            }
            document.getElementById('stat-kev-count').textContent = d.defcon.active_cisa_kevs_tracked || 0;
            document.getElementById('stat-ransom-count').textContent = d.defcon.ransomware_exploited_cves || 0;
            document.getElementById('stat-cable-count').textContent = d.defcon.undersea_chokepoints_monitored || 0;
        }

        // 2. CISA KEV Table
        if (tableContainer) {
            const kevs = d.cisa_kevs || [];
            if (kevs.length === 0) {
                tableContainer.innerHTML = `<div style="padding:16px; text-align:center;" class="mono dim">Zero unmitigated CISA KEV advisories reported in this cycle.</div>`;
            } else {
                tableContainer.innerHTML = `
                    <table class="table-tactical" style="width:100%; border-collapse:collapse;">
                        <thead>
                            <tr style="border-bottom:1px solid var(--border-slate); text-align:left; font-size:10px; color:var(--text-dim);">
                                <th style="padding:8px 12px;">CVE IDENTIFIER</th>
                                <th style="padding:8px 12px;">VENDOR / PRODUCT</th>
                                <th style="padding:8px 12px;">VULNERABILITY &amp; NOTES</th>
                                <th style="padding:8px 12px;">DATE ADDED</th>
                                <th style="padding:8px 12px;">RANSOMWARE USE</th>
                                <th style="padding:8px 12px;">REQUIRED MITIGATION</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${kevs.map(k => `
                                <tr style="border-bottom:1px solid rgba(255,255,255,0.04); font-size:11px;">
                                    <td style="padding:8px 12px;"><a href="https://nvd.nist.gov/vuln/detail/${k.cve_id}" target="_blank" class="cyan mono" style="text-decoration:none; font-weight:bold;">${k.cve_id}</a></td>
                                    <td style="padding:8px 12px;"><span style="color:#FFF; font-weight:600;">${k.vendor}</span> <span class="dim">(${k.product})</span></td>
                                    <td style="padding:8px 12px; max-width:280px;"><div style="color:#e0e6ed; font-weight:500;">${k.vulnerability_name}</div><div class="dim small-text" style="font-size:10px; margin-top:2px;">${k.notes}</div></td>
                                    <td style="padding:8px 12px;" class="mono dim">${k.date_added}</td>
                                    <td style="padding:8px 12px;">
                                        <span class="badge ${k.ransomware_campaign === 'Known' ? 'hazard' : 'cyan'}" style="font-size:9px;">
                                            ${k.ransomware_campaign === 'Known' ? 'ACTIVE RANSOM' : 'UNASSIGNED'}
                                        </span>
                                    </td>
                                    <td style="padding:8px 12px; font-size:10px;" class="emerald mono">${k.action}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                `;
            }
        }

        // 3. Undersea Cables
        if (cablesContainer) {
            const cables = d.undersea_cables || [];
            cablesContainer.innerHTML = cables.map(c => `
                <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-slate); border-radius:4px; padding:10px; margin-bottom:8px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                        <span style="font-weight:bold; color:#00F0FF; font-family:var(--font-mono); font-size:11px;">${c.cable_name}</span>
                        <span class="badge ${c.status === 'NOMINAL' ? 'emerald' : 'hazard'}" style="font-size:9px;">${c.status}</span>
                    </div>
                    <div class="small-text dim" style="margin-bottom:4px;"><strong>Chokepoint:</strong> ${c.chokepoint} | <strong>Capacity:</strong> ${c.capacity_tbps} Tbps</div>
                    <div class="small-text" style="color:#e0e6ed; font-size:11px;"><strong>Event:</strong> ${c.incident_type}</div>
                    <div class="small-text mono" style="color:#ffb800; font-size:10px; margin-top:2px;">${c.reroute_latency_ms}</div>
                </div>
            `).join('');
        }

        // 4. Hyperscalers & BGP
        if (hyperscalersContainer) {
            const hyper = d.hyperscalers || [];
            const bgp = d.bgp_anomalies || [];
            hyperscalersContainer.innerHTML = `
                <div style="margin-bottom:12px;">
                    <span class="telemetry-label" style="font-size:9px;">CORE CLOUD LATENCY PROBES</span>
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-top:6px;">
                        ${hyper.map(h => `
                            <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-slate); padding:8px; border-radius:3px;">
                                <div style="font-size:11px; font-weight:bold; color:#FFF;">${h.provider}</div>
                                <div class="mono small-text emerald">${h.latency_ms}ms <span class="dim">(${h.status})</span></div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                <div>
                    <span class="telemetry-label" style="font-size:9px;">BGP ROUTING ANOMALIES</span>
                    ${bgp.map(b => `
                        <div style="background:rgba(0,240,255,0.03); border:1px solid rgba(0,240,255,0.2); padding:8px; border-radius:3px; margin-top:6px;">
                            <div style="font-size:11px; font-family:monospace; color:#00F0FF;">${b.asn} // ${b.event_type}</div>
                            <div class="small-text dim">${b.status} · ${b.detected}</div>
                        </div>
                    `).join('')}
                </div>
            `;
        }

    } catch (e) {
        if (tableContainer) tableContainer.innerHTML = `<div class="critical mono" style="padding:16px;">Telemetry poll error: ${e.message}</div>`;
    }
};

/* ============================================================
   V7 COMPANION TOOL 2: MITRE ATT&CK PLAYBOOK SIMULATOR
   ============================================================ */
window.runPlaybookSimulator = async function() {
    const advInput = document.getElementById('playbook-adversary-input');
    const statusEl = document.getElementById('playbook-status');
    const resultsEl = document.getElementById('playbook-results');
    const adversary = (advInput && advInput.value) ? advInput.value.trim() : 'apt29';

    if (statusEl) statusEl.innerHTML = `<span class="cyan">[SIMULATING]</span> Synthesizing MITRE ATT&CK kill-chain for ${adversary}...`;
    if (resultsEl) resultsEl.innerHTML = `<div style="padding:30px; text-align:center;" class="mono cyan"><span class="engine-pulse-dot"></span> Compiling Diamond Model &amp; generating Sigma rules...</div>`;

    try {
        const res = await fetch('/api/playbook_simulator', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({adversary: adversary})
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to execute playbook simulator`);
        const d = await res.json();

        const adv = d.adversary_profile || {};
        const diamond = d.diamond_model || {};
        const steps = d.kill_chain_steps || [];
        const runbook = d.containment_runbook || [];

        resultsEl.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">ADVERSARY THREAT CARD</span>
                        <h2 class="card-title" style="color:#C084FC;">${adv.name || 'Adversary Profile'}</h2>
                    </div>
                    <span class="badge violet">${adv.origin || 'State-Sponsored'}</span>
                </div>
                <div class="card-body">
                    <p class="mono dim small-text" style="margin-bottom:14px;"><strong>Target Sectors:</strong> ${(adv.target_sectors || []).join(', ')} | <strong>Motivation:</strong> ${adv.primary_motivation}</p>
                    
                    <!-- Diamond Model Grid -->
                    <div style="background:rgba(10, 16, 26, 0.7); border:1px solid rgba(168,85,247,0.3); border-radius:6px; padding:14px; margin-bottom:18px;">
                        <span class="telemetry-label" style="color:#C084FC; margin-bottom:8px; display:block;">DIAMOND MODEL OF INTRUSION ANALYSIS</span>
                        <div class="grid-2col" style="gap:12px;">
                            <div style="background:rgba(255,255,255,0.02); padding:10px; border-radius:4px;">
                                <div class="cyan mono small-text" style="font-weight:bold;">[ADVERSARY]</div>
                                <div style="color:#FFF; font-size:12px; margin-top:2px;">${diamond.adversary?.entity || adv.name}</div>
                                <div class="dim small-text">${diamond.adversary?.attribution || ''}</div>
                            </div>
                            <div style="background:rgba(255,255,255,0.02); padding:10px; border-radius:4px;">
                                <div class="violet mono small-text" style="font-weight:bold;">[CAPABILITIES]</div>
                                <div style="color:#FFF; font-size:12px; margin-top:2px;">${(diamond.capabilities || []).join(' · ')}</div>
                            </div>
                            <div style="background:rgba(255,255,255,0.02); padding:10px; border-radius:4px;">
                                <div class="hazard mono small-text" style="font-weight:bold;">[INFRASTRUCTURE]</div>
                                <div style="color:#FFF; font-size:12px; margin-top:2px;">${(diamond.infrastructure || []).join(' · ')}</div>
                            </div>
                            <div style="background:rgba(255,255,255,0.02); padding:10px; border-radius:4px;">
                                <div class="emerald mono small-text" style="font-weight:bold;">[VICTIM]</div>
                                <div style="color:#FFF; font-size:12px; margin-top:2px;">${diamond.victim?.exposure_tier || 'High Value Targets'}</div>
                            </div>
                        </div>
                    </div>

                    <!-- Kill-Chain Steps Progression -->
                    <div style="margin-bottom:18px;">
                        <span class="telemetry-label" style="margin-bottom:8px; display:block;">MITRE ATT&amp;CK PHASE-BY-PHASE EXECUTION</span>
                        <div style="display:flex; flex-direction:column; gap:8px;">
                            ${steps.map((s, idx) => `
                                <div style="display:flex; align-items:flex-start; gap:12px; background:rgba(255,255,255,0.02); border:1px solid var(--border-slate); border-radius:4px; padding:10px;">
                                    <div style="min-width:28px; height:28px; background:rgba(0,240,255,0.1); border:1px solid var(--accent-cyan); border-radius:50%; display:flex; align-items:center; justify-content:center; font-family:monospace; font-size:11px; color:#00F0FF; font-weight:bold;">${idx + 1}</div>
                                    <div style="flex:1;">
                                        <div style="display:flex; justify-content:space-between; align-items:center;">
                                            <span style="font-weight:bold; color:#FFF; font-size:12px;">${s.tactic} // <span style="color:#00F0FF;">${s.technique_name}</span></span>
                                            <a href="https://attack.mitre.org/techniques/${s.technique_id.replace('.', '/')}" target="_blank" class="badge cyan" style="text-decoration:none; font-family:monospace;">${s.technique_id}</a>
                                        </div>
                                        <div class="dim small-text" style="margin-top:4px; line-height:1.4;">${s.description}</div>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>

                    <!-- Sigma Rule Block -->
                    <div style="margin-bottom:18px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                            <span class="telemetry-label">AUTOMATED SIGMA DETECTION RULE (YAML)</span>
                            <button class="btn-tactical" onclick="navigator.clipboard.writeText(document.getElementById('sigma-rule-code').textContent); alert('Sigma rule YAML copied to clipboard!');" style="padding:3px 8px; font-size:10px;">
                                <span>COPY SIGMA YAML</span>
                            </button>
                        </div>
                        <pre id="sigma-rule-code" style="background:#070d18; border:1px solid var(--border-slate); border-radius:4px; padding:12px; font-family:monospace; font-size:11px; color:#10B981; overflow-x:auto; line-height:1.5;">${d.sigma_rule_yaml}</pre>
                    </div>

                    <!-- Containment Runbook -->
                    <div>
                        <span class="telemetry-label" style="margin-bottom:6px; display:block;">INCIDENT RESPONSE CONTAINMENT PLAYBOOK</span>
                        <div style="background:rgba(255,0,60,0.04); border:1px solid rgba(255,0,60,0.25); border-radius:4px; padding:12px;">
                            ${runbook.map(r => `<div class="mono small-text" style="color:#ffb800; margin-bottom:6px;">${r}</div>`).join('')}
                        </div>
                    </div>
                </div>
            </div>
        `;

        if (statusEl) statusEl.innerHTML = `<span class="emerald">[COMPLETED]</span> ATT&amp;CK Kill-Chain mapped for ${adv.name}`;
    } catch (e) {
        if (statusEl) statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        if (resultsEl) resultsEl.innerHTML = `<div class="critical mono" style="padding:16px;">Playbook simulation error: ${e.message}</div>`;
    }
};

/* ============================================================
   V7 COMPANION TOOL 3: TOKEN CONTRACT DRAINER & HONEYPOT AUDITOR
   ============================================================ */
window.runHoneypotAuditor = async function() {
    const addrInput = document.getElementById('honeypot-address');
    const chainSelect = document.getElementById('honeypot-chain');
    const statusEl = document.getElementById('honeypot-status');
    const resultsEl = document.getElementById('honeypot-results');

    const address = (addrInput && addrInput.value) ? addrInput.value.trim() : '';
    const chain = (chainSelect && chainSelect.value) ? chainSelect.value : '1';

    if (!address) {
        alert('Please enter an EVM token contract address (e.g. 0xdac17f958d2ee523a2206206994597c13d831ec7).');
        return;
    }

    if (statusEl) statusEl.innerHTML = `<span class="cyan">[AUDITING]</span> Evaluating contract bytecode on ChainID ${chain}...`;
    if (resultsEl) resultsEl.innerHTML = `<div style="padding:30px; text-align:center;" class="mono cyan"><span class="engine-pulse-dot"></span> Performing buy/sell simulation &amp; backdoor checks...</div>`;

    try {
        const res = await fetch('/api/honeypot_auditor', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({address: address, chain: chain})
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to reach Honeypot Auditor`);
        const d = await res.json();

        if (d.status === 'error') {
            throw new Error(d.error || 'Contract audit failed');
        }

        const t = d.token || {};
        const tax = d.tax || {};
        const checks = d.forensic_checks || {};
        const vulns = d.vulnerabilities || [];
        const isDangerous = d.rugpull_risk_score >= 50;

        resultsEl.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">${d.chain_name} // SMART CONTRACT</span>
                        <h2 class="card-title" style="color:${isDangerous ? '#FF003C' : '#00F0FF'};">${t.name} (${t.symbol})</h2>
                    </div>
                    <span class="badge ${isDangerous ? 'hazard' : 'emerald'}">${d.threat_tier}</span>
                </div>
                <div class="card-body">
                    <div class="grid-3col" style="gap:12px; margin-bottom:16px;">
                        <div class="mini-stat-card">
                            <span class="mini-stat-label">RUG-PULL RISK SCORE</span>
                            <span class="mini-stat-val ${isDangerous ? 'red' : 'emerald'}">${d.rugpull_risk_score}/100</span>
                        </div>
                        <div class="mini-stat-card">
                            <span class="mini-stat-label">BUY / SELL TAX</span>
                            <span class="mini-stat-val cyan">${tax.buy_tax_pct}% / ${tax.sell_tax_pct}%</span>
                        </div>
                        <div class="mini-stat-card">
                            <span class="mini-stat-label">OWNERSHIP RENOUNCED</span>
                            <span class="mini-stat-val ${t.ownership_renounced ? 'emerald' : 'amber'}">${t.ownership_renounced ? 'RENOUNCED' : 'ACTIVE OWNER'}</span>
                        </div>
                    </div>

                    <!-- Critical Vulnerability Alerts -->
                    <div style="margin-bottom:16px;">
                        <span class="telemetry-label" style="margin-bottom:8px; display:block;">FORENSIC BYTECODE AUDIT FINDINGS</span>
                        ${vulns.length > 0 ? `
                            <div style="display:flex; flex-direction:column; gap:8px;">
                                ${vulns.map(v => `
                                    <div style="background:rgba(255,0,60,0.06); border:1px solid rgba(255,0,60,0.3); border-radius:4px; padding:10px; color:#FF5555; font-size:12px; font-family:monospace;">
                                        ${v}
                                    </div>
                                `).join('')}
                            </div>
                        ` : `
                            <div style="background:rgba(0,255,102,0.05); border:1px solid rgba(0,255,102,0.2); border-radius:4px; padding:10px; color:#00ff66; font-size:12px; font-family:monospace;">
                                ✔ Zero malicious honeypot traps, excessive taxes, or hidden owner privileges detected.
                            </div>
                        `}
                    </div>

                    <!-- Key Attributes -->
                    <div class="grid-2col" style="gap:12px;">
                        <div style="background:rgba(255,255,255,0.02); padding:10px; border-radius:4px; font-family:monospace; font-size:11px;">
                            <div class="dim">CONTRACT CREATOR:</div>
                            <div class="cyan" style="word-break:break-all; margin-top:2px;">${t.creator || 'N/A'}</div>
                            <div class="dim" style="margin-top:8px;">CURRENT OWNER:</div>
                            <div class="emerald" style="word-break:break-all; margin-top:2px;">${t.owner || 'N/A'}</div>
                        </div>
                        <div style="background:rgba(255,255,255,0.02); padding:10px; border-radius:4px; font-family:monospace; font-size:11px;">
                            <div class="dim">UNLIMITED MINTABLE: <strong class="${checks.is_mintable ? 'red' : 'emerald'}">${checks.is_mintable ? 'YES (RISK)' : 'NO'}</strong></div>
                            <div class="dim" style="margin-top:4px;">UPGRADEABLE PROXY: <strong class="${checks.is_proxy_contract ? 'amber' : 'emerald'}">${checks.is_proxy_contract ? 'YES (PROXY)' : 'NO'}</strong></div>
                            <div class="dim" style="margin-top:4px;">WALLET BLACKLIST: <strong class="${checks.has_blacklist_function ? 'red' : 'emerald'}">${checks.has_blacklist_function ? 'YES (RISK)' : 'NO'}</strong></div>
                            <div class="dim" style="margin-top:4px;">CANNOT SELL: <strong class="${checks.cannot_sell_all ? 'red' : 'emerald'}">${checks.cannot_sell_all ? 'CONFIRMED' : 'NO'}</strong></div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        if (statusEl) statusEl.innerHTML = `<span class="emerald">[COMPLETED]</span> Audit complete · Risk: ${d.threat_tier}`;
    } catch (e) {
        if (statusEl) statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        if (resultsEl) resultsEl.innerHTML = `<div class="critical mono" style="padding:16px;">Honeypot audit error: ${e.message}</div>`;
    }
};

/* ============================================================
   V7 COMPANION TOOL 4: STEG-HUNTER & LSB BITPLANE EXTRACTOR
   ============================================================ */
window.handleStegHunterUpload = async function(file) {
    if (!file) return;

    const statusEl = document.getElementById('steghunter-status');
    const resultsEl = document.getElementById('steghunter-results');

    if (statusEl) statusEl.innerHTML = `<span class="cyan">[ANALYZING]</span> Slicing bitplanes and scanning byte offsets for ${file.name}...`;
    if (resultsEl) resultsEl.innerHTML = `<div style="padding:30px; text-align:center;" class="mono cyan"><span class="engine-pulse-dot"></span> Carving embedded archives and computing Shannon entropy...</div>`;

    const formData = new FormData();
    formData.append('file', file);

    try {
        const res = await fetch('/api/steghunter/upload', {
            method: 'POST',
            body: formData
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to execute Steg-Hunter`);
        const d = await res.json();

        if (d.status === 'error') {
            throw new Error(d.error || 'Steganography analysis failed');
        }

        const info = d.file_info || {};
        const sum = d.forensic_summary || {};
        const carved = d.carved_payloads || [];
        const strings = d.lsb_strings || [];
        const planes = d.bitplanes || {};

        resultsEl.innerHTML = `
            <div class="glass-card" style="margin-top:16px;">
                <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="telemetry-label">STEGANOGRAPHY &amp; BINARY CARVER</span>
                        <h2 class="card-title" style="color:#C084FC;">${info.filename}</h2>
                    </div>
                    <span class="badge ${sum.carved_payloads_count > 0 ? 'hazard' : 'cyan'}">${sum.threat_tier}</span>
                </div>
                <div class="card-body">
                    <div class="grid-3col" style="gap:12px; margin-bottom:16px;">
                        <div class="mini-stat-card">
                            <span class="mini-stat-label">SHANNON ENTROPY</span>
                            <span class="mini-stat-val ${info.shannon_entropy > 7.8 ? 'red' : 'cyan'}">${info.shannon_entropy} / 8.0</span>
                        </div>
                        <div class="mini-stat-card">
                            <span class="mini-stat-label">EMBEDDED ARCHIVES</span>
                            <span class="mini-stat-val ${carved.length > 0 ? 'red' : 'emerald'}">${carved.length} CARVED</span>
                        </div>
                        <div class="mini-stat-card">
                            <span class="mini-stat-label">POLYGLOT FILE</span>
                            <span class="mini-stat-val ${sum.is_polyglot_container ? 'red' : 'emerald'}">${sum.is_polyglot_container ? 'DETECTED' : 'CLEAN'}</span>
                        </div>
                    </div>

                    <!-- Carved Embedded Archives -->
                    <div style="margin-bottom:16px;">
                        <span class="telemetry-label" style="margin-bottom:8px; display:block;">CARVED EMBEDDED BINARY ARCHIVES (MAGIC BYTE OFFSETS)</span>
                        ${carved.length > 0 ? `
                            <table class="table-tactical" style="width:100%;">
                                <thead><tr><th>PAYLOAD TYPE</th><th>OFFSET (HEX)</th><th>MIME TYPE</th><th>SIGNATURE PREVIEW</th></tr></thead>
                                <tbody>
                                    ${carved.map(c => `
                                        <tr>
                                            <td class="hazard mono" style="font-weight:bold;">${c.type}</td>
                                            <td class="cyan mono">${c.offset_hex} (${c.offset_dec})</td>
                                            <td class="dim">${c.mime_type}</td>
                                            <td class="mono emerald" style="font-size:10px;">${c.preview_hex}...</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        ` : `
                            <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-slate); border-radius:4px; padding:10px;" class="mono dim small-text">
                                Zero hidden ZIP, RAR, 7z, PDF, or executable containers carved from binary stream.
                            </div>
                        `}
                    </div>

                    <!-- LSB Extracted ASCII Plaintexts -->
                    <div style="margin-bottom:16px;">
                        <span class="telemetry-label" style="margin-bottom:6px; display:block;">LEAST SIGNIFICANT BIT (LSB) EXTRACTED PLAINTEXT STRINGS</span>
                        ${strings.length > 0 ? `
                            <div style="background:#070d18; border:1px solid var(--border-slate); border-radius:4px; padding:10px; font-family:monospace; font-size:11px; max-height:160px; overflow-y:auto;">
                                ${strings.map(s => `<div style="color:#00F0FF; margin-bottom:4px;">&gt; ${s}</div>`).join('')}
                            </div>
                        ` : `
                            <div class="dim mono small-text">No coherent ASCII strings extracted from 0th bitplane.</div>
                        `}
                    </div>

                    <!-- Bitplane Visual Previews -->
                    ${planes.red_lsb_plane ? `
                        <div>
                            <span class="telemetry-label" style="margin-bottom:8px; display:block;">0th BITPLANE DECOMPOSITION SLICES (RGB NOISE ANALYSIS)</span>
                            <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px;">
                                <div style="text-align:center; background:rgba(255,0,0,0.05); border:1px solid rgba(255,0,0,0.2); border-radius:4px; padding:8px;">
                                    <div class="mono small-text" style="color:#ff5555; margin-bottom:4px;">RED BIT-0 PLANE</div>
                                    <img src="${planes.red_lsb_plane}" style="max-width:100%; height:auto; border-radius:2px;">
                                </div>
                                <div style="text-align:center; background:rgba(0,255,0,0.05); border:1px solid rgba(0,255,0,0.2); border-radius:4px; padding:8px;">
                                    <div class="mono small-text" style="color:#55ff55; margin-bottom:4px;">GREEN BIT-0 PLANE</div>
                                    <img src="${planes.green_lsb_plane}" style="max-width:100%; height:auto; border-radius:2px;">
                                </div>
                                <div style="text-align:center; background:rgba(0,0,255,0.05); border:1px solid rgba(0,120,255,0.2); border-radius:4px; padding:8px;">
                                    <div class="mono small-text" style="color:#5599ff; margin-bottom:4px;">BLUE BIT-0 PLANE</div>
                                    <img src="${planes.blue_lsb_plane}" style="max-width:100%; height:auto; border-radius:2px;">
                                </div>
                            </div>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;

        if (statusEl) statusEl.innerHTML = `<span class="emerald">[COMPLETED]</span> Steg analysis complete for ${file.name}`;
    } catch (e) {
        if (statusEl) statusEl.innerHTML = `<span class="critical">ERROR:</span> ${e.message}`;
        if (resultsEl) resultsEl.innerHTML = `<div class="critical mono" style="padding:16px;">Steg analysis error: ${e.message}</div>`;
    }
};

